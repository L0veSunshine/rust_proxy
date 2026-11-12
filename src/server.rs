use crate::api::common::ServerStatistic;
use crate::config::ServerConfig;
use crate::connection_pool::ConnectionPool;
use crate::health::SystemMetrics;
use crate::protocol::fallback::{handle_tcp_fallback, handle_tls_fallback};
use crate::protocol::message::{
    Command, Response, encode_udp_frame, read_client_request, read_udp_frame, response_to_client,
};
use crate::protocol::net_addr::NetAddr;
use crate::protocol::utils::{NATType, bind_dual_stack_udp, get_canonical_ip, to_dual_stack};
use crate::relay::{relay_bidirectional, write_and_flush};
use crate::secret::tls;
use crate::secret::totp::{consume_token, token_fingerprint, verify_user_token};
use crate::shutdown::{ConnectionGuard, GracefulShutdown};
use crate::user_manager::{UserLimiter, UserManager};
use anyhow::Result;
use moka::future::Cache;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::collections::HashMap;
use std::io::Cursor;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::time::timeout_at;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

enum HandShakeStatus {
    Success(Uuid, Command, NetAddr, usize),
    Fallback,
    Eof,
}

pub const UDP_BUFFER_SIZE: usize = 65535;

/// 从 TCP 建连到读完 Client Hello（含 TLS 握手）的总时限，防御 Slowloris
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Client Hello 的最大长度，超过即视为非本协议流量并回落
const HANDSHAKE_BUFFER_SIZE: usize = 1024;
/// RFC 4787：NAT 维护 UDP 映射的超时时间应不少于 2 分钟
const NAT_MAPPING_IDLE: Duration = Duration::from_secs(120);
/// UDP 关联内域名解析结果的缓存时间与条目上限
const UDP_DNS_CACHE_TTL: Duration = Duration::from_secs(60);
const UDP_DNS_CACHE_MAX: usize = 1024;
/// accept 出错（如文件描述符耗尽）后的退避时间，避免空转
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

pub async fn run(
    configs: ServerConfig,
    manager: Arc<UserManager>,
    stat_map: Arc<ServerStatistic>,
    metrics: Arc<SystemMetrics>,
    connection_pool: ConnectionPool,
    shutdown: GracefulShutdown,
) -> Result<()> {
    let acceptor = Arc::new(tls::create_server_config(
        &configs.cert_path,
        &configs.key_path,
    )?);
    let addr = configs.listen_addr()?;
    let listener = bind_listener(addr)?;

    println!("Server listening on {}", addr);
    println!("Max connections: {}", connection_pool.max_connections());

    serve(
        listener,
        acceptor,
        manager,
        stat_map,
        metrics,
        connection_pool,
        shutdown,
    )
    .await
}

/// 创建监听 socket，并适配 IPv4 / IPv6 协议族
pub fn bind_listener(addr: SocketAddr) -> Result<TcpListener> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    // 如果是 IPv6 且为 [::]，关闭 IPV6_V6ONLY 允许 IPv4 映射实现双栈监听
    if addr.is_ipv6() && addr.ip() == IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED) {
        let _ = socket.set_only_v6(false);
    }

    // 设置端口复用 (防止重启报错)
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    Ok(TcpListener::from_std(socket.into())?)
}

/// 在已绑定的监听器上处理连接，直到收到关闭信号
pub async fn serve(
    listener: TcpListener,
    acceptor: Arc<TlsAcceptor>,
    manager: Arc<UserManager>,
    stat_map: Arc<ServerStatistic>,
    metrics: Arc<SystemMetrics>,
    connection_pool: ConnectionPool,
    shutdown: GracefulShutdown,
) -> Result<()> {
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(60)) // 空闲60秒后开始探测
        .with_interval(Duration::from_secs(10)) // 探测失败后每10秒重试
        .with_retries(3); // 重试3次失败则断开

    loop {
        // 等待新连接或关闭信号（CancellationToken 触发后状态保持，不会漏掉信号）
        let accept_result = select! {
            biased;
            _ = shutdown.wait_shutdown() => {
                info!("Received shutdown signal in accept loop");
                break;
            }
            result = listener.accept() => result,
        };

        let (socket, peer) = match accept_result {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };

        // 尝试获取连接许可
        let conn_permit = match connection_pool.try_acquire() {
            Ok(permit) => permit,
            Err(e) => {
                warn!("Connection pool full, rejecting connection: {}", e);
                // 设置 linger(0)，在丢弃时发送 RST 立即终止连接，防止高并发下服务端堆积大量 TIME_WAIT 套接字
                let _ = SockRef::from(&socket).set_linger(Some(Duration::ZERO));
                continue;
            }
        };

        // 单个 socket 设置失败只影响这条连接，不能让整个服务退出
        let sock_opts = {
            let native_socket = SockRef::from(&socket);
            native_socket
                .set_tcp_nodelay(true)
                .and_then(|_| native_socket.set_tcp_keepalive(&ka))
        };
        if let Err(e) = sock_opts {
            warn!("Failed to set socket options for {}: {}", peer, e);
            continue;
        }

        // 跟踪连接（RAII 自动清理）
        let conn_guard = ConnectionGuard::new(shutdown.clone());
        metrics.record_connection();

        let acceptor = acceptor.clone();
        let manager = manager.clone();
        let stat_map = stat_map.clone();
        let conn_cancel = shutdown.connection_token();

        tokio::spawn(async move {
            // 许可与守卫随任务结束一起释放
            let _permit = conn_permit;
            let _guard = conn_guard;

            // 优雅关闭超时后会取消 conn_cancel，直接丢弃整条连接
            let result = conn_cancel
                .run_until_cancelled(handle_client(
                    socket,
                    peer.ip(),
                    &acceptor,
                    NATType::FullCone,
                    manager,
                    &stat_map,
                ))
                .await;
            if let Some(Err(e)) = result {
                error!("Server Error: {}", e);
            }
        });
    }

    info!("Server accept loop stopped");
    Ok(())
}

async fn handle_client(
    socket: TcpStream,
    peer_ip: IpAddr,
    acceptor: &TlsAcceptor,
    nat_type: NATType,
    manager: Arc<UserManager>,
    stat_map: &ServerStatistic,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + HANDSHAKE_TIMEOUT;

    let mut header_byte = [0u8; 1];
    let Ok(peeked) = timeout_at(deadline, socket.peek(&mut header_byte)).await else {
        info!("Handshake timeout before first byte");
        return Ok(());
    };
    if peeked? > 0 && header_byte[0] != 0x16 {
        info!("Non-TLS traffic detected, falling back to TCP proxy");
        return handle_tcp_fallback(socket).await;
    }

    // 建立 TLS（同样受握手时限约束）
    let mut stream = match timeout_at(deadline, acceptor.accept(socket)).await {
        Ok(stream) => stream?,
        Err(_) => {
            info!("TLS handshake timeout");
            return Ok(());
        }
    };

    let mut peek = vec![0u8; HANDSHAKE_BUFFER_SIZE];
    let mut offset = 0;
    let handshake_future = async {
        loop {
            if offset >= peek.len() {
                info!("Handshake buffer full, fallback to web");
                return Ok(HandShakeStatus::Fallback);
            }
            let n = stream.read(&mut peek[offset..]).await?;
            if n == 0 {
                return Ok::<HandShakeStatus, std::io::Error>(HandShakeStatus::Eof); // EOF 连接关闭
            }
            offset += n;
            let mut cursor = Cursor::new(&peek[..offset]);
            // 读取握手包 (UUID Auth + Padding Skip)
            match read_client_request(&mut cursor).await {
                Ok((uuid, cmd, addr)) => {
                    let consumed = cursor.position() as usize;
                    return Ok(HandShakeStatus::Success(uuid, cmd, addr, consumed));
                }
                // 数据不够 (UnexpectedEof) 就继续读；其他错误说明协议不对，回落
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => continue,
                Err(e) => {
                    info!("Invalid client hello: {}, fallback", e);
                    return Ok(HandShakeStatus::Fallback);
                }
            }
        }
    };

    let (uuid, cmd, addr, consumed_len) = match timeout_at(deadline, handshake_future).await {
        // 握手超时 (Slowloris protection)
        Err(_) => {
            info!("Handshake timeout");
            return Ok(());
        }
        Ok(Err(e)) => return Err(e.into()),
        Ok(Ok(HandShakeStatus::Eof)) => return Ok(()),
        Ok(Ok(HandShakeStatus::Fallback)) => {
            return handle_tls_fallback(&peek[..offset], stream).await;
        }
        Ok(Ok(HandShakeStatus::Success(uuid, cmd, addr, len))) => (uuid, cmd, addr, len),
    };

    let key_sig: [u8; 4] = uuid.as_bytes()[12..16].try_into().unwrap_or_default();

    // 1. 先做密码学校验(此时还不消费 token)
    let verified = match verify_user_token(&manager, &uuid) {
        Some(v) => v,
        None => return handle_tls_fallback(&peek[..offset], stream).await,
    };

    // 2. 所有前置检查(IP 限制等)通过后，才真正消费 token，
    //    避免后续步骤失败时把这次 token 白白烧掉。
    //    函数结束时 _ip_guard 被销毁，自动调用 leave_ip
    let _ip_guard = manager.enter_ip(key_sig, get_canonical_ip(peer_ip))?;
    if !consume_token(&uuid, verified.expire_at) {
        // 不打印原始 token，避免日志泄露可用于重放的凭证
        warn!(
            "Replay Attack Detected (user {:x?}, token fp {})",
            key_sig,
            token_fingerprint(&uuid)
        );
        // 回落到 Web 服务前先释放 IP 名额，避免重放连接占用合法用户配额
        drop(_ip_guard);
        return handle_tls_fallback(&peek[..offset], stream).await;
    }

    let limiter = manager.get_user_limiter(key_sig, verified.profile.rate_limit);
    let limiter = limiter.as_deref();

    response_to_client(&mut stream, &Response::Success).await?;

    // 握手包之后客户端可能已经发来了数据，先把这部分接到读端前面
    let remaining = peek[consumed_len..offset].to_vec();
    let (client_reader, client_writer) = tokio::io::split(stream);
    let client_reader = AsyncReadExt::chain(Cursor::new(remaining), client_reader);

    match cmd {
        Command::TcpConnect => {
            let target = addr.connect_tcp().await?;
            info!("Tcp connect to {}", addr);
            let (target_r, target_w) = target.into_split();
            let cancel = CancellationToken::new();
            relay_bidirectional(
                client_reader,
                client_writer,
                target_r,
                target_w,
                limiter,
                &cancel,
                |n| stat_map.update_upload(key_sig, n),
                |n| stat_map.update_download(key_sig, n),
            )
            .await;
        }
        Command::UdpAssociate => {
            relay_udp(
                client_reader,
                client_writer,
                nat_type,
                limiter,
                stat_map,
                key_sig,
            )
            .await?;
        }
    }

    Ok(())
}

/// NAT 白名单的 key：Restricted 只看 IP（端口记为 0），PortRestricted 看 IP + 端口
fn nat_key(nat_type: NATType, addr: SocketAddr) -> (IpAddr, u16) {
    let ip = get_canonical_ip(addr.ip());
    match nat_type {
        NATType::PortRestricted => (ip, addr.port()),
        _ => (ip, 0),
    }
}

/// 解析 UDP 目标的候选地址列表：命中未过期缓存时直接返回上次可用的地址，否则解析全部候选地址
async fn resolve_candidates(
    cache: &HashMap<String, (SocketAddr, Instant)>,
    addr: &NetAddr,
) -> std::io::Result<Vec<SocketAddr>> {
    if let Some(socket_addr) = addr.socket_addr() {
        return Ok(vec![socket_addr]);
    }
    if let Some((resolved, at)) = cache.get(&addr.to_string())
        && at.elapsed() < UDP_DNS_CACHE_TTL
    {
        return Ok(vec![*resolved]);
    }
    addr.resolve_all().await
}

/// 缓存域名实际发送成功的 SocketAddr，避免后续包重复做 DNS 解析或反复尝试不可达地址族
fn cache_resolved_udp(
    cache: &mut HashMap<String, (SocketAddr, Instant)>,
    addr: &NetAddr,
    resolved: SocketAddr,
) {
    if !matches!(addr, NetAddr::Domain(..)) {
        return;
    }
    if cache.len() >= UDP_DNS_CACHE_MAX {
        cache.retain(|_, (_, at)| at.elapsed() < UDP_DNS_CACHE_TTL);
        if cache.len() >= UDP_DNS_CACHE_MAX {
            cache.clear();
        }
    }
    cache.insert(addr.to_string(), (resolved, Instant::now()));
}

/// 依次尝试向候选地址发送 UDP 数据包，返回首个发送成功的地址。
///
/// 解决纯 IPv4 机器绑定双栈 `[::]` socket 时 DNS 优先返回 `AAAA` 导致 `ENETUNREACH` 的问题。
async fn send_udp_first_reachable(
    socket: &tokio::net::UdpSocket,
    payload: &[u8],
    candidates: &[SocketAddr],
    nat_type: NATType,
    whitelist: Option<&Cache<(IpAddr, u16), ()>>,
) -> std::io::Result<SocketAddr> {
    let mut last_err = None;
    for &target in candidates {
        let key = nat_key(nat_type, target);
        if let Some(wl) = whitelist {
            wl.insert(key, ()).await;
        }
        match socket.send_to(payload, to_dual_stack(target)).await {
            Ok(_) => return Ok(target),
            Err(e) => {
                if let Some(wl) = whitelist {
                    wl.invalidate(&key).await;
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err
        .unwrap_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no candidate")))
}

/// UDP 模式：TLS 隧道 <-> 本地 UDP socket
async fn relay_udp<R, W>(
    mut client_reader: R,
    mut client_writer: W,
    nat_type: NATType,
    limiter: Option<&UserLimiter>,
    stat_map: &ServerStatistic,
    key_sig: [u8; 4],
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let socket = bind_dual_stack_udp()?;
    // Full Cone 不需要白名单，避免为每个关联都建一个缓存
    let whitelist: Option<Cache<(IpAddr, u16), ()>> = match nat_type {
        NATType::FullCone => None,
        _ => Some(
            Cache::builder()
                .max_capacity(10000)
                .time_to_idle(NAT_MAPPING_IDLE)
                .build(),
        ),
    };
    let cancel = CancellationToken::new();

    // 外部 -> 代理 -> 客户端
    let inbound = async {
        let mut buf = vec![0u8; UDP_BUFFER_SIZE];
        let mut frame = Vec::with_capacity(UDP_BUFFER_SIZE + 32);
        loop {
            let (n, src_addr) = match socket.recv_from(&mut buf).await {
                Ok(res) => res,
                // Windows 下向不可达 UDP 端口发送后，ICMP Port Unreachable 会在下次 recv_from 报 ConnectionReset
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Err(e) => {
                    error!("Receive data from socket Error: {}", e);
                    break;
                }
            };

            if let Some(whitelist) = &whitelist
                && !whitelist.contains_key(&nat_key(nat_type, src_addr))
            {
                continue;
            }

            let src = SocketAddr::new(get_canonical_ip(src_addr.ip()), src_addr.port());
            frame.clear();
            if let Err(e) = encode_udp_frame(&NetAddr::from(src), &buf[..n], &mut frame) {
                error!("build udp frame fail {}", e);
                continue;
            }
            if let Some(limiter) = limiter {
                limiter.consume(n).await;
            }
            if let Err(e) = write_and_flush(&mut client_writer, &frame).await {
                error!("Server write udp to client error {}", e);
                break;
            }
            stat_map.update_download(key_sig, n);
        }
    };

    // 客户端 -> 代理 -> 外部
    let outbound = async {
        let mut dns_cache = HashMap::new();
        loop {
            let (addr, payload) = match read_udp_frame(&mut client_reader).await {
                Ok(frame) => frame,
                Err(_) => break,
            };
            let candidates = match resolve_candidates(&dns_cache, &addr).await {
                Ok(candidates) => candidates,
                Err(e) => {
                    warn!("Resolve udp target {} error: {}", addr, e);
                    continue;
                }
            };
            if let Some(limiter) = limiter {
                limiter.consume(payload.len()).await;
            }
            debug!("Udp send to {}", addr);
            match send_udp_first_reachable(
                &socket,
                &payload,
                &candidates,
                nat_type,
                whitelist.as_ref(),
            )
            .await
            {
                Ok(chosen) => {
                    cache_resolved_udp(&mut dns_cache, &addr, chosen);
                    stat_map.update_upload(key_sig, payload.len());
                }
                Err(e) => {
                    // 单个目标发送失败（如目标网络不可达）不应拆除整条 UDP 关联
                    if matches!(addr, NetAddr::Domain(..)) {
                        dns_cache.remove(&addr.to_string());
                    }
                    warn!("Write udp to target {} error: {}", addr, e);
                    continue;
                }
            }
        }
    };

    // 任意一个方向结束都拆除整个关联
    tokio::join!(
        async {
            cancel.run_until_cancelled(inbound).await;
            cancel.cancel();
        },
        async {
            cancel.run_until_cancelled(outbound).await;
            cancel.cancel();
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    #[tokio::test]
    async fn test_send_udp_falls_back_to_next_candidate() {
        let socket = bind_dual_stack_udp().unwrap();
        let recv = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let recv_addr = recv.local_addr().unwrap();
        // 未指定地址 [::]:0 在各平台 send_to 均会失败，用来模拟不可达的首选候选地址
        let invalid = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
        let whitelist: Cache<(IpAddr, u16), ()> = Cache::builder().max_capacity(16).build();

        let chosen = send_udp_first_reachable(
            &socket,
            b"ping",
            &[invalid, recv_addr],
            NATType::PortRestricted,
            Some(&whitelist),
        )
        .await
        .unwrap();

        assert_eq!(chosen, recv_addr);
        assert!(!whitelist.contains_key(&nat_key(NATType::PortRestricted, invalid)));
        assert!(whitelist.contains_key(&nat_key(NATType::PortRestricted, recv_addr)));

        let mut buf = [0u8; 16];
        let (n, _) = recv.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
    }
}
