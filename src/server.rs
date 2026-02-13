use crate::api::common::ServerStatistic;
use crate::config::ServerConfig;
use crate::connection_pool::ConnectionPool;
use crate::health::SystemMetrics;
use crate::protocol::fallback::{handle_tcp_fallback, handle_tls_fallback};
use crate::protocol::message::{
    Command, Response, build_udp_frame, read_client_request, read_udp_frame, response_to_client,
};
use crate::protocol::net_addr::NetAddr;
use crate::protocol::utils::{NATType, bind_dual_stack_udp, get_canonical_ip};
use crate::secret::tls;
use crate::secret::totp::get_user_profile;
use crate::shutdown::{ConnectionGuard, GracefulShutdown};
use crate::user_manager::UserManager;
use anyhow::Result;
use bytes::BytesMut;
use moka::future::Cache;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::io::Cursor;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::Notify;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use uuid::Uuid;

enum HandShakeStatus {
    Success(Uuid, Command, NetAddr, usize),
    Fallback,
    Eof,
}

pub const UDP_BUFFER_SIZE: usize = 65535;
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
    // 1. 创建 IPv6 Socket
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    // 2. 关闭 IPV6_V6ONLY，允许 IPv4 映射到这个 IPv6 Socket
    // 这样绑定 [::] 也就同时绑定了 0.0.0.0
    socket.set_only_v6(false)?;
    // 3. 设置端口复用 (防止重启报错)
    socket.set_reuse_address(true)?;
    // 4. 设置为非阻塞，适配 Tokio
    socket.set_nonblocking(true)?;
    // 5. 绑定到 [::]:port (同时覆盖 IPv4 和 IPv6)
    let addr = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, configs.port));
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let listener = TcpListener::from_std(socket.into())?;
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(60)) // 空闲60秒后开始探测
        .with_interval(Duration::from_secs(10)) // 探测失败后每10秒重试
        .with_retries(3); // 重试3次失败则断开

    println!("Server listening on [::]:{}", configs.port);
    println!("Max connections: {}", connection_pool.max_connections());

    loop {
        // 检查是否正在关闭
        if shutdown.is_shutting_down() {
            info!("Server is shutting down, stopping accept loop");
            break;
        }

        // 等待新连接或关闭信号
        let accept_result = select! {
            result = listener.accept() => result,
            _ = shutdown.wait_shutdown() => {
                info!("Received shutdown signal in accept loop");
                break;
            }
        };

        let (socket, _) = match accept_result {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };

        // 尝试获取连接许可
        let conn_permit = match connection_pool.acquire().await {
            Ok(permit) => permit,
            Err(e) => {
                warn!("Connection pool full, rejecting connection: {}", e);
                continue;
            }
        };

        // 跟踪连接（RAII 自动清理）
        let conn_guard = ConnectionGuard::new(shutdown.clone());
        metrics.increment_connection();

        let native_socket = SockRef::from(&socket);
        native_socket.set_tcp_nodelay(true)?;
        native_socket.set_tcp_keepalive(&ka)?;
        let acceptor = acceptor.clone();
        let user_manager_cloned = manager.clone();
        let stat_map_cloned = stat_map.clone();
        let metrics_cloned = metrics.clone();

        tokio::spawn(async move {
            // 保持连接许可和连接守卫生命周期
            let _permit = conn_permit;
            let _guard = conn_guard;

            if let Err(e) = handle_client(
                socket,
                acceptor,
                NATType::FullCone,
                user_manager_cloned,
                stat_map_cloned,
            )
            .await
            {
                error!("Server Error: {}", e);
            }

            // 连接结束，减少活跃连接数
            metrics_cloned.decrement_connection();
        });
    }

    info!("Server accept loop stopped");
    Ok(())
}

async fn handle_client(
    mut socket: TcpStream,
    acceptor: Arc<TlsAcceptor>,
    nat_type: NATType,
    manager: Arc<UserManager>,
    stat_map: Arc<ServerStatistic>,
) -> Result<()> {
    let mut header_byte = [0u8; 1];
    let n = socket.peek(&mut header_byte).await?;

    if n > 0 && header_byte[0] != 0x16 {
        info!("Non-TLS traffic detected, falling back to TCP proxy");
        return handle_tcp_fallback(&mut socket).await;
    }

    let peer_ip = socket.peer_addr()?.ip();
    // 建立TLS
    let stream = acceptor.accept(socket).await?;
    let (mut client_reader, mut client_writer) = tokio::io::split(stream);

    let mut peek = vec![0u8; 1024];
    let mut offset = 0;
    let handshake_future = async {
        loop {
            if offset >= peek.len() {
                info!("Handshake buffer full, fallback to web");
                return Ok(HandShakeStatus::Fallback);
            }
            let n = client_reader.read(&mut peek[offset..]).await?;
            if n == 0 {
                return Ok::<HandShakeStatus, std::io::Error>(HandShakeStatus::Eof); // EOF 连接关闭
            }
            offset += n;
            let valid_data = &peek[..offset];
            let mut cursor = Cursor::new(valid_data);
            // 读取握手包 (UUID Auth + Padding Skip)
            match read_client_request(&mut cursor).await {
                Ok((uuid, cmd, addr)) => {
                    // 解析成功！跳出循环
                    let consumed = cursor.position() as usize;
                    return Ok(HandShakeStatus::Success(uuid, cmd, addr, consumed));
                }
                Err(e) => {
                    // 关键点：如果是数据不够 (UnexpectedEof)，则 continue 继续读
                    // 如果是其他错误 (InvalidData)，则说明协议不对，回落
                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                        // 数据不够，继续下一轮 read
                        continue;
                    } else {
                        info!("Invalid client hello: {}, fallback", e);
                        return Ok(HandShakeStatus::Fallback);
                    }
                }
            }
        }
    };

    let handshake_res = timeout(Duration::from_secs(10), handshake_future).await;
    let (uuid, cmd, addr, consumed_len) = match handshake_res {
        // 握手超时
        Err(_) => {
            // Slowloris protection
            info!("Handshake timeout");
            // 超时直接断开，或者也可以选择回落
            return Ok(());
        }
        Ok(Err(e)) => return Err(e.into()),
        Ok(Ok(res)) => match res {
            // return Ok(())结束本次链接
            HandShakeStatus::Eof => return Ok(()),
            HandShakeStatus::Fallback => {
                return handle_tls_fallback(&peek[..offset], client_reader, client_writer).await;
            }
            HandShakeStatus::Success(uuid, cmd, addr, len) => (uuid, cmd, addr, len),
        },
    };

    let key_sig: [u8; 4] = uuid.as_bytes()[12..16].try_into().unwrap_or_default();

    let user_profile = match get_user_profile(manager.clone(), &uuid) {
        Some(p) => p,
        None => return handle_tls_fallback(&peek[..offset], client_reader, client_writer).await,
    };

    let _guard = manager.enter_ip(key_sig, get_canonical_ip(peer_ip))?;
    let limiter = manager.get_user_limiter(key_sig, user_profile.rate_limit);
    let limiter_upload = limiter.clone();

    let stat_map_upload = stat_map.clone();
    let stat_map_download = stat_map.clone();

    let remaining = peek[consumed_len..offset].to_vec();
    let mut chained_reader = AsyncReadExt::chain(Cursor::new(remaining), client_reader);

    response_to_client(&mut client_writer, &Response::Success).await?;

    match cmd {
        // === TCP 模式 ===
        Command::TcpConnect => {
            let target = TcpStream::connect((addr.addr(), addr.port())).await?;
            info!("Tcp connect to {}", addr);
            let (mut target_r, mut target_w) = target.into_split();

            // 创建停机信号
            let shutdown_tcp = Arc::new(Notify::new());
            let shutdown_tcp_rx_local = shutdown_tcp.clone();
            let shutdown_tcp_rx_remote = shutdown_tcp.clone();
            let shutdown_tcp_tx_local = shutdown_tcp.clone();
            let shutdown_tcp_tx_remote = shutdown_tcp.clone();

            // 目标 -> 代理 -> 客户端
            tokio::spawn(async move {
                let mut target_to_client_buf = vec![0u8; 8192];
                loop {
                    let n = select! {
                        _ = shutdown_tcp_rx_remote.notified() => break,
                        n = target_r.read(&mut target_to_client_buf) => n
                    };
                    let length = match n {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) => {
                            error!("read form target error: {}", e);
                            break;
                        }
                    };

                    // 【限速点】: 写入目标服务器之前扣除令牌
                    if let Some(ref limiter) = limiter
                        && let Some(nz) = std::num::NonZeroU32::new(length as u32)
                    {
                        limiter.until_n_ready(nz).await.ok();
                    }

                    if let Err(e) = client_writer
                        .write_all(&target_to_client_buf[..length])
                        .await
                    {
                        error!("Target write to client error {}", e);
                        break;
                    }
                    stat_map_download.update_download(key_sig, length);
                }
                shutdown_tcp_tx_remote.notify_waiters();
            });

            // 客户端 -> 代理 -> 目标
            let mut client_to_target_buf = vec![0u8; 8192];
            loop {
                let n = select! {
                    _ = shutdown_tcp_rx_local.notified() => break,
                    n = chained_reader.read(&mut client_to_target_buf) => n
                };
                let length = match n {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        error!("Read from client error {}", e);
                        break;
                    }
                };
                if let Some(ref limiter) = limiter_upload
                    && let Some(nz) = std::num::NonZeroU32::new(length as u32)
                {
                    limiter.until_n_ready(nz).await.ok();
                };

                if let Err(e) = target_w.write_all(&client_to_target_buf[..length]).await {
                    error!("Write to target error {}", e);
                    break;
                }
                stat_map_upload.update_upload(key_sig, length);
            }
            shutdown_tcp_tx_local.notify_waiters()
        }

        // === UDP 模式 (Full Cone) ===
        Command::UdpAssociate => {
            // 创建停机信号
            let shutdown = Arc::new(Notify::new());
            let shutdown_rx_1 = shutdown.clone();
            let shutdown_tx_1 = shutdown.clone();
            let shutdown_rx_2 = shutdown.clone();
            let shutdown_tx_2 = shutdown.clone();

            // RFC 4787 NATs维护UDP映射超时时间应不少于2分钟
            let whitelist: Cache<String, ()> = Cache::builder()
                .max_capacity(10000)
                .time_to_idle(Duration::from_secs(120))
                .build();

            let socket = Arc::new(bind_dual_stack_udp()?);

            // 外部 -> 代理 -> 客户端
            let sock_recv = socket.clone();
            let whitelist_recv = whitelist.clone();

            let inbound_task = tokio::spawn(async move {
                let mut buf = BytesMut::with_capacity(UDP_BUFFER_SIZE);
                loop {
                    if buf.capacity() < UDP_BUFFER_SIZE {
                        buf.reserve(UDP_BUFFER_SIZE);
                    }
                    buf.resize(UDP_BUFFER_SIZE, 0);

                    let (n, src_addr) = select! {
                        _ = shutdown_rx_1.notified() => break,
                        res = sock_recv.recv_from(&mut buf) => {
                            match res {
                                Ok(res) => res,
                                Err(e) => {
                                    error!("Receive data from socket Error: {}", e);
                                    break;
                                }
                            }
                        }
                    };
                    if n == 0 {
                        break;
                    }

                    let canonical_ip = get_canonical_ip(src_addr.ip());

                    let allow = match nat_type {
                        NATType::FullCone => true,
                        NATType::Restricted => {
                            let key = canonical_ip.to_string();
                            whitelist_recv.contains_key(&key) // O(1) 查询
                        }
                        NATType::PortRestricted => {
                            let key = format!("{}:{}", canonical_ip, src_addr.port());
                            whitelist_recv.contains_key(&key) // O(1) 查询
                        }
                    };

                    if allow {
                        let packet = buf.split_to(n);
                        let net_addr = match canonical_ip {
                            IpAddr::V4(ip) => NetAddr::new_ipv4(ip, src_addr.port()),
                            IpAddr::V6(ip) => NetAddr::new_ipv6(ip, src_addr.port()),
                        };
                        let cmd = build_udp_frame(&net_addr, &packet.freeze());
                        match cmd {
                            Ok(c) => {
                                if let Some(ref limiter) = limiter
                                    && let Some(nz) = std::num::NonZeroU32::new(n as u32)
                                {
                                    limiter.until_n_ready(nz).await.ok();
                                };
                                if let Err(e) = client_writer.write_all(&c).await {
                                    error!("Server write udp to client error {}", e);
                                    break;
                                }
                                stat_map_download.update_download(key_sig, n);
                            }
                            Err(e) => {
                                error!("build udp frame fail {}", e);
                            }
                        };
                    }
                }
                shutdown_tx_1.notify_waiters();
            });

            // 客户端 -> 代理 -> 外部
            let sock_send = socket.clone();
            let outbound_task = tokio::spawn(async move {
                loop {
                    let resp = select! {
                        _ = shutdown_rx_2.notified() => break,
                        resp = read_udp_frame(&mut chained_reader) => resp,
                    };
                    match resp {
                        Ok((addr, payload)) => {
                            if nat_type == NATType::Restricted {
                                whitelist.insert(addr.addr(), ()).await;
                            } else if nat_type == NATType::PortRestricted {
                                whitelist.insert(addr.to_string(), ()).await;
                            }

                            if let Some(ref limiter) = limiter_upload
                                && let Some(nz) = std::num::NonZeroU32::new(payload.len() as u32)
                            {
                                limiter.until_n_ready(nz).await.ok();
                            };
                            info!("Udp connect to {}", addr);
                            if let Err(e) = sock_send
                                .send_to(&payload, (addr.addr(), addr.port()))
                                .await
                            {
                                error!("Write udp to target error: {:?}", e);
                                break;
                            };
                            stat_map_upload.update_upload(key_sig, payload.len());
                        }
                        Err(_) => break,
                    }
                }
                shutdown_tx_2.notify_waiters();
            });

            // 等待任意一个方向结束
            let _ = tokio::join!(inbound_task, outbound_task);
        }
    }

    // 函数结束时，_guard 被销毁，自动调用 leave_ip
    Ok(())
}
