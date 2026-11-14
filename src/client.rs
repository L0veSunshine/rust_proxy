use crate::api::client::{add_download, add_upload};
use crate::connection_pool::ConnectionPool;
use crate::protocol::http;
use crate::protocol::message::{
    Command, Response, client_hello, client_hello_with_payload, encode_udp_frame,
    read_response_from_server, read_udp_frame,
};
use crate::protocol::net_addr::NetAddr;
use crate::protocol::socks5;
use crate::protocol::utils::{bind_dual_stack_udp, configure_tcp_stream, get_canonical_ip};
use crate::relay::{
    DEFAULT_RELAY_IDLE_TIMEOUT, relay_bidirectional, relay_one_way_tracked, write_and_flush,
};
use crate::secret::tls;
use crate::secret::totp::generate_totp_uuid;
use crate::server::UDP_BUFFER_SIZE;
use anyhow::{Result, bail};
use rustls::pki_types::ServerName;
use socket2::SockRef;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// accept 出错后的退避时间，避免空转
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);
/// 本地应用发起 SOCKS5 / HTTP 代理握手的超时上限，防止半开连接泄漏任务
const LOCAL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// 客户端连接代理服务端（含 TCP + TLS 握手）的超时上限
const SERVER_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 等待服务端返回 `Server Response` 的超时上限（需覆盖服务端目标建连时限 + 跨网 RTT）
const SERVER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);
/// 关闭写端时的超时上限
const LOCAL_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
/// 客户端默认最大并发代理连接数
const DEFAULT_CLIENT_MAX_CONNECTIONS: usize = 4096;

type TlsReader = ReadHalf<TlsStream<TcpStream>>;
type TlsWriter = WriteHalf<TlsStream<TcpStream>>;

/// 客户端运行选项
#[derive(Debug, Clone, Copy)]
pub struct ClientOptions {
    /// 是否启用真正的 0-RTT 转发（默认开启）：
    /// - `true`：向本地应用立即回复连接就绪，并立刻在首个往返内并发发送 `Client Hello` 与应用首包，
    ///   服务端响应在下行流首部异步校验；
    /// - `false`：等待服务端真正连上目标并返回状态码后，再向本地应用回复成功或精确的 SOCKS5/HTTP 错误码。
    pub zero_rtt: bool,
    /// 本地最大并发连接数（0 表示无限制）
    pub max_connections: usize,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            zero_rtt: true,
            max_connections: DEFAULT_CLIENT_MAX_CONNECTIONS,
        }
    }
}

pub async fn run(
    listen: String,
    server: String,
    ca_path: String,
    shared_key: Uuid,
    options: ClientOptions,
) -> Result<()> {
    let connector = Arc::new(tls::create_client_config(&ca_path)?);
    let listener = TcpListener::bind(&listen).await?;
    println!("Client listening on {}", listen);
    serve(listener, server, connector, shared_key, options).await
}

/// 在已绑定的本地监听器上按指定选项接受 SOCKS5 / HTTP 代理请求
pub async fn serve(
    listener: TcpListener,
    server: String,
    connector: Arc<TlsConnector>,
    shared_key: Uuid,
    options: ClientOptions,
) -> Result<()> {
    let server = Arc::new(server);
    let pool = ConnectionPool::new(options.max_connections);
    loop {
        let socket = match listener.accept().await {
            Ok((socket, _)) => socket,
            Err(e) => {
                error!("Client accept error: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        let permit = match pool.try_acquire() {
            Ok(permit) => permit,
            Err(e) => {
                warn!("Client connection pool full, rejecting local socket: {}", e);
                let _ = SockRef::from(&socket).set_linger(Some(Duration::ZERO));
                continue;
            }
        };
        // 单个 socket 设置失败只影响这条连接，不能让整个客户端退出
        if let Err(e) = configure_tcp_stream(&socket) {
            warn!("Failed to set socket options: {}", e);
            continue;
        }
        let server = server.clone();
        let connector = connector.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(e) = handle_conn(socket, &server, &connector, shared_key, options).await {
                error!("Client Error: {}", e);
            };
        });
    }
}

pub async fn read_server_status<R: AsyncRead + Unpin>(tls_r: &mut R) -> Result<Response> {
    let resp = read_response_from_server(tls_r).await?;
    Ok(Response::try_from(resp)?)
}

pub async fn handle_response<R: AsyncRead + Unpin>(tls_r: &mut R) -> Result<()> {
    match read_server_status(tls_r).await? {
        Response::Success => Ok(()),
        status => bail!("build connect failed: {:?}", status),
    }
}

fn socks5_reply_from_response(status: Response) -> u8 {
    match status {
        Response::Success => socks5::REPLY_SUCCEEDED,
        Response::ConnectionRefused => socks5::REPLY_CONNECTION_REFUSED,
        Response::HostUnreachable | Response::TimedOut => socks5::REPLY_HOST_UNREACHABLE,
        Response::Rejected => socks5::REPLY_GENERAL_FAILURE,
    }
}

async fn handle_conn(
    local: TcpStream,
    server: &str,
    connector: &TlsConnector,
    shared_key: Uuid,
    options: ClientOptions,
) -> Result<()> {
    // 检测协议类型：peek 第一个字节（受握手超时约束）
    // SOCKS5 版本号固定为 0x05；HTTP 方法以 ASCII 字母开头 (G, P, C, D, H, O, T 等)
    let mut buf = [0u8; 1];
    let n = timeout(LOCAL_HANDSHAKE_TIMEOUT, local.peek(&mut buf)).await??;
    if n == 0 {
        return Ok(());
    }

    if buf[0] == 0x05 {
        handle_socks5_proxy(local, server, connector, shared_key, options).await
    } else {
        handle_http_proxy(local, server, connector, shared_key, options).await
    }
}

/// 连接代理服务端并完成 TLS 握手（带连接超时与 TCP 参数优化）
async fn connect_server(server: &str, connector: &TlsConnector) -> Result<(TlsReader, TlsWriter)> {
    let tls_stream = timeout(SERVER_CONNECT_TIMEOUT, async {
        let remote = TcpStream::connect(server).await?;
        let _ = configure_tcp_stream(&remote);
        let domain = ServerName::try_from("localhost")?;
        let stream = connector.connect(domain, remote).await?;
        Ok::<_, anyhow::Error>(stream)
    })
    .await??;
    Ok(tokio::io::split(tls_stream))
}

/// 本地 TCP 与 TLS 隧道之间的双向转发（用于已完成服务端响应校验的场景）
async fn relay_tcp(local: TcpStream, tls_r: TlsReader, tls_w: TlsWriter) {
    let (local_r, local_w) = local.into_split();
    let cancel = CancellationToken::new();
    relay_bidirectional(
        local_r,
        local_w,
        tls_r,
        tls_w,
        None,
        &cancel,
        add_upload,
        add_download,
    )
    .await;
}

/// 真正的 0-RTT TCP 隧道转发：
/// - 上行方向不等服务端回包，立即读取本地应用首包并写入 TLS 隧道；
/// - 下行方向先读取并校验服务端 `Server Response`：
///   - 若返回 `Success`，无缝进入下行流转发；
///   - 若返回错误状态码或超时，在普通 HTTP 场景下向本地补发 `502/504`，随后立即取消上行并关闭本地连接。
async fn relay_tcp_0rtt(
    local: TcpStream,
    mut tls_r: TlsReader,
    tls_w: TlsWriter,
    plain_http_error_fallback: bool,
) -> Result<()> {
    let (local_r, mut local_w) = local.into_split();
    let cancel = CancellationToken::new();
    let done = CancellationToken::new();
    let epoch = Instant::now();
    let last_active_ms = AtomicU64::new(0);

    let uplink = relay_one_way_tracked(
        local_r,
        tls_w,
        None,
        &cancel,
        Some((&epoch, &last_active_ms)),
        add_upload,
        "upload",
    );

    let downlink = async {
        let status_result = cancel
            .run_until_cancelled(timeout(
                SERVER_RESPONSE_TIMEOUT,
                read_server_status(&mut tls_r),
            ))
            .await;

        match status_result {
            Some(Ok(Ok(Response::Success))) => {
                last_active_ms.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
                relay_one_way_tracked(
                    tls_r,
                    local_w,
                    None,
                    &cancel,
                    Some((&epoch, &last_active_ms)),
                    add_download,
                    "download",
                )
                .await;
            }
            Some(Ok(Ok(status))) => {
                warn!("Server reported target connect failure: {:?}", status);
                if plain_http_error_fallback {
                    let (code, msg) = if status == Response::TimedOut {
                        (504, "Gateway Timeout")
                    } else {
                        (502, "Bad Gateway")
                    };
                    let _ = http::send_error(&mut local_w, code, msg).await;
                }
                cancel.cancel();
                let _ = timeout(LOCAL_SHUTDOWN_TIMEOUT, local_w.shutdown()).await;
            }
            Some(Ok(Err(e))) => {
                warn!("Failed to read server response: {}", e);
                if plain_http_error_fallback {
                    let _ = http::send_error(&mut local_w, 502, "Bad Gateway").await;
                }
                cancel.cancel();
                let _ = timeout(LOCAL_SHUTDOWN_TIMEOUT, local_w.shutdown()).await;
            }
            Some(Err(_)) => {
                warn!("Timed out waiting for server response");
                if plain_http_error_fallback {
                    let _ = http::send_error(&mut local_w, 504, "Gateway Timeout").await;
                }
                cancel.cancel();
                let _ = timeout(LOCAL_SHUTDOWN_TIMEOUT, local_w.shutdown()).await;
            }
            None => {
                let _ = timeout(LOCAL_SHUTDOWN_TIMEOUT, local_w.shutdown()).await;
            }
        }
    };

    let watchdog = async {
        let idle_ms = DEFAULT_RELAY_IDLE_TIMEOUT.as_millis().max(1) as u64;
        loop {
            let now_ms = epoch.elapsed().as_millis() as u64;
            let silent_ms = now_ms.saturating_sub(last_active_ms.load(Ordering::Relaxed));
            if silent_ms >= idle_ms {
                debug!("Client 0-RTT relay idle timeout reached, closing tunnel");
                cancel.cancel();
                break;
            }
            let wait = Duration::from_millis(idle_ms - silent_ms);
            if done
                .run_until_cancelled(tokio::time::sleep(wait))
                .await
                .is_none()
            {
                break;
            }
        }
    };

    let transfer = async {
        tokio::join!(uplink, downlink);
        done.cancel();
    };
    tokio::join!(transfer, watchdog);
    Ok(())
}

/// 处理 HTTP 代理请求
async fn handle_http_proxy(
    mut local: TcpStream,
    server: &str,
    connector: &TlsConnector,
    shared_key: Uuid,
    options: ClientOptions,
) -> Result<()> {
    let req = timeout(LOCAL_HANDSHAKE_TIMEOUT, http::handshake(&mut local)).await??;
    let (mut tls_r, mut tls_w) = match connect_server(server, connector).await {
        Ok(pair) => pair,
        Err(e) => {
            let _ = http::send_error(&mut local, 502, "Bad Gateway").await;
            return Err(e);
        }
    };
    let dynamic_uuid = generate_totp_uuid(shared_key.as_bytes());

    let (target_addr, initial_data, is_connect) = match req {
        http::HttpRequest::Connect(addr, early_data) => {
            info!("HTTPS connect to: {}", addr);
            (addr, early_data, true)
        }
        http::HttpRequest::Http(addr, data) => {
            info!("HTTP connect to: {}", addr);
            (addr, data, false)
        }
    };

    if options.zero_rtt {
        // 真 0-RTT：
        // - CONNECT 先向本地回 200，让浏览器立刻发出 TLS ClientHello；
        // - Client Hello 与已知首包一次性拼包写出，并立即启动上行转发，无需干等服务端响应。
        if is_connect {
            http::send_connect_success(&mut local).await?;
        }
        client_hello_with_payload(
            &mut tls_w,
            &dynamic_uuid,
            &Command::TcpConnect,
            &target_addr,
            &initial_data,
        )
        .await?;
        if !initial_data.is_empty() {
            add_upload(initial_data.len());
        }
        relay_tcp_0rtt(local, tls_r, tls_w, !is_connect).await?;
        return Ok(());
    }

    // 严格确认模式：等待服务端真正连上目标后再向本地回复 200 或 502/504
    client_hello(
        &mut tls_w,
        &dynamic_uuid,
        &Command::TcpConnect,
        &target_addr,
    )
    .await?;
    match timeout(SERVER_RESPONSE_TIMEOUT, read_server_status(&mut tls_r)).await {
        Ok(Ok(Response::Success)) => {}
        Ok(Ok(Response::TimedOut)) | Err(_) => {
            let _ = http::send_error(&mut local, 504, "Gateway Timeout").await;
            bail!("target connect timed out on server");
        }
        Ok(Ok(status)) => {
            let _ = http::send_error(&mut local, 502, "Bad Gateway").await;
            bail!("server rejected connect to {}: {:?}", target_addr, status);
        }
        Ok(Err(e)) => {
            let _ = http::send_error(&mut local, 502, "Bad Gateway").await;
            return Err(e);
        }
    }

    if is_connect {
        http::send_connect_success(&mut local).await?;
    }
    if !initial_data.is_empty() {
        write_and_flush(&mut tls_w, &initial_data).await?;
        add_upload(initial_data.len());
    }

    relay_tcp(local, tls_r, tls_w).await;
    Ok(())
}

/// 处理 SOCKS5 代理请求
async fn handle_socks5_proxy(
    mut local: TcpStream,
    server: &str,
    connector: &TlsConnector,
    shared_key: Uuid,
    options: ClientOptions,
) -> Result<()> {
    let req = timeout(LOCAL_HANDSHAKE_TIMEOUT, socks5::handshake(&mut local)).await??;
    let unspecified = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
    let (mut tls_r, mut tls_w) = match connect_server(server, connector).await {
        Ok(pair) => pair,
        Err(e) => {
            let _ = socks5::send_reply_with_code(
                &mut local,
                socks5::REPLY_GENERAL_FAILURE,
                unspecified,
            )
            .await;
            return Err(e);
        }
    };
    let dynamic_uuid = generate_totp_uuid(shared_key.as_bytes());

    match req {
        socks5::SocksRequest::Tcp(target_addr) => {
            info!("SOCK5 Tcp connect to {}", target_addr);
            if options.zero_rtt {
                // 真 0-RTT：立即回复本地应用成功，让应用首包与 Client Hello 在同一轮跨网飞行中发出
                socks5::send_reply(&mut local, unspecified).await?;
                client_hello(
                    &mut tls_w,
                    &dynamic_uuid,
                    &Command::TcpConnect,
                    &target_addr,
                )
                .await?;
                relay_tcp_0rtt(local, tls_r, tls_w, false).await?;
            } else {
                client_hello(
                    &mut tls_w,
                    &dynamic_uuid,
                    &Command::TcpConnect,
                    &target_addr,
                )
                .await?;
                match timeout(SERVER_RESPONSE_TIMEOUT, read_server_status(&mut tls_r)).await {
                    Ok(Ok(Response::Success)) => {
                        socks5::send_reply(&mut local, unspecified).await?;
                        relay_tcp(local, tls_r, tls_w).await;
                    }
                    Ok(Ok(status)) => {
                        let rep = socks5_reply_from_response(status);
                        let _ = socks5::send_reply_with_code(&mut local, rep, unspecified).await;
                        bail!("server rejected connect to {}: {:?}", target_addr, status);
                    }
                    Ok(Err(e)) => {
                        let _ = socks5::send_reply_with_code(
                            &mut local,
                            socks5::REPLY_GENERAL_FAILURE,
                            unspecified,
                        )
                        .await;
                        return Err(e);
                    }
                    Err(_) => {
                        let _ = socks5::send_reply_with_code(
                            &mut local,
                            socks5::REPLY_HOST_UNREACHABLE,
                            unspecified,
                        )
                        .await;
                        bail!("timed out waiting for server connect response");
                    }
                }
            }
        }

        socks5::SocksRequest::Udp(target_addr) => {
            info!("SOCK5 Udp connect to {}", target_addr);
            let udp = match bind_dual_stack_udp() {
                Ok(udp) => udp,
                Err(e) => {
                    let _ = socks5::send_reply_with_code(
                        &mut local,
                        socks5::REPLY_GENERAL_FAILURE,
                        unspecified,
                    )
                    .await;
                    return Err(e);
                }
            };
            let reply_addr = SocketAddr::new(local.local_addr()?.ip(), udp.local_addr()?.port());

            if options.zero_rtt {
                socks5::send_reply(&mut local, reply_addr).await?;
                client_hello(
                    &mut tls_w,
                    &dynamic_uuid,
                    &Command::UdpAssociate,
                    &target_addr,
                )
                .await?;
                relay_udp(local, udp, tls_r, tls_w, true).await?;
            } else {
                client_hello(
                    &mut tls_w,
                    &dynamic_uuid,
                    &Command::UdpAssociate,
                    &target_addr,
                )
                .await?;
                match timeout(SERVER_RESPONSE_TIMEOUT, read_server_status(&mut tls_r)).await {
                    Ok(Ok(Response::Success)) => {
                        socks5::send_reply(&mut local, reply_addr).await?;
                        relay_udp(local, udp, tls_r, tls_w, false).await?;
                    }
                    Ok(Ok(status)) => {
                        let rep = socks5_reply_from_response(status);
                        let _ = socks5::send_reply_with_code(&mut local, rep, unspecified).await;
                        bail!("server rejected UDP associate: {:?}", status);
                    }
                    Ok(Err(e)) => {
                        let _ = socks5::send_reply_with_code(
                            &mut local,
                            socks5::REPLY_GENERAL_FAILURE,
                            unspecified,
                        )
                        .await;
                        return Err(e);
                    }
                    Err(_) => {
                        let _ = socks5::send_reply_with_code(
                            &mut local,
                            socks5::REPLY_GENERAL_FAILURE,
                            unspecified,
                        )
                        .await;
                        bail!("timed out waiting for server UDP response");
                    }
                }
            }
        }
    }
    Ok(())
}

/// SOCKS5 UDP 关联：本地 UDP <-> TLS 隧道
///
/// - 只接受来自发起 UDP ASSOCIATE 的那个客户端 IP 的数据包，避免成为局域网开放中继
/// - 控制用的 TCP 连接关闭时结束关联 (RFC 1928)
/// - 任意方向结束或长期空闲都会拆除整个关联
async fn relay_udp<R, W>(
    mut control: TcpStream,
    udp: tokio::net::UdpSocket,
    mut tls_r: R,
    mut tls_w: W,
    await_server_response: bool,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let allowed_ip = get_canonical_ip(control.peer_addr()?.ip());
    // 本地应用的来源地址 (IP:Port)：收到它的包就更新，服务端回包发往这里
    let client_src = Mutex::new(None::<SocketAddr>);
    let cancel = CancellationToken::new();
    let done = CancellationToken::new();
    let epoch = Instant::now();
    let last_active_ms = AtomicU64::new(0);

    // 本地 UDP -> TLS
    let uplink = async {
        let mut buf = vec![0u8; UDP_BUFFER_SIZE];
        let mut frame = Vec::with_capacity(UDP_BUFFER_SIZE + 32);
        loop {
            let (n, src_addr) = match udp.recv_from(&mut buf).await {
                Ok(res) => res,
                // Windows 下先前向不可达端口发送 UDP 后，下次 recv_from 会收到 ConnectionReset
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => continue,
                Err(e) => {
                    error!("Client read udp from local error: {}", e);
                    break;
                }
            };
            if get_canonical_ip(src_addr.ip()) != allowed_ip {
                debug!("Drop udp packet from unexpected source {}", src_addr);
                continue;
            }
            last_active_ms.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
            *client_src.lock().unwrap_or_else(|e| e.into_inner()) = Some(src_addr);

            let (addr, offset) = match socks5::parse_udp_packet(&buf[..n]) {
                Ok(res) => res,
                Err(e) => {
                    error!("parse udp packet failed: {}", e);
                    continue;
                }
            };
            frame.clear();
            if let Err(e) = encode_udp_frame(&addr, &buf[offset..n], &mut frame) {
                error!("Failed to build UDP frame: {}", e);
                continue;
            }
            if let Err(e) = write_and_flush(&mut tls_w, &frame).await {
                error!("Client write udp to proxy server error: {}", e);
                break;
            }
            last_active_ms.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
            add_upload(n);
        }
    };

    // TLS -> 本地 UDP
    let downlink = async {
        if await_server_response {
            match timeout(SERVER_RESPONSE_TIMEOUT, read_server_status(&mut tls_r)).await {
                Ok(Ok(Response::Success)) => {
                    last_active_ms.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
                }
                Ok(Ok(status)) => {
                    warn!("Server rejected UDP associate: {:?}", status);
                    return;
                }
                Ok(Err(e)) => {
                    error!("Failed to read server UDP response: {}", e);
                    return;
                }
                Err(_) => {
                    error!("Timed out waiting for server UDP response");
                    return;
                }
            }
        }

        let mut packet = Vec::with_capacity(UDP_BUFFER_SIZE + 32);
        loop {
            let (addr, payload): (NetAddr, _) = match read_udp_frame(&mut tls_r).await {
                Ok(frame) => frame,
                Err(e) => {
                    error!("read udp frame error {}", e);
                    break;
                }
            };
            last_active_ms.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
            let target = *client_src.lock().unwrap_or_else(|e| e.into_inner());
            let Some(dst) = target else {
                continue;
            };
            packet.clear();
            if let Err(e) = socks5::encode_udp_packet(&addr, &payload, &mut packet) {
                error!("Failed to build UDP packet: {}", e);
                continue;
            }
            if let Err(e) = udp.send_to(&packet, dst).await {
                error!("Client write udp to local error: {}", e);
                break;
            }
            last_active_ms.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
            add_download(payload.len());
        }
    };

    // 控制连接：对端关闭或出错即结束关联
    let control_watch = async {
        let mut buf = [0u8; 64];
        while let Ok(n) = control.read(&mut buf).await {
            if n == 0 {
                break;
            }
        }
    };

    let watchdog = async {
        let idle_ms = DEFAULT_RELAY_IDLE_TIMEOUT.as_millis().max(1) as u64;
        loop {
            let now_ms = epoch.elapsed().as_millis() as u64;
            let silent_ms = now_ms.saturating_sub(last_active_ms.load(Ordering::Relaxed));
            if silent_ms >= idle_ms {
                debug!("Client UDP relay idle timeout reached, closing association");
                cancel.cancel();
                break;
            }
            let wait = Duration::from_millis(idle_ms - silent_ms);
            if done
                .run_until_cancelled(tokio::time::sleep(wait))
                .await
                .is_none()
            {
                break;
            }
        }
    };

    let transfer = async {
        tokio::join!(
            async {
                cancel.run_until_cancelled(uplink).await;
                cancel.cancel();
            },
            async {
                cancel.run_until_cancelled(downlink).await;
                cancel.cancel();
            },
            async {
                cancel.run_until_cancelled(control_watch).await;
                cancel.cancel();
            },
        );
        done.cancel();
    };
    tokio::join!(transfer, watchdog);
    Ok(())
}
