use crate::api::client::{add_download, add_upload};
use crate::protocol::http;
use crate::protocol::message::{
    Command, Response, build_udp_frame, client_hello, read_response_from_server, read_udp_frame,
};
use crate::protocol::socks5;
use crate::protocol::socks5::build_udp_packet;
use crate::protocol::utils::bind_dual_stack_udp;
use crate::secret::tls;
use crate::secret::totp::generate_totp_uuid;
use anyhow::{Result, bail};
use rustls::pki_types::ServerName;
use socket2::{SockRef, TcpKeepalive};
use std::convert::TryFrom;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{Mutex, Notify};
use tracing::{error, info};
use uuid::Uuid;

pub async fn run(listen: String, server: String, ca_path: String, shared_key: Uuid) -> Result<()> {
    let connector = Arc::new(tls::create_client_config(&ca_path)?);
    let listener = TcpListener::bind(&listen).await?;
    let ka = TcpKeepalive::new().with_time(Duration::from_secs(60)); // 空闲60秒后开始探测
    println!("Client listening on {}", listen);

    let server = Arc::new(server);
    loop {
        let (socket, _) = listener.accept().await?;
        let native_socket = SockRef::from(&socket);
        native_socket.set_tcp_nodelay(true)?;
        native_socket.set_tcp_keepalive(&ka)?;
        let server_cloned = server.clone();
        let connector = connector.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(socket, server_cloned, connector, shared_key).await {
                error!("Client Error: {}", e);
            };
        });
    }
}

pub async fn handle_response<R: AsyncRead + Unpin>(tls_r: &mut R) -> Result<()> {
    let resp = read_response_from_server(tls_r).await?;
    if let Ok(resp) = Response::try_from(resp)
        && resp == Response::Success
    {
        info!("build connect succeed");
        return Ok(());
    }
    info!("build connect failed");
    bail!("build connect failed");
}

async fn handle_conn(
    local: TcpStream,
    server: Arc<String>,
    connector: Arc<tokio_rustls::TlsConnector>,
    sharked_key: Uuid,
) -> Result<()> {
    // 检测协议类型：peek 第一个字节
    // SOCKS5: 0x05
    // HTTP CONNECT: 'C' (0x43)
    let mut buf = [0u8; 1];
    local.peek(&mut buf).await?;

    let first_byte = buf[0];

    // 判断是 SOCKS5 还是 HTTP 代理
    let is_http = first_byte == b'C'; // 'C' for CONNECT

    if is_http {
        // HTTP 代理处理
        handle_http_proxy(local, server, connector, sharked_key).await
    } else {
        // SOCKS5 代理处理
        handle_socks5_proxy(local, server, connector, sharked_key).await
    }
}

/// 双向数据中继:在两个流之间双向转发数据
fn relay_bidirectional<R, W>(
    mut reader: R,
    mut writer: W,
    shutdown_tx: Arc<Notify>,
    shutdown_rx: Arc<Notify>,
    add_metrics: fn(usize),
    direction: &'static str,
) -> tokio::task::JoinHandle<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWriteExt + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        loop {
            let n = select! {
                _ = shutdown_rx.notified() => 0,
                res = reader.read(&mut buf) => {
                    match res {
                        Ok(0) => break,
                        Ok(n) => n,
                        Err(e) => {
                            error!("Client read from {} error: {}", direction, e);
                            break;
                        }
                    }
                },
            };
            if n == 0 {
                break;
            }
            if let Err(e) = writer.write_all(&buf[..n]).await {
                error!("Client write to {} error: {}", direction, e);
                break;
            }
            add_metrics(n);
        }
        shutdown_tx.notify_waiters();
        let _ = writer.shutdown().await;
    })
}

/// 处理 HTTP 代理请求
async fn handle_http_proxy(
    mut local: TcpStream,
    server: Arc<String>,
    connector: Arc<tokio_rustls::TlsConnector>,
    sharked_key: Uuid,
) -> Result<()> {
    // HTTP 握手
    let req = http::handshake(&mut local).await?;

    // 连接 TLS 服务端
    let remote = TcpStream::connect(&*server).await?;
    let domain = ServerName::try_from("localhost")?;
    let tls_stream = connector.connect(domain, remote).await?;

    let (mut tls_r, mut tls_w) = tokio::io::split(tls_stream);
    let dynamic_uuid = generate_totp_uuid(sharked_key.as_bytes());

    match req {
        http::HttpRequest::Connect(target_addr) => {
            // 发送带 Padding 和 Auth 的握手
            client_hello(
                &mut tls_w,
                &dynamic_uuid,
                &Command::TcpConnect,
                &target_addr,
            )
            .await?;

            // 0-RTT
            handle_response(&mut tls_r).await?;

            // 发送 HTTP 200 Connection Established 响应
            http::send_connect_success(&mut local).await?;

            let (local_r, local_w) = local.into_split();

            let shutdown = Arc::new(Notify::new());
            let shutdown_tx_local = shutdown.clone();
            let shutdown_rx_local = shutdown.clone();
            let shutdown_tx_remote = shutdown.clone();
            let shutdown_rx_remote = shutdown.clone();

            // 本地 -> 代理
            let handle_upload = relay_bidirectional(
                local_r,
                tls_w,
                shutdown_tx_local,
                shutdown_rx_local,
                add_upload,
                "local",
            );

            // 代理 -> 本地
            let handle_download = relay_bidirectional(
                tls_r,
                local_w,
                shutdown_tx_remote,
                shutdown_rx_remote,
                add_download,
                "server",
            );

            // 等待两个方向的 relay 都完成
            let _ = tokio::join!(handle_upload, handle_download);
        }
    }
    Ok(())
}

/// 处理 SOCKS5 代理请求
async fn handle_socks5_proxy(
    mut local: TcpStream,
    server: Arc<String>,
    connector: Arc<tokio_rustls::TlsConnector>,
    sharked_key: Uuid,
) -> Result<()> {
    // SOCKS5 握手
    let req = socks5::handshake(&mut local).await?;

    // 连接 TLS 服务端
    let remote = TcpStream::connect(&*server).await?;
    let domain = ServerName::try_from("localhost")?;
    let tls_stream = connector.connect(domain, remote).await?;

    // let (tx, mut rx) = mpsc::channel::<Command>(100);
    let (mut tls_r, mut tls_w) = tokio::io::split(tls_stream);
    let dynamic_uuid = generate_totp_uuid(sharked_key.as_bytes());

    match req {
        socks5::SocksRequest::Tcp(target_addr) => {
            // 发送带 Padding 和 Auth 的握手
            client_hello(
                &mut tls_w,
                &dynamic_uuid,
                &Command::TcpConnect,
                &target_addr,
            )
            .await?;
            let loop_back_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
            socks5::send_reply(&mut local, loop_back_addr).await?;

            let (local_r, local_w) = local.into_split();
            // 0-RTT
            handle_response(&mut tls_r).await?;

            let shutdown = Arc::new(Notify::new());
            let shutdown_tx_local = shutdown.clone();
            let shutdown_rx_local = shutdown.clone();
            let shutdown_tx_remote = shutdown.clone();
            let shutdown_rx_remote = shutdown.clone();

            // 本地 -> 代理
            let handle_upload = relay_bidirectional(
                local_r,
                tls_w,
                shutdown_tx_local,
                shutdown_rx_local,
                add_upload,
                "local",
            );

            // 代理 -> 本地
            let handle_download = relay_bidirectional(
                tls_r,
                local_w,
                shutdown_tx_remote,
                shutdown_rx_remote,
                add_download,
                "server",
            );

            // 等待两个方向的 relay 都完成
            let _ = tokio::join!(handle_upload, handle_download);
        }

        socks5::SocksRequest::Udp(target_addr) => {
            // 发送 UDP Associate 握手
            client_hello(
                &mut tls_w,
                &dynamic_uuid,
                &Command::UdpAssociate,
                &target_addr,
            )
            .await?;

            // 绑定双栈 Socket (实际上绑定了 [::]:0，同时覆盖 IPv4/IPv6)
            let udp = bind_dual_stack_udp()?;
            let local_port = udp.local_addr()?.port();

            // 获取当前 TCP 连接的本地目标 IP
            let local_tcp_addr = local.local_addr()?;

            let reply_addr = SocketAddr::new(local_tcp_addr.ip(), local_port);
            socks5::send_reply(&mut local, reply_addr).await?;

            let udp = Arc::new(udp);

            // 记录本地应用的来源地址 (IP:Port)
            // 只要收到该应用的包，就更新这个地址；收到服务端回包，就发往这个地址
            let client_src = Arc::new(Mutex::new(None::<SocketAddr>));

            // 0-RTT
            handle_response(&mut tls_r).await?;

            let shutdown = Arc::new(Notify::new());
            let shutdown_udp_listener = shutdown.clone();
            let shutdown_main = shutdown.clone();

            let udp_recv = udp.clone();
            // --- 任务 A: 接收本地 UDP 数据 -> 写入 TLS ---
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let result = select! {
                        _ = shutdown_udp_listener.notified() => break,
                        res = udp_recv.recv_from(&mut buf) => res,
                    };
                    if let Ok((n, _)) = result {
                        if n == 0 {
                            break;
                        }

                        if let Ok((addr, cursor)) = socks5::parse_udp_packet(&buf[..n]) {
                            let udp_frame = build_udp_frame(&addr, &buf[cursor..n]);
                            match udp_frame {
                                Ok(frame) => {
                                    if let Err(e) = tls_w.write_all(&frame).await {
                                        error!("Client write udp to proxy server error: {}", e);
                                        break;
                                    }
                                    add_upload(n);
                                }
                                Err(e) => {
                                    error!("Failed to build UDP frame: {}", e);
                                }
                            }
                        } else {
                            error!("parse udp packet failed");
                        };
                    } else {
                        error!("Client read udp from local error");
                        break; // UDP 读取错误
                    }
                }
                shutdown_udp_listener.notify_waiters();
            });

            // --- 任务 B (主线程): 接收 TLS 数据 -> 转发回本地 UDP ---
            let udp_send = udp.clone();

            loop {
                select! {
                    _ = shutdown_main.notified() => break,
                    res = read_udp_frame(&mut tls_r) => {
                        match res {
                            Ok((addr,payload)) => {
                                let target = { *client_src.lock().await };
                                if let Some(src) = target {
                                    match build_udp_packet(&addr, &payload) {
                                        Ok(packet) => {
                                            if let Err(e) = udp_send.send_to(&packet, src).await{
                                                error!("Client write udp to local error: {}", e);
                                                break;
                                            }
                                            add_download(payload.len());
                                        }
                                        Err(e) => {
                                            error!("Failed to build UDP packet: {}", e);
                                            break;
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!("read udp frame error {}", e);
                                break;
                            }
                        }
                    }
                }
            }
            // 错误或连接关闭，通知其他任务退出
            shutdown_main.notify_waiters();
        }
    }
    Ok(())
}
