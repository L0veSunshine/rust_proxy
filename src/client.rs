use crate::protocol::message::{
    Command, Response, build_udp_frame, client_hello, read_response_from_server, read_udp_frame,
};
use crate::protocol::socks5;
use crate::protocol::socks5::build_udp_packet;
use crate::protocol::utils::bind_dual_stack_udp;
use crate::secret::totp::generate_totp_uuid;
use crate::tls;
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

pub async fn run(listen: &str, server: &str, shared_key: &str) -> Result<()> {
    let connector = Arc::new(tls::create_client_config("cert.pem")?);
    let listener = TcpListener::bind(listen).await?;
    let ka = TcpKeepalive::new().with_time(Duration::from_secs(60)); // 空闲60秒后开始探测
    println!("Client listening on {}", listen);

    let server = Arc::new(String::from(server));
    let shared_key = Arc::new(String::from(shared_key));
    loop {
        let (socket, _) = listener.accept().await?;
        let native_socket = SockRef::from(&socket);
        native_socket.set_tcp_nodelay(true)?;
        native_socket.set_tcp_keepalive(&ka)?;
        let server_cloned = server.clone();
        let shared_key_cloned = shared_key.clone();
        let connector = connector.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(socket, server_cloned, connector, shared_key_cloned).await {
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
    mut local: TcpStream,
    server: Arc<String>,
    connector: Arc<tokio_rustls::TlsConnector>,
    sharked_key: Arc<String>,
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

            let (mut local_r, mut local_w) = local.into_split();
            // 0-RTT
            handle_response(&mut tls_r).await?;

            let shutdown = Arc::new(Notify::new());
            let shutdown_tx_local = shutdown.clone();
            let shutdown_rx_local = shutdown.clone();
            let shutdown_tx_remote = shutdown.clone();
            let shutdown_rx_remote = shutdown.clone();

            // 本地 -> 代理
            tokio::spawn(async move {
                let mut local_to_remote_buf = vec![0u8; 8192];
                loop {
                    let n = select! {
                        _ = shutdown_rx_local.notified() => 0,
                        res = local_r.read(&mut local_to_remote_buf) => {
                            match res {
                                Ok(0) => break,
                                Ok(n) => n,
                                Err(e) => {
                                    error!("Client read from local error: {}", e);
                                    break;
                                }
                            }
                        },
                    };
                    if let Err(e) = tls_w.write_all(&local_to_remote_buf[..n]).await {
                        error!("Client write to server error: {}", e);
                        break;
                    }
                }
                shutdown_tx_local.notify_one();
                let _ = tls_w.shutdown().await;
            });
            // 代理 -> 本地
            let mut remote_to_local_buf = vec![0u8; 8192];

            loop {
                let n = select! {
                    _ = shutdown_rx_remote.notified() => break,
                    n = tls_r.read(&mut remote_to_local_buf) => n
                };
                let length = match n {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => {
                        error!("Client read from server error {:}", e);
                        break;
                    }
                };
                if let Err(e) = local_w.write_all(&remote_to_local_buf[..length]).await {
                    error!("Client write tcp to local error: {}", e);
                    break;
                }
            }
            shutdown_tx_remote.notify_one();
            let _ = local_w.shutdown().await;
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
            let client_src_recorder = client_src.clone();

            // --- 任务 A: 接收本地 UDP 数据 -> 写入 TLS ---
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                loop {
                    let result = select! {
                        _ = shutdown_udp_listener.notified() => break,
                        res = udp_recv.recv_from(&mut buf) => res,
                    };
                    if let Ok((n, src)) = result {
                        {
                            let mut guard = client_src_recorder.lock().await;
                            if guard.as_ref() != Some(&src) {
                                *guard = Some(src);
                            }
                        }

                        if let Ok((addr, cursor)) = socks5::parse_udp_packet(&buf[..n]) {
                            let udp_frame = build_udp_frame(&addr, &buf[cursor..n]);
                            match udp_frame {
                                Ok(frame) => {
                                    if let Err(e) = tls_w.write_all(&frame).await {
                                        error!("Client write udp to proxy server error: {}", e);
                                        break;
                                    }
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
                shutdown_udp_listener.notify_one();
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
            shutdown_main.notify_one();
        }
    }
    Ok(())
}
