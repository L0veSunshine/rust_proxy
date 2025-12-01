use crate::protocol::socks5;
use crate::protocol::utils::{
    Command, NATType, bind_dual_stack_udp, read_packet, write_handshake, write_packet,
};
use crate::tls;
use anyhow::Result;
use bytes::Bytes;
use rustls::pki_types::ServerName;
use socket2::{SockRef, TcpKeepalive};
use std::convert::TryFrom;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};

pub async fn run(listen: &str, server: &str, nat_type: NATType) -> Result<()> {
    let connector = Arc::new(tls::create_client_config()?);
    let listener = TcpListener::bind(listen).await?;
    let ka = TcpKeepalive::new().with_time(Duration::from_secs(60)); // 空闲60秒后开始探测
    println!("Client listening on {}", listen);

    loop {
        let (socket, _) = listener.accept().await?;
        let native_socket = SockRef::from(&socket);
        native_socket.set_tcp_nodelay(true)?;
        native_socket.set_tcp_keepalive(&ka)?;
        let server = server.to_string();
        let connector = connector.clone();
        tokio::spawn(async move {
            let _ = handle_conn(socket, server, connector, nat_type).await;
        });
    }
}

async fn handle_conn(
    mut local: TcpStream,
    server: String,
    connector: Arc<tokio_rustls::TlsConnector>,
    nat_type: NATType,
) -> Result<()> {
    // SOCKS5 握手
    let req = socks5::handshake(&mut local).await?;

    // 连接 TLS 服务端
    let remote = TcpStream::connect(&server).await?;
    let domain = ServerName::try_from("localhost")?;
    let tls_stream = connector.connect(domain, remote).await?;

    // let (tx, mut rx) = mpsc::channel::<Command>(100);
    let (mut tls_r, mut tls_w) = tokio::io::split(tls_stream);

    match req {
        socks5::SocksRequest::Tcp(target_addr) => {
            // 发送带 Padding 和 Auth 的握手
            write_handshake(&mut tls_w, &Command::Connect { addr: target_addr }).await?;
            let loop_back_addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
            socks5::send_reply(&mut local, loop_back_addr).await?;

            let (mut local_r, mut local_w) = local.into_split();

            // 本地 -> 代理
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                loop {
                    let n = local_r.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    // 使用 Bytes 避免这里再次拷贝
                    let cmd = Command::Data {
                        payload: Bytes::copy_from_slice(&buf[..n]),
                    };
                    if write_packet(&mut tls_w, &cmd).await.is_err() {
                        break;
                    }
                }
            });

            // 代理 -> 本地
            while let Ok(Command::Data { payload }) = read_packet(&mut tls_r).await {
                if local_w.write_all(&payload).await.is_err() {
                    break;
                };
            }
        }
        socks5::SocksRequest::Udp => {
            // 发送 UDP Associate 握手
            write_handshake(&mut tls_w, &Command::UdpAssociate { nat_type }).await?;

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

            // 通道：UDP Recv Loop -> TLS Writer Loop
            let (net_tx, mut net_rx) = mpsc::channel::<Command>(256);

            // --- 任务 A: 将 Channel 中的 UDP 请求写入 TLS ---
            tokio::spawn(async move {
                while let Some(cmd) = net_rx.recv().await {
                    if write_packet(&mut tls_w, &cmd).await.is_err() {
                        break;
                    };
                }
            });

            let udp_recv = udp.clone();
            let client_src_recorder = client_src.clone();

            // --- 任务 B: 接收本地 UDP 数据 -> 转发给 Channel ---
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                while let Ok((n, src)) = udp_recv.recv_from(&mut buf).await {
                    {
                        let mut guard = client_src_recorder.lock().await;
                        if guard.as_ref() != Some(&src) {
                            *guard = Some(src);
                        }
                    }

                    if let Ok((target, port, cursor)) = socks5::parse_udp_packet(&buf[..n]) {
                        let cmd = Command::UdpData {
                            addr: target,
                            port,
                            payload: Bytes::copy_from_slice(&buf[cursor..n]),
                        };
                        if net_tx.send(cmd).await.is_err() {
                            break;
                        }
                    };
                }
            });

            // --- 任务 C (主线程): 接收 TLS 数据 -> 转发回本地 UDP ---
            let udp_send = udp.clone();
            tokio::spawn(async move {
                while let Ok(Command::UdpData {
                    addr,
                    port,
                    payload,
                }) = read_packet(&mut tls_r).await
                {
                    // 取出目标地址
                    let target = { *client_src.lock().await };
                    if let Some(src) = target {
                        match socks5::build_udp_packet(&addr, port, &payload) {
                            Ok(packet) => {
                                if udp_send.send_to(&packet, src).await.is_err() {
                                    break;
                                }
                            }
                            Err(e) => {
                                eprintln!("Failed to build UDP packet: {}", e);
                            }
                        }
                    } else {
                        eprintln!("Dropping packet, no client known yet");
                    }
                }
            });
        }
    }
    Ok(())
}
