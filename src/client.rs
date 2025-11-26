use crate::protocol::socks5;
use crate::protocol::utils::{Command, read_packet, write_handshake, write_packet};
use crate::tls;
use anyhow::Result;
use bytes::Bytes;
use rustls::pki_types::ServerName;
use socket2::{SockRef, TcpKeepalive};
use std::convert::TryFrom;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

pub async fn run(listen: &str, server: &str) -> Result<()> {
    let connector = Arc::new(tls::create_client_config()?);
    let listener = TcpListener::bind(listen).await?;
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(60)) // 空闲60秒后开始探测
        .with_interval(Duration::from_secs(10)) // 探测失败后每10秒重试
        .with_retries(3); // 重试3次失败则断开
    println!("Client listening on {}", listen);

    loop {
        let (socket, _) = listener.accept().await?;
        let native_socket = SockRef::from(&socket);
        native_socket.set_tcp_nodelay(true)?;
        native_socket.set_tcp_keepalive(&ka)?;
        let server = server.to_string();
        let connector = connector.clone();
        tokio::spawn(async move {
            let _ = handle_conn(socket, server, connector).await;
        });
    }
}

async fn handle_conn(
    mut local: TcpStream,
    server: String,
    connector: Arc<tokio_rustls::TlsConnector>,
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
            socks5::send_reply(&mut local, "0.0.0.0:0".parse().unwrap()).await?;

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
            tokio::spawn(async move {
                while let Ok(Command::Data { payload }) = read_packet(&mut tls_r).await {
                    let _ = local_w.write_all(&payload).await;
                }
            });
        }
        socks5::SocksRequest::Udp => {
            // 发送 UDP Associate 握手
            write_handshake(&mut tls_w, &Command::UdpAssociate).await?;

            // 绑定本地 UDP
            let udp = UdpSocket::bind("127.0.0.1:0").await?;
            socks5::send_reply(&mut local, udp.local_addr()?).await?;
            let udp = Arc::new(udp);

            // 本地 UDP -> 代理
            let udp_recv = udp.clone();
            let mut tls_w_clone = tls_w; // 这里的 clone 需要 TlsStream 支持 split 后的引用，简化起见直接 move
            // 注意：为了同时读写 TLS，通常需要 MPSC。这里简化为直接在 UDP 循环里写 TLS
            // 但因为 TLS split 的 WriteHalf 不易 clone，我们用 Channel 控制写入

            // 修正：我们需要一个统一的 Writer Loop
            let (net_tx, mut net_rx) = mpsc::channel::<Command>(100);

            tokio::spawn(async move {
                while let Some(cmd) = net_rx.recv().await {
                    let _ = write_packet(&mut tls_w_clone, &cmd).await;
                }
            });

            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                while let Ok((n, _src)) = udp_recv.recv_from(&mut buf).await {
                    if let Ok((target, payload)) = socks5::parse_udp_packet(&buf[..n]) {
                        let cmd = Command::UdpData {
                            addr: target,
                            payload: Bytes::copy_from_slice(&payload),
                        };
                        let _ = net_tx.send(cmd).await;
                    };
                }
            });

            // 代理 -> 本地 UDP
            tokio::spawn(async move {
                while let Ok(Command::UdpData { addr: _, payload }) = read_packet(&mut tls_r).await
                {
                    let _ = udp.send_to(&payload, "127.0.0.1:1234").await;
                }
            });
        }
    }
    Ok(())
}
