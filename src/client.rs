use crate::protocol::utils::{read_packet, write_handshake, write_packet, Command};
use crate::protocol::socks5;
use crate::tls;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use anyhow::Result;
use std::sync::Arc;
use std::convert::TryFrom;
use bytes::Bytes;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn run(listen: &str, server: &str) -> Result<()> {
    let connector = Arc::new(tls::create_client_config()?);
    let listener = TcpListener::bind(listen).await?;
    println!("Client listening on {}", listen);

    loop {
        let (socket, _) = listener.accept().await?;
        let server = server.to_string();
        let connector = connector.clone();
        tokio::spawn(async move {
            let _ = handle_conn(socket, server, connector).await;
        });
    }
}

async fn handle_conn(mut local: TcpStream, server: String, connector: Arc<tokio_rustls::TlsConnector>) -> Result<()> {
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
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = local_r.read(&mut buf).await.unwrap_or(0);
                    if n == 0 { break; }
                    // 使用 Bytes 避免这里再次拷贝
                    let cmd = Command::Data { payload: Bytes::copy_from_slice(&buf[..n]) };
                    if write_packet(&mut tls_w, &cmd).await.is_err() { break; }
                }
            });

            // 代理 -> 本地
            loop {
                let pkt = read_packet(&mut tls_r).await;
                if let Ok(Command::Data { payload }) = pkt {
                    local_w.write_all(&payload).await?;
                } else { break; }
            }
        },
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
                    // 解析 SOCKS5 UDP 头，拿到真正的目标地址 (这里简化，假设头占 10 字节)
                    if n > 10 {
                        // 这是一个 Demo，实际需要解析 SOCKS5 头
                        // 假设目标是 8.8.8.8:53
                        let cmd = Command::UdpData {
                            addr: "8.8.8.8:53".to_string(),
                            payload: Bytes::copy_from_slice(&buf[10..n])
                        };
                        let _ = net_tx.send(cmd).await;
                    }
                }
            });

            // 代理 -> 本地 UDP
            loop {
                let pkt = read_packet(&mut tls_r).await;
                if let Ok(Command::UdpData { addr: _, payload }) = pkt {
                    // 封装 SOCKS5 头回传 (省略)
                    udp.send_to(&payload, "127.0.0.1:1234").await.ok();
                } else { break; }
            }
        }
    }
    Ok(())
}