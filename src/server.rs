use crate::protocol::utils::{Command, read_handshake, read_packet, write_packet};
use crate::tls;
use anyhow::Result;
use bytes::Bytes;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

pub async fn run(listen: &str) -> Result<()> {
    let acceptor = Arc::new(tls::create_server_config("cert.pem", "key.pem")?);
    let listener = TcpListener::bind(listen).await?;
    println!("Server listening on {}", listen);

    loop {
        let (socket, _) = listener.accept().await?;
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_client(socket, acceptor).await {
                eprintln!("Error: {}", e);
            }
        });
    }
}

async fn handle_client(socket: TcpStream, acceptor: Arc<TlsAcceptor>) -> Result<()> {
    let mut stream = acceptor.accept(socket).await?;

    // 1. 读取握手包 (UUID Auth + Padding Skip)
    let cmd = read_handshake(&mut stream).await?;

    let (mut client_reader, mut client_writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<Command>(100);

    match cmd {
        // === TCP 模式 ===
        Command::Connect { addr } => {
            let target = TcpStream::connect(&addr).await?;
            let (mut target_r, mut target_w) = target.into_split();

            // 目标 -> 代理 -> 客户端
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    let n = target_r.read(&mut buf).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    let cmd = Command::Data {
                        payload: Bytes::copy_from_slice(&buf[..n]),
                    };
                    if tx_clone.send(cmd).await.is_err() {
                        break;
                    }
                }
            });

            // 客户端 -> 代理 -> 目标
            tokio::spawn(async move {
                while let Ok(Command::Data { payload }) = read_packet(&mut client_reader).await {
                    target_w.write_all(&payload).await.ok();
                }
            });
        }

        // === UDP 模式 (Full Cone) ===
        Command::UdpAssociate => {
            let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

            // 外部 -> 代理 -> 客户端
            let tx_clone = tx.clone();
            let sock_recv = socket.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65535];
                while let Ok((n, addr)) = sock_recv.recv_from(&mut buf).await {
                    let cmd = Command::UdpData {
                        addr: addr.to_string(),
                        payload: Bytes::copy_from_slice(&buf[..n]),
                    };
                    let _ = tx_clone.send(cmd).await;
                }
            });

            // 客户端 -> 代理 -> 外部
            let sock_send = socket.clone();
            tokio::spawn(async move {
                while let Ok(Command::UdpData { addr, payload }) =
                    read_packet(&mut client_reader).await
                {
                    sock_send.send_to(&payload, &addr).await.ok();
                }
            });
        }
        _ => return Ok(()),
    }

    // 主循环：负责把 channel 里的数据写回给 TLS 客户端
    while let Some(cmd) = rx.recv().await {
        write_packet(&mut client_writer, &cmd).await?;
    }

    Ok(())
}
