use crate::protocol::utils::{Command, read_handshake, read_packet, write_packet};
use crate::tls;
use anyhow::Result;
use bytes::Bytes;
use socket2::{Domain, SockRef, Socket, TcpKeepalive, Type};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;

pub async fn run(port: u16) -> Result<()> {
    let acceptor = Arc::new(tls::create_server_config("cert.pem", "key.pem")?);
    // 1. 创建 IPv6 Socket
    let socket = Socket::new(Domain::IPV6, Type::STREAM, None)?;
    // 2. 关闭 IPV6_V6ONLY，允许 IPv4 映射到这个 IPv6 Socket
    // 这样绑定 [::] 也就同时绑定了 0.0.0.0
    socket.set_only_v6(false)?;
    // 3. 设置端口复用 (防止重启报错)
    socket.set_reuse_address(true)?;
    // 4. 设置为非阻塞，适配 Tokio
    socket.set_nonblocking(true)?;
    // 5. 绑定到 [::]:port (同时覆盖 IPv4 和 IPv6)
    let addr = std::net::SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let listener = TcpListener::from_std(socket.into())?;
    let ka = TcpKeepalive::new()
        .with_time(Duration::from_secs(60)) // 空闲60秒后开始探测
        .with_interval(Duration::from_secs(10)) // 探测失败后每10秒重试
        .with_retries(3); // 重试3次失败则断开
    println!("Server listening on [::]:{}", port);

    loop {
        let (socket, _) = listener.accept().await?;
        let native_socket = SockRef::from(&socket);
        native_socket.set_tcp_nodelay(true)?;
        native_socket.set_tcp_keepalive(&ka)?;
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
