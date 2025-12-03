use crate::protocol::utils::{
    Command, NATType, bind_dual_stack_udp, read_handshake, read_packet, write_packet,
};
use crate::tls;
use anyhow::Result;
use bytes::{Bytes, BytesMut};
use moka::future::Cache;
use socket2::{Domain, Protocol, SockRef, Socket, TcpKeepalive, Type};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::select;
use tokio::sync::{Notify, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::error;

pub const UDP_BUFFER_SIZE: usize = 65535;
pub async fn run(port: u16) -> Result<()> {
    let acceptor = Arc::new(tls::create_server_config("cert.pem", "key.pem")?);
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
                error!("Server Error: {}", e);
            }
        });
    }
}

async fn handle_client(socket: TcpStream, acceptor: Arc<TlsAcceptor>) -> Result<()> {
    let mut stream = acceptor.accept(socket).await?;

    let cancel_token = CancellationToken::new();
    let tcp_cancel_token = cancel_token.clone();
    let udp_cancel_token = cancel_token.clone();
    // 读取握手包 (UUID Auth + Padding Skip)
    let cmd = read_handshake(&mut stream).await?;

    let (mut client_reader, mut client_writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<Command>(256);

    match cmd {
        // === TCP 模式 ===
        Command::Connect { addr } => {
            let target = TcpStream::connect(&addr).await?;
            let (mut target_r, mut target_w) = target.into_split();

            // 创建停机信号
            let shutdown_tcp = Arc::new(Notify::new());
            let shutdown_tcp_rx_local = shutdown_tcp.clone();
            let shutdown_tcp_rx_remote = shutdown_tcp.clone();
            let shutdown_tcp_tx_local = shutdown_tcp.clone();
            let shutdown_tcp_tx_remote = shutdown_tcp.clone();

            // 目标 -> 代理 -> 客户端
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                loop {
                    select! {
                        _ = shutdown_tcp_rx_remote.notified() => break,
                        n = target_r.read(&mut buf) => {
                            match n {
                                Ok(0) => {
                                    break;
                                },
                                Ok(n) => {
                                    let cmd = Command::Data {
                                        payload: Bytes::copy_from_slice(&buf[..n]),
                                    };
                                    if tx_clone.send(cmd).await.is_err() {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    error!("read form target error: {}", e);
                                    break;
                                }
                            }
                        }
                    }
                }
                shutdown_tcp_tx_remote.notify_one();
            });

            // 客户端 -> 代理 -> 目标
            tokio::spawn(async move {
                loop {
                    select! {
                        _ = shutdown_tcp_rx_local.notified() => break,
                        data = read_packet(&mut client_reader) => {
                            match data {
                                Ok(Command::Data { payload }) => {
                                    if let Err(e) = target_w.write_all(&payload).await {
                                        error!("Write tcp to target error: {:?}",e);
                                        break;
                                    }
                                }
                                _ => {
                                    tcp_cancel_token.cancel();
                                    break
                                },
                            }
                        }
                    }
                }
                shutdown_tcp_tx_local.notify_one()
            });
        }

        // === UDP 模式 (Full Cone) ===
        Command::UdpAssociate { nat_type } => {
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
            let tx_clone = tx.clone();
            let sock_recv = socket.clone();

            let whitelist_recv = whitelist.clone();

            tokio::spawn(async move {
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

                    let canonical_ip = match src_addr.ip() {
                        IpAddr::V6(v6) => {
                            if let Some(v4) = v6.to_ipv4() {
                                IpAddr::V4(v4)
                            } else {
                                IpAddr::V6(v6)
                            }
                        }
                        v4 => v4,
                    };

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

                        let cmd = Command::UdpData {
                            addr: canonical_ip.to_string(),
                            port: src_addr.port(),
                            payload: packet.freeze(),
                        };
                        if tx_clone.send(cmd).await.is_err() {
                            break;
                        }
                    }
                }
                shutdown_tx_1.notify_one();
            });

            // 客户端 -> 代理 -> 外部
            let sock_send = socket.clone();
            tokio::spawn(async move {
                loop {
                    let resp = select! {
                        _ = shutdown_rx_2.notified() => break,
                        resp = read_packet(&mut client_reader) => resp,
                    };
                    match resp {
                        Ok(Command::UdpData {
                            addr,
                            port,
                            payload,
                        }) => {
                            if nat_type == NATType::Restricted {
                                whitelist.insert(addr.clone(), ()).await;
                            } else if nat_type == NATType::PortRestricted {
                                whitelist.insert(format!("{}:{}", addr, port), ()).await;
                            }

                            if let Err(e) = sock_send.send_to(&payload, (addr.as_str(), port)).await
                            {
                                error!("Write udp to target error: {:?}", e);
                                break;
                            };
                        }
                        _ => {
                            udp_cancel_token.cancel();
                            break;
                        }
                    }
                }
                shutdown_tx_2.notify_one();
            });
        }
        _ => return Ok(()),
    }

    // 主循环：负责把 channel 里的数据写回给 TLS 客户端
    loop {
        select! {
            _ = cancel_token.cancelled() => {
                break;
            }
            data = rx.recv() => {
                match data {
                    Some(cmd) => {
                        if let Err (e)= write_packet(&mut client_writer, &cmd).await {
                            error!("server write to client error: {}", e);
                            break;
                        }
                    },
                    None => break,
                }
            }
        }
    }

    Ok(())
}
