use crate::protocol::fallback::{handle_tcp_fallback, handle_tls_fallback};
use crate::protocol::message::{
    Command, Response, build_udp_frame, read_client_request, read_udp_frame, response_to_client,
};
use crate::protocol::net_addr::NetAddr;
use crate::protocol::utils::{NATType, bind_dual_stack_udp};
use crate::secret::SHARED_KEY;
use crate::secret::totp::verify_totp_uuid;
use crate::tls;
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
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

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
            if let Err(e) = handle_client(socket, acceptor, NATType::FullCone).await {
                error!("Server Error: {}", e);
            }
        });
    }
}

async fn handle_client(
    mut socket: TcpStream,
    acceptor: Arc<TlsAcceptor>,
    nat_type: NATType,
) -> Result<()> {
    let mut header_byte = [0u8; 1];
    let n = socket.peek(&mut header_byte).await?;

    if n > 0 && header_byte[0] != 0x16 {
        info!("Non-TLS traffic detected, falling back to TCP proxy");
        return handle_tcp_fallback(&mut socket).await;
    }
    // 建立TLS
    let stream = acceptor.accept(socket).await?;
    let (mut client_reader, mut client_writer) = tokio::io::split(stream);

    let mut peek = vec![0u8; 1024];
    let mut offset = 0;
    let (uuid, cmd, addr, consumed_len) = loop {
        if offset >= peek.len() {
            info!("Handshake buffer full, fallback to web");
            return handle_tls_fallback(&peek, client_reader, client_writer).await;
        }
        let n = client_reader.read(&mut peek[offset..]).await?;
        if n == 0 {
            return Ok(()); // EOF 连接关闭
        }
        offset += n;
        let valid_data = &peek[..offset];
        let mut cursor = Cursor::new(valid_data);
        // 读取握手包 (UUID Auth + Padding Skip)
        match read_client_request(&mut cursor).await {
            Ok((uuid, cmd, addr)) => {
                // 解析成功！跳出循环
                let consumed = cursor.position() as usize;
                break (uuid, cmd, addr, consumed);
            }
            Err(e) => {
                // 关键点：如果是数据不够 (UnexpectedEof)，则 continue 继续读
                // 如果是其他错误 (InvalidData)，则说明协议不对，回落
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    // 数据不够，继续下一轮 read
                    continue;
                } else {
                    info!("Invalid client hello: {}, fallback", e);
                    return handle_tls_fallback(valid_data, client_reader, client_writer).await;
                }
            }
        }
    };

    if !verify_totp_uuid(SHARED_KEY, &uuid) {
        return handle_tls_fallback(&peek[..offset], client_reader, client_writer).await;
    }
    let remaining = peek[consumed_len..offset].to_vec();
    let mut chained_reader = AsyncReadExt::chain(Cursor::new(remaining), client_reader);

    response_to_client(&mut client_writer, &Response::Success).await?;

    match cmd {
        // === TCP 模式 ===
        Command::TcpConnect => {
            let target = TcpStream::connect((addr.addr(), addr.port())).await?;
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
                    if let Err(e) = client_writer
                        .write_all(&target_to_client_buf[..length])
                        .await
                    {
                        error!("Target write to client error {}", e);
                        break;
                    }
                }
                shutdown_tcp_tx_remote.notify_one();
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
                if let Err(e) = target_w.write_all(&client_to_target_buf[..length]).await {
                    error!("Write to target error {}", e);
                    break;
                }
            }
            shutdown_tcp_tx_local.notify_one()
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
                        let net_addr = match canonical_ip {
                            IpAddr::V4(ip) => NetAddr::new_ipv4(ip, src_addr.port()),
                            IpAddr::V6(ip) => NetAddr::new_ipv6(ip, src_addr.port()),
                        };
                        let cmd = build_udp_frame(&net_addr, &packet.freeze());
                        match cmd {
                            Ok(c) => {
                                if let Err(e) = client_writer.write_all(&c).await {
                                    error!("Server write udp to client error {}", e);
                                    break;
                                }
                            }
                            Err(e) => {
                                error!("build udp frame fail {}", e);
                            }
                        };
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
                        resp = read_udp_frame(&mut chained_reader) => resp,
                    };
                    match resp {
                        Ok((addr, payload)) => {
                            if nat_type == NATType::Restricted {
                                whitelist.insert(addr.addr(), ()).await;
                            } else if nat_type == NATType::PortRestricted {
                                whitelist.insert(addr.to_string(), ()).await;
                            }

                            if let Err(e) = sock_send
                                .send_to(&payload, (addr.addr(), addr.port()))
                                .await
                            {
                                error!("Write udp to target error: {:?}", e);
                                break;
                            };
                        }
                        Err(_) => break,
                    }
                }
                shutdown_tx_2.notify_one();
            });
        }
    }

    Ok(())
}
