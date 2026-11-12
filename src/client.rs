use crate::api::client::{add_download, add_upload};
use crate::protocol::http;
use crate::protocol::message::{
    Command, Response, client_hello, encode_udp_frame, read_response_from_server, read_udp_frame,
};
use crate::protocol::net_addr::NetAddr;
use crate::protocol::socks5;
use crate::protocol::utils::{bind_dual_stack_udp, get_canonical_ip};
use crate::relay::{relay_bidirectional, write_and_flush};
use crate::secret::tls;
use crate::secret::totp::generate_totp_uuid;
use crate::server::UDP_BUFFER_SIZE;
use anyhow::{Result, bail};
use rustls::pki_types::ServerName;
use socket2::{SockRef, TcpKeepalive};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// accept 出错后的退避时间，避免空转
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

type TlsReader = ReadHalf<TlsStream<TcpStream>>;
type TlsWriter = WriteHalf<TlsStream<TcpStream>>;

pub async fn run(listen: String, server: String, ca_path: String, shared_key: Uuid) -> Result<()> {
    let connector = Arc::new(tls::create_client_config(&ca_path)?);
    let listener = TcpListener::bind(&listen).await?;
    println!("Client listening on {}", listen);
    serve(listener, server, connector, shared_key).await
}

/// 在已绑定的本地监听器上接受 SOCKS5 / HTTP 代理请求
pub async fn serve(
    listener: TcpListener,
    server: String,
    connector: Arc<TlsConnector>,
    shared_key: Uuid,
) -> Result<()> {
    let ka = TcpKeepalive::new().with_time(Duration::from_secs(60)); // 空闲60秒后开始探测
    let server = Arc::new(server);
    loop {
        let socket = match listener.accept().await {
            Ok((socket, _)) => socket,
            Err(e) => {
                error!("Client accept error: {}", e);
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                continue;
            }
        };
        // 单个 socket 设置失败只影响这条连接，不能让整个客户端退出
        let sock_opts = {
            let native_socket = SockRef::from(&socket);
            native_socket
                .set_tcp_nodelay(true)
                .and_then(|_| native_socket.set_tcp_keepalive(&ka))
        };
        if let Err(e) = sock_opts {
            warn!("Failed to set socket options: {}", e);
            continue;
        }
        let server = server.clone();
        let connector = connector.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(socket, &server, &connector, shared_key).await {
                error!("Client Error: {}", e);
            };
        });
    }
}

pub async fn handle_response<R: AsyncRead + Unpin>(tls_r: &mut R) -> Result<()> {
    let resp = read_response_from_server(tls_r).await?;
    match Response::try_from(resp) {
        Ok(Response::Success) => Ok(()),
        _ => bail!("build connect failed"),
    }
}

async fn handle_conn(
    local: TcpStream,
    server: &str,
    connector: &TlsConnector,
    shared_key: Uuid,
) -> Result<()> {
    // 检测协议类型：peek 第一个字节
    // SOCKS5 版本号固定为 0x05；HTTP 方法以 ASCII 字母开头 (G, P, C, D, H, O, T 等)
    let mut buf = [0u8; 1];
    local.peek(&mut buf).await?;

    if buf[0] == 0x05 {
        handle_socks5_proxy(local, server, connector, shared_key).await
    } else {
        handle_http_proxy(local, server, connector, shared_key).await
    }
}

/// 连接代理服务端并完成 TLS 握手
async fn connect_server(server: &str, connector: &TlsConnector) -> Result<(TlsReader, TlsWriter)> {
    let remote = TcpStream::connect(server).await?;
    let domain = ServerName::try_from("localhost")?;
    let tls_stream = connector.connect(domain, remote).await?;
    Ok(tokio::io::split(tls_stream))
}

/// 本地 TCP 与 TLS 隧道之间的双向转发
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

/// 处理 HTTP 代理请求
async fn handle_http_proxy(
    mut local: TcpStream,
    server: &str,
    connector: &TlsConnector,
    shared_key: Uuid,
) -> Result<()> {
    let req = http::handshake(&mut local).await?;
    let (mut tls_r, mut tls_w) = connect_server(server, connector).await?;
    let dynamic_uuid = generate_totp_uuid(shared_key.as_bytes());

    // CONNECT：先回 200，再把请求头之后已收到的数据转发出去
    // 普通 HTTP：请求行 + 头部本身就要转发给目标
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

    // 发送带 Padding 和 Auth 的握手
    client_hello(
        &mut tls_w,
        &dynamic_uuid,
        &Command::TcpConnect,
        &target_addr,
    )
    .await?;
    handle_response(&mut tls_r).await?;

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
) -> Result<()> {
    let req = socks5::handshake(&mut local).await?;
    let (mut tls_r, mut tls_w) = connect_server(server, connector).await?;
    let dynamic_uuid = generate_totp_uuid(shared_key.as_bytes());

    match req {
        socks5::SocksRequest::Tcp(target_addr) => {
            info!("SOCK5 Tcp connect to {}", target_addr);
            client_hello(
                &mut tls_w,
                &dynamic_uuid,
                &Command::TcpConnect,
                &target_addr,
            )
            .await?;
            // 0-RTT：不等服务端响应就先回复本地应用
            let unspecified = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0);
            socks5::send_reply(&mut local, unspecified).await?;
            handle_response(&mut tls_r).await?;

            relay_tcp(local, tls_r, tls_w).await;
        }

        socks5::SocksRequest::Udp(target_addr) => {
            info!("SOCK5 Udp connect to {}", target_addr);
            client_hello(
                &mut tls_w,
                &dynamic_uuid,
                &Command::UdpAssociate,
                &target_addr,
            )
            .await?;

            // 绑定双栈 Socket (实际上绑定了 [::]:0，同时覆盖 IPv4/IPv6)
            let udp = bind_dual_stack_udp()?;
            let reply_addr = SocketAddr::new(local.local_addr()?.ip(), udp.local_addr()?.port());
            socks5::send_reply(&mut local, reply_addr).await?;
            handle_response(&mut tls_r).await?;

            relay_udp(local, udp, tls_r, tls_w).await?;
        }
    }
    Ok(())
}

/// SOCKS5 UDP 关联：本地 UDP <-> TLS 隧道
///
/// - 只接受来自发起 UDP ASSOCIATE 的那个客户端 IP 的数据包，避免成为局域网开放中继
/// - 控制用的 TCP 连接关闭时结束关联 (RFC 1928)
/// - 任意方向结束都会拆除整个关联
async fn relay_udp<R, W>(
    mut control: TcpStream,
    udp: tokio::net::UdpSocket,
    mut tls_r: R,
    mut tls_w: W,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let allowed_ip = get_canonical_ip(control.peer_addr()?.ip());
    // 本地应用的来源地址 (IP:Port)：收到它的包就更新，服务端回包发往这里
    let client_src = Mutex::new(None::<SocketAddr>);
    let cancel = CancellationToken::new();

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
            add_upload(n);
        }
    };

    // TLS -> 本地 UDP
    let downlink = async {
        let mut packet = Vec::with_capacity(UDP_BUFFER_SIZE + 32);
        loop {
            let (addr, payload): (NetAddr, _) = match read_udp_frame(&mut tls_r).await {
                Ok(frame) => frame,
                Err(e) => {
                    error!("read udp frame error {}", e);
                    break;
                }
            };
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
    Ok(())
}
