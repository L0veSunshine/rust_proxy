//! 端到端测试：本地应用 -> client -> (TLS) -> server -> 目标

use rust_proxy::api::client::TOTAL_UPLOAD;
use rust_proxy::api::common::ServerStatistic;
use rust_proxy::connection_pool::ConnectionPool;
use rust_proxy::health::SystemMetrics;
use rust_proxy::protocol::net_addr::NetAddr;
use rust_proxy::protocol::socks5;
use rust_proxy::secret::tls;
use rust_proxy::shutdown::GracefulShutdown;
use rust_proxy::user_manager::UserManager;
use rust_proxy::{client, server};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::time::timeout;
use uuid::Uuid;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);

struct TestEnv {
    client_addr: SocketAddr,
    dir: PathBuf,
    shutdown: GracefulShutdown,
    server_task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
    client_task: Option<tokio::task::JoinHandle<anyhow::Result<()>>>,
}

impl TestEnv {
    /// 优雅停止后台任务并清理临时目录（Windows 下需等待 redb 关闭文件句柄后再删除）
    async fn shutdown(mut self) {
        if let Some(client_task) = self.client_task.take() {
            client_task.abort();
            let _ = client_task.await;
        }
        self.shutdown.shutdown(Duration::from_millis(50)).await;
        if let Some(server_task) = self.server_task.take() {
            let _ = server_task.await;
        }
        std::fs::remove_dir_all(&self.dir).expect("temp dir should be removed cleanly");
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if let Some(client_task) = self.client_task.take() {
            client_task.abort();
        }
        if let Some(server_task) = self.server_task.take() {
            server_task.abort();
        }
        self.shutdown.trigger_shutdown();
        if self.dir.exists() {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }
}

/// 启动一对 server + client，返回 client 的本地代理地址
async fn start_proxy() -> TestEnv {
    let dir = std::env::temp_dir().join(format!("rust_proxy_e2e_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    let db_path = dir.join("users.db");

    let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    std::fs::write(&cert_path, certified.cert.pem()).unwrap();
    std::fs::write(&key_path, certified.signing_key.serialize_pem()).unwrap();
    let cert_path = cert_path.to_str().unwrap();

    let shared_key = Uuid::new_v4();
    let manager = Arc::new(UserManager::new(db_path.to_str().unwrap()).unwrap());
    manager.add_user(shared_key, 0, 0).unwrap();

    let acceptor =
        Arc::new(tls::create_server_config(cert_path, key_path.to_str().unwrap()).unwrap());
    let listener = server::bind_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).unwrap();
    let server_addr = listener.local_addr().unwrap();
    let shutdown = GracefulShutdown::new();
    let server_task = tokio::spawn(server::serve(
        listener,
        acceptor,
        manager,
        ServerStatistic::new(),
        Arc::new(SystemMetrics::new()),
        ConnectionPool::new(100),
        shutdown.clone(),
    ));

    let connector = Arc::new(tls::create_client_config(cert_path).unwrap());
    let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client_addr = client_listener.local_addr().unwrap();
    let client_task = tokio::spawn(client::serve(
        client_listener,
        server_addr.to_string(),
        connector,
        shared_key,
    ));

    TestEnv {
        client_addr,
        dir,
        shutdown,
        server_task: Some(server_task),
        client_task: Some(client_task),
    }
}

/// TCP 回显服务；地址族不可用时返回 None
async fn start_tcp_echo(bind: &str) -> Option<SocketAddr> {
    let listener = TcpListener::bind(bind).await.ok()?;
    let addr = listener.local_addr().ok()?;
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = socket.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    Some(addr)
}

/// 完成 SOCKS5 协商并发送请求，返回控制连接和服务端回复的绑定地址
async fn socks5_request(proxy: SocketAddr, cmd: u8, target: &NetAddr) -> (TcpStream, NetAddr) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [0x05, 0x00]);

    let mut req = vec![0x05, cmd, 0x00];
    req.extend(target.to_bytes().unwrap());
    stream.write_all(&req).await.unwrap();

    let mut head = [0u8; 3];
    stream.read_exact(&mut head).await.unwrap();
    assert_eq!(head, [0x05, 0x00, 0x00]);
    let bound = NetAddr::read_from(&mut stream).await.unwrap();
    (stream, bound)
}

async fn assert_tcp_echo_via_socks5(target: SocketAddr) {
    let env = start_proxy().await;
    let (mut stream, _) = socks5_request(env.client_addr, 0x01, &NetAddr::from(target)).await;

    stream.write_all(b"hello proxy").await.unwrap();
    let mut buf = [0u8; 11];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello proxy");

    drop(stream);
    env.shutdown().await;
}

#[tokio::test]
async fn socks5_tcp_ipv4() {
    let echo = start_tcp_echo("127.0.0.1:0").await.unwrap();
    timeout(TEST_TIMEOUT, assert_tcp_echo_via_socks5(echo))
        .await
        .unwrap();
}

#[tokio::test]
async fn socks5_tcp_ipv6_target() {
    let Some(echo) = start_tcp_echo("[::1]:0").await else {
        return; // 环境不支持 IPv6
    };
    timeout(TEST_TIMEOUT, assert_tcp_echo_via_socks5(echo))
        .await
        .unwrap();
}

#[tokio::test]
async fn http_connect_keeps_early_data() {
    timeout(TEST_TIMEOUT, async {
        let echo = start_tcp_echo("127.0.0.1:0").await.unwrap();
        let env = start_proxy().await;
        let upload_before = TOTAL_UPLOAD.load(Ordering::Relaxed);

        // 请求头和隧道数据一次性发出：头部之后的 "PING" 不能被丢掉，且应计入上行流量
        let mut stream = TcpStream::connect(env.client_addr).await.unwrap();
        let req = format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\nPING");
        stream.write_all(req.as_bytes()).await.unwrap();

        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(stream.read_u8().await.unwrap());
        }
        assert!(header.starts_with(b"HTTP/1.1 200"));

        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"PING");
        assert!(TOTAL_UPLOAD.load(Ordering::Relaxed) - upload_before >= 4);

        drop(stream);
        env.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn socks5_udp_associate() {
    timeout(TEST_TIMEOUT, async {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, src)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], src).await;
            }
        });

        let env = start_proxy().await;
        let unspecified = NetAddr::new_ipv4(Ipv4Addr::UNSPECIFIED, 0);
        let (control, bound) = socks5_request(env.client_addr, 0x03, &unspecified).await;
        let relay_addr = bound.socket_addr().unwrap();

        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // 先向不可发送的目标地址 [::]:0 发包，服务端单次发送失败不应拆除整条 UDP 关联
        let bad_packet =
            socks5::build_udp_packet(&NetAddr::new_ipv6(Ipv6Addr::UNSPECIFIED, 0), b"bad").unwrap();
        app.send_to(&bad_packet, relay_addr).await.unwrap();

        let packet = socks5::build_udp_packet(&NetAddr::from(echo_addr), b"udp-ping").unwrap();
        app.send_to(&packet, relay_addr).await.unwrap();

        let mut buf = [0u8; 2048];
        let (n, _) = app.recv_from(&mut buf).await.unwrap();
        let (from, offset) = socks5::parse_udp_packet(&buf[..n]).unwrap();
        assert_eq!(from.port(), echo_addr.port());
        assert_eq!(&buf[offset..n], b"udp-ping");

        drop(control);
        env.shutdown().await;
    })
    .await
    .unwrap();
}
