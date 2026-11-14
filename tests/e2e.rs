//! 端到端测试：本地应用 -> client -> (TLS) -> server -> 目标

use rust_proxy::api::client::TOTAL_UPLOAD;
use rust_proxy::api::common::ServerStatistic;
use rust_proxy::client::ClientOptions;
use rust_proxy::connection_pool::ConnectionPool;
use rust_proxy::health::SystemMetrics;
use rust_proxy::protocol::message::{Response, read_client_request, response_to_client};
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
    server_addr: SocketAddr,
    manager: Arc<UserManager>,
    pool: ConnectionPool,
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
    start_proxy_with_options(ClientOptions::default(), 100).await
}

async fn start_proxy_with_options(options: ClientOptions, max_conns: usize) -> TestEnv {
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
    let pool = ConnectionPool::new(max_conns);
    let server_task = tokio::spawn(server::serve(
        listener,
        acceptor,
        manager.clone(),
        ServerStatistic::new(),
        Arc::new(SystemMetrics::new()),
        pool.clone(),
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
        options,
    ));

    TestEnv {
        client_addr,
        server_addr,
        manager,
        pool,
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

/// 发起 SOCKS5 请求并返回原始状态码 `REP`、绑定地址与底层流
async fn socks5_request_raw(
    proxy: SocketAddr,
    cmd: u8,
    target: &NetAddr,
) -> (u8, NetAddr, TcpStream) {
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
    assert_eq!(head[0], 0x05);
    assert_eq!(head[2], 0x00);
    let bound = NetAddr::read_from(&mut stream).await.unwrap();
    (head[1], bound, stream)
}

/// 获取一个已释放的本地端口（保证连接时立即触发 ConnectionRefused）
async fn closed_local_addr() -> SocketAddr {
    let sock = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    drop(sock);
    addr
}

#[tokio::test]
async fn true_0rtt_sends_first_payload_before_server_responds() {
    // 严格证明真 0-RTT：
    // 模拟服务端在收到 Client Hello 后**不先发送** Server Response，
    // 而是要求先从同一条流里读出本地应用发出的 "0rtt-ping"，收到后才回发 Response::Success + "0rtt-pong"。
    // 旧的“假 0-RTT”客户端因在转发前阻塞等待 handle_response，在此测试中会必然死锁超时。
    timeout(TEST_TIMEOUT, async {
        let dir = std::env::temp_dir().join(format!("rust_proxy_0rtt_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");

        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, certified.cert.pem()).unwrap();
        std::fs::write(&key_path, certified.signing_key.serialize_pem()).unwrap();
        let cert_str = cert_path.to_str().unwrap();

        let acceptor =
            Arc::new(tls::create_server_config(cert_str, key_path.to_str().unwrap()).unwrap());
        let mock_server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_server_addr = mock_server.local_addr().unwrap();

        // Mock Server 服务两次请求：一次验证 SOCKS5 TCP 0-RTT，一次验证 HTTP CONNECT 0-RTT
        let server_handle = tokio::spawn(async move {
            for _ in 0..2 {
                let (tcp, _) = mock_server.accept().await.unwrap();
                let mut tls_stream = acceptor.accept(tcp).await.unwrap();
                let (_uuid, _cmd, _addr) = read_client_request(&mut tls_stream).await.unwrap();

                // 关键断言：服务端尚未发送任何响应，就已经能直接读到客户端转发过来的应用首包
                let mut early_payload = [0u8; 9];
                tls_stream.read_exact(&mut early_payload).await.unwrap();
                assert_eq!(&early_payload, b"0rtt-ping");

                response_to_client(&mut tls_stream, &Response::Success)
                    .await
                    .unwrap();
                tls_stream.write_all(b"0rtt-pong").await.unwrap();
                tls_stream.flush().await.unwrap();
                let _ = tls_stream.shutdown().await;
            }
        });

        let connector = Arc::new(tls::create_client_config(cert_str).unwrap());
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client_listener.local_addr().unwrap();
        let client_task = tokio::spawn(client::serve(
            client_listener,
            mock_server_addr.to_string(),
            connector,
            Uuid::new_v4(),
            ClientOptions::default(),
        ));

        // 1. 验证 SOCKS5 TCP 真 0-RTT
        let target = NetAddr::new_ipv4(Ipv4Addr::LOCALHOST, 8080);
        let (mut s5, _) = socks5_request(client_addr, 0x01, &target).await;
        s5.write_all(b"0rtt-ping").await.unwrap();
        let mut reply = [0u8; 9];
        s5.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"0rtt-pong");
        drop(s5);

        // 2. 验证 HTTP CONNECT 真 0-RTT（浏览器等待 200 后才发首包的真实路径）
        let mut hc = TcpStream::connect(client_addr).await.unwrap();
        hc.write_all(b"CONNECT 127.0.0.1:8080 HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n")
            .await
            .unwrap();
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            header.push(hc.read_u8().await.unwrap());
        }
        assert!(header.starts_with(b"HTTP/1.1 200"));
        hc.write_all(b"0rtt-ping").await.unwrap();
        let mut hc_reply = [0u8; 9];
        hc.read_exact(&mut hc_reply).await.unwrap();
        assert_eq!(&hc_reply, b"0rtt-pong");
        drop(hc);

        server_handle.await.unwrap();
        client_task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn server_speaks_first_protocol_works_under_0rtt() {
    // 验证类似 SSH / MySQL 等“服务端先发欢迎横幅、客户端后发数据”的协议在 0-RTT 模式下不会死锁
    timeout(TEST_TIMEOUT, async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let banner_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"SSH-2.0-MockServer\r\n").await.unwrap();
            let mut client_line = [0u8; 4];
            sock.read_exact(&mut client_line).await.unwrap();
            assert_eq!(&client_line, b"HELO");
            sock.write_all(b"OK").await.unwrap();
        });

        let env = start_proxy().await;
        let (mut stream, _) =
            socks5_request(env.client_addr, 0x01, &NetAddr::from(banner_addr)).await;

        let mut banner = [0u8; 20];
        stream.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"SSH-2.0-MockServer\r\n");

        stream.write_all(b"HELO").await.unwrap();
        let mut ok = [0u8; 2];
        stream.read_exact(&mut ok).await.unwrap();
        assert_eq!(&ok, b"OK");

        drop(stream);
        env.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn target_connect_failures_report_cleanly_in_both_modes() {
    timeout(Duration::from_secs(20), async {
        let dead = closed_local_addr().await;

        // === A. 默认真 0-RTT 模式 ===
        let env_0rtt = start_proxy().await;

        // A1. 普通 HTTP 请求在 0-RTT 模式下目标不可达时，仍能返回明确的 502 Bad Gateway
        let mut plain_http = TcpStream::connect(env_0rtt.client_addr).await.unwrap();
        let http_req = format!("GET http://{dead}/ HTTP/1.1\r\nHost: {dead}\r\n\r\n");
        plain_http.write_all(http_req.as_bytes()).await.unwrap();
        let mut resp_buf = Vec::new();
        plain_http.read_to_end(&mut resp_buf).await.unwrap();
        assert!(
            resp_buf.starts_with(b"HTTP/1.1 502"),
            "expected 502, got {:?}",
            String::from_utf8_lossy(&resp_buf)
        );

        // A2. SOCKS5 0-RTT 模式下目标拒绝连接时，服务端返回 ConnectionRefused，客户端立即干净关闭流
        let (rep, _, mut s5_dead) =
            socks5_request_raw(env_0rtt.client_addr, 0x01, &NetAddr::from(dead)).await;
        assert_eq!(rep, socks5::REPLY_SUCCEEDED);
        let mut rest = Vec::new();
        s5_dead.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());

        env_0rtt.shutdown().await;

        // === B. 严格确认模式（zero_rtt = false）：本地应用直接拿到精确错误码 ===
        let env_strict = start_proxy_with_options(
            ClientOptions {
                zero_rtt: false,
                max_connections: 100,
            },
            100,
        )
        .await;

        // B1. SOCKS5 连已关闭端口 -> 精确返回 0x05 (Connection Refused)
        let (rep_refused, _, _) =
            socks5_request_raw(env_strict.client_addr, 0x01, &NetAddr::from(dead)).await;
        assert_eq!(rep_refused, socks5::REPLY_CONNECTION_REFUSED);

        // B2. SOCKS5 连无效域名 -> 返回 0x04 (Host Unreachable)
        let invalid_domain = NetAddr::new_domain("nonexistent.invalid".to_string(), 80);
        let (rep_dns, _, _) =
            socks5_request_raw(env_strict.client_addr, 0x01, &invalid_domain).await;
        assert_eq!(rep_dns, socks5::REPLY_HOST_UNREACHABLE);

        // B3. HTTP CONNECT 连已关闭端口 -> 返回 502 Bad Gateway，而不是先回 200 再断开
        let mut hc_dead = TcpStream::connect(env_strict.client_addr).await.unwrap();
        let connect_req = format!("CONNECT {dead} HTTP/1.1\r\nHost: {dead}\r\n\r\n");
        hc_dead.write_all(connect_req.as_bytes()).await.unwrap();
        let mut hc_resp = Vec::new();
        hc_dead.read_to_end(&mut hc_resp).await.unwrap();
        assert!(hc_resp.starts_with(b"HTTP/1.1 502"));

        env_strict.shutdown().await;

        // === C. 代理服务端自身不可达：即使开启 0-RTT，客户端也能直接返回 SOCKS5 0x01 / HTTP 502 ===
        let dir = std::env::temp_dir().join(format!("rust_proxy_down_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        std::fs::write(&cert_path, certified.cert.pem()).unwrap();
        let connector = Arc::new(tls::create_client_config(cert_path.to_str().unwrap()).unwrap());
        let client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let orphan_client_addr = client_listener.local_addr().unwrap();
        let dead_server = closed_local_addr().await;
        let orphan_task = tokio::spawn(client::serve(
            client_listener,
            dead_server.to_string(),
            connector,
            Uuid::new_v4(),
            ClientOptions::default(),
        ));

        let (rep_server_down, _, _) =
            socks5_request_raw(orphan_client_addr, 0x01, &NetAddr::from(dead)).await;
        assert_eq!(rep_server_down, socks5::REPLY_GENERAL_FAILURE);

        let mut hc_down = TcpStream::connect(orphan_client_addr).await.unwrap();
        hc_down
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        let mut hc_down_resp = Vec::new();
        hc_down.read_to_end(&mut hc_down_resp).await.unwrap();
        assert!(hc_down_resp.starts_with(b"HTTP/1.1 502"));

        orphan_task.abort();
        let _ = std::fs::remove_dir_all(&dir);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn domain_resolution_dual_stack_fallback_and_udp_negative_dns_cache() {
    timeout(Duration::from_secs(20), async {
        // 仅在 IPv4 127.0.0.1 上监听：当解析 "localhost" 同时返回 [::1] 与 127.0.0.1 时，
        // 服务端会自动从拒绝连接的 [::1] 回退到可用的 127.0.0.1
        let echo_v4 = start_tcp_echo("127.0.0.1:0").await.unwrap();
        let env = start_proxy().await;

        let domain_target = NetAddr::new_domain("localhost".to_string(), echo_v4.port());
        let (mut stream, _) = socks5_request(env.client_addr, 0x01, &domain_target).await;
        stream.write_all(b"domain-ok").await.unwrap();
        let mut echoed = [0u8; 9];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"domain-ok");
        drop(stream);

        // UDP：连续向不可解析域名发包，负缓存应快速拦截，不得阻塞或拆除同一关联上的正常包转发
        let udp_echo = rust_proxy::protocol::utils::bind_dual_stack_udp().unwrap();
        let udp_echo_addr = udp_echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            while let Ok((n, src)) = udp_echo.recv_from(&mut buf).await {
                let _ = udp_echo.send_to(&buf[..n], src).await;
            }
        });

        let unspecified = NetAddr::new_ipv4(Ipv4Addr::UNSPECIFIED, 0);
        let (control, bound) = socks5_request(env.client_addr, 0x03, &unspecified).await;
        let relay_addr = bound.socket_addr().unwrap();
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let bad_domain = NetAddr::new_domain("nonexistent-udp-target.invalid".to_string(), 5353);
        let bad_pkt = socks5::build_udp_packet(&bad_domain, b"bad-dns").unwrap();
        for _ in 0..5 {
            app.send_to(&bad_pkt, relay_addr).await.unwrap();
        }

        let good_domain = NetAddr::new_domain("localhost".to_string(), udp_echo_addr.port());
        let good_pkt = socks5::build_udp_packet(&good_domain, b"udp-domain-ok").unwrap();
        app.send_to(&good_pkt, relay_addr).await.unwrap();

        let mut recv_buf = [0u8; 1024];
        let (n, _) = app.recv_from(&mut recv_buf).await.unwrap();
        let (_, offset) = socks5::parse_udp_packet(&recv_buf[..n]).unwrap();
        assert_eq!(&recv_buf[offset..n], b"udp-domain-ok");

        drop(control);
        env.shutdown().await;
    })
    .await
    .unwrap();
}

/// 在客户端与服务端之间插入模拟弱网的中继：把字节流切碎为极小分片（1~11 字节）并注入随机延迟抖动
async fn spawn_weak_network_link(target_server: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut down, _)) = listener.accept().await {
            tokio::spawn(async move {
                let Ok(mut up) = TcpStream::connect(target_server).await else {
                    return;
                };
                let (mut dr, mut dw) = down.split();
                let (mut ur, mut uw) = up.split();

                let c_to_s = async {
                    let mut buf = [0u8; 512];
                    let mut step = 0usize;
                    while let Ok(n) = dr.read(&mut buf).await {
                        if n == 0 {
                            let _ = uw.shutdown().await;
                            break;
                        }
                        let mut pos = 0;
                        while pos < n {
                            let chunk = ((step % 11) + 1).min(n - pos);
                            step = step.wrapping_add(3);
                            if uw.write_all(&buf[pos..pos + chunk]).await.is_err() {
                                return;
                            }
                            let _ = uw.flush().await;
                            pos += chunk;
                            if step.is_multiple_of(5) {
                                tokio::time::sleep(Duration::from_millis(2)).await;
                            }
                        }
                    }
                };

                let s_to_c = async {
                    let mut buf = [0u8; 512];
                    let mut step = 2usize;
                    while let Ok(n) = ur.read(&mut buf).await {
                        if n == 0 {
                            let _ = dw.shutdown().await;
                            break;
                        }
                        let mut pos = 0;
                        while pos < n {
                            let chunk = ((step % 13) + 1).min(n - pos);
                            step = step.wrapping_add(5);
                            if dw.write_all(&buf[pos..pos + chunk]).await.is_err() {
                                return;
                            }
                            let _ = dw.flush().await;
                            pos += chunk;
                            if step.is_multiple_of(7) {
                                tokio::time::sleep(Duration::from_millis(2)).await;
                            }
                        }
                    }
                };

                tokio::join!(c_to_s, s_to_c);
            });
        }
    });
    addr
}

#[tokio::test]
async fn weak_network_fragmentation_and_jitter_preserves_stream_integrity() {
    timeout(Duration::from_secs(20), async {
        let echo = start_tcp_echo("127.0.0.1:0").await.unwrap();
        let env = start_proxy().await;
        let weak_link_addr = spawn_weak_network_link(env.server_addr).await;

        // 再启动一个通过弱网链路连接服务端的客户端
        let cert_path = env.dir.join("cert.pem");
        let shared_key = Uuid::new_v4();
        env.manager.add_user(shared_key, 0, 0).unwrap();
        let connector = Arc::new(tls::create_client_config(cert_path.to_str().unwrap()).unwrap());
        let weak_client_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let weak_client_addr = weak_client_listener.local_addr().unwrap();
        let weak_client_task = tokio::spawn(client::serve(
            weak_client_listener,
            weak_link_addr.to_string(),
            connector,
            shared_key,
            ClientOptions::default(),
        ));

        let payload: Vec<u8> = (0..16 * 1024).map(|i| (i * 31 % 251) as u8).collect();
        let (mut stream, _) = socks5_request(weak_client_addr, 0x01, &NetAddr::from(echo)).await;

        let expected = payload.clone();
        let (mut sr, mut sw) = stream.split();
        let writer = async {
            sw.write_all(&payload).await.unwrap();
            sw.shutdown().await.unwrap();
        };
        let mut received = Vec::with_capacity(expected.len());
        let reader = async {
            sr.read_to_end(&mut received).await.unwrap();
        };
        tokio::join!(writer, reader);
        assert_eq!(received, expected);

        drop(stream);
        weak_client_task.abort();
        env.shutdown().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn high_concurrency_mixed_traffic_leaves_zero_leaked_resources() {
    timeout(Duration::from_secs(25), async {
        let max_conns = 128;
        let env = start_proxy_with_options(ClientOptions::default(), max_conns).await;
        let echo = start_tcp_echo("127.0.0.1:0").await.unwrap();
        let dead = closed_local_addr().await;

        let mut tasks = Vec::new();
        for i in 0..48usize {
            let proxy_addr = env.client_addr;
            tasks.push(tokio::spawn(async move {
                match i % 3 {
                    // 1. 并发 SOCKS5 正常双向流
                    0 => {
                        let (mut s, _) =
                            socks5_request(proxy_addr, 0x01, &NetAddr::from(echo)).await;
                        let msg = format!("concurrent-socks5-{i:04}").into_bytes();
                        s.write_all(&msg).await.unwrap();
                        let mut out = vec![0u8; msg.len()];
                        s.read_exact(&mut out).await.unwrap();
                        assert_eq!(out, msg);
                    }
                    // 2. 并发 HTTP CONNECT 携带首包
                    1 => {
                        let mut s = TcpStream::connect(proxy_addr).await.unwrap();
                        let body = format!("early-http-{i:04}");
                        let req = format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n{body}");
                        s.write_all(req.as_bytes()).await.unwrap();
                        let mut hdr = Vec::new();
                        while !hdr.ends_with(b"\r\n\r\n") {
                            hdr.push(s.read_u8().await.unwrap());
                        }
                        assert!(hdr.starts_with(b"HTTP/1.1 200"));
                        let mut out = vec![0u8; body.len()];
                        s.read_exact(&mut out).await.unwrap();
                        assert_eq!(out, body.as_bytes());
                    }
                    // 3. 混入并发的目标连接失败请求，验证异常路径不会泄漏连接池或 IP 计数
                    _ => {
                        let mut s = TcpStream::connect(proxy_addr).await.unwrap();
                        let req = format!("GET http://{dead}/ HTTP/1.1\r\nHost: {dead}\r\n\r\n");
                        s.write_all(req.as_bytes()).await.unwrap();
                        let mut resp = Vec::new();
                        s.read_to_end(&mut resp).await.unwrap();
                        assert!(resp.starts_with(b"HTTP/1.1 502"));
                    }
                }
            }));
        }

        for t in tasks {
            t.await.unwrap();
        }

        // 等待后台异步任务完成收尾清理，确认连接池许可与在线 IP 追踪全部归零
        let cleanup_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            if env.pool.available() == max_conns && env.manager.list_online_users().is_empty() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < cleanup_deadline,
                "resource leak detected: pool available={}/{}, online_users={:?}",
                env.pool.available(),
                max_conns,
                env.manager.list_online_users()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        env.shutdown().await;
    })
    .await
    .unwrap();
}
