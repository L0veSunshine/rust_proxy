use crate::protocol::net_addr::NetAddr;
use serde::Serialize;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// 全局计数器保持不变
pub static TOTAL_UPLOAD: AtomicU64 = AtomicU64::new(0);
pub static TOTAL_DOWNLOAD: AtomicU64 = AtomicU64::new(0);

#[derive(Serialize)]
struct TrafficStats {
    upload: u64,
    download: u64,
    time: u64,
}

// 计数函数保持不变
pub fn add_upload(n: usize) {
    TOTAL_UPLOAD.fetch_add(n as u64, Ordering::Relaxed);
}

pub fn add_download(n: usize) {
    TOTAL_DOWNLOAD.fetch_add(n as u64, Ordering::Relaxed);
}

/// 启动监控服务 (带基础协议检查)
pub async fn start_stat_api(port: u16) {
    let addr = (Ipv4Addr::LOCALHOST, port);
    let net_addr = NetAddr::new_ipv4(addr.0, addr.1);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Stat server failed to bind {}: {}", net_addr, e);
            return;
        }
    };

    println!("stat api server is listening on http://{}/stats", net_addr);
    tracing::info!("Stat api server started");

    loop {
        if let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];

                // 1. 读取请求数据
                let n = match socket.read(&mut buf).await {
                    Ok(n) if n > 0 => n,
                    _ => return, // 读取失败或连接关闭，直接退出
                };

                // 2. 简单的 HTTP 解析 (只看第一行)
                // String::from_utf8_lossy 允许处理可能包含非 UTF-8 字节的请求，避免 panic
                let request_text = String::from_utf8_lossy(&buf[..n]);
                let first_line = request_text.lines().next().unwrap_or("");
                let mut parts = first_line.split_whitespace();

                let method = parts.next();
                let path = parts.next();

                // 3. 路由分发与响应
                let response = match (method, path) {
                    (Some("GET"), Some("/stats")) => {
                        // === 200 OK: 返回统计数据 ===
                        let stats = TrafficStats {
                            upload: TOTAL_UPLOAD.load(Ordering::Relaxed),
                            download: TOTAL_DOWNLOAD.load(Ordering::Relaxed),
                            time: SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_millis() as u64,
                        };
                        // 序列化 JSON
                        let body = serde_json::to_string(&stats).unwrap_or_default();

                        format!(
                            "HTTP/1.1 200 OK\r\n\
                             Content-Type: application/json; charset=utf-8\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\
                             \r\n\
                             {}",
                            body.len(),
                            body
                        )
                    }
                    (Some("GET"), _) => {
                        // === 404 Not Found: 路径不对 ===
                        let body = "Not Found";
                        format!(
                            "HTTP/1.1 404 Not Found\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\
                             \r\n\
                             {}",
                            body.len(),
                            body
                        )
                    }
                    _ => {
                        // === 405 Method Not Allowed: 方法不对或是非法请求 ===
                        let body = "Method Not Allowed";
                        format!(
                            "HTTP/1.1 405 Method Not Allowed\r\n\
                             Content-Length: {}\r\n\
                             Connection: close\r\n\
                             \r\n\
                             {}",
                            body.len(),
                            body
                        )
                    }
                };

                // 4. 发送响应并关闭连接
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            });
        }
    }
}
