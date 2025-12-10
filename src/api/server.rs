use crate::protocol::net_addr::NetAddr;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::ops::Deref;
use std::sync::atomic::Ordering;
use std::sync::{Arc, atomic};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(serde::Serialize)]
pub struct UserTraffic {
    upload: atomic::AtomicU64,
    download: atomic::AtomicU64,
}
#[derive(serde::Serialize)]
pub struct ServerStatistic(HashMap<String, UserTraffic>);

impl Deref for ServerStatistic {
    type Target = HashMap<String, UserTraffic>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl ServerStatistic {
    pub fn new() -> Arc<Self> {
        Arc::new(Self(HashMap::new()))
    }

    pub fn update_upload(&self, user: String, value: usize) {
        if let Some(u) = self.get(&user) {
            u.upload.store(value as u64, Ordering::Relaxed);
        }
    }

    pub fn update_download(&self, user: String, value: usize) {
        if let Some(u) = self.get(&user) {
            u.download.store(value as u64, Ordering::Relaxed);
        }
    }
}

pub async fn start_server_stat_api(port: u16, stat_map: Arc<ServerStatistic>) {
    let addr = (Ipv4Addr::LOCALHOST, port);
    let net_addr = NetAddr::new_ipv4(addr.0, addr.1);
    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Server stat server failed to bind {}: {}", net_addr, e);
            return;
        }
    };

    println!("Stat API listening on http://{}/stats", net_addr);
    loop {
        let map_cloned = stat_map.clone();
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

                        // 序列化 JSON
                        let body = serde_json::to_string(&map_cloned).unwrap_or_default();

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
