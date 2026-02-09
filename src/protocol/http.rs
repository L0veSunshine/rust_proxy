use crate::protocol::net_addr::NetAddr;
use anyhow::{Result, anyhow, bail};
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub enum HttpRequest {
    Connect(NetAddr),
    Http(NetAddr, Vec<u8>),
}

/// 解析 host:port 格式的地址或 URI
fn parse_target(target: &str, default_port: u16) -> Result<NetAddr> {
    // 1. 提取 host 和 port
    let (host, port) = if let Ok(uri) = target.parse::<http::Uri>() {
        match uri.host() {
            // 情况 A: 成功解析为 URI
            Some(h) => (h.to_string(), uri.port_u16().unwrap_or(default_port)),
            // 情况 B: URI 解析成功但无 host (如只有路径)，尝试手动切分
            None => split_host_port(target, default_port)?,
        }
    } else {
        // 情况 C: 非标准 URI，手动解析 host:port
        split_host_port(target, default_port)?
    };

    // 2. 统一构建 NetAddr (去除重复逻辑)
    let clean_host = host.trim_matches(|c| c == '[' || c == ']');
    if let Ok(ip) = clean_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => Ok(NetAddr::new_ipv4(v4, port)),
            IpAddr::V6(v6) => Ok(NetAddr::new_ipv6(v6, port)),
        }
    } else {
        Ok(NetAddr::new_domain(host, port))
    }
}

/// 辅助函数：处理 host:port 字符串切分
fn split_host_port(target: &str, default_port: u16) -> Result<(String, u16)> {
    // 使用 rsplit_once 可以更好处理带端口的 IPv6，如 [::1]:80
    if let Some((host, port_str)) = target.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| anyhow!("Invalid port"))?;
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), default_port))
    }
}

/// 解析 HTTP 代理请求
pub async fn handshake(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut buf = vec![0u8; 8192];
    let mut n = 0;

    // 读取头部，直到找到空行
    loop {
        let read = stream.read(&mut buf[n..]).await?;
        if read == 0 {
            bail!("Unexpected EOF during HTTP handshake");
        }
        n += read;

        // 寻找 \r\n\r\n 或 \n\n
        let headers_end = buf[..n]
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .map(|p| p + 4)
            .or_else(|| {
                buf[..n]
                    .windows(2)
                    .position(|w| w == b"\n\n")
                    .map(|p| p + 2)
            });

        if headers_end.is_some() {
            break; // 找到头部结束，停止读取
        }

        if n == buf.len() {
            bail!("Header too large");
        }
    }

    // 解析第一行
    let first_line_end = buf[..n]
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| anyhow!("Invalid HTTP request, no newline found"))?;

    let line_str = String::from_utf8_lossy(&buf[..first_line_end]);
    let parts: Vec<&str> = line_str.split_whitespace().collect();
    let (method, target) = match parts.as_slice() {
        [m, t, ..] => (*m, *t),
        _ => bail!("Invalid HTTP request line: {}", line_str),
    };

    if method == "CONNECT" {
        let addr = parse_target(target, 443)?;
        Ok(HttpRequest::Connect(addr))
    } else {
        let addr = parse_target(target, 80)?;
        Ok(HttpRequest::Http(addr, buf[0..n].to_vec()))
    }
}

/// 发送 HTTP 200 Connection Established 响应；
pub async fn send_connect_success(stream: &mut TcpStream) -> Result<()> {
    let response = b"HTTP/1.1 200 Connection Established\r\n\r\n";
    stream.write_all(response).await?;
    Ok(())
}

/// 发送 HTTP 错误响应
pub async fn send_error(stream: &mut TcpStream, status_code: u16, message: &str) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Length: 0\r\n\r\n",
        status_code, message
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}
