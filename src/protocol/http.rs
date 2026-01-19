use crate::protocol::net_addr::NetAddr;
use anyhow::{Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

pub enum HttpRequest {
    Connect(NetAddr), // HTTP CONNECT 方法
}

/// 解析 host:port 格式的地址
fn parse_host_port(target: &str) -> Result<NetAddr> {
    let parts: Vec<&str> = target.split(':').collect();
    if parts.len() != 2 {
        bail!("Invalid target address format, expected host:port");
    }

    let host = parts[0].to_string();
    let port: u16 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid port number"))?;

    // 尝试解析为 IP 地址
    if let Ok(ip) = host.parse::<std::net::Ipv4Addr>() {
        Ok(NetAddr::new_ipv4(ip, port))
    } else if let Ok(ip) = host.parse::<std::net::Ipv6Addr>() {
        Ok(NetAddr::new_ipv6(ip, port))
    } else {
        // 否则作为域名处理
        Ok(NetAddr::new_domain(host, port))
    }
}

/// 解析 HTTP 代理请求
/// 主要支持 CONNECT 方法用于 HTTPS 代理
pub async fn handshake(stream: &mut TcpStream) -> Result<HttpRequest> {
    let mut request_line = String::new();
    let mut reader = BufReader::new(&mut *stream);

    // 读取请求行: CONNECT host:port HTTP/1.1
    reader.read_line(&mut request_line).await?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        bail!("Invalid HTTP request line");
    }

    let method = parts[0];
    let target = parts[1];

    if method != "CONNECT" {
        bail!("Only CONNECT method is supported for HTTP proxy");
    }

    // 解析目标地址 (格式: host:port)
    let addr = parse_host_port(target)?;

    // 读取并丢弃剩余的 HTTP 头部
    let mut line = String::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await?;
        // HTTP 头部结束标志: 空行 (\r\n)
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    Ok(HttpRequest::Connect(addr))
}

/// 发送 HTTP 200 Connection Established 响应
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
