use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use anyhow::{Result, bail};
use std::net::{Ipv4Addr, SocketAddr};

pub enum SocksRequest {
    Tcp(String), // 目标地址
    Udp,         // UDP 请求
}

pub async fn handshake(stream: &mut TcpStream) -> Result<SocksRequest> {
    // 1. 认证协商
    let version = stream.read_u8().await?;
    if version != 0x05 { bail!("Not SOCKS5"); }
    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?; // No Auth

    // 2. 请求处理
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    let cmd = head[1];
    let atyp = head[3];

    if cmd == 0x01 { // CONNECT
        let addr = read_addr(stream, atyp).await?;
        Ok(SocksRequest::Tcp(addr))
    } else if cmd == 0x03 { // UDP ASSOCIATE
        // 消耗掉地址部分，不重要
        let _ = read_addr(stream, atyp).await?;
        Ok(SocksRequest::Udp)
    } else {
        bail!("Unsupported command: {}", cmd);
    }
}

async fn read_addr(stream: &mut TcpStream, atyp: u8) -> Result<String> {
    let host = match atyp {
        0x01 => { // IPv4
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            Ipv4Addr::from(buf).to_string()
        }
        0x03 => { // Domain
            let len = stream.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            String::from_utf8(buf)?
        }
        _ => bail!("IPv6/Other not supported in demo"),
    };
    let port = stream.read_u16().await?;
    Ok(format!("{}:{}", host, port))
}

pub async fn send_reply(stream: &mut TcpStream, addr: SocketAddr) -> Result<()> {
    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        _ => [0,0,0,0],
    };
    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    reply.extend_from_slice(&ip);
    reply.extend_from_slice(&addr.port().to_be_bytes());
    stream.write_all(&reply).await?;
    Ok(())
}

// 简单的 UDP 头部解析 helper (省略具体实现，可参考之前的回复或标准)
// 这里为了代码简洁，假设 UDP 只是把 SOCKS 头剥离