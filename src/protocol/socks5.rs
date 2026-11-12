use crate::protocol::net_addr::NetAddr;
use anyhow::{Result, bail};
use std::io::{Error, ErrorKind};
use std::net::IpAddr::{V4, V6};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub enum SocksRequest {
    Tcp(NetAddr), // 目标地址
    Udp(NetAddr), // UDP 请求
}

const SOCKS5_VERSION: u8 = 0x05;

const NO_AUTHENTICATE: u8 = 0x00;

pub async fn handshake(stream: &mut TcpStream) -> Result<SocksRequest> {
    // 1. 认证协商
    let version = stream.read_u8().await?;
    if version != SOCKS5_VERSION {
        bail!("Unsupported Socks version {}", version);
    }
    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&NO_AUTHENTICATE) {
        bail!("Client don't supported No Auth method");
    }
    stream.write_all(&[0x05, NO_AUTHENTICATE]).await?; // No Auth

    // 2. 请求处理
    let mut head = [0u8; 3];
    stream.read_exact(&mut head).await?; // VER, CMD, RSV
    let cmd = head[1];
    let addr = NetAddr::read_from(stream).await?;

    if cmd == 0x01 {
        Ok(SocksRequest::Tcp(addr))
    } else if cmd == 0x03 {
        Ok(SocksRequest::Udp(addr))
    } else {
        bail!("Unsupported command: {}", cmd);
    }
}

pub async fn send_reply(stream: &mut TcpStream, addr: SocketAddr) -> Result<()> {
    let mut reply = vec![0x05, 0x00, 0x00];
    match addr.ip() {
        V4(ip) => {
            reply.push(0x01);
            reply.extend_from_slice(&ip.octets())
        }
        V6(ip) => {
            reply.push(0x04);
            reply.extend_from_slice(&ip.octets())
        }
    };
    reply.extend_from_slice(&addr.port().to_be_bytes());
    stream.write_all(&reply).await?;
    Ok(())
}

/// 解析 UDP 数据包: RSV(2) + FRAG(1) + ATYP(1) + ...
pub fn parse_udp_packet(data: &[u8]) -> std::io::Result<(NetAddr, usize)> {
    // 头部校验: RSV(2) + FRAG(1) + ATYP(1) 至少 4 字节
    // data[2] 是 FRAG，必须为 0
    if data.len() < 4 || data[2] != 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Invalid UDP packet header",
        ));
    }

    // 从 index 3 (ATYP 位置) 开始正好是一个标准的地址格式
    let (addr, len) = NetAddr::parse(&data[3..])?;

    // 总消耗长度 = 头部偏移(3) + 地址长度
    Ok((addr, len + 3))
}

/// 把 SOCKS5 UDP 数据包追加编码到 `buf` (用于回复客户端)
/// 格式: RSV(2) | FRAG(1) | ATYP(1) | ADDR | PORT | DATA
pub fn encode_udp_packet(
    target_addr: &NetAddr,
    data: &[u8],
    buf: &mut Vec<u8>,
) -> std::io::Result<()> {
    buf.reserve(3 + target_addr.bytes_len() + data.len());
    // RSV + FRAG
    buf.extend_from_slice(&[0x00, 0x00, 0x00]);
    target_addr.write_to_buf(buf)?;
    buf.extend_from_slice(data);
    Ok(())
}

pub fn build_udp_packet(target_addr: &NetAddr, data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut buf = Vec::new();
    encode_udp_packet(target_addr, data, &mut buf)?;
    Ok(buf)
}
