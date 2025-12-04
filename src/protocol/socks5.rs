use crate::protocol::net_addr::{ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, NetAddr};
use anyhow::{Result, bail};
use std::io::{Error, ErrorKind};
use std::net::IpAddr::{V4, V6};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
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

pub fn parse_udp_packet(data: &[u8]) -> std::io::Result<(NetAddr, usize)> {
    // 基础校验：RSV(2) + FRAG(1) + ATYP(1) = 4 bytes
    if data.len() < 4 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Invalid UDP packet: data too short",
        ));
    }

    // SOCKS5 UDP 头部前两个字节是 RSV，通常为 0，这里略过
    // 第三个字节是 FRAG
    if data[2] != 0 {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "Invalid UDP fragment: fragmentation not supported",
        ));
    }

    let atyp = data[3];
    let mut cursor = 4;

    let addr = match atyp {
        ATYP_IPV4 => {
            // 校验长度: 当前cursor + IPv4(4) + Port(2)
            if data.len() < cursor + 4 + 2 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid IPv4 packet: data too short",
                ));
            }

            let bytes: [u8; 4] = data[cursor..cursor + 4]
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid IPv4 addr"))?; // 长度已校验，unwrap 安全
            let ip = Ipv4Addr::from(bytes);
            cursor += 4;

            // 读取端口
            let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
            cursor += 2;

            NetAddr::V4(ip, port)
        }
        ATYP_DOMAIN => {
            // 校验长度: 读取 len 字节
            if data.len() <= cursor {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid Domain packet: missing length byte",
                ));
            }

            let len = data[cursor] as usize;
            cursor += 1;

            // 校验长度: 域名内容(len) + Port(2)
            if data.len() < cursor + len + 2 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid Domain packet: data too short",
                ));
            }

            // 转换域名
            let domain_bytes = &data[cursor..cursor + len];
            let domain = String::from_utf8(domain_bytes.to_vec())
                .map_err(|_| Error::new(ErrorKind::InvalidInput, "Invalid Domain encoding"))?;
            cursor += len;

            // 读取端口
            let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
            cursor += 2;

            NetAddr::Domain(domain, port)
        }
        ATYP_IPV6 => {
            // 校验长度: IPv6(16) + Port(2)
            if data.len() < cursor + 16 + 2 {
                return Err(Error::new(
                    ErrorKind::InvalidInput,
                    "Invalid IPv6 packet: data too short",
                ));
            }

            let bytes: [u8; 16] = data[cursor..cursor + 16]
                .try_into()
                .map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid IPv6 addr"))?;
            let ip = Ipv6Addr::from(bytes);
            cursor += 16;

            let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
            cursor += 2;

            NetAddr::V6(ip, port)
        }
        _ => {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unsupported ATYP: {}", atyp),
            ));
        }
    };

    Ok((addr, cursor))
}

/// 构建 SOCKS5 UDP 数据包 (用于回复客户端)
/// 格式: RSV(2) | FRAG(1) | ATYP(1) | ADDR | PORT | DATA
pub fn build_udp_packet(target_addr: &NetAddr, data: &[u8]) -> std::io::Result<Vec<u8>> {
    // 预估头部最大长度 (IPv6 16+1+2=19, Domain 255+1+1+2=259) + 数据长度
    let mut buf = Vec::with_capacity(300 + data.len());

    // RSV
    buf.extend_from_slice(&[0x00, 0x00]);
    // FRAG
    buf.push(0x00);

    let addr_bytes: Vec<u8> = target_addr.into();
    buf.extend_from_slice(addr_bytes.as_slice());

    // Append Payload
    buf.extend_from_slice(data);
    Ok(buf)
}
