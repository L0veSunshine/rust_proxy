use anyhow::{Result, bail};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

pub enum SocksRequest {
    Tcp(String), // 目标地址
    Udp,         // UDP 请求
}

const SOCKS5_VERSION: u8 = 0x05;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

pub async fn handshake(stream: &mut TcpStream) -> Result<SocksRequest> {
    // 1. 认证协商
    let version = stream.read_u8().await?;
    if version != SOCKS5_VERSION {
        bail!("Unsupported Socks version {}", version);
    }
    let nmethods = stream.read_u8().await?;
    let mut methods = vec![0u8; nmethods as usize];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[0x05, 0x00]).await?; // No Auth

    // 2. 请求处理
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?; // VER, CMD, RSV, ATYP
    let cmd = head[1];
    let atyp = head[3];

    if cmd == 0x01 {
        // CONNECT
        let addr = read_addr(stream, atyp).await?;
        Ok(SocksRequest::Tcp(addr))
    } else if cmd == 0x03 {
        // UDP ASSOCIATE
        // 消耗掉地址部分，不重要
        let _ = read_addr(stream, atyp).await?;
        Ok(SocksRequest::Udp)
    } else {
        bail!("Unsupported command: {}", cmd);
    }
}

async fn read_addr<S>(stream: &mut S, atyp: u8) -> Result<String>
where
    S: AsyncReadExt + Unpin,
{
    let host = match atyp {
        ATYP_IPV4 => {
            // IPv4
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            Ipv4Addr::from(buf).to_string()
        }
        ATYP_DOMAIN => {
            // Domain
            let len = stream.read_u8().await? as usize;
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await?;
            String::from_utf8(buf)?
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            Ipv6Addr::from(buf).to_string()
        }
        _ => bail!("unsupported atyp: {}", atyp),
    };
    let port = stream.read_u16().await?;
    Ok(format!("{}:{}", host, port))
}

pub async fn send_reply(stream: &mut TcpStream, addr: SocketAddr) -> Result<()> {
    let ip = match addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        _ => [0, 0, 0, 0],
    };
    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    reply.extend_from_slice(&ip);
    reply.extend_from_slice(&addr.port().to_be_bytes());
    stream.write_all(&reply).await?;
    Ok(())
}

pub fn parse_udp_packet(data: &[u8]) -> Result<(String, Vec<u8>)> {
    if data.len() < 4 {
        bail!("Invalid UDP packet");
    }
    let frag = data[2];
    if frag != 0 {
        bail!("Invalid UDP fragment");
    }
    let atype = data[3];
    let mut cursor = 4;

    let addr_str = match atype {
        ATYP_IPV4 => {
            if data.len() < cursor + 4 {
                bail!("Invalid IPv4 packet");
            }
            let ip_data: [u8; 4] = data[cursor..cursor + 4]
                .to_vec()
                .try_into()
                .expect("Invalid IPv4 packet");
            let ip = Ipv4Addr::from(ip_data);
            cursor += 4;
            ip.to_string()
        }
        ATYP_DOMAIN => {
            let len = data[cursor] as usize;
            cursor += 1;
            if data.len() < cursor + len {
                bail!("Invalid Domain len");
            }
            let domain = String::from_utf8(data[cursor..cursor + len].to_vec())?;
            cursor += len;
            domain
        }
        ATYP_IPV6 => {
            let ip_data: [u8; 16] = data[cursor..cursor + 16]
                .to_vec()
                .try_into()
                .expect("Invalid IPv6 packet");
            let ip = Ipv6Addr::from(ip_data);
            cursor += 16;
            ip.to_string()
        }
        _ => {
            bail!("Invalid atyp");
        }
    };
    if data.len() < cursor + 2 {
        bail!("Invalid port");
    }
    let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
    cursor += 2;
    let payload = data[cursor..].to_vec();
    Ok((format!("{}:{}", addr_str, port), payload))
}
