use anyhow::{Result, anyhow, bail};
use std::net::IpAddr::{V4, V6};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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

pub fn parse_udp_packet(data: &[u8]) -> Result<(String, u16, usize)> {
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
    Ok((addr_str, port, cursor))
}

/// 构建 SOCKS5 UDP 数据包 (用于回复客户端)
/// 格式: RSV(2) | FRAG(1) | ATYP(1) | ADDR | PORT | DATA
pub fn build_udp_packet(target_addr: &str, port: u16, data: &[u8]) -> Result<Vec<u8>> {
    // 预估头部最大长度 (IPv6 16+1+2=19, Domain 255+1+1+2=259) + 数据长度
    let mut buf = Vec::with_capacity(300 + data.len());

    // RSV
    buf.extend_from_slice(&[0x00, 0x00]);
    // FRAG
    buf.push(0x00);

    // 尝试解析为标准 SocketAddr (IP:Port)
    if let Ok(addr) = target_addr.parse::<IpAddr>() {
        match addr {
            V4(ip) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&ip.octets());
            }
            V6(ip) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&ip.octets());
            }
        }
        buf.extend_from_slice(&port.to_be_bytes());
    } else {
        // 如果不是标准 IP 格式，尝试作为 Domain 处理
        // 格式预期: "domain.com:port" 或 "[::1]:port" 需要找到最后一个冒号来分割 Host 和 Port
        let (host, port_str) = target_addr
            .rsplit_once(':')
            .ok_or_else(|| anyhow!("Invalid address format for UDP response: {}", target_addr))?;

        let port: u16 = port_str
            .parse()
            .map_err(|_| anyhow!("Invalid port in address: {}", target_addr))?;

        if host.len() > 255 {
            bail!("Domain name too long (max 255 bytes): {}", host);
        }

        buf.push(ATYP_DOMAIN);
        buf.push(host.len() as u8);
        buf.extend_from_slice(host.as_bytes());
        buf.extend_from_slice(&port.to_be_bytes());
    }

    // Append Payload
    buf.extend_from_slice(data);
    Ok(buf)
}
