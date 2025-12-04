use std::net::{Ipv4Addr, Ipv6Addr};
use std::{fmt, io};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq)]
pub enum NetAddr {
    V4(Ipv4Addr, u16),
    Domain(String, u16),
    V6(Ipv6Addr, u16),
}

// 方便打印日志
impl fmt::Display for NetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetAddr::V4(addr, port) => write!(f, "{}:{}", addr, port),
            NetAddr::Domain(host, port) => write!(f, "{}:{}", host, port),
            NetAddr::V6(addr, port) => write!(f, "[{}]:{}", addr, port),
        }
    }
}

impl From<&NetAddr> for Vec<u8> {
    fn from(value: &NetAddr) -> Self {
        match value {
            NetAddr::V4(ip, port) => {
                // 1(ATYP) + 4(IPv4) + 2(Port) = 7
                let mut buf = Vec::with_capacity(7);
                buf.push(0x01);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
                buf
            }
            NetAddr::Domain(domain, port) => {
                let bytes = domain.as_bytes();
                let len = bytes.len();

                // 协议限制域名长度最大为 255 (1 byte)
                // From trait 不允许返回 Err，如果超长这里选择截断或 panic，
                // 生产环境建议在构造 NetAddr 时就校验长度。
                let len_u8 = if len > 255 { 255 } else { len as u8 };

                // 1(ATYP) + 1(Len) + N(Domain) + 2(Port)
                let mut buf = Vec::with_capacity(1 + 1 + len_u8 as usize + 2);
                buf.push(0x03);
                buf.push(len_u8);
                buf.extend_from_slice(&bytes[..len_u8 as usize]);
                buf.extend_from_slice(&port.to_be_bytes());
                buf
            }
            NetAddr::V6(ip, port) => {
                // 1(ATYP) + 16(IPv6) + 2(Port) = 19
                let mut buf = Vec::with_capacity(19);
                buf.push(0x04);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
                buf
            }
        }
    }
}

impl TryFrom<&Vec<u8>> for NetAddr {
    type Error = io::Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        let data = value.as_slice();

        if data.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Data too short",
            ));
        }

        let atyp = data[0];
        let mut cursor = 1;

        match atyp {
            0x01 => {
                // IPv4
                if data.len() < cursor + 4 + 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Invalid IPv4 packet length",
                    ));
                }

                // 读取 IP
                let ip_bytes: [u8; 4] = data[cursor..cursor + 4].try_into().unwrap();
                let ip = Ipv4Addr::from(ip_bytes);
                cursor += 4;

                // 读取 Port
                let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);

                Ok(NetAddr::V4(ip, port))
            }
            0x03 => {
                // Domain
                if data.len() <= cursor {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Invalid Domain packet",
                    ));
                }

                let len = data[cursor] as usize;
                cursor += 1;

                if data.len() < cursor + len + 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Invalid Domain content length",
                    ));
                }

                let domain_bytes = &data[cursor..cursor + len];
                let domain = String::from_utf8(domain_bytes.to_vec())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                cursor += len;

                let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);

                Ok(NetAddr::Domain(domain, port))
            }
            0x04 => {
                // IPv6
                if data.len() < cursor + 16 + 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Invalid IPv6 packet length",
                    ));
                }

                let ip_bytes: [u8; 16] = data[cursor..cursor + 16].try_into().unwrap();
                let ip = Ipv6Addr::from(ip_bytes);
                cursor += 16;

                let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);

                Ok(NetAddr::V6(ip, port))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported ATYP: {}", atyp),
            )),
        }
    }
}

impl NetAddr {
    pub fn new_ipv4(ip: Ipv4Addr, port: u16) -> Self {
        NetAddr::V4(ip, port)
    }

    pub fn new_ipv6(ip: Ipv6Addr, port: u16) -> Self {
        NetAddr::V6(ip, port)
    }

    pub fn new_domain(host: String, port: u16) -> Self {
        NetAddr::Domain(host, port)
    }

    /// 从 AsyncRead流中读取并解析地址
    pub async fn read_from<R>(stream: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        // 1. 读取 ATYP 字节
        let atyp = stream.read_u8().await?;

        match atyp {
            0x01 => {
                // IPv4
                let mut ip_bytes = [0u8; 4];
                stream.read_exact(&mut ip_bytes).await?;
                let port = stream.read_u16().await?; // tokio read_u16 默认是大端序

                Ok(NetAddr::V4(Ipv4Addr::from(ip_bytes), port))
            }
            0x03 => {
                // Domain
                let len = stream.read_u8().await? as usize;
                let mut domain_bytes = vec![0u8; len];
                stream.read_exact(&mut domain_bytes).await?;
                let port = stream.read_u16().await?;

                // 将 bytes 转为 String (通常假定是 UTF-8)
                let domain = String::from_utf8(domain_bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

                Ok(NetAddr::Domain(domain, port))
            }
            0x04 => {
                // IPv6
                let mut ip_bytes = [0u8; 16];
                stream.read_exact(&mut ip_bytes).await?;
                let port = stream.read_u16().await?;

                Ok(NetAddr::V6(Ipv6Addr::from(ip_bytes), port))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Unsupported ATYP: {}", atyp),
            )),
        }
    }

    /// 将地址序列化并写入流
    pub async fn write_to<W>(&self, stream: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match self {
            NetAddr::V4(addr, port) => {
                stream.write_u8(0x01).await?;
                stream.write_all(&addr.octets()).await?;
                stream.write_u16(*port).await?;
            }
            NetAddr::Domain(domain, port) => {
                stream.write_u8(0x03).await?;
                let bytes = domain.as_bytes();
                if bytes.len() > 255 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Domain too long",
                    ));
                }
                stream.write_u8(bytes.len() as u8).await?;
                stream.write_all(bytes).await?;
                stream.write_u16(*port).await?;
            }
            NetAddr::V6(addr, port) => {
                stream.write_u8(0x04).await?;
                stream.write_all(&addr.octets()).await?;
                stream.write_u16(*port).await?;
            }
        }
        Ok(())
    }
}
