use std::net::{Ipv4Addr, Ipv6Addr};
use std::{fmt, io};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
