use crate::protocol::utils::configure_tcp_stream;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use std::{fmt, io};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

/// 协议中域名长度字段只有 1 字节
pub const MAX_DOMAIN_LEN: usize = u8::MAX as usize;

/// 域名解析超时上限，防止慢 DNS 长期占用阻塞线程池
const DNS_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// 单候选地址连接超时
const SINGLE_ADDR_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// 多候选地址（如同时存在 AAAA 与 A 记录）时单个地址的尝试时限
const MULTI_ADDR_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Happy Eyeballs (RFC 8305)：前一候选地址在 250ms 内未完成建连即并发启动下一候选地址
const HAPPY_EYEBALLS_DELAY: Duration = Duration::from_millis(250);

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

impl From<SocketAddr> for NetAddr {
    fn from(addr: SocketAddr) -> Self {
        match addr.ip() {
            IpAddr::V4(ip) => NetAddr::V4(ip, addr.port()),
            IpAddr::V6(ip) => NetAddr::V6(ip, addr.port()),
        }
    }
}

fn invalid_input(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
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

    /// 编码后的字节长度: ATYP(1) + Addr + Port(2)
    pub fn bytes_len(&self) -> usize {
        match self {
            NetAddr::V4(..) => 7,
            NetAddr::Domain(domain, ..) => 4 + domain.len(),
            NetAddr::V6(..) => 19,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            NetAddr::V4(_, port) | NetAddr::Domain(_, port) | NetAddr::V6(_, port) => *port,
        }
    }

    /// 目标是 IP 时直接返回 SocketAddr；域名返回 None
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match self {
            NetAddr::V4(ip, port) => Some(SocketAddr::from((*ip, *port))),
            NetAddr::V6(ip, port) => Some(SocketAddr::from((*ip, *port))),
            NetAddr::Domain(..) => None,
        }
    }

    /// 解析为候选 SocketAddr 列表（IP 直接返回单元素，域名带超时返回全部解析结果）
    pub async fn resolve_all(&self) -> io::Result<Vec<SocketAddr>> {
        match self {
            NetAddr::Domain(host, port) => {
                if host.is_empty() {
                    return Err(invalid_input("Empty domain"));
                }
                let resolved = tokio::time::timeout(
                    DNS_RESOLVE_TIMEOUT,
                    tokio::net::lookup_host((host.as_str(), *port)),
                )
                .await
                .map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("DNS lookup timed out for {}", host),
                    )
                })?
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::HostUnreachable,
                        format!("DNS lookup failed for {}: {}", host, e),
                    )
                })?;
                let addrs: Vec<SocketAddr> = resolved.collect();
                if addrs.is_empty() {
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("no address for {}", host),
                    ));
                }
                Ok(addrs)
            }
            _ => Ok(vec![self.socket_addr().expect("IP address")]),
        }
    }

    /// 解析为单个 SocketAddr（域名取第一条解析结果）
    pub async fn resolve(&self) -> io::Result<SocketAddr> {
        self.resolve_all()
            .await
            .map(|addrs| addrs.into_iter().next().expect("non-empty"))
    }

    /// 建立到该地址的 TCP 连接。
    ///
    /// IP 直接按 SocketAddr 连接；域名先带超时解析，再按单候选限时依次尝试全部解析结果，
    /// 避免排在前面的不可达/黑洞地址（如无路由的 AAAA）耗尽整次连接时限。
    pub async fn connect_tcp(&self) -> io::Result<TcpStream> {
        let candidates = self.resolve_all().await?;
        let per_addr_timeout = if candidates.len() > 1 {
            MULTI_ADDR_CONNECT_TIMEOUT
        } else {
            SINGLE_ADDR_CONNECT_TIMEOUT
        };
        connect_tcp_candidates(&candidates, per_addr_timeout).await
    }

    /// 编码追加到 buf: ATYP(1) + Addr + Port(2)
    pub fn write_to_buf(&self, buf: &mut Vec<u8>) -> io::Result<()> {
        match self {
            NetAddr::V4(ip, port) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
            NetAddr::Domain(domain, port) => {
                let bytes = domain.as_bytes();
                if bytes.len() > MAX_DOMAIN_LEN {
                    return Err(invalid_input("Domain too long"));
                }
                buf.push(ATYP_DOMAIN);
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
                buf.extend_from_slice(&port.to_be_bytes());
            }
            NetAddr::V6(ip, port) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&ip.octets());
                buf.extend_from_slice(&port.to_be_bytes());
            }
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(self.bytes_len());
        self.write_to_buf(&mut buf)?;
        Ok(buf)
    }

    /// 从字节切片解析地址: ATYP(1) + Addr + Port(2)
    ///
    /// 返回地址以及消耗的字节数
    pub fn parse(data: &[u8]) -> io::Result<(Self, usize)> {
        let (&atyp, rest) = data
            .split_first()
            .ok_or_else(|| invalid_input("Data too short"))?;

        let (addr, consumed) = match atyp {
            ATYP_IPV4 => {
                let bytes: [u8; 4] = rest
                    .get(..4)
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| invalid_input("Invalid IPv4 packet: data too short"))?;
                (IpOrDomain::V4(Ipv4Addr::from(bytes)), 4)
            }
            ATYP_DOMAIN => {
                let len = *rest
                    .first()
                    .ok_or_else(|| invalid_input("Invalid Domain packet: missing length byte"))?
                    as usize;
                let domain_bytes = rest
                    .get(1..1 + len)
                    .ok_or_else(|| invalid_input("Invalid Domain packet: data too short"))?;
                let domain = String::from_utf8(domain_bytes.to_vec())
                    .map_err(|_| invalid_input("Invalid Domain encoding"))?;
                (IpOrDomain::Domain(domain), 1 + len)
            }
            ATYP_IPV6 => {
                let bytes: [u8; 16] = rest
                    .get(..16)
                    .and_then(|b| b.try_into().ok())
                    .ok_or_else(|| invalid_input("Invalid IPv6 packet: data too short"))?;
                (IpOrDomain::V6(Ipv6Addr::from(bytes)), 16)
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported ATYP: {}", atyp),
                ));
            }
        };

        let port_bytes: [u8; 2] = rest
            .get(consumed..consumed + 2)
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| invalid_input("Invalid address: missing port"))?;
        let port = u16::from_be_bytes(port_bytes);

        Ok((addr.with_port(port), 1 + consumed + 2))
    }

    /// 从 AsyncRead 流中读取并解析地址
    pub async fn read_from<R>(stream: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let atyp = stream.read_u8().await?;
        let addr = match atyp {
            ATYP_IPV4 => {
                let mut ip_bytes = [0u8; 4];
                stream.read_exact(&mut ip_bytes).await?;
                IpOrDomain::V4(Ipv4Addr::from(ip_bytes))
            }
            ATYP_DOMAIN => {
                let len = stream.read_u8().await? as usize;
                let mut domain_bytes = vec![0u8; len];
                stream.read_exact(&mut domain_bytes).await?;
                let domain = String::from_utf8(domain_bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                IpOrDomain::Domain(domain)
            }
            ATYP_IPV6 => {
                let mut ip_bytes = [0u8; 16];
                stream.read_exact(&mut ip_bytes).await?;
                IpOrDomain::V6(Ipv6Addr::from(ip_bytes))
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported ATYP: {}", atyp),
                ));
            }
        };
        let port = stream.read_u16().await?;
        Ok(addr.with_port(port))
    }

    /// 将地址序列化并写入流
    pub async fn write_to<W>(&self, stream: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        stream.write_all(&self.to_bytes()?).await
    }
}

/// 按 RFC 8305 将候选地址按地址族交替排列（如 IPv6、IPv4 交错），避免同一不可达地址族连续排在前面。
fn interleave_address_families(candidates: &[SocketAddr]) -> Vec<SocketAddr> {
    let first_is_v6 = candidates[0].is_ipv6();
    let (primary, secondary): (Vec<SocketAddr>, Vec<SocketAddr>) = candidates
        .iter()
        .copied()
        .partition(|addr| addr.is_ipv6() == first_is_v6);

    let mut result = Vec::with_capacity(candidates.len());
    let mut p = primary.into_iter();
    let mut s = secondary.into_iter();
    loop {
        match (p.next(), s.next()) {
            (Some(a), Some(b)) => {
                result.push(a);
                result.push(b);
            }
            (Some(a), None) => result.push(a),
            (None, Some(b)) => result.push(b),
            (None, None) => break,
        }
    }
    result
}

fn spawn_connect_attempt(
    tasks: &mut tokio::task::JoinSet<io::Result<TcpStream>>,
    addr: SocketAddr,
    per_addr_timeout: Duration,
) {
    tasks.spawn(async move {
        tokio::time::timeout(per_addr_timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect to {} timed out", addr),
                )
            })?
    });
}

/// Happy Eyeballs 并发交错竞速连接候选地址，首个连接成功即取消其余尝试并配置 `TCP_NODELAY` 与 Keepalive。
pub async fn connect_tcp_candidates(
    candidates: &[SocketAddr],
    per_addr_timeout: Duration,
) -> io::Result<TcpStream> {
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "no candidate addresses",
        ));
    }
    if candidates.len() == 1 {
        let stream = tokio::time::timeout(per_addr_timeout, TcpStream::connect(candidates[0]))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("connect to {} timed out", candidates[0]),
                )
            })??;
        let _ = configure_tcp_stream(&stream);
        return Ok(stream);
    }

    let ordered = interleave_address_families(candidates);
    let mut tasks = tokio::task::JoinSet::new();
    let mut next_idx = 1usize;
    let mut last_err = None;

    spawn_connect_attempt(&mut tasks, ordered[0], per_addr_timeout);

    loop {
        if next_idx < ordered.len() {
            tokio::select! {
                Some(join_res) = tasks.join_next() => {
                    match join_res {
                        Ok(Ok(stream)) => {
                            tasks.abort_all();
                            let _ = configure_tcp_stream(&stream);
                            return Ok(stream);
                        }
                        Ok(Err(e)) => {
                            last_err = Some(e);
                            spawn_connect_attempt(&mut tasks, ordered[next_idx], per_addr_timeout);
                            next_idx += 1;
                        }
                        Err(join_err) => {
                            last_err = Some(io::Error::other(join_err));
                        }
                    }
                }
                _ = tokio::time::sleep(HAPPY_EYEBALLS_DELAY) => {
                    spawn_connect_attempt(&mut tasks, ordered[next_idx], per_addr_timeout);
                    next_idx += 1;
                }
            }
        } else {
            let Some(join_res) = tasks.join_next().await else {
                break;
            };
            match join_res {
                Ok(Ok(stream)) => {
                    tasks.abort_all();
                    let _ = configure_tcp_stream(&stream);
                    return Ok(stream);
                }
                Ok(Err(e)) => last_err = Some(e),
                Err(join_err) => last_err = Some(io::Error::other(join_err)),
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no candidate addresses")))
}

/// 解析过程中的中间态（端口在最后才读到）
enum IpOrDomain {
    V4(Ipv4Addr),
    Domain(String),
    V6(Ipv6Addr),
}

impl IpOrDomain {
    fn with_port(self, port: u16) -> NetAddr {
        match self {
            IpOrDomain::V4(ip) => NetAddr::V4(ip, port),
            IpOrDomain::Domain(host) => NetAddr::Domain(host, port),
            IpOrDomain::V6(ip) => NetAddr::V6(ip, port),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_roundtrip_all_types() {
        let addrs = [
            NetAddr::V4(Ipv4Addr::new(1, 2, 3, 4), 80),
            NetAddr::Domain("example.com".into(), 443),
            NetAddr::V6(Ipv6Addr::LOCALHOST, 8080),
        ];
        for addr in addrs {
            let bytes = addr.to_bytes().unwrap();
            assert_eq!(bytes.len(), addr.bytes_len());
            assert_eq!(NetAddr::parse(&bytes).unwrap(), (addr.clone(), bytes.len()));
            let read = NetAddr::read_from(&mut Cursor::new(bytes)).await.unwrap();
            assert_eq!(read, addr);
        }
    }

    #[test]
    fn test_overlong_domain_is_rejected() {
        let addr = NetAddr::Domain("a".repeat(MAX_DOMAIN_LEN + 1), 80);
        assert!(addr.to_bytes().is_err());
    }

    #[test]
    fn test_parse_truncated_port() {
        assert!(NetAddr::parse(&[ATYP_IPV4, 1, 2, 3, 4, 0]).is_err());
    }

    #[tokio::test]
    async fn test_connect_ipv6_literal() {
        // IPv6 目标此前会被拼成 "[::1]" 去做 DNS 查询而连接失败
        let Ok(listener) = tokio::net::TcpListener::bind("[::1]:0").await else {
            return; // 环境不支持 IPv6
        };
        let addr = NetAddr::from(listener.local_addr().unwrap());
        let (conn, accepted) = tokio::join!(addr.connect_tcp(), listener.accept());
        assert!(conn.is_ok());
        assert!(accepted.is_ok());
    }

    #[tokio::test]
    async fn test_connect_tcp_candidates_falls_back_on_failure() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let good_addr = listener.local_addr().unwrap();

        // 找一个已关闭的本地端口作为失败首选候选
        let dead_sock = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead_sock.local_addr().unwrap();
        drop(dead_sock);

        let candidates = [dead_addr, good_addr];
        let (conn, accepted) = tokio::join!(
            connect_tcp_candidates(&candidates, Duration::from_millis(500)),
            listener.accept(),
        );
        assert!(conn.is_ok());
        assert!(accepted.is_ok());
    }
}
