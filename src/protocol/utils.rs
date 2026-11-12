use anyhow::Result;
use clap::ValueEnum;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::f64::consts::PI;
use std::fmt::Display;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, ValueEnum)]
pub enum NATType {
    FullCone = 1,
    Restricted = 2,
    PortRestricted = 3,
}

impl Display for NATType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub fn get_canonical_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(ip) = v6.to_ipv4() {
                IpAddr::V4(ip)
            } else {
                IpAddr::V6(v6)
            }
        }
        v4 => v4,
    }
}

/// 创建一个绑定到双栈 (IPv4 + IPv6) 随机端口的 UDP Socket
pub fn bind_dual_stack_udp() -> Result<tokio::net::UdpSocket> {
    // 1. 创建 IPv6 UDP Socket
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

    // 2. 关键：关闭 IPV6_V6ONLY，允许 IPv4 映射到 IPv6
    // 这样 [::]:port 就能同时接收 IPv4 (::ffff:1.2.3.4) 和 IPv6 流量
    socket.set_only_v6(false)?;

    // 3. 允许端口复用 (可选，对于随机端口绑定不是必须的，但对于固定端口很有用)
    socket.set_reuse_address(true)?;

    // 4. 设置为非阻塞模式 (Tokio 要求)
    socket.set_nonblocking(true)?;

    // 5. 绑定到 [::]:0
    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    socket.bind(&addr.into())?;

    // 6. 转换为 tokio::net::UdpSocket
    // socket2 -> std::net::UdpSocket -> tokio::net::UdpSocket
    let std_udp: std::net::UdpSocket = socket.into();
    let tokio_udp = tokio::net::UdpSocket::from_std(std_udp)?;

    Ok(tokio_udp)
}

/// 把 IPv4 地址转换为 IPv4-mapped IPv6 地址。
///
/// 双栈 UDP socket 绑定在 `[::]` 上，部分平台不接受直接向 IPv4 SocketAddr 发送。
pub fn to_dual_stack(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) => SocketAddr::new(IpAddr::V6(v4.ip().to_ipv6_mapped()), v4.port()),
        v6 => v6,
    }
}

/// 生成符合高斯分布（正态分布）的 Padding 长度
///
/// - `mean`: 均值 (期望的 Padding 大小)
/// - `std_dev`: 标准差 (数据的离散程度，越大越分散)
/// - `min` / `max`: 结果的硬性上下限
pub fn generate_gaussian_padding(mean: f64, std_dev: f64, min: u16, max: u16) -> u16 {
    let mut rng = rand::rng();

    // 1. Box-Muller 变换: 从两个均匀分布生成标准正态分布 N(0, 1)
    let u1: f64 = rng.random();
    let u2: f64 = rng.random();

    // 避免 u1 为 0 导致 ln(0) = -inf
    // 虽然概率极低，但在工业级代码中需要处理
    let u1 = if u1 < f64::EPSILON { f64::EPSILON } else { u1 };

    let z0 = (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos();

    // 2. 调整为 N(mean, std_dev): X = μ + σZ
    let value = mean + std_dev * z0;

    // 3. 限制范围并转为 u16
    value.round().clamp(min as f64, max as f64) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_padding_respects_bounds() {
        for _ in 0..10_000 {
            let len = generate_gaussian_padding(360.0, 600.0, 16, 600);
            assert!((16..=600).contains(&len));
        }
    }
}
