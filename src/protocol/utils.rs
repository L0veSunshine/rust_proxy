use anyhow::Result;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::fmt::Display;
use std::net::{Ipv6Addr, SocketAddr};
pub const UUID: &str = "8edc51f2-1bf8-42a8-9229-b9014738f617";

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
