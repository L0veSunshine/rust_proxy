use anyhow::{Result, bail};
use bytes::Bytes;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::fmt::Display;
use std::net::{Ipv6Addr, SocketAddr};
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub const UUID: &str = "8edc51f2-1bf8-42a8-9229-b9014738f617";

#[derive(Serialize, Deserialize, Debug)]
pub enum Command {
    // TCP 请求连接
    Connect {
        addr: String,
    },
    // UDP 开启会话 (Full Cone)
    UdpAssociate {
        nat_type: NATType,
    },
    // TCP 数据
    Data {
        payload: Bytes,
    },
    // UDP 数据 (需要带目标地址)
    UdpData {
        addr: String,
        port: u16,
        payload: Bytes,
    },
}
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

pub async fn write_handshake<S>(stream: &mut S, cmd: &Command) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    // 1. 写 UUID (身份认证)
    let uuid = Uuid::parse_str(UUID)?;
    let uuid_bytes: &[u8; 16] = uuid.as_bytes();
    stream.write_all(uuid_bytes).await?;

    // 2. 生成随机 Padding (抗特征分析)
    let padding_len = rand::random_range(16..128);
    stream.write_u8(padding_len as u8).await?;

    // 3. 写 Padding (全0即可)
    let zeros = vec![0u8; padding_len as usize];
    stream.write_all(&zeros).await?;

    // 4. 写实际指令
    write_packet(stream, cmd).await
}

/// 普通数据包发送 (Length + Bincode)
pub async fn write_packet<S>(stream: &mut S, cmd: &Command) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    // 使用 bincode 序列化
    let body = bincode::serde::encode_to_vec(cmd, bincode::config::standard())?;

    // Length-Prefixed Framing
    stream.write_u32(body.len() as u32).await?;
    stream.write_all(&body).await?;
    stream.flush().await?;
    Ok(())
}

/// 读取并验证握手包
pub async fn read_handshake<S>(stream: &mut S) -> Result<Command>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. 验证 UUID
    let mut uuid = [0u8; 16];
    stream.read_exact(&mut uuid).await?;
    let received_uuid = Uuid::from_bytes(uuid);

    if received_uuid != Uuid::parse_str(UUID)? {
        bail!("Authentication Failed: Invalid UUID");
    }

    // 2. 读 Padding 长度
    let pad_len = stream.read_u8().await?;

    // 3. 跳过 Padding (Discard)
    if pad_len > 0 {
        let mut limiter = stream.take(pad_len as u64);
        let mut sink = io::sink();
        io::copy(&mut limiter, &mut sink).await?;
    }

    // 4. 读取指令
    read_packet(stream).await
}

/// 普通数据包读取
pub async fn read_packet<S>(stream: &mut S) -> Result<Command>
where
    S: AsyncRead + Unpin,
{
    let len = match stream.read_u32().await {
        Ok(n) => n,
        Err(_) => bail!("Stream closed"),
    };

    // 限制最大包大小，防止 OOM 攻击
    if len > 10 * 1024 * 1024 {
        bail!("Packet too large");
    }

    let mut buf = vec![0u8; len as usize];
    stream.read_exact(&mut buf).await?;

    let (cmd, _) = bincode::serde::decode_from_slice(&buf, bincode::config::standard())?;
    Ok(cmd)
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
