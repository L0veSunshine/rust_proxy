use crate::protocol::net_addr::NetAddr;
use crate::protocol::socks5::parse_udp_packet;
use anyhow::{Result, bail};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub const MAGIC: u8 = 0xCD;
pub const MESSAGE_VERSION: u8 = 0x01;

pub const TYPE: u8 = 0x01;

#[derive(Debug, Copy, Clone)]
pub enum Command {
    TcpConnect = 0x01,
    UdpAssociate = 0x02,
}

impl From<Command> for u8 {
    fn from(c: Command) -> Self {
        c as u8
    }
}

impl TryFrom<u8> for Command {
    type Error = io::Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Command::TcpConnect),
            0x02 => Ok(Command::UdpAssociate),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unknown command",
            )),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum Response {
    Success = 0x01,
    Unauthorized = 0x02,
    Rejected = 0x03,
}

impl From<Response> for u8 {
    fn from(r: Response) -> Self {
        r as u8
    }
}

impl TryFrom<u8> for Response {
    type Error = io::Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Response::Success),
            0x02 => Ok(Response::Unauthorized),
            0x03 => Ok(Response::Rejected),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unknown response",
            )),
        }
    }
}

pub async fn client_hello<W>(
    stream: &mut W,
    user_token: &Uuid,
    cmd: &Command,
    addr: &NetAddr,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    // 1. Header
    stream.write_u8(MAGIC).await?; // MAGIC
    stream.write_u8(MESSAGE_VERSION).await?; // Ver
    stream.write_u8(TYPE).await?; // Type
    stream.write_all(user_token.as_bytes()).await?; // Token
    stream.write_u8(u8::from(*cmd)).await?; // Cmd

    // 2. Target Address
    addr.write_to(stream).await?;

    // 3. Random Padding
    let pad_len = rand::random_range(16..=128); // 16-255
    stream.write_u8(pad_len).await?;

    let padding = vec![0u8; pad_len as usize];
    stream.write_all(&padding).await?;
    Ok(())
}

pub async fn read_client_request<R>(stream: &mut R) -> Result<(Uuid, Command, NetAddr)>
where
    R: AsyncRead + Unpin,
{
    let header = stream.read_u8().await?;
    if header != MAGIC {
        bail!("Unknown protocol");
    };
    let version = stream.read_u8().await?;
    let type_id = stream.read_u8().await?;
    if version != MESSAGE_VERSION || type_id != TYPE {
        bail!("Unsupported protocol version");
    };
    let mut uuid = [0u8; 16];
    stream.read_exact(&mut uuid).await?;
    let uuid = Uuid::from_bytes(uuid);
    let cmd = stream.read_u8().await?.try_into()?;
    let addr = NetAddr::read_from(stream).await?;

    // 读 Padding 长度
    let pad_len = stream.read_u8().await?;

    // 跳过 Padding
    if pad_len > 0 {
        let mut limiter = stream.take(pad_len as u64);
        let mut sink = tokio::io::sink();
        tokio::io::copy(&mut limiter, &mut sink).await?;
    }
    Ok((uuid, cmd, addr))
}

pub async fn response_to_client<W>(stream: &mut W, status: &Response) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let random_len = rand::random_range(16..=128);
    stream.write_u8(random_len + 1).await?;
    stream.write_u8((*status).into()).await?;
    let padding = vec![0u8; random_len as usize];
    stream.write_all(&padding).await?;
    Ok(())
}

pub async fn read_response_from_server<R>(stream: &mut R) -> Result<Response>
where
    R: AsyncRead + Unpin,
{
    let length = stream.read_u8().await?;
    let status = stream.read_u8().await?;
    let padding_length = length as usize - 1;
    let mut limiter = stream.take(padding_length as u64);
    let mut sink = tokio::io::sink();
    tokio::io::copy(&mut limiter, &mut sink).await?;
    Ok(status.try_into()?)
}

pub fn build_udp_frame(addr: &NetAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let addr_bytes: Vec<u8> = addr.into();
    // 计算 Body Len
    let body_len = addr_bytes.len() + payload.len();

    // UDP 长度字段是 u16，检查溢出
    if body_len > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP frame too large",
        ));
    };
    // 构建最终帧
    // 总容量 = 2 (Length) + Addr + Payload
    let mut frame = Vec::with_capacity(2 + body_len);

    // 写入长度 (Big Endian)
    frame.extend_from_slice(&(body_len as u16).to_be_bytes());

    // 写入地址
    frame.extend_from_slice(&addr_bytes);

    // 写入 Payload
    frame.extend_from_slice(payload);

    Ok(frame)
}

pub async fn read_udp_frame<R>(stream: &mut R) -> io::Result<(NetAddr, Vec<u8>)>
where
    R: AsyncRead + Unpin,
{
    // 1. 读取 Body Len (2 字节)
    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let body_len = u16::from_be_bytes(len_buf) as usize;

    if body_len == 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Empty UDP body"));
    }

    // 2. 读取 Body (包含 Address + Payload)
    let mut body = vec![0u8; body_len];
    stream.read_exact(&mut body).await?;

    // 3. 从 Body 头部解析 NetAddr
    let (addr, consumed_len) = parse_udp_packet(&body)?;

    // 4. 截取 Payload
    // 剩下的部分就是 Payload
    if consumed_len > body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Parsed address exceeds body length",
        ));
    }

    // 使用 to_vec() 将切片转换为 Vec<u8>
    let payload = body[consumed_len..].to_vec();

    Ok((addr, payload))
}
