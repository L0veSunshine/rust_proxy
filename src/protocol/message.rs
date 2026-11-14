use crate::protocol::net_addr::NetAddr;
use crate::protocol::utils::generate_gaussian_padding;
use crate::protocol::var_int::{encode_varint, read_varint};
use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use std::io;
use std::io::{Error, ErrorKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

pub const MESSAGE_VERSION: u8 = 0x01;

pub const TYPE: u8 = 0x01;

/// Client Hello 的 Padding 长度分布：N(360, 60²)，并截断到 [16, 600]。
///
/// 上限保证 "Header(19) + 最长地址(258) + PadLen(2) + Padding" 不超过
/// 服务端 1024 字节的握手缓冲区。
const HELLO_PADDING_MEAN: f64 = 360.0;
const HELLO_PADDING_STD_DEV: f64 = 60.0;
pub const HELLO_PADDING_MIN: u16 = 16;
pub const HELLO_PADDING_MAX: u16 = 600;

/// Server Response 的 Padding 长度分布：N(150, 25²)，截断到 [0, 254]（Length 字段为 1 字节）
const RESPONSE_PADDING_MEAN: f64 = 150.0;
const RESPONSE_PADDING_STD_DEV: f64 = 25.0;
const RESPONSE_PADDING_MAX: u16 = 254;

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
    type Error = Error;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Command::TcpConnect),
            0x02 => Ok(Command::UdpAssociate),
            _ => Err(Error::new(ErrorKind::InvalidInput, "Unknown command")),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Response {
    Success = 0x01,
    Rejected = 0x02,
    HostUnreachable = 0x03,
    ConnectionRefused = 0x04,
    TimedOut = 0x05,
}

impl Response {
    /// 将服务端连接目标时的 I/O 错误映射为协议状态码
    pub fn from_io_error(err: &io::Error) -> Self {
        match err.kind() {
            ErrorKind::ConnectionRefused => Response::ConnectionRefused,
            ErrorKind::TimedOut => Response::TimedOut,
            ErrorKind::NotFound
            | ErrorKind::HostUnreachable
            | ErrorKind::NetworkUnreachable
            | ErrorKind::AddrNotAvailable => Response::HostUnreachable,
            _ => Response::Rejected,
        }
    }
}

impl From<Response> for u8 {
    fn from(r: Response) -> Self {
        r as u8
    }
}

impl TryFrom<u8> for Response {
    type Error = Error;
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Response::Success),
            0x02 => Ok(Response::Rejected),
            0x03 => Ok(Response::HostUnreachable),
            0x04 => Ok(Response::ConnectionRefused),
            0x05 => Ok(Response::TimedOut),
            _ => Err(Error::new(ErrorKind::InvalidInput, "Unknown response")),
        }
    }
}

pub async fn client_hello<W>(
    stream: &mut W,
    user_token: &Uuid,
    cmd: &Command,
    addr: &NetAddr,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    client_hello_with_payload(stream, user_token, cmd, addr, &[]).await
}

/// 将握手头与可选的 0-RTT 初始载荷一次性拼包写出，避免拆成多个 TLS record。
pub async fn client_hello_with_payload<W>(
    stream: &mut W,
    user_token: &Uuid,
    cmd: &Command,
    addr: &NetAddr,
    initial_payload: &[u8],
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let pad_len = generate_gaussian_padding(
        HELLO_PADDING_MEAN,
        HELLO_PADDING_STD_DEV,
        HELLO_PADDING_MIN,
        HELLO_PADDING_MAX,
    );

    let mut buf = Vec::with_capacity(
        16 + 3 + addr.bytes_len() + 2 + pad_len as usize + initial_payload.len(),
    );
    // 1. Header
    buf.extend_from_slice(user_token.as_bytes()); // Token
    buf.push(MESSAGE_VERSION); // Ver
    buf.push(TYPE); // Type
    buf.push(u8::from(*cmd)); // Cmd
    // 2. Target Address
    addr.write_to_buf(&mut buf)?;
    // 3. Random Padding
    buf.extend_from_slice(&pad_len.to_be_bytes());
    buf.resize(buf.len() + pad_len as usize, 0);
    // 4. Optional 0-RTT Payload
    if !initial_payload.is_empty() {
        buf.extend_from_slice(initial_payload);
    }

    stream.write_all(&buf).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_client_request<R>(stream: &mut R) -> io::Result<(Uuid, Command, NetAddr)>
where
    R: AsyncRead + Unpin,
{
    let mut uuid = [0u8; 16];
    stream.read_exact(&mut uuid).await?;
    let version = stream.read_u8().await?;
    let type_id = stream.read_u8().await?;
    if version != MESSAGE_VERSION || type_id != TYPE {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Unsupported protocol version",
        ));
    };
    let uuid = Uuid::from_bytes(uuid);
    let cmd = stream.read_u8().await?.try_into()?;
    let addr = NetAddr::read_from(stream).await?;

    // 读 Padding 长度并校验上限，防止非本协议流量因超大长度字段一直等待读满缓冲区
    let pad_len = stream.read_u16().await?;
    if pad_len > HELLO_PADDING_MAX {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Client hello padding exceeds limit",
        ));
    }

    // 跳过 Padding
    if pad_len > 0 {
        let mut limiter = stream.take(pad_len as u64);
        let mut sink = tokio::io::sink();
        let consumed = tokio::io::copy(&mut limiter, &mut sink).await?;

        // 如果 Cursor 里的数据少于 pad_len，说明内存里的包不完整
        if consumed < pad_len as u64 {
            // 手动抛出错误，外层 loop 继续读 TCP
            return Err(Error::from(ErrorKind::UnexpectedEof));
        }
    }
    Ok((uuid, cmd, addr))
}

pub async fn response_to_client<W>(stream: &mut W, status: &Response) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let random_len = generate_gaussian_padding(
        RESPONSE_PADDING_MEAN,
        RESPONSE_PADDING_STD_DEV,
        0,
        RESPONSE_PADDING_MAX,
    ) as usize;
    let mut buf = [0u8; 2 + RESPONSE_PADDING_MAX as usize];
    buf[0] = random_len as u8 + 1;
    buf[1] = (*status).into();
    stream.write_all(&buf[..2 + random_len]).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn read_response_from_server<R>(stream: &mut R) -> Result<u8>
where
    R: AsyncRead + Unpin,
{
    let length = stream.read_u8().await?;
    // Length 至少要包含 Status 自身
    let padding_length = length
        .checked_sub(1)
        .ok_or_else(|| anyhow!("Invalid server response length: 0"))?;
    let status = stream.read_u8().await?;
    let mut limiter = stream.take(padding_length as u64);
    let consumed = tokio::io::copy(&mut limiter, &mut tokio::io::sink()).await?;
    if consumed < padding_length as u64 {
        return Err(Error::from(ErrorKind::UnexpectedEof).into());
    }
    Ok(status)
}

/// 把 UDP 帧追加编码到 `frame`：VarInt(BodyLen) + Addr + Payload
///
/// 调用方可复用同一个 Vec，避免每个包都分配内存。
pub fn encode_udp_frame(addr: &NetAddr, payload: &[u8], frame: &mut Vec<u8>) -> io::Result<()> {
    let body_len = addr.bytes_len() + payload.len();

    // 长度字段最多表示 u16
    if body_len > u16::MAX as usize {
        return Err(Error::new(ErrorKind::InvalidInput, "UDP frame too large"));
    };
    frame.reserve(3 + body_len);
    encode_varint(body_len as u16, frame);
    addr.write_to_buf(frame)?;
    frame.extend_from_slice(payload);
    Ok(())
}

pub fn build_udp_frame(addr: &NetAddr, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut frame = Vec::new();
    encode_udp_frame(addr, payload, &mut frame)?;
    Ok(frame)
}

pub async fn read_udp_frame<R>(stream: &mut R) -> io::Result<(NetAddr, Bytes)>
where
    R: AsyncRead + Unpin,
{
    // 1. 读取 Body Len
    let body_len = read_varint(stream).await? as usize;

    if body_len == 0 {
        return Err(Error::new(ErrorKind::InvalidData, "Empty UDP body"));
    }

    // 2. 读取 Body (包含 Address + Payload)
    let mut body = BytesMut::zeroed(body_len);
    stream.read_exact(&mut body).await?;

    // 3. 从 Body 头部解析 NetAddr，剩下的部分就是 Payload
    let (addr, consumed_len) = NetAddr::parse(&body)?;
    let payload = body.freeze().slice(consumed_len..);

    Ok((addr, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_read_udp_frame_zero_copy() {
        // 模拟数据: VarInt(12) + IPv4(7 bytes) + Payload(5 bytes)
        let data = vec![
            12, // varint: body_len = 12
            0x01, 192, 168, 1, 1, // IPv4: 192.168.1.1
            0x00, 0x50, // Port: 80
            b'H', b'e', b'l', b'l', b'o', // Payload
        ];

        let mut cursor = Cursor::new(data);
        let (addr, payload) = read_udp_frame(&mut cursor).await.unwrap();

        assert_eq!(addr.to_string(), "192.168.1.1:80");
        assert_eq!(payload.as_ref(), b"Hello");

        // 验证 Bytes 的零拷贝特性
        let cloned_payload = payload.clone();
        assert_eq!(cloned_payload.as_ref(), b"Hello");
        // clone() 只增加引用计数,不拷贝数据
    }

    #[test]
    fn test_build_udp_frame_zero_copy() {
        let addr = NetAddr::V4(Ipv4Addr::new(192, 168, 1, 1), 80);
        let payload = Bytes::from_static(b"Hello");

        let frame = build_udp_frame(&addr, &payload).unwrap();

        // 验证帧结构
        assert_eq!(frame[0], 12); // body_len
        assert_eq!(frame[1], 0x01); // ATYP
        assert_eq!(&frame[8..], b"Hello"); // payload
    }

    #[tokio::test]
    async fn test_zero_length_response_is_rejected() {
        let mut cursor = Cursor::new(vec![0u8, 0x01]);
        assert!(read_response_from_server(&mut cursor).await.is_err());
    }

    #[tokio::test]
    async fn test_client_hello_roundtrip() {
        let token = Uuid::new_v4();
        let addr = NetAddr::Domain("a".repeat(255), 443);
        let mut buf = Vec::new();
        client_hello(&mut buf, &token, &Command::UdpAssociate, &addr)
            .await
            .unwrap();
        // 最长地址 + 最大 Padding 也必须放进服务端 1024 字节的握手缓冲区
        assert!(buf.len() <= 16 + 3 + addr.bytes_len() + 2 + HELLO_PADDING_MAX as usize);
        assert!(buf.len() <= 1024);

        let (t, cmd, a) = read_client_request(&mut Cursor::new(buf)).await.unwrap();
        assert_eq!(t, token);
        assert!(matches!(cmd, Command::UdpAssociate));
        assert_eq!(a, addr);
    }
}
