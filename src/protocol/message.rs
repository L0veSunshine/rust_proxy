use crate::protocol::net_addr::NetAddr;
use anyhow::{bail, Result};
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

#[derive(Debug, Copy, Clone)]
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

pub async fn read_server_response<R>(stream: &mut R) -> Result<(Uuid, Command, NetAddr)>
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
    Ok((uuid, cmd, addr))
}

pub async fn response_to_client<W>(stream: &mut W, status: &Response) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    stream.write_u8((*status).into()).await?;
    Ok(())
}
