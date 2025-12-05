use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

/// [同步] 将 u16 编码为 VarInt 并写入 Vec
pub fn encode_varint(value: u16, buf: &mut Vec<u8>) {
    if value < 128 {
        // 1 字节模式: 0xxxxxxx
        buf.push(value as u8);
    } else if value < 16384 {
        // 2 字节模式: 10xxxxxx yyyyyyyy
        // 高 6 位放入 byte1，低 8 位放入 byte2
        buf.push((0x80 | (value >> 8)) as u8);
        buf.push((value & 0xFF) as u8);
    } else {
        // 3 字节模式: 11xxxxxx yyyyyyyy zzzzzzzz
        // 这里的 11xxxxxx 全为 0 (因为 u16 最大 65535，不需要额外的位)
        // 实际上就是 0xC0 + 大端序 u16
        buf.push(0xC0);
        buf.push((value >> 8) as u8);
        buf.push((value & 0xFF) as u8);
    }
}

/// [异步] 从流中读取 VarInt 解析为 u16
pub async fn read_varint<R: AsyncRead + Unpin>(stream: &mut R) -> io::Result<u16> {
    let b1 = stream.read_u8().await?;

    // 检查前缀位
    if (b1 & 0x80) == 0 {
        // 0xxxxxxx -> 1 字节
        Ok(b1 as u16)
    } else if (b1 & 0xC0) == 0x80 {
        // 10xxxxxx -> 2 字节
        let b2 = stream.read_u8().await?;
        let high = (b1 & 0x3F) as u16;
        let low = b2 as u16;
        Ok((high << 8) | low)
    } else {
        // 11xxxxxx -> 3 字节
        // 这是一个兜底，用于处理 > 16383 的大包
        let b2 = stream.read_u8().await?;
        let b3 = stream.read_u8().await?;

        // 校验高位是否为0 (因为我们只返回 u16)
        if (b1 & 0x3F) != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "VarInt too large for u16",
            ));
        }

        let mid = b2 as u16;
        let low = b3 as u16;
        Ok((mid << 8) | low)
    }
}
