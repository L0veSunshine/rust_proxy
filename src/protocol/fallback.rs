use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

const FALLBACK_ADDR: &str = "127.0.0.1:80";

/// 把已解密的 TLS 流量回落到本地 Web 服务器。
///
/// `initial_data` 是握手阶段已经读出的数据，需要先补发给 Web 服务器。
/// 使用 `copy_bidirectional`：两个方向在同一个任务内完成并正确传递半关闭，
/// 不会留下无人管理的后台任务。
pub async fn handle_tls_fallback<S>(initial_data: &[u8], mut client: S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut web_server = TcpStream::connect(FALLBACK_ADDR).await?;
    if !initial_data.is_empty() {
        web_server.write_all(initial_data).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut web_server).await?;
    Ok(())
}

pub async fn handle_tcp_fallback(mut client_socket: TcpStream) -> Result<()> {
    let mut web_server = TcpStream::connect(FALLBACK_ADDR).await?;
    tokio::io::copy_bidirectional(&mut client_socket, &mut web_server).await?;
    Ok(())
}
