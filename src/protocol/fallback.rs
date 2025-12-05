use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::select;

pub async fn handle_fallback(
    initial_data: &[u8],
    mut client_reader: tokio::io::ReadHalf<tokio_rustls::server::TlsStream<TcpStream>>,
    mut client_writer: tokio::io::WriteHalf<tokio_rustls::server::TlsStream<TcpStream>>,
) -> Result<()> {
    // 连接本地 Web 服务器
    let web_server = TcpStream::connect("127.0.0.1:80").await?;

    let (mut web_reader, mut web_writer) = web_server.into_split();

    // 1. 先把刚才“偷看”的数据补发给 Web 服务器
    if !initial_data.is_empty() {
        web_writer.write_all(initial_data).await?;
    }

    // 2. 建立双向转发
    // Client -> Web Server
    let client_to_web =
        tokio::spawn(async move { tokio::io::copy(&mut client_reader, &mut web_writer).await });

    // Web Server -> Client
    let web_to_client =
        tokio::spawn(async move { tokio::io::copy(&mut web_reader, &mut client_writer).await });

    // 等待任一方向结束
    select! {
        _ = client_to_web => {},
        _ = web_to_client => {},
    };

    Ok(())
}
