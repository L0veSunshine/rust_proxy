use anyhow::Result;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::select;

pub async fn handle_tls_fallback(
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
    }

    Ok(())
}

pub async fn handle_tcp_fallback(mut client_socket: &mut TcpStream) -> Result<()> {
    let mut web_server = TcpStream::connect("127.0.0.1:80").await?;

    // 使用 copy_bidirectional 进行双向拷贝，比手动 spawn 两个任务更高效简洁
    tokio::io::copy_bidirectional(&mut client_socket, &mut web_server).await?;

    Ok(())
}
