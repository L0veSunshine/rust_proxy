use clap::Parser;
use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// 运行模式： "server" 或 "client"
    #[arg(index = 1)]
    mode: String,

    /// 监听地址和端口 (服务器模式) 或 SOCKS5 代理地址 (客户端模式)
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    listen_addr: String,

    /// 目标服务器地址和端口 (客户端模式)
    #[arg(short, long, default_value = "127.0.0.1:8080")]
    remote_addr: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mode_str: &str = &args.mode;

    match mode_str {
        "server" => {
            println!("以服务器模式启动，监听地址: {}", args.listen_addr);
            run_server(&args.listen_addr).await?;
        }
        "client" => {
            println!(
                "以客户端模式启动，SOCKS5 代理: {}, 目标服务器: {}",
                args.listen_addr, args.remote_addr
            );
            run_client(&args.listen_addr, &args.remote_addr).await?;
        }
        _ => {
            eprintln!("错误的模式。请使用 'server' 或 'client'。");
        }
    }

    Ok(())
}

async fn run_server(listen_addr: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind(listen_addr).await?;
    println!("SOCKS5 服务器正在监听: {}", listen_addr);

    loop {
        let (stream, _) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream).await {
                eprintln!("处理连接时出错: {}", e);
            }
        });
    }
}

async fn handle_connection(mut stream: TcpStream) -> anyhow::Result<()> {
    // SOCKS5 握手
    let mut buf = [0; 256];

    // 读取客户端的认证方法请求
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }

    // SOCKS 版本号，必须是 0x05
    if buf[0] != 0x05 {
        return Err(anyhow::anyhow!("不支持的 SOCKS 版本"));
    }

    // 服务器选择“无认证”方法 (0x00)
    stream.write_all(&[0x05, 0x00]).await?;

    // 读取客户端的连接请求
    let n = stream.read(&mut buf).await?;
    if n < 7 {
        return Err(anyhow::anyhow!("无效的连接请求"));
    }

    // 检查 SOCKS 版本和命令
    if buf[0] != 0x05 || buf[1] != 0x01 {
        // 0x01 表示 CONNECT 命令
        stream
            .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?; // 不支持的命令
        return Err(anyhow::anyhow!("不支持的命令"));
    }

    // 解析目标地址
    let target_addr = match buf[3] {
        0x01 => {
            // IPv4
            let addr = std::net::Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            format!("{}:{}", addr, port)
        }
        0x03 => {
            // 域名
            let domain_len = buf[4] as usize;
            let domain = String::from_utf8_lossy(&buf[5..5 + domain_len]);
            let port = u16::from_be_bytes([buf[5 + domain_len], buf[5 + domain_len + 1]]);
            format!("{}:{}", domain, port)
        }
        0x04 => {
            // IPv6
            // 为简化起见，此处未实现
            stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?; // 不支持的地址类型
            return Err(anyhow::anyhow!("不支持 IPv6"));
        }
        _ => {
            return Err(anyhow::anyhow!("无效的地址类型"));
        }
    };

    println!("正在连接到目标地址: {}", target_addr);
    let mut target_stream = match TcpStream::connect(&target_addr).await {
        Ok(stream) => stream,
        Err(e) => {
            eprintln!("连接到 {} 失败: {}", target_addr, e);
            // 响应失败
            stream
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?; // 主机不可达
            return Err(e.into());
        }
    };
    println!("已成功连接到 {}", target_addr);

    // 响应成功
    let local_addr = stream.local_addr()?;
    let ip = match local_addr.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => return Err(anyhow::anyhow!("不支持 IPv6")),
    };
    let port = local_addr.port().to_be_bytes();
    let mut reply = vec![0x05, 0x00, 0x00, 0x01];
    reply.extend_from_slice(&ip);
    reply.extend_from_slice(&port);
    stream.write_all(&reply).await?;

    // 开始代理数据
    let (mut client_reader, mut client_writer) = stream.split();
    let (mut target_reader, mut target_writer) = target_stream.split();

    let client_to_target = io::copy(&mut client_reader, &mut target_writer);
    let target_to_client = io::copy(&mut target_reader, &mut client_writer);

    tokio::select! {
        result = client_to_target => {
            match result {
                Ok(bytes) => println!("客户端到目标服务器传输了 {} 字节", bytes),
                Err(e) => eprintln!("从客户端到目标服务器传输数据时出错: {}", e),
            }
        }
        result = target_to_client => {
            match result {
                Ok(bytes) => println!("目标服务器到客户端传输了 {} 字节", bytes),
                Err(e) => eprintln!("从目标服务器到客户端传输数据时出错: {}", e),
            }
        }
    }

    Ok(())
}

async fn run_client(proxy_addr: &str, remote_addr: &str) -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let local_port = listener.local_addr()?.port();
    println!("客户端监听在: 127.0.0.1:{}", local_port);

    loop {
        let (mut inbound, _) = listener.accept().await?;
        let proxy_addr = proxy_addr.to_string();
        let remote_addr = remote_addr.to_string();

        tokio::spawn(async move {
            let mut outbound = match TcpStream::connect(&proxy_addr).await {
                Ok(stream) => stream,
                Err(e) => {
                    eprintln!("无法连接到 SOCKS5 代理 {}: {}", proxy_addr, e);
                    return;
                }
            };

            // SOCKS5 握手
            outbound.write_all(&[0x05, 0x01, 0x00]).await.unwrap(); // 版本, 1个认证方法, 无认证
            let mut buf = [0; 2];
            outbound.read_exact(&mut buf).await.unwrap();
            if buf != [0x05, 0x00] {
                eprintln!("代理服务器的认证响应不正确");
                return;
            }

            // 发送连接请求
            let remote_parts: Vec<&str> = remote_addr.split(':').collect();
            let remote_host = remote_parts[0];
            let remote_port: u16 = remote_parts[1].parse().unwrap();

            let mut request = vec![0x05, 0x01, 0x00, 0x03, remote_host.len() as u8];
            request.extend_from_slice(remote_host.as_bytes());
            request.extend_from_slice(&remote_port.to_be_bytes());
            outbound.write_all(&request).await.unwrap();

            // 读取代理的响应
            let mut buf = [0; 10];
            outbound.read_exact(&mut buf).await.unwrap();
            if buf[1] != 0x00 {
                eprintln!("代理服务器无法连接到目标地址");
                return;
            }

            println!("SOCKS5 代理连接建立成功");

            // 开始代理数据
            let (mut ri, mut wi) = inbound.split();
            let (mut ro, mut wo) = outbound.split();

            let client_to_proxy = io::copy(&mut ri, &mut wo);
            let proxy_to_client = io::copy(&mut ro, &mut wi);

            tokio::select! {
                result = client_to_proxy => {
                    match result {
                        Ok(bytes) => println!("客户端到代理传输了 {} 字节", bytes),
                        Err(e) => eprintln!("从客户端到代理传输数据时出错: {}", e),
                    }
                }
                result = proxy_to_client => {
                    match result {
                        Ok(bytes) => println!("代理到客户端传输了 {} 字节", bytes),
                        Err(e) => eprintln!("从代理到客户端传输数据时出错: {}", e),
                    }
                }
            }
        });
    }
}
