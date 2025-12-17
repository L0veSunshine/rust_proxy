use anyhow::Result;
use clap::Parser;
use rust_proxy::api::client::start_stat_api;
use rust_proxy::{client, default_value, init_logger};

#[derive(Parser, Debug)]
#[command(name = "rust_proxy_client")]
struct ClientCli {
    #[arg(long)]
    key: String,
    #[arg(long)]
    remote: String,
    #[arg(long, default_value = "127.0.0.1:1080")]
    local: String,
    #[arg(long, default_value = "cert.pem")]
    ca_path: String,
    #[arg(long, default_value_t = 1081)]
    api_port: u16,
    #[arg(long, default_value = "info")]
    log_level: String,
    #[arg(long, default_value_t = client_log_rotate_size())]
    log_rotate_size: u64,
}

default_value!(client_log_rotate_size, u64, 10 * 1024 * 1024);

#[tokio::main]
async fn main() -> Result<()> {
    let cli = ClientCli::parse();

    // 初始化日志
    init_logger("client", &cli.log_level, cli.log_rotate_size);

    // 业务逻辑
    tokio::spawn(async move {
        start_stat_api(cli.api_port).await;
    });

    println!("Client connecting to {} via {}", cli.remote, cli.local);
    client::run(&cli.local, &cli.remote, &cli.ca_path, &cli.key).await
}
