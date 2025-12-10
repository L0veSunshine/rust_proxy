use anyhow::Result;
use clap::Parser;
use rust_proxy::api::client::start_stat_api;
use rust_proxy::{client, init_logger};

#[derive(Parser, Debug)]
#[command(name = "rust_proxy_client")]
struct ClientCli {
    #[arg(long)]
    key: String,
    #[arg(long, default_value = "127.0.0.1:1080")]
    local: String,
    #[arg(long, default_value = "127.0.0.1:4433")]
    remote: String,
    #[arg(long, default_value_t = 1081)]
    api_port: u16,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = ClientCli::parse();

    // 初始化日志
    init_logger("client");

    // 业务逻辑
    tokio::spawn(async move {
        start_stat_api(cli.api_port).await;
    });

    println!("Client connecting to {} via {}", cli.remote, cli.local);
    client::run(&cli.local, &cli.remote, &cli.key).await
}
