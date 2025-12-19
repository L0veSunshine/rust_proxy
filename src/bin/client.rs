use anyhow::{Result, anyhow};
use clap::Parser;
use rust_proxy::api::client::start_stat_api;
use rust_proxy::{client, default_value, init_logger};
use tracing::info;
use uuid::Uuid;

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
    // 尝试解析key为UUID
    let key_uuid = cli
        .key
        .parse::<Uuid>()
        .map_err(|_| anyhow!("error key format"))?;
    // 初始化日志
    let _guard = init_logger("client", &cli.log_level, cli.log_rotate_size);

    // 业务逻辑
    tokio::spawn(async move {
        start_stat_api(cli.api_port).await;
    });

    info!("Client will connect to remote {}", cli.remote);
    client::run(cli.local, cli.remote, cli.ca_path, key_uuid).await
}
