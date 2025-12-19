use anyhow::Result;
use rust_proxy::api::common::ServerStatistic;
use rust_proxy::api::server::start_api_server;
use rust_proxy::config::ServerConfig;
use rust_proxy::user_manager::UserManager;
use rust_proxy::{init_logger, server};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    let configs = ServerConfig::load("config.toml")?;

    // 初始化日志
    init_logger(&configs.log_name, &configs.log_level, configs.log_max_size);

    let user_manager = Arc::new(UserManager::new(&configs.users_db)?);
    let stat_map = ServerStatistic::new();

    let api_manager = user_manager.clone();
    let api_stat_map = stat_map.clone();

    tokio::spawn(async move {
        if let Err(e) = start_api_server(configs.api_port, api_stat_map, api_manager).await {
            tracing::error!("API Server 发生错误: {}", e);
        }
    });

    server::run(configs, user_manager, stat_map).await
}
