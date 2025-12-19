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

    // 每小时清理不活跃的限速器
    let manager_for_cleanup = user_manager.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600)); // 每小时
        loop {
            interval.tick().await;
            // 遍历所有限速器
            // 注意：DashMap 迭代时会持有读锁，生产环境建议分批清理或在低峰期进行
            manager_for_cleanup.limiters.retain(|key_id, _| {
                // 如果该用户当前没有活跃 IP 连接，则认为可以清理限速器
                // 下次用户上线时会重新创建
                manager_for_cleanup.ip_tracker.contains_key(key_id)
            });
        }
    });

    server::run(configs, user_manager, stat_map).await
}
