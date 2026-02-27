use anyhow::Result;
use rust_proxy::api::common::ServerStatistic;
use rust_proxy::api::server::start_admin_api;
use rust_proxy::config::ServerConfig;
use rust_proxy::connection_pool::ConnectionPool;
use rust_proxy::health::SystemMetrics;
use rust_proxy::shutdown::{GracefulShutdown, setup_signal_handler};
use rust_proxy::user_manager::UserManager;
use rust_proxy::{init_logger, server};
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    let configs = ServerConfig::load("config.toml")?;

    // 初始化日志
    let _guard = init_logger(&configs.log_name, &configs.log_level, configs.log_max_size);

    tracing::info!("Starting rust_proxy server...");

    // 初始化核心组件
    let user_manager = Arc::new(UserManager::new(&configs.users_db)?);
    let stat_map = ServerStatistic::new();
    let metrics = Arc::new(SystemMetrics::new());
    let shutdown = GracefulShutdown::new();
    let connection_pool = ConnectionPool::new(configs.max_connections.unwrap_or(10000));

    tracing::info!(
        "Initialized with max_connections: {}",
        connection_pool.max_connections()
    );

    // 启动 API 服务器
    let api_manager = user_manager.clone();
    let api_stat_map = stat_map.clone();
    let api_metrics = metrics.clone();
    let api_shutdown = shutdown.clone();

    tokio::spawn(async move {
        let api_listen = format!("127.0.0.1:{}", configs.api_port);
        if let Err(e) = start_admin_api(&api_listen, api_manager, api_stat_map, api_metrics).await {
            tracing::error!("API server error: {}", e);
            api_shutdown.trigger_shutdown();
        }
    });

    // 每小时清理不活跃的限速器
    let manager_for_cleanup = user_manager.clone();
    let cleanup_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        interval.tick().await; // 第一次立即完成

        loop {
            tokio::select! {
                _ = cleanup_shutdown.wait_shutdown() => break,
                _ = interval.tick() => {
                    tracing::info!("Cleaning up inactive rate limiters");
                    manager_for_cleanup.limiters.retain(|key_id, _| {
                        manager_for_cleanup.ip_tracker.contains_key(key_id)
                    });
                }
            }
        }
        tracing::info!("Limiter cleanup task stopped");
    });

    // 设置信号处理器
    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        setup_signal_handler(signal_shutdown).await;
    });

    // 运行主服务器
    tracing::info!("Server starting on {}", configs.listen);
    let server_shutdown = shutdown.clone();
    let server_result = tokio::select! {
        result = server::run(configs, user_manager, stat_map, metrics, connection_pool, shutdown.clone()) => result,
        _ = server_shutdown.wait_shutdown() => {
            tracing::info!("Received shutdown signal");
            Ok(())
        }
    };

    // 执行优雅关闭
    tracing::info!("Shutting down gracefully...");
    shutdown.shutdown(Duration::from_secs(30)).await;

    server_result
}
