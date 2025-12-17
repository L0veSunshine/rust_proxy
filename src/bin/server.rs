use anyhow::{Result, bail};
use rust_proxy::api::server::{ServerStatistic, start_server_stat_api};
use rust_proxy::config::{ServerConfig, build_key_map, get_shared_keys};
use rust_proxy::{init_logger, server};

#[tokio::main]
async fn main() -> Result<()> {
    let configs = ServerConfig::load("config.toml")?;

    // 初始化日志
    init_logger(&configs.log_name, &configs.log_level, configs.log_max_size);

    // 业务逻辑
    let keys = match get_shared_keys(&configs.users_db) {
        Ok(k) => k,
        Err(e) => bail!("Read keys error: {}", e),
    };
    let arc_keys = build_key_map(&keys);
    let stat_map = ServerStatistic::new();
    let stat_map_clone = stat_map.clone();

    tokio::spawn(async move {
        start_server_stat_api(configs.api_port, stat_map).await;
    });

    server::run(configs, arc_keys, stat_map_clone).await
}
