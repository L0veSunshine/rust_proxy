use tracing::Level;
pub mod api;
pub mod client;
pub mod config;
pub mod log;
pub mod protocol;
pub mod secret;
pub mod server;

// 建议把日志初始化逻辑封装一下，方便 server 和 client 复用
pub fn init_logger(log_name: &str, level: &str, rotating_size: u64) {
    let appender = log::SizeRotatingAppender::new(".", log_name, rotating_size);
    let (non_blocking, _guard) = tracing_appender::non_blocking(appender);

    let log_level = level.parse::<Level>().unwrap_or(Level::INFO);

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(false)
        .with_max_level(log_level)
        .init();
}
