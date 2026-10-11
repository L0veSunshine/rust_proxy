use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;

/// 双向转发使用的缓冲区大小
pub const RELAY_BUFFER_SIZE: usize = 8192;

pub mod api;
pub mod client;
pub mod config;
pub mod connection_pool;
pub mod health;
pub mod log;
pub mod protocol;
pub mod secret;
pub mod server;
pub mod shutdown;
pub mod user_manager;

pub fn init_logger(log_name: &str, level: &str, rotating_size: u64) -> WorkerGuard {
    let appender = log::SizeRotatingAppender::new(".", log_name, rotating_size);
    let (non_blocking, guard) = tracing_appender::non_blocking(appender);

    let log_level = level.parse::<Level>().unwrap_or(Level::INFO);

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(false)
        .with_max_level(log_level)
        .init();

    guard
}
