use tracing::Level;
use tracing_appender::non_blocking::WorkerGuard;

pub mod api;
pub mod client;
pub mod config;
pub mod log;
pub mod protocol;
pub mod secret;
pub mod server;
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
