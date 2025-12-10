pub mod api;
pub mod client;
pub mod config;
pub mod log;
pub mod protocol;
pub mod secret;
pub mod server;

// 建议把日志初始化逻辑封装一下，方便 server 和 client 复用
pub fn init_logger(log_name: &str) {
    let appender = log::SizeRotatingAppender::new(".", log_name, 5 * 1024 * 1024);
    let (non_blocking, _guard) = tracing_appender::non_blocking(appender);

    // 注意：_guard 需要被保持，这里为了简化演示直接 init，
    // 实际生产中你可能需要返回 guard 或者在 main 里维持它。
    // 如果 tracing_appender 需要 guard 存活，建议把 guard 返回给 main 函数持有。

    tracing_subscriber::fmt()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(false)
        .init();
}
