use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// 默认优雅关闭超时时间
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(30);
/// 超时后强制取消连接，再额外等待它们退出的时间
pub const FORCE_CLOSE_GRACE: Duration = Duration::from_secs(1);

/// 优雅关闭管理器
#[derive(Clone)]
pub struct GracefulShutdown {
    /// 关闭信号（停止接受新连接）。CancellationToken 触发后状态会一直保持，
    /// 晚于触发才开始等待的任务也能立即感知，不会像 `Notify::notify_waiters` 那样丢通知。
    shutdown_signal: CancellationToken,
    /// 强制关闭现有连接的信号
    connections_signal: CancellationToken,
    /// 活跃连接数
    active_connections: Arc<AtomicUsize>,
}

impl GracefulShutdown {
    /// 创建优雅关闭管理器
    pub fn new() -> Self {
        Self {
            shutdown_signal: CancellationToken::new(),
            connections_signal: CancellationToken::new(),
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// 等待关闭信号
    pub async fn wait_shutdown(&self) {
        self.shutdown_signal.cancelled().await;
    }

    /// 检查是否正在关闭
    pub fn is_shutting_down(&self) -> bool {
        self.shutdown_signal.is_cancelled()
    }

    /// 触发关闭信号
    pub fn trigger_shutdown(&self) {
        info!("Triggering graceful shutdown");
        self.shutdown_signal.cancel();
    }

    /// 每条连接持有一个子 token：优雅关闭超时后会被统一取消
    pub fn connection_token(&self) -> CancellationToken {
        self.connections_signal.child_token()
    }

    /// 增加活跃连接数
    pub fn increment_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// 减少活跃连接数
    pub fn decrement_connections(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    /// 获取活跃连接数
    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    /// 执行优雅关闭流程
    ///
    /// # Arguments
    /// * `timeout_duration` - 等待现有连接自然结束的最大时间；超时后强制取消剩余连接
    pub async fn shutdown(&self, timeout_duration: Duration) {
        info!("Starting graceful shutdown");

        // 1. 标记为关闭状态，不再接受新连接
        self.trigger_shutdown();

        // 2. 等待现有连接完成
        if self.wait_connections(timeout_duration).await {
            info!("All connections completed gracefully");
        } else {
            // 3. 超时：通知剩余连接立即退出，并给它们一点时间释放资源
            warn!(
                "Shutdown timeout reached, force closing {} active connections",
                self.active_connections()
            );
            self.connections_signal.cancel();
            if !self.wait_connections(FORCE_CLOSE_GRACE).await {
                warn!(
                    "{} connections still active after force close",
                    self.active_connections()
                );
            }
        }

        info!("Graceful shutdown completed");
    }

    /// 等待活跃连接归零，返回是否在超时前完成
    async fn wait_connections(&self, timeout_duration: Duration) -> bool {
        timeout(timeout_duration, async {
            while self.active_connections() > 0 {
                info!(
                    "Waiting for {} active connections to complete",
                    self.active_connections()
                );
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await
        .is_ok()
    }
}

impl Default for GracefulShutdown {
    fn default() -> Self {
        Self::new()
    }
}

/// 连接守卫，用于自动跟踪连接生命周期
pub struct ConnectionGuard {
    shutdown: GracefulShutdown,
}

impl ConnectionGuard {
    pub fn new(shutdown: GracefulShutdown) -> Self {
        shutdown.increment_connections();
        Self { shutdown }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.shutdown.decrement_connections();
    }
}

/// 设置信号处理器（Unix: SIGTERM, SIGINT; Windows: Ctrl+C）
///
/// # Arguments
/// * `shutdown` - 优雅关闭控制器
/// * `is_daemon` - 是否为后台模式。为 true 时忽略 Ctrl+C (SIGINT)，仅响应 SIGTERM 或管理命令
pub async fn setup_signal_handler(shutdown: GracefulShutdown, is_daemon: bool) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate()).expect("failed to setup SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to setup SIGINT handler");

        if is_daemon {
            loop {
                tokio::select! {
                    _ = sigterm.recv() => {
                        info!("Received SIGTERM, initiating graceful shutdown");
                        break;
                    }
                    _ = sigint.recv() => {
                        info!("Ignored SIGINT (Ctrl+C) in daemon mode");
                    }
                }
            }
        } else {
            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown");
                }
                _ = sigint.recv() => {
                    info!("Received SIGINT (Ctrl+C), initiating graceful shutdown");
                }
            }
        }
    }

    #[cfg(windows)]
    {
        if is_daemon {
            let mut ctrl_c = tokio::signal::windows::ctrl_c().ok();
            let mut ctrl_break = tokio::signal::windows::ctrl_break().ok();
            let mut ctrl_close = tokio::signal::windows::ctrl_close().ok();
            let mut ctrl_shutdown = tokio::signal::windows::ctrl_shutdown().ok();

            loop {
                tokio::select! {
                    Some(_) = async {
                        match &mut ctrl_break {
                            Some(b) => b.recv().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        info!("Received Ctrl+Break, initiating graceful shutdown");
                        break;
                    }
                    Some(_) = async {
                        match &mut ctrl_close {
                            Some(c) => c.recv().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        info!("Received Ctrl+Close, initiating graceful shutdown");
                        break;
                    }
                    Some(_) = async {
                        match &mut ctrl_shutdown {
                            Some(s) => s.recv().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        info!("Received Ctrl+Shutdown, initiating graceful shutdown");
                        break;
                    }
                    Some(_) = async {
                        match &mut ctrl_c {
                            Some(c) => c.recv().await,
                            None => std::future::pending().await,
                        }
                    } => {
                        info!("Ignored Ctrl+C in daemon mode");
                    }
                }
            }
        } else {
            tokio::signal::ctrl_c()
                .await
                .expect("failed to setup Ctrl+C handler");
            info!("Received Ctrl+C, initiating graceful shutdown");
        }
    }

    shutdown.trigger_shutdown();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_graceful_shutdown() {
        let shutdown = GracefulShutdown::new();

        assert!(!shutdown.is_shutting_down());
        assert_eq!(shutdown.active_connections(), 0);

        // 模拟连接
        shutdown.increment_connections();
        assert_eq!(shutdown.active_connections(), 1);

        // 触发关闭
        shutdown.trigger_shutdown();
        assert!(shutdown.is_shutting_down());

        // 连接完成
        shutdown.decrement_connections();
        assert_eq!(shutdown.active_connections(), 0);
    }

    #[tokio::test]
    async fn test_connection_guard() {
        let shutdown = GracefulShutdown::new();

        {
            let _guard = ConnectionGuard::new(shutdown.clone());
            assert_eq!(shutdown.active_connections(), 1);
        }

        // guard 被 drop，连接数应该减少
        assert_eq!(shutdown.active_connections(), 0);
    }

    #[tokio::test]
    async fn test_shutdown_timeout() {
        let shutdown = GracefulShutdown::new();
        let conn_token = shutdown.connection_token();

        // 模拟一个不会结束的连接
        shutdown.increment_connections();

        // 关闭应该在超时 + 强制关闭宽限期后返回，并取消剩余连接
        let start = std::time::Instant::now();
        shutdown.shutdown(Duration::from_millis(100)).await;
        let elapsed = start.elapsed();

        assert!(conn_token.is_cancelled());
        assert!(elapsed >= Duration::from_millis(100) + FORCE_CLOSE_GRACE);
        assert!(elapsed < Duration::from_millis(500) + FORCE_CLOSE_GRACE);
    }

    #[tokio::test]
    async fn test_wait_after_trigger_returns_immediately() {
        // 先触发、后等待也必须能收到信号（Notify::notify_waiters 做不到）
        let shutdown = GracefulShutdown::new();
        shutdown.trigger_shutdown();
        timeout(Duration::from_millis(100), shutdown.wait_shutdown())
            .await
            .expect("wait_shutdown should return after trigger");
    }
}
