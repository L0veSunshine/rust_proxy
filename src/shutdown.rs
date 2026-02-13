use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;
use tokio::time::timeout;
use tracing::{info, warn};

/// 优雅关闭管理器
#[derive(Clone)]
pub struct GracefulShutdown {
    /// 关闭信号
    shutdown_signal: Arc<Notify>,
    /// 是否正在关闭
    is_shutting_down: Arc<AtomicBool>,
    /// 活跃连接数
    active_connections: Arc<AtomicUsize>,
}

impl GracefulShutdown {
    /// 创建优雅关闭管理器
    pub fn new() -> Self {
        Self {
            shutdown_signal: Arc::new(Notify::new()),
            is_shutting_down: Arc::new(AtomicBool::new(false)),
            active_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// 等待关闭信号
    pub async fn wait_shutdown(&self) {
        self.shutdown_signal.notified().await;
    }

    /// 检查是否正在关闭
    pub fn is_shutting_down(&self) -> bool {
        self.is_shutting_down.load(Ordering::Relaxed)
    }

    /// 触发关闭信号
    pub fn trigger_shutdown(&self) {
        info!("Triggering graceful shutdown");
        self.is_shutting_down.store(true, Ordering::Release);
        self.shutdown_signal.notify_waiters();
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
    /// * `timeout_duration` - 等待现有连接完成的最大时间
    pub async fn shutdown(&self, timeout_duration: Duration) {
        info!("Starting graceful shutdown");

        // 1. 标记为关闭状态，不再接受新连接
        self.trigger_shutdown();

        // 2. 等待现有连接完成
        let result = timeout(timeout_duration, async {
            while self.active_connections() > 0 {
                let count = self.active_connections();
                info!("Waiting for {} active connections to complete", count);
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        })
        .await;

        match result {
            Ok(_) => info!("All connections completed gracefully"),
            Err(_) => {
                let remaining = self.active_connections();
                warn!(
                    "Shutdown timeout reached, {} connections still active",
                    remaining
                );
            }
        }

        info!("Graceful shutdown completed");
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
pub async fn setup_signal_handler(shutdown: GracefulShutdown) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate()).expect("failed to setup SIGTERM handler");
        let mut sigint = signal(SignalKind::interrupt()).expect("failed to setup SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT");
            }
        }
    }

    #[cfg(windows)]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to setup Ctrl+C handler");
        info!("Received Ctrl+C");
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

        // 模拟一个不会结束的连接
        shutdown.increment_connections();

        // 关闭应该在超时后返回
        let start = std::time::Instant::now();
        shutdown.shutdown(Duration::from_millis(100)).await;
        let elapsed = start.elapsed();

        assert!(elapsed >= Duration::from_millis(100));
        assert!(elapsed < Duration::from_millis(200));
    }
}
