use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Semaphore;

/// 连接池，用于限制最大并发连接数
#[derive(Clone)]
pub struct ConnectionPool {
    /// 最大连接数
    max_connections: usize,
    /// 信号量，用于控制并发
    semaphore: Arc<Semaphore>,
}

impl ConnectionPool {
    /// 创建连接池
    ///
    /// # Arguments
    /// * `max_connections` - 最大并发连接数，0 表示无限制
    pub fn new(max_connections: usize) -> Self {
        // 如果是0，使用一个很大的数字作为无限制
        let limit = if max_connections == 0 {
            Semaphore::MAX_PERMITS
        } else {
            max_connections
        };

        Self {
            max_connections,
            semaphore: Arc::new(Semaphore::new(limit)),
        }
    }

    /// 获取连接许可
    ///
    /// 返回一个 RAII 守卫，当守卫被释放时自动归还许可
    pub async fn acquire(&self) -> Result<ConnectionGuard> {
        let permit = self.semaphore.clone().acquire_owned().await?;
        Ok(ConnectionGuard { _permit: permit })
    }

    /// 尝试获取连接许可 (非阻塞)
    pub fn try_acquire(&self) -> Result<ConnectionGuard> {
        let permit = self.semaphore.clone().try_acquire_owned()?;
        Ok(ConnectionGuard { _permit: permit })
    }

    /// 获取当前可用连接数
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// 获取最大连接数
    pub fn max_connections(&self) -> usize {
        self.max_connections
    }
}

/// 连接守卫，实现 RAII 模式
pub struct ConnectionGuard {
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl ConnectionGuard {
    // 守卫被 drop 时自动归还许可
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_pool() {
        let pool = ConnectionPool::new(2);

        // 获取2个连接
        let _g1 = pool.acquire().await.unwrap();
        assert_eq!(pool.available(), 1);

        let _g2 = pool.acquire().await.unwrap();
        assert_eq!(pool.available(), 0);

        // 释放一个连接
        drop(_g1);
        assert_eq!(pool.available(), 1);
    }

    #[tokio::test]
    async fn test_unlimited_pool() {
        let pool = ConnectionPool::new(0);
        assert!(pool.available() > 1000000);
    }
}
