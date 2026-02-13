use bytes::BytesMut;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Buffer 对象池，用于复用 BytesMut 减少内存分配
#[derive(Clone)]
pub struct BufferPool {
    /// 缓冲区容量
    capacity: usize,
    /// 池中的缓冲区
    pool: Arc<Mutex<Vec<BytesMut>>>,
    /// 池的最大大小
    max_size: usize,
}

impl BufferPool {
    /// 创建 Buffer 池
    ///
    /// # Arguments
    /// * `capacity` - 每个 buffer 的容量
    /// * `max_size` - 池中最多保留的 buffer 数量
    pub fn new(capacity: usize, max_size: usize) -> Self {
        Self {
            capacity,
            pool: Arc::new(Mutex::new(Vec::with_capacity(max_size))),
            max_size,
        }
    }

    /// 从池中获取一个 buffer
    ///
    /// 如果池为空，创建一个新的 buffer
    pub async fn acquire(&self) -> BufferGuard {
        let mut pool = self.pool.lock().await;
        let buffer = pool
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(self.capacity));

        BufferGuard {
            buffer: Some(buffer),
            pool: self.clone(),
        }
    }

    /// 归还 buffer 到池中
    async fn release(&self, mut buffer: BytesMut) {
        // 清空 buffer 内容
        buffer.clear();

        // 如果池未满，则归还
        let mut pool = self.pool.lock().await;
        if pool.len() < self.max_size {
            pool.push(buffer);
        }
        // 否则让 buffer 自然释放
    }

    /// 获取池中当前 buffer 数量
    pub async fn size(&self) -> usize {
        self.pool.lock().await.len()
    }
}

/// Buffer 守卫，实现 RAII 模式
pub struct BufferGuard {
    buffer: Option<BytesMut>,
    pool: BufferPool,
}

impl BufferGuard {
    /// 获取 buffer 的可变引用
    pub fn buffer_mut(&mut self) -> &mut BytesMut {
        self.buffer.as_mut().expect("buffer should exist")
    }

    /// 获取 buffer 的不可变引用
    pub fn buffer(&self) -> &BytesMut {
        self.buffer.as_ref().expect("buffer should exist")
    }
}

impl Drop for BufferGuard {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            let pool = self.pool.clone();
            // 异步归还 buffer
            tokio::spawn(async move {
                pool.release(buffer).await;
            });
        }
    }
}

impl std::ops::Deref for BufferGuard {
    type Target = BytesMut;

    fn deref(&self) -> &Self::Target {
        self.buffer()
    }
}

impl std::ops::DerefMut for BufferGuard {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_buffer_pool() {
        let pool = BufferPool::new(1024, 5);

        // 获取一个 buffer
        {
            let mut guard = pool.acquire().await;
            guard.extend_from_slice(b"test");
            assert_eq!(guard.len(), 4);
        }

        // buffer 应该被归还到池中
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert_eq!(pool.size().await, 1);

        // 再次获取应该复用之前的 buffer
        let guard = pool.acquire().await;
        assert_eq!(guard.len(), 0); // 应该是清空后的
    }

    #[tokio::test]
    async fn test_pool_max_size() {
        let pool = BufferPool::new(1024, 2);

        // 创建3个 buffer
        let _g1 = pool.acquire().await;
        let _g2 = pool.acquire().await;
        let _g3 = pool.acquire().await;

        drop(_g1);
        drop(_g2);
        drop(_g3);

        // 等待归还
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // 池最多只保留2个
        assert!(pool.size().await <= 2);
    }
}
