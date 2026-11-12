use crate::secret::totp::derive_key_id;
use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use governor::{DefaultDirectRateLimiter, Quota, RateLimiter};
use redb;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use thiserror::Error;
use tracing::info;
use uuid::Uuid;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("用户不存在: {0}")]
    UserNotFound(String),

    #[error("用户已存在: {0}")]
    UserAlreadyExists(String),

    #[error("非法的 KeyID 格式")]
    InvalidKeyId,

    #[error("数据库错误: {0}")]
    DatabaseError(String),

    #[error("超过最大连接数")]
    ResourceUseOut,

    #[error("序列化错误: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("请求参数错误")]
    RequestParamError,
}

impl IntoResponse for ServiceError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            ServiceError::UserNotFound(_) => (StatusCode::NOT_FOUND, self.to_string()),
            ServiceError::UserAlreadyExists(_) => (StatusCode::CONFLICT, self.to_string()),
            ServiceError::InvalidKeyId => (StatusCode::BAD_REQUEST, self.to_string()),
            ServiceError::ResourceUseOut => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            ServiceError::RequestParamError => (StatusCode::BAD_REQUEST, self.to_string()),
            ServiceError::DatabaseError(e) => {
                tracing::error!("Database error: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "数据库操作失败".to_string(),
                )
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "服务器内部故障".to_string(),
            ),
        };

        let body = Json(json!({ "error": message, "code": status.as_u16() }));
        (status, body).into_response()
    }
}

pub type ServiceResult<T> = Result<T, ServiceError>;

const USER_TABLE: TableDefinition<&[u8; 4], &[u8]> = TableDefinition::new("users");

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserProfile {
    pub secret: Vec<u8>,
    pub max_ip: u32,
    pub rate_limit: u64,
}

/// 对外展示的用户信息（不含密钥）
#[derive(Clone, Debug)]
pub struct UserSummary {
    pub key_id: [u8; 4],
    pub max_ip: u32,
    pub rate_limit: u64,
}

/// 用户级限速器（字节/秒）
///
/// governor 单次申请的令牌数不能超过 burst（= 每秒速率），否则直接返回
/// `InsufficientCapacity` 而不等待。这里把大块数据按 burst 拆开申请，
/// 保证任意大小的读写都会被真正限速。
pub struct UserLimiter {
    inner: DefaultDirectRateLimiter,
    burst: NonZeroU32,
}

impl UserLimiter {
    /// `rate_limit` 为 0 表示不限速；超过 u32 的值按 u32::MAX 处理
    pub fn new(rate_limit: u64) -> Option<Self> {
        let rate = NonZeroU32::new(u32::try_from(rate_limit).unwrap_or(u32::MAX))?;
        Some(Self {
            inner: RateLimiter::direct(Quota::per_second(rate)),
            burst: rate,
        })
    }

    /// 单次突发上限（字节），也是平滑限速时建议的单次最大读取块大小
    pub fn burst(&self) -> usize {
        self.burst.get() as usize
    }

    /// 等待直到可以发送 `bytes` 字节
    pub async fn consume(&self, bytes: usize) {
        let mut remaining = bytes;
        while remaining > 0 {
            let chunk = remaining.min(self.burst.get() as usize);
            if let Some(n) = NonZeroU32::new(chunk as u32) {
                // chunk <= burst，不会出现 InsufficientCapacity
                let _ = self.inner.until_n_ready(n).await;
            }
            remaining -= chunk;
        }
    }
}

pub struct UserManager {
    db: Database,
    pub cache: Arc<DashMap<[u8; 4], UserProfile>>,
    pub ip_tracker: Arc<DashMap<[u8; 4], DashMap<IpAddr, u32>>>,
    pub limiters: Arc<DashMap<[u8; 4], Arc<UserLimiter>>>,
}

// 定义 IP 守卫
pub struct IpGuard {
    manager: Arc<UserManager>,
    key_id: [u8; 4],
    client_ip: IpAddr,
}

// 为守卫实现 Drop Trait
impl Drop for IpGuard {
    fn drop(&mut self) {
        // 当 handle_client 函数结束，或者 Future 被取消时，
        // _guard 变量会被销毁，自动执行此逻辑
        self.manager.leave_ip(self.key_id, self.client_ip);
        tracing::debug!("IP 释放: {} for user {:x?}", self.client_ip, self.key_id);
    }
}

impl UserManager {
    pub fn new(db_path: &str) -> ServiceResult<Self> {
        let db = Database::builder()
            .create(db_path)
            .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;

        // 初始化表
        let write_txn = db
            .begin_write()
            .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
        {
            let _ = write_txn
                .open_table(USER_TABLE)
                .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;

        let manager = Self {
            db,
            cache: Arc::new(DashMap::new()),
            ip_tracker: Arc::new(DashMap::new()),
            limiters: Arc::new(DashMap::new()),
        };
        manager.load_to_cache()?;
        Ok(manager)
    }

    /// 尝试进入并获取守卫
    pub fn enter_ip(self: &Arc<Self>, key_id: [u8; 4], ip: IpAddr) -> ServiceResult<IpGuard> {
        let profile = self.get_user(key_id)?;

        let user_ips = self.ip_tracker.entry(key_id).or_default();

        // 1. 如果该 IP 已经存在连接，直接增加计数
        if let Some(mut count) = user_ips.get_mut(&ip) {
            *count += 1;
            return Ok(IpGuard {
                manager: self.clone(),
                key_id,
                client_ip: ip,
            });
        }

        // 2. 如果是新 IP，检查是否超过最大限制
        if profile.max_ip > 0 && (user_ips.len() as u32) >= profile.max_ip {
            return Err(ServiceError::ResourceUseOut);
        }

        // 3. 记录新 IP
        user_ips.insert(ip, 1);

        Ok(IpGuard {
            manager: self.clone(),
            key_id,
            client_ip: ip,
        })
    }

    pub fn leave_ip(&self, key_id: [u8; 4], ip: IpAddr) {
        if let Some(user_ips) = self.ip_tracker.get(&key_id) {
            // 在同一把锁内完成"减一并判断是否归零"，避免与并发的 enter_ip 交错
            user_ips.remove_if_mut(&ip, |_, count| {
                *count = count.saturating_sub(1);
                *count == 0
            });
        }
        // 必须在释放上面的读引用之后再拿写锁，否则同一分片会死锁。
        // remove_if 在写锁内重新检查是否为空：期间若有新连接登记了 IP，就不会被误删。
        if self
            .ip_tracker
            .remove_if(&key_id, |_, ips| ips.is_empty())
            .is_some()
        {
            tracing::debug!("User {:x?} 活跃 IP 已归零，清理追踪器存根", key_id);
        }
    }

    pub fn get_user_limiter(&self, key_id: [u8; 4], rate_limit: u64) -> Option<Arc<UserLimiter>> {
        if let Some(limiter) = self.limiters.get(&key_id) {
            return Some(limiter.clone());
        }
        let limiter = Arc::new(UserLimiter::new(rate_limit)?);
        Some(
            self.limiters
                .entry(key_id)
                .or_insert(limiter)
                .value()
                .clone(),
        )
    }

    pub fn add_user(&self, uuid: Uuid, max_ip: u32, rate_limit: u64) -> ServiceResult<String> {
        let secret_bytes = uuid.as_bytes().to_vec();
        let key_id = derive_key_id(&secret_bytes);

        if self.cache.contains_key(&key_id) {
            return Err(ServiceError::UserAlreadyExists(hex::encode(key_id)));
        }
        info!("create user signature is {}", hex::encode(key_id),);
        self.persist_user(
            key_id,
            UserProfile {
                secret: secret_bytes,
                max_ip,
                rate_limit,
            },
        )?;
        Ok(hex::encode(key_id))
    }

    // [查] 获取单个用户
    pub fn get_user(&self, key_id: [u8; 4]) -> ServiceResult<UserSummary> {
        self.cache
            .get(&key_id)
            .map(|user| UserSummary {
                key_id,
                max_ip: user.max_ip,
                rate_limit: user.rate_limit,
            })
            .ok_or_else(|| ServiceError::UserNotFound(hex::encode(key_id)))
    }

    pub fn get_all_users(&self) -> ServiceResult<Vec<UserSummary>> {
        let users = self
            .cache
            .iter()
            .map(|k| UserSummary {
                key_id: *k.key(),
                max_ip: k.max_ip,
                rate_limit: k.rate_limit,
            })
            .collect();
        Ok(users)
    }

    // [改] 修改现有用户配置
    pub fn modify_user(
        &self,
        key_id: [u8; 4],
        max_ip: Option<u32>,
        rate_limit: Option<u64>,
    ) -> ServiceResult<()> {
        // 1. 先从缓存检查用户是否存在
        let mut profile = self
            .cache
            .get(&key_id)
            .ok_or_else(|| ServiceError::UserNotFound(hex::encode(key_id)))?
            .clone();

        // 2. 更新字段
        if let Some(max_ip) = max_ip {
            profile.max_ip = max_ip;
        }
        if let Some(rate_limit) = rate_limit {
            profile.rate_limit = rate_limit;
        }

        self.limiters.remove(&key_id);
        // 3. 调用统一的持久化方法同步到 redb 和 cache
        self.persist_user(key_id, profile)
    }

    pub fn delete_user(&self, key_id: [u8; 4]) -> ServiceResult<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(USER_TABLE)
                .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
            table
                .remove(&key_id)
                .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
        self.cache.remove(&key_id);
        self.limiters.remove(&key_id);
        self.ip_tracker.remove(&key_id);
        Ok(())
    }

    fn persist_user(&self, key_id: [u8; 4], profile: UserProfile) -> ServiceResult<()> {
        let write_txn = self
            .db
            .begin_write()
            .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
        {
            let mut table = write_txn
                .open_table(USER_TABLE)
                .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
            table
                .insert(&key_id, serde_json::to_vec(&profile)?.as_slice())
                .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
        }
        write_txn
            .commit()
            .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
        self.cache.insert(key_id, profile);
        Ok(())
    }

    /// 获取当前所有在线用户的 KeyID 及其 IP 列表
    pub fn list_online_users(&self) -> Vec<([u8; 4], Vec<IpAddr>)> {
        self.ip_tracker
            .iter()
            .map(|entry| {
                let key_id = *entry.key();
                // 提取该用户下所有的活跃 IP
                let ips: Vec<IpAddr> = entry
                    .value()
                    .iter()
                    .map(|ip_entry| *ip_entry.key())
                    .collect();
                (key_id, ips)
            })
            .collect()
    }

    fn load_to_cache(&self) -> ServiceResult<()> {
        let read_txn = self
            .db
            .begin_read()
            .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
        let table = read_txn
            .open_table(USER_TABLE)
            .map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
        for result in table
            .iter()
            .map_err(|e| ServiceError::DatabaseError(e.to_string()))?
        {
            let (key, value) = result.map_err(|e| ServiceError::DatabaseError(e.to_string()))?;
            let profile: UserProfile = serde_json::from_slice(value.value())?;
            self.cache.insert(*key.value(), profile);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn test_limiter_throttles_chunks_larger_than_burst() {
        // 以前单次申请超过 burst 会直接返回错误并被忽略，等于不限速
        let limiter = UserLimiter::new(4000).unwrap();
        let start = Instant::now();
        limiter.consume(6000).await;
        assert!(start.elapsed() >= Duration::from_millis(400));
    }

    #[test]
    fn test_limiter_handles_huge_rate() {
        // 以前 rate as u32 截断为 0 后 unwrap 会 panic
        assert!(UserLimiter::new(1u64 << 32).is_some());
        assert!(UserLimiter::new(0).is_none());
    }

    #[test]
    fn test_ip_tracking_counts_connections() {
        let path = std::env::temp_dir().join(format!("rust_proxy_um_{}.db", Uuid::new_v4()));
        let manager = Arc::new(UserManager::new(path.to_str().unwrap()).unwrap());
        let key_id: [u8; 4] = hex::decode(manager.add_user(Uuid::new_v4(), 1, 0).unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        let g1 = manager.enter_ip(key_id, ip1).unwrap();
        let g2 = manager.enter_ip(key_id, ip1).unwrap();
        assert!(manager.enter_ip(key_id, ip2).is_err());

        drop(g1);
        assert!(manager.ip_tracker.contains_key(&key_id));
        drop(g2);
        assert!(!manager.ip_tracker.contains_key(&key_id));
        assert!(manager.enter_ip(key_id, ip2).is_ok());

        drop(manager);
        let _ = std::fs::remove_file(path);
    }
}
