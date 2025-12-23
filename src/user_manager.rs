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

pub struct UserManager {
    db: Database,
    pub cache: Arc<DashMap<[u8; 4], UserProfile>>,
    pub ip_tracker: Arc<DashMap<[u8; 4], DashMap<IpAddr, u32>>>,
    pub limiters: Arc<DashMap<[u8; 4], Arc<DefaultDirectRateLimiter>>>,
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
        let profile = self.get_user(key_id)?; //

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
        // 使用 entry API 或检查逻辑
        if let Some(user_ips) = self.ip_tracker.get(&key_id) {
            let mut should_remove_user_entirely = false;

            if let Some(mut count) = user_ips.get_mut(&ip) {
                if *count > 1 {
                    *count -= 1;
                } else {
                    // 当前 IP 的最后一个连接断开了
                    drop(count); // 先释放内层锁
                    user_ips.remove(&ip);

                    // 检查这个用户是否已经没有任何活跃 IP 了
                    if user_ips.is_empty() {
                        should_remove_user_entirely = true;
                    }
                }
            }

            if should_remove_user_entirely {
                drop(user_ips); // 释放外层读锁
                self.ip_tracker.remove(&key_id);
                tracing::debug!("User {:x?} 活跃 IP 已归零，清理追踪器存根", key_id);
            }
        }
    }

    pub fn get_user_limiter(
        &self,
        key_id: [u8; 4],
        rate_limit: u64,
    ) -> Option<Arc<DefaultDirectRateLimiter>> {
        if rate_limit == 0 {
            return None;
        }

        // 如果该用户的限速器已存在，直接返回；否则创建一个新的
        Some(
            self.limiters
                .entry(key_id)
                .or_insert_with(|| {
                    let quota =
                        Quota::per_second(std::num::NonZeroU32::new(rate_limit as u32).unwrap());
                    Arc::new(RateLimiter::direct(quota))
                })
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
    pub fn get_user(&self, key_id: [u8; 4]) -> ServiceResult<UserProfile> {
        self.cache
            .get(&key_id)
            .map(|kv| UserProfile {
                secret: key_id.to_vec(),
                max_ip: kv.max_ip,
                rate_limit: kv.rate_limit,
            })
            .ok_or_else(|| ServiceError::UserNotFound(hex::encode(key_id)))
    }

    pub fn get_all_users(&self) -> ServiceResult<Vec<UserProfile>> {
        let users = self
            .cache
            .iter()
            .map(|k| UserProfile {
                secret: k.key().to_vec(),
                max_ip: k.max_ip,
                rate_limit: k.rate_limit,
            })
            .collect::<Vec<_>>();
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
