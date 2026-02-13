use crate::api::common::ServerStatistic;
use crate::health::{SystemMetrics, health_check, ready_check};
use crate::user_manager::ServiceError::RequestParamError;
use crate::user_manager::{ServiceError, ServiceResult, UserManager};
use anyhow::Result;
use axum::routing::delete;
use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

pub struct AppState {
    pub manager: Arc<UserManager>,
    pub stats: Arc<ServerStatistic>,
    pub metrics: Arc<SystemMetrics>,
}

#[derive(Deserialize)]
pub struct UserUpdateRequest {
    pub max_ip: Option<u32>,
    pub rate_limit: Option<u64>,
}

#[derive(Deserialize)]
pub struct UserAdditionRequest {
    pub uuid: String,
    pub max_ip: Option<u32>,
    pub rate_limit: Option<u64>,
}

#[derive(Serialize)]
pub struct UserView {
    pub key_id: String,
    pub max_ip: u32,
    pub rate_limit: u64,
}

#[derive(Serialize)]
pub struct UserProfileView {
    pub id: String,
    pub max_ip: u32,
    pub rate_limit: u64,
}

// 修改用户信息
async fn handle_modify_user(
    State(state): State<Arc<AppState>>,
    Path(id_hex): Path<String>,
    Json(req): Json<UserUpdateRequest>,
) -> ServiceResult<StatusCode> {
    let key_id = decode_id(&id_hex)?;

    // 调用 service 修改数据
    state
        .manager
        .modify_user(key_id, req.max_ip, req.rate_limit)?;

    Ok(StatusCode::OK)
}

async fn add_user(
    State(state): State<Arc<AppState>>,
    Json(req): Json<UserAdditionRequest>,
) -> ServiceResult<(StatusCode, Json<serde_json::Value>)> {
    let Ok(uuid) = req.uuid.parse::<Uuid>() else {
        return Err(RequestParamError);
    };

    let secret = state.manager.add_user(
        uuid,
        req.max_ip.unwrap_or_default(),
        req.rate_limit.unwrap_or_default(),
    )?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "key_id": secret })),
    ))
}

async fn list_all_user_profile(
    State(state): State<Arc<AppState>>,
) -> ServiceResult<Json<serde_json::Value>> {
    let user_list = state.manager.get_all_users()?;
    let resp = user_list
        .into_iter()
        .map(|i| UserProfileView {
            id: hex::encode(i.secret),
            max_ip: i.max_ip,
            rate_limit: i.rate_limit,
        })
        .collect::<Vec<UserProfileView>>();
    Ok(Json(serde_json::json!(resp)))
}

async fn delete_user(
    State(state): State<Arc<AppState>>,
    Path(id_hex): Path<String>,
) -> ServiceResult<StatusCode> {
    let bytes = hex::decode(&id_hex).map_err(|_| ServiceError::InvalidKeyId)?;
    let key_id: [u8; 4] = bytes.try_into().map_err(|_| ServiceError::InvalidKeyId)?;
    state.manager.delete_user(key_id)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct OnlineUserView {
    pub key_id: String,
    pub ips: Vec<IpAddr>,
    pub upload: u64,
    pub download: u64,
}

async fn handle_list_online_users(State(state): State<Arc<AppState>>) -> Json<Vec<OnlineUserView>> {
    let online_info = state.manager.list_online_users();
    let mut result = Vec::with_capacity(online_info.len());

    for (key_id, ips) in online_info {
        // 从统计地图中获取流量数据
        let (up, down) = if let Some(traffic) = state.stats.get(&key_id) {
            (
                traffic.upload.load(std::sync::atomic::Ordering::Relaxed),
                traffic.download.load(std::sync::atomic::Ordering::Relaxed),
            )
        } else {
            (0, 0)
        };

        result.push(OnlineUserView {
            key_id: hex::encode(key_id),
            ips,
            upload: up,
            download: down,
        });
    }
    Json(result)
}

pub async fn start_admin_api(
    listen: &str,
    manager: Arc<UserManager>,
    stats: Arc<ServerStatistic>,
    metrics: Arc<SystemMetrics>,
) -> Result<()> {
    let state = Arc::new(AppState {
        manager,
        stats,
        metrics: metrics.clone(),
    });

    let app = Router::new()
        // 用户管理
        .route("/users", get(list_all_user_profile))
        .route("/users", post(add_user))
        .route("/users/{id}", put(handle_modify_user))
        .route("/users/{id}", delete(delete_user))
        // 统计信息
        .route("/stats", get(handle_list_online_users))
        // 健康检查
        .route("/health", get(health_check))
        .route("/ready", get(ready_check))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    println!("API server listening on {}", listen);
    axum::serve(listener, app).await?;
    Ok(())
}

fn decode_id(hex_str: &str) -> ServiceResult<[u8; 4]> {
    // 1. 使用 hex 库将字符串解码为 Vec<u8>
    let bytes = hex::decode(hex_str).map_err(|_| ServiceError::InvalidKeyId)?;

    // 2. 尝试将 Vec<u8> 转换为固定长度的 [u8; 4]
    // 如果长度不是 4，说明 ID 格式不对，返回 InvalidKeyId 错误
    bytes.try_into().map_err(|_| ServiceError::InvalidKeyId)
}
