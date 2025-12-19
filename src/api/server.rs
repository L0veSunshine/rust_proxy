use crate::api::common::ServerStatistic;
use crate::user_manager::{ServiceError, ServiceResult, UserManager};
use anyhow::Result;
use axum::{
    extract::{Path, State}, http::StatusCode,
    routing::{get, post},
    Json,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub struct AppState {
    pub manager: Arc<UserManager>,
    pub stats: Arc<ServerStatistic>,
}

#[derive(Deserialize)]
pub struct UserAction {
    pub max_ip: u32,
    pub rate_limit: u64,
}

#[derive(Serialize)]
pub struct UserView {
    pub key_id: String,
    pub max_ip: u32,
    pub rate_limit: u64,
}

async fn handle_get_user(
    State(state): State<Arc<AppState>>,
    Path(id_hex): Path<String>,
) -> ServiceResult<Json<UserView>> {
    let key_id = decode_id(&id_hex)?;

    // 调用 service 获取 profile
    let profile = state.manager.get_user(key_id)?;

    Ok(Json(UserView {
        key_id: id_hex,
        max_ip: profile.max_ip,
        rate_limit: profile.rate_limit,
    }))
}

// 修改用户信息
async fn handle_modify_user(
    State(state): State<Arc<AppState>>,
    Path(id_hex): Path<String>,
    Json(req): Json<UserAction>,
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
    Json(req): Json<UserAction>,
) -> ServiceResult<(StatusCode, Json<serde_json::Value>)> {
    let secret = state.manager.add_user(req.max_ip, req.rate_limit)?;
    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "user_uuid": secret })),
    ))
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

async fn handle_get_stats(State(state): State<Arc<AppState>>) -> Json<Arc<ServerStatistic>> {
    // 这里 state.stats 是 Arc<ServerStatistic>
    // 直接克隆 Arc，它指向的是堆上的同一份数据，不会发生所有权问题
    Json(state.stats.clone())
}

pub async fn start_api_server(
    port: u16,
    stats: Arc<ServerStatistic>,
    manager: Arc<UserManager>,
) -> Result<()> {
    let state = Arc::new(AppState { manager, stats });
    let app = Router::new()
        .route("/stats", get(handle_get_stats))
        .route("/users", post(add_user)) // 创建用户
        .route(
            "/users/:id",
            get(handle_get_user) // 获取单个
                .put(handle_modify_user) // 修改单个
                .delete(delete_user),
        ) // 删除单个
        .with_state(state);

    let addr = format!("127.0.0.1:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    println!("API server listening on {}", addr);
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
