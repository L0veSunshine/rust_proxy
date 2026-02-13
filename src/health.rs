use crate::api::server::AppState;
use axum::Json;
use axum::extract::State;
use serde::Serialize;
use std::sync::Arc;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use sysinfo::{MemoryRefreshKind, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

/// 系统启动时间
static START_TIME: LazyLock<Instant> = LazyLock::new(Instant::now);

/// 全局系统信息（共享状态）
#[derive(Clone)]
pub struct SystemMetrics {
    pub active_connections: Arc<AtomicUsize>,
    pub total_connections: Arc<AtomicU64>,
}

impl SystemMetrics {
    pub fn new() -> Self {
        Self {
            active_connections: Arc::new(AtomicUsize::new(0)),
            total_connections: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn increment_connection(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
        self.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_connection(&self) {
        self.active_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// 健康状态响应
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub uptime_seconds: u64,
    pub active_connections: usize,
    pub total_connections: u64,
    pub memory_usage_mb: u64,
    pub cpu_count: usize,
}

/// 就绪状态响应
#[derive(Serialize)]
pub struct ReadyResponse {
    pub ready: bool,
    pub checks: Vec<ReadyCheck>,
}

#[derive(Serialize)]
pub struct ReadyCheck {
    pub name: &'static str,
    pub status: &'static str,
    pub message: Option<String>,
}

/// 健康检查处理器

// 建议将 System 对象也封装进 State，或者在函数内部只初始化必要的部分
pub async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    // 1. 系统级别的刷新配置：明确传入 MemoryRefreshKind::everything()
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing().with_memory(MemoryRefreshKind::everything()),
    );

    let pid = sysinfo::get_current_pid().expect("Failed to get PID");

    // 2. 进程级别的刷新配置
    // 注意：ProcessRefreshKind 的 with_memory 通常不带参数（或视版本而定）
    // 如果这里也报同样的错，请也给它传入具体参数
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing().with_memory(),
    );

    let uptime = START_TIME.elapsed().as_secs();
    let active = state.metrics.active_connections.load(Ordering::Relaxed);
    let total = state.metrics.total_connections.load(Ordering::Relaxed);

    let memory_mb = sys
        .process(pid)
        .map(|p| p.memory() / 1024 / 1024)
        .unwrap_or(0);

    Json(HealthResponse {
        status: "ok",
        uptime_seconds: uptime,
        active_connections: active,
        total_connections: total,
        memory_usage_mb: memory_mb,
        cpu_count: sys.cpus().len(),
    })
}
/// 就绪检查处理器
pub async fn ready_check() -> Json<ReadyResponse> {
    let mut checks = Vec::new();

    // 检查1：基础运行时
    checks.push(ReadyCheck {
        name: "runtime",
        status: "ok",
        message: None,
    });

    // 检查2：运行时间（需要至少运行5秒）
    let uptime = START_TIME.elapsed();
    if uptime > Duration::from_secs(5) {
        checks.push(ReadyCheck {
            name: "uptime",
            status: "ok",
            message: Some(format!("up for {}s", uptime.as_secs())),
        });
    } else {
        checks.push(ReadyCheck {
            name: "uptime",
            status: "warning",
            message: Some("just started".to_string()),
        });
    }

    let ready = checks.iter().all(|c| c.status == "ok");

    Json(ReadyResponse { ready, checks })
}
