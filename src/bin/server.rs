use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use rust_proxy::api::common::ServerStatistic;
use rust_proxy::api::server::start_admin_api;
use rust_proxy::config::ServerConfig;
use rust_proxy::connection_pool::ConnectionPool;
use rust_proxy::health::SystemMetrics;
use rust_proxy::shutdown::{GracefulShutdown, setup_signal_handler};
use rust_proxy::user_manager::UserManager;
use rust_proxy::{init_logger, server};
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, ProcessesToUpdate, RefreshKind, System};

#[derive(Parser, Debug)]
#[command(
    name = "rust_proxy_server",
    about = "🦀 Rust Proxy Server - 高性能、安全加密的代理服务器"
)]
struct ServerCli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// 配置文件路径
    #[arg(short, long, default_value = "config.toml", global = true)]
    config: String,

    /// 在后台作为守护进程运行 (daemon 模式)
    #[arg(short, long)]
    daemon: bool,

    /// 内部标记：当前进程为后台子进程（不对外展示）
    #[arg(long, hide = true)]
    daemon_child: bool,

    /// PID 文件保存路径
    #[arg(long, default_value = "server.pid", global = true)]
    pid_file: String,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// 启动服务 (默认前台运行，添加 -d/--daemon 参数在后台运行)
    Start {
        /// 在后台运行 (daemon 模式)
        #[arg(short, long)]
        daemon: bool,
    },
    /// 优雅停止正在运行的服务
    Stop,
    /// 查看服务的运行状态
    Status,
    /// 重启服务
    Restart {
        /// 重启后是否在后台运行
        #[arg(short, long, default_value_t = true)]
        daemon: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = ServerCli::parse();

    match cli.command {
        Some(Commands::Stop) => stop_server(&cli.config, &cli.pid_file).await,
        Some(Commands::Status) => status_server(&cli.config, &cli.pid_file).await,
        Some(Commands::Restart { daemon }) => {
            restart_server(&cli.config, &cli.pid_file, daemon).await
        }
        Some(Commands::Start { daemon }) => {
            if daemon && !cli.daemon_child {
                spawn_daemon(&cli.config, &cli.pid_file)
            } else {
                run_server(&cli.config, &cli.pid_file, cli.daemon_child).await
            }
        }
        None => {
            // 没有指定子命令时，根据 -d/--daemon 参数决定前台或后台
            if cli.daemon && !cli.daemon_child {
                spawn_daemon(&cli.config, &cli.pid_file)
            } else {
                run_server(&cli.config, &cli.pid_file, cli.daemon_child).await
            }
        }
    }
}

/// 读取 PID 文件中的进程 ID
fn read_pid(pid_file: &str) -> Option<u32> {
    std::fs::read_to_string(pid_file)
        .ok()
        .and_then(|content| content.trim().parse::<u32>().ok())
}

/// 检查指定 PID 的进程是否存活
fn is_process_alive(pid: u32) -> bool {
    let sys_pid = Pid::from_u32(pid);
    let mut sys = System::new_with_specifics(RefreshKind::nothing());
    sys.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[sys_pid]),
        true,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    sys.process(sys_pid).is_some()
}

/// 在后台启动守护进程
fn spawn_daemon(config_path: &str, pid_file: &str) -> Result<()> {
    if let Some(existing_pid) = read_pid(pid_file) {
        if is_process_alive(existing_pid) {
            eprintln!("[-] 错误: 服务已在后台运行中 (PID: {})。", existing_pid);
            eprintln!(
                "    提示: 可使用 './server status' 查看，或 './server stop' / './server restart'。"
            );
            std::process::exit(1);
        } else {
            println!(
                "[!] 发现失效的 PID 文件 (PID {} 未运行)，正在清理...",
                existing_pid
            );
            let _ = std::fs::remove_file(pid_file);
        }
    }

    let current_exe = std::env::current_exe()?;
    let mut cmd = std::process::Command::new(current_exe);
    cmd.arg("--daemon-child")
        .arg("-c")
        .arg(config_path)
        .arg("--pid-file")
        .arg(pid_file)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;
        const DETACHED_PROCESS: u32 = 0x00000008;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        cmd.creation_flags(CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS | CREATE_NO_WINDOW);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }

    let child = cmd.spawn()?;
    let child_pid = child.id();

    // 预写入 PID
    std::fs::write(pid_file, child_pid.to_string())?;

    // 等待 500ms 检查子进程是否由于配置错误直接退出
    std::thread::sleep(Duration::from_millis(500));

    if !is_process_alive(child_pid) {
        let _ = std::fs::remove_file(pid_file);
        eprintln!("[-] 错误: 服务启动后立即退出了，请检查配置文件或日志。");
        std::process::exit(1);
    }

    let configs = ServerConfig::load(config_path).ok();
    let log_name = configs
        .as_ref()
        .map(|c| c.log_name.as_str())
        .unwrap_or("server");
    let listen_addr = configs
        .as_ref()
        .map(|c| c.listen.as_str())
        .unwrap_or("configured address");

    println!("============================================================");
    println!("🚀 rust_proxy server 已成功在后台启动！");
    println!("------------------------------------------------------------");
    println!("  进程 PID:   {}", child_pid);
    println!("  配置文件:   {}", config_path);
    println!("  PID 文件:   {}", pid_file);
    println!("  监听地址:   {}", listen_addr);
    println!("  日志前缀:   {}.*.log", log_name);
    println!("============================================================");
    println!("服务已脱离当前终端运行，按 Ctrl+C 或关闭终端不会影响服务。");
    println!("\n管理命令:");
    println!("  ./server status    - 查看服务运行状态与统计");
    println!("  ./server stop      - 优雅停止后台服务");
    println!("  ./server restart   - 重启服务");
    println!("============================================================");

    Ok(())
}

/// 优雅停止服务
async fn stop_server(config_path: &str, pid_file: &str) -> Result<()> {
    let pid = match read_pid(pid_file) {
        Some(pid) => pid,
        None => {
            println!("[-] 未找到 PID 文件 '{}'，服务可能未在运行。", pid_file);
            return Ok(());
        }
    };

    if !is_process_alive(pid) {
        println!("[!] 进程 (PID: {}) 未运行，正在清理残留的 PID 文件...", pid);
        let _ = std::fs::remove_file(pid_file);
        return Ok(());
    }

    println!("[*] 正在通知 rust_proxy 服务优雅退出 (PID: {})...", pid);

    // 1. 通过管理 API 发送优雅关闭请求
    let api_port = ServerConfig::load(config_path)
        .map(|c| c.api_port)
        .unwrap_or(1081);
    let _ = send_shutdown_api(api_port).await;

    // 2. Unix 平台同时发送 SIGTERM 信号
    #[cfg(unix)]
    {
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .output();
    }

    // 3. 轮询等待进程优雅退出（最多等待 10 秒）
    let mut exited = false;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if !is_process_alive(pid) {
            exited = true;
            break;
        }
    }

    if exited {
        let _ = std::fs::remove_file(pid_file);
        println!("[+] 服务已优雅退出 (PID: {})。", pid);
    } else {
        println!("[!] 服务在 10 秒内未完全退出，正在执行强制终止...");
        #[cfg(windows)]
        {
            let _ = std::process::Command::new("taskkill")
                .args(["/PID", &pid.to_string(), "/F"])
                .output();
        }
        #[cfg(unix)]
        {
            let _ = std::process::Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .output();
        }
        let _ = std::fs::remove_file(pid_file);
        println!("[+] 服务已强制停止 (PID: {})。", pid);
    }

    Ok(())
}

/// 查看服务运行状态
async fn status_server(config_path: &str, pid_file: &str) -> Result<()> {
    let pid = match read_pid(pid_file) {
        Some(pid) => pid,
        None => {
            println!("服务状态: 已停止 (未找到 PID 文件 '{}')", pid_file);
            return Ok(());
        }
    };

    if !is_process_alive(pid) {
        println!("服务状态: 已停止 (PID {} 已经不在线)", pid);
        return Ok(());
    }

    println!("============================================================");
    println!("服务状态: 🟢 运行中 (RUNNING)");
    println!("进程 PID:  {}", pid);
    println!("PID 文件:  {}", pid_file);

    let api_port = ServerConfig::load(config_path)
        .map(|c| c.api_port)
        .unwrap_or(1081);

    if let Ok(health) = fetch_health(api_port).await {
        println!("------------------------------------------------------------");
        if let Some(status) = health.get("status").and_then(|s| s.as_str()) {
            println!("健康状态:       {}", status);
        }
        if let Some(uptime) = health.get("uptime_seconds").and_then(|u| u.as_u64()) {
            let hours = uptime / 3600;
            let minutes = (uptime % 3600) / 60;
            let seconds = uptime % 60;
            println!("运行时间:       {}小时 {}分 {}秒", hours, minutes, seconds);
        }
        if let Some(active) = health.get("active_connections").and_then(|a| a.as_u64()) {
            println!("当前活跃连接:   {}", active);
        }
        if let Some(total) = health.get("total_connections").and_then(|t| t.as_u64()) {
            println!("累计处理连接:   {}", total);
        }
        if let Some(mem) = health.get("memory_usage_mb").and_then(|m| m.as_u64()) {
            println!("内存占用:       {} MB", mem);
        }
        if let Some(cpus) = health.get("cpu_count").and_then(|c| c.as_u64()) {
            println!("CPU 核心数:     {}", cpus);
        }
    } else {
        println!("------------------------------------------------------------");
        println!("管理 API:      未响应 (127.0.0.1:{})", api_port);
    }
    println!("============================================================");

    Ok(())
}

/// 重启服务
async fn restart_server(config_path: &str, pid_file: &str, daemon: bool) -> Result<()> {
    if read_pid(pid_file).is_some() {
        println!("[*] 正在停止现有的服务实例...");
        stop_server(config_path, pid_file).await?;
        // 短暂等待端口释放
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    if daemon {
        spawn_daemon(config_path, pid_file)
    } else {
        run_server(config_path, pid_file, false).await
    }
}

/// 运行主服务逻辑
async fn run_server(config_path: &str, pid_file: &str, is_daemon: bool) -> Result<()> {
    let configs = ServerConfig::load(config_path)?;

    // 初始化日志
    let _guard = init_logger(&configs.log_name, &configs.log_level, configs.log_max_size);

    tracing::info!("Starting rust_proxy server (daemon: {})...", is_daemon);

    // 如果是守护进程，记录当前真实 PID
    if is_daemon {
        let _ = std::fs::write(pid_file, std::process::id().to_string());
    }

    if !is_daemon {
        println!("============================================================");
        println!("🚀 rust_proxy server 正在前台运行...");
        println!("  监听地址: {}", configs.listen);
        println!("  管理端口: {}", configs.api_port);
        println!("  日志记录在: {}.*.log", configs.log_name);
        println!("  提示: 按 Ctrl+C 可优雅退出服务。");
        println!("============================================================");
    }

    // 初始化核心组件
    let user_manager = Arc::new(UserManager::new(&configs.users_db)?);
    let stat_map = ServerStatistic::new();
    let metrics = Arc::new(SystemMetrics::new());
    let shutdown = GracefulShutdown::new();
    let connection_pool = ConnectionPool::new(configs.max_connections.unwrap_or(10000));

    tracing::info!(
        "Initialized with max_connections: {}",
        connection_pool.max_connections()
    );

    // 启动 API 服务器
    let api_manager = user_manager.clone();
    let api_stat_map = stat_map.clone();
    let api_metrics = metrics.clone();
    let api_shutdown = shutdown.clone();

    tokio::spawn(async move {
        let api_listen = format!("127.0.0.1:{}", configs.api_port);
        if let Err(e) = start_admin_api(
            &api_listen,
            api_manager,
            api_stat_map,
            api_metrics,
            api_shutdown.clone(),
        )
        .await
        {
            tracing::error!("API server error: {}", e);
            api_shutdown.trigger_shutdown();
        }
    });

    // 每小时清理不活跃的限速器
    let manager_for_cleanup = user_manager.clone();
    let cleanup_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(3600));
        interval.tick().await; // 第一次立即完成

        loop {
            tokio::select! {
                _ = cleanup_shutdown.wait_shutdown() => break,
                _ = interval.tick() => {
                    tracing::info!("Cleaning up inactive rate limiters");
                    manager_for_cleanup.limiters.retain(|key_id, _| {
                        manager_for_cleanup.ip_tracker.contains_key(key_id)
                    });
                }
            }
        }
        tracing::info!("Limiter cleanup task stopped");
    });

    // 设置信号处理器（daemon 模式下忽略 Ctrl+C）
    let signal_shutdown = shutdown.clone();
    tokio::spawn(async move {
        setup_signal_handler(signal_shutdown, is_daemon).await;
    });

    // 运行主服务器
    tracing::info!("Server starting on {}", configs.listen);
    let server_shutdown = shutdown.clone();
    let server_result = tokio::select! {
        result = server::run(configs, user_manager, stat_map, metrics, connection_pool, shutdown.clone()) => result,
        _ = server_shutdown.wait_shutdown() => {
            tracing::info!("Received shutdown signal");
            Ok(())
        }
    };

    // 执行优雅关闭
    tracing::info!("Shutting down gracefully...");
    shutdown.shutdown(Duration::from_secs(30)).await;

    // 清理 PID 文件
    if is_daemon {
        let _ = std::fs::remove_file(pid_file);
    }

    server_result
}

/// 通过管理 API 发送优雅关闭指令
async fn send_shutdown_api(port: u16) -> Result<()> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    let addr = format!("127.0.0.1:{}", port);
    let mut stream =
        tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await??;

    let req = format!(
        "POST /shutdown HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        port
    );
    stream.write_all(req.as_bytes()).await?;
    Ok(())
}

/// 获取服务健康状态
async fn fetch_health(port: u16) -> Result<serde_json::Value> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let addr = format!("127.0.0.1:{}", port);
    let mut stream =
        tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(&addr)).await??;

    let req = format!(
        "GET /health HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
        port
    );
    stream.write_all(req.as_bytes()).await?;

    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await??;

    let text = String::from_utf8_lossy(&response);
    if let Some(pos) = text.find("\r\n\r\n") {
        let body = &text[pos + 4..];
        let val: serde_json::Value = serde_json::from_str(body)?;
        return Ok(val);
    }

    Err(anyhow!("Invalid response from health API"))
}
