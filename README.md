# 🦀 Rust Proxy

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Edition](https://img.shields.io/badge/rust-2024-orange.svg)](Cargo.toml)

一个高性能、安全可靠的代理服务器和客户端，使用 Rust 编写，支持 TCP/UDP 转发、TLS 加密、用户认证、流量限速等功能。

## ✨ 特性

- 🔐 **安全加密**: TLS 1.3 加密传输，TOTP 动态认证
- 🚀 **高性能**: 基于 Tokio 异步运行时，零拷贝设计
- 🌐 **协议支持**: HTTP/HTTPS 代理、SOCKS5 代理（TCP/UDP）
- 📊 **流量管理**: 用户限速、连接数限制、实时统计
- 🛡️ **防护机制**: Slowloris 攻击防御、重复攻击、主动探测、流量混淆（随机 Padding）
- 📈 **管理接口**: RESTful API 管理用户和查看统计

## 🏗️ 架构

```
┌─────────────┐   HTTP/SOCKS5      ┌──────────────┐   TLS + Protocol    ┌──────────────┐ TCP/UDP    ┌──────────┐
│ 本地应用程序 │ ───────────────►   │ Proxy Client │ ──────────────────► │ Proxy Server │ ─────────► │目标服务器 │
└─────────────┘                    └──────────────┘                     └──────────────┘            └──────────┘
                                                                              │
                                                                              │ HTTP API
                                                                              ▼
                                                                     ┌─────────────────┐
                                                                     │ 用户管理 / 统计  │
                                                                     └─────────────────┘
```

## 📦 快速开始

### 前置要求

- Rust 1.75+ ([安装指南](https://www.rust-lang.org/tools/install))
- OpenSSL (用于生成证书)

### 1️⃣ 克隆项目

```bash
git clone <repository-url>
cd rust_proxy
```

### 2️⃣ 生成 TLS 证书

```bash
# 生成自签名证书（有效期 365 天）
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
  -days 365 -nodes -subj "/CN=localhost"
```

### 3️⃣ 配置服务端

创建 `config.toml`:

```toml
# 服务端监听端口
port = 8443

# API 管理端口
api_port = 1081

# TLS 证书路径
cert_path = "cert.pem"
key_path = "key.pem"

# 用户数据库路径
users_db = "users.db"

# 日志配置
log_level = "info"          # trace, debug, info, warn, error
log_name = "server"         # 日志文件名前缀
log_max_size = 10485760     # 日志轮转大小（10MB）
```

### 4️⃣ 编译项目

```bash
# 开发版本
cargo build

# 生产版本（体积更小，性能更优）
cargo build --release
```

### 5️⃣ 启动服务端

```bash
# 使用开发版本
./target/debug/server

# 使用生产版本
./target/release/server
```

### 6️⃣ 创建用户

```bash
# 生成一个 UUID 作为用户密钥
UUID=$(uuidgen)  # 或使用在线工具生成

# 添加用户
curl -X POST http://localhost:1081/user \
  -H "Content-Type: application/json" \
  -d "{
    \"uuid\": \"$UUID\",
    \"max_ip\": 3,
    \"rate_limit\": 1048576
  }"

# 响应示例：
# {"key_id":"a1b2c3d4"}
```

参数说明：
- `uuid`: 用户的 UUID 密钥（16字节，客户端需要）
- `max_ip`: 最大同时连接 IP 数（0 表示无限制）
- `rate_limit`: 速率限制（字节/秒，0 表示无限制）

### 7️⃣ 启动客户端

```bash
./target/release/client \
  --key <YOUR_UUID> \
  --remote <SERVER_IP>:8443 \
  --local 127.0.0.1:1080 \
  --ca-path cert.pem
```

参数说明：
- `--key`: 在第 6 步创建的 UUID
- `--remote`: 服务端地址
- `--local`: 本地监听地址（代理地址）
- `--ca-path`: 服务端证书路径

### 8️⃣ 配置应用使用代理

客户端支持两种代理协议，可以根据应用选择：

**HTTP/HTTPS 代理：**
```
代理地址: 127.0.0.1
端口: 1080
```

**SOCKS5 代理：**
```
服务器: 127.0.0.1
端口: 1080
```

## 🔧 管理接口

服务端提供 RESTful API 用于用户管理和统计查询（默认端口 1081）。

### 用户管理

#### 创建用户

```bash
POST /user
Content-Type: application/json

{
  "uuid": "550e8400-e29b-41d4-a716-446655440000",
  "max_ip": 3,
  "rate_limit": 1048576
}

# 响应：
# {"key_id": "a1b2c3d4"}
```

#### 查询所有用户

```bash
GET /users

# 响应：
[
  {
    "id": "550e8400e29b41d4a716446655440000",
    "max_ip": 3,
    "rate_limit": 1048576
  }
]
```

#### 修改用户

```bash
PUT /user/{key_id}
Content-Type: application/json

{
  "max_ip": 5,
  "rate_limit": 2097152
}
```

#### 删除用户

```bash
DELETE /user/{key_id}
```

### 统计查询

#### 查询在线用户

```bash
GET /status

# 响应：
[
  {
    "key_id": "a1b2c3d4",
    "ips": ["192.168.1.100", "10.0.0.5"],
    "upload": 1024000,
    "download": 2048000
  }
]
```

## 📊 客户端统计接口

客户端也提供统计接口（端口由 `--api-port` 指定，默认 1081）：

```bash
GET http://localhost:1081/stats

# 响应：
{
  "upload": 1024000,
  "download": 2048000
}
```

## 🛠️ 高级配置

### 服务端命令行参数

服务端使用配置文件，无需命令行参数。

### 客户端命令行参数

```bash
client [OPTIONS]

选项:
  --key <KEY>                    用户 UUID 密钥（必需）
  --remote <REMOTE>              服务端地址（必需）
  --local <LOCAL>                本地监听地址 [默认: 127.0.0.1:1080]
  --ca-path <CA_PATH>            服务端证书路径 [默认: cert.pem]
  --api-port <API_PORT>          API 端口 [默认: 1081]
  --log-level <LOG_LEVEL>        日志级别 [默认: info]
  --log-rotate-size <SIZE>       日志轮转大小 [默认: 10485760]
  -h, --help                     显示帮助信息
```

### 系统服务部署

创建 systemd 服务文件 `/etc/systemd/system/rust-proxy-server.service`:

```ini
[Unit]
Description=Rust Proxy Server
After=network.target

[Service]
Type=simple
User=proxy
WorkingDirectory=/opt/rust_proxy
ExecStart=/opt/rust_proxy/server
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

启用并启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable rust-proxy-server
sudo systemctl start rust-proxy-server
```

## 🔐 安全建议

1. **使用强密钥**: 使用安全的 UUID 生成器（如 `uuidgen` 或在线工具）
2. **证书管理**: 生产环境建议使用 Let's Encrypt 等正规证书
3. **防火墙配置**: 限制管理 API (1081) 仅内网访问
4. **定期更新**: 及时更新依赖项以修复安全漏洞
5. **日志审计**: 定期检查日志文件，发现异常行为
6. **限速设置**: 为每个用户设置合理的速率限制

## 📝 协议说明

项目使用自定义二进制协议，详见 [`src/protocol/message.md`](src/protocol/message.md)。

**主要特性：**
- TOTP 动态 UUID 认证（基于时间戳）
- 随机 Padding（16-128 字节）实现流量混淆
- 支持 IPv4/IPv6/域名地址
- 0-RTT 握手优化

## 🧪 测试

```bash
# 运行所有测试
cargo test

# 运行特定模块测试
cargo test --lib protocol

# 详细输出
cargo test -- --nocapture
```

## 📈 性能基准

在 Intel i7-12700K, 32GB RAM 测试环境下：

- **吞吐量**: ~2.5 Gbps (单核)
- **延迟**: < 1ms (本地)
- **并发连接**: > 10,000
- **内存占用**: ~10MB (基础) + ~1KB/连接

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

本项目采用 [Apache License 2.0](LICENSE) 许可证。

## 🙏 致谢

- [Tokio](https://tokio.rs/) - 异步运行时
- [rustls](https://github.com/rustls/rustls) - TLS 实现
- [Axum](https://github.com/tokio-rs/axum) - Web 框架
- [redb](https://github.com/cberner/redb) - 嵌入式数据库

## 📮 联系方式

如有问题或建议，请提交 Issue 或联系项目维护者。

---

**注意**: 本项目仅供学习和个人使用，请遵守当地法律法规。
