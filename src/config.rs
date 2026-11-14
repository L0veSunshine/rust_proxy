use anyhow::Result;
use std::fs;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub port: u16,

    #[serde(default = "listen_addr")]
    pub listen: String,

    #[serde(default = "api_port")]
    pub api_port: u16,

    #[serde(default)]
    pub max_connections: Option<usize>,

    #[serde(default = "cert_path")]
    pub cert_path: String,

    #[serde(default = "key_path")]
    pub key_path: String,

    #[serde(default = "user_db")]
    pub users_db: String,

    #[serde(default = "log_level")]
    pub log_level: String,

    #[serde(default = "log_name")]
    pub log_name: String,

    #[serde(default = "log_rotate_size")]
    pub log_max_size: u64,
}

impl ServerConfig {
    pub fn load(path: &str) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut config: ServerConfig = toml::from_str(&content)?;
        config.normalize()?;
        Ok(config)
    }

    /// 规范化配置并校验
    pub fn normalize(&mut self) -> Result<()> {
        let addr = self.listen_addr()?;
        self.listen = addr.to_string();
        self.port = addr.port();
        Ok(())
    }

    /// 解析最终监听的 SocketAddr
    pub fn listen_addr(&self) -> Result<std::net::SocketAddr> {
        // 1. 尝试直接解析为 SocketAddr（如 "0.0.0.0:8443" 或 "[::]:8443"）
        if let Ok(mut addr) = self.listen.parse::<std::net::SocketAddr>() {
            if addr.port() == 0 {
                addr.set_port(self.port);
            }
            return Ok(addr);
        }

        // 2. 尝试作为纯 IP 解析（如 "0.0.0.0", "127.0.0.1", "::", "[::]"）
        let ip_clean = self
            .listen
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']');
        if let Ok(ip) = ip_clean.parse::<std::net::IpAddr>() {
            return Ok(std::net::SocketAddr::new(ip, self.port));
        }

        anyhow::bail!("无法解析监听地址: '{}'", self.listen)
    }
}

#[macro_export]
macro_rules! default_value {
    ($name:ident,$type:ty,$val:expr) => {
        fn $name() -> $type {
            $val
        }
    };
}

// === 下面是定义默认值 ===
default_value!(listen_addr, String, String::from("[::]:0"));
default_value!(api_port, u16, 1081);
default_value!(cert_path, String, String::from("cert.pem"));
default_value!(key_path, String, String::from("key.pem"));
default_value!(user_db, String, String::from("users.db"));
default_value!(log_level, String, String::from("info"));
default_value!(log_name, String, String::from("server"));
default_value!(log_rotate_size, u64, 10 * 1024 * 1024);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_listen_address() {
        let toml_str = r#"
            port = 8443
        "#;
        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.listen, "[::]:0");
        config.normalize().unwrap();
        assert_eq!(config.listen, "[::]:8443");
        assert_eq!(config.port, 8443);
    }

    #[test]
    fn test_ipv4_listen_address() {
        let toml_str = r#"
            port = 8443
            listen = "0.0.0.0"
        "#;
        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        config.normalize().unwrap();
        assert_eq!(config.listen, "0.0.0.0:8443");
        assert_eq!(config.port, 8443);
    }

    #[test]
    fn test_custom_port_in_listen() {
        let toml_str = r#"
            port = 8443
            listen = "127.0.0.1:9090"
        "#;
        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        config.normalize().unwrap();
        assert_eq!(config.listen, "127.0.0.1:9090");
        assert_eq!(config.port, 9090);
    }

    #[test]
    fn test_ipv6_bracket_listen_address() {
        let toml_str = r#"
            port = 8443
            listen = "[::]"
        "#;
        let mut config: ServerConfig = toml::from_str(toml_str).unwrap();
        config.normalize().unwrap();
        assert_eq!(config.listen, "[::]:8443");
    }
}
