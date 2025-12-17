use crate::secret::totp::derive_key_id;
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ServerConfig {
    pub port: u16,

    #[serde(default = "api_port")]
    pub api_port: u16,

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
        let config: ServerConfig = toml::from_str(&content)?;
        Ok(config)
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
default_value!(api_port, u16, 1081);
default_value!(cert_path, String, String::from("cert.pem"));
default_value!(key_path, String, String::from("key.pem"));
default_value!(user_db, String, String::from("users.json"));
default_value!(log_level, String, String::from("info"));
default_value!(log_name, String, String::from("server"));
default_value!(log_rotate_size, u64, 10 * 1024 * 1024);

pub fn get_shared_keys(file_name: &str) -> Result<Vec<Vec<u8>>> {
    let content = fs::read_to_string(file_name)?;
    let keys: Vec<Vec<u8>> = content
        .split(";")
        .map(|k| k.trim())
        .filter_map(|s| {
            let trimmed = s.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.as_bytes().to_vec())
            }
        })
        .collect();
    Ok(keys)
}

pub fn build_key_map(keys: &[Vec<u8>]) -> Arc<HashMap<[u8; 4], Vec<u8>>> {
    let mut key_map: HashMap<[u8; 4], Vec<u8>> = HashMap::new();
    for key in keys.iter() {
        let id = derive_key_id(key);
        key_map.entry(id).or_insert(key.clone());
    }
    Arc::new(key_map)
}
