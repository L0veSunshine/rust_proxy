use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// 使用 HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

const TIME_STEP: u64 = 30; // 30秒更新一次，同 Google Authenticator

/// 计算预共享密钥的指纹
pub fn derive_key_id(secret: &[u8]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(secret);
    let result = hasher.finalize();
    result[0..4].try_into().unwrap_or_default()
}

/// 生成基于时间的动态 UUID (16 bytes)
///
/// secret: 共享密钥 (建议 32 bytes 以上)
pub fn generate_totp_uuid(secret: &[u8]) -> Uuid {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key_id = derive_key_id(secret);
    generate_uuid_at_time(secret, &key_id, now)
}

pub fn verify_totp_uuids(key_map: Arc<HashMap<[u8; 4], Vec<u8>>>, token: &Uuid) -> bool {
    let token_bytes = token.as_bytes();
    // 1. 提取末尾 4 字节作为 KeyID
    // 客户端生成的 UUID: [Random(12) | KeyID(4)]
    let key_id: [u8; 4] = token_bytes[12..16].try_into().unwrap_or_default();
    // 2. 查表：有没有这个用户？
    if let Some(secret) = key_map.get(&key_id) {
        return verify_totp_uuid(secret, token);
    }
    false
}

/// 验证客户端传来的 UUID 是否有效
///
/// 考虑到网络延迟和时钟偏差，通常允许验证 当前时间窗口 +/- 1 的 Token
pub fn verify_totp_uuid(secret: &[u8], token: &Uuid) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key_id = derive_key_id(secret);
    // 检查当前时间窗
    if *token == generate_uuid_at_time(secret, &key_id, now) {
        return true;
    }

    // 检查上一时间窗 (容忍迟到)
    if *token == generate_uuid_at_time(secret, &key_id, now - TIME_STEP) {
        return true;
    }

    // 检查下一时间窗 (容忍时钟超前)
    if *token == generate_uuid_at_time(secret, &key_id, now + TIME_STEP) {
        return true;
    }

    false
}

fn generate_uuid_at_time(secret: &[u8], key_id: &[u8; 4], timestamp: u64) -> Uuid {
    // 1. 计算时间计数器 (Counter)
    let counter = timestamp / TIME_STEP;

    // 2. 将 Counter 转为 8字节的大端序 bytes
    let payload = counter.to_be_bytes();

    // 3. 计算 HMAC-SHA256
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(&payload);
    let result = mac.finalize().into_bytes(); // 得到 32 bytes (256 bits)

    // 4. 前12字节来自HMAC (随机性), 后4字节来自KeyID (索引)
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes[0..12].copy_from_slice(&result[0..12]);
    uuid_bytes[12..16].copy_from_slice(key_id);
    Uuid::from_bytes(uuid_bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_totp_verification() {
        let secret = b"test_secret_key";
        let uuid = generate_totp_uuid(secret);
        assert_eq!(verify_totp_uuid(secret, &uuid), true);
        assert_eq!(verify_totp_uuid(secret, &Uuid::new_v4()), false)
    }
}
