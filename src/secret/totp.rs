use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// 使用 HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

const TIME_STEP: u64 = 30; // 30秒更新一次，同 Google Authenticator

/// 生成基于时间的动态 UUID (16 bytes)
///
/// secret: 共享密钥 (建议 32 bytes 以上)
pub fn generate_totp_uuid(secret: &[u8]) -> Uuid {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    generate_uuid_at_time(secret, now)
}

/// 验证客户端传来的 UUID 是否有效
///
/// 考虑到网络延迟和时钟偏差，通常允许验证 当前时间窗口 +/- 1 的 Token
pub fn verify_totp_uuid(secret: &[u8], token: &Uuid) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 检查当前时间窗
    if *token == generate_uuid_at_time(secret, now) {
        return true;
    }

    // 检查上一时间窗 (容忍迟到)
    if *token == generate_uuid_at_time(secret, now - TIME_STEP) {
        return true;
    }

    // 检查下一时间窗 (容忍时钟超前)
    if *token == generate_uuid_at_time(secret, now + TIME_STEP) {
        return true;
    }

    false
}

fn generate_uuid_at_time(secret: &[u8], timestamp: u64) -> Uuid {
    // 1. 计算时间计数器 (Counter)
    let counter = timestamp / TIME_STEP;

    // 2. 将 Counter 转为 8字节的大端序 bytes
    let payload = counter.to_be_bytes();

    // 3. 计算 HMAC-SHA256
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(&payload);
    let result = mac.finalize().into_bytes(); // 得到 32 bytes (256 bits)

    // 4. 截取前 16 bytes 转为 UUID
    // SHA256 的输出看起来是随机的，直接截取前16个字节作为 UUID 是安全的
    let bytes: [u8; 16] = result[0..16].try_into().unwrap_or_default();

    Uuid::from_bytes(bytes)
}
