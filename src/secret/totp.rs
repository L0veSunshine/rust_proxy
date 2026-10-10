use crate::secret::replay::{REPLAY_GUARD, now_secs};
use crate::user_manager::{UserManager, UserProfile};
use hmac::{Hmac, KeyInit, Mac};
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU32, Ordering};
use uuid::Uuid;

// 使用 HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

const TIME_STEP: u64 = 10; // 10秒更新一次，减少攻击面

/// Token 布局: [Nonce(4) | HMAC(8) | KeyID(4)]
const NONCE_LEN: usize = 4;
const TAG_LEN: usize = 8;

/// 进程内单调递增的 nonce 计数器。
///
/// 防重放缓存是进程级的，因此只要保证"本进程内不重复"，就不会出现
/// 同一窗口内两条合法连接拿到相同 token、其中一条被误判为重放的情况。
/// 进程启动时随机播种后递增：进程内零碰撞，同时让不同进程/不同客户端的
/// 序列彼此错开，降低跨进程碰撞概率(把 32bit 随机 nonce 的生日碰撞问题消掉)。
static NONCE_COUNTER: AtomicU32 = AtomicU32::new(0);

/// 取下一个 nonce(进程内保证不重复)
fn next_nonce() -> [u8; NONCE_LEN] {
    static SEED: LazyLock<u32> = LazyLock::new(|| rand::rng().random());
    let step = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    SEED.wrapping_add(step).to_be_bytes()
}

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
///
/// 每次调用都会带上一个全新的 Nonce(进程内单调递增)，所以同一个时间窗内
/// 多次连接得到的 Token 也互不相同，服务端才能用"一次性"的方式校验。
pub fn generate_totp_uuid(secret: &[u8]) -> Uuid {
    let key_id = derive_key_id(secret);
    let nonce = next_nonce();
    generate_uuid_at_counter(secret, &key_id, &nonce, now_secs() / TIME_STEP)
}

/// 一次成功校验的结果：Token 密码学有效，但尚未被"消费"。
#[derive(Clone)]
pub struct VerifiedToken {
    pub profile: UserProfile,
    /// 该 Token 在 TOTP 层面最晚可用的时间点(Unix 秒)
    pub expire_at: u64,
}

/// 校验 Token 并返回对应用户(仅密码学校验，**不消费** Token)
///
/// 调用方应在所有前置检查(如 IP 限制)通过后，再调用 [`consume_token`]
/// 把这次使用记为已消费，避免后续步骤失败时把 Token 白白烧掉。
pub fn verify_user_token(user_manager: &UserManager, token: &Uuid) -> Option<VerifiedToken> {
    let token_bytes = token.as_bytes();
    // 1. 提取末尾 4 字节作为 KeyID
    // 客户端生成的 UUID: [Nonce(4) | HMAC(8) | KeyID(4)]
    let key_id: [u8; 4] = token_bytes[12..16].try_into().ok()?;
    // 2. 查表：有没有这个用户？
    let profile = user_manager.cache.get(&key_id)?;
    // 3. 校验 TOTP，拿到命中的时间窗
    let counter = match_totp_window(&profile.secret, token)?;
    // 4. 计算过期时间：counter 这个窗口的 Token 最晚会被 counter + 1 窗口接受，
    //    所以缓存保留到 (counter + 2) * TIME_STEP 即可。
    let expire_at = counter.saturating_add(2).saturating_mul(TIME_STEP);

    Some(VerifiedToken {
        profile: profile.value().clone(),
        expire_at,
    })
}

/// 消费 Token：返回 `true` 表示首次使用(放行)，`false` 表示重放(拒绝)
///
/// 与密码学校验分开，便于调用方在通过全部前置检查后再记账。
pub fn consume_token(token: &Uuid, expire_at: u64) -> bool {
    REPLAY_GUARD.try_use(token, expire_at)
}

/// Token 指纹(截断 SHA256 的十六进制)。
///
/// 仅用于日志排查：既能唯一定位一次握手，又不会把可用于重放的原始
/// Token 写进日志。
pub fn token_fingerprint(token: &Uuid) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(&hasher.finalize()[..4])
}

/// 验证客户端传来的 UUID 是否有效
///
/// 考虑到网络延迟和时钟偏差，通常允许验证 当前时间窗口 +/- 1 的 Token
///
/// 注意：这里只做密码学校验，不含防重放，防重放在 [`consume_token`] 中完成。
pub fn verify_totp_uuid(secret: &[u8], token: &Uuid) -> bool {
    match_totp_window(secret, token).is_some()
}

/// 校验 Token 并返回命中的时间窗计数器
fn match_totp_window(secret: &[u8], token: &Uuid) -> Option<u64> {
    let key_id = derive_key_id(secret);
    let token_bytes = token.as_bytes();
    if token_bytes[12..16] != key_id {
        return None;
    }
    let nonce: [u8; NONCE_LEN] = token_bytes[0..NONCE_LEN].try_into().ok()?;

    let current = now_secs() / TIME_STEP;
    // 依次检查：当前窗、上一窗(容忍迟到)、下一窗(容忍时钟超前)
    [current, current.saturating_sub(1), current.saturating_add(1)]
        .into_iter()
        .find(|&counter| *token == generate_uuid_at_counter(secret, &key_id, &nonce, counter))
}

fn generate_uuid_at_counter(
    secret: &[u8],
    key_id: &[u8; 4],
    nonce: &[u8; NONCE_LEN],
    counter: u64,
) -> Uuid {
    // 1. 计算 HMAC-SHA256(counter || nonce)
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC can take key of any size");
    mac.update(&counter.to_be_bytes());
    mac.update(nonce);
    let result = mac.finalize().into_bytes(); // 得到 32 bytes (256 bits)

    // 2. 前4字节是客户端 Nonce (保证每次连接的 Token 都不同),
    //    中间8字节来自 HMAC (认证), 后4字节是 KeyID (索引)
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes[0..NONCE_LEN].copy_from_slice(nonce);
    uuid_bytes[NONCE_LEN..NONCE_LEN + TAG_LEN].copy_from_slice(&result[0..TAG_LEN]);
    uuid_bytes[12..16].copy_from_slice(key_id);
    Uuid::from_bytes(uuid_bytes)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::secret::replay::ReplayGuard;

    #[test]
    fn test_totp_verification() {
        let secret = b"test_secret_key";
        let uuid = generate_totp_uuid(secret);
        assert!(verify_totp_uuid(secret, &uuid));
        assert!(!verify_totp_uuid(secret, &Uuid::new_v4()))
    }

    #[test]
    fn test_token_is_unique_per_call() {
        let secret = b"test_secret_key";
        let a = generate_totp_uuid(secret);
        let b = generate_totp_uuid(secret);
        // 同一个时间窗内两次生成的 Token 必须不同，否则正常客户端
        // 第二条连接会被防重放缓存误杀
        assert_ne!(a, b);
        assert!(verify_totp_uuid(secret, &a));
        assert!(verify_totp_uuid(secret, &b));
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let secret = b"test_secret_key";
        let uuid = generate_totp_uuid(secret);
        assert!(!verify_totp_uuid(b"another_secret", &uuid));
    }

    #[test]
    fn test_tampered_nonce_rejected() {
        let secret = b"test_secret_key";
        let uuid = generate_totp_uuid(secret);
        let mut bytes = *uuid.as_bytes();
        bytes[0] ^= 0xff;
        assert!(!verify_totp_uuid(secret, &Uuid::from_bytes(bytes)));
    }

    #[test]
    fn test_replay_guard_blocks_second_use() {
        let secret = b"test_secret_key";
        let token = generate_totp_uuid(secret);
        let counter = match_totp_window(secret, &token).expect("token should be valid");
        let expire_at = (counter + 2) * TIME_STEP;

        let guard = ReplayGuard::new();
        assert!(guard.try_use(&token, expire_at));
        assert!(!guard.try_use(&token, expire_at));
        // 密码学校验本身仍然通过，被拦下来的只是"重复使用"
        assert!(verify_totp_uuid(secret, &token));
    }

    #[test]
    fn test_nonce_no_collision_in_window() {
        use std::collections::HashSet;
        // 同一时间窗内生成 10 万个 Token，nonce 不允许重复，
        // 否则后面的合法连接会被防重放缓存误判成重放。
        let mut seen = HashSet::new();
        for _ in 0..100_000 {
            assert!(seen.insert(next_nonce()), "nonce 发生碰撞");
        }
    }
}
