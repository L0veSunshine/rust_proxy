use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// 两次清理之间的最小间隔(秒)，避免每次握手都做全表扫描
const PURGE_INTERVAL: u64 = 5;

/// 缓存条目数的安全上限。
///
/// 正常靠时间清理就够了；但如果系统时钟被回拨，"按时间清理"会暂时失效，
/// 这里给一个兜底，保证缓存不会无限膨胀。
const MAX_CACHED_TOKENS: usize = 100_000;

/// 全局的重放防御缓存
///
/// TOTP 只能把攻击面压缩到一个时间窗内，无法阻止攻击者在窗口内
/// 原样重放抓到的 Token，所以这里再记录一份"已经用掉的 Token"。
pub static REPLAY_GUARD: LazyLock<ReplayGuard> = LazyLock::new(ReplayGuard::new);

/// 已使用 Token 的内存缓存
///
/// key: 客户端送上来的 Token (UUID)
/// value: 该 Token 的失效时间点(Unix 秒)，过了这个点 TOTP 本身就不会再接受它，
///        所以缓存里也没有继续保留的必要。
pub struct ReplayGuard {
    used: DashMap<Uuid, u64>,
    last_purge: AtomicU64,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self {
            used: DashMap::new(),
            last_purge: AtomicU64::new(now_secs()),
        }
    }

    /// 尝试消费一个 Token
    ///
    /// - `expire_at`: 该 Token 在 TOTP 校验层面的最晚可用时间(Unix 秒)
    ///
    /// 返回 `true` 表示这是第一次使用(放行)，`false` 表示重放(拒绝)。
    pub fn try_use(&self, token: &Uuid, expire_at: u64) -> bool {
        let now = now_secs();
        self.purge_if_needed(now);

        match self.used.entry(*token) {
            // 已经记录过：只有旧记录本身已经过期才允许再次写入
            Entry::Occupied(mut entry) => {
                if *entry.get() <= now {
                    entry.insert(expire_at);
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(expire_at);
                true
            }
        }
    }

    /// 清理过期记录，保证缓存不会无限增长
    fn purge_if_needed(&self, now: u64) {
        let last = self.last_purge.load(Ordering::Relaxed);
        // 到点清理；或条目过多时兜底清理(防时钟回拨导致定时清理失效)
        let time_due = now >= last.saturating_add(PURGE_INTERVAL);
        let size_due = self.used.len() >= MAX_CACHED_TOKENS;
        if !time_due && !size_due {
            return;
        }
        // 同一时刻只让一个线程去做清理
        if self
            .last_purge
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        self.used.retain(|_, expire_at| *expire_at > now);
    }

    /// 当前缓存中的记录条数(含尚未清理的过期项)
    pub fn len(&self) -> usize {
        self.used.len()
    }

    pub fn is_empty(&self) -> bool {
        self.used.is_empty()
    }

    pub fn clear(&self) {
        self.used.clear();
    }
}

/// 当前 Unix 秒。
///
/// 系统时钟异常(早于 epoch)时退化为 0，绝不 panic。
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_reject_replay() {
        let guard = ReplayGuard::new();
        let token = Uuid::new_v4();
        let expire_at = now_secs() + 30;

        assert!(guard.try_use(&token, expire_at));
        // 同一个 Token 再来一次必须被拒绝
        assert!(!guard.try_use(&token, expire_at));
        // 其他 Token 不受影响
        assert!(guard.try_use(&Uuid::new_v4(), expire_at));
    }

    #[test]
    fn test_expired_record_can_be_reused() {
        let guard = ReplayGuard::new();
        let token = Uuid::new_v4();

        // 写入一条"已经过期"的记录
        assert!(guard.try_use(&token, now_secs().saturating_sub(1)));
        // 过期后 TOTP 本身也不会再放行，缓存不应该误伤
        assert!(guard.try_use(&token, now_secs() + 30));
    }

    #[test]
    fn test_purge_removes_expired() {
        let guard = ReplayGuard::new();
        let now = now_secs();
        for _ in 0..100 {
            guard.try_use(&Uuid::new_v4(), now.saturating_sub(1));
        }
        assert_eq!(guard.len(), 100);

        // 强制触发一次清理
        guard
            .last_purge
            .store(now.saturating_sub(PURGE_INTERVAL), Ordering::Relaxed);
        guard.try_use(&Uuid::new_v4(), now + 30);
        assert_eq!(guard.len(), 1);
    }
}
