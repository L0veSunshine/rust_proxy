use dashmap::DashMap;
use dashmap::mapref::entry::Entry;
use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// 两次"按时间清理"之间的最小间隔(秒)，避免每次握手都做全表扫描
const PURGE_INTERVAL: u64 = 5;

/// 两次"按容量兜底裁剪"之间的最小间隔(秒)。
/// 容量裁剪只有在缓存真的顶到上限时才可能触发，这里同样做节流，
/// 防止在极端情况下退化成"每次握手都扫描全表"。
const TRIM_INTERVAL: u64 = 5;

/// 缓存条目数的安全上限(默认)。
///
/// 正常靠时间清理就够了：Token 的 TOTP 窗口只有几秒，
/// 过期记录会被定期清掉，缓存规模基本等于"一个时间窗内的握手数"。
/// 只有在时间清理失效(如系统时钟被回拨)时才会顶到上限，
/// 这时由容量兜底裁剪保证内存有界。
const MAX_CACHED_TOKENS: usize = 100_000;

/// 全局的重放防御缓存
///
/// TOTP 只能把攻击面压缩到一个时间窗内，无法阻止攻击者在窗口内
/// 原样重放抓到的 Token，所以这里再记录一份"已经用掉的 Token"。
///
/// 容量策略：正常由时间清理维持规模；上限只作为时钟异常时的兜底，
/// 详见 [`ReplayGuard::purge_if_needed`]。
pub static REPLAY_GUARD: LazyLock<ReplayGuard> = LazyLock::new(ReplayGuard::new);

/// 已使用 Token 的内存缓存
///
/// key: 客户端送上来的 Token (UUID)
/// value: 该 Token 的失效时间点(Unix 秒)，过了这个点 TOTP 本身就不会再接受它，
///        所以缓存里也没有继续保留的必要。
pub struct ReplayGuard {
    used: DashMap<Uuid, u64>,
    /// 条目数上限
    max_entries: usize,
    /// 上次按时间清理的时间点(节流用)
    last_purge: AtomicU64,
    /// 上次按容量裁剪的时间点(节流用)
    last_trim: AtomicU64,
}

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayGuard {
    pub fn new() -> Self {
        Self::with_max_entries(MAX_CACHED_TOKENS)
    }

    /// 以指定条目上限创建一个缓存(便于测试)
    fn with_max_entries(max_entries: usize) -> Self {
        let now = now_secs();
        Self {
            used: DashMap::new(),
            max_entries,
            last_purge: AtomicU64::new(now),
            last_trim: AtomicU64::new(now),
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

    /// 维护缓存规模，分两级处理：
    ///
    /// 1. **按时间清理**：最多每 [`PURGE_INTERVAL`] 秒扫描一次，移除已经过期
    ///    的记录。正常时钟下 Token 的失效时间只有几秒，这一步就足以让缓存规模
    ///    维持在一个时间窗内，不会随握手次数增长。
    /// 2. **按容量兜底**：如果时间清理没能压住规模(典型原因是系统时钟被回拨，
    ///    导致 `expire_at > now` 恒成立)，缓存会顶到 [`MAX_CACHED_TOKENS`]。
    ///    此时节流地丢弃最早失效的一半记录，保证内存有界。
    ///
    /// 两级都用时间戳节流，因此**不会**出现"缓存满了以后每次握手都全表扫描"
    /// 的问题(那会把每次认证都变成 O(n))。
    fn purge_if_needed(&self, now: u64) {
        if self.try_acquire_turn(&self.last_purge, now, PURGE_INTERVAL) {
            self.used.retain(|_, expire_at| *expire_at > now);
        }

        if self.used.len() >= self.max_entries
            && self.try_acquire_turn(&self.last_trim, now, TRIM_INTERVAL)
        {
            self.trim_to_half();
        }
    }

    /// 节流：只有距上次执行超过 `interval` 且抢到执行权时才返回 true，
    /// 保证同一时间只有一个线程做清理，且不会每个请求都触发。
    fn try_acquire_turn(&self, last: &AtomicU64, now: u64, interval: u64) -> bool {
        let previous = last.load(Ordering::Relaxed);
        if now < previous.saturating_add(interval) {
            return false;
        }
        last.compare_exchange(previous, now, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// 丢弃最早失效的一半记录，把缓存规模拉回上限以下。
    ///
    /// 注意：这是内存有界优先的兜底手段，在时间清理失效的情况下会牺牲一部分
    /// 窗口内的防重放能力，换取缓存不无限膨胀。
    fn trim_to_half(&self) {
        let mut deadlines: Vec<u64> = self.used.iter().map(|entry| *entry.value()).collect();
        if deadlines.is_empty() {
            return;
        }
        // 取失效时间的中位数作为截断点，保留较晚失效的那一半
        let mid = deadlines.len() / 2;
        let (_, cutoff, _) = deadlines.select_nth_unstable(mid);
        let cutoff = *cutoff;
        self.used.retain(|_, expire_at| *expire_at > cutoff);
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

    #[test]
    fn test_purge_is_throttled() {
        let guard = ReplayGuard::new();
        let now = now_secs();

        // 让第一次调用可以清理
        guard
            .last_purge
            .store(now.saturating_sub(PURGE_INTERVAL), Ordering::Relaxed);
        assert!(guard.try_use(&Uuid::new_v4(), now + 30));
        let after_first = guard.last_purge.load(Ordering::Relaxed);

        // 紧接着的大量握手不应再触发全表扫描，
        // 否则缓存一满，每次认证都会退化成 O(n)
        for _ in 0..1000 {
            assert!(guard.try_use(&Uuid::new_v4(), now + 30));
        }
        assert_eq!(guard.last_purge.load(Ordering::Relaxed), after_first);
    }

    #[test]
    fn test_trim_to_half_evicts_earliest_deadlines() {
        let guard = ReplayGuard::with_max_entries(10);
        let now = now_secs();
        for i in 0..10u64 {
            assert!(guard.try_use(&Uuid::new_v4(), now + i + 1));
        }
        assert_eq!(guard.len(), 10);

        guard.trim_to_half();

        // 丢弃最早失效的一半，保留较晚失效的记录
        assert!(
            (4..=5).contains(&guard.len()),
            "裁剪后应剩约一半，实际 {}",
            guard.len()
        );
        assert!(guard.used.iter().all(|entry| *entry.value() > now + 5));
    }

    #[test]
    fn test_capacity_trim_keeps_cache_bounded() {
        // 模拟"系统时钟被回拨导致时间清理失效"：所有记录都远未过期
        let guard = ReplayGuard::with_max_entries(10);
        let now = now_secs();

        for i in 0..50u64 {
            // 放开裁剪节流，验证容量兜底的效果
            guard
                .last_trim
                .store(now.saturating_sub(TRIM_INTERVAL), Ordering::Relaxed);
            assert!(guard.try_use(&Uuid::new_v4(), now + 3600 + i));
        }

        // 缓存规模被限制在上限以内，不会随写入次数线性增长
        assert!(guard.len() <= 10, "缓存超过上限: {}", guard.len());
    }
}
