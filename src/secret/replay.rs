use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

/// 默认缓存条目数的严格瞬时上限。
///
/// 在 10s TOTP 步长（最多约 20~30s 有效窗口）下可支撑约 3,300~5,000 次/秒的新建握手；
/// 超出上限且清理全部已过期条目后仍满载时采用 fail-closed 拒绝，绝不提前淘汰仍有效的记录。
const MAX_CACHED_TOKENS: usize = 100_000;

/// 分片数（2 的幂），利用 Token 中的 HMAC 字节均匀散列，降低锁竞争并消除全表停顿扫描
const SHARD_COUNT: usize = 64;

/// 单条记录的最长单调时钟保留时间（秒）。
///
/// 正常 TOTP 有效窗口不超过 3 个步长（30s）。附加单调时钟上限是为了在系统时钟被大幅回拨
/// （导致墙钟 `expire_at > now` 长时间成立）时，依然能在有限单调时间内自动回收旧条目，
/// 无需依赖牺牲安全性的半表裁剪。
const MAX_MONOTONIC_RETENTION: Duration = Duration::from_secs(60);

/// Token 消费失败的原因
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayReject {
    /// 该 Token 在有效期内已被消费过（重放攻击）
    Replay,
    /// 防重放缓存已被未过期的有效记录占满（拒绝放行，避免淘汰有效记录导致重放漏检）
    CapacityExceeded,
}

/// 全局的重放防御缓存
///
/// TOTP 只能把攻击面压缩到一个时间窗内，无法阻止攻击者在窗口内
/// 原样重放抓到的 Token，所以这里再记录一份"已经用掉的 Token"。
pub static REPLAY_GUARD: LazyLock<ReplayGuard> = LazyLock::new(ReplayGuard::new);

#[derive(Clone, Copy)]
struct Record {
    generation: u64,
    expire_at: u64,
    mono_deadline: Instant,
}

impl Record {
    #[inline]
    fn is_expired(&self, now_secs: u64, now_instant: Instant) -> bool {
        self.expire_at <= now_secs || self.mono_deadline <= now_instant
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct HeapEntry {
    mono_deadline: Instant,
    generation: u64,
    token: Uuid,
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.mono_deadline
            .cmp(&other.mono_deadline)
            .then_with(|| self.generation.cmp(&other.generation))
            .then_with(|| self.token.as_bytes().cmp(other.token.as_bytes()))
    }
}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
struct Shard {
    entries: HashMap<Uuid, Record>,
    heap: BinaryHeap<Reverse<HeapEntry>>,
    next_gen: u64,
}

impl Shard {
    /// 弹出堆顶已过期的记录，返回本次从 `entries` 中真正移除的条目数
    fn pop_expired_front(&mut self, now_secs: u64, now_instant: Instant) -> usize {
        let mut removed = 0;
        while let Some(&Reverse(top)) = self.heap.peek() {
            let expired = match self.entries.get(&top.token) {
                // 已被更新为新一代记录：直接丢弃过时的堆节点
                Some(rec) if rec.generation != top.generation => {
                    self.heap.pop();
                    continue;
                }
                Some(rec) => rec.is_expired(now_secs, now_instant),
                None => {
                    self.heap.pop();
                    continue;
                }
            };
            if !expired {
                break;
            }
            self.heap.pop();
            if self.entries.remove(&top.token).is_some() {
                removed += 1;
            }
        }
        self.compact_heap_if_needed();
        removed
    }

    /// 全量清理本分片内所有已过期记录（包括墙钟跳变导致堆序未覆盖到的条目）
    fn purge_all_expired(&mut self, now_secs: u64, now_instant: Instant) -> usize {
        let before = self.entries.len();
        self.entries
            .retain(|_, rec| !rec.is_expired(now_secs, now_instant));
        let removed = before - self.entries.len();
        if removed > 0 || self.heap.len() > self.entries.len().saturating_mul(2) + 16 {
            self.rebuild_heap();
        }
        removed
    }

    fn compact_heap_if_needed(&mut self) {
        if self.heap.len() > self.entries.len().saturating_mul(2) + 32 {
            self.rebuild_heap();
        }
    }

    fn rebuild_heap(&mut self) {
        self.heap.clear();
        for (&token, rec) in &self.entries {
            self.heap.push(Reverse(HeapEntry {
                mono_deadline: rec.mono_deadline,
                generation: rec.generation,
                token,
            }));
        }
    }

    fn insert_or_overwrite(&mut self, token: Uuid, expire_at: u64, mono_deadline: Instant) {
        self.next_gen = self.next_gen.wrapping_add(1);
        let generation = self.next_gen;
        self.entries.insert(
            token,
            Record {
                generation,
                expire_at,
                mono_deadline,
            },
        );
        self.heap.push(Reverse(HeapEntry {
            mono_deadline,
            generation,
            token,
        }));
        self.compact_heap_if_needed();
    }
}

/// 已使用 Token 的分片有界缓存
///
/// - **严格瞬时容量上限**：通过原子计数 `total_entries` 预占槽位，任何时刻条目数严格 `<= max_entries`
/// - **绝不提前淘汰有效记录**：容量触顶时先精确回收过期记录；若全部为未过期记录则直接拒绝（fail-closed）
/// - **均摊 O(1) 过期回收**：按分片最小堆渐进弹出过期项，消除周期性全表扫描造成的握手尾延迟毛刺
pub struct ReplayGuard {
    shards: Box<[Mutex<Shard>]>,
    max_entries: usize,
    total_entries: AtomicUsize,
    sweep_cursor: AtomicUsize,
    max_monotonic_ttl: Duration,
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
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self::with_limits(max_entries, MAX_MONOTONIC_RETENTION)
    }

    fn with_limits(max_entries: usize, max_monotonic_ttl: Duration) -> Self {
        let shards = (0..SHARD_COUNT)
            .map(|_| Mutex::new(Shard::default()))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self {
            shards,
            max_entries,
            total_entries: AtomicUsize::new(0),
            sweep_cursor: AtomicUsize::new(0),
            max_monotonic_ttl,
        }
    }

    /// 尝试消费一个 Token，返回详细结果。
    pub fn try_consume(&self, token: &Uuid, expire_at: u64) -> Result<(), ReplayReject> {
        if self.max_entries == 0 {
            return Err(ReplayReject::CapacityExceeded);
        }

        let now = now_secs();
        let now_instant = Instant::now();
        let ttl = Duration::from_secs(expire_at.saturating_sub(now)).min(self.max_monotonic_ttl);
        let mono_deadline = now_instant + ttl;

        // 顺带渐进清理一个相邻分片的堆顶过期项，保证冷分片上的过期数据也能在 O(1) 内被回收
        let target_idx = self.shard_index(token);
        let sweep_idx = self.sweep_cursor.fetch_add(1, Ordering::Relaxed) % self.shards.len();
        if sweep_idx != target_idx {
            self.pop_shard_expired(sweep_idx, now, now_instant);
        }

        // 第一轮：在目标分片锁内检查重放并尝试预占槽位
        {
            let mut shard = self.lock_shard(target_idx);
            let freed = shard.pop_expired_front(now, now_instant);
            if freed > 0 {
                self.total_entries.fetch_sub(freed, Ordering::Release);
            }

            if let Some(existing) = shard.entries.get(token) {
                if !existing.is_expired(now, now_instant) {
                    return Err(ReplayReject::Replay);
                }
                // 旧记录已过期：原地覆盖复用该槽位，total_entries 不变
                shard.insert_or_overwrite(*token, expire_at, mono_deadline);
                return Ok(());
            }

            if self.try_reserve_slot() {
                shard.insert_or_overwrite(*token, expire_at, mono_deadline);
                return Ok(());
            }
        }

        // 容量触顶：先跨分片精确回收全部已过期项（释放目标分片锁后再按序扫描，避免死锁）
        self.purge_expired_at(now, now_instant);

        let mut shard = self.lock_shard(target_idx);
        let freed = shard.pop_expired_front(now, now_instant);
        if freed > 0 {
            self.total_entries.fetch_sub(freed, Ordering::Release);
        }

        // 释放锁期间可能已有并发请求写入了同一个 Token，需重新检查
        if let Some(existing) = shard.entries.get(token) {
            if !existing.is_expired(now, now_instant) {
                return Err(ReplayReject::Replay);
            }
            shard.insert_or_overwrite(*token, expire_at, mono_deadline);
            return Ok(());
        }

        if self.try_reserve_slot() {
            shard.insert_or_overwrite(*token, expire_at, mono_deadline);
            Ok(())
        } else {
            // 所有槽位均被未过期的有效 Token 占满：fail-closed 拒绝，绝不淘汰有效防重放记录
            Err(ReplayReject::CapacityExceeded)
        }
    }

    /// 尝试消费一个 Token
    ///
    /// - `expire_at`: 该 Token 在 TOTP 校验层面的最晚可用时间(Unix 秒)
    ///
    /// 返回 `true` 表示首次使用且放行，`false` 表示重放或缓存满载被拒绝。
    pub fn try_use(&self, token: &Uuid, expire_at: u64) -> bool {
        self.try_consume(token, expire_at).is_ok()
    }

    /// 主动清理所有分片中已过期的记录，返回清理数量
    pub fn purge_expired(&self) -> usize {
        self.purge_expired_at(now_secs(), Instant::now())
    }

    fn purge_expired_at(&self, now_secs: u64, now_instant: Instant) -> usize {
        let mut total_freed = 0;
        for idx in 0..self.shards.len() {
            let mut shard = self.lock_shard(idx);
            let freed = shard.purge_all_expired(now_secs, now_instant);
            if freed > 0 {
                self.total_entries.fetch_sub(freed, Ordering::Release);
                total_freed += freed;
            }
        }
        total_freed
    }

    fn pop_shard_expired(&self, idx: usize, now_secs: u64, now_instant: Instant) {
        if let Ok(mut shard) = self.shards[idx].try_lock() {
            let freed = shard.pop_expired_front(now_secs, now_instant);
            if freed > 0 {
                self.total_entries.fetch_sub(freed, Ordering::Release);
            }
        }
    }

    #[inline]
    fn try_reserve_slot(&self) -> bool {
        let mut current = self.total_entries.load(Ordering::Acquire);
        loop {
            if current >= self.max_entries {
                return false;
            }
            match self.total_entries.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
    }

    #[inline]
    fn shard_index(&self, token: &Uuid) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        token.hash(&mut hasher);
        (hasher.finish() as usize) & (self.shards.len() - 1)
    }

    #[inline]
    fn lock_shard(&self, idx: usize) -> std::sync::MutexGuard<'_, Shard> {
        self.shards[idx].lock().unwrap_or_else(|e| e.into_inner())
    }

    /// 当前缓存中的记录条数(含尚未触发回收的过期项，严格 `<= max_entries`)
    pub fn len(&self) -> usize {
        self.total_entries.load(Ordering::Acquire)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        for idx in 0..self.shards.len() {
            let mut shard = self.lock_shard(idx);
            let removed = shard.entries.len();
            shard.entries.clear();
            shard.heap.clear();
            if removed > 0 {
                self.total_entries.fetch_sub(removed, Ordering::Release);
            }
        }
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
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn test_reject_replay() {
        let guard = ReplayGuard::new();
        let token = Uuid::new_v4();
        let expire_at = now_secs() + 30;

        assert_eq!(guard.try_consume(&token, expire_at), Ok(()));
        // 同一个 Token 再来一次必须被识别为 Replay
        assert_eq!(
            guard.try_consume(&token, expire_at),
            Err(ReplayReject::Replay)
        );
        // 其他 Token 不受影响
        assert_eq!(guard.try_consume(&Uuid::new_v4(), expire_at), Ok(()));
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
    fn test_purge_removes_expired_automatically_when_full() {
        let guard = ReplayGuard::with_max_entries(16);
        let now = now_secs();
        for _ in 0..16 {
            assert!(guard.try_use(&Uuid::new_v4(), now.saturating_sub(1)));
        }

        // 再次写入未过期记录时，会自动精确回收已过期项并成功放入，无需等待固定时间节流窗口
        for _ in 0..16 {
            assert!(guard.try_use(&Uuid::new_v4(), now + 30));
        }
        assert_eq!(guard.len(), 16);
    }

    #[test]
    fn test_never_evicts_valid_records_under_same_deadline_saturation() {
        // 同一 TOTP 时间窗内的所有 Token 具有完全相同的离散 expire_at；
        // 满载时绝不能淘汰任何已消费的有效记录，且超过上限的新 Token 必须 fail-closed 拒绝。
        let guard = ReplayGuard::with_max_entries(10);
        let shared_deadline = now_secs() + 20;
        let mut recorded = Vec::new();

        for _ in 0..10 {
            let token = Uuid::new_v4();
            assert_eq!(guard.try_consume(&token, shared_deadline), Ok(()));
            recorded.push(token);
        }
        assert_eq!(guard.len(), 10);

        // 第 11 个新 Token 因容量已满被拒绝，且长度严格不超过上限 10
        assert_eq!(
            guard.try_consume(&Uuid::new_v4(), shared_deadline),
            Err(ReplayReject::CapacityExceeded)
        );
        assert_eq!(guard.len(), 10);

        // 先前全部 10 个已消费 Token 仍然 100% 受到重放保护，没有任何一条被提前淘汰
        for token in &recorded {
            assert_eq!(
                guard.try_consume(token, shared_deadline),
                Err(ReplayReject::Replay)
            );
        }
    }

    #[test]
    fn test_strict_instantaneous_cap_under_concurrency() {
        let cap = 64;
        let guard = Arc::new(ReplayGuard::with_max_entries(cap));
        let expire_at = now_secs() + 60;
        let accepted = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..8 {
            let g = guard.clone();
            let acc = accepted.clone();
            handles.push(thread::spawn(move || {
                for _ in 0..200 {
                    if g.try_use(&Uuid::new_v4(), expire_at) {
                        acc.fetch_add(1, Ordering::Relaxed);
                    }
                    // 任意瞬时时刻都不能突破容量上限
                    assert!(g.len() <= cap);
                }
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(accepted.load(Ordering::Relaxed), cap);
        assert_eq!(guard.len(), cap);
    }

    #[test]
    fn test_monotonic_retention_recovers_from_clock_rollback() {
        // 模拟系统墙钟被大幅回拨：expire_at 远在未来（now + 3600），
        // 依靠单调时钟保留上限仍可自动过期恢复服务，无需牺牲防重放安全性。
        let guard = ReplayGuard::with_limits(8, Duration::from_millis(40));
        let far_future = now_secs() + 3600;

        for _ in 0..8 {
            assert!(guard.try_use(&Uuid::new_v4(), far_future));
        }
        assert_eq!(
            guard.try_consume(&Uuid::new_v4(), far_future),
            Err(ReplayReject::CapacityExceeded)
        );

        thread::sleep(Duration::from_millis(60));

        // 单调时钟到期后缓存自动恢复可用
        for _ in 0..8 {
            assert_eq!(guard.try_consume(&Uuid::new_v4(), far_future), Ok(()));
        }
        assert_eq!(guard.len(), 8);
    }
}
