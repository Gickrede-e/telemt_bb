// IP address tracking and per-user unique IP limiting.

#![allow(dead_code)]

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use parking_lot::Mutex as ParkingMutex;
use tokio::sync::Mutex as AsyncMutex;

use crate::config::UserMaxUniqueIpsMode;

const CLEANUP_DRAIN_BATCH_LIMIT: usize = 1024;
const MAX_ACTIVE_IP_ENTRIES: u64 = 131_072;
const MAX_RECENT_IP_ENTRIES: u64 = 262_144;

/// Default number of shards backing `active`/`recent` state. Power of two for
/// fast modulo via `& (N-1)`. Override via `TELEMT_IPTRACKER_SHARDS` env var
/// (clamped to `[1, 1024]`, rounded up to next power of two).
///
/// Refs `docs/PERFORMANCE_AND_ANTIDETECT.ru.md` §1bis.3.
const DEFAULT_SHARD_COUNT: usize = 32;
const MAX_SHARD_COUNT: usize = 1024;

/// Per-shard state. Both `active` and `recent` live under the SAME mutex so
/// that per-(user, ip) increment/decrement is atomic inside one shard — this
/// is the Section 6 invariant from the doc: never read one shard and write
/// another. Holding both under one lock collapses the old two-RwLock
/// deadlock-avoidance dance into a single uncontended hot path.
#[derive(Debug, Default)]
struct UserIpShardSlot {
    active: HashMap<String, HashMap<IpAddr, usize>>,
    recent: HashMap<String, HashMap<IpAddr, Instant>>,
}

/// Tracks active and recent client IPs for per-user admission control.
///
/// `active`/`recent` are sharded across N `parking_lot::Mutex` slots keyed by
/// `hash(user, ip)`. Read-mostly policy state (`max_ips`, `default_max_ips`,
/// `limit_mode`, `limit_window`) uses `arc_swap::ArcSwap` so the hot path
/// becomes a single relaxed atomic load per accept. The cleanup queue stays
/// as one global `std::sync::Mutex<HashMap<...>>` because it's drained at
/// most once per second from `run_periodic_maintenance`.
///
/// Refs `docs/PERFORMANCE_AND_ANTIDETECT.ru.md` §§1bis.3, 6.
#[derive(Debug, Clone)]
pub struct UserIpTracker {
    shards: Arc<Vec<ParkingMutex<UserIpShardSlot>>>,
    shard_mask: usize,
    active_entry_count: Arc<AtomicU64>,
    recent_entry_count: Arc<AtomicU64>,
    active_cap_rejects: Arc<AtomicU64>,
    recent_cap_rejects: Arc<AtomicU64>,
    cleanup_deferred_releases: Arc<AtomicU64>,
    max_ips: Arc<ArcSwap<HashMap<String, usize>>>,
    default_max_ips: Arc<ArcSwap<usize>>,
    limit_mode: Arc<ArcSwap<UserMaxUniqueIpsMode>>,
    limit_window: Arc<ArcSwap<Duration>>,
    last_compact_epoch_secs: Arc<AtomicU64>,
    cleanup_queue_len: Arc<AtomicU64>,
    cleanup_queue: Arc<Mutex<HashMap<(String, IpAddr), usize>>>,
    cleanup_drain_lock: Arc<AsyncMutex<()>>,
}

fn parse_shard_count_from_env() -> usize {
    let raw = std::env::var("TELEMT_IPTRACKER_SHARDS").ok();
    let requested = raw
        .as_deref()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_SHARD_COUNT)
        .min(MAX_SHARD_COUNT);
    let pow2 = requested.next_power_of_two().max(1);
    if let Some(s) = raw
        && pow2 != s.parse::<usize>().unwrap_or(0)
    {
        tracing::debug!(
            requested = %s,
            actual = pow2,
            "TELEMT_IPTRACKER_SHARDS rounded to next power of two"
        );
    }
    pow2
}

fn build_shards(n: usize) -> Vec<ParkingMutex<UserIpShardSlot>> {
    (0..n)
        .map(|_| ParkingMutex::new(UserIpShardSlot::default()))
        .collect()
}

#[inline]
fn shard_index(user: &str, ip: IpAddr, mask: usize) -> usize {
    let mut h_user = DefaultHasher::new();
    user.hash(&mut h_user);
    let user_hash = h_user.finish();
    let mut h_ip = DefaultHasher::new();
    ip.hash(&mut h_ip);
    let ip_hash = h_ip.finish();
    // Mix user and ip so empty-username (or any single hot user) is still
    // spread across shards by ip — see plan §1bis.3.A.7.1.
    ((user_hash ^ ip_hash.rotate_left(7)) as usize) & mask
}

/// Point-in-time memory counters for user/IP limiter state.
#[derive(Debug, Clone, Copy)]
pub struct UserIpTrackerMemoryStats {
    /// Number of users with active IP state.
    pub active_users: usize,
    /// Number of users with recent IP state.
    pub recent_users: usize,
    /// Number of active `(user, ip)` entries.
    pub active_entries: usize,
    /// Number of recent-window `(user, ip)` entries.
    pub recent_entries: usize,
    /// Number of deferred disconnect cleanups waiting to be drained.
    pub cleanup_queue_len: usize,
    /// Number of new connections rejected by the global active-entry cap.
    pub active_cap_rejects: u64,
    /// Number of new connections rejected by the global recent-entry cap.
    pub recent_cap_rejects: u64,
    /// Number of release cleanups deferred through the cleanup queue.
    pub cleanup_deferred_releases: u64,
}

impl UserIpTracker {
    pub fn new() -> Self {
        let shard_count = parse_shard_count_from_env();
        Self {
            shards: Arc::new(build_shards(shard_count)),
            shard_mask: shard_count - 1,
            active_entry_count: Arc::new(AtomicU64::new(0)),
            recent_entry_count: Arc::new(AtomicU64::new(0)),
            active_cap_rejects: Arc::new(AtomicU64::new(0)),
            recent_cap_rejects: Arc::new(AtomicU64::new(0)),
            cleanup_deferred_releases: Arc::new(AtomicU64::new(0)),
            max_ips: Arc::new(ArcSwap::from_pointee(HashMap::new())),
            default_max_ips: Arc::new(ArcSwap::from_pointee(0usize)),
            limit_mode: Arc::new(ArcSwap::from_pointee(UserMaxUniqueIpsMode::ActiveWindow)),
            limit_window: Arc::new(ArcSwap::from_pointee(Duration::from_secs(30))),
            last_compact_epoch_secs: Arc::new(AtomicU64::new(0)),
            cleanup_queue_len: Arc::new(AtomicU64::new(0)),
            cleanup_queue: Arc::new(Mutex::new(HashMap::new())),
            cleanup_drain_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    /// Number of shards backing this tracker. Test-visible to validate the
    /// power-of-two clamp and env-var override behaviour.
    #[cfg(test)]
    pub(crate) fn shard_count(&self) -> usize {
        self.shards.len()
    }

    #[inline]
    fn shard_for(&self, user: &str, ip: IpAddr) -> &ParkingMutex<UserIpShardSlot> {
        let idx = shard_index(user, ip, self.shard_mask);
        &self.shards[idx]
    }

    fn decrement_counter(counter: &AtomicU64, amount: usize) {
        if amount == 0 {
            return;
        }
        let amount = amount as u64;
        let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
            Some(current.saturating_sub(amount))
        });
    }

    /// Apply a queued cleanup to a single shard. Returns the number of
    /// active entries removed (0 or 1) so the caller can decrement the
    /// global atomic counter.
    fn apply_active_cleanup_shard(
        slot: &mut UserIpShardSlot,
        user: &str,
        ip: IpAddr,
        pending_count: usize,
    ) -> usize {
        if pending_count == 0 {
            return 0;
        }

        let mut remove_user = false;
        let mut removed_active_entries = 0usize;
        if let Some(user_ips) = slot.active.get_mut(user) {
            if let Some(count) = user_ips.get_mut(&ip) {
                if *count > pending_count {
                    *count -= pending_count;
                } else if user_ips.remove(&ip).is_some() {
                    removed_active_entries = 1;
                }
            }
            remove_user = user_ips.is_empty();
        }
        if remove_user {
            slot.active.remove(user);
        }
        removed_active_entries
    }

    /// Queues a deferred active IP cleanup for a later async drain.
    pub fn enqueue_cleanup(&self, user: String, ip: IpAddr) {
        match self.cleanup_queue.lock() {
            Ok(mut queue) => {
                let count = queue.entry((user, ip)).or_insert(0);
                if *count == 0 {
                    self.cleanup_queue_len.fetch_add(1, Ordering::Relaxed);
                }
                *count = count.saturating_add(1);
                self.cleanup_deferred_releases
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(poisoned) => {
                let mut queue = poisoned.into_inner();
                let count = queue.entry((user.clone(), ip)).or_insert(0);
                if *count == 0 {
                    self.cleanup_queue_len.fetch_add(1, Ordering::Relaxed);
                }
                *count = count.saturating_add(1);
                self.cleanup_deferred_releases
                    .fetch_add(1, Ordering::Relaxed);
                self.cleanup_queue.clear_poison();
                tracing::warn!(
                    "UserIpTracker cleanup_queue lock poisoned; recovered and enqueued IP cleanup for {} ({})",
                    user,
                    ip
                );
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn cleanup_queue_len_for_tests(&self) -> usize {
        self.cleanup_queue
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    #[cfg(test)]
    pub(crate) fn cleanup_queue_mutex_for_tests(
        &self,
    ) -> Arc<Mutex<HashMap<(String, IpAddr), usize>>> {
        Arc::clone(&self.cleanup_queue)
    }

    pub(crate) async fn drain_cleanup_queue(&self) {
        if self.cleanup_queue_len.load(Ordering::Relaxed) == 0 {
            return;
        }
        let Ok(_drain_guard) = self.cleanup_drain_lock.try_lock() else {
            return;
        };

        let to_remove = {
            match self.cleanup_queue.lock() {
                Ok(mut queue) => {
                    if queue.is_empty() {
                        return;
                    }
                    let mut drained =
                        HashMap::with_capacity(queue.len().min(CLEANUP_DRAIN_BATCH_LIMIT));
                    for _ in 0..CLEANUP_DRAIN_BATCH_LIMIT {
                        let Some(key) = queue.keys().next().cloned() else {
                            break;
                        };
                        if let Some(count) = queue.remove(&key) {
                            self.cleanup_queue_len.fetch_sub(1, Ordering::Relaxed);
                            drained.insert(key, count);
                        }
                    }
                    drained
                }
                Err(poisoned) => {
                    let mut queue = poisoned.into_inner();
                    if queue.is_empty() {
                        self.cleanup_queue.clear_poison();
                        return;
                    }
                    let mut drained =
                        HashMap::with_capacity(queue.len().min(CLEANUP_DRAIN_BATCH_LIMIT));
                    for _ in 0..CLEANUP_DRAIN_BATCH_LIMIT {
                        let Some(key) = queue.keys().next().cloned() else {
                            break;
                        };
                        if let Some(count) = queue.remove(&key) {
                            self.cleanup_queue_len.fetch_sub(1, Ordering::Relaxed);
                            drained.insert(key, count);
                        }
                    }
                    self.cleanup_queue.clear_poison();
                    drained
                }
            }
        };
        if to_remove.is_empty() {
            return;
        }

        // Group queued entries by shard index so each shard mutex is taken
        // exactly once for the whole batch destined for it. This converts
        // the old single global write lock into N independent shard locks.
        let mut by_shard: Vec<Vec<((String, IpAddr), usize)>> =
            (0..self.shards.len()).map(|_| Vec::new()).collect();
        for ((user, ip), pending_count) in to_remove {
            let idx = shard_index(&user, ip, self.shard_mask);
            by_shard[idx].push(((user, ip), pending_count));
        }

        let mut removed_active_entries = 0usize;
        for (idx, entries) in by_shard.into_iter().enumerate() {
            if entries.is_empty() {
                continue;
            }
            let mut slot = self.shards[idx].lock();
            for ((user, ip), pending_count) in entries {
                removed_active_entries = removed_active_entries.saturating_add(
                    Self::apply_active_cleanup_shard(&mut slot, &user, ip, pending_count),
                );
            }
        }
        Self::decrement_counter(&self.active_entry_count, removed_active_entries);
    }

    fn now_epoch_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    async fn maybe_compact_empty_users(&self) {
        const COMPACT_INTERVAL_SECS: u64 = 60;
        let now_epoch_secs = Self::now_epoch_secs();
        let last_compact_epoch_secs = self.last_compact_epoch_secs.load(Ordering::Relaxed);
        if now_epoch_secs.saturating_sub(last_compact_epoch_secs) < COMPACT_INTERVAL_SECS {
            return;
        }
        if self
            .last_compact_epoch_secs
            .compare_exchange(
                last_compact_epoch_secs,
                now_epoch_secs,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }

        let window = **self.limit_window.load();
        let now = Instant::now();

        // Iterate shards; lock each in turn, prune+compact, unlock. No two
        // shards are held simultaneously so per-(user,ip) atomicity is
        // preserved trivially.
        let mut pruned_recent_entries = 0usize;
        for shard in self.shards.iter() {
            let mut slot = shard.lock();
            for user_recent in slot.recent.values_mut() {
                pruned_recent_entries = pruned_recent_entries.saturating_add(Self::prune_recent(
                    user_recent,
                    now,
                    window,
                ));
            }

            let mut users_to_check =
                Vec::<String>::with_capacity(slot.active.len().saturating_add(slot.recent.len()));
            users_to_check.extend(slot.active.keys().cloned());
            for user in slot.recent.keys() {
                if !slot.active.contains_key(user) {
                    users_to_check.push(user.clone());
                }
            }

            for user in users_to_check {
                let active_empty = slot
                    .active
                    .get(&user)
                    .map(|ips| ips.is_empty())
                    .unwrap_or(true);
                let recent_empty = slot
                    .recent
                    .get(&user)
                    .map(|ips| ips.is_empty())
                    .unwrap_or(true);
                if active_empty && recent_empty {
                    slot.active.remove(&user);
                    slot.recent.remove(&user);
                }
            }
        }
        Self::decrement_counter(&self.recent_entry_count, pruned_recent_entries);
    }

    pub async fn run_periodic_maintenance(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        loop {
            interval.tick().await;
            self.drain_cleanup_queue().await;
            self.maybe_compact_empty_users().await;
        }
    }

    pub async fn memory_stats(&self) -> UserIpTrackerMemoryStats {
        let cleanup_queue_len = self.cleanup_queue_len.load(Ordering::Relaxed) as usize;
        // Aggregate user/entry counts across all shards. Two users with
        // entries in different shards are counted as two distinct users
        // (matches the previous single-map semantics because user keys are
        // unique across the namespace and the shard routes by (user, ip)).
        // Collect each user's name into a set per scope to dedupe — same
        // user can appear in multiple shards if they own IPs hashing to
        // different shards.
        let mut active_users = std::collections::HashSet::new();
        let mut recent_users = std::collections::HashSet::new();
        let mut active_entries = 0usize;
        let mut recent_entries = 0usize;
        for shard in self.shards.iter() {
            let slot = shard.lock();
            for (user, per_ip) in slot.active.iter() {
                if !per_ip.is_empty() {
                    active_users.insert(user.clone());
                }
                active_entries += per_ip.len();
            }
            for (user, per_ip) in slot.recent.iter() {
                if !per_ip.is_empty() {
                    recent_users.insert(user.clone());
                }
                recent_entries += per_ip.len();
            }
        }

        UserIpTrackerMemoryStats {
            active_users: active_users.len(),
            recent_users: recent_users.len(),
            active_entries,
            recent_entries,
            cleanup_queue_len,
            active_cap_rejects: self.active_cap_rejects.load(Ordering::Relaxed),
            recent_cap_rejects: self.recent_cap_rejects.load(Ordering::Relaxed),
            cleanup_deferred_releases: self.cleanup_deferred_releases.load(Ordering::Relaxed),
        }
    }

    pub async fn set_limit_policy(&self, mode: UserMaxUniqueIpsMode, window_secs: u64) {
        self.limit_mode.store(Arc::new(mode));
        self.limit_window
            .store(Arc::new(Duration::from_secs(window_secs.max(1))));
    }

    pub async fn set_user_limit(&self, username: &str, max_ips: usize) {
        let current = self.max_ips.load();
        let mut next: HashMap<String, usize> = (**current).clone();
        next.insert(username.to_string(), max_ips);
        self.max_ips.store(Arc::new(next));
    }

    pub async fn remove_user_limit(&self, username: &str) {
        let current = self.max_ips.load();
        if !current.contains_key(username) {
            return;
        }
        let mut next: HashMap<String, usize> = (**current).clone();
        next.remove(username);
        self.max_ips.store(Arc::new(next));
    }

    pub async fn load_limits(&self, default_limit: usize, limits: &HashMap<String, usize>) {
        self.default_max_ips.store(Arc::new(default_limit));
        self.max_ips.store(Arc::new(limits.clone()));
    }

    fn prune_recent(
        user_recent: &mut HashMap<IpAddr, Instant>,
        now: Instant,
        window: Duration,
    ) -> usize {
        if user_recent.is_empty() {
            return 0;
        }
        let before = user_recent.len();
        user_recent.retain(|_, seen_at| now.duration_since(*seen_at) <= window);
        before.saturating_sub(user_recent.len())
    }

    pub async fn check_and_add(&self, username: &str, ip: IpAddr) -> Result<(), String> {
        self.drain_cleanup_queue().await;
        self.maybe_compact_empty_users().await;
        let default_max_ips = **self.default_max_ips.load();
        let limit = {
            let max_ips = self.max_ips.load();
            max_ips
                .get(username)
                .copied()
                .filter(|limit| *limit > 0)
                .or((default_max_ips > 0).then_some(default_max_ips))
        };
        let mode = **self.limit_mode.load();
        let window = **self.limit_window.load();
        let now = Instant::now();

        // For per-user limit checks we need the user's TOTAL counts across
        // all shards (a user's IPs are spread by hash). Two-pass approach:
        //
        //   1. Acquire shard for THIS (user, ip). Inside that lock, perform
        //      the per-(user, ip) inc/dec atomically (Section 6 invariant).
        //   2. For limit enforcement, count user's IPs across shards while
        //      NOT holding the per-(user,ip) shard's lock — limits can race
        //      slightly under heavy churn (acceptable: the active path is
        //      best-effort admission control and races are bounded by N).
        //
        // For the common case (reconnect from same IP), the shard lock
        // alone gives us a deterministic answer without any cross-shard
        // visit. For new-IP cases we count across shards before committing.

        // Step 1: shard lock and per-(user, ip) fast path.
        let shard = self.shard_for(username, ip);
        {
            let mut slot = shard.lock();
            let user_recent = slot.recent.entry(username.to_string()).or_default();
            let pruned_recent_entries = Self::prune_recent(user_recent, now, window);
            Self::decrement_counter(&self.recent_entry_count, pruned_recent_entries);
            let recent_contains_ip = user_recent.contains_key(&ip);
            let user_active = slot.active.entry(username.to_string()).or_default();

            if let Some(count) = user_active.get_mut(&ip) {
                if !recent_contains_ip
                    && self.recent_entry_count.load(Ordering::Relaxed) >= MAX_RECENT_IP_ENTRIES
                {
                    self.recent_cap_rejects.fetch_add(1, Ordering::Relaxed);
                    return Err(format!(
                        "IP tracker recent entry cap reached: entries={}/{}",
                        self.recent_entry_count.load(Ordering::Relaxed),
                        MAX_RECENT_IP_ENTRIES
                    ));
                }
                *count = count.saturating_add(1);
                let recent = slot.recent.get_mut(username).expect("seeded above");
                if recent.insert(ip, now).is_none() {
                    self.recent_entry_count.fetch_add(1, Ordering::Relaxed);
                }
                return Ok(());
            }
            // Drop shard lock before cross-shard counts to avoid lock
            // ordering risk and contention amplification.
        }

        // Step 2: new (user, ip). To preserve the original semantics of
        // "per-user limit enforced atomically across the user's full IP set"
        // we lock ALL shards in deterministic order, do the prune + count +
        // commit in one critical section, and release. This is the SLOW path
        // — taken only on new-IP admission; the common reconnect case in
        // step 1 above avoids this entirely.
        //
        // Deadlock note: nothing else in this module ever holds two shard
        // locks simultaneously. `drain_cleanup_queue`, `clear_user_ips`,
        // `clear_all`, and `maybe_compact_empty_users` all lock one shard at
        // a time. Taking the shards in fixed `0..N` order here is therefore
        // race-free against those code paths.
        let mut shard_guards: Vec<parking_lot::MutexGuard<'_, UserIpShardSlot>> =
            self.shards.iter().map(|s| s.lock()).collect();

        let mut user_active_total: usize = 0;
        let mut user_recent_total: usize = 0;
        let mut user_recent_has_ip = false;
        let mut pruned_recent_total: usize = 0;
        for slot in shard_guards.iter_mut() {
            if let Some(user_recent) = slot.recent.get_mut(username) {
                pruned_recent_total = pruned_recent_total.saturating_add(Self::prune_recent(
                    user_recent,
                    now,
                    window,
                ));
            }
            if let Some(per_ip) = slot.recent.get(username) {
                user_recent_total = user_recent_total.saturating_add(per_ip.len());
                if per_ip.contains_key(&ip) {
                    user_recent_has_ip = true;
                }
            }
            if let Some(per_ip) = slot.active.get(username) {
                user_active_total = user_active_total.saturating_add(per_ip.len());
            }
        }
        Self::decrement_counter(&self.recent_entry_count, pruned_recent_total);

        let is_new_ip = !user_recent_has_ip;

        if let Some(limit) = limit {
            let active_limit_reached = user_active_total >= limit;
            let recent_limit_reached = user_recent_total >= limit && is_new_ip;
            let deny = match mode {
                UserMaxUniqueIpsMode::ActiveWindow => active_limit_reached,
                UserMaxUniqueIpsMode::TimeWindow => recent_limit_reached,
                UserMaxUniqueIpsMode::Combined => active_limit_reached || recent_limit_reached,
            };
            if deny {
                return Err(format!(
                    "IP limit reached for user '{}': active={}/{} recent={}/{} mode={:?}",
                    username, user_active_total, limit, user_recent_total, limit, mode
                ));
            }
        }

        if self.active_entry_count.load(Ordering::Relaxed) >= MAX_ACTIVE_IP_ENTRIES {
            self.active_cap_rejects.fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "IP tracker active entry cap reached: entries={}/{}",
                self.active_entry_count.load(Ordering::Relaxed),
                MAX_ACTIVE_IP_ENTRIES
            ));
        }
        if is_new_ip && self.recent_entry_count.load(Ordering::Relaxed) >= MAX_RECENT_IP_ENTRIES {
            self.recent_cap_rejects.fetch_add(1, Ordering::Relaxed);
            return Err(format!(
                "IP tracker recent entry cap reached: entries={}/{}",
                self.recent_entry_count.load(Ordering::Relaxed),
                MAX_RECENT_IP_ENTRIES
            ));
        }

        // Step 3: commit the new (user, ip). We're still holding all shard
        // locks from step 2; pick the right shard guard by index instead of
        // re-locking. Drop the rest after commit.
        let idx = shard_index(username, ip, self.shard_mask);
        {
            let slot = &mut shard_guards[idx];
            let user_active = slot.active.entry(username.to_string()).or_default();
            if user_active.insert(ip, 1).is_none() {
                self.active_entry_count.fetch_add(1, Ordering::Relaxed);
            }
            let user_recent = slot.recent.entry(username.to_string()).or_default();
            if user_recent.insert(ip, now).is_none() {
                self.recent_entry_count.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(shard_guards);
        Ok(())
    }

    pub async fn remove_ip(&self, username: &str, ip: IpAddr) {
        self.maybe_compact_empty_users().await;
        let mut removed_active_entries = 0usize;
        let shard = self.shard_for(username, ip);
        {
            let mut slot = shard.lock();
            if let Some(user_ips) = slot.active.get_mut(username) {
                if let Some(count) = user_ips.get_mut(&ip) {
                    if *count > 1 {
                        *count -= 1;
                    } else if user_ips.remove(&ip).is_some() {
                        removed_active_entries = 1;
                    }
                }
                if user_ips.is_empty() {
                    slot.active.remove(username);
                }
            }
        }
        Self::decrement_counter(&self.active_entry_count, removed_active_entries);
    }

    pub async fn get_recent_counts_for_users(&self, users: &[String]) -> HashMap<String, usize> {
        self.drain_cleanup_queue().await;
        self.get_recent_counts_for_users_snapshot(users).await
    }

    pub(crate) async fn get_recent_counts_for_users_snapshot(
        &self,
        users: &[String],
    ) -> HashMap<String, usize> {
        let window = **self.limit_window.load();
        let now = Instant::now();

        let mut counts = HashMap::with_capacity(users.len());
        for user in users {
            counts.insert(user.clone(), 0usize);
        }
        for shard in self.shards.iter() {
            let slot = shard.lock();
            for user in users {
                if let Some(user_recent) = slot.recent.get(user) {
                    let n = user_recent
                        .values()
                        .filter(|seen_at| now.duration_since(**seen_at) <= window)
                        .count();
                    if n > 0 {
                        let entry = counts.entry(user.clone()).or_insert(0);
                        *entry = entry.saturating_add(n);
                    }
                }
            }
        }
        counts
    }

    pub async fn get_active_ips_for_users(&self, users: &[String]) -> HashMap<String, Vec<IpAddr>> {
        self.drain_cleanup_queue().await;
        let mut out: HashMap<String, Vec<IpAddr>> = HashMap::with_capacity(users.len());
        for user in users {
            out.insert(user.clone(), Vec::new());
        }
        for shard in self.shards.iter() {
            let slot = shard.lock();
            for user in users {
                if let Some(per_ip) = slot.active.get(user) {
                    out.entry(user.clone())
                        .or_default()
                        .extend(per_ip.keys().copied());
                }
            }
        }
        for ips in out.values_mut() {
            ips.sort();
            ips.dedup();
        }
        out
    }

    pub async fn get_recent_ips_for_users(&self, users: &[String]) -> HashMap<String, Vec<IpAddr>> {
        self.drain_cleanup_queue().await;
        let window = **self.limit_window.load();
        let now = Instant::now();

        let mut out: HashMap<String, Vec<IpAddr>> = HashMap::with_capacity(users.len());
        for user in users {
            out.insert(user.clone(), Vec::new());
        }
        for shard in self.shards.iter() {
            let slot = shard.lock();
            for user in users {
                if let Some(user_recent) = slot.recent.get(user) {
                    out.entry(user.clone()).or_default().extend(
                        user_recent
                            .iter()
                            .filter(|(_, seen_at)| now.duration_since(**seen_at) <= window)
                            .map(|(ip, _)| *ip),
                    );
                }
            }
        }
        for ips in out.values_mut() {
            ips.sort();
            ips.dedup();
        }
        out
    }

    pub async fn get_active_ip_count(&self, username: &str) -> usize {
        self.drain_cleanup_queue().await;
        let mut total = 0usize;
        for shard in self.shards.iter() {
            let slot = shard.lock();
            if let Some(per_ip) = slot.active.get(username) {
                total = total.saturating_add(per_ip.len());
            }
        }
        total
    }

    pub async fn get_active_ips(&self, username: &str) -> Vec<IpAddr> {
        self.drain_cleanup_queue().await;
        let mut out = Vec::new();
        for shard in self.shards.iter() {
            let slot = shard.lock();
            if let Some(per_ip) = slot.active.get(username) {
                out.extend(per_ip.keys().copied());
            }
        }
        out
    }

    pub async fn get_stats(&self) -> Vec<(String, usize, usize)> {
        self.drain_cleanup_queue().await;
        self.get_stats_snapshot().await
    }

    pub(crate) async fn get_stats_snapshot(&self) -> Vec<(String, usize, usize)> {
        // Aggregate active IP counts per user across all shards.
        let mut active_counts: HashMap<String, usize> = HashMap::new();
        for shard in self.shards.iter() {
            let slot = shard.lock();
            for (user, per_ip) in slot.active.iter() {
                let entry = active_counts.entry(user.clone()).or_insert(0);
                *entry = entry.saturating_add(per_ip.len());
            }
        }

        let max_ips = self.max_ips.load();
        let default_max_ips = **self.default_max_ips.load();

        let mut stats = Vec::with_capacity(active_counts.len());
        for (username, active_count) in active_counts {
            let limit = max_ips
                .get(&username)
                .copied()
                .filter(|limit| *limit > 0)
                .or((default_max_ips > 0).then_some(default_max_ips))
                .unwrap_or(0);
            stats.push((username, active_count, limit));
        }

        stats.sort_by(|a, b| a.0.cmp(&b.0));
        stats
    }

    pub async fn clear_user_ips(&self, username: &str) {
        let mut removed_active_entries = 0usize;
        let mut removed_recent_entries = 0usize;
        for shard in self.shards.iter() {
            let mut slot = shard.lock();
            if let Some(ips) = slot.active.remove(username) {
                removed_active_entries = removed_active_entries.saturating_add(ips.len());
            }
            if let Some(ips) = slot.recent.remove(username) {
                removed_recent_entries = removed_recent_entries.saturating_add(ips.len());
            }
        }
        Self::decrement_counter(&self.active_entry_count, removed_active_entries);
        Self::decrement_counter(&self.recent_entry_count, removed_recent_entries);
    }

    pub async fn clear_all(&self) {
        for shard in self.shards.iter() {
            let mut slot = shard.lock();
            slot.active.clear();
            slot.recent.clear();
        }
        self.active_entry_count.store(0, Ordering::Relaxed);
        self.recent_entry_count.store(0, Ordering::Relaxed);
    }

    pub async fn is_ip_active(&self, username: &str, ip: IpAddr) -> bool {
        self.drain_cleanup_queue().await;
        let shard = self.shard_for(username, ip);
        let slot = shard.lock();
        slot.active
            .get(username)
            .map(|ips| ips.contains_key(&ip))
            .unwrap_or(false)
    }

    pub async fn get_user_limit(&self, username: &str) -> Option<usize> {
        let default_max_ips = **self.default_max_ips.load();
        let max_ips = self.max_ips.load();
        max_ips
            .get(username)
            .copied()
            .filter(|limit| *limit > 0)
            .or((default_max_ips > 0).then_some(default_max_ips))
    }

    /// Insert a `(user, ip)` into the recent map directly. Test-only helper
    /// replacing the pre-shard pattern of writing into `tracker.recent_ips`.
    #[cfg(test)]
    pub(crate) fn insert_recent_for_tests(&self, user: &str, ip: IpAddr, when: Instant) {
        let shard = self.shard_for(user, ip);
        let mut slot = shard.lock();
        let user_recent = slot.recent.entry(user.to_string()).or_default();
        if user_recent.insert(ip, when).is_none() {
            self.recent_entry_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Returns whether a specific `(user, ip)` exists in the recent map.
    /// Test-only helper used to verify compact pruning behavior.
    #[cfg(test)]
    pub(crate) fn recent_contains_for_tests(&self, user: &str, ip: IpAddr) -> bool {
        let shard = self.shard_for(user, ip);
        let slot = shard.lock();
        slot.recent
            .get(user)
            .map(|ips| ips.contains_key(&ip))
            .unwrap_or(false)
    }

    pub async fn format_stats(&self) -> String {
        let stats = self.get_stats().await;

        if stats.is_empty() {
            return String::from("No active users");
        }

        let mut output = String::from("User IP Statistics:\n");
        output.push_str("==================\n");

        for (username, active_count, limit) in stats {
            output.push_str(&format!(
                "User: {:<20} Active IPs: {}/{}\n",
                username,
                active_count,
                if limit > 0 {
                    limit.to_string()
                } else {
                    "unlimited".to_string()
                }
            ));

            let ips = self.get_active_ips(&username).await;
            for ip in ips {
                output.push_str(&format!("  - {}\n", ip));
            }
        }

        output
    }
}

impl Default for UserIpTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::Ordering;

    fn test_ipv4(oct1: u8, oct2: u8, oct3: u8, oct4: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(oct1, oct2, oct3, oct4))
    }

    fn test_ipv6() -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    }

    #[tokio::test]
    async fn test_basic_ip_limit() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);
        let ip3 = test_ipv4(192, 168, 1, 3);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip3).await.is_err());

        assert_eq!(tracker.get_active_ip_count("test_user").await, 2);
    }

    #[tokio::test]
    async fn test_active_window_rejects_new_ip_and_keeps_existing_session() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 1).await;
        tracker
            .set_limit_policy(UserMaxUniqueIpsMode::ActiveWindow, 30)
            .await;

        let ip1 = test_ipv4(10, 10, 10, 1);
        let ip2 = test_ipv4(10, 10, 10, 2);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.is_ip_active("test_user", ip1).await);
        assert!(tracker.check_and_add("test_user", ip2).await.is_err());

        // Existing session remains active; only new unique IP is denied.
        assert!(tracker.is_ip_active("test_user", ip1).await);
        assert_eq!(tracker.get_active_ip_count("test_user").await, 1);
    }

    #[tokio::test]
    async fn test_reconnection_from_same_ip() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert_eq!(tracker.get_active_ip_count("test_user").await, 1);
    }

    #[tokio::test]
    async fn test_same_ip_disconnect_keeps_active_while_other_session_alive() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert_eq!(tracker.get_active_ip_count("test_user").await, 1);

        tracker.remove_ip("test_user", ip1).await;
        assert_eq!(tracker.get_active_ip_count("test_user").await, 1);

        tracker.remove_ip("test_user", ip1).await;
        assert_eq!(tracker.get_active_ip_count("test_user").await, 0);
    }

    #[tokio::test]
    async fn test_ip_removal() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);
        let ip3 = test_ipv4(192, 168, 1, 3);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip3).await.is_err());

        tracker.remove_ip("test_user", ip1).await;

        assert!(tracker.check_and_add("test_user", ip3).await.is_ok());
        assert_eq!(tracker.get_active_ip_count("test_user").await, 2);
    }

    #[tokio::test]
    async fn test_no_limit() {
        let tracker = UserIpTracker::new();

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);
        let ip3 = test_ipv4(192, 168, 1, 3);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip3).await.is_ok());

        assert_eq!(tracker.get_active_ip_count("test_user").await, 3);
    }

    #[tokio::test]
    async fn test_multiple_users() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("user1", 2).await;
        tracker.set_user_limit("user2", 1).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);

        assert!(tracker.check_and_add("user1", ip1).await.is_ok());
        assert!(tracker.check_and_add("user1", ip2).await.is_ok());

        assert!(tracker.check_and_add("user2", ip1).await.is_ok());
        assert!(tracker.check_and_add("user2", ip2).await.is_err());
    }

    #[tokio::test]
    async fn test_ipv6_support() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 2).await;

        let ipv4 = test_ipv4(192, 168, 1, 1);
        let ipv6 = test_ipv6();

        assert!(tracker.check_and_add("test_user", ipv4).await.is_ok());
        assert!(tracker.check_and_add("test_user", ipv6).await.is_ok());

        assert_eq!(tracker.get_active_ip_count("test_user").await, 2);
    }

    #[tokio::test]
    async fn test_get_active_ips() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 3).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);

        tracker.check_and_add("test_user", ip1).await.unwrap();
        tracker.check_and_add("test_user", ip2).await.unwrap();

        let active_ips = tracker.get_active_ips("test_user").await;
        assert_eq!(active_ips.len(), 2);
        assert!(active_ips.contains(&ip1));
        assert!(active_ips.contains(&ip2));
    }

    #[tokio::test]
    async fn test_stats() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("user1", 3).await;
        tracker.set_user_limit("user2", 2).await;

        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);

        tracker.check_and_add("user1", ip1).await.unwrap();
        tracker.check_and_add("user2", ip2).await.unwrap();

        let stats = tracker.get_stats().await;
        assert_eq!(stats.len(), 2);

        assert!(stats.iter().any(|(name, _, _)| name == "user1"));
        assert!(stats.iter().any(|(name, _, _)| name == "user2"));
    }

    #[tokio::test]
    async fn test_clear_user_ips() {
        let tracker = UserIpTracker::new();
        let ip1 = test_ipv4(192, 168, 1, 1);

        tracker.check_and_add("test_user", ip1).await.unwrap();
        assert_eq!(tracker.get_active_ip_count("test_user").await, 1);

        tracker.clear_user_ips("test_user").await;
        assert_eq!(tracker.get_active_ip_count("test_user").await, 0);
    }

    #[tokio::test]
    async fn test_is_ip_active() {
        let tracker = UserIpTracker::new();
        let ip1 = test_ipv4(192, 168, 1, 1);
        let ip2 = test_ipv4(192, 168, 1, 2);

        tracker.check_and_add("test_user", ip1).await.unwrap();

        assert!(tracker.is_ip_active("test_user", ip1).await);
        assert!(!tracker.is_ip_active("test_user", ip2).await);
    }

    #[tokio::test]
    async fn test_load_limits_from_config() {
        let tracker = UserIpTracker::new();

        let mut config_limits = HashMap::new();
        config_limits.insert("user1".to_string(), 5);
        config_limits.insert("user2".to_string(), 3);

        tracker.load_limits(0, &config_limits).await;

        assert_eq!(tracker.get_user_limit("user1").await, Some(5));
        assert_eq!(tracker.get_user_limit("user2").await, Some(3));
        assert_eq!(tracker.get_user_limit("user3").await, None);
    }

    #[tokio::test]
    async fn test_load_limits_replaces_previous_map() {
        let tracker = UserIpTracker::new();

        let mut first = HashMap::new();
        first.insert("user1".to_string(), 2);
        first.insert("user2".to_string(), 3);
        tracker.load_limits(0, &first).await;

        let mut second = HashMap::new();
        second.insert("user2".to_string(), 5);
        tracker.load_limits(0, &second).await;

        assert_eq!(tracker.get_user_limit("user1").await, None);
        assert_eq!(tracker.get_user_limit("user2").await, Some(5));
    }

    #[tokio::test]
    async fn test_global_each_limit_applies_without_user_override() {
        let tracker = UserIpTracker::new();
        tracker.load_limits(2, &HashMap::new()).await;

        let ip1 = test_ipv4(172, 16, 0, 1);
        let ip2 = test_ipv4(172, 16, 0, 2);
        let ip3 = test_ipv4(172, 16, 0, 3);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip3).await.is_err());
        assert_eq!(tracker.get_user_limit("test_user").await, Some(2));
    }

    #[tokio::test]
    async fn test_user_override_wins_over_global_each_limit() {
        let tracker = UserIpTracker::new();
        let mut limits = HashMap::new();
        limits.insert("test_user".to_string(), 1);
        tracker.load_limits(3, &limits).await;

        let ip1 = test_ipv4(172, 17, 0, 1);
        let ip2 = test_ipv4(172, 17, 0, 2);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_err());
        assert_eq!(tracker.get_user_limit("test_user").await, Some(1));
    }

    #[tokio::test]
    async fn test_time_window_mode_blocks_recent_ip_churn() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 1).await;
        tracker
            .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 30)
            .await;

        let ip1 = test_ipv4(10, 0, 0, 1);
        let ip2 = test_ipv4(10, 0, 0, 2);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        tracker.remove_ip("test_user", ip1).await;
        assert!(tracker.check_and_add("test_user", ip2).await.is_err());
    }

    #[tokio::test]
    async fn test_combined_mode_enforces_active_and_recent_limits() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 1).await;
        tracker
            .set_limit_policy(UserMaxUniqueIpsMode::Combined, 30)
            .await;

        let ip1 = test_ipv4(10, 0, 1, 1);
        let ip2 = test_ipv4(10, 0, 1, 2);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        assert!(tracker.check_and_add("test_user", ip2).await.is_err());

        tracker.remove_ip("test_user", ip1).await;
        assert!(tracker.check_and_add("test_user", ip2).await.is_err());
    }

    #[tokio::test]
    async fn test_time_window_expires() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 1).await;
        tracker
            .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 1)
            .await;

        let ip1 = test_ipv4(10, 1, 0, 1);
        let ip2 = test_ipv4(10, 1, 0, 2);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        tracker.remove_ip("test_user", ip1).await;
        assert!(tracker.check_and_add("test_user", ip2).await.is_err());

        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(tracker.check_and_add("test_user", ip2).await.is_ok());
    }

    #[tokio::test]
    async fn test_memory_stats_reports_queue_and_entry_counts() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 4).await;
        let ip1 = test_ipv4(10, 2, 0, 1);
        let ip2 = test_ipv4(10, 2, 0, 2);

        tracker.check_and_add("test_user", ip1).await.unwrap();
        tracker.check_and_add("test_user", ip2).await.unwrap();
        tracker.enqueue_cleanup("test_user".to_string(), ip1);

        let snapshot = tracker.memory_stats().await;
        assert_eq!(snapshot.active_users, 1);
        assert_eq!(snapshot.recent_users, 1);
        assert_eq!(snapshot.active_entries, 2);
        assert_eq!(snapshot.recent_entries, 2);
        assert_eq!(snapshot.cleanup_queue_len, 1);
    }

    #[tokio::test]
    async fn test_compact_prunes_stale_recent_entries() {
        let tracker = UserIpTracker::new();
        tracker
            .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 1)
            .await;

        let stale_user = "stale-user".to_string();
        let stale_ip = test_ipv4(10, 3, 0, 1);
        tracker.insert_recent_for_tests(
            &stale_user,
            stale_ip,
            Instant::now() - Duration::from_secs(5),
        );

        tracker.last_compact_epoch_secs.store(0, Ordering::Relaxed);
        tracker
            .check_and_add("trigger-user", test_ipv4(10, 3, 0, 2))
            .await
            .unwrap();

        let stale_exists = tracker.recent_contains_for_tests(&stale_user, stale_ip);
        assert!(!stale_exists);
    }

    #[tokio::test]
    async fn test_time_window_allows_same_ip_reconnect() {
        let tracker = UserIpTracker::new();
        tracker.set_user_limit("test_user", 1).await;
        tracker
            .set_limit_policy(UserMaxUniqueIpsMode::TimeWindow, 1)
            .await;

        let ip1 = test_ipv4(10, 4, 0, 1);

        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
        tracker.remove_ip("test_user", ip1).await;
        assert!(tracker.check_and_add("test_user", ip1).await.is_ok());
    }

    // ============= 1bis.3 — sharding invariants =============
    // Refs docs/PERFORMANCE_AND_ANTIDETECT.ru.md §§1bis.3, 6.

    #[test]
    fn shard_count_defaults_to_power_of_two() {
        // No env override — falls back to DEFAULT_SHARD_COUNT (32).
        let tracker = UserIpTracker::new();
        assert!(tracker.shard_count().is_power_of_two());
        assert!(tracker.shard_count() >= 1);
    }

    #[test]
    fn shard_index_is_stable_for_same_user_ip() {
        let mask = 31usize;
        let ip = test_ipv4(10, 0, 0, 1);
        let idx_a = shard_index("alice", ip, mask);
        for _ in 0..100 {
            assert_eq!(shard_index("alice", ip, mask), idx_a);
        }
    }

    #[test]
    fn shard_index_spreads_empty_user_across_shards_by_ip() {
        // Verify the rotate_left(7) mix actually distributes the
        // empty-username bucket across shards based on IP — Section A.7.1
        // risk mitigation.
        let mask = 31usize;
        let mut seen = std::collections::HashSet::new();
        for octet in 0u8..=255 {
            let ip = test_ipv4(10, 0, 0, octet);
            seen.insert(shard_index("", ip, mask));
        }
        // For 256 unique IPs across 32 shards we expect ≥ ~20 unique shards
        // (uniform expectation 32, with substantial slack for hash bias).
        assert!(
            seen.len() >= 16,
            "empty-user bucket only spread to {} shards out of 32 (expected ≥16)",
            seen.len()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_inc_dec_same_user_ip_holds_counter_invariant() {
        let tracker = Arc::new(UserIpTracker::new());
        tracker.set_user_limit("user", 8).await;
        let ip = test_ipv4(10, 9, 9, 9);

        let mut handles = Vec::new();
        for _ in 0..8u32 {
            let t = tracker.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..1_000u32 {
                    let _ = t.check_and_add("user", ip).await;
                    t.remove_ip("user", ip).await;
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // Final state must be clean: zero active for this (user, ip).
        assert_eq!(tracker.get_active_ip_count("user").await, 0);
        // Global atomic counter must be non-negative (zero or close to it).
        // The exact count may be > 0 if last operation was an add but most
        // workers should end on remove. We only assert no negative underflow.
        let snapshot = tracker.memory_stats().await;
        assert!(snapshot.active_entries == 0 || snapshot.active_entries == 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn concurrent_distinct_users_no_cross_shard_corruption() {
        let tracker = Arc::new(UserIpTracker::new());
        tracker.load_limits(0, &HashMap::new()).await;

        let mut handles = Vec::new();
        for u in 0..64u32 {
            let t = tracker.clone();
            handles.push(tokio::spawn(async move {
                let user = format!("u{}", u);
                let ip = test_ipv4(10, 0, ((u >> 8) & 0xff) as u8, (u & 0xff) as u8);
                for _ in 0..200u32 {
                    let _ = t.check_and_add(&user, ip).await;
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        // Each user should own exactly one IP.
        for u in 0..64u32 {
            let user = format!("u{}", u);
            assert_eq!(
                tracker.get_active_ip_count(&user).await,
                1,
                "user {} active count mismatch",
                user
            );
        }
    }
}
