//! Per-source-IP MePool sharding (Phase 1: scaffolding).
//!
//! Wraps `Vec<Arc<MePool>>` — each entry pinned to a single
//! `[[upstreams]].bind_addresses` entry — and exposes the shard-selection
//! primitives needed by the rest of the proxy: when a client connection
//! arrives the dispatcher hashes the peer IP into a shard, and from then on
//! that connection's writers, registry, quarantine, and adaptive floor all
//! come from one isolated `MePool`.
//!
//! Goals of the wrapper (vs the previous `me_writer_bind_multiplier`):
//!   * **Per-source-IP failure containment**: an endpoint that's degraded
//!     for source IP X gets quarantined only in shard X — shards Y, Z keep
//!     trying.
//!   * **Independent adaptive floor per shard**: load on shard X scales its
//!     own writer count without inflating Y's.
//!   * **Per-shard statistics**: operators see exactly which source IP is
//!     hot, which is starved.
//!
//! Phase 1 (this file): scaffolding only. `MePoolMux::new` accepts an
//! already-built `Vec<Arc<MePool>>`. Most accessors return the first shard
//! (so behaviour is byte-identical to a single-pool deployment); future
//! phases will plumb `peer_ip → shard_idx` through the request lifecycle
//! and spawn per-shard health/drain/rotation tasks.
//!
//! Refs `docs/PERFORMANCE_AND_ANTIDETECT.ru.md` §B+.

use std::collections::{BTreeMap, HashMap, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use super::pool::MePool;
use super::pool_runtime_api::{MeApiRefillDcSnapshot, MeApiRefillSnapshot};
use super::pool_status::{
    MeApiDcEndpointWriterSnapshot, MeApiDcStatusSnapshot, MeApiQuarantinedEndpointSnapshot,
    MeApiRuntimeSnapshot, MeApiStatusSnapshot,
};

/// Multiplexer over N per-source-IP `MePool` shards.
///
/// Each shard is a fully independent `MePool` constructed with a single
/// `bind_addresses` entry, so its outbound writers, quarantine list,
/// adaptive floor and registry are isolated from every other shard.
#[derive(Clone)]
pub struct MePoolMux {
    inner: Arc<MePoolMuxInner>,
}

struct MePoolMuxInner {
    /// Per-source-IP shards. `shards.len() >= 1` is an invariant — a
    /// single-element vec is the back-compat case (one pool, no sharding).
    shards: Vec<Arc<MePool>>,
    /// Cached `bind_addresses` parallel to `shards` (Some = pinned to that
    /// IP; None = legacy single-shard mode that did not pin). Used for
    /// debug logging and per-shard stats labelling.
    bind_addrs: Vec<Option<IpAddr>>,
}

impl MePoolMux {
    /// Build a mux from one or more shards. `shards` must be non-empty.
    /// `bind_addrs.len()` must equal `shards.len()` (`None` is acceptable
    /// for an unpinned legacy shard).
    pub fn from_shards(shards: Vec<Arc<MePool>>, bind_addrs: Vec<Option<IpAddr>>) -> Self {
        assert!(!shards.is_empty(), "MePoolMux requires at least one shard");
        assert_eq!(
            shards.len(),
            bind_addrs.len(),
            "MePoolMux: shards and bind_addrs must have equal length"
        );
        Self {
            inner: Arc::new(MePoolMuxInner { shards, bind_addrs }),
        }
    }

    /// Convenience: wrap a single existing `Arc<MePool>` as a 1-shard mux.
    /// Behavior is identical to the pre-mux world; useful at integration
    /// time before multi-shard startup wiring lands.
    pub fn from_single(pool: Arc<MePool>) -> Self {
        Self::from_shards(vec![pool], vec![None])
    }

    /// Number of shards.
    pub fn shard_count(&self) -> usize {
        self.inner.shards.len()
    }

    /// Shard list — borrowed slice, useful for per-shard task spawning.
    pub fn shards(&self) -> &[Arc<MePool>] {
        &self.inner.shards
    }

    /// Bind addresses corresponding to each shard (parallel to `shards()`).
    pub fn bind_addrs(&self) -> &[Option<IpAddr>] {
        &self.inner.bind_addrs
    }

    /// Pick a shard for a fresh client connection, hashed by peer IP.
    ///
    /// Sticky-by-peer is the right policy: a client's MTProto session may
    /// span multiple writers over its lifetime (DCs change, writers
    /// hardswap, etc.), but to keep KDF / fingerprint stable per session we
    /// want every one of those writers to come from the same source IP.
    /// Hash-by-peer-IP gives that for free: same peer → same shard →
    /// writers all bound to the same `our_addr` for that session.
    ///
    /// `peer_ip` is canonicalized to v4 if it's a v4-mapped v6, so a
    /// client appearing on both addresses lands on the same shard.
    pub fn shard_for_peer(&self, peer_ip: IpAddr) -> &Arc<MePool> {
        let idx = shard_index_for(peer_ip, self.inner.shards.len());
        &self.inner.shards[idx]
    }

    /// Return the shard at a specific index (e.g. for per-shard background
    /// task spawning in startup). Panics if `idx >= shard_count()`.
    pub fn shard(&self, idx: usize) -> &Arc<MePool> {
        &self.inner.shards[idx]
    }

    /// Back-compat accessor for code paths that haven't been threaded
    /// through with per-peer routing yet. Returns the FIRST shard, which is
    /// the natural primary for any non-routed callers (api snapshots,
    /// startup self-test, etc.).
    pub fn primary(&self) -> &Arc<MePool> {
        &self.inner.shards[0]
    }

    /// Aggregate `api_status_snapshot()` across every shard so /v1/stats
    /// readers see the system-wide writer pool, not just shard 0.
    ///
    /// Aggregation rules (the ONLY interesting design surface in this fn):
    ///   * **Pool-state counts** (required_writers, alive_writers,
    ///     fresh_alive_writers): SUM across shards. Each shard has its own
    ///     writer pool; the system total is the sum.
    ///   * **Config-derived counts** (configured_dc_groups,
    ///     configured_endpoints): take from primary. All shards see the
    ///     same Telegram proxy_config.
    ///   * **`available_endpoints` and `available_pct`**: RECOMPUTED from
    ///     the merged DC views, NOT taken from primary. An endpoint is
    ///     "available" if at least one shard has a live writer to it; if
    ///     shards cover disjoint endpoint subsets, primary's value would
    ///     undercount the system's actual coverage. The DC-level union
    ///     happens in `DcAccumulator::finalize`, the top-level sum in
    ///     `merge_status_snapshots`.
    ///   * **`coverage_pct`, `fresh_coverage_pct`**: RECOMPUTED from the
    ///     summed numerator/denominator. A naïve average of per-shard
    ///     ratios would weight a shard with 1 writer the same as a shard
    ///     with 100 — wrong.
    ///   * **`generated_at_epoch_secs`**: take the MAX. We want the freshest
    ///     timestamp; a clock skew across shards would otherwise pick
    ///     stale.
    ///   * **`writers: Vec`**: concatenate. Caller (api/runtime_stats) sees
    ///     N× more writers in shard mode; that's the correct view.
    ///   * **`dcs: Vec`**: merge by `dc` key — pool-state counts sum,
    ///     endpoint sets union, endpoint_writers sum per-endpoint, RTT
    ///     takes min. floor_min/floor_max come from primary (config-
    ///     derived, identical across shards) while floor_target sums
    ///     (per-shard dynamic value).
    ///
    /// Single-shard fast path: clone primary's snapshot directly so the
    /// (default) round_robin mode pays zero overhead.
    pub async fn aggregate_status_snapshot(&self) -> MeApiStatusSnapshot {
        if self.inner.shards.len() == 1 {
            return self.inner.shards[0].api_status_snapshot().await;
        }
        // Snapshot all shards concurrently. Each shard's RwLocks are
        // independent Arcs so there's no lock contention between them;
        // parallelism tightens the time window over which the merged view
        // is assembled. A serial await loop would let a generation
        // rotation slip in between shard 0 and shard N snapshots,
        // producing an incoherent mix of "old" and "new" rotation states.
        let futs = self
            .inner
            .shards
            .iter()
            .map(|shard| shard.api_status_snapshot());
        let snaps = futures::future::join_all(futs).await;
        merge_status_snapshots(snaps)
    }

    /// Aggregate `api_runtime_snapshot()` across every shard.
    ///
    /// Aggregation rules:
    ///   * **Config-derived fields** (intervals, thresholds, floor params,
    ///     keepalive, etc.): take from primary. They're identical across
    ///     shards because operator config is global.
    ///   * **`active_generation`, `warm_generation`,
    ///     `pending_hardswap_generation`**: take the MIN. A "system has
    ///     rotated past generation N" claim is only true once every shard
    ///     has reached N. Reporting the max would lie about laggards.
    ///   * **`pending_hardswap_age_secs`**: take the MAX `Option`. Oldest
    ///     pending hardswap is the most relevant operator signal — None
    ///     if no shard has one pending.
    ///   * **`adaptive_floor_active_writers_current`,
    ///     `adaptive_floor_warm_writers_current`**: SUM across shards.
    ///   * **`adaptive_floor_*_current` / `_effective` / `_target_writers_total`**:
    ///     sum (writer-count-shaped) or primary (config-shaped). See
    ///     comment per field.
    ///   * **`quarantined_endpoints`**: union by endpoint addr. When the
    ///     same endpoint is quarantined in K shards, the merged entry's
    ///     `remaining_ms` is the MAX — operator reads it as "this endpoint
    ///     stays quarantined for at least this long somewhere".
    ///   * **`network_path`**: take from primary. DC routing path is
    ///     config + network-decision-derived, identical across shards.
    pub async fn aggregate_runtime_snapshot(&self) -> MeApiRuntimeSnapshot {
        if self.inner.shards.len() == 1 {
            return self.inner.shards[0].api_runtime_snapshot().await;
        }
        let futs = self
            .inner
            .shards
            .iter()
            .map(|shard| shard.api_runtime_snapshot());
        let snaps = futures::future::join_all(futs).await;
        merge_runtime_snapshots(snaps)
    }

    /// Per-shard status snapshots, parallel to `shards()`. Each entry's
    /// position in the returned `Vec` is the shard index. Use this when
    /// you need the per-shard view (Prometheus labels, /v1/stats/me-
    /// writers/by-shard, debug dashboards) — for the aggregated view
    /// prefer `aggregate_status_snapshot()`.
    ///
    /// Implementation: `join_all` over `shard.api_status_snapshot()` so
    /// every shard's RwLock is held within the same tight window. Serial
    /// awaits would let a rotation slip between shard 0 and shard N,
    /// producing a snapshot that mixes pre/post-rotation states across
    /// shards. The single-shard fast path skips the join machinery.
    pub async fn per_shard_status_snapshots(&self) -> Vec<MeApiStatusSnapshot> {
        if self.inner.shards.len() == 1 {
            return vec![self.inner.shards[0].api_status_snapshot().await];
        }
        let futs = self
            .inner
            .shards
            .iter()
            .map(|shard| shard.api_status_snapshot());
        futures::future::join_all(futs).await
    }

    /// Aggregate `api_refill_snapshot()` across shards. Counts sum
    /// across shards — an endpoint refill in flight on shard A and the
    /// same endpoint on shard B is reported as 2 inflight ops because
    /// each is a separate connect attempt consuming its own socket
    /// budget. Operator reading "inflight_endpoints_total = 5" should
    /// understand it as "5 concurrent connect attempts," not "5 unique
    /// endpoints affected".
    ///
    /// Single-shard fast path: pass through.
    pub async fn aggregate_refill_snapshot(&self) -> MeApiRefillSnapshot {
        if self.inner.shards.len() == 1 {
            return self.inner.shards[0].api_refill_snapshot().await;
        }
        let futs = self
            .inner
            .shards
            .iter()
            .map(|shard| shard.api_refill_snapshot());
        let snaps = futures::future::join_all(futs).await;
        merge_refill_snapshots(snaps)
    }
}

pub(crate) fn merge_refill_snapshots(snaps: Vec<MeApiRefillSnapshot>) -> MeApiRefillSnapshot {
    assert!(
        !snaps.is_empty(),
        "merge_refill_snapshots requires ≥1 snapshot"
    );
    let inflight_endpoints_total: usize = snaps.iter().map(|s| s.inflight_endpoints_total).sum();
    // by_dc merges by (dc, family); sum inflight counts because each
    // shard's refill on the same DC is a distinct connect attempt.
    let mut by_dc_acc: BTreeMap<(i16, &'static str), usize> = BTreeMap::new();
    for snap in &snaps {
        for entry in &snap.by_dc {
            *by_dc_acc.entry((entry.dc, entry.family)).or_insert(0) += entry.inflight;
        }
    }
    let by_dc: Vec<MeApiRefillDcSnapshot> = by_dc_acc
        .into_iter()
        .map(|((dc, family), inflight)| MeApiRefillDcSnapshot {
            dc,
            family,
            inflight,
        })
        .collect();
    let inflight_dc_total = by_dc.len();
    MeApiRefillSnapshot {
        inflight_endpoints_total,
        inflight_dc_total,
        by_dc,
    }
}

/// Status snapshot merge — extracted so it's pure-function-testable
/// without spinning up real `MePool` instances.
pub(crate) fn merge_status_snapshots(snaps: Vec<MeApiStatusSnapshot>) -> MeApiStatusSnapshot {
    assert!(
        !snaps.is_empty(),
        "merge_status_snapshots requires ≥1 snapshot"
    );
    let generated_at_epoch_secs = snaps
        .iter()
        .map(|s| s.generated_at_epoch_secs)
        .max()
        .unwrap_or_default();
    // configured_dc_groups and configured_endpoints come from the global
    // Telegram proxy config — identical across every shard.
    let configured_dc_groups = snaps[0].configured_dc_groups;
    let configured_endpoints = snaps[0].configured_endpoints;
    let required_writers: usize = snaps.iter().map(|s| s.required_writers).sum();
    let alive_writers: usize = snaps.iter().map(|s| s.alive_writers).sum();
    let fresh_alive_writers: usize = snaps.iter().map(|s| s.fresh_alive_writers).sum();
    let coverage_pct = pct_or_zero(alive_writers, required_writers);
    let fresh_coverage_pct = pct_or_zero(fresh_alive_writers, required_writers);

    let mut writers = Vec::new();
    let mut dc_acc: BTreeMap<i16, DcAccumulator> = BTreeMap::new();
    for snap in snaps {
        writers.extend(snap.writers);
        for dc in snap.dcs {
            dc_acc
                .entry(dc.dc)
                .or_insert_with(DcAccumulator::new)
                .absorb(dc);
        }
    }
    let dcs: Vec<MeApiDcStatusSnapshot> =
        dc_acc.into_values().map(DcAccumulator::finalize).collect();

    // available_endpoints is endpoint-coverage state, NOT config — an
    // endpoint is "available" if at least one shard has a live writer to
    // it. Sum per-DC counts (each DC's finalize() already counts unique
    // endpoints with active writers via merged endpoint_writers).
    // Recomputing from the merged DCs prevents the under-counting bug
    // that taking primary's `available_endpoints` would cause when
    // shards cover disjoint endpoint subsets.
    let available_endpoints: usize = dcs.iter().map(|d| d.available_endpoints).sum();
    let available_pct = pct_or_zero(available_endpoints, configured_endpoints);

    MeApiStatusSnapshot {
        generated_at_epoch_secs,
        configured_dc_groups,
        configured_endpoints,
        available_endpoints,
        available_pct,
        required_writers,
        alive_writers,
        coverage_pct,
        fresh_alive_writers,
        fresh_coverage_pct,
        writers,
        dcs,
    }
}

/// Runtime snapshot merge — see docstring on
/// `MePoolMux::aggregate_runtime_snapshot` for the rules.
pub(crate) fn merge_runtime_snapshots(snaps: Vec<MeApiRuntimeSnapshot>) -> MeApiRuntimeSnapshot {
    debug_assert!(
        !snaps.is_empty(),
        "merge_runtime_snapshots requires ≥1 snapshot"
    );

    // Generation invariants: "system rotated past N" means every shard ≥ N.
    let active_generation = snaps.iter().map(|s| s.active_generation).min().unwrap_or(0);
    let warm_generation = snaps.iter().map(|s| s.warm_generation).min().unwrap_or(0);
    let pending_hardswap_generation = snaps
        .iter()
        .map(|s| s.pending_hardswap_generation)
        .min()
        .unwrap_or(0);
    // Max of pending-ages so operators see the worst laggard. None when no
    // shard has a pending hardswap.
    let pending_hardswap_age_secs = snaps
        .iter()
        .filter_map(|s| s.pending_hardswap_age_secs)
        .max();

    // Pool-state-derived totals (sum). These count actual writers held
    // across shards' independent pools.
    let adaptive_floor_active_writers_current: u64 = snaps
        .iter()
        .map(|s| s.adaptive_floor_active_writers_current)
        .sum();
    let adaptive_floor_warm_writers_current: u64 = snaps
        .iter()
        .map(|s| s.adaptive_floor_warm_writers_current)
        .sum();
    // target_writers_total is the sum of dc_required_writers across DCs
    // within ONE shard. Each shard's adaptive floor sets its own per-DC
    // target based on its own load signal, so the system target is the
    // sum of per-shard targets.
    let adaptive_floor_target_writers_total: u64 = snaps
        .iter()
        .map(|s| s.adaptive_floor_target_writers_total)
        .sum();
    // Caps below are operator-config-derived. Each shard loads the same
    // config into its own `floor_runtime` atomics, so the values are
    // duplicated across shards — summing inflates them N× and breaks
    // operator-dashboard comparisons like `target vs cap`. Take primary.
    let primary_rt = &snaps[0];
    let adaptive_floor_global_cap_raw = primary_rt.adaptive_floor_global_cap_raw;
    let adaptive_floor_global_cap_effective = primary_rt.adaptive_floor_global_cap_effective;
    let adaptive_floor_active_cap_configured = primary_rt.adaptive_floor_active_cap_configured;
    let adaptive_floor_active_cap_effective = primary_rt.adaptive_floor_active_cap_effective;
    let adaptive_floor_warm_cap_configured = primary_rt.adaptive_floor_warm_cap_configured;
    let adaptive_floor_warm_cap_effective = primary_rt.adaptive_floor_warm_cap_effective;

    // Quarantine union: by endpoint, max(remaining_ms).
    let mut q_acc: HashMap<SocketAddr, u64> = HashMap::new();
    for snap in &snaps {
        for q in &snap.quarantined_endpoints {
            q_acc
                .entry(q.endpoint)
                .and_modify(|v| *v = (*v).max(q.remaining_ms))
                .or_insert(q.remaining_ms);
        }
    }
    let mut quarantined_endpoints: Vec<MeApiQuarantinedEndpointSnapshot> = q_acc
        .into_iter()
        .map(
            |(endpoint, remaining_ms)| MeApiQuarantinedEndpointSnapshot {
                endpoint,
                remaining_ms,
            },
        )
        .collect();
    quarantined_endpoints.sort_by_key(|q| (q.endpoint, q.remaining_ms));

    // Everything else: take from primary (config-derived; identical across shards).
    let primary = &snaps[0];
    MeApiRuntimeSnapshot {
        active_generation,
        warm_generation,
        pending_hardswap_generation,
        pending_hardswap_age_secs,
        hardswap_enabled: primary.hardswap_enabled,
        floor_mode: primary.floor_mode,
        adaptive_floor_idle_secs: primary.adaptive_floor_idle_secs,
        adaptive_floor_min_writers_single_endpoint: primary
            .adaptive_floor_min_writers_single_endpoint,
        adaptive_floor_min_writers_multi_endpoint: primary
            .adaptive_floor_min_writers_multi_endpoint,
        adaptive_floor_recover_grace_secs: primary.adaptive_floor_recover_grace_secs,
        adaptive_floor_writers_per_core_total: primary.adaptive_floor_writers_per_core_total,
        adaptive_floor_cpu_cores_override: primary.adaptive_floor_cpu_cores_override,
        adaptive_floor_max_extra_writers_single_per_core: primary
            .adaptive_floor_max_extra_writers_single_per_core,
        adaptive_floor_max_extra_writers_multi_per_core: primary
            .adaptive_floor_max_extra_writers_multi_per_core,
        adaptive_floor_max_active_writers_per_core: primary
            .adaptive_floor_max_active_writers_per_core,
        adaptive_floor_max_warm_writers_per_core: primary.adaptive_floor_max_warm_writers_per_core,
        adaptive_floor_max_active_writers_global: primary.adaptive_floor_max_active_writers_global,
        adaptive_floor_max_warm_writers_global: primary.adaptive_floor_max_warm_writers_global,
        adaptive_floor_cpu_cores_detected: primary.adaptive_floor_cpu_cores_detected,
        adaptive_floor_cpu_cores_effective: primary.adaptive_floor_cpu_cores_effective,
        adaptive_floor_global_cap_raw,
        adaptive_floor_global_cap_effective,
        adaptive_floor_target_writers_total,
        adaptive_floor_active_cap_configured,
        adaptive_floor_active_cap_effective,
        adaptive_floor_warm_cap_configured,
        adaptive_floor_warm_cap_effective,
        adaptive_floor_active_writers_current,
        adaptive_floor_warm_writers_current,
        me_keepalive_enabled: primary.me_keepalive_enabled,
        me_keepalive_interval_secs: primary.me_keepalive_interval_secs,
        me_keepalive_jitter_secs: primary.me_keepalive_jitter_secs,
        me_keepalive_payload_random: primary.me_keepalive_payload_random,
        rpc_proxy_req_every_secs: primary.rpc_proxy_req_every_secs,
        me_reconnect_max_concurrent_per_dc: primary.me_reconnect_max_concurrent_per_dc,
        me_reconnect_backoff_base_ms: primary.me_reconnect_backoff_base_ms,
        me_reconnect_backoff_cap_ms: primary.me_reconnect_backoff_cap_ms,
        me_reconnect_fast_retry_count: primary.me_reconnect_fast_retry_count,
        me_pool_drain_ttl_secs: primary.me_pool_drain_ttl_secs,
        me_pool_force_close_secs: primary.me_pool_force_close_secs,
        me_pool_min_fresh_ratio: primary.me_pool_min_fresh_ratio,
        me_bind_stale_mode: primary.me_bind_stale_mode,
        me_bind_stale_ttl_secs: primary.me_bind_stale_ttl_secs,
        me_single_endpoint_shadow_writers: primary.me_single_endpoint_shadow_writers,
        me_single_endpoint_outage_mode_enabled: primary.me_single_endpoint_outage_mode_enabled,
        me_single_endpoint_outage_disable_quarantine: primary
            .me_single_endpoint_outage_disable_quarantine,
        me_single_endpoint_outage_backoff_min_ms: primary.me_single_endpoint_outage_backoff_min_ms,
        me_single_endpoint_outage_backoff_max_ms: primary.me_single_endpoint_outage_backoff_max_ms,
        me_single_endpoint_shadow_rotate_every_secs: primary
            .me_single_endpoint_shadow_rotate_every_secs,
        me_deterministic_writer_sort: primary.me_deterministic_writer_sort,
        me_writer_pick_mode: primary.me_writer_pick_mode,
        me_writer_pick_sample_size: primary.me_writer_pick_sample_size,
        me_socks_kdf_policy: primary.me_socks_kdf_policy,
        quarantined_endpoints,
        network_path: primary.network_path.clone(),
    }
}

/// Per-DC accumulator: for each DC seen across shards, sum the writer
/// counts and merge endpoint lists. Kept as a struct (not closure) so
/// the merge can grow new fields without restructuring.
struct DcAccumulator {
    dc: i16,
    endpoints: std::collections::BTreeSet<SocketAddr>,
    endpoint_writers: HashMap<SocketAddr, usize>,
    required_writers: usize,
    floor_min_primary: usize,
    floor_target: usize,
    floor_max_primary: usize,
    floor_capped: bool,
    alive_writers: usize,
    fresh_alive_writers: usize,
    load: usize,
    rtt_ms_min: Option<f64>,
    seen: usize,
}

impl DcAccumulator {
    fn new() -> Self {
        Self {
            dc: 0,
            endpoints: Default::default(),
            endpoint_writers: HashMap::new(),
            required_writers: 0,
            floor_min_primary: 0,
            floor_target: 0,
            floor_max_primary: 0,
            floor_capped: false,
            alive_writers: 0,
            fresh_alive_writers: 0,
            load: 0,
            rtt_ms_min: None,
            seen: 0,
        }
    }

    fn absorb(&mut self, snap: MeApiDcStatusSnapshot) {
        if self.seen == 0 {
            // Anchor config-shaped fields on the first shard contributing
            // this DC. All shards see the SAME operator config and proxy
            // config, so these stay consistent.
            //   * floor_min / floor_max are computed from
            //     me_adaptive_floor_*_per_endpoint config + core count —
            //     identical across shards. Summing 6× would inflate the
            //     visible floor and break alert thresholds.
            //   * available_pct at the DC level is recomputed in finalize()
            //     from the merged endpoint set; primary's value here is
            //     never propagated.
            self.dc = snap.dc;
            self.floor_min_primary = snap.floor_min;
            self.floor_max_primary = snap.floor_max;
        }
        self.seen += 1;
        for ep in snap.endpoints {
            self.endpoints.insert(ep);
        }
        for ew in snap.endpoint_writers {
            *self.endpoint_writers.entry(ew.endpoint).or_insert(0) += ew.active_writers;
        }
        // Pool-state-derived counts: SUM across shards.
        self.required_writers += snap.required_writers;
        // floor_target IS dc_required_writers from pool_status — per-shard
        // dynamic value driven by each shard's adaptive floor. Sum across
        // shards to get the system-wide target.
        self.floor_target += snap.floor_target;
        // floor_capped: OR — DC is capped if ANY shard hit the cap.
        self.floor_capped = self.floor_capped || snap.floor_capped;
        self.alive_writers += snap.alive_writers;
        self.fresh_alive_writers += snap.fresh_alive_writers;
        self.load += snap.load;
        // RTT: take the minimum across shards — the best path is what the
        // operator's smallest-latency shard observed.
        if let Some(r) = snap.rtt_ms {
            self.rtt_ms_min = Some(match self.rtt_ms_min {
                Some(prev) => prev.min(r),
                None => r,
            });
        }
    }

    fn finalize(self) -> MeApiDcStatusSnapshot {
        let endpoints: Vec<SocketAddr> = self.endpoints.into_iter().collect();
        let endpoint_count = endpoints.len();
        let mut endpoint_writers: Vec<MeApiDcEndpointWriterSnapshot> = self
            .endpoint_writers
            .into_iter()
            .map(|(endpoint, active_writers)| MeApiDcEndpointWriterSnapshot {
                endpoint,
                active_writers,
            })
            .collect();
        endpoint_writers.sort_by_key(|e| e.endpoint);
        // available_endpoints: unique endpoints with at least one live
        // writer across any shard. Recomputed from merged endpoint_writers
        // rather than max'ing per-shard counts — handles the disjoint-
        // endpoint-coverage case (shard A covers ep1, shard B covers ep2:
        // merged should report 2, not max(1,1)=1).
        let available_endpoints = endpoint_writers
            .iter()
            .filter(|ew| ew.active_writers > 0)
            .count();
        let available_pct = pct_or_zero(available_endpoints, endpoint_count);
        MeApiDcStatusSnapshot {
            dc: self.dc,
            endpoints,
            endpoint_writers,
            available_endpoints,
            available_pct,
            required_writers: self.required_writers,
            floor_min: self.floor_min_primary,
            floor_target: self.floor_target,
            floor_max: self.floor_max_primary,
            floor_capped: self.floor_capped,
            alive_writers: self.alive_writers,
            coverage_pct: pct_or_zero(self.alive_writers, self.required_writers),
            fresh_alive_writers: self.fresh_alive_writers,
            fresh_coverage_pct: pct_or_zero(self.fresh_alive_writers, self.required_writers),
            rtt_ms: self.rtt_ms_min,
            load: self.load,
        }
    }
}

/// `numerator/denominator * 100`, 0 when denominator is 0. Centralised so
/// aggregate coverages match per-shard formulas exactly.
fn pct_or_zero(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        (numerator as f64) * 100.0 / (denominator as f64)
    }
}

fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        other => other,
    }
}

/// Pure index calculation extracted from `MePoolMux::shard_for_peer` so it
/// can be unit-tested without constructing real `MePool` instances.
/// Returns 0 when `n <= 1` (single-shard / degenerate case).
pub(crate) fn shard_index_for(peer_ip: IpAddr, n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let key = canonicalize_ip(peer_ip);
    let mut h = DefaultHasher::new();
    key.hash(&mut h);
    (h.finish() as usize) % n
}

#[cfg(test)]
mod tests {
    //! The mux's hash-based shard selection is the contract that makes
    //! per-client source-IP affinity work. These tests pin that behaviour:
    //! single-shard degenerate case, determinism, spread, v4-mapped-v6
    //! canonicalisation. They exercise the pure `shard_index_for` helper
    //! so no live `MePool` is required — pointer-identity correctness is
    //! covered separately by integration tests in `tests/`.
    use super::shard_index_for;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn single_shard_always_returns_zero() {
        assert_eq!(shard_index_for(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 1), 0);
        assert_eq!(
            shard_index_for(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)), 1),
            0
        );
        // Degenerate zero-shard case — caller should never invoke this in
        // production but the helper must not panic.
        assert_eq!(shard_index_for(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 0), 0);
    }

    #[test]
    fn shard_index_is_deterministic() {
        let peer = IpAddr::V4(Ipv4Addr::new(45, 144, 53, 36));
        let a = shard_index_for(peer, 6);
        for _ in 0..50 {
            assert_eq!(shard_index_for(peer, 6), a);
        }
    }

    #[test]
    fn shard_index_spreads_across_shards() {
        let n = 6;
        let mut counts = [0u32; 6];
        for i in 0u32..3000 {
            let peer = IpAddr::V4(Ipv4Addr::new(
                (i >> 24) as u8,
                (i >> 16) as u8,
                (i >> 8) as u8,
                i as u8,
            ));
            counts[shard_index_for(peer, n)] += 1;
        }
        // Uniform expectation 500 / shard, allow generous slack for hash skew.
        for (idx, c) in counts.iter().enumerate() {
            assert!(
                *c >= 250 && *c <= 750,
                "shard {} got {} out of 3000 (expected 250..750)",
                idx,
                c
            );
        }
    }

    #[test]
    fn v4_mapped_v6_canonicalizes_to_same_shard_as_v4() {
        let n = 4;
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let v4_mapped = IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x0a00, 0x0001));
        assert_eq!(shard_index_for(v4, n), shard_index_for(v4_mapped, n));
    }
}

#[cfg(test)]
mod aggregation_tests {
    //! Pure-function tests for `merge_status_snapshots` and
    //! `merge_runtime_snapshots`. The aggregation must satisfy three
    //! invariants:
    //!
    //!   1. **Sum-counts are correct**: required/alive/fresh writer
    //!      counts add across shards; if they don't, /v1/stats lies about
    //!      capacity utilisation.
    //!   2. **Recomputed ratios match formulas**: coverage_pct must be
    //!      `alive_sum / required_sum * 100`, not `mean(per_shard_pct)`.
    //!      Naïve averaging weights a 1-writer shard equally with a
    //!      100-writer shard — wrong.
    //!   3. **Generations take min, not max**: "system is past generation
    //!      N" requires every shard ≥ N. Reporting max would lie about
    //!      laggards mid-rotation.
    //!
    //! These tests build raw snapshot structs (no live MePool) so they
    //! run in microseconds and can exhaustively cover edge cases.
    use super::{
        MeApiDcEndpointWriterSnapshot, MeApiDcStatusSnapshot, MeApiQuarantinedEndpointSnapshot,
        MeApiRefillSnapshot, MeApiRuntimeSnapshot, MeApiStatusSnapshot,
    };
    use super::{merge_runtime_snapshots, merge_status_snapshots};
    use std::net::SocketAddr;

    fn ep(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    fn empty_runtime() -> MeApiRuntimeSnapshot {
        MeApiRuntimeSnapshot {
            active_generation: 0,
            warm_generation: 0,
            pending_hardswap_generation: 0,
            pending_hardswap_age_secs: None,
            hardswap_enabled: false,
            floor_mode: "adaptive",
            adaptive_floor_idle_secs: 0,
            adaptive_floor_min_writers_single_endpoint: 0,
            adaptive_floor_min_writers_multi_endpoint: 0,
            adaptive_floor_recover_grace_secs: 0,
            adaptive_floor_writers_per_core_total: 0,
            adaptive_floor_cpu_cores_override: 0,
            adaptive_floor_max_extra_writers_single_per_core: 0,
            adaptive_floor_max_extra_writers_multi_per_core: 0,
            adaptive_floor_max_active_writers_per_core: 0,
            adaptive_floor_max_warm_writers_per_core: 0,
            adaptive_floor_max_active_writers_global: 0,
            adaptive_floor_max_warm_writers_global: 0,
            adaptive_floor_cpu_cores_detected: 0,
            adaptive_floor_cpu_cores_effective: 0,
            adaptive_floor_global_cap_raw: 0,
            adaptive_floor_global_cap_effective: 0,
            adaptive_floor_target_writers_total: 0,
            adaptive_floor_active_cap_configured: 0,
            adaptive_floor_active_cap_effective: 0,
            adaptive_floor_warm_cap_configured: 0,
            adaptive_floor_warm_cap_effective: 0,
            adaptive_floor_active_writers_current: 0,
            adaptive_floor_warm_writers_current: 0,
            me_keepalive_enabled: false,
            me_keepalive_interval_secs: 0,
            me_keepalive_jitter_secs: 0,
            me_keepalive_payload_random: false,
            rpc_proxy_req_every_secs: 0,
            me_reconnect_max_concurrent_per_dc: 0,
            me_reconnect_backoff_base_ms: 0,
            me_reconnect_backoff_cap_ms: 0,
            me_reconnect_fast_retry_count: 0,
            me_pool_drain_ttl_secs: 0,
            me_pool_force_close_secs: 0,
            me_pool_min_fresh_ratio: 0.0,
            me_bind_stale_mode: "off",
            me_bind_stale_ttl_secs: 0,
            me_single_endpoint_shadow_writers: 0,
            me_single_endpoint_outage_mode_enabled: false,
            me_single_endpoint_outage_disable_quarantine: false,
            me_single_endpoint_outage_backoff_min_ms: 0,
            me_single_endpoint_outage_backoff_max_ms: 0,
            me_single_endpoint_shadow_rotate_every_secs: 0,
            me_deterministic_writer_sort: false,
            me_writer_pick_mode: "random",
            me_writer_pick_sample_size: 0,
            me_socks_kdf_policy: "off",
            quarantined_endpoints: vec![],
            network_path: vec![],
        }
    }

    fn dc_snap(
        dc: i16,
        required: usize,
        alive: usize,
        fresh: usize,
        endpoints: Vec<SocketAddr>,
        rtt_ms: Option<f64>,
    ) -> MeApiDcStatusSnapshot {
        let endpoint_writers = endpoints
            .iter()
            .map(|&e| MeApiDcEndpointWriterSnapshot {
                endpoint: e,
                active_writers: 1,
            })
            .collect();
        MeApiDcStatusSnapshot {
            dc,
            endpoints,
            endpoint_writers,
            available_endpoints: 1,
            available_pct: 100.0,
            required_writers: required,
            floor_min: 1,
            floor_target: 1,
            floor_max: 2,
            floor_capped: false,
            alive_writers: alive,
            coverage_pct: 0.0, // recomputed by merge
            fresh_alive_writers: fresh,
            fresh_coverage_pct: 0.0,
            rtt_ms,
            load: 0,
        }
    }

    fn status_snap(
        generated: u64,
        required: usize,
        alive: usize,
        fresh: usize,
        dcs: Vec<MeApiDcStatusSnapshot>,
    ) -> MeApiStatusSnapshot {
        MeApiStatusSnapshot {
            generated_at_epoch_secs: generated,
            configured_dc_groups: 5,
            configured_endpoints: 12,
            available_endpoints: 12,
            available_pct: 100.0,
            required_writers: required,
            alive_writers: alive,
            coverage_pct: 0.0,
            fresh_alive_writers: fresh,
            fresh_coverage_pct: 0.0,
            writers: vec![],
            dcs,
        }
    }

    #[test]
    fn coverage_pct_uses_summed_ratio_not_mean_of_per_shard_pcts() {
        // Shard A: 1 alive / 1 required (100%). Shard B: 0 alive / 99
        // required (0%). Naïve mean would report 50% — but system-wide
        // coverage is actually 1/100 = 1%. This test fails if any future
        // refactor reverts to mean.
        let a = status_snap(100, 1, 1, 1, vec![]);
        let b = status_snap(200, 99, 0, 0, vec![]);
        let merged = merge_status_snapshots(vec![a, b]);
        assert_eq!(merged.required_writers, 100);
        assert_eq!(merged.alive_writers, 1);
        assert!(
            (merged.coverage_pct - 1.0).abs() < 1e-9,
            "expected 1%, got {}",
            merged.coverage_pct
        );
        // generated takes max
        assert_eq!(merged.generated_at_epoch_secs, 200);
    }

    #[test]
    fn dcs_merge_by_id_and_sum_writer_counts() {
        // Both shards see DC -2 + DC 2. Merged should have 2 DCs and
        // doubled writer counts.
        let a = status_snap(
            100,
            6,
            4,
            3,
            vec![
                dc_snap(-2, 3, 2, 2, vec![ep("1.1.1.1:443")], Some(10.0)),
                dc_snap(2, 3, 2, 1, vec![ep("2.2.2.2:443")], Some(20.0)),
            ],
        );
        let b = status_snap(
            150,
            6,
            5,
            4,
            vec![
                dc_snap(-2, 3, 3, 3, vec![ep("1.1.1.1:443")], Some(8.0)),
                dc_snap(2, 3, 2, 1, vec![ep("2.2.2.2:443")], Some(25.0)),
            ],
        );
        let merged = merge_status_snapshots(vec![a, b]);
        assert_eq!(merged.dcs.len(), 2);
        let dc_neg2 = merged.dcs.iter().find(|d| d.dc == -2).unwrap();
        assert_eq!(dc_neg2.required_writers, 6);
        assert_eq!(dc_neg2.alive_writers, 5);
        assert_eq!(dc_neg2.fresh_alive_writers, 5);
        // RTT: takes the minimum of contributing shards' RTTs.
        assert_eq!(dc_neg2.rtt_ms, Some(8.0));
        // coverage_pct recomputed: 5 / 6 = 83.33...
        assert!((dc_neg2.coverage_pct - (5.0 * 100.0 / 6.0)).abs() < 1e-9);
        // endpoint_writers: same endpoint contributed 1 writer per shard → 2 total.
        assert_eq!(dc_neg2.endpoint_writers.len(), 1);
        assert_eq!(dc_neg2.endpoint_writers[0].active_writers, 2);
    }

    #[test]
    fn dcs_disjoint_endpoints_across_shards_union_into_merged_set() {
        // Shard A covers ep1 in DC -2, shard B covers ep2 in DC -2 — two
        // operator-distinct endpoints. The merged DC must report BOTH
        // endpoints and 2 active_writers total. A naïve "take max
        // available_endpoints across shards" would report 1 — the bug
        // pattern the merge change is fixing.
        let a = status_snap(
            100,
            2,
            1,
            1,
            vec![dc_snap(-2, 2, 1, 1, vec![ep("1.1.1.1:443")], None)],
        );
        let b = status_snap(
            100,
            2,
            1,
            1,
            vec![dc_snap(-2, 2, 1, 1, vec![ep("1.1.1.2:443")], None)],
        );
        let merged = merge_status_snapshots(vec![a, b]);
        assert_eq!(merged.dcs.len(), 1);
        let dc = &merged.dcs[0];
        assert_eq!(dc.endpoints.len(), 2, "endpoint union should hold both");
        assert_eq!(
            dc.endpoint_writers.len(),
            2,
            "two distinct endpoints contributed writers"
        );
        assert_eq!(
            dc.available_endpoints, 2,
            "both endpoints alive: available count is union"
        );
        // available_pct at DC level: 2 alive of 2 known = 100%.
        assert!((dc.available_pct - 100.0).abs() < 1e-9);
        // Top-level available_endpoints sums DC-level counts.
        assert_eq!(merged.available_endpoints, 2);
    }

    #[test]
    fn dc_floor_min_max_take_primary_not_sum() {
        // floor_min and floor_max are config-derived (per-endpoint mins
        // + cores * extra_per_core). All shards load the same operator
        // config and produce the same floor_min/max. Summing them would
        // 6× the visible floor and break operator alert thresholds.
        // floor_target IS per-shard adaptive (dc_required_writers) and
        // does sum.
        let a = status_snap(
            100,
            6,
            6,
            6,
            vec![MeApiDcStatusSnapshot {
                dc: -2,
                endpoints: vec![],
                endpoint_writers: vec![],
                available_endpoints: 1,
                available_pct: 100.0,
                required_writers: 3,
                floor_min: 2,
                floor_target: 3,
                floor_max: 8,
                floor_capped: false,
                alive_writers: 3,
                coverage_pct: 0.0,
                fresh_alive_writers: 3,
                fresh_coverage_pct: 0.0,
                rtt_ms: None,
                load: 0,
            }],
        );
        let b = status_snap(
            100,
            6,
            6,
            6,
            vec![MeApiDcStatusSnapshot {
                dc: -2,
                endpoints: vec![],
                endpoint_writers: vec![],
                available_endpoints: 1,
                available_pct: 100.0,
                required_writers: 3,
                floor_min: 2,
                floor_target: 3,
                floor_max: 8,
                floor_capped: true, // OR'd in finalize
                alive_writers: 3,
                coverage_pct: 0.0,
                fresh_alive_writers: 3,
                fresh_coverage_pct: 0.0,
                rtt_ms: None,
                load: 0,
            }],
        );
        let merged = merge_status_snapshots(vec![a, b]);
        let dc = &merged.dcs[0];
        assert_eq!(dc.floor_min, 2, "floor_min from primary, not 2+2=4");
        assert_eq!(dc.floor_max, 8, "floor_max from primary, not 8+8=16");
        // floor_target sums: per-shard dynamic value.
        assert_eq!(dc.floor_target, 6, "3 + 3 from per-shard adaptive");
        assert!(dc.floor_capped, "OR across shards");
    }

    #[test]
    fn runtime_caps_take_primary_not_sum() {
        // global_cap_* and active/warm_cap_* are config-derived
        // duplicated per-shard atomics. Summing them N× would inflate
        // the cap and break the `target vs cap` invariant operators rely
        // on for capacity planning. Only *_writers_current and
        // target_writers_total are pool-state-derived and should sum.
        let mut a = empty_runtime();
        a.adaptive_floor_global_cap_raw = 1000;
        a.adaptive_floor_global_cap_effective = 800;
        a.adaptive_floor_active_cap_configured = 600;
        a.adaptive_floor_active_cap_effective = 500;
        a.adaptive_floor_warm_cap_configured = 200;
        a.adaptive_floor_warm_cap_effective = 150;
        // target IS per-shard dynamic — sum it.
        a.adaptive_floor_target_writers_total = 60;
        a.adaptive_floor_active_writers_current = 55;
        let b = a.clone();
        let merged = merge_runtime_snapshots(vec![a, b]);
        assert_eq!(
            merged.adaptive_floor_global_cap_raw, 1000,
            "primary, not 2000"
        );
        assert_eq!(merged.adaptive_floor_global_cap_effective, 800);
        assert_eq!(merged.adaptive_floor_active_cap_configured, 600);
        assert_eq!(merged.adaptive_floor_active_cap_effective, 500);
        assert_eq!(merged.adaptive_floor_warm_cap_configured, 200);
        assert_eq!(merged.adaptive_floor_warm_cap_effective, 150);
        // SUM cases:
        assert_eq!(merged.adaptive_floor_target_writers_total, 120);
        assert_eq!(merged.adaptive_floor_active_writers_current, 110);
    }

    #[test]
    fn dcs_present_in_only_one_shard_still_appear_in_merge() {
        // Edge case: one shard sees DC 5 (perhaps because its source IP
        // is the only one with that DC routable). The merged view must
        // include it — losing it would silently misrepresent the system.
        let a = status_snap(100, 2, 2, 2, vec![dc_snap(5, 2, 2, 2, vec![], None)]);
        let b = status_snap(100, 0, 0, 0, vec![]);
        let merged = merge_status_snapshots(vec![a, b]);
        assert_eq!(merged.dcs.len(), 1);
        assert_eq!(merged.dcs[0].dc, 5);
        assert_eq!(merged.dcs[0].alive_writers, 2);
    }

    #[test]
    fn coverage_pct_handles_zero_denominator() {
        // A shard with 0 required (e.g. no DCs configured) must not
        // divide by zero — coverage stays 0.
        let a = status_snap(100, 0, 0, 0, vec![]);
        let merged = merge_status_snapshots(vec![a]);
        assert_eq!(merged.coverage_pct, 0.0);
        assert_eq!(merged.fresh_coverage_pct, 0.0);
    }

    #[test]
    fn writers_concatenate_across_shards() {
        let mut a = status_snap(100, 2, 2, 2, vec![]);
        a.writers
            .push(super::super::pool_status::MeApiWriterStatusSnapshot {
                writer_id: 1,
                dc: Some(-2),
                endpoint: ep("1.1.1.1:443"),
                generation: 1,
                state: "active",
                draining: false,
                degraded: false,
                bound_clients: 0,
                idle_for_secs: None,
                rtt_ema_ms: None,
                matches_active_generation: true,
                in_desired_map: true,
                allow_drain_fallback: false,
                drain_started_at_epoch_secs: None,
                drain_deadline_epoch_secs: None,
                drain_over_ttl: false,
            });
        let mut b = status_snap(100, 2, 2, 2, vec![]);
        b.writers
            .push(super::super::pool_status::MeApiWriterStatusSnapshot {
                writer_id: 99,
                dc: Some(2),
                endpoint: ep("2.2.2.2:443"),
                generation: 1,
                state: "active",
                draining: false,
                degraded: false,
                bound_clients: 0,
                idle_for_secs: None,
                rtt_ema_ms: None,
                matches_active_generation: true,
                in_desired_map: true,
                allow_drain_fallback: false,
                drain_started_at_epoch_secs: None,
                drain_deadline_epoch_secs: None,
                drain_over_ttl: false,
            });
        let merged = merge_status_snapshots(vec![a, b]);
        assert_eq!(merged.writers.len(), 2);
        let ids: Vec<u64> = merged.writers.iter().map(|w| w.writer_id).collect();
        assert!(ids.contains(&1) && ids.contains(&99));
    }

    #[test]
    fn runtime_generations_take_minimum() {
        // Lying about generation would let operators believe a rotation
        // completed when one shard is still on the old generation. Take
        // min so "system is past N" is true iff every shard is past N.
        let mut a = empty_runtime();
        a.active_generation = 5;
        a.warm_generation = 4;
        a.pending_hardswap_generation = 6;
        let mut b = empty_runtime();
        b.active_generation = 3;
        b.warm_generation = 5;
        b.pending_hardswap_generation = 2;
        let merged = merge_runtime_snapshots(vec![a, b]);
        assert_eq!(merged.active_generation, 3, "min(5, 3) = 3");
        assert_eq!(merged.warm_generation, 4, "min(4, 5) = 4");
        assert_eq!(merged.pending_hardswap_generation, 2, "min(6, 2) = 2");
    }

    #[test]
    fn runtime_pending_hardswap_age_takes_max_or_none() {
        let mut a = empty_runtime();
        a.pending_hardswap_age_secs = Some(120);
        let mut b = empty_runtime();
        b.pending_hardswap_age_secs = Some(60);
        let mut c = empty_runtime();
        c.pending_hardswap_age_secs = None;
        let merged = merge_runtime_snapshots(vec![a, b, c]);
        assert_eq!(merged.pending_hardswap_age_secs, Some(120));

        let merged_all_none = merge_runtime_snapshots(vec![empty_runtime(), empty_runtime()]);
        assert_eq!(merged_all_none.pending_hardswap_age_secs, None);
    }

    #[test]
    fn runtime_writer_counts_sum_across_shards() {
        let mut a = empty_runtime();
        a.adaptive_floor_active_writers_current = 30;
        a.adaptive_floor_warm_writers_current = 5;
        a.adaptive_floor_target_writers_total = 36;
        let mut b = empty_runtime();
        b.adaptive_floor_active_writers_current = 25;
        b.adaptive_floor_warm_writers_current = 7;
        b.adaptive_floor_target_writers_total = 30;
        let merged = merge_runtime_snapshots(vec![a, b]);
        assert_eq!(merged.adaptive_floor_active_writers_current, 55);
        assert_eq!(merged.adaptive_floor_warm_writers_current, 12);
        assert_eq!(merged.adaptive_floor_target_writers_total, 66);
    }

    #[test]
    fn runtime_quarantine_union_by_endpoint_takes_max_remaining() {
        // Same endpoint quarantined in two shards with different
        // remaining_ms. Merged should show endpoint once, with the
        // longest remaining — that's the worst case operator should see.
        let mut a = empty_runtime();
        a.quarantined_endpoints = vec![
            MeApiQuarantinedEndpointSnapshot {
                endpoint: ep("9.9.9.9:443"),
                remaining_ms: 5000,
            },
            MeApiQuarantinedEndpointSnapshot {
                endpoint: ep("1.1.1.1:443"),
                remaining_ms: 3000,
            },
        ];
        let mut b = empty_runtime();
        b.quarantined_endpoints = vec![MeApiQuarantinedEndpointSnapshot {
            endpoint: ep("9.9.9.9:443"),
            remaining_ms: 12000,
        }];
        let merged = merge_runtime_snapshots(vec![a, b]);
        assert_eq!(merged.quarantined_endpoints.len(), 2);
        let nines = merged
            .quarantined_endpoints
            .iter()
            .find(|q| q.endpoint == ep("9.9.9.9:443"))
            .unwrap();
        assert_eq!(nines.remaining_ms, 12000, "should take max remaining");
    }

    #[test]
    fn refill_inflight_counts_sum_and_dc_merges_by_key() {
        // Operator-visible refill view must show system-wide load. Two
        // shards each with 3 in-flight refills means the system has 6
        // concurrent connect attempts consuming socket budget; primary-
        // only reporting would lie about half of them. by_dc merges by
        // (dc, family) and sums inflight counts.
        use super::super::pool_runtime_api::MeApiRefillDcSnapshot;
        let a = MeApiRefillSnapshot {
            inflight_endpoints_total: 3,
            inflight_dc_total: 2,
            by_dc: vec![
                MeApiRefillDcSnapshot {
                    dc: -2,
                    family: "v4",
                    inflight: 2,
                },
                MeApiRefillDcSnapshot {
                    dc: 2,
                    family: "v4",
                    inflight: 1,
                },
            ],
        };
        let b = MeApiRefillSnapshot {
            inflight_endpoints_total: 3,
            inflight_dc_total: 2,
            by_dc: vec![
                MeApiRefillDcSnapshot {
                    dc: -2,
                    family: "v4",
                    inflight: 1,
                },
                MeApiRefillDcSnapshot {
                    dc: -2,
                    family: "v6",
                    inflight: 2,
                },
            ],
        };
        let merged = super::merge_refill_snapshots(vec![a, b]);
        assert_eq!(merged.inflight_endpoints_total, 6);
        // Three distinct (dc, family) keys: (-2,v4), (2,v4), (-2,v6).
        assert_eq!(merged.inflight_dc_total, 3);
        let neg2_v4 = merged
            .by_dc
            .iter()
            .find(|e| e.dc == -2 && e.family == "v4")
            .unwrap();
        assert_eq!(neg2_v4.inflight, 3, "2 + 1 = 3");
    }

    #[test]
    fn single_shard_runtime_passthrough_is_byte_identical() {
        // Default (round_robin) mode wraps a single MePool; the merge
        // helper should be exactly equivalent to passing through the one
        // input. This is the back-compat invariant that lets us swap to
        // aggregation without changing single-shard observable behaviour.
        let mut input = empty_runtime();
        input.active_generation = 42;
        input.pending_hardswap_age_secs = Some(7);
        input.adaptive_floor_active_writers_current = 100;
        input.quarantined_endpoints = vec![MeApiQuarantinedEndpointSnapshot {
            endpoint: ep("4.4.4.4:443"),
            remaining_ms: 999,
        }];
        let merged = merge_runtime_snapshots(vec![input.clone()]);
        assert_eq!(merged.active_generation, input.active_generation);
        assert_eq!(merged.warm_generation, input.warm_generation);
        assert_eq!(merged.pending_hardswap_age_secs, Some(7));
        assert_eq!(
            merged.adaptive_floor_active_writers_current,
            input.adaptive_floor_active_writers_current
        );
        assert_eq!(merged.quarantined_endpoints.len(), 1);
    }
}
