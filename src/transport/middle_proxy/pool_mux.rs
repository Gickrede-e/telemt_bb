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

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;

use super::pool::MePool;

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
