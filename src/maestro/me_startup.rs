#![allow(clippy::too_many_arguments)]

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{RwLock, watch};
use tracing::{error, info, warn};

use crate::config::{MeWriterBindMode, ProxyConfig};
use crate::crypto::SecureRandom;
use crate::network::probe::{NetworkDecision, NetworkProbe};
use crate::startup::{
    COMPONENT_ME_POOL_CONSTRUCT, COMPONENT_ME_POOL_INIT_STAGE1, COMPONENT_ME_PROXY_CONFIG_V4,
    COMPONENT_ME_PROXY_CONFIG_V6, COMPONENT_ME_SECRET_FETCH, StartupMeStatus, StartupTracker,
};
use crate::stats::Stats;
use crate::transport::UpstreamManager;
use crate::transport::middle_proxy::{MePool, MePoolMux};

use super::helpers::load_startup_proxy_config_snapshot;

pub(crate) async fn initialize_me_pool(
    use_middle_proxy: bool,
    config: &ProxyConfig,
    decision: &NetworkDecision,
    probe: &NetworkProbe,
    startup_tracker: &Arc<StartupTracker>,
    upstream_manager: Arc<UpstreamManager>,
    rng: Arc<SecureRandom>,
    stats: Arc<Stats>,
    api_me_pool: Arc<RwLock<Option<Arc<MePoolMux>>>>,
    me_ready_tx: watch::Sender<u64>,
) -> Option<Arc<MePoolMux>> {
    if !use_middle_proxy {
        return None;
    }

    info!("=== Middle Proxy Mode ===");
    let me_nat_probe = config.general.middle_proxy_nat_probe && config.network.stun_use;
    if config.general.middle_proxy_nat_probe && !config.network.stun_use {
        info!("Middle-proxy STUN probing disabled by network.stun_use=false");
    }

    let me2dc_fallback = config.general.me2dc_fallback;
    let me_init_retry_attempts = config.general.me_init_retry_attempts;
    let me_init_warn_after_attempts: u32 = 3;

    // Global ad_tag (pool default). Used when user has no per-user tag in access.user_ad_tags.
    let proxy_tag = config
        .general
        .ad_tag
        .as_ref()
        .map(|tag| hex::decode(tag).expect("general.ad_tag must be validated before startup"));

    // =============================================================
    // CRITICAL: Download Telegram proxy-secret (NOT user secret!)
    //
    // C MTProxy uses TWO separate secrets:
    //   -S flag    = 16-byte user secret for client obfuscation
    //   --aes-pwd  = 32-512 byte binary file for ME RPC auth
    //
    // proxy-secret is from: https://core.telegram.org/getProxySecret
    // =============================================================
    let proxy_secret_path = config.general.proxy_secret_path.as_deref();
    let pool_size = config.general.middle_proxy_pool_size.max(1);
    let proxy_secret = loop {
        match crate::transport::middle_proxy::fetch_proxy_secret_with_upstream(
            proxy_secret_path,
            config.general.proxy_secret_len_max,
            config.general.proxy_secret_url.as_deref(),
            Some(upstream_manager.clone()),
        )
        .await
        {
            Ok(proxy_secret) => break Some(proxy_secret),
            Err(e) => {
                startup_tracker.set_me_last_error(Some(e.to_string())).await;
                if me2dc_fallback {
                    error!(
                        error = %e,
                        "ME startup failed: proxy-secret is unavailable and no saved secret found; falling back to direct mode"
                    );
                    break None;
                }

                warn!(
                    error = %e,
                    retry_in_secs = 2,
                    "ME startup failed: proxy-secret is unavailable and no saved secret found; retrying because me2dc_fallback=false"
                );
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    };
    match proxy_secret {
        Some(proxy_secret) => {
            startup_tracker
                .complete_component(
                    COMPONENT_ME_SECRET_FETCH,
                    Some("proxy-secret loaded".to_string()),
                )
                .await;
            info!(
                secret_len = proxy_secret.len(),
                key_sig = format_args!(
                    "0x{:08x}",
                    if proxy_secret.len() >= 4 {
                        u32::from_le_bytes([
                            proxy_secret[0],
                            proxy_secret[1],
                            proxy_secret[2],
                            proxy_secret[3],
                        ])
                    } else {
                        0
                    }
                ),
                "Proxy-secret loaded"
            );

            startup_tracker
                .start_component(
                    COMPONENT_ME_PROXY_CONFIG_V4,
                    Some("load startup proxy-config v4".to_string()),
                )
                .await;
            startup_tracker
                .set_me_status(StartupMeStatus::Initializing, COMPONENT_ME_PROXY_CONFIG_V4)
                .await;
            let cfg_v4 = load_startup_proxy_config_snapshot(
                config
                    .general
                    .proxy_config_v4_url
                    .as_deref()
                    .unwrap_or("https://core.telegram.org/getProxyConfig"),
                config.general.proxy_config_v4_cache_path.as_deref(),
                me2dc_fallback,
                "getProxyConfig",
                Some(upstream_manager.clone()),
            )
            .await;
            if cfg_v4.is_some() {
                startup_tracker
                    .complete_component(
                        COMPONENT_ME_PROXY_CONFIG_V4,
                        Some("proxy-config v4 loaded".to_string()),
                    )
                    .await;
            } else {
                startup_tracker
                    .fail_component(
                        COMPONENT_ME_PROXY_CONFIG_V4,
                        Some("proxy-config v4 unavailable".to_string()),
                    )
                    .await;
            }
            startup_tracker
                .start_component(
                    COMPONENT_ME_PROXY_CONFIG_V6,
                    Some("load startup proxy-config v6".to_string()),
                )
                .await;
            startup_tracker
                .set_me_status(StartupMeStatus::Initializing, COMPONENT_ME_PROXY_CONFIG_V6)
                .await;
            let cfg_v6 = load_startup_proxy_config_snapshot(
                config
                    .general
                    .proxy_config_v6_url
                    .as_deref()
                    .unwrap_or("https://core.telegram.org/getProxyConfigV6"),
                config.general.proxy_config_v6_cache_path.as_deref(),
                me2dc_fallback,
                "getProxyConfigV6",
                Some(upstream_manager.clone()),
            )
            .await;
            if cfg_v6.is_some() {
                startup_tracker
                    .complete_component(
                        COMPONENT_ME_PROXY_CONFIG_V6,
                        Some("proxy-config v6 loaded".to_string()),
                    )
                    .await;
            } else {
                startup_tracker
                    .fail_component(
                        COMPONENT_ME_PROXY_CONFIG_V6,
                        Some("proxy-config v6 unavailable".to_string()),
                    )
                    .await;
            }

            if let (Some(cfg_v4), Some(cfg_v6)) = (cfg_v4, cfg_v6) {
                startup_tracker
                    .start_component(
                        COMPONENT_ME_POOL_CONSTRUCT,
                        Some("construct ME pool".to_string()),
                    )
                    .await;
                startup_tracker
                    .set_me_status(StartupMeStatus::Initializing, COMPONENT_ME_POOL_CONSTRUCT)
                    .await;

                // Per-source-IP shard plan. When `me_writer_bind_mode = shard`
                // and the operator configured ≥2 `bind_addresses`, we build
                // one fully-isolated MePool per address (each pool's writers
                // pin to its single source IP via shard_bind_override). The
                // primary shard (index 0) uses the existing inline init path
                // below; supplementary shards (1..N) get their own background
                // init+supervisor via spawn_shard_supervisor.
                let shard_overrides = compute_shard_overrides(config);
                let shard_count = shard_overrides.len();

                // Closure that builds one MePool with the given source-IP
                // override. Captures every constructor input by reference
                // and clones inside the body, so the closure is callable N
                // times to build N shards. Hides 85+ MePool::new arguments
                // behind a one-arg interface — extending MePool::new now
                // requires editing one site instead of two, eliminating
                // the drift risk between primary and supplementary shards.
                let make_pool = |override_bind: Option<IpAddr>| -> Arc<MePool> {
                    MePool::new(
                        proxy_tag.clone(),
                        proxy_secret.clone(),
                        config.general.middle_proxy_nat_ip,
                        me_nat_probe,
                        None,
                        config.network.stun_servers.clone(),
                        config.general.stun_nat_probe_concurrency,
                        probe.detected_ipv6,
                        config.timeouts.me_one_retry,
                        config.timeouts.me_one_timeout_ms,
                        cfg_v4.map.clone(),
                        cfg_v6.map.clone(),
                        cfg_v4.default_dc.or(cfg_v6.default_dc),
                        decision.clone(),
                        Some(upstream_manager.clone()),
                        rng.clone(),
                        stats.clone(),
                        config.general.me_keepalive_enabled,
                        config.general.me_keepalive_interval_secs,
                        config.general.me_keepalive_jitter_secs,
                        config.general.me_keepalive_payload_random,
                        config.general.rpc_proxy_req_every,
                        config.general.me_warmup_stagger_enabled,
                        config.general.me_warmup_step_delay_ms,
                        config.general.me_warmup_step_jitter_ms,
                        config.general.me_reconnect_max_concurrent_per_dc,
                        config.general.me_reconnect_backoff_base_ms,
                        config.general.me_reconnect_backoff_cap_ms,
                        config.general.me_reconnect_fast_retry_count,
                        config.general.me_single_endpoint_shadow_writers,
                        config.general.me_single_endpoint_outage_mode_enabled,
                        config.general.me_single_endpoint_outage_disable_quarantine,
                        config.general.me_single_endpoint_outage_backoff_min_ms,
                        config.general.me_single_endpoint_outage_backoff_max_ms,
                        config.general.me_single_endpoint_shadow_rotate_every_secs,
                        config.general.me_floor_mode,
                        config.general.me_adaptive_floor_idle_secs,
                        config.general.me_adaptive_floor_min_writers_single_endpoint,
                        config.general.me_adaptive_floor_min_writers_multi_endpoint,
                        config.general.me_writer_bind_multiplier,
                        config.general.me_adaptive_floor_recover_grace_secs,
                        config.general.me_adaptive_floor_writers_per_core_total,
                        config.general.me_adaptive_floor_cpu_cores_override,
                        config
                            .general
                            .me_adaptive_floor_max_extra_writers_single_per_core,
                        config
                            .general
                            .me_adaptive_floor_max_extra_writers_multi_per_core,
                        config.general.me_adaptive_floor_max_active_writers_per_core,
                        config.general.me_adaptive_floor_max_warm_writers_per_core,
                        config.general.me_adaptive_floor_max_active_writers_global,
                        config.general.me_adaptive_floor_max_warm_writers_global,
                        config.general.hardswap,
                        config.general.me_pool_drain_ttl_secs,
                        config.general.me_instadrain,
                        config.general.me_pool_drain_threshold,
                        config.general.me_pool_drain_soft_evict_enabled,
                        config.general.me_pool_drain_soft_evict_grace_secs,
                        config.general.me_pool_drain_soft_evict_per_writer,
                        config.general.me_pool_drain_soft_evict_budget_per_core,
                        config.general.me_pool_drain_soft_evict_cooldown_ms,
                        config.general.effective_me_pool_force_close_secs(),
                        config.general.me_pool_min_fresh_ratio,
                        config.general.me_hardswap_warmup_delay_min_ms,
                        config.general.me_hardswap_warmup_delay_max_ms,
                        config.general.me_hardswap_warmup_extra_passes,
                        config.general.me_hardswap_warmup_pass_backoff_base_ms,
                        config.general.me_bind_stale_mode,
                        config.general.me_bind_stale_ttl_secs,
                        config.general.me_secret_atomic_snapshot,
                        config.general.me_deterministic_writer_sort,
                        config.general.me_writer_pick_mode,
                        config.general.me_writer_pick_sample_size,
                        config.general.me_socks_kdf_policy,
                        config.general.me_writer_cmd_channel_capacity,
                        config.general.me_route_channel_capacity,
                        config.general.me_route_backpressure_enabled,
                        config.general.me_route_fairshare_enabled,
                        config.general.me_route_backpressure_base_timeout_ms,
                        config.general.me_route_backpressure_high_timeout_ms,
                        config.general.me_route_backpressure_high_watermark_pct,
                        config.general.me_reader_route_data_wait_ms,
                        config.general.me_health_interval_ms_unhealthy,
                        config.general.me_health_interval_ms_healthy,
                        config.general.me_warn_rate_limit_ms,
                        config.general.me_route_no_writer_mode,
                        config.general.me_route_no_writer_wait_ms,
                        config.general.me_route_hybrid_max_wait_ms,
                        config.general.me_route_blocking_send_timeout_ms,
                        config.general.me_route_inline_recovery_attempts,
                        config.general.me_route_inline_recovery_wait_ms,
                        override_bind,
                    )
                };

                // Build all shards. Construction must complete before the
                // mux is published so listeners see every shard on their
                // very first accept; init (outbound MTProto handshake)
                // happens asynchronously below.
                let shards: Vec<Arc<MePool>> =
                    shard_overrides.iter().copied().map(&make_pool).collect();
                let pool = shards[0].clone();

                startup_tracker
                    .complete_component(
                        COMPONENT_ME_POOL_CONSTRUCT,
                        Some(format!("ME pool object created ({} shards)", shard_count)),
                    )
                    .await;

                // Build the mux holding all shards. When shard_count == 1
                // we still wrap in `from_single` so the api_me_pool storage
                // type is uniform; the wrapper is a 1-element vec and a
                // zero-cost passthrough at the call sites.
                let mux = if shard_count == 1 {
                    Arc::new(MePoolMux::from_single(pool.clone()))
                } else {
                    Arc::new(MePoolMux::from_shards(
                        shards.clone(),
                        shard_overrides.clone(),
                    ))
                };
                *api_me_pool.write().await = Some(mux.clone());

                // Kick off supplementary shards' init+supervisor in their own
                // background runtimes. They run in parallel with the primary
                // shard's init (below) so the slowest shard, not the sum,
                // sets ME readiness latency.
                for (idx, shard) in shards.iter().enumerate().skip(1) {
                    spawn_shard_supervisor(
                        shard.clone(),
                        idx,
                        rng.clone(),
                        pool_size,
                        me_ready_tx.clone(),
                    );
                }
                startup_tracker
                    .start_component(
                        COMPONENT_ME_POOL_INIT_STAGE1,
                        Some("initialize ME pool writers".to_string()),
                    )
                    .await;
                startup_tracker
                    .set_me_status(StartupMeStatus::Initializing, COMPONENT_ME_POOL_INIT_STAGE1)
                    .await;

                if me2dc_fallback {
                    let pool_bg = pool.clone();
                    let rng_bg = rng.clone();
                    let startup_tracker_bg = startup_tracker.clone();
                    let me_ready_tx_bg = me_ready_tx.clone();
                    let retry_limit = if me_init_retry_attempts == 0 {
                        String::from("unlimited")
                    } else {
                        me_init_retry_attempts.to_string()
                    };
                    std::thread::spawn(move || {
                        let runtime = match tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()
                        {
                            Ok(runtime) => runtime,
                            Err(error) => {
                                error!(error = %error, "Failed to build background runtime for ME initialization");
                                return;
                            }
                        };
                        runtime.block_on(async move {
                            let mut init_attempt: u32 = 0;
                            loop {
                                init_attempt = init_attempt.saturating_add(1);
                                startup_tracker_bg.set_me_init_attempt(init_attempt).await;
                                match pool_bg.init(pool_size, &rng_bg).await {
                                    Ok(()) => {
                                        startup_tracker_bg.set_me_last_error(None).await;
                                        startup_tracker_bg
                                            .complete_component(
                                                COMPONENT_ME_POOL_INIT_STAGE1,
                                                Some("ME pool initialized".to_string()),
                                            )
                                            .await;
                                        startup_tracker_bg
                                            .set_me_status(StartupMeStatus::Ready, "ready")
                                            .await;
                                        me_ready_tx_bg.send_modify(|version| {
                                            *version = version.saturating_add(1);
                                        });
                                        info!(
                                            attempt = init_attempt,
                                            "Middle-End pool initialized successfully"
                                        );

                                            // ── Supervised background tasks ──────────────────
                                            // Each task runs inside a nested tokio::spawn so
                                            // that a panic is caught via JoinHandle and the
                                            // outer loop restarts the task automatically.
                                            let pool_health = pool_bg.clone();
                                            let rng_health = rng_bg.clone();
                                            let min_conns = pool_size;
                                            tokio::spawn(async move {
                                                loop {
                                                    let p = pool_health.clone();
                                                    let r = rng_health.clone();
                                                    let res = tokio::spawn(async move {
                                                        crate::transport::middle_proxy::me_health_monitor(
                                                            p, r, min_conns,
                                                        )
                                                        .await;
                                                    })
                                                    .await;
                                                    match res {
                                                        Ok(()) => warn!("me_health_monitor exited unexpectedly, restarting"),
                                                        Err(e) => {
                                                            error!(error = %e, "me_health_monitor panicked, restarting in 1s");
                                                            tokio::time::sleep(Duration::from_secs(1)).await;
                                                        }
                                                    }
                                                }
                                            });
                                            let pool_drain_enforcer = pool_bg.clone();
                                            tokio::spawn(async move {
                                                loop {
                                                    let p = pool_drain_enforcer.clone();
                                                    let res = tokio::spawn(async move {
                                                        crate::transport::middle_proxy::me_drain_timeout_enforcer(p).await;
                                                    })
                                                    .await;
                                                    match res {
                                                        Ok(()) => warn!("me_drain_timeout_enforcer exited unexpectedly, restarting"),
                                                        Err(e) => {
                                                            error!(error = %e, "me_drain_timeout_enforcer panicked, restarting in 1s");
                                                            tokio::time::sleep(Duration::from_secs(1)).await;
                                                        }
                                                    }
                                                }
                                            });
                                            let pool_watchdog = pool_bg.clone();
                                            tokio::spawn(async move {
                                                loop {
                                                    let p = pool_watchdog.clone();
                                                    let res = tokio::spawn(async move {
                                                        crate::transport::middle_proxy::me_zombie_writer_watchdog(p).await;
                                                    })
                                                    .await;
                                                    match res {
                                                        Ok(()) => warn!("me_zombie_writer_watchdog exited unexpectedly, restarting"),
                                                        Err(e) => {
                                                            error!(error = %e, "me_zombie_writer_watchdog panicked, restarting in 1s");
                                                            tokio::time::sleep(Duration::from_secs(1)).await;
                                                        }
                                                    }
                                                }
                                            });
                                            // CRITICAL: keep the current-thread runtime
                                            // alive. Without this, block_on() returns,
                                            // the Runtime is dropped, and ALL spawned
                                            // background tasks (health monitor, drain
                                            // enforcer, zombie watchdog) are silently
                                            // cancelled — causing the draining-writer
                                            // leak that brought us here.
                                            std::future::pending::<()>().await;
                                            unreachable!();
                                    }
                                    Err(e) => {
                                        startup_tracker_bg.set_me_last_error(Some(e.to_string())).await;
                                        if init_attempt >= me_init_warn_after_attempts {
                                            warn!(
                                                error = %e,
                                                attempt = init_attempt,
                                                retry_limit = %retry_limit,
                                                retry_in_secs = 2,
                                                "ME pool is not ready yet; retrying background initialization"
                                            );
                                        } else {
                                            info!(
                                                error = %e,
                                                attempt = init_attempt,
                                                retry_limit = %retry_limit,
                                                retry_in_secs = 2,
                                                "ME pool startup warmup: retrying background initialization"
                                            );
                                        }
                                        pool_bg.reset_stun_state();
                                        tokio::time::sleep(Duration::from_secs(2)).await;
                                    }
                                }
                            }
                        });
                    });
                    startup_tracker
                        .set_me_status(StartupMeStatus::Initializing, "background_init")
                        .await;
                    info!(
                        startup_grace_secs = 80,
                        "ME pool initialization continues in background; startup continues with conditional Direct fallback"
                    );
                    Some(mux)
                } else {
                    let mut init_attempt: u32 = 0;
                    loop {
                        init_attempt = init_attempt.saturating_add(1);
                        startup_tracker.set_me_init_attempt(init_attempt).await;
                        match pool.init(pool_size, &rng).await {
                            Ok(()) => {
                                startup_tracker.set_me_last_error(None).await;
                                startup_tracker
                                    .complete_component(
                                        COMPONENT_ME_POOL_INIT_STAGE1,
                                        Some("ME pool initialized".to_string()),
                                    )
                                    .await;
                                startup_tracker
                                    .set_me_status(StartupMeStatus::Ready, "ready")
                                    .await;
                                me_ready_tx.send_modify(|version| {
                                    *version = version.saturating_add(1);
                                });
                                info!(
                                    attempt = init_attempt,
                                    "Middle-End pool initialized successfully"
                                );

                                // ── Supervised background tasks ──────────────────
                                let pool_clone = pool.clone();
                                let rng_clone = rng.clone();
                                let min_conns = pool_size;
                                tokio::spawn(async move {
                                    loop {
                                        let p = pool_clone.clone();
                                        let r = rng_clone.clone();
                                        let res = tokio::spawn(async move {
                                            crate::transport::middle_proxy::me_health_monitor(
                                                p, r, min_conns,
                                            )
                                            .await;
                                        })
                                        .await;
                                        match res {
                                            Ok(()) => warn!(
                                                "me_health_monitor exited unexpectedly, restarting"
                                            ),
                                            Err(e) => {
                                                error!(error = %e, "me_health_monitor panicked, restarting in 1s");
                                                tokio::time::sleep(Duration::from_secs(1)).await;
                                            }
                                        }
                                    }
                                });
                                let pool_drain_enforcer = pool.clone();
                                tokio::spawn(async move {
                                    loop {
                                        let p = pool_drain_enforcer.clone();
                                        let res = tokio::spawn(async move {
                                                crate::transport::middle_proxy::me_drain_timeout_enforcer(p).await;
                                            })
                                            .await;
                                        match res {
                                            Ok(()) => warn!(
                                                "me_drain_timeout_enforcer exited unexpectedly, restarting"
                                            ),
                                            Err(e) => {
                                                error!(error = %e, "me_drain_timeout_enforcer panicked, restarting in 1s");
                                                tokio::time::sleep(Duration::from_secs(1)).await;
                                            }
                                        }
                                    }
                                });
                                let pool_watchdog = pool.clone();
                                tokio::spawn(async move {
                                    loop {
                                        let p = pool_watchdog.clone();
                                        let res = tokio::spawn(async move {
                                                crate::transport::middle_proxy::me_zombie_writer_watchdog(p).await;
                                            })
                                            .await;
                                        match res {
                                            Ok(()) => warn!(
                                                "me_zombie_writer_watchdog exited unexpectedly, restarting"
                                            ),
                                            Err(e) => {
                                                error!(error = %e, "me_zombie_writer_watchdog panicked, restarting in 1s");
                                                tokio::time::sleep(Duration::from_secs(1)).await;
                                            }
                                        }
                                    }
                                });

                                break Some(mux);
                            }
                            Err(e) => {
                                startup_tracker.set_me_last_error(Some(e.to_string())).await;
                                let retries_limited = me_init_retry_attempts > 0;
                                if retries_limited && init_attempt >= me_init_retry_attempts {
                                    startup_tracker
                                        .fail_component(
                                            COMPONENT_ME_POOL_INIT_STAGE1,
                                            Some("ME init retry budget exhausted".to_string()),
                                        )
                                        .await;
                                    startup_tracker
                                        .set_me_status(StartupMeStatus::Failed, "failed")
                                        .await;
                                    error!(
                                        error = %e,
                                        attempt = init_attempt,
                                        retry_limit = me_init_retry_attempts,
                                        "ME pool init retries exhausted; startup cannot continue in middle-proxy mode"
                                    );
                                    break None;
                                }

                                let retry_limit = if me_init_retry_attempts == 0 {
                                    String::from("unlimited")
                                } else {
                                    me_init_retry_attempts.to_string()
                                };
                                if init_attempt >= me_init_warn_after_attempts {
                                    warn!(
                                        error = %e,
                                        attempt = init_attempt,
                                        retry_limit = retry_limit,
                                        me2dc_fallback = me2dc_fallback,
                                        retry_in_secs = 2,
                                        "ME pool is not ready yet; retrying startup initialization"
                                    );
                                } else {
                                    info!(
                                        error = %e,
                                        attempt = init_attempt,
                                        retry_limit = retry_limit,
                                        me2dc_fallback = me2dc_fallback,
                                        retry_in_secs = 2,
                                        "ME pool startup warmup: retrying initialization"
                                    );
                                }
                                pool.reset_stun_state();
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                        }
                    }
                }
            } else {
                startup_tracker
                    .skip_component(
                        COMPONENT_ME_POOL_CONSTRUCT,
                        Some("ME configs are incomplete".to_string()),
                    )
                    .await;
                startup_tracker
                    .fail_component(
                        COMPONENT_ME_POOL_INIT_STAGE1,
                        Some("ME configs are incomplete".to_string()),
                    )
                    .await;
                startup_tracker
                    .set_me_status(StartupMeStatus::Failed, "failed")
                    .await;
                None
            }
        }
        None => {
            startup_tracker
                .fail_component(
                    COMPONENT_ME_SECRET_FETCH,
                    Some("proxy-secret unavailable".to_string()),
                )
                .await;
            startup_tracker
                .skip_component(
                    COMPONENT_ME_PROXY_CONFIG_V4,
                    Some("proxy-secret unavailable".to_string()),
                )
                .await;
            startup_tracker
                .skip_component(
                    COMPONENT_ME_PROXY_CONFIG_V6,
                    Some("proxy-secret unavailable".to_string()),
                )
                .await;
            startup_tracker
                .skip_component(
                    COMPONENT_ME_POOL_CONSTRUCT,
                    Some("proxy-secret unavailable".to_string()),
                )
                .await;
            startup_tracker
                .fail_component(
                    COMPONENT_ME_POOL_INIT_STAGE1,
                    Some("proxy-secret unavailable".to_string()),
                )
                .await;
            startup_tracker
                .set_me_status(StartupMeStatus::Failed, "failed")
                .await;
            None
        }
    }
}

/// Derive the per-shard `bind_addresses` overrides from operator config.
///
/// Returns one entry per shard. A 1-element `[None]` vec represents the
/// legacy single-pool deployment (or fallback when shard mode was
/// requested but operator did not configure enough bind addresses).
/// Otherwise returns N×`Some(IpAddr)`, one per parsed bind entry.
///
/// Validation happens here so the rest of the startup path can assume
/// `shard_overrides.len() >= 1` is always satisfied.
fn compute_shard_overrides(config: &ProxyConfig) -> Vec<Option<IpAddr>> {
    compute_shard_overrides_inner(config.general.me_writer_bind_mode, &config.upstreams)
}

/// Pure inner — no `&ProxyConfig` so unit tests can drive it without
/// constructing a full ProxyConfig (heavy and unrelated to the policy).
fn compute_shard_overrides_inner(
    mode: MeWriterBindMode,
    upstreams: &[crate::config::UpstreamConfig],
) -> Vec<Option<IpAddr>> {
    if mode != MeWriterBindMode::Shard {
        return vec![None];
    }
    // bind_addresses lives on the Direct variant of UpstreamType. SOCKS
    // upstreams are out of scope for sharding — they bind through their
    // proxy, so they don't expose a source-IP we can pin per-shard.
    let bind_addrs: Vec<IpAddr> = upstreams
        .iter()
        .filter_map(|u| match &u.upstream_type {
            crate::config::UpstreamType::Direct { bind_addresses, .. } => bind_addresses.as_ref(),
            _ => None,
        })
        .flat_map(|v| v.iter().filter_map(|s| s.parse::<IpAddr>().ok()))
        .collect();
    if bind_addrs.len() < 2 {
        warn!(
            bind_addresses_count = bind_addrs.len(),
            "me_writer_bind_mode=shard requires ≥2 bind_addresses; falling back to single pool"
        );
        return vec![None];
    }
    info!(
        shards = bind_addrs.len(),
        "Activating MePoolMux per-source-IP sharding"
    );
    bind_addrs.into_iter().map(Some).collect()
}

#[cfg(test)]
mod tests {
    //! Tests for the shard activation policy. These are pure-function
    //! tests over `compute_shard_overrides_inner`; constructing real
    //! `MePool` shards is exercised by integration tests in
    //! `tests/middle_proxy_*` once they're added.
    use super::*;
    use crate::config::{UpstreamConfig, UpstreamType};

    fn mk_direct(bind_addresses: Option<Vec<&str>>) -> UpstreamConfig {
        UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: bind_addresses.map(|v| v.into_iter().map(String::from).collect()),
                bindtodevice: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
            ipv4: None,
            ipv6: None,
        }
    }

    #[test]
    fn round_robin_mode_yields_single_none_regardless_of_bind_count() {
        // Default mode: always one shard, override is None so connect
        // chain uses normal bind_addresses round-robin.
        let upstreams = vec![mk_direct(Some(vec!["198.51.100.10", "198.51.100.11"]))];
        let out = compute_shard_overrides_inner(MeWriterBindMode::RoundRobin, &upstreams);
        assert_eq!(out, vec![None]);
    }

    #[test]
    fn shard_mode_with_zero_bind_addresses_falls_back_to_single() {
        // Operator opted into shard mode but didn't configure bind_addrs:
        // we must NOT panic and must NOT spawn zero shards — fall back to
        // single-pool behaviour so the proxy still runs.
        let upstreams = vec![mk_direct(None)];
        let out = compute_shard_overrides_inner(MeWriterBindMode::Shard, &upstreams);
        assert_eq!(out, vec![None]);
    }

    #[test]
    fn shard_mode_with_one_bind_address_falls_back_to_single() {
        // 1 bind address provides nothing over the round-robin path —
        // multiplier=1 already gives one writer per source IP. Sharding
        // overhead (N pools, N supervisors) only earns its keep at N>=2.
        let upstreams = vec![mk_direct(Some(vec!["198.51.100.10"]))];
        let out = compute_shard_overrides_inner(MeWriterBindMode::Shard, &upstreams);
        assert_eq!(out, vec![None]);
    }

    #[test]
    fn shard_mode_with_two_or_more_yields_one_some_per_address() {
        // Happy path: each bind address becomes a separate shard's
        // override. Ordering preserves config order so operators can
        // predict which shard hosts which source IP for debugging.
        let upstreams = vec![mk_direct(Some(vec![
            "198.51.100.10",
            "198.51.100.11",
            "198.51.100.12",
        ]))];
        let out = compute_shard_overrides_inner(MeWriterBindMode::Shard, &upstreams);
        assert_eq!(
            out,
            vec![
                Some("198.51.100.10".parse::<IpAddr>().unwrap()),
                Some("198.51.100.11".parse::<IpAddr>().unwrap()),
                Some("198.51.100.12".parse::<IpAddr>().unwrap()),
            ]
        );
    }

    #[test]
    fn shard_mode_unparseable_addresses_are_silently_dropped() {
        // Malformed entries shouldn't crash startup; they get skipped
        // and we operate on whatever parsed correctly. If the remaining
        // count drops below 2, we fall back to single shard.
        let upstreams = vec![mk_direct(Some(vec![
            "not-an-ip",
            "198.51.100.10",
            "also.not.ip",
            "198.51.100.11",
        ]))];
        let out = compute_shard_overrides_inner(MeWriterBindMode::Shard, &upstreams);
        assert_eq!(
            out,
            vec![
                Some("198.51.100.10".parse::<IpAddr>().unwrap()),
                Some("198.51.100.11".parse::<IpAddr>().unwrap()),
            ]
        );
    }

    #[test]
    fn shard_mode_socks_upstreams_contribute_no_shards() {
        // SOCKS upstreams have no source-IP to pin (they bind via the
        // SOCKS server's interface). Mixing SOCKS + Direct: only Direct
        // entries' bind_addresses count toward shard count.
        let upstreams = vec![
            UpstreamConfig {
                upstream_type: UpstreamType::Socks5 {
                    address: "127.0.0.1:1080".to_string(),
                    interface: None,
                    username: None,
                    password: None,
                },
                weight: 1,
                enabled: true,
                scopes: String::new(),
                selected_scope: String::new(),
                ipv4: None,
                ipv6: None,
            },
            mk_direct(Some(vec!["198.51.100.10", "198.51.100.11"])),
        ];
        let out = compute_shard_overrides_inner(MeWriterBindMode::Shard, &upstreams);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], Some("198.51.100.10".parse::<IpAddr>().unwrap()));
        assert_eq!(out[1], Some("198.51.100.11".parse::<IpAddr>().unwrap()));
    }
}

/// Run the per-shard init retry loop + spawn the supervised background
/// tasks (health monitor / drain timeout enforcer / zombie watchdog).
///
/// Unlike the primary shard's inline init code in `initialize_me_pool`,
/// this helper does NOT touch `StartupTracker` — that surface tracks
/// startup of the proxy as a whole, which is gated only on shard 0. The
/// additional shards init in their own background runtimes so that their
/// (potentially slower) MTProto handshakes don't block primary readiness.
fn spawn_shard_supervisor(
    pool: Arc<MePool>,
    shard_idx: usize,
    rng: Arc<SecureRandom>,
    pool_size: usize,
    me_ready_tx: watch::Sender<u64>,
) {
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(error) => {
                error!(
                    error = %error,
                    shard_idx = shard_idx,
                    "Failed to build background runtime for shard init"
                );
                return;
            }
        };
        runtime.block_on(async move {
            let mut init_attempt: u32 = 0;
            loop {
                init_attempt = init_attempt.saturating_add(1);
                match pool.init(pool_size, &rng).await {
                    Ok(()) => {
                        info!(
                            shard_idx,
                            attempt = init_attempt,
                            "Additional MePool shard initialised successfully"
                        );
                        // Per-shard readiness gate: flip the runtime-ready
                        // flag only AFTER init() seeds writers, so the api
                        // surface (`/v1/gates`, admission, stats) reports
                        // truthful per-shard state instead of a global lie.
                        // Connectivity.rs no longer flips this for
                        // supplementary shards — the gate now flows from
                        // each shard's own init lifecycle.
                        pool.set_runtime_ready(true);
                        // Bump readiness watch so any /v1/* probe sees the
                        // additional shard as alive. Primary shard owns the
                        // initial readiness signal; this is supplementary.
                        me_ready_tx.send_modify(|v| *v = v.saturating_add(1));

                        // Supervised background tasks — one set per shard.
                        // Each task restarts on panic via nested tokio::spawn
                        // and JoinHandle inspection, matching the primary
                        // shard's supervisor pattern.
                        let health = pool.clone();
                        let rng_h = rng.clone();
                        let min_conns = pool_size;
                        tokio::spawn(async move {
                            loop {
                                let p = health.clone();
                                let r = rng_h.clone();
                                let res = tokio::spawn(async move {
                                    crate::transport::middle_proxy::me_health_monitor(
                                        p, r, min_conns,
                                    )
                                    .await;
                                })
                                .await;
                                match res {
                                    Ok(()) => warn!(
                                        shard_idx,
                                        "me_health_monitor exited unexpectedly, restarting"
                                    ),
                                    Err(e) => {
                                        error!(error = %e, shard_idx, "me_health_monitor panicked, restarting in 1s");
                                        tokio::time::sleep(Duration::from_secs(1)).await;
                                    }
                                }
                            }
                        });
                        let drain = pool.clone();
                        tokio::spawn(async move {
                            loop {
                                let p = drain.clone();
                                let res = tokio::spawn(async move {
                                    crate::transport::middle_proxy::me_drain_timeout_enforcer(p)
                                        .await;
                                })
                                .await;
                                match res {
                                    Ok(()) => warn!(
                                        shard_idx,
                                        "me_drain_timeout_enforcer exited unexpectedly, restarting"
                                    ),
                                    Err(e) => {
                                        error!(error = %e, shard_idx, "me_drain_timeout_enforcer panicked, restarting in 1s");
                                        tokio::time::sleep(Duration::from_secs(1)).await;
                                    }
                                }
                            }
                        });
                        let watchdog = pool.clone();
                        tokio::spawn(async move {
                            loop {
                                let p = watchdog.clone();
                                let res = tokio::spawn(async move {
                                    crate::transport::middle_proxy::me_zombie_writer_watchdog(p)
                                        .await;
                                })
                                .await;
                                match res {
                                    Ok(()) => warn!(
                                        shard_idx,
                                        "me_zombie_writer_watchdog exited unexpectedly, restarting"
                                    ),
                                    Err(e) => {
                                        error!(error = %e, shard_idx, "me_zombie_writer_watchdog panicked, restarting in 1s");
                                        tokio::time::sleep(Duration::from_secs(1)).await;
                                    }
                                }
                            }
                        });
                        // Keep this background runtime alive — see comment
                        // in primary init at me_startup.rs.
                        std::future::pending::<()>().await;
                        unreachable!();
                    }
                    Err(e) => {
                        // Match the primary background path: retry
                        // forever. Abandoning a shard would leave it in
                        // the mux as a phantom — `shard_for_peer` still
                        // routes ~1/N of clients to it but no writers
                        // exist, returning no_writer for the lifetime of
                        // the proxy. Retry-attempts is intentionally
                        // *not* honoured here for that reason; operators
                        // who want a fail-fast signal should use
                        // me2dc_fallback + the primary path's hard fail.
                        warn!(
                            shard_idx,
                            error = %e,
                            attempt = init_attempt,
                            retry_in_secs = 2,
                            "Shard MePool init failed, retrying"
                        );
                        pool.reset_stun_state();
                        tokio::time::sleep(Duration::from_secs(2)).await;
                    }
                }
            }
        });
    });
}
