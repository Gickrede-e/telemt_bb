//! telemt — Telegram MTProto Proxy

mod api;
mod cli;
mod config;
mod conntrack_control;
mod crypto;
#[cfg(unix)]
mod daemon;
mod error;
mod healthcheck;
mod ip_tracker;
#[cfg(test)]
#[path = "tests/ip_tracker_encapsulation_adversarial_tests.rs"]
mod ip_tracker_encapsulation_adversarial_tests;
#[cfg(test)]
#[path = "tests/ip_tracker_hotpath_adversarial_tests.rs"]
mod ip_tracker_hotpath_adversarial_tests;
#[cfg(test)]
#[path = "tests/ip_tracker_regression_tests.rs"]
mod ip_tracker_regression_tests;
mod logging;
mod maestro;
mod metrics;
mod network;
mod protocol;
mod proxy;
mod quota_state;
mod service;
mod startup;
mod stats;
mod stream;
mod tls_front;
mod transport;
mod util;

// Replace the system allocator with mimalloc for the entire process.
//
// Why: telemt's hot path allocates a small buffer (~64-256 B) per relayed
// packet across hundreds of thousands of writers. ptmalloc/dlmalloc serialize
// on per-arena locks under that pressure, which shows up as wasted CPU at
// high connection counts even though each individual alloc is tiny. mimalloc
// uses heap-per-thread + free-list sharding, eliminating the contention.
// Benchmark expectation: 10-20% throughput improvement at >50k concurrent
// connections; minor (~1%) regression at low load due to slightly larger
// per-thread state — net positive for production scale, neutral for dev.
//
// `default-features = false` drops mimalloc's secure mode (guard pages,
// double-free detection). We're not trusting allocator-level hardening for
// a network-facing service — defense in depth lives elsewhere (rustls,
// MTProto crypto, scope-limited unsafe). Speed > paranoia here.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn build_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.enable_all().thread_name("telemt-worker");

    // Allow tuning the worker pool and blocking pool without recompiling.
    // TELEMT_WORKER_THREADS / TELEMT_MAX_BLOCKING_THREADS override the defaults.
    if let Some(n) = std::env::var("TELEMT_WORKER_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
    {
        builder.worker_threads(n);
    }
    let max_blocking = std::env::var("TELEMT_MAX_BLOCKING_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(1024);
    builder.max_blocking_threads(max_blocking);

    // Reduce scheduler ping-pong on many-core hosts. These are advisory hints
    // for how often workers visit the global queue / I/O driver.
    builder.event_interval(31);
    builder.global_queue_interval(31);

    builder.build()
}

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    // Install rustls crypto provider early
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Initialise per-feature env-var-driven flags before runtime startup so
    // every connection observes a stable view of the config. Currently only
    // gates the reserved merged-tasks middle-relay path; see the static at
    // `proxy::middle_relay::MIDDLE_RELAY_MERGED_TASKS` for the deferral note.
    proxy::middle_relay::init_middle_relay_feature_flags();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = cli::parse_command(&args);

    // Handle subcommands that don't need the server (stop, reload, status, init)
    if let Some(exit_code) = cli::execute_subcommand(&cmd) {
        std::process::exit(exit_code);
    }

    #[cfg(unix)]
    {
        let daemon_opts = cmd.daemon_opts;

        // Daemonize BEFORE runtime
        if daemon_opts.should_daemonize() {
            match daemon::daemonize(daemon_opts.working_dir.as_deref()) {
                Ok(daemon::DaemonizeResult::Parent) => {
                    std::process::exit(0);
                }
                Ok(daemon::DaemonizeResult::Child) => {
                    // continue
                }
                Err(e) => {
                    eprintln!("[telemt] Daemonization failed: {}", e);
                    std::process::exit(1);
                }
            }
        }

        build_runtime()?.block_on(maestro::run_with_daemon(daemon_opts))
    }

    #[cfg(not(unix))]
    {
        build_runtime()?.block_on(maestro::run())
    }
}
