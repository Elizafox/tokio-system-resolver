//! Throughput comparison between `tokio-system-resolver` and `hickory-resolver`.
//!
//! These resolvers are not interchangeable (see the caveats below) so this is
//! a comparison of *machinery overhead* on overlapping workloads, not a claim
//! that either is universally faster.
//!
//! Scenarios (all reproducible without external network by default):
//!
//! - `ip_literal` — resolve `127.0.0.1`. Both short-circuit numeric input
//!   (this crate via its inline fast path with `AI_NUMERICHOST`; hickory detects
//!   the IP literal and returns it without a query). Pure fast-path overhead.
//! - `localhost` — resolve `localhost` from the hosts file. This crate goes
//!   through NSS on a worker thread; hickory reads `/etc/hosts`
//!   (`ResolveHosts::Always`). No external network.
//!
//! Opt-in network scenario (set `TSR_BENCH_DOMAIN=example.com`):
//!
//! - `domain` — resolve the given name repeatedly. Both hit the configured
//!   nameserver on the first lookup; afterwards **hickory serves from its
//!   in-memory cache** while this crate re-invokes `getaddrinfo` every time
//!   (unless a system cache like `nscd`/`systemd-resolved` is in front of it).
//!   This exposes the cache asymmetry, the single biggest real-world difference.
//!
//! Caveats this benchmark cannot capture:
//!
//! - **Fidelity.** hickory speaks DNS directly and ignores `/etc/nsswitch.conf`,
//!   NSS plugins (SSSD/LDAP/mDNS), and split-horizon configuration. This crate
//!   behaves like every other program on the host. The `localhost` numbers only
//!   line up because hosts-file support is explicitly enabled for hickory.
//! - **Caching.** Left at hickory's default; that is the point of the `domain`
//!   scenario.
//!
//! Tunables (env): `TSR_BENCH_TOTAL`, `TSR_BENCH_WARMUP`, `TSR_BENCH_CONCURRENCY`
//! (comma-separated), `TSR_BENCH_DOMAIN`.
//!
//! This benchmark is gated behind the `bench-compare` feature so that
//! hickory-resolver's large dependency tree stays out of the default build:
//!
//! ```sh
//! cargo bench --features bench-compare --bench compare_hickory
//! ```

use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use hickory_resolver::config::ResolveHosts;
use tokio::runtime::Builder;
use tokio_system_resolver::{AddrInfoHints, AiFlags, ResolverConfig, SystemResolver};

#[derive(Clone)]
enum Scenario {
    IpLiteral,
    Localhost,
    Domain(String),
}

impl Scenario {
    fn host(&self) -> &str {
        match self {
            Self::IpLiteral => "127.0.0.1",
            Self::Localhost => "localhost",
            Self::Domain(domain) => domain,
        }
    }

    fn label(&self) -> String {
        match self {
            Self::IpLiteral => "ip_literal (127.0.0.1)".to_owned(),
            Self::Localhost => "localhost (hosts file)".to_owned(),
            Self::Domain(domain) => format!("domain ({domain}, network + hickory cache)"),
        }
    }
}

async fn ours_once(resolver: &SystemResolver, scenario: &Scenario) {
    match scenario {
        Scenario::IpLiteral => {
            // AI_NUMERICHOST takes this crate's inline fast path.
            let hints = AddrInfoHints {
                flags: AiFlags::NUMERICHOST,
                ..Default::default()
            };
            resolver
                .resolve_host("127.0.0.1", Some(hints))
                .await
                .unwrap();
        }
        Scenario::Localhost => {
            resolver.resolve_host("localhost", None).await.unwrap();
        }
        Scenario::Domain(domain) => {
            resolver.resolve_host(domain, None).await.unwrap();
        }
    }
}

async fn run_parallel<Run, Fut>(total: usize, concurrency: usize, run_once: Run) -> Duration
where
    Run: Fn() -> Fut + Send + Sync + Clone + 'static,
    Fut: Future<Output = ()> + Send,
{
    let workers = concurrency.min(total.max(1));
    let base = total / workers;
    let extra = total % workers;

    let start = Instant::now();
    let mut handles = Vec::with_capacity(workers);
    for worker in 0..workers {
        let run_once = run_once.clone();
        let iterations = base + usize::from(worker < extra);
        handles.push(tokio::spawn(async move {
            for _ in 0..iterations {
                run_once().await;
            }
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
    start.elapsed()
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_concurrency_list(name: &str, default: &[usize]) -> Vec<usize> {
    env::var(name).map_or_else(
        |_| default.to_vec(),
        |value| {
            let parsed: Vec<_> = value
                .split(',')
                .filter_map(|item| item.trim().parse::<usize>().ok())
                .filter(|value| *value > 0)
                .collect();
            if parsed.is_empty() {
                default.to_vec()
            } else {
                parsed
            }
        },
    )
}

#[allow(
    clippy::cast_precision_loss,
    reason = "iteration counts stay well within f64 precision"
)]
fn per_sec(total: usize, elapsed: Duration) -> f64 {
    total as f64 / elapsed.as_secs_f64()
}

fn main() {
    let total = env_usize("TSR_BENCH_TOTAL", 2_000);
    let warmup = env_usize("TSR_BENCH_WARMUP", 200);
    let concurrency = env_concurrency_list("TSR_BENCH_CONCURRENCY", &[1, 8, 32]);

    let mut scenarios = vec![Scenario::IpLiteral, Scenario::Localhost];
    if let Ok(domain) = env::var("TSR_BENCH_DOMAIN") {
        if !domain.trim().is_empty() {
            scenarios.push(Scenario::Domain(domain.trim().to_owned()));
        }
    }

    let worker_threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .min(concurrency.iter().copied().max().unwrap_or(1).max(1))
        .max(1);

    let runtime = Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap();

    println!("tokio-system-resolver vs hickory-resolver");
    println!("timing: total_iterations={total}, warmup_iterations={warmup}");
    println!("concurrency: {concurrency:?}");
    println!();

    runtime.block_on(async move {
        let ours = Arc::new(SystemResolver::new(ResolverConfig::default()));

        // Build hickory from the system configuration (nameservers, etc.) but
        // force hosts-file lookups so `localhost` resolves locally for a fair,
        // network-free comparison.
        let hickory = {
            let mut builder = TokioResolver::builder_tokio()
                .expect("build hickory resolver from system configuration");
            builder.options_mut().use_hosts_file = ResolveHosts::Always;
            Arc::new(builder.build())
        };

        for scenario in &scenarios {
            println!("{}", scenario.label());

            for &concurrent in &concurrency {
                // Warmup (also primes hickory's cache for the domain scenario).
                if warmup > 0 {
                    let r = Arc::clone(&ours);
                    let s = scenario.clone();
                    run_parallel(warmup, concurrent, move || {
                        let r = Arc::clone(&r);
                        let s = s.clone();
                        async move { ours_once(&r, &s).await }
                    })
                    .await;

                    let h = Arc::clone(&hickory);
                    let host = scenario.host().to_owned();
                    run_parallel(warmup, concurrent, move || {
                        let h = Arc::clone(&h);
                        let host = host.clone();
                        async move {
                            h.lookup_ip(host).await.unwrap();
                        }
                    })
                    .await;
                }

                let ours_elapsed = {
                    let r = Arc::clone(&ours);
                    let s = scenario.clone();
                    run_parallel(total, concurrent, move || {
                        let r = Arc::clone(&r);
                        let s = s.clone();
                        async move { ours_once(&r, &s).await }
                    })
                    .await
                };

                let hickory_elapsed = {
                    let h = Arc::clone(&hickory);
                    let host = scenario.host().to_owned();
                    run_parallel(total, concurrent, move || {
                        let h = Arc::clone(&h);
                        let host = host.clone();
                        async move {
                            h.lookup_ip(host).await.unwrap();
                        }
                    })
                    .await
                };

                let ours_ops = per_sec(total, ours_elapsed);
                let hickory_ops = per_sec(total, hickory_elapsed);
                let (leader, ratio) = if ours_ops >= hickory_ops {
                    ("ours", ours_ops / hickory_ops)
                } else {
                    ("hickory", hickory_ops / ours_ops)
                };

                println!(
                    "  concurrency={concurrent:<3} ours={ours_ops:>10.0} ops/s   \
                     hickory={hickory_ops:>10.0} ops/s   ({leader} {ratio:.1}x)",
                );
            }
            println!();
        }
    });
}
