use std::env;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::runtime::Builder;
use tokio_system_resolver::{
    AddrInfoHints, AddressFamily, NiFlags, ResolverConfig, SystemResolver,
};

#[derive(Clone, Copy)]
enum Workload {
    ResolveHostLocalhost,
    ResolveHostLocalhostIpv4,
    ResolveAddrLocalhostV4,
    ResolveAddrNumericV4,
    ResolveAddrNumericV6,
}

impl Workload {
    const ALL: [Self; 5] = [
        Self::ResolveHostLocalhost,
        Self::ResolveHostLocalhostIpv4,
        Self::ResolveAddrLocalhostV4,
        Self::ResolveAddrNumericV4,
        Self::ResolveAddrNumericV6,
    ];

    const fn name(self) -> &'static str {
        match self {
            Self::ResolveHostLocalhost => "resolve_host(localhost)",
            Self::ResolveHostLocalhostIpv4 => "resolve_host(localhost, ipv4)",
            Self::ResolveAddrLocalhostV4 => "resolve_addr(127.0.0.1:0, reverse)",
            Self::ResolveAddrNumericV4 => "resolve_addr(127.0.0.1:80, numeric)",
            Self::ResolveAddrNumericV6 => "resolve_addr([::1]:443, numeric)",
        }
    }

    async fn run_once(self, resolver: &SystemResolver) {
        match self {
            Self::ResolveHostLocalhost => {
                resolver.resolve_host("localhost", None).await.unwrap();
            }
            Self::ResolveHostLocalhostIpv4 => {
                let hints = AddrInfoHints {
                    family: AddressFamily::Inet,
                    ..Default::default()
                };
                resolver
                    .resolve_host("localhost", Some(hints))
                    .await
                    .unwrap();
            }
            Self::ResolveAddrLocalhostV4 => {
                let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
                resolver.resolve_addr(addr, NiFlags::NONE).await.unwrap();
            }
            Self::ResolveAddrNumericV4 => {
                let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80));
                let flags = NiFlags::NUMERICHOST | NiFlags::NUMERICSERV;
                resolver.resolve_addr(addr, flags).await.unwrap();
            }
            Self::ResolveAddrNumericV6 => {
                let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0));
                let flags = NiFlags::NUMERICHOST | NiFlags::NUMERICSERV;
                resolver.resolve_addr(addr, flags).await.unwrap();
            }
        }
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_duration_ms(name: &str, default_ms: u64) -> Duration {
    Duration::from_millis(
        env::var(name)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(default_ms),
    )
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

async fn run_parallel(
    resolver: Arc<SystemResolver>,
    workload: Workload,
    total: usize,
    concurrency: usize,
) {
    let workers = concurrency.min(total.max(1));
    let base = total / workers;
    let extra = total % workers;

    let mut handles = Vec::with_capacity(workers);
    for worker in 0..workers {
        let resolver = Arc::clone(&resolver);
        let iterations = base + usize::from(worker < extra);
        handles.push(tokio::spawn(async move {
            for _ in 0..iterations {
                workload.run_once(&resolver).await;
            }
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

async fn time_workload(
    resolver: Arc<SystemResolver>,
    workload: Workload,
    warmup: usize,
    total: usize,
    concurrency: usize,
) -> Duration {
    if warmup > 0 {
        run_parallel(Arc::clone(&resolver), workload, warmup, concurrency).await;
    }

    let start = Instant::now();
    run_parallel(resolver, workload, total, concurrency).await;
    start.elapsed()
}

fn print_header(config: &ResolverConfig, totals: usize, warmup: usize, concurrency: &[usize]) {
    println!("tokio-system-resolver throughput benchmark");
    println!(
        "config: soft_limit={}, hard_limit={}, stall_threshold={:?}",
        config.soft_limit, config.hard_limit, config.stall_threshold
    );
    println!("timing: total_iterations={totals}, warmup_iterations={warmup}");
    println!("concurrency: {concurrency:?}");
    println!();
}

fn main() {
    let soft_limit = env_usize("TSR_BENCH_SOFT_LIMIT", 8);
    let hard_limit = env_usize("TSR_BENCH_HARD_LIMIT", 32);
    let total = env_usize("TSR_BENCH_TOTAL", 2_000);
    let warmup = env_usize("TSR_BENCH_WARMUP", 200);
    let concurrency = env_concurrency_list("TSR_BENCH_CONCURRENCY", &[1, 8, 32]);
    let stall_threshold = env_duration_ms("TSR_BENCH_STALL_MS", 500);

    let config = ResolverConfig {
        soft_limit,
        hard_limit,
        stall_threshold,
        timeout: None,
    };

    let worker_threads = std::thread::available_parallelism()
        .map_or(4, std::num::NonZero::get)
        .min(concurrency.iter().copied().max().unwrap_or(1).max(1))
        .max(1);

    let runtime = Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap();

    print_header(&config, total, warmup, &concurrency);

    runtime.block_on(async move {
        for workload in Workload::ALL {
            println!("{}", workload.name());
            for concurrent in &concurrency {
                let resolver = Arc::new(SystemResolver::new(config));
                let elapsed = time_workload(resolver, workload, warmup, total, *concurrent).await;
                #[allow(
                    clippy::cast_precision_loss,
                    reason = "Total should not exceed f64 width"
                )]
                let per_sec = total as f64 / elapsed.as_secs_f64();
                println!(
                    "  concurrency={concurrent:<3} elapsed={elapsed:>8.3?} throughput={per_sec:>10.0} ops/s",
                );
            }
            println!();
        }
    });
}
