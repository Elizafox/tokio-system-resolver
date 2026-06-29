# tokio-system-resolver

[![OS CI](https://github.com/Elizafox/tokio-system-resolver/actions/workflows/os-ci.yml/badge.svg)](https://github.com/Elizafox/tokio-system-resolver/actions/workflows/os-ci.yml)

Tokio-compatible async DNS resolver wrapping the system `getaddrinfo(3)` and
`getnameinfo(3)` calls.


## Rationale

Most async Rust resolvers (`hickory-dns`, `trust-dns`) implement DNS resolution
themselves in pure Rust. That means they speak DNS wire format directly and
bypass the host's resolver configuration entirely. If your application needs to
respect `/etc/hosts`, NSS plugins, mDNS, LLMNR, split-horizon DNS, or anything
else configured via `/etc/nsswitch.conf`, those resolvers will not see it.

This crate delegates to the C library's `getaddrinfo` and `getnameinfo`
instead, which means it behaves exactly like every other program on the host.
Because these calls can block, the crate offloads them to on-demand OS threads
and bridges the result back to a Tokio future. Lookups that are guaranteed not
to block — purely numeric conversions — skip the thread and run inline on the
calling task.

## Platform support

Unix only (`getaddrinfo` exists on Windows too, but the `libc` surface needed
here is not fully available there). Linux, macOS, the BSDs, and any other
POSIX-compliant system should work.


## Usage

```toml
[dependencies]
tokio-system-resolver = "0.5"
tokio = { version = "1", features = ["full"] }
```

### Forward lookup

```rust
use tokio_system_resolver::{SystemResolver, ResolverConfig};

let resolver = SystemResolver::new(ResolverConfig::default());

let addrs = resolver.resolve_host("example.com", None).await?;
for a in &addrs {
    println!("{}", a.addr);
}
```

### Host + service lookup

```rust
use tokio_system_resolver::{SystemResolver, ResolverConfig};

let resolver = SystemResolver::new(ResolverConfig::default());

let addrs = resolver.resolve_host_service("example.com", "443", None).await?;
for a in &addrs {
    println!("{}", a.addr); // port 443 included
}
```

### Passive / wildcard lookup

Resolve a service with no host — useful for obtaining addresses to `bind` to.
With `AiFlags::PASSIVE` you get wildcard addresses (`0.0.0.0` / `::`); without
it, loopback.

```rust
use tokio_system_resolver::{SystemResolver, ResolverConfig, AddrInfoHints, AiFlags};

let resolver = SystemResolver::new(ResolverConfig::default());

let hints = AddrInfoHints { flags: AiFlags::PASSIVE, ..Default::default() };
let addrs = resolver.resolve_passive("8080", Some(hints)).await?;
for a in &addrs {
    println!("{}", a.addr); // e.g. 0.0.0.0:8080
}
```

### Reverse lookup

```rust
use tokio_system_resolver::{SystemResolver, ResolverConfig, NiFlags};

let resolver = SystemResolver::new(ResolverConfig::default());

let addr = "93.184.216.34:0".parse()?;
let names = resolver.resolve_addr(addr, NiFlags::NONE).await?;
println!("{:?}", names.hostname); // Some("example.com")
```

`hostname` and `service` are lossy UTF-8. DNS, `/etc/hosts`, and NSS can return
names that are not valid UTF-8; the exact bytes are preserved in
`hostname_raw` / `service_raw` (and `AddrInfo::canonname_raw` for canonical
names).

### Narrowing results with hints

```rust
use tokio_system_resolver::{SystemResolver, ResolverConfig, AddrInfoHints, AddressFamily};

let resolver = SystemResolver::new(ResolverConfig::default());

let hints = AddrInfoHints {
    family: AddressFamily::Inet, // IPv4 only
    ..Default::default()
};
let addrs = resolver.resolve_host("example.com", Some(hints)).await?;
```

### `getnameinfo` flags

`NiFlags` constants mirror the `NI_*` flags from `<netdb.h>` and can be
combined with `|`:

```rust
use tokio_system_resolver::NiFlags;

// Return the numeric address string instead of doing a reverse-DNS lookup.
let flags = NiFlags::NUMERICHOST | NiFlags::NUMERICSERV;
```

## Concurrency model

Each resolution call that may block occupies one OS thread for the duration of
the system call (calls that cannot block run inline — see *Inline fast path*
below). Thread counts are governed by two limits:

| Limit | Default | Meaning |
|-------|---------|---------|
| `soft_limit` | 8 | Normal maximum concurrent threads. |
| `hard_limit` | 32 | Absolute ceiling, enforced by a semaphore. |
| `stall_threshold` | 500 ms | After this long, a thread is considered stalled. |
| `timeout` | `None` | Optional end-to-end wait limit for a lookup. |

**Stall handling.** `getaddrinfo` can block for a very long time (slow or
unreachable nameservers, broken NSS plugins, etc.). When a thread exceeds
`stall_threshold`, its soft-limit slot is released early so new queries can
still proceed. The stalled thread keeps running in the background and releases
its hard-limit permit when it eventually returns.

**Cancellation.** Dropping a resolution future is always safe. The OS thread
cannot be interrupted, but it will finish on its own and release its permit. The
soft-limit slot is freed immediately so waiting callers are not held up.

**Timeouts.** If `timeout` is set, the future returns an error when that
deadline expires. The timeout covers waiting for a soft slot, waiting for a
hard permit, and waiting for the system call result. Timing out does not stop
an already-started worker thread; it continues in the background and releases
its hard-limit permit when it exits.

**Backpressure.** When the hard limit is saturated, callers block on
`acquire_owned()` until a permit is available. There is no queue size cap; use
your own task semaphore upstream if you need one.

**Inline fast path.** Lookups that cannot perform name resolution are guaranteed
not to block, so they run inline on the calling task — no thread, no permit, and
not subject to `timeout`. This covers `resolve_addr` with
`NI_NUMERICHOST | NI_NUMERICSERV`, and `resolve_host` / `resolve_host_service` /
`resolve_passive` when the host is numeric (`AI_NUMERICHOST`) or absent and the
service is numeric (`AI_NUMERICSERV`) or absent, with `AI_ADDRCONFIG` unset.
These calls are bounded only by the executor, not by the limits above.

**Shutdown.** `resolver.shutdown()` stops the resolver from admitting new work:
calls waiting for capacity — and any started afterwards, including inline ones —
return `ResolveError::Cancelled`. Threads already running a system call finish
in the background and release their permits. `is_closed()` reports whether
shutdown has happened.


### Custom configuration

```rust
use std::time::Duration;
use tokio_system_resolver::{SystemResolver, ResolverConfig};

let resolver = SystemResolver::new(ResolverConfig {
    soft_limit: 4,
    hard_limit: 16,
    stall_threshold: Duration::from_millis(200),
    timeout: Some(Duration::from_secs(2)),
});
```

### Sharing across tasks

`SystemResolver` is `Send + Sync`. Wrap it in an `Arc` to share across tasks:

```rust
use std::sync::Arc;
use tokio_system_resolver::{SystemResolver, ResolverConfig};

let resolver = Arc::new(SystemResolver::new(ResolverConfig::default()));

for _ in 0..10 {
    let r = Arc::clone(&resolver);
    tokio::spawn(async move {
        let _ = r.resolve_host("example.com", None).await;
    });
}
```

## License

This is free and unencumbered software released into the public domain
(unlicense). See [LICENSE](LICENSE) or <https://unlicense.org> for details.
