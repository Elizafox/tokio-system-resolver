//! The asynchronous resolver implementation.
//!
//! This module exposes [`SystemResolver`], the main entry point for performing
//! hostname and reverse-address lookups through the host libc's
//! `getaddrinfo(3)` and `getnameinfo(3)` functions.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::config::ResolverConfig;
use crate::error::ResolveError;
use crate::ffi;
use crate::types::{AddrInfo, AddrInfoHints, AiFlags, NiFlags, ResolvedNames};

/// Whether a `getnameinfo` request is guaranteed not to consult the network,
/// files, or NSS, and so can run inline on the calling task instead of on a
/// worker thread.
///
/// `NI_NUMERICHOST | NI_NUMERICSERV` makes the call pure string formatting of
/// the supplied address and port — no reverse DNS, no `/etc/services` lookup.
const fn getnameinfo_is_inline(flags: NiFlags) -> bool {
    flags.contains(NiFlags::NUMERICHOST) && flags.contains(NiFlags::NUMERICSERV)
}

/// Whether a `getaddrinfo` request is guaranteed not to consult the network,
/// files, or NSS, and so can run inline on the calling task.
///
/// This holds when the host cannot trigger a name lookup (it is absent, or
/// `AI_NUMERICHOST` forces a numeric-only parse), the service cannot trigger a
/// lookup (it is absent, or `AI_NUMERICSERV` forces a numeric-only parse), and
/// `AI_ADDRCONFIG` — which inspects the system's configured interfaces — is not
/// requested. POSIX guarantees `AI_NUMERICHOST`/`AI_NUMERICSERV` prevent any
/// name-resolution service from being invoked.
const fn getaddrinfo_is_inline(
    host: Option<&str>,
    service: Option<&str>,
    hints: Option<&AddrInfoHints>,
) -> bool {
    let Some(hints) = hints else {
        return false;
    };
    let host_ok = host.is_none() || hints.flags.contains(AiFlags::NUMERICHOST);
    let service_ok = service.is_none() || hints.flags.contains(AiFlags::NUMERICSERV);
    host_ok && service_ok && !hints.flags.contains(AiFlags::ADDRCONFIG)
}

/// Stack size for the worker threads that run the blocking system calls.
///
/// `getaddrinfo`/`getnameinfo` need far less than a thread's default stack
/// (~2 MiB on most platforms), so a smaller stack sharply cuts the memory
/// reserved when threads pile up under stalls (up to `hard_limit` of them at
/// once). The value keeps a comfortable margin above what NSS modules
/// (`/etc/nsswitch.conf` plugins such as mDNS, LDAP, or SSSD) are likely to use
/// on the stack — going much smaller risks a stack overflow inside third-party
/// resolver code, which would abort the process.
const WORKER_STACK_SIZE: usize = 512 * 1024;

/// Async resolver backed by the system `getaddrinfo` and `getnameinfo` calls.
///
/// A call that may block — anything that can reach DNS, NSS, or `/etc/*` — runs
/// on a dedicated OS thread and sends its result back through a oneshot channel.
/// A call that is guaranteed *not* to block runs inline on the calling task with
/// no thread and no permit (see "Inline fast path" below). Thread counts for the
/// blocking path are governed by the limits in [`ResolverConfig`]:
///
/// - At most [`soft_limit`](ResolverConfig::soft_limit) threads run
///   concurrently under normal conditions.
/// - When threads stall (exceed [`stall_threshold`](ResolverConfig::stall_threshold))
///   or their callers drop the future, the soft-limit slot is released early so
///   new queries can proceed. The stalled thread retains its hard-limit permit
///   and releases it when it exits.
/// - At most [`hard_limit`](ResolverConfig::hard_limit) threads run at any
///   time. Callers that arrive when this ceiling is reached await backpressure
///   until a permit becomes available.
///
/// # Inline fast path
///
/// Requests that cannot perform name resolution are guaranteed not to block, so
/// they run inline on the calling task — no worker thread, no soft/hard permit,
/// and not subject to [`ResolverConfig::timeout`]. This applies to:
///
/// - [`resolve_addr`](Self::resolve_addr) with `NI_NUMERICHOST | NI_NUMERICSERV`
///   (pure address/port formatting), and
/// - [`resolve_host`](Self::resolve_host) /
///   [`resolve_host_service`](Self::resolve_host_service) /
///   [`resolve_passive`](Self::resolve_passive) when the host is numeric
///   (`AI_NUMERICHOST`) or absent and the service is numeric (`AI_NUMERICSERV`)
///   or absent, and `AI_ADDRCONFIG` is not set.
///
/// Because these calls hold no permit, the concurrency limits do not apply to
/// them; they are bounded only by the executor. After [`shutdown`](Self::shutdown)
/// they still return [`ResolveError::Cancelled`].
///
/// `SystemResolver` is cheaply cloneable via [`Arc`] — wrap it in one to share
/// it across tasks.
pub struct SystemResolver {
    config: Arc<ResolverConfig>,
    soft_sem: Arc<Semaphore>,
    hard_sem: Arc<Semaphore>,
}

impl SystemResolver {
    /// Create a new resolver with the given configuration.
    ///
    /// `config.soft_limit` is clamped to `config.hard_limit`: the soft limit can
    /// never exceed the hard ceiling. In debug builds a configuration that
    /// violates this invariant also trips an assertion.
    ///
    /// # Panics (debug builds only)
    ///
    /// Panics if `config.hard_limit < config.soft_limit`.
    #[must_use]
    pub fn new(config: ResolverConfig) -> Self {
        debug_assert!(
            config.hard_limit >= config.soft_limit,
            "hard_limit must be >= soft_limit"
        );
        let soft_limit = config.soft_limit.min(config.hard_limit);
        Self {
            soft_sem: Arc::new(Semaphore::new(soft_limit)),
            hard_sem: Arc::new(Semaphore::new(config.hard_limit)),
            config: Arc::new(config),
        }
    }

    /// Shut the resolver down: stop admitting new work.
    ///
    /// Closes the soft- and hard-limit semaphores so that any call currently
    /// waiting for capacity — and any call started afterwards — returns
    /// [`ResolveError::Cancelled`]. Worker threads already running their system
    /// call cannot be interrupted; they run to completion in the background and
    /// release their permits when they exit. Idempotent.
    pub fn shutdown(&self) {
        self.soft_sem.close();
        self.hard_sem.close();
    }

    /// Returns `true` if the resolver has been [`shutdown`](Self::shutdown).
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.hard_sem.is_closed()
    }

    async fn acquire_permit(
        sem: &Arc<Semaphore>,
        deadline: Option<Instant>,
    ) -> Result<OwnedSemaphorePermit, ResolveError> {
        let acquire = Arc::clone(sem).acquire_owned();
        tokio::pin!(acquire);

        if let Some(deadline) = deadline {
            let timeout = tokio::time::sleep_until(deadline);
            tokio::pin!(timeout);
            tokio::select! {
                permit = &mut acquire => permit.map_err(|_| ResolveError::Cancelled),
                () = &mut timeout => Err(ResolveError::TimedOut),
            }
        } else {
            acquire.await.map_err(|_| ResolveError::Cancelled)
        }
    }

    async fn await_worker_result<T>(
        mut soft_permit: Option<OwnedSemaphorePermit>,
        stall_threshold: Duration,
        deadline: Option<Instant>,
        rx: &mut tokio::sync::oneshot::Receiver<Result<T, ResolveError>>,
    ) -> Result<T, ResolveError> {
        let stall = tokio::time::sleep(stall_threshold);
        tokio::pin!(stall);
        let mut stalled = false;

        loop {
            match (stalled, deadline) {
                (false, Some(deadline)) => {
                    let timeout = tokio::time::sleep_until(deadline);
                    tokio::pin!(timeout);
                    tokio::select! {
                        result = &mut *rx => {
                            drop(soft_permit.take());
                            return result.unwrap_or(Err(ResolveError::Cancelled));
                        }
                        () = &mut stall => {
                            drop(soft_permit.take());
                            stalled = true;
                        }
                        () = &mut timeout => {
                            drop(soft_permit.take());
                            return Err(ResolveError::TimedOut);
                        }
                    }
                }
                (false, None) => {
                    tokio::select! {
                        result = &mut *rx => {
                            drop(soft_permit.take());
                            return result.unwrap_or(Err(ResolveError::Cancelled));
                        }
                        () = &mut stall => {
                            drop(soft_permit.take());
                            stalled = true;
                        }
                    }
                }
                (true, Some(deadline)) => {
                    let timeout = tokio::time::sleep_until(deadline);
                    tokio::pin!(timeout);
                    tokio::select! {
                        result = &mut *rx => return result.unwrap_or(Err(ResolveError::Cancelled)),
                        () = &mut timeout => return Err(ResolveError::TimedOut),
                    }
                }
                (true, None) => {
                    return rx.await.unwrap_or(Err(ResolveError::Cancelled));
                }
            }
        }
    }

    async fn resolve_host_impl(
        &self,
        host: Option<&str>,
        service: Option<&str>,
        hints: Option<AddrInfoHints>,
    ) -> Result<Vec<AddrInfo>, ResolveError> {
        // Fast path: a guaranteed non-blocking lookup runs inline, with no
        // worker thread, no permit, and no timeout (it cannot stall).
        if getaddrinfo_is_inline(host, service, hints.as_ref()) {
            return if self.is_closed() {
                Err(ResolveError::Cancelled)
            } else {
                ffi::call_getaddrinfo(host, service, hints)
            };
        }

        let deadline = self.config.timeout.map(|timeout| Instant::now() + timeout);
        let soft_permit = Self::acquire_permit(&self.soft_sem, deadline).await?;

        let hard_permit = match Self::acquire_permit(&self.hard_sem, deadline).await {
            Ok(permit) => permit,
            Err(err) => {
                drop(soft_permit);
                return Err(err);
            }
        };

        let (tx, mut rx) = tokio::sync::oneshot::channel();
        let host = host.map(ToOwned::to_owned);
        let service = service.map(ToOwned::to_owned);
        let stall_threshold = self.config.stall_threshold;

        if let Err(err) = std::thread::Builder::new()
            .stack_size(WORKER_STACK_SIZE)
            .spawn(move || {
                let _ = tx.send(ffi::call_getaddrinfo(
                    host.as_deref(),
                    service.as_deref(),
                    hints,
                ));
                drop(hard_permit);
            })
        {
            // Spawning the worker failed (e.g. the process hit its thread
            // limit). The closure — and the hard permit it captured — was
            // dropped by the failed spawn; release the soft permit too.
            drop(soft_permit);
            return Err(ResolveError::Io(err));
        }

        Self::await_worker_result(Some(soft_permit), stall_threshold, deadline, &mut rx).await
    }

    /// Resolve a hostname to a list of socket addresses via `getaddrinfo`.
    ///
    /// `hints` narrows the query (address family, socket type, flags). Pass
    /// `None` to accept all results, equivalent to a null hints pointer.
    ///
    /// # Examples
    ///
    /// Basic lookup:
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), tokio_system_resolver::ResolveError> {
    /// use tokio_system_resolver::{SystemResolver, ResolverConfig};
    ///
    /// let resolver = SystemResolver::new(ResolverConfig::default());
    /// let addrs = resolver.resolve_host("localhost", None).await?;
    /// for a in &addrs {
    ///     println!("{}", a.addr);
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// Restrict to IPv4 using hints:
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), tokio_system_resolver::ResolveError> {
    /// use tokio_system_resolver::{SystemResolver, ResolverConfig, AddrInfoHints, AddressFamily};
    ///
    /// let resolver = SystemResolver::new(ResolverConfig::default());
    /// let hints = AddrInfoHints { family: AddressFamily::Inet, ..Default::default() };
    /// let addrs = resolver.resolve_host("localhost", Some(hints)).await?;
    /// # Ok(()) }
    /// ```
    ///
    /// # Cancellation
    ///
    /// Dropping this future before it resolves is safe. The underlying OS
    /// thread continues to completion (there is no way to interrupt
    /// `getaddrinfo`), and its hard-limit permit is released when the thread
    /// exits. The soft-limit slot is released immediately on drop so that
    /// waiting callers are not held up.
    ///
    /// If [`ResolverConfig::timeout`] is set and expires first, this method
    /// returns [`ResolveError::TimedOut`]. If the worker thread has already
    /// started, it continues running in the background and releases its
    /// hard-limit permit when it exits.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError::Gai`] if `getaddrinfo` fails, [`ResolveError::Io`]
    /// if the hostname contains an interior NUL byte or the worker thread could
    /// not be spawned, [`ResolveError::TimedOut`] if the configured timeout
    /// expires while waiting for capacity or the system call result, or
    /// [`ResolveError::Cancelled`] if the resolver is [`shutdown`](Self::shutdown)
    /// while this call is waiting for capacity.
    pub async fn resolve_host(
        &self,
        host: &str,
        hints: Option<AddrInfoHints>,
    ) -> Result<Vec<AddrInfo>, ResolveError> {
        self.resolve_host_impl(Some(host), None, hints).await
    }

    /// Resolve a hostname and service to a list of socket addresses via
    /// `getaddrinfo`.
    ///
    /// This is like [`resolve_host`](Self::resolve_host), but passes a service
    /// name or numeric port string to `getaddrinfo` so the returned
    /// [`SocketAddr`] values have the corresponding port populated.
    ///
    /// Pass values like `"http"` or `"443"` for `service`.
    ///
    /// # Cancellation
    ///
    /// Same semantics as [`resolve_host`](Self::resolve_host): dropping this
    /// future is safe, and timing out does not stop an already-started worker
    /// thread.
    ///
    /// # Errors
    ///
    /// Returns the same error variants as [`resolve_host`](Self::resolve_host).
    pub async fn resolve_host_service(
        &self,
        host: &str,
        service: &str,
        hints: Option<AddrInfoHints>,
    ) -> Result<Vec<AddrInfo>, ResolveError> {
        self.resolve_host_impl(Some(host), Some(service), hints)
            .await
    }

    /// Resolve a service with no host (a NULL `getaddrinfo` node), yielding
    /// addresses suitable for local use.
    ///
    /// With [`AiFlags::PASSIVE`](crate::AiFlags::PASSIVE) set in `hints`, the
    /// results are wildcard addresses (`0.0.0.0` / `::`) intended for
    /// [`bind(2)`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html).
    /// Without it, the results are loopback addresses (`127.0.0.1` / `::1`)
    /// intended for connecting to a local service. This mirrors `getaddrinfo`
    /// called with a null node pointer.
    ///
    /// `service` is required (a service name like `"http"` or a numeric port
    /// like `"443"`), since a `getaddrinfo` call with neither node nor service
    /// is invalid.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), tokio_system_resolver::ResolveError> {
    /// use tokio_system_resolver::{SystemResolver, ResolverConfig, AddrInfoHints, AiFlags};
    ///
    /// let resolver = SystemResolver::new(ResolverConfig::default());
    /// let hints = AddrInfoHints { flags: AiFlags::PASSIVE, ..Default::default() };
    /// let addrs = resolver.resolve_passive("8080", Some(hints)).await?;
    /// for a in &addrs {
    ///     println!("{}", a.addr); // wildcard, e.g. 0.0.0.0:8080
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// # Cancellation
    ///
    /// Same semantics as [`resolve_host`](Self::resolve_host).
    ///
    /// # Errors
    ///
    /// Returns the same error variants as [`resolve_host`](Self::resolve_host).
    pub async fn resolve_passive(
        &self,
        service: &str,
        hints: Option<AddrInfoHints>,
    ) -> Result<Vec<AddrInfo>, ResolveError> {
        self.resolve_host_impl(None, Some(service), hints).await
    }

    /// Resolve a socket address to a hostname and service name via `getnameinfo`.
    ///
    /// `flags` controls the lookup behaviour (e.g. [`NiFlags::NUMERICHOST`] to
    /// skip reverse-DNS and return the numeric address string).
    ///
    /// # Examples
    ///
    /// Numeric address and port (no DNS lookup):
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), tokio_system_resolver::ResolveError> {
    /// use tokio_system_resolver::{SystemResolver, ResolverConfig, NiFlags};
    ///
    /// let resolver = SystemResolver::new(ResolverConfig::default());
    /// let addr = "127.0.0.1:80".parse().unwrap();
    /// let names = resolver
    ///     .resolve_addr(addr, NiFlags::NUMERICHOST | NiFlags::NUMERICSERV)
    ///     .await?;
    /// assert_eq!(names.hostname.as_deref(), Some("127.0.0.1"));
    /// assert_eq!(names.service.as_deref(), Some("80"));
    /// # Ok(()) }
    /// ```
    ///
    /// Reverse-DNS lookup (may fail or return `None` for addresses without PTR records):
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), tokio_system_resolver::ResolveError> {
    /// use tokio_system_resolver::{SystemResolver, ResolverConfig, NiFlags};
    ///
    /// let resolver = SystemResolver::new(ResolverConfig::default());
    /// let addr = "93.184.216.34:0".parse().unwrap();
    /// let names = resolver.resolve_addr(addr, NiFlags::NONE).await?;
    /// println!("{:?}", names.hostname); // Some("example.com") or None
    /// # Ok(()) }
    /// ```
    ///
    /// # Cancellation
    ///
    /// Same semantics as [`resolve_host`](Self::resolve_host): dropping the
    /// future is safe; the thread runs to completion in the background.
    /// If [`ResolverConfig::timeout`] is set and expires first, this method
    /// returns [`ResolveError::TimedOut`]. If the worker thread has already
    /// started, it continues running in the background and releases its
    /// hard-limit permit when it exits.
    ///
    /// # Errors
    ///
    /// Returns [`ResolveError::Gni`] if `getnameinfo` fails,
    /// [`ResolveError::Io`] if the worker thread could not be spawned,
    /// [`ResolveError::TimedOut`] if the configured timeout expires while
    /// waiting for capacity or the system call result, or
    /// [`ResolveError::Cancelled`] if the resolver is [`shutdown`](Self::shutdown)
    /// while this call is waiting for capacity.
    pub async fn resolve_addr(
        &self,
        addr: SocketAddr,
        flags: NiFlags,
    ) -> Result<ResolvedNames, ResolveError> {
        // Fast path: a guaranteed non-blocking lookup runs inline, with no
        // worker thread, no permit, and no timeout (it cannot stall).
        if getnameinfo_is_inline(flags) {
            return if self.is_closed() {
                Err(ResolveError::Cancelled)
            } else {
                ffi::call_getnameinfo(addr, flags)
            };
        }

        let deadline = self.config.timeout.map(|timeout| Instant::now() + timeout);
        let soft_permit = Self::acquire_permit(&self.soft_sem, deadline).await?;

        let hard_permit = match Self::acquire_permit(&self.hard_sem, deadline).await {
            Ok(permit) => permit,
            Err(err) => {
                drop(soft_permit);
                return Err(err);
            }
        };

        let (tx, mut rx) = tokio::sync::oneshot::channel();
        let stall_threshold = self.config.stall_threshold;

        if let Err(err) = std::thread::Builder::new()
            .stack_size(WORKER_STACK_SIZE)
            .spawn(move || {
                let _ = tx.send(ffi::call_getnameinfo(addr, flags));
                drop(hard_permit);
            })
        {
            // See resolve_host_impl: the failed spawn dropped the hard permit;
            // release the soft permit too.
            drop(soft_permit);
            return Err(ResolveError::Io(err));
        }

        Self::await_worker_result(Some(soft_permit), stall_threshold, deadline, &mut rx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;

    use crate::types::{AddressFamily, AiFlags};

    /// A held soft permit drawn from a fresh single-permit semaphore, plus the
    /// semaphore itself. When the permit is dropped, `available_permits()`
    /// returns to 1 — the analogue of the old "effective back to 0" check.
    fn test_soft_permit() -> (Option<OwnedSemaphorePermit>, Arc<Semaphore>) {
        let sem = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&sem).try_acquire_owned().unwrap();
        (Some(permit), sem)
    }

    /// The number of soft permits a fully-idle resolver should have available
    /// (the soft limit, clamped to the hard limit).
    fn soft_full(resolver: &SystemResolver) -> usize {
        resolver.config.soft_limit.min(resolver.config.hard_limit)
    }

    async fn wait_for_idle(resolver: &SystemResolver) {
        for _ in 0..50 {
            if resolver.soft_sem.available_permits() == soft_full(resolver)
                && resolver.hard_sem.available_permits() == resolver.config.hard_limit
            {
                return;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        assert_eq!(resolver.soft_sem.available_permits(), soft_full(resolver));
        assert_eq!(
            resolver.hard_sem.available_permits(),
            resolver.config.hard_limit
        );
    }

    #[tokio::test]
    async fn test_resolve_localhost() {
        let resolver = SystemResolver::new(ResolverConfig::default());
        let results = resolver.resolve_host("localhost", None).await.unwrap();
        assert!(
            !results.is_empty(),
            "expected at least one result for localhost"
        );
        assert!(
            results.iter().all(|r| r.addr.port() == 0),
            "expected resolve_host results to use port 0 when no service is supplied"
        );
        let has_loopback = results.iter().any(|r| r.addr.ip().is_loopback());
        assert!(has_loopback, "expected a loopback address for localhost");
    }

    #[tokio::test]
    async fn test_resolve_localhost_ipv6_only() {
        let resolver = SystemResolver::new(ResolverConfig::default());
        let hints = AddrInfoHints {
            family: AddressFamily::Inet6,
            ..Default::default()
        };
        let results = resolver
            .resolve_host("localhost", Some(hints))
            .await
            .unwrap();

        assert!(
            !results.is_empty(),
            "expected at least one IPv6 localhost result"
        );
        assert!(
            results.iter().all(|r| matches!(r.addr, SocketAddr::V6(_))),
            "expected only IPv6 results with AF_INET6 hint"
        );
        assert!(
            results
                .iter()
                .any(|r| matches!(r.addr, SocketAddr::V6(v6) if v6.ip().is_loopback())),
            "expected an IPv6 loopback address for localhost"
        );
    }

    #[tokio::test]
    async fn test_resolve_addr_numeric() {
        let resolver = SystemResolver::new(ResolverConfig::default());
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let flags = NiFlags::NUMERICHOST | NiFlags::NUMERICSERV;
        let names = resolver.resolve_addr(addr, flags).await.unwrap();
        assert_eq!(names.hostname.as_deref(), Some("127.0.0.1"));
        assert_eq!(names.service.as_deref(), Some("80"));
    }

    #[tokio::test]
    async fn test_resolve_host_service_numeric_port() {
        let resolver = SystemResolver::new(ResolverConfig::default());
        let results = resolver
            .resolve_host_service("localhost", "443", None)
            .await
            .unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.addr.port() == 443));
    }

    #[tokio::test]
    async fn test_resolve_host_service_named_service() {
        let resolver = SystemResolver::new(ResolverConfig::default());
        let results = resolver
            .resolve_host_service("127.0.0.1", "http", None)
            .await
            .unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.addr.port() == 80));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "hard_limit must be >= soft_limit")]
    fn test_new_panics_when_hard_limit_is_less_than_soft_limit() {
        let _ = SystemResolver::new(ResolverConfig {
            soft_limit: 2,
            hard_limit: 1,
            stall_threshold: Duration::from_millis(500),
            timeout: None,
        });
    }

    #[tokio::test]
    async fn test_concurrent_50() {
        let resolver = Arc::new(SystemResolver::new(ResolverConfig::default()));
        let handles: Vec<_> = (0..50)
            .map(|_| {
                let r = Arc::clone(&resolver);
                tokio::spawn(async move { r.resolve_host("localhost", None).await })
            })
            .collect();
        for h in handles {
            h.await.unwrap().unwrap();
        }
        wait_for_idle(&resolver).await;
    }

    #[tokio::test]
    async fn test_soft_limit_equal_to_hard_limit() {
        let resolver = Arc::new(SystemResolver::new(ResolverConfig {
            soft_limit: 2,
            hard_limit: 2,
            stall_threshold: Duration::from_millis(500),
            timeout: None,
        }));

        let handles: Vec<_> = (0..16)
            .map(|_| {
                let r = Arc::clone(&resolver);
                tokio::spawn(async move { r.resolve_host("localhost", None).await })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        wait_for_idle(&resolver).await;
    }

    #[tokio::test]
    async fn test_cancellation_safety() {
        let resolver = Arc::new(SystemResolver::new(ResolverConfig {
            soft_limit: 2,
            hard_limit: 4,
            stall_threshold: Duration::from_millis(500),
            timeout: None,
        }));

        // Drop unpolled futures: no permit ever acquired.
        for _ in 0..20 {
            let fut = resolver.resolve_host("localhost", None);
            drop(fut);
        }

        // Abort spawned tasks mid-flight
        let mut handles = Vec::new();
        for _ in 0..5 {
            let r = Arc::clone(&resolver);
            handles.push(tokio::spawn(async move {
                r.resolve_host("localhost", None).await
            }));
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
        for h in handles {
            h.abort();
        }

        // Resolver must still be healthy: a fresh lookup naturally waits for
        // any aborted worker threads to release their hard permits.
        resolver.resolve_host("localhost", None).await.unwrap();
        wait_for_idle(&resolver).await;
    }

    /// A waiter blocked on the hard permit is cancelled when the resolver is
    /// shut down.
    #[tokio::test]
    async fn test_shutdown_cancels_waiting_call() {
        let resolver = Arc::new(SystemResolver::new(ResolverConfig {
            soft_limit: 1,
            hard_limit: 1,
            stall_threshold: Duration::from_secs(5),
            timeout: None,
        }));

        let held_permit = Arc::clone(&resolver.hard_sem)
            .acquire_owned()
            .await
            .unwrap();

        let waiter = {
            let r = Arc::clone(&resolver);
            tokio::spawn(async move { r.resolve_host("localhost", None).await })
        };

        // Wait until the call has taken the soft permit and is blocked on hard.
        for _ in 0..20 {
            if resolver.soft_sem.available_permits() == 0 {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(resolver.soft_sem.available_permits(), 0);

        resolver.shutdown();
        drop(held_permit);

        let result = waiter.await.unwrap();
        assert!(matches!(result, Err(ResolveError::Cancelled)));
        assert!(resolver.is_closed());
    }

    #[tokio::test]
    async fn test_aborting_while_waiting_on_hard_permit_releases_soft_permit() {
        let resolver = Arc::new(SystemResolver::new(ResolverConfig {
            soft_limit: 1,
            hard_limit: 1,
            stall_threshold: Duration::from_secs(5),
            timeout: None,
        }));

        let held_permit = Arc::clone(&resolver.hard_sem)
            .acquire_owned()
            .await
            .unwrap();

        let waiter = {
            let r = Arc::clone(&resolver);
            tokio::spawn(async move { r.resolve_host("localhost", None).await })
        };

        for _ in 0..20 {
            if resolver.soft_sem.available_permits() == 0 {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(resolver.soft_sem.available_permits(), 0);

        waiter.abort();
        let _ = waiter.await;

        tokio::task::yield_now().await;
        assert_eq!(resolver.soft_sem.available_permits(), 1);

        drop(held_permit);
        assert_eq!(resolver.hard_sem.available_permits(), 1);
    }

    #[tokio::test]
    async fn test_hints_ipv4_only() {
        let resolver = SystemResolver::new(ResolverConfig::default());
        let hints = AddrInfoHints {
            family: AddressFamily::Inet,
            ..Default::default()
        };
        let results = resolver
            .resolve_host("localhost", Some(hints))
            .await
            .unwrap();
        assert!(!results.is_empty());
        for r in &results {
            assert!(
                matches!(r.addr, SocketAddr::V4(_)),
                "expected only IPv4 results with AF_INET hint"
            );
        }
    }

    #[tokio::test]
    async fn test_resolve_addr_ipv6_numeric() {
        let resolver = SystemResolver::new(ResolverConfig::default());
        let addr: SocketAddr = "[::1]:443".parse().unwrap();
        let flags = NiFlags::NUMERICHOST | NiFlags::NUMERICSERV;
        let names = resolver.resolve_addr(addr, flags).await.unwrap();
        assert_eq!(names.hostname.as_deref(), Some("::1"));
        assert_eq!(names.service.as_deref(), Some("443"));
    }

    #[tokio::test(start_paused = true)]
    async fn test_resolve_host_times_out_waiting_for_soft_slot() {
        let resolver = SystemResolver::new(ResolverConfig {
            soft_limit: 1,
            hard_limit: 1,
            stall_threshold: Duration::from_secs(1),
            timeout: Some(Duration::from_millis(20)),
        });
        // Hold the only soft permit so the call blocks on soft-limit capacity.
        let held_soft = Arc::clone(&resolver.soft_sem)
            .acquire_owned()
            .await
            .unwrap();

        let result = resolver.resolve_host("localhost", None).await;
        assert!(matches!(result, Err(ResolveError::TimedOut)));
        assert_eq!(resolver.soft_sem.available_permits(), 0);
        drop(held_soft);
    }

    #[tokio::test(start_paused = true)]
    async fn test_resolve_host_times_out_waiting_for_hard_permit() {
        let resolver = Arc::new(SystemResolver::new(ResolverConfig {
            soft_limit: 1,
            hard_limit: 1,
            stall_threshold: Duration::from_secs(1),
            timeout: Some(Duration::from_millis(20)),
        }));
        let held_permit = Arc::clone(&resolver.hard_sem)
            .acquire_owned()
            .await
            .unwrap();

        let result = resolver.resolve_host("localhost", None).await;
        assert!(matches!(result, Err(ResolveError::TimedOut)));
        // The soft permit is released on the timeout path.
        assert_eq!(resolver.soft_sem.available_permits(), 1);
        assert_eq!(resolver.hard_sem.available_permits(), 0);

        drop(held_permit);
        assert_eq!(resolver.hard_sem.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_resolve_addr_times_out_waiting_for_hard_permit() {
        let resolver = Arc::new(SystemResolver::new(ResolverConfig {
            soft_limit: 1,
            hard_limit: 1,
            stall_threshold: Duration::from_secs(1),
            timeout: Some(Duration::from_millis(20)),
        }));
        let held_permit = Arc::clone(&resolver.hard_sem)
            .acquire_owned()
            .await
            .unwrap();

        let addr = SocketAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::LOCALHOST,
            80,
        ));
        let result = resolver.resolve_addr(addr, NiFlags::NUMERICHOST).await;
        assert!(matches!(result, Err(ResolveError::TimedOut)));
        assert_eq!(resolver.soft_sem.available_permits(), 1);
        assert_eq!(resolver.hard_sem.available_permits(), 0);

        drop(held_permit);
        assert_eq!(resolver.hard_sem.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_await_worker_result_times_out_before_stall() {
        let (_tx, mut rx) = tokio::sync::oneshot::channel::<Result<(), ResolveError>>();
        let (soft_permit, sem) = test_soft_permit();

        let result = SystemResolver::await_worker_result(
            soft_permit,
            Duration::from_secs(1),
            Some(Instant::now() + Duration::from_millis(20)),
            &mut rx,
        )
        .await;

        assert!(matches!(result, Err(ResolveError::TimedOut)));
        assert_eq!(sem.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_await_worker_result_completes_before_stall_with_deadline() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<Result<&'static str, ResolveError>>();
        let (soft_permit, sem) = test_soft_permit();
        let _ = tx.send(Ok("done"));

        let result = SystemResolver::await_worker_result(
            soft_permit,
            Duration::from_secs(1),
            Some(Instant::now() + Duration::from_millis(200)),
            &mut rx,
        )
        .await;

        assert_eq!(result.unwrap(), "done");
        assert_eq!(sem.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_await_worker_result_stalls_then_completes() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<Result<&'static str, ResolveError>>();
        let (soft_permit, sem) = test_soft_permit();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let _ = tx.send(Ok("done"));
        });

        let result = SystemResolver::await_worker_result(
            soft_permit,
            Duration::from_millis(10),
            Some(Instant::now() + Duration::from_millis(200)),
            &mut rx,
        )
        .await;

        assert_eq!(result.unwrap(), "done");
        assert_eq!(sem.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_await_worker_result_stalls_without_deadline_then_completes() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<Result<&'static str, ResolveError>>();
        let (soft_permit, sem) = test_soft_permit();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let _ = tx.send(Ok("done"));
        });

        let result = SystemResolver::await_worker_result(
            soft_permit,
            Duration::from_millis(10),
            None,
            &mut rx,
        )
        .await;

        assert_eq!(result.unwrap(), "done");
        assert_eq!(sem.available_permits(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn test_await_worker_result_stalls_then_times_out() {
        let (_tx, mut rx) = tokio::sync::oneshot::channel::<Result<(), ResolveError>>();
        let (soft_permit, sem) = test_soft_permit();

        let result = SystemResolver::await_worker_result(
            soft_permit,
            Duration::from_millis(10),
            Some(Instant::now() + Duration::from_millis(40)),
            &mut rx,
        )
        .await;

        assert!(matches!(result, Err(ResolveError::TimedOut)));
        assert_eq!(sem.available_permits(), 1);
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn test_soft_limit_clamped_to_hard_limit() {
        // In release builds the debug_assert is gone; the soft limit must still
        // be clamped to the hard limit.
        let resolver = SystemResolver::new(ResolverConfig {
            soft_limit: 10,
            hard_limit: 2,
            stall_threshold: Duration::from_millis(500),
            timeout: None,
        });
        assert_eq!(resolver.soft_sem.available_permits(), 2);
    }

    #[tokio::test]
    async fn test_resolve_passive_loopback() {
        let resolver = SystemResolver::new(ResolverConfig::default());
        let results = resolver.resolve_passive("80", None).await.unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.addr.port() == 80));
        assert!(results.iter().all(|r| r.addr.ip().is_loopback()));
    }

    #[tokio::test]
    async fn test_resolve_passive_wildcard() {
        let resolver = SystemResolver::new(ResolverConfig::default());
        let hints = AddrInfoHints {
            flags: AiFlags::PASSIVE | AiFlags::NUMERICSERV,
            ..Default::default()
        };
        let results = resolver.resolve_passive("8080", Some(hints)).await.unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.addr.port() == 8080));
        assert!(results.iter().all(|r| r.addr.ip().is_unspecified()));
    }

    #[tokio::test]
    async fn test_resolve_addr_populates_raw_bytes() {
        let resolver = SystemResolver::new(ResolverConfig::default());
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let flags = NiFlags::NUMERICHOST | NiFlags::NUMERICSERV;
        let names = resolver.resolve_addr(addr, flags).await.unwrap();
        assert_eq!(names.hostname.as_deref(), Some("127.0.0.1"));
        assert_eq!(names.hostname_raw.as_deref(), Some(&b"127.0.0.1"[..]));
        assert_eq!(names.service_raw.as_deref(), Some(&b"80"[..]));
    }

    #[test]
    fn getnameinfo_inline_predicate() {
        assert!(getnameinfo_is_inline(
            NiFlags::NUMERICHOST | NiFlags::NUMERICSERV
        ));
        // Either flag alone may still hit /etc/services or reverse DNS.
        assert!(!getnameinfo_is_inline(NiFlags::NUMERICHOST));
        assert!(!getnameinfo_is_inline(NiFlags::NUMERICSERV));
        assert!(!getnameinfo_is_inline(NiFlags::NONE));
    }

    #[test]
    fn getaddrinfo_inline_predicate() {
        let numeric = AddrInfoHints {
            flags: AiFlags::NUMERICHOST | AiFlags::NUMERICSERV,
            ..Default::default()
        };
        assert!(getaddrinfo_is_inline(
            Some("127.0.0.1"),
            Some("80"),
            Some(&numeric)
        ));

        // Numeric host, no service: still inline.
        let host_only = AddrInfoHints {
            flags: AiFlags::NUMERICHOST,
            ..Default::default()
        };
        assert!(getaddrinfo_is_inline(
            Some("127.0.0.1"),
            None,
            Some(&host_only)
        ));

        // Absent host (passive) with numeric service: inline.
        let passive = AddrInfoHints {
            flags: AiFlags::PASSIVE | AiFlags::NUMERICSERV,
            ..Default::default()
        };
        assert!(getaddrinfo_is_inline(None, Some("80"), Some(&passive)));

        // A service name without NUMERICSERV may hit /etc/services.
        assert!(!getaddrinfo_is_inline(
            Some("127.0.0.1"),
            Some("http"),
            Some(&host_only)
        ));

        // No hints: a host would be resolved via NSS/DNS.
        assert!(!getaddrinfo_is_inline(Some("127.0.0.1"), None, None));

        // ADDRCONFIG inspects system interfaces, so it disables the fast path.
        let with_addrcfg = AddrInfoHints {
            flags: AiFlags::NUMERICHOST | AiFlags::NUMERICSERV | AiFlags::ADDRCONFIG,
            ..Default::default()
        };
        assert!(!getaddrinfo_is_inline(
            Some("127.0.0.1"),
            Some("80"),
            Some(&with_addrcfg)
        ));
    }

    /// A numeric reverse lookup runs inline, so it succeeds even when every
    /// soft and hard permit is held and the timeout is tiny.
    #[tokio::test(start_paused = true)]
    async fn test_numeric_addr_bypasses_limits() {
        let resolver = Arc::new(SystemResolver::new(ResolverConfig {
            soft_limit: 1,
            hard_limit: 1,
            stall_threshold: Duration::from_secs(1),
            timeout: Some(Duration::from_millis(1)),
        }));
        let _soft = Arc::clone(&resolver.soft_sem)
            .acquire_owned()
            .await
            .unwrap();
        let _hard = Arc::clone(&resolver.hard_sem)
            .acquire_owned()
            .await
            .unwrap();

        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let names = resolver
            .resolve_addr(addr, NiFlags::NUMERICHOST | NiFlags::NUMERICSERV)
            .await
            .unwrap();
        assert_eq!(names.hostname.as_deref(), Some("127.0.0.1"));

        // The permits were never touched.
        assert_eq!(resolver.soft_sem.available_permits(), 0);
        assert_eq!(resolver.hard_sem.available_permits(), 0);
    }

    /// A numeric forward lookup likewise bypasses the limits.
    #[tokio::test(start_paused = true)]
    async fn test_numeric_host_bypasses_limits() {
        let resolver = Arc::new(SystemResolver::new(ResolverConfig {
            soft_limit: 1,
            hard_limit: 1,
            stall_threshold: Duration::from_secs(1),
            timeout: Some(Duration::from_millis(1)),
        }));
        let _soft = Arc::clone(&resolver.soft_sem)
            .acquire_owned()
            .await
            .unwrap();
        let _hard = Arc::clone(&resolver.hard_sem)
            .acquire_owned()
            .await
            .unwrap();

        let hints = AddrInfoHints {
            flags: AiFlags::NUMERICHOST | AiFlags::NUMERICSERV,
            ..Default::default()
        };
        let results = resolver
            .resolve_host_service("127.0.0.1", "80", Some(hints))
            .await
            .unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().all(|r| r.addr.port() == 80));

        assert_eq!(resolver.soft_sem.available_permits(), 0);
        assert_eq!(resolver.hard_sem.available_permits(), 0);
    }

    /// After shutdown, even inline calls are rejected.
    #[tokio::test]
    async fn test_shutdown_rejects_inline_call() {
        let resolver = SystemResolver::new(ResolverConfig::default());
        resolver.shutdown();
        let addr: SocketAddr = "127.0.0.1:80".parse().unwrap();
        let result = resolver
            .resolve_addr(addr, NiFlags::NUMERICHOST | NiFlags::NUMERICSERV)
            .await;
        assert!(matches!(result, Err(ResolveError::Cancelled)));
    }
}
