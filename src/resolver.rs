//! The asynchronous resolver implementation.
//!
//! This module exposes [`SystemResolver`], the main entry point for performing
//! hostname and reverse-address lookups through the host libc's
//! `getaddrinfo(3)` and `getnameinfo(3)` functions.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;

use crate::config::ResolverConfig;
use crate::error::ResolveError;
use crate::ffi;
use crate::types::{AddrInfo, AddrInfoHints, NiFlags, ResolvedNames};

struct SoftSlot {
    effective: Arc<AtomicUsize>,
    soft_notify: Arc<Notify>,
    released: bool,
}

impl SoftSlot {
    fn release(&mut self) {
        if !self.released {
            self.released = true;
            self.effective.fetch_sub(1, Ordering::Release);
            self.soft_notify.notify_one();
        }
    }
}

impl Drop for SoftSlot {
    fn drop(&mut self) {
        self.release();
    }
}

/// Async resolver backed by the system `getaddrinfo` and `getnameinfo` calls.
///
/// Each call spawns a dedicated OS thread that runs the blocking system call,
/// then sends the result back through a oneshot channel. Thread counts are
/// governed by the limits in [`ResolverConfig`]:
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
/// `SystemResolver` is cheaply cloneable via [`Arc`] — wrap it in one to share
/// it across tasks.
pub struct SystemResolver {
    config: Arc<ResolverConfig>,
    hard_sem: Arc<Semaphore>,
    effective: Arc<AtomicUsize>,
    soft_notify: Arc<Notify>,
}

impl SystemResolver {
    /// Create a new resolver with the given configuration.
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
        let hard_sem = Arc::new(Semaphore::new(config.hard_limit));
        Self {
            hard_sem,
            effective: Arc::new(AtomicUsize::new(0)),
            soft_notify: Arc::new(Notify::new()),
            config: Arc::new(config),
        }
    }

    async fn acquire_soft_slot(&self, deadline: Option<Instant>) -> Result<SoftSlot, ResolveError> {
        loop {
            let notified = self.soft_notify.notified();
            tokio::pin!(notified);
            // Arm BEFORE the atomic load to avoid the window where a slot frees and
            // notify_one() fires between our load and our .await.
            notified.as_mut().enable();

            let eff = self.effective.load(Ordering::Acquire);
            if eff < self.config.soft_limit {
                match self.effective.compare_exchange(
                    eff,
                    eff + 1,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        return Ok(SoftSlot {
                            effective: Arc::clone(&self.effective),
                            soft_notify: Arc::clone(&self.soft_notify),
                            released: false,
                        });
                    }
                    Err(_) => continue, // CAS race; re-arm and retry immediately
                }
            }

            if let Some(deadline) = deadline {
                let timeout = tokio::time::sleep_until(deadline);
                tokio::pin!(timeout);
                tokio::select! {
                    () = &mut notified => {}
                    () = &mut timeout => return Err(ResolveError::TimedOut),
                }
            } else {
                notified.await;
            }
        }
    }

    async fn acquire_hard_permit(
        &self,
        deadline: Option<Instant>,
    ) -> Result<OwnedSemaphorePermit, ResolveError> {
        let acquire = Arc::clone(&self.hard_sem).acquire_owned();
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
        mut soft_slot: Option<SoftSlot>,
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
                            drop(soft_slot.take());
                            return result.unwrap_or(Err(ResolveError::Cancelled));
                        }
                        () = &mut stall => {
                            drop(soft_slot.take());
                            stalled = true;
                        }
                        () = &mut timeout => {
                            drop(soft_slot.take());
                            return Err(ResolveError::TimedOut);
                        }
                    }
                }
                (false, None) => {
                    tokio::select! {
                        result = &mut *rx => {
                            drop(soft_slot.take());
                            return result.unwrap_or(Err(ResolveError::Cancelled));
                        }
                        () = &mut stall => {
                            drop(soft_slot.take());
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
    /// if the hostname contains an interior NUL byte, [`ResolveError::TimedOut`]
    /// if the configured timeout expires while waiting for capacity or the
    /// system call result, or [`ResolveError::Cancelled`] if the resolver is
    /// dropped while the hard-limit semaphore is being acquired.
    pub async fn resolve_host(
        &self,
        host: &str,
        hints: Option<AddrInfoHints>,
    ) -> Result<Vec<AddrInfo>, ResolveError> {
        let deadline = self.config.timeout.map(|timeout| Instant::now() + timeout);
        let soft_slot = self.acquire_soft_slot(deadline).await?;

        let hard_permit = match self.acquire_hard_permit(deadline).await {
            Ok(permit) => permit,
            Err(err) => {
                drop(soft_slot);
                return Err(err);
            }
        };

        let (tx, mut rx) = tokio::sync::oneshot::channel();
        let host = host.to_owned();
        let stall_threshold = self.config.stall_threshold;

        std::thread::spawn(move || {
            let _ = tx.send(ffi::call_getaddrinfo(&host, hints));
            drop(hard_permit);
        });

        Self::await_worker_result(Some(soft_slot), stall_threshold, deadline, &mut rx).await
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
    /// [`ResolveError::TimedOut`] if the configured timeout expires while
    /// waiting for capacity or the system call result, or
    /// [`ResolveError::Cancelled`] if the resolver is dropped while the
    /// hard-limit semaphore is being acquired.
    pub async fn resolve_addr(
        &self,
        addr: SocketAddr,
        flags: NiFlags,
    ) -> Result<ResolvedNames, ResolveError> {
        let deadline = self.config.timeout.map(|timeout| Instant::now() + timeout);
        let soft_slot = self.acquire_soft_slot(deadline).await?;

        let hard_permit = match self.acquire_hard_permit(deadline).await {
            Ok(permit) => permit,
            Err(err) => {
                drop(soft_slot);
                return Err(err);
            }
        };

        let (tx, mut rx) = tokio::sync::oneshot::channel();
        let stall_threshold = self.config.stall_threshold;

        std::thread::spawn(move || {
            let _ = tx.send(ffi::call_getnameinfo(addr, flags));
            drop(hard_permit);
        });

        Self::await_worker_result(Some(soft_slot), stall_threshold, deadline, &mut rx).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;

    use crate::types::AddressFamily;

    fn test_soft_slot(initial: usize) -> (Option<SoftSlot>, Arc<AtomicUsize>) {
        let effective = Arc::new(AtomicUsize::new(initial));
        let slot = SoftSlot {
            effective: Arc::clone(&effective),
            soft_notify: Arc::new(Notify::new()),
            released: false,
        };
        (Some(slot), effective)
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
        // After all tasks complete, both counters should be at zero / full.
        assert_eq!(resolver.effective.load(Ordering::Relaxed), 0);
        assert_eq!(
            resolver.hard_sem.available_permits(),
            resolver.config.hard_limit
        );
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

        assert_eq!(resolver.effective.load(Ordering::Relaxed), 0);
        assert_eq!(resolver.hard_sem.available_permits(), 2);
    }

    #[tokio::test]
    async fn test_cancellation_safety() {
        let resolver = Arc::new(SystemResolver::new(ResolverConfig {
            soft_limit: 2,
            hard_limit: 4,
            stall_threshold: Duration::from_millis(500),
            timeout: None,
        }));

        // Drop unpolled futures
        // hard_sem never acquired, effective never incremented
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

        // Give threads a moment to finish and release hard permits
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Resolver must still be healthy
        resolver.resolve_host("localhost", None).await.unwrap();
        assert_eq!(resolver.effective.load(Ordering::Relaxed), 0);
        assert_eq!(
            resolver.hard_sem.available_permits(),
            resolver.config.hard_limit
        );
    }

    #[tokio::test]
    async fn test_waiting_call_cancelled_when_resolver_semaphore_closes() {
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
            if resolver.effective.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(resolver.effective.load(Ordering::Relaxed), 1);

        resolver.hard_sem.close();
        drop(held_permit);

        let result = waiter.await.unwrap();
        assert!(matches!(result, Err(ResolveError::Cancelled)));
        assert_eq!(resolver.effective.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_aborting_while_waiting_on_hard_permit_releases_soft_slot() {
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
            if resolver.effective.load(Ordering::Relaxed) == 1 {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(resolver.effective.load(Ordering::Relaxed), 1);

        waiter.abort();
        let _ = waiter.await;

        tokio::task::yield_now().await;
        assert_eq!(resolver.effective.load(Ordering::Relaxed), 0);

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

    #[tokio::test]
    async fn test_resolve_host_times_out_waiting_for_soft_slot() {
        let resolver = SystemResolver::new(ResolverConfig {
            soft_limit: 1,
            hard_limit: 1,
            stall_threshold: Duration::from_secs(1),
            timeout: Some(Duration::from_millis(20)),
        });
        resolver.effective.store(1, Ordering::Relaxed);

        let result = resolver.resolve_host("localhost", None).await;
        assert!(matches!(result, Err(ResolveError::TimedOut)));
        assert_eq!(resolver.effective.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
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
        assert_eq!(resolver.effective.load(Ordering::Relaxed), 0);
        assert_eq!(resolver.hard_sem.available_permits(), 0);

        drop(held_permit);
        assert_eq!(resolver.hard_sem.available_permits(), 1);
    }

    #[tokio::test]
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
        assert_eq!(resolver.effective.load(Ordering::Relaxed), 0);
        assert_eq!(resolver.hard_sem.available_permits(), 0);

        drop(held_permit);
        assert_eq!(resolver.hard_sem.available_permits(), 1);
    }

    #[tokio::test]
    async fn test_await_worker_result_times_out_before_stall() {
        let (_tx, mut rx) = tokio::sync::oneshot::channel::<Result<(), ResolveError>>();
        let (soft_slot, effective) = test_soft_slot(1);

        let result = SystemResolver::await_worker_result(
            soft_slot,
            Duration::from_secs(1),
            Some(Instant::now() + Duration::from_millis(20)),
            &mut rx,
        )
        .await;

        assert!(matches!(result, Err(ResolveError::TimedOut)));
        assert_eq!(effective.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_await_worker_result_completes_before_stall_with_deadline() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<Result<&'static str, ResolveError>>();
        let (soft_slot, effective) = test_soft_slot(1);
        let _ = tx.send(Ok("done"));

        let result = SystemResolver::await_worker_result(
            soft_slot,
            Duration::from_secs(1),
            Some(Instant::now() + Duration::from_millis(200)),
            &mut rx,
        )
        .await;

        assert_eq!(result.unwrap(), "done");
        assert_eq!(effective.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_await_worker_result_stalls_then_completes() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<Result<&'static str, ResolveError>>();
        let (soft_slot, effective) = test_soft_slot(1);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let _ = tx.send(Ok("done"));
        });

        let result = SystemResolver::await_worker_result(
            soft_slot,
            Duration::from_millis(10),
            Some(Instant::now() + Duration::from_millis(200)),
            &mut rx,
        )
        .await;

        assert_eq!(result.unwrap(), "done");
        assert_eq!(effective.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_await_worker_result_stalls_without_deadline_then_completes() {
        let (tx, mut rx) = tokio::sync::oneshot::channel::<Result<&'static str, ResolveError>>();
        let (soft_slot, effective) = test_soft_slot(1);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(40)).await;
            let _ = tx.send(Ok("done"));
        });

        let result = SystemResolver::await_worker_result(
            soft_slot,
            Duration::from_millis(10),
            None,
            &mut rx,
        )
        .await;

        assert_eq!(result.unwrap(), "done");
        assert_eq!(effective.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_await_worker_result_stalls_then_times_out() {
        let (_tx, mut rx) = tokio::sync::oneshot::channel::<Result<(), ResolveError>>();
        let (soft_slot, effective) = test_soft_slot(1);

        let result = SystemResolver::await_worker_result(
            soft_slot,
            Duration::from_millis(10),
            Some(Instant::now() + Duration::from_millis(40)),
            &mut rx,
        )
        .await;

        assert!(matches!(result, Err(ResolveError::TimedOut)));
        assert_eq!(effective.load(Ordering::Relaxed), 0);
    }
}
