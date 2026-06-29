//! Resolver configuration knobs.
//!
//! This module contains [`ResolverConfig`], which controls how many blocking
//! resolver threads may run concurrently and how quickly long-running lookups
//! are treated as stalled for soft-limit accounting.

use std::time::Duration;

/// Configuration for a [`SystemResolver`](crate::SystemResolver).
///
/// Controls the two-tier thread-count limits and the stall detection threshold.
/// Construct with [`Default`] for sensible starting values, then adjust fields
/// as needed.
///
/// # Invariant
///
/// `hard_limit` must be greater than or equal to `soft_limit`. This is
/// asserted in debug builds when the resolver is created.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use tokio_system_resolver::ResolverConfig;
///
/// let config = ResolverConfig {
///     soft_limit: 4,
///     hard_limit: 16,
///     stall_threshold: Duration::from_millis(200),
///     timeout: Some(Duration::from_secs(2)),
/// };
/// ```
#[derive(Debug, Copy, Clone)]
pub struct ResolverConfig {
    /// Target maximum number of concurrently running resolution threads.
    ///
    /// Under normal conditions no more than this many threads will be active at
    /// once. This limit can be exceeded (up to [`hard_limit`](Self::hard_limit))
    /// when threads are stalled or their callers have cancelled.
    pub soft_limit: usize,

    /// Absolute maximum number of concurrently running resolution threads.
    ///
    /// Enforced by a semaphore. Callers that arrive when this limit is reached
    /// block until a permit is released (backpressure). Must be ≥
    /// [`soft_limit`](Self::soft_limit).
    pub hard_limit: usize,

    /// How long a thread must be running before it is considered stalled.
    ///
    /// Once this threshold is exceeded the thread's soft-limit slot is
    /// released early, allowing new queries to start. The stalled thread
    /// continues running and releases its hard-limit permit when it exits.
    ///
    /// Defaults to 500 ms.
    pub stall_threshold: Duration,

    /// Maximum time to wait for a lookup before returning
    /// [`ResolveError::TimedOut`](crate::ResolveError::TimedOut).
    ///
    /// This timeout covers queueing behind the soft and hard limits as well as
    /// the time spent waiting for the underlying system call to complete.
    /// Timing out does not stop the worker thread; if one has already been
    /// spawned it continues running in the background and releases its
    /// hard-limit permit when it exits.
    ///
    /// It does not apply to lookups taken by the inline fast path (see
    /// [`SystemResolver`](crate::SystemResolver)), which cannot block.
    ///
    /// Defaults to `None`, which means wait indefinitely.
    pub timeout: Option<Duration>,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            soft_limit: 8,
            hard_limit: 32,
            stall_threshold: Duration::from_millis(500),
            timeout: None,
        }
    }
}
