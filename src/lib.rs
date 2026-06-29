//! Tokio-compatible async resolver wrapping the system [`getaddrinfo(3)`] and
//! [`getnameinfo(3)`] calls.
//!
//! POSIX calls that may block are offloaded to on-demand OS threads. Calls that
//! are guaranteed not to block — purely numeric `getnameinfo`, and `getaddrinfo`
//! with a numeric or absent host and service — run inline on the calling task
//! with no thread (see [`SystemResolver`]). Concurrency for the threaded path is
//! controlled by a two-tier limit:
//!
//! - **Soft limit** – the target maximum number of concurrently running
//!   resolution threads under normal conditions.
//! - **Hard limit** – the absolute ceiling, enforced by a semaphore. Callers
//!   that arrive when the hard limit is saturated await backpressure until a
//!   permit is released.
//!
//! Threads whose queries have been running longer than [`ResolverConfig::stall_threshold`]
//! (or whose callers have dropped their futures) release their soft-limit slot
//! early so that fresh queries can proceed without being blocked by stalled
//! system calls. The stalled thread continues to completion and releases its
//! hard-limit permit when it exits.
//!
//! Optionally, [`ResolverConfig::timeout`] bounds how long callers wait for a
//! result. The timeout covers queueing behind the soft and hard limits as well
//! as the system call itself. Timing out abandons the future and returns
//! [`ResolveError::TimedOut`], but it does not stop any already-started worker
//! thread.
//!
//! # Quick start
//!
//! ```no_run
//! use tokio_system_resolver::{SystemResolver, ResolverConfig, NiFlags};
//!
//! #[tokio::main]
//! async fn main() {
//!     let resolver = SystemResolver::new(ResolverConfig::default());
//!
//!     let addrs = resolver.resolve_host("example.com", None).await.unwrap();
//!     for a in &addrs {
//!         println!("{}", a.addr);
//!     }
//!
//!     let https = resolver
//!         .resolve_host_service("example.com", "443", None)
//!         .await
//!         .unwrap();
//!     println!("{}", https[0].addr);
//!
//!     let names = resolver
//!         .resolve_addr("93.184.216.34:80".parse().unwrap(), NiFlags::NONE)
//!         .await
//!         .unwrap();
//!     println!("{:?}", names.hostname);
//! }
//! ```
//!
//! [`getaddrinfo(3)`]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/getaddrinfo.html
//! [`getnameinfo(3)`]: https://pubs.opengroup.org/onlinepubs/9699919799/functions/getnameinfo.html

pub mod config;
pub mod error;
mod ffi;
pub mod resolver;
pub mod types;

pub use config::ResolverConfig;
pub use error::ResolveError;
pub use resolver::SystemResolver;
pub use types::{
    AddrInfo, AddrInfoHints, AddressFamily, AiFlags, NiFlags, Protocol, ResolvedNames, SockType,
};
