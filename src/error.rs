//! Error types returned by resolver operations.
//!
//! [`ResolveError`] preserves the distinction between failures originating from
//! `getaddrinfo`, failures originating from `getnameinfo`, local input / I/O
//! validation errors, and resolver shutdown while a call is waiting for
//! capacity.

use std::{ffi::CStr, io};

use libc::gai_strerror;
use thiserror::Error;

fn gai_message(code: &i32) -> String {
    // SAFETY: `*code` is valid (Rust reference guarantee). `gai_strerror`
    // returns a pointer to a static or thread-local string; the null check
    // guards `CStr::from_ptr`, and `to_string_lossy().into_owned()` copies
    // the data before any subsequent call could overwrite the buffer.
    unsafe {
        let ptr = gai_strerror(*code);
        if ptr.is_null() {
            return format!("error code {code}");
        }
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

/// Errors returned by [`SystemResolver`](crate::SystemResolver).
#[derive(Debug, Error)]
pub enum ResolveError {
    /// `getaddrinfo` failed. The inner value is the `EAI_*` error code; the
    /// [`Display`](std::fmt::Display) impl calls `gai_strerror` to produce a
    /// human-readable message.
    #[error("getaddrinfo: {}", gai_message(_0))]
    Gai(i32),

    /// `getnameinfo` failed. The inner value is the `EAI_*` error code.
    #[error("getnameinfo: {}", gai_message(_0))]
    Gni(i32),

    /// An I/O error occurred before the system call was made (e.g. the hostname
    /// contained an interior NUL byte).
    #[error(transparent)]
    Io(#[from] io::Error),

    /// The call could not complete because the resolver stopped admitting work.
    ///
    /// This is returned when:
    ///
    /// - [`SystemResolver::shutdown`](crate::SystemResolver::shutdown) is called
    ///   while this call is waiting for soft- or hard-limit capacity, or
    /// - the worker thread terminated without producing a result (for example,
    ///   it panicked), dropping the result channel.
    #[error("resolver cancelled")]
    Cancelled,

    /// The lookup exceeded the configured
    /// [`ResolverConfig::timeout`](crate::ResolverConfig::timeout).
    #[error("resolver timed out")]
    TimedOut,

    /// Length invariant violated (shouldn't happen).
    #[error("Length invariant violated")]
    LengthInvariantViolated,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_formats_getaddrinfo_errors() {
        let rendered = ResolveError::Gai(libc::EAI_NONAME).to_string();
        assert!(rendered.starts_with("getaddrinfo: "));
        assert!(rendered.len() > "getaddrinfo: ".len());
    }

    #[test]
    fn display_formats_getnameinfo_errors() {
        let rendered = ResolveError::Gni(libc::EAI_NONAME).to_string();
        assert!(rendered.starts_with("getnameinfo: "));
        assert!(rendered.len() > "getnameinfo: ".len());
    }

    #[test]
    fn display_formats_io_errors() {
        let rendered =
            ResolveError::Io(io::Error::new(io::ErrorKind::InvalidInput, "bad input")).to_string();
        assert_eq!(rendered, "bad input");
    }

    #[test]
    fn display_formats_cancelled_errors() {
        assert_eq!(ResolveError::Cancelled.to_string(), "resolver cancelled");
    }

    #[test]
    fn display_formats_timed_out_errors() {
        assert_eq!(ResolveError::TimedOut.to_string(), "resolver timed out");
    }
}
