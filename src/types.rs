//! Request and response types for system name resolution.
//!
//! These types model the portable subset of the `getaddrinfo(3)` and
//! `getnameinfo(3)` API surface: lookup hints, returned address records, and
//! the flag / enum types used to configure calls.

use std::net::SocketAddr;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, Not};

#[cfg(not(any(target_os = "netbsd", target_os = "openbsd")))]
use libc::AI_V4MAPPED;
use libc::{
    AF_INET, AF_INET6, AF_UNSPEC, AI_ADDRCONFIG, AI_CANONNAME, AI_NUMERICHOST, AI_NUMERICSERV,
    AI_PASSIVE, IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_IP, IPPROTO_TCP, IPPROTO_UDP, NI_DGRAM,
    NI_NAMEREQD, NI_NOFQDN, NI_NUMERICHOST, NI_NUMERICSERV, SOCK_DGRAM, SOCK_RAW, SOCK_STREAM,
    c_int,
};

/// Address family passed to `getaddrinfo` via the hints struct.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressFamily {
    /// `AF_UNSPEC` — accept both IPv4 and IPv6 results (default).
    #[default]
    Unspec,

    /// `AF_INET` — restrict results to IPv4.
    Inet,

    /// `AF_INET6` — restrict results to IPv6.
    Inet6,
}

impl From<AddressFamily> for c_int {
    fn from(f: AddressFamily) -> Self {
        match f {
            AddressFamily::Unspec => AF_UNSPEC,
            AddressFamily::Inet => AF_INET,
            AddressFamily::Inet6 => AF_INET6,
        }
    }
}

/// Socket type associated with an address record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SockType {
    /// Unspecified (default).
    #[default]
    Unspec,

    /// `SOCK_STREAM` — TCP.
    Stream,

    /// `SOCK_DGRAM` — UDP.
    Dgram,

    /// `SOCK_RAW`.
    Raw,

    /// Any other `SOCK_*` value returned by the system.
    Other(i32),
}

impl From<c_int> for SockType {
    fn from(v: c_int) -> Self {
        match v {
            0 => Self::Unspec,
            SOCK_STREAM => Self::Stream,
            SOCK_DGRAM => Self::Dgram,
            SOCK_RAW => Self::Raw,
            other => Self::Other(other),
        }
    }
}

impl From<SockType> for c_int {
    fn from(s: SockType) -> Self {
        match s {
            SockType::Unspec => 0,
            SockType::Stream => SOCK_STREAM,
            SockType::Dgram => SOCK_DGRAM,
            SockType::Raw => SOCK_RAW,
            SockType::Other(v) => v,
        }
    }
}

/// Protocol associated with an address record.
///
/// This mirrors the `ai_protocol` field returned by `getaddrinfo`.
/// It is usually only relevant when the same socket address can be returned
/// for multiple transport protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Protocol {
    /// Unspecified/default protocol (`IPPROTO_IP`, value `0` on supported
    /// targets).
    ///
    /// Use this when you do not want to restrict the lookup to a specific
    /// transport protocol.
    #[default]
    Unspec,

    /// `IPPROTO_TCP` — TCP.
    Tcp,

    /// `IPPROTO_UDP` — UDP.
    Udp,

    /// `IPPROTO_ICMP` — ICMP (v4).
    Icmp,

    /// `IPPROTO_ICMPV6` — ICMP (v6).
    IcmpV6,

    /// Any other `IPPROTO_*` value returned by the system.
    Other(i32),
}

impl From<c_int> for Protocol {
    fn from(v: c_int) -> Self {
        match v {
            IPPROTO_IP => Self::Unspec,
            IPPROTO_TCP => Self::Tcp,
            IPPROTO_UDP => Self::Udp,
            IPPROTO_ICMP => Self::Icmp,
            IPPROTO_ICMPV6 => Self::IcmpV6,
            other => Self::Other(other),
        }
    }
}

impl From<Protocol> for c_int {
    fn from(s: Protocol) -> Self {
        match s {
            Protocol::Unspec => IPPROTO_IP,
            Protocol::Tcp => IPPROTO_TCP,
            Protocol::Udp => IPPROTO_UDP,
            Protocol::Icmp => IPPROTO_ICMP,
            Protocol::IcmpV6 => IPPROTO_ICMPV6,
            Protocol::Other(v) => v,
        }
    }
}

/// `ai_flags` bitmask passed to `getaddrinfo` via the hints struct.
///
/// Combine flags with `|`:
///
/// ```
/// use tokio_system_resolver::AiFlags;
/// let flags = AiFlags::CANONNAME | AiFlags::ADDRCONFIG;
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct AiFlags(pub c_int);

impl AiFlags {
    /// No flags.
    pub const NONE: Self = Self(0);

    /// `AI_PASSIVE` — Intended for [`bind(2)`](https://pubs.opengroup.org/onlinepubs/9699919799/functions/bind.html).
    pub const PASSIVE: Self = Self(AI_PASSIVE);

    /// `AI_CANONNAME` — Request the canonical name in [`AddrInfo::canonname`].
    pub const CANONNAME: Self = Self(AI_CANONNAME);

    /// `AI_NUMERICHOST` — Treat the hostname as a numeric address string.
    pub const NUMERICHOST: Self = Self(AI_NUMERICHOST);

    /// `AI_NUMERICSERV` — Treat the service as a numeric port string.
    pub const NUMERICSERV: Self = Self(AI_NUMERICSERV);

    /// `AI_V4MAPPED` — Return IPv4-mapped IPv6 addresses when no IPv6 records exist.
    #[cfg(not(any(target_os = "netbsd", target_os = "openbsd")))]
    pub const V4MAPPED: Self = Self(AI_V4MAPPED);

    /// `AI_ADDRCONFIG` — Only return address families configured on the host.
    pub const ADDRCONFIG: Self = Self(AI_ADDRCONFIG);
}

impl AiFlags {
    #[must_use]
    pub const fn contains(&self, flag: Self) -> bool {
        (self.0 & flag.0) > 0
    }

    pub const fn insert(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    pub const fn remove(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }
}

impl BitAnd for AiFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for AiFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = Self(self.0 & rhs.0);
    }
}

impl BitOr for AiFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for AiFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = Self(self.0 | rhs.0);
    }
}

impl Not for AiFlags {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

/// `flags` bitmask passed to `getnameinfo`.
///
/// Combine flags with `|`:
///
/// ```
/// use tokio_system_resolver::NiFlags;
/// let flags = NiFlags::NUMERICHOST | NiFlags::NUMERICSERV;
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[must_use]
pub struct NiFlags(pub c_int);

impl NiFlags {
    /// No flags.
    pub const NONE: Self = Self(0);

    /// Return the numeric form of the host address.
    pub const NUMERICHOST: Self = Self(NI_NUMERICHOST);

    /// Return the numeric form of the service (port number).
    pub const NUMERICSERV: Self = Self(NI_NUMERICSERV);

    /// Return only the hostname portion of the FQDN.
    pub const NOFQDN: Self = Self(NI_NOFQDN);

    /// Return an error if no hostname can be found.
    pub const NAMEREQD: Self = Self(NI_NAMEREQD);

    /// Indicate the socket is datagram-based (affects port lookup).
    pub const DGRAM: Self = Self(NI_DGRAM);
}

impl NiFlags {
    #[must_use]
    pub const fn contains(&self, flag: Self) -> bool {
        (self.0 & flag.0) > 0
    }

    pub const fn insert(&mut self, flag: Self) {
        self.0 |= flag.0;
    }

    pub const fn remove(&mut self, flag: Self) {
        self.0 &= !flag.0;
    }
}

impl BitAnd for NiFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for NiFlags {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = Self(self.0 & rhs.0);
    }
}

impl BitOr for NiFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for NiFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = Self(self.0 | rhs.0);
    }
}

impl Not for NiFlags {
    type Output = Self;
    fn not(self) -> Self {
        Self(!self.0)
    }
}

/// Hints passed to [`crate::SystemResolver::resolve_host`] to narrow
/// `getaddrinfo` results.
///
/// All fields default to "unspecified / any", which is equivalent to calling
/// `getaddrinfo` with a null hints pointer.
///
/// # Examples
///
/// ```
/// use tokio_system_resolver::{AddrInfoHints, AddressFamily, AiFlags};
///
/// let hints = AddrInfoHints {
///     family: AddressFamily::Inet6,
/// #   #[cfg(not(any(target_os = "netbsd", target_os = "openbsd")))]
///     flags: AiFlags::ADDRCONFIG | AiFlags::V4MAPPED,
/// #   #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
/// #   flags: AiFlags::ADDRCONFIG,
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone)]
#[must_use]
pub struct AddrInfoHints {
    /// Restrict results to this address family. Defaults to [`AddressFamily::Unspec`].
    pub family: AddressFamily,

    /// Restrict results to this socket type. Use `SockType::Unspec` for any.
    pub socktype: SockType,

    /// Restrict results to this protocol. Use `Protocol::Unspec` for any.
    pub protocol: Protocol,

    /// Additional `AI_*` flags. Defaults to [`AiFlags::NONE`].
    pub flags: AiFlags,
}

impl Default for AddrInfoHints {
    fn default() -> Self {
        Self {
            family: AddressFamily::Unspec,
            socktype: SockType::Unspec,
            protocol: Protocol::Unspec,
            flags: AiFlags::NONE,
        }
    }
}

/// A single address record returned by [`crate::SystemResolver::resolve_host`].
#[derive(Debug, Clone)]
#[must_use]
pub struct AddrInfo {
    /// The resolved socket address.
    ///
    /// When produced by [`crate::SystemResolver::resolve_host`], the port is
    /// `0` because no service was requested. When produced by
    /// [`crate::SystemResolver::resolve_host_service`], the port reflects the
    /// resolved service.
    pub addr: SocketAddr,

    /// The canonical name, populated only when [`AiFlags::CANONNAME`] was set.
    ///
    /// This is a lossy UTF-8 rendering: bytes that are not valid UTF-8 are
    /// replaced with the Unicode replacement character (U+FFFD). For the exact
    /// bytes returned by the system, use [`canonname_raw`](Self::canonname_raw).
    pub canonname: Option<String>,

    /// The canonical name as the exact bytes returned by `getaddrinfo`, with the
    /// trailing NUL removed.
    ///
    /// Populated whenever [`canonname`](Self::canonname) is. Canonical names
    /// originate from DNS, `/etc/hosts`, or NSS modules and are not guaranteed
    /// to be valid UTF-8, so this preserves them losslessly.
    pub canonname_raw: Option<Vec<u8>>,

    /// The socket type associated with this record.
    pub socktype: SockType,

    /// The protocol associated with this record, as returned by
    /// `getaddrinfo`.
    ///
    /// This may distinguish otherwise similar records that share the same
    /// socket address and socket type.
    pub protocol: Protocol,
}

/// Names returned by [`crate::SystemResolver::resolve_addr`].
#[derive(Debug, Clone)]
#[must_use]
pub struct ResolvedNames {
    /// The hostname for the address, or `None` if the system returned an empty string.
    ///
    /// This is a lossy UTF-8 rendering: bytes that are not valid UTF-8 are
    /// replaced with the Unicode replacement character (U+FFFD). For the exact
    /// bytes returned by the system, use [`hostname_raw`](Self::hostname_raw).
    pub hostname: Option<String>,

    /// The service name for the port, or `None` if the system returned an empty string.
    ///
    /// Lossy UTF-8, like [`hostname`](Self::hostname). For the exact bytes, use
    /// [`service_raw`](Self::service_raw).
    pub service: Option<String>,

    /// The hostname as the exact bytes returned by `getnameinfo`, with the
    /// trailing NUL removed, or `None` if the system returned an empty string.
    ///
    /// Reverse-resolved names originate from DNS PTR records, `/etc/hosts`, or
    /// NSS modules and are not guaranteed to be valid UTF-8, so this preserves
    /// them losslessly. Populated whenever [`hostname`](Self::hostname) is.
    pub hostname_raw: Option<Vec<u8>>,

    /// The service name as the exact bytes returned by `getnameinfo`, with the
    /// trailing NUL removed, or `None` if the system returned an empty string.
    ///
    /// Populated whenever [`service`](Self::service) is.
    pub service_raw: Option<Vec<u8>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_family_maps_to_libc_constants() {
        assert_eq!(c_int::from(AddressFamily::Unspec), AF_UNSPEC);
        assert_eq!(c_int::from(AddressFamily::Inet), AF_INET);
        assert_eq!(c_int::from(AddressFamily::Inet6), AF_INET6);
    }

    #[test]
    fn socktype_round_trips_through_c_int() {
        assert_eq!(SockType::from(0), SockType::Unspec);
        assert_eq!(SockType::from(SOCK_STREAM), SockType::Stream);
        assert_eq!(SockType::from(SOCK_DGRAM), SockType::Dgram);
        assert_eq!(SockType::from(SOCK_RAW), SockType::Raw);
        assert_eq!(SockType::from(12345), SockType::Other(12345));

        assert_eq!(c_int::from(SockType::Unspec), 0);
        assert_eq!(c_int::from(SockType::Stream), SOCK_STREAM);
        assert_eq!(c_int::from(SockType::Dgram), SOCK_DGRAM);
        assert_eq!(c_int::from(SockType::Raw), SOCK_RAW);
        assert_eq!(c_int::from(SockType::Other(7)), 7);
    }

    #[test]
    fn protocol_round_trips_through_c_int() {
        assert_eq!(Protocol::from(IPPROTO_IP), Protocol::Unspec);
        assert_eq!(Protocol::from(IPPROTO_TCP), Protocol::Tcp);
        assert_eq!(Protocol::from(IPPROTO_UDP), Protocol::Udp);
        assert_eq!(Protocol::from(IPPROTO_ICMP), Protocol::Icmp);
        assert_eq!(Protocol::from(IPPROTO_ICMPV6), Protocol::IcmpV6);
        assert_eq!(Protocol::from(12345), Protocol::Other(12345));

        assert_eq!(c_int::from(Protocol::Unspec), IPPROTO_IP);
        assert_eq!(c_int::from(Protocol::Tcp), IPPROTO_TCP);
        assert_eq!(c_int::from(Protocol::Udp), IPPROTO_UDP);
        assert_eq!(c_int::from(Protocol::Icmp), IPPROTO_ICMP);
        assert_eq!(c_int::from(Protocol::IcmpV6), IPPROTO_ICMPV6);
        assert_eq!(c_int::from(Protocol::Other(7)), 7);
    }

    #[test]
    fn flag_bitors_preserve_underlying_bits() {
        #[cfg(not(any(target_os = "netbsd", target_os = "openbsd")))]
        {
            let ai = AiFlags::CANONNAME | AiFlags::ADDRCONFIG | AiFlags::V4MAPPED;
            assert_eq!(ai.0, AI_CANONNAME | AI_ADDRCONFIG | AI_V4MAPPED);
        }

        #[cfg(any(target_os = "netbsd", target_os = "openbsd"))]
        {
            let ai = AiFlags::CANONNAME | AiFlags::ADDRCONFIG;
            assert_eq!(ai.0, AI_CANONNAME | AI_ADDRCONFIG);
        }

        let ni = NiFlags::NUMERICHOST | NiFlags::NUMERICSERV | NiFlags::DGRAM;
        assert_eq!(ni.0, NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM);
    }

    #[test]
    fn aiflags_support_flag_manipulation() {
        let mut flags = AiFlags::CANONNAME | AiFlags::ADDRCONFIG;
        assert!(flags.contains(AiFlags::CANONNAME));
        assert!(flags.contains(AiFlags::ADDRCONFIG));
        assert!(!flags.contains(AiFlags::NUMERICHOST));

        flags.insert(AiFlags::NUMERICHOST);
        assert!(flags.contains(AiFlags::NUMERICHOST));

        let masked = flags & (AiFlags::CANONNAME | AiFlags::NUMERICHOST);
        assert!(masked.contains(AiFlags::CANONNAME));
        assert!(masked.contains(AiFlags::NUMERICHOST));
        assert!(!masked.contains(AiFlags::ADDRCONFIG));

        flags &= !AiFlags::CANONNAME;
        assert!(!flags.contains(AiFlags::CANONNAME));
        assert!(flags.contains(AiFlags::ADDRCONFIG));
        assert!(flags.contains(AiFlags::NUMERICHOST));

        flags |= AiFlags::NUMERICSERV;
        assert!(flags.contains(AiFlags::NUMERICSERV));

        flags.remove(AiFlags::ADDRCONFIG | AiFlags::NUMERICHOST);
        assert!(!flags.contains(AiFlags::ADDRCONFIG));
        assert!(!flags.contains(AiFlags::NUMERICHOST));
        assert!(flags.contains(AiFlags::NUMERICSERV));
    }

    #[test]
    fn niflags_support_flag_manipulation() {
        let mut flags = NiFlags::NUMERICHOST | NiFlags::NUMERICSERV;
        assert!(flags.contains(NiFlags::NUMERICHOST));
        assert!(flags.contains(NiFlags::NUMERICSERV));
        assert!(!flags.contains(NiFlags::DGRAM));

        flags.insert(NiFlags::DGRAM);
        assert!(flags.contains(NiFlags::DGRAM));

        let masked = flags & (NiFlags::NUMERICSERV | NiFlags::DGRAM);
        assert!(!masked.contains(NiFlags::NUMERICHOST));
        assert!(masked.contains(NiFlags::NUMERICSERV));
        assert!(masked.contains(NiFlags::DGRAM));

        flags &= !NiFlags::NUMERICSERV;
        assert!(flags.contains(NiFlags::NUMERICHOST));
        assert!(!flags.contains(NiFlags::NUMERICSERV));
        assert!(flags.contains(NiFlags::DGRAM));

        flags |= NiFlags::NAMEREQD;
        assert!(flags.contains(NiFlags::NAMEREQD));

        flags.remove(NiFlags::NUMERICHOST | NiFlags::DGRAM);
        assert!(!flags.contains(NiFlags::NUMERICHOST));
        assert!(!flags.contains(NiFlags::DGRAM));
        assert!(flags.contains(NiFlags::NAMEREQD));
    }

    #[test]
    fn addrinfo_hints_default_matches_unrestricted_lookup() {
        let hints = AddrInfoHints::default();
        assert_eq!(hints.family, AddressFamily::Unspec);
        assert_eq!(hints.socktype, SockType::Unspec);
        assert_eq!(hints.flags.0, AiFlags::NONE.0);
    }
}
