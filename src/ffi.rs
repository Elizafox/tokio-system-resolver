use std::ffi::{CStr, CString};
use std::io;
use std::mem::{MaybeUninit, size_of};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::ptr;

use libc::{
    AF_INET, AF_INET6, NI_MAXHOST, addrinfo, c_char, c_int, freeaddrinfo, getaddrinfo, getnameinfo,
    in_addr, in6_addr, sa_family_t, sockaddr, sockaddr_in, sockaddr_in6, sockaddr_storage,
    socklen_t,
};

// NI_MAXSERV is not exposed by libc on Linux. The value is 32 on every
// platform.
const NI_MAXSERV: usize = 32;

use crate::error::ResolveError;
use crate::types::{AddrInfo, AddrInfoHints, NiFlags, Protocol, ResolvedNames, SockType};

struct AddrInfoList(*mut addrinfo);

// SAFETY: getaddrinfo result is not thread-affine; freeaddrinfo is re-entrant
// for distinct lists.
unsafe impl Send for AddrInfoList {}

impl Drop for AddrInfoList {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: self.0 is non-null (guarded above) and was returned by
            // getaddrinfo.
            unsafe { freeaddrinfo(self.0) }
        }
    }
}

pub fn call_getaddrinfo(
    host: &str,
    service: Option<&str>,
    hints: Option<AddrInfoHints>,
) -> Result<Vec<AddrInfo>, ResolveError> {
    let node = CString::new(host)
        .map_err(|e| ResolveError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;
    let service = service
        .map(CString::new)
        .transpose()
        .map_err(|e| ResolveError::Io(io::Error::new(io::ErrorKind::InvalidInput, e)))?;

    // SAFETY: `p` is a valid aligned pointer into a live MaybeUninit. All
    // fields are initialized: the four written explicitly, all others zeroed
    // by `zeroed()`. Calling `assume_init()` is therefore sound.
    let hints_struct: Option<addrinfo> = hints.map(|h| unsafe {
        let mut ai = MaybeUninit::<addrinfo>::zeroed();
        let p = ai.as_mut_ptr();
        (*p).ai_flags = h.flags.0;
        (*p).ai_family = c_int::from(h.family);
        (*p).ai_socktype = c_int::from(h.socktype);
        (*p).ai_protocol = c_int::from(h.protocol);
        ai.assume_init()
    });

    let hints_ptr: *const addrinfo = hints_struct.as_ref().map_or(ptr::null(), ptr::from_ref);

    let mut res: *mut addrinfo = ptr::null_mut();

    // SAFETY: `node` is a valid null-terminated C string (from CString);
    // `hints_ptr` is null or a pointer to the valid addrinfo built above
    // (lifetime covers this call); `res` is a valid writable pointer to receive
    // the result.
    let ret = unsafe {
        getaddrinfo(
            node.as_ptr(),
            service.as_ref().map_or(ptr::null(), |value| value.as_ptr()),
            hints_ptr,
            &raw mut res,
        )
    };

    if ret != 0 {
        return Err(ResolveError::Gai(ret));
    }

    let list = AddrInfoList(res);
    let mut results = Vec::new();

    let mut cur = list.0;
    while !cur.is_null() {
        // SAFETY: cur is non-null (loop condition), properly aligned, and
        // points to a valid addrinfo initialized by getaddrinfo.
        let node_ref = unsafe { &*cur };
        // SAFETY: node_ref was returned by getaddrinfo, which guarantees
        // ai_addr is valid, properly aligned, and typed for the advertised
        // ai_family.
        if let Some(info) = unsafe { parse_node(node_ref) } {
            results.push(info);
        }
        cur = node_ref.ai_next;
    }

    Ok(results)
}

// SAFETY: `ai_addr` is filled in by getaddrinfo and is correctly aligned and
// typed for the advertised ai_family. The cast_ptr_alignment lint fires because
// sockaddr has align = 1 on some platforms, but the actual pointed-to data is
// always a fully-aligned `sockaddr_in` or `sockaddr_in6` as guaranteed by
// POSIX.
#[must_use]
unsafe fn parse_node(node: &addrinfo) -> Option<AddrInfo> {
    let addr = match node.ai_family {
        AF_INET => {
            // SAFETY: node.ai_addr is sockaddr_in for AF_INET and allocated
            #[allow(clippy::cast_ptr_alignment, reason = "casting as API designed")]
            let sin = unsafe { &*(node.ai_addr as *const sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr));
            let port = u16::from_be(sin.sin_port);
            SocketAddr::V4(SocketAddrV4::new(ip, port))
        }
        AF_INET6 => {
            // SAFETY: node.ai_addr is sockaddr_in6 for AF_INET6 and allocated
            #[allow(clippy::cast_ptr_alignment, reason = "casting as API designed")]
            let sin6 = unsafe { &*(node.ai_addr as *const sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            let port = u16::from_be(sin6.sin6_port);
            SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                sin6.sin6_flowinfo,
                sin6.sin6_scope_id,
            ))
        }
        _ => return None,
    };

    let canonname = if node.ai_canonname.is_null() {
        None
    } else {
        Some(
            // SAFETY: ai_canonname is non-null (checked above); getaddrinfo
            // guarantees it is a valid null-terminated C string that lives as
            // long as the addrinfo list.
            unsafe { CStr::from_ptr(node.ai_canonname) }
                .to_string_lossy()
                .into_owned(),
        )
    };

    Some(AddrInfo {
        addr,
        canonname,
        socktype: SockType::from(node.ai_socktype),
        protocol: Protocol::from(node.ai_protocol),
    })
}

// All casts here are safe: sockaddr_in is 16 bytes and sockaddr_in6 is 28
// bytes, both fitting in u8 (for sin_len) and well under socklen_t's u32
// range. AF_INET/AF_INET6 are 2 and 10 respectively, fitting in sa_family_t
// (u8 on BSDs).
#[must_use]
fn socketaddr_to_raw(addr: SocketAddr) -> (sockaddr_storage, socklen_t) {
    match addr {
        SocketAddr::V4(v4) => {
            let sin = sockaddr_in {
                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "freebsd",
                    target_os = "dragonfly",
                    target_os = "netbsd",
                    target_os = "openbsd",
                ))]
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "sizeof(sockaddr_in) fits in a byte by design"
                )]
                sin_len: size_of::<sockaddr_in>() as u8,
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "sa_family_t wide enough by design"
                )]
                sin_family: AF_INET as sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };

            #[allow(
                clippy::cast_possible_truncation,
                reason = "socklen_t wide enough by design"
            )]
            let len = size_of::<sockaddr_in>() as socklen_t;
            let mut storage = MaybeUninit::<sockaddr_storage>::zeroed();
            // SAFETY: `sockaddr_storage` is defined to have at least the size
            // and alignment of any sockaddr type, so the cast to `*mut
            // sockaddr_in` is valid. `ptr::write` does not require the
            // destination to be initialized.
            unsafe { ptr::write(storage.as_mut_ptr().cast::<sockaddr_in>(), sin) };
            // SAFETY: the sockaddr_in fields are fully written above; the
            // remaining bytes of sockaddr_storage were zeroed by
            // `MaybeUninit::zeroed()`, so all bytes are init.
            (unsafe { storage.assume_init() }, len)
        }
        SocketAddr::V6(v6) => {
            let sin6 = sockaddr_in6 {
                #[cfg(any(
                    target_os = "macos",
                    target_os = "ios",
                    target_os = "freebsd",
                    target_os = "dragonfly",
                    target_os = "netbsd",
                    target_os = "openbsd",
                ))]
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "sizeof(sockaddr_in6) fits in a byte by design"
                )]
                sin6_len: size_of::<sockaddr_in6>() as u8,
                #[allow(
                    clippy::cast_possible_truncation,
                    reason = "sa_family_t wide enough by design"
                )]
                sin6_family: AF_INET6 as sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            #[allow(
                clippy::cast_possible_truncation,
                reason = "socklen_t wide enough by design"
            )]
            let len = size_of::<sockaddr_in6>() as socklen_t;
            let mut storage = MaybeUninit::<sockaddr_storage>::zeroed();
            // SAFETY: same as the IPv4 arm — sockaddr_storage has sufficient
            // size and alignment for sockaddr_in6.
            unsafe { ptr::write(storage.as_mut_ptr().cast::<sockaddr_in6>(), sin6) };
            // SAFETY: sockaddr_in6 fields fully written; remaining bytes zeroed
            // by `MaybeUninit::zeroed()`.
            (unsafe { storage.assume_init() }, len)
        }
    }
}

pub fn call_getnameinfo(addr: SocketAddr, flags: NiFlags) -> Result<ResolvedNames, ResolveError> {
    let (storage, salen) = socketaddr_to_raw(addr);

    let mut host_buf = [0u8; NI_MAXHOST as usize];
    let mut serv_buf = [0u8; NI_MAXSERV];
    let host_len = host_buf
        .len()
        .try_into()
        .expect("NI_MAXHOST fits in getnameinfo length type");
    let serv_len = serv_buf
        .len()
        .try_into()
        .expect("NI_MAXSERV fits in getnameinfo length type");

    // SAFETY: `storage` holds a valid sockaddr_in or sockaddr_in6; `salen` is
    // the exact size of that type (not the full sockaddr_storage), matching
    // what getnameinfo reads. `host_buf` and
    // `serv_buf` are writable buffers of NI_MAXHOST / NI_MAXSERV bytes
    // respectively.
    let ret = unsafe {
        getnameinfo(
            (&raw const storage).cast::<sockaddr>(),
            salen,
            host_buf.as_mut_ptr().cast::<c_char>(),
            host_len,
            serv_buf.as_mut_ptr().cast::<c_char>(),
            serv_len,
            flags.0,
        )
    };

    if ret != 0 {
        return Err(ResolveError::Gni(ret));
    }

    let to_opt = |buf: &[u8]| -> Option<String> {
        // SAFETY: getnameinfo succeeded and wrote a null-terminated string
        // into buf; the buffer was zero-initialized so it is null-terminated
        // even if getnameinfo wrote nothing.
        let s = unsafe { CStr::from_ptr(buf.as_ptr().cast::<c_char>()) }
            .to_string_lossy()
            .into_owned();
        (!s.is_empty()).then_some(s)
    };

    Ok(ResolvedNames {
        hostname: to_opt(&host_buf),
        service: to_opt(&serv_buf),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::ffi::CString;
    use std::ptr;

    use libc::{AF_UNIX, SOCK_STREAM};

    use crate::types::{AddressFamily, AiFlags};

    #[test]
    fn getaddrinfo_rejects_interior_nul() {
        let err = call_getaddrinfo("bad\0host", None, None).unwrap_err();
        assert!(matches!(
            err,
            ResolveError::Io(ref io_err) if io_err.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn getaddrinfo_numeric_ipv4_with_hints() {
        let hints = AddrInfoHints {
            family: AddressFamily::Inet,
            socktype: SockType::Stream,
            protocol: Protocol::Unspec,
            flags: AiFlags::NUMERICHOST,
        };

        let results = call_getaddrinfo("127.0.0.1", None, Some(hints)).unwrap();
        assert!(!results.is_empty());
        assert!(
            results
                .iter()
                .all(|info| matches!(info.addr, SocketAddr::V4(_)))
        );
        assert!(results.iter().all(|info| info.socktype == SockType::Stream));
    }

    #[test]
    fn getaddrinfo_invalid_numeric_host_returns_gai() {
        let hints = AddrInfoHints {
            flags: AiFlags::NUMERICHOST,
            ..Default::default()
        };

        let err = call_getaddrinfo("999.999.999.999", None, Some(hints)).unwrap_err();
        assert!(matches!(err, ResolveError::Gai(_)));
    }

    #[test]
    fn getaddrinfo_numeric_service_sets_port() {
        let hints = AddrInfoHints {
            family: AddressFamily::Inet,
            flags: AiFlags::NUMERICHOST | AiFlags::NUMERICSERV,
            ..Default::default()
        };

        let results = call_getaddrinfo("127.0.0.1", Some("443"), Some(hints)).unwrap();
        assert!(!results.is_empty());
        assert!(results.iter().all(|info| info.addr.port() == 443));
    }

    #[test]
    fn getnameinfo_namereqd_without_ptr_returns_gni() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 80));
        let err = call_getnameinfo(addr, NiFlags::NAMEREQD | NiFlags::NUMERICSERV).unwrap_err();
        assert!(matches!(err, ResolveError::Gni(_)));
    }

    #[test]
    fn socketaddr_to_raw_preserves_ipv4_fields() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 1, 2, 3), 8080));
        let (storage, len) = socketaddr_to_raw(addr);

        assert_eq!(len as usize, size_of::<sockaddr_in>());

        // SAFETY: socketaddr_to_raw wrote a sockaddr_in into the storage for
        // IPv4 inputs.
        let raw = unsafe { &*((&raw const storage).cast::<sockaddr_in>()) };
        assert_eq!(c_int::from(raw.sin_family), AF_INET);
        assert_eq!(u16::from_be(raw.sin_port), 8080);
        assert_eq!(
            Ipv4Addr::from(u32::from_be(raw.sin_addr.s_addr)),
            Ipv4Addr::new(127, 1, 2, 3)
        );
    }

    #[test]
    fn socketaddr_to_raw_preserves_ipv6_fields() {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 7, 11));
        let (storage, len) = socketaddr_to_raw(addr);

        assert_eq!(len as usize, size_of::<sockaddr_in6>());

        // SAFETY: socketaddr_to_raw wrote a sockaddr_in6 into the storage for
        // IPv6 inputs.
        let raw = unsafe { &*((&raw const storage).cast::<sockaddr_in6>()) };
        assert_eq!(c_int::from(raw.sin6_family), AF_INET6);
        assert_eq!(u16::from_be(raw.sin6_port), 443);
        assert_eq!(raw.sin6_flowinfo, 7);
        assert_eq!(raw.sin6_scope_id, 11);
        assert_eq!(raw.sin6_addr.s6_addr, Ipv6Addr::LOCALHOST.octets());
    }

    #[test]
    fn parse_node_extracts_canonname() {
        let canonname = CString::new("localhost").unwrap();
        let mut raw_addr = sockaddr_in {
            #[cfg(any(
                target_os = "macos",
                target_os = "ios",
                target_os = "freebsd",
                target_os = "dragonfly",
                target_os = "netbsd",
                target_os = "openbsd",
            ))]
            #[allow(
                clippy::cast_possible_truncation,
                reason = "sizeof(sockaddr_in) fits in a byte by design"
            )]
            sin_len: size_of::<sockaddr_in>() as u8,
            #[allow(
                clippy::cast_possible_truncation,
                reason = "sa_family_t wide enough by design"
            )]
            sin_family: AF_INET as sa_family_t,
            sin_port: 0u16.to_be(),
            sin_addr: in_addr {
                s_addr: u32::from(Ipv4Addr::LOCALHOST).to_be(),
            },
            sin_zero: [0; 8],
        };
        let node = addrinfo {
            ai_flags: 0,
            ai_family: AF_INET,
            ai_socktype: SOCK_STREAM,
            ai_protocol: 0,
            #[allow(
                clippy::cast_possible_truncation,
                reason = "socklen_t wide enough by design"
            )]
            ai_addrlen: size_of::<sockaddr_in>() as socklen_t,
            ai_addr: (&raw mut raw_addr).cast::<sockaddr>(),
            ai_canonname: canonname.as_ptr().cast_mut(),
            ai_next: ptr::null_mut(),
        };

        // SAFETY: node points to a live sockaddr_in and canonname CString for
        // the duration of the call, matching parse_node's expectations.
        let parsed = unsafe { parse_node(&node) }.unwrap();
        assert_eq!(
            parsed.addr,
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        );
        assert_eq!(parsed.canonname.as_deref(), Some("localhost"));
        assert_eq!(parsed.socktype, SockType::Stream);
    }

    #[test]
    fn parse_node_returns_none_for_unsupported_family() {
        let node = addrinfo {
            ai_flags: 0,
            ai_family: AF_UNIX,
            ai_socktype: SOCK_STREAM,
            ai_protocol: 0,
            ai_addrlen: 0,
            ai_addr: ptr::null_mut(),
            ai_canonname: ptr::null_mut(),
            ai_next: ptr::null_mut(),
        };

        // SAFETY: parse_node returns before dereferencing ai_addr for
        // unsupported families.
        let parsed = unsafe { parse_node(&node) };
        assert!(parsed.is_none());
    }
}
