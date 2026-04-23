//! Probe-error classification — maps `io::Error` from `TcpStream::connect`
//! to the policy `connect_probe` applies on the WireGuard-peer side:
//! synthetic TCP RST, userspace ICMP unreachable, or silent drop.
//!
//! Phase 11 fix #1 preserves the natural distinction a direct route would
//! produce. The kernel's connect() enforces its own SYN-retry timeout
//! (~21s Windows / ~127s Linux); burrow does NOT overlay an artificial
//! `tokio::time::timeout`, because doing so would conflate "peer firewall
//! drops SYN" with "peer RST" — the exact signal Phase 11 is trying to
//! preserve for nmap-style scanning.

use std::io;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ConnectClass {
    /// ECONNREFUSED — destination actively refused. Mirror a TCP RST back so
    /// the peer sees `closed`, not `open`.
    Refused,
    /// EHOSTUNREACH — host unreachable (no ARP, ICMP host unreachable).
    /// Return ICMP Type 3 Code 1.
    HostUnreachable,
    /// ENETUNREACH — no route to network. Return ICMP Type 3 Code 0.
    NetUnreachable,
    /// ETIMEDOUT or an unrecognised error — drop silently so the peer sees
    /// `filtered` (its own SYN retries time out).
    Filtered,
}

pub fn classify_connect_error(err: &io::Error) -> ConnectClass {
    match err.raw_os_error() {
        // ECONNREFUSED
        Some(111) | Some(10061) => ConnectClass::Refused,
        // EHOSTUNREACH
        Some(113) | Some(10065) => ConnectClass::HostUnreachable,
        // ENETUNREACH
        Some(101) | Some(10051) => ConnectClass::NetUnreachable,
        // ETIMEDOUT — kernel gave up on SYN retransmits.
        Some(110) | Some(10060) => ConnectClass::Filtered,
        _ => ConnectClass::Filtered,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(code: i32) -> io::Error {
        io::Error::from_raw_os_error(code)
    }

    #[test]
    fn refused_on_linux_and_windows() {
        assert_eq!(classify_connect_error(&err(111)), ConnectClass::Refused);
        assert_eq!(classify_connect_error(&err(10061)), ConnectClass::Refused);
    }

    #[test]
    fn host_unreachable_on_linux_and_windows() {
        assert_eq!(
            classify_connect_error(&err(113)),
            ConnectClass::HostUnreachable
        );
        assert_eq!(
            classify_connect_error(&err(10065)),
            ConnectClass::HostUnreachable
        );
    }

    #[test]
    fn net_unreachable_on_linux_and_windows() {
        assert_eq!(
            classify_connect_error(&err(101)),
            ConnectClass::NetUnreachable
        );
        assert_eq!(
            classify_connect_error(&err(10051)),
            ConnectClass::NetUnreachable
        );
    }

    #[test]
    fn timed_out_maps_to_filtered() {
        assert_eq!(classify_connect_error(&err(110)), ConnectClass::Filtered);
        assert_eq!(classify_connect_error(&err(10060)), ConnectClass::Filtered);
    }

    #[test]
    fn unrecognised_errno_is_filtered_by_default() {
        // EACCES (13) / EPERM (1) / anything else — default to dropping, never
        // misreport a filtered port as closed.
        assert_eq!(classify_connect_error(&err(13)), ConnectClass::Filtered);
        assert_eq!(classify_connect_error(&err(1)), ConnectClass::Filtered);
        assert_eq!(classify_connect_error(&err(9999)), ConnectClass::Filtered);
    }

    #[test]
    fn no_raw_os_error_is_filtered() {
        let e = io::Error::other("synthetic");
        assert_eq!(classify_connect_error(&e), ConnectClass::Filtered);
    }
}
