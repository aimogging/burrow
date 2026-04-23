//! Phase 11 fix #1 regression: `classify_connect_error` maps
//! `TcpStream::connect` errors to the right on-wire response policy so the
//! peer sees the truth — `closed` vs `filtered` vs ICMP unreachable — that
//! a direct route would produce.
//!
//! The actual connect is driven by the OS, so these tests exercise the
//! classification and the downstream `send_dest_unreachable` output. The
//! "probe sends nothing on filtered" case (plan ref: probe_filtered_drops_silently)
//! is covered by asserting `ConnectClass::Filtered` is what timeout/other
//! errors map to — `main.rs::connect_probe` has a `Filtered => { /* drop */ }`
//! arm that emits nothing, which is trivially correct given the mapping.

use std::io;
use std::net::Ipv4Addr;

use tokio::sync::mpsc;

use burrow::icmp::{
    send_dest_unreachable, ICMP_CODE_ADMIN_PROHIBITED, ICMP_CODE_HOST_UNREACHABLE,
    ICMP_CODE_NET_UNREACHABLE,
};
use burrow::probe::{classify_connect_error, ConnectClass};
use burrow::rewrite::{parse_5tuple, PROTO_ICMP, PROTO_TCP};

fn synthetic_os_error(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

/// Build a minimal IPv4+TCP SYN from peer → original_dst, used as the
/// "packet that triggered the probe" that `send_dest_unreachable` embeds
/// into its ICMP body per RFC 792.
fn build_syn(
    peer: Ipv4Addr,
    peer_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_TCP;
    pkt[12..16].copy_from_slice(&peer.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let mut s: u32 = 0;
    for i in (0..20).step_by(2) {
        s += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
    }
    while (s >> 16) != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    pkt[10..12].copy_from_slice(&(!(s as u16)).to_be_bytes());
    pkt[20..22].copy_from_slice(&peer_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = 0x02; // SYN
    pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
    // checksum of 0 is fine — send_dest_unreachable only reads the 5-tuple
    // fields and embeds the first 8 bytes of the TCP header; it doesn't
    // validate the TCP checksum of the embedded packet.
    pkt
}

#[test]
fn classify_matches_spec_for_all_four_classes() {
    // Linux and Windows errno values both map correctly.
    assert_eq!(
        classify_connect_error(&synthetic_os_error(111)),
        ConnectClass::Refused
    );
    assert_eq!(
        classify_connect_error(&synthetic_os_error(10061)),
        ConnectClass::Refused
    );
    assert_eq!(
        classify_connect_error(&synthetic_os_error(113)),
        ConnectClass::HostUnreachable
    );
    assert_eq!(
        classify_connect_error(&synthetic_os_error(10065)),
        ConnectClass::HostUnreachable
    );
    assert_eq!(
        classify_connect_error(&synthetic_os_error(101)),
        ConnectClass::NetUnreachable
    );
    assert_eq!(
        classify_connect_error(&synthetic_os_error(10051)),
        ConnectClass::NetUnreachable
    );
    assert_eq!(
        classify_connect_error(&synthetic_os_error(110)),
        ConnectClass::Filtered
    );
    assert_eq!(
        classify_connect_error(&synthetic_os_error(10060)),
        ConnectClass::Filtered
    );
}

#[test]
fn filtered_is_the_default_for_unknown_errors() {
    // EACCES / EPERM / anything else → drop, never misclassify as closed.
    assert_eq!(
        classify_connect_error(&synthetic_os_error(1)),
        ConnectClass::Filtered
    );
    assert_eq!(
        classify_connect_error(&synthetic_os_error(13)),
        ConnectClass::Filtered
    );
    assert_eq!(
        classify_connect_error(&synthetic_os_error(9999)),
        ConnectClass::Filtered
    );
}

/// HostUnreachable → ICMP Type 3 Code 1, src=dst, dst=peer, with the
/// original SYN's IP header + first 8 bytes embedded.
#[test]
fn host_unreachable_emits_well_formed_icmp() {
    let peer = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(192, 168, 1, 50);
    let syn = build_syn(peer, 54321, dst, 80);

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    send_dest_unreachable(&tx, &syn, ICMP_CODE_HOST_UNREACHABLE);

    let icmp_pkt = rx.try_recv().expect("ICMP packet must be emitted");
    let view = parse_5tuple(&icmp_pkt).expect("parseable IPv4 packet");
    assert_eq!(view.proto, PROTO_ICMP);
    assert_eq!(view.src_ip, dst, "src = the host we spoke for");
    assert_eq!(view.dst_ip, peer, "dst = the originating peer");

    let ihl = ((icmp_pkt[0] & 0x0F) as usize) * 4;
    assert_eq!(icmp_pkt[ihl], 3, "ICMP Type 3 (Destination Unreachable)");
    assert_eq!(icmp_pkt[ihl + 1], 1, "ICMP Code 1 (Host Unreachable)");

    // Embedded original: IP header (20 bytes) + first 8 bytes of TCP header.
    let embed_start = ihl + 8;
    assert!(
        icmp_pkt.len() >= embed_start + 28,
        "must embed at least 28 bytes of original (20 IP + 8 TCP)"
    );
    assert_eq!(
        &icmp_pkt[embed_start..embed_start + 20],
        &syn[..20],
        "embedded IP header matches original"
    );
    assert_eq!(
        &icmp_pkt[embed_start + 20..embed_start + 28],
        &syn[20..28],
        "embedded first 8 TCP bytes match original"
    );

    // No additional ICMP should be emitted.
    assert!(rx.try_recv().is_err(), "only one ICMP response expected");
}

/// NetUnreachable → ICMP Type 3 Code 0. Same packet shape, different code.
#[test]
fn net_unreachable_emits_well_formed_icmp() {
    let peer = Ipv4Addr::new(10, 0, 0, 1);
    let dst = Ipv4Addr::new(203, 0, 113, 9);
    let syn = build_syn(peer, 40000, dst, 443);

    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    send_dest_unreachable(&tx, &syn, ICMP_CODE_NET_UNREACHABLE);

    let icmp_pkt = rx.try_recv().expect("ICMP packet must be emitted");
    let ihl = ((icmp_pkt[0] & 0x0F) as usize) * 4;
    assert_eq!(icmp_pkt[ihl], 3);
    assert_eq!(icmp_pkt[ihl + 1], 0, "Code 0 = Net Unreachable");
    assert_ne!(
        ICMP_CODE_NET_UNREACHABLE, ICMP_CODE_HOST_UNREACHABLE,
        "codes must be distinct so test can tell them apart"
    );
    assert_ne!(ICMP_CODE_NET_UNREACHABLE, ICMP_CODE_ADMIN_PROHIBITED);
}

/// Sanity: probe-error classification is independent of the message content
/// of `io::Error::new`. Only `raw_os_error()` is consulted.
#[test]
fn classification_ignores_error_message() {
    let a = io::Error::other("synthetic");
    let b = io::Error::new(io::ErrorKind::TimedOut, "tokio timeout");
    // Neither carries a `raw_os_error`, so both fall into Filtered.
    assert_eq!(classify_connect_error(&a), ConnectClass::Filtered);
    assert_eq!(classify_connect_error(&b), ConnectClass::Filtered);
}
