//! Phase 11 fix #2: (virtual_ip, gateway_port) allocator spans the full
//! 198.18.0.0/15 × 65535-port space, so the identifier ceiling moves from
//! ~32K to ~8.6 billion slots per protocol. This test drives 100K distinct
//! flows through the NAT table from one peer_port to 100K destinations and
//! asserts:
//!   * all 100K coexist
//!   * every (virtual_ip, gateway_port) pair is unique
//!   * egress rewrite restores the right (src_ip, src_port) per flow
//!
//! syn_collision_storm.rs covers the 256-flow one-subnet variant (the
//! realistic nmap workload); this test stresses the allocator past the
//! old gateway_port-only ceiling of 32K-per-peer.

use std::collections::HashSet;
use std::net::Ipv4Addr;

use wgnat::nat::NatTable;
use wgnat::rewrite::{parse_5tuple, PROTO_TCP};

fn build_tcp_syn(src: Ipv4Addr, dst: Ipv4Addr, src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_TCP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let mut s: u32 = 0;
    for i in (0..20).step_by(2) {
        s += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
    }
    while (s >> 16) != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    pkt[10..12].copy_from_slice(&(!(s as u16)).to_be_bytes());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = 0x02; // SYN
    pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
    // Pseudo-header TCP checksum.
    let tcp_len = 20u16;
    let mut buf = Vec::new();
    buf.extend_from_slice(&pkt[12..16]);
    buf.extend_from_slice(&pkt[16..20]);
    buf.push(0);
    buf.push(PROTO_TCP);
    buf.extend_from_slice(&tcp_len.to_be_bytes());
    buf.extend_from_slice(&pkt[20..]);
    let mut c: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        c += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    while (c >> 16) != 0 {
        c = (c & 0xFFFF) + (c >> 16);
    }
    pkt[36..38].copy_from_slice(&(!(c as u16)).to_be_bytes());
    pkt
}

/// 100K distinct destinations from ONE (peer_ip, peer_port, dst_port). Pre
/// Phase 11 the allocator topped out at ~32K; post-Phase 11 the (vip, port)
/// Cartesian gives billions of slots.
#[test]
fn hundred_thousand_flows_coexist_with_distinct_identifiers() {
    let peer_ip = Ipv4Addr::new(10, 0, 0, 1);
    let peer_port: u16 = 49152;
    let dst_port: u16 = 443;
    let nat = NatTable::new();

    // Fan out across 100.64.0.0/14 (CGN shared address space — plenty large,
    // never collides with the virtual 198.18.0.0/15 pool). 100K = 0x18696
    // addresses within the first half of that /14.
    const N: u32 = 100_000;
    let mut seen: HashSet<(Ipv4Addr, u16)> = HashSet::with_capacity(N as usize);
    let mut flows: Vec<(Ipv4Addr, Ipv4Addr, u16)> = Vec::with_capacity(N as usize);

    for i in 0..N {
        let octets = (0x64_40_00_00u32 + i).to_be_bytes();
        let dst = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);
        let mut syn = build_tcp_syn(peer_ip, dst, peer_port, dst_port);
        let (key, vip, gw) = nat
            .rewrite_inbound(&mut syn)
            .expect("rewrite must succeed under allocator headroom");
        assert_eq!(key.original_dst_ip, dst);
        assert_eq!(key.original_dst_port, dst_port);
        assert!(
            seen.insert((vip, gw)),
            "endpoint collision: ({}, {}) reused at iteration {} (dst {})",
            vip,
            gw,
            i,
            dst
        );
        flows.push((dst, vip, gw));
    }

    assert_eq!(nat.len(), N as usize, "all {} flows must coexist", N);
    assert_eq!(seen.len(), N as usize, "allocator must issue distinct ids");

    // Spot-check egress on a sample of flows — doing all 100K is slow for
    // little additional coverage, and the syn_collision_storm test already
    // verifies full-fanout egress at 256 entries.
    let samples = [0usize, 1, 1234, 50_000, (N as usize) - 1];
    for &idx in &samples {
        let (expected_dst_ip, vip, gw) = flows[idx];
        let mut eg = build_tcp_syn(vip, peer_ip, gw, peer_port);
        let restored = nat.rewrite_outbound(&mut eg).expect("egress lookup");
        assert_eq!(restored.original_dst_ip, expected_dst_ip);
        let view = parse_5tuple(&eg).unwrap();
        assert_eq!(view.src_ip, expected_dst_ip);
        assert_eq!(view.src_port, dst_port);
    }
}
