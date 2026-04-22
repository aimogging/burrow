//! Phase 9 fix #2 regression: nmap-style scan that reuses ONE source port
//! across many destinations on the SAME dst_port must produce one distinct
//! NAT entry per (peer, peer_port, dst_ip, dst_port) — not silently evict
//! the prior in-flight flow.
//!
//! Pre-fix: NAT keyed on (proto, peer_ip, peer_port, dst_port). 256
//! distinct dst_ip's collided on the index, eviction left only the last
//! one alive. SRV02 stress test confirmed this: only DC01 (kept warm by
//! a long-lived hold) showed open ports through wgnat; DC02..SRV03 all
//! filtered.
//!
//! Post-fix: each flow gets a per-flow `gateway_port` from the 32768..=65535
//! pool. All 256 entries coexist; egress on any of them restores the
//! correct (src_ip, src_port) pair for that specific flow.

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
    let mut sum: u32 = 0;
    for i in (0..20).step_by(2) {
        sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    pkt[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[32] = 0x50;
    pkt[33] = 0x02; // SYN
    pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
    let tcp_len = 20u16;
    let mut buf = Vec::new();
    buf.extend_from_slice(&pkt[12..16]);
    buf.extend_from_slice(&pkt[16..20]);
    buf.push(0);
    buf.push(PROTO_TCP);
    buf.extend_from_slice(&tcp_len.to_be_bytes());
    buf.extend_from_slice(&pkt[20..]);
    let mut s: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        s += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    while (s >> 16) != 0 {
        s = (s & 0xFFFF) + (s >> 16);
    }
    pkt[36..38].copy_from_slice(&(!(s as u16)).to_be_bytes());
    pkt
}

#[test]
fn nmap_style_syn_storm_preserves_every_flow() {
    let smoltcp_addr = Ipv4Addr::new(10, 0, 0, 2);
    let peer_ip = Ipv4Addr::new(10, 0, 0, 1);
    let peer_port: u16 = 54321;
    let dst_port: u16 = 80;
    let nat = NatTable::new(smoltcp_addr);

    // 256 distinct destinations, ONE peer source port, SAME dst_port.
    // This is exactly the nmap -sS pattern that broke pre-Phase-9.
    let mut gateway_ports = std::collections::HashSet::new();
    let mut packets_per_dst = Vec::new();
    for i in 0..=255u8 {
        let dst = Ipv4Addr::new(192, 168, 1, i);
        let mut syn = build_tcp_syn(peer_ip, dst, peer_port, dst_port);
        let (key, gw) = nat
            .rewrite_inbound(&mut syn)
            .expect("rewrite must succeed");
        assert_eq!(key.original_dst_ip, dst);
        assert_eq!(key.original_dst_port, dst_port);
        assert!(
            gateway_ports.insert(gw),
            "gateway_port {} reused for dst {} (collides with prior flow)",
            gw,
            dst
        );
        packets_per_dst.push((dst, gw, syn));
    }

    // All 256 flows must coexist.
    assert_eq!(nat.len(), 256, "every distinct flow must have its own NAT entry");

    // Egress: simulate smoltcp emitting a SYN-ACK for each flow. Outbound
    // packet has src=(smoltcp_addr, gateway_port), dst=(peer_ip, peer_port).
    // After rewrite_outbound, src must be restored to the ORIGINAL dst_ip
    // for that specific flow — proves the egress lookup picks the right
    // entry out of 256 candidates.
    for (expected_dst_ip, gw, _syn) in &packets_per_dst {
        let mut eg = build_tcp_syn(smoltcp_addr, peer_ip, *gw, peer_port);
        let restored = nat.rewrite_outbound(&mut eg).expect("egress lookup");
        assert_eq!(
            restored.original_dst_ip, *expected_dst_ip,
            "egress on gateway_port {} should restore src to {}",
            gw, expected_dst_ip
        );
        let view = parse_5tuple(&eg).unwrap();
        assert_eq!(view.src_ip, *expected_dst_ip);
        assert_eq!(view.src_port, dst_port);
    }
}
