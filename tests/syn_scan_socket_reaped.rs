//! Phase 10 regression: an `nmap -sS`-style flow (SYN → read SYN-ACK → RST,
//! never reaching ESTABLISHED) must NOT leak smoltcp listeners and NAT
//! entries.
//!
//! Pre-fix the smoltcp listener went LISTEN → SYN-RCVD → LISTEN on RST
//! (smoltcp 0.13 socket/tcp.rs:1818-1826 explicitly resets a listener back
//! to LISTEN on RST so it can accept the next connection). Our runtime only
//! tore down conns/sockets when state reached CLOSED, so SYN-scan flows
//! parked listeners + NAT entries forever — observed in production as
//! `smoltcp cardinality sockets=N conns=N by_handle=N` stuck exactly at the
//! count of open destination ports across an nmap sweep.
//!
//! The fix: track which conns ever reached ESTABLISHED. On any backwards
//! transition (SYN-RCVD → LISTEN) or direct CLOSED transition WITHOUT
//! prior ESTABLISHED, emit `SmoltcpEvent::TcpAborted`, tear down the
//! smoltcp socket, and evict the NAT entry immediately (no grace).
//!
//! This test drives a hand-rolled SYN through the runtime, reads the
//! SYN-ACK off the egress channel, sends a RST back, and asserts:
//!   * `TcpAborted` fires within a bounded poll window
//!   * `nat.len()` returns to zero — entry was evicted
//!   * a fresh ensure_listener for a new key succeeds — no slot is wedged

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use tokio::time::timeout;

use wgnat::nat::NatTable;
use wgnat::rewrite::PROTO_TCP;
use wgnat::runtime::{spawn_smoltcp, SmoltcpEvent};

const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const ORIGINAL_DST: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 50);
const PEER_PORT: u16 = 54321;
const ORIGINAL_DST_PORT: u16 = 8080;

fn ip_checksum(hdr: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < hdr.len() {
        sum += u16::from_be_bytes([hdr[i], hdr[i + 1]]) as u32;
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp_segment: &[u8]) -> u16 {
    let mut buf = Vec::new();
    buf.extend_from_slice(&src.octets());
    buf.extend_from_slice(&dst.octets());
    buf.push(0);
    buf.push(PROTO_TCP);
    buf.extend_from_slice(&(tcp_segment.len() as u16).to_be_bytes());
    buf.extend_from_slice(tcp_segment);
    if buf.len() % 2 == 1 {
        buf.push(0);
    }
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < buf.len() {
        sum += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a minimal IPv4 + TCP packet with the given flags and seq/ack
/// numbers. dst_ip/dst_port are the *peer's* view (i.e. ORIGINAL_DST and
/// ORIGINAL_DST_PORT for inbound) — the NAT layer rewrites them.
fn build_pkt(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
) -> Vec<u8> {
    let total_len = 40usize;
    let mut pkt = vec![0u8; total_len];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = PROTO_TCP;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    let csum = ip_checksum(&pkt[0..20]);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());
    pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
    pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
    pkt[24..28].copy_from_slice(&seq.to_be_bytes());
    pkt[28..32].copy_from_slice(&ack.to_be_bytes());
    pkt[32] = 0x50; // data offset = 5
    pkt[33] = flags;
    pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
    let tcs = tcp_checksum(src, dst, &pkt[20..]);
    pkt[36..38].copy_from_slice(&tcs.to_be_bytes());
    pkt
}

#[tokio::test]
async fn syn_scan_style_rst_reaps_listener_and_nat_entry() {
    let nat = Arc::new(NatTable::new());
    let (handle, mut events, mut tx_rx) = spawn_smoltcp(Arc::clone(&nat));

    // Ingress: SYN from peer to ORIGINAL_DST:ORIGINAL_DST_PORT, NAT rewrites
    // dst to GATEWAY_IP:gateway_port.
    let mut syn = build_pkt(
        PEER_IP,
        ORIGINAL_DST,
        PEER_PORT,
        ORIGINAL_DST_PORT,
        1000,
        0,
        0x02,
    );
    let (key, virtual_ip, gateway_port) = nat.rewrite_inbound(&mut syn).unwrap();

    // Register the listener BEFORE enqueueing — same ordering as connect_probe.
    let _id = handle.ensure_listener(virtual_ip, gateway_port, key).await.unwrap();
    assert_eq!(nat.len(), 1, "NAT entry created on rewrite_inbound");

    handle.enqueue_inbound(syn);

    // Wait for SYN-ACK to land in the egress queue.
    let mut synack: Option<Vec<u8>> = None;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        if let Ok(p) = tx_rx.try_recv() {
            synack = Some(p);
            break;
        }
    }
    let mut synack = synack.expect("expected SYN-ACK from smoltcp");
    let ihl = ((synack[0] & 0x0F) as usize) * 4;
    let flags = synack[ihl + 13];
    assert_eq!(flags & 0x12, 0x12, "must be SYN-ACK, got 0x{flags:02x}");
    // smoltcp's chosen ISN — RST's seq must equal SYN-ACK's ack, RST's ack
    // must equal SYN-ACK's seq + 1 (since SYN consumes one seq).
    let smoltcp_seq = u32::from_be_bytes([
        synack[ihl + 4],
        synack[ihl + 5],
        synack[ihl + 6],
        synack[ihl + 7],
    ]);
    let smoltcp_ack = u32::from_be_bytes([
        synack[ihl + 8],
        synack[ihl + 9],
        synack[ihl + 10],
        synack[ihl + 11],
    ]);
    // Run egress rewrite to consume the by_gateway lookup; not strictly
    // necessary for this test but keeps the NAT internal state consistent
    // with what main.rs does.
    let _ = nat.rewrite_outbound(&mut synack);

    // Now send the RST — what `nmap -sS` does after seeing SYN-ACK on an
    // open port. Must be sent as if from the peer to ORIGINAL_DST so the
    // NAT inbound rewrite finds the existing entry.
    let mut rst = build_pkt(
        PEER_IP,
        ORIGINAL_DST,
        PEER_PORT,
        ORIGINAL_DST_PORT,
        smoltcp_ack,
        smoltcp_seq.wrapping_add(1),
        0x04, // RST only
    );
    let _ = nat.rewrite_inbound(&mut rst).unwrap();
    handle.enqueue_inbound(rst);

    // The runtime should observe SYN-RCVD → LISTEN, classify it as an
    // abort (never reached ESTABLISHED), emit TcpAborted, and tear down
    // the smoltcp socket + NAT entry within a few poll cycles.
    let evt = timeout(Duration::from_secs(2), events.evt_rx.recv())
        .await
        .expect("expected event within 2s")
        .expect("event channel closed");
    match evt {
        SmoltcpEvent::TcpAborted { key: k, .. } => {
            assert_eq!(k, key, "abort event for the right NatKey");
        }
        other => panic!("expected TcpAborted, got {other:?}"),
    }

    // The NAT entry must be gone — no grace window for aborted attempts.
    // Allow a few polls of slack for the eviction to land.
    let mut nat_len = nat.len();
    for _ in 0..50 {
        if nat_len == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        nat_len = nat.len();
    }
    assert_eq!(nat_len, 0, "NAT entry should be evicted after abort");

    // Sanity: the gateway_port pool isn't wedged — a fresh listener for a
    // different key allocates cleanly. (If allocation failed, this would
    // hang or panic.)
    let new_key = wgnat::nat::NatKey {
        proto: PROTO_TCP,
        peer_ip: PEER_IP,
        peer_port: PEER_PORT.wrapping_add(1),
        original_dst_ip: ORIGINAL_DST,
        original_dst_port: ORIGINAL_DST_PORT,
    };
    let mut probe_syn = build_pkt(
        PEER_IP,
        ORIGINAL_DST,
        PEER_PORT.wrapping_add(1),
        ORIGINAL_DST_PORT,
        2000,
        0,
        0x02,
    );
    let (_, new_vip, new_gw) = nat.rewrite_inbound(&mut probe_syn).unwrap();
    let _new_id = timeout(
        Duration::from_secs(1),
        handle.ensure_listener(new_vip, new_gw, new_key),
    )
    .await
    .expect("ensure_listener didn't reply within 1s")
    .expect("ensure_listener oneshot dropped");
}
