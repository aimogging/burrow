//! Phase 12 integration test: wgnat originates an outbound TCP connection
//! on its WG IP and completes the handshake against a hand-rolled peer that
//! replies with SYN-ACK. Verifies:
//!   * `SmoltcpHandle::open_outbound_tcp` returns a fresh `ConnectionId`.
//!   * smoltcp emits a SYN with `src_ip = wg_ip` — the foundational guarantee
//!     that makes reverse tunnels (Phase 13) and DNS (Phase 15) routable
//!     through the WG peer's `AllowedIPs`.
//!   * After a valid SYN-ACK is enqueued, smoltcp fires `TcpConnected` for
//!     the outbound id and emits the final ACK.
//!
//! No boringtun layer here — this test sits directly against the smoltcp
//! runtime the same way `tests/tcp_proxy_loopback.rs` does. The WG
//! handshake is already covered by `handshake_loopback.rs`; this test
//! isolates the new originated-flow plumbing.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use wgnat::nat::NatTable;
use wgnat::rewrite::{parse_5tuple, PROTO_TCP};
use wgnat::runtime::{spawn_smoltcp, SmoltcpEvent};
use wgnat::test_helpers::{build_tcp, ACK, SYN};

const WG_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER_PORT: u16 = 8080;

/// Build a SYN-ACK in reply to a SYN that carried `peer_seq`, bound for
/// `wg_ip:wg_port` coming back from `peer_ip:peer_port`. Lifted from the
/// same pattern as `runtime::tests::build_tcp_syn`.
fn build_synack(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
) -> Vec<u8> {
    build_tcp(src, dst, src_port, dst_port, seq, ack, SYN | ACK, &[])
}

/// Extract the TCP seq number from a 20-byte-IP + 20-byte-TCP packet.
fn tcp_seq(pkt: &[u8]) -> u32 {
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    u32::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5], pkt[ihl + 6], pkt[ihl + 7]])
}

fn tcp_flags(pkt: &[u8]) -> u8 {
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    pkt[ihl + 13]
}

#[tokio::test]
async fn originated_tcp_completes_handshake() {
    let nat = Arc::new(NatTable::new());
    let (handle, mut events, mut tx_rx) = spawn_smoltcp(Arc::clone(&nat), WG_IP);

    // Let smoltcp bind its interface address before we ask it to connect.
    tokio::time::sleep(Duration::from_millis(20)).await;

    // Port 0 tells smoltcp to pick any local port — but smoltcp 0.13 doesn't
    // accept zero on listen endpoints in all code paths; pick a concrete
    // ephemeral port so the test is deterministic.
    let local_port: u16 = 49152;
    let id = handle
        .open_outbound_tcp(
            SocketAddrV4::new(WG_IP, local_port),
            SocketAddrV4::new(PEER_IP, PEER_PORT),
        )
        .await
        .expect("open_outbound_tcp returns a ConnectionId");

    // Drain tx_rx until we see the SYN from wgnat.
    let mut syn = None;
    for _ in 0..200 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        if let Ok(p) = tx_rx.try_recv() {
            syn = Some(p);
            break;
        }
    }
    let syn = syn.expect("smoltcp should emit a SYN for the originated connect");

    let view = parse_5tuple(&syn).expect("SYN is parseable");
    assert_eq!(view.proto, PROTO_TCP);
    assert_eq!(view.src_ip, WG_IP, "src must be wg_ip so WG server routes it");
    assert_eq!(view.src_port, local_port);
    assert_eq!(view.dst_ip, PEER_IP);
    assert_eq!(view.dst_port, PEER_PORT);
    assert_eq!(tcp_flags(&syn) & 0x3F, 0x02, "SYN only");

    // Craft a SYN-ACK for smoltcp's SYN. ack = wgnat_seq + 1.
    let wg_seq = tcp_seq(&syn);
    let peer_seq: u32 = 0xDEAD_BEEF;
    let synack = build_synack(
        PEER_IP,
        WG_IP,
        PEER_PORT,
        local_port,
        peer_seq,
        wg_seq.wrapping_add(1),
    );
    handle.enqueue_inbound(synack);

    // Expect the TcpConnected event for *this* id.
    let mut connected = false;
    for _ in 0..200 {
        match tokio::time::timeout(Duration::from_millis(5), events.evt_rx.recv()).await {
            Ok(Some(SmoltcpEvent::TcpConnected { id: got_id, .. })) if got_id == id => {
                connected = true;
                break;
            }
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => continue,
        }
    }
    assert!(connected, "TcpConnected must fire for originated id");

    // smoltcp should also emit a final ACK completing the 3-way handshake,
    // again with src=wg_ip. Drain up to a few frames.
    let mut saw_ack = false;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(5)).await;
        if let Ok(p) = tx_rx.try_recv() {
            let v = parse_5tuple(&p).unwrap();
            assert_eq!(v.src_ip, WG_IP, "ACK must also have src=wg_ip");
            let flags = tcp_flags(&p);
            if flags & 0x10 != 0 && flags & 0x02 == 0 {
                saw_ack = true;
                break;
            }
        }
    }
    assert!(saw_ack, "smoltcp must send the final ACK to complete the handshake");
}
