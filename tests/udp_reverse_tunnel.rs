//! Phase 14 integration test: UDP reverse-tunnel dispatch end-to-end.
//!
//! Drives `dispatch_udp_to_wg_ip` directly with hand-crafted UDP
//! packets. Exercises both the forward path (peer → wgnat → forward_to
//! with ephemeral src_port allocation) and the reply path (forward_to →
//! wgnat → peer with src_port restored to listen_port).
//!
//! No smoltcp needed — UDP reverse tunnels intercept at ingest and
//! emit straight to the egress channel.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use tokio::sync::mpsc;

use wgnat::rewrite::{build_udp_packet, parse_5tuple};
use wgnat::reverse_registry::ReverseRegistry;
use wgnat::udp_reverse::{dispatch_udp_to_wg_ip, UdpReverseState};
use wgnat::wire::Proto;

const WG_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const FORWARD_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);

const LISTEN_PORT: u16 = 53;
const FORWARD_PORT: u16 = 5353;
const PEER_PORT: u16 = 44000;

#[tokio::test]
async fn udp_reverse_forward_and_reply() {
    let registry = Arc::new(ReverseRegistry::new());
    let state = Arc::new(UdpReverseState::new());
    registry
        .start(
            Proto::Udp,
            LISTEN_PORT,
            SocketAddrV4::new(FORWARD_IP, FORWARD_PORT),
        )
        .unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Phase A: peer sends UDP to (wg_ip, LISTEN_PORT). Expect wgnat to
    // emit a datagram with src=(wg_ip, ephemeral) dst=(FORWARD_IP, FORWARD_PORT).
    let query = b"DNS-LIKE-QUERY";
    let inbound = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, LISTEN_PORT, query);
    let view = parse_5tuple(&inbound).unwrap();
    dispatch_udp_to_wg_ip(&inbound, &view, WG_IP, &registry, &state, &tx, false).await;

    let forward_pkt = rx.try_recv().expect("forward datagram should be emitted");
    let fwd_view = parse_5tuple(&forward_pkt).unwrap();
    assert_eq!(fwd_view.src_ip, WG_IP);
    assert_eq!(fwd_view.dst_ip, FORWARD_IP);
    assert_eq!(fwd_view.dst_port, FORWARD_PORT);
    assert!(
        fwd_view.src_port >= 49152,
        "ephemeral src_port should be in IANA dynamic range, got {}",
        fwd_view.src_port
    );
    let fwd_payload = udp_payload(&forward_pkt);
    assert_eq!(fwd_payload, query);
    let ephemeral = fwd_view.src_port;

    // Phase B: forward_to responds. Datagram arrives at wgnat with
    // src=(FORWARD_IP, FORWARD_PORT), dst=(wg_ip, ephemeral). Expect
    // wgnat to emit a reply with src=(wg_ip, LISTEN_PORT), dst=peer.
    let answer = b"DNS-LIKE-RESPONSE";
    let reply_in = build_udp_packet(FORWARD_IP, WG_IP, FORWARD_PORT, ephemeral, answer);
    let reply_view = parse_5tuple(&reply_in).unwrap();
    dispatch_udp_to_wg_ip(&reply_in, &reply_view, WG_IP, &registry, &state, &tx, false).await;

    let reply_pkt = rx.try_recv().expect("reply datagram should be emitted");
    let reply_view = parse_5tuple(&reply_pkt).unwrap();
    assert_eq!(reply_view.src_ip, WG_IP);
    assert_eq!(reply_view.src_port, LISTEN_PORT);
    assert_eq!(reply_view.dst_ip, PEER_IP);
    assert_eq!(reply_view.dst_port, PEER_PORT);
    let reply_payload = udp_payload(&reply_pkt);
    assert_eq!(reply_payload, answer);

    // Phase C: a second datagram from the same peer should reuse the
    // same ephemeral (flow state persists).
    let q2 = b"Q2";
    let inbound2 = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, LISTEN_PORT, q2);
    let view2 = parse_5tuple(&inbound2).unwrap();
    dispatch_udp_to_wg_ip(&inbound2, &view2, WG_IP, &registry, &state, &tx, false).await;
    let fwd2 = rx.try_recv().expect("second forward should be emitted");
    let fwd2_view = parse_5tuple(&fwd2).unwrap();
    assert_eq!(
        fwd2_view.src_port, ephemeral,
        "same flow must reuse the same ephemeral port"
    );

    // Phase D: a datagram to an unregistered listen_port gets dropped.
    let bogus = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, 9999, b"nope");
    let bogus_view = parse_5tuple(&bogus).unwrap();
    dispatch_udp_to_wg_ip(&bogus, &bogus_view, WG_IP, &registry, &state, &tx, false).await;
    assert!(rx.try_recv().is_err(), "unregistered port must drop silently");

    // Phase E: a reply on an unrecognized ephemeral port also drops.
    let stale = build_udp_packet(FORWARD_IP, WG_IP, FORWARD_PORT, 58000, b"stale");
    let stale_view = parse_5tuple(&stale).unwrap();
    dispatch_udp_to_wg_ip(&stale, &stale_view, WG_IP, &registry, &state, &tx, false).await;
    assert!(rx.try_recv().is_err(), "stale ephemeral must drop silently");
}

fn udp_payload(pkt: &[u8]) -> Vec<u8> {
    // 20-byte IP header + 8-byte UDP header, payload follows.
    pkt[28..].to_vec()
}
