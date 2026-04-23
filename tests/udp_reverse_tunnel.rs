//! Phase 14 integration test: UDP reverse-tunnel ingest dispatch.
//!
//! Under the client-originated tunnel model, wgnat does NOT originate
//! UDP toward `forward_to`. Instead, a peer datagram to a registered
//! `(wg_ip, listen_port)` gets pushed into the owning client's
//! `UdpTunnelHandle` via the `UdpTunnelMap` side-table. The owning
//! client reads the framed datagram off its yamux substream and dials
//! `forward_to` from its own machine.
//!
//! This test drives `dispatch_udp_to_wg_ip` directly and asserts the
//! tunnel handle receives the expected `(peer_ip, peer_port, payload)`.
//! The reply path (substream bytes → outbound UDP packet) lives in
//! `control::spawn_udp_side` and is exercised by the end-to-end
//! reverse-tunnel tests.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use tokio::sync::mpsc;

use wgnat::control::{UdpTunnelHandle, UdpTunnelMap};
use wgnat::reverse_registry::{OpenRequest, ReverseRegistry, SubstreamOpener};
use wgnat::rewrite::{build_udp_packet, parse_5tuple};
use wgnat::udp_reverse::dispatch_udp_to_wg_ip;
use wgnat::wire::{BindAddr, Proto, TunnelId};

const WG_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const LISTEN_PORT: u16 = 53;
const PEER_PORT: u16 = 44000;

fn dummy_opener() -> SubstreamOpener {
    let (tx, _rx) = mpsc::unbounded_channel::<OpenRequest>();
    tx
}

fn install_tunnel(
    registry: &Arc<ReverseRegistry>,
    udp_tunnels: &UdpTunnelMap,
    listen_port: u16,
    forward_to: &str,
) -> (TunnelId, mpsc::UnboundedReceiver<(Ipv4Addr, u16, Vec<u8>)>) {
    let tunnel_id = registry
        .start(
            Proto::Udp,
            listen_port,
            BindAddr::Default,
            forward_to.to_string(),
            dummy_opener(),
        )
        .unwrap();
    let (handle, rx): (UdpTunnelHandle, _) = mpsc::unbounded_channel();
    udp_tunnels.lock().unwrap().insert(tunnel_id, handle);
    (tunnel_id, rx)
}

#[tokio::test]
async fn udp_reverse_forwards_to_tunnel_handle() {
    let registry = Arc::new(ReverseRegistry::new());
    let udp_tunnels: UdpTunnelMap = Arc::new(Mutex::new(HashMap::new()));
    let (_, mut handle_rx) =
        install_tunnel(&registry, &udp_tunnels, LISTEN_PORT, "10.0.0.3:5353");
    let (egress_tx, mut egress_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Peer sends UDP to (wg_ip, LISTEN_PORT).
    let query = b"DNS-LIKE-QUERY";
    let inbound = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, LISTEN_PORT, query);
    let view = parse_5tuple(&inbound).unwrap();
    dispatch_udp_to_wg_ip(&inbound, &view, WG_IP, &registry, &udp_tunnels, &egress_tx, false)
        .await;

    // The owning client's handle should receive the framed datagram.
    let (peer_ip, peer_port, payload) =
        handle_rx.try_recv().expect("tunnel handle should receive the datagram");
    assert_eq!(peer_ip, PEER_IP);
    assert_eq!(peer_port, PEER_PORT);
    assert_eq!(payload, query);

    // No outbound UDP packet should leave wgnat — the client is the
    // origination point under the new model.
    assert!(
        egress_rx.try_recv().is_err(),
        "wgnat must not originate UDP in the client-originated model"
    );

    // A second datagram on the same flow goes through the same handle.
    let q2 = b"Q2";
    let inbound2 = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, LISTEN_PORT, q2);
    let view2 = parse_5tuple(&inbound2).unwrap();
    dispatch_udp_to_wg_ip(&inbound2, &view2, WG_IP, &registry, &udp_tunnels, &egress_tx, false)
        .await;
    let (_, _, p2) = handle_rx.try_recv().expect("second datagram delivered");
    assert_eq!(p2, q2);
}

#[tokio::test]
async fn udp_to_unregistered_port_drops_silently() {
    let registry = Arc::new(ReverseRegistry::new());
    let udp_tunnels: UdpTunnelMap = Arc::new(Mutex::new(HashMap::new()));
    let (egress_tx, mut egress_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let bogus = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, 9999, b"nope");
    let view = parse_5tuple(&bogus).unwrap();
    dispatch_udp_to_wg_ip(&bogus, &view, WG_IP, &registry, &udp_tunnels, &egress_tx, false)
        .await;

    assert!(
        egress_rx.try_recv().is_err(),
        "datagrams to unregistered ports must not generate egress"
    );
}

#[tokio::test]
async fn udp_with_missing_tunnel_handle_drops_silently() {
    // Registry knows about the tunnel but the side-table handle isn't
    // installed yet (racy startup window). Ingest must not panic; the
    // datagram is dropped.
    let registry = Arc::new(ReverseRegistry::new());
    let udp_tunnels: UdpTunnelMap = Arc::new(Mutex::new(HashMap::new()));
    registry
        .start(
            Proto::Udp,
            LISTEN_PORT,
            BindAddr::Default,
            "10.0.0.3:5353".to_string(),
            dummy_opener(),
        )
        .unwrap();
    let (egress_tx, mut egress_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let inbound = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, LISTEN_PORT, b"orphan");
    let view = parse_5tuple(&inbound).unwrap();
    dispatch_udp_to_wg_ip(&inbound, &view, WG_IP, &registry, &udp_tunnels, &egress_tx, false)
        .await;
    assert!(egress_rx.try_recv().is_err());
}
