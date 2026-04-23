//! Phase 15 integration test: DNS service on `(wg_ip, 53/udp)`.
//!
//! A peer sends a standard DNS A query in a UDP datagram to
//! `wg_ip:53`. burrow's ingest dispatcher sees the port, delegates to
//! `dns_service::handle_query` (which uses `tokio::net::lookup_host` on
//! the local machine), wraps the response in a UDP+IP frame, and emits
//! it on the egress channel. The test asserts that the response is
//! well-formed and contains the expected A record.
//!
//! Under the client-originated tunnel model, a registered UDP reverse
//! tunnel does NOT originate an outbound UDP packet; instead, its
//! `UdpTunnelHandle` receives `(peer_ip, peer_port, payload)`. The
//! mock tunnels in the 2nd/3rd tests stub the handle with a plain
//! channel and assert delivery.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::sync::mpsc;

use burrow::control::{UdpTunnelHandle, UdpTunnelMap};
use burrow::reverse_registry::{OpenRequest, ReverseRegistry, SubstreamOpener};
use burrow::rewrite::{build_udp_packet, parse_5tuple};
use burrow::udp_reverse::dispatch_udp_to_wg_ip;
use burrow::wire::{BindAddr, Proto, TunnelId};

const WG_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER_PORT: u16 = 45000;

fn build_a_query(name: &str) -> Vec<u8> {
    let mut m = Message::new();
    m.set_id(0x5a5a);
    m.set_recursion_desired(true);
    let mut q = Query::new();
    q.set_name(Name::from_ascii(name).unwrap());
    q.set_query_type(RecordType::A);
    q.set_query_class(DNSClass::IN);
    m.add_query(q);
    m.to_bytes().unwrap()
}

/// Stub the things a real `control::start_tunnel` would wire up:
///   * a `SubstreamOpener` the registry can store (never used here)
///   * a `UdpTunnelHandle` that funnels `(peer_ip, peer_port, payload)`
///     into a test channel, inserted into the `UdpTunnelMap` so ingest
///     finds it.
fn stub_tunnel(
    tunnel_id: TunnelId,
    udp_tunnels: &UdpTunnelMap,
) -> mpsc::UnboundedReceiver<(Ipv4Addr, u16, Vec<u8>)> {
    let (handle, rx): (UdpTunnelHandle, _) = mpsc::unbounded_channel();
    udp_tunnels.lock().unwrap().insert(tunnel_id, handle);
    rx
}

fn dummy_opener() -> SubstreamOpener {
    let (tx, _rx) = mpsc::unbounded_channel::<OpenRequest>();
    tx
}

#[tokio::test]
async fn dns_resolves_localhost_through_dispatch() {
    let registry = Arc::new(ReverseRegistry::new());
    let udp_tunnels: UdpTunnelMap = Arc::new(Mutex::new(HashMap::new()));
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Peer sends a DNS query for "localhost" to wg_ip:53.
    let query = build_a_query("localhost.");
    let inbound = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, 53, &query);
    let view = parse_5tuple(&inbound).unwrap();
    dispatch_udp_to_wg_ip(&inbound, &view, WG_IP, &registry, &udp_tunnels, &tx, true).await;

    // Response packet should have src=(wg_ip, 53), dst=(peer, PEER_PORT).
    let resp_pkt = rx.try_recv().expect("DNS response should be emitted");
    let resp_view = parse_5tuple(&resp_pkt).unwrap();
    assert_eq!(resp_view.src_ip, WG_IP);
    assert_eq!(resp_view.src_port, 53);
    assert_eq!(resp_view.dst_ip, PEER_IP);
    assert_eq!(resp_view.dst_port, PEER_PORT);

    // DNS payload: 20-byte IP header + 8-byte UDP header, then DNS message.
    let dns_payload = &resp_pkt[28..];
    let response = Message::from_bytes(dns_payload).unwrap();
    assert_eq!(response.id(), 0x5a5a);
    assert_eq!(response.response_code(), ResponseCode::NoError);
    let answers: Vec<Ipv4Addr> = response
        .answers()
        .iter()
        .filter_map(|r| match r.data() {
            Some(RData::A(a)) => Some(a.0),
            _ => None,
        })
        .collect();
    assert!(
        answers.iter().any(|a| *a == Ipv4Addr::new(127, 0, 0, 1)),
        "expected 127.0.0.1 in answers, got {:?}",
        answers
    );
}

#[tokio::test]
async fn dns_disabled_passes_port_53_to_reverse_registry() {
    // With dns_enabled=false, port 53 is just another UDP port — if a
    // reverse tunnel is registered there, the datagram should land on
    // that tunnel's UdpTunnelHandle.
    let registry = Arc::new(ReverseRegistry::new());
    let udp_tunnels: UdpTunnelMap = Arc::new(Mutex::new(HashMap::new()));
    let tunnel_id = registry
        .start(
            Proto::Udp,
            53,
            BindAddr::Default,
            "10.0.0.3:5353".to_string(),
            dummy_opener(),
        )
        .unwrap();
    let mut handle_rx = stub_tunnel(tunnel_id, &udp_tunnels);
    let (tx, _rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let query = build_a_query("localhost.");
    let inbound = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, 53, &query);
    let view = parse_5tuple(&inbound).unwrap();
    dispatch_udp_to_wg_ip(&inbound, &view, WG_IP, &registry, &udp_tunnels, &tx, false).await;

    let (peer_ip, peer_port, payload) =
        handle_rx.try_recv().expect("forwarded to reverse tunnel");
    assert_eq!(peer_ip, PEER_IP);
    assert_eq!(peer_port, PEER_PORT);
    assert_eq!(payload, query);
}

#[tokio::test]
async fn reverse_tunnel_on_port_53_overrides_dns_even_when_enabled() {
    // Registering a reverse UDP tunnel on port 53 takes precedence over
    // DNS even when dns_enabled=true — the registry lookup runs before
    // the DNS fallback in dispatch order.
    let registry = Arc::new(ReverseRegistry::new());
    let udp_tunnels: UdpTunnelMap = Arc::new(Mutex::new(HashMap::new()));
    let tunnel_id = registry
        .start(
            Proto::Udp,
            53,
            BindAddr::Default,
            "10.0.0.3:5353".to_string(),
            dummy_opener(),
        )
        .unwrap();
    let mut handle_rx = stub_tunnel(tunnel_id, &udp_tunnels);
    let (tx, _rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let query = build_a_query("localhost.");
    let inbound = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, 53, &query);
    let view = parse_5tuple(&inbound).unwrap();
    dispatch_udp_to_wg_ip(&inbound, &view, WG_IP, &registry, &udp_tunnels, &tx, true).await;

    let (_, _, payload) = handle_rx.try_recv().expect("forwarded to reverse tunnel");
    assert_eq!(
        payload, query,
        "reverse tunnel must win over DNS"
    );
}
