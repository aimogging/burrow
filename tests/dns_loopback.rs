//! Phase 15 integration test: DNS service on `(wg_ip, 53/udp)`.
//!
//! A peer sends a standard DNS A query in a UDP datagram to
//! `wg_ip:53`. wgnat's ingest dispatcher sees the port, delegates to
//! `dns_service::handle_query` (which uses `tokio::net::lookup_host` on
//! the local machine), wraps the response in a UDP+IP frame, and emits
//! it on the egress channel. The test asserts that the response is
//! well-formed and contains the expected A record.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::sync::mpsc;

use wgnat::rewrite::{build_udp_packet, parse_5tuple};
use wgnat::reverse_registry::ReverseRegistry;
use wgnat::udp_reverse::{dispatch_udp_to_wg_ip, UdpReverseState};
use wgnat::wire::Proto;

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

#[tokio::test]
async fn dns_resolves_localhost_through_dispatch() {
    let registry = Arc::new(ReverseRegistry::new());
    let state = Arc::new(UdpReverseState::new());
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Peer sends a DNS query for "localhost" to wg_ip:53.
    let query = build_a_query("localhost.");
    let inbound = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, 53, &query);
    let view = parse_5tuple(&inbound).unwrap();
    dispatch_udp_to_wg_ip(&inbound, &view, WG_IP, &registry, &state, &tx, true).await;

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
    // reverse tunnel is registered there it should forward normally.
    let registry = Arc::new(ReverseRegistry::new());
    let state = Arc::new(UdpReverseState::new());
    registry
        .register(
            Proto::Udp,
            53,
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 5353),
        )
        .unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let query = build_a_query("localhost.");
    let inbound = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, 53, &query);
    let view = parse_5tuple(&inbound).unwrap();
    dispatch_udp_to_wg_ip(&inbound, &view, WG_IP, &registry, &state, &tx, false).await;

    let fwd = rx.try_recv().expect("forwarded to reverse tunnel");
    let fwd_view = parse_5tuple(&fwd).unwrap();
    assert_eq!(fwd_view.src_ip, WG_IP);
    assert_eq!(fwd_view.dst_ip, Ipv4Addr::new(10, 0, 0, 3));
    assert_eq!(fwd_view.dst_port, 5353);
}

#[tokio::test]
async fn reverse_tunnel_on_port_53_overrides_dns_even_when_enabled() {
    // Registering a reverse UDP tunnel on port 53 takes precedence over
    // DNS even when dns_enabled=true (the registered tunnel's forward
    // path runs first in the dispatch order).
    let registry = Arc::new(ReverseRegistry::new());
    let state = Arc::new(UdpReverseState::new());
    registry
        .register(
            Proto::Udp,
            53,
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 5353),
        )
        .unwrap();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let query = build_a_query("localhost.");
    let inbound = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, 53, &query);
    let view = parse_5tuple(&inbound).unwrap();
    dispatch_udp_to_wg_ip(&inbound, &view, WG_IP, &registry, &state, &tx, true).await;

    let fwd = rx.try_recv().expect("forwarded to reverse tunnel");
    let fwd_view = parse_5tuple(&fwd).unwrap();
    assert_eq!(
        fwd_view.dst_ip,
        Ipv4Addr::new(10, 0, 0, 3),
        "reverse tunnel must win over DNS"
    );
}
