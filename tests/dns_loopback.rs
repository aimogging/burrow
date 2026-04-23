//! DNS service test: `dispatch_udp_to_wg_ip` answers A queries to
//! `(wg_ip, 53/udp)` by calling the host's system resolver and
//! framing the response back onto the egress channel. Everything
//! else gets dropped silently — reverse UDP tunnels live on real OS
//! `UdpSocket`s now, so they do not flow through this dispatcher.

use std::net::Ipv4Addr;

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::sync::mpsc;

use burrow::rewrite::{build_udp_packet, parse_5tuple};
use burrow::udp_reverse::dispatch_udp_to_wg_ip;

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
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let query = build_a_query("localhost.");
    let inbound = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, 53, &query);
    let view = parse_5tuple(&inbound).unwrap();
    dispatch_udp_to_wg_ip(&inbound, &view, WG_IP, &tx, true).await;

    let resp_pkt = rx.try_recv().expect("DNS response should be emitted");
    let resp_view = parse_5tuple(&resp_pkt).unwrap();
    assert_eq!(resp_view.src_ip, WG_IP);
    assert_eq!(resp_view.src_port, 53);
    assert_eq!(resp_view.dst_ip, PEER_IP);
    assert_eq!(resp_view.dst_port, PEER_PORT);

    // 20-byte IP header + 8-byte UDP header, then DNS message.
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
async fn dns_disabled_drops_port_53_silently() {
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let query = build_a_query("localhost.");
    let inbound = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, 53, &query);
    let view = parse_5tuple(&inbound).unwrap();
    dispatch_udp_to_wg_ip(&inbound, &view, WG_IP, &tx, false).await;

    assert!(
        rx.try_recv().is_err(),
        "DNS disabled should drop port-53 datagrams silently"
    );
}

#[tokio::test]
async fn non_dns_udp_to_wg_ip_is_dropped() {
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();

    let junk = b"not dns";
    let inbound = build_udp_packet(PEER_IP, WG_IP, PEER_PORT, 9999, junk);
    let view = parse_5tuple(&inbound).unwrap();
    dispatch_udp_to_wg_ip(&inbound, &view, WG_IP, &tx, true).await;

    assert!(
        rx.try_recv().is_err(),
        "non-DNS UDP to wg_ip should drop silently"
    );
}
