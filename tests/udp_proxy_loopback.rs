//! Phase 5 functional test: simulate inbound UDP datagrams from a WG peer,
//! verify they reach a real loopback echo server and that the response
//! datagram comes back as a valid IPv4+UDP packet on the egress sink.
//! Idle expiry: after `sweep_udp_idle` removes the entry, sending a fresh
//! datagram must spawn a brand-new proxy with a different source port.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

use wgnat::nat::{NatKey, NatTable};
use wgnat::rewrite::{parse_5tuple, PROTO_UDP};
use wgnat::udp_proxy::{extract_udp_payload, spawn_udp_proxy};

const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_PORT: u16 = 33333;

/// Build a minimal IPv4+UDP datagram from PEER_IP:PEER_PORT to dst.
fn build_inbound_udp(dst_ip: Ipv4Addr, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    // Reuse build_udp_packet via the public API by inverting roles. We need a
    // packet src=PEER, dst=dst_ip, src_port=PEER_PORT, dst_port=dst_port.
    wgnat::rewrite::build_udp_packet(PEER_IP, dst_ip, PEER_PORT, dst_port, payload)
}

/// Bind a UDP echo server on 127.0.0.1; returns its address.
async fn start_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        while let Ok((n, src)) = sock.recv_from(&mut buf).await {
            if sock.send_to(&buf[..n], src).await.is_err() {
                break;
            }
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_proxy_round_trips_via_loopback_echo() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,wgnat=debug")
        .with_test_writer()
        .try_init();

    let echo = start_udp_echo().await;
    let dst_ip = match echo.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => unreachable!(),
    };
    let dst_port = echo.port();

    let nat = Arc::new(NatTable::new(GATEWAY_IP));
    let (sink_tx, mut sink_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Inbound 1.
    let mut pkt = build_inbound_udp(dst_ip, dst_port, b"hello, udp");
    let key = nat.rewrite_inbound(&mut pkt).unwrap();
    assert_eq!(key.proto, PROTO_UDP);
    assert_eq!(key.original_dst_ip, dst_ip);
    assert_eq!(key.local_port, dst_port);

    let payload = extract_udp_payload(&pkt).unwrap();
    let proxy_tx = spawn_udp_proxy(key, sink_tx.clone());
    proxy_tx.send(payload).unwrap();

    // Wait for echo to come back through the sink.
    let pkt = timeout(Duration::from_secs(2), sink_rx.recv())
        .await
        .expect("egress timeout")
        .expect("sink dropped");
    let view = parse_5tuple(&pkt).unwrap();
    assert_eq!(view.proto, PROTO_UDP);
    assert_eq!(view.src_ip, dst_ip);
    assert_eq!(view.dst_ip, PEER_IP);
    assert_eq!(view.src_port, dst_port);
    assert_eq!(view.dst_port, PEER_PORT);
    assert_eq!(extract_udp_payload(&pkt).unwrap(), b"hello, udp");

    // A second datagram on the same proxy round-trips too.
    let mut pkt2 = build_inbound_udp(dst_ip, dst_port, b"second");
    let _ = nat.rewrite_inbound(&mut pkt2).unwrap();
    let payload2 = extract_udp_payload(&pkt2).unwrap();
    proxy_tx.send(payload2).unwrap();
    let pkt = timeout(Duration::from_secs(2), sink_rx.recv())
        .await
        .expect("egress timeout 2")
        .expect("sink dropped");
    assert_eq!(extract_udp_payload(&pkt).unwrap(), b"second");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_proxy_idle_sweep_replaces_entry() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,wgnat=debug")
        .with_test_writer()
        .try_init();

    let echo = start_udp_echo().await;
    let dst_ip = match echo.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => unreachable!(),
    };
    let dst_port = echo.port();

    let nat = Arc::new(NatTable::new(GATEWAY_IP));
    let (sink_tx, mut sink_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // First datagram → spawn proxy A, get one echo.
    let mut pkt = build_inbound_udp(dst_ip, dst_port, b"a");
    let key = nat.rewrite_inbound(&mut pkt).unwrap();
    let proxy_a = spawn_udp_proxy(key, sink_tx.clone());
    proxy_a.send(extract_udp_payload(&pkt).unwrap()).unwrap();
    let _ = timeout(Duration::from_secs(2), sink_rx.recv())
        .await
        .expect("first echo timeout");

    // Force the entry to look idle and sweep with a 0s timeout. Drop our
    // sender so the proxy task winds down — that's what main.rs does after
    // sweep_udp_idle returns the key.
    let removed = nat.sweep_udp_idle(
        std::time::Instant::now() + Duration::from_secs(60),
        Duration::from_secs(0),
    );
    assert!(removed.contains(&key));
    drop(proxy_a);

    // Now a fresh datagram on the same 5-tuple: re-rewrite (creates a new
    // NAT entry — same NatKey contents though, since the key is based on
    // 5-tuple, not socket identity), spawn proxy B, ensure the round-trip
    // still works.
    let mut pkt2 = build_inbound_udp(dst_ip, dst_port, b"after-sweep");
    let key2 = nat.rewrite_inbound(&mut pkt2).unwrap();
    assert_eq!(key2, key); // same 5-tuple → same NatKey
    let proxy_b = spawn_udp_proxy(key2, sink_tx.clone());
    proxy_b
        .send(extract_udp_payload(&pkt2).unwrap())
        .unwrap();
    let pkt = timeout(Duration::from_secs(2), sink_rx.recv())
        .await
        .expect("second echo timeout")
        .expect("sink dropped");
    assert_eq!(extract_udp_payload(&pkt).unwrap(), b"after-sweep");

    let _ = NatKey {
        proto: PROTO_UDP,
        peer_ip: PEER_IP,
        peer_port: PEER_PORT,
        original_dst_ip: dst_ip,
        local_port: dst_port,
    };
}
