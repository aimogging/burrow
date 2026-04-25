//! Phase 1 functional test: two `WgCore` instances complete a full WireGuard
//! handshake against each other in-process, then exchange an encrypted IPv4
//! datagram. No real network, no smoltcp — just the protocol layer.
//!
//! This is the strongest correctness check we can give Phase 1 without
//! external infrastructure. If this passes, encap/decap, the boringtun
//! drain-after-WriteToNetwork contract, and key handling are all wired up
//! correctly.

use std::net::Ipv4Addr;

use burrow::config::{Config, InterfaceConfig, PeerConfig};
use burrow::tunnel::{CoreStep, WgCore};
use x25519_dalek::{PublicKey, StaticSecret};

fn build_pair() -> (WgCore, WgCore) {
    let client_secret = StaticSecret::from([0x11u8; 32]);
    let server_secret = StaticSecret::from([0x22u8; 32]);
    let client_public = PublicKey::from(&client_secret);
    let server_public = PublicKey::from(&server_secret);

    let client_cfg = Config {
        interface: InterfaceConfig {
            private_key: client_secret,
            address: "10.0.0.1/24".parse().unwrap(),
            control_port: burrow::config::DEFAULT_CONTROL_PORT,
            dns_enabled: true,
            transport: None,
            relay_token: None,
            tls_skip_verify: false,
        },
        peer: PeerConfig {
            public_key: server_public,
            endpoint: "127.0.0.1:51820".to_string(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            persistent_keepalive: None,
            preshared_key: None,
        },
    };
    let server_cfg = Config {
        interface: InterfaceConfig {
            private_key: server_secret,
            address: "10.0.0.2/24".parse().unwrap(),
            control_port: burrow::config::DEFAULT_CONTROL_PORT,
            dns_enabled: true,
            transport: None,
            relay_token: None,
            tls_skip_verify: false,
        },
        peer: PeerConfig {
            public_key: client_public,
            endpoint: "127.0.0.1:51821".to_string(),
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            persistent_keepalive: None,
            preshared_key: None,
        },
    };
    (WgCore::new(&client_cfg), WgCore::new(&server_cfg))
}

/// Pump every `to_network` packet from `from` into `to.decapsulate`,
/// and back again, until both sides report no further network traffic.
fn pump(client: &WgCore, server: &WgCore, mut step: CoreStep, mut from_client: bool) {
    let mut iters = 0;
    while !step.to_network.is_empty() {
        iters += 1;
        assert!(iters < 16, "handshake pump did not converge");
        let packets = std::mem::take(&mut step.to_network);
        let next_step_holder = if from_client {
            // Packets from client → feed each into server, accumulating outputs.
            let mut combined = CoreStep::default();
            for pkt in packets {
                let s = server.decapsulate(None, &pkt).expect("server decapsulate");
                combined.to_network.extend(s.to_network);
                if combined.to_tunnel.is_none() {
                    combined.to_tunnel = s.to_tunnel;
                }
                combined.expired |= s.expired;
            }
            combined
        } else {
            let mut combined = CoreStep::default();
            for pkt in packets {
                let s = client.decapsulate(None, &pkt).expect("client decapsulate");
                combined.to_network.extend(s.to_network);
                if combined.to_tunnel.is_none() {
                    combined.to_tunnel = s.to_tunnel;
                }
                combined.expired |= s.expired;
            }
            combined
        };
        step = next_step_holder;
        from_client = !from_client;
    }
}

#[test]
fn full_handshake_completes_between_two_cores() {
    let (client, server) = build_pair();

    // 1. Client sends handshake init.
    let init = client.handshake_init(false).expect("handshake init");
    assert_eq!(init.to_network.len(), 1);
    assert_eq!(init.to_network[0][0], 1, "type=1 INIT");

    // 2. Drive the rest of the handshake to completion. After receiving INIT,
    //    server should produce a HANDSHAKE_RESPONSE (type 2) which client decaps
    //    silently — both sides are then in ESTABLISHED.
    pump(&client, &server, init, true);

    // 3. Client encapsulates a real IP packet and server decapsulates it.
    let mut ip_packet = vec![0u8; 28]; // 20-byte IP header + 8 bytes payload
    ip_packet[0] = 0x45; // ver 4, IHL 5
    ip_packet[2] = 0x00;
    ip_packet[3] = 0x1c; // total length 28
    ip_packet[8] = 64; // TTL
    ip_packet[9] = 17; // proto = UDP
    // src = 10.0.0.1
    ip_packet[12..16].copy_from_slice(&[10, 0, 0, 1]);
    // dst = 10.0.0.2
    ip_packet[16..20].copy_from_slice(&[10, 0, 0, 2]);
    // Recompute IP header checksum.
    let csum = ip_checksum(&ip_packet[..20]);
    ip_packet[10..12].copy_from_slice(&csum.to_be_bytes());
    // 8 bytes payload (treated as opaque by boringtun)
    ip_packet[20..28].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);

    let enc = client.encapsulate(&ip_packet).expect("client encap");
    assert_eq!(enc.to_network.len(), 1, "encap should emit one ciphertext");

    let dec = server
        .decapsulate(None, &enc.to_network[0])
        .expect("server decap");
    let pkt = dec.to_tunnel.expect("server should yield a plaintext packet");
    assert_eq!(pkt.src, Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(pkt.data.len(), 28);
    assert_eq!(&pkt.data[20..28], &[0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04]);
}

fn ip_checksum(header: &[u8]) -> u16 {
    assert!(header.len() >= 20);
    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]);
        // Skip the checksum field at offset 10..12 by zeroing it: caller already does.
        sum = sum.wrapping_add(word as u32);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
