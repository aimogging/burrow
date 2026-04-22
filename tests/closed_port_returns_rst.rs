//! Phase 9 fix #1 regression: when the OS-side connect to the original
//! destination fails, the gateway must synthesize a TCP RST in userspace
//! and tunnel it back to the peer — never let smoltcp answer the SYN with
//! a SYN-ACK. Pre-fix nmap saw closed ports as `open` because smoltcp
//! optimistically completed the 3-way handshake before wgnat even tried
//! to connect.
//!
//! `connect_probe` itself lives in the binary (`src/main.rs`), so this
//! test exercises the same primitives it composes:
//!   * `NatTable::try_reserve_pending` claims the slot
//!   * `tokio::net::TcpStream::connect` to a guaranteed-closed port fails
//!   * `rewrite::build_tcp_rst` produces a well-formed RST packet
//!   * `NatTable::evict_key` rolls back the pending reservation
//!
//! It also asserts the RST has the right shape: flags=RST|ACK,
//! src/dst/ports as the peer would expect, ack=peer_seq+1.

use std::net::Ipv4Addr;
use std::time::Duration;

use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use wgnat::nat::{NatKey, NatTable};
use wgnat::rewrite::{build_tcp_rst, parse_5tuple, PROTO_TCP};

#[tokio::test]
async fn probe_failure_synthesizes_rst_and_releases_slot() {
    let nat = NatTable::new(Ipv4Addr::new(10, 0, 0, 2));

    // Find a guaranteed-closed loopback port: bind, capture, drop. The OS
    // usually leaves the port unbound long enough for the connect attempt
    // to be refused.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closed_port = listener.local_addr().unwrap().port();
    drop(listener);

    let key = NatKey {
        proto: PROTO_TCP,
        peer_ip: Ipv4Addr::new(10, 0, 0, 1),
        peer_port: 54321,
        original_dst_ip: Ipv4Addr::new(127, 0, 0, 1),
        original_dst_port: closed_port,
    };

    // Reserve the NAT slot like connect_probe does.
    let gw = nat
        .try_reserve_pending(key)
        .expect("reservation result")
        .expect("slot must be fresh");
    assert_eq!(nat.len(), 1);

    // Try the connect; expect refusal (or at worst a fast timeout).
    let result = timeout(Duration::from_secs(2), TcpStream::connect(("127.0.0.1", closed_port))).await;
    let connect_failed = match result {
        Ok(Ok(_)) => false,                     // someone bound it again
        Ok(Err(_)) => true,                     // connection refused
        Err(_) => true,                         // timeout (also a failure path)
    };
    assert!(
        connect_failed,
        "test setup raced — port {} was reused before we could probe it",
        closed_port
    );

    // Build and inspect the RST that connect_probe would send.
    let peer_seq: u32 = 0xDEAD_BEEF;
    let rst = build_tcp_rst(
        key.original_dst_ip,
        key.peer_ip,
        key.original_dst_port,
        key.peer_port,
        peer_seq.wrapping_add(1),
    );

    let view = parse_5tuple(&rst).expect("rst is parseable IPv4+TCP");
    assert_eq!(view.proto, PROTO_TCP);
    assert_eq!(view.src_ip, key.original_dst_ip);
    assert_eq!(view.dst_ip, key.peer_ip);
    assert_eq!(view.src_port, key.original_dst_port);
    assert_eq!(view.dst_port, key.peer_port);

    // Flags: RST | ACK = 0x14. Pre-fix the peer would have received a
    // SYN-ACK (0x12); post-fix it gets a RST and reports the port closed.
    let ihl = ((rst[0] & 0x0F) as usize) * 4;
    let flags = rst[ihl + 13];
    assert_eq!(flags, 0x14, "RST|ACK expected, got 0x{:02x}", flags);

    // Ack number must be peer_seq + 1.
    let ack = u32::from_be_bytes([rst[ihl + 8], rst[ihl + 9], rst[ihl + 10], rst[ihl + 11]]);
    assert_eq!(ack, peer_seq.wrapping_add(1));

    // Roll back the slot — connect_probe calls evict_key on failure.
    nat.evict_key(key);
    assert_eq!(nat.len(), 0, "slot must be released");

    // The released gateway_port must be free again — try_reserve_pending
    // a fresh key and observe that allocation succeeds (would fail on
    // pool exhaustion if eviction didn't return the port).
    let key2 = NatKey {
        proto: PROTO_TCP,
        peer_ip: Ipv4Addr::new(10, 0, 0, 1),
        peer_port: 54322,
        original_dst_ip: Ipv4Addr::new(127, 0, 0, 1),
        original_dst_port: closed_port,
    };
    let gw2 = nat
        .try_reserve_pending(key2)
        .expect("reservation result")
        .expect("post-eviction reservation");
    let _ = (gw, gw2);
}
