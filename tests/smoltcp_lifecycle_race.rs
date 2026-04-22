//! Regression test for the smoltcp panic introduced when stale `WriteTcp`
//! commands raced `TcpClosed` events. Pre-fix, the smoltcp thread would
//! panic with "handle does not refer to a valid socket" on
//! `sockets.get_mut(handle)` after the slot was freed, killing the whole
//! TCP path while the rest of the process kept running.
//!
//! The fix (see `src/runtime.rs`): commands carry an opaque `ConnectionId`
//! that the smoltcp thread resolves against an internal map. Stale
//! commands silently no-op.
//!
//! Strategy: spin up the runtime with no peer, register a TCP listener,
//! abort it (which transitions through Closed → emits `TcpClosed` → drops
//! the entry), then immediately fire a `WriteTcp` for the now-dead
//! `ConnectionId`. Repeat in a tight loop. Pre-fix this would panic the
//! smoltcp thread within tens of iterations; post-fix the loop completes
//! and the thread is still responsive.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use wgnat::config::Ipv4Cidr;
use wgnat::nat::{NatKey, NatTable};
use wgnat::rewrite::PROTO_TCP;
use wgnat::runtime::spawn_smoltcp;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stale_write_after_close_does_not_panic() {
    let nat = Arc::new(NatTable::new(Ipv4Addr::new(10, 0, 0, 2)));
    let cidr: Ipv4Cidr = "10.0.0.2/24".parse().unwrap();
    let (handle, _events, _tx_rx) = spawn_smoltcp(Arc::clone(&nat), cidr);

    // Many short-lived listeners. Each one is registered, immediately
    // aborted, and then we *intentionally* try to write to its (now-stale)
    // ConnectionId. Pre-fix this kills the smoltcp thread.
    for i in 0..1000u32 {
        let key = NatKey {
            proto: PROTO_TCP,
            peer_ip: Ipv4Addr::new(10, 0, 0, 1),
            peer_port: 40000 + (i as u16 & 0x7FFF),
            original_dst_ip: Ipv4Addr::new(192, 168, 1, 50),
            original_dst_port: 80,
        };
        // Register (issues a fresh ConnectionId) and tear down immediately.
        // Listener port can be anything stable for this test — it's never
        // actually receiving real packets.
        let id = handle.ensure_listener(50000 + (i as u16 & 0x3FFF), key).await.unwrap();
        handle.abort_tcp(id);

        // Race: fire writes against the id without waiting for TcpClosed.
        // Some succeed (slot still alive), some land on a stale id (no-op).
        // The point is: neither outcome may panic.
        for _ in 0..4 {
            let _ = handle.write_tcp(id, vec![0xAB; 32]).await;
        }
    }

    // Final smoke test: thread must still be alive and responsive. If it
    // panicked, this `ensure_listener` await never completes.
    let key = NatKey {
        proto: PROTO_TCP,
        peer_ip: Ipv4Addr::new(10, 0, 0, 1),
        peer_port: 12345,
        original_dst_ip: Ipv4Addr::new(192, 168, 1, 99),
        original_dst_port: 8080,
    };
    let result = tokio::time::timeout(
        Duration::from_secs(2),
        handle.ensure_listener(8080, key),
    )
    .await
    .expect("smoltcp thread must still respond to commands")
    .expect("ensure_listener must reply");
    let _ = result;
}
