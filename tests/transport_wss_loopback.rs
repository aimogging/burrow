//! Transport-layer fidelity test for the WSS path. Skips TLS (drives the
//! relay logic directly over a plain TCP stream) — this isolates the
//! WS-frame ↔ UDP-datagram bridge and the burrow-side WssTransport from
//! cert handling, which has no behavioural overlap with what we want
//! to verify here. Real WG end-to-end is exercised manually against a
//! deployed relay; see the WSS section of the README.
//!
//! Topology:
//!
//!   [test driver] ── ws:// ──► [burrow::relay::serve_ws_connection] ── UDP ──► [echo server]
//!                                                                                 │
//!   [test driver] ◄── ws:// ──── [relay's UDP recv pump] ◄──────────────────  reply
//!
//! The driver uses `WssTransport` (the production client) so what's
//! tested is the same code path that runs under burrow.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use burrow::relay::serve_ws_connection;
use burrow::transport::WgTransport;
use burrow::transport_wss::WssTransport;
use tokio::net::{TcpListener, UdpSocket};

const TOKEN: &str = "loopback-test-token";

/// Spawn a UDP "echo" server impersonating kernel wg0: every datagram
/// gets a fixed prefix prepended and sent back to the source.
async fn spawn_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1700];
        loop {
            let (n, from) = match sock.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => return,
            };
            let mut out = Vec::with_capacity(n + 6);
            out.extend_from_slice(b"ECHO::");
            out.extend_from_slice(&buf[..n]);
            let _ = sock.send_to(&out, from).await;
        }
    });
    addr
}

/// Spawn a plain (non-TLS) WS listener that runs the relay's
/// serve_ws_connection on each accepted TCP stream.
async fn spawn_relay(forward_to: SocketAddr) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (tcp, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let _ = serve_ws_connection(tcp, TOKEN, forward_to).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn wss_transport_round_trips_through_relay() {
    let echo = spawn_echo().await;
    let relay = spawn_relay(echo).await;
    let url = format!("ws://{}/v1/wg", relay);

    let transport: Arc<dyn WgTransport> = WssTransport::connect(&url, TOKEN).await.unwrap();

    // Three back-to-back round-trips. Each datagram shape is intentionally
    // different so we'd notice if frames were merged or split.
    let payloads: &[&[u8]] = &[b"hello", b"a", &[0xAA; 1200]];
    for payload in payloads {
        // Give the supervisor up to a second to come up before the first send.
        // Subsequent iterations are fast — connection is reused.
        let mut delivered = false;
        for _ in 0..40 {
            transport.send(payload).await.unwrap();
            match tokio::time::timeout(Duration::from_millis(250), transport.recv()).await {
                Ok(Ok(reply)) => {
                    let mut expected = b"ECHO::".to_vec();
                    expected.extend_from_slice(payload);
                    assert_eq!(reply, expected, "echoed payload mismatch");
                    delivered = true;
                    break;
                }
                _ => {
                    // Either the supervisor hasn't connected yet (first send
                    // gets dropped silently — see WssTransport::send) or the
                    // echo server hasn't replied yet. Spin and retry.
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
        assert!(delivered, "round-trip never completed for {:?}-byte payload", payload.len());
    }
}

#[tokio::test]
async fn wss_transport_rejected_on_wrong_token() {
    // The relay's accept_hdr_async callback returns 401 for a missing/wrong
    // bearer; tokio-tungstenite surfaces that as a connect error.
    let echo = spawn_echo().await;
    let relay = spawn_relay(echo).await;
    let url = format!("ws://{}/v1/wg", relay);

    let transport = WssTransport::connect(&url, "wrong-token").await.unwrap();

    // Supervisor will repeatedly fail to upgrade. send() is non-blocking
    // and just queues; recv() should never produce a packet.
    transport.send(b"will-not-be-delivered").await.unwrap();
    let result = tokio::time::timeout(Duration::from_millis(800), transport.recv()).await;
    assert!(result.is_err(), "recv() should have timed out — no successful upgrade");
}

#[tokio::test]
async fn wss_transport_rejected_on_wrong_path() {
    let echo = spawn_echo().await;
    let relay = spawn_relay(echo).await;
    let url = format!("ws://{}/wrong-path", relay);

    let transport = WssTransport::connect(&url, TOKEN).await.unwrap();
    transport.send(b"will-not-be-delivered").await.unwrap();
    let result = tokio::time::timeout(Duration::from_millis(800), transport.recv()).await;
    assert!(result.is_err(), "recv() should have timed out — relay rejected path");
}
