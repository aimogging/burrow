//! WebSocket-over-HTTPS transport. Carries WG datagrams as binary WS frames
//! (one frame == one datagram) over a TLS connection to `burrow-relay`,
//! which sits next to kernel `wg0` on the WG server box.
//!
//! ## Why this exists
//!
//! Networks that aggressively NAT or block UDP often still allow egress
//! 443. WSS is a "transport of last resort" for the server↔burrow leg —
//! the client↔server leg stays plain WG/UDP, so client-side configuration
//! is unaffected. See `PIVOT.md` for the full rationale.
//!
//! ## Lifecycle and reconnect
//!
//! A single supervisor task owns the live WebSocket connection. The
//! `WssTransport` handle is just a pair of channels (outbound queue,
//! inbound queue). Connect errors and mid-session disconnects are
//! retried with capped exponential backoff. Packets queued during a
//! disconnect are bounded — if we're offline long enough that the
//! channel fills, new outbound packets are dropped; WG's own retransmit
//! handles the loss the same way it would for a UDP packet on the
//! floor. Re-establishment goes back through a fresh WG handshake from
//! kernel `wg0`'s side.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use tokio::sync::{mpsc, Mutex};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

use crate::transport::WgTransport;

/// Bounded outbound queue. WG datagrams are at most ~1.5 KB; 64 entries
/// is enough for typical bursts but small enough that a long disconnect
/// doesn't pile up megabytes of stale ciphertext that won't decrypt
/// anyway after the session expires.
const SEND_QUEUE_DEPTH: usize = 64;

/// Inbound queue. Same reasoning — keep it small so we don't hold onto
/// stale packets across reconnects.
const RECV_QUEUE_DEPTH: usize = 64;

const INITIAL_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

pub struct WssTransport {
    out_tx: mpsc::Sender<Vec<u8>>,
    in_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
}

impl WssTransport {
    /// Construct a WSS transport pointing at `url` (must be `wss://...`).
    /// Returns once the supervisor task is spawned — the first connect
    /// happens asynchronously in the background, so this never blocks
    /// the caller on a network round-trip. recv() will simply return
    /// nothing until the supervisor establishes the first session.
    pub async fn connect(url: &str, token: &str) -> Result<Arc<Self>> {
        if !url.starts_with("wss://") && !url.starts_with("ws://") {
            bail!("WSS transport URL must start with wss:// or ws:// (got `{url}`)");
        }
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(SEND_QUEUE_DEPTH);
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(RECV_QUEUE_DEPTH);
        let url = url.to_string();
        let token = token.to_string();
        tokio::spawn(async move {
            supervise(url, token, out_rx, in_tx).await;
        });
        Ok(Arc::new(Self {
            out_tx,
            in_rx: Mutex::new(in_rx),
        }))
    }
}

#[async_trait]
impl WgTransport for WssTransport {
    async fn send(&self, packet: &[u8]) -> std::io::Result<()> {
        // try_send rather than send().await: if the supervisor is offline
        // and the queue has filled, drop this packet rather than block
        // the caller waiting for a reconnect that may take 30s+. WG will
        // retransmit from its own state machine.
        match self.out_tx.try_send(packet.to_vec()) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                tracing::debug!("wss send queue full — dropping packet");
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "wss supervisor task exited",
            )),
        }
    }

    async fn recv(&self) -> std::io::Result<Vec<u8>> {
        let mut rx = self.in_rx.lock().await;
        rx.recv().await.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "wss supervisor task exited",
            )
        })
    }
}

/// Long-lived task that owns the WS connection. Reconnects with capped
/// exponential backoff. Exits cleanly when the `WssTransport` handle is
/// dropped (out_rx returns None) or when forwarding to the inbound queue
/// fails (in_rx side dropped).
async fn supervise(
    url: String,
    token: String,
    mut out_rx: mpsc::Receiver<Vec<u8>>,
    in_tx: mpsc::Sender<Vec<u8>>,
) {
    let mut delay = INITIAL_BACKOFF;
    loop {
        let ws = match connect_with_token(&url, &token).await {
            Ok(ws) => {
                tracing::info!(url = %url, "wss connected");
                delay = INITIAL_BACKOFF;
                ws
            }
            Err(e) => {
                tracing::warn!(error = %e, ?delay, "wss connect failed; backing off");
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = out_rx.recv() => {
                        // sender side dropped during backoff → exit
                        return;
                    }
                }
                delay = (delay * 2).min(MAX_BACKOFF);
                continue;
            }
        };

        match run_session(ws, &mut out_rx, &in_tx).await {
            SessionEnd::HandleDropped => return,
            SessionEnd::ConsumerDropped => return,
            SessionEnd::TransportError(e) => {
                tracing::warn!(error = %e, "wss session ended; reconnecting");
            }
            SessionEnd::PeerClosed => {
                tracing::info!("wss closed by peer; reconnecting");
            }
        }

        tokio::select! {
            _ = tokio::time::sleep(delay) => {}
            _ = out_rx.recv() => return,
        }
        delay = (delay * 2).min(MAX_BACKOFF);
    }
}

enum SessionEnd {
    /// The `WssTransport` handle was dropped (`out_rx` returned None).
    HandleDropped,
    /// The consumer of inbound packets disappeared (`in_tx.send` failed).
    /// Treated like HandleDropped — no point reconnecting.
    ConsumerDropped,
    /// Underlying WS framing or I/O error. Reconnect.
    TransportError(String),
    /// Peer sent a Close frame or the stream ended cleanly. Reconnect.
    PeerClosed,
}

async fn run_session(
    ws: WebSocket,
    out_rx: &mut mpsc::Receiver<Vec<u8>>,
    in_tx: &mpsc::Sender<Vec<u8>>,
) -> SessionEnd {
    // Splitting locks the inner stream behind a mutex; only one of (sink,
    // stream) can be polled at a time. WG traffic is far below WS frame
    // throughput so the contention isn't measurable.
    let (mut sink, mut stream) = ws.split();
    loop {
        tokio::select! {
            biased;
            packet = out_rx.recv() => {
                let Some(packet) = packet else {
                    return SessionEnd::HandleDropped;
                };
                if let Err(e) = sink.send(Message::Binary(packet)).await {
                    return SessionEnd::TransportError(format!("ws send: {e}"));
                }
            }
            inbound = stream.next() => match inbound {
                Some(Ok(Message::Binary(data))) => {
                    if in_tx.send(data).await.is_err() {
                        return SessionEnd::ConsumerDropped;
                    }
                }
                Some(Ok(Message::Close(_))) | None => {
                    return SessionEnd::PeerClosed;
                }
                Some(Ok(_)) => {
                    // Ignore text/ping/pong — tungstenite auto-handles ping/pong
                    // at the protocol level; text on a binary channel is a peer
                    // bug we don't care about.
                }
                Some(Err(e)) => {
                    return SessionEnd::TransportError(format!("ws recv: {e}"));
                }
            }
        }
    }
}

type WebSocket = tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
>;

async fn connect_with_token(url: &str, token: &str) -> Result<WebSocket> {
    let mut request = url
        .into_client_request()
        .with_context(|| format!("invalid WS URL: {url}"))?;
    let header_value = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|e| anyhow!("invalid bearer token (must be ASCII): {e}"))?;
    request.headers_mut().insert("Authorization", header_value);
    let (ws, _resp) = tokio_tungstenite::connect_async(request)
        .await
        .with_context(|| format!("connecting to {url}"))?;
    Ok(ws)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connect_rejects_non_ws_url() {
        let result = WssTransport::connect("https://example.com/v1/wg", "tok").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn send_after_supervisor_offline_drops_silently() {
        // No relay reachable at this address — supervisor will keep failing
        // to connect. send() should not block, just drop packets.
        let t = WssTransport::connect("ws://127.0.0.1:1/v1/wg", "tok")
            .await
            .unwrap();
        // Several sends in quick succession. None should error or hang.
        for _ in 0..10 {
            t.send(b"x").await.expect("send must not error");
        }
    }
}
