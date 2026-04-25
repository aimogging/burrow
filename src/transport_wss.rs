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
use tokio_tungstenite::Connector;

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
        Self::connect_with(url, token, false).await
    }

    /// Like `connect` but with the option to skip TLS certificate
    /// verification. Required when the relay is using a self-signed
    /// cert (the typical embed-mode deployment) — pairs with the
    /// `gen --relay` workflow that produces matching binaries with
    /// the cert baked into burrow-relay and `TlsSkipVerify=true` baked
    /// into burrow.
    pub async fn connect_with(url: &str, token: &str, tls_skip_verify: bool) -> Result<Arc<Self>> {
        if !url.starts_with("wss://") && !url.starts_with("ws://") {
            bail!("WSS transport URL must start with wss:// or ws:// (got `{url}`)");
        }
        if tls_skip_verify && url.starts_with("ws://") {
            tracing::warn!("--tls-skip-verify with ws:// URL has no effect (no TLS to skip)");
        }
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(SEND_QUEUE_DEPTH);
        let (in_tx, in_rx) = mpsc::channel::<Vec<u8>>(RECV_QUEUE_DEPTH);
        let url = url.to_string();
        let token = token.to_string();
        let connector = if tls_skip_verify {
            Some(no_verify_connector()?)
        } else {
            None
        };
        tokio::spawn(async move {
            supervise(url, token, connector, out_rx, in_tx).await;
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
    connector: Option<Connector>,
    mut out_rx: mpsc::Receiver<Vec<u8>>,
    in_tx: mpsc::Sender<Vec<u8>>,
) {
    let mut delay = INITIAL_BACKOFF;
    loop {
        let ws = match connect_with_token(&url, &token, connector.clone()).await {
            Ok(ws) => {
                tracing::info!(url = %url, "wss connected");
                delay = INITIAL_BACKOFF;
                ws
            }
            Err(e) => {
                tracing::warn!(error = %e, ?delay, "wss connect failed; backing off");
                tokio::time::sleep(delay).await;
                if out_rx.is_closed() {
                    return;
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

        tokio::time::sleep(delay).await;
        if out_rx.is_closed() {
            return;
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

async fn connect_with_token(
    url: &str,
    token: &str,
    connector: Option<Connector>,
) -> Result<WebSocket> {
    let mut request = url
        .into_client_request()
        .with_context(|| format!("invalid WS URL: {url}"))?;
    let header_value = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|e| anyhow!("invalid bearer token (must be ASCII): {e}"))?;
    request.headers_mut().insert("Authorization", header_value);
    let (ws, _resp) = tokio_tungstenite::connect_async_tls_with_config(
        request, None, false, connector,
    )
    .await
    .with_context(|| format!("connecting to {url}"))?;
    Ok(ws)
}

/// Build a tokio-tungstenite `Connector::Rustls` whose verifier accepts any
/// server certificate. Used by `--tls-skip-verify` so a relay running with a
/// freshly-generated self-signed cert is reachable without operator-side
/// trust glue. This degrades the TLS layer to obfuscation only — anyone
/// who can MITM the wire can impersonate the relay. The bearer token
/// remains the only meaningful auth.
fn no_verify_connector() -> Result<Connector> {
    use tokio_rustls::rustls;
    // rustls 0.23 requires a default crypto provider before any
    // ClientConfig::builder() call. Idempotent — we don't care if it's
    // already installed elsewhere in the process.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoCertVerifier))
        .with_no_client_auth();
    Ok(Connector::Rustls(Arc::new(config)))
}

#[derive(Debug)]
struct NoCertVerifier;

impl tokio_rustls::rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::ServerCertVerified,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> std::result::Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        Ok(tokio_rustls::rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        use tokio_rustls::rustls::SignatureScheme as S;
        vec![
            S::ECDSA_NISTP256_SHA256,
            S::ECDSA_NISTP384_SHA384,
            S::ED25519,
            S::RSA_PKCS1_SHA256,
            S::RSA_PKCS1_SHA384,
            S::RSA_PSS_SHA256,
            S::RSA_PSS_SHA384,
        ]
    }
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
