//! Relay logic shared between the `burrow-relay` binary and integration
//! tests. Generic over the IO type so production callers feed in a TLS
//! stream (`tokio_rustls::server::TlsStream<TcpStream>`) and tests feed
//! in a plain `TcpStream`.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::UdpSocket;
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as WsRequest, Response as WsResponse,
};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;
use tracing::debug;

pub const WG_ENDPOINT_PATH: &str = "/v1/wg";

/// Run the relay state machine over an already-accepted IO stream:
///   1. WebSocket upgrade. Reject with 404 unless the path is
///      `WG_ENDPOINT_PATH`; reject with 401 on bearer-token mismatch.
///   2. Bind a fresh ephemeral UDP socket on 127.0.0.1.
///   3. Bridge: WS binary frames → UDP send to `forward_to`; UDP recv
///      → WS binary frames. Returns when either side closes/errors.
///
/// Caller is responsible for transport-level concerns: TLS in production,
/// nothing in tests. Caller also picks the lifecycle: spawning per
/// connection, logging, reconnect on the burrow side.
pub async fn serve_ws_connection<S>(io: S, token: &str, forward_to: SocketAddr) -> Result<BridgeEnd>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let expected = format!("Bearer {}", token);
    let callback = move |req: &WsRequest, resp: WsResponse| -> Result<WsResponse, ErrorResponse> {
        if req.uri().path() != WG_ENDPOINT_PATH {
            return Err(WsResponse::builder()
                .status(StatusCode::NOT_FOUND)
                .body(None)
                .unwrap());
        }
        let auth = req.headers().get("Authorization").and_then(|h| h.to_str().ok());
        if auth != Some(expected.as_str()) {
            return Err(WsResponse::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(None)
                .unwrap());
        }
        Ok(resp)
    };

    let ws = tokio_tungstenite::accept_hdr_async(io, callback)
        .await
        .context("WebSocket upgrade")?;

    let udp = UdpSocket::bind("127.0.0.1:0")
        .await
        .context("binding ephemeral UDP socket")?;
    let local = udp.local_addr().ok();
    debug!(?local, "relay UDP socket bound");
    let udp = Arc::new(udp);

    Ok(bridge_ws_udp(ws, udp, forward_to).await)
}

/// Outcome of one bridged session.
#[derive(Debug)]
#[allow(dead_code)]
pub enum BridgeEnd {
    /// Peer sent Close frame or stream ended cleanly.
    WsClosed,
    /// WebSocket framing or read/write failure.
    WsError(String),
    /// Local UDP socket failure (most often: target unreachable).
    UdpError(String),
}

async fn bridge_ws_udp<S>(
    ws: tokio_tungstenite::WebSocketStream<S>,
    udp: Arc<UdpSocket>,
    forward_to: SocketAddr,
) -> BridgeEnd
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = ws.split();
    let (end_tx, mut end_rx) = tokio::sync::mpsc::channel::<BridgeEnd>(2);

    // UDP → WS pump
    let udp_recv = Arc::clone(&udp);
    let end_tx_udp = end_tx.clone();
    let udp_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 1700];
        loop {
            let n = match udp_recv.recv_from(&mut buf).await {
                Ok((n, _from)) => n,
                Err(e) => {
                    let _ = end_tx_udp
                        .send(BridgeEnd::UdpError(format!("recv_from: {e}")))
                        .await;
                    return;
                }
            };
            if let Err(e) = sink.send(Message::Binary(buf[..n].to_vec())).await {
                let _ = end_tx_udp
                    .send(BridgeEnd::WsError(format!("send: {e}")))
                    .await;
                return;
            }
        }
    });

    // WS → UDP pump
    let udp_send = Arc::clone(&udp);
    let end_tx_ws = end_tx.clone();
    let ws_to_udp = tokio::spawn(async move {
        while let Some(msg) = stream.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    let _ = end_tx_ws
                        .send(BridgeEnd::WsError(format!("recv: {e}")))
                        .await;
                    return;
                }
            };
            match msg {
                Message::Binary(data) => {
                    if let Err(e) = udp_send.send_to(&data, forward_to).await {
                        let _ = end_tx_ws
                            .send(BridgeEnd::UdpError(format!("send_to: {e}")))
                            .await;
                        return;
                    }
                }
                Message::Close(_) => {
                    let _ = end_tx_ws.send(BridgeEnd::WsClosed).await;
                    return;
                }
                _ => { /* tungstenite auto-handles ping/pong */ }
            }
        }
        let _ = end_tx_ws.send(BridgeEnd::WsClosed).await;
    });

    let end = end_rx.recv().await.unwrap_or(BridgeEnd::WsClosed);
    udp_to_ws.abort();
    ws_to_udp.abort();
    end
}
