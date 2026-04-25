//! `burrow-relay` — sidecar for the WG server box that bridges incoming
//! HTTPS WebSocket connections to local UDP datagrams aimed at kernel
//! `wg0` (or another WG implementation listening on UDP).
//!
//! One WS frame in == one WG datagram out. Authentication is a single
//! shared bearer token; kernel WG still does its own per-peer crypto auth,
//! so the relay just bridges bytes after the token check.
//!
//! Per accepted connection:
//!   1. TLS-accept the TCP stream.
//!   2. Run the WebSocket upgrade. Reject if the path != `/v1/wg` or the
//!      `Authorization: Bearer <token>` header is missing/wrong.
//!   3. Bind a fresh ephemeral UDP socket on 127.0.0.1.
//!   4. Bridge: WS binary frames → UDP send (to `--forward-to`); UDP
//!      recv → WS binary frames.
//!   5. The kernel auto-learns the burrow peer's "endpoint" as
//!      `127.0.0.1:<ephemeral_port>` from the first inbound packet —
//!      same path it would take if a NAT rebinding moved the peer's
//!      apparent source. The relay never has to call `wg set ... endpoint`.

use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use futures::{SinkExt, StreamExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::handshake::server::{
    ErrorResponse, Request as WsRequest, Response as WsResponse,
};
use tokio_tungstenite::tungstenite::http::StatusCode;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

const WG_ENDPOINT_PATH: &str = "/v1/wg";

#[derive(Parser, Debug)]
#[command(version, about = "WSS-to-UDP relay for the burrow WireGuard transport")]
struct Cli {
    /// Address to bind the HTTPS listener on.
    #[arg(long, default_value = "0.0.0.0:443")]
    listen: SocketAddr,

    /// Path to the TLS certificate chain (PEM).
    #[arg(long)]
    cert: PathBuf,

    /// Path to the TLS private key (PEM).
    #[arg(long)]
    key: PathBuf,

    /// Bearer token clients must present in `Authorization: Bearer <token>`.
    /// Falls back to the `BURROW_RELAY_TOKEN` env var if not provided.
    #[arg(long)]
    token: Option<String>,

    /// UDP destination for WG datagrams forwarded out of WS frames.
    /// Default targets a kernel-wg listener on the same host.
    #[arg(long, default_value = "127.0.0.1:51820")]
    forward_to: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,burrow_relay=debug")),
        )
        .init();

    // rustls 0.23 requires installing a default crypto provider once
    // before any ServerConfig::builder() call. The `ring` feature on
    // tokio-rustls pulls in the matching backend.
    tokio_rustls::rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow!("failed to install rustls ring crypto provider"))?;

    let cli = Cli::parse();
    let token = match cli.token.clone() {
        Some(t) => t,
        None => std::env::var("BURROW_RELAY_TOKEN")
            .context("--token or BURROW_RELAY_TOKEN env var required")?,
    };
    if token.is_empty() {
        bail!("bearer token must not be empty");
    }

    let tls_config = build_tls_config(&cli.cert, &cli.key).context("loading TLS materials")?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("binding {}", cli.listen))?;
    info!(listen = %cli.listen, forward_to = %cli.forward_to, "burrow-relay listening");

    let token = Arc::new(token);
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let token = Arc::clone(&token);
        let forward_to = cli.forward_to;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(tcp, peer, acceptor, token, forward_to).await {
                debug!(%peer, error = %e, "connection ended");
            }
        });
    }
}

fn build_tls_config(cert_path: &PathBuf, key_path: &PathBuf) -> Result<ServerConfig> {
    let cert_file = std::fs::File::open(cert_path)
        .with_context(|| format!("opening cert file {}", cert_path.display()))?;
    let mut cert_reader = BufReader::new(cert_file);
    let cert_chain: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<std::io::Result<Vec<_>>>()
        .context("parsing cert chain PEM")?;
    if cert_chain.is_empty() {
        bail!("no certificates found in {}", cert_path.display());
    }

    let key_file = std::fs::File::open(key_path)
        .with_context(|| format!("opening key file {}", key_path.display()))?;
    let mut key_reader = BufReader::new(key_file);
    let private_key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_reader)
        .context("parsing private key PEM")?
        .ok_or_else(|| anyhow!("no private key found in {}", key_path.display()))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("building TLS server config")?;
    Ok(config)
}

async fn handle_connection(
    tcp: TcpStream,
    peer: SocketAddr,
    acceptor: TlsAcceptor,
    token: Arc<String>,
    forward_to: SocketAddr,
) -> Result<()> {
    let _ = tcp.set_nodelay(true);
    let tls = acceptor.accept(tcp).await.context("TLS accept")?;
    debug!(%peer, "TLS handshake complete");

    let expected = format!("Bearer {}", token);
    let callback = move |req: &WsRequest, resp: WsResponse| -> Result<WsResponse, ErrorResponse> {
        if req.uri().path() != WG_ENDPOINT_PATH {
            let body = WsResponse::builder()
                .status(StatusCode::NOT_FOUND)
                .body(None)
                .unwrap();
            return Err(body);
        }
        let auth = req.headers().get("Authorization").and_then(|h| h.to_str().ok());
        if auth != Some(expected.as_str()) {
            let body = WsResponse::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(None)
                .unwrap();
            return Err(body);
        }
        Ok(resp)
    };

    let ws = tokio_tungstenite::accept_hdr_async(tls, callback)
        .await
        .context("WebSocket upgrade")?;
    info!(%peer, "WS connection established");

    let udp = UdpSocket::bind("127.0.0.1:0")
        .await
        .context("binding ephemeral UDP socket")?;
    let local = udp.local_addr().context("ephemeral UDP local_addr")?;
    debug!(%peer, %local, "UDP socket bound");
    let udp = Arc::new(udp);

    let result = bridge(ws, udp, forward_to).await;
    info!(%peer, "WS connection closed: {:?}", result);
    Ok(())
}

// String fields are surfaced via the Debug formatter in the info! log
// when a session ends; the compiler's dead-code pass doesn't follow
// derived Debug into format args, hence the allow.
#[derive(Debug)]
#[allow(dead_code)]
enum BridgeEnd {
    WsClosed,
    WsError(String),
    UdpError(String),
}

async fn bridge(
    ws: tokio_tungstenite::WebSocketStream<tokio_rustls::server::TlsStream<TcpStream>>,
    udp: Arc<UdpSocket>,
    forward_to: SocketAddr,
) -> BridgeEnd {
    let (mut sink, mut stream) = ws.split();
    let udp_recv = Arc::clone(&udp);

    // UDP → WS pump: read datagrams off the ephemeral socket, frame as
    // WS Binary. Runs as a separate task so neither direction blocks the
    // other. Communication back to the main task is via a oneshot
    // channel that signals which side ended the session.
    let (end_tx, mut end_rx) = tokio::sync::mpsc::channel::<BridgeEnd>(2);
    let end_tx_udp = end_tx.clone();
    let udp_to_ws = tokio::spawn(async move {
        let mut buf = vec![0u8; 1700];
        loop {
            let (n, _from) = match udp_recv.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(e) => {
                    let _ = end_tx_udp.send(BridgeEnd::UdpError(format!("recv_from: {e}"))).await;
                    return;
                }
            };
            let frame = Message::Binary(buf[..n].to_vec());
            if let Err(e) = sink.send(frame).await {
                let _ = end_tx_udp.send(BridgeEnd::WsError(format!("send: {e}"))).await;
                return;
            }
        }
    });

    let end_tx_ws = end_tx.clone();
    let udp_send = Arc::clone(&udp);
    let ws_to_udp = tokio::spawn(async move {
        while let Some(msg) = stream.next().await {
            let msg = match msg {
                Ok(m) => m,
                Err(e) => {
                    let _ = end_tx_ws.send(BridgeEnd::WsError(format!("recv: {e}"))).await;
                    return;
                }
            };
            match msg {
                Message::Binary(data) => {
                    if let Err(e) = udp_send.send_to(&data, forward_to).await {
                        let _ = end_tx_ws.send(BridgeEnd::UdpError(format!("send_to: {e}"))).await;
                        return;
                    }
                }
                Message::Close(_) => {
                    let _ = end_tx_ws.send(BridgeEnd::WsClosed).await;
                    return;
                }
                _ => { /* ignore text/ping/pong; tungstenite auto-responds to ping */ }
            }
        }
        let _ = end_tx_ws.send(BridgeEnd::WsClosed).await;
    });

    let end = end_rx.recv().await.unwrap_or(BridgeEnd::WsClosed);
    udp_to_ws.abort();
    ws_to_udp.abort();
    end
}
