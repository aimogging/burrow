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
//!
//! The actual bridge logic lives in `burrow::relay::serve_ws_connection`
//! so that integration tests can drive it on a plain (non-TLS) socket.

use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use tokio::net::TcpListener;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use burrow::relay::serve_ws_connection;

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
                .unwrap_or_else(|_| EnvFilter::new("info,burrow_relay=debug,burrow::relay=debug")),
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
            let _ = tcp.set_nodelay(true);
            let tls = match acceptor.accept(tcp).await {
                Ok(s) => s,
                Err(e) => {
                    debug!(%peer, error = %e, "TLS handshake failed");
                    return;
                }
            };
            debug!(%peer, "TLS handshake complete");
            match serve_ws_connection(tls, &token, forward_to).await {
                Ok(end) => info!(%peer, ?end, "WS connection closed"),
                Err(e) => debug!(%peer, error = %e, "connection ended early"),
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
