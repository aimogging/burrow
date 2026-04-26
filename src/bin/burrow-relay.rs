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
//!
//! ## Embedded mode
//!
//! When built with `--features embedded-relay-bundle`, the binary has
//! its TLS materials + bearer token baked in (see Cargo.toml for the
//! list of build-time env vars). CLI args are then optional; missing
//! ones fall back to the embedded values. This pairs with `burrow-client
//! gen --relay`, which produces matching configs for both halves of the
//! transport.

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
#[cfg(not(feature = "silent"))]
use tracing_subscriber::EnvFilter;

use burrow::relay::serve_ws_connection;

#[cfg(feature = "embedded-relay-bundle")]
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_relay_bundle.rs"));
}

const EMBEDDED_TOKEN: Option<&str> = {
    #[cfg(feature = "embedded-relay-bundle")]
    {
        Some(embedded::RELAY_TOKEN)
    }
    #[cfg(not(feature = "embedded-relay-bundle"))]
    {
        None
    }
};

const EMBEDDED_CERT_PEM: Option<&str> = {
    #[cfg(feature = "embedded-relay-bundle")]
    {
        Some(embedded::RELAY_CERT_PEM)
    }
    #[cfg(not(feature = "embedded-relay-bundle"))]
    {
        None
    }
};

const EMBEDDED_KEY_PEM: Option<&str> = {
    #[cfg(feature = "embedded-relay-bundle")]
    {
        Some(embedded::RELAY_KEY_PEM)
    }
    #[cfg(not(feature = "embedded-relay-bundle"))]
    {
        None
    }
};

const EMBEDDED_LISTEN: Option<&str> = {
    #[cfg(feature = "embedded-relay-bundle")]
    {
        Some(embedded::RELAY_LISTEN)
    }
    #[cfg(not(feature = "embedded-relay-bundle"))]
    {
        None
    }
};

const EMBEDDED_FORWARD: Option<&str> = {
    #[cfg(feature = "embedded-relay-bundle")]
    {
        Some(embedded::RELAY_FORWARD)
    }
    #[cfg(not(feature = "embedded-relay-bundle"))]
    {
        None
    }
};

#[derive(Parser, Debug)]
#[command(version, about = "WSS-to-UDP relay for the burrow WireGuard transport")]
struct Cli {
    /// Address to bind the HTTPS listener on.
    #[arg(long)]
    listen: Option<SocketAddr>,

    /// Path to the TLS certificate chain (PEM). Optional under the
    /// `embedded-relay-bundle` feature; otherwise required.
    #[arg(long)]
    cert: Option<PathBuf>,

    /// Path to the TLS private key (PEM). Optional under the
    /// `embedded-relay-bundle` feature; otherwise required.
    #[arg(long)]
    key: Option<PathBuf>,

    /// Bearer token clients must present in `Authorization: Bearer <token>`.
    /// Optional under the `embedded-relay-bundle` feature; otherwise falls
    /// back to the `BURROW_RELAY_TOKEN` env var.
    #[arg(long)]
    token: Option<String>,

    /// UDP destination for WG datagrams forwarded out of WS frames.
    /// Default targets a kernel-wg listener on the same host.
    #[arg(long)]
    forward_to: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // See main.rs for why this is gated — `silent` statically disables
    // every tracing event, so installing an EnvFilter would warn that
    // its directives are unreachable.
    #[cfg(not(feature = "silent"))]
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

    let listen: SocketAddr = match cli.listen {
        Some(s) => s,
        None => EMBEDDED_LISTEN
            .unwrap_or("0.0.0.0:443")
            .parse()
            .context("parsing embedded BURROW_RELAY_EMBED_LISTEN")?,
    };
    let forward_to: SocketAddr = match cli.forward_to {
        Some(s) => s,
        None => EMBEDDED_FORWARD
            .unwrap_or("127.0.0.1:51820")
            .parse()
            .context("parsing embedded BURROW_RELAY_EMBED_FORWARD")?,
    };

    let token = match cli.token {
        Some(t) => t,
        None => match EMBEDDED_TOKEN {
            Some(t) => t.to_string(),
            None => std::env::var("BURROW_RELAY_TOKEN")
                .context("--token, BURROW_RELAY_TOKEN env var, or embedded-relay-bundle required")?,
        },
    };
    if token.is_empty() {
        bail!("bearer token must not be empty");
    }

    let tls_config = build_tls_config(cli.cert.as_ref(), cli.key.as_ref())
        .context("loading TLS materials")?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("binding {}", listen))?;
    info!(%listen, %forward_to, "burrow-relay listening");

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

fn build_tls_config(cert_path: Option<&PathBuf>, key_path: Option<&PathBuf>) -> Result<ServerConfig> {
    // Cert chain: prefer file path if given, otherwise embedded PEM.
    let cert_chain: Vec<CertificateDer<'static>> = if let Some(p) = cert_path {
        let f = std::fs::File::open(p).with_context(|| format!("opening cert file {}", p.display()))?;
        rustls_pemfile::certs(&mut BufReader::new(f))
            .collect::<std::io::Result<Vec<_>>>()
            .context("parsing cert chain PEM")?
    } else if let Some(pem) = EMBEDDED_CERT_PEM {
        rustls_pemfile::certs(&mut pem.as_bytes())
            .collect::<std::io::Result<Vec<_>>>()
            .context("parsing embedded cert chain PEM")?
    } else {
        bail!("--cert is required (or rebuild with --features embedded-relay-bundle)");
    };
    if cert_chain.is_empty() {
        bail!("no certificates found");
    }

    let private_key: PrivateKeyDer<'static> = if let Some(p) = key_path {
        let f = std::fs::File::open(p).with_context(|| format!("opening key file {}", p.display()))?;
        rustls_pemfile::private_key(&mut BufReader::new(f))
            .context("parsing private key PEM")?
            .ok_or_else(|| anyhow!("no private key found in {}", p.display()))?
    } else if let Some(pem) = EMBEDDED_KEY_PEM {
        rustls_pemfile::private_key(&mut pem.as_bytes())
            .context("parsing embedded private key PEM")?
            .ok_or_else(|| anyhow!("no private key found in embedded bundle"))?
    } else {
        bail!("--key is required (or rebuild with --features embedded-relay-bundle)");
    };

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("building TLS server config")?;
    Ok(config)
}
