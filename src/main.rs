use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use wgnat::config;
use wgnat::tunnel::WgTunnel;

/// WireGuard userspace NAT gateway — connects outbound to a WireGuard server
/// and proxies traffic from peers to internal hosts via real OS sockets. No
/// TUN interface, no kernel drivers.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// Path to a wg-quick style configuration file.
    #[arg(short, long)]
    config: PathBuf,

    /// Override the peer endpoint from the config file (host:port).
    #[arg(long)]
    endpoint: Option<String>,

    /// Override PersistentKeepalive (seconds; 0 disables).
    #[arg(long)]
    keepalive: Option<u16>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,wgnat=debug")))
        .init();

    let cli = Cli::parse();
    let mut cfg = config::load(&cli.config)
        .with_context(|| format!("loading config from {}", cli.config.display()))?;

    if let Some(ep) = cli.endpoint {
        cfg.peer.endpoint = ep;
    }
    if let Some(ka) = cli.keepalive {
        cfg.peer.persistent_keepalive = if ka == 0 { None } else { Some(ka) };
    }

    info!(
        endpoint = %cfg.peer.endpoint,
        address = %cfg.interface.address,
        keepalive = ?cfg.peer.persistent_keepalive,
        "starting wgnat"
    );

    let tunnel = WgTunnel::new(&cfg)
        .await
        .context("constructing WireGuard tunnel")?;

    info!(local = %tunnel.local_addr()?, peer = %tunnel.endpoint(), "WireGuard socket bound");
    tunnel
        .initiate_handshake()
        .await
        .context("sending initial handshake")?;
    info!("handshake initiation sent");

    let mut timer = tokio::time::interval(Duration::from_millis(250));

    loop {
        tokio::select! {
            biased;

            _ = signal::ctrl_c() => {
                info!("ctrl-c received, shutting down");
                return Ok(());
            }

            _ = timer.tick() => {
                if let Err(e) = tunnel.tick_timers().await {
                    warn!(error = %e, "timer tick failed");
                }
            }

            res = tunnel.recv_step() => {
                match res {
                    Ok(Some(pkt)) => {
                        // Phase 1 stub: log the decrypted packet. Phase 2 hands
                        // this off to the rewrite shim and smoltcp.
                        debug!(
                            src = %pkt.src,
                            len = pkt.data.len(),
                            "rx tunnel packet (Phase 1: dropped)"
                        );
                    }
                    Ok(None) => {
                        // Control-plane traffic (handshake response, cookie,
                        // keepalive). flush_to_network already handled it.
                    }
                    Err(e) => {
                        error!(error = %e, "recv_step failed");
                    }
                }
            }
        }
    }
}
