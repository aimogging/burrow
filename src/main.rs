use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use smoltcp::iface::SocketHandle;
use tokio::signal;
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use wgnat::config;
use wgnat::nat::NatTable;
use wgnat::proxy::{spawn_tcp_proxy, ProxyMsg};
use wgnat::rewrite::{self, PROTO_TCP};
use wgnat::runtime::{spawn_smoltcp, SmoltcpEvent, SmoltcpHandle};
use wgnat::tunnel::WgTunnel;

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
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,wgnat=debug")),
        )
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

    let nat = Arc::new(NatTable::new(cfg.interface.address.address));
    let tunnel = Arc::new(WgTunnel::new(&cfg).await.context("WireGuard tunnel")?);
    info!(local = %tunnel.local_addr()?, peer = %tunnel.endpoint(), "WG socket bound");

    let (smoltcp, mut events) = spawn_smoltcp(Arc::clone(&nat), cfg.interface.address);
    info!("smoltcp runtime spawned");

    tunnel
        .initiate_handshake()
        .await
        .context("initial handshake")?;
    info!("handshake initiation sent");

    // Per-connection ProxyMsg senders, keyed by smoltcp handle.
    let proxies: Arc<Mutex<HashMap<SocketHandle, mpsc::UnboundedSender<ProxyMsg>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Spawn the smoltcp egress drainer: pulls packets out of smoltcp's tx
    // queue, runs the source rewrite, encapsulates, sends through WG.
    let egress = tokio::spawn(egress_loop(
        Arc::clone(&tunnel),
        smoltcp.clone(),
        Arc::clone(&nat),
    ));

    // Spawn the smoltcp event consumer: turns runtime events into proxy
    // task lifecycle.
    let event_loop = tokio::spawn({
        let smoltcp = smoltcp.clone();
        let nat = Arc::clone(&nat);
        let proxies = Arc::clone(&proxies);
        async move {
            while let Some(evt) = events.evt_rx.recv().await {
                match evt {
                    SmoltcpEvent::TcpConnected { key, handle } => {
                        debug!(?key, ?handle, "tcp connected");
                        let tx = spawn_tcp_proxy(key, handle, smoltcp.clone(), Arc::clone(&nat));
                        proxies.lock().await.insert(handle, tx);
                    }
                    SmoltcpEvent::TcpData { key: _, handle, data } => {
                        if let Some(tx) = proxies.lock().await.get(&handle) {
                            let _ = tx.send(ProxyMsg::Data(data));
                        }
                    }
                    SmoltcpEvent::TcpFinFromPeer { handle, .. } => {
                        if let Some(tx) = proxies.lock().await.get(&handle) {
                            let _ = tx.send(ProxyMsg::PeerFin);
                        }
                    }
                    SmoltcpEvent::TcpClosed { handle, .. } => {
                        if let Some(tx) = proxies.lock().await.remove(&handle) {
                            let _ = tx.send(ProxyMsg::Closed);
                        }
                    }
                }
            }
        }
    });

    // Periodic NAT sweep.
    let sweep = tokio::spawn({
        let nat = Arc::clone(&nat);
        async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let now = std::time::Instant::now();
                let removed = nat.sweep_expired(now);
                if !removed.is_empty() {
                    debug!(count = removed.len(), "NAT entries swept (expired)");
                }
                let removed_udp = nat.sweep_udp_idle(now, wgnat::nat::DEFAULT_UDP_IDLE);
                if !removed_udp.is_empty() {
                    debug!(count = removed_udp.len(), "NAT entries swept (udp idle)");
                }
            }
        }
    });

    // Main loop: drive WG timers and process inbound packets.
    let mut timer = tokio::time::interval(Duration::from_millis(250));
    let result: Result<()> = loop {
        tokio::select! {
            biased;

            _ = signal::ctrl_c() => {
                info!("ctrl-c received, shutting down");
                break Ok(());
            }
            _ = timer.tick() => {
                if let Err(e) = tunnel.tick_timers().await {
                    warn!(error = %e, "timer tick");
                }
            }
            res = tunnel.recv_step() => {
                match res {
                    Ok(Some(pkt)) => {
                        ingest_tunnel_packet(pkt.data, &smoltcp, &nat).await;
                    }
                    Ok(None) => { /* control plane */ }
                    Err(e) => error!(error = %e, "wg recv"),
                }
            }
        }
    };

    egress.abort();
    event_loop.abort();
    sweep.abort();
    result
}

/// Take a decrypted IPv4 packet from the WG tunnel, run NAT rewrite, ensure
/// a TCP listener exists for the destination port (Phase 4: TCP only), and
/// hand the packet to smoltcp.
async fn ingest_tunnel_packet(mut packet: Vec<u8>, smoltcp: &SmoltcpHandle, nat: &Arc<NatTable>) {
    // Pre-parse the proto so we can branch (UDP/ICMP land in later phases).
    let view = match rewrite::parse_5tuple(&packet) {
        Ok(v) => v,
        Err(e) => {
            debug!(error = %e, "non-IPv4 / unparseable tunnel packet, dropping");
            return;
        }
    };
    if view.proto != PROTO_TCP {
        debug!(proto = view.proto, "non-TCP tunnel packet (Phase 4 stub: dropping)");
        return;
    }

    let key = match nat.rewrite_inbound(&mut packet) {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "nat rewrite_inbound failed");
            return;
        }
    };

    // Ensure listener exists *before* the SYN reaches the smoltcp poll.
    if nat.get(key).and_then(|e| e.smoltcp_handle).is_none() {
        match smoltcp.ensure_listener(key.local_port, key).await {
            Ok(_) => {}
            Err(_) => {
                error!(?key, "smoltcp thread dropped ensure_listener reply");
                return;
            }
        }
    }
    smoltcp.enqueue_inbound(packet);
}

async fn egress_loop(tunnel: Arc<WgTunnel>, smoltcp: SmoltcpHandle, nat: Arc<NatTable>) {
    let mut interval = tokio::time::interval(Duration::from_millis(2));
    loop {
        interval.tick().await;
        let pkts = smoltcp.drain_outbound();
        for mut pkt in pkts {
            if let Err(e) = nat.rewrite_outbound(&mut pkt) {
                debug!(error = %e, "egress rewrite (no NAT entry — likely RST for unknown flow)");
                continue;
            }
            if let Err(e) = tunnel.send_packet(&pkt).await {
                warn!(error = %e, "wg send");
            }
        }
    }
}
