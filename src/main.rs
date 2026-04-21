use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use tokio::signal;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use wgnat::config;
use wgnat::icmp::IcmpForwarder;
use wgnat::nat::{NatKey, NatTable};
use wgnat::proxy::{spawn_tcp_proxy, ProxyMsg};
use wgnat::rewrite::{self, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use wgnat::runtime::{spawn_smoltcp, SmoltcpEvent, SmoltcpHandle};
use wgnat::tunnel::WgTunnel;
use wgnat::udp_proxy::{extract_udp_payload, spawn_udp_proxy};

/// `udp_proxies` is touched on every UDP packet (ingress task) and on the
/// 10s NAT sweep — real but minimal contention. `std::sync::Mutex` is the
/// right tool: critical sections are bounded HashMap ops with no `.await`
/// held; tokio's Mutex pays for park/unpark uncontended for no benefit.
type UdpProxyMap = Arc<Mutex<HashMap<NatKey, mpsc::UnboundedSender<Vec<u8>>>>>;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Run the NAT gateway against a wg-quick style config.
    Run {
        /// Path to a wg-quick style configuration file.
        #[arg(short, long)]
        config: PathBuf,

        /// Override the peer endpoint from the config file (host:port).
        #[arg(long)]
        endpoint: Option<String>,

        /// Override PersistentKeepalive (seconds; 0 disables).
        #[arg(long)]
        keepalive: Option<u16>,
    },
    /// Generate an x25519 keypair (base64) for use in a wg-quick config.
    Keygen,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen => return keygen(),
        Cmd::Run { config, endpoint, keepalive } => run(config, endpoint, keepalive).await,
    }
}

fn keygen() -> Result<()> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("OS RNG: {e}"))?;
    let secret = x25519_dalek::StaticSecret::from(bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    let b64 = base64::engine::general_purpose::STANDARD;
    println!("PrivateKey = {}", b64.encode(secret.to_bytes()));
    println!("PublicKey  = {}", b64.encode(public.as_bytes()));
    Ok(())
}

async fn run(
    config_path: PathBuf,
    endpoint: Option<String>,
    keepalive: Option<u16>,
) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,wgnat=debug")),
        )
        .init();

    let mut cfg = config::load(&config_path)
        .with_context(|| format!("loading config from {}", config_path.display()))?;

    if let Some(ep) = endpoint {
        cfg.peer.endpoint = ep;
    }
    if let Some(ka) = keepalive {
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

    let (smoltcp, mut events, smoltcp_tx_rx) =
        spawn_smoltcp(Arc::clone(&nat), cfg.interface.address);
    info!("smoltcp runtime spawned");

    tunnel
        .initiate_handshake()
        .await
        .context("initial handshake")?;
    info!("handshake initiation sent");

    // Per-NAT-entry UDP forwarders. Sender accepts raw payloads; the proxy
    // task sends them to (original_dst_ip, local_port) and pushes responses
    // (as fully formed IPv4+UDP packets) onto `egress_tx`.
    let udp_proxies: UdpProxyMap = Arc::new(Mutex::new(HashMap::new()));
    // Single shared egress channel for both UDP and ICMP — they both want to
    // emit fully formed IPv4 packets back through the tunnel.
    let (egress_tx, mut egress_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let direct_egress = tokio::spawn({
        let tunnel = Arc::clone(&tunnel);
        async move {
            while let Some(pkt) = egress_rx.recv().await {
                if let Err(e) = tunnel.send_packet(&pkt).await {
                    warn!(error = %e, "direct egress tunnel send");
                }
            }
        }
    });

    // Probe at startup; logs which mode we're in and (if Raw) spawns the
    // raw-socket reader + pending sweeper.
    let icmp = Arc::new(IcmpForwarder::probe(egress_tx.clone()));

    // Spawn the smoltcp egress drainer: receives packets straight off the
    // device tx channel, runs the source rewrite, encapsulates, sends through WG.
    let egress = tokio::spawn(egress_loop(
        Arc::clone(&tunnel),
        smoltcp_tx_rx,
        Arc::clone(&nat),
    ));

    // Spawn the smoltcp event consumer: turns runtime events into proxy
    // task lifecycle. The `proxies` map lives entirely inside this closure
    // — only one task touches it, so plain HashMap is correct.
    let event_loop = tokio::spawn({
        let smoltcp = smoltcp.clone();
        let nat = Arc::clone(&nat);
        async move {
            let mut proxies: HashMap<
                wgnat::runtime::ConnectionId,
                mpsc::UnboundedSender<ProxyMsg>,
            > = HashMap::new();
            while let Some(evt) = events.evt_rx.recv().await {
                match evt {
                    SmoltcpEvent::TcpConnected { key, id } => {
                        debug!(?key, ?id, "tcp connected");
                        let tx = spawn_tcp_proxy(key, id, smoltcp.clone(), Arc::clone(&nat));
                        proxies.insert(id, tx);
                    }
                    SmoltcpEvent::TcpData { id, data, .. } => {
                        if let Some(tx) = proxies.get(&id) {
                            let _ = tx.send(ProxyMsg::Data(data));
                        }
                    }
                    SmoltcpEvent::TcpFinFromPeer { id, .. } => {
                        if let Some(tx) = proxies.get(&id) {
                            let _ = tx.send(ProxyMsg::PeerFin);
                        }
                    }
                    SmoltcpEvent::TcpClosed { id, .. } => {
                        if let Some(tx) = proxies.remove(&id) {
                            let _ = tx.send(ProxyMsg::Closed);
                        }
                    }
                }
            }
        }
    });

    // Periodic NAT sweep. Idle UDP entries also drop their proxy sender,
    // which closes the channel and lets the proxy task wind down.
    let sweep = tokio::spawn({
        let nat = Arc::clone(&nat);
        let udp_proxies = Arc::clone(&udp_proxies);
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
                    let mut map = udp_proxies.lock().unwrap();
                    for k in &removed_udp {
                        map.remove(k);
                    }
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
                        ingest_tunnel_packet(
                            pkt.data,
                            &smoltcp,
                            &nat,
                            &udp_proxies,
                            &egress_tx,
                            &icmp,
                        ).await;
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
    direct_egress.abort();
    result
}

/// Take a decrypted IPv4 packet from the WG tunnel, run NAT rewrite, and
/// dispatch by protocol: TCP into smoltcp, UDP into the per-entry forwarder.
/// ICMP lands in Phase 6.
async fn ingest_tunnel_packet(
    mut packet: Vec<u8>,
    smoltcp: &SmoltcpHandle,
    nat: &Arc<NatTable>,
    udp_proxies: &UdpProxyMap,
    egress_tx: &mpsc::UnboundedSender<Vec<u8>>,
    icmp: &Arc<IcmpForwarder>,
) {
    let view = match rewrite::parse_5tuple(&packet) {
        Ok(v) => v,
        Err(e) => {
            debug!(error = %e, "non-IPv4 / unparseable tunnel packet, dropping");
            return;
        }
    };
    match view.proto {
        PROTO_TCP => {
            let key = match nat.rewrite_inbound(&mut packet) {
                Ok(k) => k,
                Err(e) => {
                    warn!(error = %e, "nat rewrite_inbound (tcp) failed");
                    return;
                }
            };
            // Ensure listener exists *before* the SYN reaches the smoltcp poll.
            if nat.get(key).and_then(|e| e.smoltcp_id).is_none()
                && smoltcp.ensure_listener(key.local_port, key).await.is_err()
            {
                error!(?key, "smoltcp thread dropped ensure_listener reply");
                return;
            }
            smoltcp.enqueue_inbound(packet);
        }
        PROTO_UDP => {
            let key = match nat.rewrite_inbound(&mut packet) {
                Ok(k) => k,
                Err(e) => {
                    warn!(error = %e, "nat rewrite_inbound (udp) failed");
                    return;
                }
            };
            let payload = match extract_udp_payload(&packet) {
                Some(p) => p,
                None => {
                    debug!(?key, "malformed udp datagram");
                    return;
                }
            };
            let tx = {
                let mut map = udp_proxies.lock().unwrap();
                map.entry(key)
                    .or_insert_with(|| spawn_udp_proxy(key, egress_tx.clone()))
                    .clone()
            };
            if tx.send(payload).is_err() {
                // Stale proxy sender — its task already exited. Drop the entry
                // so the next datagram spawns a fresh one.
                udp_proxies.lock().unwrap().remove(&key);
            }
        }
        PROTO_ICMP => {
            icmp.handle_inbound(packet).await;
        }
        other => {
            debug!(proto = other, "unsupported proto, dropping");
        }
    }
}

async fn egress_loop(
    tunnel: Arc<WgTunnel>,
    mut tx_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    nat: Arc<NatTable>,
) {
    while let Some(mut pkt) = tx_rx.recv().await {
        if let Err(e) = nat.rewrite_outbound(&mut pkt) {
            debug!(error = %e, "egress rewrite (no NAT entry — likely RST for unknown flow)");
            continue;
        }
        if let Err(e) = tunnel.send_packet(&pkt).await {
            warn!(error = %e, "wg send");
        }
    }
}
