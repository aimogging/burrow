use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use tokio::net::TcpStream;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

use wgnat::config;
use wgnat::icmp::IcmpForwarder;
use wgnat::nat::{NatKey, NatTable};
use wgnat::proxy::{spawn_tcp_proxy_with_stream, ProxyMsg};
use wgnat::rewrite::{self, build_tcp_rst, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use wgnat::runtime::{spawn_smoltcp, SmoltcpEvent, SmoltcpHandle};
use wgnat::tunnel::WgTunnel;
use wgnat::udp_proxy::{extract_udp_payload, spawn_udp_proxy};

/// How long to wait on the OS-side TCP connect during the probe before
/// giving up and synthesizing a RST back to the peer. Roughly matches the
/// first SYN-ACK retransmit window so we don't keep peers waiting.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Optional config baked in at build time via the `embedded-config` feature.
/// The path is taken from `WGNAT_EMBEDDED_CONFIG` at build time; `build.rs`
/// reads the file and emits `$OUT_DIR/embedded_config.rs` containing
/// `pub const EMBEDDED_CONFIG: &str = "..."`. Cargo's `rerun-if-changed`
/// directive on that path means editing the .conf invalidates the build.
#[cfg(feature = "embedded-config")]
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_config.rs"));
}

const EMBEDDED_CONFIG: Option<&str> = {
    #[cfg(feature = "embedded-config")]
    {
        Some(embedded::EMBEDDED_CONFIG)
    }
    #[cfg(not(feature = "embedded-config"))]
    {
        None
    }
};

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
        /// Path to a wg-quick style configuration file. Optional when the
        /// binary was built with the `embedded-config` feature; required
        /// otherwise. An explicit `--config` always overrides the embedded
        /// one (useful for testing the same binary against a throwaway).
        #[arg(short, long)]
        config: Option<PathBuf>,

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
    let secret = x25519_dalek::StaticSecret::random();
    let public = x25519_dalek::PublicKey::from(&secret);
    let b64 = base64::engine::general_purpose::STANDARD;
    println!("PrivateKey = {}", b64.encode(secret.to_bytes()));
    println!("PublicKey  = {}", b64.encode(public.as_bytes()));
    Ok(())
}

async fn run(
    config_path: Option<PathBuf>,
    endpoint: Option<String>,
    keepalive: Option<u16>,
) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,wgnat=debug")),
        )
        .init();

    // Make panics in any thread (including tokio worker tasks and the
    // smoltcp poll thread) loud. Pre-Phase-9 a panic in the smoltcp thread
    // killed only that thread and the rest of the process kept running with
    // every TCP path silently broken; the panic itself never landed in
    // logs. This hook ensures the next stress test fails loudly.
    //
    // When the `silent` feature is on we skip the eprintln and the default
    // libstd hook (which also writes to stderr) — only the `tracing::error!`
    // path runs, and that itself becomes a no-op under `release_max_level_off`.
    #[cfg(not(feature = "silent"))]
    {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let thread = std::thread::current();
            error!(thread = thread.name().unwrap_or("<unnamed>"), %info, "PANIC");
            eprintln!("PANIC in thread {:?}: {}", thread.name(), info);
            default_hook(info);
        }));
    }
    #[cfg(feature = "silent")]
    {
        std::panic::set_hook(Box::new(|info| {
            let thread = std::thread::current();
            error!(thread = thread.name().unwrap_or("<unnamed>"), %info, "PANIC");
        }));
    }

    let mut cfg = match (config_path, EMBEDDED_CONFIG) {
        (Some(path), _) => {
            info!(path = %path.display(), "loading config from file");
            config::load(&path)
                .with_context(|| format!("loading config from {}", path.display()))?
        }
        (None, Some(embedded)) => {
            info!("using embedded config (built with --features embedded-config)");
            config::parse_str(embedded).context("parsing embedded config")?
        }
        (None, None) => bail!(
            "--config is required (this binary was built without the embedded-config feature)"
        ),
    };

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

    let nat = Arc::new(NatTable::new(cfg.interface.address.address()));
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
    // task sends them to (original_dst_ip, original_dst_port) and pushes
    // responses (as fully formed IPv4+UDP packets) onto `egress_tx`.
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

    // Channel that connect_probe uses to hand a successfully-connected OS
    // TcpStream over to the event loop, where it's parked until the matching
    // smoltcp `TcpConnected` event arrives. Fix #1: the SYN-ACK only goes
    // back to the peer after the OS-side connect succeeds.
    let (arm_tx, mut arm_rx) = mpsc::unbounded_channel::<(NatKey, TcpStream)>();

    // Spawn the smoltcp event consumer: turns runtime events into proxy
    // task lifecycle. The `proxies` and `armed` maps live entirely inside
    // this closure — only one task touches them, so plain HashMaps suffice.
    let event_loop = tokio::spawn({
        let smoltcp = smoltcp.clone();
        let nat = Arc::clone(&nat);
        async move {
            let mut proxies: HashMap<
                wgnat::runtime::ConnectionId,
                mpsc::UnboundedSender<ProxyMsg>,
            > = HashMap::new();
            // Streams pre-dialed by connect_probe, awaiting their matching
            // TcpConnected event so we can hand them off to the proxy task.
            let mut armed: HashMap<NatKey, TcpStream> = HashMap::new();
            loop {
                tokio::select! {
                    Some((key, stream)) = arm_rx.recv() => {
                        if armed.insert(key, stream).is_some() {
                            warn!(?key, "armed stream replaced — duplicate probe");
                        }
                    }
                    Some(evt) = events.evt_rx.recv() => match evt {
                        SmoltcpEvent::TcpConnected { key, id } => {
                            debug!(?key, ?id, "tcp connected");
                            let Some(stream) = armed.remove(&key) else {
                                error!(?key, ?id, "TcpConnected with no armed stream — Fix #1 invariant violated; aborting smoltcp side");
                                smoltcp.abort_tcp(id);
                                continue;
                            };
                            let tx = spawn_tcp_proxy_with_stream(
                                key,
                                id,
                                smoltcp.clone(),
                                Arc::clone(&nat),
                                stream,
                            );
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
                        SmoltcpEvent::TcpClosed { key, id } => {
                            if let Some(tx) = proxies.remove(&id) {
                                let _ = tx.send(ProxyMsg::Closed);
                            }
                            // Defensive: clear any orphaned armed entry.
                            armed.remove(&key);
                        }
                        SmoltcpEvent::TcpAborted { key, id } => {
                            // Phase 10: peer aborted before reaching ESTABLISHED
                            // (typical of `nmap -sS`: SYN → SYN-ACK → RST without
                            // an intervening ACK). The runtime has already torn
                            // down its smoltcp socket and evicted the NAT entry;
                            // we just need to drop the OS-side stream that
                            // connect_probe parked. No proxy was spawned because
                            // TcpConnected never fired.
                            debug!(?key, ?id, "tcp aborted before establishment — dropping armed stream");
                            armed.remove(&key);
                        }
                    },
                    else => break,
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
                            &arm_tx,
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
/// dispatch by protocol: TCP into smoltcp, UDP into the per-entry forwarder,
/// ICMP into the dedicated forwarder.
async fn ingest_tunnel_packet(
    mut packet: Vec<u8>,
    smoltcp: &SmoltcpHandle,
    nat: &Arc<NatTable>,
    udp_proxies: &UdpProxyMap,
    egress_tx: &mpsc::UnboundedSender<Vec<u8>>,
    arm_tx: &mpsc::UnboundedSender<(NatKey, TcpStream)>,
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
            // Compute the prospective NatKey from the packet's natural
            // 5-tuple WITHOUT triggering rewrite/registration yet — the
            // probe path needs to claim the slot before any rewrite, so
            // retransmits during the probe see Pending and short-circuit.
            let key = NatKey {
                proto: PROTO_TCP,
                peer_ip: view.src_ip,
                peer_port: view.src_port,
                original_dst_ip: view.dst_ip,
                original_dst_port: view.dst_port,
            };
            let entry = nat.get(key);
            match entry {
                Some(e) if e.smoltcp_id.is_some() => {
                    // Fast path: listener exists, just rewrite and enqueue.
                    if let Err(err) = nat.rewrite_inbound(&mut packet) {
                        warn!(?key, error = %err, "nat rewrite_inbound (tcp fast path) failed");
                        return;
                    }
                    smoltcp.enqueue_inbound(packet);
                }
                Some(_) => {
                    // Probe in flight (Pending, no smoltcp_id yet). This is
                    // a SYN retransmit — drop. The probe will resolve and
                    // either enqueue the original SYN (success) or send
                    // back a RST (failure).
                    debug!(?key, "tcp packet during connect probe — dropping");
                }
                None => {
                    // No entry: only kick off a probe for a fresh SYN.
                    // Anything else is stale traffic with no listener and
                    // should be dropped silently.
                    use smoltcp::wire::{Ipv4Packet, TcpPacket};
                    let is_syn_only = Ipv4Packet::new_checked(&packet[..])
                        .ok()
                        .and_then(|ip| TcpPacket::new_checked(ip.payload()).ok().map(|tcp| tcp.syn() && !tcp.ack()))
                        .unwrap_or(false);
                    if !is_syn_only {
                        debug!(?key, "tcp packet to unknown flow (not SYN) — dropping");
                        return;
                    }
                    let smoltcp = smoltcp.clone();
                    let nat = Arc::clone(nat);
                    let arm_tx = arm_tx.clone();
                    let egress_tx = egress_tx.clone();
                    tokio::spawn(async move {
                        connect_probe(packet, key, smoltcp, nat, arm_tx, egress_tx).await;
                    });
                }
            }
        }
        PROTO_UDP => {
            let (key, _gateway_port) = match nat.rewrite_inbound(&mut packet) {
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

/// Phase 9 fix #1: try to dial the OS-side destination *before* letting
/// smoltcp answer the peer's SYN. Outcomes:
///   * Connect succeeds → arm the stream for the event loop, register the
///     smoltcp listener, enqueue the original SYN. Smoltcp emits SYN-ACK
///     and the proxy task takes over once `TcpConnected` fires.
///   * Connect fails or times out → synthesize a TCP RST in userspace and
///     send it straight back through the tunnel. The peer correctly sees
///     the destination port as closed, instead of a SYN-ACK + delayed RST
///     (which gets reported as `open` by tools like nmap).
///
/// `try_reserve_pending` claims the NAT slot up-front, so SYN retransmits
/// arriving while this probe is in flight see a Pending entry and are
/// dropped by the dispatch in `ingest_tunnel_packet` rather than starting
/// a second probe.
async fn connect_probe(
    mut packet: Vec<u8>,
    key: NatKey,
    smoltcp: SmoltcpHandle,
    nat: Arc<NatTable>,
    arm_tx: mpsc::UnboundedSender<(NatKey, TcpStream)>,
    egress_tx: mpsc::UnboundedSender<Vec<u8>>,
) {
    // Capture peer's SYN sequence number BEFORE any rewrite mutates the
    // packet — needed if we have to synthesize a RST.
    let ihl = ((packet[0] & 0x0F) as usize) * 4;
    if packet.len() < ihl + 8 {
        debug!(?key, "probe: malformed SYN, dropping");
        return;
    }
    let peer_seq = u32::from_be_bytes([
        packet[ihl + 4],
        packet[ihl + 5],
        packet[ihl + 6],
        packet[ihl + 7],
    ]);

    // Claim the NAT slot first so concurrent retransmits short-circuit.
    match nat.try_reserve_pending(key) {
        Ok(Some(_gw)) => { /* fresh — proceed */ }
        Ok(None) => {
            // Lost a race — another task is already probing for this exact
            // 5-tuple. Drop this duplicate.
            debug!(?key, "probe: another probe already in flight; dropping");
            return;
        }
        Err(e) => {
            warn!(?key, error = %e, "probe: cannot reserve NAT slot");
            return;
        }
    };

    let dst = (key.original_dst_ip, key.original_dst_port);
    let stream = match timeout(PROBE_TIMEOUT, TcpStream::connect(dst)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            debug!(?key, error = %e, "probe: OS connect refused/failed → RST to peer");
            send_rst(&egress_tx, key, peer_seq);
            nat.evict_key(key);
            return;
        }
        Err(_) => {
            debug!(?key, ?PROBE_TIMEOUT, "probe: OS connect timed out → RST to peer");
            send_rst(&egress_tx, key, peer_seq);
            nat.evict_key(key);
            return;
        }
    };

    // Hand the stream off BEFORE enqueueing the SYN — guarantees that the
    // event loop has the stream parked by the time the matching
    // TcpConnected event arrives.
    if arm_tx.send((key, stream)).is_err() {
        warn!(?key, "probe: event loop receiver gone; aborting");
        nat.evict_key(key);
        return;
    }

    // Now actually rewrite the SYN and register the listener. Idempotent
    // against the slot try_reserve_pending already created.
    let gateway_port = match nat.rewrite_inbound(&mut packet) {
        Ok((_, gw)) => gw,
        Err(e) => {
            warn!(?key, error = %e, "probe: rewrite_inbound failed post-connect");
            nat.evict_key(key);
            return;
        }
    };
    if smoltcp.ensure_listener(gateway_port, key).await.is_err() {
        error!(?key, "probe: smoltcp dropped ensure_listener reply");
        nat.evict_key(key);
        return;
    }
    smoltcp.enqueue_inbound(packet);
}

fn send_rst(egress_tx: &mpsc::UnboundedSender<Vec<u8>>, key: NatKey, peer_seq: u32) {
    let rst = build_tcp_rst(
        key.original_dst_ip,
        key.peer_ip,
        key.original_dst_port,
        key.peer_port,
        peer_seq.wrapping_add(1),
    );
    let _ = egress_tx.send(rst);
}
