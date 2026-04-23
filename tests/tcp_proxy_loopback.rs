//! Phase 4 functional test: a hand-crafted "peer" sends a TCP SYN through
//! `NatTable + SmoltcpRuntime + spawn_tcp_proxy` to a real loopback echo
//! server and verifies bytes round-trip correctly. No WireGuard layer —
//! this isolates the rewrite + smoltcp + proxy plumbing.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use burrow::nat::NatTable;
use burrow::proxy::{spawn_tcp_proxy, ProxyMsg};
use burrow::runtime::{spawn_smoltcp, ConnectionId, SmoltcpEvent};
use burrow::test_helpers::{build_tcp, ACK, FIN, PSH, SYN};

const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER_PORT: u16 = 54321;

/// Minimal hand-rolled TCP peer state — enough to do a 3-way handshake,
/// push a data segment, and FIN. Operates on the *peer's* perspective:
/// `local_*` is the peer side, `remote_*` is the original-dst (the burrow
/// gateway will rewrite the dst on inbound, but we always craft packets
/// with the original-dst since that's what a real peer would emit).
struct TcpPeer {
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    seq: u32,
    ack: u32,
}

impl TcpPeer {
    fn new(local_ip: Ipv4Addr, local_port: u16, remote_ip: Ipv4Addr, remote_port: u16) -> Self {
        Self {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            seq: 1000,
            ack: 0,
        }
    }

    fn build(&self, flags: u8, payload: &[u8]) -> Vec<u8> {
        build_tcp(
            self.local_ip,
            self.remote_ip,
            self.local_port,
            self.remote_port,
            self.seq,
            self.ack,
            flags,
            payload,
        )
    }

    fn syn(&mut self) -> Vec<u8> {
        // SYN consumes one sequence number (logically — caller bumps seq).
        self.build(SYN, &[])
    }

    fn ack_only(&mut self) -> Vec<u8> {
        self.build(ACK, &[])
    }

    fn psh_ack(&mut self, payload: &[u8]) -> Vec<u8> {
        let p = self.build(PSH | ACK, payload);
        self.seq = self.seq.wrapping_add(payload.len() as u32);
        p
    }

    fn fin_ack(&mut self) -> Vec<u8> {
        self.build(FIN | ACK, &[])
    }
}

/// Parsed TCP segment from the gateway → peer direction.
#[derive(Debug, Clone)]
struct ParsedTcp {
    flags: u8,
    seq: u32,
    ack: u32,
    payload: Vec<u8>,
}

fn parse_outbound(pkt: &[u8]) -> ParsedTcp {
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    let flags = pkt[ihl + 13];
    let seq = u32::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5], pkt[ihl + 6], pkt[ihl + 7]]);
    let ack = u32::from_be_bytes([pkt[ihl + 8], pkt[ihl + 9], pkt[ihl + 10], pkt[ihl + 11]]);
    let data_off = (pkt[ihl + 12] >> 4) as usize * 4;
    let payload = pkt[ihl + data_off..].to_vec();
    ParsedTcp {
        flags,
        seq,
        ack,
        payload,
    }
}

async fn start_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });
    addr
}

/// Drain everything currently outbound from the device tx channel, return
/// the parsed TCP segments after running each through `nat.rewrite_outbound`.
fn drain_parsed(tx_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>, nat: &NatTable) -> Vec<ParsedTcp> {
    let mut out = Vec::new();
    while let Ok(mut pkt) = tx_rx.try_recv() {
        if nat.rewrite_outbound(&mut pkt).is_err() {
            continue;
        }
        out.push(parse_outbound(&pkt));
    }
    out
}

/// Wait until at least one outbound TCP packet matches `pred`, draining and
/// keeping every parsed segment for inspection. Returns ALL segments seen
/// before (and including) the matching one.
async fn wait_for(
    tx_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    nat: &NatTable,
    timeout: Duration,
    mut pred: impl FnMut(&ParsedTcp) -> bool,
) -> Vec<ParsedTcp> {
    let deadline = std::time::Instant::now() + timeout;
    let mut all = Vec::new();
    while std::time::Instant::now() < deadline {
        let parsed = drain_parsed(tx_rx, nat);
        for p in parsed {
            let matched = pred(&p);
            all.push(p);
            if matched {
                return all;
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    all
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_proxy_round_trips_via_loopback_echo() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,burrow=info")
        .with_test_writer()
        .try_init();

    let echo_addr = start_echo().await;
    let dst_ip = match echo_addr.ip() {
        std::net::IpAddr::V4(v4) => v4,
        _ => unreachable!(),
    };
    let dst_port = echo_addr.port();

    let nat = Arc::new(NatTable::new());
    let (runtime, mut events, mut tx_rx) = spawn_smoltcp(Arc::clone(&nat), std::net::Ipv4Addr::new(10, 0, 0, 2));

    // Wire the same event-loop logic as main.rs. The proxies map lives
    // entirely inside this task — single-owner, no Mutex needed.
    let event_task = tokio::spawn({
        let runtime = runtime.clone();
        let nat = Arc::clone(&nat);
        async move {
            let mut proxies: HashMap<ConnectionId, mpsc::UnboundedSender<ProxyMsg>> =
                HashMap::new();
            while let Some(evt) = events.evt_rx.recv().await {
                match evt {
                    SmoltcpEvent::TcpConnected { key, id } => {
                        let tx = spawn_tcp_proxy(key, id, runtime.clone(), Arc::clone(&nat));
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
                    SmoltcpEvent::TcpAborted { id, .. } => {
                        proxies.remove(&id);
                    }
                }
            }
        }
    });

    let mut peer = TcpPeer::new(PEER_IP, PEER_PORT, dst_ip, dst_port);

    // Helper: every inbound packet has to go through rewrite_inbound (which
    // is what main.rs / ingest_tunnel_packet does) so dst_ip is rewritten to
    // the smoltcp interface IP. Without this smoltcp silently drops the
    // packet because it's addressed to the original-dst IP.
    let send_inbound = |pkt: Vec<u8>| {
        let mut p = pkt;
        nat.rewrite_inbound(&mut p).unwrap();
        runtime.enqueue_inbound(p);
    };

    // 1. Send SYN.
    let mut syn = peer.syn();
    let (key, virtual_ip, gateway_port) = nat.rewrite_inbound(&mut syn).unwrap();
    let _ = runtime.ensure_listener(virtual_ip, gateway_port, key).await.unwrap();
    runtime.enqueue_inbound(syn);
    peer.seq = peer.seq.wrapping_add(1); // SYN consumes seq

    // 2. Wait for SYN-ACK.
    let segs = wait_for(&mut tx_rx, &nat, Duration::from_secs(2), |p| {
        p.flags & 0x12 == 0x12
    })
    .await;
    let synack = segs.iter().rev().find(|p| p.flags & 0x12 == 0x12).expect("SYN-ACK");
    peer.ack = synack.seq.wrapping_add(1);

    // 3. Send ACK to complete handshake.
    send_inbound(peer.ack_only());

    // 4. Send PSH+ACK with payload.
    let payload = b"hello, burrow";
    send_inbound(peer.psh_ack(payload));

    // 5. Wait for echoed data to come back.
    let segs = wait_for(&mut tx_rx, &nat, Duration::from_secs(3), |p| {
        p.payload == payload
    })
    .await;
    let echoed = segs.iter().find(|p| p.payload == payload);
    assert!(
        echoed.is_some(),
        "expected echoed payload {:?}, saw segments: {:?}",
        payload,
        segs.iter().map(|p| (p.flags, p.payload.len())).collect::<Vec<_>>()
    );
    // ACK the echoed data (smoltcp will re-transmit if we don't).
    let echoed = echoed.unwrap();
    peer.ack = echoed.seq.wrapping_add(echoed.payload.len() as u32);
    send_inbound(peer.ack_only());

    // 6. FIN, expect FIN-ACK back eventually.
    send_inbound(peer.fin_ack());
    peer.seq = peer.seq.wrapping_add(1);

    // The echo server closes its half once we close ours, which propagates
    // back. Ensure smoltcp emits at least an ACK or FIN for our FIN.
    let segs = wait_for(&mut tx_rx, &nat, Duration::from_secs(3), |p| {
        // ACK of our FIN: ack == peer.seq
        p.ack == peer.seq && (p.flags & 0x10 != 0)
    })
    .await;
    assert!(
        !segs.is_empty(),
        "expected at least an ACK after sending FIN"
    );

    event_task.abort();
}
