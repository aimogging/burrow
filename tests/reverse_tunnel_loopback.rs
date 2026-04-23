//! Phase 13 end-to-end integration test: a reverse-tunnel flow from an
//! incoming peer on `(wg_ip, listen_port)` through wgnat's bridge to a
//! responder on `(forward_to_ip, forward_to_port)`. All three parties
//! are hand-rolled peers operating against a single smoltcp runtime;
//! packets are demuxed by destination IP.
//!
//! Flow:
//!   1. Control peer registers the tunnel via CBOR `StartReverse`.
//!   2. Incoming peer does a TCP handshake to `(wg_ip, 8080)`.
//!   3. Bridge opens an outbound smoltcp flow to `(responder_ip, 9000)`
//!      with `src = wg_ip`.
//!   4. Responder (hand-rolled) completes that handshake.
//!   5. Incoming peer sends bytes → responder sees them.
//!   6. Responder echoes → incoming peer sees them.
//!
//! This proves the bridge plumbing end-to-end without a real network,
//! real WireGuard, or real TCP sockets — every side is orchestrated by
//! the test.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use wgnat::bridge::{spawn_reverse_bridge, BridgeRegister};
use wgnat::control::{listener_key, spawn_control_handler};
use wgnat::nat::NatTable;
use wgnat::proxy::ProxyMsg;
use wgnat::reverse_registry::ReverseRegistry;
use wgnat::rewrite::parse_5tuple;
use wgnat::runtime::{spawn_smoltcp, ConnectionId, SmoltcpEvent};
use wgnat::test_helpers::{build_tcp, ACK, FIN, PSH, SYN};
use wgnat::wire::{ClientReq, Proto, ServerResp};

const WG_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const CTRL_PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const INCOMING_PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 4);
const RESPONDER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 3);

const CONTROL_PORT: u16 = 57821;
const TUNNEL_LISTEN_PORT: u16 = 8080;
const RESPONDER_PORT: u16 = 9000;

struct Peer {
    local_ip: Ipv4Addr,
    local_port: u16,
    remote_ip: Ipv4Addr,
    remote_port: u16,
    seq: u32,
    ack: u32,
}

impl Peer {
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

    fn pkt(&self, flags: u8, payload: &[u8]) -> Vec<u8> {
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
        self.pkt(SYN, &[])
    }
    fn ack_only(&mut self) -> Vec<u8> {
        self.pkt(ACK, &[])
    }
    fn psh_ack(&mut self, payload: &[u8]) -> Vec<u8> {
        let p = self.pkt(PSH | ACK, payload);
        self.seq = self.seq.wrapping_add(payload.len() as u32);
        p
    }
    fn fin_ack(&mut self) -> Vec<u8> {
        self.pkt(FIN | ACK, &[])
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ParsedTcp {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    seq: u32,
    payload: Vec<u8>,
}

fn parse(pkt: &[u8]) -> ParsedTcp {
    let view = parse_5tuple(pkt).unwrap();
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    let flags = pkt[ihl + 13];
    let seq = u32::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5], pkt[ihl + 6], pkt[ihl + 7]]);
    let data_off = (pkt[ihl + 12] >> 4) as usize * 4;
    let payload = pkt[ihl + data_off..].to_vec();
    ParsedTcp {
        src_ip: view.src_ip,
        dst_ip: view.dst_ip,
        src_port: view.src_port,
        dst_port: view.dst_port,
        flags,
        seq,
        payload,
    }
}

fn encode_cbor<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(value, &mut payload).unwrap();
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}


#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_tunnel_end_to_end() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,wgnat=info")
        .with_test_writer()
        .try_init();

    let nat = Arc::new(NatTable::new());
    let (runtime, mut events, mut tx_rx) = spawn_smoltcp(Arc::clone(&nat), WG_IP);
    let registry = Arc::new(ReverseRegistry::new());

    // Bootstrap the control listener.
    let _ = runtime
        .ensure_listener(WG_IP, CONTROL_PORT, listener_key(WG_IP, CONTROL_PORT))
        .await
        .unwrap();

    // Event loop: same shape as main.rs.
    let (bridge_register_tx, mut bridge_register_rx) =
        mpsc::unbounded_channel::<BridgeRegister>();
    let event_task = tokio::spawn({
        let runtime = runtime.clone();
        let registry = Arc::clone(&registry);
        async move {
            let mut proxies: HashMap<ConnectionId, mpsc::UnboundedSender<ProxyMsg>> =
                HashMap::new();
            loop {
                tokio::select! {
                    Some((id, tx)) = bridge_register_rx.recv() => {
                        proxies.insert(id, tx);
                    }
                    Some(evt) = events.evt_rx.recv() => match evt {
                        SmoltcpEvent::TcpConnected { key, id } => {
                            // Originated (bridge outbound) — already has a proxy registered.
                            if key.original_dst_ip == WG_IP
                                && key.peer_ip != Ipv4Addr::UNSPECIFIED
                            {
                                continue;
                            }
                            if key.original_dst_ip == WG_IP
                                && key.original_dst_port == CONTROL_PORT
                            {
                                let next = listener_key(WG_IP, CONTROL_PORT);
                                let _ = runtime
                                    .ensure_listener(WG_IP, CONTROL_PORT, next).await;
                                let tx = spawn_control_handler(
                                    id, runtime.clone(), WG_IP, Arc::clone(&registry),
                                );
                                proxies.insert(id, tx);
                            } else if key.original_dst_ip == WG_IP {
                                let Some(entry) = registry
                                    .lookup(Proto::Tcp, key.original_dst_port)
                                else {
                                    runtime.abort_tcp(id);
                                    continue;
                                };
                                let next = listener_key(WG_IP, key.original_dst_port);
                                let _ = runtime
                                    .ensure_listener(WG_IP, key.original_dst_port, next)
                                    .await;
                                let tx = spawn_reverse_bridge(
                                    id,
                                    runtime.clone(),
                                    WG_IP,
                                    entry.forward_to,
                                    bridge_register_tx.clone(),
                                );
                                proxies.insert(id, tx);
                            } else {
                                runtime.abort_tcp(id);
                            }
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
                            if let Some(tx) = proxies.remove(&id) {
                                let _ = tx.send(ProxyMsg::Closed);
                            }
                        }
                    },
                    else => break,
                }
            }
        }
    });

    // ============================================================
    // Phase A: control peer registers the tunnel.
    // ============================================================
    let mut ctrl = Peer::new(CTRL_PEER_IP, 50001, WG_IP, CONTROL_PORT);
    runtime.enqueue_inbound(ctrl.syn());
    ctrl.seq = ctrl.seq.wrapping_add(1);

    // Absorb ctrl's SYN-ACK.
    let synack = wait_for_packet(&mut tx_rx, Duration::from_secs(2), |p| {
        p.dst_ip == CTRL_PEER_IP && p.flags & 0x12 == 0x12
    })
    .await
    .expect("ctrl SYN-ACK");
    ctrl.ack = synack.seq.wrapping_add(1);
    runtime.enqueue_inbound(ctrl.ack_only());

    // Send StartReverse.
    let req = ClientReq::StartReverse {
        proto: Proto::Tcp,
        listen_port: TUNNEL_LISTEN_PORT,
        forward_to: SocketAddrV4::new(RESPONDER_IP, RESPONDER_PORT),
    };
    runtime.enqueue_inbound(ctrl.psh_ack(&encode_cbor(&req)));

    // Collect ctrl response frame and ACK everything that comes back.
    let mut resp_bytes = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if std::time::Instant::now() >= deadline {
            panic!("control response timeout; got {} bytes", resp_bytes.len());
        }
        for p in drain_all(&mut tx_rx) {
            if p.dst_ip == CTRL_PEER_IP && !p.payload.is_empty() {
                resp_bytes.extend_from_slice(&p.payload);
                ctrl.ack = ctrl.ack.wrapping_add(p.payload.len() as u32);
                runtime.enqueue_inbound(ctrl.ack_only());
            }
        }
        if resp_bytes.len() >= 4 {
            let len = u32::from_be_bytes([
                resp_bytes[0], resp_bytes[1], resp_bytes[2], resp_bytes[3],
            ]) as usize;
            if resp_bytes.len() >= 4 + len {
                resp_bytes.truncate(4 + len);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let resp: ServerResp = ciborium::de::from_reader(&resp_bytes[4..]).unwrap();
    match resp {
        ServerResp::Started { .. } => (),
        other => panic!("expected Ok, got {other:?}"),
    }

    // ============================================================
    // Phase B: incoming peer connects to (wg_ip, TUNNEL_LISTEN_PORT).
    // ============================================================
    let mut incoming = Peer::new(INCOMING_PEER_IP, 50002, WG_IP, TUNNEL_LISTEN_PORT);
    runtime.enqueue_inbound(incoming.syn());
    incoming.seq = incoming.seq.wrapping_add(1);

    // ============================================================
    // Phase C: complete incoming's handshake first. Only after the
    // incoming side reaches Established does the event loop spawn the
    // bridge, which in turn opens the outbound to the responder.
    // ============================================================
    let incoming_synack = wait_for_packet(&mut tx_rx, Duration::from_secs(2), |p| {
        p.dst_ip == INCOMING_PEER_IP && p.flags & 0x12 == 0x12
    })
    .await
    .expect("incoming SYN-ACK");
    incoming.ack = incoming_synack.seq.wrapping_add(1);
    runtime.enqueue_inbound(incoming.ack_only());

    // Now the bridge spawns, opens outbound. Wait for its SYN.
    let bridge_syn = wait_for_packet(&mut tx_rx, Duration::from_secs(2), |p| {
        p.dst_ip == RESPONDER_IP && p.flags & 0x02 != 0
    })
    .await
    .expect("bridge SYN to responder");

    // Set up the responder peer mirroring the bridge's chosen src_port.
    let bridge_src_port = bridge_syn.src_port;
    let mut responder = Peer::new(RESPONDER_IP, RESPONDER_PORT, WG_IP, bridge_src_port);
    responder.ack = bridge_syn.seq.wrapping_add(1);
    runtime.enqueue_inbound(responder.pkt(SYN | ACK, &[]));
    responder.seq = responder.seq.wrapping_add(1);

    // Bridge completes its handshake with the responder — final ACK.
    let _ = wait_for_packet(&mut tx_rx, Duration::from_secs(2), |p| {
        p.dst_ip == RESPONDER_IP && p.flags == 0x10
    })
    .await
    .expect("bridge final ACK to responder");

    // ============================================================
    // Phase D: incoming → bridge → responder data flow.
    // ============================================================
    let payload = b"forward-me";
    runtime.enqueue_inbound(incoming.psh_ack(payload));

    // Wait for the same bytes to arrive at the responder side.
    let mut seen_at_responder: Vec<u8> = Vec::new();
    let mut responder = responder;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        for p in drain_all(&mut tx_rx) {
            // ACK any data addressed to incoming so the peer doesn't
            // retransmit. (The bridge's write-through from responder to
            // incoming happens later — for now we just eat ACKs/empty
            // segments.)
            if p.dst_ip == INCOMING_PEER_IP && !p.payload.is_empty() {
                incoming.ack = incoming.ack.wrapping_add(p.payload.len() as u32);
                runtime.enqueue_inbound(incoming.ack_only());
            }
            if p.dst_ip == RESPONDER_IP && !p.payload.is_empty() {
                seen_at_responder.extend_from_slice(&p.payload);
                responder.ack = responder.ack.wrapping_add(p.payload.len() as u32);
                runtime.enqueue_inbound(responder.ack_only());
            }
        }
        if seen_at_responder.ends_with(payload) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        seen_at_responder.ends_with(payload),
        "payload did not reach responder; got {:?}",
        seen_at_responder
    );

    // ============================================================
    // Phase E: responder → bridge → incoming (echo).
    // ============================================================
    let echo = b"echo-back";
    runtime.enqueue_inbound(responder.psh_ack(echo));

    let mut seen_at_incoming: Vec<u8> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        for p in drain_all(&mut tx_rx) {
            if p.dst_ip == INCOMING_PEER_IP && !p.payload.is_empty() {
                seen_at_incoming.extend_from_slice(&p.payload);
                incoming.ack = incoming.ack.wrapping_add(p.payload.len() as u32);
                runtime.enqueue_inbound(incoming.ack_only());
            }
            if p.dst_ip == RESPONDER_IP && !p.payload.is_empty() {
                responder.ack = responder.ack.wrapping_add(p.payload.len() as u32);
                runtime.enqueue_inbound(responder.ack_only());
            }
        }
        if seen_at_incoming.ends_with(echo) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(
        seen_at_incoming.ends_with(echo),
        "echo did not reach incoming peer; got {:?}",
        seen_at_incoming
    );

    // Tidy up.
    runtime.enqueue_inbound(incoming.fin_ack());
    runtime.enqueue_inbound(responder.fin_ack());
    tokio::time::sleep(Duration::from_millis(50)).await;
    event_task.abort();
}

fn drain_all(tx_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<ParsedTcp> {
    let mut out = Vec::new();
    while let Ok(pkt) = tx_rx.try_recv() {
        out.push(parse(&pkt));
    }
    out
}

async fn wait_for_packet(
    tx_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    timeout: Duration,
    mut pred: impl FnMut(&ParsedTcp) -> bool,
) -> Option<ParsedTcp> {
    let deadline = std::time::Instant::now() + timeout;
    let mut buffered: Vec<ParsedTcp> = Vec::new();
    while std::time::Instant::now() < deadline {
        for p in drain_all(tx_rx) {
            if pred(&p) {
                buffered.push(p.clone());
                return buffered.into_iter().find(|q| pred(q));
            }
            buffered.push(p);
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    None
}

