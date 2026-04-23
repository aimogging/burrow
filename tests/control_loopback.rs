//! Phase 13 integration test: hand-rolled peer speaks the CBOR-framed
//! control protocol over smoltcp on `(wg_ip, CONTROL_PORT)`, registers a
//! reverse tunnel, and asserts the roundtrip response + server-side
//! registry state.
//!
//! Mirrors the three-way-handshake + data + FIN pattern from
//! `tests/tcp_proxy_loopback.rs`, but targets the control flow directly
//! — no NAT rewrite, no forward target, no bridge yet. Phase 13b's
//! reverse-tunnel bridge gets its own integration test next.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use wgnat::control::{listener_key, spawn_control_handler};
use wgnat::nat::NatTable;
use wgnat::proxy::ProxyMsg;
use wgnat::reverse_registry::ReverseRegistry;
use wgnat::runtime::{spawn_smoltcp, ConnectionId, SmoltcpEvent};
use wgnat::test_helpers::{build_tcp, ACK, FIN, PSH, SYN};
use wgnat::wire::{ClientReq, Proto, ServerResp};

const WG_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 2);
const PEER_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);
const PEER_PORT: u16 = 54321;
const CONTROL_PORT: u16 = 57821;

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

    fn syn(&mut self) -> Vec<u8> { self.build(SYN, &[]) }
    fn ack_only(&mut self) -> Vec<u8> { self.build(ACK, &[]) }
    fn psh_ack(&mut self, payload: &[u8]) -> Vec<u8> {
        let p = self.build(PSH | ACK, payload);
        self.seq = self.seq.wrapping_add(payload.len() as u32);
        p
    }
    fn fin_ack(&mut self) -> Vec<u8> { self.build(FIN | ACK, &[]) }
}

#[derive(Debug, Clone)]
struct ParsedTcp {
    flags: u8,
    seq: u32,
    _ack: u32,
    payload: Vec<u8>,
}

fn parse_outbound(pkt: &[u8]) -> ParsedTcp {
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    let flags = pkt[ihl + 13];
    let seq = u32::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5], pkt[ihl + 6], pkt[ihl + 7]]);
    let ack = u32::from_be_bytes([pkt[ihl + 8], pkt[ihl + 9], pkt[ihl + 10], pkt[ihl + 11]]);
    let data_off = (pkt[ihl + 12] >> 4) as usize * 4;
    let payload = pkt[ihl + data_off..].to_vec();
    ParsedTcp { flags, seq, _ack: ack, payload }
}

fn encode_frame<T: serde::Serialize>(value: &T) -> Vec<u8> {
    let mut payload = Vec::new();
    ciborium::ser::into_writer(value, &mut payload).unwrap();
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Drain packets from tx_rx — egress bypass (Phase 12) means outbound
/// packets from the control listener have src=wg_ip and skip rewrite.
fn drain_parsed(tx_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>) -> Vec<ParsedTcp> {
    let mut out = Vec::new();
    while let Ok(pkt) = tx_rx.try_recv() {
        out.push(parse_outbound(&pkt));
    }
    out
}

async fn wait_for(
    tx_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    timeout: Duration,
    mut pred: impl FnMut(&ParsedTcp) -> bool,
) -> Vec<ParsedTcp> {
    let deadline = std::time::Instant::now() + timeout;
    let mut all = Vec::new();
    while std::time::Instant::now() < deadline {
        for p in drain_parsed(tx_rx) {
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
async fn control_register_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,wgnat=info")
        .with_test_writer()
        .try_init();

    let nat = Arc::new(NatTable::new());
    let (runtime, mut events, mut tx_rx) = spawn_smoltcp(Arc::clone(&nat), WG_IP);
    let registry = Arc::new(ReverseRegistry::new());

    // Bootstrap the initial control listener — same as main.rs startup.
    let _ = runtime
        .ensure_listener(WG_IP, CONTROL_PORT, listener_key(WG_IP, CONTROL_PORT))
        .await
        .unwrap();

    // Event-loop: dispatches TcpConnected on control port → spawn_control_handler.
    let event_task = tokio::spawn({
        let runtime = runtime.clone();
        let registry = Arc::clone(&registry);
        async move {
            let mut proxies: HashMap<ConnectionId, mpsc::UnboundedSender<ProxyMsg>> =
                HashMap::new();
            while let Some(evt) = events.evt_rx.recv().await {
                match evt {
                    SmoltcpEvent::TcpConnected { key, id } => {
                        if key.original_dst_ip == WG_IP
                            && key.original_dst_port == CONTROL_PORT
                        {
                            let next = listener_key(WG_IP, CONTROL_PORT);
                            let _ = runtime
                                .ensure_listener(WG_IP, CONTROL_PORT, next)
                                .await;
                            let tx = spawn_control_handler(
                                id,
                                runtime.clone(),
                                WG_IP,
                                Arc::clone(&registry),
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
                }
            }
        }
    });

    // Peer-side dance — three-way handshake to the control listener.
    let mut peer = TcpPeer::new(PEER_IP, PEER_PORT, WG_IP, CONTROL_PORT);

    // 1. SYN — dst=wg_ip bypasses NAT (Phase 12 ingress path), goes
    //    directly to smoltcp.
    let syn = peer.syn();
    runtime.enqueue_inbound(syn);
    peer.seq = peer.seq.wrapping_add(1);

    // 2. Await SYN-ACK.
    let segs = wait_for(&mut tx_rx, Duration::from_secs(2), |p| {
        p.flags & 0x12 == 0x12
    })
    .await;
    let synack = segs
        .iter()
        .rev()
        .find(|p| p.flags & 0x12 == 0x12)
        .expect("SYN-ACK");
    peer.ack = synack.seq.wrapping_add(1);

    // 3. Complete handshake with a pure ACK.
    runtime.enqueue_inbound(peer.ack_only());

    // 4. Send the CBOR StartReverse frame.
    let req = ClientReq::StartReverse {
        proto: Proto::Tcp,
        listen_port: 8080,
        forward_to: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 9000),
    };
    let frame = encode_frame(&req);
    runtime.enqueue_inbound(peer.psh_ack(&frame));

    // 5. Collect response bytes from smoltcp output. Responses may span
    //    multiple segments — keep going until we've got a full CBOR
    //    frame (4-byte length prefix + that many bytes of payload).
    let mut resp_bytes: Vec<u8> = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    let expected_total: Option<usize>;
    loop {
        if std::time::Instant::now() >= deadline {
            panic!(
                "timed out collecting response; got {} bytes: {:?}",
                resp_bytes.len(),
                resp_bytes
            );
        }
        for p in drain_parsed(&mut tx_rx) {
            if !p.payload.is_empty() {
                resp_bytes.extend_from_slice(&p.payload);
                // ACK the data so smoltcp doesn't retransmit.
                peer.ack = peer.ack.wrapping_add(p.payload.len() as u32);
                runtime.enqueue_inbound(peer.ack_only());
            }
        }
        if resp_bytes.len() >= 4 {
            let len = u32::from_be_bytes([
                resp_bytes[0],
                resp_bytes[1],
                resp_bytes[2],
                resp_bytes[3],
            ]) as usize;
            if resp_bytes.len() >= 4 + len {
                expected_total = Some(4 + len);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let total = expected_total.unwrap();
    resp_bytes.truncate(total);

    // 6. Decode the CBOR response.
    let resp: ServerResp = ciborium::de::from_reader(&resp_bytes[4..]).unwrap();
    let tunnel_id = match resp {
        ServerResp::Started { tunnel_id } => tunnel_id,
        other => panic!("expected Ok{{tunnel_id}}, got {other:?}"),
    };

    // 7. Verify the registry state.
    let entry = registry
        .lookup(Proto::Tcp, 8080)
        .expect("registry should contain the new tunnel");
    assert_eq!(entry.tunnel_id, tunnel_id);
    assert_eq!(
        entry.forward_to,
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 3), 9000)
    );

    // 8. FIN-ACK from peer; server also closes after writing the response.
    runtime.enqueue_inbound(peer.fin_ack());
    // Let the event_task drain the final closes.
    tokio::time::sleep(Duration::from_millis(50)).await;
    event_task.abort();
}
