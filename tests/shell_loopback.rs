//! Phase 16 integration test: a peer issues a `RequestShell {
//! mode: Oneshot }` through the control channel and receives a
//! `ShellResult` containing captured stdout.
//!
//! Exercises the full control flow: three-way handshake, CBOR request,
//! shell handler spawns the child, captures stdout+stderr+status, CBOR
//! response, close. Mirrors the `control_loopback.rs` shape.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::mpsc;

use wgnat::control::{listener_key, spawn_control_handler};
use wgnat::nat::NatTable;
use wgnat::proxy::ProxyMsg;
use wgnat::reverse_registry::ReverseRegistry;
use wgnat::runtime::{spawn_smoltcp, ConnectionId, SmoltcpEvent};
use wgnat::test_helpers::{build_tcp, ACK, PSH, SYN};
use wgnat::wire::{ClientReq, ServerResp, ShellMode};

const WG_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 0, 0, 2);
const PEER_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(10, 0, 0, 1);
const PEER_PORT: u16 = 54321;
const CONTROL_PORT: u16 = 57821;

struct Peer {
    seq: u32,
    ack: u32,
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
async fn shell_oneshot_returns_captured_output() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,wgnat=info")
        .with_test_writer()
        .try_init();

    let nat = Arc::new(NatTable::new());
    let (runtime, mut events, mut tx_rx) = spawn_smoltcp(Arc::clone(&nat), WG_IP);
    let registry = Arc::new(ReverseRegistry::new());
    let _ = runtime
        .ensure_listener(WG_IP, CONTROL_PORT, listener_key(WG_IP, CONTROL_PORT))
        .await
        .unwrap();

    let event_task = tokio::spawn({
        let runtime = runtime.clone();
        let registry = Arc::clone(&registry);
        async move {
            let mut proxies: HashMap<ConnectionId, mpsc::UnboundedSender<ProxyMsg>> =
                HashMap::new();
            while let Some(evt) = events.evt_rx.recv().await {
                match evt {
                    SmoltcpEvent::TcpConnected { key, id } => {
                        if key.original_dst_ip == WG_IP && key.original_dst_port == CONTROL_PORT {
                            let next = listener_key(WG_IP, CONTROL_PORT);
                            let _ = runtime.ensure_listener(WG_IP, CONTROL_PORT, next).await;
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
                    SmoltcpEvent::TcpClosed { id, .. } | SmoltcpEvent::TcpAborted { id, .. } => {
                        if let Some(tx) = proxies.remove(&id) {
                            let _ = tx.send(ProxyMsg::Closed);
                        }
                    }
                }
            }
        }
    });

    let mut peer = Peer { seq: 1000, ack: 0 };
    // 1. SYN
    runtime.enqueue_inbound(build_tcp(
        PEER_IP, WG_IP, PEER_PORT, CONTROL_PORT, peer.seq, peer.ack, SYN, &[],
    ));
    peer.seq = peer.seq.wrapping_add(1);
    // 2. Await SYN-ACK.
    let synack = wait_for_flags(&mut tx_rx, 0x12).await.expect("SYN-ACK");
    peer.ack = seq_of(&synack).wrapping_add(1);
    // 3. ACK.
    runtime.enqueue_inbound(build_tcp(
        PEER_IP, WG_IP, PEER_PORT, CONTROL_PORT, peer.seq, peer.ack, ACK, &[],
    ));
    // 4. CBOR request.
    let (program, args) = shell_args_for_echo("hello");
    let req = ClientReq::RequestShell {
        mode: ShellMode::Oneshot,
        program: Some(program),
        args,
    };
    let frame = encode_cbor(&req);
    runtime.enqueue_inbound(build_tcp(
        PEER_IP, WG_IP, PEER_PORT, CONTROL_PORT, peer.seq, peer.ack, PSH | ACK, &frame,
    ));
    peer.seq = peer.seq.wrapping_add(frame.len() as u32);

    // 5. Collect response CBOR.
    let mut resp_bytes = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if std::time::Instant::now() >= deadline {
            panic!("shell response timeout; got {} bytes", resp_bytes.len());
        }
        while let Ok(pkt) = tx_rx.try_recv() {
            let payload = tcp_payload(&pkt);
            if !payload.is_empty() {
                resp_bytes.extend_from_slice(&payload);
                peer.ack = peer.ack.wrapping_add(payload.len() as u32);
                runtime.enqueue_inbound(build_tcp(
                    PEER_IP, WG_IP, PEER_PORT, CONTROL_PORT, peer.seq, peer.ack, ACK, &[],
                ));
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
        ServerResp::ShellResult {
            exit_code,
            stdout,
            stderr: _,
        } => {
            assert_eq!(exit_code, Some(0));
            let s = String::from_utf8_lossy(&stdout);
            assert!(
                s.contains("hello"),
                "expected 'hello' in stdout, got {s:?}"
            );
        }
        other => panic!("expected ShellResult, got {other:?}"),
    }

    event_task.abort();
}

fn shell_args_for_echo(word: &str) -> (String, Vec<String>) {
    if cfg!(windows) {
        (
            "cmd.exe".to_string(),
            vec!["/C".to_string(), format!("echo {word}")],
        )
    } else {
        (
            "/bin/sh".to_string(),
            vec!["-c".to_string(), format!("echo {word}")],
        )
    }
}

fn seq_of(pkt: &[u8]) -> u32 {
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    u32::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5], pkt[ihl + 6], pkt[ihl + 7]])
}

fn tcp_payload(pkt: &[u8]) -> Vec<u8> {
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    let data_off = (pkt[ihl + 12] >> 4) as usize * 4;
    pkt[ihl + data_off..].to_vec()
}

async fn wait_for_flags(
    tx_rx: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    flags: u8,
) -> Option<Vec<u8>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        while let Ok(pkt) = tx_rx.try_recv() {
            let ihl = ((pkt[0] & 0x0F) as usize) * 4;
            if pkt[ihl + 13] & flags == flags {
                return Some(pkt);
            }
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    None
}
