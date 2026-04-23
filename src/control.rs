//! Control-channel handler. Runs per accepted TCP flow on
//! `(wg_ip, CONTROL_PORT)` — reads one `ClientReq`, executes it against
//! the `ReverseRegistry`, writes one `ServerResp`, closes.
//!
//! The only persistent piece here is the `ReverseRegistry` (shared via
//! `Arc`); each control flow is short-lived and stateless from the
//! handler's perspective.
//!
//! Shell sessions (Phase 16) will split off here: on `RequestShell`, the
//! flow stays open and the handler switches into the framed stdio
//! protocol. Phase 13 responds `Error{NotYetSupported}` for anything
//! beyond the tunnel requests.

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::nat::NatKey;
use crate::proxy::ProxyMsg;
use crate::reverse_registry::{ReverseRegistry, StartError, StopError};
use crate::rewrite::PROTO_TCP;
use crate::runtime::{ConnectionId, SmoltcpHandle};
use crate::shell_handler::{handle_shell_request, run_interactive};
use crate::wire::{ClientReq, ErrorKind, Proto, ServerResp, ShellMode, MAX_FRAME_LEN};

/// Build a unique synthetic `NatKey` for a service listener on
/// `(wg_ip, port)` — shared between `main.rs` and this handler so the
/// runtime's `conns` map never sees duplicate keys across control and
/// reverse-tunnel listeners.
pub fn listener_key(wg_ip: Ipv4Addr, port: u16) -> NatKey {
    static COUNTER: AtomicU16 = AtomicU16::new(1);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    NatKey {
        proto: PROTO_TCP,
        peer_ip: Ipv4Addr::UNSPECIFIED,
        peer_port: seq,
        original_dst_ip: wg_ip,
        original_dst_port: port,
    }
}

/// Spawn the per-flow handler. Returns the `ProxyMsg` sender that the
/// event loop feeds with `TcpData` / `PeerFin` / `Closed`. Mirrors the
/// shape of `spawn_tcp_proxy_with_stream` so the event loop can store it
/// uniformly in the `proxies` map.
pub fn spawn_control_handler(
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    wg_ip: Ipv4Addr,
    registry: Arc<ReverseRegistry>,
) -> mpsc::UnboundedSender<ProxyMsg> {
    let (msg_tx, msg_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = run_once(id, smoltcp, wg_ip, msg_rx, registry).await {
            tracing::debug!(?id, error = %e, "control handler exited");
        }
    });
    msg_tx
}

async fn run_once(
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    wg_ip: Ipv4Addr,
    mut msg_rx: mpsc::UnboundedReceiver<ProxyMsg>,
    registry: Arc<ReverseRegistry>,
) -> anyhow::Result<()> {
    let mut leftover: Vec<u8> = Vec::new();

    let len_bytes = read_n(&mut msg_rx, &mut leftover, 4).await?;
    let len = u32::from_be_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
    if len > MAX_FRAME_LEN {
        send_error(
            &smoltcp,
            id,
            ErrorKind::InvalidRequest,
            format!("frame {len} exceeds cap {MAX_FRAME_LEN}"),
        )
        .await;
        smoltcp.close_tcp(id);
        return Ok(());
    }
    let frame = read_n(&mut msg_rx, &mut leftover, len as usize).await?;

    let req: ClientReq = match ciborium::de::from_reader(&frame[..]) {
        Ok(r) => r,
        Err(e) => {
            send_error(
                &smoltcp,
                id,
                ErrorKind::InvalidRequest,
                format!("cbor decode: {e}"),
            )
            .await;
            smoltcp.close_tcp(id);
            return Ok(());
        }
    };

    // Interactive shell takes over the flow. Write ShellReady, then
    // hand msg_rx + any leftover bytes to the framed pump.
    if let ClientReq::RequestShell {
        mode: ShellMode::Interactive,
        program,
        args,
    } = &req
    {
        write_resp(&smoltcp, id, &ServerResp::ShellReady).await;
        run_interactive(
            id,
            smoltcp,
            leftover,
            msg_rx,
            program.clone(),
            args.clone(),
        )
        .await;
        return Ok(());
    }

    let resp = handle_request(req, &registry, &smoltcp, wg_ip).await;
    write_resp(&smoltcp, id, &resp).await;
    smoltcp.close_tcp(id);
    Ok(())
}

async fn handle_request(
    req: ClientReq,
    registry: &ReverseRegistry,
    smoltcp: &SmoltcpHandle,
    wg_ip: Ipv4Addr,
) -> ServerResp {
    match req {
        ClientReq::StartReverse {
            proto,
            listen_port,
            forward_to,
        } => {
            let tunnel_id = match registry.start(proto, listen_port, forward_to) {
                Ok(id) => id,
                Err(StartError::PortInUse) => {
                    return ServerResp::Error {
                        kind: ErrorKind::PortInUse,
                        msg: format!("port {listen_port}/{proto:?} already started"),
                    }
                }
            };
            // UDP reverse tunnels don't need a smoltcp listener — the
            // ingest path intercepts them directly and handles
            // forwarding through `UdpReverseState`. Registry entry is
            // sufficient.
            if matches!(proto, Proto::Tcp) {
                let lk = listener_key(wg_ip, listen_port);
                if smoltcp.ensure_listener(wg_ip, listen_port, lk).await.is_err() {
                    let _ = registry.stop(tunnel_id);
                    return ServerResp::Error {
                        kind: ErrorKind::Internal,
                        msg: "failed to create listener".into(),
                    };
                }
            }
            tracing::info!(
                ?proto,
                listen_port,
                ?forward_to,
                ?tunnel_id,
                "reverse tunnel started"
            );
            ServerResp::Started { tunnel_id }
        }
        ClientReq::StopReverse { tunnel_id } => match registry.stop(tunnel_id) {
            Ok(()) => {
                tracing::info!(?tunnel_id, "reverse tunnel stopped");
                ServerResp::Stopped
            }
            Err(StopError::UnknownTunnel) => ServerResp::Error {
                kind: ErrorKind::UnknownTunnel,
                msg: format!("tunnel {tunnel_id:?} not found"),
            },
        },
        ClientReq::ListReverse => ServerResp::ReverseList(registry.list()),
        ClientReq::RequestShell {
            mode,
            program,
            args,
        } => handle_shell_request(mode, program, args).await,
    }
}

async fn read_n(
    msg_rx: &mut mpsc::UnboundedReceiver<ProxyMsg>,
    leftover: &mut Vec<u8>,
    n: usize,
) -> anyhow::Result<Vec<u8>> {
    while leftover.len() < n {
        match msg_rx.recv().await {
            Some(ProxyMsg::Data(data)) => leftover.extend_from_slice(&data),
            Some(ProxyMsg::PeerFin) | Some(ProxyMsg::Closed) | None => {
                anyhow::bail!("peer closed before full frame");
            }
        }
    }
    Ok(leftover.drain(..n).collect())
}

async fn send_error(smoltcp: &SmoltcpHandle, id: ConnectionId, kind: ErrorKind, msg: String) {
    let resp = ServerResp::Error { kind, msg };
    write_resp(smoltcp, id, &resp).await;
}

async fn write_resp(smoltcp: &SmoltcpHandle, id: ConnectionId, resp: &ServerResp) {
    let mut payload = Vec::new();
    if let Err(e) = ciborium::ser::into_writer(resp, &mut payload) {
        tracing::warn!(?id, error = %e, "control resp: cbor encode failed");
        return;
    }
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(&payload);
    // Retry briefly if smoltcp tx buffer is full — control frames are
    // small (kilobytes), so this loop should terminate quickly.
    let mut remaining = &framed[..];
    for _ in 0..32 {
        match smoltcp.write_tcp(id, remaining.to_vec()).await {
            Ok(0) => tokio::time::sleep(std::time::Duration::from_millis(2)).await,
            Ok(n) => {
                remaining = &remaining[n..];
                if remaining.is_empty() {
                    return;
                }
            }
            Err(e) => {
                tracing::debug!(?id, error = %e, "control resp: smoltcp gone");
                return;
            }
        }
    }
    if !remaining.is_empty() {
        tracing::warn!(?id, "control resp: gave up writing after repeated buffer-full");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Registry-level logic is covered by `reverse_registry::tests`.
    // End-to-end handler tests (including the smoltcp listener side effect)
    // live in `tests/control_loopback.rs` (Phase 13 integration test), which
    // drives real SYN/ACK packets through the runtime.

    #[test]
    fn listener_keys_are_unique() {
        let a = listener_key(Ipv4Addr::new(10, 0, 0, 2), 57821);
        let b = listener_key(Ipv4Addr::new(10, 0, 0, 2), 57821);
        assert_ne!(a, b, "each listener_key call must produce a fresh key");
    }
}
