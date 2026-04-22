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

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::proxy::ProxyMsg;
use crate::reverse_registry::{RegisterError, ReverseRegistry, UnregisterError};
use crate::runtime::{ConnectionId, SmoltcpHandle};
use crate::wire::{ClientReq, ErrorKind, ServerResp, MAX_FRAME_LEN};

/// Spawn the per-flow handler. Returns the `ProxyMsg` sender that the
/// event loop feeds with `TcpData` / `PeerFin` / `Closed`. Mirrors the
/// shape of `spawn_tcp_proxy_with_stream` so the event loop can store it
/// uniformly in the `proxies` map.
pub fn spawn_control_handler(
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    registry: Arc<ReverseRegistry>,
) -> mpsc::UnboundedSender<ProxyMsg> {
    let (msg_tx, msg_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = run_once(id, smoltcp, msg_rx, registry).await {
            tracing::debug!(?id, error = %e, "control handler exited");
        }
    });
    msg_tx
}

async fn run_once(
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
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

    let resp = handle_request(req, &registry);
    write_resp(&smoltcp, id, &resp).await;
    smoltcp.close_tcp(id);
    Ok(())
}

fn handle_request(req: ClientReq, registry: &ReverseRegistry) -> ServerResp {
    match req {
        ClientReq::RegisterReverse {
            proto,
            listen_port,
            forward_to,
        } => match registry.register(proto, listen_port, forward_to) {
            Ok(tunnel_id) => {
                tracing::info!(
                    ?proto,
                    listen_port,
                    ?forward_to,
                    ?tunnel_id,
                    "reverse tunnel registered"
                );
                ServerResp::Ok { tunnel_id }
            }
            Err(RegisterError::PortInUse) => ServerResp::Error {
                kind: ErrorKind::PortInUse,
                msg: format!("port {listen_port}/{proto:?} already registered"),
            },
        },
        ClientReq::UnregisterReverse { tunnel_id } => match registry.unregister(tunnel_id) {
            Ok(()) => {
                tracing::info!(?tunnel_id, "reverse tunnel unregistered");
                ServerResp::Unregistered
            }
            Err(UnregisterError::UnknownTunnel) => ServerResp::Error {
                kind: ErrorKind::UnknownTunnel,
                msg: format!("tunnel {tunnel_id:?} not found"),
            },
        },
        ClientReq::ListReverse => ServerResp::ReverseList(registry.list()),
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
    use crate::wire::Proto;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn handle_register_ok() {
        let reg = ReverseRegistry::new();
        let resp = handle_request(
            ClientReq::RegisterReverse {
                proto: Proto::Tcp,
                listen_port: 8080,
                forward_to: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000),
            },
            &reg,
        );
        match resp {
            ServerResp::Ok { .. } => (),
            other => panic!("expected Ok, got {other:?}"),
        }
        assert_eq!(reg.len(), 1);
    }

    #[test]
    fn handle_register_collision_gives_error() {
        let reg = ReverseRegistry::new();
        let _ = reg.register(
            Proto::Tcp,
            8080,
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000),
        );
        let resp = handle_request(
            ClientReq::RegisterReverse {
                proto: Proto::Tcp,
                listen_port: 8080,
                forward_to: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 9000),
            },
            &reg,
        );
        match resp {
            ServerResp::Error {
                kind: ErrorKind::PortInUse,
                ..
            } => (),
            other => panic!("expected PortInUse, got {other:?}"),
        }
    }

    #[test]
    fn handle_unregister_roundtrip() {
        let reg = ReverseRegistry::new();
        let id = reg
            .register(
                Proto::Tcp,
                8080,
                SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000),
            )
            .unwrap();
        let resp = handle_request(ClientReq::UnregisterReverse { tunnel_id: id }, &reg);
        assert!(matches!(resp, ServerResp::Unregistered));
        assert!(reg.is_empty());
    }

    #[test]
    fn handle_list_empty() {
        let reg = ReverseRegistry::new();
        let resp = handle_request(ClientReq::ListReverse, &reg);
        match resp {
            ServerResp::ReverseList(entries) => assert!(entries.is_empty()),
            other => panic!("expected ReverseList, got {other:?}"),
        }
    }
}
