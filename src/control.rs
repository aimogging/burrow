//! Control-channel handler. Runs per accepted TCP flow on
//! `(wg_ip, CONTROL_PORT)`. Reads one `ClientReq`, routes based on kind:
//!
//! * `StopReverse` / `ListReverse` — synchronous response, close.
//! * `RequestShell { Interactive }` — hand the flow to the framed stdio
//!   pump in `shell_handler::run_interactive`.
//! * `RequestShell { Oneshot | FireAndForget }` — synchronous response
//!   with the captured output / pid, close.
//! * `StartTcpTunnel` / `StartUdpTunnel` — register, write
//!   `ServerResp::Started`, then upgrade the flow to yamux. Server
//!   opens outbound substreams on demand (one per peer connection for
//!   TCP; one shared substream carrying framed datagrams for UDP).

use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio_util::compat::TokioAsyncReadCompatExt;

use crate::nat::NatKey;
use crate::proxy::ProxyMsg;
use crate::reverse_registry::{ReverseRegistry, StartError, StopError, SubstreamOpener};
use crate::rewrite::PROTO_TCP;
use crate::runtime::{ConnectionId, SmoltcpHandle};
use crate::shell_handler::{handle_shell_request, run_interactive};
use crate::wire::{
    BindAddr, ClientReq, ErrorKind, Proto, ServerResp, ShellMode, TunnelSpec, MAX_FRAME_LEN,
};
use crate::yamux_bridge::{drive_connection, smoltcp_as_duplex};

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

/// Passed to the `udp_reverse` module on UDP tunnel start so the ingest
/// path can push datagrams into the owning client's yamux substream.
/// The handle internally fans (peer, payload) messages into the single
/// writer task for a tunnel.
pub type UdpTunnelHandle =
    mpsc::UnboundedSender<(std::net::Ipv4Addr, u16, Vec<u8>)>;

/// Side-table (one entry per active UDP tunnel) that the ingest path
/// consults to route incoming datagrams into the right yamux substream.
pub type UdpTunnelMap = Arc<std::sync::Mutex<
    std::collections::HashMap<crate::wire::TunnelId, UdpTunnelHandle>,
>>;

/// Spawn the per-flow handler. Returns the `ProxyMsg` sender that the
/// event loop feeds with `TcpData` / `PeerFin` / `Closed`.
pub fn spawn_control_handler(
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    wg_ip: Ipv4Addr,
    registry: Arc<ReverseRegistry>,
    udp_tunnels: UdpTunnelMap,
    egress_tx: mpsc::UnboundedSender<Vec<u8>>,
) -> mpsc::UnboundedSender<ProxyMsg> {
    let (msg_tx, msg_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = run_once(id, smoltcp, wg_ip, msg_rx, registry, udp_tunnels, egress_tx)
            .await
        {
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
    udp_tunnels: UdpTunnelMap,
    egress_tx: mpsc::UnboundedSender<Vec<u8>>,
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

    // Interactive shell takes over the flow with a framed stdio pump.
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

    // TCP / UDP reverse tunnels upgrade the flow to yamux after the
    // Started response.
    if let ClientReq::StartTcpTunnel(spec) | ClientReq::StartUdpTunnel(spec) = &req {
        let proto = if matches!(req, ClientReq::StartTcpTunnel(_)) {
            Proto::Tcp
        } else {
            Proto::Udp
        };
        start_tunnel(
            id,
            smoltcp,
            wg_ip,
            leftover,
            msg_rx,
            registry,
            udp_tunnels,
            egress_tx,
            proto,
            spec.clone(),
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
    _smoltcp: &SmoltcpHandle,
    _wg_ip: Ipv4Addr,
) -> ServerResp {
    match req {
        ClientReq::StartTcpTunnel(_) | ClientReq::StartUdpTunnel(_) => {
            // Dispatched above; reaching here means a wiring mistake.
            ServerResp::Error {
                kind: ErrorKind::Internal,
                msg: "tunnel start reached synchronous path".into(),
            }
        }
        ClientReq::StopReverse { tunnel_id } => match registry.stop(tunnel_id) {
            Ok(_entry) => {
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

/// Start a reverse tunnel. Flow sequence:
///   1. Validate bind (Default only for now; log NotYetSupported otherwise).
///   2. Allocate an opener channel + register in the tunnel registry.
///   3. For TCP, create a smoltcp listener on the bind/port.
///   4. Write `ServerResp::Started{tunnel_id}`.
///   5. Wrap the smoltcp flow as a duplex stream, hand to yamux::Connection
///      (server mode).
///   6. Run the yamux driver until the connection closes. Then tear down
///      the registry entry (and for UDP, the side-table handle).
#[allow(clippy::too_many_arguments)]
async fn start_tunnel(
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    wg_ip: Ipv4Addr,
    leftover: Vec<u8>,
    msg_rx: mpsc::UnboundedReceiver<ProxyMsg>,
    registry: Arc<ReverseRegistry>,
    udp_tunnels: UdpTunnelMap,
    egress_tx: mpsc::UnboundedSender<Vec<u8>>,
    proto: Proto,
    spec: TunnelSpec,
) {
    if !matches!(spec.bind, BindAddr::Default) {
        send_error(
            &smoltcp,
            id,
            ErrorKind::NotYetSupported,
            "bind addresses other than Default not yet implemented".into(),
        )
        .await;
        smoltcp.close_tcp(id);
        return;
    }

    let (opener_tx, opener_rx) = mpsc::unbounded_channel();
    let tunnel_id = match registry.start(
        proto,
        spec.listen_port,
        spec.bind,
        spec.forward_to.clone(),
        opener_tx.clone(),
    ) {
        Ok(t) => t,
        Err(StartError::PortInUse) => {
            send_error(
                &smoltcp,
                id,
                ErrorKind::PortInUse,
                format!(
                    "port {}/{:?} already has a tunnel bound on {:?}",
                    spec.listen_port, proto, spec.bind
                ),
            )
            .await;
            smoltcp.close_tcp(id);
            return;
        }
    };

    // For TCP, create the smoltcp listener so incoming peer SYNs land.
    // UDP skips this — the ingest path intercepts datagrams directly.
    if matches!(proto, Proto::Tcp) {
        let lk = listener_key(wg_ip, spec.listen_port);
        if smoltcp
            .ensure_listener(wg_ip, spec.listen_port, lk)
            .await
            .is_err()
        {
            let _ = registry.stop(tunnel_id);
            send_error(
                &smoltcp,
                id,
                ErrorKind::Internal,
                "failed to create smoltcp listener".into(),
            )
            .await;
            smoltcp.close_tcp(id);
            return;
        }
    }

    // Respond Started before the yamux handshake.
    write_resp(&smoltcp, id, &ServerResp::Started { tunnel_id }).await;

    // For UDP, open a single long-lived substream for framed datagrams
    // and kick off reader/writer tasks. Put the writer sender into the
    // udp_tunnels side-table so ingest can push datagrams into it.
    if matches!(proto, Proto::Udp) {
        spawn_udp_side(&opener_tx, tunnel_id, wg_ip, spec.listen_port, udp_tunnels.clone(), egress_tx.clone()).await;
    }

    // Upgrade the control flow to yamux.
    tracing::info!(
        ?proto,
        listen_port = spec.listen_port,
        forward_to = %spec.forward_to,
        ?tunnel_id,
        "reverse tunnel started; upgrading flow to yamux"
    );
    let duplex = smoltcp_as_duplex(id, smoltcp.clone(), leftover, msg_rx);
    let conn = yamux::Connection::new(
        duplex.compat(),
        yamux::Config::default(),
        yamux::Mode::Server,
    );
    // Server doesn't expect inbound substreams from the client;
    // inbound_tx = None. If one ever arrives, drive_connection logs.
    drive_connection(conn, opener_rx, None).await;

    // Client disconnected — teardown.
    let _ = registry.stop(tunnel_id);
    udp_tunnels.lock().unwrap().remove(&tunnel_id);
    tracing::info!(?tunnel_id, ?proto, "reverse tunnel yamux closed; removed");
}

/// Open the per-UDP-tunnel yamux substream and spawn the I/O tasks that
/// connect the UDP ingest path to it.
async fn spawn_udp_side(
    opener_tx: &SubstreamOpener,
    tunnel_id: crate::wire::TunnelId,
    wg_ip: Ipv4Addr,
    listen_port: u16,
    udp_tunnels: UdpTunnelMap,
    egress_tx: mpsc::UnboundedSender<Vec<u8>>,
) {
    // Ask the driver to open a substream for this UDP tunnel. We do
    // this AFTER drive_connection starts polling — but that start is
    // below in the caller. Work around by spawning a task that waits
    // until opener can produce a stream.
    let opener_for_task = opener_tx.clone();
    tokio::spawn(async move {
        // Brief backoff loop: the driver isn't running yet when we
        // get here; wait until it picks up the OpenRequest.
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if opener_for_task
            .send(crate::reverse_registry::OpenRequest { reply: reply_tx })
            .is_err()
        {
            tracing::debug!(?tunnel_id, "udp tunnel: opener channel closed before use");
            return;
        }
        let stream = match reply_rx.await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                tracing::warn!(?tunnel_id, error = %e, "udp tunnel: yamux open_stream failed");
                return;
            }
            Err(_) => return,
        };

        // Split the yamux stream into reader / writer halves via the
        // tokio compat shim.
        use tokio_util::compat::FuturesAsyncReadCompatExt;
        let compat = stream.compat();
        let (mut y_r, mut y_w) = tokio::io::split(compat);

        // Writer: ingest → substream.
        let (send_tx, mut send_rx) =
            mpsc::unbounded_channel::<(Ipv4Addr, u16, Vec<u8>)>();
        udp_tunnels.lock().unwrap().insert(tunnel_id, send_tx);
        tokio::spawn(async move {
            while let Some((peer_ip, peer_port, payload)) = send_rx.recv().await {
                if crate::yamux_bridge::udp_frame::write(&mut y_w, peer_ip, peer_port, &payload)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        // Reader: substream → egress (construct UDP packet + inject).
        tokio::spawn(async move {
            loop {
                let (peer_ip, peer_port, payload) =
                    match crate::yamux_bridge::udp_frame::read(&mut y_r).await {
                        Ok(tuple) => tuple,
                        Err(_) => break,
                    };
                let pkt =
                    crate::rewrite::build_udp_packet(wg_ip, peer_ip, listen_port, peer_port, &payload);
                let _ = egress_tx.send(pkt);
            }
        });
    });
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

    #[test]
    fn listener_keys_are_unique() {
        let a = listener_key(Ipv4Addr::new(10, 0, 0, 2), 57821);
        let b = listener_key(Ipv4Addr::new(10, 0, 0, 2), 57821);
        assert_ne!(a, b, "each listener_key call must produce a fresh key");
    }
}
