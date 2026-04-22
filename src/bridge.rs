//! Reverse-tunnel bridge. Pairs an incoming peer-initiated flow (accepted
//! on the wgnat WG address at a registered reverse-tunnel port) with an
//! originated outbound flow back through the WG tunnel to the registering
//! client's forward-to address. Bytes flow bidirectionally until either
//! side closes.
//!
//! ## Event routing
//!
//! The main event loop feeds this task with `ProxyMsg` on TWO senders —
//! one keyed on the incoming flow's `ConnectionId`, one on the outbound
//! flow's. Both are registered in the event loop's `proxies` map so that
//! `TcpData` / `TcpFinFromPeer` / `TcpClosed` / `TcpAborted` events for
//! either id arrive at this task.
//!
//! ## Outbound handshake
//!
//! We do NOT block the setup on the outbound TcpConnected event. The
//! bridge starts pumping immediately; any write to an unestablished
//! outbound socket returns `Ok(0)` and the pump backs off briefly. Once
//! smoltcp reaches Established, writes start succeeding. If the outbound
//! connect fails (TcpAborted), the event loop forwards `ProxyMsg::Closed`
//! via the outbound sender, which this task detects and tears down the
//! incoming side in response.

use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicU16, Ordering};

use tokio::sync::mpsc;

use crate::proxy::ProxyMsg;
use crate::runtime::{ConnectionId, SmoltcpHandle};

/// Allocate an ephemeral local port for an originated outbound TCP
/// connection. Walks the 49152..=65535 IANA ephemeral range round-robin.
/// Collisions at the smoltcp level are possible in theory (same
/// `(local, remote)` pair picked twice concurrently) but vanishingly
/// rare — 16K concurrent outbounds is well beyond expected workload.
pub fn next_ephemeral_port() -> u16 {
    static NEXT: AtomicU16 = AtomicU16::new(49152);
    NEXT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |p| {
        Some(if p >= 65535 { 49152 } else { p + 1 })
    })
    .unwrap()
}

/// Registration payload sent by the bridge to the event loop once its
/// outbound flow has a `ConnectionId`. The event loop inserts the
/// sender into its `proxies` map so subsequent `TcpData` / `TcpClosed`
/// events for the outbound id are forwarded to this bridge.
pub type BridgeRegister = (ConnectionId, mpsc::UnboundedSender<ProxyMsg>);

/// Spawn a bridge task. Returns the incoming-side `ProxyMsg` sender that
/// the event loop registers under `incoming_id`. The task asynchronously
/// opens its outbound flow and registers the outbound sender by pushing
/// onto `register_tx`. If the outbound open fails, the bridge aborts the
/// incoming side and never registers.
pub fn spawn_reverse_bridge(
    incoming_id: ConnectionId,
    smoltcp: SmoltcpHandle,
    wg_ip: std::net::Ipv4Addr,
    forward_to: SocketAddrV4,
    register_tx: mpsc::UnboundedSender<BridgeRegister>,
) -> mpsc::UnboundedSender<ProxyMsg> {
    let (incoming_tx, incoming_rx) = mpsc::unbounded_channel::<ProxyMsg>();
    tokio::spawn(async move {
        let local = SocketAddrV4::new(wg_ip, next_ephemeral_port());
        let outbound_id = match smoltcp.open_outbound_tcp(local, forward_to).await {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    ?incoming_id,
                    ?forward_to,
                    error = %e,
                    "reverse bridge: outbound open failed; aborting incoming"
                );
                smoltcp.abort_tcp(incoming_id);
                return;
            }
        };
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel::<ProxyMsg>();
        if register_tx.send((outbound_id, outbound_tx)).is_err() {
            tracing::debug!(?incoming_id, "reverse bridge: event loop gone; aborting");
            smoltcp.abort_tcp(incoming_id);
            smoltcp.abort_tcp(outbound_id);
            return;
        }
        if let Err(e) = pump(smoltcp, incoming_id, outbound_id, incoming_rx, outbound_rx).await {
            tracing::debug!(?incoming_id, ?outbound_id, error = %e, "reverse bridge pump ended");
        }
    });
    incoming_tx
}

async fn pump(
    smoltcp: SmoltcpHandle,
    incoming_id: ConnectionId,
    outbound_id: ConnectionId,
    mut incoming_rx: mpsc::UnboundedReceiver<ProxyMsg>,
    mut outbound_rx: mpsc::UnboundedReceiver<ProxyMsg>,
) -> anyhow::Result<()> {
    let mut incoming_done = false;
    let mut outbound_done = false;
    loop {
        tokio::select! {
            biased;
            msg = incoming_rx.recv(), if !incoming_done => {
                match msg {
                    Some(ProxyMsg::Data(data)) => {
                        write_all(&smoltcp, outbound_id, data).await;
                    }
                    Some(ProxyMsg::PeerFin) => {
                        smoltcp.close_tcp(outbound_id);
                    }
                    Some(ProxyMsg::Closed) | None => {
                        incoming_done = true;
                        smoltcp.close_tcp(outbound_id);
                        if outbound_done { break; }
                    }
                }
            }
            msg = outbound_rx.recv(), if !outbound_done => {
                match msg {
                    Some(ProxyMsg::Data(data)) => {
                        write_all(&smoltcp, incoming_id, data).await;
                    }
                    Some(ProxyMsg::PeerFin) => {
                        smoltcp.close_tcp(incoming_id);
                    }
                    Some(ProxyMsg::Closed) | None => {
                        outbound_done = true;
                        smoltcp.close_tcp(incoming_id);
                        if incoming_done { break; }
                    }
                }
            }
        }
    }
    Ok(())
}

/// Write a buffer through `smoltcp.write_tcp`, retrying briefly on
/// `Ok(0)` (buffer full or socket not yet established). Abandons after
/// 500 iterations (~1s) to prevent permanent stall on a wedged flow.
async fn write_all(smoltcp: &SmoltcpHandle, id: ConnectionId, data: Vec<u8>) {
    let mut remaining = &data[..];
    for _ in 0..500 {
        if remaining.is_empty() {
            return;
        }
        match smoltcp.write_tcp(id, remaining.to_vec()).await {
            Ok(0) => tokio::time::sleep(std::time::Duration::from_millis(2)).await,
            Ok(n) => remaining = &remaining[n..],
            Err(e) => {
                tracing::debug!(?id, error = %e, "bridge write_tcp: smoltcp gone");
                return;
            }
        }
    }
    if !remaining.is_empty() {
        tracing::warn!(?id, "bridge write_tcp: abandoning after 500 buffer-full retries");
    }
}
