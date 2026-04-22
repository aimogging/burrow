//! Per-connection proxy tasks. Each accepted smoltcp connection gets paired
//! with a real OS `TcpStream` to the original destination; this module
//! shuffles bytes between the two and propagates close/reset.
//!
//! Architecture: we never touch the smoltcp `TcpSocket` directly here — all
//! reads/writes funnel through `SmoltcpHandle` to the smoltcp thread, keyed
//! by the opaque `ConnectionId` issued at listener-creation time. The
//! per-connection task owns:
//!   * the OS-side `TcpStream` (reads to forward to smoltcp, writes from
//!     smoltcp)
//!   * an `mpsc::UnboundedReceiver` of `Vec<u8>` chunks the runtime forwards
//!     when smoltcp emits `TcpData` for our id.

use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use crate::nat::{ConnectionState, NatKey, NatTable};
use crate::runtime::{ConnectionId, SmoltcpHandle};

/// Legacy entry point: spawn a task that dials the original destination
/// itself and then proxies data in both directions. Used by tests that drive
/// the runtime directly without going through main.rs's connect-probe path.
/// In production main.rs always pre-dials and uses `spawn_tcp_proxy_with_stream`.
pub fn spawn_tcp_proxy(
    key: NatKey,
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    nat: Arc<NatTable>,
) -> mpsc::UnboundedSender<ProxyMsg> {
    let (msg_tx, msg_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let dst = (key.original_dst_ip, key.original_dst_port);
        let stream = match TcpStream::connect(dst).await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(?key, error = %e, "proxy: OS connect failed; aborting smoltcp side");
                smoltcp.abort_tcp(id);
                nat.set_state(key, ConnectionState::Closed);
                return;
            }
        };
        if let Err(e) = run_tcp_proxy_inner(stream, key, id, smoltcp, nat, msg_rx).await {
            tracing::warn!(?key, error = %e, "tcp proxy task failed");
        }
    });
    msg_tx
}

/// Production entry point: caller pre-dials the OS stream (so the SYN-ACK
/// to the peer reflects the real reachability of the destination — fix #1)
/// and hands it off here once smoltcp emits `TcpConnected`.
pub fn spawn_tcp_proxy_with_stream(
    key: NatKey,
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    nat: Arc<NatTable>,
    stream: TcpStream,
) -> mpsc::UnboundedSender<ProxyMsg> {
    let (msg_tx, msg_rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(e) = run_tcp_proxy_inner(stream, key, id, smoltcp, nat, msg_rx).await {
            tracing::warn!(?key, error = %e, "tcp proxy task failed");
        }
    });
    msg_tx
}

#[derive(Debug)]
pub enum ProxyMsg {
    /// Bytes received from peer (via smoltcp). Forward to OS stream.
    Data(Vec<u8>),
    /// Peer sent FIN. Half-close the OS write side.
    PeerFin,
    /// Smoltcp reports the socket is closed. Tear down.
    Closed,
}

async fn run_tcp_proxy_inner(
    stream: TcpStream,
    key: NatKey,
    id: ConnectionId,
    smoltcp: SmoltcpHandle,
    nat: Arc<NatTable>,
    mut msg_rx: mpsc::UnboundedReceiver<ProxyMsg>,
) -> Result<()> {
    let _ = stream.set_nodelay(true);
    let (mut os_read, mut os_write) = stream.into_split();

    // OS → smoltcp pump (spawned). Reads from the OS stream and writes to
    // the smoltcp tx buffer via the runtime.
    let smoltcp_for_os_pump = smoltcp.clone();
    let os_pump = tokio::spawn(async move {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match os_read.read(&mut buf).await {
                Ok(0) => break, // OS-side EOF (server closed)
                Ok(n) => {
                    let mut to_send = buf[..n].to_vec();
                    while !to_send.is_empty() {
                        match smoltcp_for_os_pump.write_tcp(id, to_send.clone()).await {
                            Ok(0) => {
                                // smoltcp tx buffer is full — back off briefly.
                                tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                            }
                            Ok(written) => {
                                to_send.drain(..written);
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "smoltcp gone; ending os pump");
                                return;
                            }
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(error = %e, "os read err; ending os pump");
                    break;
                }
            }
        }
        // OS-side hit EOF or error. Close the smoltcp side gracefully so
        // the peer sees a FIN.
        smoltcp_for_os_pump.close_tcp(id);
    });

    // smoltcp → OS pump runs inline.
    let mut peer_fin_seen = false;
    while let Some(msg) = msg_rx.recv().await {
        match msg {
            ProxyMsg::Data(data) => {
                if let Err(e) = os_write.write_all(&data).await {
                    tracing::debug!(error = %e, "os write failed; aborting smoltcp side");
                    smoltcp.abort_tcp(id);
                    break;
                }
            }
            ProxyMsg::PeerFin => {
                peer_fin_seen = true;
                if let Err(e) = os_write.shutdown().await {
                    tracing::debug!(error = %e, "os shutdown failed (peer-fin)");
                }
            }
            ProxyMsg::Closed => break,
        }
    }

    // Drop os_write so its half-close propagates if we haven't already.
    if !peer_fin_seen {
        let _ = os_write.shutdown().await;
    }

    // Wait for the OS pump to wind down so we don't leak the read half. A
    // join error here means the pump panicked — surface it (fix #3 — pre
    // Phase-9 this was silently `let _ = ...`).
    if let Err(e) = os_pump.await {
        tracing::warn!(?key, error = %e, "tcp os_pump joined with error");
    }

    nat.set_state(key, ConnectionState::Closed);
    tracing::debug!(?key, "proxy task exiting");
    Ok(())
}
