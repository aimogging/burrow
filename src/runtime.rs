//! Dedicated thread that owns the smoltcp `Interface`, `SocketSet`, and
//! `ChannelDevice`. smoltcp's API is single-threaded and pull-based, so all
//! manipulation funnels through this thread via a command channel. State
//! changes and inbound data flow back to the tokio runtime through an event
//! channel.
//!
//! ## Why `ConnectionId`, not `SocketHandle`
//!
//! `smoltcp::iface::SocketHandle` is a bare `pub struct SocketHandle(usize)`
//! — an index into a slot table with no generation counter. When the smoltcp
//! thread evicts a closed socket via `sockets.remove(handle)`, the slot is
//! freed and may be reused on the next `sockets.add(...)`. But cross-thread
//! commands (`WriteTcp`, `CloseTcp`, ...) sit in the cmd channel after their
//! socket is gone — at best smoltcp panics on `get_mut` on the freed slot,
//! at worst a brand new connection silently receives stale writes.
//!
//! The fix: bare `SocketHandle`s never leave this thread. Every connection
//! is also issued a monotonically increasing `ConnectionId(u64)` — the
//! opaque token that crosses the channel. `handle_command` resolves
//! `ConnectionId → SocketHandle` against an internal map; if the id is gone
//! (because we already emitted `TcpClosed` and tore down the entry), the
//! command is silently no-op'd. Slot reuse is harmless because the new
//! socket gets a fresh `ConnectionId`.
//!
//! This module is the *plumbing* for the smoltcp side. The actual proxying
//! (open OS TcpStream, shuffle bytes both ways) lives in `crate::proxy`.

use std::collections::HashMap;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::time::Instant as SmolInstant;
use tokio::sync::{mpsc, oneshot};

use crate::config::Ipv4Cidr;
use crate::nat::{ConnectionState, NatKey, NatTable, DEFAULT_TCP_GRACE};
use crate::smoltcp_iface::{build_interface, ChannelDevice, PacketReceiver, PacketSender};

/// Per-socket smoltcp buffer size. 64 KiB matches a typical Linux default
/// and avoids stalling large transfers.
const TCP_BUF_SIZE: usize = 65536;

/// Maximum bytes drained from a single socket per poll cycle. Keeps any one
/// flow from monopolising the smoltcp thread under heavy load.
const RECV_CHUNK: usize = 16 * 1024;

/// Loop sleep when the thread is idle. Sets the worst-case latency for new
/// packets / commands. Small enough to feel snappy, large enough to keep
/// CPU at idle low.
const IDLE_SLEEP: Duration = Duration::from_millis(2);

/// Opaque token identifying a single smoltcp connection across thread
/// boundaries. Never reused — even if smoltcp recycles the underlying
/// `SocketHandle` slot, a new connection gets a new `ConnectionId`.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct ConnectionId(u64);

pub enum SmoltcpCmd {
    /// Idempotently create a TCP listener bound to `port` and tag it with
    /// `key` so the runtime can route the eventual ESTABLISHED event to the
    /// right NAT entry. Replies once with the issued `ConnectionId`.
    EnsureTcpListener {
        port: u16,
        key: NatKey,
        ready: oneshot::Sender<ConnectionId>,
    },
    /// Append `data` to the smoltcp socket's tx buffer. Replies with the
    /// number of bytes accepted (0 if the buffer is full or the socket is
    /// not in a sendable state — caller should retry). Replies with 0 if
    /// the connection has already been torn down.
    WriteTcp {
        id: ConnectionId,
        data: Vec<u8>,
        ack: oneshot::Sender<usize>,
    },
    /// Initiate a graceful close (FIN). Returns when the command is
    /// dispatched, not when the close completes. Silently no-op if the
    /// connection has already been torn down.
    CloseTcp { id: ConnectionId },
    /// Send RST. Silently no-op if the connection has already been torn down.
    AbortTcp { id: ConnectionId },
}

#[derive(Debug)]
pub enum SmoltcpEvent {
    /// Socket transitioned to ESTABLISHED. Spawn a proxy task here.
    TcpConnected { key: NatKey, id: ConnectionId },
    /// Bytes were received on a socket. May arrive in many small chunks.
    TcpData {
        key: NatKey,
        id: ConnectionId,
        data: Vec<u8>,
    },
    /// Socket entered a closing state (FIN from peer). Caller should
    /// half-close the OS-side stream's write half.
    TcpFinFromPeer { key: NatKey, id: ConnectionId },
    /// Socket reached terminal CLOSED state. The `ConnectionId` is no longer
    /// valid after this event; subsequent commands referencing it no-op.
    TcpClosed { key: NatKey, id: ConnectionId },
}

/// Cheap-to-clone handle for issuing commands and feeding inbound packets to
/// the smoltcp thread.
#[derive(Clone)]
pub struct SmoltcpHandle {
    cmd_tx: mpsc::UnboundedSender<SmoltcpCmd>,
    rx_tx: PacketSender,
}

impl SmoltcpHandle {
    /// Push an inbound packet (already dst-rewritten by the NAT table) into
    /// the smoltcp Device's rx queue.
    pub fn enqueue_inbound(&self, packet: Vec<u8>) {
        // If the smoltcp thread has gone, drop silently — the rest of the
        // system will surface that elsewhere.
        let _ = self.rx_tx.send(packet);
    }

    pub fn ensure_listener(&self, port: u16, key: NatKey) -> oneshot::Receiver<ConnectionId> {
        let (tx, rx) = oneshot::channel();
        let _ = self.cmd_tx.send(SmoltcpCmd::EnsureTcpListener {
            port,
            key,
            ready: tx,
        });
        rx
    }

    pub async fn write_tcp(&self, id: ConnectionId, data: Vec<u8>) -> Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SmoltcpCmd::WriteTcp { id, data, ack: tx })
            .map_err(|_| anyhow!("smoltcp thread terminated"))?;
        rx.await
            .map_err(|_| anyhow!("smoltcp thread dropped reply"))
    }

    pub fn close_tcp(&self, id: ConnectionId) {
        let _ = self.cmd_tx.send(SmoltcpCmd::CloseTcp { id });
    }

    pub fn abort_tcp(&self, id: ConnectionId) {
        let _ = self.cmd_tx.send(SmoltcpCmd::AbortTcp { id });
    }
}

pub struct SmoltcpEvents {
    pub evt_rx: mpsc::UnboundedReceiver<SmoltcpEvent>,
}

/// Spawn the smoltcp poll thread. Returns the cmd handle, an event stream,
/// and the receiver end of the device's tx queue (drained by the egress
/// task to encapsulate and send through the WG tunnel).
pub fn spawn_smoltcp(
    nat: Arc<NatTable>,
    addr: Ipv4Cidr,
) -> (SmoltcpHandle, SmoltcpEvents, PacketReceiver) {
    let (rx_tx, rx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (tx_tx, tx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel();

    let nat_thread = Arc::clone(&nat);

    thread::Builder::new()
        .name("wgnat-smoltcp".into())
        .spawn(move || run_smoltcp_thread(addr, rx_rx, tx_tx, cmd_rx, evt_tx, nat_thread))
        .expect("spawn smoltcp thread");

    (
        SmoltcpHandle { cmd_tx, rx_tx },
        SmoltcpEvents { evt_rx },
        tx_rx,
    )
}

/// The smoltcp thread's view of an open connection. Owned exclusively by
/// the smoltcp thread; never crosses a channel.
struct ConnState {
    handle: SocketHandle,
    key: NatKey,
}

fn run_smoltcp_thread(
    addr: Ipv4Cidr,
    rx_queue: PacketReceiver,
    tx_queue: PacketSender,
    mut cmd_rx: mpsc::UnboundedReceiver<SmoltcpCmd>,
    evt_tx: mpsc::UnboundedSender<SmoltcpEvent>,
    nat: Arc<NatTable>,
) {
    let mut device = ChannelDevice::new(rx_queue, tx_queue);
    let mut iface = build_interface(&addr, &mut device);
    let mut sockets: SocketSet<'static> = SocketSet::new(vec![]);

    let mut conns: HashMap<ConnectionId, ConnState> = HashMap::new();
    let mut by_handle: HashMap<SocketHandle, ConnectionId> = HashMap::new();
    let mut last_states: HashMap<ConnectionId, tcp::State> = HashMap::new();
    let mut next_id: u64 = 0;

    tracing::info!(addr = ?addr, "smoltcp thread started");

    loop {
        // 1. Drain commands first so a freshly registered listener is in place
        //    before its triggering SYN reaches `iface.poll`.
        while let Ok(cmd) = cmd_rx.try_recv() {
            handle_command(cmd, &mut sockets, &mut conns, &mut by_handle, &mut next_id, &nat);
        }

        // 2. Drive the stack. This consumes packets from the rx channel,
        //    runs state machines, emits packets onto the tx channel.
        let _ = iface.poll(SmolInstant::now(), &mut device, &mut sockets);

        // 3. Inspect each socket; emit events on transitions / data.
        let mut to_drop: Vec<ConnectionId> = Vec::new();
        for (handle, socket) in sockets.iter_mut() {
            let smoltcp::socket::Socket::Tcp(tcp_sock) = socket else {
                continue;
            };
            let Some(&id) = by_handle.get(&handle) else {
                continue;
            };
            let Some(state) = conns.get(&id) else {
                continue;
            };
            let key = state.key;

            let new_state = tcp_sock.state();
            let prev = last_states.get(&id).copied();

            if prev != Some(new_state) {
                last_states.insert(id, new_state);
                tracing::trace!(?id, ?key, ?prev, ?new_state, "tcp state change");

                if matches!(new_state, tcp::State::Established)
                    && !matches!(prev, Some(tcp::State::Established))
                {
                    nat.set_state(key, ConnectionState::Established);
                    let _ = evt_tx.send(SmoltcpEvent::TcpConnected { key, id });
                }

                // CLOSE_WAIT means peer has FIN'd us. Half-close signal.
                if matches!(new_state, tcp::State::CloseWait)
                    && !matches!(prev, Some(tcp::State::CloseWait))
                {
                    let _ = evt_tx.send(SmoltcpEvent::TcpFinFromPeer { key, id });
                }
            }

            if tcp_sock.can_recv() {
                let mut buf = vec![0u8; RECV_CHUNK];
                if let Ok(n) = tcp_sock.recv_slice(&mut buf) {
                    if n > 0 {
                        buf.truncate(n);
                        let _ = evt_tx.send(SmoltcpEvent::TcpData { key, id, data: buf });
                    }
                }
            }

            if matches!(new_state, tcp::State::Closed) {
                let _ = evt_tx.send(SmoltcpEvent::TcpClosed { key, id });
                nat.mark_closing(key, DEFAULT_TCP_GRACE);
                to_drop.push(id);
            }
        }

        for id in to_drop {
            if let Some(state) = conns.remove(&id) {
                sockets.remove(state.handle);
                by_handle.remove(&state.handle);
            }
            last_states.remove(&id);
        }

        thread::sleep(IDLE_SLEEP);
    }
}

fn handle_command(
    cmd: SmoltcpCmd,
    sockets: &mut SocketSet<'static>,
    conns: &mut HashMap<ConnectionId, ConnState>,
    by_handle: &mut HashMap<SocketHandle, ConnectionId>,
    next_id: &mut u64,
    nat: &NatTable,
) {
    match cmd {
        SmoltcpCmd::EnsureTcpListener { port, key, ready } => {
            // If we already have a listener for this key, hand back the same
            // id. Idempotent: callers can fire this on every inbound packet
            // without growing the socket set.
            if let Some(existing) = conns
                .iter()
                .find_map(|(id, st)| (st.key == key).then_some(*id))
            {
                let _ = ready.send(existing);
                return;
            }
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
            let mut sock = tcp::Socket::new(rx_buf, tx_buf);
            if let Err(e) = sock.listen(port) {
                tracing::warn!(port, ?e, "tcp listen failed");
                // Drop `ready` so the caller's await wakes up with an error.
                drop(ready);
                return;
            }
            let handle = sockets.add(sock);
            let id = ConnectionId(*next_id);
            *next_id += 1;
            conns.insert(id, ConnState { handle, key });
            by_handle.insert(handle, id);
            nat.set_id(key, id);
            let _ = ready.send(id);
        }
        SmoltcpCmd::WriteTcp { id, data, ack } => {
            // Stale id (already torn down). No-op with 0 bytes accepted —
            // the proxy task's pump will treat it as backpressure and exit
            // its loop on the next channel error.
            let Some(state) = conns.get(&id) else {
                let _ = ack.send(0);
                return;
            };
            let sock = sockets.get_mut::<tcp::Socket>(state.handle);
            let n = sock.send_slice(&data).unwrap_or(0);
            let _ = ack.send(n);
        }
        SmoltcpCmd::CloseTcp { id } => {
            let Some(state) = conns.get(&id) else { return };
            let sock = sockets.get_mut::<tcp::Socket>(state.handle);
            sock.close();
        }
        SmoltcpCmd::AbortTcp { id } => {
            let Some(state) = conns.get(&id) else { return };
            let sock = sockets.get_mut::<tcp::Socket>(state.handle);
            sock.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nat::NatTable;
    use crate::rewrite::PROTO_TCP;
    use std::net::Ipv4Addr;
    use std::time::Duration as StdDuration;

    fn build_tcp_syn(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = PROTO_TCP;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let csum = !(sum as u16);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = 0x02; // SYN
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
        let tcp_len = 20u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&pkt[12..16]);
        buf.extend_from_slice(&pkt[16..20]);
        buf.push(0);
        buf.push(PROTO_TCP);
        buf.extend_from_slice(&tcp_len.to_be_bytes());
        buf.extend_from_slice(&pkt[20..]);
        let mut s: u32 = 0;
        let mut i = 0;
        while i + 1 < buf.len() {
            s += u16::from_be_bytes([buf[i], buf[i + 1]]) as u32;
            i += 2;
        }
        while (s >> 16) != 0 {
            s = (s & 0xFFFF) + (s >> 16);
        }
        let tc = !(s as u16);
        pkt[36..38].copy_from_slice(&tc.to_be_bytes());
        pkt
    }

    #[tokio::test]
    async fn runtime_emits_synack_for_listened_port() {
        let nat = Arc::new(NatTable::new(Ipv4Addr::new(10, 0, 0, 2)));
        let cidr: Ipv4Cidr = "10.0.0.2/24".parse().unwrap();
        let (handle, _events, mut tx_rx) = spawn_smoltcp(Arc::clone(&nat), cidr);

        let mut syn = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            8080,
        );
        let key = nat.rewrite_inbound(&mut syn).unwrap();

        // Set up listener BEFORE enqueueing the packet so the SYN finds it.
        let id = handle.ensure_listener(8080, key).await.unwrap();
        assert_eq!(nat.get(key).unwrap().smoltcp_id, Some(id));

        handle.enqueue_inbound(syn);

        // Spin until smoltcp emits a SYN-ACK.
        let mut found = None;
        for _ in 0..200 {
            tokio::time::sleep(StdDuration::from_millis(5)).await;
            if let Ok(p) = tx_rx.try_recv() {
                found = Some(p);
                break;
            }
        }
        let mut out = found.expect("expected SYN-ACK from smoltcp runtime");
        let ihl = ((out[0] & 0x0F) as usize) * 4;
        let flags = out[ihl + 13];
        assert_eq!(flags & 0x12, 0x12, "must be SYN-ACK");

        // After egress rewrite, src should be the original dst.
        let restored = nat.rewrite_outbound(&mut out).unwrap();
        assert_eq!(restored.original_dst_ip, Ipv4Addr::new(192, 168, 1, 50));
    }
}
