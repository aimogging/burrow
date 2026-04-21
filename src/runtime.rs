//! Dedicated thread that owns the smoltcp `Interface`, `SocketSet`, and
//! `ChannelDevice`. smoltcp's API is single-threaded and pull-based, so all
//! manipulation funnels through this thread via a command channel. State
//! changes and inbound data flow back to the tokio runtime through an event
//! channel.
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
use crate::smoltcp_iface::{build_interface, new_queue, ChannelDevice, PacketQueue};

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

pub enum SmoltcpCmd {
    /// Idempotently create a TCP listener bound to `port` and tag it with
    /// `key` so the runtime can route the eventual ESTABLISHED event to the
    /// right NAT entry. Replies once with the chosen `SocketHandle`.
    EnsureTcpListener {
        port: u16,
        key: NatKey,
        ready: oneshot::Sender<SocketHandle>,
    },
    /// Append `data` to the smoltcp socket's tx buffer. Replies with the
    /// number of bytes accepted (0 if the buffer is full or the socket is
    /// not in a sendable state — caller should retry).
    WriteTcp {
        handle: SocketHandle,
        data: Vec<u8>,
        ack: oneshot::Sender<usize>,
    },
    /// Initiate a graceful close (FIN). Returns when the command is
    /// dispatched, not when the close completes.
    CloseTcp { handle: SocketHandle },
    /// Send RST.
    AbortTcp { handle: SocketHandle },
}

#[derive(Debug)]
pub enum SmoltcpEvent {
    /// Socket transitioned to ESTABLISHED. Spawn a proxy task here.
    TcpConnected { key: NatKey, handle: SocketHandle },
    /// Bytes were received on a socket. May arrive in many small chunks.
    TcpData {
        key: NatKey,
        handle: SocketHandle,
        data: Vec<u8>,
    },
    /// Socket entered a closing state (FIN from peer). Caller should
    /// half-close the OS-side stream's write half.
    TcpFinFromPeer { key: NatKey, handle: SocketHandle },
    /// Socket reached terminal CLOSED state. The `SocketHandle` is no longer
    /// valid after this event.
    TcpClosed { key: NatKey, handle: SocketHandle },
}

/// Cheap-to-clone handle for issuing commands and feeding packets to/from
/// the smoltcp thread.
#[derive(Clone)]
pub struct SmoltcpHandle {
    cmd_tx: mpsc::UnboundedSender<SmoltcpCmd>,
    pub rx_queue: PacketQueue,
    pub tx_queue: PacketQueue,
}

impl SmoltcpHandle {
    /// Push an inbound packet (already dst-rewritten by the NAT table) into
    /// the smoltcp Device's rx queue.
    pub fn enqueue_inbound(&self, packet: Vec<u8>) {
        self.rx_queue.lock().unwrap().push_back(packet);
    }

    /// Drain all currently queued outbound packets from the smoltcp Device.
    /// Returned packets still have `src = smoltcp_addr` — caller must run
    /// them through `NatTable::rewrite_outbound` before encapsulation.
    pub fn drain_outbound(&self) -> Vec<Vec<u8>> {
        let mut q = self.tx_queue.lock().unwrap();
        q.drain(..).collect()
    }

    pub fn ensure_listener(&self, port: u16, key: NatKey) -> oneshot::Receiver<SocketHandle> {
        let (tx, rx) = oneshot::channel();
        let _ = self.cmd_tx.send(SmoltcpCmd::EnsureTcpListener {
            port,
            key,
            ready: tx,
        });
        rx
    }

    pub async fn write_tcp(&self, handle: SocketHandle, data: Vec<u8>) -> Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(SmoltcpCmd::WriteTcp {
                handle,
                data,
                ack: tx,
            })
            .map_err(|_| anyhow!("smoltcp thread terminated"))?;
        rx.await
            .map_err(|_| anyhow!("smoltcp thread dropped reply"))
    }

    pub fn close_tcp(&self, handle: SocketHandle) {
        let _ = self.cmd_tx.send(SmoltcpCmd::CloseTcp { handle });
    }

    pub fn abort_tcp(&self, handle: SocketHandle) {
        let _ = self.cmd_tx.send(SmoltcpCmd::AbortTcp { handle });
    }
}

pub struct SmoltcpEvents {
    pub evt_rx: mpsc::UnboundedReceiver<SmoltcpEvent>,
}

pub fn spawn_smoltcp(nat: Arc<NatTable>, addr: Ipv4Cidr) -> (SmoltcpHandle, SmoltcpEvents) {
    let rx_queue = new_queue();
    let tx_queue = new_queue();
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (evt_tx, evt_rx) = mpsc::unbounded_channel();

    let rxq = Arc::clone(&rx_queue);
    let txq = Arc::clone(&tx_queue);
    let nat_thread = Arc::clone(&nat);

    thread::Builder::new()
        .name("wgnat-smoltcp".into())
        .spawn(move || run_smoltcp_thread(addr, rxq, txq, cmd_rx, evt_tx, nat_thread))
        .expect("spawn smoltcp thread");

    (
        SmoltcpHandle {
            cmd_tx,
            rx_queue,
            tx_queue,
        },
        SmoltcpEvents { evt_rx },
    )
}

fn run_smoltcp_thread(
    addr: Ipv4Cidr,
    rx_queue: PacketQueue,
    tx_queue: PacketQueue,
    mut cmd_rx: mpsc::UnboundedReceiver<SmoltcpCmd>,
    evt_tx: mpsc::UnboundedSender<SmoltcpEvent>,
    nat: Arc<NatTable>,
) {
    let mut device = ChannelDevice::new(rx_queue, tx_queue);
    let mut iface = build_interface(&addr, &mut device);
    let mut sockets: SocketSet<'static> = SocketSet::new(vec![]);

    let mut handle_to_key: HashMap<SocketHandle, NatKey> = HashMap::new();
    let mut last_states: HashMap<SocketHandle, tcp::State> = HashMap::new();

    tracing::info!(addr = ?addr, "smoltcp thread started");

    loop {
        // 1. Drain commands first so a freshly registered listener is in place
        //    before its triggering SYN reaches `iface.poll`.
        while let Ok(cmd) = cmd_rx.try_recv() {
            handle_command(cmd, &mut sockets, &mut handle_to_key, &nat);
        }

        // 2. Drive the stack. This consumes `device.rx`, runs state machines,
        //    fills `device.tx`.
        let _ = iface.poll(SmolInstant::now(), &mut device, &mut sockets);

        // 3. Inspect each socket; emit events on transitions / data.
        let mut to_drop: Vec<SocketHandle> = Vec::new();
        for (handle, socket) in sockets.iter_mut() {
            let smoltcp::socket::Socket::Tcp(tcp_sock) = socket else {
                continue;
            };
            let Some(&key) = handle_to_key.get(&handle) else {
                continue;
            };

            let new_state = tcp_sock.state();
            let prev = last_states.get(&handle).copied();

            if prev != Some(new_state) {
                last_states.insert(handle, new_state);
                tracing::trace!(?handle, ?key, ?prev, ?new_state, "tcp state change");

                if matches!(new_state, tcp::State::Established)
                    && !matches!(prev, Some(tcp::State::Established))
                {
                    nat.set_state(key, ConnectionState::Established);
                    let _ = evt_tx.send(SmoltcpEvent::TcpConnected { key, handle });
                }

                // CLOSE_WAIT means peer has FIN'd us. Half-close signal.
                if matches!(new_state, tcp::State::CloseWait)
                    && !matches!(prev, Some(tcp::State::CloseWait))
                {
                    let _ = evt_tx.send(SmoltcpEvent::TcpFinFromPeer { key, handle });
                }
            }

            if tcp_sock.can_recv() {
                let mut buf = vec![0u8; RECV_CHUNK];
                if let Ok(n) = tcp_sock.recv_slice(&mut buf) {
                    if n > 0 {
                        buf.truncate(n);
                        let _ = evt_tx.send(SmoltcpEvent::TcpData { key, handle, data: buf });
                    }
                }
            }

            if matches!(new_state, tcp::State::Closed) {
                let _ = evt_tx.send(SmoltcpEvent::TcpClosed { key, handle });
                nat.mark_closing(key, DEFAULT_TCP_GRACE);
                to_drop.push(handle);
            }
        }

        for handle in to_drop {
            sockets.remove(handle);
            handle_to_key.remove(&handle);
            last_states.remove(&handle);
        }

        thread::sleep(IDLE_SLEEP);
    }
}

fn handle_command(
    cmd: SmoltcpCmd,
    sockets: &mut SocketSet<'static>,
    handle_to_key: &mut HashMap<SocketHandle, NatKey>,
    nat: &NatTable,
) {
    match cmd {
        SmoltcpCmd::EnsureTcpListener { port, key, ready } => {
            // If we already have a listener for this key, hand back the same
            // handle. Idempotent: callers can fire this on every inbound
            // packet without growing the socket set.
            if let Some(existing) = handle_to_key
                .iter()
                .find_map(|(h, k)| (*k == key).then_some(*h))
            {
                let _ = ready.send(existing);
                return;
            }
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_BUF_SIZE]);
            let mut sock = tcp::Socket::new(rx_buf, tx_buf);
            if let Err(e) = sock.listen(port) {
                tracing::warn!(port, ?e, "tcp listen failed");
                return;
            }
            let handle = sockets.add(sock);
            handle_to_key.insert(handle, key);
            nat.set_handle(key, handle);
            let _ = ready.send(handle);
        }
        SmoltcpCmd::WriteTcp { handle, data, ack } => {
            let sock = sockets.get_mut::<tcp::Socket>(handle);
            let n = sock.send_slice(&data).unwrap_or(0);
            let _ = ack.send(n);
        }
        SmoltcpCmd::CloseTcp { handle } => {
            let sock = sockets.get_mut::<tcp::Socket>(handle);
            sock.close();
        }
        SmoltcpCmd::AbortTcp { handle } => {
            let sock = sockets.get_mut::<tcp::Socket>(handle);
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
        let (handle, _events) = spawn_smoltcp(Arc::clone(&nat), cidr);

        let mut syn = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            8080,
        );
        let key = nat.rewrite_inbound(&mut syn).unwrap();

        // Set up listener BEFORE enqueueing the packet so the SYN finds it.
        let h = handle.ensure_listener(8080, key).await.unwrap();
        assert_eq!(nat.get(key).unwrap().smoltcp_handle, Some(h));

        handle.enqueue_inbound(syn);

        // Spin until smoltcp emits a SYN-ACK.
        let mut found = None;
        for _ in 0..200 {
            tokio::time::sleep(StdDuration::from_millis(5)).await;
            let pkts = handle.drain_outbound();
            if let Some(p) = pkts.into_iter().next() {
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
