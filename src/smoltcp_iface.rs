//! smoltcp `Device` implementation backed by tokio mpsc channels. Inbound
//! packets (from the WireGuard tunnel after destination rewrite) are pushed
//! into the rx sender; outbound packets emitted by smoltcp are forwarded out
//! the tx sender for src-IP rewrite + WireGuard encapsulation.
//!
//! smoltcp's `Interface::poll` is single-threaded and pull-based — the
//! `SmoltcpRuntime` (Phase 4) wraps everything in a dedicated thread plus a
//! command channel. For Phase 2 we expose the building blocks so tests can
//! drive `Interface::poll` directly.
//!
//! Tokio `UnboundedSender::send` is sync; `UnboundedReceiver::try_recv` is
//! sync. That's exactly the shape smoltcp's blocking poll loop needs, while
//! still letting tokio tasks consume the receiver asynchronously.

use smoltcp::iface::{Config as IfaceConfig, Interface};
use smoltcp::phy::{self, DeviceCapabilities, Medium};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr};
use tokio::sync::mpsc::{self, error::TryRecvError};

use crate::config::Ipv4Cidr;

/// MTU presented to smoltcp. WireGuard adds 32 bytes of overhead to a 1500
/// byte underlying MTU; we round to a safe 1420.
pub const MTU: usize = 1420;

pub type PacketSender = mpsc::UnboundedSender<Vec<u8>>;
pub type PacketReceiver = mpsc::UnboundedReceiver<Vec<u8>>;

/// `Device` implementation that reads inbound packets from `rx` (a receiver
/// owned by the smoltcp thread) and emits outbound packets via `tx` (a
/// sender shared with the egress task).
pub struct ChannelDevice {
    rx: PacketReceiver,
    tx: PacketSender,
    mtu: usize,
}

impl ChannelDevice {
    pub fn new(rx: PacketReceiver, tx: PacketSender) -> Self {
        Self { rx, tx, mtu: MTU }
    }
}

pub struct ChannelRxToken {
    buffer: Vec<u8>,
}

impl phy::RxToken for ChannelRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

pub struct ChannelTxToken {
    tx: PacketSender,
}

impl phy::TxToken for ChannelTxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        // Receiver hangs up only on shutdown; failure here is harmless.
        let _ = self.tx.send(buf);
        r
    }
}

impl phy::Device for ChannelDevice {
    type RxToken<'a>
        = ChannelRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = ChannelTxToken
    where
        Self: 'a;

    fn receive(
        &mut self,
        _ts: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        match self.rx.try_recv() {
            Ok(buf) => Some((
                ChannelRxToken { buffer: buf },
                ChannelTxToken { tx: self.tx.clone() },
            )),
            Err(TryRecvError::Empty | TryRecvError::Disconnected) => None,
        }
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(ChannelTxToken { tx: self.tx.clone() })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

/// Build a smoltcp `Interface` for IP medium with the given gateway address.
pub fn build_interface(addr: &Ipv4Cidr, device: &mut ChannelDevice) -> Interface {
    let config = IfaceConfig::new(HardwareAddress::Ip);
    let mut iface = Interface::new(config, device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::Ipv4(*addr))
            .expect("IP address vec full — should hold at least one");
    });
    iface
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::iface::SocketSet;
    use smoltcp::socket::tcp;
    use std::net::Ipv4Addr;

    use crate::nat::NatTable;
    use crate::rewrite;

    fn build_tcp_syn(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = rewrite::PROTO_TCP;
        pkt[12..16].copy_from_slice(&src.octets());
        pkt[16..20].copy_from_slice(&dst.octets());
        // ip checksum
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
        pkt[24..28].copy_from_slice(&seq.to_be_bytes());
        pkt[32] = 0x50;
        pkt[33] = 0x02; // SYN
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());

        // tcp checksum (pseudo-header + segment)
        let tcp_len = 20u16;
        let mut buf = Vec::new();
        buf.extend_from_slice(&pkt[12..16]);
        buf.extend_from_slice(&pkt[16..20]);
        buf.push(0);
        buf.push(rewrite::PROTO_TCP);
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

    /// Functional test for Phase 2: synthetic TCP SYN through the rewrite shim
    /// + smoltcp produces a SYN-ACK at the device tx queue, which after the
    ///   outbound rewrite has src restored to the original destination.
    #[test]
    fn syn_through_pipeline_yields_synack() {
        let smoltcp_addr = Ipv4Addr::new(10, 0, 0, 2);
        let cidr = crate::config::parse_ipv4_cidr("10.0.0.2/24").unwrap();

        let (rx_tx, rx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let (tx_tx, mut tx_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let mut device = ChannelDevice::new(rx_rx, tx_tx);
        let mut iface = build_interface(&cidr, &mut device);

        let mut sockets = SocketSet::new(vec![]);

        let table = NatTable::new(smoltcp_addr);

        // Build a SYN from peer 10.0.0.1:54321 → 192.168.1.50:80 (original dst).
        let mut syn = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
            1000,
        );
        let (key, gateway_port) = table.rewrite_inbound(&mut syn).unwrap();
        assert_eq!(key.original_dst_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(key.original_dst_port, 80);

        // Bind the listener on the per-flow gateway_port — that's where
        // smoltcp will see the rewritten SYN arrive.
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
        let mut listener = tcp::Socket::new(rx_buf, tx_buf);
        listener.listen(gateway_port).expect("listen ok");
        let _handle = sockets.add(listener);

        rx_tx.send(syn).unwrap();

        // Poll smoltcp until it produces output.
        let mut produced = None;
        for _ in 0..16 {
            iface.poll(SmolInstant::now(), &mut device, &mut sockets);
            if let Ok(p) = tx_rx.try_recv() {
                produced = Some(p);
                break;
            }
        }
        let mut out = produced.expect("smoltcp should have produced a SYN-ACK");

        // Must be a SYN-ACK (flags = 0x12) before the rewrite pass.
        let view = rewrite::parse_5tuple(&out).unwrap();
        assert_eq!(view.proto, rewrite::PROTO_TCP);
        assert_eq!(view.src_ip, smoltcp_addr);
        assert_eq!(view.src_port, gateway_port);
        assert_eq!(view.dst_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(view.dst_port, 54321);
        let ihl = ((out[0] & 0x0F) as usize) * 4;
        let flags = out[ihl + 13];
        assert_eq!(flags & 0x12, 0x12, "SYN+ACK flags must be set");

        // Outbound rewrite restores the peer's view: src = original dst.
        let restored = table.rewrite_outbound(&mut out).unwrap();
        assert_eq!(restored.original_dst_ip, Ipv4Addr::new(192, 168, 1, 50));
        let view_after = rewrite::parse_5tuple(&out).unwrap();
        assert_eq!(view_after.src_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(view_after.src_port, 80);
    }
}
