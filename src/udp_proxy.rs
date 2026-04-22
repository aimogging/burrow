//! Per-NAT-entry UDP forwarder. Unlike TCP, UDP has no connection state to
//! track, so we bypass smoltcp entirely: each NAT entry owns a real OS
//! `UdpSocket`, an inline pump for peer→internal datagrams, and a reader
//! task for internal→peer responses (which constructs an IPv4+UDP packet
//! and hands it to the supplied sink — typically the WireGuard tunnel).
//!
//! Lifetime: the proxy task lives until its inbound channel is dropped
//! (which the main loop does when `nat::sweep_udp_idle` removes the entry).

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::nat::NatKey;
use crate::rewrite::build_udp_packet;

/// Sink for outbound IPv4 packets the UDP proxy emits. Production wires this
/// to the WireGuard tunnel; tests feed it a plain channel for inspection.
pub type PacketSink = mpsc::UnboundedSender<Vec<u8>>;

/// Spawn a UDP forwarder for `key`. The returned sender accepts UDP payloads
/// extracted from inbound peer datagrams; each one is sent to the original
/// destination. Replies arrive on the OS socket and are pushed onto `sink`
/// as fully formed IPv4+UDP packets ready to be tunneled.
pub fn spawn_udp_proxy(key: NatKey, sink: PacketSink) -> mpsc::UnboundedSender<Vec<u8>> {
    let (tx, rx) = mpsc::unbounded_channel::<Vec<u8>>();
    tokio::spawn(async move {
        if let Err(e) = run_udp_proxy(key, sink, rx).await {
            tracing::warn!(?key, error = %e, "udp proxy task failed");
        }
        tracing::debug!(?key, "udp proxy task exiting");
    });
    tx
}

async fn run_udp_proxy(
    key: NatKey,
    sink: PacketSink,
    mut rx: mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<()> {
    let dst: SocketAddr = (key.original_dst_ip, key.original_dst_port).into();
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
    socket.connect(dst).await?;
    tracing::debug!(?key, ?dst, local = ?socket.local_addr().ok(), "udp proxy bound");

    // Reader task: OS socket → sink.
    let socket_for_reader = Arc::clone(&socket);
    let sink_for_reader = sink.clone();
    let reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        loop {
            match socket_for_reader.recv(&mut buf).await {
                Ok(n) => {
                    let pkt = build_udp_packet(
                        key.original_dst_ip,
                        key.peer_ip,
                        key.original_dst_port,
                        key.peer_port,
                        &buf[..n],
                    );
                    if sink_for_reader.send(pkt).is_err() {
                        tracing::debug!(?key, "udp packet sink closed; ending reader");
                        break;
                    }
                }
                Err(e) => {
                    tracing::debug!(?key, error = %e, "udp os recv ended");
                    break;
                }
            }
        }
    });

    // Inline pump: tunnel → OS socket. Ends when the NAT sweep drops the tx.
    while let Some(payload) = rx.recv().await {
        if let Err(e) = socket.send(&payload).await {
            tracing::debug!(?key, error = %e, "udp os send failed");
            break;
        }
    }

    reader.abort();
    Ok(())
}

/// Extract the UDP payload (bytes after IHL+8) from an inbound IPv4 packet.
/// Returns None if the packet is malformed or not UDP-shaped.
pub fn extract_udp_payload(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 28 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0F) as usize) * 4;
    if pkt.len() < ihl + 8 {
        return None;
    }
    Some(pkt[ihl + 8..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::PROTO_UDP;
    use std::net::Ipv4Addr;

    #[test]
    fn extract_udp_payload_strips_headers() {
        // 20 IP + 8 UDP + 5 payload
        let mut pkt = vec![0u8; 33];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&33u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = PROTO_UDP;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 50]);
        pkt[20..22].copy_from_slice(&53u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&33333u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&13u16.to_be_bytes());
        pkt[28..33].copy_from_slice(b"hello");
        let payload = extract_udp_payload(&pkt).unwrap();
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn extract_udp_payload_rejects_short() {
        assert!(extract_udp_payload(&[]).is_none());
        assert!(extract_udp_payload(&[0u8; 20]).is_none());
    }

    #[test]
    fn nat_key_dst_addr_format() {
        let key = NatKey {
            proto: 17,
            peer_ip: Ipv4Addr::new(10, 0, 0, 1),
            peer_port: 1234,
            original_dst_ip: Ipv4Addr::new(127, 0, 0, 1),
            original_dst_port: 5353,
        };
        let dst: SocketAddr = (key.original_dst_ip, key.original_dst_port).into();
        assert_eq!(dst.to_string(), "127.0.0.1:5353");
    }
}
