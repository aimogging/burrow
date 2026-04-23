//! UDP ingress dispatch for wg_ip datagrams.
//!
//! Under the client-originated tunnel model, burrow does NOT originate
//! UDP to `forward_to`. When a peer sends a datagram to a registered
//! `(wg_ip, listen_port)`, we look up the tunnel in the registry, find
//! its `UdpTunnelHandle` in the side-table populated by
//! `control::spawn_udp_side`, and push `(peer_ip, peer_port, payload)`
//! into it. The owning client reads the framed datagram off its yamux
//! substream, delivers it to its local `forward_to`, and frames the
//! reply back. The reply arrives at `control::spawn_udp_side`'s reader
//! task, which constructs the outbound IPv4+UDP packet with
//! `src=(wg_ip, listen_port)` and emits it via `egress_tx`.
//!
//! This module used to carry an ephemeral-port state machine for the
//! old server-originated model; all of that went away when the tunnel
//! origination moved to the client.

use std::net::Ipv4Addr;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::control::UdpTunnelMap;
use crate::dns_service::{handle_query, DNS_PORT};
use crate::rewrite::{build_udp_packet, PacketView};
use crate::reverse_registry::ReverseRegistry;
use crate::udp_proxy::extract_udp_payload;
use crate::wire::Proto;

/// Dispatch a UDP datagram whose dst is `wg_ip`. Order of precedence:
/// 1. Registered reverse tunnel (forward path → push into yamux side-table).
/// 2. DNS service (dst_port == 53), unless `dns_enabled` is false.
/// Non-matching datagrams drop silently.
pub async fn dispatch_udp_to_wg_ip(
    packet: &[u8],
    view: &PacketView,
    wg_ip: Ipv4Addr,
    reverse_registry: &Arc<ReverseRegistry>,
    udp_tunnels: &UdpTunnelMap,
    egress_tx: &mpsc::UnboundedSender<Vec<u8>>,
    dns_enabled: bool,
) {
    let Some(payload) = extract_udp_payload(packet) else {
        tracing::debug!(?view, "malformed UDP to wg_ip — dropping");
        return;
    };
    // Forward path: peer sending to a registered UDP reverse tunnel.
    // Push into the per-tunnel side-table handle; spawn_udp_side's
    // writer task frames + sends over the yamux substream.
    if let Some(entry) = reverse_registry.lookup(Proto::Udp, view.dst_ip, view.dst_port, wg_ip) {
        let handle = udp_tunnels.lock().unwrap().get(&entry.tunnel_id).cloned();
        if let Some(tx) = handle {
            if tx.send((view.src_ip, view.src_port, payload)).is_err() {
                tracing::debug!(
                    ?view,
                    tunnel_id = ?entry.tunnel_id,
                    "UDP reverse: tunnel handle dropped — datagram lost"
                );
            }
        } else {
            tracing::debug!(
                ?view,
                tunnel_id = ?entry.tunnel_id,
                "UDP reverse: registry has entry but side-table is empty — datagram lost"
            );
        }
        return;
    }
    // DNS service: peers querying wg_ip as a resolver. Registered
    // tunnels on port 53 already took priority above.
    if dns_enabled && view.dst_port == DNS_PORT {
        if let Some(resp) = handle_query(&payload).await {
            let out = build_udp_packet(
                wg_ip,
                view.src_ip,
                DNS_PORT,
                view.src_port,
                &resp.payload,
            );
            let _ = egress_tx.send(out);
            return;
        }
    }
    tracing::debug!(?view, "UDP to wg_ip matched no handler — dropping");
}
