//! Per-flow state for UDP reverse tunnels.
//!
//! For each (peer_ip, peer_port, listen_port) flow the state holds an
//! ephemeral local port allocated on wgnat's WG address. Outbound
//! datagrams leave wgnat with src=(wg_ip, ephemeral_port); the response
//! from `forward_to` arrives with dst=(wg_ip, ephemeral_port) and the
//! reverse lookup maps back to the original peer.
//!
//! Entries age out after `DEFAULT_UDP_IDLE` of no activity — same
//! timeout convention as the forward-NAT UDP path.
//!
//! Unlike TCP reverse tunnels, we do NOT go through smoltcp at all —
//! ingest intercepts UDP to wg_ip, we rewrite headers in-place via
//! `rewrite::build_udp_packet`, and emit straight to the egress channel.
//! Stateless by design.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::dns_service::{handle_query, DNS_PORT};
use crate::rewrite::{build_udp_packet, PacketView};
use crate::reverse_registry::ReverseRegistry;
use crate::udp_proxy::extract_udp_payload;
use crate::wire::Proto;

/// Ephemeral port pool for originated outbound UDP. IANA ephemeral
/// range so it never collides with well-known listener ports.
const EPHEMERAL_MIN: u16 = 49152;
const EPHEMERAL_MAX: u16 = 65535;

#[derive(Clone, Copy, Debug)]
pub struct PeerFlow {
    pub peer_ip: Ipv4Addr,
    pub peer_port: u16,
    pub listen_port: u16,
}

#[derive(Clone, Copy, Debug)]
struct FlowState {
    ephemeral_port: u16,
    last_activity: Instant,
}

pub struct UdpReverseState {
    inner: Mutex<Inner>,
}

struct Inner {
    forward: HashMap<(Ipv4Addr, u16, u16), FlowState>,
    reverse: HashMap<u16, PeerFlow>,
    next_ephemeral: u16,
}

impl UdpReverseState {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                forward: HashMap::new(),
                reverse: HashMap::new(),
                next_ephemeral: EPHEMERAL_MIN,
            }),
        }
    }

    /// Look up or allocate the ephemeral port for a forward-path flow.
    /// Updates `last_activity`. Returns `None` if the ephemeral pool is
    /// fully saturated (pathological — 16K concurrent flows per listener).
    pub fn get_or_allocate_forward(
        &self,
        peer_ip: Ipv4Addr,
        peer_port: u16,
        listen_port: u16,
    ) -> Option<u16> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        let key = (peer_ip, peer_port, listen_port);
        if let Some(state) = inner.forward.get_mut(&key) {
            state.last_activity = now;
            return Some(state.ephemeral_port);
        }
        // Allocate a fresh ephemeral. Walk from the cursor; wrap at bounds.
        let start = clamp(inner.next_ephemeral);
        let mut candidate = start;
        loop {
            if !inner.reverse.contains_key(&candidate) {
                break;
            }
            candidate = advance(candidate);
            if candidate == start {
                return None; // pool exhausted
            }
        }
        inner.next_ephemeral = advance(candidate);
        inner.forward.insert(
            key,
            FlowState {
                ephemeral_port: candidate,
                last_activity: now,
            },
        );
        inner.reverse.insert(
            candidate,
            PeerFlow {
                peer_ip,
                peer_port,
                listen_port,
            },
        );
        Some(candidate)
    }

    /// Reverse lookup — given the dst_port on a response packet, return
    /// the originating peer flow if the port maps to an active flow.
    /// Updates `last_activity` on hit.
    pub fn lookup_response(&self, ephemeral_port: u16) -> Option<PeerFlow> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        let flow = inner.reverse.get(&ephemeral_port).copied()?;
        if let Some(state) = inner.forward.get_mut(&(
            flow.peer_ip,
            flow.peer_port,
            flow.listen_port,
        )) {
            state.last_activity = now;
        }
        Some(flow)
    }

    /// Remove flows idle longer than `idle_timeout`. Returns the number
    /// of entries removed.
    pub fn sweep_idle(&self, now: Instant, idle_timeout: Duration) -> usize {
        let mut inner = self.inner.lock().unwrap();
        let stale: Vec<((Ipv4Addr, u16, u16), u16)> = inner
            .forward
            .iter()
            .filter_map(|(k, v)| {
                if now.duration_since(v.last_activity) >= idle_timeout {
                    Some((*k, v.ephemeral_port))
                } else {
                    None
                }
            })
            .collect();
        let n = stale.len();
        for (k, port) in stale {
            inner.forward.remove(&k);
            inner.reverse.remove(&port);
        }
        n
    }

    /// Remove all state for a given listen_port — called when the
    /// reverse-tunnel registration for that port is removed.
    pub fn evict_listen_port(&self, listen_port: u16) {
        let mut inner = self.inner.lock().unwrap();
        let to_evict: Vec<((Ipv4Addr, u16, u16), u16)> = inner
            .forward
            .iter()
            .filter_map(|(k, v)| {
                if k.2 == listen_port {
                    Some((*k, v.ephemeral_port))
                } else {
                    None
                }
            })
            .collect();
        for (k, port) in to_evict {
            inner.forward.remove(&k);
            inner.reverse.remove(&port);
        }
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().forward.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for UdpReverseState {
    fn default() -> Self {
        Self::new()
    }
}

/// Dispatch a UDP datagram whose dst is `wg_ip`. Order of precedence:
/// 1. Ephemeral reverse-lookup (reply to an originated outbound).
/// 2. Registered reverse tunnel (forward path).
/// 3. DNS service (dst_port == 53), unless `dns_enabled` is false.
/// Non-matching datagrams drop silently.
pub async fn dispatch_udp_to_wg_ip(
    packet: &[u8],
    view: &PacketView,
    wg_ip: Ipv4Addr,
    reverse_registry: &Arc<ReverseRegistry>,
    udp_reverse: &Arc<UdpReverseState>,
    egress_tx: &mpsc::UnboundedSender<Vec<u8>>,
    dns_enabled: bool,
) {
    let Some(payload) = extract_udp_payload(packet) else {
        tracing::debug!(?view, "malformed UDP to wg_ip — dropping");
        return;
    };
    // Reply path: dst_port was previously allocated as an ephemeral for
    // a forward-path flow; this is the forward_to endpoint responding.
    if let Some(flow) = udp_reverse.lookup_response(view.dst_port) {
        let out = build_udp_packet(
            wg_ip,
            flow.peer_ip,
            flow.listen_port,
            flow.peer_port,
            &payload,
        );
        let _ = egress_tx.send(out);
        return;
    }
    // Forward path: peer sending to a registered UDP reverse tunnel.
    if let Some(entry) = reverse_registry.lookup(Proto::Udp, view.dst_port) {
        let Some(ephemeral) =
            udp_reverse.get_or_allocate_forward(view.src_ip, view.src_port, view.dst_port)
        else {
            tracing::warn!(?view, "UDP reverse: ephemeral pool exhausted");
            return;
        };
        let out = build_udp_packet(
            wg_ip,
            *entry.forward_to.ip(),
            ephemeral,
            entry.forward_to.port(),
            &payload,
        );
        let _ = egress_tx.send(out);
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

fn clamp(p: u16) -> u16 {
    if (EPHEMERAL_MIN..=EPHEMERAL_MAX).contains(&p) {
        p
    } else {
        EPHEMERAL_MIN
    }
}

fn advance(p: u16) -> u16 {
    if p >= EPHEMERAL_MAX {
        EPHEMERAL_MIN
    } else {
        p + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_and_reuses_per_flow() {
        let state = UdpReverseState::new();
        let a = state
            .get_or_allocate_forward(Ipv4Addr::new(10, 0, 0, 1), 55000, 53)
            .unwrap();
        let b = state
            .get_or_allocate_forward(Ipv4Addr::new(10, 0, 0, 1), 55000, 53)
            .unwrap();
        assert_eq!(a, b, "same flow must reuse ephemeral port");
    }

    #[test]
    fn distinct_flows_get_distinct_ports() {
        let state = UdpReverseState::new();
        let a = state
            .get_or_allocate_forward(Ipv4Addr::new(10, 0, 0, 1), 55000, 53)
            .unwrap();
        let b = state
            .get_or_allocate_forward(Ipv4Addr::new(10, 0, 0, 1), 55001, 53)
            .unwrap();
        assert_ne!(a, b);
        let c = state
            .get_or_allocate_forward(Ipv4Addr::new(10, 0, 0, 2), 55000, 53)
            .unwrap();
        assert_ne!(a, c);
    }

    #[test]
    fn response_lookup_round_trips() {
        let state = UdpReverseState::new();
        let port = state
            .get_or_allocate_forward(Ipv4Addr::new(10, 0, 0, 1), 55000, 53)
            .unwrap();
        let flow = state.lookup_response(port).unwrap();
        assert_eq!(flow.peer_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(flow.peer_port, 55000);
        assert_eq!(flow.listen_port, 53);
    }

    #[test]
    fn idle_sweep_removes_stale() {
        let state = UdpReverseState::new();
        let _ = state.get_or_allocate_forward(Ipv4Addr::new(10, 0, 0, 1), 55000, 53);
        let future = Instant::now() + Duration::from_secs(60);
        let removed = state.sweep_idle(future, Duration::from_secs(30));
        assert_eq!(removed, 1);
        assert!(state.is_empty());
    }

    #[test]
    fn evict_listen_port_clears_all_flows_for_that_port() {
        let state = UdpReverseState::new();
        state.get_or_allocate_forward(Ipv4Addr::new(10, 0, 0, 1), 55000, 53);
        state.get_or_allocate_forward(Ipv4Addr::new(10, 0, 0, 2), 55000, 53);
        state.get_or_allocate_forward(Ipv4Addr::new(10, 0, 0, 1), 55000, 80);
        state.evict_listen_port(53);
        assert_eq!(state.len(), 1, "only the port-80 flow survives");
    }
}
