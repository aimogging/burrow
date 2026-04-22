//! Connection tracking + destination/source IP rewrite. The NAT table is the
//! single source of truth for an in-flight connection: it owns the 5-tuple →
//! gateway-side port mapping (so the egress rewrite can restore the
//! peer-visible src), the smoltcp ConnectionId, and the lifecycle state.
//!
//! ## Two-index design
//!
//! * `entries`: full 5-tuple (`NatKey`) → `NatEntry`. `NatEntry` carries the
//!   per-flow `gateway_port`.
//! * `by_gateway`: post-rewrite 4-tuple `(proto, peer_ip, peer_port,
//!   gateway_port)` → 5-tuple `NatKey`, used on egress when both the original
//!   `dst_ip` AND `dst_port` have been replaced with smoltcp-side values.
//!
//! ## Why per-flow gateway ports
//!
//! Pre-Phase-9 the second index was keyed on `(peer_ip, peer_port,
//! original_dst_port)` — the original dst_port was preserved on rewrite and
//! used as the egress disambiguator. That broke under any port-scan workload
//! (`nmap -sS` reuses ONE source port across hundreds of destinations on the
//! SAME dst port), because every new SYN from `(peer, peer_port)` to a
//! different `original_dst_ip` on the same `dst_port` collided on the index
//! and silently evicted the prior in-flight flow.
//!
//! Fix: on inbound, allocate a per-flow `gateway_port` from a global pool
//! (32768..=65535) and rewrite the packet's `dst_port` to it. Each flow now
//! has its own (smoltcp listener, gateway_port) pair, so the egress lookup
//! `(proto, peer_ip, peer_port, gateway_port)` is unique by construction and
//! no flow can stomp another.

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};

use crate::rewrite::{
    parse_5tuple, rewrite_dst_ip, rewrite_dst_port, rewrite_src_ip, rewrite_src_port,
    PROTO_TCP, PROTO_UDP,
};
use crate::runtime::ConnectionId;

/// Grace period after a TCP connection's smoltcp socket reports closed
/// before the entry is swept.
pub const DEFAULT_TCP_GRACE: Duration = Duration::from_secs(60);
/// Idle timeout for UDP entries (no smoltcp state to observe).
pub const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(30);

/// Lower bound of the per-flow gateway-port pool. Conventional ephemeral
/// range; well below the registered-port boundary so we don't shadow anything.
const GW_PORT_MIN: u16 = 32768;
/// Upper bound (inclusive) of the gateway-port pool.
const GW_PORT_MAX: u16 = 65535;

/// Natural 5-tuple identifying a peer-initiated flow. Derivable purely from
/// the inbound packet — NO gateway-side state in here. The gateway_port that
/// disambiguates the egress side lives on `NatEntry`.
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct NatKey {
    pub proto: u8,
    pub peer_ip: Ipv4Addr,
    pub peer_port: u16,
    pub original_dst_ip: Ipv4Addr,
    pub original_dst_port: u16,
}

/// Egress-side index key. The peer's view of the smoltcp endpoint is
/// `(smoltcp_addr, gateway_port)`, so when an outbound packet from smoltcp
/// arrives carrying `(src=smoltcp_addr, src_port=gateway_port,
/// dst=peer_ip, dst_port=peer_port)`, we recover the full 5-tuple via this
/// index.
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
struct KeyGw {
    proto: u8,
    peer_ip: Ipv4Addr,
    peer_port: u16,
    gateway_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Pending,
    Established,
    Closing,
    Closed,
}

#[derive(Debug, Clone, Copy)]
pub struct NatEntry {
    /// Per-flow port allocated on the smoltcp side. Inbound rewrite changes
    /// `dst_port` to this value; egress rewrite uses it to recover the
    /// `NatKey`.
    pub gateway_port: u16,
    /// Set once the smoltcp thread has issued a `ConnectionId` for this NAT
    /// entry. `None` until the first `EnsureTcpListener` reply lands (or for
    /// UDP entries, where smoltcp isn't involved).
    pub smoltcp_id: Option<ConnectionId>,
    pub state: ConnectionState,
    pub created: Instant,
    pub last_activity: Instant,
    pub expiry: Option<Instant>,
}

pub struct NatTable {
    smoltcp_addr: Ipv4Addr,
    inner: Mutex<NatInner>,
}

struct NatInner {
    entries: HashMap<NatKey, NatEntry>,
    by_gateway: HashMap<KeyGw, NatKey>,
    allocated_ports: HashSet<u16>,
    next_port: u16,
}

impl Default for NatInner {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            by_gateway: HashMap::new(),
            allocated_ports: HashSet::new(),
            next_port: GW_PORT_MIN,
        }
    }
}

impl NatTable {
    pub fn new(smoltcp_addr: Ipv4Addr) -> Self {
        Self {
            smoltcp_addr,
            inner: Mutex::new(NatInner::default()),
        }
    }

    pub fn smoltcp_addr(&self) -> Ipv4Addr {
        self.smoltcp_addr
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.lock().unwrap().entries.is_empty()
    }

    /// Inbound rewrite (peer → smoltcp). Registers or refreshes the entry,
    /// allocates a per-flow `gateway_port` on first sight, and rewrites BOTH
    /// `dst_ip` → smoltcp address AND `dst_port` → `gateway_port`. Returns
    /// the (5-tuple, gateway_port) so the caller can immediately register the
    /// matching smoltcp listener without a follow-up lookup.
    pub fn rewrite_inbound(&self, packet: &mut [u8]) -> Result<(NatKey, u16)> {
        let view = parse_5tuple(packet)?;
        if view.proto != PROTO_TCP && view.proto != PROTO_UDP {
            bail!("rewrite_inbound: unsupported proto {}", view.proto);
        }
        let key = NatKey {
            proto: view.proto,
            peer_ip: view.src_ip,
            peer_port: view.src_port,
            original_dst_ip: view.dst_ip,
            original_dst_port: view.dst_port,
        };
        let now = Instant::now();
        let gateway_port = {
            let mut inner = self.inner.lock().unwrap();
            // Hit on the existing 5-tuple → reuse its gateway_port.
            if let Some(entry) = inner.entries.get_mut(&key) {
                entry.last_activity = now;
                entry.gateway_port
            } else {
                // New flow → allocate a fresh gateway_port (collision-free
                // by construction with any other live entry).
                let gw = allocate_gateway_port(&mut inner)?;
                inner.entries.insert(
                    key,
                    NatEntry {
                        gateway_port: gw,
                        smoltcp_id: None,
                        state: ConnectionState::Pending,
                        created: now,
                        last_activity: now,
                        expiry: None,
                    },
                );
                inner.by_gateway.insert(
                    KeyGw {
                        proto: key.proto,
                        peer_ip: key.peer_ip,
                        peer_port: key.peer_port,
                        gateway_port: gw,
                    },
                    key,
                );
                gw
            }
        };
        rewrite_dst_ip(packet, self.smoltcp_addr)?;
        rewrite_dst_port(packet, gateway_port)?;
        Ok((key, gateway_port))
    }

    /// Outbound rewrite (smoltcp → peer). Looks up the entry by the
    /// gateway-side 4-tuple (because `dst_ip` is now the smoltcp address and
    /// `src_port` is the per-flow gateway_port) and restores BOTH `src_ip` →
    /// original_dst_ip AND `src_port` → original_dst_port so the peer sees a
    /// coherent return path.
    pub fn rewrite_outbound(&self, packet: &mut [u8]) -> Result<NatKey> {
        let view = parse_5tuple(packet)?;
        let key_gw = KeyGw {
            proto: view.proto,
            peer_ip: view.dst_ip,
            peer_port: view.dst_port,
            gateway_port: view.src_port,
        };
        let (key, original_dst_ip, original_dst_port) = {
            let mut inner = self.inner.lock().unwrap();
            let key = inner
                .by_gateway
                .get(&key_gw)
                .copied()
                .ok_or_else(|| anyhow!("rewrite_outbound: no NAT entry for {:?}", key_gw))?;
            let entry = inner
                .entries
                .get_mut(&key)
                .ok_or_else(|| anyhow!("rewrite_outbound: entry vanished for {:?}", key))?;
            entry.last_activity = Instant::now();
            (key, key.original_dst_ip, key.original_dst_port)
        };
        rewrite_src_ip(packet, original_dst_ip)?;
        rewrite_src_port(packet, original_dst_port)?;
        Ok(key)
    }

    /// Insert a `Pending` entry directly without touching the packet. Used by
    /// the connect-probe path (Phase 9 fix #1) to claim the NAT slot BEFORE
    /// any rewrite happens, so SYN retransmits arriving while the OS-side
    /// connect is in flight see an existing entry and short-circuit. Returns
    /// `None` if an entry already exists for this 5-tuple, leaving it in
    /// place. Returns `Some(gateway_port)` on a fresh insertion.
    pub fn try_reserve_pending(&self, key: NatKey) -> Result<Option<u16>> {
        let now = Instant::now();
        let mut inner = self.inner.lock().unwrap();
        if inner.entries.contains_key(&key) {
            return Ok(None);
        }
        let gw = allocate_gateway_port(&mut inner)?;
        inner.entries.insert(
            key,
            NatEntry {
                gateway_port: gw,
                smoltcp_id: None,
                state: ConnectionState::Pending,
                created: now,
                last_activity: now,
                expiry: None,
            },
        );
        inner.by_gateway.insert(
            KeyGw {
                proto: key.proto,
                peer_ip: key.peer_ip,
                peer_port: key.peer_port,
                gateway_port: gw,
            },
            key,
        );
        Ok(Some(gw))
    }

    /// Remove an entry — used by the probe-failure path to roll back a
    /// `try_reserve_pending` that didn't lead to a real connection.
    pub fn evict_key(&self, key: NatKey) {
        let mut inner = self.inner.lock().unwrap();
        evict(&mut inner, key);
    }

    pub fn set_id(&self, key: NatKey, id: ConnectionId) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.smoltcp_id = Some(id);
        }
    }

    pub fn set_state(&self, key: NatKey, state: ConnectionState) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.state = state;
        }
    }

    /// Begin the close grace period. Subsequent `sweep_expired(now)` calls
    /// will remove the entry once `now >= now_at_call + grace`.
    pub fn mark_closing(&self, key: NatKey, grace: Duration) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.state = ConnectionState::Closing;
            entry.expiry = Some(Instant::now() + grace);
        }
    }

    /// Force the entry to expire on the next sweep.
    pub fn mark_closed(&self, key: NatKey) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.state = ConnectionState::Closed;
            entry.expiry = Some(Instant::now());
        }
    }

    /// Update `last_activity` to now.
    pub fn touch(&self, key: NatKey) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(entry) = inner.entries.get_mut(&key) {
            entry.last_activity = Instant::now();
        }
    }

    /// Remove entries whose `expiry` has passed. Returns the removed keys.
    pub fn sweep_expired(&self, now: Instant) -> Vec<NatKey> {
        let mut inner = self.inner.lock().unwrap();
        let to_remove: Vec<NatKey> = inner
            .entries
            .iter()
            .filter_map(|(k, e)| match e.expiry {
                Some(exp) if exp <= now => Some(*k),
                _ => None,
            })
            .collect();
        for key in &to_remove {
            evict(&mut inner, *key);
        }
        to_remove
    }

    /// Remove UDP entries idle longer than `idle_timeout`.
    pub fn sweep_udp_idle(&self, now: Instant, idle_timeout: Duration) -> Vec<NatKey> {
        let mut inner = self.inner.lock().unwrap();
        let to_remove: Vec<NatKey> = inner
            .entries
            .iter()
            .filter_map(|(k, e)| {
                if k.proto == PROTO_UDP && now.duration_since(e.last_activity) >= idle_timeout {
                    Some(*k)
                } else {
                    None
                }
            })
            .collect();
        for key in &to_remove {
            evict(&mut inner, *key);
        }
        to_remove
    }

    pub fn get(&self, key: NatKey) -> Option<NatEntry> {
        self.inner.lock().unwrap().entries.get(&key).copied()
    }

    /// Visit every entry (for diagnostics or bulk operations on the smoltcp
    /// thread). Holds the lock for the duration of the call.
    pub fn for_each<F: FnMut(&NatKey, &NatEntry)>(&self, mut f: F) {
        let inner = self.inner.lock().unwrap();
        for (k, e) in inner.entries.iter() {
            f(k, e);
        }
    }
}

/// Walk `[next_port, GW_PORT_MAX] ∪ [GW_PORT_MIN, next_port)` looking for a
/// free slot in the pool. Errors only on full exhaustion (all 32768 ports
/// in use simultaneously — orders of magnitude beyond realistic load).
fn allocate_gateway_port(inner: &mut NatInner) -> Result<u16> {
    let start = inner.next_port.max(GW_PORT_MIN);
    let mut p = start;
    loop {
        if !inner.allocated_ports.contains(&p) {
            inner.allocated_ports.insert(p);
            inner.next_port = if p == GW_PORT_MAX { GW_PORT_MIN } else { p + 1 };
            return Ok(p);
        }
        p = if p == GW_PORT_MAX { GW_PORT_MIN } else { p + 1 };
        if p == start {
            bail!("gateway-port pool exhausted");
        }
    }
}

fn evict(inner: &mut NatInner, key: NatKey) {
    if let Some(entry) = inner.entries.remove(&key) {
        let kgw = KeyGw {
            proto: key.proto,
            peer_ip: key.peer_ip,
            peer_port: key.peer_port,
            gateway_port: entry.gateway_port,
        };
        if inner.by_gateway.get(&kgw) == Some(&key) {
            inner.by_gateway.remove(&kgw);
        }
        inner.allocated_ports.remove(&entry.gateway_port);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rewrite::PROTO_TCP;
    use std::thread::sleep;

    fn build_tcp_syn(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        // Reuse the same construction as rewrite::tests by inlining. Keeps
        // the modules independent.
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
        pkt[33] = 0x02;
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
        // tcp checksum
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

    #[test]
    fn ingress_creates_entry_and_rewrites_dst() {
        let table = NatTable::new(Ipv4Addr::new(10, 0, 0, 2));
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        let (key, gw) = table.rewrite_inbound(&mut pkt).unwrap();
        assert_eq!(key.peer_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(key.original_dst_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(key.original_dst_port, 80);
        assert!((GW_PORT_MIN..=GW_PORT_MAX).contains(&gw));
        assert_eq!(table.len(), 1);

        // packet's dst should now be (smoltcp_addr, gateway_port).
        let view = crate::rewrite::parse_5tuple(&pkt).unwrap();
        assert_eq!(view.dst_ip, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(view.dst_port, gw);

        let entry = table.get(key).unwrap();
        assert_eq!(entry.state, ConnectionState::Pending);
        assert!(entry.smoltcp_id.is_none());
        assert_eq!(entry.gateway_port, gw);
    }

    #[test]
    fn egress_restores_src_after_ingress() {
        let table = NatTable::new(Ipv4Addr::new(10, 0, 0, 2));
        let mut ing = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        let (_, gw) = table.rewrite_inbound(&mut ing).unwrap();

        // smoltcp would emit (src=10.0.0.2:gw, dst=10.0.0.1:54321)
        let mut eg = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            gw,
            54321,
        );
        let key = table.rewrite_outbound(&mut eg).unwrap();
        assert_eq!(key.original_dst_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(key.original_dst_port, 80);

        let view = crate::rewrite::parse_5tuple(&eg).unwrap();
        assert_eq!(view.src_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(view.src_port, 80);
    }

    #[test]
    fn same_4tuple_different_dst_ip_coexist() {
        // The whole reason for per-flow gateway-port allocation: nmap-style
        // workloads where one (peer_ip, peer_port) reaches many distinct
        // (dst_ip) on the same dst_port. Both flows must coexist with
        // distinct gateway_ports so neither stomps the other.
        let table = NatTable::new(Ipv4Addr::new(10, 0, 0, 2));
        let mut a = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        let mut b = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 99),
            54321,
            80,
        );
        let (ka, gwa) = table.rewrite_inbound(&mut a).unwrap();
        let (kb, gwb) = table.rewrite_inbound(&mut b).unwrap();
        assert_ne!(ka, kb);
        assert_ne!(gwa, gwb, "distinct flows must get distinct gateway_ports");
        assert_eq!(table.len(), 2, "both entries must coexist");
        assert!(table.get(ka).is_some());
        assert!(table.get(kb).is_some());
    }

    #[test]
    fn state_transitions_persist() {
        let table = NatTable::new(Ipv4Addr::new(10, 0, 0, 2));
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        let (key, _) = table.rewrite_inbound(&mut pkt).unwrap();

        table.set_state(key, ConnectionState::Established);
        assert_eq!(table.get(key).unwrap().state, ConnectionState::Established);

        table.mark_closing(key, Duration::from_millis(50));
        let entry = table.get(key).unwrap();
        assert_eq!(entry.state, ConnectionState::Closing);
        assert!(entry.expiry.is_some());

        // sweep before expiry → no removal
        let removed = table.sweep_expired(Instant::now());
        assert!(removed.is_empty());
        assert_eq!(table.len(), 1);

        sleep(Duration::from_millis(60));
        let removed = table.sweep_expired(Instant::now());
        assert_eq!(removed, vec![key]);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn evict_releases_gateway_port() {
        // After eviction, the gateway_port returns to the pool.
        let table = NatTable::new(Ipv4Addr::new(10, 0, 0, 2));
        let mut pkt = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(192, 168, 1, 50),
            54321,
            80,
        );
        let (key, gw) = table.rewrite_inbound(&mut pkt).unwrap();
        table.evict_key(key);
        assert!(table.get(key).is_none());
        assert!(
            !table.inner.lock().unwrap().allocated_ports.contains(&gw),
            "evicted gateway_port must be released"
        );
    }

    #[test]
    fn try_reserve_pending_idempotent() {
        let table = NatTable::new(Ipv4Addr::new(10, 0, 0, 2));
        let key = NatKey {
            proto: PROTO_TCP,
            peer_ip: Ipv4Addr::new(10, 0, 0, 1),
            peer_port: 54321,
            original_dst_ip: Ipv4Addr::new(192, 168, 1, 50),
            original_dst_port: 80,
        };
        let gw = table.try_reserve_pending(key).unwrap().expect("first reserve");
        assert!((GW_PORT_MIN..=GW_PORT_MAX).contains(&gw));
        let second = table.try_reserve_pending(key).unwrap();
        assert!(second.is_none(), "second reserve on same key must be a no-op");
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn udp_idle_sweep() {
        let table = NatTable::new(Ipv4Addr::new(10, 0, 0, 2));
        // Build a minimal UDP packet so we can register a UDP entry.
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = PROTO_UDP;
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 50]);
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        let csum = !(sum as u16);
        pkt[10..12].copy_from_slice(&csum.to_be_bytes());
        pkt[20..22].copy_from_slice(&53u16.to_be_bytes());
        pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
        pkt[24..26].copy_from_slice(&8u16.to_be_bytes());

        let (key, _) = table.rewrite_inbound(&mut pkt).unwrap();
        assert_eq!(key.proto, PROTO_UDP);

        // Idle of 0 from "now in the future" sweeps everything immediately.
        let future = Instant::now() + Duration::from_secs(60);
        let removed = table.sweep_udp_idle(future, Duration::from_secs(30));
        assert_eq!(removed, vec![key]);
    }

    #[test]
    fn outbound_without_entry_errors() {
        let table = NatTable::new(Ipv4Addr::new(10, 0, 0, 2));
        let mut eg = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            80,
            54321,
        );
        let err = table.rewrite_outbound(&mut eg).unwrap_err();
        assert!(err.to_string().contains("no NAT entry"));
    }

    #[test]
    fn icmp_inbound_rejected() {
        // ICMP is handled by the dedicated path in proxy/icmp.rs (Phase 6),
        // not by NAT. rewrite_inbound should bail.
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 1; // ICMP
        pkt[12..16].copy_from_slice(&[10, 0, 0, 1]);
        pkt[16..20].copy_from_slice(&[192, 168, 1, 50]);
        let table = NatTable::new(Ipv4Addr::new(10, 0, 0, 2));
        let err = table.rewrite_inbound(&mut pkt).unwrap_err();
        assert!(err.to_string().contains("unsupported proto"));
    }
}
