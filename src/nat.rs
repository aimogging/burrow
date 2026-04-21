//! Connection tracking + destination/source IP rewrite. The NAT table is the
//! single source of truth for an in-flight connection: it owns the 4-tuple →
//! original-dst mapping (so the egress rewrite can restore the peer-visible
//! src), the smoltcp socket handle, and the lifecycle state.
//!
//! Two indices, per the design in CLAUDE.md:
//!   * `entries`: full 5-tuple (`NatKey`) → `NatEntry`
//!   * `by_4tuple`: post-rewrite 4-tuple → 5-tuple, used on egress when the
//!     original `dst_ip` has been replaced with the smoltcp interface address.
//!
//! 4-tuple collisions (same peer + dst_port hitting two different original
//! dst_ips concurrently) overwrite the older entry — they are negligibly
//! rare in practice and we don't multiplex.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Result};

use crate::rewrite::{parse_5tuple, rewrite_dst_ip, rewrite_src_ip, PROTO_TCP, PROTO_UDP};
use crate::runtime::ConnectionId;

/// Grace period after a TCP connection's smoltcp socket reports closed
/// before the entry is swept.
pub const DEFAULT_TCP_GRACE: Duration = Duration::from_secs(60);
/// Idle timeout for UDP entries (no smoltcp state to observe).
pub const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(30);

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
pub struct NatKey {
    pub proto: u8,
    pub peer_ip: Ipv4Addr,
    pub peer_port: u16,
    pub original_dst_ip: Ipv4Addr,
    pub local_port: u16,
}

#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
struct Key4 {
    proto: u8,
    peer_ip: Ipv4Addr,
    peer_port: u16,
    local_port: u16,
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
    pub original_dst_ip: Ipv4Addr,
    /// Set once the smoltcp thread has issued a `ConnectionId` for this NAT
    /// entry. `None` until the first `EnsureTcpListener` reply lands. Used by
    /// the ingress dispatcher to skip redundant listener-creation requests.
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

#[derive(Default)]
struct NatInner {
    entries: HashMap<NatKey, NatEntry>,
    by_4tuple: HashMap<Key4, NatKey>,
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

    /// Inbound rewrite (peer → smoltcp). Registers or refreshes the entry and
    /// swaps `dst_ip` → smoltcp address. Returns the connection's `NatKey`.
    pub fn rewrite_inbound(&self, packet: &mut [u8]) -> Result<NatKey> {
        let view = parse_5tuple(packet)?;
        if view.proto != PROTO_TCP && view.proto != PROTO_UDP {
            bail!("rewrite_inbound: unsupported proto {}", view.proto);
        }
        let key = NatKey {
            proto: view.proto,
            peer_ip: view.src_ip,
            peer_port: view.src_port,
            original_dst_ip: view.dst_ip,
            local_port: view.dst_port,
        };
        let key4 = key4_of(&key);
        let now = Instant::now();
        {
            let mut inner = self.inner.lock().unwrap();
            // 4-tuple collision: same peer + dst_port hitting a different
            // original dst. Evict the prior entry — we cannot multiplex.
            if let Some(prev_key) = inner.by_4tuple.get(&key4).copied() {
                if prev_key != key {
                    inner.entries.remove(&prev_key);
                    tracing::debug!(?prev_key, new = ?key, "evicted 4-tuple collision");
                }
            }
            let entry = inner.entries.entry(key).or_insert(NatEntry {
                original_dst_ip: view.dst_ip,
                smoltcp_id: None,
                state: ConnectionState::Pending,
                created: now,
                last_activity: now,
                expiry: None,
            });
            entry.last_activity = now;
            inner.by_4tuple.insert(key4, key);
        }
        rewrite_dst_ip(packet, self.smoltcp_addr)?;
        Ok(key)
    }

    /// Outbound rewrite (smoltcp → peer). Looks up the entry by 4-tuple
    /// (because `dst_ip` is now the smoltcp address) and restores `src_ip`
    /// to the original destination so the peer sees a coherent return path.
    pub fn rewrite_outbound(&self, packet: &mut [u8]) -> Result<NatKey> {
        let view = parse_5tuple(packet)?;
        let key4 = Key4 {
            proto: view.proto,
            peer_ip: view.dst_ip,
            peer_port: view.dst_port,
            local_port: view.src_port,
        };
        let (key, original_dst_ip) = {
            let mut inner = self.inner.lock().unwrap();
            let key = inner
                .by_4tuple
                .get(&key4)
                .copied()
                .ok_or_else(|| anyhow!("rewrite_outbound: no NAT entry for {:?}", key4))?;
            let entry = inner
                .entries
                .get_mut(&key)
                .ok_or_else(|| anyhow!("rewrite_outbound: entry vanished for {:?}", key))?;
            entry.last_activity = Instant::now();
            (key, entry.original_dst_ip)
        };
        rewrite_src_ip(packet, original_dst_ip)?;
        Ok(key)
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

fn key4_of(key: &NatKey) -> Key4 {
    Key4 {
        proto: key.proto,
        peer_ip: key.peer_ip,
        peer_port: key.peer_port,
        local_port: key.local_port,
    }
}

fn evict(inner: &mut NatInner, key: NatKey) {
    inner.entries.remove(&key);
    let k4 = key4_of(&key);
    if inner.by_4tuple.get(&k4) == Some(&key) {
        inner.by_4tuple.remove(&k4);
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
        let key = table.rewrite_inbound(&mut pkt).unwrap();
        assert_eq!(key.peer_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(key.original_dst_ip, Ipv4Addr::new(192, 168, 1, 50));
        assert_eq!(table.len(), 1);

        let entry = table.get(key).unwrap();
        assert_eq!(entry.state, ConnectionState::Pending);
        assert!(entry.smoltcp_id.is_none());
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
        let _ = table.rewrite_inbound(&mut ing).unwrap();

        // smoltcp would emit (src=10.0.0.2:80, dst=10.0.0.1:54321)
        let mut eg = build_tcp_syn(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 1),
            80,
            54321,
        );
        let key = table.rewrite_outbound(&mut eg).unwrap();
        assert_eq!(key.original_dst_ip, Ipv4Addr::new(192, 168, 1, 50));

        let view = crate::rewrite::parse_5tuple(&eg).unwrap();
        assert_eq!(view.src_ip, Ipv4Addr::new(192, 168, 1, 50));
    }

    #[test]
    fn collision_evicts_older_entry() {
        let table = NatTable::new(Ipv4Addr::new(10, 0, 0, 2));

        // Same peer+local_port, two different dst IPs. Second wins.
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
        let ka = table.rewrite_inbound(&mut a).unwrap();
        let kb = table.rewrite_inbound(&mut b).unwrap();
        assert_ne!(ka, kb);
        assert_eq!(table.len(), 1, "older entry must be evicted");
        assert!(table.get(ka).is_none());
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
        let key = table.rewrite_inbound(&mut pkt).unwrap();

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

        let key = table.rewrite_inbound(&mut pkt).unwrap();
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
