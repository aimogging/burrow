//! Dynamic reverse-tunnel registry. Clients register `(proto, listen_port)
//! → forward_to`; wgnat's ingress dispatch checks the registry before
//! falling through to the NAT path.
//!
//! Port-collision: first registrant on a `(proto, listen_port)` wins.
//! Second gets `PortInUse`. Unregister releases the port.
//!
//! Lifetime: registrations are fire-and-forget — the registering client
//! disconnects immediately after the `Ok` response. Registrations persist
//! until `StopReverse` or wgnat restart. There's no automatic reap
//! in Phase 13; `ttl` is reserved as a follow-up.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::wire::{Proto, ReverseEntry, TunnelId};

#[derive(Clone, Debug)]
pub struct RegEntry {
    pub tunnel_id: TunnelId,
    pub proto: Proto,
    pub listen_port: u16,
    pub forward_to: SocketAddrV4,
}

impl From<&RegEntry> for ReverseEntry {
    fn from(e: &RegEntry) -> Self {
        ReverseEntry {
            tunnel_id: e.tunnel_id,
            proto: e.proto,
            listen_port: e.listen_port,
            forward_to: e.forward_to,
        }
    }
}

pub struct ReverseRegistry {
    next_id: AtomicU64,
    inner: Mutex<Inner>,
}

struct Inner {
    /// Primary index: (proto, listen_port) → entry. Port uniqueness is
    /// enforced here (collision check on insert).
    by_port: HashMap<(Proto, u16), RegEntry>,
    /// Secondary index: tunnel_id → (proto, listen_port). Lets
    /// `stop` find the primary entry without a linear scan.
    by_id: HashMap<TunnelId, (Proto, u16)>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StartError {
    PortInUse,
}

#[derive(Debug, PartialEq, Eq)]
pub enum StopError {
    UnknownTunnel,
}

impl ReverseRegistry {
    pub fn new() -> Self {
        Self {
            // Start at 1 so zero stays available as a sentinel "no tunnel"
            // if anyone later wants one.
            next_id: AtomicU64::new(1),
            inner: Mutex::new(Inner {
                by_port: HashMap::new(),
                by_id: HashMap::new(),
            }),
        }
    }

    pub fn start(
        &self,
        proto: Proto,
        listen_port: u16,
        forward_to: SocketAddrV4,
    ) -> Result<TunnelId, StartError> {
        let mut inner = self.inner.lock().unwrap();
        if inner.by_port.contains_key(&(proto, listen_port)) {
            return Err(StartError::PortInUse);
        }
        let tunnel_id = TunnelId(self.next_id.fetch_add(1, Ordering::Relaxed));
        let entry = RegEntry {
            tunnel_id,
            proto,
            listen_port,
            forward_to,
        };
        inner.by_port.insert((proto, listen_port), entry);
        inner.by_id.insert(tunnel_id, (proto, listen_port));
        Ok(tunnel_id)
    }

    pub fn stop(&self, tunnel_id: TunnelId) -> Result<(), StopError> {
        let mut inner = self.inner.lock().unwrap();
        let Some(key) = inner.by_id.remove(&tunnel_id) else {
            return Err(StopError::UnknownTunnel);
        };
        inner.by_port.remove(&key);
        Ok(())
    }

    pub fn lookup(&self, proto: Proto, listen_port: u16) -> Option<RegEntry> {
        self.inner
            .lock()
            .unwrap()
            .by_port
            .get(&(proto, listen_port))
            .cloned()
    }

    pub fn list(&self) -> Vec<ReverseEntry> {
        self.inner
            .lock()
            .unwrap()
            .by_port
            .values()
            .map(ReverseEntry::from)
            .collect()
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().by_port.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ReverseRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn sa(port: u16) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), port)
    }

    #[test]
    fn register_and_lookup_roundtrip() {
        let reg = ReverseRegistry::new();
        let id = reg.start(Proto::Tcp, 8080, sa(9000)).unwrap();
        let entry = reg.lookup(Proto::Tcp, 8080).unwrap();
        assert_eq!(entry.tunnel_id, id);
        assert_eq!(entry.forward_to, sa(9000));
        // UDP on same port should not collide with TCP.
        assert!(reg.lookup(Proto::Udp, 8080).is_none());
    }

    #[test]
    fn port_collision_rejected() {
        let reg = ReverseRegistry::new();
        reg.start(Proto::Tcp, 443, sa(443)).unwrap();
        let err = reg.start(Proto::Tcp, 443, sa(8443));
        assert_eq!(err, Err(StartError::PortInUse));
    }

    #[test]
    fn unregister_frees_port() {
        let reg = ReverseRegistry::new();
        let id = reg.start(Proto::Tcp, 8080, sa(9000)).unwrap();
        reg.stop(id).unwrap();
        // Now a fresh register should succeed.
        reg.start(Proto::Tcp, 8080, sa(9001)).unwrap();
        let entry = reg.lookup(Proto::Tcp, 8080).unwrap();
        assert_eq!(entry.forward_to, sa(9001));
    }

    #[test]
    fn unregister_unknown_errors() {
        let reg = ReverseRegistry::new();
        let err = reg.stop(TunnelId(999));
        assert_eq!(err, Err(StopError::UnknownTunnel));
    }

    #[test]
    fn list_returns_all_entries() {
        let reg = ReverseRegistry::new();
        reg.start(Proto::Tcp, 80, sa(80)).unwrap();
        reg.start(Proto::Tcp, 443, sa(443)).unwrap();
        reg.start(Proto::Udp, 53, sa(53)).unwrap();
        let list = reg.list();
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn tunnel_ids_are_unique() {
        let reg = ReverseRegistry::new();
        let a = reg.start(Proto::Tcp, 1, sa(1)).unwrap();
        let b = reg.start(Proto::Tcp, 2, sa(2)).unwrap();
        assert_ne!(a, b);
    }
}
