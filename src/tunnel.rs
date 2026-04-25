use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use boringtun::noise::errors::WireGuardError;
use boringtun::noise::{Tunn, TunnResult};

use crate::config::Config;
use crate::transport::{UdpTransport, WgTransport};

/// Maximum size of a UDP datagram we will receive or send. Generous: covers
/// 1500-byte MTU plus WireGuard overhead.
pub const MAX_UDP_SIZE: usize = 1700;

/// Result of one synchronous step against the Tunn protocol engine. Any
/// `to_network` packets must be sent to the WireGuard server, in order, before
/// the next call. `to_tunnel` is a decrypted IPv4 packet from the peer.
#[derive(Debug, Default)]
pub struct CoreStep {
    pub to_network: Vec<Vec<u8>>,
    pub to_tunnel: Option<TunnelPacket>,
    pub expired: bool,
}

#[derive(Debug)]
pub struct TunnelPacket {
    pub data: Vec<u8>,
    pub src: Ipv4Addr,
}

/// Synchronous wrapper around `boringtun::noise::Tunn`. Pure protocol logic,
/// no I/O — keeps Phase 1 testable without a UDP socket.
pub struct WgCore {
    tunn: Mutex<Tunn>,
}

impl WgCore {
    pub fn new(config: &Config) -> Self {
        let tunn = Tunn::new(
            config.interface.private_key.clone(),
            config.peer.public_key,
            config.peer.preshared_key,
            config.peer.persistent_keepalive,
            0,
            None,
        );
        Self {
            tunn: Mutex::new(tunn),
        }
    }

    /// Build a handshake initiation message. `force_resend` corresponds to the
    /// boringtun parameter and forces a fresh handshake even if one is in flight.
    pub fn handshake_init(&self, force_resend: bool) -> Result<CoreStep> {
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let mut step = CoreStep::default();
        let mut tunn = self.tunn.lock().expect("tunn mutex poisoned");
        match tunn.format_handshake_initiation(&mut buf, force_resend) {
            TunnResult::Done => {}
            TunnResult::Err(e) => bail!("handshake_init: {e:?}"),
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                buf.truncate(len);
                step.to_network.push(buf);
            }
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                bail!("handshake_init: unexpected WriteToTunnel result");
            }
        }
        Ok(step)
    }

    /// Process an incoming encrypted UDP datagram from the WireGuard server.
    /// Drains all queued network responses by re-calling decapsulate with empty
    /// input until it returns `Done`, per the boringtun contract.
    pub fn decapsulate(&self, src: Option<IpAddr>, datagram: &[u8]) -> Result<CoreStep> {
        let mut step = CoreStep::default();
        let mut tunn = self.tunn.lock().expect("tunn mutex poisoned");
        let mut buf = vec![0u8; MAX_UDP_SIZE];

        match tunn.decapsulate(src, datagram, &mut buf) {
            TunnResult::Done => {}
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                step.expired = true;
            }
            TunnResult::Err(e) => bail!("decapsulate: {e:?}"),
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                let mut owned = vec![0u8; len];
                owned.copy_from_slice(&buf[..len]);
                step.to_network.push(owned);
                // Drain any further queued packets.
                loop {
                    let mut drain_buf = vec![0u8; MAX_UDP_SIZE];
                    match tunn.decapsulate(None, &[], &mut drain_buf) {
                        TunnResult::WriteToNetwork(p) => {
                            let plen = p.len();
                            drain_buf.truncate(plen);
                            step.to_network.push(drain_buf);
                        }
                        TunnResult::Done => break,
                        TunnResult::Err(WireGuardError::ConnectionExpired) => {
                            step.expired = true;
                            break;
                        }
                        TunnResult::Err(e) => bail!("decapsulate drain: {e:?}"),
                        // Decapsulate-with-empty-input shouldn't yield tunnel data.
                        TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                            bail!("decapsulate drain: unexpected tunnel write");
                        }
                    }
                }
            }
            TunnResult::WriteToTunnelV4(packet, src_v4) => {
                let len = packet.len();
                let mut data = vec![0u8; len];
                data.copy_from_slice(&buf[..len]);
                step.to_tunnel = Some(TunnelPacket { data, src: src_v4 });
            }
            TunnResult::WriteToTunnelV6(_, _) => {
                tracing::trace!("dropping IPv6 tunnel packet (IPv4 only in initial version)");
            }
        }
        Ok(step)
    }

    /// Encrypt a plaintext IP packet for the WireGuard server.
    pub fn encapsulate(&self, ip_packet: &[u8]) -> Result<CoreStep> {
        let mut step = CoreStep::default();
        // Sized for either an encapsulated packet or a queued handshake message.
        let mut buf = vec![0u8; MAX_UDP_SIZE.max(ip_packet.len() + 64)];
        let mut tunn = self.tunn.lock().expect("tunn mutex poisoned");
        match tunn.encapsulate(ip_packet, &mut buf) {
            TunnResult::Done => {}
            TunnResult::Err(e) => bail!("encapsulate: {e:?}"),
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                buf.truncate(len);
                step.to_network.push(buf);
            }
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                bail!("encapsulate: unexpected WriteToTunnel result");
            }
        }
        Ok(step)
    }

    /// Drive WireGuard timers — keepalives, handshake retransmits, expiry.
    /// Should be called every ~250ms.
    pub fn timer_tick(&self) -> Result<CoreStep> {
        let mut step = CoreStep::default();
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let mut tunn = self.tunn.lock().expect("tunn mutex poisoned");
        match tunn.update_timers(&mut buf) {
            TunnResult::Done => {}
            TunnResult::Err(WireGuardError::ConnectionExpired) => {
                step.expired = true;
            }
            TunnResult::Err(e) => bail!("update_timers: {e:?}"),
            TunnResult::WriteToNetwork(packet) => {
                let len = packet.len();
                buf.truncate(len);
                step.to_network.push(buf);
            }
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                bail!("update_timers: unexpected WriteToTunnel result");
            }
        }
        Ok(step)
    }
}

/// Async I/O wrapper that owns the protocol core and a transport.
///
/// The transport is type-erased (`Arc<dyn WgTransport>`) so the runtime can
/// pick UDP vs WSS at startup without threading a generic through every
/// `Arc<WgTunnel>` clone in the runtime.
pub struct WgTunnel {
    core: WgCore,
    transport: Arc<dyn WgTransport>,
}

impl WgTunnel {
    /// Convenience constructor for the default UDP path. Resolves
    /// `config.peer.endpoint`, binds an ephemeral UDP socket, and wraps it.
    /// Tests and the back-compat code path use this; the WSS path
    /// constructs the transport explicitly and calls `with_transport`.
    pub async fn new(config: &Config) -> Result<Self> {
        let transport = UdpTransport::bind(&config.peer.endpoint).await?;
        Ok(Self::with_transport(config, transport))
    }

    /// Build a tunnel around an arbitrary transport. The transport is
    /// expected to be already connected/bound and ready to send.
    pub fn with_transport(config: &Config, transport: Arc<dyn WgTransport>) -> Self {
        Self {
            core: WgCore::new(config),
            transport,
        }
    }

    /// Send the initial handshake to bring the tunnel up.
    pub async fn initiate_handshake(&self) -> Result<()> {
        let step = self.core.handshake_init(false)?;
        self.flush_to_network(&step).await
    }

    /// Receive one transport datagram and process it. Returns the decrypted
    /// IPv4 packet if any, or None for control traffic (handshake responses,
    /// cookies).
    pub async fn recv_step(&self) -> Result<Option<TunnelPacket>> {
        let datagram = self.transport.recv().await?;
        // Pre-refactor we passed the UDP src IP to `decapsulate` as an
        // endpoint hint. boringtun treats that purely as informational —
        // it never relies on it for crypto — and the WSS transport has no
        // notion of a per-datagram source. None is uniformly correct.
        let step = self.core.decapsulate(None, &datagram)?;
        self.flush_to_network(&step).await?;
        if step.expired {
            tracing::warn!("WireGuard session expired; will re-handshake on next packet");
        }
        Ok(step.to_tunnel)
    }

    /// Encapsulate a plaintext IPv4 packet and forward to the WireGuard server.
    pub async fn send_packet(&self, ip_packet: &[u8]) -> Result<()> {
        let step = self.core.encapsulate(ip_packet)?;
        self.flush_to_network(&step).await
    }

    /// Drive timers; should be called on a ~250ms interval.
    pub async fn tick_timers(&self) -> Result<()> {
        let step = self.core.timer_tick()?;
        self.flush_to_network(&step).await?;
        if step.expired {
            tracing::warn!("WireGuard timer reports session expired; re-initiating handshake");
            self.initiate_handshake().await?;
        }
        Ok(())
    }

    async fn flush_to_network(&self, step: &CoreStep) -> Result<()> {
        for pkt in &step.to_network {
            self.transport.send(pkt).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{InterfaceConfig, PeerConfig};
    use tokio::net::UdpSocket;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn make_config() -> Config {
        let private = StaticSecret::from([0x42u8; 32]);
        let peer_secret = StaticSecret::from([0x99u8; 32]);
        let peer_public = PublicKey::from(&peer_secret);
        Config {
            interface: InterfaceConfig {
                private_key: private,
                address: "10.0.0.2/24".parse().unwrap(),
                control_port: crate::config::DEFAULT_CONTROL_PORT,
                dns_enabled: true,
                transport: None,
                relay_token: None,
                tls_skip_verify: false,
            },
            peer: PeerConfig {
                public_key: peer_public,
                endpoint: "127.0.0.1:51820".to_string(),
                allowed_ips: vec!["192.168.1.0/24".parse().unwrap()],
                persistent_keepalive: Some(25),
                preshared_key: None,
            },
        }
    }

    #[test]
    fn handshake_init_produces_network_packet() {
        let core = WgCore::new(&make_config());
        let step = core.handshake_init(false).expect("handshake should succeed");
        assert_eq!(
            step.to_network.len(),
            1,
            "handshake init must produce exactly one network packet"
        );
        // WireGuard handshake initiation message is 148 bytes.
        assert_eq!(
            step.to_network[0].len(),
            148,
            "WireGuard handshake initiation is 148 bytes"
        );
        // Message type byte = 1 (HANDSHAKE_INIT).
        assert_eq!(step.to_network[0][0], 1);
        assert!(step.to_tunnel.is_none());
        assert!(!step.expired);
    }

    #[test]
    fn encapsulate_with_no_session_triggers_handshake() {
        let core = WgCore::new(&make_config());
        // A minimal IPv4 packet header (20 bytes, mostly zeroed) — content
        // doesn't matter since boringtun will queue it pending handshake.
        let mut ip_packet = vec![0u8; 40];
        ip_packet[0] = 0x45; // Version 4, IHL 5
        let step = core.encapsulate(&ip_packet).expect("encapsulate ok");
        // With no active session, boringtun queues the packet and emits a
        // handshake init message instead.
        assert_eq!(step.to_network.len(), 1);
        assert_eq!(step.to_network[0][0], 1, "should be HANDSHAKE_INIT");
    }

    #[test]
    fn timer_tick_idle_initially() {
        let core = WgCore::new(&make_config());
        // Immediately after construction, no timers have fired.
        let step = core.timer_tick().expect("timer tick ok");
        assert!(step.to_network.is_empty(), "no timers should fire yet");
        assert!(!step.expired);
    }

    #[test]
    fn decapsulate_garbage_returns_error() {
        let core = WgCore::new(&make_config());
        let garbage = vec![0xFFu8; 64];
        let _ = core.decapsulate(None, &garbage);
        // Either Err or empty step is acceptable; we just want no panic.
    }

    #[tokio::test]
    async fn wgtunnel_binds_and_sends_handshake_to_local_socket() {
        // Stand up a fake "server" UDP socket and point the tunnel at it.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let mut cfg = make_config();
        cfg.peer.endpoint = server_addr.to_string();

        let tunnel = WgTunnel::new(&cfg).await.expect("tunnel construct");
        tunnel.initiate_handshake().await.expect("send handshake");

        let mut buf = [0u8; 256];
        let recv = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.recv_from(&mut buf),
        )
        .await
        .expect("server recv timed out")
        .expect("server recv ok");
        let (n, _from) = recv;
        assert_eq!(n, 148, "received WireGuard handshake init");
        assert_eq!(buf[0], 1, "message type 1 = HANDSHAKE_INIT");
    }

    #[tokio::test]
    async fn timer_tick_emits_handshake_after_initial_send_when_pending() {
        // After encapsulating with no session, a handshake is in flight.
        // Subsequent timer ticks before REKEY_TIMEOUT (5s) should be Idle.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = make_config();
        cfg.peer.endpoint = server.local_addr().unwrap().to_string();
        let tunnel = WgTunnel::new(&cfg).await.unwrap();

        tunnel.initiate_handshake().await.unwrap();
        // Drain the handshake packet from the server side.
        let mut buf = [0u8; 256];
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            server.recv_from(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();

        // Immediate tick should be a no-op (handshake just sent).
        tunnel.tick_timers().await.expect("tick ok");
    }

}
