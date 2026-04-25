//! Transport abstraction for the WG datagrams between burrow and the WG
//! server.
//!
//! The original (and default) transport is plain UDP. A WebSocket-over-HTTPS
//! impl lives in `transport_wss.rs` for use against networks that only allow
//! egress 443. Adding more transports later (HTTP/2, QUIC, raw TCP framing)
//! is a localised change: drop a new `WgTransport` impl in, plumb it through
//! the CLI, nothing else has to move.
//!
//! ## Why a trait object instead of a generic
//!
//! `WgTunnel` is parameterised by neither: it stores `Arc<dyn WgTransport>`.
//! The runtime overhead (one virtual call per send/recv, both of which
//! already incur a syscall or WS framing pass) is negligible, and avoiding
//! a generic keeps the rest of the runtime — channel types, task spawning,
//! `Arc<WgTunnel>` clones across many futures — free of a trailing type
//! parameter.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::net::{lookup_host, UdpSocket};

use crate::tunnel::MAX_UDP_SIZE;

/// One frame in == one WG datagram in. Implementations must preserve frame
/// boundaries — no batching, no length prefix, no application-level framing.
/// (For UDP this is intrinsic; for WSS we use one binary frame per datagram.)
#[async_trait]
pub trait WgTransport: Send + Sync + 'static {
    /// Send a single WG datagram to the peer.
    async fn send(&self, packet: &[u8]) -> std::io::Result<()>;

    /// Receive the next WG datagram from the peer. Cancel-safe: dropping
    /// the returned future before it resolves must not lose or corrupt a
    /// datagram. UDP is naturally cancel-safe; WSS implements this via a
    /// background reader task draining into an mpsc channel.
    async fn recv(&self) -> std::io::Result<Vec<u8>>;
}

/// Plain UDP transport — the original behaviour. Binds an ephemeral local
/// socket and sends every datagram to a fixed remote endpoint.
pub struct UdpTransport {
    socket: UdpSocket,
    endpoint: SocketAddr,
}

impl UdpTransport {
    pub async fn bind(endpoint_str: &str) -> Result<Arc<Self>> {
        let endpoint = resolve_endpoint(endpoint_str).await?;
        let bind_addr = match endpoint {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };
        let socket = UdpSocket::bind(bind_addr).await?;
        disable_udp_connreset(&socket)?;
        Ok(Arc::new(Self { socket, endpoint }))
    }

    pub fn endpoint(&self) -> SocketAddr {
        self.endpoint
    }

    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

#[async_trait]
impl WgTransport for UdpTransport {
    async fn send(&self, packet: &[u8]) -> std::io::Result<()> {
        self.socket.send_to(packet, self.endpoint).await.map(|_| ())
    }

    async fn recv(&self) -> std::io::Result<Vec<u8>> {
        let mut buf = vec![0u8; MAX_UDP_SIZE];
        let (n, _src) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok(buf)
    }
}

async fn resolve_endpoint(addr: &str) -> Result<SocketAddr> {
    let mut iter = lookup_host(addr).await?;
    iter.find(|a| a.is_ipv4())
        .ok_or_else(|| anyhow!("no IPv4 address resolved for endpoint {addr}"))
}

/// On Windows, a UDP `recv()` returns `WSAECONNRESET` (10054) after a previous
/// `send_to()` provoked an ICMP port-unreachable. That permanently breaks the
/// recv loop here even though the WG socket is supposed to be connectionless —
/// any single misrouted packet would kill the tunnel. The `SIO_UDP_CONNRESET`
/// ioctl with FALSE suppresses this behavior. No-op everywhere else.
#[cfg(windows)]
fn disable_udp_connreset(socket: &UdpSocket) -> Result<()> {
    use std::os::windows::io::AsRawSocket;
    use windows_sys::Win32::Networking::WinSock::{WSAGetLastError, WSAIoctl, SIO_UDP_CONNRESET};

    let raw = socket.as_raw_socket() as windows_sys::Win32::Networking::WinSock::SOCKET;
    let value: u32 = 0;
    let mut bytes_returned: u32 = 0;
    let rc = unsafe {
        WSAIoctl(
            raw,
            SIO_UDP_CONNRESET,
            &value as *const _ as *const _,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            None,
        )
    };
    if rc != 0 {
        let err = unsafe { WSAGetLastError() };
        anyhow::bail!("WSAIoctl(SIO_UDP_CONNRESET) failed: WSAError {err}");
    }
    Ok(())
}

#[cfg(not(windows))]
fn disable_udp_connreset(_socket: &UdpSocket) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn udp_transport_send_recv_roundtrip() {
        // Two UDP transports point at each other (well, one points at a
        // UdpSocket impersonating the peer) and exchange one datagram.
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let transport = UdpTransport::bind(&peer_addr.to_string()).await.unwrap();

        // burrow → peer
        transport.send(b"hello").await.unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = peer.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // peer → burrow (reply path uses the source the peer just observed —
        // local_addr() returns the bind addr, which is 0.0.0.0:port, while
        // the peer sees 127.0.0.1:port).
        peer.send_to(b"world", from).await.unwrap();
        let got = transport.recv().await.unwrap();
        assert_eq!(got, b"world");
    }

    #[tokio::test]
    async fn udp_transport_resolves_hostname() {
        // localhost should resolve to an IPv4 address.
        let _t = UdpTransport::bind("localhost:65530").await.unwrap();
    }

    #[tokio::test]
    async fn udp_transport_rejects_v6_only_endpoint() {
        // Pure IPv6 literal has no IPv4 to bind against.
        let result = UdpTransport::bind("[::1]:65530").await;
        assert!(result.is_err());
    }
}
