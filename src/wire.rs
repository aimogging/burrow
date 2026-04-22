//! Wire protocol types for the wgnat control channel.
//!
//! Encoded as CBOR (via `ciborium`) to give us compact binary with field
//! names preserved — good forward-compat for adding new variants without
//! breaking older clients. Each control-port TCP flow carries a single
//! `ClientReq` from the client followed by one `ServerResp` from the
//! server, framed as:
//!
//! ```text
//! | u32 be length | CBOR bytes |
//! ```
//!
//! One exception: `ClientReq::RequestShell` makes the flow bidirectional
//! for the session lifetime (landing in Phase 16). Phase 13 ships only
//! the request/response shapes.
//!
//! ## TunnelId opacity
//!
//! `TunnelId` is a plain wrapper around `u64` — server-assigned, client
//! stores it only so it can `UnregisterReverse`. Clients MUST NOT
//! interpret the value; format/layout is unspecified and may change.
//!
//! ## Frame-size cap
//!
//! The reader rejects frames whose length field exceeds `MAX_FRAME_LEN`.
//! A hostile or broken client could otherwise force the server to buffer
//! 4 GiB before failing. Control frames carry kilobyte-range payloads at
//! most — 1 MiB is already far more than any realistic request.

use std::io;
use std::net::SocketAddrV4;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard cap on a single control frame's encoded payload length. Matches
/// the check in `read_frame`.
pub const MAX_FRAME_LEN: u32 = 1 << 20;

/// Transport protocol selector for reverse-tunnel registrations.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

/// Server-assigned opaque handle. Clients pass it back for
/// `UnregisterReverse`. Server chooses the allocation scheme.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TunnelId(pub u64);

/// Shape of a `ListReverse` response entry. Kept small so the response
/// stays under `MAX_FRAME_LEN` even with thousands of active tunnels.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReverseEntry {
    pub tunnel_id: TunnelId,
    pub proto: Proto,
    pub listen_port: u16,
    pub forward_to: SocketAddrV4,
}

/// Reason codes for `ServerResp::Error`. Kept narrow so clients can match
/// on them — message string is for human eyes only.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorKind {
    PortInUse,
    UnknownTunnel,
    InvalidRequest,
    NotYetSupported,
    Internal,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ClientReq {
    RegisterReverse {
        proto: Proto,
        listen_port: u16,
        forward_to: SocketAddrV4,
    },
    UnregisterReverse {
        tunnel_id: TunnelId,
    },
    ListReverse,
    // Phase 16 will add `RequestShell { program, args, cols, rows }`.
    // Reserved tag slot so clients can feature-detect by attempting the
    // request and matching `Error{NotYetSupported}`.
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ServerResp {
    Ok { tunnel_id: TunnelId },
    Unregistered,
    ReverseList(Vec<ReverseEntry>),
    Error { kind: ErrorKind, msg: String },
}

/// Read one length-prefixed CBOR frame. Returns `Err(io::ErrorKind::UnexpectedEof)`
/// on clean close; any other error indicates a protocol violation.
pub async fn read_frame<R, T>(reader: &mut R) -> io::Result<T>
where
    R: AsyncRead + Unpin,
    T: for<'de> Deserialize<'de>,
{
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("control frame length {len} exceeds cap {MAX_FRAME_LEN}"),
        ));
    }
    let mut buf = vec![0u8; len as usize];
    reader.read_exact(&mut buf).await?;
    ciborium::de::from_reader(&buf[..])
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("cbor decode: {e}")))
}

/// Serialize and emit one length-prefixed CBOR frame.
pub async fn write_frame<W, T>(writer: &mut W, value: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut payload = Vec::new();
    ciborium::ser::into_writer(value, &mut payload)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("cbor encode: {e}")))?;
    let len = payload.len();
    if len > MAX_FRAME_LEN as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("encoded frame {len} exceeds cap {MAX_FRAME_LEN}"),
        ));
    }
    writer.write_all(&(len as u32).to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::duplex;

    #[tokio::test]
    async fn roundtrip_register_reverse() {
        let (mut a, mut b) = duplex(4096);
        let req = ClientReq::RegisterReverse {
            proto: Proto::Tcp,
            listen_port: 8080,
            forward_to: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000),
        };
        write_frame(&mut a, &req).await.unwrap();
        let got: ClientReq = read_frame(&mut b).await.unwrap();
        match got {
            ClientReq::RegisterReverse {
                proto,
                listen_port,
                forward_to,
            } => {
                assert_eq!(proto, Proto::Tcp);
                assert_eq!(listen_port, 8080);
                assert_eq!(forward_to, SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 9000));
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[tokio::test]
    async fn roundtrip_server_resp_list() {
        let (mut a, mut b) = duplex(4096);
        let resp = ServerResp::ReverseList(vec![ReverseEntry {
            tunnel_id: TunnelId(42),
            proto: Proto::Udp,
            listen_port: 53,
            forward_to: SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 53),
        }]);
        write_frame(&mut a, &resp).await.unwrap();
        let got: ServerResp = read_frame(&mut b).await.unwrap();
        match got {
            ServerResp::ReverseList(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].tunnel_id, TunnelId(42));
                assert_eq!(entries[0].proto, Proto::Udp);
            }
            _ => panic!("unexpected variant"),
        }
    }

    #[tokio::test]
    async fn oversized_frame_rejected() {
        let (mut a, mut b) = duplex(8);
        // Write a bogus length header claiming 2 GiB.
        tokio::spawn(async move {
            let _ = a.write_all(&(2_000_000_000u32).to_be_bytes()).await;
        });
        let err: io::Result<ClientReq> = read_frame(&mut b).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn clean_close_yields_eof() {
        let (a, mut b) = duplex(8);
        drop(a);
        let err: io::Result<ClientReq> = read_frame(&mut b).await;
        let e = err.unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
    }
}
