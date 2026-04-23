//! End-to-end test for the client-originated TCP reverse-tunnel
//! mechanics — without smoltcp or real WireGuard. Exercises:
//!
//!   * CBOR `StartTcpTunnel` handshake over a plain duplex stream.
//!   * Server side upgrades the flow to `yamux::Mode::Server` and
//!     drives it via `drive_connection`, exposing a `SubstreamOpener`
//!     in the `ReverseRegistry`.
//!   * Client side upgrades to `yamux::Mode::Client` and accepts
//!     inbound substreams into a channel (same shape wgnat-client
//!     uses in production).
//!   * "Incoming peer" flow: use the registry's opener to open a new
//!     outbound substream on the server side. Bytes written into that
//!     substream arrive at the client's inbound substream. The client
//!     echoes them back. Bytes round-trip.
//!
//! The full smoltcp-through-WG path is covered by the Ludus-based E2E
//! (see CLAUDE.md) — this test is the in-process unit of the new
//! mechanic that replaces the old server-originated bridge.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use wgnat::reverse_registry::{OpenRequest, ReverseRegistry};
use wgnat::wire::{
    read_frame, write_frame, BindAddr, ClientReq, Proto, ServerResp, TunnelSpec,
};
use wgnat::yamux_bridge::drive_connection;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_tunnel_substream_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,wgnat=info")
        .with_test_writer()
        .try_init();

    // Single flow between "client" and "server" — this stands in for
    // the smoltcp-carried TCP flow between wgnat-client and wgnat.
    let (server_side, client_side) = tokio::io::duplex(64 * 1024);

    let registry = Arc::new(ReverseRegistry::new());

    // ---- Server: read CBOR, write Started, upgrade to yamux server ----
    let server_registry = Arc::clone(&registry);
    let server_task = tokio::spawn(async move {
        let mut flow = server_side;
        let req: ClientReq = read_frame(&mut flow).await.unwrap();
        let spec = match req {
            ClientReq::StartTcpTunnel(s) => s,
            other => panic!("expected StartTcpTunnel, got {other:?}"),
        };
        let (opener_tx, opener_rx) = mpsc::unbounded_channel::<OpenRequest>();
        let tunnel_id = server_registry
            .start(
                Proto::Tcp,
                spec.listen_port,
                spec.bind,
                spec.forward_to,
                opener_tx,
            )
            .unwrap();
        write_frame(&mut flow, &ServerResp::Started { tunnel_id })
            .await
            .unwrap();

        // Upgrade to yamux. drive_connection holds the Connection and
        // services opener_rx (for outbound) + poll_next_inbound (unused
        // server-side).
        let conn = yamux::Connection::new(
            flow.compat(),
            yamux::Config::default(),
            yamux::Mode::Server,
        );
        drive_connection(conn, opener_rx, None).await;
    });

    // ---- Client: write CBOR, read Started, upgrade to yamux client ----
    let mut flow = client_side;
    let req = ClientReq::StartTcpTunnel(TunnelSpec {
        listen_port: 8080,
        forward_to: "1.2.3.4:9000".to_string(),
        bind: BindAddr::Default,
    });
    write_frame(&mut flow, &req).await.unwrap();
    let resp: ServerResp = read_frame(&mut flow).await.unwrap();
    match resp {
        ServerResp::Started { .. } => (),
        other => panic!("expected Started, got {other:?}"),
    }
    let conn = yamux::Connection::new(
        flow.compat(),
        yamux::Config::default(),
        yamux::Mode::Client,
    );
    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<yamux::Stream>();
    // No outbound substreams from the client — hold opener_tx alive
    // so drive_connection doesn't exit.
    let (_opener_tx, opener_rx) = mpsc::unbounded_channel::<OpenRequest>();
    let client_driver =
        tokio::spawn(drive_connection(conn, opener_rx, Some(inbound_tx)));

    // Client-side "forward_to dialer": whatever bytes arrive on an
    // inbound substream are echoed back. Mimics what wgnat-client would
    // do if its local forward_to were an echo server.
    let client_echoer = tokio::spawn(async move {
        while let Some(substream) = inbound_rx.recv().await {
            tokio::spawn(async move {
                let compat = substream.compat();
                let (mut r, mut w) = tokio::io::split(compat);
                let mut buf = [0u8; 4096];
                loop {
                    match r.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if w.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            if w.flush().await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    });

    // ---- Simulate an incoming peer hitting the tunnel port ----
    // Production wgnat does this from its smoltcp event loop via
    // spawn_reverse_tcp_yamux_bridge. Here we do the same thing by hand
    // against the registry's opener.
    let entry = {
        // Registry is populated by server_task; spin briefly.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(e) = registry.lookup(
                Proto::Tcp,
                std::net::Ipv4Addr::new(10, 0, 0, 2),
                8080,
                std::net::Ipv4Addr::new(10, 0, 0, 2),
            ) {
                break e;
            }
            if std::time::Instant::now() >= deadline {
                panic!("tunnel never showed up in registry");
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    };
    let (reply_tx, reply_rx) = oneshot::channel();
    entry
        .opener
        .send(OpenRequest { reply: reply_tx })
        .expect("opener channel alive");
    let substream = reply_rx
        .await
        .expect("opener replies")
        .expect("open_stream succeeds");

    // Write bytes into the substream; expect echo on the read side.
    let compat = substream.compat();
    let (mut r, mut w) = tokio::io::split(compat);
    let payload = b"hello from the peer side";
    w.write_all(payload).await.unwrap();
    w.flush().await.unwrap();

    let mut got = vec![0u8; payload.len()];
    r.read_exact(&mut got).await.unwrap();
    assert_eq!(got, payload);

    // Write more to prove the bridge stays up.
    let p2 = b"second message";
    w.write_all(p2).await.unwrap();
    w.flush().await.unwrap();
    let mut got2 = vec![0u8; p2.len()];
    r.read_exact(&mut got2).await.unwrap();
    assert_eq!(got2, p2);

    // Cleanup — drop substream halves, let the drivers wind down.
    drop(r);
    drop(w);
    tokio::time::sleep(Duration::from_millis(50)).await;
    client_echoer.abort();
    client_driver.abort();
    server_task.abort();
}
