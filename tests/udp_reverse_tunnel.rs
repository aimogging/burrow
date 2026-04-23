//! End-to-end UDP reverse tunnel test. Under the OS-listener model:
//!
//! 1. Server side (control handler analog) binds a real `UdpSocket`
//!    on `127.0.0.1:PORT` and runs the UDP accept loop against a
//!    yamux substream.
//! 2. Client side runs a yamux client on the other end of the duplex
//!    control flow; when the server opens the tunnel substream, the
//!    client pumps framed datagrams back and forth with a simulated
//!    `forward_to` (here: an in-test echo socket).
//! 3. Test sends a UDP datagram to `127.0.0.1:PORT`, expects the
//!    framed datagram to reach the echoer, and the echoed response
//!    to arrive back on the test's sending socket.
//!
//! Exercises the full path: OS `UdpSocket.recv_from` → yamux frame →
//! client-side UDP originate → response framed → server-side
//! `UdpSocket.send_to` → test receives.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::FuturesAsyncReadCompatExt;

use burrow::reverse_registry::{OpenRequest, SubstreamOpener};
use burrow::yamux_bridge::{drive_connection, udp_frame};

const LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

async fn bind_local_udp() -> (Arc<UdpSocket>, u16) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();
    (Arc::new(sock), port)
}

/// Server-side UDP accept loop: mirrors `control::udp_accept_loop`
/// without the surrounding control-flow plumbing. Takes ownership of
/// an already-bound `UdpSocket` and a `SubstreamOpener`.
async fn server_udp_loop(socket: Arc<UdpSocket>, opener: SubstreamOpener) {
    let (reply_tx, reply_rx) = oneshot::channel();
    opener.send(OpenRequest { reply: reply_tx }).unwrap();
    let substream = reply_rx.await.unwrap().unwrap();

    let compat = substream.compat();
    let (mut y_r, mut y_w) = tokio::io::split(compat);

    let (frame_tx, mut frame_rx) =
        mpsc::unbounded_channel::<(Ipv4Addr, u16, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((ip, port, payload)) = frame_rx.recv().await {
            let _ = udp_frame::write(&mut y_w, ip, port, &payload).await;
        }
    });

    let sock_r = Arc::clone(&socket);
    tokio::spawn(async move {
        loop {
            let (peer_ip, peer_port, payload) = match udp_frame::read(&mut y_r).await {
                Ok(x) => x,
                Err(_) => return,
            };
            let addr = SocketAddr::V4(SocketAddrV4::new(peer_ip, peer_port));
            let _ = sock_r.send_to(&payload, addr).await;
        }
    });

    let mut buf = vec![0u8; 65_535];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(_) => return,
        };
        let SocketAddr::V4(peer) = peer else { continue };
        if frame_tx
            .send((*peer.ip(), peer.port(), buf[..n].to_vec()))
            .is_err()
        {
            return;
        }
    }
}

/// Client-side forward_to dialer: when a framed datagram arrives,
/// send to a local UDP echo socket and frame the echo back.
async fn client_udp_echoer(
    substream: yamux::Stream,
    forward_to: SocketAddr,
) {
    let compat = substream.compat();
    let (mut y_r, mut y_w) = tokio::io::split(compat);

    let (reply_tx, mut reply_rx) = mpsc::unbounded_channel::<(Ipv4Addr, u16, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((ip, port, data)) = reply_rx.recv().await {
            let _ = udp_frame::write(&mut y_w, ip, port, &data).await;
        }
    });

    loop {
        let (peer_ip, peer_port, payload) = match udp_frame::read(&mut y_r).await {
            Ok(x) => x,
            Err(_) => return,
        };
        // Dial forward_to from a fresh ephemeral socket, send the
        // payload, receive the echo, frame it back. Real burrow-client
        // holds one socket per peer; the test is simpler.
        let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sock.connect(forward_to).await.unwrap();
        sock.send(&payload).await.unwrap();
        let mut buf = vec![0u8; 65_535];
        let n = sock.recv(&mut buf).await.unwrap();
        let _ = reply_tx.send((peer_ip, peer_port, buf[..n].to_vec()));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_reverse_tunnel_roundtrip() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("warn,burrow=info")
        .with_test_writer()
        .try_init();

    // Duplex stream stands in for the burrow-client <-> burrow control
    // flow (the part that is smoltcp-backed in production).
    let (server_side, client_side) = tokio::io::duplex(64 * 1024);

    // Server opener (produced inside start_tunnel) — we emulate the
    // essential parts: bind an OS socket and run the UDP accept loop.
    let (opener_tx, opener_rx) = mpsc::unbounded_channel::<OpenRequest>();

    // Server yamux: drives the connection, serves outbound opens.
    let server_task = tokio::spawn(async move {
        use tokio_util::compat::TokioAsyncReadCompatExt;
        let conn = yamux::Connection::new(
            server_side.compat(),
            yamux::Config::default(),
            yamux::Mode::Server,
        );
        drive_connection(conn, opener_rx, None).await;
    });

    // Echo target for "client's forward_to".
    let (echo_sock, echo_port) = bind_local_udp().await;
    let echo_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        loop {
            let Ok((n, peer)) = echo_sock.recv_from(&mut buf).await else {
                return;
            };
            let _ = echo_sock.send_to(&buf[..n], peer).await;
        }
    });

    // Client-side yamux: accepts the single substream the server opens
    // for the UDP tunnel; runs the client-side frame pump against the
    // echo target.
    let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<yamux::Stream>();
    let (_client_opener_tx, client_opener_rx) = mpsc::unbounded_channel::<OpenRequest>();
    let client_task = tokio::spawn({
        async move {
            use tokio_util::compat::TokioAsyncReadCompatExt;
            let conn = yamux::Connection::new(
                client_side.compat(),
                yamux::Config::default(),
                yamux::Mode::Client,
            );
            drive_connection(conn, client_opener_rx, Some(inbound_tx)).await;
        }
    });

    let echoer_task = tokio::spawn(async move {
        let substream = inbound_rx.recv().await.expect("inbound substream");
        let forward_to = SocketAddr::V4(SocketAddrV4::new(LOOPBACK, echo_port));
        client_udp_echoer(substream, forward_to).await;
    });

    // Bind the real OS listener the "server side of the tunnel" owns
    // (this is what start_tunnel would do for Proto::Udp).
    let (server_sock, server_port) = bind_local_udp().await;
    let server_udp_task = tokio::spawn(server_udp_loop(
        Arc::clone(&server_sock),
        opener_tx.clone(),
    ));

    // Now: send a datagram from a fresh client socket to the tunnel's
    // server-bound port. Expect the bytes to tunnel across, hit the
    // echo target, come back, and arrive on our sending socket.
    let tester = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let dst = SocketAddr::V4(SocketAddrV4::new(LOOPBACK, server_port));
    tester.send_to(b"hello tunnel", dst).await.unwrap();

    let mut reply = vec![0u8; 1024];
    let recv = tokio::time::timeout(
        Duration::from_secs(3),
        tester.recv_from(&mut reply),
    )
    .await
    .expect("echo reply timeout")
    .unwrap();
    let (n, from) = recv;
    assert_eq!(&reply[..n], b"hello tunnel", "echo payload mismatch");
    assert_eq!(
        from,
        dst,
        "reply source should be the tunnel's server port"
    );

    server_udp_task.abort();
    echoer_task.abort();
    client_task.abort();
    echo_task.abort();
    server_task.abort();
}
