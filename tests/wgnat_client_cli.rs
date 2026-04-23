//! Phase 17a integration test for the `wgnat-client` binary. Spins up
//! a mock control server on 127.0.0.1, invokes wgnat-client as a
//! subprocess, asserts the request on the wire and exit semantics.
//!
//! The mock server reads one CBOR `ClientReq`, validates it, writes a
//! canned `ServerResp`, closes. Mirrors what wgnat's real control
//! handler does for `one_shot_request` flows.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::process::{Command, Stdio};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use wgnat::wire::{ClientReq, Proto, ServerResp, TunnelId};

fn wgnat_client_path() -> &'static str {
    env!("CARGO_BIN_EXE_wgnat-client")
}

async fn bind_mock_server() -> (TcpListener, SocketAddrV4) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = match listener.local_addr().unwrap() {
        std::net::SocketAddr::V4(v4) => v4,
        _ => panic!("expected IPv4 bind"),
    };
    (listener, addr)
}

/// Accept one connection, read one length-prefixed CBOR frame, write
/// the given response, close.
async fn handle_one<R>(listener: &TcpListener, respond: impl FnOnce(ClientReq) -> R)
where
    R: Into<ServerResp>,
{
    let (mut sock, _) = listener.accept().await.unwrap();
    let mut len_buf = [0u8; 4];
    sock.read_exact(&mut len_buf).await.unwrap();
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut frame = vec![0u8; len];
    sock.read_exact(&mut frame).await.unwrap();
    let req: ClientReq = ciborium::de::from_reader(&frame[..]).unwrap();
    let resp: ServerResp = respond(req).into();
    let mut payload = Vec::new();
    ciborium::ser::into_writer(&resp, &mut payload).unwrap();
    sock.write_all(&(payload.len() as u32).to_be_bytes())
        .await
        .unwrap();
    sock.write_all(&payload).await.unwrap();
    sock.shutdown().await.ok();
}

#[tokio::test]
async fn tunnel_register_prints_tunnel_id_and_exits_zero() {
    let (listener, addr) = bind_mock_server().await;

    let server = tokio::spawn(async move {
        handle_one(&listener, |req| {
            match req {
                ClientReq::StartReverse {
                    proto,
                    listen_port,
                    forward_to,
                } => {
                    assert_eq!(proto, Proto::Tcp);
                    assert_eq!(listen_port, 8080);
                    assert_eq!(
                        forward_to,
                        SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9000)
                    );
                }
                other => panic!("expected StartReverse, got {other:?}"),
            }
            ServerResp::Started {
                tunnel_id: TunnelId(42),
            }
        })
        .await;
    });

    let out = tokio::task::spawn_blocking({
        let client_path = wgnat_client_path().to_string();
        let ip = addr.ip().to_string();
        let port = addr.port().to_string();
        move || {
            Command::new(&client_path)
                .args([
                    &ip,
                    "--control-port",
                    &port,
                    "tunnel",
                    "start",
                    "-R",
                    "8080:127.0.0.1:9000",
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();

    server.await.unwrap();
    assert!(
        out.status.success(),
        "wgnat-client failed: status={:?} stderr={}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "42");
}

#[tokio::test]
async fn tunnel_register_udp_flag_sets_proto() {
    let (listener, addr) = bind_mock_server().await;

    let server = tokio::spawn(async move {
        handle_one(&listener, |req| match req {
            ClientReq::StartReverse { proto, .. } => {
                assert_eq!(proto, Proto::Udp);
                ServerResp::Started {
                    tunnel_id: TunnelId(7),
                }
            }
            other => panic!("expected StartReverse, got {other:?}"),
        })
        .await;
    });

    let out = tokio::task::spawn_blocking({
        let client_path = wgnat_client_path().to_string();
        let ip = addr.ip().to_string();
        let port = addr.port().to_string();
        move || {
            Command::new(&client_path)
                .args([
                    &ip,
                    "--control-port",
                    &port,
                    "tunnel",
                    "start",
                    "-U",
                    "-R",
                    "53:127.0.0.1:53",
                ])
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();

    server.await.unwrap();
    assert!(out.status.success());
}

#[tokio::test]
async fn shell_oneshot_prints_captured_stdout_and_exit_code() {
    let (listener, addr) = bind_mock_server().await;

    let server = tokio::spawn(async move {
        handle_one(&listener, |req| match req {
            ClientReq::RequestShell { mode, .. } => {
                assert!(matches!(mode, wgnat::wire::ShellMode::Oneshot));
                ServerResp::ShellResult {
                    exit_code: Some(0),
                    stdout: b"mock-stdout\n".to_vec(),
                    stderr: Vec::new(),
                }
            }
            other => panic!("expected RequestShell, got {other:?}"),
        })
        .await;
    });

    let out = tokio::task::spawn_blocking({
        let client_path = wgnat_client_path().to_string();
        let ip = addr.ip().to_string();
        let port = addr.port().to_string();
        move || {
            Command::new(&client_path)
                .args([
                    &ip,
                    "--control-port",
                    &port,
                    "shell",
                    "--output",
                    "-",
                    "--program",
                    "anything",
                    "--",
                    "arg1",
                ])
                .stdout(Stdio::piped())
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();

    server.await.unwrap();
    assert!(out.status.success(), "exit: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("mock-stdout"),
        "expected 'mock-stdout' in stdout, got {stdout:?}"
    );
}

#[tokio::test]
async fn shell_nonzero_exit_propagates() {
    let (listener, addr) = bind_mock_server().await;

    let server = tokio::spawn(async move {
        handle_one(&listener, |_| ServerResp::ShellResult {
            exit_code: Some(7),
            stdout: Vec::new(),
            stderr: Vec::new(),
        })
        .await;
    });

    let out = tokio::task::spawn_blocking({
        let client_path = wgnat_client_path().to_string();
        let ip = addr.ip().to_string();
        let port = addr.port().to_string();
        move || {
            Command::new(&client_path)
                .args([&ip, "--control-port", &port, "shell", "--output", "-"])
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();

    server.await.unwrap();
    assert_eq!(out.status.code(), Some(7), "exit code should be 7");
}

#[tokio::test]
async fn shell_detach_prints_pid() {
    let (listener, addr) = bind_mock_server().await;

    let server = tokio::spawn(async move {
        handle_one(&listener, |req| match req {
            ClientReq::RequestShell { mode, .. } => {
                assert!(matches!(mode, wgnat::wire::ShellMode::FireAndForget));
                ServerResp::ShellSpawned { pid: 1234 }
            }
            other => panic!("expected RequestShell, got {other:?}"),
        })
        .await;
    });

    let out = tokio::task::spawn_blocking({
        let client_path = wgnat_client_path().to_string();
        let ip = addr.ip().to_string();
        let port = addr.port().to_string();
        move || {
            Command::new(&client_path)
                .args([&ip, "--control-port", &port, "shell", "--detach"])
                .stdout(Stdio::piped())
                .output()
                .unwrap()
        }
    })
    .await
    .unwrap();

    server.await.unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(stdout.trim(), "1234");
}
