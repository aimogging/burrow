//! Integration test for `burrowctl gen` — write a spec into a
//! tempdir, run `orchestration::gen::run_with_layout`, assert the
//! generated outputs are present and that `burrow.conf` round-trips
//! cleanly through the lower-level config parser.
//!
//! The actual config-generator math (subnet allocation, key
//! distinctness, route propagation) is exercised by `config_gen`'s
//! own unit tests; this just validates the orchestration glue.

use std::fs;

use burrow::config::parse_str;
use burrow::orchestration::gen;
use burrow::spec::Layout;

const SPEC_TOML: &str = r#"
[wg]
endpoint = "vpn.example.com:51820"
routes = ["192.168.1.0/24"]

[transport]
mode = "wss"
relay_host = "vpn.example.com:443"

[build.gateway]
target = "x86_64-pc-windows-msvc"
"#;

#[test]
fn gen_writes_full_set_for_wss_spec() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = Layout::new(tmp.path(), "dev").unwrap();
    fs::create_dir_all(&layout.root).unwrap();
    fs::write(layout.spec_path(), SPEC_TOML).unwrap();

    gen::run_with_layout(&layout).unwrap();

    // Trio + bundle materials all present.
    for name in [
        "server.conf",
        "burrow.conf",
        "client1.conf",
        "relay-bundle/cert.pem",
        "relay-bundle/key.pem",
        "relay-bundle/token.txt",
        "relay-bundle/listen.txt",
        "relay-bundle/forward.txt",
    ] {
        let p = layout.root.join(name);
        assert!(p.exists(), "missing expected output {}", p.display());
    }

    // burrow.conf round-trips through the runtime parser, including
    // the WSS-extension keys produced by gen --relay.
    let burrow_conf = fs::read_to_string(layout.burrow_conf()).unwrap();
    let cfg = parse_str(&burrow_conf).expect("burrow.conf must parse");
    assert_eq!(
        cfg.interface.transport.as_deref(),
        Some("wss://vpn.example.com:443/v1/wg")
    );
    assert!(cfg.interface.tls_skip_verify);
    assert!(cfg.interface.relay_token.is_some());
    assert_eq!(cfg.peer.endpoint, "vpn.example.com:51820");

    // Cert and key look like PEM.
    let cert = fs::read_to_string(layout.bundle_file("cert.pem")).unwrap();
    let key = fs::read_to_string(layout.bundle_file("key.pem")).unwrap();
    assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
    assert!(key.contains("PRIVATE KEY"));
}

#[test]
fn gen_for_udp_spec_skips_relay_bundle() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = Layout::new(tmp.path(), "udp-only").unwrap();
    fs::create_dir_all(&layout.root).unwrap();
    fs::write(
        layout.spec_path(),
        r#"
        [wg]
        endpoint = "vpn.example.com:51820"
        [transport]
        mode = "udp"
        [build.gateway]
        target = "x86_64-unknown-linux-gnu"
        "#,
    )
    .unwrap();

    gen::run_with_layout(&layout).unwrap();

    assert!(layout.burrow_conf().exists());
    assert!(layout.server_conf().exists());
    assert!(layout.client_conf(1).exists());
    // No relay bundle on the UDP path.
    assert!(!layout.bundle_dir().exists());

    // burrow.conf has no Transport= line for UDP.
    let cfg = parse_str(&fs::read_to_string(layout.burrow_conf()).unwrap()).unwrap();
    assert!(cfg.interface.transport.is_none());
    assert!(cfg.interface.relay_token.is_none());
}

#[test]
fn missing_spec_emits_helpful_error() {
    let tmp = tempfile::tempdir().unwrap();
    let layout = Layout::new(tmp.path(), "ghost").unwrap();
    let err = gen::run_with_layout(&layout).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("spec"), "{msg}");
}
