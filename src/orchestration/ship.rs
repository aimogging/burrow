//! Lifecycle orchestration: `ship`, `teardown`, `shell`. Reads the
//! `[deploy]` section of the spec to know where the WG server lives
//! and what netns name to use on each side; emits the same kernel-WG
//! + netns + (for WSS) burrow-relay setup the legacy
//! `scripts/deploy-server.sh` and `scripts/deploy-client.sh` did, but
//! driven by Rust + the spec.
//!
//! Server side runs over ssh + sudo (the host string from the spec is
//! whatever ssh accepts: alias, `user@host`, or IP). Client side runs
//! locally with sudo — the netns isolation is the whole point of the
//! client-side workflow, so we don't bother supporting "remote
//! client" — that's just `wg-quick up` on whatever box you want.
//!
//! The server-side relay is started with `setsid -f` so the ssh
//! session disconnects cleanly. Logs land in `/var/log/burrow-relay.log`
//! on the remote.

use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::spec::{Layout, Spec, TransportMode};

use super::exec;

/// Ship the server side: scp `server.conf` (and burrow-relay if WSS),
/// then run the kernel-WG-in-netns setup over ssh.
pub fn server(name: &str) -> Result<()> {
    let layout = Layout::for_name(name)?;
    layout.require_spec()?;
    let spec = Spec::parse(&layout.spec_path())?;
    let deploy = spec.require_deploy()?;

    if !layout.server_conf().exists() {
        bail!(
            "missing {} — run `burrowctl gen {name}` first",
            layout.server_conf().display()
        );
    }

    let host = deploy.server.host.as_str();
    let key = deploy.server.ssh_key.as_deref();
    let ns = deploy.server.namespace.as_str();
    let remote_conf = format!("/tmp/burrow-{ns}.conf");

    println!(
        ">>> shipping {} -> {host}:{remote_conf}",
        layout.server_conf().display()
    );
    exec::scp_to(&layout.server_conf(), host, key, &remote_conf)?;

    let want_relay = spec.transport.mode == TransportMode::Wss;
    if want_relay {
        let relay_bin = layout.bundle_file("burrow-relay");
        if !relay_bin.exists() {
            bail!(
                "no Linux burrow-relay binary in {} — \
                 [build.relay].target must be a Linux triple, \
                 and `burrowctl build {name}` must have run",
                layout.bundle_dir().display()
            );
        }
        println!(
            ">>> shipping {} -> {host}:/tmp/burrow-relay-new",
            relay_bin.display()
        );
        exec::scp_to(&relay_bin, host, key, "/tmp/burrow-relay-new")?;
    }

    let script = build_server_script(ns, &remote_conf, want_relay);
    println!(">>> running netns + wg setup on {host} (namespace={ns})");
    exec::ssh_sudo_script(host, key, &script)
        .with_context(|| format!("server-side setup on {host}"))
}

/// Ship the client side: local netns + wg-quick-equivalent setup.
/// Linux-only because `ip netns` is a Linux concept.
pub fn client(name: &str) -> Result<()> {
    require_linux("ship-client")?;
    let layout = Layout::for_name(name)?;
    layout.require_spec()?;
    let spec = Spec::parse(&layout.spec_path())?;
    let deploy = spec.require_deploy()?;

    let conf = layout.client_conf(1);
    if !conf.exists() {
        bail!(
            "missing {} — run `burrowctl gen {name}` first",
            conf.display()
        );
    }

    let ns = deploy.client.namespace.as_str();
    let abs_conf = std::fs::canonicalize(&conf)
        .with_context(|| format!("canonicalize {}", conf.display()))?;
    let abs_conf = abs_conf.to_string_lossy().to_string();

    let script = build_client_script(ns, &abs_conf);
    println!(">>> running local netns + wg setup (namespace={ns})");
    exec::local_sudo_script(&script).context("client-side setup (local)")
}

/// Tear down both sides, best-effort. Errors on either side are
/// reported but don't stop the other from being torn down — partial
/// state is the worst outcome.
pub fn down(name: &str) -> Result<()> {
    let layout = Layout::for_name(name)?;
    layout.require_spec()?;
    let spec = Spec::parse(&layout.spec_path())?;
    let deploy = spec.require_deploy()?;

    let mut errors = Vec::new();

    // Local client side first — fast.
    if cfg!(target_os = "linux") {
        let ns = deploy.client.namespace.as_str();
        if let Err(e) = exec::local_sudo_script(&build_teardown_script(ns, false)) {
            errors.push(format!("client-side teardown: {e:#}"));
        }
    }

    // Remote server side.
    let host = deploy.server.host.as_str();
    let key = deploy.server.ssh_key.as_deref();
    let ns = deploy.server.namespace.as_str();
    if let Err(e) = exec::ssh_sudo_script(host, key, &build_teardown_script(ns, true)) {
        errors.push(format!("server-side teardown ({host}): {e:#}"));
    }

    if !errors.is_empty() {
        bail!("teardown completed with errors:\n  {}", errors.join("\n  "));
    }
    Ok(())
}

/// Drop into an interactive shell inside the local client netns.
pub fn shell(name: &str) -> Result<()> {
    require_linux("shell")?;
    let layout = Layout::for_name(name)?;
    layout.require_spec()?;
    let spec = Spec::parse(&layout.spec_path())?;
    let deploy = spec.require_deploy()?;
    let ns = deploy.client.namespace.as_str();

    if !netns_exists(ns)? {
        bail!(
            "namespace `{ns}` doesn't exist locally — \
             run `burrowctl ship-client {name}` (or `burrowctl up {name}`) first"
        );
    }
    exec::local_sudo_interactive(&["ip", "netns", "exec", ns, "bash"])
}

fn require_linux(cmd: &str) -> Result<()> {
    if cfg!(target_os = "linux") {
        Ok(())
    } else {
        bail!(
            "`burrowctl {cmd}` requires Linux (netns is a Linux concept). \
             Run burrowctl on the Linux dev box."
        )
    }
}

fn netns_exists(ns: &str) -> Result<bool> {
    use std::process::Command;
    let out = Command::new("sudo")
        .args(["ip", "netns", "list"])
        .output()
        .context("listing netns")?;
    if !out.status.success() {
        bail!("ip netns list failed (exit {:?})", out.status.code());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .any(|l| l.split_whitespace().next() == Some(ns)))
}

fn build_server_script(ns: &str, remote_conf: &str, install_relay: bool) -> String {
    let mut s = String::new();
    s.push_str("set -e\n");
    s.push_str(WG_INSTALL_BLOCK);
    s.push_str(&netns_setup_block(ns, remote_conf, /* enable_forward = */ true));
    s.push_str(&routes_from_allowed_ips_block(ns, remote_conf));
    s.push_str(&format!(
        "echo\necho \"WG server up in netns {ns}:\"\nip netns exec {ns} wg show\n"
    ));
    if install_relay {
        s.push_str(RELAY_START_BLOCK);
    }
    s
}

fn build_client_script(ns: &str, conf_path: &str) -> String {
    let mut s = String::new();
    s.push_str("set -e\n");
    s.push_str(WG_INSTALL_BLOCK);
    s.push_str(&netns_setup_block(ns, conf_path, /* enable_forward = */ false));
    s.push_str(&routes_from_allowed_ips_block(ns, conf_path));
    s.push_str(&format!(r#"
echo
echo "WG client up in netns {ns}:"
ip netns exec {ns} wg show
echo
echo "routes in netns:"
ip netns exec {ns} ip route
"#));
    s
}

/// Walk every `[Peer] AllowedIPs` line in `conf_path` and install a
/// route inside the netns for each CIDR — kernel WG by itself only
/// uses AllowedIPs to filter packets *from* peers; routing packets
/// *to* the right peer is the kernel routing table's job, and
/// `wg setconf` (unlike `wg-quick up`) doesn't add those routes for
/// you. Skip 0.0.0.0/0 (would steal the netns default route) and any
/// IPv6 entries.
fn routes_from_allowed_ips_block(ns: &str, conf_path: &str) -> String {
    format!(r#"
allowed=$(awk -F'= *' '/^AllowedIPs[[:space:]]*=/{{gsub(/[, ]+/, " ", $2); print $2}}' {conf_path})
for cidr in $allowed; do
    case "$cidr" in
        *:*) continue;;
        0.0.0.0/0) continue;;
    esac
    ip netns exec {ns} ip route replace "$cidr" dev {ns} 2>/dev/null || true
done
"#)
}

fn build_teardown_script(ns: &str, kill_relay: bool) -> String {
    let mut s = String::new();
    s.push_str("set +e\n");
    if kill_relay {
        s.push_str("pkill -f /usr/local/bin/burrow-relay 2>/dev/null || true\n");
        s.push_str("rm -f /usr/local/bin/burrow-relay /var/log/burrow-relay.log\n");
    }
    s.push_str(&format!("ip link del {ns} 2>/dev/null || true\n"));
    s.push_str(&format!("ip netns del {ns} 2>/dev/null || true\n"));
    s.push_str(&format!("rm -f /tmp/burrow-{ns}.conf\n"));
    s.push_str("exit 0\n");
    s
}

const WG_INSTALL_BLOCK: &str = r#"
if ! command -v wg >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y wireguard-tools iproute2
    elif command -v yum >/dev/null 2>&1; then
        yum install -y wireguard-tools iproute
    else
        echo "no apt-get or yum found — install wireguard-tools manually" >&2
        exit 1
    fi
fi
"#;

/// Common netns + wg interface setup. Following the
/// wireguard.com/netns trick — interface is created in the host netns
/// (so the UDP socket lives there + can talk to the public internet),
/// then moved into the named netns. `wg-quick strip` filters out the
/// wg-quick-only keys (Address, DNS, ...) so `wg setconf` doesn't
/// gag.
fn netns_setup_block(ns: &str, conf_path: &str, enable_forward: bool) -> String {
    let fwd = if enable_forward {
        format!("ip netns exec {ns} sysctl -wq net.ipv4.ip_forward=1\n\
                 ip netns exec {ns} iptables -A FORWARD -i {ns} -j ACCEPT 2>/dev/null || true\n\
                 ip netns exec {ns} iptables -A FORWARD -o {ns} -j ACCEPT 2>/dev/null || true\n")
    } else {
        String::new()
    };
    format!(r#"
ip link del {ns} 2>/dev/null || true
ip netns del {ns} 2>/dev/null || true

ip netns add {ns}
{fwd}\
ip netns exec {ns} ip link set lo up

ip link add {ns} type wireguard
ip link set {ns} netns {ns}
ip netns exec {ns} wg setconf {ns} <(wg-quick strip {conf_path})

addrs=$(awk -F'= *' '/^Address[[:space:]]*=/{{gsub(/[, ]+/, " ", $2); print $2; exit}}' {conf_path})
for a in $addrs; do
    ip netns exec {ns} ip addr add "$a" dev {ns}
done
ip netns exec {ns} ip link set {ns} up
"#)
}

const RELAY_START_BLOCK: &str = r#"

# Relay
pkill -f /usr/local/bin/burrow-relay 2>/dev/null || true
sleep 0.3
install -m 0755 /tmp/burrow-relay-new /usr/local/bin/burrow-relay
rm -f /tmp/burrow-relay-new
setsid -f /usr/local/bin/burrow-relay >/var/log/burrow-relay.log 2>&1 </dev/null
echo "burrow-relay started (PID via pgrep: $(pgrep -f /usr/local/bin/burrow-relay | tr '\n' ' '))"
"#;

#[allow(dead_code)]
fn _path_for_doc(_p: &Path) {} // keep `Path` in scope for future use
