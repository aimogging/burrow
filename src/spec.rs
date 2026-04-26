//! Deployment spec — the single TOML file a human edits to drive
//! everything else (`burrowctl gen`, `burrowctl build`, eventually
//! `burrowctl ship`/`up`/`down`).
//!
//! Lives at `deployments/<name>/spec.toml`. The rest of the directory
//! is generated state (configs, cert, token, binaries) — gitignored.
//!
//! ## Design
//!
//! * **Intent only, no state.** Generated values (the random WG keys,
//!   the random bearer token, the self-signed cert) never round-trip
//!   into the spec. They live in `relay-bundle/` next to the spec.
//! * **Opinionated defaults.** The relay/client cross-targets default
//!   to 64-bit Linux because that's where the boxes overwhelmingly
//!   live; the gateway target is required because picking it wrong is
//!   the only way to ship a binary that won't run.
//! * **Phase 1 scope.** Only `mode = "wss"` and `mode = "udp"` are
//!   implemented; `transport.tls` is implicitly self-signed +
//!   skip-verify. A `tls = "byo"` knob (operator brings cert) is the
//!   obvious next axis but isn't shipped yet.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use crate::config::parse_ipv4_cidr;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub wg: WgSection,
    pub transport: TransportSection,
    pub build: BuildSection,
    /// Where the binaries actually run. Optional — only required for
    /// `ship` / `up` / `down` / `shell`. `gen` and `build` work
    /// without it.
    #[serde(default)]
    pub deploy: Option<DeploySection>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct WgSection {
    /// `host:port` of the WireGuard server. Goes into every peer's
    /// `Endpoint =` line.
    pub endpoint: String,
    /// CIDRs the burrow gateway should expose to the rest of the mesh.
    /// Empty = pure peer-to-peer WG (clients can still hit burrow's
    /// DNS / control / reverse-tunnel surfaces).
    #[serde(default)]
    pub routes: Vec<String>,
    /// Resolvers to write into each `client.conf` as `DNS = ...`.
    /// Empty = no DNS line; clients keep their system resolver.
    #[serde(default)]
    pub dns: Vec<String>,
    /// WG subnet. Server gets `.1`, gateway `.2`, clients `.10+`.
    #[serde(default = "default_subnet")]
    pub subnet: String,
    /// Number of client peers to generate (writes `clientN.conf` for N
    /// in `1..=clients`).
    #[serde(default = "default_clients")]
    pub clients: u16,
    /// WG server's UDP listen port.
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TransportSection {
    pub mode: TransportMode,
    /// `host[:port]` burrow will dial via WSS. Required when
    /// `mode = "wss"`. Default port if omitted is 443.
    pub relay_host: Option<String>,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TransportMode {
    Udp,
    Wss,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BuildSection {
    /// Build settings for the burrow gateway binary. Required — the
    /// gateway runs on whatever your private-network host is, which
    /// may not match the orchestration host's OS.
    pub gateway: BinaryBuild,
    /// Build settings for `burrow-relay`. Defaults to 64-bit Linux
    /// because the relay sits next to kernel WG on the WG server box,
    /// which is essentially always Linux.
    #[serde(default = "default_linux_build")]
    pub relay: BinaryBuild,
    /// Build settings for `burrow-client`. Same Linux default for the
    /// same reason — the operator-side CLI runs on the dev box, which
    /// is typically Linux/macOS, but this is overridable.
    #[serde(default = "default_linux_build")]
    pub client: BinaryBuild,
}

/// Per-binary build knobs. Just `target` for now; nested as a table
/// so we can add `features`, `profile`, `cargo` (e.g. swap to `cross`),
/// etc., later without reshuffling the spec format.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct BinaryBuild {
    /// Standard rustc target triple (e.g. `x86_64-pc-windows-msvc`,
    /// `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`).
    pub target: String,
}

/// Deploy targets — where each side of the tunnel actually runs.
/// Optional in the spec because `gen` and `build` don't need it; only
/// the lifecycle commands (`ship`, `up`, `down`, `shell`) do.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DeploySection {
    pub server: DeployServer,
    #[serde(default)]
    pub client: DeployClient,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DeployServer {
    /// Anything ssh accepts: an SSH-config alias, `user@host`, or a
    /// bare hostname/IP. Auth resolves through the usual
    /// agent / `~/.ssh/config` / default-key path; if you need
    /// something custom, set it in `~/.ssh/config`.
    pub host: String,
    /// netns name on the remote. Default `burrow`.
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DeployClient {
    /// Local netns name. Default `burrow`. The client always runs
    /// locally — burrowctl is a dev-host tool and the netns wrapper
    /// is meant to isolate test traffic from your host's routing.
    #[serde(default = "default_namespace")]
    pub namespace: String,
}

impl Default for DeployClient {
    fn default() -> Self {
        Self { namespace: default_namespace() }
    }
}

fn default_namespace() -> String { "burrow".into() }

fn default_subnet() -> String { "10.0.0.0/24".into() }
fn default_clients() -> u16 { 1 }
fn default_listen_port() -> u16 { 51820 }
fn default_linux_build() -> BinaryBuild {
    BinaryBuild { target: "x86_64-unknown-linux-gnu".into() }
}

impl Spec {
    /// Parse a spec TOML file.
    pub fn parse(path: &Path) -> Result<Self> {
        let body = fs::read_to_string(path)
            .with_context(|| format!("reading spec {}", path.display()))?;
        let spec: Spec = toml::from_str(&body)
            .with_context(|| format!("parsing spec {}", path.display()))?;
        spec.validate()
            .with_context(|| format!("validating spec {}", path.display()))?;
        Ok(spec)
    }

    /// Surface schema/value errors. Called automatically by `parse`.
    pub fn validate(&self) -> Result<()> {
        if self.wg.endpoint.trim().is_empty() {
            bail!("[wg] endpoint must not be empty");
        }
        // host:port shape — bare host without port is rejected.
        if !self.wg.endpoint.contains(':') {
            bail!("[wg] endpoint must be `host:port` (got `{}`)", self.wg.endpoint);
        }
        for r in &self.wg.routes {
            parse_ipv4_cidr(r)
                .with_context(|| format!("[wg] route `{r}` is not a valid IPv4 CIDR"))?;
        }
        parse_ipv4_cidr(&self.wg.subnet)
            .with_context(|| format!("[wg] subnet `{}` is not a valid IPv4 CIDR", self.wg.subnet))?;
        if self.wg.clients == 0 {
            bail!("[wg] clients must be >= 1");
        }

        match self.transport.mode {
            TransportMode::Wss => {
                let host = self.transport.relay_host.as_deref().unwrap_or("");
                if host.trim().is_empty() {
                    bail!("[transport] relay_host is required when mode = \"wss\"");
                }
            }
            TransportMode::Udp => {
                if self.transport.relay_host.is_some() {
                    bail!("[transport] relay_host has no meaning when mode = \"udp\"");
                }
            }
        }

        if self.build.gateway.target.trim().is_empty() {
            bail!("[build.gateway] target triple is required");
        }
        if self.build.relay.target.trim().is_empty() {
            bail!("[build.relay] target triple must not be empty");
        }
        if self.build.client.target.trim().is_empty() {
            bail!("[build.client] target triple must not be empty");
        }

        if let Some(d) = &self.deploy {
            if d.server.host.trim().is_empty() {
                bail!("[deploy.server] host must not be empty");
            }
            if d.server.namespace.trim().is_empty() {
                bail!("[deploy.server] namespace must not be empty");
            }
            if d.client.namespace.trim().is_empty() {
                bail!("[deploy.client] namespace must not be empty");
            }
        }
        Ok(())
    }

    /// Fetch the `[deploy]` section, erroring with a pointer to the
    /// missing field if absent. Used by `ship` / `up` / `down` /
    /// `shell` (which need it); `gen` and `build` use direct access
    /// because they tolerate it being missing.
    pub fn require_deploy(&self) -> Result<&DeploySection> {
        self.deploy.as_ref().ok_or_else(|| {
            anyhow!(
                "this command needs a [deploy] section in spec.toml, e.g.:\n  \
                 [deploy.server]\n  host = \"vpn.example.com\"\n  \
                 # namespace = \"burrow\"  (default)\n  \
                 [deploy.client]\n  # namespace = \"burrow\"  (default)"
            )
        })
    }
}

/// Filesystem layout helpers — every part of the orchestration that
/// touches disk goes through these so the conventions live in one
/// place.
pub struct Layout {
    pub root: PathBuf,
}

impl Layout {
    /// `deployments/<name>/` under the current working directory. The
    /// usual entry point.
    pub fn for_name(name: &str) -> Result<Self> {
        Self::new(Path::new("deployments"), name)
    }

    /// Lower-level constructor — `<base>/<name>/`. Used by tests that
    /// want to point at a tempdir.
    pub fn new(base: &Path, name: &str) -> Result<Self> {
        if name.is_empty() || name.contains(['/', '\\']) {
            bail!("deployment name must be a single path segment, got `{name}`");
        }
        Ok(Self {
            root: base.join(name),
        })
    }

    pub fn spec_path(&self) -> PathBuf { self.root.join("spec.toml") }
    pub fn server_conf(&self) -> PathBuf { self.root.join("server.conf") }
    pub fn burrow_conf(&self) -> PathBuf { self.root.join("burrow.conf") }
    pub fn client_conf(&self, n: u16) -> PathBuf {
        self.root.join(format!("client{n}.conf"))
    }
    pub fn bundle_dir(&self) -> PathBuf { self.root.join("relay-bundle") }
    pub fn bundle_file(&self, name: &str) -> PathBuf { self.bundle_dir().join(name) }

    /// Where the resolved spec must already exist for `gen`/`build` to
    /// proceed. Returns a clear error message if it doesn't.
    pub fn require_spec(&self) -> Result<()> {
        if !self.spec_path().exists() {
            bail!(
                "no spec at {} — write one (see `deployments/README.md` or run \
                 `burrowctl init <name>` once the wizard lands)",
                self.spec_path().display()
            );
        }
        Ok(())
    }

    pub fn ensure_dirs(&self, want_bundle: bool) -> Result<()> {
        fs::create_dir_all(&self.root)
            .with_context(|| format!("creating {}", self.root.display()))?;
        if want_bundle {
            fs::create_dir_all(self.bundle_dir())
                .with_context(|| format!("creating {}", self.bundle_dir().display()))?;
        }
        Ok(())
    }
}

/// Helper to return the parsed `relay_host` split into host and port.
/// `host:port` → `(host, port)`; bare `host` → `(host, 443)`.
pub fn split_host_port(host_port: &str, default_port: u16) -> Result<(String, u16)> {
    match host_port.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p
                .parse()
                .map_err(|e| anyhow!("invalid port in `{host_port}`: {e}"))?;
            Ok((h.to_string(), port))
        }
        None => Ok((host_port.to_string(), default_port)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_spec(dir: &Path, body: &str) -> PathBuf {
        let p = dir.join("spec.toml");
        fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn minimal_wss_spec_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_spec(
            dir.path(),
            r#"
            [wg]
            endpoint = "vpn.example.com:51820"
            routes = ["192.168.1.0/24"]

            [transport]
            mode = "wss"
            relay_host = "vpn.example.com:443"

            [build.gateway]
            target = "x86_64-pc-windows-msvc"
            "#,
        );
        let spec = Spec::parse(&p).unwrap();
        assert_eq!(spec.wg.endpoint, "vpn.example.com:51820");
        assert_eq!(spec.wg.subnet, "10.0.0.0/24");
        assert_eq!(spec.wg.clients, 1);
        assert_eq!(spec.wg.listen_port, 51820);
        assert_eq!(spec.transport.mode, TransportMode::Wss);
        assert_eq!(spec.transport.relay_host.as_deref(), Some("vpn.example.com:443"));
        assert_eq!(spec.build.gateway.target, "x86_64-pc-windows-msvc");
        assert_eq!(spec.build.relay.target, "x86_64-unknown-linux-gnu");
        assert_eq!(spec.build.client.target, "x86_64-unknown-linux-gnu");
    }

    #[test]
    fn udp_spec_does_not_need_relay_host() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_spec(
            dir.path(),
            r#"
            [wg]
            endpoint = "vpn.example.com:51820"

            [transport]
            mode = "udp"

            [build.gateway]
            target = "x86_64-unknown-linux-gnu"
            "#,
        );
        let spec = Spec::parse(&p).unwrap();
        assert_eq!(spec.transport.mode, TransportMode::Udp);
        assert!(spec.transport.relay_host.is_none());
    }

    #[test]
    fn wss_without_relay_host_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_spec(
            dir.path(),
            r#"
            [wg]
            endpoint = "vpn.example.com:51820"
            [transport]
            mode = "wss"
            [build.gateway]
            target = "x86_64-pc-windows-msvc"
            "#,
        );
        let err = Spec::parse(&p).unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("relay_host"), "{err}");
    }

    #[test]
    fn udp_with_relay_host_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_spec(
            dir.path(),
            r#"
            [wg]
            endpoint = "vpn.example.com:51820"
            [transport]
            mode = "udp"
            relay_host = "x:443"
            [build.gateway]
            target = "x86_64-unknown-linux-gnu"
            "#,
        );
        let err = Spec::parse(&p).unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("no meaning"), "{err}");
    }

    #[test]
    fn missing_endpoint_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_spec(
            dir.path(),
            r#"
            [wg]
            endpoint = ""
            [transport]
            mode = "udp"
            [build.gateway]
            target = "x86_64-unknown-linux-gnu"
            "#,
        );
        let err = Spec::parse(&p).unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("endpoint"), "{err}");
    }

    #[test]
    fn endpoint_without_port_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_spec(
            dir.path(),
            r#"
            [wg]
            endpoint = "vpn.example.com"
            [transport]
            mode = "udp"
            [build.gateway]
            target = "x86_64-unknown-linux-gnu"
            "#,
        );
        let err = Spec::parse(&p).unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("host:port"), "{err}");
    }

    #[test]
    fn bad_route_cidr_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_spec(
            dir.path(),
            r#"
            [wg]
            endpoint = "vpn.example.com:51820"
            routes = ["not-a-cidr"]
            [transport]
            mode = "udp"
            [build.gateway]
            target = "x86_64-unknown-linux-gnu"
            "#,
        );
        let err = Spec::parse(&p).unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("not-a-cidr"), "{err}");
    }

    #[test]
    fn unknown_transport_mode_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_spec(
            dir.path(),
            r#"
            [wg]
            endpoint = "vpn.example.com:51820"
            [transport]
            mode = "h2"
            [build.gateway]
            target = "x86_64-unknown-linux-gnu"
            "#,
        );
        assert!(Spec::parse(&p).is_err());
    }

    #[test]
    fn missing_gateway_target_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_spec(
            dir.path(),
            r#"
            [wg]
            endpoint = "vpn.example.com:51820"
            [transport]
            mode = "udp"
            [build.gateway]
            target = ""
            "#,
        );
        let err = Spec::parse(&p).unwrap_err();
        let err = format!("{err:#}");
        assert!(err.contains("gateway"), "{err}");
    }

    #[test]
    fn unknown_field_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = write_spec(
            dir.path(),
            r#"
            [wg]
            endpoint = "vpn.example.com:51820"
            mystery = true
            [transport]
            mode = "udp"
            [build.gateway]
            target = "x86_64-unknown-linux-gnu"
            "#,
        );
        // serde's deny_unknown_fields catches this — guards against
        // typos that would silently no-op.
        assert!(Spec::parse(&p).is_err());
    }

    #[test]
    fn split_host_port_handles_both_forms() {
        let (h, p) = split_host_port("vpn.example.com:443", 0).unwrap();
        assert_eq!(h, "vpn.example.com");
        assert_eq!(p, 443);
        let (h, p) = split_host_port("vpn.example.com", 443).unwrap();
        assert_eq!(h, "vpn.example.com");
        assert_eq!(p, 443);
    }

    #[test]
    fn layout_rejects_traversal() {
        assert!(Layout::for_name("").is_err());
        assert!(Layout::for_name("foo/bar").is_err());
        assert!(Layout::for_name("..\\evil").is_err());
        assert!(Layout::for_name("dev").is_ok());
    }
}
