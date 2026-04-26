//! `FormState` — the data model shared by both the TUI form and the
//! batch CLI path. Constructors:
//!
//! * `with_defaults()` — for the TUI's "blank starting point".
//! * `from_args(&InitArgs)` — for batch mode.
//!
//! `require_complete()` flags missing required fields by their CLI
//! flag name so error messages always point at something the user
//! can act on. Per-field validation for the TUI happens in `tui.rs`
//! (where it can render inline errors); the final `Spec::parse` call
//! in `mod.rs::write_spec` is the universal gate.

use anyhow::{bail, Result};

/// Mirror of `crate::spec::TlsStrategy` carried in FormState.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsChoice {
    #[default]
    SelfSigned,
    Byo,
}

impl TlsChoice {
    pub fn from_cli(s: &str) -> Result<Self> {
        match s {
            "self-signed" | "selfsigned" => Ok(Self::SelfSigned),
            "byo" => Ok(Self::Byo),
            other => bail!("--tls must be `self-signed` or `byo` (got `{other}`)"),
        }
    }
    pub fn as_toml(self) -> &'static str {
        match self {
            Self::SelfSigned => "self-signed",
            Self::Byo => "byo",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::SelfSigned => "self-signed (default; cert generated)",
            Self::Byo => "bring your own (point at cert.pem + key.pem)",
        }
    }
}

/// Wizard fields. The Phase 3 advanced fields are stored as
/// optional strings: `None` means "leave at the spec default";
/// `Some` means "user/CLI overrode it" and gets emitted explicitly.
/// The TUI's "Advanced" toggle reveals them; collapsing the section
/// without changes keeps them `None` so the emitted spec stays
/// minimal.
#[derive(Debug, Clone)]
pub struct FormState {
    pub endpoint: String,
    pub gateway_target: String,
    pub deploy_enabled: bool,
    pub deploy_host: String,
    pub wss_enabled: bool,
    pub relay_host: String,
    pub tls_strategy: TlsChoice,
    pub cert_path: String,
    pub key_path: String,
    pub routes: String,

    // Advanced — None means "use spec default", Some means override.
    // Stored as strings so the TUI's text-input path is uniform; the
    // post-emit `Spec::parse_str` gate catches non-numeric content.
    pub subnet: Option<String>,
    pub clients: Option<String>,
    pub listen_port: Option<String>,
    pub dns: Option<String>,
    pub server_namespace: Option<String>,
    pub client_namespace: Option<String>,
    pub relay_target: Option<String>,
    pub client_target: Option<String>,
}

impl FormState {
    /// Sensible starting point for an interactive run: the gateway
    /// target defaults to the host's triple, deploy starts toggled on
    /// (the most common path), WSS off (UDP unless you need it).
    pub fn with_defaults() -> Self {
        Self {
            endpoint: String::new(),
            gateway_target: detect_host_triple().to_string(),
            deploy_enabled: true,
            deploy_host: String::new(),
            wss_enabled: false,
            relay_host: String::new(),
            tls_strategy: TlsChoice::SelfSigned,
            cert_path: String::new(),
            key_path: String::new(),
            routes: String::new(),
            subnet: None,
            clients: None,
            listen_port: None,
            dns: None,
            server_namespace: None,
            client_namespace: None,
            relay_target: None,
            client_target: None,
        }
    }

    /// Populate from a parsed `Spec` — used by `burrowctl edit` so the
    /// TUI starts on the existing values. Advanced fields are surfaced
    /// only when they differ from the spec-side defaults so the user
    /// doesn't see Some everywhere.
    pub fn from_spec(spec: &crate::spec::Spec) -> Self {
        let wss = spec.transport.mode == crate::spec::TransportMode::Wss;
        let some_if = |v: String, default: &str| if v == default { None } else { Some(v) };
        let some_u16 = |v: u16, default: u16| if v == default { None } else { Some(v.to_string()) };
        Self {
            endpoint: spec.wg.endpoint.clone(),
            gateway_target: spec.build.gateway.target.clone(),
            deploy_enabled: spec.deploy.is_some(),
            deploy_host: spec
                .deploy
                .as_ref()
                .map(|d| d.server.host.clone())
                .unwrap_or_default(),
            wss_enabled: wss,
            relay_host: spec.transport.relay_host.clone().unwrap_or_default(),
            tls_strategy: match spec.transport.tls {
                crate::spec::TlsStrategy::SelfSigned => TlsChoice::SelfSigned,
                crate::spec::TlsStrategy::Byo => TlsChoice::Byo,
            },
            cert_path: spec.transport.cert_path.clone().unwrap_or_default(),
            key_path: spec.transport.key_path.clone().unwrap_or_default(),
            routes: spec.wg.routes.join(", "),
            subnet: some_if(spec.wg.subnet.clone(), "10.0.0.0/24"),
            clients: some_u16(spec.wg.clients, 1),
            listen_port: some_u16(spec.wg.listen_port, 51820),
            dns: if spec.wg.dns.is_empty() {
                None
            } else {
                Some(spec.wg.dns.join(", "))
            },
            server_namespace: spec
                .deploy
                .as_ref()
                .and_then(|d| some_if(d.server.namespace.clone(), "burrow")),
            client_namespace: spec
                .deploy
                .as_ref()
                .and_then(|d| some_if(d.client.namespace.clone(), "burrow")),
            relay_target: some_if(spec.build.relay.target.clone(), "x86_64-unknown-linux-gnu"),
            client_target: some_if(spec.build.client.target.clone(), "x86_64-unknown-linux-gnu"),
        }
    }

    /// Build from CLI flags. Missing optional fields fall back to the
    /// same values `with_defaults()` uses; missing required fields
    /// stay empty so `require_complete` can flag them.
    pub fn from_args(args: &InitArgs) -> Result<Self> {
        let endpoint = args.endpoint.clone().unwrap_or_default();
        let gateway_target = args
            .gateway_target
            .clone()
            .unwrap_or_else(|| detect_host_triple().to_string());

        // --deploy-host present (even empty string) controls whether
        // the deploy section gets emitted; absent flag → default to
        // "use endpoint host" (matching TUI default behavior).
        let (deploy_enabled, deploy_host) = match &args.deploy_host {
            Some(h) if h.is_empty() => (false, String::new()),
            Some(h) => (true, h.clone()),
            None => {
                // Batch mode without --deploy-host: default to
                // "deploy enabled, host = endpoint hostname".
                let host = endpoint
                    .split(':')
                    .next()
                    .unwrap_or("")
                    .to_string();
                (!host.is_empty(), host)
            }
        };

        let wss_enabled = matches!(args.transport.as_deref(), Some("wss"));
        let relay_host = args.relay_host.clone().unwrap_or_else(|| {
            if wss_enabled {
                // Default to endpoint host + :443.
                let host = endpoint.split(':').next().unwrap_or("");
                if host.is_empty() {
                    String::new()
                } else {
                    format!("{host}:443")
                }
            } else {
                String::new()
            }
        });

        let routes = args.routes.clone().unwrap_or_default();
        let tls_strategy = match &args.tls {
            Some(s) => TlsChoice::from_cli(s)?,
            None => TlsChoice::SelfSigned,
        };
        let cert_path = args.cert_path.clone().unwrap_or_default();
        let key_path = args.key_path.clone().unwrap_or_default();

        Ok(Self {
            endpoint,
            gateway_target,
            deploy_enabled,
            deploy_host,
            wss_enabled,
            relay_host,
            tls_strategy,
            cert_path,
            key_path,
            routes,
            subnet: args.subnet.clone(),
            clients: args.clients.map(|n| n.to_string()),
            listen_port: args.listen_port.map(|n| n.to_string()),
            dns: args.dns.clone(),
            server_namespace: args.server_namespace.clone(),
            client_namespace: args.client_namespace.clone(),
            relay_target: args.relay_target.clone(),
            client_target: args.client_target.clone(),
        })
    }

    /// Returns the name of the first missing required field
    /// (formatted as the CLI flag the user would set), or Ok(()) if
    /// the state is complete enough to emit. Required is
    /// context-sensitive: deploy_host only required when
    /// deploy_enabled; relay_host only when wss_enabled.
    pub fn require_complete(&self) -> std::result::Result<(), String> {
        if self.endpoint.trim().is_empty() {
            return Err("endpoint".into());
        }
        if self.gateway_target.trim().is_empty() {
            return Err("gateway-target".into());
        }
        if self.deploy_enabled && self.deploy_host.trim().is_empty() {
            return Err("deploy-host".into());
        }
        if self.wss_enabled && self.relay_host.trim().is_empty() {
            return Err("relay-host".into());
        }
        if self.wss_enabled && self.tls_strategy == TlsChoice::Byo {
            if self.cert_path.trim().is_empty() {
                return Err("cert-path".into());
            }
            if self.key_path.trim().is_empty() {
                return Err("key-path".into());
            }
        }
        Ok(())
    }

    /// Routes split into trimmed non-empty entries.
    pub fn routes_vec(&self) -> Vec<String> {
        self.routes
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

/// CLI flags driving batch mode. Mirrors the TUI fields one-for-one.
#[derive(Debug, Default, Clone)]
pub struct InitArgs {
    pub endpoint: Option<String>,
    pub gateway_target: Option<String>,
    pub deploy_host: Option<String>,
    pub transport: Option<String>,
    pub relay_host: Option<String>,
    pub routes: Option<String>,
    pub force: bool,
    pub prefill: bool,
    pub editor: bool,

    pub tls: Option<String>,
    pub cert_path: Option<String>,
    pub key_path: Option<String>,

    // Phase 3 advanced fields.
    pub subnet: Option<String>,
    pub clients: Option<u16>,
    pub listen_port: Option<u16>,
    pub dns: Option<String>,
    pub server_namespace: Option<String>,
    pub client_namespace: Option<String>,
    pub relay_target: Option<String>,
    pub client_target: Option<String>,
}

impl InitArgs {
    /// True iff at least one field-flag is set (i.e. caller asked for
    /// batch mode rather than the TUI). `force` / `prefill` / `editor`
    /// don't count — they're mode modifiers, not value sources.
    pub fn has_any_flag(&self) -> bool {
        self.endpoint.is_some()
            || self.gateway_target.is_some()
            || self.deploy_host.is_some()
            || self.transport.is_some()
            || self.relay_host.is_some()
            || self.routes.is_some()
            || self.subnet.is_some()
            || self.clients.is_some()
            || self.listen_port.is_some()
            || self.dns.is_some()
            || self.server_namespace.is_some()
            || self.client_namespace.is_some()
            || self.relay_target.is_some()
            || self.client_target.is_some()
            || self.tls.is_some()
            || self.cert_path.is_some()
            || self.key_path.is_some()
    }

    /// Sanity-check flag values that aren't tied to required-field
    /// presence — currently just `--transport`.
    pub fn validate_shape(&self) -> Result<()> {
        if let Some(t) = &self.transport {
            match t.as_str() {
                "udp" | "wss" => {}
                other => bail!("--transport must be `udp` or `wss` (got `{other}`)"),
            }
        }
        Ok(())
    }
}

/// Detect the host's rustc target triple — used as the default for
/// `gateway_target`. Keeps the user from hand-typing a triple in the
/// most common case (build for the box you're running on). Matches
/// only the four pairs we ship presets for; anything else falls back
/// to Linux x86_64.
pub fn detect_host_triple() -> &'static str {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => "x86_64-unknown-linux-gnu",
        ("windows", "x86_64") => "x86_64-pc-windows-msvc",
        ("macos", "aarch64") => "aarch64-apple-darwin",
        ("macos", "x86_64") => "x86_64-apple-darwin",
        _ => "x86_64-unknown-linux-gnu",
    }
}
