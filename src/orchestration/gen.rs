//! `burrowctl gen <name>` — read `deployments/<name>/spec.toml`, run
//! `config_gen::generate`, write the resulting wg-quick configs +
//! relay-bundle materials into the deployment dir.
//!
//! The mapping from `Spec` to `GenParams` is the only intelligence
//! here; the actual config generation, cert generation, and key
//! generation live in `crate::config_gen` and are reused as-is.

use std::fs;

use anyhow::{Context, Result};

use crate::config::parse_ipv4_cidr;
use crate::config_gen::{generate, GenParams, RelayParams};
use crate::config::DEFAULT_CONTROL_PORT;
use crate::spec::{Layout, Spec, TransportMode};

/// Drive `gen` for the deployment named `name`. Reads
/// `deployments/<name>/spec.toml`, writes the trio + (for WSS)
/// relay-bundle into `deployments/<name>/`.
pub fn run(name: &str) -> Result<()> {
    let layout = Layout::for_name(name)?;
    run_with_layout(&layout)
}

/// Same as `run`, but lets the caller (typically tests) supply a
/// pre-built Layout pointing at an arbitrary base dir.
pub fn run_with_layout(layout: &Layout) -> Result<()> {
    layout.require_spec()?;
    let spec = Spec::parse(&layout.spec_path())?;

    let want_bundle = spec.transport.mode == TransportMode::Wss;
    layout.ensure_dirs(want_bundle)?;

    let subnet = parse_ipv4_cidr(&spec.wg.subnet)
        .with_context(|| format!("[wg] subnet `{}`", spec.wg.subnet))?;

    let params = GenParams {
        endpoint: spec.wg.endpoint.clone(),
        routes: spec.wg.routes.clone(),
        dns: spec.wg.dns.clone(),
        subnet,
        clients: spec.wg.clients,
        listen_port: spec.wg.listen_port,
        control_port: DEFAULT_CONTROL_PORT,
        relay: match (spec.transport.mode, &spec.transport.relay_host) {
            (TransportMode::Wss, Some(host)) => Some(RelayParams {
                host_port: host.clone(),
            }),
            _ => None,
        },
    };

    let configs = generate(&params)?;
    for c in &configs {
        let path = layout.root.join(&c.filename);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        fs::write(&path, &c.contents)
            .with_context(|| format!("writing {}", path.display()))?;
        set_private_file_permissions(&path);
    }

    println!("wrote {} files into {}:", configs.len(), layout.root.display());
    for c in &configs {
        println!("  {}", c.filename);
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &std::path::Path) {
    // Windows: NTFS ACLs are the right tool for restricting access;
    // the gitignore on relay-bundle/ is the practical safety net.
}
