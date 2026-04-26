//! `burrowctl` — single-source-of-truth orchestration for burrow.
//!
//! Each deployment lives at `deployments/<name>/` and is driven by a
//! single `spec.toml`. Three subcommands today: `validate` parses the
//! spec; `gen` produces the wg-quick configs + cert + token; `build`
//! invokes cargo for each binary at its own target, with the embed
//! env vars set internally.
//!
//! `ship` / `up` / `down` come later. For now, deploy still goes
//! through `scripts/*.sh` + the existing `just` recipes.

use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};

use burrow::orchestration::{build, gen, ship};
use burrow::spec::{Layout, Spec};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "burrow deployment orchestrator (build + configure)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Parse + sanity-check `deployments/<name>/spec.toml`. Exits 0 on
    /// success and prints a one-line summary; exits 2 with the parse /
    /// validation error otherwise.
    Validate {
        /// Deployment name (the directory under `deployments/`).
        name: String,
    },
    /// Generate `server.conf`, `burrow.conf`, `clientN.conf`, and (for
    /// WSS) `relay-bundle/{cert,key,token,listen,forward}` from the
    /// spec. Run before `build`.
    Gen {
        name: String,
    },
    /// Cross-compile burrow + burrow-relay + burrow-client per the
    /// spec's `[build]` targets, with the bundle's embed materials set
    /// internally. Collects artifacts into `relay-bundle/`.
    Build {
        name: String,
    },
    /// scp `server.conf` (and burrow-relay if WSS) to the deploy
    /// target's host, then ssh + bring up kernel WG inside a netns.
    /// The relay is started under `setsid -f` so the ssh session
    /// disconnects cleanly.
    ShipServer {
        name: String,
    },
    /// Local-only: bring up a kernel WG client inside a netns on this
    /// box. Linux only.
    ShipClient {
        name: String,
    },
    /// `gen` + `build` + `ship-server` + `ship-client` end-to-end.
    Up {
        name: String,
    },
    /// Tear down both sides — kill the remote relay + drop both
    /// netnses. Best-effort; partial state is reported but doesn't
    /// stop the rest of the teardown.
    Down {
        name: String,
    },
    /// Drop into an interactive bash inside the local client netns.
    /// Anything you run from there (curl, dig, ssh) rides the tunnel.
    Shell {
        name: String,
    },
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn real_main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Validate { name } => {
            let layout = Layout::for_name(&name)?;
            layout.require_spec()?;
            let spec = Spec::parse(&layout.spec_path())?;
            println!(
                "OK: deployments/{name}/spec.toml parses + validates.\n  \
                 wg.endpoint   = {}\n  \
                 wg.subnet     = {}\n  \
                 wg.clients    = {}\n  \
                 transport     = {:?}{}\n  \
                 build.gateway = {}\n  \
                 build.relay   = {}\n  \
                 build.client  = {}",
                spec.wg.endpoint,
                spec.wg.subnet,
                spec.wg.clients,
                spec.transport.mode,
                spec.transport
                    .relay_host
                    .as_deref()
                    .map(|h| format!(" ({h})"))
                    .unwrap_or_default(),
                spec.build.gateway.target,
                spec.build.relay.target,
                spec.build.client.target,
            );
        }
        Cmd::Gen { name } => gen::run(&name)?,
        Cmd::Build { name } => build::run(&name)?,
        Cmd::ShipServer { name } => ship::server(&name)?,
        Cmd::ShipClient { name } => ship::client(&name)?,
        Cmd::Up { name } => {
            gen::run(&name)?;
            build::run(&name)?;
            ship::server(&name)?;
            ship::client(&name)?;
        }
        Cmd::Down { name } => ship::down(&name)?,
        Cmd::Shell { name } => ship::shell(&name)?,
    }
    Ok(())
}
