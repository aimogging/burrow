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

use burrow::orchestration::{build, gen, init, ship};
use burrow::orchestration::init::InitArgs;
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
    /// Bootstrap a new deployment. With no flags + a TTY, opens a
    /// short ratatui form. With any field flag set (or no TTY), runs
    /// in batch mode: missing required fields exit non-zero. Refuses
    /// to overwrite an existing spec without `--force`.
    Init {
        /// Deployment name (`deployments/<name>/spec.toml`).
        name: String,

        /// WireGuard server endpoint (host:port). Required in batch mode.
        #[arg(long)]
        endpoint: Option<String>,

        /// Target triple for the burrow gateway binary. Default = host's triple.
        #[arg(long)]
        gateway_target: Option<String>,

        /// SSH host for `ship-server` / `up` / `down`. Pass empty
        /// string to disable the [deploy] section.
        #[arg(long)]
        deploy_host: Option<String>,

        /// Transport: `udp` (default) or `wss`.
        #[arg(long)]
        transport: Option<String>,

        /// Relay host:port. Required when --transport wss.
        #[arg(long)]
        relay_host: Option<String>,

        /// TLS strategy when --transport wss: `self-signed` (default,
        /// gen generates the cert) or `byo` (gen reads cert + key
        /// from --cert-path / --key-path).
        #[arg(long, value_name = "STRATEGY")]
        tls: Option<String>,

        /// Path to the cert PEM. Required when --tls byo.
        #[arg(long, value_name = "PATH")]
        cert_path: Option<String>,

        /// Path to the private key PEM. Required when --tls byo.
        #[arg(long, value_name = "PATH")]
        key_path: Option<String>,

        /// Routes as a comma-separated list of CIDRs.
        #[arg(long)]
        routes: Option<String>,

        /// Overwrite an existing spec.
        #[arg(long)]
        force: bool,

        /// Open the TUI even when CLI flags are set, with the flag
        /// values pre-filled. Lets you tweak before saving.
        #[arg(long)]
        prefill: bool,

        /// Skip the TUI; open the spec template in $VISUAL / $EDITOR
        /// (falls back to `vi` on Unix, `notepad` on Windows). The
        /// editor opens with placeholders + comments; on save the
        /// content is re-validated, and on validation error you're
        /// re-opened with the error annotated at the top.
        #[arg(long)]
        editor: bool,

        // -------------------------------------------------------------
        // Advanced fields — most users never need these. Defaults
        // documented in the TUI's Hidden defaults comment.
        // -------------------------------------------------------------
        #[arg(long, value_name = "CIDR", help_heading = "Advanced")]
        subnet: Option<String>,
        #[arg(long, value_name = "N", help_heading = "Advanced")]
        clients: Option<u16>,
        #[arg(long, value_name = "PORT", help_heading = "Advanced")]
        listen_port: Option<u16>,
        #[arg(long, value_name = "IP[,IP...]", help_heading = "Advanced")]
        dns: Option<String>,
        #[arg(long, value_name = "NAME", help_heading = "Advanced")]
        server_namespace: Option<String>,
        #[arg(long, value_name = "NAME", help_heading = "Advanced")]
        client_namespace: Option<String>,
        #[arg(long, value_name = "TRIPLE", help_heading = "Advanced")]
        relay_target: Option<String>,
        #[arg(long, value_name = "TRIPLE", help_heading = "Advanced")]
        client_target: Option<String>,
    },
    /// Open the TUI populated from an existing
    /// `deployments/<name>/spec.toml`. Save (Ctrl-S / `:w`) writes
    /// back atomically.
    Edit {
        /// Deployment name.
        name: String,
    },
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
        Cmd::Init {
            name,
            endpoint,
            gateway_target,
            deploy_host,
            transport,
            relay_host,
            tls,
            cert_path,
            key_path,
            routes,
            force,
            prefill,
            editor,
            subnet,
            clients,
            listen_port,
            dns,
            server_namespace,
            client_namespace,
            relay_target,
            client_target,
        } => {
            let args = InitArgs {
                endpoint,
                gateway_target,
                deploy_host,
                transport,
                relay_host,
                tls,
                cert_path,
                key_path,
                routes,
                force,
                prefill,
                editor,
                subnet,
                clients,
                listen_port,
                dns,
                server_namespace,
                client_namespace,
                relay_target,
                client_target,
            };
            args.validate_shape()?;
            init::run(&name, args)?;
        }
        Cmd::Edit { name } => init::edit(&name)?,
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
