//! `burrowctl build <name>` — invoke cargo three times (gateway,
//! relay, client) with the right per-binary `--target` and
//! `--features`, set the `BURROW_*_EMBED_*` env vars internally so
//! humans never see them, and collect the resulting artifacts into the
//! deployment's `relay-bundle/`.
//!
//! UDP-mode builds skip the relay (no bundle, nothing to embed).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::spec::{Layout, Spec, TransportMode};

/// Drive `build` for the deployment named `name`. Requires `gen` to
/// have already produced the configs (and, for WSS, the bundle
/// materials).
pub fn run(name: &str) -> Result<()> {
    let layout = Layout::for_name(name)?;
    layout.require_spec()?;
    let spec = Spec::parse(&layout.spec_path())?;

    // gen must have produced burrow.conf at minimum; for WSS also the
    // bundle materials (cert/key/token/listen/forward).
    if !layout.burrow_conf().exists() {
        bail!(
            "no {} — run `burrowctl gen {name}` first",
            layout.burrow_conf().display()
        );
    }
    if spec.transport.mode == TransportMode::Wss {
        for f in ["cert.pem", "key.pem", "token.txt", "listen.txt", "forward.txt"] {
            let p = layout.bundle_file(f);
            if !p.exists() {
                bail!(
                    "relay-bundle missing {} — re-run `burrowctl gen {name}`",
                    p.display()
                );
            }
        }
    } else {
        // UDP mode still needs the bundle dir to land binaries in.
        layout.ensure_dirs(true)?;
    }

    build_gateway(&layout, &spec.build.gateway.target)?;
    if spec.transport.mode == TransportMode::Wss {
        build_relay(&layout, &spec.build.relay.target)?;
    }
    build_client(&spec.build.client.target)?;

    collect_artifacts(&layout, &spec)?;

    println!("\nartifacts collected into {}:", layout.bundle_dir().display());
    for entry in fs::read_dir(layout.bundle_dir())? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            println!("  {}", entry.file_name().to_string_lossy());
        }
    }
    Ok(())
}

fn build_gateway(layout: &Layout, target: &str) -> Result<()> {
    let abs_conf = fs::canonicalize(layout.burrow_conf())
        .with_context(|| format!("canonicalize {}", layout.burrow_conf().display()))?;
    println!(
        "\n>>> building burrow (gateway) for {target} with embedded config {}",
        abs_conf.display()
    );
    let mut cmd = cargo();
    cmd.args([
        "build",
        "--bin", "burrow",
        "--profile", "min",
        "--features", "embedded-config,silent",
        "--target", target,
    ])
    .env("BURROW_EMBEDDED_CONFIG", &abs_conf);
    run_cargo(cmd)
}

fn build_relay(layout: &Layout, target: &str) -> Result<()> {
    let bundle = fs::canonicalize(layout.bundle_dir())
        .with_context(|| format!("canonicalize {}", layout.bundle_dir().display()))?;
    let token = read_trim(&bundle.join("token.txt"))?;
    let listen = read_trim(&bundle.join("listen.txt"))?;
    let forward = read_trim(&bundle.join("forward.txt"))?;
    println!(
        "\n>>> building burrow-relay for {target} with embedded bundle from {}",
        bundle.display()
    );
    let mut cmd = cargo();
    cmd.args([
        "build",
        "--bin", "burrow-relay",
        "--profile", "min",
        "--features", "embedded-relay-bundle,silent",
        "--target", target,
    ])
    .env("BURROW_RELAY_EMBED_TOKEN", token)
    .env("BURROW_RELAY_EMBED_CERT_FILE", bundle.join("cert.pem"))
    .env("BURROW_RELAY_EMBED_KEY_FILE", bundle.join("key.pem"))
    .env("BURROW_RELAY_EMBED_LISTEN", listen)
    .env("BURROW_RELAY_EMBED_FORWARD", forward);
    run_cargo(cmd)
}

fn build_client(target: &str) -> Result<()> {
    println!("\n>>> building burrow-client for {target}");
    let mut cmd = cargo();
    cmd.args([
        "build",
        "--bin", "burrow-client",
        "--profile", "min",
        "--features", "silent",
        "--target", target,
    ]);
    run_cargo(cmd)
}

/// Copy each binary from `target/<triple>/min/` into the bundle dir.
/// Matches both unix and `.exe` forms so any combo of targets lands
/// correctly.
fn collect_artifacts(layout: &Layout, spec: &Spec) -> Result<()> {
    let bundle = layout.bundle_dir();
    let triples = [
        ("burrow", spec.build.gateway.target.as_str()),
        ("burrow-client", spec.build.client.target.as_str()),
    ];
    let mut all: Vec<(&str, &str)> = triples.to_vec();
    if spec.transport.mode == TransportMode::Wss {
        all.push(("burrow-relay", spec.build.relay.target.as_str()));
    }
    for (bin, triple) in all {
        let mut copied = false;
        for variant in [bin.to_string(), format!("{bin}.exe")] {
            let src: PathBuf = ["target", triple, "min", &variant].iter().collect();
            if src.exists() {
                let dst = bundle.join(&variant);
                fs::copy(&src, &dst)
                    .with_context(|| format!("copy {} -> {}", src.display(), dst.display()))?;
                copied = true;
            }
        }
        if !copied {
            bail!(
                "no built artifact for {bin} found under target/{triple}/min/ — \
                 cargo build silently produced nothing?"
            );
        }
    }
    Ok(())
}

fn cargo() -> Command {
    // Honour CARGO if cargo set it (we may be running under cargo run);
    // otherwise just call `cargo` and let PATH resolve it.
    let cargo_bin = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    Command::new(cargo_bin)
}

fn run_cargo(mut cmd: Command) -> Result<()> {
    let status = cmd
        .status()
        .with_context(|| format!("spawning {cmd:?}"))?;
    if !status.success() {
        bail!("cargo build failed (exit {:?})", status.code());
    }
    Ok(())
}

fn read_trim(path: &Path) -> Result<String> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(s.trim().to_string())
}
