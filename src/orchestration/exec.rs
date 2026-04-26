//! Execution helpers for the orchestration layer — wraps
//! `std::process::Command` for the three patterns we need: local sudo
//! bash with a piped script, ssh with a piped script, and scp file
//! transfer. Errors carry the originating command in their context so
//! a failed step is easy to attribute.
//!
//! Auth notes: ssh and scp inherit the user's `~/.ssh/config`,
//! ssh-agent, default keys, and ProxyCommand. The spec only carries
//! the host string — anything more elaborate goes in ssh config.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};

/// Pipe `script` into a fresh `sudo bash -s` on this host. Inherits
/// stdout/stderr so the user sees what's happening live.
pub fn local_sudo_script(script: &str) -> Result<()> {
    let mut child = Command::new("sudo")
        .args(["bash", "-s"])
        .stdin(Stdio::piped())
        .spawn()
        .context("spawning local `sudo bash -s`")?;
    child
        .stdin
        .as_mut()
        .expect("stdin requested above")
        .write_all(script.as_bytes())
        .context("writing script to sudo stdin")?;
    let status = child.wait().context("waiting on sudo bash")?;
    if !status.success() {
        bail!("local sudo bash failed (exit {:?})", status.code());
    }
    Ok(())
}

/// Pipe `script` into `ssh <host> sudo bash -s`. Errors include the
/// host so multi-host runs are debuggable.
pub fn ssh_sudo_script(host: &str, script: &str) -> Result<()> {
    let mut child = Command::new("ssh")
        .args([host, "sudo", "bash", "-s"])
        .stdin(Stdio::piped())
        .spawn()
        .with_context(|| format!("spawning `ssh {host} sudo bash -s`"))?;
    child
        .stdin
        .as_mut()
        .expect("stdin requested above")
        .write_all(script.as_bytes())
        .with_context(|| format!("writing script to ssh stdin ({host})"))?;
    let status = child.wait().with_context(|| format!("waiting on ssh ({host})"))?;
    if !status.success() {
        bail!("ssh {host} bash script failed (exit {:?})", status.code());
    }
    Ok(())
}

/// Copy `local` to `<host>:<remote>` via scp. The remote path is
/// passed as one shell-arg to scp, so embed quoting carefully if the
/// path contains spaces (currently never the case for our use).
pub fn scp_to(local: &Path, host: &str, remote: &str) -> Result<()> {
    let dest = format!("{host}:{remote}");
    let status = Command::new("scp")
        .arg(local)
        .arg(&dest)
        .status()
        .with_context(|| format!("spawning scp {} -> {dest}", local.display()))?;
    if !status.success() {
        bail!(
            "scp {} -> {dest} failed (exit {:?})",
            local.display(),
            status.code()
        );
    }
    Ok(())
}

/// Spawn an interactive ssh — used by `shell` for a remote netns. The
/// `-t` flag forces TTY allocation so the inner shell behaves
/// interactively. Inherits the user's terminal directly.
pub fn ssh_interactive(host: &str, remote_cmd: &str) -> Result<()> {
    let status = Command::new("ssh")
        .arg("-t")
        .arg(host)
        .arg(remote_cmd)
        .status()
        .with_context(|| format!("spawning interactive `ssh -t {host}`"))?;
    if !status.success() {
        bail!("ssh -t {host} exited {:?}", status.code());
    }
    Ok(())
}

/// Run an interactive local sudo command — used by `shell` to drop
/// the user into a netns. Inherits the terminal.
pub fn local_sudo_interactive(args: &[&str]) -> Result<()> {
    let status = Command::new("sudo")
        .args(args)
        .status()
        .context("spawning local sudo for interactive shell")?;
    if !status.success() {
        bail!("local sudo {args:?} exited {:?}", status.code());
    }
    Ok(())
}
