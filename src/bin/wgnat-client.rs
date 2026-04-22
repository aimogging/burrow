//! Companion CLI for wgnat. Speaks the CBOR-framed control protocol
//! over a plain TCP connection to `wgnat_wg_ip:CONTROL_PORT`.
//!
//! The peer running this binary needs its own WireGuard stack
//! configured so that `wgnat_wg_ip` routes through the tunnel —
//! wgnat-client itself makes a normal TCP connect and is oblivious to
//! WireGuard at the binary level.
//!
//! SSH-style positional: `wgnat-client <wgnat_wg_ip> <subcommand>`.
//!
//! Phase 17a scope: non-interactive shell (--oneshot, --detach) +
//! tunnel register/unregister/list. Interactive PTY mode lands with
//! Phase 17b when portable-pty comes in.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use wgnat::config::DEFAULT_CONTROL_PORT;
use wgnat::wire::{
    read_frame, write_frame, ClientReq, ErrorKind, Proto, ServerResp, ShellMode, TunnelId,
};

#[derive(Parser, Debug)]
#[command(version, about = "CLI peer for wgnat's control channel")]
struct Cli {
    /// WG address of the wgnat host to connect to.
    wgnat_ip: Ipv4Addr,

    /// Control port (defaults to wgnat's DEFAULT_CONTROL_PORT = 57821).
    #[arg(long, default_value_t = DEFAULT_CONTROL_PORT)]
    control_port: u16,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Reverse-tunnel management.
    Tunnel {
        #[command(subcommand)]
        action: TunnelCmd,
    },
    /// Run a command on the wgnat host.
    Shell(ShellArgs),
}

#[derive(Subcommand, Debug)]
enum TunnelCmd {
    /// Register a reverse tunnel. Syntax: `-R LISTEN:HOST:PORT`.
    Register {
        /// `LISTEN:HOST:PORT` — peers hit `wg_ip:LISTEN`, wgnat
        /// forwards to `HOST:PORT`. Default protocol is TCP.
        #[arg(short = 'R', value_name = "LISTEN:HOST:PORT")]
        spec: String,
        /// Use UDP instead of TCP.
        #[arg(short = 'U', long)]
        udp: bool,
    },
    /// Remove a previously-registered tunnel by id.
    Unregister { tunnel_id: u64 },
    /// List active reverse tunnels.
    List,
}

#[derive(clap::Args, Debug)]
struct ShellArgs {
    /// Run the command, capture stdout+stderr, print to local terminal
    /// (with `--output -`, the default) or write to a file.
    #[arg(long, value_name = "PATH")]
    output: Option<String>,

    /// Spawn detached; return immediately with the pid. No output
    /// captured.
    #[arg(long, conflicts_with = "output")]
    detach: bool,

    /// Request an interactive PTY session (Phase 17b — not yet wired).
    /// Exposed now so the CLI surface is stable.
    #[arg(long, conflicts_with_all = ["output", "detach"])]
    interactive: bool,

    /// Executable to run on the wgnat host. Defaults per-OS on the
    /// server side (cmd.exe on Windows, $SHELL / /bin/sh on Unix).
    #[arg(long)]
    program: Option<String>,

    /// Positional args passed after `--`.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(ValueEnum, Clone, Debug)]
enum OutputTarget {
    Stdout,
    File,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("wgnat-client: {e:#}");
            ExitCode::from(1)
        }
    }
}

async fn run(cli: Cli) -> Result<ExitCode> {
    let addr = SocketAddrV4::new(cli.wgnat_ip, cli.control_port);
    match cli.cmd {
        Cmd::Tunnel { action } => run_tunnel(addr, action).await,
        Cmd::Shell(args) => run_shell(addr, args).await,
    }
}

async fn connect_control(addr: SocketAddrV4) -> Result<TcpStream> {
    let stream = TcpStream::connect(addr)
        .await
        .with_context(|| format!("connecting to wgnat control at {addr}"))?;
    stream.set_nodelay(true).ok();
    Ok(stream)
}

async fn run_tunnel(addr: SocketAddrV4, action: TunnelCmd) -> Result<ExitCode> {
    match action {
        TunnelCmd::Register { spec, udp } => {
            let (listen_port, forward_to) = parse_r_spec(&spec)?;
            let req = ClientReq::RegisterReverse {
                proto: if udp { Proto::Udp } else { Proto::Tcp },
                listen_port,
                forward_to,
            };
            let resp = one_shot_request(addr, &req).await?;
            match resp {
                ServerResp::Ok { tunnel_id } => {
                    println!("{}", tunnel_id.0);
                    Ok(ExitCode::SUCCESS)
                }
                ServerResp::Error { kind, msg } => {
                    eprintln!("register failed: {kind:?}: {msg}");
                    Ok(ExitCode::from(2))
                }
                other => bail!("unexpected response: {other:?}"),
            }
        }
        TunnelCmd::Unregister { tunnel_id } => {
            let req = ClientReq::UnregisterReverse {
                tunnel_id: TunnelId(tunnel_id),
            };
            let resp = one_shot_request(addr, &req).await?;
            match resp {
                ServerResp::Unregistered => {
                    println!("unregistered {tunnel_id}");
                    Ok(ExitCode::SUCCESS)
                }
                ServerResp::Error { kind, msg } => {
                    eprintln!("unregister failed: {kind:?}: {msg}");
                    Ok(ExitCode::from(2))
                }
                other => bail!("unexpected response: {other:?}"),
            }
        }
        TunnelCmd::List => {
            let resp = one_shot_request(addr, &ClientReq::ListReverse).await?;
            match resp {
                ServerResp::ReverseList(entries) => {
                    if entries.is_empty() {
                        println!("(no active tunnels)");
                    } else {
                        println!("{:<10} {:<5} {:<10} {}", "TUNNEL", "PROTO", "LISTEN", "FORWARD");
                        for e in entries {
                            let proto = match e.proto {
                                Proto::Tcp => "TCP",
                                Proto::Udp => "UDP",
                            };
                            println!(
                                "{:<10} {:<5} {:<10} {}",
                                e.tunnel_id.0, proto, e.listen_port, e.forward_to
                            );
                        }
                    }
                    Ok(ExitCode::SUCCESS)
                }
                ServerResp::Error { kind, msg } => {
                    eprintln!("list failed: {kind:?}: {msg}");
                    Ok(ExitCode::from(2))
                }
                other => bail!("unexpected response: {other:?}"),
            }
        }
    }
}

async fn run_shell(addr: SocketAddrV4, args: ShellArgs) -> Result<ExitCode> {
    let mode = if args.interactive {
        ShellMode::Interactive
    } else if args.detach {
        ShellMode::FireAndForget
    } else {
        ShellMode::Oneshot
    };
    let req = ClientReq::RequestShell {
        mode,
        program: args.program,
        args: args.args,
    };
    let resp = one_shot_request(addr, &req).await?;
    match resp {
        ServerResp::ShellResult {
            exit_code,
            stdout,
            stderr,
        } => {
            let target = args.output.as_deref();
            match target {
                Some("-") | None => {
                    use std::io::Write;
                    std::io::stdout().write_all(&stdout).ok();
                    std::io::stderr().write_all(&stderr).ok();
                }
                Some(path) => {
                    let p = PathBuf::from(path);
                    std::fs::write(&p, &stdout).with_context(|| {
                        format!("writing stdout to {}", p.display())
                    })?;
                    // stderr still goes to local stderr so the caller
                    // knows something went wrong.
                    use std::io::Write;
                    std::io::stderr().write_all(&stderr).ok();
                }
            }
            Ok(match exit_code {
                Some(c) if (0..=255).contains(&c) => ExitCode::from(c as u8),
                Some(_) => ExitCode::from(127),
                None => ExitCode::from(128),
            })
        }
        ServerResp::ShellSpawned { pid } => {
            println!("{}", pid);
            Ok(ExitCode::SUCCESS)
        }
        ServerResp::ShellReady => {
            bail!("server opened an interactive session but this client build doesn't support it yet (Phase 17b)");
        }
        ServerResp::Error { kind, msg } => {
            eprintln!("shell failed: {kind:?}: {msg}");
            Ok(match kind {
                ErrorKind::NotYetSupported => ExitCode::from(3),
                _ => ExitCode::from(2),
            })
        }
        other => bail!("unexpected response: {other:?}"),
    }
}

/// Send one request, read one response, close. Most subcommands follow
/// this shape.
async fn one_shot_request(addr: SocketAddrV4, req: &ClientReq) -> Result<ServerResp> {
    let mut stream = connect_control(addr).await?;
    write_frame(&mut stream, req).await?;
    let resp: ServerResp = read_frame(&mut stream)
        .await
        .map_err(|e| anyhow!("reading response: {e}"))?;
    let _ = stream.shutdown().await;
    Ok(resp)
}

/// Parse `LISTEN:HOST:PORT`. LISTEN and PORT are u16; HOST is an
/// IPv4 address.
fn parse_r_spec(spec: &str) -> Result<(u16, SocketAddrV4)> {
    let parts: Vec<&str> = spec.splitn(3, ':').collect();
    if parts.len() != 3 {
        bail!("expected LISTEN:HOST:PORT, got `{spec}`");
    }
    let listen: u16 = parts[0]
        .parse()
        .with_context(|| format!("invalid LISTEN port `{}`", parts[0]))?;
    let host: Ipv4Addr = parts[1]
        .parse()
        .with_context(|| format!("invalid HOST `{}` (IPv4 required)", parts[1]))?;
    let port: u16 = parts[2]
        .parse()
        .with_context(|| format!("invalid PORT `{}`", parts[2]))?;
    Ok((listen, SocketAddrV4::new(host, port)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_r_spec_happy() {
        let (listen, fwd) = parse_r_spec("443:127.0.0.1:443").unwrap();
        assert_eq!(listen, 443);
        assert_eq!(fwd, SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 443));
    }

    #[test]
    fn parse_r_spec_rejects_bad_input() {
        assert!(parse_r_spec("443:127.0.0.1").is_err()); // missing port
        assert!(parse_r_spec("not-a-port:127.0.0.1:443").is_err());
        assert!(parse_r_spec("443:not-an-ip:443").is_err());
    }
}
