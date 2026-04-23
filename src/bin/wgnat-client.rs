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
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

use wgnat::config::DEFAULT_CONTROL_PORT;
use wgnat::shell_protocol as sp;
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
    /// Run the command non-interactively, capture stdout+stderr.
    /// `--output -` prints to local stdout/stderr; `--output PATH`
    /// writes stdout to the file and stderr still to the terminal.
    /// Mutually exclusive with `--detach`; implies no PTY.
    #[arg(long, value_name = "PATH")]
    output: Option<String>,

    /// Spawn detached; return immediately with the pid. No output
    /// captured. Mutually exclusive with `--output`.
    #[arg(long, conflicts_with = "output")]
    detach: bool,

    /// Request an interactive PTY session. This is the default; the
    /// flag is kept for explicitness and scripts that want to assert
    /// the mode. Mutually exclusive with `--output` and `--detach`.
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
    // Default is Interactive (matches the plan: an `ssh`-like UX
    // where bare `shell` drops you into a prompt). `--output` opts
    // into one-shot capture; `--detach` opts into fire-and-forget.
    // Fire-and-forget is NEVER the default — silently swallowing
    // output is a footgun.
    let mode = if args.detach {
        ShellMode::FireAndForget
    } else if args.output.is_some() {
        ShellMode::Oneshot
    } else {
        ShellMode::Interactive
    };
    // Interactive takes over the flow after ShellReady. Hand off to a
    // dedicated handler rather than using the one-shot request helper.
    if mode == ShellMode::Interactive {
        return run_shell_interactive(addr, args.program, args.args).await;
    }
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

/// Restore terminal raw mode (and Windows console modes) on scope
/// exit, including panic unwind. On Windows, crossterm's raw mode
/// doesn't touch `ENABLE_VIRTUAL_TERMINAL_INPUT` /
/// `ENABLE_VIRTUAL_TERMINAL_PROCESSING`, so arrow keys arrive as
/// Windows-native console events (which cmd.exe's line editor can't
/// parse as VT sequences) and PTY-generated ANSI on the way back isn't
/// processed. We set both flags explicitly and save the prior modes
/// for restoration.
struct TermGuard {
    #[cfg(windows)]
    prev_stdin_mode: Option<u32>,
    #[cfg(windows)]
    prev_stdout_mode: Option<u32>,
}

impl TermGuard {
    fn new() -> Result<Self> {
        crossterm::terminal::enable_raw_mode().context("enable_raw_mode")?;
        #[cfg(windows)]
        {
            let (prev_stdin_mode, prev_stdout_mode) = configure_windows_console();
            return Ok(Self {
                prev_stdin_mode,
                prev_stdout_mode,
            });
        }
        #[cfg(not(windows))]
        {
            Ok(Self {})
        }
    }
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            restore_windows_console(self.prev_stdin_mode, self.prev_stdout_mode);
        }
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

#[cfg(windows)]
fn configure_windows_console() -> (Option<u32>, Option<u32>) {
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, DISABLE_NEWLINE_AUTO_RETURN,
        ENABLE_VIRTUAL_TERMINAL_INPUT, ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_INPUT_HANDLE,
        STD_OUTPUT_HANDLE,
    };
    let (mut prev_in, mut prev_out) = (None, None);
    unsafe {
        let h_in = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode: u32 = 0;
        if !h_in.is_null() && GetConsoleMode(h_in, &mut mode) != 0 {
            prev_in = Some(mode);
            let _ = SetConsoleMode(h_in, mode | ENABLE_VIRTUAL_TERMINAL_INPUT);
        }
        let h_out = GetStdHandle(STD_OUTPUT_HANDLE);
        let mut mode: u32 = 0;
        if !h_out.is_null() && GetConsoleMode(h_out, &mut mode) != 0 {
            prev_out = Some(mode);
            let _ = SetConsoleMode(
                h_out,
                mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING | DISABLE_NEWLINE_AUTO_RETURN,
            );
        }
    }
    (prev_in, prev_out)
}

#[cfg(windows)]
fn restore_windows_console(prev_stdin: Option<u32>, prev_stdout: Option<u32>) {
    use windows_sys::Win32::System::Console::{GetStdHandle, SetConsoleMode, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE};
    unsafe {
        if let Some(m) = prev_stdin {
            let h = GetStdHandle(STD_INPUT_HANDLE);
            if !h.is_null() {
                let _ = SetConsoleMode(h, m);
            }
        }
        if let Some(m) = prev_stdout {
            let h = GetStdHandle(STD_OUTPUT_HANDLE);
            if !h.is_null() {
                let _ = SetConsoleMode(h, m);
            }
        }
    }
}

/// Drive an interactive shell session. After the CBOR request/ShellReady
/// handshake, the control flow carries the framed stdio protocol in
/// both directions: STDIN / RESIZE / STDIN_EOF client→server, STDOUT /
/// EXIT server→client.
async fn run_shell_interactive(
    addr: SocketAddrV4,
    program: Option<String>,
    cmd_args: Vec<String>,
) -> Result<ExitCode> {
    let mut stream = connect_control(addr).await?;
    let req = ClientReq::RequestShell {
        mode: ShellMode::Interactive,
        program,
        args: cmd_args,
    };
    write_frame(&mut stream, &req).await?;
    let resp: ServerResp = read_frame(&mut stream)
        .await
        .map_err(|e| anyhow!("reading ShellReady: {e}"))?;
    match resp {
        ServerResp::ShellReady => {}
        ServerResp::Error { kind, msg } => {
            eprintln!("interactive shell: {kind:?}: {msg}");
            return Ok(ExitCode::from(match kind {
                ErrorKind::NotYetSupported => 3,
                _ => 2,
            }));
        }
        other => bail!("unexpected response: {other:?}"),
    }

    // Enable raw mode before we start reading stdin or writing PTY
    // output. `_guard` restores on drop, including the panic path.
    let _guard = TermGuard::new()?;
    // Best-effort: a panic hook that disables raw mode before the
    // default handler runs, so stack traces print cleanly.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = crossterm::terminal::disable_raw_mode();
        default_hook(info);
    }));

    let (mut reader, mut writer) = stream.into_split();

    // Send the initial terminal size so the server sizes the PTY
    // correctly on the first prompt render.
    let (cols0, rows0) = crossterm::terminal::size().unwrap_or((80, 24));
    sp::write_resize(&mut writer, cols0, rows0).await?;

    // Single writer channel: stdin bytes and resize events both funnel
    // through here so writes to the socket are serialized.
    enum Out {
        Stdin(Vec<u8>),
        Resize(u16, u16),
        StdinEof,
    }
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Out>();

    // stdin pump — reads raw bytes from the local terminal and forwards
    // as STDIN frames. Ends on EOF or error.
    let stdin_tx = out_tx.clone();
    let stdin_task = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = vec![0u8; 4096];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) => {
                    let _ = stdin_tx.send(Out::StdinEof);
                    break;
                }
                Ok(n) => {
                    if stdin_tx.send(Out::Stdin(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Resize poller — crossterm's EventStream would be the idiomatic
    // cross-platform path but requires an extra feature. Polling
    // `terminal::size()` at 200 ms is simpler and works on all targets;
    // SIGWINCH-driven precision doesn't matter for terminal resize UX.
    let resize_tx = out_tx.clone();
    let resize_task = tokio::spawn(async move {
        let mut last = (cols0, rows0);
        let mut interval = tokio::time::interval(Duration::from_millis(200));
        loop {
            interval.tick().await;
            match crossterm::terminal::size() {
                Ok(size) if size != last => {
                    last = size;
                    if resize_tx.send(Out::Resize(size.0, size.1)).is_err() {
                        break;
                    }
                }
                _ => {}
            }
        }
    });

    // Writer task: serializes frames to the TCP half.
    let writer_task = tokio::spawn(async move {
        while let Some(out) = out_rx.recv().await {
            let res = match out {
                Out::Stdin(data) => sp::write_stdin(&mut writer, &data).await,
                Out::Resize(cols, rows) => sp::write_resize(&mut writer, cols, rows).await,
                Out::StdinEof => {
                    let r = sp::write_stdin_eof(&mut writer).await;
                    if r.is_err() {
                        break;
                    }
                    // After EOF we keep the channel open for resize
                    // events — the shell might still be running.
                    continue;
                }
            };
            if res.is_err() {
                break;
            }
        }
    });

    // Main read loop — decode STDOUT / EXIT frames, write to local
    // stdout.
    let mut stdout = tokio::io::stdout();
    let mut scratch = Vec::new();
    let mut exit_code: i32 = 0;
    loop {
        match sp::read_frame(&mut reader, &mut scratch).await {
            Ok(sp::Frame::Stdout(data)) => {
                if stdout.write_all(data).await.is_err() {
                    break;
                }
                let _ = stdout.flush().await;
            }
            Ok(sp::Frame::Exit(code)) => {
                exit_code = code;
                break;
            }
            Ok(_) => { /* ignore unknown or server-only frames */ }
            Err(_) => break,
        }
    }

    stdin_task.abort();
    resize_task.abort();
    writer_task.abort();
    // `_guard` drops here → raw mode restored.
    // Clamp negative / large codes to 1..=255 so ExitCode is sane.
    Ok(ExitCode::from(match exit_code {
        0 => 0u8,
        c if (1..=255).contains(&c) => c as u8,
        _ => 1,
    }))
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
