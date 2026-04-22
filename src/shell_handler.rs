//! Server-side handlers for `ClientReq::RequestShell`.
//!
//! Phase 16 implements the two non-interactive modes:
//! - `Oneshot` — run to completion, capture output, one response frame.
//! - `FireAndForget` — detach the child, return its pid immediately.
//!
//! `Interactive` is deferred to Phase 17 since it requires a PTY crate
//! + matching client-side terminal handling. Phase 16 responds
//! `Error{NotYetSupported}` for that mode.
//!
//! The default program is chosen at call time so the same config parses
//! cleanly on both Windows and Unix:
//! - Windows: `%ComSpec%` → `cmd.exe`.
//! - Unix: `$SHELL` → `/bin/sh`.
//!
//! `args` is passed verbatim to the child — no shell interpolation on
//! the server side.

use std::process::Stdio;

use tokio::process::Command;

use crate::wire::{ErrorKind, ServerResp, ShellMode};

/// Execute a RequestShell. Never panics; pathological failures produce
/// `ServerResp::Error`.
pub async fn handle_shell_request(
    mode: ShellMode,
    program: Option<String>,
    args: Vec<String>,
) -> ServerResp {
    match mode {
        ShellMode::Interactive => ServerResp::Error {
            kind: ErrorKind::NotYetSupported,
            msg: "Interactive shell lands in Phase 17 (requires client-side PTY)".into(),
        },
        ShellMode::Oneshot => run_oneshot(program, args).await,
        ShellMode::FireAndForget => run_detached(program, args),
    }
}

fn default_program() -> String {
    if cfg!(windows) {
        std::env::var("ComSpec").unwrap_or_else(|_| "cmd.exe".to_string())
    } else {
        std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string())
    }
}

async fn run_oneshot(program: Option<String>, args: Vec<String>) -> ServerResp {
    let program = program.unwrap_or_else(default_program);
    let output = match Command::new(&program)
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
    {
        Ok(o) => o,
        Err(e) => {
            return ServerResp::Error {
                kind: ErrorKind::Internal,
                msg: format!("spawn `{program}`: {e}"),
            };
        }
    };
    ServerResp::ShellResult {
        exit_code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    }
}

fn run_detached(program: Option<String>, args: Vec<String>) -> ServerResp {
    let program = program.unwrap_or_else(default_program);
    let mut cmd = Command::new(&program);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // `kill_on_drop(false)` is the default, but stating it makes the
    // fire-and-forget semantics explicit: when `child` drops at the end
    // of this function, the child process must keep running.
    cmd.kill_on_drop(false);
    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return ServerResp::Error {
                kind: ErrorKind::Internal,
                msg: format!("spawn `{program}`: {e}"),
            };
        }
    };
    let pid = child.id().unwrap_or(0);
    // Explicitly drop the handle so wait-on-drop behaviors don't fire.
    drop(child);
    ServerResp::ShellSpawned { pid }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn interactive_returns_not_yet_supported() {
        let resp = handle_shell_request(ShellMode::Interactive, None, vec![]).await;
        match resp {
            ServerResp::Error {
                kind: ErrorKind::NotYetSupported,
                ..
            } => (),
            other => panic!("expected NotYetSupported, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oneshot_captures_stdout() {
        // Use a command that's on every platform:
        //   Windows:  cmd.exe /C echo hello
        //   Unix:     /bin/sh -c "echo hello"
        let (program, args) = if cfg!(windows) {
            (
                Some("cmd.exe".to_string()),
                vec!["/C".to_string(), "echo hello".to_string()],
            )
        } else {
            (
                Some("/bin/sh".to_string()),
                vec!["-c".to_string(), "echo hello".to_string()],
            )
        };
        let resp = handle_shell_request(ShellMode::Oneshot, program, args).await;
        match resp {
            ServerResp::ShellResult {
                exit_code,
                stdout,
                stderr: _,
            } => {
                assert_eq!(exit_code, Some(0));
                let stdout_str = String::from_utf8_lossy(&stdout);
                assert!(
                    stdout_str.contains("hello"),
                    "expected 'hello' in stdout, got {stdout_str:?}"
                );
            }
            other => panic!("expected ShellResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oneshot_nonzero_exit() {
        // Always returns a non-zero exit.
        let (program, args) = if cfg!(windows) {
            (
                Some("cmd.exe".to_string()),
                vec!["/C".to_string(), "exit 7".to_string()],
            )
        } else {
            (
                Some("/bin/sh".to_string()),
                vec!["-c".to_string(), "exit 7".to_string()],
            )
        };
        let resp = handle_shell_request(ShellMode::Oneshot, program, args).await;
        match resp {
            ServerResp::ShellResult { exit_code, .. } => {
                assert_eq!(exit_code, Some(7));
            }
            other => panic!("expected ShellResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oneshot_missing_program_errors() {
        let resp = handle_shell_request(
            ShellMode::Oneshot,
            Some("this-binary-definitely-does-not-exist-zzz".to_string()),
            vec![],
        )
        .await;
        match resp {
            ServerResp::Error {
                kind: ErrorKind::Internal,
                ..
            } => (),
            other => panic!("expected Internal error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fire_and_forget_returns_pid() {
        // A trivially short-lived program. We don't wait for it.
        let (program, args) = if cfg!(windows) {
            (
                Some("cmd.exe".to_string()),
                vec!["/C".to_string(), "exit 0".to_string()],
            )
        } else {
            (
                Some("/bin/sh".to_string()),
                vec!["-c".to_string(), "exit 0".to_string()],
            )
        };
        let resp = handle_shell_request(ShellMode::FireAndForget, program, args).await;
        match resp {
            ServerResp::ShellSpawned { pid } => {
                assert!(pid > 0, "expected a nonzero pid, got {pid}");
            }
            other => panic!("expected ShellSpawned, got {other:?}"),
        }
    }
}
