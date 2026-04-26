//! `--editor` mode for `burrowctl init`. Skips the TUI entirely;
//! emits the spec template (seeded from `FormState`), opens it in
//! `$VISUAL` / `$EDITOR` (falls back to `vi` on Unix, `notepad` on
//! Windows), re-validates on save. On validation error, the file is
//! re-opened with the error annotated as a comment block at the top
//! so the user sees what to fix.

use std::env;
use std::fs;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::spec::{Layout, Spec};

use super::{emit, write_raw, FormState};

/// Open the editor loop. Returns when the user saves a spec that
/// passes `Spec::parse_str`. Writes directly to `layout.spec_path()`
/// via the atomic helper.
pub fn run(layout: &Layout, initial: FormState) -> Result<()> {
    let mut body = emit::format_spec(&initial);
    let tmp = layout.spec_path().with_extension("toml.editing");

    loop {
        fs::create_dir_all(&layout.root)
            .with_context(|| format!("creating {}", layout.root.display()))?;
        fs::write(&tmp, &body).with_context(|| format!("writing {}", tmp.display()))?;
        let before = body.clone();
        invoke_editor(&tmp)?;
        body = fs::read_to_string(&tmp)
            .with_context(|| format!("reading {}", tmp.display()))?;
        match Spec::parse_str(&body) {
            Ok(_) => {
                let _ = fs::remove_file(&tmp);
                return write_raw(layout, &body);
            }
            Err(e) => {
                if body == before {
                    // Editor closed without changes and we're still
                    // invalid → user gave up. Don't loop.
                    let _ = fs::remove_file(&tmp);
                    bail!("editor closed without changes; spec still invalid: {e:#}");
                }
                let err_block = format!(
                    "# Validation error: {e:#}\n\
                     # Edit + save again to retry, or close without saving to abort.\n\n"
                );
                let stripped = strip_error_block(&body);
                body = format!("{err_block}{stripped}");
            }
        }
    }
}

fn invoke_editor(path: &std::path::Path) -> Result<()> {
    let editor = env::var("VISUAL")
        .or_else(|_| env::var("EDITOR"))
        .unwrap_or_else(|_| {
            if cfg!(target_os = "windows") {
                "notepad".into()
            } else {
                "vi".into()
            }
        });
    // Editors may be a command + args (e.g. EDITOR='code -w'). Split
    // on whitespace; takes the first token as the program, rest as
    // initial args.
    let mut parts = editor.split_whitespace();
    let program = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("$VISUAL / $EDITOR is empty"))?;
    let mut cmd = Command::new(program);
    for a in parts {
        cmd.arg(a);
    }
    cmd.arg(path);
    let status = cmd
        .status()
        .with_context(|| format!("spawning {program} {}", path.display()))?;
    if !status.success() {
        bail!("editor {program} exited {:?}", status.code());
    }
    Ok(())
}

fn strip_error_block(body: &str) -> String {
    // Strip a leading run of `#`-comment lines whose first one
    // contains "Validation error:" — we drop the prior annotation
    // before re-prepending a fresh one.
    let mut lines = body.lines().peekable();
    if !matches!(lines.peek(), Some(l) if l.starts_with("# Validation error:")) {
        return body.to_string();
    }
    while let Some(l) = lines.peek() {
        if l.starts_with('#') || l.is_empty() {
            lines.next();
        } else {
            break;
        }
    }
    lines.collect::<Vec<_>>().join("\n")
}
