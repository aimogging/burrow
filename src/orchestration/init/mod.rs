//! `burrowctl init <name>` and `burrowctl edit <name>`.
//!
//! Four routes:
//!   * Default + TTY → ratatui form, defaults pre-populated.
//!   * Field flag(s) set → batch (no TUI), missing required = exit 2.
//!   * `--prefill` → ratatui form, flag values pre-populated.
//!   * `--editor`  → opens the spec template in $VISUAL / $EDITOR;
//!                    re-validates on save.
//!
//! `burrowctl edit <name>` is the same TUI but seeded from the
//! existing spec via `FormState::from_spec`.

mod editor;
mod emit;
mod state;
mod tui;

use std::fs;
use std::io::IsTerminal;

use anyhow::{anyhow, bail, Context, Result};

use crate::spec::{Layout, Spec};

pub use state::{FormState, InitArgs};

/// Drive `init` for the deployment named `name`.
pub fn run(name: &str, args: InitArgs) -> Result<()> {
    let layout = Layout::for_name(name)?;
    if layout.spec_path().exists() && !args.force {
        bail!(
            "{} already exists — use `burrowctl init {name} --force` to overwrite \
             (or `burrowctl edit {name}` to tweak interactively)",
            layout.spec_path().display()
        );
    }

    let initial = FormState::from_args(&args)
        .context("constructing form state from CLI flags / defaults")?;

    if args.editor {
        editor::run(&layout, initial)?;
    } else {
        let final_state = if args.prefill || (!args.has_any_flag() && have_tty()) {
            match tui::run_form(initial)? {
                Some(s) => s,
                None => {
                    eprintln!("init cancelled");
                    return Ok(());
                }
            }
        } else if args.has_any_flag() {
            initial
                .require_complete()
                .map_err(|missing| anyhow!("required: --{missing}"))?;
            initial
        } else {
            bail!(
                "no flags + no TTY — burrowctl init needs either --endpoint (and friends), \
                 --editor, or an interactive terminal. See `burrowctl init --help`."
            );
        };
        write_spec(&layout, &final_state)?;
    }

    print_next_steps(name, &layout);
    Ok(())
}

/// Drive `edit <name>`. Same TUI as `init`, but seeded from the
/// existing spec.
pub fn edit(name: &str) -> Result<()> {
    let layout = Layout::for_name(name)?;
    if !layout.spec_path().exists() {
        bail!(
            "no {} — run `burrowctl init {name}` first",
            layout.spec_path().display()
        );
    }
    if !have_tty() {
        bail!(
            "burrowctl edit needs an interactive terminal. \
             Edit `{}` directly with $EDITOR if you're in a script.",
            layout.spec_path().display()
        );
    }
    let spec = Spec::parse(&layout.spec_path())?;
    let initial = FormState::from_spec(&spec);
    let final_state = match tui::run_form(initial)? {
        Some(s) => s,
        None => {
            eprintln!("edit cancelled");
            return Ok(());
        }
    };
    write_spec(&layout, &final_state)?;
    println!(
        "✓ updated {} (re-run `burrowctl up {name}` to apply)",
        layout.spec_path().display()
    );
    Ok(())
}

fn have_tty() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

fn write_spec(layout: &Layout, state: &FormState) -> Result<()> {
    fs::create_dir_all(&layout.root)
        .with_context(|| format!("creating {}", layout.root.display()))?;
    let body = emit::format_spec(state);
    Spec::parse_str(&body).context("internal: emitter produced an invalid spec")?;
    let tmp = layout.spec_path().with_extension("toml.tmp");
    fs::write(&tmp, &body).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, layout.spec_path())
        .with_context(|| format!("renaming {} -> {}", tmp.display(), layout.spec_path().display()))?;
    Ok(())
}

fn print_next_steps(name: &str, layout: &Layout) {
    println!(
        "✓ wrote {}\n\n\
         Next:\n    \
         burrowctl up {name}          # gen + build + ship-server + ship-client\n    \
         burrowctl shell {name}       # drop into the local client netns",
        layout.spec_path().display()
    );
}

/// Used by `editor::run` so it can write the validated spec without
/// re-going-through FormState (the user may have set advanced fields
/// directly in the TOML that don't have FormState slots yet).
pub(crate) fn write_raw(layout: &Layout, body: &str) -> Result<()> {
    fs::create_dir_all(&layout.root)
        .with_context(|| format!("creating {}", layout.root.display()))?;
    let tmp = layout.spec_path().with_extension("toml.tmp");
    fs::write(&tmp, body).with_context(|| format!("writing {}", tmp.display()))?;
    fs::rename(&tmp, layout.spec_path())
        .with_context(|| format!("renaming {} -> {}", tmp.display(), layout.spec_path().display()))?;
    Ok(())
}
