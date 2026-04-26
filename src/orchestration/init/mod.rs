//! `burrowctl init <name>` — bootstrap wizard.
//!
//! Two modes: a short ratatui form for interactive use (run with no
//! flags from a TTY) and a flag-driven batch mode for scripting (any
//! flag set, or no TTY available). Both produce the same fully-valid
//! `deployments/<name>/spec.toml` by way of `state::FormState` →
//! `emit::format_spec` → `Spec::parse` validation gate.
//!
//! Phase 1 surfaces only the essentials in the TUI (endpoint, gateway
//! target, deploy toggle, WSS toggle, routes). Phase 3 grows an
//! "Advanced" toggle for the rest of the spec axes.

mod emit;
mod state;
mod tui;

use std::fs;
use std::io::IsTerminal;

use anyhow::{anyhow, bail, Context, Result};

use crate::spec::{Layout, Spec};

pub use state::{FormState, InitArgs};

/// Drive `init` for the deployment named `name`. See module docs for
/// the dispatch rules.
pub fn run(name: &str, args: InitArgs) -> Result<()> {
    let layout = Layout::for_name(name)?;
    if layout.spec_path().exists() && !args.force {
        bail!(
            "{} already exists — use `burrowctl init {name} --force` to overwrite \
             (or `burrowctl edit {name}` once Phase 2 lands)",
            layout.spec_path().display()
        );
    }

    let final_state = if args.has_any_flag() {
        // Batch mode: flags set, no TUI even if a TTY is present.
        // Caller asked for non-interactive; honour it.
        let st = FormState::from_args(&args)
            .context("constructing form state from CLI flags")?;
        st.require_complete()
            .map_err(|missing| anyhow!("required: --{missing}"))?;
        st
    } else if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        // Interactive: open the TUI with defaults pre-populated.
        let st = FormState::with_defaults();
        match tui::run_form(st)? {
            Some(st) => st,
            None => {
                eprintln!("init cancelled");
                return Ok(());
            }
        }
    } else {
        bail!(
            "no flags + no TTY — burrowctl init needs either --endpoint (and friends) \
             or an interactive terminal. See `burrowctl init --help`."
        );
    };

    write_spec(&layout, &final_state)?;
    print_next_steps(name, &layout);
    Ok(())
}

fn write_spec(layout: &Layout, state: &FormState) -> Result<()> {
    fs::create_dir_all(&layout.root)
        .with_context(|| format!("creating {}", layout.root.display()))?;
    let body = emit::format_spec(state);
    // Final gate: parse what we're about to write through the same
    // validator any other entry point uses. A bug in the wizard
    // (rather than a user mistake) would have caught it here.
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
