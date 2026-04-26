//! ratatui form for `burrowctl init`. Single screen, ~15 lines.
//!
//! Field set (Phase 1):
//!   * WireGuard endpoint                  text
//!   * Gateway target                      Select (4 presets + "other")
//!   * [x] Deploy via SSH                  toggle
//!         SSH host                        text (only when toggled on)
//!   * [ ] WSS transport                   toggle
//!         Relay host:port                 text (only when toggled on)
//!   * Routes                              text (comma-separated)
//!
//! Navigation: Tab / Shift-Tab move; Space toggles checkboxes;
//! Up/Down navigate the Select menu when focused; arrows + backspace
//! edit text fields; Ctrl-S saves; Esc cancels.
//!
//! Validation surfaces inline below each field; save is gated on
//! every required field being valid.

use std::io;
use std::time::Duration;

use anyhow::{Context, Result};
use crossterm::event::{
    self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, EnableMouseCapture,
    Event, KeyCode, KeyEventKind, KeyModifiers,
};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use ratatui::{Frame, Terminal};

// -----------------------------------------------------------------------------
// Palette — vaporwave on true-black: vibrant saturated text + faint border
// lines. Roles from the old phosphor palette map 1:1; only the hex values
// change. ratatui degrades 24-bit colors gracefully on terminals that don't
// support them (256/16-color fallback), so explicit RGB is safe.
//
//   VAPOR_CYAN     focused values, title — the "wow" pop
//   VAPOR_PINK     unfocused values
//   VAPOR_PURPLE   unfocused labels (the dimmer of the two label states)
//   VAPOR_MAGENTA  focused labels, cursor — focus accent
//   VAPOR_RED      errors
//   VAPOR_LINE     borders + disabled text — faint, recedes
//   DEEP_BLACK     background, painted explicitly so terminals with grey
//                  defaults still render the form on true black.
// -----------------------------------------------------------------------------
const VAPOR_CYAN:    Color = Color::Rgb(0x00, 0xff, 0xff);
const VAPOR_PINK:    Color = Color::Rgb(0xff, 0x71, 0xce);
const VAPOR_PURPLE:  Color = Color::Rgb(0xb9, 0x67, 0xff);
const VAPOR_MAGENTA: Color = Color::Rgb(0xff, 0x00, 0xff);
const VAPOR_RED:     Color = Color::Rgb(0xff, 0x5e, 0x5e);
const VAPOR_LINE:    Color = Color::Rgb(0x3a, 0x2a, 0x5a);
const DEEP_BLACK:    Color = Color::Rgb(0x00, 0x00, 0x00);

use super::state::{detect_host_triple, FormState};

/// Placeholder hint text shown in dim grey when a text field is empty.
/// Helps the user know what shape of input to enter without having to
/// hit `?` for the full help modal.
fn placeholder(f: Field) -> &'static str {
    match f {
        Field::Endpoint   => "vpn.example.com:51820",
        Field::DeployHost => "user@vpn.example.com  (or ssh-config alias)",
        Field::SshKey     => "/path/to/id_ed25519  (optional — agent / default key by default)",
        Field::RelayHost  => "vpn.example.com:443",
        Field::CertPath   => "/etc/letsencrypt/live/host/fullchain.pem",
        Field::KeyPath    => "/etc/letsencrypt/live/host/privkey.pem",
        Field::Routes     => "192.168.1.0/24, 10.50.0.0/24",
        Field::Dns        => "10.0.0.2  (or 1.1.1.1, 9.9.9.9 — empty = system resolver)",
        // Advanced fields use their default-shown-as-greyed UI; no
        // placeholder needed — the default value IS the hint.
        _ => "",
    }
}

/// One-paragraph description + example block for the `?` modal.
/// First string is the prose; second is a small examples block
/// (already-indented for monospace alignment).
fn help_text(f: Field) -> (&'static str, &'static str) {
    match f {
        Field::Endpoint => (
            "Public host:port of the WireGuard server burrow connects to.",
            "  vpn.example.com:51820\n  159.65.218.242:51820",
        ),
        Field::Gateway => (
            "Target triple for the burrow gateway binary. Pick the OS your gateway machine runs. F2 pops a list modal with all presets and toolchain-installed markers (`[+]`).",
            "  Linux x86_64 (default on Linux hosts)\n  Windows x86_64 MSVC\n  Windows x86_64 mingw\n  macOS Apple Silicon\n  Other... (type your own triple)",
        ),
        Field::DeployToggle => (
            "Toggle on to have burrowctl ship + start the WG server (and relay, if WSS) over SSH automatically. Off = you manage the server side manually.",
            "  on / off",
        ),
        Field::DeployHost => (
            "ssh-resolvable: alias from ~/.ssh/config, user@host, or bare host:port. Used by `burrowctl ship-server` and `burrowctl up`. F2 pops a picker of aliases parsed from your ssh config (recursive, follows Include). Password authentication isn't supported (the relay-start step pipes a script over stdin, which collides with sshd's TTY-based password prompt) — use ssh-agent or set SSH_KEY below.",
            "  vpn.example.com\n  root@vpn.example.com\n  do          (alias from ~/.ssh/config)",
        ),
        Field::SshKey => (
            "Optional path to an SSH private key (`ssh -i`). Most setups don't need this — the user's agent / ~/.ssh/config / default key already works. Set it when you have a non-default key for this deployment.",
            "  /home/user/.ssh/id_ed25519_burrow\n  ./deploy-key",
        ),
        Field::Transport => (
            "How burrow's WireGuard datagrams reach the WG server. UDP is native + lowest overhead. WSS tunnels the same datagrams through HTTPS WebSockets — use it when egress UDP is blocked (corporate, hotel, captive-portal).",
            "  UDP\n  HTTPS WebSockets",
        ),
        Field::RelayHost => (
            "host:port burrow dials for the WSS connection. Often the same host as WG_ENDPOINT, on port 443.",
            "  vpn.example.com:443\n  159.65.218.242:443",
        ),
        Field::TlsChoice => (
            "How the relay's TLS cert is obtained.\n  self-signed: gen produces a fresh ECDSA P-256 cert and bakes it in;\n               burrow trusts it via TlsSkipVerify=true.\n  bring your own: point at your existing cert + key (e.g. Let's Encrypt\n               fullchain). Burrow does real cert verification.",
            "",
        ),
        Field::CertPath => (
            "Filesystem path to the cert chain PEM. Read at gen time and copied into the relay bundle.",
            "  /etc/letsencrypt/live/host/fullchain.pem\n  ./mycert.pem",
        ),
        Field::KeyPath => (
            "Filesystem path to the private key PEM (matches CERT_PEM_PATH).",
            "  /etc/letsencrypt/live/host/privkey.pem\n  ./mykey.pem",
        ),
        Field::Routes => (
            "CIDRs the burrow gateway exposes to the WG mesh. Empty = peer-to-peer only (clients can still reach burrow's DNS / control / reverse-tunnel surfaces).",
            "  192.168.1.0/24\n  192.168.1.0/24, 10.50.0.0/24\n  1.1.1.1/32",
        ),
        Field::AdvancedToggle => (
            "Toggle on to reveal advanced fields: subnet, client count, namespaces, per-binary cross-targets, etc. Defaults are good for the common case.",
            "",
        ),
        Field::Subnet => (
            "WG mesh subnet. Server gets .1, gateway gets .2, clients get .10+.",
            "  10.0.0.0/24  (default)\n  10.50.0.0/24",
        ),
        Field::Clients => (
            "How many client peer configs to generate (client1.conf, client2.conf, ...).",
            "  1  (default)\n  3",
        ),
        Field::ListenPort => (
            "WG server's UDP listen port.",
            "  51820  (default)",
        ),
        Field::Dns => (
            "Comma-separated DNS resolvers to write into client.conf as `DNS = ...`. Empty = clients keep their system resolver.",
            "  10.0.0.2  (point at burrow's built-in resolver)\n  1.1.1.1, 9.9.9.9",
        ),
        Field::ServerNs => (
            "Linux network namespace name on the deploy server. Change if you have multiple deployments on the same box.",
            "  burrow  (default)\n  burrow-prod",
        ),
        Field::ClientNs => (
            "Local netns name on the client (this box). Same defaulting.",
            "  burrow  (default)",
        ),
        Field::RelayTarget => (
            "rustc target triple for cross-building burrow-relay. Defaults to Linux x86_64 because the relay almost always sits next to kernel WG on a Linux box.",
            "  x86_64-unknown-linux-gnu  (default)\n  aarch64-unknown-linux-gnu",
        ),
        Field::ClientTarget => (
            "rustc target triple for cross-building burrow-client. Same Linux default for the same reason.",
            "  x86_64-unknown-linux-gnu  (default)",
        ),
    }
}

const TARGET_PRESETS: &[(&str, &str)] = &[
    ("Linux x86_64",         "x86_64-unknown-linux-gnu"),
    ("Windows x86_64 MSVC",  "x86_64-pc-windows-msvc"),
    ("Windows x86_64 mingw", "x86_64-pc-windows-gnu"),
    ("macOS Apple Silicon",  "aarch64-apple-darwin"),
    ("macOS Intel",          "x86_64-apple-darwin"),
];

/// Run the form. Returns `Some(state)` if the user pressed Ctrl-S,
/// `None` if Esc-cancelled. Restores the terminal on every exit
/// path including panics-from-render (drop guard).
pub fn run_form(initial: FormState) -> Result<Option<FormState>> {
    let mut term = enter_tui().context("entering TUI")?;
    let _guard = TuiGuard;
    let outcome = drive(&mut term, initial);
    // _guard's Drop restores the terminal even if drive() returned Err.
    outcome
}

fn drive(
    term: &mut Terminal<CrosstermBackend<io::Stdout>>,
    initial: FormState,
) -> Result<Option<FormState>> {
    let mut model = Model::new(initial);
    loop {
        term.draw(|f| render(f, &model)).context("draw")?;
        if !event::poll(Duration::from_millis(250)).context("poll")? {
            continue;
        }
        let evt = event::read().context("read")?;
        match handle(evt, &mut model) {
            Outcome::Save => return Ok(Some(model.state)),
            Outcome::Cancel => return Ok(None),
            Outcome::Continue => {}
        }
    }
}

fn enter_tui() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode().context("enable raw mode")?;
    let mut stdout = io::stdout();
    crossterm::execute!(
        stdout,
        EnterAlternateScreen,
        EnableMouseCapture,
        EnableBracketedPaste,
    )
    .context("enter alt screen")?;
    Terminal::new(CrosstermBackend::new(stdout)).context("init terminal")
}

/// RAII restorer — runs on normal exit, error, or panic.
struct TuiGuard;
impl Drop for TuiGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(
            io::stdout(),
            LeaveAlternateScreen,
            DisableMouseCapture,
            DisableBracketedPaste,
        );
    }
}

// ----------------------------------------------------------------------------
// Model
// ----------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Field {
    Endpoint,
    Gateway,
    DeployToggle,
    DeployHost,
    SshKey,
    Transport,
    RelayHost,
    TlsChoice,
    CertPath,
    KeyPath,
    Routes,
    Dns,
    AdvancedToggle,
    Subnet,
    Clients,
    ListenPort,
    ServerNs,
    ClientNs,
    RelayTarget,
    ClientTarget,
}

const ALL_FIELDS: &[Field] = &[
    Field::Endpoint,
    Field::Gateway,
    Field::DeployToggle,
    Field::DeployHost,
    Field::SshKey,
    Field::Transport,
    Field::RelayHost,
    Field::TlsChoice,
    Field::CertPath,
    Field::KeyPath,
    Field::Routes,
    Field::Dns,
    Field::AdvancedToggle,
    Field::Subnet,
    Field::Clients,
    Field::ListenPort,
    Field::ServerNs,
    Field::ClientNs,
    Field::RelayTarget,
    Field::ClientTarget,
];

const ADVANCED_FIELDS: &[Field] = &[
    Field::Subnet,
    Field::Clients,
    Field::ListenPort,
    Field::ServerNs,
    Field::ClientNs,
    Field::RelayTarget,
    Field::ClientTarget,
];

struct Model {
    state: FormState,
    focus: Field,
    /// Index into TARGET_PRESETS; >= len means "Other (custom)".
    gateway_idx: usize,
    error: Option<String>,
    /// `Some(buf)` when the user is typing a `:w`/`:q`/`:wq` command.
    /// `None` in normal form mode. Mutually exclusive with the
    /// per-field key handling.
    cmd_buffer: Option<String>,
    /// Whether the Advanced section is expanded. Auto-expands when
    /// the seeded FormState already has any advanced field set.
    advanced_expanded: bool,
    /// Whether the `?` help modal is open for the focused field.
    help_open: bool,
    /// Whether the Gateway list modal (popped on Enter) is open.
    gateway_modal_open: bool,
    /// Selected row inside the gateway modal; len(TARGET_PRESETS) =
    /// "Other..." (the custom-triple text input row).
    gateway_modal_idx: usize,
    /// Cached `rustup target list --installed` output. None until
    /// the gateway modal is first opened (lazy fetch).
    installed_targets: Option<Vec<String>>,
    /// SSH alias picker modal state — same shape as gateway_modal_*.
    ssh_modal_open: bool,
    ssh_modal_idx: usize,
    /// Cached aliases from ~/.ssh/config (recursive, follows Include).
    /// None until the picker is first opened.
    ssh_aliases: Option<Vec<String>>,
    /// User has manually touched these fields — once true, never auto-
    /// infer their value (e.g. from WG_ENDPOINT) again. Without this,
    /// toggling DEPLOY_VIA_SSH off/on or TRANSPORT WSS→UDP→WSS could
    /// stomp on input the user typed earlier.
    deploy_host_touched: bool,
    relay_host_touched: bool,
}

impl Model {
    fn new(state: FormState) -> Self {
        let gateway_idx = TARGET_PRESETS
            .iter()
            .position(|(_, t)| *t == state.gateway_target)
            .unwrap_or(TARGET_PRESETS.len());
        let advanced_expanded = state.subnet.is_some()
            || state.clients.is_some()
            || state.listen_port.is_some()
            || state.dns.is_some()
            || state.server_namespace.is_some()
            || state.client_namespace.is_some()
            || state.relay_target.is_some()
            || state.client_target.is_some();
        // Treat any seeded value as user-provided so cycling the
        // toggles never overwrites it.
        let deploy_host_touched = !state.deploy_host.is_empty();
        let relay_host_touched = !state.relay_host.is_empty();
        Self {
            state,
            focus: Field::Endpoint,
            gateway_idx,
            error: None,
            cmd_buffer: None,
            advanced_expanded,
            help_open: false,
            gateway_modal_open: false,
            gateway_modal_idx: 0,
            installed_targets: None,
            ssh_modal_open: false,
            ssh_modal_idx: 0,
            ssh_aliases: None,
            deploy_host_touched,
            relay_host_touched,
        }
    }

    /// True iff the focused field is text-input (so a literal `:` is
    /// part of valid input — host:port, host, CIDR list — rather than
    /// the start of a vim-style command).
    /// Whether the focused field is a Select-style widget that
    /// responds to Tab/Shift-Tab as "cycle the value" rather than
    /// "move to next field".
    fn focus_is_select(&self) -> bool {
        matches!(
            self.focus,
            Field::Gateway | Field::Transport | Field::TlsChoice
        )
    }

    fn focus_is_text(&self) -> bool {
        matches!(
            self.focus,
            Field::Endpoint
                | Field::DeployHost
                | Field::SshKey
                | Field::RelayHost
                | Field::CertPath
                | Field::KeyPath
                | Field::Routes
                | Field::Dns
                | Field::Subnet
                | Field::Clients
                | Field::ListenPort
                | Field::ServerNs
                | Field::ClientNs
                | Field::RelayTarget
                | Field::ClientTarget
        ) || (self.focus == Field::Gateway && self.gateway_idx >= TARGET_PRESETS.len())
    }

    /// Fields skip themselves when their gating toggle is off.
    fn focusable(&self, f: Field) -> bool {
        match f {
            Field::DeployHost | Field::SshKey => self.state.deploy_enabled,
            Field::RelayHost | Field::TlsChoice => self.state.transport.is_wss(),
            Field::CertPath | Field::KeyPath => {
                self.state.transport.is_wss()
                    && self.state.tls_strategy == super::state::TlsChoice::Byo
            }
            Field::Subnet
            | Field::Clients
            | Field::ListenPort
            | Field::ServerNs
            | Field::ClientNs
            | Field::RelayTarget
            | Field::ClientTarget => self.advanced_expanded,
            _ => true,
        }
    }

    fn focus_next(&mut self) {
        let cur = ALL_FIELDS.iter().position(|f| *f == self.focus).unwrap_or(0);
        for offset in 1..=ALL_FIELDS.len() {
            let i = (cur + offset) % ALL_FIELDS.len();
            if self.focusable(ALL_FIELDS[i]) {
                self.focus = ALL_FIELDS[i];
                return;
            }
        }
    }

    fn focus_prev(&mut self) {
        let cur = ALL_FIELDS.iter().position(|f| *f == self.focus).unwrap_or(0);
        for offset in 1..=ALL_FIELDS.len() {
            let i = (cur + ALL_FIELDS.len() - offset) % ALL_FIELDS.len();
            if self.focusable(ALL_FIELDS[i]) {
                self.focus = ALL_FIELDS[i];
                return;
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Event handling
// ----------------------------------------------------------------------------

enum Outcome {
    Continue,
    Save,
    Cancel,
}

fn handle(evt: Event, m: &mut Model) -> Outcome {
    // Bracketed paste: terminals that support it deliver pasted text
    // as one Event::Paste. Append into whichever text-ish field has
    // focus. Falls back gracefully for terminals that just stream
    // KeyCode::Char per pasted character (the existing edit_text
    // handler already covers that).
    if let Event::Paste(s) = &evt {
        if !m.help_open && m.cmd_buffer.is_none() {
            paste_into_focused(m, s);
        }
        return Outcome::Continue;
    }
    let Event::Key(k) = evt else {
        return Outcome::Continue;
    };
    if k.kind != KeyEventKind::Press {
        return Outcome::Continue;
    }

    // Help modal eats all input until closed.
    if m.help_open {
        if matches!(
            k.code,
            KeyCode::Esc | KeyCode::Enter | KeyCode::F(1) | KeyCode::Char('?') | KeyCode::Char('q')
        ) {
            m.help_open = false;
        }
        return Outcome::Continue;
    }

    // Gateway list modal handles its own keys.
    if m.gateway_modal_open {
        return handle_gateway_modal(k, m);
    }

    // SSH alias picker modal handles its own keys.
    if m.ssh_modal_open {
        return handle_ssh_modal(k, m);
    }

    // If we're in command-bar mode (`:w` / `:q` / `:wq`), keystrokes
    // accumulate into the buffer until Enter executes or Esc cancels.
    if let Some(buf) = m.cmd_buffer.as_mut() {
        match k.code {
            KeyCode::Esc => {
                m.cmd_buffer = None;
            }
            KeyCode::Enter => {
                let cmd = buf.clone();
                m.cmd_buffer = None;
                return run_command(m, &cmd);
            }
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Char(c) => {
                buf.push(c);
            }
            _ => {}
        }
        return Outcome::Continue;
    }

    // Global keybinds first.
    match (k.code, k.modifiers) {
        (KeyCode::Esc, _) => return Outcome::Cancel,
        (KeyCode::Char('s'), KeyModifiers::CONTROL)
        | (KeyCode::Char('S'), KeyModifiers::CONTROL) => {
            return on_save(m);
        }
        // ↑/↓ always navigate fields. Tab/Shift-Tab cycle Select
        // values when focused on one; on non-Select fields Tab is a
        // no-op (use ↑/↓ to move).
        (KeyCode::Up, _) => {
            m.focus_prev();
            return Outcome::Continue;
        }
        (KeyCode::Down, _) => {
            m.focus_next();
            return Outcome::Continue;
        }
        (KeyCode::Tab, _) => {
            if m.focus_is_select() {
                cycle_select(m, true);
            }
            return Outcome::Continue;
        }
        (KeyCode::BackTab, _) => {
            if m.focus_is_select() {
                cycle_select(m, false);
            }
            return Outcome::Continue;
        }
        // F1 opens the per-field help modal — works from any field
        // including text inputs (no key collision). `?` is also bound
        // as an alias when focus isn't on a text field, since `?` is
        // a literal character there.
        (KeyCode::F(1), _) => {
            m.help_open = true;
            return Outcome::Continue;
        }
        (KeyCode::Char('?'), KeyModifiers::NONE) | (KeyCode::Char('?'), KeyModifiers::SHIFT)
            if !m.focus_is_text() =>
        {
            m.help_open = true;
            return Outcome::Continue;
        }
        // `:` enters command-bar mode — same gating as `?`.
        (KeyCode::Char(':'), KeyModifiers::NONE) | (KeyCode::Char(':'), KeyModifiers::SHIFT)
            if !m.focus_is_text() =>
        {
            m.cmd_buffer = Some(String::new());
            return Outcome::Continue;
        }
        _ => {}
    }

    match m.focus {
        Field::Endpoint => edit_text(&mut m.state.endpoint, k.code),
        Field::DeployHost => {
            if k.code == KeyCode::F(2) {
                open_ssh_modal(m);
            } else {
                edit_text(&mut m.state.deploy_host, k.code);
                m.deploy_host_touched = true;
            }
        }
        Field::SshKey => edit_text(&mut m.state.deploy_ssh_key, k.code),
        Field::RelayHost => {
            edit_text(&mut m.state.relay_host, k.code);
            m.relay_host_touched = true;
        }
        Field::Routes => edit_text(&mut m.state.routes, k.code),
        Field::DeployToggle => {
            if matches!(k.code, KeyCode::Char(' ') | KeyCode::Enter) {
                m.state.deploy_enabled = !m.state.deploy_enabled;
                if m.state.deploy_enabled
                    && !m.deploy_host_touched
                    && m.state.deploy_host.is_empty()
                {
                    m.state.deploy_host = endpoint_host(&m.state.endpoint);
                }
            }
        }
        Field::Transport => match k.code {
            KeyCode::Left => cycle_select(m, false),
            KeyCode::Right | KeyCode::Char(' ') | KeyCode::Enter => cycle_select(m, true),
            _ => {}
        },
        Field::AdvancedToggle => {
            if matches!(k.code, KeyCode::Char(' ') | KeyCode::Enter) {
                m.advanced_expanded = !m.advanced_expanded;
            }
        }
        Field::TlsChoice => match k.code {
            KeyCode::Left => cycle_select(m, false),
            KeyCode::Right | KeyCode::Char(' ') | KeyCode::Enter => cycle_select(m, true),
            _ => {}
        },
        Field::CertPath => edit_text(&mut m.state.cert_path, k.code),
        Field::KeyPath => edit_text(&mut m.state.key_path, k.code),
        Field::Subnet => edit_optional(&mut m.state.subnet, k.code),
        Field::Clients => edit_optional(&mut m.state.clients, k.code),
        Field::ListenPort => edit_optional(&mut m.state.listen_port, k.code),
        Field::Dns => edit_optional(&mut m.state.dns, k.code),
        Field::ServerNs => edit_optional(&mut m.state.server_namespace, k.code),
        Field::ClientNs => edit_optional(&mut m.state.client_namespace, k.code),
        Field::RelayTarget => edit_optional(&mut m.state.relay_target, k.code),
        Field::ClientTarget => edit_optional(&mut m.state.client_target, k.code),
        Field::Gateway => match k.code {
            KeyCode::F(2) => {
                // Pop the list modal so the user can see all options
                // (with toolchain-installed markers) at once.
                open_gateway_modal(m);
            }
            KeyCode::Left => cycle_select(m, false),
            KeyCode::Right | KeyCode::Char(' ') | KeyCode::Enter => cycle_select(m, true),
            // When on "Other", let the user type to edit the triple.
            _ if m.gateway_idx >= TARGET_PRESETS.len() => {
                edit_text(&mut m.state.gateway_target, k.code);
            }
            _ => {}
        },
    }
    Outcome::Continue
}

/// `Option<String>` text edit — typing creates the Some, fully
/// backspacing it goes back to None (so emit treats it as "use
/// default" again).
fn edit_optional(buf: &mut Option<String>, code: KeyCode) {
    match code {
        KeyCode::Char(c) => {
            buf.get_or_insert_with(String::new).push(c);
        }
        KeyCode::Backspace => {
            if let Some(s) = buf.as_mut() {
                s.pop();
                if s.is_empty() {
                    *buf = None;
                }
            }
        }
        _ => {}
    }
}

fn edit_text(buf: &mut String, code: KeyCode) {
    match code {
        KeyCode::Char(c) => buf.push(c),
        KeyCode::Backspace => {
            buf.pop();
        }
        _ => {}
    }
}

fn sync_gateway(m: &mut Model) {
    if m.gateway_idx < TARGET_PRESETS.len() {
        m.state.gateway_target = TARGET_PRESETS[m.gateway_idx].1.to_string();
    } else if m.state.gateway_target.is_empty() {
        m.state.gateway_target = detect_host_triple().to_string();
    }
}

fn endpoint_host(endpoint: &str) -> String {
    endpoint.split(':').next().unwrap_or("").to_string()
}

/// Append pasted text to whichever field has focus, if it's a text
/// input. No-op for Select / checkbox focus (paste into a checkbox
/// makes no sense; just drop it).
fn paste_into_focused(m: &mut Model, s: &str) {
    let focus = m.focus;
    let target: Option<&mut String> = match focus {
        Field::Endpoint        => Some(&mut m.state.endpoint),
        Field::DeployHost      => Some(&mut m.state.deploy_host),
        Field::SshKey          => Some(&mut m.state.deploy_ssh_key),
        Field::RelayHost       => Some(&mut m.state.relay_host),
        Field::CertPath        => Some(&mut m.state.cert_path),
        Field::KeyPath         => Some(&mut m.state.key_path),
        Field::Routes          => Some(&mut m.state.routes),
        // Gateway "Other" mode is also text input.
        Field::Gateway if m.gateway_idx >= TARGET_PRESETS.len() => Some(&mut m.state.gateway_target),
        _ => None,
    };
    if let Some(buf) = target {
        // Strip line breaks — pasted multi-line content rarely makes
        // sense in our single-line fields.
        let cleaned: String = s.chars().filter(|c| *c != '\n' && *c != '\r').collect();
        buf.push_str(&cleaned);
        if focus == Field::DeployHost {
            m.deploy_host_touched = true;
        } else if focus == Field::RelayHost {
            m.relay_host_touched = true;
        }
        return;
    }
    // Advanced fields are Option<String>; promote to Some on paste.
    let opt: Option<&mut Option<String>> = match m.focus {
        Field::Subnet       => Some(&mut m.state.subnet),
        Field::Clients      => Some(&mut m.state.clients),
        Field::ListenPort   => Some(&mut m.state.listen_port),
        Field::Dns          => Some(&mut m.state.dns),
        Field::ServerNs     => Some(&mut m.state.server_namespace),
        Field::ClientNs     => Some(&mut m.state.client_namespace),
        Field::RelayTarget  => Some(&mut m.state.relay_target),
        Field::ClientTarget => Some(&mut m.state.client_target),
        _ => None,
    };
    if let Some(slot) = opt {
        let cleaned: String = s.chars().filter(|c| *c != '\n' && *c != '\r').collect();
        slot.get_or_insert_with(String::new).push_str(&cleaned);
    }
}

/// Open the gateway-target picker modal. Lazily fetches `rustup
/// target list --installed` on first open + caches it for session.
fn open_gateway_modal(m: &mut Model) {
    if m.installed_targets.is_none() {
        m.installed_targets = Some(fetch_installed_targets());
    }
    // Land on the row matching the current selection.
    m.gateway_modal_idx = m.gateway_idx.min(TARGET_PRESETS.len());
    m.gateway_modal_open = true;
}

/// Run `rustup target list --installed` and parse triples. Returns
/// an empty vec on any failure (rustup missing, weird output, etc.) —
/// the modal then just shows nothing as installed, which is a safe
/// regression to "we don't know".
fn fetch_installed_targets() -> Vec<String> {
    let out = std::process::Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output();
    let Ok(out) = out else { return Vec::new() };
    if !out.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Open the SSH alias picker. Lazy-fetches `~/.ssh/config` (recursive,
/// follows Include) on first open + caches for the session.
fn open_ssh_modal(m: &mut Model) {
    if m.ssh_aliases.is_none() {
        m.ssh_aliases = Some(super::ssh_alias::fetch_ssh_aliases());
    }
    let aliases = m.ssh_aliases.as_deref().unwrap_or(&[]);
    // Land on the row matching the current value if there is one,
    // otherwise on the first alias (or "Other..." if no aliases).
    m.ssh_modal_idx = aliases
        .iter()
        .position(|a| a == &m.state.deploy_host)
        .unwrap_or(0);
    m.ssh_modal_open = true;
}

/// Modal-mode key handling for the SSH alias picker.
fn handle_ssh_modal(k: crossterm::event::KeyEvent, m: &mut Model) -> Outcome {
    let aliases_len = m.ssh_aliases.as_deref().map(|a| a.len()).unwrap_or(0);
    let other_idx = aliases_len; // last row is "Other..."
    let max = other_idx;
    match k.code {
        KeyCode::Esc => {
            m.ssh_modal_open = false;
        }
        KeyCode::Up => {
            if m.ssh_modal_idx > 0 {
                m.ssh_modal_idx -= 1;
            }
        }
        KeyCode::Down => {
            if m.ssh_modal_idx < max {
                m.ssh_modal_idx += 1;
            }
        }
        KeyCode::Enter => {
            if m.ssh_modal_idx < aliases_len {
                if let Some(name) = m
                    .ssh_aliases
                    .as_ref()
                    .and_then(|a| a.get(m.ssh_modal_idx))
                    .cloned()
                {
                    m.state.deploy_host = name;
                    m.deploy_host_touched = true;
                }
            }
            // "Other..." row: deploy_host already holds whatever the
            // user typed inline; just close the modal.
            m.ssh_modal_open = false;
        }
        // When on "Other..." let the user type to edit the host inline.
        _ if m.ssh_modal_idx >= aliases_len => {
            edit_text(&mut m.state.deploy_host, k.code);
            m.deploy_host_touched = true;
        }
        _ => {}
    }
    Outcome::Continue
}

/// Modal-mode key handling. Up/Down navigate options; Enter selects
/// + closes; Esc cancels. When focused on the "Other..." row, typing
/// edits the custom triple.
fn handle_gateway_modal(k: crossterm::event::KeyEvent, m: &mut Model) -> Outcome {
    let other_idx = TARGET_PRESETS.len();
    let max = other_idx; // valid indices: 0..=other_idx
    match k.code {
        KeyCode::Esc => {
            m.gateway_modal_open = false;
        }
        KeyCode::Up => {
            if m.gateway_modal_idx > 0 {
                m.gateway_modal_idx -= 1;
            }
        }
        KeyCode::Down => {
            if m.gateway_modal_idx < max {
                m.gateway_modal_idx += 1;
            }
        }
        KeyCode::Enter => {
            m.gateway_idx = m.gateway_modal_idx;
            sync_gateway(m);
            m.gateway_modal_open = false;
        }
        // When on "Other...", let the user type to edit the triple.
        _ if m.gateway_modal_idx >= TARGET_PRESETS.len() => {
            edit_text(&mut m.state.gateway_target, k.code);
        }
        _ => {}
    }
    Outcome::Continue
}

/// Cycle the currently-focused Select field one step. `forward = true`
/// = next option; `false` = previous. Triggered by Tab/Shift-Tab on
/// Gateway/Transport/TlsChoice.
fn cycle_select(m: &mut Model, forward: bool) {
    use super::state::{TlsChoice as TLS, TransportChoice as T};
    match m.focus {
        Field::Gateway => {
            let n = TARGET_PRESETS.len() + 1; // +1 for "Other"
            m.gateway_idx = if forward {
                (m.gateway_idx + 1) % n
            } else {
                (m.gateway_idx + n - 1) % n
            };
            sync_gateway(m);
        }
        Field::Transport => {
            let cur = T::ALL.iter().position(|&t| t == m.state.transport).unwrap_or(0);
            let next = if forward {
                (cur + 1) % T::ALL.len()
            } else {
                (cur + T::ALL.len() - 1) % T::ALL.len()
            };
            m.state.transport = T::ALL[next];
            if m.state.transport.is_wss()
                && !m.relay_host_touched
                && m.state.relay_host.is_empty()
            {
                let host = endpoint_host(&m.state.endpoint);
                if !host.is_empty() {
                    m.state.relay_host = format!("{host}:443");
                }
            }
        }
        Field::TlsChoice => {
            m.state.tls_strategy = match m.state.tls_strategy {
                TLS::SelfSigned => TLS::Byo,
                TLS::Byo => TLS::SelfSigned,
            };
        }
        _ => {}
    }
}

fn run_command(m: &mut Model, cmd: &str) -> Outcome {
    match cmd {
        "w" => on_save(m),
        "q" => Outcome::Cancel,
        "wq" | "x" => match on_save(m) {
            Outcome::Save => Outcome::Save,
            other => other,
        },
        other => {
            m.error = Some(format!("unknown command `:{other}` (try :w / :q / :wq)"));
            Outcome::Continue
        }
    }
}

fn on_save(m: &mut Model) -> Outcome {
    match m.state.require_complete() {
        Ok(()) => {
            // Final structural gate via the canonical parser.
            let body = super::emit::format_spec(&m.state);
            match crate::spec::Spec::parse_str(&body) {
                Ok(_) => Outcome::Save,
                Err(e) => {
                    m.error = Some(format!("{e:#}"));
                    Outcome::Continue
                }
            }
        }
        Err(missing) => {
            m.error = Some(format!("missing/invalid: {missing}"));
            Outcome::Continue
        }
    }
}

// ----------------------------------------------------------------------------
// Render
// ----------------------------------------------------------------------------

fn render(f: &mut Frame, m: &Model) {
    let area = centered(f.area(), 80, dynamic_height(m));
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(VAPOR_LINE))
        // Paint the form on true black explicitly so terminals with a
        // grey/off-white default background still render on black.
        .style(Style::default().bg(DEEP_BLACK))
        .title(Span::styled(
            " BURROWCTL :: INIT ",
            Style::default().fg(VAPOR_MAGENTA).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(&block, area);
    let inner = block.inner(area);

    // Build the row plan dynamically — sub-fields hidden entirely
    // (not greyed) when their gating context isn't active.
    let wss = m.state.transport.is_wss();
    let byo = wss && m.state.tls_strategy == super::state::TlsChoice::Byo;
    let mut rows_plan: Vec<Field> = vec![Field::Endpoint, Field::Gateway, Field::DeployToggle];
    if m.state.deploy_enabled {
        rows_plan.push(Field::DeployHost);
        rows_plan.push(Field::SshKey);
    }
    rows_plan.push(Field::Transport);
    if wss {
        rows_plan.push(Field::RelayHost);
        rows_plan.push(Field::TlsChoice);
        if byo {
            rows_plan.push(Field::CertPath);
            rows_plan.push(Field::KeyPath);
        }
    }
    rows_plan.push(Field::Routes);
    rows_plan.push(Field::Dns);
    rows_plan.push(Field::AdvancedToggle);
    if m.advanced_expanded {
        rows_plan.extend(ADVANCED_FIELDS);
    }

    let mut constraints: Vec<Constraint> = rows_plan.iter().map(|_| Constraint::Length(1)).collect();
    constraints.push(Constraint::Min(1));    // spacer
    constraints.push(Constraint::Length(1)); // error
    constraints.push(Constraint::Length(1)); // help / cmd bar
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    for (idx, field) in rows_plan.iter().enumerate() {
        render_field(f, m, *field, rows[idx]);
    }

    // Error line lives in the second-to-last row; help/cmd bar in the last.
    let last = rows.len() - 1;
    let err_line = m
        .error
        .as_deref()
        .map(|e| {
            Line::from(Span::styled(
                format!("[ERR] {e}"),
                Style::default().fg(VAPOR_RED).add_modifier(Modifier::BOLD),
            ))
        })
        .unwrap_or_else(|| Line::from(""));
    f.render_widget(Paragraph::new(err_line), rows[last - 1]);

    let bottom = if let Some(buf) = &m.cmd_buffer {
        Line::from(Span::styled(
            format!(":{buf}_"),
            Style::default().fg(VAPOR_MAGENTA).add_modifier(Modifier::BOLD),
        ))
    } else {
        let prefix = Span::styled(
            "[SYS] READY  ",
            Style::default().fg(VAPOR_CYAN).add_modifier(Modifier::BOLD),
        );
        let help = Span::styled(
            "↑/↓:NAV  TAB:CYCLE  SPC:TOG  F1:HELP  F2:PICK  ^S/:w COMMIT  ESC/:q ABORT",
            Style::default().fg(VAPOR_PURPLE),
        );
        Line::from(vec![prefix, help])
    };
    f.render_widget(Paragraph::new(bottom), rows[last]);

    if m.gateway_modal_open {
        render_gateway_modal(f, m, area);
    }
    if m.ssh_modal_open {
        render_ssh_modal(f, m, area);
    }
    if m.help_open {
        render_help_modal(f, m, area);
    }
}

/// How tall to make the form. Counts the dynamically-rendered rows
/// + 3 (spacer + error + help/cmd) + 2 (top/bottom border).
fn dynamic_height(m: &Model) -> u16 {
    let wss = m.state.transport.is_wss();
    let byo = wss && m.state.tls_strategy == super::state::TlsChoice::Byo;
    let mut n: u16 = 3; // endpoint + gateway + deploy toggle
    if m.state.deploy_enabled { n += 2; } // deploy_host + ssh_key
    n += 1; // transport
    if wss { n += 2; if byo { n += 2; } }
    n += 3; // routes + dns + advanced toggle
    if m.advanced_expanded { n += ADVANCED_FIELDS.len() as u16; }
    n + 3 + 2 // spacer + err + help/cmd  +  borders
}

/// Render whichever Field belongs in `area`. Centralises the
/// per-field-type dispatch so the layout pass only has to pick
/// which fields go where.
fn render_field(f: &mut Frame, m: &Model, field: Field, area: Rect) {
    use super::state::TlsChoice;
    match field {
        Field::Endpoint => f.render_widget(text_field(m, field, "WG_ENDPOINT       ", &m.state.endpoint), area),
        Field::Gateway => f.render_widget(gateway_field(m), area),
        Field::DeployToggle => f.render_widget(checkbox(m, field, "DEPLOY_VIA_SSH", m.state.deploy_enabled), area),
        Field::DeployHost => f.render_widget(sub_field(m, field, "  SSH_HOST         ", &m.state.deploy_host, m.state.deploy_enabled), area),
        Field::SshKey => f.render_widget(sub_field(m, field, "  SSH_KEY          ", &m.state.deploy_ssh_key, m.state.deploy_enabled), area),
        Field::Transport => f.render_widget(transport_field(m), area),
        Field::RelayHost => f.render_widget(sub_field(m, field, "  RELAY_HOSTPORT   ", &m.state.relay_host, true), area),
        Field::TlsChoice => f.render_widget(tls_field(m), area),
        Field::CertPath => f.render_widget(sub_field(m, field, "  CERT_PEM_PATH    ", &m.state.cert_path, true), area),
        Field::KeyPath => f.render_widget(sub_field(m, field, "  KEY_PEM_PATH     ", &m.state.key_path, true), area),
        Field::Routes => f.render_widget(text_field(m, field, "ROUTES_CIDR       ", &m.state.routes), area),
        Field::Dns => {
            // DNS is now a top-level text field. Renders as Option<String>
            // because the FormState carries it that way (None = empty).
            let value = m.state.dns.clone().unwrap_or_default();
            f.render_widget(
                text_field(m, field, "DNS               ", &value),
                area,
            );
        }
        Field::AdvancedToggle => f.render_widget(checkbox(m, field, "ADVANCED (subnet, namespaces, cross-targets, ...)", m.advanced_expanded), area),
        Field::Subnet | Field::Clients | Field::ListenPort
        | Field::ServerNs | Field::ClientNs | Field::RelayTarget | Field::ClientTarget => {
            // Look up the (label, default) for this advanced field.
            let (label, default) = ADVANCED_FIELD_META.iter()
                .find(|(fid, _, _)| *fid == field)
                .map(|(_, l, d)| (*l, *d))
                .expect("advanced field not in meta table");
            let val = match field {
                Field::Subnet => &m.state.subnet,
                Field::Clients => &m.state.clients,
                Field::ListenPort => &m.state.listen_port,
                Field::Dns => &m.state.dns,
                Field::ServerNs => &m.state.server_namespace,
                Field::ClientNs => &m.state.client_namespace,
                Field::RelayTarget => &m.state.relay_target,
                Field::ClientTarget => &m.state.client_target,
                _ => unreachable!(),
            };
            f.render_widget(adv_field(m, field, label, val.as_deref(), default), area);
        }
    }
    let _ = TlsChoice::SelfSigned; // silence unused-import warning if any
}

/// Render the gateway-target picker modal over `parent`. Each preset
/// row shows: `[*]` for the current selection, `[+]`/`[ ]` for
/// toolchain installed/not. Last row is "Other..." for a custom triple.
fn render_gateway_modal(f: &mut Frame, m: &Model, parent: Rect) {
    let other_idx = TARGET_PRESETS.len();
    let n_rows = TARGET_PRESETS.len() + 1; // + Other...
    // Sized to fit: ~5 lines chrome + one line per row.
    let w = parent.width.saturating_sub(8).min(72);
    let h = (n_rows as u16 + 5).min(parent.height.saturating_sub(4));
    let area = centered(parent, w, h);

    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(VAPOR_MAGENTA))
        .style(Style::default().bg(DEEP_BLACK))
        .title(Span::styled(
            " GATEWAY TARGET ",
            Style::default().fg(VAPOR_MAGENTA).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(&block, area);
    let inner = block.inner(area);

    let mut constraints: Vec<Constraint> =
        (0..n_rows).map(|_| Constraint::Length(1)).collect();
    constraints.push(Constraint::Min(1));    // spacer
    constraints.push(Constraint::Length(1)); // hint
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let installed = m.installed_targets.as_deref().unwrap_or(&[]);
    let is_installed = |triple: &str| installed.iter().any(|t| t == triple);

    for (i, (label, triple)) in TARGET_PRESETS.iter().enumerate() {
        let highlighted = i == m.gateway_modal_idx;
        let selected = i == m.gateway_idx;
        let install_marker = if is_installed(triple) { "[+]" } else { "[ ]" };
        let sel_marker = if selected { "[*]" } else { "   " };
        let arrow = if highlighted { "▶ " } else { "  " };
        let line_text = format!(" {arrow}{sel_marker} {install_marker}  {label}  ({triple}) ");
        let style = if highlighted {
            Style::default().fg(VAPOR_MAGENTA).add_modifier(Modifier::BOLD)
        } else if selected {
            Style::default().fg(VAPOR_CYAN)
        } else {
            Style::default().fg(VAPOR_PINK)
        };
        f.render_widget(Paragraph::new(Line::from(Span::styled(line_text, style))), rows[i]);
    }

    // "Other..." row — text input when highlighted.
    let highlighted = m.gateway_modal_idx == other_idx;
    let selected = m.gateway_idx == other_idx;
    let sel_marker = if selected { "[*]" } else { "   " };
    let arrow = if highlighted { "▶ " } else { "  " };
    let label_style_ = if highlighted {
        Style::default().fg(VAPOR_MAGENTA).add_modifier(Modifier::BOLD)
    } else if selected {
        Style::default().fg(VAPOR_CYAN)
    } else {
        Style::default().fg(VAPOR_PINK)
    };
    let prefix = format!(" {arrow}{sel_marker}      Other...  ");
    let mut spans = vec![Span::styled(prefix, label_style_)];
    if highlighted {
        if m.state.gateway_target.is_empty() {
            spans.push(Span::styled("▏", cursor_style()));
            spans.push(Span::styled(
                "type a custom triple",
                Style::default().fg(VAPOR_LINE),
            ));
        } else {
            spans.push(Span::styled(
                m.state.gateway_target.clone(),
                Style::default().fg(VAPOR_CYAN).add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled("▏", cursor_style()));
        }
    } else if !m.state.gateway_target.is_empty()
        && !TARGET_PRESETS.iter().any(|(_, t)| *t == m.state.gateway_target)
    {
        spans.push(Span::styled(
            m.state.gateway_target.clone(),
            Style::default().fg(VAPOR_PINK),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), rows[other_idx]);

    let hint = "↑/↓ MOVE  ENTER SELECT  ESC CANCEL    [+]=toolchain installed  [*]=current";
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            hint,
            Style::default().fg(VAPOR_PURPLE),
        ))),
        rows[rows.len() - 1],
    );
}

/// Render the SSH alias picker — same shape as the gateway modal but
/// list of strings (no per-row install marker, no preset/triple split).
fn render_ssh_modal(f: &mut Frame, m: &Model, parent: Rect) {
    let aliases = m.ssh_aliases.as_deref().unwrap_or(&[]);
    let other_idx = aliases.len();
    let n_rows = aliases.len() + 1;
    let w = parent.width.saturating_sub(8).min(60);
    // 5 chrome lines + room for a (no aliases) note when empty.
    let h = (n_rows as u16 + 5).min(parent.height.saturating_sub(4));
    let area = centered(parent, w, h);

    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(VAPOR_MAGENTA))
        .style(Style::default().bg(DEEP_BLACK))
        .title(Span::styled(
            " SSH HOST ",
            Style::default().fg(VAPOR_MAGENTA).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(&block, area);
    let inner = block.inner(area);

    let mut constraints: Vec<Constraint> =
        (0..n_rows).map(|_| Constraint::Length(1)).collect();
    constraints.push(Constraint::Min(1));    // spacer
    constraints.push(Constraint::Length(1)); // hint
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    for (i, name) in aliases.iter().enumerate() {
        let highlighted = i == m.ssh_modal_idx;
        let selected = name == &m.state.deploy_host;
        let sel_marker = if selected { "[*]" } else { "   " };
        let arrow = if highlighted { "▶ " } else { "  " };
        let style = if highlighted {
            Style::default().fg(VAPOR_MAGENTA).add_modifier(Modifier::BOLD)
        } else if selected {
            Style::default().fg(VAPOR_CYAN)
        } else {
            Style::default().fg(VAPOR_PINK)
        };
        let line_text = format!(" {arrow}{sel_marker}  {name} ");
        f.render_widget(
            Paragraph::new(Line::from(Span::styled(line_text, style))),
            rows[i],
        );
    }

    // Other... row — text input when highlighted; mirrors the
    // gateway-modal behavior so users learn one pattern.
    let highlighted = m.ssh_modal_idx == other_idx;
    let arrow = if highlighted { "▶ " } else { "  " };
    let label_style_ = if highlighted {
        Style::default().fg(VAPOR_MAGENTA).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(VAPOR_PINK)
    };
    let prefix = format!(" {arrow}      Other...  ");
    let mut spans = vec![Span::styled(prefix, label_style_)];
    if highlighted {
        if m.state.deploy_host.is_empty() {
            spans.push(Span::styled("▏", cursor_style()));
            spans.push(Span::styled(
                "type a host or alias",
                Style::default().fg(VAPOR_LINE),
            ));
        } else {
            spans.push(Span::styled(
                m.state.deploy_host.clone(),
                Style::default().fg(VAPOR_CYAN).add_modifier(Modifier::BOLD),
            ));
            spans.push(Span::styled("▏", cursor_style()));
        }
    } else if !m.state.deploy_host.is_empty()
        && !aliases.iter().any(|a| a == &m.state.deploy_host)
    {
        spans.push(Span::styled(
            m.state.deploy_host.clone(),
            Style::default().fg(VAPOR_PINK),
        ));
    }
    f.render_widget(Paragraph::new(Line::from(spans)), rows[other_idx]);

    let hint = if aliases.is_empty() {
        "↑/↓ MOVE  ENTER SELECT  ESC CANCEL    (no aliases found in ~/.ssh/config)"
    } else {
        "↑/↓ MOVE  ENTER SELECT  ESC CANCEL    [*]=current"
    };
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            hint,
            Style::default().fg(VAPOR_PURPLE),
        ))),
        rows[rows.len() - 1],
    );
}

/// Render the help modal over `parent` — clears a centered area then
/// draws the help text for the focused field.
fn render_help_modal(f: &mut Frame, m: &Model, parent: Rect) {
    let (prose, examples) = help_text(m.focus);
    // Modal sized 60×~12 inside the parent area (clamped).
    let w = parent.width.saturating_sub(8).min(70);
    let h = (8 + examples.lines().count() as u16).min(parent.height.saturating_sub(4));
    let area = centered(parent, w, h);

    // Wipe the area so the form doesn't bleed through.
    f.render_widget(Clear, area);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(VAPOR_MAGENTA))
        .style(Style::default().bg(DEEP_BLACK))
        .title(Span::styled(
            format!(" ?  {} ", field_help_title(m.focus)),
            Style::default().fg(VAPOR_MAGENTA).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(&block, area);
    let inner = block.inner(area);

    let body = format!(
        "{prose}\n\n{}{examples}\n\n{}",
        if examples.is_empty() { "" } else { "EXAMPLES:\n" },
        "(? or Esc to close)",
    );
    f.render_widget(
        Paragraph::new(body)
            .style(Style::default().fg(VAPOR_CYAN))
            .wrap(Wrap { trim: false }),
        inner,
    );
}

fn field_help_title(f: Field) -> &'static str {
    match f {
        Field::Endpoint => "WG_ENDPOINT",
        Field::Gateway => "GW_TARGET",
        Field::DeployToggle => "DEPLOY_VIA_SSH",
        Field::DeployHost => "SSH_HOST",
        Field::SshKey => "SSH_KEY",
        Field::Transport => "TRANSPORT",
        Field::RelayHost => "RELAY_HOSTPORT",
        Field::TlsChoice => "TLS",
        Field::CertPath => "CERT_PEM_PATH",
        Field::KeyPath => "KEY_PEM_PATH",
        Field::Routes => "ROUTES_CIDR",
        Field::AdvancedToggle => "ADVANCED",
        Field::Subnet => "SUBNET",
        Field::Clients => "CLIENTS",
        Field::ListenPort => "WG_LISTEN_PORT",
        Field::Dns => "DNS_CSV",
        Field::ServerNs => "SRV_NETNS",
        Field::ClientNs => "CLIENT_NETNS",
        Field::RelayTarget => "RELAY_TARGET",
        Field::ClientTarget => "CLIENT_TARGET",
    }
}

const ADVANCED_FIELD_META: &[(Field, &str, &str)] = &[
    (Field::Subnet,       "  SUBNET              ", "10.0.0.0/24"),
    (Field::Clients,      "  CLIENTS             ", "1"),
    (Field::ListenPort,   "  WG_LISTEN_PORT      ", "51820"),
    (Field::ServerNs,     "  SRV_NETNS           ", "burrow"),
    (Field::ClientNs,     "  CLIENT_NETNS        ", "burrow"),
    (Field::RelayTarget,  "  RELAY_TARGET        ", "x86_64-unknown-linux-gnu"),
    (Field::ClientTarget, "  CLIENT_TARGET       ", "x86_64-unknown-linux-gnu"),
];

fn transport_field(m: &Model) -> Paragraph<'_> {
    let focused = m.focus == Field::Transport;
    Paragraph::new(Line::from(vec![
        Span::styled("TRANSPORT         ", label_style(focused)),
        Span::styled(format!("[ {} ]", m.state.transport.label()), value_style(focused)),
    ]))
}

fn tls_field(m: &Model) -> Paragraph<'_> {
    let focused = m.focus == Field::TlsChoice;
    let enabled = m.state.transport.is_wss();
    let (label_style_, value_style_) = if enabled {
        (label_style(focused), value_style(focused))
    } else {
        (disabled_style(), disabled_style())
    };
    Paragraph::new(Line::from(vec![
        Span::styled("  TLS              ", label_style_),
        Span::styled(format!("[ {} ]", m.state.tls_strategy.label()), value_style_),
    ]))
}

fn adv_field<'a>(m: &Model, field: Field, label: &'a str, value: Option<&'a str>, default: &'a str) -> Paragraph<'a> {
    let focused = m.focus == field;
    let label_span = Span::styled(label.to_string(), label_style(focused));
    let cursor_span = if focused {
        Span::styled("▏", cursor_style())
    } else {
        Span::raw("")
    };
    match value {
        Some(v) => {
            // User has an override — render normally with cursor at end.
            Paragraph::new(Line::from(vec![
                label_span,
                Span::styled(v.to_string(), value_style(focused)),
                cursor_span,
            ]))
        }
        None => {
            // Default placeholder — cursor anchors before so it reads as
            // "start typing here" rather than already-entered content.
            Paragraph::new(Line::from(vec![
                label_span,
                cursor_span,
                Span::styled(format!("{default}  (default)"), disabled_style()),
            ]))
        }
    }
}

fn text_field<'a>(m: &Model, f: Field, label: &'a str, value: &'a str) -> Paragraph<'a> {
    let focused = m.focus == f;
    render_text_row(label, value, placeholder(f), focused, true)
}

fn sub_field<'a>(m: &Model, f: Field, label: &'a str, value: &'a str, enabled: bool) -> Paragraph<'a> {
    let focused = m.focus == f && enabled;
    render_text_row(label, value, placeholder(f), focused, enabled)
}

/// Shared render for any single-line text input. When `value` is
/// empty, shows `placeholder` in dim grey with the cursor anchored
/// before it; placeholder disappears the moment the user types.
fn render_text_row<'a>(
    label: &'a str,
    value: &'a str,
    placeholder: &'a str,
    focused: bool,
    enabled: bool,
) -> Paragraph<'a> {
    let label_span = if !enabled {
        Span::styled(label.to_string(), disabled_style())
    } else {
        Span::styled(label.to_string(), label_style(focused))
    };
    let cursor_span = if focused {
        Span::styled("▏", cursor_style())
    } else {
        Span::raw("")
    };
    if value.is_empty() {
        let placeholder_span = Span::styled(placeholder.to_string(), disabled_style());
        Paragraph::new(Line::from(vec![label_span, cursor_span, placeholder_span]))
    } else {
        let style = if !enabled { disabled_style() } else { value_style(focused) };
        let value_span = Span::styled(value.to_string(), style);
        Paragraph::new(Line::from(vec![label_span, value_span, cursor_span]))
    }
}

fn checkbox<'a>(m: &Model, f: Field, label: &'a str, on: bool) -> Paragraph<'a> {
    let focused = m.focus == f;
    let mark = if on { "[x]" } else { "[ ]" };
    Paragraph::new(Line::from(vec![
        Span::styled(format!("{mark} "), label_style(focused)),
        Span::styled(label.to_string(), label_style(focused)),
    ]))
}

fn gateway_field(m: &Model) -> Paragraph<'_> {
    let focused = m.focus == Field::Gateway;
    let preset_label = if m.gateway_idx < TARGET_PRESETS.len() {
        format!("{} ({})", TARGET_PRESETS[m.gateway_idx].0, TARGET_PRESETS[m.gateway_idx].1)
    } else {
        format!("Other (custom): {}", m.state.gateway_target)
    };
    Paragraph::new(Line::from(vec![
        Span::styled("GW_TARGET         ", label_style(focused)),
        Span::styled(preset_label, value_style(focused)),
    ]))
}

fn label_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(VAPOR_MAGENTA).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(VAPOR_PURPLE)
    }
}

fn value_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(VAPOR_CYAN).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(VAPOR_PINK)
    }
}

fn cursor_style() -> Style {
    Style::default().fg(VAPOR_MAGENTA).add_modifier(Modifier::SLOW_BLINK)
}

fn disabled_style() -> Style {
    Style::default().fg(VAPOR_LINE)
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect {
        x,
        y,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}
