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
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
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
// Palette — Phosphor Green CRT aesthetic with amber focus accent. ratatui
// degrades 24-bit colors gracefully on terminals that don't support them
// (256-color or 16-color fallback), so explicit RGB is safe.
// -----------------------------------------------------------------------------
const PHOSPHOR_BRIGHT: Color = Color::Rgb(0x00, 0xff, 0x00);
const PHOSPHOR_MED:    Color = Color::Rgb(0x00, 0xcc, 0x00);
const PHOSPHOR_DIM:    Color = Color::Rgb(0x00, 0x99, 0x00);
const AMBER_FOCUS:     Color = Color::Rgb(0xff, 0xb0, 0x00);
const RED_ERR:         Color = Color::Rgb(0xff, 0x44, 0x44);
const DIM_GRAY:        Color = Color::Rgb(0x55, 0x55, 0x55);

use super::state::{detect_host_triple, FormState};

/// Placeholder hint text shown in dim grey when a text field is empty.
/// Helps the user know what shape of input to enter without having to
/// hit `?` for the full help modal.
fn placeholder(f: Field) -> &'static str {
    match f {
        Field::Endpoint   => "vpn.example.com:51820",
        Field::DeployHost => "vpn.example.com  (or user@host, or IP)",
        Field::RelayHost  => "vpn.example.com:443",
        Field::CertPath   => "/etc/letsencrypt/live/host/fullchain.pem",
        Field::KeyPath    => "/etc/letsencrypt/live/host/privkey.pem",
        Field::Routes     => "192.168.1.0/24, 10.50.0.0/24",
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
            "Target triple for the burrow gateway binary. Pick the OS your gateway machine runs.",
            "  Linux x86_64 (default on Linux hosts)\n  Windows x86_64 MSVC\n  Windows x86_64 mingw\n  macOS Apple Silicon\n  Other... (type your own triple)",
        ),
        Field::DeployToggle => (
            "Toggle on to have burrowctl ship + start the WG server (and relay, if WSS) over SSH automatically. Off = you manage the server side manually.",
            "  on / off",
        ),
        Field::DeployHost => (
            "ssh-resolvable: alias from ~/.ssh/config, user@host, or bare IP. Used by `burrowctl ship-server` and `burrowctl up`.",
            "  vpn.example.com\n  root@vpn.example.com\n  do          (alias from ~/.ssh/config)",
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
    crossterm::execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .context("enter alt screen")?;
    Terminal::new(CrosstermBackend::new(stdout)).context("init terminal")
}

/// RAII restorer — runs on normal exit, error, or panic.
struct TuiGuard;
impl Drop for TuiGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = crossterm::execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
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
    Transport,
    RelayHost,
    TlsChoice,
    CertPath,
    KeyPath,
    Routes,
    AdvancedToggle,
    Subnet,
    Clients,
    ListenPort,
    Dns,
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
    Field::Transport,
    Field::RelayHost,
    Field::TlsChoice,
    Field::CertPath,
    Field::KeyPath,
    Field::Routes,
    Field::AdvancedToggle,
    Field::Subnet,
    Field::Clients,
    Field::ListenPort,
    Field::Dns,
    Field::ServerNs,
    Field::ClientNs,
    Field::RelayTarget,
    Field::ClientTarget,
];

const ADVANCED_FIELDS: &[Field] = &[
    Field::Subnet,
    Field::Clients,
    Field::ListenPort,
    Field::Dns,
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
        Self {
            state,
            focus: Field::Endpoint,
            gateway_idx,
            error: None,
            cmd_buffer: None,
            advanced_expanded,
            help_open: false,
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
                | Field::RelayHost
                | Field::CertPath
                | Field::KeyPath
                | Field::Routes
                | Field::Subnet
                | Field::Clients
                | Field::ListenPort
                | Field::Dns
                | Field::ServerNs
                | Field::ClientNs
                | Field::RelayTarget
                | Field::ClientTarget
        ) || (self.focus == Field::Gateway && self.gateway_idx >= TARGET_PRESETS.len())
    }

    /// Fields skip themselves when their gating toggle is off.
    fn focusable(&self, f: Field) -> bool {
        match f {
            Field::DeployHost => self.state.deploy_enabled,
            Field::RelayHost | Field::TlsChoice => self.state.transport.is_wss(),
            Field::CertPath | Field::KeyPath => {
                self.state.transport.is_wss()
                    && self.state.tls_strategy == super::state::TlsChoice::Byo
            }
            Field::Subnet
            | Field::Clients
            | Field::ListenPort
            | Field::Dns
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
            KeyCode::Esc | KeyCode::Enter | KeyCode::Char('?') | KeyCode::Char('q')
        ) {
            m.help_open = false;
        }
        return Outcome::Continue;
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
        // values when focused on one; otherwise they fall through to
        // navigation. (Lets vim-ish users use Tab to flip TRANSPORT
        // / TLS / GW_TARGET without leaving the field.)
        (KeyCode::Up, _) => {
            m.focus_prev();
            return Outcome::Continue;
        }
        (KeyCode::Down, _) => {
            m.focus_next();
            return Outcome::Continue;
        }
        (KeyCode::Tab, _) => {
            if !m.focus_is_select() {
                m.focus_next();
                return Outcome::Continue;
            }
            // Select cycling falls through to per-field handler below
            // via the `cycle_select(m, true)` translation.
            cycle_select(m, true);
            return Outcome::Continue;
        }
        (KeyCode::BackTab, _) => {
            if !m.focus_is_select() {
                m.focus_prev();
                return Outcome::Continue;
            }
            cycle_select(m, false);
            return Outcome::Continue;
        }
        // `?` opens the per-field help modal — but only when focus
        // isn't on a text field, where `?` is a legitimate character.
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
        Field::DeployHost => edit_text(&mut m.state.deploy_host, k.code),
        Field::RelayHost => edit_text(&mut m.state.relay_host, k.code),
        Field::Routes => edit_text(&mut m.state.routes, k.code),
        Field::DeployToggle => {
            if matches!(k.code, KeyCode::Char(' ') | KeyCode::Enter) {
                m.state.deploy_enabled = !m.state.deploy_enabled;
                if m.state.deploy_enabled && m.state.deploy_host.is_empty() {
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
            if m.state.transport.is_wss() && m.state.relay_host.is_empty() {
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
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(PHOSPHOR_MED))
        .title(Span::styled(
            " BURROWCTL :: INIT ",
            Style::default().fg(PHOSPHOR_BRIGHT).add_modifier(Modifier::BOLD),
        ));
    f.render_widget(&block, area);
    let inner = block.inner(area);

    // Build the row plan dynamically — sub-fields hidden entirely
    // (not greyed) when their gating context isn't active.
    let wss = m.state.transport.is_wss();
    let byo = wss && m.state.tls_strategy == super::state::TlsChoice::Byo;
    let mut rows_plan: Vec<Field> = vec![Field::Endpoint, Field::Gateway, Field::DeployToggle];
    if m.state.deploy_enabled { rows_plan.push(Field::DeployHost); }
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
                Style::default().fg(RED_ERR).add_modifier(Modifier::BOLD),
            ))
        })
        .unwrap_or_else(|| Line::from(""));
    f.render_widget(Paragraph::new(err_line), rows[last - 1]);

    let bottom = if let Some(buf) = &m.cmd_buffer {
        Line::from(Span::styled(
            format!(":{buf}_"),
            Style::default().fg(AMBER_FOCUS).add_modifier(Modifier::BOLD),
        ))
    } else {
        let prefix = Span::styled(
            "[SYS] READY  ",
            Style::default().fg(PHOSPHOR_BRIGHT).add_modifier(Modifier::BOLD),
        );
        let help = Span::styled(
            "↑/↓:NAV  TAB:CYCLE  SPC:TOG  ?:HELP  ^S/:w COMMIT  ESC/:q ABORT",
            Style::default().fg(PHOSPHOR_DIM),
        );
        Line::from(vec![prefix, help])
    };
    f.render_widget(Paragraph::new(bottom), rows[last]);

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
    if m.state.deploy_enabled { n += 1; }
    n += 1; // transport
    if wss { n += 2; if byo { n += 2; } }
    n += 2; // routes + advanced toggle
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
        Field::Transport => f.render_widget(transport_field(m), area),
        Field::RelayHost => f.render_widget(sub_field(m, field, "  RELAY_HOSTPORT   ", &m.state.relay_host, true), area),
        Field::TlsChoice => f.render_widget(tls_field(m), area),
        Field::CertPath => f.render_widget(sub_field(m, field, "  CERT_PEM_PATH    ", &m.state.cert_path, true), area),
        Field::KeyPath => f.render_widget(sub_field(m, field, "  KEY_PEM_PATH     ", &m.state.key_path, true), area),
        Field::Routes => f.render_widget(text_field(m, field, "ROUTES_CIDR       ", &m.state.routes), area),
        Field::AdvancedToggle => f.render_widget(checkbox(m, field, "ADVANCED (subnet, namespaces, cross-targets, ...)", m.advanced_expanded), area),
        Field::Subnet | Field::Clients | Field::ListenPort | Field::Dns
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
        .border_style(Style::default().fg(AMBER_FOCUS))
        .title(Span::styled(
            format!(" ?  {} ", field_help_title(m.focus)),
            Style::default().fg(AMBER_FOCUS).add_modifier(Modifier::BOLD),
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
            .style(Style::default().fg(PHOSPHOR_BRIGHT))
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
    (Field::Dns,          "  DNS_CSV             ", "(empty)"),
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
    let (display, style) = match value {
        Some(v) => (v.to_string(), value_style(focused)),
        None => (
            format!("{default}  (default)"),
            disabled_style(),
        ),
    };
    let cursor = if focused { Span::styled("▏", cursor_style()) } else { Span::raw("") };
    Paragraph::new(Line::from(vec![
        Span::styled(label.to_string(), label_style(focused)),
        Span::styled(display, style),
        cursor,
    ]))
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
        Style::default().fg(AMBER_FOCUS).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(PHOSPHOR_DIM)
    }
}

fn value_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(PHOSPHOR_BRIGHT).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(PHOSPHOR_MED)
    }
}

fn cursor_style() -> Style {
    Style::default().fg(AMBER_FOCUS).add_modifier(Modifier::SLOW_BLINK)
}

fn disabled_style() -> Style {
    Style::default().fg(DIM_GRAY)
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
