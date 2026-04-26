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
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::{Frame, Terminal};

use super::state::{detect_host_triple, FormState};

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
        }
    }

    /// True iff the focused field is text-input (so a literal `:` is
    /// part of valid input — host:port, host, CIDR list — rather than
    /// the start of a vim-style command).
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
        (KeyCode::Tab, _) => {
            m.focus_next();
            return Outcome::Continue;
        }
        (KeyCode::BackTab, _) => {
            m.focus_prev();
            return Outcome::Continue;
        }
        // `:` enters command-bar mode — but only when focus isn't on
        // a text field, where `:` is a legitimate character (host:port,
        // CIDR lists, etc.). From a text field, use Ctrl-S to save.
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
        Field::Transport => {
            // Cycle through TransportChoice::ALL.
            use super::state::TransportChoice as T;
            if matches!(
                k.code,
                KeyCode::Left
                    | KeyCode::Right
                    | KeyCode::Up
                    | KeyCode::Down
                    | KeyCode::Char(' ')
                    | KeyCode::Enter
            ) {
                let cur = T::ALL.iter().position(|&t| t == m.state.transport).unwrap_or(0);
                let dir = matches!(k.code, KeyCode::Left | KeyCode::Up);
                let next = if dir {
                    (cur + T::ALL.len() - 1) % T::ALL.len()
                } else {
                    (cur + 1) % T::ALL.len()
                };
                m.state.transport = T::ALL[next];
                // Ergonomic: switching to WSS pre-fills relay_host
                // from the endpoint host if we don't have one yet.
                if m.state.transport.is_wss() && m.state.relay_host.is_empty() {
                    let host = endpoint_host(&m.state.endpoint);
                    if !host.is_empty() {
                        m.state.relay_host = format!("{host}:443");
                    }
                }
            }
        }
        Field::AdvancedToggle => {
            if matches!(k.code, KeyCode::Char(' ') | KeyCode::Enter) {
                m.advanced_expanded = !m.advanced_expanded;
            }
        }
        Field::TlsChoice => {
            // Toggle between the 2 TLS strategies.
            use super::state::TlsChoice as T;
            if matches!(
                k.code,
                KeyCode::Left
                    | KeyCode::Right
                    | KeyCode::Up
                    | KeyCode::Down
                    | KeyCode::Char(' ')
                    | KeyCode::Enter
            ) {
                m.state.tls_strategy = match m.state.tls_strategy {
                    T::SelfSigned => T::Byo,
                    T::Byo => T::SelfSigned,
                };
            }
        }
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
            KeyCode::Up => {
                if m.gateway_idx > 0 {
                    m.gateway_idx -= 1;
                    sync_gateway(m);
                }
            }
            KeyCode::Down => {
                if m.gateway_idx + 1 <= TARGET_PRESETS.len() {
                    m.gateway_idx += 1;
                    sync_gateway(m);
                }
            }
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
    let height = if m.advanced_expanded { 32 } else { 22 };
    let area = centered(f.area(), 80, height);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" burrowctl init ");
    f.render_widget(&block, area);
    let inner = block.inner(area);

    let mut constraints = vec![
        Constraint::Length(1), // endpoint
        Constraint::Length(1), // gateway
        Constraint::Length(1), // deploy toggle
        Constraint::Length(1), // deploy host
        Constraint::Length(1), // wss toggle
        Constraint::Length(1), // relay host
        Constraint::Length(1), // tls choice
        Constraint::Length(1), // cert path
        Constraint::Length(1), // key path
        Constraint::Length(1), // routes
        Constraint::Length(1), // advanced toggle
    ];
    if m.advanced_expanded {
        for _ in 0..ADVANCED_FIELDS.len() {
            constraints.push(Constraint::Length(1));
        }
    }
    constraints.push(Constraint::Min(1)); // spacer
    constraints.push(Constraint::Length(1)); // error
    constraints.push(Constraint::Length(1)); // help / cmd bar

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner);

    let mut i = 0;
    f.render_widget(text_field(m, Field::Endpoint, "WireGuard endpoint", &m.state.endpoint), rows[i]); i += 1;
    f.render_widget(gateway_field(m), rows[i]); i += 1;
    f.render_widget(checkbox(m, Field::DeployToggle, "Deploy via SSH", m.state.deploy_enabled), rows[i]); i += 1;
    f.render_widget(sub_field(m, Field::DeployHost, "  SSH host         ", &m.state.deploy_host, m.state.deploy_enabled), rows[i]); i += 1;
    f.render_widget(transport_field(m), rows[i]); i += 1;
    f.render_widget(sub_field(m, Field::RelayHost, "  Relay host:port  ", &m.state.relay_host, m.state.transport.is_wss()), rows[i]); i += 1;
    f.render_widget(tls_field(m), rows[i]); i += 1;
    let byo = m.state.transport.is_wss() && m.state.tls_strategy == super::state::TlsChoice::Byo;
    f.render_widget(
        sub_field(m, Field::CertPath, "  Cert PEM path    ", &m.state.cert_path, byo),
        rows[i],
    ); i += 1;
    f.render_widget(
        sub_field(m, Field::KeyPath,  "  Key PEM path     ", &m.state.key_path, byo),
        rows[i],
    ); i += 1;
    f.render_widget(text_field(m, Field::Routes, "Routes (comma-separated CIDRs, optional)", &m.state.routes), rows[i]); i += 1;
    f.render_widget(checkbox(m, Field::AdvancedToggle, "Advanced (subnet, namespaces, cross-targets, ...)", m.advanced_expanded), rows[i]); i += 1;

    if m.advanced_expanded {
        for &(field, label, default) in ADVANCED_FIELD_META {
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
            f.render_widget(adv_field(m, field, label, val.as_deref(), default), rows[i]);
            i += 1;
        }
    }

    let err_line = m
        .error
        .as_deref()
        .map(|e| Line::from(Span::styled(format!("error: {e}"), Style::default().fg(Color::Red))))
        .unwrap_or_else(|| Line::from(""));
    f.render_widget(Paragraph::new(err_line), rows[constraints_len(m) - 2]);

    let bottom = if let Some(buf) = &m.cmd_buffer {
        Line::from(Span::styled(
            format!(":{buf}_"),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(Span::styled(
            "Tab/Shift-Tab move • Space toggle • Ctrl-S or :w save • Esc or :q cancel",
            Style::default().fg(Color::DarkGray),
        ))
    };
    f.render_widget(Paragraph::new(bottom), rows[constraints_len(m) - 1]);
}

const ADVANCED_FIELD_META: &[(Field, &str, &str)] = &[
    (Field::Subnet,       "  Subnet              ", "10.0.0.0/24"),
    (Field::Clients,      "  Clients             ", "1"),
    (Field::ListenPort,   "  WG listen port      ", "51820"),
    (Field::Dns,          "  DNS (csv)           ", "(empty)"),
    (Field::ServerNs,     "  Server netns name   ", "burrow"),
    (Field::ClientNs,     "  Client netns name   ", "burrow"),
    (Field::RelayTarget,  "  Relay target triple ", "x86_64-unknown-linux-gnu"),
    (Field::ClientTarget, "  Client target triple", "x86_64-unknown-linux-gnu"),
];

fn constraints_len(m: &Model) -> usize {
    11 + (if m.advanced_expanded { ADVANCED_FIELDS.len() } else { 0 }) + 3
}

fn transport_field(m: &Model) -> Paragraph<'_> {
    let focused = m.focus == Field::Transport;
    Paragraph::new(Line::from(vec![
        Span::styled("Transport          ", label_style(focused)),
        Span::styled(format!("[ {} ]", m.state.transport.label()), value_style(focused)),
    ]))
}

fn tls_field(m: &Model) -> Paragraph<'_> {
    let focused = m.focus == Field::TlsChoice;
    let enabled = m.state.transport.is_wss();
    let label_style_ = if !enabled {
        Style::default().fg(Color::DarkGray)
    } else {
        label_style(focused)
    };
    let value_style_ = if !enabled {
        Style::default().fg(Color::DarkGray)
    } else {
        value_style(focused)
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
            Style::default().fg(Color::DarkGray),
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
    let label_span = Span::styled(format!("{label}: "), label_style(focused));
    let value_span = Span::styled(value.to_string(), value_style(focused));
    let cursor = if focused { Span::styled("▏", cursor_style()) } else { Span::raw("") };
    Paragraph::new(Line::from(vec![label_span, value_span, cursor]))
}

fn sub_field<'a>(m: &Model, f: Field, label: &'a str, value: &'a str, enabled: bool) -> Paragraph<'a> {
    let focused = m.focus == f && enabled;
    let style = if !enabled {
        Style::default().fg(Color::DarkGray)
    } else if focused {
        value_style(true)
    } else {
        value_style(false)
    };
    let cursor = if focused { Span::styled("▏", cursor_style()) } else { Span::raw("") };
    Paragraph::new(Line::from(vec![
        Span::styled(label.to_string(), label_style(focused)),
        Span::styled(value.to_string(), style),
        cursor,
    ]))
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
        Span::styled("Gateway runs on: ", label_style(focused)),
        Span::styled(preset_label, value_style(focused)),
    ]))
}

fn label_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    }
}

fn value_style(focused: bool) -> Style {
    if focused {
        Style::default().fg(Color::White).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Gray)
    }
}

fn cursor_style() -> Style {
    Style::default().fg(Color::Yellow).add_modifier(Modifier::SLOW_BLINK)
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
