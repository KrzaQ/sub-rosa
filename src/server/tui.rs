use std::collections::VecDeque;
use std::path::Path;
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};

use crate::config::{parse_duration, Config, Policy};
use crate::server::peer::comm_matches;
use crate::server::{
    format_remaining, pidfd_for, Decision, Grant, GrantScope, GrantUntil, PendingReq,
    PolicyOverride, PolicySource, ServerMsg, Shared,
};
use crate::store;

const LOG_CAP: usize = 500;

struct LogLine {
    ts: String,
    msg: String,
    deny: bool,
}

#[derive(Clone)]
enum Action {
    AllowOnce,
    AllowFor(Duration, String),
    AllowSession,
    Deny,
}

/// Which modal column has focus.
#[derive(Clone, Copy, PartialEq)]
enum Col {
    Procs,
    Actions,
}

/// Idle, or inside the user-opened per-secret menu. While the menu is open
/// the request modal stays hidden and incoming requests queue (their
/// auto-deny clock keeps ticking) — a user-opened modal is never interrupted.
enum UiMode {
    Idle,
    SecretMenu(SecretMenu),
}

struct SecretMenu {
    /// Secret name captured at open; re-validated against the store at
    /// every commit, since a reload can remove it while the menu is up.
    name: String,
    view: MenuView,
    state: ListState,
}

#[derive(Clone, Copy, PartialEq)]
enum MenuView {
    Root,
    Durations,
}

#[derive(Clone, Copy)]
enum MenuItem {
    MakeAuto,
    ForceConfirm,
    RevertToConfig,
    Cancel,
}

#[derive(Clone)]
enum DurationItem {
    For(Duration, String),
    Session,
    Back,
}

struct App {
    shared: Arc<Mutex<Shared>>,
    rx: Receiver<ServerMsg>,
    log: VecDeque<LogLine>,
    pending: VecDeque<PendingReq>,
    action_state: ListState,
    proc_state: ListState,
    focus: Col,
    mode: UiMode,
    /// Secrets-pane cursor, by name: the store is a sorted BTreeMap, so a
    /// name survives reloads and resolves to a stable position.
    cursor: Option<String>,
    secret_state: ListState,
    sock: String,
    timeout: Duration,
    quit: bool,
    want_reload: bool,
}

impl App {
    fn log(&mut self, msg: String, deny: bool) {
        self.log.push_back(LogLine {
            ts: chrono::Local::now().format("%H:%M:%S").to_string(),
            msg,
            deny,
        });
        while self.log.len() > LOG_CAP {
            self.log.pop_front();
        }
    }

    /// Reset modal selection for a new front request: action = deny (always
    /// last), so a stray buffered Enter fails safe — see the KEYBINDING
    /// INVARIANT on handle_key. Process = the requester (last tree row),
    /// focus on the action column.
    fn reset_modal(&mut self) {
        let n_actions = action_items(self).len();
        self.action_state.select(Some(n_actions.saturating_sub(1)));
        let rows = self.proc_rows();
        self.proc_state.select(Some(rows.saturating_sub(1)));
        self.focus = Col::Actions;
    }

    /// Number of selectable rows in the process tree (root..requester).
    fn proc_rows(&self) -> usize {
        self.pending
            .front()
            .map(|p| p.peer.ancestry.len().max(1))
            .unwrap_or(1)
    }

    /// Index of the cursor in the sorted `names`; a vanished secret slides
    /// to its lexicographic successor. Rewrites the cursor to the resolved
    /// name. `names` must be non-empty.
    fn resolve_cursor(&mut self, names: &[String]) -> usize {
        let idx = match &self.cursor {
            Some(name) => match names.binary_search(name) {
                Ok(i) => i,
                Err(i) => i.min(names.len() - 1),
            },
            None => 0,
        };
        self.cursor = Some(names[idx].clone());
        idx
    }

    fn secret_names(&self) -> Vec<String> {
        self.shared.lock().unwrap().store.keys().cloned().collect()
    }

    fn move_cursor(&mut self, delta: i64) {
        let names = self.secret_names();
        if names.is_empty() {
            self.cursor = None;
            return;
        }
        let cur = self.resolve_cursor(&names) as i64;
        let next = (cur + delta).clamp(0, names.len() as i64 - 1) as usize;
        self.cursor = Some(names[next].clone());
    }

    fn open_menu(&mut self) {
        let names = self.secret_names();
        if names.is_empty() {
            return;
        }
        let idx = self.resolve_cursor(&names);
        self.mode = UiMode::SecretMenu(SecretMenu {
            name: names[idx].clone(),
            view: MenuView::Root,
            state: ListState::default().with_selected(Some(0)),
        });
    }

    /// Grant scope for the currently selected process-tree row.
    fn selected_scope(&self, p: &PendingReq) -> GrantScope {
        let rows = p.peer.ancestry.len();
        let sel = self.proc_state.selected().unwrap_or(rows.saturating_sub(1));
        if rows == 0 || sel + 1 >= rows {
            // The requester itself: scope by exe path so re-runs still match.
            GrantScope::Exe(p.peer.exe.clone())
        } else {
            // An ancestor: ancestry is leaf-first, tree rows are root-first.
            let proc = &p.peer.ancestry[rows - 1 - sel];
            GrantScope::Pid { pid: proc.pid, comm: proc.comm.clone() }
        }
    }
}

pub fn run(shared: Arc<Mutex<Shared>>, rx: Receiver<ServerMsg>, sock: &Path) -> Result<()> {
    let timeout = shared.lock().unwrap().cfg.request_timeout();
    let mut app = App {
        shared,
        rx,
        log: VecDeque::new(),
        pending: VecDeque::new(),
        action_state: ListState::default().with_selected(Some(0)),
        proc_state: ListState::default(),
        focus: Col::Actions,
        mode: UiMode::Idle,
        cursor: None,
        secret_state: ListState::default(),
        sock: sock.display().to_string(),
        timeout,
        quit: false,
        want_reload: false,
    };
    app.log("agent started".into(), false);

    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &mut app);
    ratatui::restore();

    // Anything still pending gets an explicit deny rather than a hang.
    for p in app.pending.drain(..) {
        let _ = p.respond.send(Decision::Deny);
    }
    result
}

fn event_loop(terminal: &mut DefaultTerminal, app: &mut App) -> Result<()> {
    while !app.quit {
        while let Ok(msg) = app.rx.try_recv() {
            match msg {
                ServerMsg::Request(req) => {
                    let was_empty = app.pending.is_empty();
                    app.pending.push_back(req);
                    if was_empty {
                        app.reset_modal();
                    }
                }
                ServerMsg::Log { msg, deny } => app.log(msg, deny),
                ServerMsg::ReloadReq => app.want_reload = true,
            }
        }

        // Auto-deny requests the human ignored past the deadline.
        while app
            .pending
            .front()
            .is_some_and(|p| p.received.elapsed() > app.timeout)
        {
            let p = app.pending.pop_front().unwrap();
            let _ = p.respond.send(Decision::Deny);
            let caller = p.peer.ancestry.first().map(|a| a.comm.as_str()).unwrap_or("?");
            app.log(
                format!("DENY  {} ← {}({}) [timeout]", p.name, caller, p.peer.pid),
                true,
            );
            app.reset_modal();
        }

        if app.want_reload {
            app.want_reload = false;
            reload(terminal, app);
        }

        terminal.draw(|f| draw(f, app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    handle_key(app, key.code, key.modifiers);
                }
            }
        }
    }
    Ok(())
}

/// KEYBINDING INVARIANT — the request-approval modal is the only UI surface
/// that appears WITHOUT user action, so it must be robust against keystrokes
/// buffered before it appeared (slow SSH, typed against a stale screen):
///   (a) no key bound in the idle view may act as a commit key in the
///       request modal (idle keys q r c ↑ ↓ j k space either move a
///       selection there or do nothing);
///   (b) no commit key of the request modal may be bound in the idle view
///       (Enter commits only inside modals and is a no-op in idle; there is
///       deliberately no single-key "allow" shortcut).
/// n/d/Esc deny in the request modal — an accidental deny is safe, an
/// accidental allow is not. reset_modal() pre-selects Deny so even a stray
/// Enter fails safe. User-opened modals (the secret menu) can't be raced:
/// requests queue behind them instead of stealing focus.
fn handle_key(app: &mut App, code: KeyCode, mods: KeyModifiers) {
    if code == KeyCode::Char('c') && mods.contains(KeyModifiers::CONTROL) {
        app.quit = true;
        return;
    }
    if matches!(app.mode, UiMode::SecretMenu(_)) {
        handle_menu_key(app, code);
    } else if !app.pending.is_empty() {
        handle_request_key(app, code);
    } else {
        handle_idle_key(app, code);
    }
}

fn handle_idle_key(app: &mut App, code: KeyCode) {
    match code {
        KeyCode::Char('q') => app.quit = true,
        KeyCode::Char('r') => app.want_reload = true,
        KeyCode::Char('c') => {
            let n = {
                let mut sh = app.shared.lock().unwrap();
                let n = sh.grants.len();
                sh.grants.clear();
                n
            };
            app.log(format!("cleared {n} grant(s)"), false);
        }
        KeyCode::Up | KeyCode::Char('k') => app.move_cursor(-1),
        KeyCode::Down | KeyCode::Char('j') => app.move_cursor(1),
        KeyCode::Char(' ') => app.open_menu(),
        // Enter is deliberately unbound here — see the KEYBINDING INVARIANT.
        _ => {}
    }
}

fn handle_request_key(app: &mut App, code: KeyCode) {
    let actions = action_items(app);
    match code {
        KeyCode::Left | KeyCode::Char('h') => app.focus = Col::Procs,
        KeyCode::Right | KeyCode::Char('l') => app.focus = Col::Actions,
        KeyCode::Tab => {
            app.focus = if app.focus == Col::Procs { Col::Actions } else { Col::Procs }
        }
        KeyCode::Up | KeyCode::Char('k') => {
            let st = match app.focus {
                Col::Procs => &mut app.proc_state,
                Col::Actions => &mut app.action_state,
            };
            st.select(Some(st.selected().unwrap_or(0).saturating_sub(1)));
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let proc_rows = app.proc_rows();
            let (st, max) = match app.focus {
                Col::Procs => (&mut app.proc_state, proc_rows),
                Col::Actions => (&mut app.action_state, actions.len()),
            };
            let max = max.saturating_sub(1);
            st.select(Some((st.selected().unwrap_or(0) + 1).min(max)));
        }
        KeyCode::Enter => {
            let sel = app.action_state.selected().unwrap_or(0).min(actions.len() - 1);
            decide(app, actions[sel].clone());
        }
        KeyCode::Char('n') | KeyCode::Char('d') | KeyCode::Esc => decide(app, Action::Deny),
        // Space is bound in the idle view; it must stay a no-op here — see
        // the KEYBINDING INVARIANT.
        KeyCode::Char(' ') => {}
        _ => {}
    }
}

fn handle_menu_key(app: &mut App, code: KeyCode) {
    let (name, view) = match &app.mode {
        UiMode::SecretMenu(m) => (m.name.clone(), m.view),
        _ => return,
    };
    match view {
        MenuView::Root => menu_root_key(app, &name, code),
        MenuView::Durations => menu_durations_key(app, &name, code),
    }
}

fn action_items(app: &App) -> Vec<Action> {
    let mut items = vec![Action::AllowOnce];
    let durations = app.shared.lock().unwrap().cfg.grant_durations.clone();
    for d in &durations {
        if let Some(dur) = parse_duration(d) {
            items.push(Action::AllowFor(dur, d.clone()));
        }
    }
    items.push(Action::AllowSession);
    items.push(Action::Deny);
    items
}

// ------------------------------------------------------- secret menu ----

/// Recomputed from live state on every keypress and frame, so an override
/// expiring mid-menu just flips the items instead of going stale.
fn menu_root_items(sh: &Shared, name: &str) -> Vec<MenuItem> {
    match sh.effective_policy(name) {
        (_, PolicySource::Override) => vec![MenuItem::RevertToConfig, MenuItem::Cancel],
        (Policy::Confirm, _) => vec![MenuItem::MakeAuto, MenuItem::Cancel],
        (Policy::Auto, _) => vec![MenuItem::ForceConfirm, MenuItem::Cancel],
    }
}

fn menu_item_label(item: MenuItem) -> &'static str {
    match item {
        MenuItem::MakeAuto => "make auto…",
        MenuItem::ForceConfirm => "force confirm (revokes grants)",
        MenuItem::RevertToConfig => "revert to config",
        MenuItem::Cancel => "cancel",
    }
}

/// Empty/unparseable grant_durations degrade to just session + back.
fn duration_items(cfg: &Config) -> Vec<DurationItem> {
    let mut items: Vec<DurationItem> = cfg
        .grant_durations
        .iter()
        .filter_map(|d| parse_duration(d).map(|dur| DurationItem::For(dur, d.clone())))
        .collect();
    items.push(DurationItem::Session);
    items.push(DurationItem::Back);
    items
}

fn duration_item_label(item: &DurationItem) -> String {
    match item {
        DurationItem::For(_, d) => format!("auto for {d}"),
        DurationItem::Session => "auto until agent exits".to_string(),
        DurationItem::Back => "back".to_string(),
    }
}

/// Selected menu index, clamped to `len` (the item list can shrink under
/// the cursor when an override expires mid-menu).
fn menu_selected(app: &App, len: usize) -> usize {
    match &app.mode {
        UiMode::SecretMenu(m) => m.state.selected().unwrap_or(0).min(len.saturating_sub(1)),
        _ => 0,
    }
}

fn menu_move(app: &mut App, delta: i64, len: usize) {
    if let UiMode::SecretMenu(m) = &mut app.mode {
        let cur = m.state.selected().unwrap_or(0) as i64;
        let max = len.saturating_sub(1) as i64;
        m.state.select(Some((cur + delta).clamp(0, max) as usize));
    }
}

fn menu_set_view(app: &mut App, view: MenuView) {
    if let UiMode::SecretMenu(m) = &mut app.mode {
        m.view = view;
        m.state.select(Some(0));
    }
}

fn close_menu(app: &mut App) {
    app.mode = UiMode::Idle;
    // A queued request's modal is revealed now; make sure it sits on Deny.
    if !app.pending.is_empty() {
        app.reset_modal();
    }
}

fn menu_root_key(app: &mut App, name: &str, code: KeyCode) {
    let items = {
        let sh = app.shared.lock().unwrap();
        menu_root_items(&sh, name)
    };
    match code {
        KeyCode::Up | KeyCode::Char('k') => menu_move(app, -1, items.len()),
        KeyCode::Down | KeyCode::Char('j') => menu_move(app, 1, items.len()),
        KeyCode::Esc => close_menu(app),
        KeyCode::Enter => match items[menu_selected(app, items.len())] {
            MenuItem::MakeAuto => menu_set_view(app, MenuView::Durations),
            MenuItem::ForceConfirm => apply_override(
                app,
                name,
                PolicyOverride { policy: Policy::Confirm, until: GrantUntil::Session },
                "session",
            ),
            MenuItem::RevertToConfig => {
                let msg = {
                    let mut sh = app.shared.lock().unwrap();
                    sh.overrides.remove(name);
                    format!("override {name} reverted to config")
                };
                app.log(msg, false);
                close_menu(app);
            }
            MenuItem::Cancel => close_menu(app),
        },
        _ => {}
    }
}

fn menu_durations_key(app: &mut App, name: &str, code: KeyCode) {
    let items = duration_items(&app.shared.lock().unwrap().cfg);
    match code {
        KeyCode::Up | KeyCode::Char('k') => menu_move(app, -1, items.len()),
        KeyCode::Down | KeyCode::Char('j') => menu_move(app, 1, items.len()),
        KeyCode::Esc => menu_set_view(app, MenuView::Root),
        KeyCode::Enter => match &items[menu_selected(app, items.len())] {
            DurationItem::For(dur, label) => {
                let until = GrantUntil::At(Instant::now() + *dur);
                let label = label.clone();
                apply_override(
                    app,
                    name,
                    PolicyOverride { policy: Policy::Auto, until },
                    &label,
                );
            }
            DurationItem::Session => apply_override(
                app,
                name,
                PolicyOverride { policy: Policy::Auto, until: GrantUntil::Session },
                "session",
            ),
            DurationItem::Back => menu_set_view(app, MenuView::Root),
        },
        _ => {}
    }
}

fn apply_override(app: &mut App, name: &str, ov: PolicyOverride, label: &str) {
    let msg = {
        let mut sh = app.shared.lock().unwrap();
        if !sh.store.contains_key(name) {
            format!("{name} vanished; no change")
        } else if ov.policy == Policy::Confirm {
            let revoked = sh.set_override(name, ov);
            format!("override {name} confirm (lock) — revoked {revoked} grant(s)")
        } else {
            sh.set_override(name, ov);
            format!("override {name} auto [{label}]")
        }
    };
    app.log(msg, false);
    close_menu(app);
}

fn decide(app: &mut App, action: Action) {
    let p = app.pending.pop_front().expect("decide only runs with a pending request");
    let caller = p.peer.ancestry.first().map(|a| a.comm.as_str()).unwrap_or("?");

    let (decision, note) = match action {
        Action::Deny => (Decision::Deny, None),
        Action::AllowOnce => (Decision::Allow, None),
        Action::AllowFor(dur, label) => {
            let scope = app.selected_scope(&p);
            let note = format!("grant {} {}", scope.label(), label);
            let watch = pidfd_for(&scope);
            app.shared.lock().unwrap().add_grant(Grant {
                name: p.name.clone(),
                scope,
                until: GrantUntil::At(Instant::now() + dur),
                watch,
            });
            (Decision::Allow, Some(note))
        }
        Action::AllowSession => {
            let scope = app.selected_scope(&p);
            let note = format!("grant {} session", scope.label());
            let watch = pidfd_for(&scope);
            app.shared.lock().unwrap().add_grant(Grant {
                name: p.name.clone(),
                scope,
                until: GrantUntil::Session,
                watch,
            });
            (Decision::Allow, Some(note))
        }
    };
    let _ = p.respond.send(decision);
    match decision {
        Decision::Allow => app.log(
            format!(
                "ALLOW {} ← {}({}){}",
                p.name,
                caller,
                p.peer.pid,
                note.map(|n| format!(" [{n}]")).unwrap_or_default()
            ),
            false,
        ),
        Decision::Deny => app.log(format!("DENY  {} ← {}({})", p.name, caller, p.peer.pid), true),
    }
    app.reset_modal();
}

/// Drop out of the TUI so gpg's pinentry gets a normal terminal, re-decrypt,
/// come back.
fn reload(terminal: &mut DefaultTerminal, app: &mut App) {
    let path = app.shared.lock().unwrap().cfg.store_path();
    let _ = disable_raw_mode();
    let _ = crossterm::execute!(std::io::stdout(), LeaveAlternateScreen);
    eprintln!("rosa: reloading {} …", path.display());
    let loaded = store::load(&path);
    let _ = enable_raw_mode();
    let _ = crossterm::execute!(std::io::stdout(), EnterAlternateScreen);
    let _ = terminal.clear();
    match loaded {
        Ok(map) => {
            let n = map.len();
            {
                let mut guard = app.shared.lock().unwrap();
                let sh = &mut *guard;
                sh.store = map;
                // A deleted-then-readded secret must not resurrect an auto
                // override; confirm locks are kept (fail-safe either way).
                let store = &sh.store;
                sh.overrides
                    .retain(|name, o| o.policy == Policy::Confirm || store.contains_key(name));
            }
            app.log(format!("store reloaded ({n} secrets)"), false);
            let menu_name = match &app.mode {
                UiMode::SecretMenu(m) => Some(m.name.clone()),
                _ => None,
            };
            if let Some(name) = menu_name {
                if !app.shared.lock().unwrap().store.contains_key(&name) {
                    app.log(format!("{name} removed; closing menu"), false);
                    close_menu(app);
                }
            }
        }
        Err(e) => app.log(format!("reload failed: {e:#}"), true),
    }
}

// ------------------------------------------------------------------ draw ----

fn draw(f: &mut Frame, app: &mut App) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3), Constraint::Length(1)])
        .split(f.area());

    let (n_secrets, n_grants, secret_lines) = secrets_snapshot(app);

    // Front-request countdown stays visible even while an open menu hides
    // the request modal, so a queued request can't silently run out.
    let deny_in = app
        .pending
        .front()
        .map(|p| {
            format!(
                " · deny in {}",
                format_remaining(app.timeout.saturating_sub(p.received.elapsed()))
            )
        })
        .unwrap_or_default();
    let header = format!(
        " sub rosa · {} secrets · {} grants · {} pending{} · {}",
        n_secrets,
        n_grants,
        app.pending.len(),
        deny_in,
        app.sock,
    );
    f.render_widget(
        Paragraph::new(header).style(Style::default().add_modifier(Modifier::REVERSED)),
        rows[0],
    );

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(34), Constraint::Percentage(66)])
        .split(rows[1]);

    f.render_stateful_widget(
        List::new(secret_lines)
            .block(Block::default().borders(Borders::ALL).title(" secrets "))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED)),
        cols[0],
        &mut app.secret_state,
    );

    let log_height = cols[1].height.saturating_sub(2) as usize;
    let items: Vec<ListItem> = app
        .log
        .iter()
        .rev()
        .take(log_height)
        .rev()
        .map(|l| {
            let style = if l.deny {
                Style::default().fg(Color::Red)
            } else {
                Style::default()
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{} ", l.ts), Style::default().fg(Color::DarkGray)),
                Span::styled(l.msg.clone(), style),
            ]))
        })
        .collect();
    f.render_widget(
        List::new(items).block(Block::default().borders(Borders::ALL).title(" log ")),
        cols[1],
    );

    let help = if matches!(app.mode, UiMode::SecretMenu(_)) {
        " ↑/↓ select · enter apply · esc back"
    } else if !app.pending.is_empty() {
        " ←/→ column · ↑/↓ select · enter apply · n deny"
    } else {
        " ↑/↓ select · space menu · q quit · r reload store · c clear grants"
    };
    f.render_widget(
        Paragraph::new(help).style(Style::default().fg(Color::DarkGray)),
        rows[2],
    );

    // The request modal is drawn (and keyed) only when no user-opened modal
    // is active; requests queue behind the secret menu.
    if !app.pending.is_empty() && matches!(app.mode, UiMode::Idle) {
        draw_modal(f, app);
    }
    if matches!(app.mode, UiMode::SecretMenu(_)) {
        draw_secret_menu(f, app);
    }
}

fn secrets_snapshot(app: &mut App) -> (usize, usize, Vec<ListItem<'static>>) {
    let (names, n_grants, lines) = {
        let mut sh = app.shared.lock().unwrap();
        sh.prune_grants();
        let n_grants = sh.grants.len();
        let now = Instant::now();
        let names: Vec<String> = sh.store.keys().cloned().collect();
        let lines = names
            .iter()
            .map(|name| {
                let mut spans = vec![Span::raw(format!("{name} "))];
                match sh.effective_policy(name) {
                    (Policy::Auto, PolicySource::Config) => {
                        spans.push(Span::styled("auto", Style::default().fg(Color::Yellow)))
                    }
                    (Policy::Confirm, PolicySource::Config) => {
                        spans.push(Span::styled("confirm", Style::default().fg(Color::DarkGray)))
                    }
                    (policy, PolicySource::Override) => {
                        let label = match policy {
                            Policy::Auto => "auto*",
                            Policy::Confirm => "confirm*",
                        };
                        spans.push(Span::styled(
                            label,
                            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
                        ));
                        if let Some(exp) = sh.override_expiry(name) {
                            spans.push(Span::styled(
                                format!(" ({exp})"),
                                Style::default().fg(Color::Magenta),
                            ));
                        }
                    }
                }
                for g in sh.grants.iter().filter(|g| g.name == *name) {
                    let until = match g.until {
                        GrantUntil::Session => "session".to_string(),
                        GrantUntil::At(t) => format_remaining(t.saturating_duration_since(now)),
                    };
                    spans.push(Span::styled(
                        format!(" ●{}:{}", g.scope.label(), until),
                        Style::default().fg(Color::Green),
                    ));
                }
                ListItem::new(Line::from(spans))
            })
            .collect();
        (names, n_grants, lines)
    };
    if names.is_empty() {
        app.cursor = None;
        app.secret_state.select(None);
    } else {
        let idx = app.resolve_cursor(&names);
        app.secret_state.select(Some(idx));
    }
    (names.len(), n_grants, lines)
}

fn draw_secret_menu(f: &mut Frame, app: &mut App) {
    let (name, view) = match &app.mode {
        UiMode::SecretMenu(m) => (m.name.clone(), m.view),
        _ => return,
    };
    let (labels, title) = match view {
        MenuView::Root => {
            let sh = app.shared.lock().unwrap();
            let labels: Vec<String> = menu_root_items(&sh, &name)
                .iter()
                .map(|i| menu_item_label(*i).to_string())
                .collect();
            (labels, format!(" {name} "))
        }
        MenuView::Durations => {
            let cfg_items = duration_items(&app.shared.lock().unwrap().cfg);
            let labels: Vec<String> = cfg_items.iter().map(duration_item_label).collect();
            (labels, format!(" {name} · make auto "))
        }
    };

    let width = labels
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0)
        .max(title.chars().count())
        .max(24) as u16
        + 4;
    let area = centered(f.area(), width, labels.len() as u16 + 2);
    f.render_widget(Clear, area);

    let items: Vec<ListItem> = labels.iter().map(|l| ListItem::new(format!(" {l}"))).collect();
    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Magenta))
                .title(title),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED).add_modifier(Modifier::BOLD));
    if let UiMode::SecretMenu(m) = &mut app.mode {
        let sel = m.state.selected().unwrap_or(0).min(labels.len().saturating_sub(1));
        m.state.select(Some(sel));
        f.render_stateful_widget(list, area, &mut m.state);
    }
}

fn draw_modal(f: &mut Frame, app: &mut App) {
    let actions = action_items(app);
    let (flag_patterns, timeout) = {
        let sh = app.shared.lock().unwrap();
        (sh.cfg.flag_ancestors.clone(), app.timeout)
    };
    let front = app.pending.front().unwrap();
    let remaining = timeout.saturating_sub(front.received.elapsed());
    let flagged = front.peer.flagged(&flag_patterns).join(", ");

    let mut detail: Vec<Line> = vec![
        Line::from(vec![
            Span::raw("  secret : "),
            Span::styled(
                front.name.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(format!("  from   : pid {} (uid {})", front.peer.pid, front.peer.uid)),
        Line::from(format!("  exe    : {}", front.peer.exe)),
        Line::from(format!("  cmd    : {}", front.peer.cmdline)),
    ];
    if !flagged.is_empty() {
        detail.push(Line::from(Span::styled(
            format!("  ⚠ flagged ancestor: {flagged}"),
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )));
    }
    detail.push(Line::from(Span::styled(
        format!(
            "  auto-deny in {}{}",
            format_remaining(remaining),
            if app.pending.len() > 1 {
                format!(" · {} more waiting", app.pending.len() - 1)
            } else {
                String::new()
            }
        ),
        Style::default().fg(Color::DarkGray),
    )));

    // Process tree, root first; the last row is the requester.
    let chain: Vec<&crate::server::peer::Proc> = front.peer.ancestry.iter().rev().collect();
    let proc_items: Vec<ListItem> = if chain.is_empty() {
        vec![ListItem::new(Span::raw(format!("{} (requester)", front.peer.exe)))]
    } else {
        chain
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let hot = flag_patterns.iter().any(|pat| comm_matches(&p.comm, pat));
                let prefix = if i == 0 {
                    String::new()
                } else {
                    format!("{}└ ", " ".repeat((i - 1) * 2))
                };
                let mut spans = vec![
                    Span::raw(prefix),
                    Span::styled(
                        format!("{}({})", p.comm, p.pid),
                        if hot {
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
                        } else {
                            Style::default()
                        },
                    ),
                ];
                if hot {
                    spans.push(Span::styled(" ⚠", Style::default().fg(Color::Red)));
                }
                if i == chain.len() - 1 {
                    spans.push(Span::styled(
                        " (requester)",
                        Style::default().fg(Color::DarkGray),
                    ));
                }
                ListItem::new(Line::from(spans))
            })
            .collect()
    };

    let action_items_r: Vec<ListItem> = actions
        .iter()
        .map(|a| {
            let (label, style) = match a {
                Action::AllowOnce => ("allow once".to_string(), Style::default()),
                Action::AllowFor(_, d) => (format!("allow for {d}"), Style::default()),
                Action::AllowSession => ("allow until agent exits".to_string(), Style::default()),
                Action::Deny => ("deny".to_string(), Style::default().fg(Color::Red)),
            };
            ListItem::new(Span::styled(format!(" {label}"), style))
        })
        .collect();

    let detail_height = detail.len() as u16;
    let list_height = (proc_items.len().max(actions.len()) as u16) + 2; // + column borders
    let area = centered(f.area(), 84, detail_height + list_height + 2);

    f.render_widget(Clear, area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if flagged.is_empty() {
            Color::Cyan
        } else {
            Color::Red
        }))
        .title(" secret request ");
    let inner = block.inner(area);
    f.render_widget(block, area);

    let parts = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(detail_height), Constraint::Min(3)])
        .split(inner);

    f.render_widget(Paragraph::new(detail).wrap(Wrap { trim: false }), parts[0]);

    let menu_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(parts[1]);

    let focus_style = |focused: bool| {
        if focused {
            Style::default().fg(Color::Cyan)
        } else {
            Style::default().fg(Color::DarkGray)
        }
    };
    let highlight = |focused: bool| {
        if focused {
            Style::default()
                .add_modifier(Modifier::REVERSED)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().add_modifier(Modifier::UNDERLINED)
        }
    };

    f.render_stateful_widget(
        List::new(proc_items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(focus_style(app.focus == Col::Procs))
                    .title(" grant to "),
            )
            .highlight_style(highlight(app.focus == Col::Procs)),
        menu_cols[0],
        &mut app.proc_state,
    );
    f.render_stateful_widget(
        List::new(action_items_r)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(focus_style(app.focus == Col::Actions))
                    .title(" action "),
            )
            .highlight_style(highlight(app.focus == Col::Actions)),
        menu_cols[1],
        &mut app.action_state,
    );
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width.saturating_sub(2));
    let h = height.min(area.height.saturating_sub(2));
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}
