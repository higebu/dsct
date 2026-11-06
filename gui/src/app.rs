//! The main window: toolbar, packet table, detail tree, hex dump, the
//! Follow Stream / Stats panel, and a status bar.

use std::path::PathBuf;
use std::time::Duration;

use dsct::session::tree::visible_nodes;
use dsct::session::{FilterOutcome, Session, Tick};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::table::{DataTable, TableEvent, TableState};
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Sizable as _, h_flex, h_resizable, resizable_panel, v_flex,
    v_resizable,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::bottom::{BottomPanel, StreamView};
use crate::format::{self, TimeFormat};
use crate::packet_table::PacketTable;
use crate::{
    CloseBottom, CycleTimeFormat, FocusBytes, FocusDetails, FocusNextPane, FocusPackets,
    FocusPrevPane, Open, SharedSession,
};

/// How often background work (indexing, the in-order pass, filter scans)
/// is driven while there is any; nothing runs while the session is idle.
const TICK_INTERVAL: Duration = Duration::from_millis(16);

/// Key context of the packet table (set by gpui-component).
pub const TABLE_CONTEXT: &str = "DataTable";
/// Key context of the detail tree.
pub const TREE_CONTEXT: &str = "DetailTree";
/// Key context of the hex dump.
pub const HEX_CONTEXT: &str = "HexDump";

/// The panes keyboard focus moves between, in Tab order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    Packets,
    Details,
    Bytes,
}

impl Pane {
    const ORDER: [Pane; 3] = [Pane::Packets, Pane::Details, Pane::Bytes];

    fn step(self, forward: bool) -> Self {
        let i = Self::ORDER.iter().position(|p| *p == self).unwrap_or(0);
        let n = Self::ORDER.len();
        Self::ORDER[if forward {
            (i + 1) % n
        } else {
            (i + n - 1) % n
        }]
    }
}

/// Which detail tree node is selected, what is visible, and where the tree
/// and the hex dump are scrolled.
pub struct TreeView {
    /// Index into the selected packet's tree nodes.
    pub selected: Option<usize>,
    /// Tree nodes shown (not inside a collapsed node), by index.
    pub visible: Vec<usize>,
    /// Byte under the hex dump's keyboard cursor.
    pub hex_cursor: Option<usize>,
    pub tree_scroll: UniformListScrollHandle,
    pub hex_scroll: UniformListScrollHandle,
}

impl TreeView {
    /// Show the newly selected packet of `session` from its top.
    pub fn reset(&mut self, session: &Session) {
        self.selected = None;
        self.hex_cursor = None;
        self.tree_scroll.scroll_to_item(0, ScrollStrategy::Top);
        self.hex_scroll.scroll_to_item(0, ScrollStrategy::Top);
        self.refresh(session);
    }

    /// Recompute the visible nodes after expanding or collapsing some.
    pub fn refresh(&mut self, session: &Session) {
        self.visible = session
            .selected
            .as_ref()
            .map(|sel| visible_nodes(&sel.tree_nodes).map(|(i, _)| i).collect())
            .unwrap_or_default();
    }
}

/// The application window's root view.
pub struct DsctApp {
    pub(crate) session: SharedSession,
    table: Entity<TableState<PacketTable>>,
    filter: Entity<InputState>,
    pub(crate) tree_focus: FocusHandle,
    pub(crate) hex_focus: FocusHandle,
    /// Displayed row of the selected packet.
    selected_row: Option<usize>,
    pub(crate) tree: TreeView,
    pub(crate) bottom: BottomPanel,
    time_format: TimeFormat,
    /// Last error or notice, shown in the status bar.
    message: Option<(String, bool)>,
    /// The filter could not be applied: shown under the filter input.
    filter_error: Option<String>,
    /// Whether background work was running at the last tick, so the status
    /// bar is redrawn once more when it stops.
    busy: bool,
    /// Whether the tick loop is running (see [`Self::ensure_ticking`]).
    ticking: bool,
    _subscriptions: Vec<Subscription>,
}

impl DsctApp {
    /// Create the view, opening `path` when given.
    pub fn new(path: Option<PathBuf>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let session: SharedSession = Default::default();
        let table = cx.new(|cx| TableState::new(PacketTable::new(session.clone()), window, cx));
        let filter = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Filter, e.g. tcp.dst_port == 443 or dns (Enter to apply)")
        });
        let subscriptions = vec![
            cx.subscribe_in(&table, window, |this, _, event: &TableEvent, _, cx| {
                if let TableEvent::SelectRow(row) = event {
                    this.select_row(*row, cx);
                }
            }),
            cx.subscribe_in(&filter, window, |this, state, event: &InputEvent, _, cx| {
                match event {
                    InputEvent::PressEnter { .. } => {
                        let text = state.read(cx).value().to_string();
                        this.apply_filter(&text, cx);
                    }
                    // Editing the filter dismisses its error and updates
                    // the "Enter to apply" hint.
                    InputEvent::Change => {
                        this.filter_error = None;
                        cx.notify();
                    }
                    _ => {}
                }
            }),
        ];

        let mut app = Self {
            session,
            table,
            filter,
            tree_focus: cx.focus_handle(),
            hex_focus: cx.focus_handle(),
            selected_row: None,
            tree: TreeView {
                selected: None,
                visible: Vec::new(),
                hex_cursor: None,
                tree_scroll: UniformListScrollHandle::new(),
                hex_scroll: UniformListScrollHandle::new(),
            },
            bottom: BottomPanel::default(),
            time_format: TimeFormat::default(),
            message: None,
            filter_error: None,
            busy: false,
            ticking: false,
            _subscriptions: subscriptions,
        };
        if let Some(path) = path {
            app.open(path, cx);
        }
        app
    }

    /// Ask for a capture file and open it.
    pub fn prompt_open(&mut self, cx: &mut Context<Self>) {
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Open".into()),
        });
        cx.spawn(async move |this, cx| {
            if let Ok(Ok(Some(paths))) = paths.await
                && let Some(path) = paths.into_iter().next()
            {
                let _ = this.update(cx, |app, cx| app.open(path, cx));
            }
        })
        .detach();
    }

    /// Replace the shown capture with the one at `path`.
    pub fn open(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        match Session::open(&path, Vec::new()) {
            Ok(session) => {
                *self.session.borrow_mut() = Some(session);
                self.selected_row = None;
                self.tree.selected = None;
                self.tree.hex_cursor = None;
                self.tree.visible.clear();
                self.bottom = BottomPanel::default();
                self.message = None;
                self.filter_error = None;
                self.table.update(cx, |table, cx| {
                    table.clear_selection(cx);
                    table.refresh(cx);
                });
                self.ensure_ticking(cx);
            }
            Err(e) => self.message = Some((format!("Cannot open {}: {e}", path.display()), true)),
        }
        cx.notify();
    }

    /// Run [`Self::tick`] every [`TICK_INTERVAL`] until the session has no
    /// background work left. Call after anything that may start some.
    fn ensure_ticking(&mut self, cx: &mut Context<Self>) {
        if self.ticking {
            return;
        }
        self.ticking = true;
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(TICK_INTERVAL).await;
                match this.update(cx, |app, cx| app.tick(cx)) {
                    Ok(true) => {}
                    // Idle, or the window is gone.
                    Ok(false) | Err(_) => break,
                }
            }
        })
        .detach();
    }

    /// Drive the session's background work and refresh what changed.
    ///
    /// Returns whether work is left; when there is none, the tick loop stops
    /// (`ticking` is cleared) until [`Self::ensure_ticking`] starts it again.
    fn tick(&mut self, cx: &mut Context<Self>) -> bool {
        let mut guard = self.session.borrow_mut();
        let Some(session) = guard.as_mut() else {
            self.ticking = false;
            return false;
        };
        let mut changed = false;
        let mut reload = false;
        let mut rows_changed = false;
        // The bottom panel opened and shrank the table.
        let mut panel_opened = false;

        let ordered = session.ordered_tick();
        changed |= ordered.changed;
        reload |= ordered.reload_selected;
        if let Some(e) = ordered.error {
            self.message = Some((
                format!("Error: {e}; dissecting packets on demand instead"),
                true,
            ));
        }

        if session.is_indexing() {
            let before = session.displayed_count();
            if session.index_tick() && self.selected_row.is_none() {
                self.selected_row = Some(0);
                reload = true;
            }
            rows_changed |= session.displayed_count() != before;
            changed = true;
        }

        match session.filter_tick() {
            Tick::Idle => {}
            Tick::Running => changed = true,
            Tick::Done(outcome) => {
                if let FilterOutcome::Failed(msg) = outcome {
                    self.filter_error = Some(msg);
                }
                self.selected_row = (session.displayed_count() > 0).then_some(0);
                reload = true;
                rows_changed = true;
            }
        }
        match session.stream_tick() {
            Tick::Idle => {}
            Tick::Running => changed = true,
            Tick::Done(stream) => {
                self.bottom.show_stream(StreamView {
                    title: stream.title,
                    lines: stream
                        .lines
                        .into_iter()
                        .map(|l| (l.text, l.is_client))
                        .collect(),
                });
                changed = true;
                panel_opened = true;
            }
        }
        match session.stats_tick() {
            Tick::Idle => {}
            Tick::Running => changed = true,
            Tick::Done(output) => {
                self.bottom.show_stats(output);
                changed = true;
                panel_opened = true;
            }
        }

        if reload {
            session.load_packet(self.selected_row.unwrap_or(0));
            self.tree.reset(session);
        }
        let busy = session.is_indexing()
            || session.ordered_needs_tick()
            || session.filter_running()
            || session.stream_running()
            || session.stats_running();
        changed |= busy != self.busy;
        self.busy = busy;
        self.ticking = busy;
        drop(guard);

        if rows_changed || reload {
            let selected = self.selected_row;
            self.table.update(cx, |table, cx| {
                table.refresh(cx);
                match selected {
                    Some(row) if table.selected_row() != Some(row) => {
                        table.set_selected_row(row, cx)
                    }
                    None => table.clear_selection(cx),
                    _ => {}
                }
            });
        }
        if panel_opened && let Some(row) = self.selected_row {
            // Keep the selected packet in view above the panel.
            self.table
                .update(cx, |table, cx| table.scroll_to_row(row, cx));
        }
        if changed || rows_changed || reload {
            cx.notify();
        }
        busy
    }

    /// Show the packet at displayed `row`.
    fn select_row(&mut self, row: usize, cx: &mut Context<Self>) {
        if self.selected_row == Some(row) {
            return;
        }
        self.selected_row = Some(row);
        let mut guard = self.session.borrow_mut();
        if let Some(session) = guard.as_mut() {
            session.load_packet(row);
            self.tree.reset(session);
        }
        drop(guard);
        // A placeholder waits for the in-order pass.
        self.ensure_ticking(cx);
        cx.notify();
    }

    fn apply_filter(&mut self, text: &str, cx: &mut Context<Self>) {
        let mut guard = self.session.borrow_mut();
        let Some(session) = guard.as_mut() else {
            return;
        };
        self.filter_error = None;
        match session.apply_filter(text) {
            Err(msg) => self.filter_error = Some(msg),
            Ok(None) => {
                drop(guard);
                self.ensure_ticking(cx);
            }
            Ok(Some(outcome)) => {
                if let FilterOutcome::Failed(msg) = outcome {
                    self.filter_error = Some(msg);
                }
                self.selected_row = (session.displayed_count() > 0).then_some(0);
                session.load_packet(0);
                self.tree.reset(session);
                drop(guard);
                let selected = self.selected_row;
                self.table.update(cx, |table, cx| {
                    table.refresh(cx);
                    match selected {
                        Some(row) => table.set_selected_row(row, cx),
                        None => table.clear_selection(cx),
                    }
                });
            }
        }
        cx.notify();
    }

    fn follow_stream(&mut self, cx: &mut Context<Self>) {
        let started = self
            .session
            .borrow_mut()
            .as_mut()
            .map(Session::start_follow_stream);
        self.start_job(started, cx);
    }

    fn stats(&mut self, cx: &mut Context<Self>) {
        let started = self.session.borrow_mut().as_mut().map(Session::start_stats);
        self.start_job(started, cx);
    }

    /// Report a job that failed to start, or drive the one that did.
    fn start_job(&mut self, started: Option<Result<(), String>>, cx: &mut Context<Self>) {
        match started {
            Some(Ok(())) => self.ensure_ticking(cx),
            Some(Err(msg)) => self.message = Some((msg, true)),
            None => {}
        }
        cx.notify();
    }

    fn cycle_time_format(&mut self, cx: &mut Context<Self>) {
        self.time_format = self.time_format.next();
        let time_format = self.time_format;
        self.table.update(cx, |table, cx| {
            table.delegate_mut().time_format = time_format;
            table.refresh(cx);
        });
        cx.notify();
    }

    // -- Focus ----------------------------------------------------------------

    fn table_focus(&self, cx: &App) -> FocusHandle {
        self.table.read(cx).focus_handle(cx)
    }

    /// The pane holding keyboard focus, if any.
    fn focused_pane(&self, window: &Window, cx: &App) -> Option<Pane> {
        if self.table_focus(cx).contains_focused(window, cx) {
            Some(Pane::Packets)
        } else if self.tree_focus.contains_focused(window, cx) {
            Some(Pane::Details)
        } else if self.hex_focus.contains_focused(window, cx) {
            Some(Pane::Bytes)
        } else {
            None
        }
    }

    pub(crate) fn focus_pane(&mut self, pane: Pane, window: &mut Window, cx: &mut Context<Self>) {
        let handle = match pane {
            Pane::Packets => self.table_focus(cx),
            Pane::Details => self.tree_focus.clone(),
            Pane::Bytes => self.hex_focus.clone(),
        };
        window.focus(&handle, cx);
        cx.notify();
    }

    fn step_pane(&mut self, forward: bool, window: &mut Window, cx: &mut Context<Self>) {
        let pane = self
            .focused_pane(window, cx)
            .map_or(Pane::Packets, |p| p.step(forward));
        self.focus_pane(pane, window, cx);
    }

    /// Border of a pane: the focus ring color while it holds focus.
    pub(crate) fn pane_border(&self, pane: Pane, window: &Window, cx: &App) -> Hsla {
        if self.focused_pane(window, cx) == Some(pane) {
            cx.theme().blue
        } else {
            transparent_black()
        }
    }

    // -- Rendering ------------------------------------------------------------

    fn render_toolbar(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let (has_session, has_packet, applied) = match self.session.borrow().as_ref() {
            Some(s) => (true, s.selected.is_some(), s.applied_filter.clone()),
            None => (false, false, String::new()),
        };
        // The text in the input is not the filter in effect until Enter.
        let edited = has_session && *self.filter.read(cx).value() != *applied;
        let theme = cx.theme();
        let (error, error_border, muted, border) = (
            theme.red,
            theme.danger,
            theme.muted_foreground,
            theme.border,
        );
        let filter = h_flex()
            .flex_1()
            .gap_2()
            .child(
                div()
                    .flex_1()
                    .rounded(px(6.))
                    .when(self.filter_error.is_some(), |d| {
                        d.border_1().border_color(error_border)
                    })
                    .child(Input::new(&self.filter).small()),
            )
            .when(edited && self.filter_error.is_none(), |d| {
                d.child(div().text_xs().text_color(muted).child("Enter to apply"))
            });
        let toolbar = h_flex()
            .gap_2()
            .p_2()
            .child(
                Button::new("open")
                    .label("Open…")
                    .small()
                    .on_click(cx.listener(|this, _, _, cx| this.prompt_open(cx))),
            )
            .child(filter)
            .child(
                Button::new("time-format")
                    .label(format!("Time: {}", self.time_format.label()))
                    .small()
                    .ghost()
                    .tooltip(format!("Change the time format ({})", crate::shortcut("T")))
                    .disabled(!has_session)
                    .on_click(cx.listener(|this, _, _, cx| this.cycle_time_format(cx))),
            )
            .child(div().w(px(1.)).h(px(20.)).bg(border))
            .child(
                Button::new("follow")
                    .label("Follow Stream")
                    .small()
                    .tooltip("Payload of the selected packet's TCP/UDP/SCTP stream")
                    .disabled(!has_packet)
                    .on_click(cx.listener(|this, _, _, cx| this.follow_stream(cx))),
            )
            .child(
                Button::new("stats")
                    .label("Stats")
                    .small()
                    .tooltip("Statistics of the displayed packets")
                    .disabled(!has_session)
                    .on_click(cx.listener(|this, _, _, cx| this.stats(cx))),
            );
        v_flex()
            .border_b_1()
            .border_color(border)
            .child(toolbar)
            .children(self.filter_error.as_ref().map(|msg| {
                div()
                    .px_2()
                    .pb_2()
                    .text_sm()
                    .text_color(error)
                    .child(format!("Filter error: {msg}"))
            }))
    }

    /// Shown instead of the panes until a capture is open.
    fn render_empty(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .gap_3()
            .child(
                div()
                    .text_xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Open a capture file"),
            )
            .child(
                div()
                    .text_color(theme.muted_foreground)
                    .child("pcap or pcapng — or drop a file anywhere in this window"),
            )
            .child(
                Button::new("open-empty")
                    .label("Open…")
                    .primary()
                    .on_click(cx.listener(|this, _, _, cx| this.prompt_open(cx))),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child(crate::shortcut("O")),
            )
    }

    fn render_status(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let mut parts: Vec<String> = Vec::new();
        if let Some(session) = self.session.borrow().as_ref() {
            parts.push(session.file_name.clone());
            parts.push(if session.applied_filter.is_empty() {
                format!("{} packets", session.total_count())
            } else {
                format!(
                    "{} / {} packets",
                    session.displayed_count(),
                    session.total_count()
                )
            });
            if let Some(bg) = &session.bg_indexer {
                parts.push(format!("Indexing {}%", format::percent(bg.fraction())));
            }
            if let Some(fraction) = session.filter_fraction() {
                parts.push(format!("Filtering {}%", format::percent(fraction)));
            }
            if session.stream_running() {
                parts.push("Following stream…".to_string());
            }
            if session.stats_running() {
                parts.push("Collecting stats…".to_string());
            }
            if session.ordered_needs_tick() {
                parts.push("Dissecting in capture order…".to_string());
            }
        }
        let theme = cx.theme();
        h_flex()
            .px_2()
            .py_1()
            .gap_4()
            .border_t_1()
            .border_color(theme.border)
            .text_color(theme.muted_foreground)
            .text_sm()
            .children(parts)
            .children(self.message.as_ref().map(|(msg, error)| {
                div()
                    .when(*error, |d| d.text_color(theme.red))
                    .child(if *error {
                        format!("⚠ {msg}")
                    } else {
                        msg.clone()
                    })
            }))
    }
}

impl Render for DsctApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let has_session = self.session.borrow().is_some();
        let toolbar = self.render_toolbar(cx);
        let status = self.render_status(cx);

        let body = if has_session {
            let table_border = self.pane_border(Pane::Packets, window, cx);
            let tree = self.render_tree(window, cx);
            let hex = self.render_hex(window, cx);
            let bottom = self.render_bottom(cx);
            let mut main = v_resizable("main")
                .child(
                    resizable_panel().size(px(320.)).child(
                        div()
                            .size_full()
                            .border_1()
                            .border_color(table_border)
                            .child(DataTable::new(&self.table)),
                    ),
                )
                .child(
                    resizable_panel().child(
                        h_resizable("details")
                            .child(resizable_panel().size(px(560.)).child(tree))
                            .child(resizable_panel().child(hex)),
                    ),
                );
            if let Some(bottom) = bottom {
                main = main.child(resizable_panel().size(px(320.)).child(bottom));
            }
            div().size_full().child(main).into_any_element()
        } else {
            self.render_empty(cx).into_any_element()
        };

        let theme = cx.theme();
        v_flex()
            .id("dsct")
            .key_context("DsctApp")
            .size_full()
            .bg(theme.background)
            .text_color(theme.foreground)
            .on_action(cx.listener(|this, _: &Open, _, cx| this.prompt_open(cx)))
            .on_action(cx.listener(|this, _: &CycleTimeFormat, _, cx| {
                if this.session.borrow().is_some() {
                    this.cycle_time_format(cx);
                }
            }))
            .on_action(
                cx.listener(|this, _: &FocusNextPane, window, cx| this.step_pane(true, window, cx)),
            )
            .on_action(
                cx.listener(|this, _: &FocusPrevPane, window, cx| {
                    this.step_pane(false, window, cx)
                }),
            )
            .on_action(cx.listener(|this, _: &FocusPackets, window, cx| {
                this.focus_pane(Pane::Packets, window, cx)
            }))
            .on_action(cx.listener(|this, _: &FocusDetails, window, cx| {
                this.focus_pane(Pane::Details, window, cx)
            }))
            .on_action(cx.listener(|this, _: &FocusBytes, window, cx| {
                this.focus_pane(Pane::Bytes, window, cx)
            }))
            .on_action(cx.listener(|this, _: &CloseBottom, _, cx| {
                this.bottom.open = false;
                cx.notify();
            }))
            .drag_over::<ExternalPaths>(|style, _, _, cx| style.bg(cx.theme().drop_target))
            .on_drop(cx.listener(|this, paths: &ExternalPaths, _, cx| {
                if let Some(path) = paths.paths().first() {
                    this.open(path.clone(), cx);
                }
            }))
            .child(toolbar)
            .child(div().flex_1().min_h_0().child(body))
            .child(status)
    }
}
