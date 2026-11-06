//! The main window: toolbar, packet table, detail tree, hex dump, an
//! optional Follow Stream / Stats panel, and a status bar.

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

use crate::format;
use crate::packet_table::PacketTable;
use crate::{Open, SharedSession};

/// How often background work (indexing, the in-order pass, filter scans)
/// is driven while there is any; nothing runs while the session is idle.
const TICK_INTERVAL: Duration = Duration::from_millis(16);

/// Contents of the bottom panel.
enum BottomPanel {
    /// A followed stream: title and lines, `true` for client → server.
    Stream {
        title: String,
        lines: Vec<(String, bool)>,
    },
    /// Stats as pretty-printed JSON lines.
    Stats(Vec<String>),
}

/// Which detail tree nodes are shown and selected, and where the hex dump
/// is scrolled.
struct TreeView {
    /// Index into the selected packet's tree nodes.
    selected: Option<usize>,
    /// Tree nodes shown (not inside a collapsed node), by index.
    visible: Vec<usize>,
    hex_scroll: UniformListScrollHandle,
}

impl TreeView {
    /// Show the newly selected packet of `session` from its top.
    fn reset(&mut self, session: &Session) {
        self.selected = None;
        self.hex_scroll.scroll_to_item(0, ScrollStrategy::Top);
        self.refresh(session);
    }

    /// Recompute the visible nodes after expanding or collapsing one.
    fn refresh(&mut self, session: &Session) {
        self.visible = session
            .selected
            .as_ref()
            .map(|sel| visible_nodes(&sel.tree_nodes).map(|(i, _)| i).collect())
            .unwrap_or_default();
    }
}

/// The application window's root view.
pub struct DsctApp {
    session: SharedSession,
    table: Entity<TableState<PacketTable>>,
    filter: Entity<InputState>,
    /// Displayed row of the selected packet.
    selected_row: Option<usize>,
    tree: TreeView,
    bottom: Option<BottomPanel>,
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
            selected_row: None,
            tree: TreeView {
                selected: None,
                visible: Vec::new(),
                hex_scroll: UniformListScrollHandle::new(),
            },
            bottom: None,
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
                self.tree.visible.clear();
                self.bottom = None;
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
                self.bottom = Some(BottomPanel::Stream {
                    title: stream.title,
                    lines: stream
                        .lines
                        .into_iter()
                        .map(|l| (l.text, l.is_client))
                        .collect(),
                });
                changed = true;
            }
        }
        match session.stats_tick() {
            Tick::Idle => {}
            Tick::Running => changed = true,
            Tick::Done(output) => {
                let text = serde_json::to_string_pretty(&output)
                    .unwrap_or_else(|e| format!("cannot format stats: {e}"));
                self.bottom = Some(BottomPanel::Stats(text.lines().map(String::from).collect()));
                changed = true;
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

    /// Select tree node `idx`, highlighting its bytes in the hex dump.
    fn select_node(&mut self, idx: usize, cx: &mut Context<Self>) {
        self.tree.selected = Some(idx);
        if let Some(range) = self.selected_byte_range() {
            self.tree.hex_scroll.scroll_to_item(
                format::first_highlighted_line(&range),
                ScrollStrategy::Center,
            );
        }
        cx.notify();
    }

    /// Expand or collapse tree node `idx`.
    fn toggle_node(&mut self, idx: usize, cx: &mut Context<Self>) {
        let mut guard = self.session.borrow_mut();
        if let Some(session) = guard.as_mut() {
            if let Some(node) = session
                .selected
                .as_mut()
                .and_then(|sel| sel.tree_nodes.get_mut(idx))
            {
                node.expanded = !node.expanded;
            }
            self.tree.refresh(session);
        }
        cx.notify();
    }

    fn selected_byte_range(&self) -> Option<std::ops::Range<usize>> {
        let idx = self.tree.selected?;
        let guard = self.session.borrow();
        let node = guard.as_ref()?.selected.as_ref()?.tree_nodes.get(idx)?;
        Some(node.byte_range.clone())
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
        let (danger, muted, border) = (theme.danger, theme.muted_foreground, theme.border);
        let filter = h_flex()
            .flex_1()
            .gap_2()
            .child(
                div()
                    .flex_1()
                    .rounded(px(6.))
                    .when(self.filter_error.is_some(), |d| {
                        d.border_1().border_color(danger)
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
                Button::new("follow")
                    .label("Follow Stream")
                    .small()
                    .disabled(!has_packet)
                    .on_click(cx.listener(|this, _, _, cx| this.follow_stream(cx))),
            )
            .child(
                Button::new("stats")
                    .label("Stats")
                    .small()
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
                    .text_color(danger)
                    .child(format!("Filter error: {msg}"))
            }))
    }

    fn render_tree(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let count = self.tree.visible.len();
        v_flex().size_full().child(
            uniform_list(
                "detail-tree",
                count,
                cx.processor(|this, range: std::ops::Range<usize>, _, cx| {
                    let guard = this.session.borrow();
                    let nodes = guard
                        .as_ref()
                        .and_then(|s| s.selected.as_ref())
                        .map(|sel| &sel.tree_nodes[..])
                        .unwrap_or(&[]);
                    let theme = cx.theme();
                    let mut rows = Vec::with_capacity(range.len());
                    for row in range {
                        let Some(&idx) = this.tree.visible.get(row) else {
                            continue;
                        };
                        let Some(node) = nodes.get(idx) else {
                            continue;
                        };
                        let chevron = match (node.children_count > 0, node.expanded) {
                            (false, _) => " ",
                            (true, true) => "▼",
                            (true, false) => "▶",
                        };
                        let selected = this.tree.selected == Some(idx);
                        rows.push(
                            h_flex()
                                .id(("node", idx))
                                .w_full()
                                .px_2()
                                .pl(px(8. + node.depth as f32 * 14.))
                                .gap_1()
                                .when(selected, |d| d.bg(theme.selection))
                                .when(node.is_layer, |d| d.font_weight(FontWeight::SEMIBOLD))
                                .child(
                                    div()
                                        .id(("toggle", idx))
                                        .w(px(14.))
                                        .text_color(theme.muted_foreground)
                                        .child(chevron)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            // Toggling is not also a click on the row.
                                            cx.stop_propagation();
                                            this.toggle_node(idx, cx)
                                        })),
                                )
                                .child(div().whitespace_nowrap().child(node.label.clone()))
                                .on_click(cx.listener(move |this, event: &ClickEvent, _, cx| {
                                    if event.click_count() == 2 {
                                        this.toggle_node(idx, cx);
                                    }
                                    this.select_node(idx, cx);
                                })),
                        );
                    }
                    rows
                }),
            )
            .size_full(),
        )
    }

    fn render_hex(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let lines = self
            .session
            .borrow()
            .as_ref()
            .and_then(|s| s.selected_raw_bytes())
            .map_or(0, |data| format::hex_line_count(data.len()));
        let mono = cx.theme().mono_font_family.clone();
        v_flex().size_full().font_family(mono).child(
            uniform_list(
                "hex-dump",
                lines,
                cx.processor(|this, range: std::ops::Range<usize>, _, cx| {
                    let highlight = this.selected_byte_range();
                    let guard = this.session.borrow();
                    let data = guard
                        .as_ref()
                        .and_then(|s| s.selected_raw_bytes())
                        .unwrap_or(&[]);
                    let theme = cx.theme();
                    range
                        .map(|line| {
                            let line = format::hex_line(data, line, highlight.as_ref());
                            h_flex()
                                .px_2()
                                .gap_3()
                                .child(div().text_color(theme.muted_foreground).child(line.offset))
                                .child(h_flex().gap_1().children(line.cells.iter().map(|c| {
                                    div()
                                        .when(c.highlighted, |d| d.bg(theme.selection))
                                        .child(c.hex.clone())
                                })))
                                .child(h_flex().children(line.cells.iter().map(|c| {
                                    div()
                                        .when(c.highlighted, |d| d.bg(theme.selection))
                                        .child(c.ascii.to_string())
                                })))
                        })
                        .collect::<Vec<_>>()
                }),
            )
            .track_scroll(&self.tree.hex_scroll)
            .size_full(),
        )
    }

    fn render_bottom(&mut self, cx: &mut Context<Self>) -> Option<impl IntoElement + use<>> {
        let bottom = self.bottom.as_ref()?;
        let title = match bottom {
            BottomPanel::Stream { title, .. } => title.clone(),
            BottomPanel::Stats(_) => "Stats".to_string(),
        };
        let count = match bottom {
            BottomPanel::Stream { lines, .. } => lines.len(),
            BottomPanel::Stats(lines) => lines.len(),
        };
        let mono = cx.theme().mono_font_family.clone();
        Some(
            v_flex()
                .size_full()
                .child(
                    h_flex()
                        .px_2()
                        .py_1()
                        .gap_2()
                        .border_b_1()
                        .border_color(cx.theme().border)
                        .child(
                            div()
                                .flex_1()
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(title),
                        )
                        .child(
                            Button::new("close-bottom")
                                .label("Close")
                                .xsmall()
                                .ghost()
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.bottom = None;
                                    cx.notify();
                                })),
                        ),
                )
                .child(
                    uniform_list(
                        "bottom-lines",
                        count,
                        cx.processor(|this, range: std::ops::Range<usize>, _, cx| {
                            let theme = cx.theme();
                            let Some(bottom) = this.bottom.as_ref() else {
                                return Vec::new();
                            };
                            range
                                .filter_map(|i| match bottom {
                                    BottomPanel::Stream { lines, .. } => {
                                        let (text, client) = lines.get(i)?;
                                        Some(
                                            div()
                                                .px_2()
                                                .whitespace_nowrap()
                                                .text_color(if *client {
                                                    theme.red
                                                } else {
                                                    theme.blue
                                                })
                                                .child(text.clone()),
                                        )
                                    }
                                    BottomPanel::Stats(lines) => Some(
                                        div()
                                            .px_2()
                                            .whitespace_nowrap()
                                            .child(lines.get(i)?.clone()),
                                    ),
                                })
                                .collect::<Vec<_>>()
                        }),
                    )
                    .font_family(mono)
                    .size_full(),
                ),
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
        } else {
            parts.push("No capture open — use Open… or drop a file".to_string());
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
                    .when(*error, |d| d.text_color(theme.danger))
                    .child(msg.clone())
            }))
    }
}

impl Render for DsctApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let toolbar = self.render_toolbar(cx);
        let tree = self.render_tree(cx);
        let hex = self.render_hex(cx);
        let bottom = self.render_bottom(cx);
        let status = self.render_status(cx);
        let theme = cx.theme();

        let mut main = v_resizable("main")
            .child(
                resizable_panel()
                    .size(px(320.))
                    .child(DataTable::new(&self.table).stripe(true)),
            )
            .child(
                resizable_panel().child(
                    h_resizable("details")
                        .child(resizable_panel().size(px(560.)).child(tree))
                        .child(resizable_panel().child(hex)),
                ),
            );
        if let Some(bottom) = bottom {
            main = main.child(resizable_panel().size(px(200.)).child(bottom));
        }

        v_flex()
            .id("dsct")
            .size_full()
            .bg(theme.background)
            .text_color(theme.foreground)
            .on_action(cx.listener(|this, _: &Open, _, cx| this.prompt_open(cx)))
            .on_drop(cx.listener(|this, paths: &ExternalPaths, _, cx| {
                if let Some(path) = paths.paths().first() {
                    this.open(path.clone(), cx);
                }
            }))
            .child(toolbar)
            .child(div().flex_1().min_h_0().child(main))
            .child(status)
    }
}
