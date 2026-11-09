//! The main window: title bar, sidebar, packet table, detail tree, hex
//! dump, the Follow Stream / Stats dock, a status bar, and the command
//! palette over them.

use std::path::PathBuf;
use std::time::Duration;

use dsct::session::tree::visible_nodes;
use dsct::session::{FilterOutcome, Session, Tick};
use gpui_kit::assets::IconName as AssetIcon;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::table::TableState;
use gpui_kit::component::{
    Disableable as _, Icon, IconName, ResizableState, Sizable as _, TitleBar, h_flex, h_resizable,
    resizable_panel, v_flex, v_resizable,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::bottom::{BottomPanel, BottomTab};
use crate::decode_as::{DecodeAsPanel, Rule};
use crate::format::{self, TimeFormat};
use crate::layout::Layout;
use crate::marks::ExportSet;
use crate::packet_table::PacketTable;
use crate::palette::{Command, PaletteState};
use crate::sequence::SequenceView;
use crate::sidebar::FieldsPanel;
use crate::tabs::Slot;
use crate::timeline::{BUCKETS, Timeline};
use crate::{
    CloseBottom, CloseTab, CycleTimeFormat, ExportDisplayed, ExportMarked, FocusBytes,
    FocusDetails, FocusNextPane, FocusPackets, FocusPrevPane, FollowStream, NextTab, Open,
    OpenPalette, PrevTab, SharedSession, ShowStats, ToggleDock, ToggleMark, ToggleSidebar, theme,
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
#[derive(Default)]
pub struct TreeView {
    /// Index into the selected packet's tree nodes.
    pub selected: Option<usize>,
    /// Tree nodes shown (not inside a collapsed node), by index.
    pub visible: Vec<usize>,
    /// Summary beside each protocol layer, in layer order.
    pub summaries: Vec<Option<String>>,
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
        self.summaries = session
            .selected
            .as_ref()
            .map(|sel| crate::summary::layer_summaries(&sel.packet))
            .unwrap_or_default();
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
    pub(crate) table: Entity<TableState<PacketTable>>,
    pub(crate) filter: Entity<InputState>,
    /// Holds focus when no pane does, so shortcuts reach the window.
    root_focus: FocusHandle,
    pub(crate) tree_focus: FocusHandle,
    pub(crate) hex_focus: FocusHandle,
    /// Displayed row of the selected packet.
    pub(crate) selected_row: Option<usize>,
    pub(crate) tree: TreeView,
    pub(crate) bottom: BottomPanel,
    pub(crate) fields: FieldsPanel,
    pub(crate) timeline: Timeline,
    pub(crate) palette: Option<PaletteState>,
    sidebar_open: bool,
    pub(crate) time_format: TimeFormat,
    /// Last error or notice, shown in the status bar.
    pub(crate) message: Option<(String, bool)>,
    /// The filter could not be applied: shown under the filter input.
    pub(crate) filter_error: Option<String>,
    /// Open captures in tab order: [`Slot::Active`] is the one whose state
    /// is in the fields above. Empty until a capture is opened.
    pub(crate) tabs: Vec<Slot>,
    /// Subscriptions to the active tab's table and filter input.
    pub(crate) tab_subscriptions: Vec<Subscription>,
    /// A filter applied in one tab is applied in every tab.
    pub(crate) filter_all: bool,
    /// The tab shown beside the active one (split view).
    pub(crate) split: Option<usize>,
    /// In a split view, selecting a packet marks the nearest in time on the
    /// other side.
    pub(crate) linked: bool,
    /// Which packet is marked on the other side, and how far in time.
    pub(crate) link_note: Option<String>,
    /// The temporary file of the active tab when it is a merged capture.
    pub(crate) merged_file: Option<tempfile::TempPath>,
    /// Decode As rules, applied in every tab.
    pub(crate) decode_rules: Vec<Rule>,
    /// The open Decode As panel.
    pub(crate) decode_panel: Option<DecodeAsPanel>,
    /// Highlighting the sequence of the selected packet.
    pub(crate) sequence: SequenceView,
    /// Where the panes go and their sizes.
    pub(crate) layout: Layout,
    /// Bumped on every layout change, so only the last one is saved.
    pub(crate) layout_generation: u64,
    /// Protocols Decode As can choose (registry names), read when the
    /// panel first opens.
    pub(crate) protocols: Vec<String>,
    /// Whether background work was running at the last tick, so the status
    /// bar is redrawn once more when it stops.
    busy: bool,
    /// Whether the tick loop is running (see [`Self::ensure_ticking`]).
    ticking: bool,
    _subscriptions: Vec<Subscription>,
}

impl DsctApp {
    /// Create the view, opening each of `paths` in a tab.
    pub fn new(paths: Vec<PathBuf>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let tab = Self::new_tab_state(window, cx);
        let field_search = cx.new(|cx| InputState::new(window, cx).placeholder("Search fields"));
        let subscriptions =
            vec![
                cx.subscribe_in(&field_search, window, |_, _, event: &InputEvent, _, cx| {
                    if let InputEvent::Change = event {
                        cx.notify();
                    }
                }),
            ];

        let root_focus = cx.focus_handle();
        window.focus(&root_focus, cx);
        let mut app = Self {
            session: tab.session,
            table: tab.table,
            filter: tab.filter,
            root_focus,
            tree_focus: cx.focus_handle(),
            hex_focus: cx.focus_handle(),
            selected_row: None,
            tree: tab.tree,
            bottom: tab.bottom,
            fields: FieldsPanel::new(field_search),
            timeline: tab.timeline,
            palette: None,
            sidebar_open: true,
            time_format: TimeFormat::default(),
            message: None,
            filter_error: None,
            busy: false,
            ticking: false,
            tabs: Vec::new(),
            tab_subscriptions: tab.subscriptions,
            filter_all: false,
            split: None,
            linked: true,
            link_note: None,
            merged_file: None,
            decode_rules: Vec::new(),
            decode_panel: None,
            sequence: SequenceView::default(),
            layout: Layout::load(),
            layout_generation: 0,
            protocols: Vec::new(),
            _subscriptions: subscriptions,
        };
        app.open_paths(paths, window, cx);
        app
    }

    /// Ask for capture files and open each in a tab.
    pub fn prompt_open(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: true,
            prompt: Some("Open".into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(paths))) = paths.await {
                let _ = this.update_in(cx, |app, window, cx| app.open_paths(paths, window, cx));
            }
        })
        .detach();
    }

    pub(crate) fn reset_views(&mut self, cx: &mut Context<Self>) {
        self.selected_row = None;
        self.tree.selected = None;
        self.tree.hex_cursor = None;
        self.tree.visible.clear();
        self.tree.summaries.clear();
        self.bottom = BottomPanel::default();
        self.fields.reset();
        self.timeline.histogram = None;
        self.timeline.stale = true;
        self.message = None;
        self.filter_error = None;
        self.table.update(cx, |table, cx| {
            table.delegate_mut().selected = None;
            table.clear_selection(cx);
            table.refresh(cx);
        });
    }

    /// Run [`Self::tick`] every [`TICK_INTERVAL`] until the session has no
    /// background work left. Call after anything that may start some.
    pub(crate) fn ensure_ticking(&mut self, cx: &mut Context<Self>) {
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

    /// Recount the sidebar's field values and recompute the chart when they
    /// no longer match the displayed packets, once those are known (the
    /// capture indexed and no filter scan running).
    ///
    /// Returns the error of a job that could not start.
    fn start_field_jobs(
        fields: &mut FieldsPanel,
        timeline: &mut Timeline,
        session: &mut Session,
    ) -> Option<String> {
        if session.is_indexing() || session.filter_running() {
            return None;
        }
        let mut error = None;
        if fields.stale && !session.field_stats_running() {
            fields.stale = false;
            error = session
                .start_field_stats(fields.sample.sample(fields.spread))
                .err();
        }
        if timeline.stale && !session.histogram_running() {
            timeline.stale = false;
            match session.start_histogram(timeline.split.clone(), BUCKETS) {
                Ok(histogram) => timeline.histogram = Some(histogram),
                Err(msg) => error = Some(msg),
            }
        }
        error
    }

    /// The displayed packets changed: recount the sidebar and the chart.
    pub(crate) fn invalidate_field_jobs(
        fields: &mut FieldsPanel,
        timeline: &mut Timeline,
        session: &mut Session,
    ) {
        session.cancel_field_stats();
        session.cancel_histogram();
        fields.stale = true;
        timeline.stale = true;
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
                self.bottom.show_stream(stream);
                changed = true;
                panel_opened = true;
            }
        }
        match session.stats_tick() {
            Tick::Idle => {}
            Tick::Running => changed = true,
            Tick::Done(output) => {
                self.bottom.show_stats(output);
                panel_opened = true;
                changed = true;
            }
        }
        if let Tick::Done(stats) = session.field_stats_tick() {
            self.fields.stats = Some(stats);
            changed = true;
        }
        if let Tick::Done(histogram) = session.histogram_tick() {
            self.timeline.histogram = Some(histogram);
            changed = true;
        }
        if self.fields.stale || self.timeline.stale {
            if let Some(msg) = Self::start_field_jobs(&mut self.fields, &mut self.timeline, session)
            {
                self.message = Some((msg, true));
            }
            changed = true;
        }

        let mut sequence_changed = false;
        if !matches!(session.sequence_tick(), Tick::Idle) {
            sequence_changed = true;
        }
        if session.problems().is_none() {
            session.start_problems();
        }
        if !matches!(session.problems_tick(), Tick::Idle) {
            // New marks in the packet list.
            sequence_changed = true;
            changed = true;
        }
        if reload {
            session.load_packet(self.selected_row.unwrap_or(0));
            self.tree.reset(session);
        }
        let displayed = session.displayed_count();
        let busy = session.is_indexing()
            || session.ordered_needs_tick()
            || session.filter_running()
            || session.stream_running()
            || session.stats_running()
            || session.field_stats_running()
            || session.histogram_running()
            || session.sequence().is_some_and(|s| !s.complete(displayed))
            || session.problems().is_some_and(|s| !s.complete(displayed))
            // Field jobs wait for indexing or a filter scan to end.
            || self.fields.stale
            || self.timeline.stale;
        changed |= busy != self.busy;
        self.busy = busy;
        drop(guard);

        // Captures in other tabs keep indexing; their tab shows the count.
        let parked = self.tick_parked();
        changed |= parked;
        self.ticking = busy || parked;

        if rows_changed || reload {
            self.sync_table_selection(cx);
        }
        if rows_changed || (reload && self.sequence.keys.is_none()) {
            // Another packet is selected after a filter, or the selected
            // packet's keys came with the in-order pass.
            self.update_sequence(cx);
        } else if sequence_changed {
            self.refresh_table(cx);
        }
        if panel_opened && let Some(row) = self.selected_row {
            // Keep the selected packet in view above the panel.
            self.table
                .update(cx, |table, cx| table.scroll_to_row(row, cx));
        }
        if changed || rows_changed || reload {
            cx.notify();
        }
        self.ticking
    }

    /// Refresh the table's rows and show `selected_row` as selected.
    pub(crate) fn sync_table_selection(&mut self, cx: &mut Context<Self>) {
        let selected = self.selected_row;
        self.table.update(cx, |table, cx| {
            table.delegate_mut().selected = selected;
            table.refresh(cx);
            match selected {
                Some(row) if table.selected_row() != Some(row) => table.set_selected_row(row, cx),
                None => table.clear_selection(cx),
                _ => {}
            }
        });
    }

    /// Show the packet at displayed `row`.
    pub(crate) fn select_row(&mut self, row: usize, cx: &mut Context<Self>) {
        if self.selected_row == Some(row) {
            return;
        }
        self.selected_row = Some(row);
        self.table
            .update(cx, |table, _| table.delegate_mut().selected = Some(row));
        let mut guard = self.session.borrow_mut();
        if let Some(session) = guard.as_mut() {
            session.load_packet(row);
            self.tree.reset(session);
        }
        drop(guard);
        self.update_link(cx);
        self.update_sequence(cx);
        // A placeholder waits for the in-order pass.
        self.ensure_ticking(cx);
        cx.notify();
    }

    /// Select packet `number` (1-based) if it is displayed.
    pub(crate) fn go_to_packet(&mut self, number: u64, cx: &mut Context<Self>) {
        let row = self.session.borrow().as_ref().and_then(|s| {
            let pkt_idx = usize::try_from(number).ok()?.checked_sub(1)?;
            s.filtered
                .contains(pkt_idx)
                .then(|| s.filtered.rank(pkt_idx))
        });
        match row {
            Some(row) => {
                self.select_row(row, cx);
                self.sync_table_selection(cx);
                self.table
                    .update(cx, |table, cx| table.scroll_to_row(row, cx));
            }
            None => self.message = Some((format!("Packet {number} is not displayed"), true)),
        }
        cx.notify();
    }

    pub(crate) fn apply_filter(&mut self, text: &str, cx: &mut Context<Self>) {
        let mut guard = self.session.borrow_mut();
        let Some(session) = guard.as_mut() else {
            return;
        };
        self.filter_error = None;
        match session.apply_filter(text) {
            Err(msg) => self.filter_error = Some(msg),
            Ok(None) => {
                Self::invalidate_field_jobs(&mut self.fields, &mut self.timeline, session);
                drop(guard);
                self.ensure_ticking(cx);
            }
            Ok(Some(outcome)) => {
                if let FilterOutcome::Failed(msg) = outcome {
                    self.filter_error = Some(msg);
                }
                Self::invalidate_field_jobs(&mut self.fields, &mut self.timeline, session);
                self.selected_row = (session.displayed_count() > 0).then_some(0);
                session.load_packet(0);
                self.tree.reset(session);
                drop(guard);
                self.sync_table_selection(cx);
                self.update_sequence(cx);
                self.ensure_ticking(cx);
            }
        }
        cx.notify();
    }

    /// Put `text` in the filter input and apply it.
    pub(crate) fn set_filter(&mut self, text: &str, window: &mut Window, cx: &mut Context<Self>) {
        let value = text.to_string();
        self.filter
            .update(cx, |state, cx| state.set_value(value, window, cx));
        self.submit_filter(text, window, cx);
    }

    pub(crate) fn follow_stream(&mut self, cx: &mut Context<Self>) {
        let started = self
            .session
            .borrow_mut()
            .as_mut()
            .map(Session::start_follow_stream);
        self.start_job(started, cx);
    }

    fn stats(&mut self, cx: &mut Context<Self>) {
        self.bottom.stats_tab = None;
        let started = self.session.borrow_mut().as_mut().map(Session::start_stats);
        self.start_job(started, cx);
    }

    /// Collect the stats and show the Graph tab when they are done.
    fn graph(&mut self, cx: &mut Context<Self>) {
        self.stats(cx);
        self.bottom.stats_tab = Some(BottomTab::Graph);
    }

    /// Report a job that failed to start, or drive the one that did.
    fn start_job(&mut self, started: Option<Result<(), String>>, cx: &mut Context<Self>) {
        match started {
            Some(Ok(())) => {
                // An earlier failure no longer applies.
                if self.message.as_ref().is_some_and(|(_, error)| *error) {
                    self.message = None;
                }
                self.ensure_ticking(cx);
            }
            Some(Err(msg)) => self.message = Some((msg, true)),
            None => {}
        }
        cx.notify();
    }

    fn cycle_time_format(&mut self, cx: &mut Context<Self>) {
        if self.session.borrow().is_none() {
            return;
        }
        let next = self.time_format.next();
        self.set_time_format(next, cx);
    }

    /// The field columns of the packet table.
    pub(crate) fn columns(&self, cx: &App) -> Vec<String> {
        self.table.read(cx).delegate().extra.clone()
    }

    /// Show the field at `path` as a column, or stop showing it.
    pub(crate) fn toggle_column(&mut self, path: &str, cx: &mut Context<Self>) {
        self.table.update(cx, |table, cx| {
            let extra = &mut table.delegate_mut().extra;
            match extra.iter().position(|p| p == path) {
                Some(i) => {
                    extra.remove(i);
                }
                None => extra.push(path.to_string()),
            }
            table.refresh(cx);
        });
        cx.notify();
    }

    fn toggle_dock(&mut self, cx: &mut Context<Self>) {
        self.bottom.open = !self.bottom.open;
        cx.notify();
    }

    /// Run a command from the palette, a menu, or a shortcut.
    pub(crate) fn run_command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match command {
            Command::Open => self.prompt_open(window, cx),
            Command::FollowStream => self.follow_stream(cx),
            Command::Stats => self.stats(cx),
            Command::Graph => self.graph(cx),
            Command::CycleTime => self.cycle_time_format(cx),
            Command::ToggleDock => self.toggle_dock(cx),
            Command::Focus(pane) => self.focus_pane(pane, window, cx),
            Command::GoTo(number) => self.go_to_packet(number, cx),
            Command::Filter(text) => self.set_filter(&text, window, cx),
            Command::DecodeAs => self.open_decode_as(None, window, cx),
            Command::Mark => self.toggle_mark(cx),
            Command::ToggleBytes => self.toggle_bytes(cx),
            Command::DetailsSide => self.toggle_details_side(cx),
            Command::ExportDisplayed => self.export_packets(ExportSet::Displayed, window, cx),
            Command::ExportMarked => self.export_packets(ExportSet::Marked, window, cx),
            Command::Sequence => {
                let on = !self.sequence.on;
                self.set_sequence_on(on, cx);
            }
        }
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

    /// Whether `pane` holds keyboard focus.
    pub(crate) fn pane_focused(&self, pane: Pane, window: &Window, cx: &App) -> bool {
        self.focused_pane(window, cx) == Some(pane)
    }

    // -- Rendering ------------------------------------------------------------

    fn icon_button(id: &'static str, icon: IconName, tooltip: &'static str) -> Button {
        Button::new(id).icon(icon).small().ghost().tooltip(tooltip)
    }

    fn render_title_bar(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let file = self.session.borrow().as_ref().map(|s| s.file_name.clone());
        TitleBar::new()
            .child(
                h_flex()
                    .gap_1p5()
                    .text_sm()
                    .text_color(theme::text_muted())
                    .child(
                        div()
                            .text_color(theme::text_bright())
                            .font_weight(FontWeight::SEMIBOLD)
                            .child("dsct"),
                    )
                    .children(file.map(|f| {
                        h_flex()
                            .gap_1p5()
                            .child("/")
                            .child(div().text_color(theme::text()).child(f))
                    })),
            )
            .child(
                h_flex().flex_1().justify_center().child(
                    Button::new("palette")
                        .small()
                        .outline()
                        .w(px(420.))
                        .child(
                            h_flex()
                                .w_full()
                                .gap_2()
                                .text_color(theme::text_muted())
                                .child(Icon::new(IconName::Search).small())
                                .child(div().flex_1().child("Search actions, packets and filters…"))
                                .child(div().text_xs().child(crate::shortcut("K"))),
                        )
                        .on_click(cx.listener(|this, _, window, cx| this.open_palette(window, cx))),
                ),
            )
            .child(
                h_flex()
                    .gap_1()
                    .pr_2()
                    .child(
                        Self::icon_button("toggle-sidebar", IconName::PanelLeft, "Toggle sidebar")
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.sidebar_open = !this.sidebar_open;
                                cx.notify();
                            })),
                    )
                    .child(
                        Self::icon_button(
                            "toggle-dock",
                            IconName::PanelBottom,
                            "Toggle bottom dock",
                        )
                        .on_click(cx.listener(|this, _, _, cx| this.toggle_dock(cx))),
                    ),
            )
    }

    fn render_filter_bar(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let (has_packet, applied, displayed, total) = match self.session.borrow().as_ref() {
            Some(s) => (
                s.selected.is_some(),
                s.applied_filter.clone(),
                s.displayed_count(),
                s.total_count(),
            ),
            None => (false, String::new(), 0, 0),
        };
        // The text in the input is not the filter in effect until Enter.
        let edited = *self.filter.read(cx).value() != *applied;
        let count = if applied.is_empty() {
            format!("{total} packets")
        } else {
            format!("{displayed} of {total}")
        };
        let bar = h_flex()
            .flex_wrap()
            .gap_2p5()
            .px_3()
            .py_2()
            .child(
                h_flex()
                    .gap_1p5()
                    .text_xs()
                    .text_color(theme::text_muted())
                    .child(Icon::new(AssetIcon::Funnel).xsmall())
                    .child("Filter"),
            )
            .child(
                div()
                    .flex_1()
                    .min_w(px(200.))
                    .rounded(px(6.))
                    .border_1()
                    .border_color(if self.filter_error.is_some() {
                        theme::red()
                    } else {
                        gpui_kit::transparent_black()
                    })
                    .child(Input::new(&self.filter).small()),
            )
            .child(div().text_xs().text_color(theme::text_muted()).child(
                if edited && self.filter_error.is_none() {
                    "Enter to apply".to_string()
                } else {
                    count
                },
            ))
            .when(self.tabs.len() > 1, |bar| {
                bar.child(self.render_filter_scope(cx))
            })
            .child(div().w(px(1.)).h(px(18.)).bg(theme::border()))
            .child(
                Button::new("time-format")
                    .icon(Icon::new(AssetIcon::Clock))
                    .label(self.time_format.label())
                    .small()
                    .outline()
                    .tooltip(format!("Change the time format ({})", crate::shortcut("T")))
                    .on_click(cx.listener(|this, _, _, cx| this.cycle_time_format(cx))),
            )
            .child(
                Button::new("follow")
                    .icon(Icon::new(AssetIcon::ArrowLeftRight))
                    .label("Follow Stream")
                    .small()
                    .outline()
                    .tooltip(format!(
                        "Payload of the selected packet's TCP/UDP/SCTP stream ({})",
                        crate::shortcut_shift("F")
                    ))
                    .disabled(!has_packet)
                    .on_click(cx.listener(|this, _, _, cx| this.follow_stream(cx))),
            )
            .child(
                Button::new("stats")
                    .icon(Icon::new(AssetIcon::ChartColumn))
                    .label("Stats")
                    .small()
                    .outline()
                    .tooltip(format!(
                        "Statistics of the displayed packets ({})",
                        crate::shortcut_shift("S")
                    ))
                    .on_click(cx.listener(|this, _, _, cx| this.stats(cx))),
            )
            .child(self.render_problems_button(cx))
            .child(self.render_decode_as_button(cx));
        v_flex()
            .flex_shrink_0()
            .border_b_1()
            .border_color(theme::border())
            .child(bar)
            .children(self.filter_error.as_ref().map(|msg| {
                div()
                    .px_3()
                    .pb_2()
                    .text_sm()
                    .text_color(theme::red())
                    .child(format!("Filter error: {msg}"))
            }))
            .children(self.render_sequence_bar(cx))
    }

    /// Shown instead of the panes until a capture is open.
    fn render_empty(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        v_flex()
            .size_full()
            .items_center()
            .justify_center()
            .gap_3()
            .bg(theme::surface())
            .child(
                div()
                    .text_xl()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme::text_bright())
                    .child("Open a capture file"),
            )
            .child(
                div()
                    .text_color(theme::text_muted())
                    .child("pcap or pcapng — or drop a file anywhere in this window"),
            )
            .child(
                Button::new("open-empty")
                    .label("Open…")
                    .primary()
                    .on_click(cx.listener(|this, _, window, cx| this.prompt_open(window, cx))),
            )
            .child(
                div()
                    .text_sm()
                    .text_color(theme::text_muted())
                    .child(format!(
                        "{} to open · {} for every action",
                        crate::shortcut("O"),
                        crate::shortcut("K")
                    )),
            )
    }

    fn render_status(&mut self, _cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let mut left: Vec<String> = Vec::new();
        let mut right: Vec<String> = Vec::new();
        let mut working = false;
        if let Some(session) = self.session.borrow().as_ref() {
            if let Some(bg) = &session.bg_indexer {
                left.push(format!("Indexing {}%", format::percent(bg.fraction())));
                working = true;
            } else if let Some(fraction) = session.filter_fraction() {
                left.push(format!("Filtering {}%", format::percent(fraction)));
                working = true;
            } else if session.stream_running() {
                left.push("Following stream…".to_string());
                working = true;
            } else if session.stats_running() {
                left.push("Collecting stats…".to_string());
                working = true;
            } else if session.field_stats_running() || session.histogram_running() {
                left.push("Counting fields…".to_string());
                working = true;
            } else {
                left.push("Ready".to_string());
            }
            left.push(format!("{} packets", session.total_count()));
            let marked = session.marked().count();
            if marked > 0 {
                left.push(format!("{marked} marked"));
            }
            if session.ordered_needs_tick() {
                left.push("Dissecting in capture order…".to_string());
            }
            if let (Some(row), Some(sel)) = (self.selected_row, session.selected.as_ref()) {
                let number = session.filtered.select(row).map_or(0, |i| i + 1);
                let byte = self.tree.hex_cursor.or_else(|| {
                    let idx = self.tree.selected?;
                    sel.tree_nodes.get(idx).map(|n| n.byte_range.start)
                });
                right.push(match byte {
                    Some(b) => format!("Packet {number} · Byte 0x{b:04x}"),
                    None => format!("Packet {number}"),
                });
            }
            right.push(format!("Time: {}", self.time_format.label()));
        }
        let dot = if working {
            theme::accent()
        } else {
            theme::green()
        };
        let has_session = !left.is_empty();
        h_flex()
            .h(px(26.))
            .flex_shrink_0()
            .px_3()
            .gap_4()
            .bg(theme::chrome())
            .border_t_1()
            .border_color(theme::border())
            .text_xs()
            .text_color(theme::text_muted())
            .when(has_session, |d| {
                d.child(div().size(px(7.)).rounded_full().bg(dot))
            })
            .children(left)
            .children(self.message.as_ref().map(|(msg, error)| {
                div()
                    .when(*error, |d| d.text_color(theme::red()))
                    .child(if *error {
                        format!("⚠ {msg}")
                    } else {
                        msg.clone()
                    })
            }))
            .child(div().flex_1())
            .children(right)
    }
}

impl Render for DsctApp {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let has_session = self.session.borrow().is_some();
        let title_bar = self.render_title_bar(cx);
        let status = self.render_status(cx);
        let palette = self.render_palette(cx);
        let decode_as = self.render_decode_as(cx);

        let body = if has_session {
            let sidebar = self.sidebar_open.then(|| self.render_sidebar(cx));
            let tab_bar = self.render_tab_bar(cx);
            let filter_bar = self.render_filter_bar(cx);
            let table_border = if self.pane_focused(Pane::Packets, window, cx) {
                theme::accent()
            } else {
                transparent_black()
            };
            let timeline = self.render_timeline(cx);
            let tree = self.render_tree(window, cx);
            let hex = self.render_hex(window, cx);
            let bottom = self.render_bottom(cx);
            let tables = self.render_tables(table_border, cx);
            let weak = cx.entity().downgrade();
            // The packet list's height, or the details' width when they are
            // on the right, as the user drags it.
            let on_resize = move |panel: usize| {
                let weak = weak.clone();
                move |state: &Entity<ResizableState>, _: &mut Window, cx: &mut App| {
                    let Some(size) = state.read(cx).sizes().get(panel).copied() else {
                        return;
                    };
                    let _ = weak.update(cx, |app, cx| app.layout_resized(f32::from(size), cx));
                }
            };
            let panes = if self.layout.details_right {
                let mut left = v_resizable("main-left").child(resizable_panel().child(tables));
                if let Some(bottom) = bottom {
                    left = left.child(resizable_panel().size(px(300.)).child(bottom));
                }
                let details = if self.layout.bytes_open {
                    v_resizable("details-right")
                        .child(resizable_panel().child(tree))
                        .child(resizable_panel().size(px(240.)).child(hex))
                        .into_any_element()
                } else {
                    tree.into_any_element()
                };
                h_resizable("main-h")
                    .on_resize(on_resize(1))
                    .child(resizable_panel().child(left))
                    .child(
                        resizable_panel()
                            .size(px(self.layout.details_size))
                            .child(details),
                    )
                    .into_any_element()
            } else {
                let details = if self.layout.bytes_open {
                    h_resizable("details")
                        .child(resizable_panel().size(px(420.)).child(tree))
                        .child(resizable_panel().child(hex))
                        .into_any_element()
                } else {
                    tree.into_any_element()
                };
                let mut panes = v_resizable("main")
                    .on_resize(on_resize(0))
                    .child(
                        resizable_panel()
                            .size(px(self.layout.list_size))
                            .child(tables),
                    )
                    .child(resizable_panel().child(details));
                if let Some(bottom) = bottom {
                    panes = panes.child(resizable_panel().size(px(300.)).child(bottom));
                }
                panes.into_any_element()
            };
            h_flex()
                .size_full()
                .children(sidebar)
                .child(
                    v_flex()
                        .flex_1()
                        .min_w_0()
                        .h_full()
                        .bg(theme::surface())
                        .child(tab_bar)
                        .child(filter_bar)
                        .child(div().flex_1().min_h_0().child(match timeline {
                            // The chart and the panes share a resizable split.
                            Some(timeline) => {
                                let weak = cx.entity().downgrade();
                                v_resizable("timeline-split")
                                    .on_resize(move |state: &Entity<ResizableState>, _, cx| {
                                        let Some(size) = state.read(cx).sizes().first().copied()
                                        else {
                                            return;
                                        };
                                        let _ = weak.update(cx, |app, cx| {
                                            app.timeline_resized(f32::from(size), cx)
                                        });
                                    })
                                    .child(
                                        resizable_panel()
                                            .size(px(self.layout.timeline_size))
                                            .size_range(
                                                px(crate::layout::MIN_TIMELINE_SIZE)..px(400.),
                                            )
                                            .child(timeline),
                                    )
                                    .child(resizable_panel().child(panes))
                                    .into_any_element()
                            }
                            None => panes,
                        })),
                )
                .into_any_element()
        } else {
            self.render_empty(cx).into_any_element()
        };

        v_flex()
            .id("dsct")
            .key_context("DsctApp")
            .track_focus(&self.root_focus)
            .relative()
            .size_full()
            .bg(theme::chrome())
            .text_color(theme::text())
            .on_action(cx.listener(|this, _: &Open, window, cx| this.prompt_open(window, cx)))
            .on_action(cx.listener(|this, _: &CloseTab, _, cx| {
                if !this.tabs.is_empty() {
                    let active = this.active_tab();
                    this.close_tab(active, cx);
                }
            }))
            .on_action(cx.listener(|this, _: &NextTab, _, cx| this.step_tab(true, cx)))
            .on_action(cx.listener(|this, _: &PrevTab, _, cx| this.step_tab(false, cx)))
            .on_action(
                cx.listener(|this, _: &OpenPalette, window, cx| this.open_palette(window, cx)),
            )
            .on_action(cx.listener(|this, _: &CycleTimeFormat, _, cx| this.cycle_time_format(cx)))
            .on_action(cx.listener(|this, _: &FollowStream, _, cx| this.follow_stream(cx)))
            .on_action(cx.listener(|this, _: &ToggleMark, _, cx| this.toggle_mark(cx)))
            .on_action(cx.listener(|this, _: &ExportDisplayed, window, cx| {
                this.export_packets(ExportSet::Displayed, window, cx)
            }))
            .on_action(cx.listener(|this, _: &ExportMarked, window, cx| {
                this.export_packets(ExportSet::Marked, window, cx)
            }))
            .on_action(cx.listener(|this, _: &ShowStats, _, cx| {
                if this.session.borrow().is_some() {
                    this.stats(cx);
                }
            }))
            .on_action(cx.listener(|this, _: &ToggleDock, _, cx| this.toggle_dock(cx)))
            .on_action(cx.listener(|this, _: &ToggleSidebar, _, cx| {
                this.sidebar_open = !this.sidebar_open;
                cx.notify();
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
                if !this.layout.bytes_open {
                    this.toggle_bytes(cx);
                }
                this.focus_pane(Pane::Bytes, window, cx)
            }))
            .on_action(cx.listener(|this, _: &CloseBottom, _, cx| {
                this.bottom.open = false;
                cx.notify();
            }))
            .drag_over::<ExternalPaths>(|style, _, _, _| style.bg(theme::drop_target()))
            .on_drop(cx.listener(|this, paths: &ExternalPaths, window, cx| {
                this.open_paths(paths.paths().to_vec(), window, cx)
            }))
            .child(title_bar)
            .child(div().flex_1().min_h_0().child(body))
            .child(status)
            .children(palette)
            .children(decode_as)
    }
}
