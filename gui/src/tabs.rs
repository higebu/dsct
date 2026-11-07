//! Captures open in tabs, like files in an editor.
//!
//! The active tab's state lives in [`DsctApp`]'s own fields, which every
//! pane reads; the other tabs' states are parked in [`DsctApp::tabs`] and
//! swapped in when their tab is activated. Each tab has its own
//! [`Session`], so a parked capture keeps indexing in the background.

use std::io::BufWriter;
use std::path::PathBuf;
use std::rc::Rc;

use dsct::session::fields::FieldStats;
use dsct::session::merge::write_merged_pcapng;
use dsct::session::{FilterOutcome, Session, Tick};
use gpui_kit::assets::IconName as AssetIcon;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::component::menu::{ContextMenuExt as _, PopupMenuItem};
use gpui_kit::component::table::{DataTable, TableEvent, TableState};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::component::{
    Icon, IconName, Sizable as _, h_flex, h_resizable, resizable_panel, v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::{DsctApp, TreeView};
use crate::bottom::BottomPanel;
use crate::decode_as;
use crate::fields_view::grouped;
use crate::format::TimeFormat;
use crate::packet_table::{PacketTable, Sources};
use crate::timeline::{MonoFont as _, Timeline};
use crate::{SharedSession, theme};

/// Widest a file name shows in its tab; longer ones are cut with an
/// ellipsis (the tooltip has the whole name).
const MAX_NAME_WIDTH: f32 = 220.;

/// The view state of one capture.
pub struct TabState {
    pub session: SharedSession,
    pub table: Entity<TableState<PacketTable>>,
    pub filter: Entity<InputState>,
    pub selected_row: Option<usize>,
    pub tree: TreeView,
    pub bottom: BottomPanel,
    pub field_stats: Option<FieldStats>,
    pub field_stale: bool,
    pub timeline: Timeline,
    pub filter_error: Option<String>,
    pub subscriptions: Vec<Subscription>,
    /// The temporary file of a merged capture, deleted with the tab (after
    /// its session, declared above, is dropped).
    pub merged_file: Option<tempfile::TempPath>,
}

/// A tab in the tab bar: the active one (whose state is in [`DsctApp`]) or
/// a parked one.
pub enum Slot {
    Active,
    Parked(Box<TabState>),
}

/// A signed time offset in µs, in ms under a second and in seconds above.
pub fn time_offset(us: i64) -> String {
    if us.unsigned_abs() < 1_000_000 {
        format!("{:+.3} ms", us as f64 / 1e3)
    } else {
        format!("{:+.3} s", us as f64 / 1e6)
    }
}

/// Index of the tab after (`forward`) or before `active`, wrapping around.
pub fn step_tab(active: usize, count: usize, forward: bool) -> usize {
    if count == 0 {
        return 0;
    }
    if forward {
        (active + 1) % count
    } else {
        (active + count - 1) % count
    }
}

/// The tab to show after closing tab `closed` of `count`: the one to its
/// right, or the new last one.
pub fn after_close(closed: usize, count: usize) -> Option<usize> {
    match count {
        0 | 1 => None,
        _ if closed + 1 < count => Some(closed + 1),
        _ => Some(closed - 1),
    }
}

impl DsctApp {
    /// A fresh tab with no capture yet, its widgets wired to this view.
    pub(crate) fn new_tab_state(window: &mut Window, cx: &mut Context<Self>) -> TabState {
        let session: SharedSession = Default::default();
        let table = cx.new(|cx| TableState::new(PacketTable::new(session.clone()), window, cx));
        let filter =
            cx.new(|cx| InputState::new(window, cx).placeholder("tcp.dst_port == 443 or dns"));
        let subscriptions = vec![
            cx.subscribe_in(&table, window, |this, table, event: &TableEvent, _, cx| {
                if let TableEvent::SelectRow(row) = event {
                    this.on_table_select(table.entity_id(), *row, cx);
                }
            }),
            cx.subscribe_in(
                &filter,
                window,
                |this, state, event: &InputEvent, window, cx| {
                    match event {
                        InputEvent::PressEnter { .. } => {
                            let text = state.read(cx).value().to_string();
                            this.submit_filter(&text, window, cx);
                        }
                        // Editing the filter dismisses its error and updates
                        // the "Enter to apply" hint.
                        InputEvent::Change => {
                            this.filter_error = None;
                            cx.notify();
                        }
                        _ => {}
                    }
                },
            ),
        ];
        TabState {
            session,
            table,
            filter,
            selected_row: None,
            tree: TreeView::default(),
            bottom: BottomPanel::default(),
            field_stats: None,
            field_stale: true,
            timeline: Timeline::default(),
            filter_error: None,
            subscriptions,
            merged_file: None,
        }
    }

    /// Put `tab` in place of the active tab's state and return the latter.
    fn swap_active(&mut self, mut tab: TabState) -> TabState {
        std::mem::swap(&mut self.session, &mut tab.session);
        std::mem::swap(&mut self.table, &mut tab.table);
        std::mem::swap(&mut self.filter, &mut tab.filter);
        std::mem::swap(&mut self.selected_row, &mut tab.selected_row);
        std::mem::swap(&mut self.tree, &mut tab.tree);
        std::mem::swap(&mut self.bottom, &mut tab.bottom);
        std::mem::swap(&mut self.fields.stats, &mut tab.field_stats);
        std::mem::swap(&mut self.fields.stale, &mut tab.field_stale);
        std::mem::swap(&mut self.timeline, &mut tab.timeline);
        std::mem::swap(&mut self.filter_error, &mut tab.filter_error);
        std::mem::swap(&mut self.tab_subscriptions, &mut tab.subscriptions);
        std::mem::swap(&mut self.merged_file, &mut tab.merged_file);
        tab
    }

    /// Index of the active tab.
    pub(crate) fn active_tab(&self) -> usize {
        self.tabs
            .iter()
            .position(|s| matches!(s, Slot::Active))
            .unwrap_or(0)
    }

    /// Show tab `index`.
    pub(crate) fn activate_tab(&mut self, index: usize, cx: &mut Context<Self>) {
        let active = self.active_tab();
        if index == active || index >= self.tabs.len() {
            return;
        }
        let Slot::Parked(tab) = std::mem::replace(&mut self.tabs[index], Slot::Active) else {
            return;
        };
        let previous = self.swap_active(*tab);
        self.tabs[active] = Slot::Parked(Box::new(previous));
        // Side by side, the two tabs trade places as the active one; any
        // other tab ends the split.
        self.split = (self.split == Some(index)).then_some(active);
        self.show_active_tab(cx);
        self.update_link(cx);
    }

    /// Bring the panes in line with the tab just made active.
    fn show_active_tab(&mut self, cx: &mut Context<Self>) {
        // A capture opened, or filtered, in the background has nothing
        // selected yet.
        if self.selected_row.is_none()
            && let Some(session) = self.session.borrow_mut().as_mut()
        {
            self.selected_row = (session.displayed_count() > 0).then_some(0);
            session.load_packet(0);
            self.tree.reset(session);
        }
        let time_format = self.time_format;
        self.table.update(cx, |table, _| {
            table.delegate_mut().time_format = time_format;
        });
        self.sync_table_selection(cx);
        self.ensure_ticking(cx);
        cx.notify();
    }

    /// Open the captures at `paths`, each in a tab of its own; the last one
    /// is shown.
    pub fn open_paths(&mut self, paths: Vec<PathBuf>, window: &mut Window, cx: &mut Context<Self>) {
        // With one filter for all tabs, new tabs take it too.
        let shared_filter = self
            .filter_all
            .then(|| {
                self.session
                    .borrow()
                    .as_ref()
                    .map(|s| s.applied_filter.clone())
            })
            .flatten()
            .filter(|f| !f.is_empty());
        for path in paths {
            let session = match Session::open(&path, decode_as::args(&self.decode_rules)) {
                Ok(session) => session,
                Err(e) => {
                    self.message = Some((format!("Cannot open {}: {e}", path.display()), true));
                    continue;
                }
            };
            if self.tabs.is_empty() {
                // The empty window's state becomes the first tab.
                *self.session.borrow_mut() = Some(session);
                self.tabs.push(Slot::Active);
                self.reset_views(cx);
            } else {
                let tab = Self::new_tab_state(window, cx);
                *tab.session.borrow_mut() = Some(session);
                self.tabs.push(Slot::Parked(Box::new(tab)));
                self.activate_tab(self.tabs.len() - 1, cx);
            }
            if let Some(filter) = &shared_filter {
                let value = filter.clone();
                self.filter
                    .update(cx, |state, cx| state.set_value(value, window, cx));
                self.apply_filter(filter, cx);
            }
        }
        self.ensure_ticking(cx);
        cx.notify();
    }

    /// Close tab `index`; closing the last one empties the window.
    pub(crate) fn close_tab(&mut self, index: usize, cx: &mut Context<Self>) {
        if index >= self.tabs.len() {
            return;
        }
        self.end_split(cx);
        if index == self.active_tab() {
            match after_close(index, self.tabs.len()) {
                Some(next) => self.activate_tab(next, cx),
                None => {
                    // The last tab: back to the empty window.
                    *self.session.borrow_mut() = None;
                    self.merged_file = None;
                    self.table
                        .update(cx, |table, _| table.delegate_mut().sources = None);
                    self.tabs.clear();
                    self.reset_views(cx);
                    cx.notify();
                    return;
                }
            }
        }
        // Now parked: dropping it closes its capture.
        self.tabs.remove(index);
        cx.notify();
    }

    /// A row was selected in the table `table`: in the active tab, or in
    /// the other tab of a split view, which then becomes the active one.
    pub(crate) fn on_table_select(&mut self, table: EntityId, row: usize, cx: &mut Context<Self>) {
        if table != self.table.entity_id() {
            let Some(index) = self
                .tabs
                .iter()
                .position(|s| matches!(s, Slot::Parked(t) if t.table.entity_id() == table))
            else {
                return;
            };
            self.activate_tab(index, cx);
        }
        self.select_row(row, cx);
    }

    /// Show tab `partner` beside the active one, or end the split.
    pub(crate) fn show_beside(&mut self, partner: Option<usize>, cx: &mut Context<Self>) {
        let partner = partner.filter(|&p| p != self.active_tab() && p < self.tabs.len());
        if partner.is_none() {
            self.end_split(cx);
            cx.notify();
            return;
        }
        self.split = partner;
        // Each capture's relative time starts at its own first packet;
        // wall-clock times line the two up.
        if self.time_format != TimeFormat::Absolute {
            self.set_time_format(TimeFormat::Absolute, cx);
        }
        self.update_link(cx);
        cx.notify();
    }

    /// Split with the next tab, or end the split.
    pub(crate) fn toggle_split(&mut self, cx: &mut Context<Self>) {
        let next = (self.split.is_none() && self.tabs.len() > 1)
            .then(|| step_tab(self.active_tab(), self.tabs.len(), true));
        self.show_beside(next, cx);
    }

    fn end_split(&mut self, cx: &mut Context<Self>) {
        if let Some(Slot::Parked(partner)) = self.split.and_then(|p| self.tabs.get(p)) {
            partner.table.update(cx, |table, cx| {
                table.delegate_mut().linked = None;
                cx.notify();
            });
        }
        self.split = None;
        self.link_note = None;
    }

    pub(crate) fn toggle_linked(&mut self, cx: &mut Context<Self>) {
        self.linked = !self.linked;
        self.update_link(cx);
        cx.notify();
    }

    /// Mark, in the tab beside, the packet nearest in time to the selected
    /// one.
    pub(crate) fn update_link(&mut self, cx: &mut Context<Self>) {
        self.table
            .update(cx, |table, _| table.delegate_mut().linked = None);
        let Some(Slot::Parked(partner)) = self.split.and_then(|p| self.tabs.get(p)) else {
            self.link_note = None;
            return;
        };
        let time = self.session.borrow().as_ref().and_then(|s| {
            let pkt_idx = s.filtered.select(self.selected_row?)?;
            s.packet_time_us(pkt_idx)
        });
        let (found, note) = {
            let guard = partner.session.borrow();
            let session = guard.as_ref();
            let found = time
                .filter(|_| self.linked)
                .and_then(|t| session?.nearest_row(t));
            let note = found.and_then(|(row, delta)| {
                let s = session?;
                let number = s.filtered.select(row)? + 1;
                Some(format!(
                    "Nearest in {}: packet {number}, {}",
                    s.file_name,
                    time_offset(delta)
                ))
            });
            (found, note)
        };
        let Some(Slot::Parked(partner)) = self.split.and_then(|p| self.tabs.get_mut(p)) else {
            return;
        };
        // The other side follows: its packet becomes the linked one, shown
        // in place of its own selection.
        if let Some((row, _)) = found
            && partner.selected_row != Some(row)
        {
            partner.selected_row = Some(row);
            if let Some(session) = partner.session.borrow_mut().as_mut() {
                session.load_packet(row);
                partner.tree.reset(session);
            }
        }
        partner.table.update(cx, |table, cx| {
            table.delegate_mut().linked = found.map(|(row, _)| row);
            if let Some((row, _)) = found {
                table.delegate_mut().selected = None;
                table.clear_selection(cx);
                table.scroll_to_row(row, cx);
            }
            cx.notify();
        });
        self.link_note = note;
    }

    /// Show every table's time in `format`.
    pub(crate) fn set_time_format(&mut self, format: TimeFormat, cx: &mut Context<Self>) {
        self.time_format = format;
        let tables =
            std::iter::once(self.table.clone()).chain(self.tabs.iter().filter_map(|s| match s {
                Slot::Parked(t) => Some(t.table.clone()),
                Slot::Active => None,
            }));
        for table in tables {
            table.update(cx, |table, cx| {
                table.delegate_mut().time_format = format;
                table.refresh(cx);
            });
        }
        cx.notify();
    }

    /// Merge the displayed packets of the active tab and tab `other` by
    /// time into a new tab, a temporary pcapng file with a Capture column.
    pub(crate) fn merge_with(&mut self, other: usize, window: &mut Window, cx: &mut Context<Self>) {
        let Some(Slot::Parked(partner)) = self.tabs.get(other) else {
            return;
        };
        let partner_session = partner.session.clone();
        let written = {
            let (a, b) = (self.session.borrow(), partner_session.borrow());
            let (Some(a), Some(b)) = (a.as_ref(), b.as_ref()) else {
                return;
            };
            if a.is_indexing() || b.is_indexing() || a.filter_running() || b.filter_running() {
                self.message = Some((
                    "Both captures must be read and filtered before merging".to_string(),
                    true,
                ));
                cx.notify();
                return;
            }
            let names = vec![
                SharedString::from(a.file_name.clone()),
                SharedString::from(b.file_name.clone()),
            ];
            (|| -> std::io::Result<_> {
                let file = tempfile::Builder::new()
                    .prefix("dsct-merged-")
                    .suffix(".pcapng")
                    .tempfile()?;
                let mut out = BufWriter::new(file.as_file());
                let of_packet = write_merged_pcapng(&[a, b], &mut out)?;
                drop(out);
                Ok((file.into_temp_path(), Sources { of_packet, names }))
            })()
        };
        let (path, sources) = match written {
            Ok(written) => written,
            Err(e) => {
                self.message = Some((format!("Cannot merge: {e}"), true));
                cx.notify();
                return;
            }
        };
        let mut session = match Session::open(&path, decode_as::args(&self.decode_rules)) {
            Ok(session) => session,
            Err(e) => {
                self.message = Some((format!("Cannot open the merged capture: {e}"), true));
                cx.notify();
                return;
            }
        };
        session.file_name = sources
            .names
            .iter()
            .map(|n| n.as_ref())
            .collect::<Vec<_>>()
            .join(" + ");
        let mut tab = Self::new_tab_state(window, cx);
        *tab.session.borrow_mut() = Some(session);
        tab.merged_file = Some(path);
        let time_format = self.time_format;
        tab.table.update(cx, |table, cx| {
            let delegate = table.delegate_mut();
            delegate.sources = Some(Rc::new(sources));
            delegate.time_format = time_format;
            table.refresh(cx);
        });
        self.tabs.push(Slot::Parked(Box::new(tab)));
        self.activate_tab(self.tabs.len() - 1, cx);
    }

    /// The packet table, or the two tables of a split view.
    pub(crate) fn render_tables(&mut self, border: Hsla, cx: &mut Context<Self>) -> AnyElement {
        let single = |table: &Entity<TableState<PacketTable>>, border: Hsla| {
            div()
                .size_full()
                .border_1()
                .border_color(border)
                .child(DataTable::new(table).small())
        };
        let partner = match self.split.and_then(|p| self.tabs.get(p)) {
            Some(Slot::Parked(tab)) => tab.table.clone(),
            _ => return single(&self.table, border).into_any_element(),
        };
        let mono = cx.theme_mono_font();
        let active = self.active_tab();
        let partner_ix = self.split.unwrap_or(active);
        let side = |this: &Self,
                    index: usize,
                    table: &Entity<TableState<PacketTable>>,
                    cx: &mut Context<Self>| {
            let (name, count, indexing, _) = this.tab_label(index);
            let on = index == active;
            v_flex()
                .size_full()
                .child(
                    h_flex()
                        .id(("split-head", index))
                        .h(px(28.))
                        .flex_shrink_0()
                        .px_3()
                        .gap_2()
                        .text_xs()
                        .border_b_1()
                        .border_color(theme::border())
                        .bg(if on { theme::surface() } else { theme::panel() })
                        .text_color(if on {
                            theme::text_bright()
                        } else {
                            theme::text_muted()
                        })
                        .when(!on, |d| d.cursor_pointer())
                        .child(div().size(px(6.)).rounded_full().bg(if on {
                            theme::accent()
                        } else {
                            theme::border_strong()
                        }))
                        .child(
                            div()
                                .font_weight(FontWeight::SEMIBOLD)
                                .overflow_hidden()
                                .text_ellipsis()
                                .whitespace_nowrap()
                                .child(name),
                        )
                        .child(
                            div()
                                .font_family(mono.clone())
                                .text_color(theme::text_muted())
                                .child(if indexing {
                                    format!("{}…", grouped(count as u64))
                                } else {
                                    grouped(count as u64)
                                }),
                        )
                        .on_click(cx.listener(move |this, _, _, cx| this.activate_tab(index, cx))),
                )
                .child(
                    div()
                        .flex_1()
                        .min_h_0()
                        .child(single(table, if on { border } else { transparent_black() })),
                )
        };
        let active_side = side(self, active, &self.table.clone(), cx);
        let partner_side = side(self, partner_ix, &partner, cx);
        let (left, right) = if active < partner_ix {
            (active_side, partner_side)
        } else {
            (partner_side, active_side)
        };
        let linked = self.linked;
        v_flex()
            .size_full()
            .child(
                h_flex()
                    .flex_shrink_0()
                    .px_3()
                    .py_1()
                    .gap_2p5()
                    .text_xs()
                    .text_color(theme::text_muted())
                    .border_b_1()
                    .border_color(theme::border())
                    .child(
                        Button::new("linked-by-time")
                            .label("Linked by time")
                            .xsmall()
                            .when(linked, |b| b.primary())
                            .when(!linked, |b| b.outline())
                            .tooltip("Mark the packet nearest in time on the other side")
                            .on_click(cx.listener(|this, _, _, cx| this.toggle_linked(cx))),
                    )
                    .child(match (&self.link_note, linked) {
                        (Some(note), true) => note.clone(),
                        (None, true) => {
                            "Select a packet to mark the nearest one on the other side".to_string()
                        }
                        (_, false) => "Each side scrolls and selects on its own".to_string(),
                    })
                    .child(div().flex_1())
                    .child(
                        Button::new("end-split")
                            .icon(IconName::Close)
                            .xsmall()
                            .ghost()
                            .tooltip("Close the split view")
                            .on_click(cx.listener(|this, _, _, cx| this.show_beside(None, cx))),
                    ),
            )
            .child(
                h_resizable("split")
                    .child(resizable_panel().child(left))
                    .child(resizable_panel().child(right)),
            )
            .into_any_element()
    }

    /// Show the next (`forward`) or previous tab.
    pub(crate) fn step_tab(&mut self, forward: bool, cx: &mut Context<Self>) {
        let next = step_tab(self.active_tab(), self.tabs.len(), forward);
        self.activate_tab(next, cx);
    }

    /// Drive the parked tabs' indexing and in-order passes, so their packet
    /// counts grow and they are ready when shown. Returns whether any has
    /// work left.
    pub(crate) fn tick_parked(&mut self) -> bool {
        let mut busy = false;
        for slot in &mut self.tabs {
            let Slot::Parked(tab) = slot else {
                continue;
            };
            let mut guard = tab.session.borrow_mut();
            let Some(session) = guard.as_mut() else {
                continue;
            };
            if session.is_indexing() {
                session.index_tick();
            }
            session.ordered_tick();
            if let Tick::Done(outcome) = session.filter_tick() {
                if let FilterOutcome::Failed(msg) = outcome {
                    tab.filter_error = Some(msg);
                }
                tab.selected_row = None;
            }
            busy |=
                session.is_indexing() || session.ordered_needs_tick() || session.filter_running();
        }
        busy
    }

    /// Apply `text` to the active tab, and to every other tab when one
    /// filter is set for all tabs.
    pub(crate) fn submit_filter(
        &mut self,
        text: &str,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.apply_filter(text, cx);
        if self.filter_all {
            self.apply_filter_to_parked(text, window, cx);
        }
    }

    /// Apply `text` to every tab but the active one; each scans in the
    /// background, and is shown from its first match.
    fn apply_filter_to_parked(&mut self, text: &str, window: &mut Window, cx: &mut Context<Self>) {
        for slot in &mut self.tabs {
            let Slot::Parked(tab) = slot else {
                continue;
            };
            let value = text.to_string();
            tab.filter
                .update(cx, |state, cx| state.set_value(value, window, cx));
            let mut guard = tab.session.borrow_mut();
            let Some(session) = guard.as_mut() else {
                continue;
            };
            tab.filter_error = None;
            match session.apply_filter(text) {
                Err(msg) => tab.filter_error = Some(msg),
                Ok(outcome) => {
                    if let Some(FilterOutcome::Failed(msg)) = outcome {
                        tab.filter_error = Some(msg);
                    }
                    session.cancel_field_stats();
                    session.cancel_histogram();
                    tab.field_stale = true;
                    tab.timeline.stale = true;
                    tab.selected_row = None;
                }
            }
        }
        self.ensure_ticking(cx);
    }

    /// Use the filter for this tab only, or for all tabs (applying the
    /// active tab's filter to the others right away).
    pub(crate) fn set_filter_all(
        &mut self,
        all: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.filter_all == all {
            return;
        }
        self.filter_all = all;
        if all {
            let text = self
                .session
                .borrow()
                .as_ref()
                .map(|s| s.applied_filter.clone())
                .unwrap_or_default();
            self.apply_filter_to_parked(&text, window, cx);
        }
        cx.notify();
    }

    /// Name, packet count, whether it is still indexing, and (with one
    /// filter for all tabs) the matches, of tab `index`.
    fn tab_label(&self, index: usize) -> (String, usize, bool, Option<String>) {
        let session = match &self.tabs[index] {
            Slot::Active => &self.session,
            Slot::Parked(tab) => &tab.session,
        };
        session.borrow().as_ref().map_or_else(
            || (String::new(), 0, false, None),
            |s| {
                let matches = (self.filter_all && !s.applied_filter.is_empty()).then(|| {
                    if s.filter_running() {
                        "…".to_string()
                    } else {
                        grouped(s.displayed_count() as u64)
                    }
                });
                (
                    s.file_name.clone(),
                    s.total_count(),
                    s.is_indexing(),
                    matches,
                )
            },
        )
    }

    /// "This tab | All tabs": where the filter applies.
    pub(crate) fn render_filter_scope(&self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let segment = |id: &'static str, label: &'static str, all: bool, on: bool| {
            Button::new(id)
                .label(label)
                .small()
                .when(on, |b| b.primary())
                .when(!on, |b| b.ghost())
                .on_click(
                    cx.listener(move |this, _, window, cx| this.set_filter_all(all, window, cx)),
                )
        };
        h_flex()
            .gap_0p5()
            .p_0p5()
            .rounded(px(6.))
            .border_1()
            .border_color(theme::border())
            .child(segment(
                "filter-this-tab",
                "This tab",
                false,
                !self.filter_all,
            ))
            .child(segment(
                "filter-all-tabs",
                "All tabs",
                true,
                self.filter_all,
            ))
    }

    pub(crate) fn render_tab_bar(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let mono = cx.theme_mono_font();
        let active = self.active_tab();
        let weak = cx.entity().downgrade();
        let active_name = self.tab_label(active).0;
        let tabs: Vec<AnyElement> = (0..self.tabs.len())
            .map(|i| {
                let (name, count, indexing, matches) = self.tab_label(i);
                let on = i == active;
                let tab = h_flex()
                    .id(("tab", i))
                    .relative()
                    .h_full()
                    .flex_shrink_0()
                    .gap_2()
                    .pl_3()
                    .pr_1()
                    .border_r_1()
                    .border_color(theme::border())
                    .when(on, |d| {
                        d.bg(theme::surface())
                            .text_color(theme::text_bright())
                            .child(
                                div()
                                    .absolute()
                                    .top_0()
                                    .left_0()
                                    .right_0()
                                    .h(px(2.))
                                    .bg(theme::accent()),
                            )
                    })
                    .when(!on, |d| {
                        d.text_color(theme::text_muted())
                            .cursor_pointer()
                            .hover(|d| d.bg(theme::hover()))
                    })
                    .child(
                        div()
                            .max_w(px(MAX_NAME_WIDTH))
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_ellipsis()
                            .child(name.clone()),
                    )
                    .child(
                        div()
                            .text_xs()
                            .font_family(mono.clone())
                            .text_color(theme::text_muted())
                            .child(if indexing {
                                format!("{}…", grouped(count as u64))
                            } else {
                                grouped(count as u64)
                            }),
                    )
                    .children(matches.map(|m| {
                        let none = m == "0";
                        div()
                            .px_1p5()
                            .rounded(px(9.))
                            .text_xs()
                            .font_family(mono.clone())
                            .bg(if none {
                                theme::border()
                            } else {
                                theme::selection()
                            })
                            .text_color(if none {
                                theme::text_muted()
                            } else {
                                theme::text_bright()
                            })
                            .child(m)
                    }))
                    .child(
                        Button::new(("close-tab", i))
                            .icon(IconName::Close)
                            .xsmall()
                            .ghost()
                            .tooltip(format!("Close {name} ({})", crate::shortcut("W")))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                cx.stop_propagation();
                                this.close_tab(i, cx);
                            })),
                    )
                    .tooltip({
                        let name = name.clone();
                        move |window, cx| Tooltip::new(name.clone()).build(window, cx)
                    })
                    .on_click(cx.listener(move |this, _, _, cx| this.activate_tab(i, cx)));
                if on {
                    return tab.into_any_element();
                }
                // Another tab: show it beside the active one, or merge the two.
                let weak = weak.clone();
                let merge_label = format!("Merge with {active_name}");
                tab.context_menu(move |menu, _, _| {
                    let (split, merge) = (weak.clone(), weak.clone());
                    menu.item(
                        PopupMenuItem::new("Show side by side").on_click(move |_, _, cx| {
                            let _ = split.update(cx, |app, cx| app.show_beside(Some(i), cx));
                        }),
                    )
                    .item(
                        PopupMenuItem::new(merge_label.clone()).on_click(move |_, window, cx| {
                            let _ = merge.update(cx, |app, cx| app.merge_with(i, window, cx));
                        }),
                    )
                })
                .into_any_element()
            })
            .collect();
        let split_on = self.split.is_some();
        h_flex()
            .h(px(34.))
            .flex_shrink_0()
            .bg(theme::panel())
            .border_b_1()
            .border_color(theme::border())
            .child(
                h_flex()
                    .id("tabs")
                    .h_full()
                    .min_w_0()
                    .overflow_x_scroll()
                    .children(tabs),
            )
            .child(
                Button::new("open-tab")
                    .icon(IconName::Plus)
                    .small()
                    .ghost()
                    .mx_1()
                    .tooltip(format!(
                        "Open captures in new tabs ({})",
                        crate::shortcut("O")
                    ))
                    .on_click(cx.listener(|this, _, window, cx| this.prompt_open(window, cx))),
            )
            .child(div().flex_1())
            .when(self.tabs.len() > 1, |bar| {
                bar.child(
                    Button::new("split")
                        .icon(Icon::new(AssetIcon::Columns2))
                        .label("Split")
                        .small()
                        .mx_2()
                        .when(split_on, |b| b.primary())
                        .when(!split_on, |b| b.outline())
                        .tooltip("Show the next tab beside this one (or right-click a tab)")
                        .on_click(cx.listener(|this, _, _, cx| this.toggle_split(cx))),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::{after_close, step_tab, time_offset};

    #[test]
    fn time_offsets_switch_to_seconds_from_one_second() {
        assert_eq!(time_offset(815), "+0.815 ms");
        assert_eq!(time_offset(-999_999), "-999.999 ms");
        assert_eq!(time_offset(40_040_812), "+40.041 s");
    }

    #[test]
    fn tabs_wrap_around() {
        assert_eq!(step_tab(0, 3, true), 1);
        assert_eq!(step_tab(2, 3, true), 0);
        assert_eq!(step_tab(0, 3, false), 2);
        assert_eq!(step_tab(0, 0, true), 0);
    }

    #[test]
    fn closing_shows_the_tab_to_the_right() {
        assert_eq!(after_close(0, 1), None);
        assert_eq!(after_close(0, 3), Some(1));
        assert_eq!(after_close(1, 3), Some(2));
        assert_eq!(after_close(2, 3), Some(1));
    }
}
