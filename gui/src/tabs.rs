//! Captures open in tabs, like files in an editor.
//!
//! The active tab's state lives in [`DsctApp`]'s own fields, which every
//! pane reads; the other tabs' states are parked in [`DsctApp::tabs`] and
//! swapped in when their tab is activated. Each tab has its own
//! [`Session`], so a parked capture keeps indexing in the background.

use std::path::PathBuf;

use dsct::session::Session;
use dsct::session::fields::FieldStats;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::component::table::{TableEvent, TableState};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::component::{IconName, Sizable as _, h_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::{DsctApp, TreeView};
use crate::bottom::BottomPanel;
use crate::fields_view::grouped;
use crate::packet_table::PacketTable;
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
}

/// A tab in the tab bar: the active one (whose state is in [`DsctApp`]) or
/// a parked one.
pub enum Slot {
    Active,
    Parked(Box<TabState>),
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
        self.show_active_tab(cx);
    }

    /// Bring the panes in line with the tab just made active.
    fn show_active_tab(&mut self, cx: &mut Context<Self>) {
        // A capture opened in the background has rows but nothing selected.
        if self.selected_row.is_none()
            && let Some(session) = self.session.borrow_mut().as_mut()
            && session.displayed_count() > 0
        {
            self.selected_row = Some(0);
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
        for path in paths {
            let session = match Session::open(&path, Vec::new()) {
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
        }
        self.ensure_ticking(cx);
        cx.notify();
    }

    /// Close tab `index`; closing the last one empties the window.
    pub(crate) fn close_tab(&mut self, index: usize, cx: &mut Context<Self>) {
        if index >= self.tabs.len() {
            return;
        }
        if index == self.active_tab() {
            match after_close(index, self.tabs.len()) {
                Some(next) => self.activate_tab(next, cx),
                None => {
                    // The last tab: back to the empty window.
                    *self.session.borrow_mut() = None;
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
            busy |= session.is_indexing() || session.ordered_needs_tick();
        }
        busy
    }

    /// Name and packet count of tab `index` (the count while indexing grows).
    fn tab_label(&self, index: usize) -> (String, usize, bool) {
        let session = match &self.tabs[index] {
            Slot::Active => &self.session,
            Slot::Parked(tab) => &tab.session,
        };
        session.borrow().as_ref().map_or_else(
            || (String::new(), 0, false),
            |s| (s.file_name.clone(), s.total_count(), s.is_indexing()),
        )
    }

    pub(crate) fn render_tab_bar(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let mono = cx.theme_mono_font();
        let active = self.active_tab();
        let tabs = (0..self.tabs.len()).map(|i| {
            let (name, count, indexing) = self.tab_label(i);
            let on = i == active;
            h_flex()
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
                .on_click(cx.listener(move |this, _, _, cx| this.activate_tab(i, cx)))
        });
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
    }
}

#[cfg(test)]
mod tests {
    use super::{after_close, step_tab};

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
