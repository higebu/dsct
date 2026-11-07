//! The command palette (⌘K): every action by name, plus "go to packet N"
//! and "apply this filter" for what is typed.

use std::ops::Range;

use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::{h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::{DsctApp, Pane};
use crate::theme;

/// Context of the palette; its input's arrow keys move the selection.
pub const PALETTE_CONTEXT: &str = "CommandPalette";

/// Rows shown at most.
const MAX_ITEMS: usize = 9;

/// What a palette row does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Open,
    FollowStream,
    Stats,
    CycleTime,
    ToggleDock,
    Focus(Pane),
    GoTo(u64),
    Filter(String),
    DecodeAs,
}

/// One palette row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub command: Command,
    pub group: &'static str,
    pub title: String,
    /// Shortcut, as shown to the user.
    pub key: Option<String>,
    /// Bytes of `title` matching the query, to emphasize.
    pub matched: Option<Range<usize>>,
}

/// The fixed commands, in the order they are listed.
fn commands(has_session: bool) -> Vec<(Command, &'static str, &'static str, Option<String>)> {
    let mut list = vec![(
        Command::Open,
        "File",
        "Open capture…",
        Some(crate::shortcut("O")),
    )];
    if has_session {
        list.extend([
            (
                Command::FollowStream,
                "Stream",
                "Follow stream of the selected packet",
                Some(crate::shortcut_shift("F")),
            ),
            (
                Command::Stats,
                "Stats",
                "Show statistics of the displayed packets",
                Some(crate::shortcut_shift("S")),
            ),
            (
                Command::DecodeAs,
                "Decode",
                "Decode a port as another protocol…",
                None,
            ),
            (
                Command::CycleTime,
                "View",
                "Change time format",
                Some(crate::shortcut("T")),
            ),
            (
                Command::ToggleDock,
                "View",
                "Toggle bottom dock",
                Some(crate::shortcut("J")),
            ),
            (
                Command::Focus(Pane::Packets),
                "Focus",
                "Packets",
                Some(crate::shortcut("1")),
            ),
            (
                Command::Focus(Pane::Details),
                "Focus",
                "Details",
                Some(crate::shortcut("2")),
            ),
            (
                Command::Focus(Pane::Bytes),
                "Focus",
                "Bytes",
                Some(crate::shortcut("3")),
            ),
        ]);
    }
    list
}

/// The rows for `query`: a packet number first, then the commands whose
/// group or title contains the query (ignoring case), then applying the
/// query as a filter.
pub fn items(query: &str, has_session: bool) -> Vec<Item> {
    let q = query.trim();
    let lower = q.to_lowercase();
    let mut out = Vec::new();
    if has_session
        && let Ok(number) = q.parse::<u64>()
        && number > 0
    {
        out.push(Item {
            command: Command::GoTo(number),
            group: "Go",
            title: format!("Go to packet {number}"),
            key: None,
            matched: None,
        });
    }
    for (command, group, title, key) in commands(has_session) {
        let matched = if lower.is_empty() {
            None
        } else if let Some(at) = title.to_lowercase().find(&lower) {
            Some(at..at + lower.len())
        } else if group.to_lowercase().contains(&lower) {
            None
        } else {
            continue;
        };
        out.push(Item {
            command,
            group,
            title: title.to_string(),
            key,
            matched,
        });
    }
    if has_session && !q.is_empty() {
        out.push(Item {
            command: Command::Filter(q.to_string()),
            group: "Filter",
            title: format!("Apply filter: {q}"),
            key: None,
            matched: None,
        });
    }
    out
}

/// The open palette.
pub struct PaletteState {
    pub input: Entity<InputState>,
    pub selected: usize,
    _subscription: Subscription,
}

actions!(dsct_palette, [PaletteUp, PaletteDown, ClosePalette]);

impl DsctApp {
    pub(crate) fn open_palette(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.palette.is_some() {
            return;
        }
        let input = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("Search actions, or type a packet number or a filter")
        });
        let subscription = cx.subscribe_in(
            &input,
            window,
            |this, _, event: &InputEvent, window, cx| match event {
                InputEvent::PressEnter { .. } => this.run_palette(window, cx),
                InputEvent::Change => {
                    if let Some(p) = this.palette.as_mut() {
                        p.selected = 0;
                    }
                    cx.notify();
                }
                _ => {}
            },
        );
        let handle = input.read(cx).focus_handle(cx);
        window.focus(&handle, cx);
        self.palette = Some(PaletteState {
            input,
            selected: 0,
            _subscription: subscription,
        });
        cx.notify();
    }

    pub(crate) fn close_palette(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.palette.take().is_some() {
            let pane = if self.session.borrow().is_some() {
                Pane::Packets
            } else {
                return cx.notify();
            };
            self.focus_pane(pane, window, cx);
        }
        cx.notify();
    }

    fn palette_items(&self, cx: &App) -> Vec<Item> {
        let Some(p) = &self.palette else {
            return Vec::new();
        };
        let query = p.input.read(cx).value().to_string();
        let mut items = items(&query, self.session.borrow().is_some());
        items.truncate(MAX_ITEMS);
        items
    }

    fn move_palette(&mut self, down: bool, cx: &mut Context<Self>) {
        let count = self.palette_items(cx).len();
        if let Some(p) = self.palette.as_mut()
            && count > 0
        {
            p.selected = if down {
                (p.selected + 1) % count
            } else {
                (p.selected + count - 1) % count
            };
        }
        cx.notify();
    }

    fn run_palette(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let items = self.palette_items(cx);
        let Some(item) = self
            .palette
            .as_ref()
            .and_then(|p| items.get(p.selected).cloned())
        else {
            return;
        };
        self.close_palette(window, cx);
        self.run_command(item.command, window, cx);
    }

    pub(crate) fn render_palette(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let p = self.palette.as_ref()?;
        let items = self.palette_items(cx);
        let selected = p.selected.min(items.len().saturating_sub(1));
        let rows = items.into_iter().enumerate().map(|(i, item)| {
            let (pre, hit, post) = match &item.matched {
                Some(r) => (
                    item.title[..r.start].to_string(),
                    item.title[r.clone()].to_string(),
                    item.title[r.end..].to_string(),
                ),
                None => (item.title.clone(), String::new(), String::new()),
            };
            h_flex()
                .id(("palette-item", i))
                .h(px(34.))
                .px_3()
                .gap_3()
                .rounded(px(6.))
                .when(i == selected, |d| d.bg(theme::selection()))
                .hover(|d| d.bg(theme::hover()))
                .child(
                    div()
                        .w(px(52.))
                        .flex_shrink_0()
                        .text_xs()
                        .text_color(theme::text_muted())
                        .child(item.group),
                )
                .child(
                    h_flex()
                        .flex_1()
                        .min_w_0()
                        .child(pre)
                        .child(
                            div()
                                .text_color(theme::accent())
                                .font_weight(FontWeight::SEMIBOLD)
                                .child(hit),
                        )
                        .child(post),
                )
                .children(item.key.map(|k| {
                    div()
                        .px_1p5()
                        .rounded(px(4.))
                        .border_1()
                        .border_color(theme::border_strong())
                        .text_xs()
                        .text_color(theme::text_muted())
                        .child(k)
                }))
                .on_click(cx.listener(move |this, _, window, cx| {
                    if let Some(p) = this.palette.as_mut() {
                        p.selected = i;
                    }
                    this.run_palette(window, cx);
                }))
        });
        let input = p.input.clone();
        Some(
            div()
                .id("palette-overlay")
                .absolute()
                .inset_0()
                .bg(theme::chrome().opacity(0.6))
                .flex()
                .justify_center()
                .items_start()
                .pt(px(72.))
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, window, cx| this.close_palette(window, cx)),
                )
                .child(
                    v_flex()
                        .id("palette")
                        .key_context(PALETTE_CONTEXT)
                        .w(px(600.))
                        .max_h(px(440.))
                        .bg(theme::elevated())
                        .border_1()
                        .border_color(c_strong())
                        .rounded(px(10.))
                        .shadow_lg()
                        .overflow_hidden()
                        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                        .on_action(
                            cx.listener(|this, _: &PaletteUp, _, cx| this.move_palette(false, cx)),
                        )
                        .on_action(
                            cx.listener(|this, _: &PaletteDown, _, cx| this.move_palette(true, cx)),
                        )
                        .on_action(cx.listener(|this, _: &ClosePalette, window, cx| {
                            this.close_palette(window, cx)
                        }))
                        .child(
                            div()
                                .p_2()
                                .border_b_1()
                                .border_color(theme::border())
                                .child(Input::new(&input).appearance(false)),
                        )
                        .child(v_flex().p_1().gap(px(1.)).children(rows))
                        .child(
                            h_flex()
                                .px_3()
                                .py_2()
                                .gap_4()
                                .border_t_1()
                                .border_color(theme::border())
                                .text_xs()
                                .text_color(theme::text_muted())
                                .child("↑↓ to move")
                                .child("↵ to run")
                                .child("esc to close"),
                        ),
                )
                .into_any_element(),
        )
    }
}

fn c_strong() -> Hsla {
    theme::border_strong()
}

#[cfg(test)]
mod tests {
    use super::{Command, items};

    #[test]
    fn empty_query_lists_every_command() {
        let all = items("", true);
        assert!(all.iter().any(|i| i.command == Command::FollowStream));
        assert!(all.iter().all(|i| i.matched.is_none()));
        assert!(!all.iter().any(|i| matches!(i.command, Command::Filter(_))));
        // Without a capture only opening one makes sense.
        let none = items("", false);
        assert_eq!(none.len(), 1);
        assert_eq!(none[0].command, Command::Open);
    }

    #[test]
    fn query_matches_titles_and_marks_the_match() {
        let found = items("FOLLOW", true);
        assert_eq!(found[0].command, Command::FollowStream);
        assert_eq!(found[0].matched, Some(0..6));
        // The query can also be applied as a filter, last.
        assert_eq!(
            found.last().map(|i| &i.command),
            Some(&Command::Filter("FOLLOW".to_string()))
        );
    }

    #[test]
    fn group_names_match_too() {
        let found = items("focus", true);
        let focus: Vec<_> = found
            .iter()
            .filter(|i| matches!(i.command, Command::Focus(_)))
            .collect();
        assert_eq!(focus.len(), 3);
    }

    #[test]
    fn numbers_go_to_a_packet_first() {
        let found = items("44", true);
        assert_eq!(found[0].command, Command::GoTo(44));
        assert!(
            items("0", true)
                .iter()
                .all(|i| !matches!(i.command, Command::GoTo(_)))
        );
        assert!(
            items("44", false)
                .iter()
                .all(|i| !matches!(i.command, Command::GoTo(_)))
        );
    }
}
