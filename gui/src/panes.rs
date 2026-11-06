//! The detail tree and hex dump panes, operable with the mouse and the
//! keyboard: ↑/↓ move, ←/→ collapse/expand (tree) or move by byte (hex),
//! Enter/Space toggle, and a click or Tab gives a pane focus.

use std::ops::Range;

use gpui_kit::component::{ActiveTheme as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::{DsctApp, HEX_CONTEXT, Pane, TREE_CONTEXT};
use crate::format::{self, HEX_BYTES_PER_LINE};
use crate::tree_nav::{self, TreeMove};
use crate::{Collapse, Expand, SelectNext, SelectPrev, ToggleNode};

/// Opacity of the selection color (the theme's blue), shared by the packet
/// table, the selected tree node, and the hex cursor.
pub const SELECTION_ALPHA: f32 = 0.35;

/// The selection color: the same in every pane.
pub fn selection_color(cx: &App) -> Hsla {
    cx.theme().blue.opacity(SELECTION_ALPHA)
}

impl DsctApp {
    /// Select tree node `idx`: highlight its bytes and keep both panes
    /// scrolled to it.
    pub(crate) fn select_node(&mut self, idx: usize, cx: &mut Context<Self>) {
        self.tree.selected = Some(idx);
        self.tree.hex_cursor = None;
        if let Some(pos) = self.tree.visible.iter().position(|&i| i == idx) {
            self.tree
                .tree_scroll
                .scroll_to_item(pos, ScrollStrategy::Nearest);
        }
        if let Some(range) = self.selected_byte_range() {
            self.tree.hex_scroll.scroll_to_item(
                format::first_highlighted_line(&range),
                ScrollStrategy::Nearest,
            );
        }
        cx.notify();
    }

    /// Expand or collapse tree node `idx`.
    pub(crate) fn toggle_node(&mut self, idx: usize, cx: &mut Context<Self>) {
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

    pub(crate) fn selected_byte_range(&self) -> Option<Range<usize>> {
        let idx = self.tree.selected?;
        let guard = self.session.borrow();
        let node = guard.as_ref()?.selected.as_ref()?.tree_nodes.get(idx)?;
        Some(node.byte_range.clone())
    }

    /// Apply a keyboard move in the tree.
    fn tree_move(&mut self, mv: TreeMove, cx: &mut Context<Self>) {
        match mv {
            TreeMove::Select(idx) => self.select_node(idx, cx),
            TreeMove::Toggle(idx) => self.toggle_node(idx, cx),
            TreeMove::None => {}
        }
    }

    /// Compute a keyboard move from the selected node's state.
    fn tree_key(
        &self,
        f: impl FnOnce(&[dsct::session::state::TreeNode], usize) -> TreeMove,
    ) -> TreeMove {
        let guard = self.session.borrow();
        let Some(nodes) = guard
            .as_ref()
            .and_then(|s| s.selected.as_ref())
            .map(|sel| &sel.tree_nodes[..])
        else {
            return TreeMove::None;
        };
        match self.tree.selected {
            Some(selected) => f(nodes, selected),
            None => tree_nav::step(&self.tree.visible, None, true),
        }
    }

    /// Move the hex cursor by `delta` bytes and select the field under it,
    /// expanding the tree down to it.
    fn move_hex_cursor(&mut self, delta: isize, cx: &mut Context<Self>) {
        let mut guard = self.session.borrow_mut();
        let Some(session) = guard.as_mut() else {
            return;
        };
        let len = session.selected_raw_bytes().map_or(0, <[u8]>::len);
        let Some(cursor) = format::move_cursor(self.tree.hex_cursor, delta, len) else {
            return;
        };
        let node = session.selected.as_mut().and_then(|sel| {
            let idx = tree_nav::innermost_at(&sel.tree_nodes, cursor)?;
            tree_nav::expand_ancestors(&mut sel.tree_nodes, idx);
            Some(idx)
        });
        self.tree.refresh(session);
        drop(guard);
        if let Some(idx) = node {
            self.select_node(idx, cx);
        }
        self.tree.hex_cursor = Some(cursor);
        self.tree
            .hex_scroll
            .scroll_to_item(cursor / HEX_BYTES_PER_LINE, ScrollStrategy::Nearest);
        cx.notify();
    }

    /// A small title over a pane, accented while the pane has focus.
    fn pane_title(&self, title: &'static str, focused: bool, cx: &App) -> impl IntoElement {
        let theme = cx.theme();
        div()
            .px_2()
            .py_1()
            .text_xs()
            .font_weight(FontWeight::SEMIBOLD)
            .border_b_1()
            .border_color(theme.border)
            .text_color(if focused {
                theme.foreground
            } else {
                theme.muted_foreground
            })
            .child(title)
    }

    pub(crate) fn render_tree(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let count = self.tree.visible.len();
        let border = self.pane_border(Pane::Details, window, cx);
        let focused = self.tree_focus.contains_focused(window, cx);
        let title = self.pane_title("Details", focused, cx);
        v_flex()
            .size_full()
            .border_1()
            .border_color(border)
            .track_focus(&self.tree_focus)
            .key_context(TREE_CONTEXT)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, window, cx| this.focus_pane(Pane::Details, window, cx)),
            )
            .on_action(cx.listener(|this, _: &SelectNext, _, cx| {
                let mv = tree_nav::step(&this.tree.visible, this.tree.selected, true);
                this.tree_move(mv, cx);
            }))
            .on_action(cx.listener(|this, _: &SelectPrev, _, cx| {
                let mv = tree_nav::step(&this.tree.visible, this.tree.selected, false);
                this.tree_move(mv, cx);
            }))
            .on_action(cx.listener(|this, _: &Expand, _, cx| {
                let mv = this.tree_key(tree_nav::right);
                this.tree_move(mv, cx);
            }))
            .on_action(cx.listener(|this, _: &Collapse, _, cx| {
                let mv = this.tree_key(tree_nav::left);
                this.tree_move(mv, cx);
            }))
            .on_action(cx.listener(|this, _: &ToggleNode, _, cx| {
                if let Some(idx) = this.tree.selected {
                    this.toggle_node(idx, cx);
                }
            }))
            .child(title)
            .child(
                uniform_list(
                    "detail-tree",
                    count,
                    cx.processor(|this, range: Range<usize>, _, cx| {
                        let selection = selection_color(cx);
                        let guard = this.session.borrow();
                        let nodes = guard
                            .as_ref()
                            .and_then(|s| s.selected.as_ref())
                            .map(|sel| &sel.tree_nodes[..])
                            .unwrap_or(&[]);
                        let muted = cx.theme().muted_foreground;
                        let mut rows = Vec::with_capacity(range.len());
                        for row in range {
                            let Some(&idx) = this.tree.visible.get(row) else {
                                continue;
                            };
                            let Some(node) = nodes.get(idx) else {
                                continue;
                            };
                            let chevron = match (node.children_count > 0, node.expanded) {
                                (false, _) => "",
                                (true, true) => "▼",
                                (true, false) => "▶",
                            };
                            let selected = this.tree.selected == Some(idx);
                            rows.push(
                                h_flex()
                                    .id(("node", idx))
                                    .w_full()
                                    .h(px(26.))
                                    .pr_2()
                                    .pl(px(4. + node.depth as f32 * 16.))
                                    .when(selected, |d| d.bg(selection))
                                    .when(node.is_layer, |d| d.font_weight(FontWeight::SEMIBOLD))
                                    .child(
                                        // A 24 × 26 px target for the chevron.
                                        div()
                                            .id(("toggle", idx))
                                            .w(px(24.))
                                            .h_full()
                                            .flex()
                                            .items_center()
                                            .justify_center()
                                            .text_color(muted)
                                            .child(chevron)
                                            .on_click(cx.listener(move |this, _, _, cx| {
                                                // Toggling is not also a click on the row.
                                                cx.stop_propagation();
                                                this.toggle_node(idx, cx)
                                            })),
                                    )
                                    .child(div().whitespace_nowrap().child(node.label.clone()))
                                    .on_click(cx.listener(
                                        move |this, event: &ClickEvent, _, cx| {
                                            if event.click_count() == 2 {
                                                this.toggle_node(idx, cx);
                                            }
                                            this.select_node(idx, cx);
                                        },
                                    )),
                            );
                        }
                        rows
                    }),
                )
                .track_scroll(&self.tree.tree_scroll)
                .flex_1(),
            )
    }

    pub(crate) fn render_hex(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let lines = self
            .session
            .borrow()
            .as_ref()
            .and_then(|s| s.selected_raw_bytes())
            .map_or(0, |data| format::hex_line_count(data.len()));
        let border = self.pane_border(Pane::Bytes, window, cx);
        let focused = self.hex_focus.contains_focused(window, cx);
        let title = self.pane_title("Bytes", focused, cx);
        let mono = cx.theme().mono_font_family.clone();
        v_flex()
            .size_full()
            .border_1()
            .border_color(border)
            .track_focus(&self.hex_focus)
            .key_context(HEX_CONTEXT)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, window, cx| this.focus_pane(Pane::Bytes, window, cx)),
            )
            .on_action(cx.listener(|this, _: &SelectNext, _, cx| {
                this.move_hex_cursor(HEX_BYTES_PER_LINE as isize, cx)
            }))
            .on_action(cx.listener(|this, _: &SelectPrev, _, cx| {
                this.move_hex_cursor(-(HEX_BYTES_PER_LINE as isize), cx)
            }))
            .on_action(cx.listener(|this, _: &Expand, _, cx| this.move_hex_cursor(1, cx)))
            .on_action(cx.listener(|this, _: &Collapse, _, cx| this.move_hex_cursor(-1, cx)))
            .child(title)
            .child(
                uniform_list(
                    "hex-dump",
                    lines,
                    cx.processor(|this, range: Range<usize>, _, cx| {
                        let selection = selection_color(cx);
                        let related = cx.theme().selection;
                        let muted = cx.theme().muted_foreground;
                        let highlight = this.selected_byte_range();
                        let cursor = this.tree.hex_cursor;
                        let guard = this.session.borrow();
                        let data = guard
                            .as_ref()
                            .and_then(|s| s.selected_raw_bytes())
                            .unwrap_or(&[]);
                        range
                            .map(|line_ix| {
                                let line =
                                    format::hex_line(data, line_ix, highlight.as_ref(), cursor);
                                let base = line_ix * HEX_BYTES_PER_LINE;
                                let cell_bg = move |c: &format::HexCell| {
                                    if c.cursor {
                                        Some(selection)
                                    } else if c.highlighted {
                                        Some(related)
                                    } else {
                                        None
                                    }
                                };
                                h_flex()
                                    .px_2()
                                    .gap_3()
                                    .child(div().text_color(muted).child(line.offset))
                                    .child(h_flex().gap_1().children(
                                        line.cells.iter().enumerate().map(|(i, c)| {
                                            let byte = base + i;
                                            div()
                                                .id(("hex", byte))
                                                .when_some(cell_bg(c), |d, bg| d.bg(bg))
                                                .child(c.hex.clone())
                                                .on_click(cx.listener(move |this, _, _, cx| {
                                                    this.tree.hex_cursor = Some(byte);
                                                    this.move_hex_cursor(0, cx);
                                                }))
                                        }),
                                    ))
                                    .child(h_flex().children(line.cells.iter().map(|c| {
                                        div()
                                            .when_some(cell_bg(c), |d, bg| d.bg(bg))
                                            .child(c.ascii.to_string())
                                    })))
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .track_scroll(&self.tree.hex_scroll)
                .font_family(mono)
                .flex_1(),
            )
    }
}
