//! The detail tree and hex dump panes, operable with the mouse and the
//! keyboard: ↑/↓ move, ←/→ collapse/expand (tree) or move by byte (hex),
//! Enter/Space toggle, and a click or Tab gives a pane focus.

use std::ops::Range;

use dsct::session::fields::{FieldRef, Split};
use dsct::session::state::TreeNode;
use gpui_kit::assets::IconName as AssetIcon;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::menu::{ContextMenuExt as _, DropdownMenu as _, PopupMenu, PopupMenuItem};
use gpui_kit::component::{ActiveTheme as _, Icon, IconName, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::{DsctApp, HEX_CONTEXT, Pane, TREE_CONTEXT};
use crate::format::{self, HEX_BYTES_PER_LINE};
use crate::tree_nav::{self, TreeMove};
use crate::{Collapse, Expand, SelectNext, SelectPrev, ToggleNode, theme};

/// Height of a detail tree row.
const TREE_ROW: f32 = 24.;
/// Indentation per tree level; indent guides sit on this grid.
const INDENT: f32 = 16.;

/// What the actions on a detail tree value may do.
#[derive(Clone)]
struct ValueActions {
    field: FieldRef,
    /// The field can be a column, be pinned and split the chart (not a
    /// protocol, nor a value name the sidebar does not count).
    field_actions: bool,
    is_column: bool,
    pinned: bool,
}

/// `value` shortened for a menu label.
fn quoted(value: &str) -> String {
    const MAX: usize = 32;
    if value.chars().count() > MAX {
        let short: String = value.chars().take(MAX).collect();
        format!("\"{short}…\"")
    } else {
        format!("\"{value}\"")
    }
}

/// The menu of actions on a value (the ⋯ button and the right-click menu).
fn value_menu(mut menu: PopupMenu, app: &WeakEntity<DsctApp>, actions: &ValueActions) -> PopupMenu {
    let target = match &actions.field.value {
        Some(v) => quoted(v),
        None => actions.field.path.to_uppercase(),
    };
    for (exclude, label) in [(false, "Filter for"), (true, "Filter out")] {
        let app = app.clone();
        let field = actions.field.clone();
        menu = menu.item(PopupMenuItem::new(format!("{label} {target}")).on_click(
            move |_, window, cx| {
                let _ = app.update(cx, |app, cx| app.refine(&field, exclude, window, cx));
            },
        ));
    }
    if actions.field_actions {
        let path = actions.field.path.clone();
        let column = {
            let (app, path) = (app.clone(), path.clone());
            PopupMenuItem::new(if actions.is_column {
                format!("Remove the {path} column")
            } else {
                format!("Add {path} as a column")
            })
            .on_click(move |_, _, cx| {
                let _ = app.update(cx, |app, cx| app.toggle_column(&path, cx));
            })
        };
        let pin = {
            let (app, path) = (app.clone(), path.clone());
            PopupMenuItem::new(if actions.pinned {
                format!("Unpin {path}")
            } else {
                format!("Pin {path} in the sidebar")
            })
            .on_click(move |_, _, cx| {
                let _ = app.update(cx, |app, cx| app.toggle_pin(&path, cx));
            })
        };
        let split = {
            let app = app.clone();
            PopupMenuItem::new(format!("Split the chart by {path}")).on_click(move |_, _, cx| {
                let split = Split::Field(path.clone());
                let _ = app.update(cx, |app, cx| app.set_split(split, cx));
            })
        };
        menu = menu.separator().item(column).item(pin).item(split);
    }
    if let Some(value) = actions.field.value.clone() {
        menu = menu
            .separator()
            .item(PopupMenuItem::new("Copy value").on_click(move |_, _, cx| {
                cx.write_to_clipboard(ClipboardItem::new_string(value.clone()))
            }));
    }
    menu
}

impl DsctApp {
    /// What the actions on tree node `node` may do, if it has a value.
    fn value_actions(&self, node: &TreeNode, columns: &[String]) -> Option<ValueActions> {
        let field = node.filter.clone()?;
        let field_actions = field.value.is_some()
            && (!field.path.ends_with("_name")
                || self
                    .fields
                    .stats
                    .as_ref()
                    .is_some_and(|s| s.field(&field.path).is_some()));
        Some(ValueActions {
            is_column: columns.contains(&field.path),
            pinned: self.fields.pinned.contains(&field.path),
            field,
            field_actions,
        })
    }

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
    fn tree_key(&self, f: impl FnOnce(&[TreeNode], usize) -> TreeMove) -> TreeMove {
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

    /// The bar over a pane: its title (bright while focused) and context.
    fn pane_header(&self, title: &'static str, focused: bool, detail: Vec<String>) -> Div {
        h_flex()
            .h(px(30.))
            .flex_shrink_0()
            .px_3()
            .gap_1p5()
            .border_b_1()
            .border_color(theme::border())
            .text_xs()
            .text_color(theme::text_muted())
            .child(
                div()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(if focused {
                        theme::text_bright()
                    } else {
                        theme::text_muted()
                    })
                    .child(title),
            )
            .children(detail.into_iter().map(|d| div().child(d)))
    }

    /// Path of names from the selected node's layer down to it, for the
    /// Details header (`HTTP › Method`).
    fn selection_path(&self) -> Vec<String> {
        let guard = self.session.borrow();
        let (Some(idx), Some(nodes)) = (
            self.tree.selected,
            guard
                .as_ref()
                .and_then(|s| s.selected.as_ref())
                .map(|sel| &sel.tree_nodes[..]),
        ) else {
            return Vec::new();
        };
        let mut path = Vec::new();
        let mut current = Some(idx);
        while let Some(i) = current {
            path.push(format::split_label(&nodes[i].label).0.to_string());
            current = tree_nav::parent(nodes, i);
        }
        path.reverse();
        let mut out = vec!["·".to_string()];
        for (i, name) in path.into_iter().enumerate() {
            if i > 0 {
                out.push("›".to_string());
            }
            out.push(name);
        }
        out
    }

    pub(crate) fn render_tree(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let count = self.tree.visible.len();
        let focused = self.pane_focused(Pane::Details, window, cx);
        let header = self.pane_header("Details", focused, self.selection_path());
        v_flex()
            .size_full()
            .border_1()
            .border_color(if focused {
                theme::accent()
            } else {
                transparent_black()
            })
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
            .child(header)
            .child(
                uniform_list(
                    "detail-tree",
                    count,
                    cx.processor(|this, range: Range<usize>, _, cx| {
                        let mono = cx.theme().mono_font_family.clone();
                        let guard = this.session.borrow();
                        let nodes = guard
                            .as_ref()
                            .and_then(|s| s.selected.as_ref())
                            .map(|sel| &sel.tree_nodes[..])
                            .unwrap_or(&[]);
                        // Layer number of each top-level node, for its summary.
                        let layer_of =
                            |idx: usize| nodes[..idx].iter().filter(|n| n.depth == 0).count();
                        let columns = this.table.read(cx).delegate().extra.clone();
                        let app = cx.entity().downgrade();
                        let mut rows = Vec::with_capacity(range.len());
                        for row in range {
                            let Some(&idx) = this.tree.visible.get(row) else {
                                continue;
                            };
                            let Some(node) = nodes.get(idx) else {
                                continue;
                            };
                            let selected = this.tree.selected == Some(idx);
                            let chevron = (node.children_count > 0).then(|| {
                                Icon::new(if node.expanded {
                                    IconName::ChevronDown
                                } else {
                                    IconName::ChevronRight
                                })
                                .xsmall()
                                .text_color(theme::text_muted())
                            });
                            let guides =
                                (0..node.depth).map(|_| {
                                    div().w(px(INDENT)).h_full().flex_shrink_0().child(
                                        div().ml(px(11.)).w(px(1.)).h_full().bg(theme::border()),
                                    )
                                });
                            let content = if node.depth == 0 {
                                let name = node.label.clone();
                                let color = format::protocol_swatch(&name)
                                    .map_or(theme::text_bright(), theme::swatch);
                                let summary =
                                    this.tree.summaries.get(layer_of(idx)).cloned().flatten();
                                h_flex()
                                    .gap_2p5()
                                    .child(
                                        div()
                                            .font_weight(FontWeight::SEMIBOLD)
                                            .text_color(color)
                                            .child(name),
                                    )
                                    .children(summary.map(|s| {
                                        div()
                                            .font_family(mono.clone())
                                            .text_xs()
                                            .text_color(theme::text_muted())
                                            .child(s)
                                    }))
                            } else {
                                let (name, value) = format::split_label(&node.label);
                                h_flex()
                                    .child(
                                        div()
                                            .text_color(theme::text_muted())
                                            .child(name.to_string()),
                                    )
                                    .children(value.map(|v| {
                                        h_flex()
                                            .child(
                                                div()
                                                    .mx_1p5()
                                                    .text_color(theme::text_faint())
                                                    .child("="),
                                            )
                                            .child(
                                                div()
                                                    .font_family(mono.clone())
                                                    .text_xs()
                                                    .text_color(theme::value(format::value_kind(v)))
                                                    .child(v.to_string()),
                                            )
                                    }))
                            };
                            let actions = this.value_actions(node, &columns);
                            let buttons = actions.clone().filter(|_| selected).map(|actions| {
                                let (plus, minus) = (actions.field.clone(), actions.field.clone());
                                let menu_app = app.clone();
                                h_flex()
                                    .flex_shrink_0()
                                    .gap_0p5()
                                    .child(
                                        Button::new(("tree-for", idx))
                                            .icon(Icon::new(AssetIcon::ZoomIn))
                                            .xsmall()
                                            .ghost()
                                            .tooltip("Filter for this value")
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                cx.stop_propagation();
                                                this.refine(&plus, false, window, cx)
                                            })),
                                    )
                                    .child(
                                        Button::new(("tree-out", idx))
                                            .icon(Icon::new(AssetIcon::ZoomOut))
                                            .xsmall()
                                            .ghost()
                                            .tooltip("Filter out this value")
                                            .on_click(cx.listener(move |this, _, window, cx| {
                                                cx.stop_propagation();
                                                this.refine(&minus, true, window, cx)
                                            })),
                                    )
                                    .child(
                                        Button::new(("tree-more", idx))
                                            .icon(Icon::new(AssetIcon::Ellipsis))
                                            .xsmall()
                                            .ghost()
                                            .tooltip("More actions")
                                            .dropdown_menu(move |menu, _, _| {
                                                value_menu(menu, &menu_app, &actions)
                                            }),
                                    )
                            });
                            let row_el = h_flex()
                                .id(("node", idx))
                                .w_full()
                                .h(px(TREE_ROW))
                                .pl_1()
                                .pr_3()
                                .whitespace_nowrap()
                                .when(selected, |d| d.bg(theme::selection()))
                                .when(!selected, |d| d.hover(|d| d.bg(theme::hover())))
                                .children(guides)
                                .child(
                                    // A 24 × 24 px target for the chevron.
                                    div()
                                        .id(("toggle", idx))
                                        .size(px(24.))
                                        .flex_shrink_0()
                                        .flex()
                                        .items_center()
                                        .justify_center()
                                        .children(chevron)
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            // Toggling is not also a click on the row.
                                            cx.stop_propagation();
                                            this.toggle_node(idx, cx)
                                        })),
                                )
                                .child(content)
                                .child(div().flex_1())
                                .children(buttons)
                                .on_click(cx.listener(move |this, event: &ClickEvent, _, cx| {
                                    if event.click_count() == 2 {
                                        this.toggle_node(idx, cx);
                                    }
                                    this.select_node(idx, cx);
                                }));
                            rows.push(match actions {
                                Some(actions) => {
                                    let app = app.clone();
                                    row_el
                                        .context_menu(move |menu, _, _| {
                                            value_menu(menu, &app, &actions)
                                        })
                                        .into_any_element()
                                }
                                None => row_el.into_any_element(),
                            });
                        }
                        rows
                    }),
                )
                .track_scroll(&self.tree.tree_scroll)
                .py_1()
                .flex_1(),
            )
    }

    pub(crate) fn render_hex(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let len = self
            .session
            .borrow()
            .as_ref()
            .and_then(|s| s.selected_raw_bytes())
            .map_or(0, <[u8]>::len);
        let lines = format::hex_line_count(len);
        let focused = self.pane_focused(Pane::Bytes, window, cx);
        let mut detail = vec!["·".to_string(), format!("{len} bytes")];
        if let Some(range) = self.selected_byte_range() {
            detail.push("·".to_string());
            detail.push(format!(
                "0x{:04x}–0x{:04x} · {} bytes",
                range.start,
                range.end.saturating_sub(1),
                range.len()
            ));
        }
        let header = self.pane_header("Bytes", focused, detail);
        let mono = cx.theme().mono_font_family.clone();
        v_flex()
            .size_full()
            .border_1()
            .border_color(if focused {
                theme::accent()
            } else {
                transparent_black()
            })
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
            .child(header)
            .child(
                uniform_list(
                    "hex-dump",
                    lines,
                    cx.processor(|this, range: Range<usize>, _, cx| {
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
                                let hex_cells = line.cells.iter().enumerate().map(|(i, c)| {
                                    let byte = base + i;
                                    let zero = data.get(byte) == Some(&0);
                                    div()
                                        .id(("hex", byte))
                                        .px(px(3.))
                                        .rounded(px(3.))
                                        .when(i == 7, |d| d.mr(px(10.)))
                                        .when(c.highlighted, |d| {
                                            d.bg(theme::selection())
                                                .text_color(theme::text_bright())
                                        })
                                        .when(c.cursor, |d| {
                                            d.border_1().border_color(theme::accent())
                                        })
                                        .when(!c.highlighted && zero, |d| {
                                            d.text_color(theme::text_faint())
                                        })
                                        .child(c.hex.clone())
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.tree.hex_cursor = Some(byte);
                                            this.move_hex_cursor(0, cx);
                                        }))
                                });
                                let ascii_cells = line.cells.iter().map(|c| {
                                    div()
                                        .w(px(8.))
                                        .when(c.highlighted, |d| {
                                            d.bg(theme::selection())
                                                .text_color(theme::text_bright())
                                        })
                                        .when(!c.highlighted && c.ascii == '.', |d| {
                                            d.text_color(theme::text_faint())
                                        })
                                        .child(c.ascii.to_string())
                                });
                                h_flex()
                                    .h(px(22.))
                                    .px_3()
                                    .gap_4()
                                    .child(
                                        div()
                                            .w(px(40.))
                                            .text_right()
                                            .text_color(theme::text_faint())
                                            .child(line.offset),
                                    )
                                    .child(h_flex().children(hex_cells))
                                    .child(h_flex().text_color(theme::text()).children(ascii_cells))
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .track_scroll(&self.tree.hex_scroll)
                .py_1()
                .font_family(mono)
                .text_sm()
                .flex_1(),
            )
    }
}
