//! Protocol detail tree widget.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState};

use crate::tui::app::{App, visible_nodes};
use crate::tui::state::{Pane, SelectionMode};

/// Render the protocol detail tree into the given area.
pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_pane == Pane::DetailTree
        || app.active_pane == Pane::TreeSearch
        || app.active_pane == Pane::YankPrompt;
    let border_style = if is_active {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let nodes = app
        .selected
        .as_ref()
        .map(|sel| sel.tree_nodes.as_slice())
        .unwrap_or(&[]);

    let visible: Vec<(usize, &crate::tui::state::TreeNode)> = visible_nodes(nodes).collect();

    // Determine line-selection range (if active).
    let line_sel_range = app.detail_tree.selection.as_ref().and_then(|s| {
        if s.mode != SelectionMode::Line {
            return None;
        }
        let a = visible.iter().position(|(i, _)| *i == s.anchor_node)?;
        let b = visible
            .iter()
            .position(|(i, _)| *i == app.detail_tree.selected)?;
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        Some(lo..=hi)
    });

    let items: Vec<ListItem> = visible
        .iter()
        .enumerate()
        .map(|(vis_idx, (_, node))| {
            let indent = "  ".repeat(node.depth);
            let icon = if node.children_count > 0 {
                if node.expanded {
                    "\u{25bc} "
                } else {
                    "\u{25b6} "
                }
            } else {
                "  "
            };

            let mut style = if node.is_layer {
                Style::default().add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            // Highlight line-selected rows.
            if let Some(ref range) = line_sel_range
                && range.contains(&vis_idx)
            {
                style = style.bg(Color::DarkGray).fg(Color::White);
            }

            ListItem::new(Line::from(vec![
                Span::raw(indent),
                Span::raw(icon.to_string()),
                Span::styled(node.label.clone(), style),
            ]))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(" Protocol Detail "),
        )
        .highlight_style(
            Style::default()
                .add_modifier(Modifier::REVERSED)
                .fg(Color::White),
        );

    let selected_visible_idx = visible
        .iter()
        .position(|(orig_idx, _)| *orig_idx == app.detail_tree.selected);

    let mut state = ListState::default();
    state.select(selected_visible_idx);

    f.render_stateful_widget(list, area, &mut state);
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use super::*;
    use crate::tui::test_util::{make_test_app, render_to_string};

    #[test]
    fn detail_tree_renders_title() {
        let app = make_test_app(1);
        let dump = render_to_string(60, 15, |f| {
            let area = Rect {
                x: 0,
                y: 0,
                width: 60,
                height: 15,
            };
            render(f, &app, area);
        });
        assert!(dump.contains("Protocol Detail"), "dump: {dump}");
    }

    #[test]
    fn detail_tree_renders_layer_label() {
        let app = make_test_app(1);
        let dump = render_to_string(60, 15, |f| {
            let area = Rect {
                x: 0,
                y: 0,
                width: 60,
                height: 15,
            };
            render(f, &app, area);
        });
        assert!(
            dump.contains("Ethernet") || dump.contains("IPv4") || dump.contains("UDP"),
            "expected a layer label in dump: {dump}"
        );
    }

    #[test]
    fn detail_tree_renders_empty_when_no_selection() {
        let app = make_test_app(0);
        let dump = render_to_string(60, 15, |f| {
            let area = Rect {
                x: 0,
                y: 0,
                width: 60,
                height: 15,
            };
            render(f, &app, area);
        });
        assert!(dump.contains("Protocol Detail"), "dump: {dump}");
    }
}
