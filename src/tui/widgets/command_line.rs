//! Vim-style command line widget with floating completion dropdown.
//!
//! Displayed on the last line of the terminal.  Shows `/query` when filter
//! input is active, empty otherwise.  Completion candidates float above
//! the command line.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

use crate::tui::app::App;
use crate::tui::state::Pane;

/// Render the command line and floating completion dropdown.
pub fn render(f: &mut Frame, app: &App, area: Rect) {
    if app.active_pane == Pane::TreeSearch {
        // Tree search mode: show "/query" for in-tree search.
        let line = Line::from(vec![
            Span::styled("/", Style::default().fg(Color::Yellow)),
            Span::raw(app.detail_tree.search_query.as_str()),
        ]);
        f.render_widget(Paragraph::new(line), area);
        f.set_cursor_position((
            area.x + 1 + app.detail_tree.search_query.len() as u16,
            area.y,
        ));

        // Floating completion dropdown for tree search.
        if !app.detail_tree.search_completions.is_empty() {
            let max_items = 8;
            let completions = &app.detail_tree.search_completions;
            let n = completions.len().min(max_items) as u16;
            let dropdown_height = n + 2;

            let max_label_width = completions
                .iter()
                .take(max_items)
                .map(|c| c.label.len())
                .max()
                .unwrap_or(0) as u16;
            let dropdown_width = (max_label_width + 3)
                .max(20)
                .min(area.width.saturating_sub(1));

            let dropdown_area = Rect {
                x: area.x + 1,
                y: area.y.saturating_sub(dropdown_height),
                width: dropdown_width,
                height: dropdown_height,
            };

            f.render_widget(Clear, dropdown_area);

            let items: Vec<ListItem> = completions
                .iter()
                .take(max_items)
                .map(|c| ListItem::new(c.label.as_str()))
                .collect();

            let list = List::new(items)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Yellow)),
                )
                .highlight_style(
                    Style::default()
                        .add_modifier(Modifier::REVERSED)
                        .fg(Color::Yellow),
                );

            let mut state = ListState::default();
            state.select(Some(app.detail_tree.search_completion_selected));
            f.render_stateful_widget(list, dropdown_area, &mut state);
        }
        return;
    }

    if app.active_pane == Pane::CommandMode {
        if let Some(cmd) = &app.command {
            let line = Line::from(vec![
                Span::styled(":", Style::default().fg(Color::Cyan)),
                Span::raw(cmd.buf.input.as_str()),
            ]);
            f.render_widget(Paragraph::new(line), area);
            f.set_cursor_position((area.x + 1 + cmd.buf.cursor as u16, area.y));
        }
        return;
    }

    if app.active_pane == Pane::YankPrompt {
        let line = Line::from(vec![Span::styled(
            "Copy as: [t]ext / [h]ex",
            Style::default().fg(Color::Yellow),
        )]);
        f.render_widget(Paragraph::new(line), area);
        return;
    }

    if app.active_pane != Pane::FilterInput {
        // Show transient yank message if present.
        if let Some(msg) = &app.detail_tree.yank_message {
            let line = Line::from(Span::styled(
                msg.as_str(),
                Style::default().fg(Color::Green),
            ));
            f.render_widget(Paragraph::new(line), area);
            return;
        }
        // Normal mode: show applied filter or tree search query in dim style.
        if !app.filter.applied.is_empty() {
            let line = Line::from(vec![
                Span::styled("/", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    app.filter.applied.as_str(),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            f.render_widget(Paragraph::new(line), area);
        } else if !app.detail_tree.search_query.is_empty() {
            let line = Line::from(vec![
                Span::styled("/", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    app.detail_tree.search_query.as_str(),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);
            f.render_widget(Paragraph::new(line), area);
        }
        return;
    }

    // Show filter error message in red if present.
    if let Some(ref err) = app.filter.error_message {
        let line = Line::from(Span::styled(err.as_str(), Style::default().fg(Color::Red)));
        f.render_widget(Paragraph::new(line), area);
        f.set_cursor_position((area.x + 1 + app.filter.buf.cursor as u16, area.y));
        return;
    }

    // "/" prefix + input text
    let line = Line::from(vec![
        Span::styled("/", Style::default().fg(Color::Cyan)),
        Span::raw(app.filter.buf.input.as_str()),
    ]);
    f.render_widget(Paragraph::new(line), area);

    // Cursor position: "/" (1 char) + cursor offset
    f.set_cursor_position((area.x + 1 + app.filter.buf.cursor as u16, area.y));

    // Floating completion dropdown (above the command line)
    if app.filter.completion_visible && !app.filter.completions.is_empty() {
        let max_items = 8;
        let n = app.filter.completions.len().min(max_items) as u16;
        let dropdown_height = n + 2; // items + top/bottom border

        // Width adapts to the longest candidate (+ 2 for borders, + 1 padding).
        let max_label_width = app
            .filter
            .completions
            .iter()
            .take(max_items)
            .map(|c| c.label.len())
            .max()
            .unwrap_or(0) as u16;
        let dropdown_width = (max_label_width + 3)
            .max(20)
            .min(area.width.saturating_sub(1));

        let dropdown_area = Rect {
            x: area.x + 1,
            y: area.y.saturating_sub(dropdown_height),
            width: dropdown_width,
            height: dropdown_height,
        };

        // Clear the area behind the dropdown.
        f.render_widget(Clear, dropdown_area);

        let items: Vec<ListItem> = app
            .filter
            .completions
            .iter()
            .take(max_items)
            .map(|c| ListItem::new(c.label.as_str()))
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::DarkGray)),
            )
            .highlight_style(
                Style::default()
                    .add_modifier(Modifier::REVERSED)
                    .fg(Color::Cyan),
            );

        let mut state = ListState::default();
        state.select(Some(app.filter.completion_selected));
        f.render_stateful_widget(list, dropdown_area, &mut state);
    }
}
