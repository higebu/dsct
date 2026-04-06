//! Full-screen Follow Stream overlay widget.
//!
//! Renders the collected stream data with direction-based coloring:
//! client → server in blue, server → client in red.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};

use crate::tui::state::StreamViewState;

/// Render the Follow Stream overlay over the entire frame area.
pub fn render(f: &mut Frame, sv: &StreamViewState, area: Rect) {
    f.render_widget(Clear, area);

    let inner_height = area.height.saturating_sub(4) as usize; // borders + hint line
    let total = sv.lines.len();
    let offset = sv.scroll_offset.min(total.saturating_sub(1));
    let end = total.min(offset + inner_height);

    let lines: Vec<Line> = sv.lines[offset..end]
        .iter()
        .map(|line| {
            let style = if line.is_client {
                Style::default().fg(Color::Blue)
            } else {
                Style::default().fg(Color::Red)
            };
            let arrow = if line.is_client {
                "\u{25b6} "
            } else {
                "\u{25c0} "
            };
            Line::from(vec![
                Span::styled(arrow, style.add_modifier(Modifier::BOLD)),
                Span::styled(line.text.as_str(), style),
            ])
        })
        .collect();

    let position = if total > 0 {
        format!(" {}/{} ", offset + 1, total)
    } else {
        " empty ".to_string()
    };

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(format!(" {} ", sv.title))
        .title_bottom(Line::from(vec![
            Span::styled(" Esc", Style::default().fg(Color::Yellow)),
            Span::raw(": close  "),
            Span::styled("j/k", Style::default().fg(Color::Yellow)),
            Span::raw(": scroll  "),
            Span::styled("g/G", Style::default().fg(Color::Yellow)),
            Span::raw(": top/bottom "),
            Span::raw(position),
        ]));

    let paragraph = Paragraph::new(lines).block(block);
    f.render_widget(paragraph, area);
}
