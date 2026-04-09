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

#[cfg(all(test, feature = "tui"))]
mod tests {
    use super::*;
    use crate::tui::state::StreamLine;
    use crate::tui::test_util::render_to_string;

    #[test]
    fn stream_view_renders_title_and_lines() {
        let sv = StreamViewState {
            lines: vec![
                StreamLine {
                    text: "GET / HTTP/1.1".into(),
                    is_client: true,
                },
                StreamLine {
                    text: "HTTP/1.1 200 OK".into(),
                    is_client: false,
                },
            ],
            scroll_offset: 0,
            title: "TCP Stream #1".into(),
        };
        let dump = render_to_string(60, 10, |f| {
            render(f, &sv, f.area());
        });
        assert!(dump.contains("TCP Stream #1"), "dump: {dump}");
        assert!(dump.contains("GET / HTTP/1.1"), "dump: {dump}");
        assert!(dump.contains("HTTP/1.1 200 OK"), "dump: {dump}");
    }

    #[test]
    fn stream_view_renders_arrows() {
        let sv = StreamViewState {
            lines: vec![
                StreamLine {
                    text: "client".into(),
                    is_client: true,
                },
                StreamLine {
                    text: "server".into(),
                    is_client: false,
                },
            ],
            scroll_offset: 0,
            title: "t".into(),
        };
        let dump = render_to_string(60, 10, |f| {
            render(f, &sv, f.area());
        });
        assert!(dump.contains("\u{25B6}"), "missing client arrow: {dump}");
        assert!(dump.contains("\u{25C0}"), "missing server arrow: {dump}");
    }

    #[test]
    fn stream_view_empty_state() {
        let sv = StreamViewState {
            lines: Vec::new(),
            scroll_offset: 0,
            title: "empty-test".into(),
        };
        let dump = render_to_string(60, 10, |f| {
            render(f, &sv, f.area());
        });
        assert!(dump.contains("empty"), "dump: {dump}");
    }
}
