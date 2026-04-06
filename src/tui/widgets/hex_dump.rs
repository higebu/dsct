//! Hex dump widget with byte-range highlighting and windowed rendering.

use std::ops::Range;

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::tui::app::App;
use crate::tui::state::Pane;

/// Render the hex dump into the given area.
pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let is_active = app.active_pane == Pane::HexDump;
    let border_style = if is_active {
        Style::default().fg(ratatui::style::Color::Cyan)
    } else {
        Style::default().fg(ratatui::style::Color::DarkGray)
    };

    let highlight_range = app.selected_byte_range();
    // Zero-copy: raw bytes come directly from the mmap.
    let raw = app.selected_raw_bytes();

    let inner_height = area.height.saturating_sub(2) as usize;
    let offset = app.hex_dump.scroll_offset;

    let lines = match raw {
        Some(data) => {
            build_hex_lines_windowed(data, highlight_range.as_ref(), offset, inner_height)
        }
        None => vec![],
    };

    let paragraph = Paragraph::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_style)
            .title(" Hex Dump "),
    );

    f.render_widget(paragraph, area);
}

/// Build hex dump lines for a window of visible rows only.
fn build_hex_lines_windowed<'a>(
    data: &[u8],
    highlight: Option<&Range<usize>>,
    line_offset: usize,
    max_lines: usize,
) -> Vec<Line<'a>> {
    let highlight_style = Style::default()
        .add_modifier(Modifier::REVERSED)
        .fg(ratatui::style::Color::Yellow);
    let normal_style = Style::default();
    let offset_style = Style::default().fg(ratatui::style::Color::DarkGray);

    let total_lines = data.len().div_ceil(16);
    let start_line = line_offset.min(total_lines);
    let end_line = total_lines.min(start_line + max_lines);

    let mut lines = Vec::with_capacity(end_line - start_line);

    for line_idx in start_line..end_line {
        let base_offset = line_idx * 16;
        let chunk_end = data.len().min(base_offset + 16);
        let chunk = &data[base_offset..chunk_end];
        let mut spans: Vec<Span> = Vec::new();

        spans.push(Span::styled(format!("{base_offset:04x}  "), offset_style));

        for (i, &byte) in chunk.iter().enumerate() {
            let byte_offset = base_offset + i;
            let is_highlighted =
                highlight.is_some_and(|r| byte_offset >= r.start && byte_offset < r.end);
            let style = if is_highlighted {
                highlight_style
            } else {
                normal_style
            };
            spans.push(Span::styled(format!("{byte:02x}"), style));
            if i == 7 {
                spans.push(Span::raw("  "));
            } else if i < 15 {
                spans.push(Span::raw(" "));
            }
        }

        if chunk.len() < 16 {
            for i in chunk.len()..16 {
                spans.push(Span::raw("  "));
                if i == 7 {
                    spans.push(Span::raw("  "));
                } else if i < 15 {
                    spans.push(Span::raw(" "));
                }
            }
        }

        spans.push(Span::raw("  "));

        for (i, &byte) in chunk.iter().enumerate() {
            let byte_offset = base_offset + i;
            let is_highlighted =
                highlight.is_some_and(|r| byte_offset >= r.start && byte_offset < r.end);
            let style = if is_highlighted {
                highlight_style
            } else {
                normal_style
            };
            let ch = if byte.is_ascii_graphic() || byte == b' ' {
                byte as char
            } else {
                '.'
            };
            spans.push(Span::styled(String::from(ch), style));
        }

        lines.push(Line::from(spans));
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_hex_lines_windowed_empty() {
        let lines = build_hex_lines_windowed(&[], None, 0, 10);
        assert!(lines.is_empty());
    }

    #[test]
    fn build_hex_lines_windowed_single_line() {
        let data: Vec<u8> = (0..16).collect();
        let lines = build_hex_lines_windowed(&data, None, 0, 10);
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn build_hex_lines_windowed_with_offset() {
        let data: Vec<u8> = (0..64).collect();
        let lines = build_hex_lines_windowed(&data, None, 2, 10);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn build_hex_lines_windowed_with_highlight() {
        let data: Vec<u8> = (0..32).collect();
        let lines = build_hex_lines_windowed(&data, Some(&(4..8)), 0, 10);
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn build_hex_lines_windowed_limits_output() {
        let data: Vec<u8> = (0..160).collect();
        let lines = build_hex_lines_windowed(&data, None, 0, 3);
        assert_eq!(lines.len(), 3);
    }
}
