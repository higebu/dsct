//! Packet list table widget with virtual scrolling and lazy dissection.
//!
//! Only creates [`Row`] objects for the visible rows.  Each visible row's
//! summary is obtained from the [`SummaryCache`] (which dissects on cache miss
//! using zero-copy mmap data).

use ratatui::Frame;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table, TableState};

use crate::tui::app::App;
use crate::tui::color::protocol_color;
use crate::tui::loader;
use crate::tui::state::{PacketIndex, Pane, TimeFormat};

/// Render the packet list table into the given area.
pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let is_active = app.active_pane == Pane::PacketList;
    let border_style = if is_active {
        Style::default().fg(ratatui::style::Color::Cyan)
    } else {
        Style::default().fg(ratatui::style::Color::DarkGray)
    };

    let header = Row::new(vec![
        "No.",
        "Time",
        "Source",
        "Destination",
        "Proto",
        "Len",
        "Info",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD))
    .bottom_margin(0);

    // Virtual scrolling: only create Row objects for visible rows.
    let inner_height = area.height.saturating_sub(4) as usize;
    if inner_height > 0 {
        let selected = app.packet_list.selected;

        // Auto-adjust scroll_offset so the selected row is always visible.
        if selected < app.packet_list.scroll_offset {
            app.packet_list.scroll_offset = selected;
        } else if selected >= app.packet_list.scroll_offset + inner_height {
            app.packet_list.scroll_offset = selected + 1 - inner_height;
        }
    }

    let total = app.displayed_count();
    let offset = app.packet_list.scroll_offset;
    let visible_end = total.min(offset + inner_height);

    // Prefetch: dissect visible range + margin for smooth scrolling.
    let prefetch_start = offset.saturating_sub(10);
    let prefetch_end = total.min(visible_end + 10);
    for i in prefetch_start..prefetch_end {
        if let Some(&pkt_idx) = app.filtered_indices.get(i) {
            let _ = app.get_or_dissect_summary(pkt_idx);
        }
    }

    // Collect visible packet metadata first (avoids borrow conflicts with cache).
    let visible_packets: Vec<(usize, PacketIndex)> = (offset..visible_end)
        .filter_map(|i| {
            let &pkt_idx = app.filtered_indices.get(i)?;
            let index = app.indices.get(pkt_idx)?.clone();
            Some((pkt_idx, index))
        })
        .collect();

    // Base packet for relative timestamps.
    let base_index = app.indices.first().cloned();
    let time_format = app.time_format;

    // Build visible rows and measure actual Source/Destination widths.
    let mut max_src: u16 = 6; // "Source" header
    let mut max_dst: u16 = 11; // "Destination" header
    let mut prev_index: Option<&PacketIndex> = None;
    let rows: Vec<Row> = visible_packets
        .iter()
        .map(|(pkt_idx, index)| {
            let summary = app.get_or_dissect_summary(*pkt_idx);
            let timestamp = match time_format {
                TimeFormat::Absolute => loader::format_index_timestamp(index),
                TimeFormat::Relative => {
                    if let Some(ref base) = base_index {
                        loader::format_relative_timestamp(index, base)
                    } else {
                        "0.000000".into()
                    }
                }
                TimeFormat::Delta => {
                    let ts = if let Some(prev) = prev_index {
                        loader::format_delta_timestamp(index, prev)
                    } else {
                        "0.000000".into()
                    };
                    prev_index = Some(index);
                    ts
                }
            };
            let color = protocol_color(summary.protocol);
            max_src = max_src.max(summary.source.len() as u16);
            max_dst = max_dst.max(summary.destination.len() as u16);
            Row::new(vec![
                (pkt_idx + 1).to_string(),
                timestamp,
                summary.source.clone(),
                summary.destination.clone(),
                summary.protocol.to_string(),
                index.captured_len.to_string(),
                summary.info.clone(),
            ])
            .style(Style::default().fg(color))
        })
        .collect();

    // Dynamic column widths.
    // Absolute: 27 chars (ISO 8601), Relative/Delta: 16 chars max.
    let time_width: u16 = match time_format {
        TimeFormat::Absolute => 27,
        _ => 16,
    };
    let fixed = 8 + time_width + 8 + 6; // No + Time + Proto + Len
    let remaining = area.width.saturating_sub(fixed + 2 + 6); // borders + column gaps
    let addr_budget = remaining / 2;
    let src_width = max_src.min(addr_budget).max(6);
    let dst_width = max_dst.min(addr_budget).max(6);
    let info_width = remaining.saturating_sub(src_width + dst_width);

    let widths = [
        Constraint::Length(8),
        Constraint::Length(time_width),
        Constraint::Length(src_width),
        Constraint::Length(dst_width),
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Min(info_width),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(border_style)
                .title(" Packet List "),
        )
        .row_highlight_style(
            Style::default()
                .add_modifier(Modifier::REVERSED)
                .fg(ratatui::style::Color::White),
        );

    let mut state = TableState::default();
    let selected = app.packet_list.selected;
    if selected >= offset && selected < visible_end {
        state.select(Some(selected - offset));
    }

    f.render_stateful_widget(table, area, &mut state);
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use super::*;
    use crate::tui::test_util::{make_test_app, render_to_string};

    #[test]
    fn packet_list_renders_header() {
        let mut app = make_test_app(3);
        let dump = render_to_string(120, 10, |f| {
            let area = Rect {
                x: 0,
                y: 0,
                width: 120,
                height: 10,
            };
            render(f, &mut app, area);
        });
        for label in [
            "No.",
            "Time",
            "Source",
            "Destination",
            "Proto",
            "Len",
            "Info",
        ] {
            assert!(dump.contains(label), "missing {label:?} in dump: {dump}");
        }
    }

    #[test]
    fn packet_list_renders_addresses() {
        let mut app = make_test_app(3);
        let dump = render_to_string(120, 10, |f| {
            let area = Rect {
                x: 0,
                y: 0,
                width: 120,
                height: 10,
            };
            render(f, &mut app, area);
        });
        assert!(dump.contains("10.0.0.1"), "dump: {dump}");
        assert!(dump.contains("10.0.0.2"), "dump: {dump}");
    }

    #[test]
    fn packet_list_renders_title() {
        let mut app = make_test_app(1);
        let dump = render_to_string(120, 10, |f| {
            let area = Rect {
                x: 0,
                y: 0,
                width: 120,
                height: 10,
            };
            render(f, &mut app, area);
        });
        assert!(dump.contains("Packet List"), "dump: {dump}");
    }

    #[test]
    fn packet_list_empty_renders_without_panic() {
        let mut app = make_test_app(0);
        let dump = render_to_string(120, 10, |f| {
            let area = Rect {
                x: 0,
                y: 0,
                width: 120,
                height: 10,
            };
            render(f, &mut app, area);
        });
        assert!(dump.contains("Packet List"), "dump: {dump}");
        assert!(dump.contains("No."), "dump: {dump}");
    }
}
