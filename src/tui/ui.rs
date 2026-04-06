//! Layout and rendering root for the TUI.
//!
//! Vim-style layout with three content panes and a two-line bottom area
//! (status line + command line).

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use ratatui::widgets::{Block, Borders, Clear, Gauge};

use super::app::App;
use super::state::Pane;
use super::widgets;

/// Render the entire TUI into the given frame.
pub fn render(f: &mut Frame, app: &mut App) {
    let (c0, c1, c2) = if let Some(maximized) = app.maximized_pane {
        // Maximized mode: give all space to the maximized pane.
        match maximized {
            Pane::PacketList => (
                Constraint::Min(3),
                Constraint::Length(0),
                Constraint::Length(0),
            ),
            Pane::DetailTree => (
                Constraint::Length(0),
                Constraint::Min(3),
                Constraint::Length(0),
            ),
            Pane::HexDump => (
                Constraint::Length(0),
                Constraint::Length(0),
                Constraint::Min(3),
            ),
            Pane::FilterInput | Pane::TreeSearch | Pane::YankPrompt | Pane::CommandMode => (
                Constraint::Min(3),
                Constraint::Length(0),
                Constraint::Length(0),
            ),
        }
    } else {
        // Normal mode: use pane weights.
        let w = app.pane_weights;
        let total = w[0] as u32 + w[1] as u32 + w[2] as u32;
        if total == 0 {
            (
                Constraint::Percentage(35),
                Constraint::Percentage(35),
                Constraint::Min(3),
            )
        } else {
            (
                Constraint::Percentage((u32::from(w[0]) * 100 / total) as u16),
                Constraint::Percentage((u32::from(w[1]) * 100 / total) as u16),
                Constraint::Min(3),
            )
        }
    };

    let chunks = Layout::vertical([
        c0,                    // Packet list
        c1,                    // Protocol detail tree
        c2,                    // Hex dump
        Constraint::Length(1), // Status line (always visible)
        Constraint::Length(1), // Command line (/ filter or empty)
    ])
    .split(f.area());

    // Save pane rectangles for mouse hit-testing and dynamic page sizing.
    app.pane_layout.packet_list = chunks[0];
    app.pane_layout.detail_tree = chunks[1];
    app.pane_layout.hex_dump = chunks[2];
    app.pane_layout.frame_area = f.area();

    widgets::packet_list::render(f, app, chunks[0]);
    widgets::detail_tree::render(f, app, chunks[1]);
    widgets::hex_dump::render(f, app, chunks[2]);
    widgets::status_bar::render(f, app, chunks[3]);
    widgets::command_line::render(f, app, chunks[4]);

    // Overlay: Follow Stream full-screen view.
    if let Some(sv) = &app.stream_view {
        widgets::stream_view::render(f, sv, f.area());
        return;
    }

    // Overlay: stats progress bar.
    if let Some(progress) = &app.stats_progress {
        let total = app.filtered_indices.len();
        render_progress_overlay(f, "Stats", progress.cursor, total, progress.fraction(total));
    }

    // Overlay: stats output.
    if let Some(stats) = &app.stats_output {
        render_stats_overlay(f, stats);
    }

    // Overlay: centered progress bar while stream is building.
    if let Some(progress) = &app.stream_build_progress {
        let total = app.indices.len();
        render_progress_overlay(
            f,
            "Following",
            progress.cursor,
            total,
            progress.fraction(total),
        );
    }

    // Overlay: centered progress bar while filter is scanning.
    if let Some(progress) = &app.filter_progress {
        let total = app.indices.len();
        render_progress_overlay(
            f,
            "Filtering",
            progress.cursor,
            total,
            progress.fraction(total),
        );
    }

    // Overlay: help screen.
    if app.show_help {
        render_help(f);
    }
}

/// Render a centered progress bar overlay with the given label and progress info.
fn render_progress_overlay(f: &mut Frame, label: &str, cursor: usize, total: usize, fraction: f64) {
    let area = f.area();
    let bar_width = 40u16.min(area.width.saturating_sub(4));
    let bar_height = 3u16;
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(bar_width)) / 2,
        y: area.y + (area.height.saturating_sub(bar_height)) / 2,
        width: bar_width,
        height: bar_height,
    };
    f.render_widget(Clear, popup);

    let pct = (fraction * 100.0) as u16;
    let label = Span::styled(
        format!(" {label}... {cursor}/{total} "),
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD),
    );
    let gauge = Gauge::default()
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
        )
        .gauge_style(Style::default().fg(Color::Cyan).bg(Color::DarkGray))
        .percent(pct)
        .label(label);
    f.render_widget(gauge, popup);
}

fn render_help(f: &mut Frame) {
    use ratatui::text::{Line, Text};
    use ratatui::widgets::Paragraph;

    let help_lines = [
        ("Navigation", ""),
        ("j/k, ↑/↓", "Move up/down"),
        ("g, Home", "Go to top"),
        ("G, End", "Go to bottom"),
        ("123G", "Jump to packet #123"),
        ("Tab/BackTab", "Next/previous pane"),
        ("PageDown/Up", "Page down/up"),
        ("", ""),
        ("Pane Control", ""),
        ("z", "Toggle pane zoom"),
        ("+/-", "Resize pane"),
        ("=", "Reset pane sizes"),
        ("", ""),
        ("Detail Tree", ""),
        ("Enter/Space", "Toggle expand/collapse"),
        ("l/→, h/←", "Expand/collapse or navigate"),
        ("e", "Toggle expand/collapse all"),
        ("v", "Visual char selection"),
        ("V", "Visual line selection"),
        ("y", "Yank (copy) current line"),
        ("", ""),
        ("Filter & Search", ""),
        ("/", "Enter filter (or tree search when Detail zoomed)"),
        ("n/N", "Next/previous search match"),
        ("Ctrl+U", "Clear filter input"),
        ("Ctrl+P/N", "Filter history prev/next"),
        ("", ""),
        ("Stream", ""),
        ("f", "Follow TCP/UDP/SCTP stream"),
        ("", ""),
        ("", ""),
        ("Commands", ""),
        (":", "Command mode (:w, :q, :wq)"),
        ("", ""),
        ("Display", ""),
        ("t", "Cycle time format (Abs/Rel/Delta)"),
        ("?", "Toggle this help"),
        ("q", "Quit"),
    ];

    let text = Text::from(
        help_lines
            .iter()
            .map(|(key, desc)| {
                if desc.is_empty() && !key.is_empty() {
                    // Section header.
                    Line::styled(
                        format!("  {key}"),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    )
                } else if key.is_empty() {
                    Line::raw("")
                } else {
                    Line::from(vec![
                        Span::styled(format!("  {key:<16}"), Style::default().fg(Color::Yellow)),
                        Span::raw(desc.to_string()),
                    ])
                }
            })
            .collect::<Vec<_>>(),
    );

    let area = f.area();
    let height = (help_lines.len() as u16 + 2).min(area.height.saturating_sub(2));
    let width = 42u16.min(area.width.saturating_sub(4));
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };

    f.render_widget(Clear, popup);
    let para = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Help (press any key to close) "),
    );
    f.render_widget(para, popup);
}

fn render_stats_overlay(f: &mut Frame, stats: &crate::stats::StatsOutput) {
    use ratatui::text::{Line, Text};
    use ratatui::widgets::Paragraph;

    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::styled(
        format!("  Packets: {}", stats.total_packets),
        Style::default().fg(Color::White),
    ));
    if let Some(start) = &stats.time_start {
        lines.push(Line::raw(format!("  Start:   {start}")));
    }
    if let Some(end) = &stats.time_end {
        lines.push(Line::raw(format!("  End:     {end}")));
    }
    lines.push(Line::raw(format!(
        "  Duration: {:.3}s",
        stats.duration_secs
    )));
    lines.push(Line::raw(""));

    // Protocol distribution (sorted by count descending).
    lines.push(Line::styled(
        "  Protocols",
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD),
    ));
    let mut protos: Vec<_> = stats.protocols.iter().collect();
    protos.sort_by(|a, b| b.1.cmp(a.1));
    for (name, count) in protos.iter().take(15) {
        lines.push(Line::from(vec![
            Span::styled(format!("  {name:<20}"), Style::default().fg(Color::Yellow)),
            Span::raw(format!("{count}")),
        ]));
    }

    // Top talkers (if present).
    if let Some(talkers) = &stats.top_talkers
        && !talkers.is_empty()
    {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "  Top Talkers",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ));
        for t in talkers.iter().take(5) {
            lines.push(Line::raw(format!(
                "  {} ↔ {} ({} pkts)",
                t.src, t.dst, t.packets
            )));
        }
    }

    let text = Text::from(lines.clone());
    let area = f.area();
    let height = (lines.len() as u16 + 2).min(area.height.saturating_sub(2));
    let width = 50u16.min(area.width.saturating_sub(4));
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };

    f.render_widget(Clear, popup);
    let para = Paragraph::new(text).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan))
            .title(" Stats (press any key to close) "),
    );
    f.render_widget(para, popup);
}
