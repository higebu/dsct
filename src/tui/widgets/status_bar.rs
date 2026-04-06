//! Lightline-style status line widget.
//!
//! Renders a powerline-style status bar with colored sections separated by
//! arrow characters (U+E0B0 / U+E0B2).  Each section has a distinct background
//! color.

use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::tui::app::App;
use crate::tui::state::{LiveMode, Pane, SelectionMode};

/// Powerline right-arrow separator.
const SEP_RIGHT: &str = "\u{E0B0}"; //
/// Powerline left-arrow separator.
const SEP_LEFT: &str = "\u{E0B2}"; //

// -- Section colors --
const MODE_BG: Color = Color::Blue;
const MODE_FG: Color = Color::White;
const INFO_BG: Color = Color::Indexed(238); // dark gray
const INFO_FG: Color = Color::White;
const MID_BG: Color = Color::Indexed(236); // darker gray
const MID_FG: Color = Color::Indexed(250); // light gray
const RIGHT_BG: Color = Color::Indexed(238);
const RIGHT_FG: Color = Color::White;
const POS_BG: Color = Color::Green;
const POS_FG: Color = Color::Black;
const LIVE_BG: Color = Color::Green;
const LIVE_FG: Color = Color::Black;
const PAUSED_BG: Color = Color::Yellow;
const PAUSED_FG: Color = Color::Black;

/// Render the lightline-style status line.
pub fn render(f: &mut Frame, app: &mut App, area: Rect) {
    let zoom = app.maximized_pane.is_some();
    let pane_label = match app.active_pane {
        Pane::PacketList if zoom => " PACKETS [Z] ",
        Pane::PacketList => " PACKETS ",
        Pane::DetailTree if zoom => " DETAIL [Z] ",
        Pane::DetailTree => " DETAIL ",
        Pane::HexDump if zoom => " HEX [Z] ",
        Pane::HexDump => " HEX ",
        Pane::FilterInput => " FILTER ",
        Pane::TreeSearch => " SEARCH ",
        Pane::YankPrompt => " YANK ",
        Pane::CommandMode => " COMMAND ",
    };

    // Override pane label for visual selection mode.
    let pane_label = if let Some(sel) = &app.detail_tree.selection {
        match sel.mode {
            SelectionMode::Char => " -- VISUAL -- ",
            SelectionMode::Line => " -- VISUAL LINE -- ",
        }
    } else {
        pane_label
    };

    let total = app.total_count();
    let displayed = app.displayed_count();
    let selected_num = app.selected_number();

    // -- Left side: [MODE] > [packets info] > [filter] > [summary] --
    let mut spans: Vec<Span> = Vec::new();

    // Section 1: Mode/Pane label (bold, accent color)
    spans.push(Span::styled(
        pane_label,
        Style::default()
            .fg(MODE_FG)
            .bg(MODE_BG)
            .add_modifier(Modifier::BOLD),
    ));
    // Live mode indicator (between MODE and file name sections).
    if let Some(live_mode) = app.live_mode {
        let (label, bg) = match live_mode {
            LiveMode::Live => ("\u{25B6} Live", LIVE_BG),
            LiveMode::Paused => ("\u{23F8} Paused", PAUSED_BG),
            LiveMode::Complete => ("\u{2713} Complete", INFO_BG),
        };
        let fg = match live_mode {
            LiveMode::Complete => INFO_FG,
            _ => {
                if bg == LIVE_BG {
                    LIVE_FG
                } else {
                    PAUSED_FG
                }
            }
        };
        spans.push(Span::styled(SEP_RIGHT, Style::default().fg(MODE_BG).bg(bg)));
        spans.push(Span::styled(
            format!(" {label} "),
            Style::default().fg(fg).bg(bg).add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(SEP_RIGHT, Style::default().fg(bg).bg(INFO_BG)));
    } else if app.index_progress.is_some() || app.bg_indexer.is_some() {
        // File indexing in progress indicator.
        let pct = if let Some(ref bg) = app.bg_indexer {
            (bg.fraction() * 100.0) as u32
        } else if let Some(ref progress) = app.index_progress {
            (progress.fraction() * 100.0) as u32
        } else {
            0
        };
        let label = format!("\u{23F3} Indexing {pct}%");
        spans.push(Span::styled(
            SEP_RIGHT,
            Style::default().fg(MODE_BG).bg(PAUSED_BG),
        ));
        spans.push(Span::styled(
            format!(" {label} "),
            Style::default()
                .fg(PAUSED_FG)
                .bg(PAUSED_BG)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            SEP_RIGHT,
            Style::default().fg(PAUSED_BG).bg(INFO_BG),
        ));
    } else {
        spans.push(Span::styled(
            SEP_RIGHT,
            Style::default().fg(MODE_BG).bg(INFO_BG),
        ));
    }

    // Section 2: File name + packet counts
    spans.push(Span::styled(
        format!(" {} ", app.file_name),
        Style::default().fg(INFO_FG).bg(INFO_BG),
    ));
    spans.push(Span::styled(
        SEP_RIGHT,
        Style::default().fg(INFO_BG).bg(MID_BG),
    ));

    // Section 3: Packet counts + time format
    let time_label = app.time_format.label();
    let count_text = if !app.filter.applied.is_empty() {
        format!(" {displayed}/{total} [{time_label}] ")
    } else {
        format!(" {total} pkts [{time_label}] ")
    };
    spans.push(Span::styled(
        count_text,
        Style::default().fg(MID_FG).bg(MID_BG),
    ));

    // Section 4: Selected packet summary (middle, dim)
    let sel_pkt_idx = app
        .filtered_indices
        .get(app.packet_list.selected)
        .copied()
        .unwrap_or(usize::MAX);
    if let Some(summary) = app.summary_cache.get(&sel_pkt_idx) {
        spans.push(Span::styled(
            format!(
                " {} {} \u{2192} {} ",
                summary.protocol, summary.source, summary.destination
            ),
            Style::default().fg(MID_FG).bg(MID_BG),
        ));
    } else {
        spans.push(Span::styled(" ", Style::default().bg(MID_BG)));
    }

    // -- Build right side spans first to calculate fill width --
    let mut right_spans: Vec<Span> = Vec::new();

    // Show pending digit count if any.
    if !app.pending_count.is_empty() {
        right_spans.push(Span::styled(
            SEP_LEFT,
            Style::default().fg(Color::Yellow).bg(MID_BG),
        ));
        right_spans.push(Span::styled(
            format!(" {} ", app.pending_count),
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
        right_spans.push(Span::styled(
            SEP_LEFT,
            Style::default().fg(RIGHT_BG).bg(Color::Yellow),
        ));
    } else {
        right_spans.push(Span::styled(
            SEP_LEFT,
            Style::default().fg(RIGHT_BG).bg(MID_BG),
        ));
    }

    right_spans.push(Span::styled(
        format!(" #{selected_num} "),
        Style::default().fg(RIGHT_FG).bg(RIGHT_BG),
    ));
    right_spans.push(Span::styled(
        SEP_LEFT,
        Style::default().fg(POS_BG).bg(RIGHT_BG),
    ));
    right_spans.push(Span::styled(
        format!(" {displayed} "),
        Style::default()
            .fg(POS_FG)
            .bg(POS_BG)
            .add_modifier(Modifier::BOLD),
    ));

    // Fill middle with background
    let left_used: usize = spans.iter().map(|s| s.content.chars().count()).sum();
    let right_len: usize = right_spans.iter().map(|s| s.content.chars().count()).sum();
    let fill_width = (area.width as usize).saturating_sub(left_used + right_len);
    if fill_width > 0 {
        spans.push(Span::styled(
            " ".repeat(fill_width),
            Style::default().bg(MID_BG),
        ));
    }

    spans.extend(right_spans);

    let line = Line::from(spans);
    let paragraph = Paragraph::new(line);
    f.render_widget(paragraph, area);
}
