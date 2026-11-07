//! The packet list: a virtual table over the session's filtered packets.

use dsct::session::loader;
use gpui_kit::component::ActiveTheme as _;
use gpui_kit::component::table::{Column, TableDelegate, TableState};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::{SharedSession, format, theme};

/// Columns of numbers and times: right-aligned (numbers) in a monospace font
/// so their digits line up, and muted next to the row's content.
const NO_COL: usize = 0;
const TIME_COL: usize = 1;
const SRC_COL: usize = 2;
const DST_COL: usize = 3;
const PROTO_COL: usize = 4;
const LEN_COL: usize = 5;

/// Column keys and titles, in display order.
const COLUMNS: [(&str, &str, f32); 7] = [
    ("no", "No.", 72.),
    ("time", "Time", 250.),
    ("src", "Source", 150.),
    ("dst", "Destination", 150.),
    ("proto", "Protocol", 104.),
    ("len", "Length", 72.),
    ("info", "Info", 600.),
];

/// Rows of the table are the session's displayed (filtered) packets.
pub struct PacketTable {
    session: SharedSession,
    /// How the Time column shows timestamps.
    pub time_format: format::TimeFormat,
    /// The selected row, marked with an accent line.
    pub selected: Option<usize>,
}

impl PacketTable {
    /// A table showing the packets of `session`.
    pub fn new(session: SharedSession) -> Self {
        Self {
            session,
            time_format: format::TimeFormat::default(),
            selected: None,
        }
    }

    /// The protocol of the packet at `row`, dissecting it on demand.
    fn protocol(&self, row: usize) -> &'static str {
        let mut guard = self.session.borrow_mut();
        let Some(session) = guard.as_mut() else {
            return "";
        };
        let Some(pkt_idx) = session.filtered.select(row) else {
            return "";
        };
        session.get_or_dissect_summary(pkt_idx).protocol
    }

    /// The text of cell (`row`, `col`), dissecting the row's packet on
    /// demand (cached by the session).
    fn cell(&self, row: usize, col: usize) -> String {
        let mut guard = self.session.borrow_mut();
        let Some(session) = guard.as_mut() else {
            return String::new();
        };
        let Some(pkt_idx) = session.filtered.select(row) else {
            return String::new();
        };
        let Some(index) = session.indices.get(pkt_idx).cloned() else {
            return String::new();
        };
        match col {
            NO_COL => (pkt_idx + 1).to_string(),
            TIME_COL => match self.time_format {
                format::TimeFormat::Absolute => loader::format_index_timestamp(&index),
                format::TimeFormat::Relative => match session.indices.first() {
                    Some(first) => loader::format_relative_timestamp(&index, first),
                    None => String::new(),
                },
                // Since the previous displayed packet, as in the TUI.
                format::TimeFormat::Delta => match row
                    .checked_sub(1)
                    .and_then(|prev| session.filtered.select(prev))
                    .and_then(|prev| session.indices.get(prev))
                {
                    Some(prev) => loader::format_delta_timestamp(&index, prev),
                    None => loader::format_delta_timestamp(&index, &index),
                },
            },
            LEN_COL => index.original_len.to_string(),
            _ => {
                let summary = session.get_or_dissect_summary(pkt_idx);
                match col {
                    SRC_COL => summary.source.clone(),
                    DST_COL => summary.destination.clone(),
                    PROTO_COL => summary.protocol.to_string(),
                    _ => summary.info.clone(),
                }
            }
        }
    }
}

impl TableDelegate for PacketTable {
    fn columns_count(&self, _: &App) -> usize {
        COLUMNS.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.session
            .borrow()
            .as_ref()
            .map_or(0, |s| s.displayed_count())
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let (key, name, width) = COLUMNS[col_ix];
        let width = if col_ix == TIME_COL {
            self.time_format.column_width()
        } else {
            width
        };
        let column = Column::new(key, name).width(px(width));
        if matches!(col_ix, NO_COL | LEN_COL) {
            column.text_right()
        } else {
            column
        }
    }

    fn render_tr(
        &mut self,
        row_ix: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> Stateful<Div> {
        let selected = self.selected == Some(row_ix);
        div()
            .id(("row", row_ix))
            .border_l_2()
            .border_color(if selected {
                theme::accent()
            } else {
                transparent_black()
            })
            .when(selected, |row| row.text_color(theme::text_bright()))
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        cx: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        let mono = cx.theme().mono_font_family.clone();
        let cell = div().overflow_hidden().whitespace_nowrap();
        if col_ix == PROTO_COL {
            // A colored mark and name instead of tinting the whole row.
            let protocol = self.protocol(row_ix);
            let color =
                format::protocol_swatch(protocol).map_or(theme::text_muted(), theme::swatch);
            return cell
                .flex()
                .items_center()
                .gap_1p5()
                .font_weight(FontWeight::MEDIUM)
                .text_color(color)
                .child(div().size(px(7.)).rounded(px(2.)).bg(color))
                .child(protocol);
        }
        let selected = self.selected == Some(row_ix);
        cell.when(
            matches!(col_ix, NO_COL | TIME_COL | LEN_COL | SRC_COL | DST_COL),
            |d| d.font_family(mono),
        )
        .when(
            matches!(col_ix, NO_COL | TIME_COL | LEN_COL) && !selected,
            |d| d.text_color(theme::text_muted()),
        )
        .child(self.cell(row_ix, col_ix))
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        self.cell(row_ix, col_ix)
    }
}
