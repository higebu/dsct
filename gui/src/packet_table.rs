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
const INFO_COL: usize = 6;

/// Column keys and titles, in display order; field columns go before Info.
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
    /// Field columns (filter paths) shown before Info.
    pub extra: Vec<String>,
}

/// What a column of the table shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Col {
    /// One of [`COLUMNS`].
    Fixed(usize),
    /// One of [`PacketTable::extra`].
    Field(usize),
}

/// The column at `col_ix` with `extra` field columns before Info.
fn col_at(col_ix: usize, extra: usize) -> Col {
    if col_ix < INFO_COL {
        Col::Fixed(col_ix)
    } else if col_ix < INFO_COL + extra {
        Col::Field(col_ix - INFO_COL)
    } else {
        Col::Fixed(INFO_COL)
    }
}

impl PacketTable {
    /// A table showing the packets of `session`.
    pub fn new(session: SharedSession) -> Self {
        Self {
            session,
            time_format: format::TimeFormat::default(),
            selected: None,
            extra: Vec::new(),
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

    /// The text of cell (`row`, `col_ix`), dissecting the row's packet on
    /// demand (cached by the session, except for field columns).
    fn cell(&self, row: usize, col_ix: usize) -> String {
        match col_at(col_ix, self.extra.len()) {
            Col::Fixed(col) => self.fixed_cell(row, col),
            Col::Field(i) => self.field_cell(row, &self.extra[i]),
        }
    }

    /// The text of cell (`row`, `col`) of one of [`COLUMNS`].
    fn fixed_cell(&self, row: usize, col: usize) -> String {
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

impl PacketTable {
    /// The value of the field at `path` in the packet at `row`.
    fn field_cell(&self, row: usize, path: &str) -> String {
        let guard = self.session.borrow();
        guard
            .as_ref()
            .and_then(|s| s.field_value(s.filtered.select(row)?, path))
            .unwrap_or_else(|| "—".to_string())
    }
}

impl TableDelegate for PacketTable {
    fn columns_count(&self, _: &App) -> usize {
        COLUMNS.len() + self.extra.len()
    }

    fn rows_count(&self, _: &App) -> usize {
        self.session
            .borrow()
            .as_ref()
            .map_or(0, |s| s.displayed_count())
    }

    fn column(&self, col_ix: usize, _: &App) -> Column {
        let col_ix = match col_at(col_ix, self.extra.len()) {
            Col::Fixed(col) => col,
            Col::Field(i) => {
                let path = &self.extra[i];
                return Column::new(SharedString::from(format!("field:{path}")), path.clone())
                    .width(px(170.));
            }
        };
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
        let col_ix = match col_at(col_ix, self.extra.len()) {
            Col::Fixed(col) => col,
            Col::Field(i) => {
                let text = self.field_cell(row_ix, &self.extra[i]);
                return cell
                    .font_family(mono)
                    .text_ellipsis()
                    .when(text == "—", |d| d.text_color(theme::text_faint()))
                    .child(text);
            }
        };
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
        .child(self.fixed_cell(row_ix, col_ix))
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        self.cell(row_ix, col_ix)
    }
}

#[cfg(test)]
mod tests {
    use super::{Col, col_at};

    #[test]
    fn field_columns_go_before_info() {
        assert_eq!(col_at(5, 2), Col::Fixed(5));
        assert_eq!(col_at(6, 2), Col::Field(0));
        assert_eq!(col_at(7, 2), Col::Field(1));
        assert_eq!(col_at(8, 2), Col::Fixed(6));
        assert_eq!(col_at(6, 0), Col::Fixed(6));
    }
}
