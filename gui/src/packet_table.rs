//! The packet list: a virtual table over the session's filtered packets.

use dsct::session::loader;
use gpui_kit::component::table::{Column, TableDelegate, TableState};
use gpui_kit::*;

use crate::SharedSession;

/// Column keys and titles, in display order.
const COLUMNS: [(&str, &str, f32); 7] = [
    ("no", "No.", 80.),
    ("time", "Time", 250.),
    ("src", "Source", 170.),
    ("dst", "Destination", 170.),
    ("proto", "Protocol", 90.),
    ("len", "Length", 70.),
    ("info", "Info", 600.),
];

/// Rows of the table are the session's displayed (filtered) packets.
pub struct PacketTable {
    session: SharedSession,
}

impl PacketTable {
    /// A table showing the packets of `session`.
    pub fn new(session: SharedSession) -> Self {
        Self { session }
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
            0 => (pkt_idx + 1).to_string(),
            1 => loader::format_index_timestamp(&index),
            5 => index.original_len.to_string(),
            _ => {
                let summary = session.get_or_dissect_summary(pkt_idx);
                match col {
                    2 => summary.source.clone(),
                    3 => summary.destination.clone(),
                    4 => summary.protocol.to_string(),
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
        Column::new(key, name).width(px(width))
    }

    fn render_td(
        &mut self,
        row_ix: usize,
        col_ix: usize,
        _: &mut Window,
        _: &mut Context<TableState<Self>>,
    ) -> impl IntoElement {
        div()
            .overflow_hidden()
            .whitespace_nowrap()
            .child(self.cell(row_ix, col_ix))
    }

    fn cell_text(&self, row_ix: usize, col_ix: usize, _: &App) -> String {
        self.cell(row_ix, col_ix)
    }
}
