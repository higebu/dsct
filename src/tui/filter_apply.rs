//! Filter application and chunked filter scanning.

use packet_dissector_core::packet::{DissectBuffer, Packet};

use super::app::App;
use super::state::FilterProgress;
use crate::filter_expr::FilterExpr;

impl App {
    pub(super) fn apply_filter(&mut self) {
        self.filter.error_message = None;

        let expr = match FilterExpr::parse(&self.filter.buf.input) {
            Ok(expr) => expr,
            Err(msg) => {
                self.filter.error_message = Some(msg);
                return;
            }
        };

        self.filter.applied = self.filter.buf.input.clone();

        if expr.is_none() {
            // Empty filter — show all packets immediately.
            self.filtered_indices = (0..self.indices.len()).collect();
            self.summary_cache.clear();
            self.packet_list.selected = 0;
            self.packet_list.scroll_offset = 0;
            self.load_selected();
            self.hex_dump.scroll_offset = 0;
            return;
        }

        // Start a chunked filter scan.
        self.filter_progress = Some(FilterProgress {
            expr,
            cursor: 0,
            results: Vec::new(),
        });
    }

    /// Number of packets to scan per tick during filter progress.
    const FILTER_CHUNK_SIZE: usize = 10_000;

    /// Process one chunk of the in-progress filter scan.
    ///
    /// Returns `true` while the scan is still running.
    pub fn filter_tick(&mut self) -> bool {
        let total = self.indices.len();
        let progress = match &mut self.filter_progress {
            Some(p) => p,
            None => return false,
        };

        let end = (progress.cursor + Self::FILTER_CHUNK_SIZE).min(total);
        // Fast path: packet-number-only filters don't need dissection.
        let pn_only = progress
            .expr
            .as_ref()
            .is_some_and(|e| e.is_packet_number_only());

        let mut dissect_buf = DissectBuffer::new();
        for i in progress.cursor..end {
            let number = (i as u64) + 1; // 1-based packet number
            let matches = if let Some(expr) = &progress.expr {
                if pn_only {
                    let buf = dissect_buf.clear_into();
                    let empty_pkt = Packet::new(buf, &[]);
                    expr.matches_with_number(&empty_pkt, number)
                } else {
                    let index = &self.indices[i];
                    if let Some(data) = self.capture.packet_data(index) {
                        let buf = dissect_buf.clear_into();
                        if self
                            .registry
                            .dissect_with_link_type(data, index.link_type as u32, buf)
                            .is_ok()
                        {
                            let packet = Packet::new(buf, data);
                            expr.matches_with_number(&packet, number)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
            } else {
                true
            };
            if matches {
                progress.results.push(i);
            }
        }
        progress.cursor = end;

        if progress.cursor >= total {
            // Scan complete — take results and finalize.
            let results = match std::mem::take(&mut self.filter_progress) {
                Some(fp) => fp.results,
                None => Vec::new(),
            };
            self.filtered_indices = results;
            self.summary_cache.clear();
            self.packet_list.selected = 0;
            self.packet_list.scroll_offset = 0;
            self.load_selected();
            self.hex_dump.scroll_offset = 0;
            return false;
        }
        true
    }
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use super::super::test_util::make_test_app;

    #[test]
    fn apply_filter_empty_shows_all() {
        let mut app = make_test_app(3);
        app.filter.buf.input.clear();
        app.filter.buf.cursor = 0;
        app.apply_filter();
        assert!(app.filter_progress.is_none());
        assert_eq!(app.filtered_indices.len(), app.indices.len());
        assert_eq!(app.displayed_count(), 3);
    }

    #[test]
    fn apply_filter_parse_error_sets_message() {
        let mut app = make_test_app(3);
        app.filter.buf.input = "udp.port ==".into();
        app.filter.buf.cursor = app.filter.buf.input.len();
        app.apply_filter();
        assert!(app.filter.error_message.is_some());
        assert!(app.filter_progress.is_none());
    }

    #[test]
    fn filter_tick_runs_to_completion() {
        let mut app = make_test_app(3);
        app.filter.buf.input = "udp".into();
        app.filter.buf.cursor = 3;
        app.apply_filter();
        // Either empty path or chunked path — drive until done.
        while app.filter_tick() {}
        assert!(app.filter_progress.is_none());
        // Fixture packets are all UDP.
        assert_eq!(app.displayed_count(), 3);
    }

    #[test]
    fn filter_tick_returns_false_when_idle() {
        let mut app = make_test_app(1);
        assert!(app.filter_progress.is_none());
        assert!(!app.filter_tick());
    }
}
