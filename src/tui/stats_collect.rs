//! Stats collection tick logic.

use packet_dissector_core::packet::{DissectBuffer, Packet};

use super::app::App;

impl App {
    /// Number of packets to scan per tick during stats collection.
    const STATS_CHUNK_SIZE: usize = 10_000;

    /// Process one chunk of the in-progress stats collection.
    ///
    /// Returns `true` while the collection is still running.
    pub fn stats_tick(&mut self) -> bool {
        let total = self.filtered.count_ones();
        let progress = match &mut self.stats_progress {
            Some(p) => p,
            None => return false,
        };

        let end = (progress.cursor + Self::STATS_CHUNK_SIZE).min(total);
        let mut dissect_buf = DissectBuffer::new();
        // One select to position at the cursor, then cheap iteration over the
        // chunk's matching packet indices.
        let chunk_len = end - progress.cursor;
        for idx in self.filtered.iter_from(progress.cursor).take(chunk_len) {
            let index = &self.indices[idx];
            let data = match self.capture.packet_data(index) {
                Some(d) => d,
                None => continue,
            };
            let buf = dissect_buf.clear_into();
            if self
                .registry
                .dissect_with_link_type(data, index.link_type as u32, buf)
                .is_ok()
            {
                let packet = Packet::new(buf, data);
                progress
                    .collector
                    .record_meta(index.timestamp_secs, index.timestamp_usecs);
                progress.collector.process_packet(
                    &packet,
                    index.timestamp_secs,
                    index.timestamp_usecs,
                    index.original_len,
                );
            }
        }
        progress.cursor = end;

        if progress.cursor >= total {
            if let Some(sp) = std::mem::take(&mut self.stats_progress) {
                self.stats_output = Some(sp.collector.finalize(10));
            }
            return false;
        }
        true
    }
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use super::super::state::StatsProgress;
    use super::super::test_util::make_test_app;
    use crate::stats::{StatsCollector, StatsFlags};

    #[test]
    fn stats_tick_idle_returns_false() {
        let mut app = make_test_app(3);
        assert!(app.stats_progress.is_none());
        assert!(!app.stats_tick());
        assert!(app.stats_output.is_none());
    }

    #[test]
    fn stats_tick_runs_to_completion() {
        let mut app = make_test_app(5);
        app.stats_progress = Some(StatsProgress {
            cursor: 0,
            collector: StatsCollector::from_flags(&StatsFlags::all_protocols(true, true)),
        });
        while app.stats_tick() {}
        let out = app.stats_output.as_ref().expect("stats_output set");
        assert_eq!(out.total_packets, 5);
    }
}
