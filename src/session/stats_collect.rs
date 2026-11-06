//! Chunked stats collection over the displayed packets.

use packet_dissector_core::packet::{DissectBuffer, Packet};

use super::state::StatsProgress;
use super::{Session, Tick};
use crate::stats::StatsOutput;

impl Session {
    /// Start collecting stats over the displayed packets.
    ///
    /// Returns `Err` with a message when the collection cannot start.
    pub fn start_stats(&mut self) -> Result<(), String> {
        let registry = self.scan_registry().map_err(|e| format!("Error: {e}"))?;
        self.stats_progress = Some(StatsProgress {
            cursor: 0,
            collector: crate::stats::StatsCollector::from_flags(
                &crate::stats::StatsFlags::all_protocols(true, true),
            ),
            registry,
        });
        Ok(())
    }

    /// Whether stats are being collected.
    pub fn stats_running(&self) -> bool {
        self.stats_progress.is_some()
    }

    /// Stop collecting stats.
    pub fn cancel_stats(&mut self) {
        self.stats_progress = None;
    }

    /// Number of packets to scan per tick during stats collection.
    const STATS_CHUNK_SIZE: usize = 10_000;

    /// Process one chunk of the in-progress stats collection.
    pub fn stats_tick(&mut self) -> Tick<StatsOutput> {
        let total = self.filtered.count_ones();
        let progress = match &mut self.stats_progress {
            Some(p) => p,
            None => return Tick::Idle,
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
            if progress
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

        if progress.cursor >= total
            && let Some(sp) = std::mem::take(&mut self.stats_progress)
        {
            return Tick::Done(sp.collector.finalize(10));
        }
        Tick::Running
    }
}

#[cfg(test)]
mod tests {
    use super::super::Tick;
    use super::super::tests::test_session;

    #[test]
    fn stats_cover_the_displayed_packets() {
        let (mut session, _tmp) = test_session(4);
        assert!(matches!(session.stats_tick(), Tick::Idle));
        session.start_stats().unwrap();
        assert!(session.stats_running());
        let output = loop {
            match session.stats_tick() {
                Tick::Running => {}
                Tick::Done(output) => break output,
                Tick::Idle => panic!("no stats collected"),
            }
        };
        assert_eq!(output.total_packets, 4);
        assert!(!session.stats_running());
    }

    #[test]
    fn start_stats_fails_with_invalid_decode_as() {
        let (mut session, _tmp) = test_session(1);
        session.decode_as_args = vec!["not-a-decode-as".to_string()];
        assert!(session.start_stats().is_err());
        assert!(!session.stats_running());
    }

    #[test]
    fn cancel_stats_stops_the_collection() {
        let (mut session, _tmp) = test_session(2);
        session.start_stats().unwrap();
        session.cancel_stats();
        assert!(!session.stats_running());
        assert!(matches!(session.stats_tick(), Tick::Idle));
    }
}
