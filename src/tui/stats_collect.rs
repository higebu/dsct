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
        let total = self.filtered_indices.len();
        let progress = match &mut self.stats_progress {
            Some(p) => p,
            None => return false,
        };

        let end = (progress.cursor + Self::STATS_CHUNK_SIZE).min(total);
        let mut dissect_buf = DissectBuffer::new();
        for fi in progress.cursor..end {
            let idx = self.filtered_indices[fi];
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
