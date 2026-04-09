use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, field_u32, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated HTTP/2 statistics.
#[derive(Debug, Clone, Serialize)]
pub struct Http2Stats {
    pub total_frames: u64,
    pub frame_type_distribution: Vec<CountEntry>,
    pub error_code_distribution: Vec<CountEntry>,
    pub top_stream_ids: Vec<CountEntry>,
}

/// Collects HTTP/2 frame statistics.
#[derive(Debug)]
pub struct Http2StatsCollector {
    frame_types: HashMap<String, u64>,
    error_codes: HashMap<String, u64>,
    stream_ids: HashMap<u32, u64>,
    total_frames: u64,
}

impl Default for Http2StatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Http2StatsCollector {
    pub fn new() -> Self {
        Self {
            frame_types: HashMap::new(),
            error_codes: HashMap::new(),
            stream_ids: HashMap::new(),
            total_frames: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(http2) = packet.layer_by_name("HTTP2") else {
            return;
        };
        let fields = packet.layer_fields(http2);
        self.total_frames += 1;

        if let Some(name) = display_name(packet, http2, fields, "frame_type_name", "frame_type") {
            *self.frame_types.entry(name).or_insert(0) += 1;
        }

        if let Some(name) = display_name(packet, http2, fields, "error_code_name", "error_code") {
            *self.error_codes.entry(name).or_insert(0) += 1;
        }

        if let Some(sid) = field_u32(fields, "stream_id") {
            *self.stream_ids.entry(sid).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> Http2Stats {
        Http2Stats {
            total_frames: self.total_frames,
            frame_type_distribution: sorted_top_n(self.frame_types.into_iter(), top_n),
            error_code_distribution: sorted_top_n(self.error_codes.into_iter(), top_n),
            top_stream_ids: sorted_top_n(
                self.stream_ids.into_iter().map(|(k, v)| (k.to_string(), v)),
                top_n,
            ),
        }
    }
}

super::impl_protocol_stats_collector!(Http2StatsCollector, "http2", Http2Stats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_http2_buf(frame_type: u8, stream_id: u32) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("HTTP2", None, &[], 0..9);
        buf.push_field(
            test_desc("frame_type", "Frame Type"),
            FieldValue::U8(frame_type),
            3..4,
        );
        buf.push_field(
            test_desc("stream_id", "Stream ID"),
            FieldValue::U32(stream_id),
            5..9,
        );
        buf.end_layer();
        buf
    }

    #[test]
    fn http2_ignores_non_http2_packets() {
        let mut c = Http2StatsCollector::new();
        let buf = DissectBuffer::new();
        c.process_packet(&pkt(&buf), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_frames, 0);
        assert!(stats.frame_type_distribution.is_empty());
        assert!(stats.top_stream_ids.is_empty());
    }

    #[test]
    fn http2_counts_frames_and_frame_type() {
        let mut c = Http2StatsCollector::new();
        let b1 = build_http2_buf(1, 1); // HEADERS
        c.process_packet(&pkt(&b1), None);
        let b2 = build_http2_buf(1, 1);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_http2_buf(0, 3); // DATA
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_frames, 3);
        assert_eq!(stats.frame_type_distribution[0].name, "1");
        assert_eq!(stats.frame_type_distribution[0].count, 2);
        assert_eq!(stats.frame_type_distribution[1].name, "0");
        assert_eq!(stats.frame_type_distribution[1].count, 1);
    }

    #[test]
    fn http2_records_stream_ids() {
        let mut c = Http2StatsCollector::new();
        let b1 = build_http2_buf(1, 1);
        c.process_packet(&pkt(&b1), None);
        let b2 = build_http2_buf(0, 1);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_http2_buf(1, 3);
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.top_stream_ids[0].name, "1");
        assert_eq!(stats.top_stream_ids[0].count, 2);
        assert_eq!(stats.top_stream_ids[1].name, "3");
        assert_eq!(stats.top_stream_ids[1].count, 1);
    }

    #[test]
    fn http2_finalize_top_n_limits_frame_types() {
        let mut c = Http2StatsCollector::new();
        for t in 0u8..6 {
            let b = build_http2_buf(t, u32::from(t) + 1);
            c.process_packet(&pkt(&b), None);
        }

        let stats = c.finalize_stats(3);
        assert_eq!(stats.frame_type_distribution.len(), 3);
        assert_eq!(stats.total_frames, 6);
    }
}
