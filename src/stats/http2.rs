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
