use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated RADIUS statistics.
#[derive(Debug, Clone, Serialize)]
pub struct RadiusStats {
    pub total_packets: u64,
    pub code_distribution: Vec<CountEntry>,
}

/// Collects RADIUS message statistics.
#[derive(Debug)]
pub struct RadiusStatsCollector {
    codes: HashMap<String, u64>,
    total_packets: u64,
}

impl Default for RadiusStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl RadiusStatsCollector {
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
            total_packets: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(radius) = packet.layer_by_name("RADIUS") else {
            return;
        };
        let fields = packet.layer_fields(radius);
        self.total_packets += 1;

        if let Some(name) = display_name(packet, radius, fields, "code_name", "code") {
            *self.codes.entry(name).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> RadiusStats {
        RadiusStats {
            total_packets: self.total_packets,
            code_distribution: sorted_top_n(self.codes.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(RadiusStatsCollector, "radius", RadiusStats);
