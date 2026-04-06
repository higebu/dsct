use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated PFCP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct PfcpStats {
    pub total_messages: u64,
    pub message_type_distribution: Vec<CountEntry>,
}

/// Collects PFCP message statistics.
#[derive(Debug)]
pub struct PfcpStatsCollector {
    message_types: HashMap<String, u64>,
    total_messages: u64,
}

impl Default for PfcpStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl PfcpStatsCollector {
    pub fn new() -> Self {
        Self {
            message_types: HashMap::new(),
            total_messages: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(pfcp) = packet.layer_by_name("PFCP") else {
            return;
        };
        let fields = packet.layer_fields(pfcp);
        self.total_messages += 1;

        if let Some(name) = display_name(packet, pfcp, fields, "message_type_name", "message_type")
        {
            *self.message_types.entry(name).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> PfcpStats {
        PfcpStats {
            total_messages: self.total_messages,
            message_type_distribution: sorted_top_n(self.message_types.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(PfcpStatsCollector, "pfcp", PfcpStats);
