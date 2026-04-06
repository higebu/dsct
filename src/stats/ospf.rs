use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated OSPF statistics.
#[derive(Debug, Clone, Serialize)]
pub struct OspfStats {
    pub total_packets: u64,
    pub packet_type_distribution: Vec<CountEntry>,
    pub version_distribution: Vec<CountEntry>,
}

/// Collects OSPF packet statistics.
#[derive(Debug)]
pub struct OspfStatsCollector {
    packet_types: HashMap<String, u64>,
    versions: HashMap<&'static str, u64>,
    total_packets: u64,
}

impl Default for OspfStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl OspfStatsCollector {
    pub fn new() -> Self {
        Self {
            packet_types: HashMap::new(),
            versions: HashMap::new(),
            total_packets: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        // Try both OSPFv2 and OSPFv3.
        let (layer, ver) = if let Some(l) = packet.layer_by_name("OSPFv2") {
            (l, "v2")
        } else if let Some(l) = packet.layer_by_name("OSPFv3") {
            (l, "v3")
        } else {
            return;
        };
        let fields = packet.layer_fields(layer);
        self.total_packets += 1;
        *self.versions.entry(ver).or_insert(0) += 1;

        if let Some(name) = display_name(packet, layer, fields, "msg_type_name", "msg_type") {
            *self.packet_types.entry(name).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> OspfStats {
        OspfStats {
            total_packets: self.total_packets,
            packet_type_distribution: sorted_top_n(self.packet_types.into_iter(), top_n),
            version_distribution: sorted_top_n(
                self.versions.into_iter().map(|(k, v)| (k.to_owned(), v)),
                top_n,
            ),
        }
    }
}

super::impl_protocol_stats_collector!(OspfStatsCollector, "ospf", OspfStats);
