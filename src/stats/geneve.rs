use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, field_u32, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};

use serde::Serialize;

/// Aggregated GENEVE statistics.
#[derive(Debug, Clone, Serialize)]
pub struct GeneveStats {
    pub total_packets: u64,
    pub protocol_type_distribution: Vec<CountEntry>,
    pub top_vnis: Vec<CountEntry>,
}

/// Collects GENEVE tunnel statistics.
#[derive(Debug)]
pub struct GeneveStatsCollector {
    protocol_types: HashMap<String, u64>,
    vnis: HashMap<u32, u64>,
    total_packets: u64,
}

impl Default for GeneveStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl GeneveStatsCollector {
    /// Create a new collector with the given entry cap.
    pub fn new() -> Self {
        Self {
            protocol_types: HashMap::new(),
            vnis: HashMap::new(),
            total_packets: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(geneve) = packet.layer_by_name("GENEVE") else {
            return;
        };
        let fields = packet.layer_fields(geneve);
        self.total_packets += 1;

        if let Some(name) = display_name(
            packet,
            geneve,
            fields,
            "protocol_type_name",
            "protocol_type",
        ) {
            *self.protocol_types.entry(name).or_insert(0) += 1;
        }

        if let Some(vni) = field_u32(fields, "vni") {
            *self.vnis.entry(vni).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> GeneveStats {
        GeneveStats {
            total_packets: self.total_packets,
            protocol_type_distribution: sorted_top_n(self.protocol_types.into_iter(), top_n),
            top_vnis: sorted_top_n(
                self.vnis.into_iter().map(|(k, v)| (k.to_string(), v)),
                top_n,
            ),
        }
    }
}

super::impl_protocol_stats_collector!(GeneveStatsCollector, "geneve", GeneveStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{build_vxlan_buf, pkt};
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_geneve_buf(protocol_type: u16, vni: u32) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("GENEVE", None, &[], 0..8);
        buf.push_field(
            test_desc("protocol_type", "Protocol Type"),
            FieldValue::U16(protocol_type),
            2..4,
        );
        buf.push_field(test_desc("vni", "VNI"), FieldValue::U32(vni), 4..7);
        buf.end_layer();
        buf
    }

    #[test]
    fn geneve_collector_tracks_protocol_type_and_vni() {
        let mut c = GeneveStatsCollector::new();
        c.process_packet(&pkt(&build_geneve_buf(0x6558, 10)), None);
        c.process_packet(&pkt(&build_geneve_buf(0x6558, 10)), None);
        c.process_packet(&pkt(&build_geneve_buf(0x0800, 20)), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 3);
        assert_eq!(stats.protocol_type_distribution.len(), 2);
        assert_eq!(stats.top_vnis[0].name, "10");
        assert_eq!(stats.top_vnis[0].count, 2);
    }

    #[test]
    fn geneve_collector_ignores_non_geneve_packets() {
        let mut c = GeneveStatsCollector::new();
        c.process_packet(&pkt(&build_vxlan_buf(100)), None);
        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
    }
}
