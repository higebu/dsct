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

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_ospf_buf(layer: &'static str, msg_type: u8) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer(layer, None, &[], 0..24);
        buf.push_field(
            test_desc("msg_type", "Message Type"),
            FieldValue::U8(msg_type),
            1..2,
        );
        buf.end_layer();
        buf
    }

    #[test]
    fn ospf_ignores_non_ospf_packets() {
        let mut c = OspfStatsCollector::new();
        let buf = DissectBuffer::new();
        c.process_packet(&pkt(&buf), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
        assert!(stats.packet_type_distribution.is_empty());
        assert!(stats.version_distribution.is_empty());
    }

    #[test]
    fn ospf_v2_counts_packets() {
        let mut c = OspfStatsCollector::new();
        let b1 = build_ospf_buf("OSPFv2", 1); // Hello
        c.process_packet(&pkt(&b1), None);
        let b2 = build_ospf_buf("OSPFv2", 1);
        c.process_packet(&pkt(&b2), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 2);
        assert_eq!(stats.version_distribution[0].name, "v2");
        assert_eq!(stats.version_distribution[0].count, 2);
        assert_eq!(stats.packet_type_distribution[0].name, "1");
        assert_eq!(stats.packet_type_distribution[0].count, 2);
    }

    #[test]
    fn ospf_v3_counts_packets() {
        let mut c = OspfStatsCollector::new();
        let b1 = build_ospf_buf("OSPFv3", 2); // Database Description
        c.process_packet(&pkt(&b1), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 1);
        assert_eq!(stats.version_distribution[0].name, "v3");
        assert_eq!(stats.version_distribution[0].count, 1);
        assert_eq!(stats.packet_type_distribution[0].name, "2");
    }

    #[test]
    fn ospf_finalize_top_n_limits_msg_types() {
        let mut c = OspfStatsCollector::new();
        for t in 1u8..=5 {
            let b = build_ospf_buf("OSPFv2", t);
            c.process_packet(&pkt(&b), None);
        }

        let stats = c.finalize_stats(2);
        assert_eq!(stats.packet_type_distribution.len(), 2);
        assert_eq!(stats.total_packets, 5);
    }
}
