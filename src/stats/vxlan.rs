use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{field_u32, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated VXLAN statistics.
#[derive(Debug, Clone, Serialize)]
pub struct VxlanStats {
    pub total_packets: u64,
    pub top_vnis: Vec<CountEntry>,
}

/// Collects VXLAN tunnel statistics.
#[derive(Debug)]
pub struct VxlanStatsCollector {
    vnis: HashMap<u32, u64>,
    total_packets: u64,
}

impl Default for VxlanStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl VxlanStatsCollector {
    /// Create a new collector.
    pub fn new() -> Self {
        Self {
            vnis: HashMap::new(),
            total_packets: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(vxlan) = packet.layer_by_name("VXLAN") else {
            return;
        };
        let fields = packet.layer_fields(vxlan);
        self.total_packets += 1;

        if let Some(vni) = field_u32(fields, "vni") {
            *self.vnis.entry(vni).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> VxlanStats {
        VxlanStats {
            total_packets: self.total_packets,
            top_vnis: sorted_top_n(
                self.vnis.into_iter().map(|(k, v)| (k.to_string(), v)),
                top_n,
            ),
        }
    }
}

super::impl_protocol_stats_collector!(VxlanStatsCollector, "vxlan", VxlanStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{build_vxlan_buf, pkt};
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    #[test]
    fn vxlan_collector_tracks_vnis() {
        let mut c = VxlanStatsCollector::new();
        let b1 = build_vxlan_buf(100);
        c.process_packet(&pkt(&b1), None);
        let b2 = build_vxlan_buf(100);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_vxlan_buf(200);
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 3);
        assert_eq!(stats.top_vnis[0].name, "100");
        assert_eq!(stats.top_vnis[0].count, 2);
        assert_eq!(stats.top_vnis[1].name, "200");
        assert_eq!(stats.top_vnis[1].count, 1);
    }

    #[test]
    fn vxlan_collector_ignores_non_vxlan_packets() {
        let mut c = VxlanStatsCollector::new();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..20);
        buf.push_field(test_desc("id", "Transaction ID"), FieldValue::U16(1), 0..2);
        buf.push_field(test_desc("qr", "QR"), FieldValue::U8(0), 2..3);
        buf.end_layer();
        c.process_packet(&pkt(&buf), None);
        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
        assert!(stats.top_vnis.is_empty());
    }
}
