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

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_radius_buf(code: u8) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("RADIUS", None, &[], 0..20);
        buf.push_field(test_desc("code", "Code"), FieldValue::U8(code), 0..1);
        buf.end_layer();
        buf
    }

    #[test]
    fn radius_ignores_non_radius_packets() {
        let mut c = RadiusStatsCollector::new();
        let buf = DissectBuffer::new();
        c.process_packet(&pkt(&buf), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
        assert!(stats.code_distribution.is_empty());
    }

    #[test]
    fn radius_counts_codes() {
        let mut c = RadiusStatsCollector::new();
        let b1 = build_radius_buf(1); // Access-Request
        c.process_packet(&pkt(&b1), None);
        let b2 = build_radius_buf(1);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_radius_buf(2); // Access-Accept
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 3);
        assert_eq!(stats.code_distribution[0].name, "1");
        assert_eq!(stats.code_distribution[0].count, 2);
        assert_eq!(stats.code_distribution[1].name, "2");
        assert_eq!(stats.code_distribution[1].count, 1);
    }

    #[test]
    fn radius_finalize_top_n_limits_distribution() {
        let mut c = RadiusStatsCollector::new();
        for code in 1u8..=5 {
            let b = build_radius_buf(code);
            c.process_packet(&pkt(&b), None);
        }

        let stats = c.finalize_stats(2);
        assert_eq!(stats.code_distribution.len(), 2);
        assert_eq!(stats.total_packets, 5);
    }
}
