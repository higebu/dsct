use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated BGP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct BgpStats {
    pub total_messages: u64,
    pub message_type_distribution: Vec<CountEntry>,
}

/// Collects BGP message statistics.
#[derive(Debug)]
pub struct BgpStatsCollector {
    message_types: HashMap<String, u64>,
    total_messages: u64,
}

impl Default for BgpStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl BgpStatsCollector {
    pub fn new() -> Self {
        Self {
            message_types: HashMap::new(),
            total_messages: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(bgp) = packet.layer_by_name("BGP") else {
            return;
        };
        let fields = packet.layer_fields(bgp);
        self.total_messages += 1;

        if let Some(name) = display_name(packet, bgp, fields, "type_name", "type") {
            *self.message_types.entry(name).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> BgpStats {
        BgpStats {
            total_messages: self.total_messages,
            message_type_distribution: sorted_top_n(self.message_types.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(BgpStatsCollector, "bgp", BgpStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_bgp_buf(msg_type: u8) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("BGP", None, &[], 0..19);
        buf.push_field(test_desc("type", "Type"), FieldValue::U8(msg_type), 18..19);
        buf.end_layer();
        buf
    }

    #[test]
    fn bgp_ignores_non_bgp_packets() {
        let mut c = BgpStatsCollector::new();
        let buf = DissectBuffer::new();
        c.process_packet(&pkt(&buf), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_messages, 0);
        assert!(stats.message_type_distribution.is_empty());
    }

    #[test]
    fn bgp_counts_message_types() {
        let mut c = BgpStatsCollector::new();
        let b1 = build_bgp_buf(2); // UPDATE
        c.process_packet(&pkt(&b1), None);
        let b2 = build_bgp_buf(2);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_bgp_buf(4); // KEEPALIVE
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_messages, 3);
        assert_eq!(stats.message_type_distribution[0].name, "2");
        assert_eq!(stats.message_type_distribution[0].count, 2);
        assert_eq!(stats.message_type_distribution[1].name, "4");
        assert_eq!(stats.message_type_distribution[1].count, 1);
    }

    #[test]
    fn bgp_finalize_top_n_limits_distribution() {
        let mut c = BgpStatsCollector::new();
        for t in 1u8..=5 {
            let b = build_bgp_buf(t);
            c.process_packet(&pkt(&b), None);
        }

        let stats = c.finalize_stats(2);
        assert_eq!(stats.message_type_distribution.len(), 2);
        assert_eq!(stats.total_messages, 5);
    }
}
