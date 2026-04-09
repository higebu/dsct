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

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_pfcp_buf(message_type: u8) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("PFCP", None, &[], 0..8);
        buf.push_field(
            test_desc("message_type", "Message Type"),
            FieldValue::U8(message_type),
            1..2,
        );
        buf.end_layer();
        buf
    }

    #[test]
    fn pfcp_ignores_non_pfcp_packets() {
        let mut c = PfcpStatsCollector::new();
        let buf = DissectBuffer::new();
        c.process_packet(&pkt(&buf), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_messages, 0);
        assert!(stats.message_type_distribution.is_empty());
    }

    #[test]
    fn pfcp_counts_message_types() {
        let mut c = PfcpStatsCollector::new();
        let b1 = build_pfcp_buf(50); // Session Establishment Request
        c.process_packet(&pkt(&b1), None);
        let b2 = build_pfcp_buf(50);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_pfcp_buf(51); // Session Establishment Response
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_messages, 3);
        assert_eq!(stats.message_type_distribution[0].name, "50");
        assert_eq!(stats.message_type_distribution[0].count, 2);
        assert_eq!(stats.message_type_distribution[1].name, "51");
        assert_eq!(stats.message_type_distribution[1].count, 1);
    }

    #[test]
    fn pfcp_finalize_top_n_limits_distribution() {
        let mut c = PfcpStatsCollector::new();
        for t in 50u8..55 {
            let b = build_pfcp_buf(t);
            c.process_packet(&pkt(&b), None);
        }

        let stats = c.finalize_stats(2);
        assert_eq!(stats.message_type_distribution.len(), 2);
        assert_eq!(stats.total_messages, 5);
    }
}
