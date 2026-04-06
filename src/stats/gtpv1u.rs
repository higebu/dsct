use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, field_value_to_string, find_field, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated GTPv1-U statistics.
#[derive(Debug, Clone, Serialize)]
pub struct Gtpv1uStats {
    pub total_packets: u64,
    pub message_type_distribution: Vec<CountEntry>,
    pub top_teids: Vec<CountEntry>,
}

/// Collects GTPv1-U tunnel statistics.
#[derive(Debug)]
pub struct Gtpv1uStatsCollector {
    message_types: HashMap<String, u64>,
    teids: HashMap<String, u64>,
    total_packets: u64,
}

impl Default for Gtpv1uStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Gtpv1uStatsCollector {
    pub fn new() -> Self {
        Self {
            message_types: HashMap::new(),
            teids: HashMap::new(),
            total_packets: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(gtp) = packet.layer_by_name("GTPv1-U") else {
            return;
        };
        let fields = packet.layer_fields(gtp);
        self.total_packets += 1;

        if let Some(name) = display_name(packet, gtp, fields, "message_type_name", "message_type") {
            *self.message_types.entry(name).or_insert(0) += 1;
        }
        if let Some(teid) = find_field(fields, "teid") {
            let key = field_value_to_string(&teid.value);
            *self.teids.entry(key).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> Gtpv1uStats {
        Gtpv1uStats {
            total_packets: self.total_packets,
            message_type_distribution: sorted_top_n(self.message_types.into_iter(), top_n),
            top_teids: sorted_top_n(self.teids.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(Gtpv1uStatsCollector, "gtpv1u", Gtpv1uStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{build_gtpv1u_buf, pkt};
    use super::*;
    use packet_dissector_core::packet::DissectBuffer;

    #[test]
    fn gtpv1u_collector_counts_packets() {
        let mut c = Gtpv1uStatsCollector::new();
        c.process_packet(&pkt(&build_gtpv1u_buf(255, 1)), None);
        c.process_packet(&pkt(&build_gtpv1u_buf(255, 2)), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 2);
    }

    #[test]
    fn gtpv1u_collector_message_type_distribution() {
        let mut c = Gtpv1uStatsCollector::new();
        c.process_packet(&pkt(&build_gtpv1u_buf(255, 1)), None);
        c.process_packet(&pkt(&build_gtpv1u_buf(255, 2)), None);
        c.process_packet(&pkt(&build_gtpv1u_buf(1, 3)), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.message_type_distribution.len(), 2);
        assert_eq!(stats.message_type_distribution[0].count, 2);
    }

    #[test]
    fn gtpv1u_collector_top_teids() {
        let mut c = Gtpv1uStatsCollector::new();
        for _ in 0..3 {
            c.process_packet(&pkt(&build_gtpv1u_buf(255, 42)), None);
        }
        c.process_packet(&pkt(&build_gtpv1u_buf(255, 99)), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.top_teids[0].count, 3);
        assert_eq!(stats.top_teids[1].count, 1);
    }

    #[test]
    fn gtpv1u_collector_ignores_non_gtp_packets() {
        let mut c = Gtpv1uStatsCollector::new();
        c.process_packet(&pkt(&DissectBuffer::new()), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
        assert!(stats.message_type_distribution.is_empty());
        assert!(stats.top_teids.is_empty());
    }
}
