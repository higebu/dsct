use std::collections::HashMap;
use std::net::Ipv4Addr;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, field_value_to_string, find_field, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated ARP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct ArpStats {
    pub total_packets: u64,
    pub oper_distribution: Vec<CountEntry>,
    pub top_spa: Vec<CountEntry>,
    pub top_sha: Vec<CountEntry>,
}

/// Collects ARP operation and address statistics.
#[derive(Debug)]
pub struct ArpStatsCollector {
    opers: HashMap<String, u64>,
    spa_counts: HashMap<Ipv4Addr, u64>,
    sha_counts: HashMap<String, u64>,
    total_packets: u64,
}

impl Default for ArpStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl ArpStatsCollector {
    pub fn new() -> Self {
        Self {
            opers: HashMap::new(),
            spa_counts: HashMap::new(),
            sha_counts: HashMap::new(),
            total_packets: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(arp) = packet.layer_by_name("ARP") else {
            return;
        };
        let fields = packet.layer_fields(arp);
        self.total_packets += 1;

        if let Some(name) = display_name(packet, arp, fields, "oper_name", "oper") {
            *self.opers.entry(name).or_insert(0) += 1;
        }

        if let Some(f) = find_field(fields, "spa")
            && let FieldValue::Ipv4Addr(b) = &f.value
        {
            let addr = Ipv4Addr::from(*b);
            *self.spa_counts.entry(addr).or_insert(0) += 1;
        }

        if let Some(f) = find_field(fields, "sha") {
            let s = field_value_to_string(&f.value);
            if !s.is_empty() {
                *self.sha_counts.entry(s).or_insert(0) += 1;
            }
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> ArpStats {
        ArpStats {
            total_packets: self.total_packets,
            oper_distribution: sorted_top_n(self.opers.into_iter(), top_n),
            top_spa: sorted_top_n(
                self.spa_counts.into_iter().map(|(k, v)| (k.to_string(), v)),
                top_n,
            ),
            top_sha: sorted_top_n(self.sha_counts.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(ArpStatsCollector, "arp", ArpStats);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::test_helpers::pkt;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    #[allow(unused_imports)]
    use packet_dissector_test_alloc::test_desc;

    fn build_arp_buf(
        oper: u16,
        oper_name: &'static str,
        spa: [u8; 4],
        sha: &'static str,
    ) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("ARP", None, &[], 0..28);
        buf.push_field(test_desc("oper", "Operation"), FieldValue::U16(oper), 6..8);
        buf.push_field(
            test_desc("oper_name", "Operation Name"),
            FieldValue::Str(oper_name),
            6..8,
        );
        buf.push_field(
            test_desc("sha", "Sender Hardware Address"),
            FieldValue::Str(sha),
            8..14,
        );
        buf.push_field(
            test_desc("spa", "Sender Protocol Address"),
            FieldValue::Ipv4Addr(spa),
            14..18,
        );
        buf.end_layer();
        buf
    }

    #[test]
    fn arp_collector_counts_total_packets() {
        let mut c = ArpStatsCollector::new();
        let b1 = build_arp_buf(1, "Request", [192, 168, 1, 1], "aa:bb:cc:dd:ee:01");
        c.process_packet(&pkt(&b1), None);
        let b2 = build_arp_buf(2, "Reply", [192, 168, 1, 2], "aa:bb:cc:dd:ee:02");
        c.process_packet(&pkt(&b2), None);
        let b3 = build_arp_buf(1, "Request", [192, 168, 1, 1], "aa:bb:cc:dd:ee:01");
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 3);
    }

    #[test]
    fn arp_collector_oper_distribution() {
        let mut c = ArpStatsCollector::new();
        let b1 = build_arp_buf(1, "Request", [10, 0, 0, 1], "aa:bb:cc:dd:ee:01");
        c.process_packet(&pkt(&b1), None);
        let b2 = build_arp_buf(1, "Request", [10, 0, 0, 2], "aa:bb:cc:dd:ee:02");
        c.process_packet(&pkt(&b2), None);
        let b3 = build_arp_buf(2, "Reply", [10, 0, 0, 3], "aa:bb:cc:dd:ee:03");
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.oper_distribution.len(), 2);
        // test_desc has no display_fn, so display_name falls back to the numeric oper value.
        assert_eq!(stats.oper_distribution[0].count, 2);
        assert_eq!(stats.oper_distribution[1].count, 1);
    }

    #[test]
    fn arp_collector_top_spa() {
        let mut c = ArpStatsCollector::new();
        let b1 = build_arp_buf(1, "Request", [10, 0, 0, 1], "aa:bb:cc:dd:ee:01");
        c.process_packet(&pkt(&b1), None);
        let b2 = build_arp_buf(1, "Request", [10, 0, 0, 1], "aa:bb:cc:dd:ee:01");
        c.process_packet(&pkt(&b2), None);
        let b3 = build_arp_buf(2, "Reply", [10, 0, 0, 2], "aa:bb:cc:dd:ee:02");
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.top_spa[0].name, "10.0.0.1");
        assert_eq!(stats.top_spa[0].count, 2);
        assert_eq!(stats.top_spa[1].name, "10.0.0.2");
        assert_eq!(stats.top_spa[1].count, 1);
    }

    #[test]
    fn arp_collector_top_sha() {
        let mut c = ArpStatsCollector::new();
        let b1 = build_arp_buf(1, "Request", [10, 0, 0, 1], "aa:bb:cc:dd:ee:01");
        c.process_packet(&pkt(&b1), None);
        let b2 = build_arp_buf(1, "Request", [10, 0, 0, 1], "aa:bb:cc:dd:ee:01");
        c.process_packet(&pkt(&b2), None);
        let b3 = build_arp_buf(2, "Reply", [10, 0, 0, 2], "aa:bb:cc:dd:ee:02");
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.top_sha[0].name, "aa:bb:cc:dd:ee:01");
        assert_eq!(stats.top_sha[0].count, 2);
    }

    #[test]
    fn arp_collector_skips_non_arp_packets() {
        let mut c = ArpStatsCollector::new();
        let buf = DissectBuffer::new();
        c.process_packet(&pkt(&buf), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
        assert!(stats.oper_distribution.is_empty());
    }
}
