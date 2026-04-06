use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, sorted_top_n};
use serde::Serialize;

use super::{CountEntry, ProtocolStatsCollector};

/// Shared implementation for ICMP-like collectors that track type and code distributions.
#[derive(Debug)]
struct TypeCodeCollector {
    layer_name: &'static str,
    types: HashMap<String, u64>,
    codes: HashMap<String, u64>,
    total_packets: u64,
}

impl TypeCodeCollector {
    fn new(layer_name: &'static str) -> Self {
        Self {
            layer_name,
            types: HashMap::new(),
            codes: HashMap::new(),
            total_packets: 0,
        }
    }

    fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(layer) = packet.layer_by_name(self.layer_name) else {
            return;
        };
        let fields = packet.layer_fields(layer);
        self.total_packets += 1;
        if let Some(name) = display_name(packet, layer, fields, "type_name", "type") {
            *self.types.entry(name).or_insert(0) += 1;
        }
        if let Some(name) = display_name(packet, layer, fields, "code_name", "code") {
            *self.codes.entry(name).or_insert(0) += 1;
        }
    }

    fn into_distributions(self, top_n: usize) -> (u64, Vec<CountEntry>, Vec<CountEntry>) {
        (
            self.total_packets,
            sorted_top_n(self.types.into_iter(), top_n),
            sorted_top_n(self.codes.into_iter(), top_n),
        )
    }
}

/// Aggregated ICMP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct IcmpStats {
    pub total_packets: u64,
    pub type_distribution: Vec<CountEntry>,
    pub code_distribution: Vec<CountEntry>,
}

/// Aggregated ICMPv6 statistics.
#[derive(Debug, Clone, Serialize)]
pub struct Icmpv6Stats {
    pub total_packets: u64,
    pub type_distribution: Vec<CountEntry>,
    pub code_distribution: Vec<CountEntry>,
}

/// Collects ICMP packet statistics.
#[derive(Debug)]
pub struct IcmpStatsCollector(TypeCodeCollector);

impl Default for IcmpStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl IcmpStatsCollector {
    pub fn new() -> Self {
        Self(TypeCodeCollector::new("ICMP"))
    }

    pub fn process_packet(&mut self, packet: &Packet, timestamp: Option<f64>) {
        self.0.process_packet(packet, timestamp);
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> IcmpStats {
        let (total_packets, type_distribution, code_distribution) =
            self.0.into_distributions(top_n);
        IcmpStats {
            total_packets,
            type_distribution,
            code_distribution,
        }
    }
}

super::impl_protocol_stats_collector!(IcmpStatsCollector, "icmp", IcmpStats);

/// Collects ICMPv6 packet statistics.
#[derive(Debug)]
pub struct Icmpv6StatsCollector(TypeCodeCollector);

impl Default for Icmpv6StatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Icmpv6StatsCollector {
    pub fn new() -> Self {
        Self(TypeCodeCollector::new("ICMPv6"))
    }

    pub fn process_packet(&mut self, packet: &Packet, timestamp: Option<f64>) {
        self.0.process_packet(packet, timestamp);
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> Icmpv6Stats {
        let (total_packets, type_distribution, code_distribution) =
            self.0.into_distributions(top_n);
        Icmpv6Stats {
            total_packets,
            type_distribution,
            code_distribution,
        }
    }
}

super::impl_protocol_stats_collector!(Icmpv6StatsCollector, "icmpv6", Icmpv6Stats);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::test_helpers::{build_icmp_like_buf, pkt};

    #[test]
    fn icmp_collector_counts_packets() {
        let mut c = IcmpStatsCollector::new();
        let b1 = build_icmp_like_buf("ICMP", 8, 0); // Echo Request
        c.process_packet(&pkt(&b1), None);
        c.process_packet(&pkt(&b1), None);
        let b2 = build_icmp_like_buf("ICMP", 0, 0); // Echo Reply
        c.process_packet(&pkt(&b2), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 3);
        assert_eq!(stats.type_distribution.len(), 2);
        assert_eq!(stats.type_distribution[0].count, 2);
        assert_eq!(stats.type_distribution[1].count, 1);
    }

    #[test]
    fn icmp_collector_type_distribution() {
        let mut c = IcmpStatsCollector::new();
        let b = build_icmp_like_buf("ICMP", 8, 0);
        c.process_packet(&pkt(&b), None);
        c.process_packet(&pkt(&b), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.type_distribution.len(), 1);
        assert_eq!(stats.type_distribution[0].count, 2);
    }

    #[test]
    fn icmp_collector_code_distribution() {
        let mut c = IcmpStatsCollector::new();
        let b1 = build_icmp_like_buf("ICMP", 3, 0); // Destination Unreachable, Net Unreachable
        let b2 = build_icmp_like_buf("ICMP", 3, 1); // Destination Unreachable, Host Unreachable
        c.process_packet(&pkt(&b1), None);
        c.process_packet(&pkt(&b2), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.code_distribution.len(), 2);
    }

    #[test]
    fn icmp_collector_ignores_non_icmp_packets() {
        use packet_dissector_core::packet::DissectBuffer;
        let mut c = IcmpStatsCollector::new();
        let buf = DissectBuffer::new();
        c.process_packet(&pkt(&buf), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
        assert!(stats.type_distribution.is_empty());
    }

    #[test]
    fn icmp_collector_empty() {
        let c = IcmpStatsCollector::new();
        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
        assert!(stats.type_distribution.is_empty());
        assert!(stats.code_distribution.is_empty());
    }

    #[test]
    fn icmp_collector_top_n_limits_results() {
        let mut c = IcmpStatsCollector::new();
        for t in 0u8..10 {
            let b = build_icmp_like_buf("ICMP", t, 0);
            c.process_packet(&pkt(&b), None);
        }
        let stats = c.finalize_stats(5);
        assert_eq!(stats.type_distribution.len(), 5);
    }

    #[test]
    fn icmpv6_collector_counts_packets() {
        let mut c = Icmpv6StatsCollector::new();
        let b1 = build_icmp_like_buf("ICMPv6", 128, 0); // Echo Request
        c.process_packet(&pkt(&b1), None);
        c.process_packet(&pkt(&b1), None);
        let b2 = build_icmp_like_buf("ICMPv6", 129, 0); // Echo Reply
        c.process_packet(&pkt(&b2), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 3);
        assert_eq!(stats.type_distribution.len(), 2);
        assert_eq!(stats.type_distribution[0].count, 2);
        assert_eq!(stats.type_distribution[1].count, 1);
    }

    #[test]
    fn icmpv6_collector_type_distribution() {
        let mut c = Icmpv6StatsCollector::new();
        let b = build_icmp_like_buf("ICMPv6", 135, 0); // Neighbor Solicitation
        c.process_packet(&pkt(&b), None);
        c.process_packet(&pkt(&b), None);
        c.process_packet(&pkt(&b), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.type_distribution.len(), 1);
        assert_eq!(stats.type_distribution[0].count, 3);
    }

    #[test]
    fn icmpv6_collector_ignores_non_icmpv6_packets() {
        let mut c = Icmpv6StatsCollector::new();
        let b = build_icmp_like_buf("ICMP", 8, 0); // ICMP, not ICMPv6
        c.process_packet(&pkt(&b), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
    }

    #[test]
    fn icmpv6_collector_empty() {
        let c = Icmpv6StatsCollector::new();
        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
        assert!(stats.type_distribution.is_empty());
        assert!(stats.code_distribution.is_empty());
    }
}
