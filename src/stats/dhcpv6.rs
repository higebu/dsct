use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated DHCPv6 statistics.
#[derive(Debug, Clone, Serialize)]
pub struct Dhcpv6Stats {
    pub total_packets: u64,
    pub msg_type_distribution: Vec<CountEntry>,
}

/// Collects DHCPv6 message statistics.
#[derive(Debug)]
pub struct Dhcpv6StatsCollector {
    msg_types: HashMap<String, u64>,
    total_packets: u64,
}

impl Default for Dhcpv6StatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Dhcpv6StatsCollector {
    pub fn new() -> Self {
        Self {
            msg_types: HashMap::new(),
            total_packets: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(dhcpv6) = packet.layer_by_name("DHCPv6") else {
            return;
        };
        let fields = packet.layer_fields(dhcpv6);
        self.total_packets += 1;

        if let Some(name) = display_name(packet, dhcpv6, fields, "msg_type_name", "msg_type") {
            *self.msg_types.entry(name).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> Dhcpv6Stats {
        Dhcpv6Stats {
            total_packets: self.total_packets,
            msg_type_distribution: sorted_top_n(self.msg_types.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(Dhcpv6StatsCollector, "dhcpv6", Dhcpv6Stats);
