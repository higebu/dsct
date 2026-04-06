use std::collections::HashMap;
use std::net::Ipv4Addr;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, field_value_to_string, find_field, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated DHCP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct DhcpStats {
    pub total_packets: u64,
    pub message_type_distribution: Vec<CountEntry>,
    pub top_hostnames: Vec<CountEntry>,
    pub top_requested_ips: Vec<CountEntry>,
}

/// Collects DHCP message statistics.
#[derive(Debug)]
pub struct DhcpStatsCollector {
    message_types: HashMap<String, u64>,
    hostnames: HashMap<String, u64>,
    requested_ips: HashMap<Ipv4Addr, u64>,
    total_packets: u64,
}

impl Default for DhcpStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl DhcpStatsCollector {
    pub fn new() -> Self {
        Self {
            message_types: HashMap::new(),
            hostnames: HashMap::new(),
            requested_ips: HashMap::new(),
            total_packets: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(dhcp) = packet.layer_by_name("DHCP") else {
            return;
        };
        let fields = packet.layer_fields(dhcp);
        self.total_packets += 1;

        if let Some(name) = display_name(
            packet,
            dhcp,
            fields,
            "dhcp_message_type_name",
            "dhcp_message_type",
        ) {
            *self.message_types.entry(name).or_insert(0) += 1;
        }

        // hostname is stored as Bytes in DHCP options.
        if let Some(hostname_field) = find_field(fields, "hostname") {
            let name = field_value_to_string(&hostname_field.value);
            if !name.is_empty() {
                *self.hostnames.entry(name).or_insert(0) += 1;
            }
        }

        if let Some(requested_ip_field) = find_field(fields, "requested_ip")
            && let FieldValue::Ipv4Addr(b) = &requested_ip_field.value
        {
            let addr = Ipv4Addr::from(*b);
            *self.requested_ips.entry(addr).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> DhcpStats {
        DhcpStats {
            total_packets: self.total_packets,
            message_type_distribution: sorted_top_n(self.message_types.into_iter(), top_n),
            top_hostnames: sorted_top_n(self.hostnames.into_iter(), top_n),
            top_requested_ips: sorted_top_n(
                self.requested_ips
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v)),
                top_n,
            ),
        }
    }
}

super::impl_protocol_stats_collector!(DhcpStatsCollector, "dhcp", DhcpStats);
