use std::collections::HashMap;
use std::net::Ipv4Addr;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;
use serde::Serialize;

use super::helpers::{find_field, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};

/// Human-readable name for an IGMP message type byte.
fn igmp_type_name(t: u8) -> &'static str {
    match t {
        0x11 => "Membership Query",
        0x12 => "IGMPv1 Membership Report",
        0x16 => "IGMPv2 Membership Report",
        0x17 => "Leave Group",
        0x22 => "IGMPv3 Membership Report",
        _ => "Unknown",
    }
}

/// IGMP version string inferred from message type.
fn igmp_version(t: u8) -> &'static str {
    match t {
        0x12 => "IGMPv1",
        0x16 | 0x17 => "IGMPv2",
        0x22 => "IGMPv3",
        _ => "Other",
    }
}

/// Aggregated IGMP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct IgmpStats {
    /// Total number of IGMP packets observed.
    pub total_packets: u64,
    /// Distribution of IGMP message types using human-readable names.
    pub type_distribution: Vec<CountEntry>,
    /// Most frequent multicast group addresses (from `group_address` and
    /// IGMPv3 `multicast_address` fields).
    pub top_group_addresses: Vec<CountEntry>,
    /// IGMP version distribution inferred from message type.
    pub version_distribution: Vec<CountEntry>,
}

/// Collects IGMP statistics in a single pass.
#[derive(Debug)]
pub struct IgmpStatsCollector {
    total_packets: u64,
    types: HashMap<String, u64>,
    group_addrs: HashMap<String, u64>,
    versions: HashMap<String, u64>,
}

impl Default for IgmpStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl IgmpStatsCollector {
    /// Create a new collector with the given per-map entry cap.
    pub fn new() -> Self {
        Self {
            total_packets: 0,
            types: HashMap::new(),
            group_addrs: HashMap::new(),
            versions: HashMap::new(),
        }
    }

    /// Process a single dissected packet.
    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(igmp) = packet.layer_by_name("IGMP") else {
            return;
        };
        let fields = packet.layer_fields(igmp);
        self.total_packets += 1;

        // Message type
        if let Some(f) = find_field(fields, "type")
            && let FieldValue::U8(t) = f.value
        {
            let type_name = igmp_type_name(t).to_string();
            *self.types.entry(type_name).or_insert(0) += 1;
            let version = igmp_version(t).to_string();
            *self.versions.entry(version).or_insert(0) += 1;
        }

        // Group address (top-level, present in v1/v2)
        if let Some(f) = find_field(fields, "group_address")
            && let FieldValue::Ipv4Addr(b) = f.value
        {
            let addr = Ipv4Addr::from(b).to_string();
            *self.group_addrs.entry(addr).or_insert(0) += 1;
        }

        // IGMPv3 group records
        if let Some(records_field) = find_field(fields, "group_records")
            && let FieldValue::Array(ref arr_range) = records_field.value
        {
            for elem in packet.nested_fields(arr_range) {
                if let FieldValue::Object(ref obj_range) = elem.value {
                    let rec_fields = packet.nested_fields(obj_range);
                    for f in rec_fields {
                        if f.name() == "multicast_address"
                            && let FieldValue::Ipv4Addr(b) = &f.value
                        {
                            let addr = Ipv4Addr::from(*b).to_string();
                            *self.group_addrs.entry(addr).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }

    /// Produce the final [`IgmpStats`] output.
    pub(super) fn finalize_stats(self, top_n: usize) -> IgmpStats {
        IgmpStats {
            total_packets: self.total_packets,
            type_distribution: sorted_top_n(self.types.into_iter(), top_n),
            top_group_addresses: sorted_top_n(self.group_addrs.into_iter(), top_n),
            version_distribution: sorted_top_n(self.versions.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(IgmpStatsCollector, "igmp", IgmpStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_igmp_buf(igmp_type: u8, group_addr: [u8; 4]) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("IGMP", None, &[], 0..8);
        buf.push_field(test_desc("type", "Type"), FieldValue::U8(igmp_type), 0..1);
        buf.push_field(
            test_desc("group_address", "Group Address"),
            FieldValue::Ipv4Addr(group_addr),
            4..8,
        );
        buf.end_layer();
        buf
    }

    #[test]
    fn igmp_type_distribution() {
        let mut c = IgmpStatsCollector::new();
        c.process_packet(&pkt(&build_igmp_buf(0x16, [224, 0, 0, 1])), None);
        c.process_packet(&pkt(&build_igmp_buf(0x16, [224, 0, 0, 2])), None);
        c.process_packet(&pkt(&build_igmp_buf(0x17, [224, 0, 0, 1])), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 3);
        assert_eq!(stats.type_distribution[0].name, "IGMPv2 Membership Report");
        assert_eq!(stats.type_distribution[0].count, 2);
    }

    #[test]
    fn igmp_top_group_addresses() {
        let mut c = IgmpStatsCollector::new();
        c.process_packet(&pkt(&build_igmp_buf(0x16, [224, 0, 0, 1])), None);
        c.process_packet(&pkt(&build_igmp_buf(0x16, [224, 0, 0, 1])), None);
        c.process_packet(&pkt(&build_igmp_buf(0x16, [224, 0, 0, 2])), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.top_group_addresses[0].name, "224.0.0.1");
        assert_eq!(stats.top_group_addresses[0].count, 2);
    }

    #[test]
    fn igmp_version_distribution() {
        let mut c = IgmpStatsCollector::new();
        c.process_packet(&pkt(&build_igmp_buf(0x12, [224, 0, 0, 1])), None);
        c.process_packet(&pkt(&build_igmp_buf(0x16, [224, 0, 0, 1])), None);
        c.process_packet(&pkt(&build_igmp_buf(0x22, [224, 0, 0, 1])), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.version_distribution.len(), 3);
    }

    #[test]
    fn igmp_ignores_non_igmp_packets() {
        let mut c = IgmpStatsCollector::new();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("UDP", None, &[], 0..8);
        buf.end_layer();
        c.process_packet(&pkt(&buf), None);
        assert_eq!(c.finalize_stats(10).total_packets, 0);
    }
}
