use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, field_u32, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated GRE statistics.
#[derive(Debug, Clone, Serialize)]
pub struct GreStats {
    pub total_packets: u64,
    pub protocol_type_distribution: Vec<CountEntry>,
    pub top_keys: Vec<CountEntry>,
}

/// Collects GRE tunnel statistics.
#[derive(Debug)]
pub struct GreStatsCollector {
    protocol_types: HashMap<String, u64>,
    keys: HashMap<u32, u64>,
    total_packets: u64,
}

impl Default for GreStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl GreStatsCollector {
    /// Create a new collector with the given entry cap.
    pub fn new() -> Self {
        Self {
            protocol_types: HashMap::new(),
            keys: HashMap::new(),
            total_packets: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(gre) = packet.layer_by_name("GRE") else {
            return;
        };
        let fields = packet.layer_fields(gre);
        self.total_packets += 1;

        if let Some(name) = display_name(packet, gre, fields, "protocol_type_name", "protocol_type")
        {
            *self.protocol_types.entry(name).or_insert(0) += 1;
        }

        if let Some(key) = field_u32(fields, "key") {
            *self.keys.entry(key).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> GreStats {
        GreStats {
            total_packets: self.total_packets,
            protocol_type_distribution: sorted_top_n(self.protocol_types.into_iter(), top_n),
            top_keys: sorted_top_n(
                self.keys.into_iter().map(|(k, v)| (k.to_string(), v)),
                top_n,
            ),
        }
    }
}

super::impl_protocol_stats_collector!(GreStatsCollector, "gre", GreStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{build_vxlan_buf, pkt};
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_gre_buf(protocol_type: u16, key: Option<u32>) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("GRE", None, &[], 0..12);
        buf.push_field(
            test_desc("protocol_type", "Protocol Type"),
            FieldValue::U16(protocol_type),
            2..4,
        );
        if let Some(k) = key {
            buf.push_field(test_desc("key", "Key"), FieldValue::U32(k), 4..8);
        }
        buf.end_layer();
        buf
    }

    #[test]
    fn gre_collector_tracks_protocol_type_and_key() {
        let mut c = GreStatsCollector::new();
        c.process_packet(&pkt(&build_gre_buf(0x0800, Some(42))), None);
        c.process_packet(&pkt(&build_gre_buf(0x0800, Some(42))), None);
        c.process_packet(&pkt(&build_gre_buf(0x86DD, None)), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 3);
        assert_eq!(stats.protocol_type_distribution.len(), 2);
        assert_eq!(stats.top_keys.len(), 1);
        assert_eq!(stats.top_keys[0].count, 2);
    }

    #[test]
    fn gre_collector_ignores_non_gre_packets() {
        let mut c = GreStatsCollector::new();
        c.process_packet(&pkt(&build_vxlan_buf(100)), None);
        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
    }

    #[test]
    fn gre_collector_no_key_when_absent() {
        let mut c = GreStatsCollector::new();
        c.process_packet(&pkt(&build_gre_buf(0x0800, None)), None);
        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 1);
        assert!(stats.top_keys.is_empty());
    }
}
