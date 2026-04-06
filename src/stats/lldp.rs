use std::collections::HashMap;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;

use super::helpers::{find_field, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Map a TLV type byte to its name.
fn tlv_type_name(t: u8) -> &'static str {
    match t {
        0 => "End Of LLDPDU",
        1 => "Chassis ID",
        2 => "Port ID",
        3 => "Time To Live",
        4 => "Port Description",
        5 => "System Name",
        6 => "System Description",
        7 => "System Capabilities",
        8 => "Management Address",
        127 => "Organizationally Specific",
        _ => "Reserved",
    }
}

/// Aggregated LLDP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct LldpStats {
    /// Total LLDP packets processed.
    pub total_packets: u64,
    /// Distribution of TLV types seen across all packets.
    pub tlv_type_distribution: Vec<CountEntry>,
    /// Most frequent System Name TLV values.
    pub top_system_names: Vec<CountEntry>,
}

/// Collects LLDP packet statistics.
#[derive(Debug)]
pub struct LldpStatsCollector {
    total_packets: u64,
    tlv_types: HashMap<String, u64>,
    system_names: HashMap<String, u64>,
}

impl Default for LldpStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl LldpStatsCollector {
    /// Create a new collector with the given maximum number of tracked entries.
    pub fn new() -> Self {
        Self {
            total_packets: 0,
            tlv_types: HashMap::new(),
            system_names: HashMap::new(),
        }
    }

    /// Process a single dissected packet, extracting LLDP TLV statistics.
    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(lldp) = packet.layer_by_name("LLDP") else {
            return;
        };
        let fields = packet.layer_fields(lldp);
        self.total_packets += 1;

        let Some(tlvs_field) = find_field(fields, "tlvs") else {
            return;
        };
        let FieldValue::Array(ref arr_range) = tlvs_field.value else {
            return;
        };

        for elem in packet.nested_fields(arr_range) {
            let FieldValue::Object(ref obj_range) = elem.value else {
                continue;
            };
            let tlv_fields = packet.nested_fields(obj_range);

            let tlv_type = tlv_fields.iter().find_map(|f| {
                if f.name() == "type" {
                    if let FieldValue::U8(t) = f.value {
                        Some(t)
                    } else {
                        None
                    }
                } else {
                    None
                }
            });

            if let Some(t) = tlv_type {
                let type_name = tlv_type_name(t).to_string();
                *self.tlv_types.entry(type_name).or_insert(0) += 1;

                // For System Name TLV (type=5): extract the value as UTF-8.
                if t == 5 {
                    for f in tlv_fields {
                        if f.name() == "value"
                            && let FieldValue::Bytes(b) = &f.value
                            && let Ok(name) = std::str::from_utf8(b)
                        {
                            let name = name.trim().to_string();
                            if !name.is_empty() {
                                *self.system_names.entry(name).or_insert(0) += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> LldpStats {
        LldpStats {
            total_packets: self.total_packets,
            tlv_type_distribution: sorted_top_n(self.tlv_types.into_iter(), top_n),
            top_system_names: sorted_top_n(self.system_names.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(LldpStatsCollector, "lldp", LldpStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_lldp_buf_with_system_name(system_name: &'static [u8]) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("LLDP", None, &[], 0..100);
        let arr = buf.begin_container(test_desc("tlvs", "TLVs"), FieldValue::Array(0..0), 0..100);

        // Chassis ID TLV (type=1)
        let tlv1 = buf.begin_container(test_desc("tlv", "TLV"), FieldValue::Object(0..0), 0..10);
        buf.push_field(test_desc("type", "TLV Type"), FieldValue::U8(1), 0..1);
        buf.end_container(tlv1);

        // System Name TLV (type=5)
        let tlv2 = buf.begin_container(test_desc("tlv", "TLV"), FieldValue::Object(0..0), 10..20);
        buf.push_field(test_desc("type", "TLV Type"), FieldValue::U8(5), 10..11);
        buf.push_field(
            test_desc("value", "Value"),
            FieldValue::Bytes(system_name),
            11..20,
        );
        buf.end_container(tlv2);

        buf.end_container(arr);
        buf.end_layer();
        buf
    }

    fn build_lldp_buf_no_system_name() -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("LLDP", None, &[], 0..50);
        let arr = buf.begin_container(test_desc("tlvs", "TLVs"), FieldValue::Array(0..0), 0..50);
        // Chassis ID TLV only
        let tlv = buf.begin_container(test_desc("tlv", "TLV"), FieldValue::Object(0..0), 0..10);
        buf.push_field(test_desc("type", "TLV Type"), FieldValue::U8(1), 0..1);
        buf.end_container(tlv);
        buf.end_container(arr);
        buf.end_layer();
        buf
    }

    #[test]
    fn lldp_tlv_type_distribution() {
        let mut c = LldpStatsCollector::new();
        c.process_packet(&pkt(&build_lldp_buf_with_system_name(b"router1")), None);
        c.process_packet(&pkt(&build_lldp_buf_no_system_name()), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 2);
        // Should have seen Chassis ID TLV (type=1) twice
        let chassis = stats
            .tlv_type_distribution
            .iter()
            .find(|e| e.name == "Chassis ID");
        assert!(chassis.is_some());
        assert_eq!(chassis.unwrap().count, 2);
    }

    #[test]
    fn lldp_top_system_names() {
        let mut c = LldpStatsCollector::new();
        c.process_packet(&pkt(&build_lldp_buf_with_system_name(b"router1")), None);
        c.process_packet(&pkt(&build_lldp_buf_with_system_name(b"router1")), None);
        c.process_packet(&pkt(&build_lldp_buf_with_system_name(b"switch1")), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.top_system_names[0].name, "router1");
        assert_eq!(stats.top_system_names[0].count, 2);
    }

    #[test]
    fn lldp_ignores_non_lldp_packets() {
        let mut c = LldpStatsCollector::new();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("ARP", None, &[], 0..28);
        buf.end_layer();
        c.process_packet(&pkt(&buf), None);
        assert_eq!(c.finalize_stats(10).total_packets, 0);
    }
}
