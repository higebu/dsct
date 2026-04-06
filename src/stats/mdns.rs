use std::collections::HashMap;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;

use super::helpers::{field_u8, find_field, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

// ---------------------------------------------------------------------------
// mDNS query type display names
// ---------------------------------------------------------------------------

#[cfg(feature = "dns")]
fn mdns_type_display(qtype: u16) -> String {
    packet_dissector::dissectors::dns::dns_type_name(qtype)
        .map(String::from)
        .unwrap_or_else(|| format!("TYPE{qtype}"))
}

#[cfg(not(feature = "dns"))]
fn mdns_type_display(qtype: u16) -> String {
    format!("TYPE{qtype}")
}

/// Aggregated mDNS statistics.
#[derive(Debug, Clone, Serialize)]
pub struct MdnsStats {
    pub total_packets: u64,
    pub total_queries: u64,
    pub total_responses: u64,
    pub top_query_names: Vec<CountEntry>,
    pub query_type_distribution: Vec<CountEntry>,
    pub service_distribution: Vec<CountEntry>,
}

/// Collects mDNS packet statistics.
#[derive(Debug)]
pub struct MdnsStatsCollector {
    query_names: HashMap<String, u64>,
    query_types: HashMap<String, u64>,
    services: HashMap<String, u64>,
    total_packets: u64,
    total_queries: u64,
    total_responses: u64,
}

impl Default for MdnsStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl MdnsStatsCollector {
    /// Create a new collector.
    pub fn new() -> Self {
        Self {
            query_names: HashMap::new(),
            query_types: HashMap::new(),
            services: HashMap::new(),
            total_packets: 0,
            total_queries: 0,
            total_responses: 0,
        }
    }

    /// Process a single dissected packet, updating running counters.
    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(mdns) = packet.layer_by_name("mDNS") else {
            return;
        };
        let fields = packet.layer_fields(mdns);
        self.total_packets += 1;

        let qr = field_u8(fields, "qr").unwrap_or(0);
        if qr == 0 {
            self.total_queries += 1;
        } else {
            self.total_responses += 1;
        }

        if let Some(questions_field) = find_field(fields, "questions")
            && let FieldValue::Array(ref arr_range) = questions_field.value
        {
            for elem in packet.nested_fields(arr_range) {
                if let FieldValue::Object(ref obj_range) = elem.value {
                    let q_fields = packet.nested_fields(obj_range);
                    for f in q_fields {
                        if f.name() == "name" {
                            if let FieldValue::Str(s) = &f.value {
                                let name = (*s).to_string();
                                *self.query_names.entry(name.clone()).or_insert(0) += 1;
                                if s.starts_with('_') {
                                    *self.services.entry(name).or_insert(0) += 1;
                                }
                            }
                        } else if f.name() == "type"
                            && let FieldValue::U16(t) = f.value
                        {
                            let type_name = mdns_type_display(t);
                            *self.query_types.entry(type_name).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }

    /// Consume the collector and produce the final [`MdnsStats`].
    pub(super) fn finalize_stats(self, top_n: usize) -> MdnsStats {
        MdnsStats {
            total_packets: self.total_packets,
            total_queries: self.total_queries,
            total_responses: self.total_responses,
            top_query_names: sorted_top_n(self.query_names.into_iter(), top_n),
            query_type_distribution: sorted_top_n(self.query_types.into_iter(), top_n),
            service_distribution: sorted_top_n(self.services.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(MdnsStatsCollector, "mdns", MdnsStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_mdns_query_buf(name: &'static str, qtype: u16) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("mDNS", None, &[], 0..20);
        buf.push_field(test_desc("id", "ID"), FieldValue::U16(0), 0..2);
        buf.push_field(test_desc("qr", "QR"), FieldValue::U8(0), 2..3);
        let arr = buf.begin_container(
            test_desc("questions", "Questions"),
            FieldValue::Array(0..0),
            12..14,
        );
        let obj = buf.begin_container(test_desc("q", "Q"), FieldValue::Object(0..0), 12..14);
        buf.push_field(test_desc("name", "Name"), FieldValue::Str(name), 12..12);
        buf.push_field(test_desc("type", "Type"), FieldValue::U16(qtype), 12..14);
        buf.end_container(obj);
        buf.end_container(arr);
        buf.end_layer();
        buf
    }

    #[test]
    fn mdns_query_name_frequency() {
        let mut c = MdnsStatsCollector::new();
        let b1 = build_mdns_query_buf("_http._tcp.local", 12);
        c.process_packet(&pkt(&b1), None);
        let b2 = build_mdns_query_buf("_http._tcp.local", 12);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_mdns_query_buf("mydevice.local", 1);
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_queries, 3);
        assert_eq!(stats.top_query_names[0].name, "_http._tcp.local");
        assert_eq!(stats.top_query_names[0].count, 2);
    }

    #[test]
    fn mdns_service_distribution() {
        let mut c = MdnsStatsCollector::new();
        let b1 = build_mdns_query_buf("_http._tcp.local", 12);
        c.process_packet(&pkt(&b1), None);
        let b2 = build_mdns_query_buf("device.local", 1);
        c.process_packet(&pkt(&b2), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.service_distribution.len(), 1);
        assert_eq!(stats.service_distribution[0].name, "_http._tcp.local");
    }

    #[test]
    fn mdns_ignores_non_mdns_packets() {
        let mut c = MdnsStatsCollector::new();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..10);
        buf.end_layer();
        c.process_packet(&pkt(&buf), None);
        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
    }
}
