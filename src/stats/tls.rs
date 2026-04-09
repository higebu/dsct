use std::collections::HashMap;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, field_value_to_string, find_field, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated TLS statistics.
#[derive(Debug, Clone, Serialize)]
pub struct TlsStats {
    pub total_records: u64,
    pub content_type_distribution: Vec<CountEntry>,
    pub version_distribution: Vec<CountEntry>,
    pub top_server_names: Vec<CountEntry>,
}

/// Collects TLS record statistics.
#[derive(Debug)]
pub struct TlsStatsCollector {
    content_types: HashMap<String, u64>,
    versions: HashMap<String, u64>,
    server_names: HashMap<String, u64>,
    total_records: u64,
}

impl Default for TlsStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsStatsCollector {
    pub fn new() -> Self {
        Self {
            content_types: HashMap::new(),
            versions: HashMap::new(),
            server_names: HashMap::new(),
            total_records: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(tls) = packet.layer_by_name("TLS") else {
            return;
        };
        let fields = packet.layer_fields(tls);
        self.total_records += 1;

        if let Some(name) = display_name(packet, tls, fields, "content_type_name", "content_type") {
            *self.content_types.entry(name).or_insert(0) += 1;
        }
        if let Some(name) = display_name(packet, tls, fields, "version_name", "version") {
            *self.versions.entry(name).or_insert(0) += 1;
        }

        // Extract SNI from extensions array.
        if let Some(ext_field) = find_field(fields, "extensions")
            && let FieldValue::Array(ref range) = ext_field.value
        {
            for elem in packet.nested_fields(range) {
                if let FieldValue::Object(ref obj_range) = elem.value {
                    let ext_fields = packet.nested_fields(obj_range);
                    for f in ext_fields {
                        if f.name() == "server_name" {
                            let name = field_value_to_string(&f.value);
                            *self.server_names.entry(name).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> TlsStats {
        TlsStats {
            total_records: self.total_records,
            content_type_distribution: sorted_top_n(self.content_types.into_iter(), top_n),
            version_distribution: sorted_top_n(self.versions.into_iter(), top_n),
            top_server_names: sorted_top_n(self.server_names.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(TlsStatsCollector, "tls", TlsStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_tls_buf(
        content_type: u8,
        version: u16,
        sni: Option<&'static str>,
    ) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("TLS", None, &[], 0..40);
        buf.push_field(
            test_desc("content_type", "Content Type"),
            FieldValue::U8(content_type),
            0..1,
        );
        buf.push_field(
            test_desc("version", "Version"),
            FieldValue::U16(version),
            1..3,
        );

        if let Some(name) = sni {
            let arr = buf.begin_container(
                test_desc("extensions", "Extensions"),
                FieldValue::Array(0..0),
                5..40,
            );
            let obj = buf.begin_container(
                test_desc("ext", "Extension"),
                FieldValue::Object(0..0),
                5..40,
            );
            buf.push_field(
                test_desc("server_name", "Server Name"),
                FieldValue::Str(name),
                5..40,
            );
            buf.end_container(obj);
            buf.end_container(arr);
        }

        buf.end_layer();
        buf
    }

    #[test]
    fn tls_ignores_non_tls_packets() {
        let mut c = TlsStatsCollector::new();
        let buf = DissectBuffer::new();
        c.process_packet(&pkt(&buf), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_records, 0);
        assert!(stats.content_type_distribution.is_empty());
        assert!(stats.version_distribution.is_empty());
        assert!(stats.top_server_names.is_empty());
    }

    #[test]
    fn tls_counts_records_and_distributions() {
        let mut c = TlsStatsCollector::new();
        let b1 = build_tls_buf(23, 0x0303, None); // application_data, TLS 1.2
        c.process_packet(&pkt(&b1), None);
        let b2 = build_tls_buf(23, 0x0303, None);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_tls_buf(22, 0x0304, None); // handshake, TLS 1.3
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_records, 3);
        assert_eq!(stats.content_type_distribution[0].name, "23");
        assert_eq!(stats.content_type_distribution[0].count, 2);
        assert_eq!(stats.version_distribution[0].name, "771");
        assert_eq!(stats.version_distribution[0].count, 2);
    }

    #[test]
    fn tls_extracts_sni_from_extensions() {
        let mut c = TlsStatsCollector::new();
        let b1 = build_tls_buf(22, 0x0303, Some("example.com"));
        c.process_packet(&pkt(&b1), None);
        let b2 = build_tls_buf(22, 0x0303, Some("example.com"));
        c.process_packet(&pkt(&b2), None);
        let b3 = build_tls_buf(22, 0x0303, Some("other.test"));
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.top_server_names[0].name, "example.com");
        assert_eq!(stats.top_server_names[0].count, 2);
        assert_eq!(stats.top_server_names[1].name, "other.test");
        assert_eq!(stats.top_server_names[1].count, 1);
    }

    #[test]
    fn tls_finalize_top_n_limits_server_names() {
        let mut c = TlsStatsCollector::new();
        let names = ["a.test", "b.test", "c.test", "d.test", "e.test"];
        for n in names {
            let b = build_tls_buf(22, 0x0303, Some(n));
            c.process_packet(&pkt(&b), None);
        }

        let stats = c.finalize_stats(2);
        assert_eq!(stats.top_server_names.len(), 2);
        assert_eq!(stats.total_records, 5);
    }
}
