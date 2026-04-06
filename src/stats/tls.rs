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
