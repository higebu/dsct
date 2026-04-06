use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{field_str, field_u16, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated HTTP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct HttpStats {
    pub total_requests: u64,
    pub total_responses: u64,
    pub method_distribution: Vec<CountEntry>,
    pub status_code_distribution: Vec<CountEntry>,
    pub top_uris: Vec<CountEntry>,
}

/// Collects HTTP request/response statistics.
#[derive(Debug)]
pub struct HttpStatsCollector {
    methods: HashMap<String, u64>,
    status_codes: HashMap<u16, u64>,
    uris: HashMap<String, u64>,
    total_requests: u64,
    total_responses: u64,
}

impl Default for HttpStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpStatsCollector {
    pub fn new() -> Self {
        Self {
            methods: HashMap::new(),
            status_codes: HashMap::new(),
            uris: HashMap::new(),
            total_requests: 0,
            total_responses: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(http) = packet.layer_by_name("HTTP") else {
            return;
        };
        let fields = packet.layer_fields(http);

        // Detect request vs response via presence of `method` or `status_code`.
        if let Some(method) = field_str(fields, "method") {
            self.total_requests += 1;
            if let Some(count) = self.methods.get_mut(method) {
                *count += 1;
            } else {
                self.methods.insert(method.to_string(), 1);
            }

            if let Some(uri) = field_str(fields, "uri") {
                *self.uris.entry(uri.to_string()).or_insert(0) += 1;
            }
        } else if let Some(code) = field_u16(fields, "status_code") {
            self.total_responses += 1;
            *self.status_codes.entry(code).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> HttpStats {
        HttpStats {
            total_requests: self.total_requests,
            total_responses: self.total_responses,
            method_distribution: sorted_top_n(self.methods.into_iter(), top_n),
            status_code_distribution: sorted_top_n(
                self.status_codes
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v)),
                top_n,
            ),
            top_uris: sorted_top_n(self.uris.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(HttpStatsCollector, "http", HttpStats);
