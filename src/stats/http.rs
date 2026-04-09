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

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_http_request_buf(method: &'static str, uri: &'static str) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("HTTP", None, &[], 0..16);
        buf.push_field(test_desc("method", "Method"), FieldValue::Str(method), 0..4);
        buf.push_field(test_desc("uri", "URI"), FieldValue::Str(uri), 4..16);
        buf.end_layer();
        buf
    }

    fn build_http_response_buf(status_code: u16) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("HTTP", None, &[], 0..16);
        buf.push_field(
            test_desc("status_code", "Status Code"),
            FieldValue::U16(status_code),
            0..2,
        );
        buf.end_layer();
        buf
    }

    #[test]
    fn http_ignores_non_http_packets() {
        let mut c = HttpStatsCollector::new();
        let buf = DissectBuffer::new();
        c.process_packet(&pkt(&buf), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.total_responses, 0);
        assert!(stats.method_distribution.is_empty());
        assert!(stats.top_uris.is_empty());
    }

    #[test]
    fn http_counts_request_method_and_uri() {
        let mut c = HttpStatsCollector::new();
        let b1 = build_http_request_buf("GET", "/index.html");
        c.process_packet(&pkt(&b1), None);
        let b2 = build_http_request_buf("GET", "/index.html");
        c.process_packet(&pkt(&b2), None);
        let b3 = build_http_request_buf("POST", "/api/login");
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.total_responses, 0);
        assert_eq!(stats.method_distribution[0].name, "GET");
        assert_eq!(stats.method_distribution[0].count, 2);
        assert_eq!(stats.top_uris[0].name, "/index.html");
        assert_eq!(stats.top_uris[0].count, 2);
    }

    #[test]
    fn http_counts_response_status_code() {
        let mut c = HttpStatsCollector::new();
        let b1 = build_http_response_buf(200);
        c.process_packet(&pkt(&b1), None);
        let b2 = build_http_response_buf(200);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_http_response_buf(404);
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_responses, 3);
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.status_code_distribution[0].name, "200");
        assert_eq!(stats.status_code_distribution[0].count, 2);
        assert_eq!(stats.status_code_distribution[1].name, "404");
        assert_eq!(stats.status_code_distribution[1].count, 1);
    }

    #[test]
    fn http_finalize_top_n_limits_uris() {
        let mut c = HttpStatsCollector::new();
        let uris = ["/a", "/b", "/c", "/d", "/e", "/f"];
        for uri in uris {
            let b = build_http_request_buf("GET", uri);
            c.process_packet(&pkt(&b), None);
        }

        let stats = c.finalize_stats(3);
        assert_eq!(stats.top_uris.len(), 3);
        assert_eq!(stats.total_requests, 6);
    }
}
