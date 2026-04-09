use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{field_str, field_u8, field_u16, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated SIP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct SipStats {
    pub total_requests: u64,
    pub total_responses: u64,
    pub method_distribution: Vec<CountEntry>,
    pub status_code_distribution: Vec<CountEntry>,
}

/// Collects SIP request/response statistics.
#[derive(Debug)]
pub struct SipStatsCollector {
    methods: HashMap<String, u64>,
    status_codes: HashMap<u16, u64>,
    total_requests: u64,
    total_responses: u64,
}

impl Default for SipStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SipStatsCollector {
    pub fn new() -> Self {
        Self {
            methods: HashMap::new(),
            status_codes: HashMap::new(),
            total_requests: 0,
            total_responses: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(sip) = packet.layer_by_name("SIP") else {
            return;
        };
        let fields = packet.layer_fields(sip);

        let is_response = field_u8(fields, "is_response").unwrap_or(0);
        if is_response == 1 {
            self.total_responses += 1;
            if let Some(code) = field_u16(fields, "status_code") {
                *self.status_codes.entry(code).or_insert(0) += 1;
            }
        } else {
            self.total_requests += 1;
            if let Some(method) = field_str(fields, "method") {
                if let Some(count) = self.methods.get_mut(method) {
                    *count += 1;
                } else {
                    self.methods.insert(method.to_string(), 1);
                }
            }
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> SipStats {
        SipStats {
            total_requests: self.total_requests,
            total_responses: self.total_responses,
            method_distribution: sorted_top_n(self.methods.into_iter(), top_n),
            status_code_distribution: sorted_top_n(
                self.status_codes
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v)),
                top_n,
            ),
        }
    }
}

super::impl_protocol_stats_collector!(SipStatsCollector, "sip", SipStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_sip_request_buf(method: &'static str) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("SIP", None, &[], 0..16);
        buf.push_field(
            test_desc("is_response", "Is Response"),
            FieldValue::U8(0),
            0..1,
        );
        buf.push_field(test_desc("method", "Method"), FieldValue::Str(method), 1..8);
        buf.end_layer();
        buf
    }

    fn build_sip_response_buf(status_code: u16) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("SIP", None, &[], 0..16);
        buf.push_field(
            test_desc("is_response", "Is Response"),
            FieldValue::U8(1),
            0..1,
        );
        buf.push_field(
            test_desc("status_code", "Status Code"),
            FieldValue::U16(status_code),
            1..3,
        );
        buf.end_layer();
        buf
    }

    #[test]
    fn sip_ignores_non_sip_packets() {
        let mut c = SipStatsCollector::new();
        let buf = DissectBuffer::new();
        c.process_packet(&pkt(&buf), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.total_responses, 0);
        assert!(stats.method_distribution.is_empty());
        assert!(stats.status_code_distribution.is_empty());
    }

    #[test]
    fn sip_counts_request_with_method() {
        let mut c = SipStatsCollector::new();
        let b1 = build_sip_request_buf("INVITE");
        c.process_packet(&pkt(&b1), None);
        let b2 = build_sip_request_buf("INVITE");
        c.process_packet(&pkt(&b2), None);
        let b3 = build_sip_request_buf("BYE");
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.total_responses, 0);
        assert_eq!(stats.method_distribution[0].name, "INVITE");
        assert_eq!(stats.method_distribution[0].count, 2);
    }

    #[test]
    fn sip_counts_response_with_status_code() {
        let mut c = SipStatsCollector::new();
        let b1 = build_sip_response_buf(200);
        c.process_packet(&pkt(&b1), None);
        let b2 = build_sip_response_buf(200);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_sip_response_buf(486);
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_responses, 3);
        assert_eq!(stats.total_requests, 0);
        assert_eq!(stats.status_code_distribution[0].name, "200");
        assert_eq!(stats.status_code_distribution[0].count, 2);
    }

    #[test]
    fn sip_finalize_top_n_limits_methods() {
        let mut c = SipStatsCollector::new();
        let methods = ["INVITE", "BYE", "REGISTER", "OPTIONS", "ACK"];
        for m in methods {
            let b = build_sip_request_buf(m);
            c.process_packet(&pkt(&b), None);
        }

        let stats = c.finalize_stats(2);
        assert_eq!(stats.method_distribution.len(), 2);
        assert_eq!(stats.total_requests, 5);
    }
}
