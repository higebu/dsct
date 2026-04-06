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
