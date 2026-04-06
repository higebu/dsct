use std::collections::HashMap;
use std::net::IpAddr;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;

use super::helpers::{
    compute_response_time_stats, extract_ip_addr_pair, extract_transport, field_u8, field_u16,
    find_field, sorted_top_n,
};
use super::{CountEntry, ProtocolStatsCollector, ResponseTimeStats};
use crate::field_format::format_field_to_string;
use serde::Serialize;

/// Composite key for tracking pending DNS queries:
/// (src_ip, dst_ip, src_port, dst_port, transport, transaction_id).
type DnsPendingKey = (IpAddr, IpAddr, u16, u16, &'static str, u16);

/// Maximum age (seconds) for pending DNS query entries before eviction.
const DNS_PENDING_TIMEOUT_SECS: f64 = 30.0;

// ---------------------------------------------------------------------------
// DNS query type / rcode display names (delegates to packet-dissector-dns)
// ---------------------------------------------------------------------------

#[cfg(feature = "dns")]
fn dns_type_display(qtype: u16) -> String {
    packet_dissector::dissectors::dns::dns_type_name(qtype)
        .map(String::from)
        .unwrap_or_else(|| format!("TYPE{qtype}"))
}

#[cfg(not(feature = "dns"))]
fn dns_type_display(qtype: u16) -> String {
    format!("TYPE{qtype}")
}

#[cfg(feature = "dns")]
fn dns_rcode_display(rcode: u8) -> String {
    packet_dissector::dissectors::dns::dns_rcode_name(rcode)
        .map(String::from)
        .unwrap_or_else(|| format!("RCODE{rcode}"))
}

#[cfg(not(feature = "dns"))]
fn dns_rcode_display(rcode: u8) -> String {
    format!("RCODE{rcode}")
}

/// Build a composite flow key for a DNS query packet.
fn build_dns_flow_key(packet: &Packet, id: u16) -> Option<DnsPendingKey> {
    let (src, dst) = extract_ip_addr_pair(packet)?;
    let (transport, src_port, dst_port) = extract_transport(packet)?;
    Some((src, dst, src_port, dst_port, transport, id))
}

/// Build a composite flow key for a DNS response packet, reversing src/dst
/// so the key matches the original query direction.
fn build_dns_flow_key_reversed(packet: &Packet, id: u16) -> Option<DnsPendingKey> {
    let (src, dst) = extract_ip_addr_pair(packet)?;
    let (transport, src_port, dst_port) = extract_transport(packet)?;
    // Response: src/dst are reversed relative to the query.
    Some((dst, src, dst_port, src_port, transport, id))
}

/// Aggregated DNS statistics.
#[derive(Debug, Clone, Serialize)]
pub struct DnsStats {
    pub total_queries: u64,
    pub total_responses: u64,
    pub top_query_names: Vec<CountEntry>,
    pub query_type_distribution: Vec<CountEntry>,
    pub rcode_distribution: Vec<CountEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_time: Option<ResponseTimeStats>,
}

/// Collects DNS query/response statistics.
#[derive(Debug)]
pub struct DnsStatsCollector {
    query_names: HashMap<String, u64>,
    query_types: HashMap<u16, u64>,
    rcodes: HashMap<u8, u64>,
    /// Maps (src_ip, dst_ip, src_port, dst_port, transport, DNS transaction ID)
    /// → timestamp (secs as f64) for response time.
    pending_queries: HashMap<DnsPendingKey, f64>,
    response_times: Vec<f64>,
    total_queries: u64,
    total_responses: u64,
}

impl Default for DnsStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsStatsCollector {
    pub fn new() -> Self {
        Self {
            query_names: HashMap::new(),
            query_types: HashMap::new(),
            rcodes: HashMap::new(),
            pending_queries: HashMap::new(),
            response_times: Vec::new(),
            total_queries: 0,
            total_responses: 0,
        }
    }

    /// Remove pending queries older than [`DNS_PENDING_TIMEOUT_SECS`].
    ///
    /// Invariant: this method is only called after incrementing
    /// `total_queries` or `total_responses`, so `total` is always >= 1.
    /// This guarantees `is_multiple_of(1000)` never receives 0.
    fn evict_stale(&mut self, now: f64) {
        let total = self.total_queries + self.total_responses;
        debug_assert!(total > 0, "evict_stale called with zero total count");
        if total.is_multiple_of(1000) {
            self.pending_queries
                .retain(|_, ts| now - *ts < DNS_PENDING_TIMEOUT_SECS);
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, timestamp: Option<f64>) {
        let Some(dns) = packet.layer_by_name("DNS") else {
            return;
        };
        let dns_fields = packet.layer_fields(dns);

        let Some(qr) = field_u8(dns_fields, "qr") else {
            return;
        };
        let Some(id) = field_u16(dns_fields, "id") else {
            return;
        };

        if qr == 0 {
            // Query
            self.total_queries += 1;

            // Only track pending queries for RTT when timestamps are available.
            if let Some(ts) = timestamp {
                if let Some(key) = build_dns_flow_key(packet, id) {
                    // Preserve the first-seen query timestamp for this key to avoid
                    // overwriting it when multiple queries share the same ID/flow.
                    self.pending_queries.entry(key).or_insert(ts);
                }

                // Evict stale pending queries to bound memory usage.
                self.evict_stale(ts);
            }

            if let Some(questions_field) = find_field(dns_fields, "questions")
                && let FieldValue::Array(ref range) = questions_field.value
            {
                for elem in packet.nested_fields(range) {
                    if let FieldValue::Object(ref obj_range) = elem.value {
                        let fields = packet.nested_fields(obj_range);
                        for f in fields {
                            if f.name() == "name" {
                                let name_str: Option<String> = match &f.value {
                                    FieldValue::Str(s) => Some((*s).to_string()),
                                    _ => format_field_to_string(
                                        f,
                                        packet.data(),
                                        dns,
                                        packet.buf().scratch(),
                                    ),
                                };
                                if let Some(name) = name_str {
                                    *self.query_names.entry(name).or_insert(0) += 1;
                                }
                            }
                            if f.name() == "type"
                                && let FieldValue::U16(qtype) = &f.value
                            {
                                *self.query_types.entry(*qtype).or_insert(0) += 1;
                            }
                        }
                    }
                }
            }
        } else {
            // Response
            self.total_responses += 1;

            if let Some(f) = find_field(dns_fields, "rcode")
                && let FieldValue::U8(rcode) = &f.value
            {
                *self.rcodes.entry(*rcode).or_insert(0) += 1;
            }

            // RTT matching requires timestamps.
            if let Some(ts) = timestamp {
                // Evict stale pending queries during response processing too,
                // so captures dominated by responses still get periodic cleanup.
                self.evict_stale(ts);

                // For response matching, reverse src/dst so the key matches the
                // original query direction.
                if let Some(key) = build_dns_flow_key_reversed(packet, id)
                    && let Some(query_ts) = self.pending_queries.remove(&key)
                {
                    let rtt = ts - query_ts;
                    if rtt >= 0.0 {
                        self.response_times.push(rtt);
                    }
                }
            }
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> DnsStats {
        DnsStats {
            total_queries: self.total_queries,
            total_responses: self.total_responses,
            top_query_names: sorted_top_n(self.query_names.into_iter(), top_n),
            query_type_distribution: sorted_top_n(
                self.query_types
                    .into_iter()
                    .map(|(k, v)| (dns_type_display(k), v)),
                top_n,
            ),
            rcode_distribution: sorted_top_n(
                self.rcodes
                    .into_iter()
                    .map(|(k, v)| (dns_rcode_display(k), v)),
                top_n,
            ),
            response_time: compute_response_time_stats(self.response_times),
        }
    }
}

super::impl_protocol_stats_collector!(DnsStatsCollector, "dns", DnsStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{add_ipv4_udp, build_dns_query_buf, pkt};
    use super::*;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    /// Helper: build a DNS response DissectBuffer with given id and rcode.
    fn build_dns_response_buf(id: u16, rcode: u8) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..20);
        buf.push_field(test_desc("id", "Transaction ID"), FieldValue::U16(id), 0..2);
        buf.push_field(test_desc("qr", "QR"), FieldValue::U8(1), 2..3);
        buf.push_field(
            test_desc("rcode", "Response Code"),
            FieldValue::U8(rcode),
            3..4,
        );
        buf.end_layer();
        buf
    }

    #[test]
    fn dns_query_name_frequency() {
        let mut c = DnsStatsCollector::new();
        let b1 = build_dns_query_buf(1, "example.com", 1);
        c.process_packet(&pkt(&b1), Some(1.0));
        let b2 = build_dns_query_buf(2, "example.com", 1);
        c.process_packet(&pkt(&b2), Some(2.0));
        let b3 = build_dns_query_buf(3, "test.org", 28);
        c.process_packet(&pkt(&b3), Some(3.0));

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_queries, 3);
        assert_eq!(stats.top_query_names[0].name, "example.com");
        assert_eq!(stats.top_query_names[0].count, 2);
        assert_eq!(stats.top_query_names[1].name, "test.org");
        assert_eq!(stats.top_query_names[1].count, 1);
    }

    #[test]
    fn dns_query_type_distribution() {
        let mut c = DnsStatsCollector::new();
        let b1 = build_dns_query_buf(1, "a.com", 1);
        c.process_packet(&pkt(&b1), Some(1.0));
        let b2 = build_dns_query_buf(2, "b.com", 1);
        c.process_packet(&pkt(&b2), Some(2.0));
        let b3 = build_dns_query_buf(3, "c.com", 28);
        c.process_packet(&pkt(&b3), Some(3.0));

        let stats = c.finalize_stats(10);
        assert_eq!(stats.query_type_distribution[0].name, "A");
        assert_eq!(stats.query_type_distribution[0].count, 2);
        assert_eq!(stats.query_type_distribution[1].name, "AAAA");
        assert_eq!(stats.query_type_distribution[1].count, 1);
    }

    #[test]
    fn dns_rcode_distribution() {
        let mut c = DnsStatsCollector::new();
        let b1 = build_dns_response_buf(1, 0);
        c.process_packet(&pkt(&b1), Some(1.0));
        let b2 = build_dns_response_buf(2, 0);
        c.process_packet(&pkt(&b2), Some(2.0));
        let b3 = build_dns_response_buf(3, 3);
        c.process_packet(&pkt(&b3), Some(3.0));

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_responses, 3);
        assert_eq!(stats.rcode_distribution[0].name, "NOERROR");
        assert_eq!(stats.rcode_distribution[0].count, 2);
        assert_eq!(stats.rcode_distribution[1].name, "NXDOMAIN");
        assert_eq!(stats.rcode_distribution[1].count, 1);
    }

    #[test]
    fn dns_response_time_matching() {
        let client = [10, 0, 0, 1];
        let server = [10, 0, 0, 2];
        let mut c = DnsStatsCollector::new();

        // Query at t=1.0, response at t=1.5 → rtt=0.5
        let mut q1 = build_dns_query_buf(100, "example.com", 1);
        add_ipv4_udp(&mut q1, client, server, 12345, 53);
        c.process_packet(&pkt(&q1), Some(1.0));
        let mut r1 = build_dns_response_buf(100, 0);
        add_ipv4_udp(&mut r1, server, client, 53, 12345);
        c.process_packet(&pkt(&r1), Some(1.5));

        // Query at t=2.0, response at t=2.1 → rtt=0.1
        let mut q2 = build_dns_query_buf(200, "test.org", 1);
        add_ipv4_udp(&mut q2, client, server, 12346, 53);
        c.process_packet(&pkt(&q2), Some(2.0));
        let mut r2 = build_dns_response_buf(200, 0);
        add_ipv4_udp(&mut r2, server, client, 53, 12346);
        c.process_packet(&pkt(&r2), Some(2.1));

        let stats = c.finalize_stats(10);
        let rt = stats.response_time.expect("should have response times");
        assert_eq!(rt.count, 2);
        assert!((rt.min - 0.1).abs() < 1e-9);
        assert!((rt.max - 0.5).abs() < 1e-9);
        assert!((rt.mean - 0.3).abs() < 1e-9);
    }

    #[test]
    fn dns_query_only_no_response_time() {
        let mut c = DnsStatsCollector::new();
        let b = build_dns_query_buf(1, "example.com", 1);
        c.process_packet(&pkt(&b), Some(1.0));

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_queries, 1);
        assert_eq!(stats.total_responses, 0);
        assert!(stats.response_time.is_none());
    }

    #[test]
    fn dns_empty_collector() {
        let c = DnsStatsCollector::new();
        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_queries, 0);
        assert_eq!(stats.total_responses, 0);
        assert!(stats.top_query_names.is_empty());
        assert!(stats.response_time.is_none());
    }

    #[test]
    fn dns_top_n_limits_results() {
        let mut c = DnsStatsCollector::new();
        for i in 0..20 {
            let name = format!("host{i}.example.com");
            let b = build_dns_query_buf(i as u16, name.leak(), 1);
            c.process_packet(&pkt(&b), Some(i as f64));
        }
        let stats = c.finalize_stats(5);
        assert_eq!(stats.top_query_names.len(), 5);
    }

    #[test]
    fn dns_or_insert_preserves_first_query_timestamp() {
        let client = [10, 0, 0, 1];
        let server = [10, 0, 0, 2];
        let mut c = DnsStatsCollector::new();

        // First query at t=1.0
        let mut q1 = build_dns_query_buf(100, "example.com", 1);
        add_ipv4_udp(&mut q1, client, server, 12345, 53);
        c.process_packet(&pkt(&q1), Some(1.0));

        // Retransmit same query at t=2.0 (same flow key)
        let mut q2 = build_dns_query_buf(100, "example.com", 1);
        add_ipv4_udp(&mut q2, client, server, 12345, 53);
        c.process_packet(&pkt(&q2), Some(2.0));

        // Response at t=1.5 → RTT should be 0.5 (from first query), not -0.5
        let mut r = build_dns_response_buf(100, 0);
        add_ipv4_udp(&mut r, server, client, 53, 12345);
        c.process_packet(&pkt(&r), Some(1.5));

        let stats = c.finalize_stats(10);
        let rt = stats.response_time.expect("should have response times");
        assert_eq!(rt.count, 1);
        assert!((rt.min - 0.5).abs() < 1e-9);
    }
}
