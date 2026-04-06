use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{field_u16, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated SCTP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct SctpStats {
    pub total_packets: u64,
    pub top_src_ports: Vec<CountEntry>,
    pub top_dst_ports: Vec<CountEntry>,
    pub top_port_pairs: Vec<CountEntry>,
}

/// Collects SCTP port statistics.
#[derive(Debug)]
pub struct SctpStatsCollector {
    src_ports: HashMap<String, u64>,
    dst_ports: HashMap<String, u64>,
    port_pairs: HashMap<String, u64>,
    total_packets: u64,
}

impl Default for SctpStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SctpStatsCollector {
    pub fn new() -> Self {
        Self {
            src_ports: HashMap::new(),
            dst_ports: HashMap::new(),
            port_pairs: HashMap::new(),
            total_packets: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(sctp) = packet.layer_by_name("SCTP") else {
            return;
        };
        let fields = packet.layer_fields(sctp);
        self.total_packets += 1;

        let src_port = field_u16(fields, "src_port");
        let dst_port = field_u16(fields, "dst_port");

        if let Some(sp) = src_port {
            *self.src_ports.entry(sp.to_string()).or_insert(0) += 1;
        }
        if let Some(dp) = dst_port {
            *self.dst_ports.entry(dp.to_string()).or_insert(0) += 1;
        }
        if let (Some(sp), Some(dp)) = (src_port, dst_port) {
            *self.port_pairs.entry(format!("{sp}:{dp}")).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> SctpStats {
        SctpStats {
            total_packets: self.total_packets,
            top_src_ports: sorted_top_n(self.src_ports.into_iter(), top_n),
            top_dst_ports: sorted_top_n(self.dst_ports.into_iter(), top_n),
            top_port_pairs: sorted_top_n(self.port_pairs.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(SctpStatsCollector, "sctp", SctpStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_sctp_buf(src_port: u16, dst_port: u16) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("SCTP", None, &[], 0..12);
        buf.push_field(
            test_desc("src_port", "Source Port"),
            FieldValue::U16(src_port),
            0..2,
        );
        buf.push_field(
            test_desc("dst_port", "Destination Port"),
            FieldValue::U16(dst_port),
            2..4,
        );
        buf.end_layer();
        buf
    }

    fn build_dns_query_buf() -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..20);
        buf.push_field(test_desc("id", "Transaction ID"), FieldValue::U16(1), 0..2);
        buf.push_field(test_desc("qr", "QR"), FieldValue::U8(0), 2..3);
        buf.end_layer();
        buf
    }

    #[test]
    fn sctp_basic_counts() {
        let mut c = SctpStatsCollector::new();
        let b1 = build_sctp_buf(3868, 3868);
        c.process_packet(&pkt(&b1), Some(1.0));
        let b2 = build_sctp_buf(3868, 3868);
        c.process_packet(&pkt(&b2), Some(2.0));
        let b3 = build_sctp_buf(2905, 3868);
        c.process_packet(&pkt(&b3), Some(3.0));

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 3);
        assert_eq!(stats.top_src_ports[0].name, "3868");
        assert_eq!(stats.top_src_ports[0].count, 2);
        assert_eq!(stats.top_dst_ports[0].name, "3868");
        assert_eq!(stats.top_dst_ports[0].count, 3);
        assert_eq!(stats.top_port_pairs[0].name, "3868:3868");
        assert_eq!(stats.top_port_pairs[0].count, 2);
        assert_eq!(stats.top_port_pairs[1].name, "2905:3868");
        assert_eq!(stats.top_port_pairs[1].count, 1);
    }

    #[test]
    fn sctp_ignores_non_sctp_packets() {
        let mut c = SctpStatsCollector::new();
        let b = build_dns_query_buf();
        c.process_packet(&pkt(&b), Some(1.0));

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
        assert!(stats.top_src_ports.is_empty());
    }

    #[test]
    fn sctp_protocol_stats_collector_key() {
        let c = SctpStatsCollector::new();
        let boxed: Box<dyn ProtocolStatsCollector> = Box::new(c);
        assert_eq!(boxed.key(), "sctp");
    }
}
