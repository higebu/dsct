use std::collections::HashMap;
use std::net::IpAddr;

use packet_dissector_core::packet::Packet;

use super::TalkerEntry;
use super::helpers::extract_ip_addr_pair;

#[derive(Debug, Default)]
struct TrafficCount {
    packets: u64,
    bytes: u64,
}

/// Collects IP pair traffic statistics.
#[derive(Debug)]
pub struct TopTalkersCollector {
    pairs: HashMap<(IpAddr, IpAddr), TrafficCount>,
}

impl Default for TopTalkersCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl TopTalkersCollector {
    pub fn new() -> Self {
        Self {
            pairs: HashMap::new(),
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, original_length: u32) {
        let Some((src, dst)) = extract_ip_addr_pair(packet) else {
            return;
        };

        let entry = self.pairs.entry((src, dst)).or_default();
        entry.packets += 1;
        entry.bytes += original_length as u64;
    }

    pub fn finalize(self, top_n: usize) -> Vec<TalkerEntry> {
        let mut entries: Vec<TalkerEntry> = self
            .pairs
            .into_iter()
            .map(|((src, dst), tc)| TalkerEntry {
                src: src.to_string(),
                dst: dst.to_string(),
                packets: tc.packets,
                bytes: tc.bytes,
            })
            .collect();
        entries.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| b.packets.cmp(&a.packets))
        });
        entries.truncate(top_n);
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{build_ipv4_buf, pkt};
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    #[test]
    fn top_talkers_basic() {
        let mut c = TopTalkersCollector::new();
        let p1 = build_ipv4_buf([10, 0, 0, 1], [10, 0, 0, 2]);
        c.process_packet(&pkt(&p1), 100);
        c.process_packet(&pkt(&p1), 200);
        let p2 = build_ipv4_buf([10, 0, 0, 3], [10, 0, 0, 4]);
        c.process_packet(&pkt(&p2), 500);

        let result = c.finalize(10);
        assert_eq!(result.len(), 2);
        // Sorted by bytes descending
        assert_eq!(result[0].src, "10.0.0.3");
        assert_eq!(result[0].dst, "10.0.0.4");
        assert_eq!(result[0].bytes, 500);
        assert_eq!(result[0].packets, 1);
        assert_eq!(result[1].src, "10.0.0.1");
        assert_eq!(result[1].dst, "10.0.0.2");
        assert_eq!(result[1].bytes, 300);
        assert_eq!(result[1].packets, 2);
    }

    #[test]
    fn top_talkers_ipv6() {
        let mut c = TopTalkersCollector::new();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("IPv6", None, &[], 0..40);
        buf.push_field(
            test_desc("src", "Source"),
            FieldValue::Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            8..24,
        );
        buf.push_field(
            test_desc("dst", "Destination"),
            FieldValue::Ipv6Addr([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]),
            24..40,
        );
        buf.end_layer();
        c.process_packet(&pkt(&buf), 100);
        let result = c.finalize(10);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src, "2001:db8::1");
        assert_eq!(result[0].dst, "2001:db8::2");
    }

    #[test]
    fn top_talkers_empty() {
        let c = TopTalkersCollector::new();
        let result = c.finalize(10);
        assert!(result.is_empty());
    }

    #[test]
    fn top_talkers_no_ip_layer() {
        let mut c = TopTalkersCollector::new();
        let buf = DissectBuffer::new(); // No layers
        c.process_packet(&pkt(&buf), 100);
        let result = c.finalize(10);
        assert!(result.is_empty());
    }
}
