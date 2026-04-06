use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::TcpStreamEntry;
use super::helpers::{extract_ip_pair, field_u16, field_u32};

#[derive(Debug)]
struct StreamAccum {
    packets: u64,
    bytes: u64,
    first_ts: Option<f64>,
    last_ts: Option<f64>,
    src: String,
    src_port: u16,
    dst: String,
    dst_port: u16,
}

/// Collects per-stream TCP statistics.
#[derive(Debug)]
pub struct TcpStreamCollector {
    streams: HashMap<u32, StreamAccum>,
}

impl Default for TcpStreamCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpStreamCollector {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
        }
    }

    pub fn process_packet(
        &mut self,
        packet: &Packet,
        original_length: u32,
        timestamp: Option<f64>,
    ) {
        let Some(tcp) = packet.layer_by_name("TCP") else {
            return;
        };
        let tcp_fields = packet.layer_fields(tcp);

        let Some(stream_id) = field_u32(tcp_fields, "stream_id") else {
            return;
        };

        let entry = self.streams.entry(stream_id);
        match entry {
            std::collections::hash_map::Entry::Occupied(mut e) => {
                let accum = e.get_mut();
                accum.packets += 1;
                accum.bytes += original_length as u64;
                if let Some(ts) = timestamp {
                    match accum.first_ts {
                        Some(cur) if ts < cur => accum.first_ts = Some(ts),
                        None => accum.first_ts = Some(ts),
                        _ => {}
                    }
                    match accum.last_ts {
                        Some(cur) if ts > cur => accum.last_ts = Some(ts),
                        None => accum.last_ts = Some(ts),
                        _ => {}
                    }
                }
                // Update endpoints if the first packet lacked IP/port info.
                if accum.src == "unknown"
                    && let Some((src, dst)) = extract_ip_pair(packet)
                {
                    accum.src = src;
                    accum.dst = dst;
                }
                if accum.src_port == 0 {
                    if let Some(port) = field_u16(tcp_fields, "src_port") {
                        accum.src_port = port;
                    }
                    if let Some(port) = field_u16(tcp_fields, "dst_port") {
                        accum.dst_port = port;
                    }
                }
            }
            std::collections::hash_map::Entry::Vacant(e) => {
                let src_port = field_u16(tcp_fields, "src_port").unwrap_or(0);
                let dst_port = field_u16(tcp_fields, "dst_port").unwrap_or(0);
                let (src, dst) = extract_ip_pair(packet)
                    .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()));
                e.insert(StreamAccum {
                    packets: 1,
                    bytes: original_length as u64,
                    first_ts: timestamp,
                    last_ts: timestamp,
                    src,
                    src_port,
                    dst,
                    dst_port,
                });
            }
        }
    }

    pub fn finalize(self, top_n: usize) -> Vec<TcpStreamEntry> {
        let mut entries: Vec<TcpStreamEntry> = self
            .streams
            .into_iter()
            .map(|(sid, a)| {
                let duration = match (a.first_ts, a.last_ts) {
                    (Some(first), Some(last)) => last - first,
                    _ => 0.0,
                };
                TcpStreamEntry {
                    stream_id: sid,
                    src: a.src,
                    src_port: a.src_port,
                    dst: a.dst,
                    dst_port: a.dst_port,
                    packets: a.packets,
                    bytes: a.bytes,
                    duration_secs: (duration * 1_000.0).round() / 1_000.0,
                }
            })
            .collect();
        entries.sort_by(|a, b| {
            b.bytes
                .cmp(&a.bytes)
                .then_with(|| a.stream_id.cmp(&b.stream_id))
        });
        entries.truncate(top_n);
        entries
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::{add_tcp_layer, build_ipv4_buf, pkt};
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    #[test]
    fn tcp_stream_basic() {
        let mut c = TcpStreamCollector::new();
        let mut p1 = build_ipv4_buf([10, 0, 0, 1], [10, 0, 0, 2]);
        add_tcp_layer(&mut p1, 12345, 80, 0);
        c.process_packet(&pkt(&p1), 100, Some(1.0));
        c.process_packet(&pkt(&p1), 200, Some(2.0));
        c.process_packet(&pkt(&p1), 150, Some(3.0));

        let result = c.finalize(10);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].stream_id, 0);
        assert_eq!(result[0].packets, 3);
        assert_eq!(result[0].bytes, 450);
        assert_eq!(result[0].src, "10.0.0.1");
        assert_eq!(result[0].src_port, 12345);
        assert_eq!(result[0].dst, "10.0.0.2");
        assert_eq!(result[0].dst_port, 80);
        assert!((result[0].duration_secs - 2.0).abs() < 1e-9);
    }

    #[test]
    fn tcp_stream_multiple_streams() {
        let mut c = TcpStreamCollector::new();
        let mut p1 = build_ipv4_buf([10, 0, 0, 1], [10, 0, 0, 2]);
        add_tcp_layer(&mut p1, 12345, 80, 0);
        c.process_packet(&pkt(&p1), 100, Some(1.0));

        let mut p2 = build_ipv4_buf([10, 0, 0, 3], [10, 0, 0, 4]);
        add_tcp_layer(&mut p2, 54321, 443, 1);
        c.process_packet(&pkt(&p2), 500, Some(1.0));

        let result = c.finalize(10);
        assert_eq!(result.len(), 2);
        // Sorted by bytes descending
        assert_eq!(result[0].stream_id, 1);
        assert_eq!(result[0].bytes, 500);
        assert_eq!(result[1].stream_id, 0);
        assert_eq!(result[1].bytes, 100);
    }

    #[test]
    fn tcp_stream_empty() {
        let c = TcpStreamCollector::new();
        let result = c.finalize(10);
        assert!(result.is_empty());
    }

    #[test]
    fn tcp_stream_no_stream_id_skipped() {
        let mut c = TcpStreamCollector::new();
        let mut buf = DissectBuffer::new();
        // TCP layer without stream_id
        buf.begin_layer("TCP", None, &[], 0..20);
        buf.push_field(
            test_desc("src_port", "Source Port"),
            FieldValue::U16(80),
            0..2,
        );
        buf.push_field(
            test_desc("dst_port", "Destination Port"),
            FieldValue::U16(443),
            2..4,
        );
        buf.end_layer();
        c.process_packet(&pkt(&buf), 100, Some(1.0));
        let result = c.finalize(10);
        assert!(result.is_empty());
    }

    #[test]
    fn tcp_stream_updates_unknown_endpoints() {
        let mut c = TcpStreamCollector::new();

        // First packet: TCP layer with stream_id but no IP layer
        let mut p1 = DissectBuffer::new();
        add_tcp_layer(&mut p1, 0, 0, 42);
        c.process_packet(&pkt(&p1), 100, Some(1.0));

        // Second packet: with IP layer and ports
        let mut p2 = build_ipv4_buf([10, 0, 0, 1], [10, 0, 0, 2]);
        add_tcp_layer(&mut p2, 12345, 80, 42);
        c.process_packet(&pkt(&p2), 200, Some(2.0));

        let result = c.finalize(10);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].src, "10.0.0.1");
        assert_eq!(result[0].dst, "10.0.0.2");
        assert_eq!(result[0].src_port, 12345);
        assert_eq!(result[0].dst_port, 80);
    }
}
