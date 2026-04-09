use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{field_u8, field_u32, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated RTP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct RtpStats {
    pub total_packets: u64,
    pub payload_type_distribution: Vec<CountEntry>,
    pub ssrc_distribution: Vec<CountEntry>,
}

/// Collects RTP packet statistics.
#[derive(Debug)]
pub struct RtpStatsCollector {
    payload_types: HashMap<u8, u64>,
    ssrcs: HashMap<u32, u64>,
    total_packets: u64,
}

impl Default for RtpStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl RtpStatsCollector {
    pub fn new() -> Self {
        Self {
            payload_types: HashMap::new(),
            ssrcs: HashMap::new(),
            total_packets: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(rtp) = packet.layer_by_name("RTP") else {
            return;
        };
        let fields = packet.layer_fields(rtp);
        self.total_packets += 1;

        if let Some(pt) = field_u8(fields, "payload_type") {
            *self.payload_types.entry(pt).or_insert(0) += 1;
        }
        if let Some(ssrc) = field_u32(fields, "ssrc") {
            *self.ssrcs.entry(ssrc).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> RtpStats {
        RtpStats {
            total_packets: self.total_packets,
            payload_type_distribution: sorted_top_n(
                self.payload_types
                    .into_iter()
                    .map(|(k, v)| (rtp_payload_type_name(k), v)),
                top_n,
            ),
            ssrc_distribution: sorted_top_n(
                self.ssrcs
                    .into_iter()
                    .map(|(k, v)| (format!("0x{k:08X}"), v)),
                top_n,
            ),
        }
    }
}

super::impl_protocol_stats_collector!(RtpStatsCollector, "rtp", RtpStats);

fn rtp_payload_type_name(pt: u8) -> String {
    match pt {
        0 => "PCMU".to_string(),
        3 => "GSM".to_string(),
        4 => "G723".to_string(),
        8 => "PCMA".to_string(),
        9 => "G722".to_string(),
        18 => "G729".to_string(),
        26 => "JPEG".to_string(),
        31 => "H261".to_string(),
        32 => "MPV".to_string(),
        33 => "MP2T".to_string(),
        34 => "H263".to_string(),
        96..=127 => format!("Dynamic({pt})"),
        _ => format!("PT({pt})"),
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_rtp_buf(payload_type: u8, ssrc: u32) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("RTP", None, &[], 0..12);
        buf.push_field(
            test_desc("payload_type", "Payload Type"),
            FieldValue::U8(payload_type),
            1..2,
        );
        buf.push_field(test_desc("ssrc", "SSRC"), FieldValue::U32(ssrc), 8..12);
        buf.end_layer();
        buf
    }

    #[test]
    fn rtp_ignores_non_rtp_packets() {
        let mut c = RtpStatsCollector::new();
        let buf = DissectBuffer::new();
        c.process_packet(&pkt(&buf), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 0);
        assert!(stats.payload_type_distribution.is_empty());
        assert!(stats.ssrc_distribution.is_empty());
    }

    #[test]
    fn rtp_counts_payload_types_with_well_known_name() {
        let mut c = RtpStatsCollector::new();
        let b1 = build_rtp_buf(0, 0x12345678); // PCMU
        c.process_packet(&pkt(&b1), None);
        let b2 = build_rtp_buf(0, 0x12345678);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_rtp_buf(8, 0x12345678); // PCMA
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_packets, 3);
        assert_eq!(stats.payload_type_distribution[0].name, "PCMU");
        assert_eq!(stats.payload_type_distribution[0].count, 2);
        assert_eq!(stats.payload_type_distribution[1].name, "PCMA");
        assert_eq!(stats.payload_type_distribution[1].count, 1);
    }

    #[test]
    fn rtp_dynamic_payload_type_format() {
        let mut c = RtpStatsCollector::new();
        let b = build_rtp_buf(96, 0x11111111);
        c.process_packet(&pkt(&b), None);
        let b2 = build_rtp_buf(200, 0x11111111);
        c.process_packet(&pkt(&b2), None);

        let stats = c.finalize_stats(10);
        let names: Vec<&str> = stats
            .payload_type_distribution
            .iter()
            .map(|e| e.name.as_str())
            .collect();
        assert!(names.contains(&"Dynamic(96)"));
        assert!(names.contains(&"PT(200)"));
    }

    #[test]
    fn rtp_ssrc_distribution_hex_formatted() {
        let mut c = RtpStatsCollector::new();
        let b1 = build_rtp_buf(0, 0x12345678);
        c.process_packet(&pkt(&b1), None);
        let b2 = build_rtp_buf(0, 0x12345678);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_rtp_buf(0, 0xDEADBEEF);
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.ssrc_distribution[0].name, "0x12345678");
        assert_eq!(stats.ssrc_distribution[0].count, 2);
        assert_eq!(stats.ssrc_distribution[1].name, "0xDEADBEEF");
        assert_eq!(stats.ssrc_distribution[1].count, 1);
    }
}
