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
