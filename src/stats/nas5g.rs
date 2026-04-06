use std::collections::HashMap;

use packet_dissector_core::packet::Packet;
use serde::Serialize;

use super::helpers::{field_u8, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};

/// Extended protocol discriminator value for 5GS mobility management (3GPP TS 24.007).
const EPD_5GMM: u8 = 0x7E;
/// Extended protocol discriminator value for 5GS session management (3GPP TS 24.007).
const EPD_5GSM: u8 = 0x2E;

/// Extended protocol discriminator name (3GPP TS 24.007, Table 11.2).
fn epd_name(epd: u8) -> &'static str {
    match epd {
        0x2E => "5GS session management",
        0x7E => "5GS mobility management",
        _ => "Unknown",
    }
}

/// 5GMM message type name (3GPP TS 24.501, Table 8.2.1).
fn mm_message_type_name(mt: u8) -> &'static str {
    match mt {
        0x41 => "Registration request",
        0x42 => "Registration accept",
        0x43 => "Registration complete",
        0x44 => "Registration reject",
        0x45 => "Deregistration request (UE originating)",
        0x46 => "Deregistration accept (UE originating)",
        0x47 => "Deregistration request (UE terminated)",
        0x48 => "Deregistration accept (UE terminated)",
        0x54 => "Service request",
        0x55 => "Service reject",
        0x56 => "Service accept",
        0x5c => "Configuration update command",
        0x5d => "Configuration update complete",
        0x5e => "Authentication request",
        0x5f => "Authentication response",
        0x60 => "Authentication reject",
        0x61 => "Authentication failure",
        0x62 => "Authentication result",
        0x64 => "Identity request",
        0x65 => "Identity response",
        0x66 => "Security mode command",
        0x67 => "Security mode complete",
        0x68 => "Security mode reject",
        0x6a => "5GMM status",
        0x6b => "Notification",
        0x6c => "Notification response",
        0x6d => "UL NAS transport",
        0x6e => "DL NAS transport",
        _ => "Unknown",
    }
}

/// 5GSM message type name (3GPP TS 24.501, Table 8.3.1).
fn sm_message_type_name(mt: u8) -> &'static str {
    match mt {
        0xc1 => "PDU session establishment request",
        0xc2 => "PDU session establishment accept",
        0xc3 => "PDU session establishment reject",
        0xc5 => "PDU session authentication command",
        0xc6 => "PDU session authentication complete",
        0xc7 => "PDU session authentication result",
        0xc9 => "PDU session modification request",
        0xca => "PDU session modification reject",
        0xcb => "PDU session modification command",
        0xcc => "PDU session modification complete",
        0xcd => "PDU session modification command reject",
        0xd1 => "PDU session release request",
        0xd2 => "PDU session release reject",
        0xd3 => "PDU session release command",
        0xd4 => "PDU session release complete",
        0xd6 => "5GSM status",
        _ => "Unknown",
    }
}

/// Aggregated 5G NAS statistics.
#[derive(Debug, Clone, Serialize)]
pub struct Nas5gStats {
    /// Total number of NAS-5G messages observed.
    pub total_messages: u64,
    /// Distribution of extended protocol discriminator values.
    pub epd_distribution: Vec<CountEntry>,
    /// Distribution of 5GMM (EPD=0x7E) message types.
    pub mm_message_type_distribution: Vec<CountEntry>,
    /// Distribution of 5GSM (EPD=0x2E) message types.
    pub sm_message_type_distribution: Vec<CountEntry>,
}

/// Collects NAS-5G message statistics.
#[derive(Debug)]
pub struct Nas5gStatsCollector {
    total_messages: u64,
    epds: HashMap<String, u64>,
    mm_types: HashMap<String, u64>,
    sm_types: HashMap<String, u64>,
}

impl Default for Nas5gStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Nas5gStatsCollector {
    /// Create a new collector.
    pub fn new() -> Self {
        Self {
            total_messages: 0,
            epds: HashMap::new(),
            mm_types: HashMap::new(),
            sm_types: HashMap::new(),
        }
    }

    /// Process a single packet, extracting NAS-5G fields if present.
    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(nas) = packet.layer_by_name("NAS-5G") else {
            return;
        };
        let fields = packet.layer_fields(nas);
        self.total_messages += 1;

        let epd = field_u8(fields, "extended_protocol_discriminator");
        if let Some(e) = epd {
            *self.epds.entry(epd_name(e).to_string()).or_insert(0) += 1;
        }

        if let Some(mt) = field_u8(fields, "message_type") {
            match epd {
                Some(EPD_5GMM) => {
                    *self
                        .mm_types
                        .entry(mm_message_type_name(mt).to_string())
                        .or_insert(0) += 1;
                }
                Some(EPD_5GSM) => {
                    *self
                        .sm_types
                        .entry(sm_message_type_name(mt).to_string())
                        .or_insert(0) += 1;
                }
                _ => {}
            }
        }
    }

    /// Produce final statistics, keeping at most `top_n` entries per distribution.
    pub(super) fn finalize_stats(self, top_n: usize) -> Nas5gStats {
        Nas5gStats {
            total_messages: self.total_messages,
            epd_distribution: sorted_top_n(self.epds.into_iter(), top_n),
            mm_message_type_distribution: sorted_top_n(self.mm_types.into_iter(), top_n),
            sm_message_type_distribution: sorted_top_n(self.sm_types.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(Nas5gStatsCollector, "nas5g", Nas5gStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_nas5g_buf(epd: u8, message_type: u8) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("NAS-5G", None, &[], 0..4);
        buf.push_field(
            test_desc("extended_protocol_discriminator", "EPD"),
            FieldValue::U8(epd),
            0..1,
        );
        buf.push_field(
            test_desc("security_header_type", "Security Header Type"),
            FieldValue::U8(0),
            1..2,
        );
        buf.push_field(
            test_desc("message_type", "Message Type"),
            FieldValue::U8(message_type),
            2..3,
        );
        buf.end_layer();
        buf
    }

    #[test]
    fn nas5g_epd_distribution() {
        let mut c = Nas5gStatsCollector::new();
        c.process_packet(&pkt(&build_nas5g_buf(0x7E, 0x41)), None); // Registration request
        c.process_packet(&pkt(&build_nas5g_buf(0x7E, 0x42)), None); // Registration accept
        c.process_packet(&pkt(&build_nas5g_buf(0x2E, 0xc1)), None); // PDU session establishment request

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_messages, 3);
        let mm = stats
            .epd_distribution
            .iter()
            .find(|e| e.name == "5GS mobility management");
        assert!(mm.is_some());
        assert_eq!(mm.unwrap().count, 2);
    }

    #[test]
    fn nas5g_mm_message_type_distribution() {
        let mut c = Nas5gStatsCollector::new();
        c.process_packet(&pkt(&build_nas5g_buf(0x7E, 0x41)), None);
        c.process_packet(&pkt(&build_nas5g_buf(0x7E, 0x41)), None);
        c.process_packet(&pkt(&build_nas5g_buf(0x7E, 0x42)), None);

        let stats = c.finalize_stats(10);
        assert_eq!(
            stats.mm_message_type_distribution[0].name,
            "Registration request"
        );
        assert_eq!(stats.mm_message_type_distribution[0].count, 2);
    }

    #[test]
    fn nas5g_sm_message_type_distribution() {
        let mut c = Nas5gStatsCollector::new();
        c.process_packet(&pkt(&build_nas5g_buf(0x2E, 0xc1)), None);
        c.process_packet(&pkt(&build_nas5g_buf(0x2E, 0xc2)), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.sm_message_type_distribution.len(), 2);
    }

    #[test]
    fn nas5g_ignores_non_nas5g_packets() {
        let mut c = Nas5gStatsCollector::new();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("NGAP", None, &[], 0..10);
        buf.end_layer();
        c.process_packet(&pkt(&buf), None);
        assert_eq!(c.finalize_stats(10).total_messages, 0);
    }
}
