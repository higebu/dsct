use std::collections::HashMap;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, field_u8, field_value_to_string, find_field, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// AVP code for Result-Code (RFC 6733 §7.1).
const DIAMETER_AVP_RESULT_CODE: u32 = 268;
/// AVP code for Experimental-Result-Code (RFC 6733 §7.4).
const DIAMETER_AVP_EXPERIMENTAL_RESULT_CODE: u32 = 298;

/// Aggregated Diameter statistics.
#[derive(Debug, Clone, Serialize)]
pub struct DiameterStats {
    pub total_messages: u64,
    pub total_requests: u64,
    pub total_answers: u64,
    pub command_code_distribution: Vec<CountEntry>,
    pub application_id_distribution: Vec<CountEntry>,
    pub result_code_distribution: Vec<CountEntry>,
}

/// Collects Diameter message statistics.
#[derive(Debug)]
pub struct DiameterStatsCollector {
    command_codes: HashMap<String, u64>,
    application_ids: HashMap<String, u64>,
    result_codes: HashMap<String, u64>,
    total_messages: u64,
    total_requests: u64,
    total_answers: u64,
}

impl Default for DiameterStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl DiameterStatsCollector {
    pub fn new() -> Self {
        Self {
            command_codes: HashMap::new(),
            application_ids: HashMap::new(),
            result_codes: HashMap::new(),
            total_messages: 0,
            total_requests: 0,
            total_answers: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(diam) = packet.layer_by_name("Diameter") else {
            return;
        };
        let fields = packet.layer_fields(diam);
        self.total_messages += 1;

        if field_u8(fields, "is_request") == Some(1) {
            self.total_requests += 1;
        } else {
            self.total_answers += 1;
        }

        if let Some(name) = display_name(packet, diam, fields, "command_name", "command_code") {
            *self.command_codes.entry(name).or_insert(0) += 1;
        }
        if let Some(name) = display_name(packet, diam, fields, "application_name", "application_id")
        {
            *self.application_ids.entry(name).or_insert(0) += 1;
        }

        // Extract Result-Code or Experimental-Result-Code from AVPs.
        if let Some(avps_field) = find_field(fields, "avps")
            && let FieldValue::Array(ref range) = avps_field.value
        {
            for elem in packet.nested_fields(range) {
                if let FieldValue::Object(ref obj_range) = elem.value {
                    let avp_fields = packet.nested_fields(obj_range);
                    let code = avp_fields.iter().find_map(|f| match (&f.value, f.name()) {
                        (FieldValue::U32(v), "code") => Some(*v),
                        _ => None,
                    });
                    let Some(avp_code) = code else {
                        continue;
                    };
                    if avp_code != DIAMETER_AVP_RESULT_CODE
                        && avp_code != DIAMETER_AVP_EXPERIMENTAL_RESULT_CODE
                    {
                        continue;
                    }
                    // Try display name first, fall back to raw value string.
                    let name = packet
                        .resolve_nested_display_name(obj_range, "value_name")
                        .map(|s| s.to_owned())
                        .or_else(|| {
                            avp_fields
                                .iter()
                                .find(|f| f.name() == "value")
                                .map(|f| field_value_to_string(&f.value))
                        });
                    if let Some(name) = name {
                        *self.result_codes.entry(name).or_insert(0) += 1;
                    }
                    break;
                }
            }
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> DiameterStats {
        DiameterStats {
            total_messages: self.total_messages,
            total_requests: self.total_requests,
            total_answers: self.total_answers,
            command_code_distribution: sorted_top_n(self.command_codes.into_iter(), top_n),
            application_id_distribution: sorted_top_n(self.application_ids.into_iter(), top_n),
            result_code_distribution: sorted_top_n(self.result_codes.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(DiameterStatsCollector, "diameter", DiameterStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    /// Build a Diameter DissectBuffer with command_code, application_id,
    /// is_request flag, and an optional Result-Code AVP.
    fn build_diameter_buf(
        command_code: u32,
        application_id: u32,
        is_request: u8,
        result_code: Option<u32>,
    ) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Diameter", None, &[], 0..40);
        buf.push_field(
            test_desc("command_code", "Command Code"),
            FieldValue::U32(command_code),
            0..4,
        );
        buf.push_field(
            test_desc("application_id", "Application ID"),
            FieldValue::U32(application_id),
            4..8,
        );
        buf.push_field(
            test_desc("is_request", "Request"),
            FieldValue::U8(is_request),
            8..9,
        );

        if let Some(rc) = result_code {
            let arr =
                buf.begin_container(test_desc("avps", "AVPs"), FieldValue::Array(0..0), 12..40);
            let obj =
                buf.begin_container(test_desc("avp", "AVP"), FieldValue::Object(0..0), 12..24);
            buf.push_field(
                test_desc("code", "AVP Code"),
                FieldValue::U32(DIAMETER_AVP_RESULT_CODE),
                12..16,
            );
            buf.push_field(test_desc("value", "Value"), FieldValue::U32(rc), 16..20);
            buf.end_container(obj);
            buf.end_container(arr);
        }

        buf.end_layer();
        buf
    }

    #[test]
    fn diameter_collector_counts_requests_and_answers() {
        let mut c = DiameterStatsCollector::new();
        let b1 = build_diameter_buf(272, 4, 1, None);
        c.process_packet(&pkt(&b1), None);
        let b2 = build_diameter_buf(272, 4, 0, Some(2001));
        c.process_packet(&pkt(&b2), None);
        let b3 = build_diameter_buf(257, 0, 1, None);
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_messages, 3);
        assert_eq!(stats.total_requests, 2);
        assert_eq!(stats.total_answers, 1);
        assert_eq!(stats.command_code_distribution.len(), 2);
        assert_eq!(stats.application_id_distribution.len(), 2);
    }

    #[test]
    fn diameter_collector_extracts_result_code() {
        let mut c = DiameterStatsCollector::new();
        let b1 = build_diameter_buf(272, 4, 0, Some(2001));
        c.process_packet(&pkt(&b1), None);
        let b2 = build_diameter_buf(272, 4, 0, Some(2001));
        c.process_packet(&pkt(&b2), None);
        let b3 = build_diameter_buf(272, 4, 0, Some(5012));
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.result_code_distribution.len(), 2);
        // Uses fallback numeric strings since test_desc has no display_fn.
        let total: u64 = stats.result_code_distribution.iter().map(|e| e.count).sum();
        assert_eq!(total, 3);
    }

    #[test]
    fn diameter_collector_no_result_code_when_absent() {
        let mut c = DiameterStatsCollector::new();
        let b = build_diameter_buf(257, 0, 1, None);
        c.process_packet(&pkt(&b), None);

        let stats = c.finalize_stats(10);
        assert!(stats.result_code_distribution.is_empty());
    }
}
