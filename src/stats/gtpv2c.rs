use std::collections::{BTreeMap, HashMap, HashSet};

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, field_u32, field_value_to_string, find_field, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// GTPv2-C IE type code for IMSI.
const IE_IMSI: u32 = 1;
/// GTPv2-C IE type code for Cause.
const IE_CAUSE: u32 = 2;
/// GTPv2-C IE type code for Serving Network.
const IE_SERVING_NETWORK: u32 = 83;

/// Aggregated GTPv2-C statistics.
#[derive(Debug, Clone, Serialize)]
pub struct Gtpv2cStats {
    pub total_messages: u64,
    pub message_type_distribution: Vec<CountEntry>,
    pub unique_imsi_count: u64,
    pub unique_teid_count: u64,
    pub cause_per_message_type: std::collections::BTreeMap<String, Vec<CountEntry>>,
    pub plmn_distribution: Vec<CountEntry>,
}

/// Collects GTPv2-C message statistics.
#[derive(Debug)]
pub struct Gtpv2cStatsCollector {
    message_types: HashMap<String, u64>,
    total_messages: u64,
    imsis: HashSet<String>,
    teids: HashSet<u32>,
    /// Cause counts keyed by message type name, then by cause name.
    causes: HashMap<String, HashMap<String, u64>>,
    plmns: HashMap<String, u64>,
}

impl Default for Gtpv2cStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl Gtpv2cStatsCollector {
    pub fn new() -> Self {
        Self {
            message_types: HashMap::new(),
            total_messages: 0,
            imsis: HashSet::new(),
            teids: HashSet::new(),
            causes: HashMap::new(),
            plmns: HashMap::new(),
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(gtp) = packet.layer_by_name("GTPv2-C") else {
            return;
        };
        let fields = packet.layer_fields(gtp);
        self.total_messages += 1;

        let msg_type_name = display_name(packet, gtp, fields, "message_type_name", "message_type");

        if let Some(ref name) = msg_type_name {
            *self.message_types.entry(name.clone()).or_insert(0) += 1;
        }

        // TEID is a top-level field.
        if let Some(teid) = field_u32(fields, "teid") {
            self.teids.insert(teid);
        }

        // Extract IE-level statistics.
        let Some(ies_field) = find_field(fields, "ies") else {
            return;
        };
        let FieldValue::Array(ref ies_range) = ies_field.value else {
            return;
        };
        for elem in packet.nested_fields(ies_range) {
            let FieldValue::Object(ref obj_range) = elem.value else {
                continue;
            };
            let ie_fields = packet.nested_fields(obj_range);
            let ie_type = ie_fields.iter().find_map(|f| match (&f.value, f.name()) {
                (FieldValue::U32(v), "type") => Some(*v),
                _ => None,
            });
            match ie_type {
                // IMSI — value is Scratch (BCD-decoded string).
                Some(IE_IMSI) => {
                    if let Some(f) = ie_fields.iter().find(|f| f.name() == "value")
                        && let FieldValue::Scratch(r) = &f.value
                    {
                        let bytes = packet.resolve_scratch(r);
                        if let Ok(imsi) = std::str::from_utf8(bytes) {
                            self.imsis.insert(imsi.to_owned());
                        }
                    }
                }
                // Cause — value is Object { cause_value: U8 }.
                // Keyed by message type name for per-message-type breakdown.
                Some(IE_CAUSE) => {
                    if let Some(val_f) = ie_fields.iter().find(|f| f.name() == "value")
                        && let FieldValue::Object(ref val_range) = val_f.value
                    {
                        let cause_name = packet
                            .resolve_nested_display_name(val_range, "cause_value_name")
                            .map(|s| s.to_owned())
                            .or_else(|| {
                                let inner = packet.nested_fields(val_range);
                                inner
                                    .iter()
                                    .find(|f| f.name() == "cause_value")
                                    .map(|f| field_value_to_string(&f.value))
                            });
                        if let Some(cause) = cause_name {
                            let msg_key = msg_type_name
                                .clone()
                                .unwrap_or_else(|| "Unknown".to_owned());
                            let per_msg = self.causes.entry(msg_key).or_default();
                            *per_msg.entry(cause).or_insert(0) += 1;
                        }
                    }
                }
                // Serving Network — value is Object { mcc: Scratch, mnc: Scratch }.
                Some(IE_SERVING_NETWORK) => {
                    if let Some(val_f) = ie_fields.iter().find(|f| f.name() == "value")
                        && let FieldValue::Object(ref val_range) = val_f.value
                    {
                        let inner = packet.nested_fields(val_range);
                        let mcc =
                            inner
                                .iter()
                                .find(|f| f.name() == "mcc")
                                .and_then(|f| match &f.value {
                                    FieldValue::Scratch(r) => {
                                        std::str::from_utf8(packet.resolve_scratch(r)).ok()
                                    }
                                    _ => None,
                                });
                        let mnc =
                            inner
                                .iter()
                                .find(|f| f.name() == "mnc")
                                .and_then(|f| match &f.value {
                                    FieldValue::Scratch(r) => {
                                        std::str::from_utf8(packet.resolve_scratch(r)).ok()
                                    }
                                    _ => None,
                                });
                        if let (Some(mcc), Some(mnc)) = (mcc, mnc) {
                            let plmn = format!("{mcc}-{mnc}");
                            *self.plmns.entry(plmn).or_insert(0) += 1;
                        }
                    }
                }
                _ => {}
            }
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> Gtpv2cStats {
        let cause_per_message_type: BTreeMap<String, Vec<CountEntry>> = self
            .causes
            .into_iter()
            .map(|(msg_type, causes)| (msg_type, sorted_top_n(causes.into_iter(), top_n)))
            .collect();

        Gtpv2cStats {
            total_messages: self.total_messages,
            message_type_distribution: sorted_top_n(self.message_types.into_iter(), top_n),
            unique_imsi_count: self.imsis.len() as u64,
            unique_teid_count: self.teids.len() as u64,
            cause_per_message_type,
            plmn_distribution: sorted_top_n(self.plmns.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(Gtpv2cStatsCollector, "gtpv2c", Gtpv2cStats);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::test_helpers::pkt;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_gtpv2c_base(message_type: u32, teid: Option<u32>) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("GTPv2-C", None, &[], 0..40);
        buf.push_field(
            test_desc("message_type", "Message Type"),
            FieldValue::U32(message_type),
            0..1,
        );
        if let Some(t) = teid {
            buf.push_field(test_desc("teid", "TEID"), FieldValue::U32(t), 4..8);
        }
        buf.end_layer();
        buf
    }

    fn build_gtpv2c_with_imsi(
        message_type: u32,
        teid: Option<u32>,
        imsi: &str,
    ) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("GTPv2-C", None, &[], 0..40);
        buf.push_field(
            test_desc("message_type", "Message Type"),
            FieldValue::U32(message_type),
            0..1,
        );
        if let Some(t) = teid {
            buf.push_field(test_desc("teid", "TEID"), FieldValue::U32(t), 4..8);
        }
        let arr = buf.begin_container(test_desc("ies", "IEs"), FieldValue::Array(0..0), 8..40);
        let ie_obj = buf.begin_container(test_desc("ie", "IE"), FieldValue::Object(0..0), 8..20);
        buf.push_field(test_desc("type", "Type"), FieldValue::U32(IE_IMSI), 8..9);
        let scratch_range = buf.push_scratch(imsi.as_bytes());
        buf.push_field(
            test_desc("value", "Value"),
            FieldValue::Scratch(scratch_range),
            9..20,
        );
        buf.end_container(ie_obj);
        buf.end_container(arr);
        buf.end_layer();
        buf
    }

    fn build_gtpv2c_with_cause(
        message_type: u32,
        teid: Option<u32>,
        cause_value: u8,
    ) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("GTPv2-C", None, &[], 0..40);
        buf.push_field(
            test_desc("message_type", "Message Type"),
            FieldValue::U32(message_type),
            0..1,
        );
        if let Some(t) = teid {
            buf.push_field(test_desc("teid", "TEID"), FieldValue::U32(t), 4..8);
        }
        let arr = buf.begin_container(test_desc("ies", "IEs"), FieldValue::Array(0..0), 8..40);
        let ie_obj = buf.begin_container(test_desc("ie", "IE"), FieldValue::Object(0..0), 8..20);
        buf.push_field(test_desc("type", "Type"), FieldValue::U32(IE_CAUSE), 8..9);
        let val_obj =
            buf.begin_container(test_desc("value", "Value"), FieldValue::Object(0..0), 9..20);
        buf.push_field(
            test_desc("cause_value", "Cause Value"),
            FieldValue::U8(cause_value),
            9..10,
        );
        buf.end_container(val_obj);
        buf.end_container(ie_obj);
        buf.end_container(arr);
        buf.end_layer();
        buf
    }

    fn build_gtpv2c_with_serving_network(
        message_type: u32,
        teid: Option<u32>,
        mcc: &str,
        mnc: &str,
    ) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("GTPv2-C", None, &[], 0..40);
        buf.push_field(
            test_desc("message_type", "Message Type"),
            FieldValue::U32(message_type),
            0..1,
        );
        if let Some(t) = teid {
            buf.push_field(test_desc("teid", "TEID"), FieldValue::U32(t), 4..8);
        }
        let arr = buf.begin_container(test_desc("ies", "IEs"), FieldValue::Array(0..0), 8..40);
        let ie_obj = buf.begin_container(test_desc("ie", "IE"), FieldValue::Object(0..0), 8..20);
        buf.push_field(
            test_desc("type", "Type"),
            FieldValue::U32(IE_SERVING_NETWORK),
            8..9,
        );
        let val_obj =
            buf.begin_container(test_desc("value", "Value"), FieldValue::Object(0..0), 9..20);
        let mcc_range = buf.push_scratch(mcc.as_bytes());
        buf.push_field(
            test_desc("mcc", "MCC"),
            FieldValue::Scratch(mcc_range),
            9..12,
        );
        let mnc_range = buf.push_scratch(mnc.as_bytes());
        buf.push_field(
            test_desc("mnc", "MNC"),
            FieldValue::Scratch(mnc_range),
            12..15,
        );
        buf.end_container(val_obj);
        buf.end_container(ie_obj);
        buf.end_container(arr);
        buf.end_layer();
        buf
    }

    #[test]
    fn gtpv2c_collector_counts_messages() {
        let mut c = Gtpv2cStatsCollector::new();
        let b1 = build_gtpv2c_base(32, Some(0x1234));
        c.process_packet(&pkt(&b1), None);
        let b2 = build_gtpv2c_base(33, Some(0x5678));
        c.process_packet(&pkt(&b2), None);
        let b3 = build_gtpv2c_base(32, Some(0x1234));
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_messages, 3);
        assert_eq!(stats.message_type_distribution.len(), 2);
    }

    #[test]
    fn gtpv2c_collector_unique_teid_count() {
        let mut c = Gtpv2cStatsCollector::new();
        let b1 = build_gtpv2c_base(32, Some(0x1111));
        c.process_packet(&pkt(&b1), None);
        let b2 = build_gtpv2c_base(33, Some(0x2222));
        c.process_packet(&pkt(&b2), None);
        let b3 = build_gtpv2c_base(32, Some(0x1111));
        c.process_packet(&pkt(&b3), None);
        let b4 = build_gtpv2c_base(32, None);
        c.process_packet(&pkt(&b4), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.unique_teid_count, 2);
    }

    #[test]
    fn gtpv2c_collector_unique_imsi_count() {
        let mut c = Gtpv2cStatsCollector::new();
        let b1 = build_gtpv2c_with_imsi(32, Some(0x1111), "440101234567890");
        c.process_packet(&pkt(&b1), None);
        let b2 = build_gtpv2c_with_imsi(32, Some(0x2222), "440109876543210");
        c.process_packet(&pkt(&b2), None);
        let b3 = build_gtpv2c_with_imsi(32, Some(0x3333), "440101234567890");
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.unique_imsi_count, 2);
    }

    #[test]
    fn gtpv2c_collector_cause_per_message_type() {
        let mut c = Gtpv2cStatsCollector::new();
        // Create Session Response (type=33) with cause values
        let b1 = build_gtpv2c_with_cause(33, Some(0x1111), 16);
        c.process_packet(&pkt(&b1), None);
        let b2 = build_gtpv2c_with_cause(33, Some(0x2222), 16);
        c.process_packet(&pkt(&b2), None);
        let b3 = build_gtpv2c_with_cause(33, Some(0x3333), 64);
        c.process_packet(&pkt(&b3), None);
        // Modify Bearer Response (type=35) with different cause
        let b4 = build_gtpv2c_with_cause(35, Some(0x4444), 16);
        c.process_packet(&pkt(&b4), None);

        let stats = c.finalize_stats(10);
        // Two message types have causes.
        assert_eq!(stats.cause_per_message_type.len(), 2);

        // test_desc has no display_fn, so message type falls back to numeric "33".
        let causes_33 = &stats.cause_per_message_type["33"];
        assert_eq!(causes_33.len(), 2);
        let total_33: u64 = causes_33.iter().map(|e| e.count).sum();
        assert_eq!(total_33, 3);

        let causes_35 = &stats.cause_per_message_type["35"];
        assert_eq!(causes_35.len(), 1);
        assert_eq!(causes_35[0].count, 1);
    }

    #[test]
    fn gtpv2c_collector_plmn_distribution() {
        let mut c = Gtpv2cStatsCollector::new();
        let b1 = build_gtpv2c_with_serving_network(32, Some(0x1111), "440", "10");
        c.process_packet(&pkt(&b1), None);
        let b2 = build_gtpv2c_with_serving_network(32, Some(0x2222), "440", "10");
        c.process_packet(&pkt(&b2), None);
        let b3 = build_gtpv2c_with_serving_network(32, Some(0x3333), "310", "260");
        c.process_packet(&pkt(&b3), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.plmn_distribution.len(), 2);
        assert_eq!(stats.plmn_distribution[0].name, "440-10");
        assert_eq!(stats.plmn_distribution[0].count, 2);
        assert_eq!(stats.plmn_distribution[1].name, "310-260");
        assert_eq!(stats.plmn_distribution[1].count, 1);
    }
}
