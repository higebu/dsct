use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{field_u8, field_u16, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated STUN statistics.
#[derive(Debug, Clone, Serialize)]
pub struct StunStats {
    /// Total number of STUN messages processed.
    pub total_messages: u64,
    /// Distribution of STUN message classes (Request, Indication, etc.).
    pub class_distribution: Vec<CountEntry>,
    /// Distribution of STUN message methods (Binding, etc.).
    pub method_distribution: Vec<CountEntry>,
}

/// Collects STUN message statistics.
#[derive(Debug)]
pub struct StunStatsCollector {
    classes: HashMap<String, u64>,
    methods: HashMap<String, u64>,
    total_messages: u64,
}

impl Default for StunStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl StunStatsCollector {
    /// Create a new collector with the given maximum number of tracked entries.
    pub fn new() -> Self {
        Self {
            classes: HashMap::new(),
            methods: HashMap::new(),
            total_messages: 0,
        }
    }

    /// Process a single dissected packet, updating STUN statistics if a STUN
    /// layer is present.
    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(stun) = packet.layer_by_name("STUN") else {
            return;
        };
        let fields = packet.layer_fields(stun);
        self.total_messages += 1;

        if let Some(class_val) = field_u8(fields, "message_class") {
            let name = class_name(class_val).to_string();
            *self.classes.entry(name).or_insert(0) += 1;
        }

        if let Some(method_val) = field_u16(fields, "message_method") {
            let name = method_name(method_val).to_string();
            *self.methods.entry(name).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> StunStats {
        StunStats {
            total_messages: self.total_messages,
            class_distribution: sorted_top_n(self.classes.into_iter(), top_n),
            method_distribution: sorted_top_n(self.methods.into_iter(), top_n),
        }
    }
}

/// Map a STUN message class value to a human-readable name.
fn class_name(v: u8) -> &'static str {
    match v {
        0b00 => "Request",
        0b01 => "Indication",
        0b10 => "Success Response",
        0b11 => "Error Response",
        _ => "Unknown",
    }
}

/// Map a STUN message method value to a human-readable name.
fn method_name(v: u16) -> &'static str {
    match v {
        0x001 => "Binding",
        _ => "Unknown",
    }
}

super::impl_protocol_stats_collector!(StunStatsCollector, "stun", StunStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_stun_buf(message_class: u8, message_method: u16) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("STUN", None, &[], 0..20);
        buf.push_field(
            test_desc("message_class", "Message Class"),
            FieldValue::U8(message_class),
            0..1,
        );
        buf.push_field(
            test_desc("message_method", "Message Method"),
            FieldValue::U16(message_method),
            0..2,
        );
        buf.end_layer();
        buf
    }

    #[test]
    fn stun_class_distribution() {
        let mut c = StunStatsCollector::new();
        c.process_packet(&pkt(&build_stun_buf(0b00, 0x001)), None);
        c.process_packet(&pkt(&build_stun_buf(0b00, 0x001)), None);
        c.process_packet(&pkt(&build_stun_buf(0b10, 0x001)), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_messages, 3);
        assert_eq!(stats.class_distribution.len(), 2);
        // Most common class (Request) should appear first with count 2.
        assert_eq!(stats.class_distribution[0].count, 2);
    }

    #[test]
    fn stun_method_distribution() {
        let mut c = StunStatsCollector::new();
        c.process_packet(&pkt(&build_stun_buf(0b00, 0x001)), None);
        c.process_packet(&pkt(&build_stun_buf(0b10, 0x001)), None);

        let stats = c.finalize_stats(10);
        assert_eq!(stats.method_distribution.len(), 1);
        assert_eq!(stats.method_distribution[0].count, 2);
        assert_eq!(stats.method_distribution[0].name, "Binding");
    }

    #[test]
    fn stun_ignores_non_stun_packets() {
        let mut c = StunStatsCollector::new();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("UDP", None, &[], 0..8);
        buf.end_layer();
        c.process_packet(&pkt(&buf), None);
        assert_eq!(c.finalize_stats(10).total_messages, 0);
    }

    #[test]
    fn stun_class_names_correct() {
        assert_eq!(class_name(0b00), "Request");
        assert_eq!(class_name(0b01), "Indication");
        assert_eq!(class_name(0b10), "Success Response");
        assert_eq!(class_name(0b11), "Error Response");
        assert_eq!(class_name(0xFF), "Unknown");
    }

    #[test]
    fn stun_method_name_binding() {
        assert_eq!(method_name(0x001), "Binding");
    }

    #[test]
    fn stun_unknown_method() {
        let mut c = StunStatsCollector::new();
        c.process_packet(&pkt(&build_stun_buf(0b00, 0x002)), None);
        let stats = c.finalize_stats(10);
        assert_eq!(stats.method_distribution[0].name, "Unknown");
    }

    #[test]
    fn stun_empty_collector() {
        let c = StunStatsCollector::new();
        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_messages, 0);
        assert!(stats.class_distribution.is_empty());
        assert!(stats.method_distribution.is_empty());
    }
}
