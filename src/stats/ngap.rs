use std::collections::HashMap;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;
use serde::Serialize;

use super::helpers::{find_field, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};

/// NGAP PDU type name (3GPP TS 38.413, Section 9.4.2).
fn pdu_type_name(pdu_type: u8) -> &'static str {
    match pdu_type {
        0 => "initiatingMessage",
        1 => "successfulOutcome",
        2 => "unsuccessfulOutcome",
        _ => "Unknown",
    }
}

/// NGAP procedure code name (3GPP TS 38.413, Section 9.4.4).
fn procedure_code_name(code: u8) -> &'static str {
    match code {
        0 => "AMFConfigurationUpdate",
        1 => "AMFStatusIndication",
        2 => "CellTrafficTrace",
        3 => "DeactivateTrace",
        4 => "DownlinkNASTransport",
        5 => "DownlinkNonUEAssociatedNRPPaTransport",
        6 => "DownlinkRANConfigurationTransfer",
        7 => "DownlinkRANStatusTransfer",
        8 => "DownlinkUEAssociatedNRPPaTransport",
        9 => "ErrorIndication",
        10 => "HandoverCancel",
        11 => "HandoverNotification",
        12 => "HandoverPreparation",
        13 => "HandoverResourceAllocation",
        14 => "InitialContextSetup",
        15 => "InitialUEMessage",
        16 => "LocationReportingControl",
        17 => "LocationReportingFailureIndication",
        18 => "LocationReport",
        19 => "NASNonDeliveryIndication",
        20 => "NGReset",
        21 => "NGSetup",
        22 => "OverloadStart",
        23 => "OverloadStop",
        24 => "Paging",
        25 => "PathSwitchRequest",
        26 => "PDUSessionResourceModify",
        27 => "PDUSessionResourceModifyIndication",
        28 => "PDUSessionResourceRelease",
        29 => "PDUSessionResourceSetup",
        30 => "PDUSessionResourceNotify",
        31 => "PrivateMessage",
        32 => "PWSCancel",
        33 => "PWSFailureIndication",
        34 => "PWSRestartIndication",
        35 => "RANConfigurationUpdate",
        36 => "RerouteNASRequest",
        37 => "RRCInactiveTransitionReport",
        38 => "TraceFailureIndication",
        39 => "TraceStart",
        40 => "UEContextModification",
        41 => "UEContextRelease",
        42 => "UEContextReleaseRequest",
        43 => "UERadioCapabilityCheck",
        44 => "UERadioCapabilityInfoIndication",
        45 => "UETNLABindingRelease",
        46 => "UplinkNASTransport",
        47 => "UplinkNonUEAssociatedNRPPaTransport",
        48 => "UplinkRANConfigurationTransfer",
        49 => "UplinkRANStatusTransfer",
        50 => "UplinkUEAssociatedNRPPaTransport",
        51 => "WriteReplaceWarning",
        52 => "SecondaryRATDataUsageReport",
        _ => "Unknown",
    }
}

/// Aggregated NGAP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct NgapStats {
    /// Total number of NGAP messages observed.
    pub total_messages: u64,
    /// Distribution of NGAP PDU types (initiatingMessage / successfulOutcome / unsuccessfulOutcome).
    pub pdu_type_distribution: Vec<CountEntry>,
    /// Distribution of NGAP procedure codes by name.
    pub procedure_code_distribution: Vec<CountEntry>,
}

/// Collects NGAP statistics in a single pass.
#[derive(Debug)]
pub struct NgapStatsCollector {
    total_messages: u64,
    pdu_types: HashMap<String, u64>,
    procedure_codes: HashMap<String, u64>,
}

impl Default for NgapStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl NgapStatsCollector {
    /// Create a new collector.
    pub fn new() -> Self {
        Self {
            total_messages: 0,
            pdu_types: HashMap::new(),
            procedure_codes: HashMap::new(),
        }
    }

    /// Process a single dissected packet.
    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(ngap) = packet.layer_by_name("NGAP") else {
            return;
        };
        let fields = packet.layer_fields(ngap);
        self.total_messages += 1;

        if let Some(f) = find_field(fields, "pdu_type")
            && let FieldValue::U8(t) = f.value
        {
            *self
                .pdu_types
                .entry(pdu_type_name(t).to_string())
                .or_insert(0) += 1;
        }

        if let Some(f) = find_field(fields, "procedure_code")
            && let FieldValue::U8(c) = f.value
        {
            *self
                .procedure_codes
                .entry(procedure_code_name(c).to_string())
                .or_insert(0) += 1;
        }
    }

    /// Produce the final [`NgapStats`] output.
    pub(super) fn finalize_stats(self, top_n: usize) -> NgapStats {
        NgapStats {
            total_messages: self.total_messages,
            pdu_type_distribution: sorted_top_n(self.pdu_types.into_iter(), top_n),
            procedure_code_distribution: sorted_top_n(self.procedure_codes.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(NgapStatsCollector, "ngap", NgapStats);

#[cfg(test)]
mod tests {
    use super::super::test_helpers::pkt;
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn build_ngap_buf(pdu_type: u8, procedure_code: u8) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("NGAP", None, &[], 0..10);
        buf.push_field(
            test_desc("pdu_type", "PDU Type"),
            FieldValue::U8(pdu_type),
            0..1,
        );
        buf.push_field(
            test_desc("procedure_code", "Procedure Code"),
            FieldValue::U8(procedure_code),
            1..2,
        );
        buf.push_field(
            test_desc("criticality", "Criticality"),
            FieldValue::U8(0),
            2..3,
        );
        buf.end_layer();
        buf
    }

    #[test]
    fn ngap_pdu_type_distribution() {
        let mut c = NgapStatsCollector::new();
        c.process_packet(&pkt(&build_ngap_buf(0, 21)), None); // initiatingMessage, NGSetup
        c.process_packet(&pkt(&build_ngap_buf(0, 21)), None); // initiatingMessage, NGSetup
        c.process_packet(&pkt(&build_ngap_buf(1, 21)), None); // successfulOutcome, NGSetup

        let stats = c.finalize_stats(10);
        assert_eq!(stats.total_messages, 3);
        let init = stats
            .pdu_type_distribution
            .iter()
            .find(|e| e.name == "initiatingMessage");
        assert!(init.is_some());
        assert_eq!(init.unwrap().count, 2);
    }

    #[test]
    fn ngap_procedure_code_distribution() {
        let mut c = NgapStatsCollector::new();
        c.process_packet(&pkt(&build_ngap_buf(0, 21)), None); // NGSetup
        c.process_packet(&pkt(&build_ngap_buf(1, 21)), None); // NGSetup
        c.process_packet(&pkt(&build_ngap_buf(0, 14)), None); // InitialContextSetup

        let stats = c.finalize_stats(10);
        let ngsetup = stats
            .procedure_code_distribution
            .iter()
            .find(|e| e.name == "NGSetup");
        assert!(ngsetup.is_some());
        assert_eq!(ngsetup.unwrap().count, 2);
    }

    #[test]
    fn ngap_ignores_non_ngap_packets() {
        let mut c = NgapStatsCollector::new();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("SCTP", None, &[], 0..12);
        buf.end_layer();
        c.process_packet(&pkt(&buf), None);
        assert_eq!(c.finalize_stats(10).total_messages, 0);
    }
}
