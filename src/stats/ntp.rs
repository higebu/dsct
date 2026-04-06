use std::collections::HashMap;

use packet_dissector_core::packet::Packet;

use super::helpers::{display_name, field_value_to_string, find_field, sorted_top_n};
use super::{CountEntry, ProtocolStatsCollector};
use serde::Serialize;

/// Aggregated NTP statistics.
#[derive(Debug, Clone, Serialize)]
pub struct NtpStats {
    pub total_packets: u64,
    pub mode_distribution: Vec<CountEntry>,
    pub stratum_distribution: Vec<CountEntry>,
    pub version_distribution: Vec<CountEntry>,
}

/// Collects NTP packet statistics.
#[derive(Debug)]
pub struct NtpStatsCollector {
    modes: HashMap<String, u64>,
    strata: HashMap<String, u64>,
    versions: HashMap<String, u64>,
    total_packets: u64,
}

impl Default for NtpStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl NtpStatsCollector {
    pub fn new() -> Self {
        Self {
            modes: HashMap::new(),
            strata: HashMap::new(),
            versions: HashMap::new(),
            total_packets: 0,
        }
    }

    pub fn process_packet(&mut self, packet: &Packet, _timestamp: Option<f64>) {
        let Some(ntp) = packet.layer_by_name("NTP") else {
            return;
        };
        let fields = packet.layer_fields(ntp);
        self.total_packets += 1;

        if let Some(name) = display_name(packet, ntp, fields, "mode_name", "mode") {
            *self.modes.entry(name).or_insert(0) += 1;
        }
        if let Some(name) = display_name(packet, ntp, fields, "stratum_name", "stratum") {
            *self.strata.entry(name).or_insert(0) += 1;
        }
        if let Some(f) = find_field(fields, "version") {
            let ver = field_value_to_string(&f.value);
            *self.versions.entry(ver).or_insert(0) += 1;
        }
    }

    pub(super) fn finalize_stats(self, top_n: usize) -> NtpStats {
        NtpStats {
            total_packets: self.total_packets,
            mode_distribution: sorted_top_n(self.modes.into_iter(), top_n),
            stratum_distribution: sorted_top_n(self.strata.into_iter(), top_n),
            version_distribution: sorted_top_n(self.versions.into_iter(), top_n),
        }
    }
}

super::impl_protocol_stats_collector!(NtpStatsCollector, "ntp", NtpStats);
