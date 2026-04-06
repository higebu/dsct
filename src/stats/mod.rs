//! Statistics collectors for the `dsct stats` command.
//!
//! Each collector aggregates data in a single pass over the capture file.
//! After processing, [`StatsCollector::finalize`] produces a
//! [`StatsOutput`] ready for JSON serialization.

mod helpers;
#[cfg(test)]
mod test_helpers;

mod arp;
mod bgp;
mod dhcp;
mod dhcpv6;
mod diameter;
mod dns;
mod geneve;
mod gre;
mod gtpv1u;
mod gtpv2c;
mod http;
mod http2;
mod icmp;
mod igmp;
mod lldp;
mod mdns;
mod nas5g;
mod ngap;
mod ntp;
mod ospf;
mod pfcp;
mod radius;
mod rtp;
mod sctp;
mod sip;
mod stun;
mod tcp_streams;
mod tls;
mod top_talkers;
mod vxlan;

/// Implement [`ProtocolStatsCollector`] for a collector type.
///
/// Generates the boilerplate trait impl that delegates `process_packet` and
/// `finalize` to the collector's inherent methods.
macro_rules! impl_protocol_stats_collector {
    ($ty:ty, $key:expr, $stats_ty:ident) => {
        impl ProtocolStatsCollector for $ty {
            fn key(&self) -> &'static str {
                $key
            }

            fn process_packet(
                &mut self,
                packet: &::packet_dissector_core::packet::Packet,
                timestamp: Option<f64>,
            ) {
                self.process_packet(packet, timestamp);
            }

            fn finalize(
                self: Box<Self>,
                top_n: usize,
            ) -> Result<::serde_json::Value, ::serde_json::Error> {
                ::serde_json::to_value(self.finalize_stats(top_n))
            }
        }
    };
}

pub(crate) use impl_protocol_stats_collector;

use std::collections::{HashMap, HashSet};

use packet_dissector_core::packet::Packet;
use serde::Serialize;

use crate::serialize::format_timestamp;

// Re-export per-protocol stats output types so they remain part of the public
// API without requiring callers to reach into sub-modules.
pub use arp::ArpStats;
pub use bgp::BgpStats;
pub use dhcp::DhcpStats;
pub use dhcpv6::Dhcpv6Stats;
pub use diameter::DiameterStats;
pub use dns::DnsStats;
pub use geneve::GeneveStats;
pub use gre::GreStats;
pub use gtpv1u::Gtpv1uStats;
pub use gtpv2c::Gtpv2cStats;
pub use http::HttpStats;
pub use http2::Http2Stats;
pub use icmp::{IcmpStats, Icmpv6Stats};
pub use igmp::IgmpStats;
pub use lldp::LldpStats;
pub use mdns::MdnsStats;
pub use nas5g::Nas5gStats;
pub use ngap::NgapStats;
pub use ntp::NtpStats;
pub use ospf::OspfStats;
pub use pfcp::PfcpStats;
pub use radius::RadiusStats;
pub use rtp::RtpStats;
pub use sctp::SctpStats;
pub use sip::SipStats;
pub use stun::StunStats;
pub use tls::TlsStats;
pub use vxlan::VxlanStats;

use arp::ArpStatsCollector;
use bgp::BgpStatsCollector;
use dhcp::DhcpStatsCollector;
use dhcpv6::Dhcpv6StatsCollector;
use diameter::DiameterStatsCollector;
use dns::DnsStatsCollector;
use geneve::GeneveStatsCollector;
use gre::GreStatsCollector;
use gtpv1u::Gtpv1uStatsCollector;
use gtpv2c::Gtpv2cStatsCollector;
use http::HttpStatsCollector;
use http2::Http2StatsCollector;
use icmp::{IcmpStatsCollector, Icmpv6StatsCollector};
use igmp::IgmpStatsCollector;
use lldp::LldpStatsCollector;
use mdns::MdnsStatsCollector;
use nas5g::Nas5gStatsCollector;
use ngap::NgapStatsCollector;
use ntp::NtpStatsCollector;
use ospf::OspfStatsCollector;
use pfcp::PfcpStatsCollector;
use radius::RadiusStatsCollector;
use rtp::RtpStatsCollector;
use sctp::SctpStatsCollector;
use sip::SipStatsCollector;
use stun::StunStatsCollector;
use tcp_streams::TcpStreamCollector;
use tls::TlsStatsCollector;
use top_talkers::TopTalkersCollector;
use vxlan::VxlanStatsCollector;

// ---------------------------------------------------------------------------
// Protocol stats collector trait
// ---------------------------------------------------------------------------

/// Trait for protocol-specific stats collectors.
///
/// Implementations are stored in [`StatsCollector`] and dispatched dynamically
/// during packet processing.
pub trait ProtocolStatsCollector {
    /// Protocol key used in the output JSON (e.g. `"dns"`, `"http"`).
    fn key(&self) -> &'static str;
    /// Process a single dissected packet.
    fn process_packet(&mut self, packet: &Packet, timestamp: Option<f64>);
    /// Produce final stats as a JSON value.
    fn finalize(self: Box<Self>, top_n: usize) -> Result<serde_json::Value, serde_json::Error>;
}

// ---------------------------------------------------------------------------
// StatsFlags
// ---------------------------------------------------------------------------

/// Flags controlling which stats collectors are enabled.
///
/// Protocol collectors are identified by name (e.g. `"dns"`, `"http"`) via a
/// [`HashSet`] so that adding a new protocol never requires changing this type.
#[derive(Debug, Clone, Default)]
pub struct StatsFlags {
    /// Protocol keys to enable (e.g. `"dns"`, `"http"`).
    pub protocols: HashSet<String>,
    pub top_talkers: bool,
    pub tcp_streams: bool,
}

impl StatsFlags {
    /// Build flags from a list of normalised protocol names.
    pub fn from_protocols(proto_norm: &[String], top_talkers: bool, tcp_streams: bool) -> Self {
        Self {
            protocols: proto_norm.iter().cloned().collect(),
            top_talkers,
            tcp_streams,
        }
    }

    /// Return flags that enable **all** known protocol collectors.
    pub fn all_protocols(top_talkers: bool, tcp_streams: bool) -> Self {
        Self {
            protocols: PROTOCOL_REGISTRY
                .iter()
                .map(|(k, _)| (*k).to_string())
                .collect(),
            top_talkers,
            tcp_streams,
        }
    }
}

// ---------------------------------------------------------------------------
// Output structures
// ---------------------------------------------------------------------------

/// Top-level stats output, serialized as JSON.
#[derive(Debug, Clone, Serialize)]
pub struct StatsOutput {
    /// Discriminator for JSONL consumers (`"stats"`).
    #[serde(rename = "type")]
    pub record_type: String,
    pub total_packets: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_start: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_end: Option<String>,
    pub duration_secs: f64,
    pub protocols: HashMap<String, u64>,
    /// Protocol-specific deep statistics, keyed by protocol name (e.g. `"dns"`,
    /// `"http"`).  Each value is the JSON produced by the protocol's
    /// [`ProtocolStatsCollector::finalize`] implementation.
    #[serde(flatten)]
    pub protocol_stats: HashMap<String, serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_talkers: Option<Vec<TalkerEntry>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tcp_streams: Option<Vec<TcpStreamEntry>>,
}

/// A name/count pair used for frequency tables.
#[derive(Debug, Clone, Serialize)]
pub struct CountEntry {
    pub name: String,
    pub count: u64,
}

/// Percentile statistics for response times (seconds).
#[derive(Debug, Clone, Serialize)]
pub struct ResponseTimeStats {
    pub min: f64,
    pub max: f64,
    pub mean: f64,
    pub median: f64,
    pub p95: f64,
    pub p99: f64,
    pub count: u64,
}

/// A single entry in the top-talkers list.
#[derive(Debug, Clone, Serialize)]
pub struct TalkerEntry {
    pub src: String,
    pub dst: String,
    pub packets: u64,
    pub bytes: u64,
}

/// Per-stream summary for TCP stream statistics.
#[derive(Debug, Clone, Serialize)]
pub struct TcpStreamEntry {
    pub stream_id: u32,
    pub src: String,
    pub src_port: u16,
    pub dst: String,
    pub dst_port: u16,
    pub packets: u64,
    pub bytes: u64,
    pub duration_secs: f64,
}

// ---------------------------------------------------------------------------
// Protocol registry
// ---------------------------------------------------------------------------

/// Constructor function that creates a boxed [`ProtocolStatsCollector`].
type CollectorCtor = fn() -> Box<dyn ProtocolStatsCollector>;

/// Registry of all known protocol stats collectors.
///
/// Each entry maps a protocol key (e.g. `"dns"`) to a constructor function that
/// creates its collector.  Adding a new protocol requires only one new line
/// here (plus the corresponding module).
pub static PROTOCOL_REGISTRY: &[(&str, CollectorCtor)] = &[
    ("dns", || Box::new(DnsStatsCollector::new())),
    ("http", || Box::new(HttpStatsCollector::new())),
    ("tls", || Box::new(TlsStatsCollector::new())),
    ("dhcp", || Box::new(DhcpStatsCollector::new())),
    ("dhcpv6", || Box::new(Dhcpv6StatsCollector::new())),
    ("sip", || Box::new(SipStatsCollector::new())),
    ("rtp", || Box::new(RtpStatsCollector::new())),
    ("bgp", || Box::new(BgpStatsCollector::new())),
    ("ospf", || Box::new(OspfStatsCollector::new())),
    ("radius", || Box::new(RadiusStatsCollector::new())),
    ("diameter", || Box::new(DiameterStatsCollector::new())),
    ("gtpv1u", || Box::new(Gtpv1uStatsCollector::new())),
    ("gtpv2c", || Box::new(Gtpv2cStatsCollector::new())),
    ("pfcp", || Box::new(PfcpStatsCollector::new())),
    ("vxlan", || Box::new(VxlanStatsCollector::new())),
    ("gre", || Box::new(GreStatsCollector::new())),
    ("geneve", || Box::new(GeneveStatsCollector::new())),
    ("ntp", || Box::new(NtpStatsCollector::new())),
    ("sctp", || Box::new(SctpStatsCollector::new())),
    ("http2", || Box::new(Http2StatsCollector::new())),
    ("icmp", || Box::new(IcmpStatsCollector::new())),
    ("icmpv6", || Box::new(Icmpv6StatsCollector::new())),
    ("arp", || Box::new(ArpStatsCollector::new())),
    ("lldp", || Box::new(LldpStatsCollector::new())),
    ("stun", || Box::new(StunStatsCollector::new())),
    ("nas5g", || Box::new(Nas5gStatsCollector::new())),
    ("igmp", || Box::new(IgmpStatsCollector::new())),
    ("mdns", || Box::new(MdnsStatsCollector::new())),
    ("ngap", || Box::new(NgapStatsCollector::new())),
];

// ---------------------------------------------------------------------------
// Top-level collector
// ---------------------------------------------------------------------------

/// Orchestrates all sub-collectors in a single pass.
pub struct StatsCollector {
    total_packets: u64,
    first_ts: Option<(u64, u32)>,
    last_ts: Option<(u64, u32)>,
    proto_counts: HashMap<&'static str, u64>,
    protocol_collectors: Vec<Box<dyn ProtocolStatsCollector>>,
    top_talkers: Option<TopTalkersCollector>,
    tcp_streams: Option<TcpStreamCollector>,
}

impl StatsCollector {
    /// Create a new stats collector from [`StatsFlags`].
    pub fn from_flags(flags: &StatsFlags) -> Self {
        let protocol_collectors: Vec<Box<dyn ProtocolStatsCollector>> = PROTOCOL_REGISTRY
            .iter()
            .filter(|(key, _)| flags.protocols.contains(*key))
            .map(|(_, ctor)| ctor())
            .collect();

        Self {
            total_packets: 0,
            first_ts: None,
            last_ts: None,
            proto_counts: HashMap::new(),
            protocol_collectors,
            top_talkers: if flags.top_talkers {
                Some(TopTalkersCollector::new())
            } else {
                None
            },
            tcp_streams: if flags.tcp_streams {
                Some(TcpStreamCollector::new())
            } else {
                None
            },
        }
    }

    /// Record packet metadata (count, timestamps) unconditionally — even when
    /// dissection fails — so that `total_packets` and duration are accurate.
    ///
    /// Timestamps of (0, 0) are treated as unknown (e.g. pcapng
    /// `SimplePacket` blocks) and ignored for start/end/duration computation.
    pub fn record_meta(&mut self, timestamp_secs: u64, timestamp_usecs: u32) {
        self.total_packets += 1;
        // Ignore (0, 0) timestamps — they indicate missing timestamp data.
        if timestamp_secs == 0 && timestamp_usecs == 0 {
            return;
        }
        let ts = (timestamp_secs, timestamp_usecs);
        match self.first_ts {
            Some(cur) if ts < cur => self.first_ts = Some(ts),
            None => self.first_ts = Some(ts),
            _ => {}
        }
        match self.last_ts {
            Some(cur) if ts > cur => self.last_ts = Some(ts),
            None => self.last_ts = Some(ts),
            _ => {}
        }
    }

    /// Feed a dissected packet into all active collectors.
    pub fn process_packet(
        &mut self,
        packet: &Packet,
        timestamp_secs: u64,
        timestamp_usecs: u32,
        original_length: u32,
    ) {
        for layer in packet.layers() {
            *self.proto_counts.entry(layer.name).or_insert(0) += 1;
        }

        // Treat (0, 0) as missing timestamp (see `record_meta`).
        let timestamp = if timestamp_secs != 0 || timestamp_usecs != 0 {
            Some(timestamp_secs as f64 + timestamp_usecs as f64 / 1_000_000.0)
        } else {
            None
        };

        for collector in &mut self.protocol_collectors {
            collector.process_packet(packet, timestamp);
        }
        if let Some(tcp) = &mut self.tcp_streams {
            tcp.process_packet(packet, original_length, timestamp);
        }
        if let Some(tt) = &mut self.top_talkers {
            tt.process_packet(packet, original_length);
        }
    }

    /// Produce the final output structure.
    pub fn finalize(self, top_n: usize) -> StatsOutput {
        let duration_secs = match (self.first_ts, self.last_ts) {
            (Some((s1, us1)), Some((s2, us2))) => {
                let raw =
                    (s2 as f64 + us2 as f64 / 1_000_000.0) - (s1 as f64 + us1 as f64 / 1_000_000.0);
                (raw * 1_000.0).round() / 1_000.0
            }
            _ => 0.0,
        };

        let time_start = self.first_ts.map(|(s, us)| format_timestamp(s, us));
        let time_end = self.last_ts.map(|(s, us)| format_timestamp(s, us));

        let protocol_stats: HashMap<String, serde_json::Value> = self
            .protocol_collectors
            .into_iter()
            .filter_map(|c| {
                let key = c.key().to_string();
                match c.finalize(top_n) {
                    Ok(val) => Some((key, val)),
                    Err(_) => None,
                }
            })
            .collect();

        StatsOutput {
            record_type: "stats".to_string(),
            total_packets: self.total_packets,
            time_start,
            time_end,
            duration_secs,
            protocols: self
                .proto_counts
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            protocol_stats,
            top_talkers: self.top_talkers.map(|t| t.finalize(top_n)),
            tcp_streams: self.tcp_streams.map(|t| t.finalize(top_n)),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::test_helpers::{build_dns_query_buf, pkt};
    use super::*;
    use helpers::{compute_response_time_stats, percentile};
    use packet_dissector_core::packet::DissectBuffer;

    /// Create [`StatsFlags`] for test compatibility.
    fn test_flags(dns: bool, top_talkers: bool, tcp_streams: bool) -> StatsFlags {
        let protocols = if dns {
            HashSet::from(["dns".to_string()])
        } else {
            HashSet::new()
        };
        StatsFlags {
            protocols,
            top_talkers,
            tcp_streams,
        }
    }

    // -----------------------------------------------------------------------
    // StatsCollector integration tests
    // -----------------------------------------------------------------------

    #[test]
    fn stats_collector_empty_capture() {
        let collector = StatsCollector::from_flags(&test_flags(true, true, true));
        let output = collector.finalize(10);
        assert_eq!(output.total_packets, 0);
        assert_eq!(output.duration_secs, 0.0);
        assert_eq!(output.record_type, "stats");
    }

    #[test]
    fn stats_collector_dns_only() {
        let mut collector = StatsCollector::from_flags(&test_flags(true, false, false));
        let buf = build_dns_query_buf(1, "example.com", 1);
        collector.record_meta(1_000_000, 0);
        collector.process_packet(&pkt(&buf), 1_000_000, 0, 64);
        let output = collector.finalize(10);
        assert_eq!(output.total_packets, 1);
        assert!(output.protocol_stats.contains_key("dns"));
        assert!(output.top_talkers.is_none());
        assert!(output.tcp_streams.is_none());
    }

    #[test]
    fn stats_collector_disabled_collectors() {
        let mut collector = StatsCollector::from_flags(&test_flags(false, false, false));
        let buf = build_dns_query_buf(1, "example.com", 1);
        collector.record_meta(1_000_000, 0);
        collector.process_packet(&pkt(&buf), 1_000_000, 0, 64);
        let output = collector.finalize(10);
        assert_eq!(output.total_packets, 1);
        assert!(!output.protocol_stats.contains_key("dns"));
        assert!(output.top_talkers.is_none());
        assert!(output.tcp_streams.is_none());
    }

    #[test]
    fn stats_collector_duration_calculation() {
        let mut collector = StatsCollector::from_flags(&test_flags(false, false, false));
        let buf = DissectBuffer::new();
        collector.record_meta(100, 0);
        collector.process_packet(&pkt(&buf), 100, 0, 64);
        collector.record_meta(110, 500_000);
        collector.process_packet(&pkt(&buf), 110, 500_000, 64);
        let output = collector.finalize(10);
        assert!((output.duration_secs - 10.5).abs() < 0.01);
    }

    #[test]
    fn stats_collector_ignores_zero_timestamps() {
        let mut collector = StatsCollector::from_flags(&test_flags(false, false, false));
        collector.record_meta(0, 0); // SimplePacket — no timestamp
        collector.record_meta(100, 0);
        collector.record_meta(0, 0); // another zero
        collector.record_meta(200, 0);
        let output = collector.finalize(10);
        assert_eq!(output.total_packets, 4);
        // Duration should be 200 - 100 = 100, not affected by zero timestamps.
        assert!((output.duration_secs - 100.0).abs() < 0.01);
        assert!(output.time_start.is_some());
        assert!(output.time_end.is_some());
    }

    #[test]
    fn stats_collector_all_zero_timestamps() {
        let mut collector = StatsCollector::from_flags(&test_flags(false, false, false));
        collector.record_meta(0, 0);
        collector.record_meta(0, 0);
        let output = collector.finalize(10);
        assert_eq!(output.total_packets, 2);
        assert_eq!(output.duration_secs, 0.0);
        assert!(output.time_start.is_none());
        assert!(output.time_end.is_none());
    }

    // -----------------------------------------------------------------------
    // Percentile helper tests
    // -----------------------------------------------------------------------

    #[test]
    fn percentile_single_value() {
        assert!((percentile(&[5.0], 50.0) - 5.0).abs() < 1e-9);
        assert!((percentile(&[5.0], 99.0) - 5.0).abs() < 1e-9);
    }

    #[test]
    fn percentile_two_values() {
        let vals = [1.0, 3.0];
        assert!((percentile(&vals, 0.0) - 1.0).abs() < 1e-9);
        assert!((percentile(&vals, 50.0) - 2.0).abs() < 1e-9);
        assert!((percentile(&vals, 100.0) - 3.0).abs() < 1e-9);
    }

    #[test]
    fn percentile_ten_values() {
        let vals: Vec<f64> = (1..=10).map(|i| i as f64).collect();
        let median = percentile(&vals, 50.0);
        assert!((median - 5.5).abs() < 1e-9);
    }

    #[test]
    fn response_time_stats_empty() {
        assert!(compute_response_time_stats(Vec::new()).is_none());
    }

    #[test]
    fn response_time_stats_single() {
        let stats = compute_response_time_stats(vec![0.42]).expect("should produce stats");
        assert_eq!(stats.count, 1);
        assert!((stats.min - 0.42).abs() < 1e-9);
        assert!((stats.max - 0.42).abs() < 1e-9);
        assert!((stats.mean - 0.42).abs() < 1e-9);
    }

    // -----------------------------------------------------------------------
    // Serialization tests
    // -----------------------------------------------------------------------

    #[test]
    fn stats_output_serializes_to_json() {
        let output = StatsOutput {
            record_type: "stats".to_string(),
            total_packets: 100,
            time_start: None,
            time_end: None,
            duration_secs: 5.0,
            protocols: HashMap::new(),
            protocol_stats: HashMap::new(),
            top_talkers: None,
            tcp_streams: None,
        };
        let json = serde_json::to_string(&output).expect("serialize");
        assert!(json.contains("\"type\":\"stats\""));
        assert!(json.contains("\"total_packets\":100"));
        assert!(json.contains("\"protocols\""));
        // None fields should be omitted
        assert!(!json.contains("\"dns\""));
        assert!(!json.contains("\"top_talkers\""));
    }

    #[test]
    fn stats_output_with_dns_serializes() {
        let dns_stats = DnsStats {
            total_queries: 5,
            total_responses: 5,
            top_query_names: vec![CountEntry {
                name: "example.com".to_string(),
                count: 5,
            }],
            query_type_distribution: vec![CountEntry {
                name: "A".to_string(),
                count: 5,
            }],
            rcode_distribution: vec![CountEntry {
                name: "NOERROR".to_string(),
                count: 5,
            }],
            response_time: Some(ResponseTimeStats {
                min: 0.001,
                max: 0.1,
                mean: 0.05,
                median: 0.04,
                p95: 0.09,
                p99: 0.1,
                count: 5,
            }),
        };
        let output = StatsOutput {
            record_type: "stats".to_string(),
            total_packets: 10,
            time_start: Some("2024-01-15T12:30:00.000000Z".to_string()),
            time_end: Some("2024-01-15T12:30:01.000000Z".to_string()),
            duration_secs: 1.0,
            protocols: HashMap::from([("DNS".to_string(), 10)]),
            protocol_stats: HashMap::from([(
                "dns".to_string(),
                serde_json::to_value(dns_stats).expect("serialize"),
            )]),
            top_talkers: None,
            tcp_streams: None,
        };
        let json = serde_json::to_string(&output).expect("serialize");
        assert!(json.contains("\"dns\""));
        assert!(json.contains("\"top_query_names\""));
        assert!(json.contains("\"response_time\""));
    }
}
