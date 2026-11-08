//! What the fields sidebar lists, worked out from the sampled field stats:
//! the pinned fields, the key ones, and every field grouped by
//! protocol and by the protocol's stack position.

use dsct::session::fields::{FieldKind, FieldStats, FieldSummary, Sample, ValueCount, shown_value};
use packet_dissector_core::dissector::ProtocolLayer;

/// Fields listed under "Key fields" at most.
pub const KEY_FIELDS: usize = 8;

/// Key fields of one protocol at most, so one protocol does not crowd out
/// the others (the ports, a tunnel's ID).
const KEY_FIELDS_PER_PROTOCOL: usize = 4;

/// Top values shown for an expanded field at most.
pub const TOP_VALUES: usize = 5;

/// Stack positions in the order the sidebar lists them: what a packet
/// carries first, the link it travelled over last.
const LAYER_ORDER: [ProtocolLayer; 5] = [
    ProtocolLayer::Application,
    ProtocolLayer::Tunnel,
    ProtocolLayer::Transport,
    ProtocolLayer::Network,
    ProtocolLayer::Link,
];

/// Where a stack position is listed; positions the app does not know yet
/// (the enum is non-exhaustive) and protocols without one come last.
pub fn layer_rank(layer: Option<ProtocolLayer>) -> usize {
    layer
        .and_then(|l| LAYER_ORDER.iter().position(|&o| o == l))
        .unwrap_or(LAYER_ORDER.len())
}

/// The heading of a stack position.
pub fn layer_title(layer: Option<ProtocolLayer>) -> &'static str {
    match layer {
        Some(ProtocolLayer::Application) => "Application",
        Some(ProtocolLayer::Tunnel) => "Tunnel",
        Some(ProtocolLayer::Transport) => "Transport",
        Some(ProtocolLayer::Network) => "Network",
        Some(ProtocolLayer::Link) => "Link",
        _ => "Other",
    }
}

/// Whether a stack position starts expanded.
pub fn layer_open_by_default(layer: Option<ProtocolLayer>) -> bool {
    matches!(
        layer,
        Some(ProtocolLayer::Application | ProtocolLayer::Transport)
    )
}

/// The short type mark beside a field name.
pub fn kind_badge(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Number => "123",
        FieldKind::Address => "addr",
        FieldKind::Text => "abc",
    }
}

/// Whether `path` matches the search `query` (case-insensitive substring).
pub fn matches(path: &str, query: &str) -> bool {
    query.is_empty() || path.to_lowercase().contains(&query.to_lowercase())
}

/// One protocol and its fields.
pub struct ProtocolGroup<'a> {
    pub name: &'static str,
    pub packets: u64,
    pub fields: Vec<&'a FieldSummary>,
}

/// One stack position and its protocols.
pub struct LayerGroup<'a> {
    pub layer: Option<ProtocolLayer>,
    pub packets: u64,
    pub protocols: Vec<ProtocolGroup<'a>>,
}

/// Every field matching `query`, by stack position (in [`layer_rank`]
/// order) and protocol (in the order they appeared). Protocols whose name
/// matches keep all their fields; others without a matching field are left
/// out.
pub fn by_layer<'a>(stats: &'a FieldStats, query: &str) -> Vec<LayerGroup<'a>> {
    let mut groups: Vec<LayerGroup<'a>> = Vec::new();
    for protocol in &stats.protocols {
        let all = matches(protocol.name, query);
        let fields: Vec<&FieldSummary> = stats
            .fields
            .iter()
            .filter(|f| f.protocol == protocol.name && (all || matches(&f.path, query)))
            .collect();
        if fields.is_empty() && !all {
            continue;
        }
        let group = ProtocolGroup {
            name: protocol.name,
            packets: protocol.packets,
            fields,
        };
        match groups.iter_mut().find(|g| g.layer == protocol.layer) {
            Some(layer) => layer.protocols.push(group),
            None => groups.push(LayerGroup {
                layer: protocol.layer,
                packets: stats
                    .layers
                    .iter()
                    .find(|l| Some(l.layer) == protocol.layer)
                    .map_or(protocol.packets, |l| l.packets),
                protocols: vec![group],
            }),
        }
    }
    groups.sort_by_key(|g| layer_rank(g.layer));
    for group in &mut groups {
        if group.layer.is_none() {
            group.packets = group.protocols.iter().map(|p| p.packets).max().unwrap_or(0);
        }
    }
    groups
}

/// Whether the field at `path` measures or counts its packet rather than
/// tells what it is: a length, a checksum, or a sequence or acknowledgment
/// number (which repeat across pure ACKs and retransmissions, so their
/// values can look grouped).
pub fn is_measure(path: &str) -> bool {
    let name = path.rsplit('.').next().unwrap_or(path);
    name.ends_with("length")
        || name.ends_with("_len")
        || name.contains("checksum")
        || matches!(
            name,
            "seq" | "ack" | "sequence_number" | "acknowledgment_number"
        )
        || name.ends_with("_seq")
}

/// Whether the field's values sort packets into a few groups: one value
/// in most packets (not a repeated field, such as each header of a
/// message), and its most frequent values cover at least half of the
/// packets that have it (not IDs, nearly unique per packet).
fn groups_packets(field: &FieldSummary) -> bool {
    let covered: u64 = field.top.iter().map(|v| v.packets).sum();
    field.multi_valued * 2 <= field.packets
        && covered * 2 >= field.packets
        && field.distinct as u64 * 2 <= field.packets.max(2)
}

/// The fields worth a look first: those dsct shows by default
/// ([`FieldSummary::key`]) that group packets (see [`groups_packets`]),
/// are not lengths or checksums ([`is_measure`]), not pinned, and match
/// `query`, at most [`KEY_FIELDS_PER_PROTOCOL`] of a protocol. Fields with
/// several values come first, then the constant ones; each group runs from
/// the application layer down, a layer's fields with the most values first
/// (then in the order they appeared).
pub fn key_fields<'a>(
    stats: &'a FieldStats,
    pinned: &[String],
    query: &str,
) -> Vec<&'a FieldSummary> {
    let layer_of = |protocol: &str| {
        stats
            .protocols
            .iter()
            .find(|p| p.name == protocol)
            .and_then(|p| p.layer)
    };
    let mut fields: Vec<&FieldSummary> = stats
        .fields
        .iter()
        .filter(|f| {
            f.key
                && groups_packets(f)
                && !is_measure(&f.path)
                && !pinned.contains(&f.path)
                && matches(&f.path, query)
        })
        .collect();
    // Stable: equal fields keep the order they appeared in.
    fields.sort_by_key(|f| {
        (
            f.distinct < 2,
            layer_rank(layer_of(f.protocol)),
            std::cmp::Reverse(f.distinct),
        )
    });
    let mut per_protocol: Vec<(&str, usize)> = Vec::new();
    fields.retain(|f| {
        match per_protocol.iter_mut().find(|(p, _)| *p == f.protocol) {
            Some((_, n)) if *n >= KEY_FIELDS_PER_PROTOCOL => return false,
            Some((_, n)) => *n += 1,
            None => per_protocol.push((f.protocol, 1)),
        }
        true
    });
    fields.truncate(KEY_FIELDS);
    fields
}

/// The line above an expanded field's top values.
pub fn values_title(field: &FieldSummary, sampled: u64) -> String {
    let shown = field.top.len().min(TOP_VALUES);
    let of = if field.distinct_capped {
        format!("{}+", field.distinct)
    } else {
        field.distinct.to_string()
    };
    let top = if field.distinct > shown {
        format!("Top {shown} of {of} values")
    } else if shown == 1 {
        "1 value".to_string()
    } else {
        format!("{shown} values")
    };
    format!(
        "{top} · in {} of {} packets",
        grouped(field.packets),
        grouped(sampled)
    )
}

/// `n` with thousands separators (`"12,345"`).
pub fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// A value as listed: `"1 (A)"` when the dissector names it.
pub fn value_text(value: &ValueCount) -> String {
    shown_value(&value.value, value.label)
}

/// `count` as a share of `total`, from 0 to 1.
pub fn share(count: u64, total: u64) -> f32 {
    if total == 0 {
        0.
    } else {
        (count as f64 / total as f64) as f32
    }
}

/// `count` of `total` as a percentage with one decimal (`"12.5%"`).
pub fn percent_text(count: u64, total: u64) -> String {
    format!("{:.1}%", share(count, total) * 100.)
}

/// How many displayed packets the sidebar counts values over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SampleSize {
    #[default]
    Small,
    Large,
    All,
}

impl SampleSize {
    pub const ALL: [SampleSize; 3] = [SampleSize::Small, SampleSize::Large, SampleSize::All];

    /// Packets to sample at most (`None` = every displayed packet).
    pub fn limit(self) -> Option<usize> {
        match self {
            SampleSize::Small => Some(5_000),
            SampleSize::Large => Some(50_000),
            SampleSize::All => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SampleSize::Small => "5,000 packets",
            SampleSize::Large => "50,000 packets",
            SampleSize::All => "All displayed packets",
        }
    }

    /// The sample to count over: `spread` takes packets from the whole
    /// range instead of the first ones.
    pub fn sample(self, spread: bool) -> Sample {
        match (self.limit(), spread) {
            (None, _) => Sample::All,
            (Some(n), true) => Sample::Spread(n),
            (Some(n), false) => Sample::First(n),
        }
    }
}

/// The note under the search box: what the counts cover.
pub fn sample_note(stats: &FieldStats) -> String {
    if stats.sampled < stats.displayed {
        let how = match stats.sample {
            Sample::Spread(_) => "spread across",
            _ => "from the start of",
        };
        format!(
            "Counted over {} packets {how} the {} displayed",
            grouped(stats.sampled),
            grouped(stats.displayed)
        )
    } else {
        format!(
            "Counted over all {} displayed packets",
            grouped(stats.sampled)
        )
    }
}

#[cfg(test)]
mod tests {
    use dsct::session::fields::{LayerSummary, ProtocolSummary};

    use super::*;

    fn field(
        path: &str,
        protocol: &'static str,
        packets: u64,
        values: &[(&str, u64)],
    ) -> FieldSummary {
        const KEYS: [&str; 10] = [
            "ethernet.src",
            "ipv4.ttl",
            "ipv4.dst",
            "udp.dst_port",
            "udp.length",
            "dns.qname",
            "tcp.flags",
            "tcp.seq",
            "sip.headers.name",
            "sip.content_length",
        ];
        FieldSummary {
            path: path.to_string(),
            key: KEYS.contains(&path),
            protocol,
            kind: FieldKind::Number,
            packets,
            distinct: values.len(),
            distinct_capped: false,
            top: values
                .iter()
                .map(|&(v, n)| ValueCount {
                    value: v.to_string(),
                    label: None,
                    packets: n,
                })
                .collect(),
            multi_valued: 0,
        }
    }

    fn stats() -> FieldStats {
        let protocol = |name, layer, packets| ProtocolSummary {
            name,
            layer,
            packets,
        };
        FieldStats {
            sample: Sample::First(10),
            sampled: 10,
            displayed: 40,
            protocols: vec![
                protocol("Ethernet", Some(ProtocolLayer::Link), 10),
                protocol("IPv4", Some(ProtocolLayer::Network), 10),
                protocol("UDP", Some(ProtocolLayer::Transport), 6),
                protocol("DNS", Some(ProtocolLayer::Application), 6),
                protocol("TCP", Some(ProtocolLayer::Transport), 4),
                protocol("Mystery", None, 1),
            ],
            layers: vec![
                LayerSummary {
                    layer: ProtocolLayer::Link,
                    packets: 10,
                },
                LayerSummary {
                    layer: ProtocolLayer::Network,
                    packets: 10,
                },
                LayerSummary {
                    layer: ProtocolLayer::Transport,
                    packets: 10,
                },
                LayerSummary {
                    layer: ProtocolLayer::Application,
                    packets: 6,
                },
            ],
            fields: vec![
                field("ethernet.src", "Ethernet", 10, &[("aa", 10)]),
                field("ipv4.ttl", "IPv4", 10, &[("64", 10)]),
                field("ipv4.dst", "IPv4", 10, &[("1.1.1.1", 6), ("2.2.2.2", 4)]),
                field("ipv4.id", "IPv4", 10, &[("1", 1), ("2", 1), ("3", 1)]),
                field(
                    "ipv4.checksum",
                    "IPv4",
                    10,
                    &[("1", 2), ("2", 1), ("3", 1), ("4", 1), ("5", 1), ("6", 1)],
                ),
                field("udp.dst_port", "UDP", 6, &[("53", 6)]),
                field("dns.qname", "DNS", 6, &[("a", 3), ("b", 2), ("c", 1)]),
                field("tcp.flags", "TCP", 4, &[("2", 2), ("16", 2)]),
            ],
        }
    }

    #[test]
    fn layers_run_from_application_to_link() {
        let stats = stats();
        let groups = by_layer(&stats, "");
        let titles: Vec<&str> = groups.iter().map(|g| layer_title(g.layer)).collect();
        assert_eq!(
            titles,
            ["Application", "Transport", "Network", "Link", "Other"]
        );
        let transport = &groups[1];
        assert_eq!(transport.packets, 10);
        let names: Vec<&str> = transport.protocols.iter().map(|p| p.name).collect();
        assert_eq!(names, ["UDP", "TCP"]);
        assert_eq!(groups[2].protocols[0].fields.len(), 4);
        // A protocol without fields is still listed.
        assert_eq!(groups[4].protocols[0].name, "Mystery");
        assert_eq!(groups[4].packets, 1);
    }

    #[test]
    fn search_keeps_matching_fields_and_protocols() {
        let stats = stats();
        let groups = by_layer(&stats, "DST");
        let paths: Vec<&str> = groups
            .iter()
            .flat_map(|g| &g.protocols)
            .flat_map(|p| &p.fields)
            .map(|f| f.path.as_str())
            .collect();
        assert_eq!(paths, ["udp.dst_port", "ipv4.dst"]);
        let groups = by_layer(&stats, "dns");
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].protocols[0].fields.len(), 1);
    }

    #[test]
    fn key_fields_vary_first_and_run_down_the_stack() {
        let stats = stats();
        let paths = |pinned: &[String], query: &str| -> Vec<String> {
            key_fields(&stats, pinned, query)
                .iter()
                .map(|f| f.path.clone())
                .collect()
        };
        // Fields with several values, application first; then the constant
        // ones. ipv4.id and ipv4.checksum are not key fields.
        assert_eq!(
            paths(&[], ""),
            [
                "dns.qname",
                "tcp.flags",
                "ipv4.dst",
                "udp.dst_port",
                "ipv4.ttl",
                "ethernet.src"
            ]
        );
        assert_eq!(paths(&["dns.qname".to_string()], "")[0], "tcp.flags");
        assert_eq!(paths(&[], "flags"), ["tcp.flags"]);

        // A key field with a new value in nearly every packet is left out.
        let mut unique = stats.clone();
        let i = unique
            .fields
            .iter()
            .position(|f| f.path == "dns.qname")
            .unwrap();
        unique.fields[i].top = (0..6)
            .map(|i| ValueCount {
                value: i.to_string(),
                label: None,
                packets: 1,
            })
            .collect();
        unique.fields[i].distinct = 6;
        assert!(key_fields(&unique, &[], "qname").is_empty());
    }

    #[test]
    fn key_fields_leave_out_what_does_not_group_packets() {
        let mut stats = stats();
        stats.protocols.push(ProtocolSummary {
            name: "SIP",
            layer: Some(ProtocolLayer::Application),
            packets: 6,
        });
        // Lengths, whatever their values.
        stats
            .fields
            .push(field("udp.length", "UDP", 6, &[("40", 6)]));
        stats.fields.push(field(
            "sip.content_length",
            "SIP",
            6,
            &[("0", 3), ("120", 3)],
        ));
        // A field repeated in each packet (one value per header).
        let mut names = field("sip.headers.name", "SIP", 6, &[("Via", 6), ("To", 6)]);
        names.multi_valued = 6;
        stats.fields.push(names);
        // Two messages in one packet now and then still group packets.
        let mut method = field("sip.method", "SIP", 6, &[("INVITE", 4), ("ACK", 3)]);
        method.multi_valued = 1;
        method.key = true;
        stats.fields.push(method);
        // Values spread thin: the top five cover 5 of 10 packets... or less.
        let mut seq = field(
            "tcp.seq",
            "TCP",
            10,
            &[("1", 1), ("2", 1), ("3", 1), ("4", 1)],
        );
        seq.distinct = 5;
        stats.fields.push(seq);

        let paths: Vec<&str> = key_fields(&stats, &[], "")
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert_eq!(
            paths,
            [
                "dns.qname",
                "sip.method",
                "tcp.flags",
                "ipv4.dst",
                "udp.dst_port",
                "ipv4.ttl",
                "ethernet.src"
            ]
        );
    }

    #[test]
    fn key_fields_take_a_few_of_each_protocol_most_values_first() {
        let mut stats = stats();
        stats.protocols.push(ProtocolSummary {
            name: "SIP",
            layer: Some(ProtocolLayer::Application),
            packets: 6,
        });
        let mut sip = |path: &str, values: &[(&str, u64)]| {
            let packets = values.iter().map(|v| v.1).sum();
            let mut f = field(path, "SIP", packets, values);
            f.key = true;
            stats.fields.push(f);
        };
        sip("sip.is_response", &[("1", 6), ("0", 6)]);
        sip("sip.status_code", &[("200", 3), ("180", 2), ("100", 1)]);
        sip(
            "sip.reason_phrase",
            &[("OK", 3), ("Ringing", 2), ("Trying", 1)],
        );
        sip("sip.method", &[("INVITE", 2), ("ACK", 2), ("BYE", 2)]);
        sip("sip.uri", &[("a", 3), ("b", 2), ("c", 2), ("d", 1)]);
        let paths: Vec<&str> = key_fields(&stats, &[], "")
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert_eq!(
            paths[..6],
            [
                "sip.uri",
                "dns.qname",
                "sip.status_code",
                "sip.reason_phrase",
                "sip.method",
                "tcp.flags",
            ]
        );
        // Four SIP fields already: the fifth, with the fewest values, waits.
        assert!(!paths.contains(&"sip.is_response"));
    }

    #[test]
    fn lengths_checksums_and_sequence_numbers_are_measures() {
        assert!(is_measure("udp.length"));
        assert!(is_measure("ipv6.payload_length"));
        assert!(is_measure("sip.content_length"));
        assert!(is_measure("ip.header_len"));
        assert!(is_measure("tcp.checksum"));
        assert!(is_measure("udp.checksum_status"));
        assert!(is_measure("tcp.seq"));
        assert!(is_measure("tcp.ack"));
        assert!(is_measure("gtpv1u.sequence_number"));
        assert!(is_measure("esp.sequence_number"));
        assert!(!is_measure("tcp.flags"));
        assert!(!is_measure("dns.qr"));
        assert!(!is_measure("ipv4.dst"));
        assert!(!is_measure("dns.questions.name"));
        assert!(!is_measure("tcp.lenient"));
    }

    #[test]
    fn titles_and_shares() {
        let stats = stats();
        let qname = stats.field("dns.qname").unwrap();
        assert_eq!(values_title(qname, 10), "3 values · in 6 of 10 packets");
        let mut many = qname.clone();
        many.distinct = 12;
        many.distinct_capped = true;
        assert_eq!(
            values_title(&many, 10),
            "Top 3 of 12+ values · in 6 of 10 packets"
        );
        assert_eq!(
            values_title(&stats.fields[0], 10),
            "1 value · in 10 of 10 packets"
        );
        assert_eq!(percent_text(1, 8), "12.5%");
        assert_eq!(grouped(0), "0");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_000), "1,000");
        assert_eq!(grouped(1_234_567), "1,234,567");
        assert_eq!(share(1, 0), 0.);
        assert_eq!(
            sample_note(&stats),
            "Counted over 10 packets from the start of the 40 displayed"
        );
        let spread = FieldStats {
            sample: Sample::Spread(10),
            ..stats.clone()
        };
        assert_eq!(
            sample_note(&spread),
            "Counted over 10 packets spread across the 40 displayed"
        );
        let all = FieldStats {
            sample: Sample::All,
            sampled: 40,
            ..stats
        };
        assert_eq!(sample_note(&all), "Counted over all 40 displayed packets");
    }

    #[test]
    fn layer_helpers() {
        assert!(
            layer_rank(Some(ProtocolLayer::Application)) < layer_rank(Some(ProtocolLayer::Link))
        );
        assert_eq!(layer_rank(None), 5);
        assert!(layer_open_by_default(Some(ProtocolLayer::Transport)));
        assert!(!layer_open_by_default(Some(ProtocolLayer::Link)));
        assert_eq!(kind_badge(FieldKind::Address), "addr");
        assert!(matches("ipv4.src", "V4.S"));
        assert_eq!(SampleSize::Small.sample(true), Sample::Spread(5_000));
        assert_eq!(SampleSize::Large.sample(false), Sample::First(50_000));
        assert_eq!(SampleSize::All.sample(true), Sample::All);
    }
}
