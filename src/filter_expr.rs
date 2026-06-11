//! Filter expression parser.
//!
//! Parses SQL-style filter expressions into a [`FilterExpr`] tree.
//!
//! # Examples
//!
//! ```text
//! tcp                                         — protocol existence
//! ipv4.src = '10.0.0.1'                       — field comparison
//! tcp AND ipv4.src = '10.0.0.1'               — AND
//! tcp OR udp                                  — OR
//! NOT dns                                     — negation
//! (tcp OR udp) AND ipv4.src = '10.0.0.1'      — parentheses
//! tcp.dst_port > 1024                         — comparison operators
//! packet_number BETWEEN 1 AND 100             — packet number filter
//! ```

use packet_dissector_core::packet::Packet;

use crate::filter::{
    PacketNumberFilter, WhereClause, normalize_protocol_name, protocol_names_match,
};

/// Protocol names (normalized via [`normalize_protocol_name`]) whose *presence*
/// in a packet is decided by the deterministic per-packet dissection chain
/// (link / network / transport / tunnel layers), independent of TCP stream
/// reassembly.
///
/// TCP reassembly never adds or removes any of these layers — it only buffers
/// TCP payload and dispatches the reassembled bytes to an *application* layer
/// dissector (HTTP, TLS, DNS-over-TCP, …) on the segment where a PDU completes.
/// A filter that references only these protocols therefore produces the same
/// match decision whether or not earlier segments of a stream were seen, which
/// is what makes per-thread (registry-per-worker) parallel scanning sound.
///
/// This is intentionally an *allowlist*: application protocols (even
/// UDP-borne ones such as `dns`, which can also run length-prefixed over TCP)
/// are excluded so that any unrecognized or reassembly-sensitive reference
/// falls back to the sequential path.
const REASSEMBLY_INDEPENDENT_PROTOCOLS: &[&str] = &[
    "ethernet",
    "linuxsll",
    "linuxsll2",
    "ipv4",
    "ipv6",
    "arp",
    "tcp",
    "udp",
    "sctp",
    "icmp",
    "icmpv6",
    "igmp",
    "mpls",
    "gre",
    "vxlan",
    "geneve",
    "vrrp",
    "stp",
    "lacp",
    "lldp",
];

/// Protocol names (normalized) that are terminal IP/link protocols which can
/// never carry a TCP layer.  A filter that *guarantees* every matched packet
/// contains one of these is safe to evaluate — and to serialize — in parallel,
/// because such packets are never subject to TCP reassembly, so their full
/// dissection output is byte-identical to the sequential path.
const NON_TCP_TERMINAL_PROTOCOLS: &[&str] = &["arp", "icmp", "icmpv6", "igmp"];

/// A parsed filter expression.
#[derive(Debug)]
pub enum FilterExpr {
    /// Match packets containing a protocol layer with the given name.
    Protocol(String),
    /// Match packets where a field satisfies a comparison.
    Where(WhereClause),
    /// Both sub-expressions must match.
    And(Box<FilterExpr>, Box<FilterExpr>),
    /// Either sub-expression must match.
    Or(Box<FilterExpr>, Box<FilterExpr>),
    /// Negate the sub-expression.
    Not(Box<FilterExpr>),
    /// Match packets by 1-based packet number.
    PacketNumber(PacketNumberFilter),
}

impl FilterExpr {
    /// Parse a filter expression from user input.
    ///
    /// Returns `Ok(None)` for empty/blank input, `Ok(Some(expr))` for a valid
    /// filter, or `Err(msg)` when the input is non-empty but malformed.
    pub fn parse(input: &str) -> Result<Option<Self>, String> {
        let input = input.trim();
        if input.is_empty() {
            return Ok(None);
        }
        crate::sql_filter::parse(input).map(Some)
    }

    /// Test whether a dissected packet matches this expression.
    ///
    /// Shorthand for `matches_with_number(packet, 0)` — usable when no
    /// packet-number filter is present.
    #[cfg(test)]
    pub fn matches(&self, packet: &Packet) -> bool {
        self.matches_with_number(packet, 0)
    }

    /// Test whether a dissected packet matches, with a 1-based packet number
    /// for packet-number filters.
    pub fn matches_with_number(&self, packet: &Packet, number: u64) -> bool {
        match self {
            FilterExpr::Protocol(name) => packet
                .layers()
                .iter()
                .any(|l| protocol_names_match(l.name, name)),
            FilterExpr::Where(clause) => clause.matches_packet(packet),
            FilterExpr::And(a, b) => {
                a.matches_with_number(packet, number) && b.matches_with_number(packet, number)
            }
            FilterExpr::Or(a, b) => {
                a.matches_with_number(packet, number) || b.matches_with_number(packet, number)
            }
            FilterExpr::Not(e) => !e.matches_with_number(packet, number),
            FilterExpr::PacketNumber(pnf) => pnf.contains(number),
        }
    }

    /// Returns `true` if this filter's **match decision** is independent of TCP
    /// reassembly state, so it can be evaluated correctly with a separate
    /// per-thread registry over disjoint chunks of the packet index.
    ///
    /// True when every referenced protocol is in
    /// [`REASSEMBLY_INDEPENDENT_PROTOCOLS`] and no referenced field is a
    /// reassembly-metadata field (e.g. `tcp.reassembly_in_progress`).
    ///
    /// Used by the TUI's parallel filter scan, which only needs each packet's
    /// match decision (the displayed list is dissected lazily on demand).
    pub fn match_is_reassembly_independent(&self) -> bool {
        self.all_protocol_refs_in(REASSEMBLY_INDEPENDENT_PROTOCOLS)
            && !self.references_reassembly_field()
    }

    /// Returns `true` if every packet this filter can match is guaranteed to
    /// contain no TCP layer, so the packet's full dissection output is
    /// independent of TCP reassembly state.
    ///
    /// Used by the CLI `read` parallel path, where the JSONL output contains
    /// each matched packet's complete dissection: reassembly can alter the
    /// per-segment output of a TCP packet, so parallel serialization is only
    /// byte-identical to the sequential path when matched packets are never
    /// TCP segments.  This is deliberately conservative — `tcp`, `tcp.port`,
    /// `ipv4.*` and similar filters fall back to the sequential path.
    pub fn output_is_reassembly_free(&self) -> bool {
        self.guarantees_non_tcp()
    }

    /// Recursively check that every `Protocol` / `Where` reference uses a
    /// protocol in `set`.  `PacketNumber` terms reference no protocol and are
    /// always considered in-set.
    fn all_protocol_refs_in(&self, set: &[&str]) -> bool {
        match self {
            FilterExpr::Protocol(name) => set.contains(&normalize_protocol_name(name).as_str()),
            FilterExpr::Where(clause) => {
                set.contains(&normalize_protocol_name(&clause.protocol).as_str())
            }
            FilterExpr::And(a, b) | FilterExpr::Or(a, b) => {
                a.all_protocol_refs_in(set) && b.all_protocol_refs_in(set)
            }
            FilterExpr::Not(e) => e.all_protocol_refs_in(set),
            FilterExpr::PacketNumber(_) => true,
        }
    }

    /// Recursively check whether any `Where` clause references a
    /// reassembly-metadata field, whose value depends on stream state.
    fn references_reassembly_field(&self) -> bool {
        match self {
            FilterExpr::Where(clause) => clause.field.contains("reassembl"),
            FilterExpr::Protocol(_) | FilterExpr::PacketNumber(_) => false,
            FilterExpr::Not(e) => e.references_reassembly_field(),
            FilterExpr::And(a, b) | FilterExpr::Or(a, b) => {
                a.references_reassembly_field() || b.references_reassembly_field()
            }
        }
    }

    /// Recursively determine whether a match implies the packet contains no TCP
    /// layer.  For `And`, either operand guaranteeing non-TCP suffices; for
    /// `Or`, both operands must guarantee it.  `Not` and `PacketNumber` place
    /// no protocol constraint on a match, so they cannot guarantee non-TCP.
    fn guarantees_non_tcp(&self) -> bool {
        match self {
            FilterExpr::Protocol(name) => {
                NON_TCP_TERMINAL_PROTOCOLS.contains(&normalize_protocol_name(name).as_str())
            }
            FilterExpr::Where(clause) => NON_TCP_TERMINAL_PROTOCOLS
                .contains(&normalize_protocol_name(&clause.protocol).as_str()),
            FilterExpr::And(a, b) => a.guarantees_non_tcp() || b.guarantees_non_tcp(),
            FilterExpr::Or(a, b) => a.guarantees_non_tcp() && b.guarantees_non_tcp(),
            FilterExpr::Not(_) | FilterExpr::PacketNumber(_) => false,
        }
    }

    /// Returns `true` if this expression contains only `PacketNumber` filters
    /// (possibly combined with AND/OR/NOT), meaning no dissection is needed.
    pub fn is_packet_number_only(&self) -> bool {
        match self {
            FilterExpr::PacketNumber(_) => true,
            FilterExpr::Not(e) => e.is_packet_number_only(),
            FilterExpr::And(a, b) | FilterExpr::Or(a, b) => {
                a.is_packet_number_only() && b.is_packet_number_only()
            }
            FilterExpr::Protocol(_) | FilterExpr::Where(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::FieldValue;
    use packet_dissector_core::packet::DissectBuffer;
    use packet_dissector_test_alloc::test_desc;

    fn make_tcp_buf() -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Ethernet", None, &[], 0..14);
        buf.end_layer();
        buf.begin_layer("IPv4", None, &[], 14..34);
        buf.push_field(
            test_desc("src", "Source"),
            FieldValue::Ipv4Addr([10, 0, 0, 1]),
            14..18,
        );
        buf.push_field(
            test_desc("dst", "Destination"),
            FieldValue::Ipv4Addr([10, 0, 0, 2]),
            18..22,
        );
        buf.end_layer();
        buf.begin_layer("TCP", None, &[], 34..54);
        buf.push_field(
            test_desc("src_port", "Source Port"),
            FieldValue::U16(80),
            34..36,
        );
        buf.push_field(
            test_desc("dst_port", "Destination Port"),
            FieldValue::U16(12345),
            36..38,
        );
        buf.end_layer();
        buf
    }

    static EMPTY_DATA: [u8; 0] = [];

    fn make_tcp_packet_ref<'a>(buf: &'a DissectBuffer<'static>) -> Packet<'a, 'static> {
        Packet::new(buf, &EMPTY_DATA)
    }

    #[test]
    fn parse_empty() {
        assert!(FilterExpr::parse("").unwrap().is_none());
        assert!(FilterExpr::parse("   ").unwrap().is_none());
    }

    #[test]
    fn protocol_filter() {
        let expr = FilterExpr::parse("tcp").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn protocol_filter_case_insensitive() {
        let expr = FilterExpr::parse("TCP").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn protocol_filter_hyphen_insensitive() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Ethernet", None, &[], 0..14);
        buf.end_layer();
        buf.begin_layer("GTPv2-C", None, &[], 14..34);
        buf.end_layer();
        let pkt = Packet::new(&buf, &EMPTY_DATA);

        for input in &["gtpv2c", "GTPv2C", "GTPV2C"] {
            let expr = FilterExpr::parse(input).unwrap().unwrap();
            assert!(expr.matches(&pkt), "expected '{input}' to match GTPv2-C");
        }
    }

    #[test]
    fn protocol_no_match() {
        let expr = FilterExpr::parse("dns").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(!expr.matches(&pkt));
    }

    #[test]
    fn where_filter() {
        let expr = FilterExpr::parse("ipv4.src = '10.0.0.1'").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn where_filter_no_match() {
        let expr = FilterExpr::parse("ipv4.src = '192.168.1.1'")
            .unwrap()
            .unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(!expr.matches(&pkt));
    }

    #[test]
    fn and_filter() {
        let expr = FilterExpr::parse("tcp AND ipv4.src = '10.0.0.1'")
            .unwrap()
            .unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn and_filter_partial_fail() {
        let expr = FilterExpr::parse("dns AND ipv4.src = '10.0.0.1'")
            .unwrap()
            .unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(!expr.matches(&pkt));
    }

    #[test]
    fn or_filter() {
        let expr = FilterExpr::parse("tcp OR dns").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn or_filter_both_fail() {
        let expr = FilterExpr::parse("dns OR sip").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(!expr.matches(&pkt));
    }

    #[test]
    fn and_or_precedence() {
        // SQL standard: AND binds tighter than OR
        // (dns AND ipv4.src = '10.0.0.1') OR tcp → false OR true = true
        let expr = FilterExpr::parse("dns AND ipv4.src = '10.0.0.1' OR tcp")
            .unwrap()
            .unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn multiple_or() {
        let expr = FilterExpr::parse(
            "ipv4.src = '1.2.3.4' OR ipv4.src = '10.0.0.1' OR ipv4.src = '5.6.7.8'",
        )
        .unwrap()
        .unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn where_filter_numeric() {
        let expr = FilterExpr::parse("tcp.dst_port = 80").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(!expr.matches(&pkt)); // dst_port is 12345, not 80
    }

    #[test]
    fn where_filter_quoted_string() {
        let expr = FilterExpr::parse("ipv4.src = '10.0.0.1'").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn not_protocol() {
        let expr = FilterExpr::parse("NOT dns").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn not_protocol_negative() {
        let expr = FilterExpr::parse("NOT tcp").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(!expr.matches(&pkt));
    }

    #[test]
    fn not_where() {
        let expr = FilterExpr::parse("NOT ipv4.src = '192.168.1.1'")
            .unwrap()
            .unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn double_not() {
        let expr = FilterExpr::parse("NOT NOT tcp").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn not_and_precedence() {
        // NOT dns AND tcp → (NOT dns) AND tcp → true AND true = true
        let expr = FilterExpr::parse("NOT dns AND tcp").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn not_or_precedence() {
        // NOT tcp OR dns → (NOT tcp) OR dns → false OR false = false
        let expr = FilterExpr::parse("NOT tcp OR dns").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(!expr.matches(&pkt));
    }

    #[test]
    fn not_case_insensitive() {
        let expr = FilterExpr::parse("not tcp").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(!expr.matches(&pkt));
    }

    // --- Parentheses (new capability) ---

    #[test]
    fn parentheses_grouping() {
        // Without parens: tcp OR dns AND ipv4.src = '10.0.0.1'
        //   → tcp OR (dns AND ipv4.src = ...) → true
        // With parens: (tcp OR dns) AND ipv4.src = '10.0.0.2'
        //   → true AND false → false
        let expr = FilterExpr::parse("(tcp OR dns) AND ipv4.src = '10.0.0.2'")
            .unwrap()
            .unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(!expr.matches(&pkt));
    }

    // --- Comparison operators (new capability) ---

    #[test]
    fn gt_filter() {
        let expr = FilterExpr::parse("tcp.src_port > 79").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt)); // src_port = 80
    }

    #[test]
    fn lt_filter() {
        let expr = FilterExpr::parse("tcp.src_port < 81").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    #[test]
    fn ne_filter() {
        let expr = FilterExpr::parse("tcp.src_port != 81").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    // --- packet_number ---

    #[test]
    fn packet_number_eq() {
        let expr = FilterExpr::parse("packet_number = 5").unwrap().unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches_with_number(&pkt, 5));
        assert!(!expr.matches_with_number(&pkt, 4));
    }

    #[test]
    fn packet_number_between() {
        let expr = FilterExpr::parse("packet_number BETWEEN 10 AND 20")
            .unwrap()
            .unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches_with_number(&pkt, 10));
        assert!(expr.matches_with_number(&pkt, 15));
        assert!(expr.matches_with_number(&pkt, 20));
        assert!(!expr.matches_with_number(&pkt, 9));
    }

    #[test]
    fn packet_number_in_list() {
        let expr = FilterExpr::parse("packet_number IN (1, 5, 10)")
            .unwrap()
            .unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches_with_number(&pkt, 1));
        assert!(expr.matches_with_number(&pkt, 5));
        assert!(!expr.matches_with_number(&pkt, 3));
    }

    #[test]
    fn packet_number_combined_with_protocol() {
        let expr = FilterExpr::parse("packet_number BETWEEN 1 AND 100 AND tcp")
            .unwrap()
            .unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches_with_number(&pkt, 50));
        assert!(!expr.matches_with_number(&pkt, 150));
    }

    #[test]
    fn packet_number_only_detection() {
        let pn = FilterExpr::parse("packet_number BETWEEN 1 AND 100")
            .unwrap()
            .unwrap();
        assert!(pn.is_packet_number_only());

        let mixed = FilterExpr::parse("packet_number = 1 AND tcp")
            .unwrap()
            .unwrap();
        assert!(!mixed.is_packet_number_only());

        let not_pn = FilterExpr::parse("NOT packet_number = 5").unwrap().unwrap();
        assert!(not_pn.is_packet_number_only());
    }

    // --- BETWEEN for fields ---

    #[test]
    fn between_filter() {
        let expr = FilterExpr::parse("tcp.src_port BETWEEN 70 AND 90")
            .unwrap()
            .unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt)); // src_port = 80
    }

    // --- IN for fields ---

    #[test]
    fn in_filter() {
        let expr = FilterExpr::parse("tcp.src_port IN (22, 80, 443)")
            .unwrap()
            .unwrap();
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        assert!(expr.matches(&pkt));
    }

    // --- Reassembly-safety predicates ---

    fn parse(input: &str) -> FilterExpr {
        FilterExpr::parse(input).unwrap().unwrap()
    }

    #[test]
    fn match_independent_for_transport_and_below() {
        for input in [
            "tcp",
            "udp",
            "tcp.dst_port > 1024",
            "ipv4.src = '10.0.0.1'",
            "tcp AND ipv4.src = '10.0.0.1'",
            "(tcp OR udp) AND NOT arp",
            "packet_number BETWEEN 1 AND 100",
            "vxlan",
        ] {
            assert!(
                parse(input).match_is_reassembly_independent(),
                "{input} should be reassembly-independent"
            );
        }
    }

    #[test]
    fn match_dependent_for_app_over_tcp() {
        for input in ["http", "tls", "dns", "sip", "bgp", "tcp OR http"] {
            assert!(
                !parse(input).match_is_reassembly_independent(),
                "{input} should require the sequential path"
            );
        }
    }

    #[test]
    fn match_dependent_for_reassembly_metadata_field() {
        assert!(
            !parse("tcp.reassembly_in_progress = 1").match_is_reassembly_independent(),
            "reassembly-metadata fields are stream-state dependent"
        );
    }

    #[test]
    fn output_reassembly_free_only_for_non_tcp_terminal() {
        for input in [
            "icmp",
            "arp",
            "igmp",
            "icmpv6",
            "icmp AND ipv4.src = '10.0.0.1'", // AND: one branch guarantees non-TCP
            "icmp OR arp",
        ] {
            assert!(
                parse(input).output_is_reassembly_free(),
                "{input} should be safe for parallel CLI output"
            );
        }
    }

    #[test]
    fn output_not_reassembly_free_when_tcp_possible() {
        for input in [
            "tcp",
            "udp",
            "ipv4.src = '10.0.0.1'",
            "tcp.port = 443",
            "icmp OR tcp", // OR: tcp branch can match a reassembled segment
            "NOT icmp",
            "packet_number = 5",
        ] {
            assert!(
                !parse(input).output_is_reassembly_free(),
                "{input} must fall back to the sequential CLI path"
            );
        }
    }

    #[test]
    fn where_clause_protocol_name_is_normalized() {
        // A `Where` clause stores the protocol name as typed; the allowlist
        // lookups normalize it just like the `Protocol` variant, so mixed-case
        // field filters are classified consistently with their lowercase forms.
        assert!(
            parse("IPV4.src = '10.0.0.1'").match_is_reassembly_independent(),
            "mixed-case Where protocol should be reassembly-independent"
        );
        assert!(
            parse("ICMP.type = 8").output_is_reassembly_free(),
            "mixed-case Where protocol should be output-reassembly-free"
        );
    }
}
