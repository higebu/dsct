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
//! timestamp >= '2024-01-15T10:30:00Z'         — capture time filter
//! ```

use packet_dissector_core::packet::Packet;

use crate::filter::{PacketNumberFilter, TimestampFilter, WhereClause, protocol_names_match};

/// What a filter can test about a packet besides its dissection: its
/// record in the capture file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RecordInfo {
    /// 1-based packet number in the capture.
    pub number: u64,
    /// Capture timestamp in microseconds since the Unix epoch.
    pub timestamp_us: u64,
}

impl RecordInfo {
    /// The record of packet `number` captured at `secs`.`usecs`.
    pub fn new(number: u64, secs: u64, usecs: u32) -> Self {
        Self {
            number,
            timestamp_us: secs
                .saturating_mul(1_000_000)
                .saturating_add(u64::from(usecs)),
        }
    }
}

/// A parsed filter expression.
#[derive(Debug, Clone)]
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
    /// Match packets by capture timestamp.
    Timestamp(TimestampFilter),
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
    /// packet-number or timestamp filter is present.
    #[cfg(test)]
    pub fn matches(&self, packet: &Packet) -> bool {
        self.matches_with_number(packet, 0)
    }

    /// [`matches_record`](Self::matches_record) with only a packet number.
    #[cfg(test)]
    pub fn matches_with_number(&self, packet: &Packet, number: u64) -> bool {
        self.matches_record(
            packet,
            RecordInfo {
                number,
                timestamp_us: 0,
            },
        )
    }

    /// Test whether a dissected packet, whose record in the capture is
    /// `record`, matches.
    pub fn matches_record(&self, packet: &Packet, record: RecordInfo) -> bool {
        match self {
            FilterExpr::Protocol(name) => packet
                .layers()
                .iter()
                .any(|l| protocol_names_match(l.name, name)),
            FilterExpr::Where(clause) => clause.matches_packet(packet),
            FilterExpr::And(a, b) => {
                a.matches_record(packet, record) && b.matches_record(packet, record)
            }
            FilterExpr::Or(a, b) => {
                a.matches_record(packet, record) || b.matches_record(packet, record)
            }
            FilterExpr::Not(e) => !e.matches_record(packet, record),
            FilterExpr::PacketNumber(pnf) => pnf.contains(record.number),
            FilterExpr::Timestamp(tf) => tf.contains(record.timestamp_us),
        }
    }

    /// Returns `true` if this expression tests only the packet record
    /// (`PacketNumber` and `Timestamp`, possibly combined with
    /// AND/OR/NOT), meaning no dissection is needed.
    pub fn is_metadata_only(&self) -> bool {
        match self {
            FilterExpr::PacketNumber(_) | FilterExpr::Timestamp(_) => true,
            FilterExpr::Not(e) => e.is_metadata_only(),
            FilterExpr::And(a, b) | FilterExpr::Or(a, b) => {
                a.is_metadata_only() && b.is_metadata_only()
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
    fn metadata_only_detection() {
        let pn = FilterExpr::parse("packet_number BETWEEN 1 AND 100")
            .unwrap()
            .unwrap();
        assert!(pn.is_metadata_only());

        let mixed = FilterExpr::parse("packet_number = 1 AND tcp")
            .unwrap()
            .unwrap();
        assert!(!mixed.is_metadata_only());

        let not_pn = FilterExpr::parse("NOT packet_number = 5").unwrap().unwrap();
        assert!(not_pn.is_metadata_only());
    }

    #[test]
    fn timestamp_comparisons() {
        let buf = make_tcp_buf();
        let pkt = make_tcp_packet_ref(&buf);
        // 2023-11-14T22:13:20Z is 1_700_000_000 s.
        let at = |us: u64| RecordInfo {
            number: 1,
            timestamp_us: us,
        };
        let t = 1_700_000_000_000_000;
        let cases = [
            ("timestamp = '2023-11-14T22:13:20Z'", t, true),
            ("timestamp = 1700000000", t + 1, false),
            ("timestamp >= '2023-11-14T22:13:20.000001Z'", t, false),
            ("timestamp > 1700000000", t + 1, true),
            ("timestamp < '2023-11-15T07:13:20+09:00'", t, false),
            ("timestamp <= '2023-11-15T07:13:20+09:00'", t, true),
            ("timestamp != 1700000000.5", t + 500_000, false),
            (
                "timestamp BETWEEN '2023-11-14T22:13:20Z' AND '2023-11-14T22:13:21Z'",
                t + 999_999,
                true,
            ),
            ("timestamp NOT BETWEEN 1700000000 AND 1700000001", t, false),
            ("timestamp IN (1700000000, 1700000002)", t, true),
            ("tcp AND timestamp >= 1700000000", t, true),
        ];
        for (filter, us, expected) in cases {
            let expr = FilterExpr::parse(filter).unwrap().unwrap();
            assert_eq!(expr.matches_record(&pkt, at(us)), expected, "{filter}");
        }
        let ts = FilterExpr::parse("timestamp > 1").unwrap().unwrap();
        assert!(ts.is_metadata_only());
        let mixed = FilterExpr::parse("timestamp > 1 AND tcp").unwrap().unwrap();
        assert!(!mixed.is_metadata_only());
    }

    #[test]
    fn invalid_timestamps_are_rejected() {
        for filter in [
            "timestamp > 'yesterday'",
            "timestamp > '2023-02-29T00:00:00Z'",
            "timestamp > '2023-11-14T22:13:20'",
            "timestamp > '2023-11-14T22:13:20.1234567Z'",
            "timestamp > '1969-12-31T23:59:59Z'",
            "timestamp < 0",
        ] {
            let err = FilterExpr::parse(filter).err();
            assert!(err.is_some(), "{filter} should be rejected");
        }
    }

    #[test]
    fn record_info_from_a_pcap_timestamp() {
        assert_eq!(
            RecordInfo::new(3, 1_700_000_000, 42),
            RecordInfo {
                number: 3,
                timestamp_us: 1_700_000_000_000_042
            }
        );
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
}
