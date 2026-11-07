//! Protocol and field filtering.

use packet_dissector_core::field::{Field, FieldValue};
use packet_dissector_core::packet::{Layer, Packet};

#[cfg(test)]
use packet_dissector_test_alloc::test_desc;

use crate::error::{DsctError, Result};
use crate::field_format::format_field_to_string;

/// Normalize a protocol name for flexible matching: strip non-alphanumeric
/// characters and lowercase.  E.g. `"GTPv2-C"` → `"gtpv2c"`.
pub fn normalize_protocol_name(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Compare two protocol names by their normalized forms without allocating.
///
/// Returns `true` if both strings, after stripping non-alphanumeric characters
/// and lowercasing, produce the same sequence.
pub(crate) fn protocol_names_match(a: &str, b: &str) -> bool {
    let mut a_iter = a
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase());
    let mut b_iter = b
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase());
    loop {
        match (a_iter.next(), b_iter.next()) {
            (Some(ca), Some(cb)) if ca == cb => continue,
            (None, None) => return true,
            _ => return false,
        }
    }
}

/// Filter packets by file packet number (1-based).
///
/// Accepts comma-separated single numbers and inclusive ranges:
/// - `"42"` — single packet
/// - `"1-100"` — range
/// - `"1,5,10-20"` — mixed
#[derive(Debug, Clone, PartialEq)]
pub struct PacketNumberFilter {
    ranges: Vec<(u64, u64)>,
}

impl PacketNumberFilter {
    /// Create a filter from pre-built inclusive ranges.
    pub fn from_ranges(ranges: Vec<(u64, u64)>) -> Self {
        Self { ranges }
    }

    /// Parse a packet-number expression like `"42"`, `"1-100"`, or `"1,5,10-20"`.
    pub fn parse(s: &str) -> Result<Self> {
        if s.trim().is_empty() {
            return Err(DsctError::invalid_argument(
                "packet number expression must not be empty",
            ));
        }
        let mut ranges = Vec::new();
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                return Err(DsctError::invalid_argument(format!(
                    "empty segment in packet number expression: '{s}'"
                )));
            }
            if let Some((lo, hi)) = part.split_once('-') {
                let lo: u64 = lo.trim().parse().map_err(|_| {
                    DsctError::invalid_argument(format!("invalid packet number '{lo}' in '{s}'"))
                })?;
                let hi: u64 = hi.trim().parse().map_err(|_| {
                    DsctError::invalid_argument(format!("invalid packet number '{hi}' in '{s}'"))
                })?;
                if lo == 0 || hi == 0 {
                    return Err(DsctError::invalid_argument(format!(
                        "packet numbers are 1-based; got 0 in '{s}'"
                    )));
                }
                if lo > hi {
                    return Err(DsctError::invalid_argument(format!(
                        "invalid range {lo}-{hi} in '{s}': start must not exceed end"
                    )));
                }
                ranges.push((lo, hi));
            } else {
                let n: u64 = part.parse().map_err(|_| {
                    DsctError::invalid_argument(format!("invalid packet number '{part}' in '{s}'"))
                })?;
                if n == 0 {
                    return Err(DsctError::invalid_argument(format!(
                        "packet numbers are 1-based; got 0 in '{s}'"
                    )));
                }
                ranges.push((n, n));
            }
        }
        Ok(Self { ranges })
    }

    /// Returns `true` if `n` falls within any of the specified ranges.
    pub fn contains(&self, n: u64) -> bool {
        self.ranges.iter().any(|&(lo, hi)| n >= lo && n <= hi)
    }

    /// Returns the maximum packet number in the filter, or `None` if empty.
    ///
    /// Used for early-exit optimisation: once the file packet number exceeds
    /// this value, no further packets can match and processing can stop.
    pub fn max(&self) -> Option<u64> {
        self.ranges.iter().map(|&(_, hi)| hi).max()
    }
}

/// Filter packets by capture timestamp: inclusive ranges of microseconds
/// since the Unix epoch.
#[derive(Debug, Clone, PartialEq)]
pub struct TimestampFilter {
    ranges: Vec<(u64, u64)>,
}

impl TimestampFilter {
    /// Create a filter from inclusive ranges of microseconds since the epoch.
    pub fn from_ranges(ranges: Vec<(u64, u64)>) -> Self {
        Self { ranges }
    }

    /// Returns `true` if `timestamp_us` falls within any of the ranges.
    pub fn contains(&self, timestamp_us: u64) -> bool {
        self.ranges
            .iter()
            .any(|&(lo, hi)| timestamp_us >= lo && timestamp_us <= hi)
    }

    /// Parse a timestamp value into microseconds since the Unix epoch.
    ///
    /// Accepts the form `dsct` prints (RFC 3339 with a `Z` or `±hh:mm`
    /// offset, e.g. `2024-01-15T10:30:00.123456Z`) or seconds since the
    /// epoch (`1705314600.123456`), each with at most six fractional digits.
    pub fn parse_value(s: &str) -> std::result::Result<u64, String> {
        let s = s.trim();
        let invalid = || {
            format!(
                "invalid timestamp '{s}': expected RFC 3339 (e.g. 2024-01-15T10:30:00.123456Z) \
                 or seconds since the Unix epoch"
            )
        };
        if s.bytes().next().is_some_and(|b| b.is_ascii_digit()) && !s.contains('-') {
            let (secs, frac) = s.split_once('.').unwrap_or((s, ""));
            let secs: u64 = secs.parse().map_err(|_| invalid())?;
            let usecs = parse_fraction(frac).ok_or_else(invalid)?;
            return secs
                .checked_mul(1_000_000)
                .and_then(|t| t.checked_add(usecs))
                .ok_or_else(invalid);
        }
        parse_rfc3339(s).ok_or_else(invalid)
    }
}

/// Parse up to six fractional-second digits into microseconds (`""` = 0).
fn parse_fraction(frac: &str) -> Option<u64> {
    if frac.len() > 6 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut padded = frac.to_string();
    while padded.len() < 6 {
        padded.push('0');
    }
    padded.parse().ok()
}

/// Days from 1970-01-01 to the given proleptic Gregorian date (H. Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parse `YYYY-MM-DDThh:mm:ss[.ffffff](Z|±hh:mm)` into microseconds since the
/// Unix epoch; `None` when malformed or before the epoch.
fn parse_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !matches!(b[10], b'T' | b't') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let part = s.get(r)?;
        part.bytes()
            .all(|c| c.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        _ => return None,
    };
    if day == 0 || day > days_in_month || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let rest = &s[19..];
    let (frac, zone) = match rest.strip_prefix('.') {
        Some(r) => {
            let end = r.find(|c: char| !c.is_ascii_digit()).unwrap_or(r.len());
            (&r[..end], &r[end..])
        }
        None => ("", rest),
    };
    if rest.starts_with('.') && frac.is_empty() {
        return None;
    }
    let usecs = parse_fraction(frac)?;
    let offset_secs: i64 = match zone {
        "Z" | "z" => 0,
        _ => {
            let zb = zone.as_bytes();
            if zb.len() != 6 || zb[3] != b':' {
                return None;
            }
            let sign = match zb[0] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let zh: i64 = zone.get(1..3)?.parse().ok()?;
            let zm: i64 = zone.get(4..6)?.parse().ok()?;
            if zh > 23 || zm > 59 {
                return None;
            }
            sign * (zh * 3600 + zm * 60)
        }
    };
    let days = days_from_civil(i64::from(year), month, day);
    let secs = days * 86_400 + i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second)
        - offset_secs;
    let secs = u64::try_from(secs).ok()?;
    secs.checked_mul(1_000_000)?.checked_add(usecs)
}

/// Comparison operator for where-clause conditions.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum CompareOp {
    /// Equal (`=`).
    #[default]
    Eq,
    /// Not equal (`!=`, `<>`).
    Ne,
    /// Less than (`<`).
    Lt,
    /// Less than or equal (`<=`).
    Le,
    /// Greater than (`>`).
    Gt,
    /// Greater than or equal (`>=`).
    Ge,
}

impl CompareOp {
    /// Compare two `Ord` values using this operator.
    fn cmp_ord<T: Ord>(&self, actual: &T, expected: &T) -> bool {
        match self {
            CompareOp::Eq => actual == expected,
            CompareOp::Ne => actual != expected,
            CompareOp::Lt => actual < expected,
            CompareOp::Le => actual <= expected,
            CompareOp::Gt => actual > expected,
            CompareOp::Ge => actual >= expected,
        }
    }

    /// For types that only support equality, evaluate `eq_fn` for `Eq`/`Ne`
    /// and return `false` for ordering operators.
    fn cmp_eq_only(&self, eq_fn: impl FnOnce() -> bool) -> bool {
        match self {
            CompareOp::Eq => eq_fn(),
            CompareOp::Ne => !eq_fn(),
            _ => false,
        }
    }
}

/// Pre-parsed value cache to avoid per-packet string parsing.
#[derive(Debug, Clone)]
struct ParsedValue {
    /// The original string value (used for string comparisons and formatted
    /// byte fields).
    raw: String,
    /// Eagerly parsed numeric / address representations.
    as_u8: Option<u8>,
    as_u16: Option<u16>,
    as_u32: Option<u32>,
    as_u64: Option<u64>,
    as_i32: Option<i32>,
    as_ipv4: Option<std::net::Ipv4Addr>,
    as_ipv6: Option<std::net::Ipv6Addr>,
    as_mac: Option<[u8; 6]>,
}

impl ParsedValue {
    fn new(raw: String) -> Self {
        let as_u8 = raw.parse().ok();
        let as_u16 = raw.parse().ok();
        let as_u32 = raw.parse().ok();
        let as_u64 = raw.parse().ok();
        let as_i32 = raw.parse().ok();
        let as_ipv4 = raw.parse().ok();
        let as_ipv6 = raw.parse().ok();
        let as_mac = parse_mac_addr(&raw);
        Self {
            raw,
            as_u8,
            as_u16,
            as_u32,
            as_u64,
            as_i32,
            as_ipv4,
            as_ipv6,
            as_mac,
        }
    }
}

impl PartialEq for ParsedValue {
    fn eq(&self, other: &Self) -> bool {
        self.raw == other.raw
    }
}

/// A single where-clause condition: `protocol.field op value`.
#[derive(Debug, Clone, PartialEq)]
pub struct WhereClause {
    /// Protocol name (lowercase), e.g., "ipv4".
    pub protocol: String,
    /// Field name, e.g., "src".
    pub field: String,
    /// Comparison operator.
    pub op: CompareOp,
    /// Pre-parsed expected value.
    parsed: ParsedValue,
}

impl WhereClause {
    /// Create a new where-clause with explicit components.
    pub fn new(protocol: String, field: String, op: CompareOp, value: String) -> Self {
        let parsed = ParsedValue::new(value);
        Self {
            protocol: normalize_protocol_name(&protocol),
            field,
            op,
            parsed,
        }
    }

    /// The raw string value of this clause.
    pub fn value(&self) -> &str {
        &self.parsed.raw
    }

    /// Check if the raw [`Packet`] matches this where-clause.
    ///
    /// This operates on pre-annotation [`FieldValue`]s, enabling filters like
    /// `dns.qr=0` or `ipv4.protocol=17` that use raw numeric values.
    ///
    /// A bare field name (`bgp.code`) only ever matches one of the layer's
    /// own top-level fields; it never reaches into a nested container.
    /// A dotted path (`bgp.nlri.prefix`) is resolved by
    /// [`dotted_path_matches`](Self::dotted_path_matches).
    pub fn matches_packet(&self, packet: &Packet) -> bool {
        for layer in packet.layers() {
            if !protocol_names_match(layer.name, &self.protocol) {
                continue;
            }
            let fields = packet.layer_fields(layer);
            let top_level = crate::field_iter::top_level_fields(fields, layer.field_range.start);
            // Direct field match — restricted to the layer's own top-level
            // fields, so e.g. "bgp.code" doesn't reach into a nested
            // optional_parameters capability's "code" field.
            if let Some(field) = top_level.clone().find(|f| f.name() == self.field)
                && self.field_value_matches(field, packet, layer)
            {
                return true;
            }
            // Virtual _name field match (e.g., "protocol_name=UDP"),
            // likewise restricted to top-level base fields.
            if let Some(base_name) = self.field.strip_suffix("_name")
                && display_name_matches(top_level.clone(), fields, base_name, self.op, self.value())
            {
                return true;
            }
            // Nested field match (e.g., "questions.name").
            if let Some((group, rest)) = self.field.split_once('.')
                && self.dotted_path_matches(group, rest, fields, packet, layer)
            {
                return true;
            }
        }
        false
    }

    /// Resolve a dotted filter path (`group` + `rest`) against one layer.
    ///
    /// `group` is matched against every **container** (`Array`/`Object`)
    /// of that name in the layer — the top-level field and any nested one —
    /// and the clause matches if `rest` matches inside any of them. A BGP
    /// UPDATE therefore answers `bgp.nlri.route_type` from the MP_REACH
    /// NLRI whether or not it also carries a top-level `nlri`, and
    /// `bgp.nlri.prefix` from either array. This keeps the result
    /// independent of which containers a particular packet happens to
    /// have, and matches what TUI value completion collects.
    ///
    /// Only containers take part: a nested *scalar* is never reachable
    /// this way, which is also why a bare `bgp.code` cannot match a
    /// capability's nested `code`.
    fn dotted_path_matches(
        &self,
        group: &str,
        rest: &str,
        fields: &[Field],
        packet: &Packet,
        layer: &Layer,
    ) -> bool {
        fields
            .iter()
            .filter(|f| {
                matches!(f.value, FieldValue::Array(_) | FieldValue::Object(_)) && f.name() == group
            })
            .any(|f| self.nested_field_matches(f, rest, packet, layer))
    }

    /// Compare the expected value against a [`Field`], using `format_fn` for
    /// byte fields that have one (e.g. DNS domain names).
    fn field_value_matches(&self, field: &Field, packet: &Packet, layer: &Layer) -> bool {
        if let FieldValue::Bytes(_) | FieldValue::Scratch(_) = &field.value
            && let Some(formatted) =
                format_field_to_string(field, packet.data(), layer, packet.buf().scratch())
        {
            return self
                .op
                .cmp_eq_only(|| formatted.eq_ignore_ascii_case(&self.parsed.raw));
        }
        self.raw_value_matches(&field.value, packet, layer)
    }

    /// Compare the pre-parsed expected value against a raw [`FieldValue`].
    fn raw_value_matches(&self, fv: &FieldValue, packet: &Packet, layer: &Layer) -> bool {
        let p = &self.parsed;
        match fv {
            FieldValue::U8(n) => p.as_u8.is_some_and(|v| self.op.cmp_ord(n, &v)),
            FieldValue::U16(n) => p.as_u16.is_some_and(|v| self.op.cmp_ord(n, &v)),
            FieldValue::U32(n) => p.as_u32.is_some_and(|v| self.op.cmp_ord(n, &v)),
            FieldValue::U64(n) => p.as_u64.is_some_and(|v| self.op.cmp_ord(n, &v)),
            FieldValue::I32(n) => p.as_i32.is_some_and(|v| self.op.cmp_ord(n, &v)),
            FieldValue::Str(s) => self.op.cmp_eq_only(|| s.eq_ignore_ascii_case(&p.raw)),
            FieldValue::Ipv4Addr(a) => self
                .op
                .cmp_eq_only(|| p.as_ipv4.is_some_and(|v| v == std::net::Ipv4Addr::from(*a))),
            FieldValue::Ipv6Addr(a) => self
                .op
                .cmp_eq_only(|| p.as_ipv6.is_some_and(|v| v == std::net::Ipv6Addr::from(*a))),
            FieldValue::MacAddr(a) => self.op.cmp_eq_only(|| p.as_mac.is_some_and(|m| m == a.0)),
            FieldValue::Bytes(_) | FieldValue::Scratch(_) => false,
            FieldValue::Array(range) => packet
                .nested_fields(range)
                .iter()
                .any(|child| self.field_value_matches(child, packet, layer)),
            FieldValue::Object(range) => packet
                .nested_fields(range)
                .iter()
                .any(|child| self.field_value_matches(child, packet, layer)),
        }
    }

    /// Recursively match a nested field path against a [`Field`].
    fn nested_field_matches(
        &self,
        field: &Field,
        path: &str,
        packet: &Packet,
        layer: &Layer,
    ) -> bool {
        let (head, tail) = match path.split_once('.') {
            Some((h, t)) => (h, Some(t)),
            None => (path, None),
        };
        match &field.value {
            FieldValue::Object(range) => {
                let children = packet.nested_fields(range);
                let top_level_children = crate::field_iter::top_level_fields(children, range.start);
                if let Some(child) = top_level_children.clone().find(|f| f.name() == head) {
                    match tail {
                        Some(rest) => self.nested_field_matches(child, rest, packet, layer),
                        None => self.field_value_matches(child, packet, layer),
                    }
                } else if tail.is_none() {
                    // Virtual _name fallback: resolve via display_fn
                    head.strip_suffix("_name").is_some_and(|base| {
                        display_name_matches(
                            top_level_children.clone(),
                            children,
                            base,
                            self.op,
                            self.value(),
                        )
                    })
                } else {
                    false
                }
            }
            // An array's elements are its *direct* children only: walk
            // them with `top_level_fields` so a nested container's own
            // children (e.g. a BGP path attribute's `value.afi`) aren't
            // treated as array elements and matched one level too high.
            FieldValue::Array(range) => {
                crate::field_iter::top_level_fields(packet.nested_fields(range), range.start)
                    .any(|child| self.nested_field_matches(child, path, packet, layer))
            }
            _ => false,
        }
    }
}

/// Check if a virtual `_name` companion field matches by resolving via `display_fn`.
///
/// When the filter references `X_name` and no real field with that name exists,
/// this looks for a top-level field `X` (via `top_level`, restricted to the
/// layer's own direct fields so a nested container's same-named field
/// can't be matched instead), invokes its `display_fn` with `siblings` —
/// the full flat field slice, matching what the dissector's `display_fn`
/// receives during normal serialization — and compares the result
/// case-insensitively against `expected`.
///
/// The `op` parameter controls how the comparison is performed.  For `Eq` and
/// `Ne`, case-insensitive string equality is used.  Ordering operators (`Lt`,
/// `Le`, `Gt`, `Ge`) return `false` because display names are unordered labels.
fn display_name_matches(
    top_level: crate::field_iter::TopLevelFields<'_, '_>,
    siblings: &[Field],
    base_name: &str,
    op: CompareOp,
    expected: &str,
) -> bool {
    let Some(base_field) = top_level.into_iter().find(|f| f.name() == base_name) else {
        return false;
    };
    let Some(dfn) = base_field.descriptor.display_fn else {
        return false;
    };
    let Some(display_value) = dfn(&base_field.value, siblings) else {
        return false;
    };
    op.cmp_eq_only(|| display_value.eq_ignore_ascii_case(expected))
}

/// Parse a MAC address string (colon- or dash-separated hex octets) into raw bytes.
///
/// Accepts both `"aa:bb:cc:dd:ee:ff"` and `"aa-bb-cc-dd-ee-ff"` formats,
/// case-insensitively.
fn parse_mac_addr(s: &str) -> Option<[u8; 6]> {
    let sep = if s.contains(':') {
        ':'
    } else if s.contains('-') {
        '-'
    } else {
        return None;
    };
    let mut bytes = [0u8; 6];
    let mut parts = s.split(sep);
    for byte in &mut bytes {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *byte = u8::from_str_radix(part, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- PacketNumberFilter tests ---

    #[test]
    fn test_pnf_parse_single() {
        let f = PacketNumberFilter::parse("42").unwrap();
        assert_eq!(f.ranges, vec![(42, 42)]);
    }

    #[test]
    fn test_pnf_parse_range() {
        let f = PacketNumberFilter::parse("10-20").unwrap();
        assert_eq!(f.ranges, vec![(10, 20)]);
    }

    #[test]
    fn test_pnf_parse_mixed() {
        let f = PacketNumberFilter::parse("1,5,10-20").unwrap();
        assert_eq!(f.ranges, vec![(1, 1), (5, 5), (10, 20)]);
    }

    #[test]
    fn test_pnf_parse_single_range_equals() {
        let f = PacketNumberFilter::parse("7-7").unwrap();
        assert_eq!(f.ranges, vec![(7, 7)]);
    }

    #[test]
    fn test_pnf_contains_single() {
        let f = PacketNumberFilter::parse("5").unwrap();
        assert!(!f.contains(4));
        assert!(f.contains(5));
        assert!(!f.contains(6));
    }

    #[test]
    fn test_pnf_contains_range() {
        let f = PacketNumberFilter::parse("10-12").unwrap();
        assert!(!f.contains(9));
        assert!(f.contains(10));
        assert!(f.contains(11));
        assert!(f.contains(12));
        assert!(!f.contains(13));
    }

    #[test]
    fn test_pnf_contains_mixed() {
        let f = PacketNumberFilter::parse("1,5,10-12").unwrap();
        assert!(f.contains(1));
        assert!(!f.contains(2));
        assert!(f.contains(5));
        assert!(f.contains(10));
        assert!(f.contains(12));
        assert!(!f.contains(13));
    }

    #[test]
    fn test_pnf_max() {
        let f = PacketNumberFilter::parse("1,5,10-20").unwrap();
        assert_eq!(f.max(), Some(20));
    }

    #[test]
    fn test_pnf_max_single() {
        let f = PacketNumberFilter::parse("42").unwrap();
        assert_eq!(f.max(), Some(42));
    }

    #[test]
    fn test_pnf_parse_error_empty() {
        assert!(PacketNumberFilter::parse("").is_err());
    }

    #[test]
    fn test_pnf_parse_error_zero() {
        assert!(PacketNumberFilter::parse("0").is_err());
    }

    #[test]
    fn test_pnf_parse_error_zero_in_range() {
        assert!(PacketNumberFilter::parse("0-10").is_err());
    }

    #[test]
    fn test_pnf_parse_error_inverted_range() {
        assert!(PacketNumberFilter::parse("20-10").is_err());
    }

    #[test]
    fn test_pnf_parse_error_non_numeric() {
        assert!(PacketNumberFilter::parse("abc").is_err());
    }

    #[test]
    fn test_pnf_parse_error_empty_segment() {
        assert!(PacketNumberFilter::parse("1,,3").is_err());
    }

    #[test]
    fn test_pnf_parse_error_non_numeric_range_end() {
        assert!(PacketNumberFilter::parse("1-abc").is_err());
    }
    use packet_dissector_core::field::{Field, FieldValue};
    use packet_dissector_core::packet::DissectBuffer;

    /// Create a leaked static FieldDescriptor with a display_fn for tests.
    fn test_desc_with_display_fn(
        name: &'static str,
        display_name: &'static str,
        display_fn: fn(&FieldValue<'_>, &[Field<'_>]) -> Option<&'static str>,
    ) -> &'static packet_dissector_core::field::FieldDescriptor {
        Box::leak(Box::new(packet_dissector_core::field::FieldDescriptor {
            name,
            display_name,
            field_type: packet_dissector_core::field::FieldType::U32,
            optional: false,
            children: None,
            display_fn: Some(display_fn),
            format_fn: None,
        }))
    }

    /// Build a DissectBuffer with a single layer containing the given fields.
    fn make_single_layer_buf(
        name: &'static str,
        fields: &[(&'static str, FieldValue<'static>)],
    ) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer(name, None, &[], 0..0);
        for (fname, fval) in fields {
            buf.push_field(test_desc(fname, fname), fval.clone(), 0..0);
        }
        buf.end_layer();
        buf
    }

    static EMPTY_DATA: [u8; 0] = [];

    fn pkt_from<'a>(buf: &'a DissectBuffer<'static>) -> Packet<'a, 'static> {
        Packet::new(buf, &EMPTY_DATA)
    }

    /// Shorthand to build an `Eq` where-clause for tests.
    fn wc(protocol: &str, field: &str, value: &str) -> WhereClause {
        WhereClause::new(protocol.into(), field.into(), CompareOp::Eq, value.into())
    }

    // --- WhereClause::new tests ---

    #[test]
    fn test_where_new_fields() {
        let w = wc("ipv4", "src", "10.0.0.1");
        assert_eq!(w.protocol, "ipv4");
        assert_eq!(w.field, "src");
        assert_eq!(w.value(), "10.0.0.1");
        assert_eq!(w.op, CompareOp::Eq);
    }

    #[test]
    fn test_where_new_normalizes_protocol() {
        let w = wc("IPv4", "src", "10.0.0.1");
        assert_eq!(w.protocol, "ipv4");
    }

    // --- Packet matching tests ---

    #[test]
    fn test_where_raw_u8() {
        let w = wc("dns", "qr", "0");
        let buf = make_single_layer_buf("DNS", &[("qr", FieldValue::U8(0))]);
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_u8_no_match() {
        let w = wc("dns", "qr", "99");
        let buf = make_single_layer_buf("DNS", &[("qr", FieldValue::U8(0))]);
        assert!(!w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_u16() {
        let w = wc("ethernet", "ethertype", "2048");
        let buf = make_single_layer_buf("Ethernet", &[("ethertype", FieldValue::U16(2048))]);
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_u32() {
        let w = wc("test", "val", "100000");
        let buf = make_single_layer_buf("Test", &[("val", FieldValue::U32(100000))]);
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_u64() {
        let w = wc("test", "val", "9999999999");
        let buf = make_single_layer_buf("Test", &[("val", FieldValue::U64(9_999_999_999))]);
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_i32() {
        let w = wc("test", "val", "-1");
        let buf = make_single_layer_buf("Test", &[("val", FieldValue::I32(-1))]);
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_str() {
        let w = wc("dns", "name", "Example.COM");
        let buf = make_single_layer_buf("DNS", &[("name", FieldValue::Str("example.com"))]);
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_ipv4addr() {
        let w = wc("ipv4", "src", "10.0.0.1");
        let buf = make_single_layer_buf("IPv4", &[("src", FieldValue::Ipv4Addr([10, 0, 0, 1]))]);
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_ipv6addr() {
        let w = wc("ipv6", "src", "::1");
        let buf = make_single_layer_buf(
            "IPv6",
            &[(
                "src",
                FieldValue::Ipv6Addr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            )],
        );
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_ipv6addr_expanded() {
        let w = wc("ipv6", "src", "0:0:0:0:0:0:0:1");
        let buf = make_single_layer_buf(
            "IPv6",
            &[(
                "src",
                FieldValue::Ipv6Addr([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            )],
        );
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_macaddr() {
        use packet_dissector_core::field::MacAddr;
        let w = wc("ethernet", "src", "aa:bb:cc:dd:ee:ff");
        let buf = make_single_layer_buf(
            "Ethernet",
            &[(
                "src",
                FieldValue::MacAddr(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
            )],
        );
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_macaddr_uppercase_dash() {
        use packet_dissector_core::field::MacAddr;
        let w = wc("ethernet", "src", "AA-BB-CC-DD-EE-FF");
        let buf = make_single_layer_buf(
            "Ethernet",
            &[(
                "src",
                FieldValue::MacAddr(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
            )],
        );
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_macaddr_invalid_octet_count() {
        use packet_dissector_core::field::MacAddr;
        let buf = make_single_layer_buf(
            "Ethernet",
            &[(
                "src",
                FieldValue::MacAddr(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
            )],
        );
        let w = wc("ethernet", "src", "aa:bb:cc:dd:ee");
        assert!(!w.matches_packet(&pkt_from(&buf)));
        let w = wc("ethernet", "src", "aa:bb:cc:dd:ee:ff:00");
        assert!(!w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_macaddr_mixed_separators() {
        use packet_dissector_core::field::MacAddr;
        let buf = make_single_layer_buf(
            "Ethernet",
            &[(
                "src",
                FieldValue::MacAddr(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
            )],
        );
        let w = wc("ethernet", "src", "aa:bb-cc:dd-ee:ff");
        assert!(!w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_macaddr_non_hex() {
        use packet_dissector_core::field::MacAddr;
        let buf = make_single_layer_buf(
            "Ethernet",
            &[(
                "src",
                FieldValue::MacAddr(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
            )],
        );
        let w = wc("ethernet", "src", "gg:bb:cc:dd:ee:ff");
        assert!(!w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_macaddr_single_digit() {
        use packet_dissector_core::field::MacAddr;
        let buf = make_single_layer_buf(
            "Ethernet",
            &[(
                "src",
                FieldValue::MacAddr(MacAddr([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])),
            )],
        );
        let w = wc("ethernet", "src", "a:b:c:d:e:f");
        assert!(!w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_protocol_case_insensitive() {
        let w = wc("DNS", "qr", "0");
        let buf = make_single_layer_buf("DNS", &[("qr", FieldValue::U8(0))]);
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_nested_array() {
        let w = WhereClause::new(
            "dns".into(),
            "questions.name".into(),
            CompareOp::Eq,
            "example.com".into(),
        );
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..0);
        let arr = buf.begin_container(
            test_desc("questions", "Questions"),
            FieldValue::Array(0..0),
            0..0,
        );
        let obj = buf.begin_container(test_desc("q", "Q"), FieldValue::Object(0..0), 0..0);
        buf.push_field(
            test_desc("name", "Name"),
            FieldValue::Str("example.com"),
            0..0,
        );
        buf.push_field(test_desc("type", "Type"), FieldValue::U16(1), 0..0);
        buf.end_container(obj);
        buf.end_container(arr);
        buf.end_layer();
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_nested_object() {
        let w = WhereClause::new(
            "icmp".into(),
            "invoking_packet.version".into(),
            CompareOp::Eq,
            "4".into(),
        );
        let mut buf = DissectBuffer::new();
        buf.begin_layer("ICMP", None, &[], 0..0);
        let obj = buf.begin_container(
            test_desc("invoking_packet", "Invoking Packet"),
            FieldValue::Object(0..0),
            0..0,
        );
        buf.push_field(test_desc("version", "Version"), FieldValue::U8(4), 0..0);
        buf.push_field(
            test_desc("src", "Source"),
            FieldValue::Ipv4Addr([10, 0, 0, 1]),
            0..0,
        );
        buf.end_container(obj);
        buf.end_layer();
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_bytes_no_match() {
        let w = wc("test", "data", "ff");
        let buf = make_single_layer_buf("Test", &[("data", FieldValue::Bytes(&[0xff]))]);
        assert!(!w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_wrong_field() {
        let w = wc("dns", "opcode", "0");
        let buf = make_single_layer_buf("DNS", &[("qr", FieldValue::U8(0))]);
        assert!(!w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_wrong_protocol() {
        let w = wc("tcp", "qr", "0");
        let buf = make_single_layer_buf("DNS", &[("qr", FieldValue::U8(0))]);
        assert!(!w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_raw_array_element_direct() {
        let w = wc("dns", "questions", "example.com");
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..0);
        let arr = buf.begin_container(
            test_desc("questions", "Questions"),
            FieldValue::Array(0..0),
            0..0,
        );
        let obj = buf.begin_container(test_desc("q", "Q"), FieldValue::Object(0..0), 0..0);
        buf.push_field(
            test_desc("name", "Name"),
            FieldValue::Str("example.com"),
            0..0,
        );
        buf.end_container(obj);
        buf.end_container(arr);
        buf.end_layer();
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    // --- normalize_protocol_name tests ---

    #[test]
    fn test_normalize_protocol_name() {
        assert_eq!(normalize_protocol_name("GTPv2-C"), "gtpv2c");
        assert_eq!(normalize_protocol_name("GTPv1-U"), "gtpv1u");
        assert_eq!(normalize_protocol_name("HTTP/2"), "http2");
        assert_eq!(normalize_protocol_name("IPv4"), "ipv4");
        assert_eq!(normalize_protocol_name("TCP"), "tcp");
        assert_eq!(normalize_protocol_name("tcp"), "tcp");
        assert_eq!(normalize_protocol_name(""), "");
    }

    #[test]
    fn test_protocol_names_match() {
        assert!(protocol_names_match("GTPv2-C", "gtpv2c"));
        assert!(protocol_names_match("GTPv2-C", "GTPv2C"));
        assert!(protocol_names_match("GTPv2-C", "GTPv2-C"));
        assert!(protocol_names_match("GTPv2-C", "gtpv2-c"));
        assert!(protocol_names_match("HTTP/2", "http2"));
        assert!(protocol_names_match("TCP", "tcp"));
        assert!(protocol_names_match("tcp", "TCP"));
        assert!(!protocol_names_match("TCP", "UDP"));
        assert!(!protocol_names_match("GTPv2-C", "gtpv1u"));
        assert!(protocol_names_match("", ""));
        assert!(!protocol_names_match("TCP", ""));
    }

    #[test]
    fn test_where_protocol_hyphen_insensitive() {
        let w = wc("gtpv2c", "teid", "1");
        let buf = make_single_layer_buf("GTPv2-C", &[("teid", FieldValue::U32(1))]);
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_protocol_slash_insensitive() {
        let w = wc("http2", "stream_id", "1");
        let buf = make_single_layer_buf("HTTP/2", &[("stream_id", FieldValue::U32(1))]);
        assert!(w.matches_packet(&pkt_from(&buf)));
    }

    // --- Virtual _name field tests ---

    fn ie_type_display_fn(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
        match v {
            FieldValue::U32(2) => Some("Cause"),
            FieldValue::U32(93) => Some("Bearer Context"),
            _ => None,
        }
    }

    #[test]
    fn test_where_display_name_top_level() {
        let wc = WhereClause::new(
            "ipv4".into(),
            "protocol_name".into(),
            CompareOp::Eq,
            "udp".into(),
        );
        fn proto_display(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
            match v {
                FieldValue::U8(17) => Some("UDP"),
                _ => None,
            }
        }
        let mut buf = DissectBuffer::new();
        buf.begin_layer("IPv4", None, &[], 0..0);
        buf.push_field(
            test_desc_with_display_fn("protocol", "Protocol", proto_display),
            FieldValue::U8(17),
            0..0,
        );
        buf.end_layer();
        assert!(wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_display_name_nested_array() {
        let wc = WhereClause::new(
            "gtpv2c".into(),
            "ies.type_name".into(),
            CompareOp::Eq,
            "Cause".into(),
        );
        let mut buf = DissectBuffer::new();
        buf.begin_layer("GTPv2-C", None, &[], 0..0);
        let arr = buf.begin_container(test_desc("ies", "IEs"), FieldValue::Array(0..0), 0..0);
        let obj = buf.begin_container(test_desc("ie", "IE"), FieldValue::Object(0..0), 0..0);
        buf.push_field(
            test_desc_with_display_fn("type", "Type", ie_type_display_fn),
            FieldValue::U32(2),
            0..0,
        );
        buf.end_container(obj);
        buf.end_container(arr);
        buf.end_layer();
        assert!(wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_display_name_no_match() {
        let wc = WhereClause::new(
            "gtpv2c".into(),
            "ies.type_name".into(),
            CompareOp::Eq,
            "Cause".into(),
        );
        let mut buf = DissectBuffer::new();
        buf.begin_layer("GTPv2-C", None, &[], 0..0);
        let arr = buf.begin_container(test_desc("ies", "IEs"), FieldValue::Array(0..0), 0..0);
        let obj = buf.begin_container(test_desc("ie", "IE"), FieldValue::Object(0..0), 0..0);
        buf.push_field(
            test_desc_with_display_fn("type", "Type", ie_type_display_fn),
            FieldValue::U32(93), // Bearer Context, not Cause
            0..0,
        );
        buf.end_container(obj);
        buf.end_container(arr);
        buf.end_layer();
        assert!(!wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_direct_match_does_not_match_nested_only_field() {
        // "code" only exists nested inside optional_parameters' capability
        // objects, not as a top-level BGP field. A direct match on
        // "bgp.code" must not reach into the nested container.
        let wc = WhereClause::new("bgp".into(), "code".into(), CompareOp::Eq, "2".into());
        let mut buf = DissectBuffer::new();
        buf.begin_layer("BGP", None, &[], 0..0);
        let arr = buf.begin_container(
            test_desc("optional_parameters", "Optional Parameters"),
            FieldValue::Array(0..0),
            0..0,
        );
        let obj = buf.begin_container(
            test_desc("capability", "Capability"),
            FieldValue::Object(0..0),
            0..0,
        );
        buf.push_field(test_desc("code", "Code"), FieldValue::U8(2), 0..0);
        buf.end_container(obj);
        buf.end_container(arr);
        buf.end_layer();
        assert!(!wc.matches_packet(&pkt_from(&buf)));
    }

    /// Build a BGP UPDATE-shaped layer: a `path_attributes` array whose
    /// MP_REACH attribute carries a nested `nlri` array (with a
    /// `route_type` field that exists only there), optionally followed by
    /// the top-level `nlri` array. The nested container comes first in
    /// buffer order, which is what a flat-slice lookup would pick.
    fn bgp_nlri_buf(with_top_level_nlri: bool) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("BGP", None, &[], 0..0);
        let attrs = buf.begin_container(
            test_desc("path_attributes", "Path Attributes"),
            FieldValue::Array(0..0),
            0..0,
        );
        let attr = buf.begin_container(
            test_desc("attribute", "Attribute"),
            FieldValue::Object(0..0),
            0..0,
        );
        let value =
            buf.begin_container(test_desc("value", "Value"), FieldValue::Object(0..0), 0..0);
        let nested_nlri =
            buf.begin_container(test_desc("nlri", "NLRI"), FieldValue::Array(0..0), 0..0);
        let nested_entry =
            buf.begin_container(test_desc("entry", "Entry"), FieldValue::Object(0..0), 0..0);
        buf.push_field(
            test_desc("route_type", "Route Type"),
            FieldValue::U8(1),
            0..0,
        );
        buf.push_field(
            test_desc("prefix", "Prefix"),
            FieldValue::Str("2001:db8::/32"),
            0..0,
        );
        buf.end_container(nested_entry);
        buf.end_container(nested_nlri);
        buf.end_container(value);
        buf.end_container(attr);
        buf.end_container(attrs);
        if with_top_level_nlri {
            let nlri =
                buf.begin_container(test_desc("nlri", "NLRI"), FieldValue::Array(0..0), 0..0);
            let entry =
                buf.begin_container(test_desc("entry", "Entry"), FieldValue::Object(0..0), 0..0);
            buf.push_field(test_desc("path_id", "Path ID"), FieldValue::U32(7), 0..0);
            buf.push_field(
                test_desc("prefix", "Prefix"),
                FieldValue::Str("10.0.0.0/8"),
                0..0,
            );
            buf.end_container(entry);
            buf.end_container(nlri);
        }
        buf.end_layer();
        buf
    }

    #[test]
    fn test_dotted_path_matches_any_same_named_container() {
        let buf = bgp_nlri_buf(true);
        let packet = pkt_from(&buf);
        // Both the top-level `nlri` and the nested MP_REACH one take part,
        // so values from either array match ...
        assert!(wc("bgp", "nlri.prefix", "10.0.0.0/8").matches_packet(&packet));
        assert!(wc("bgp", "nlri.prefix", "2001:db8::/32").matches_packet(&packet));
        // ... and a field only the nested one carries is still reachable.
        assert!(wc("bgp", "nlri.route_type", "1").matches_packet(&packet));
        assert!(!wc("bgp", "nlri.route_type", "2").matches_packet(&packet));
    }

    #[test]
    fn test_dotted_path_reaches_nested_container_without_top_level() {
        let buf = bgp_nlri_buf(false);
        let packet = pkt_from(&buf);
        // Without a top-level `nlri`, the MP_REACH one is still reached.
        assert!(wc("bgp", "nlri.route_type", "1").matches_packet(&packet));
        assert!(wc("bgp", "nlri.prefix", "2001:db8::/32").matches_packet(&packet));
    }

    #[test]
    fn test_array_path_does_not_reach_grandchildren() {
        // `path_attributes` is an Array whose element Objects carry a
        // nested `value` Object. A path that stops at the array
        // ("bgp.path_attributes.afi") must only look at the elements'
        // direct fields — the grandchild `afi` inside `value` must not be
        // matched as if it were one of them. The full path
        // ("bgp.path_attributes.value.afi") must still match it.
        let mut buf = DissectBuffer::new();
        buf.begin_layer("BGP", None, &[], 0..0);
        let arr = buf.begin_container(
            test_desc("path_attributes", "Path Attributes"),
            FieldValue::Array(0..0),
            0..0,
        );
        let attr = buf.begin_container(
            test_desc("attribute", "Attribute"),
            FieldValue::Object(0..0),
            0..0,
        );
        buf.push_field(
            test_desc("type_code", "Type Code"),
            FieldValue::U8(14),
            0..0,
        );
        let value =
            buf.begin_container(test_desc("value", "Value"), FieldValue::Object(0..0), 0..0);
        buf.push_field(test_desc("afi", "AFI"), FieldValue::U16(1), 0..0);
        buf.end_container(value);
        buf.end_container(attr);
        buf.end_container(arr);
        buf.end_layer();
        let packet = pkt_from(&buf);

        let shallow = WhereClause::new(
            "bgp".into(),
            "path_attributes.afi".into(),
            CompareOp::Eq,
            "1".into(),
        );
        assert!(
            !shallow.matches_packet(&packet),
            "a grandchild inside a nested object must not match through the array path"
        );

        // A direct child of the array elements still matches.
        let direct = WhereClause::new(
            "bgp".into(),
            "path_attributes.type_code".into(),
            CompareOp::Eq,
            "14".into(),
        );
        assert!(direct.matches_packet(&packet));

        // And the grandchild matches via its full path.
        let full = WhereClause::new(
            "bgp".into(),
            "path_attributes.value.afi".into(),
            CompareOp::Eq,
            "1".into(),
        );
        assert!(full.matches_packet(&packet));
    }

    #[test]
    fn test_display_name_match_does_not_match_nested_only_field() {
        // Same shape, but for the virtual "_name" companion match: a
        // nested field's display_fn companion must not be reachable via a
        // top-level "<field>_name" filter.
        let wc = WhereClause::new(
            "bgp".into(),
            "code_name".into(),
            CompareOp::Eq,
            "Multiprotocol Extensions".into(),
        );
        fn code_display_fn(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
            match v {
                FieldValue::U8(1) => Some("Multiprotocol Extensions"),
                _ => None,
            }
        }
        let mut buf = DissectBuffer::new();
        buf.begin_layer("BGP", None, &[], 0..0);
        let arr = buf.begin_container(
            test_desc("optional_parameters", "Optional Parameters"),
            FieldValue::Array(0..0),
            0..0,
        );
        let obj = buf.begin_container(
            test_desc("capability", "Capability"),
            FieldValue::Object(0..0),
            0..0,
        );
        buf.push_field(
            test_desc_with_display_fn("code", "Code", code_display_fn),
            FieldValue::U8(1),
            0..0,
        );
        buf.end_container(obj);
        buf.end_container(arr);
        buf.end_layer();
        assert!(!wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_display_name_no_display_fn() {
        let wc = WhereClause::new(
            "dns".into(),
            "qr_name".into(),
            CompareOp::Eq,
            "query".into(),
        );
        let buf = make_single_layer_buf("DNS", &[("qr", FieldValue::U8(0))]);
        assert!(!wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_where_display_name_ne_operator() {
        fn proto_display(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
            match v {
                FieldValue::U8(17) => Some("UDP"),
                _ => None,
            }
        }
        let mut buf = DissectBuffer::new();
        buf.begin_layer("IPv4", None, &[], 0..0);
        buf.push_field(
            test_desc_with_display_fn("protocol", "Protocol", proto_display),
            FieldValue::U8(17),
            0..0,
        );
        buf.end_layer();
        let packet = pkt_from(&buf);

        // Ne: "protocol_name != 'udp'" should NOT match when display is "UDP"
        let wc_ne = WhereClause::new(
            "ipv4".into(),
            "protocol_name".into(),
            CompareOp::Ne,
            "udp".into(),
        );
        assert!(!wc_ne.matches_packet(&packet));

        // Ne: "protocol_name != 'tcp'" should match when display is "UDP"
        let wc_ne2 = WhereClause::new(
            "ipv4".into(),
            "protocol_name".into(),
            CompareOp::Ne,
            "tcp".into(),
        );
        assert!(wc_ne2.matches_packet(&packet));

        // Gt: ordering operators return false for display names
        let wc_gt = WhereClause::new(
            "ipv4".into(),
            "protocol_name".into(),
            CompareOp::Gt,
            "aaa".into(),
        );
        assert!(!wc_gt.matches_packet(&packet));
    }

    // --- CompareOp tests ---

    #[test]
    fn test_compare_op_u16_gt() {
        let wc = WhereClause::new("tcp".into(), "src_port".into(), CompareOp::Gt, "79".into());
        let buf = make_single_layer_buf("TCP", &[("src_port", FieldValue::U16(80))]);
        assert!(wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_compare_op_u16_lt() {
        let wc = WhereClause::new("tcp".into(), "src_port".into(), CompareOp::Lt, "81".into());
        let buf = make_single_layer_buf("TCP", &[("src_port", FieldValue::U16(80))]);
        assert!(wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_compare_op_u16_ge() {
        let wc = WhereClause::new("tcp".into(), "src_port".into(), CompareOp::Ge, "80".into());
        let buf = make_single_layer_buf("TCP", &[("src_port", FieldValue::U16(80))]);
        assert!(wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_compare_op_u16_le() {
        let wc = WhereClause::new("tcp".into(), "src_port".into(), CompareOp::Le, "80".into());
        let buf = make_single_layer_buf("TCP", &[("src_port", FieldValue::U16(80))]);
        assert!(wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_compare_op_ne() {
        let wc = WhereClause::new("tcp".into(), "src_port".into(), CompareOp::Ne, "81".into());
        let buf = make_single_layer_buf("TCP", &[("src_port", FieldValue::U16(80))]);
        assert!(wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_compare_op_ne_equal_returns_false() {
        let wc = WhereClause::new("tcp".into(), "src_port".into(), CompareOp::Ne, "80".into());
        let buf = make_single_layer_buf("TCP", &[("src_port", FieldValue::U16(80))]);
        assert!(!wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_compare_op_str_ne() {
        let wc = WhereClause::new(
            "dns".into(),
            "name".into(),
            CompareOp::Ne,
            "other.com".into(),
        );
        let buf = make_single_layer_buf("DNS", &[("name", FieldValue::Str("example.com"))]);
        assert!(wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_compare_op_str_gt_returns_false() {
        let wc = WhereClause::new(
            "dns".into(),
            "name".into(),
            CompareOp::Gt,
            "example.com".into(),
        );
        let buf = make_single_layer_buf("DNS", &[("name", FieldValue::Str("example.com"))]);
        assert!(!wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_compare_op_ipv4_ne() {
        let wc = WhereClause::new(
            "ipv4".into(),
            "src".into(),
            CompareOp::Ne,
            "10.0.0.2".into(),
        );
        let buf = make_single_layer_buf("IPv4", &[("src", FieldValue::Ipv4Addr([10, 0, 0, 1]))]);
        assert!(wc.matches_packet(&pkt_from(&buf)));
    }

    #[test]
    fn test_compare_op_i32() {
        let wc = WhereClause::new("test".into(), "val".into(), CompareOp::Gt, "0".into());
        let buf = make_single_layer_buf("Test", &[("val", FieldValue::I32(1))]);
        assert!(wc.matches_packet(&pkt_from(&buf)));
    }
}
