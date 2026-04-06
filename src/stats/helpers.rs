use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use packet_dissector_core::field::{Field, FieldValue};
use packet_dissector_core::packet::{Layer, Packet};

use super::{CountEntry, ResponseTimeStats};

/// Extract (src_ip, dst_ip) as [`IpAddr`] from IPv4 or IPv6 layers.
pub(super) fn extract_ip_addr_pair(packet: &Packet) -> Option<(IpAddr, IpAddr)> {
    if let Some(ipv4) = packet.layer_by_name("IPv4") {
        let fields = packet.layer_fields(ipv4);
        let src = match find_field(fields, "src").map(|f| &f.value) {
            Some(FieldValue::Ipv4Addr(b)) => IpAddr::V4(Ipv4Addr::from(*b)),
            _ => return None,
        };
        let dst = match find_field(fields, "dst").map(|f| &f.value) {
            Some(FieldValue::Ipv4Addr(b)) => IpAddr::V4(Ipv4Addr::from(*b)),
            _ => return None,
        };
        return Some((src, dst));
    }
    if let Some(ipv6) = packet.layer_by_name("IPv6") {
        let fields = packet.layer_fields(ipv6);
        let src = match find_field(fields, "src").map(|f| &f.value) {
            Some(FieldValue::Ipv6Addr(b)) => IpAddr::V6(Ipv6Addr::from(*b)),
            _ => return None,
        };
        let dst = match find_field(fields, "dst").map(|f| &f.value) {
            Some(FieldValue::Ipv6Addr(b)) => IpAddr::V6(Ipv6Addr::from(*b)),
            _ => return None,
        };
        return Some((src, dst));
    }
    None
}

/// Extract the transport layer name and (src_port, dst_port).
pub(super) fn extract_transport(packet: &Packet) -> Option<(&'static str, u16, u16)> {
    for name in &["UDP", "TCP"] {
        if let Some(layer) = packet.layer_by_name(name) {
            let fields = packet.layer_fields(layer);
            let src_port = field_u16(fields, "src_port")?;
            let dst_port = field_u16(fields, "dst_port")?;
            return Some((name, src_port, dst_port));
        }
    }
    None
}

/// Extract (src_ip, dst_ip) strings from IPv4 or IPv6 layers.
pub(super) fn extract_ip_pair(packet: &Packet) -> Option<(String, String)> {
    let (src, dst) = extract_ip_addr_pair(packet)?;
    Some((src.to_string(), dst.to_string()))
}

/// Resolve a display name for a field via `Packet::resolve_display_name`.
///
/// Falls back to the raw field value formatted as a string when no
/// `display_fn` is registered for the base field.
pub(super) fn display_name(
    packet: &Packet,
    layer: &Layer,
    fields: &[Field<'_>],
    name_field: &str,
    base_field: &str,
) -> Option<String> {
    if let Some(name) = packet.resolve_display_name(layer, name_field) {
        return Some(name.to_owned());
    }
    find_field(fields, base_field).map(|f| field_value_to_string(&f.value))
}

pub(super) fn find_field<'a, 'b>(fields: &'a [Field<'b>], name: &str) -> Option<&'a Field<'b>> {
    fields.iter().find(|f| f.name() == name)
}

pub(super) fn field_u8(fields: &[Field<'_>], name: &str) -> Option<u8> {
    match find_field(fields, name).map(|f| &f.value) {
        Some(FieldValue::U8(v)) => Some(*v),
        _ => None,
    }
}

pub(super) fn field_str<'a>(fields: &'a [Field<'_>], name: &str) -> Option<&'a str> {
    match find_field(fields, name).map(|f| &f.value) {
        Some(FieldValue::Str(s)) => Some(s),
        _ => None,
    }
}

/// Convert a [`FieldValue`] to a display string for stats aggregation.
pub(super) fn field_value_to_string(value: &FieldValue) -> String {
    match value {
        FieldValue::Str(s) => (*s).to_string(),
        FieldValue::U8(v) => v.to_string(),
        FieldValue::U16(v) => v.to_string(),
        FieldValue::U32(v) => v.to_string(),
        FieldValue::U64(v) => v.to_string(),
        FieldValue::I32(v) => v.to_string(),
        FieldValue::Ipv4Addr(b) => Ipv4Addr::from(*b).to_string(),
        FieldValue::Ipv6Addr(b) => Ipv6Addr::from(*b).to_string(),
        FieldValue::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        FieldValue::MacAddr(m) => m.to_string(),
        _ => String::new(),
    }
}

pub(super) fn field_u16(fields: &[Field<'_>], name: &str) -> Option<u16> {
    match find_field(fields, name).map(|f| &f.value) {
        Some(FieldValue::U16(v)) => Some(*v),
        _ => None,
    }
}

pub(super) fn field_u32(fields: &[Field<'_>], name: &str) -> Option<u32> {
    match find_field(fields, name).map(|f| &f.value) {
        Some(FieldValue::U32(v)) => Some(*v),
        _ => None,
    }
}

/// Sort entries by count descending and take top N.
pub(super) fn sorted_top_n(
    iter: impl Iterator<Item = (String, u64)>,
    top_n: usize,
) -> Vec<CountEntry> {
    let mut entries: Vec<CountEntry> = iter
        .map(|(name, count)| CountEntry { name, count })
        .collect();
    entries.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.name.cmp(&b.name)));
    entries.truncate(top_n);
    entries
}

/// Compute percentile stats from a list of response times.
pub(super) fn compute_response_time_stats(mut times: Vec<f64>) -> Option<ResponseTimeStats> {
    if times.is_empty() {
        return None;
    }
    times.sort_by(|a, b| a.total_cmp(b));
    let n = times.len();
    let sum: f64 = times.iter().sum();
    Some(ResponseTimeStats {
        min: times[0],
        max: times[n - 1],
        mean: sum / n as f64,
        median: percentile(&times, 50.0),
        p95: percentile(&times, 95.0),
        p99: percentile(&times, 99.0),
        count: n as u64,
    })
}

/// Compute the p-th percentile from a sorted slice using linear interpolation.
pub(super) fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = p / 100.0 * (sorted.len() - 1) as f64;
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;
    if lower == upper {
        sorted[lower]
    } else {
        let frac = rank - lower as f64;
        sorted[lower] * (1.0 - frac) + sorted[upper] * frac
    }
}
