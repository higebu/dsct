//! Streaming JSON serialization for the [`DissectBuffer`] API.
//!
//! This module writes packet data directly as JSON without building
//! intermediate serde structures. It:
//!
//! - Adds packet metadata (number, timestamp, lengths)
//! - Filters fields based on a per-protocol config (include or exclude mode)
//! - Preserves field insertion order (protocol specification order)
//!
//! Human-readable names for well-known numeric values are emitted directly by
//! each protocol dissector as `_name` companion fields (e.g. `protocol_name`,
//! `ethertype_name`). No post-processing annotation is performed here.
//!
//! Dissectors emit grouped structures directly (e.g. `questions: [{name, type,
//! class}]`), so no regrouping is performed here.

use std::io::Write;

use crate::json_escape::write_json_escaped;
use std::ops::Range;

use packet_dissector_core::field::{Field, FieldValue, FormatContext};
use packet_dissector_core::packet::{DissectBuffer, Layer};
use serde::Serialize;

use crate::error::Result;
use crate::field_config::FieldConfig;

#[cfg(test)]
use packet_dissector_test_alloc::test_desc;

/// Metadata about a single captured packet (from the pcap header).
#[derive(Debug, Clone, Serialize)]
pub struct PacketMeta {
    /// 1-based packet number within the capture.
    pub number: u64,
    /// Capture timestamp as seconds since the Unix epoch.
    pub timestamp_secs: u64,
    /// Sub-second part of the timestamp in microseconds.
    pub timestamp_usecs: u32,
    /// Number of bytes actually captured.
    pub captured_length: u32,
    /// Original length of the packet on the wire.
    pub original_length: u32,
    /// Pcap link-layer header type (e.g. 1 = Ethernet, 113 = Linux SLL, 276 = Linux SLL2).
    pub link_type: u32,
}

/// Decomposed date-time parts from a Unix timestamp.
struct TimeParts {
    year: u64,
    month: u64,
    day: u64,
    hours: u64,
    minutes: u64,
    seconds: u64,
}

fn is_leap_year(year: u64) -> bool {
    (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400)
}

/// Decompose a Unix timestamp (seconds since epoch) into date-time parts.
fn decompose_timestamp(secs: u64) -> TimeParts {
    const SECS_PER_DAY: u64 = 86400;
    const DAYS_PER_YEAR: u64 = 365;

    let days = secs / SECS_PER_DAY;
    let time_of_day = secs % SECS_PER_DAY;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let mut year = 1970u64;
    let mut remaining_days = days;
    loop {
        // Guard against corrupted timestamps that would cause billions of
        // iterations.  Year 9999 is well beyond any valid pcap timestamp.
        if year > 9999 {
            return TimeParts {
                year: 9999,
                month: 12,
                day: 31,
                hours: 23,
                minutes: 59,
                seconds: 59,
            };
        }
        let days_in_year = if is_leap_year(year) {
            366
        } else {
            DAYS_PER_YEAR
        };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let leap = is_leap_year(year);
    let month_days: [u64; 12] = if leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u64;
    for &md in &month_days {
        if remaining_days < md {
            break;
        }
        remaining_days -= md;
        month += 1;
    }
    let day = remaining_days + 1;

    TimeParts {
        year,
        month,
        day,
        hours,
        minutes,
        seconds,
    }
}

/// Format a Unix timestamp as an ISO 8601 string.
pub fn format_timestamp(secs: u64, usecs: u32) -> String {
    use std::fmt::Write;
    let p = decompose_timestamp(secs);
    // ISO 8601 timestamp is fixed-length: "YYYY-MM-DDThh:mm:ss.ffffffZ" = 27 bytes
    let mut buf = String::with_capacity(27);
    let _ = write!(
        buf,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{usecs:06}Z",
        p.year, p.month, p.day, p.hours, p.minutes, p.seconds
    );
    buf
}

/// Write an ISO 8601 timestamp directly into an [`std::io::Write`] target.
///
/// Avoids allocating a `String` on the hot path.
fn write_timestamp_to<W: Write>(w: &mut W, secs: u64, usecs: u32) -> std::io::Result<()> {
    let p = decompose_timestamp(secs);
    write!(
        w,
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{usecs:06}Z",
        p.year, p.month, p.day, p.hours, p.minutes, p.seconds
    )
}

// ---------------------------------------------------------------------------
// Streaming JSON write — zero-allocation packet serialization via DissectBuffer.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------

/// Write a [`FieldValue`] as a JSON token to `w`.
///
/// When `field` is provided and has a [`FormatFn`](packet_dissector_core::field::FormatFn),
/// that function is called to format the value. Otherwise the default
/// formatting for each variant is used.
fn write_field_value_json<W: Write>(
    w: &mut W,
    field: &Field<'_>,
    buf: &DissectBuffer<'_>,
    data: &[u8],
    layer_range: &Range<usize>,
) -> Result<()> {
    // If the descriptor has a format_fn, use it.
    if let Some(format_fn) = field.descriptor.format_fn {
        let ctx = FormatContext {
            packet_data: data,
            scratch: buf.scratch(),
            layer_range: layer_range.start as u32..layer_range.end as u32,
            field_range: field.range.start as u32..field.range.end as u32,
        };
        format_fn(&field.value, &ctx, &mut *w)?;
        return Ok(());
    }
    write_raw_field_value_json(w, &field.value, buf)
}

/// Write a raw [`FieldValue`] as a JSON token without consulting `format_fn`.
fn write_raw_field_value_json<W: Write>(
    w: &mut W,
    value: &FieldValue<'_>,
    buf: &DissectBuffer<'_>,
) -> Result<()> {
    match value {
        FieldValue::U8(v) => write!(w, "{v}")?,
        FieldValue::U16(v) => write!(w, "{v}")?,
        FieldValue::U32(v) => write!(w, "{v}")?,
        FieldValue::U64(v) => write!(w, "{v}")?,
        FieldValue::I32(v) => write!(w, "{v}")?,
        FieldValue::Str(s) => {
            w.write_all(b"\"")?;
            write_json_escaped(w, s)?;
            w.write_all(b"\"")?;
        }
        FieldValue::Ipv4Addr(a) => write!(w, "\"{}.{}.{}.{}\"", a[0], a[1], a[2], a[3])?,
        FieldValue::Ipv6Addr(a) => {
            let addr = std::net::Ipv6Addr::from(*a);
            write!(w, "\"{addr}\"")?;
        }
        FieldValue::MacAddr(m) => write!(w, "\"{m}\"")?,
        FieldValue::Bytes(b) => {
            write!(w, "\"")?;
            for byte in *b {
                write!(w, "{byte:02x}")?;
            }
            write!(w, "\"")?;
        }
        FieldValue::Scratch(range) => {
            let scratch_bytes = &buf.scratch()[range.start as usize..range.end as usize];
            write!(w, "\"")?;
            for byte in scratch_bytes {
                write!(w, "{byte:02x}")?;
            }
            write!(w, "\"")?;
        }
        FieldValue::Array(_) | FieldValue::Object(_) => {
            // Container fields should be handled by write_field_json;
            // if we reach here, emit null as a defensive fallback.
            write!(w, "null")?;
        }
    }
    Ok(())
}

/// Write a field value as JSON, recursing into `Array`/`Object` sub-fields
/// and applying `field_config` filtering to nested object entries.
#[allow(clippy::too_many_arguments)]
fn write_field_json<W: Write>(
    w: &mut W,
    protocol: &str,
    field_name: &str,
    field: &Field<'_>,
    buf: &DissectBuffer<'_>,
    data: &[u8],
    layer_range: &Range<usize>,
    field_config: Option<&FieldConfig>,
) -> Result<()> {
    // Recurse into Array: write each direct child element.
    // Direct children are iterated by skipping over container sub-ranges.
    if let FieldValue::Array(ref range) = field.value {
        write!(w, "[")?;
        let mut first = true;
        let mut idx = range.start;
        while idx < range.end {
            let child = &buf.fields()[idx as usize];
            if !first {
                write!(w, ",")?;
            }
            first = false;
            write_field_json(
                w,
                protocol,
                field_name,
                child,
                buf,
                data,
                layer_range,
                field_config,
            )?;
            // Skip over sub-container's children
            idx = match &child.value {
                FieldValue::Array(r) | FieldValue::Object(r) => r.end,
                _ => idx + 1,
            };
        }
        write!(w, "]")?;
        return Ok(());
    }

    // Recurse into Object: filter and write each named direct sub-field.
    // `field_name` is the parent container name (e.g., "answers").
    // Direct children are iterated by skipping over container sub-ranges.
    if let FieldValue::Object(ref range) = field.value {
        write!(w, "{{")?;
        let mut first = true;
        let children = buf.nested_fields(range);
        let mut idx = range.start;
        while idx < range.end {
            let f = &buf.fields()[idx as usize];
            let include_field = field_config
                .is_none_or(|cfg| cfg.should_include_nested(protocol, field_name, f.name()));

            if include_field {
                if !first {
                    write!(w, ",")?;
                }
                first = false;
                w.write_all(b"\"")?;
                w.write_all(f.name().as_bytes())?;
                w.write_all(b"\":")?;
                write_field_json(
                    w,
                    protocol,
                    f.name(),
                    f,
                    buf,
                    data,
                    layer_range,
                    field_config,
                )?;
            }

            emit_virtual_name_field(
                w,
                f,
                children,
                |vn| {
                    field_config
                        .is_none_or(|cfg| cfg.should_include_nested(protocol, field_name, vn))
                },
                &mut first,
            )?;

            // Skip over sub-container's children
            idx = match &f.value {
                FieldValue::Array(r) | FieldValue::Object(r) => r.end,
                _ => idx + 1,
            };
        }
        write!(w, "}}")?;
        return Ok(());
    }

    write_field_value_json(w, field, buf, data, layer_range)
}

/// Emit a virtual `_name` companion field if the descriptor has a `display_fn`.
///
/// `siblings` is the sibling field slice passed to `display_fn`.
/// `include_check` decides whether the virtual field passes the current filter.
fn emit_virtual_name_field<W: Write>(
    w: &mut W,
    f: &Field<'_>,
    siblings: &[Field<'_>],
    include_check: impl FnOnce(&str) -> bool,
    first: &mut bool,
) -> Result<()> {
    let Some(display_fn) = f.descriptor.display_fn else {
        return Ok(());
    };
    let Some(display_value) = display_fn(&f.value, siblings) else {
        return Ok(());
    };
    let name = f.name();
    let suffix = b"_name";
    let total_len = name.len() + suffix.len();
    // Stack buffer for the virtual field name; fall back to a heap
    // allocation if the field name is unusually long (> 123 chars).
    let mut stack_buf = [0u8; 128];
    let heap_buf;
    let virtual_name = if total_len <= stack_buf.len() {
        stack_buf[..name.len()].copy_from_slice(name.as_bytes());
        stack_buf[name.len()..total_len].copy_from_slice(suffix);
        // SAFETY: `name` is a `&str` (valid UTF-8) and `suffix` is ASCII,
        // so the concatenation is always valid UTF-8.  `unwrap_or("")` is a
        // defensive fallback that should never be reached.
        let result = std::str::from_utf8(&stack_buf[..total_len]).unwrap_or("");
        debug_assert!(!result.is_empty(), "stack buffer produced invalid UTF-8");
        result
    } else {
        heap_buf = format!("{name}_name");
        heap_buf.as_str()
    };

    if include_check(virtual_name) {
        if !*first {
            write!(w, ",")?;
        }
        *first = false;
        w.write_all(b"\"")?;
        w.write_all(name.as_bytes())?;
        w.write_all(b"_name\":\"")?;
        write_json_escaped(&mut *w, display_value)?;
        w.write_all(b"\"")?;
    }
    Ok(())
}

/// Write all fields of a protocol layer as JSON key-value pairs (no surrounding `{}`).
///
/// Fields are filtered by `field_config` when present. Filtering is applied
/// recursively using dot-qualified patterns: sub-fields within
/// `FieldValue::Object` values are checked via `should_include_nested`.
fn write_layer_fields<W: Write>(
    w: &mut W,
    layer: &Layer,
    buf: &DissectBuffer<'_>,
    data: &[u8],
    field_config: Option<&FieldConfig>,
) -> Result<()> {
    let fields = buf.layer_fields(layer);
    let mut first = true;
    for f in fields {
        let include_field = field_config.is_none_or(|cfg| cfg.should_include(layer.name, f.name()));

        if include_field {
            if !first {
                write!(w, ",")?;
            }
            first = false;
            w.write_all(b"\"")?;
            w.write_all(f.name().as_bytes())?;
            w.write_all(b"\":")?;
            write_field_json(
                w,
                layer.name,
                f.name(),
                f,
                buf,
                data,
                &layer.range,
                field_config,
            )?;
        }

        let layer_name = layer.name;
        emit_virtual_name_field(
            w,
            f,
            fields,
            |vn| field_config.is_none_or(|cfg| cfg.should_include(layer_name, vn)),
            &mut first,
        )?;
    }
    Ok(())
}

/// Write a packet as a single-line JSON object directly to `w`.
///
/// Uses the flat [`DissectBuffer`] API — no intermediate serde structures
/// are allocated.
pub fn write_packet_json<W: Write>(
    w: &mut W,
    meta: &PacketMeta,
    buf: &DissectBuffer<'_>,
    data: &[u8],
    field_config: Option<&FieldConfig>,
) -> Result<()> {
    // number
    write!(w, "{{\"number\":{},\"timestamp\":\"", meta.number)?;
    // timestamp (no String allocation)
    write_timestamp_to(w, meta.timestamp_secs, meta.timestamp_usecs)?;
    // length / original_length
    write!(
        w,
        "\",\"length\":{},\"original_length\":{},\"stack\":\"",
        meta.captured_length, meta.original_length
    )?;
    // stack — layer names joined by ':'
    for (i, layer) in buf.layers().iter().enumerate() {
        if i > 0 {
            write!(w, ":")?;
        }
        write!(w, "{}", layer.protocol_name())?;
    }
    // layers array
    write!(w, "\",\"layers\":[")?;
    for (i, layer) in buf.layers().iter().enumerate() {
        if i > 0 {
            write!(w, ",")?;
        }
        w.write_all(b"{\"protocol\":\"")?;
        w.write_all(layer.protocol_name().as_bytes())?;
        w.write_all(b"\",\"fields\":{")?;
        write_layer_fields(w, layer, buf, data, field_config)?;
        write!(w, "}}}}")?; // close fields, close layer
    }
    write!(w, "]}}")?; // close layers, close packet
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field_config::FieldConfig;
    use packet_dissector_core::field::MacAddr;

    // --- helpers ---

    /// Build a DissectBuffer with an Ethernet layer containing a single MAC field.
    fn make_single_mac_buf() -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Ethernet", None, &[], 0..14);
        buf.push_field(
            test_desc("dst_mac", "Destination MAC"),
            FieldValue::MacAddr(MacAddr([0xff; 6])),
            0..6,
        );
        buf.end_layer();
        buf
    }

    /// Build a DissectBuffer with Ethernet / IPv4 / TCP layers.
    fn make_eth_ipv4_tcp_buf() -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();

        // Ethernet
        buf.begin_layer("Ethernet", None, &[], 0..14);
        buf.push_field(
            test_desc("dst", "Destination"),
            FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
            0..6,
        );
        buf.push_field(
            test_desc("src", "Source"),
            FieldValue::MacAddr(MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])),
            6..12,
        );
        buf.push_field(
            test_desc("ethertype", "EtherType"),
            FieldValue::U16(0x0800),
            12..14,
        );
        buf.end_layer();

        // IPv4
        buf.begin_layer("IPv4", None, &[], 14..34);
        buf.push_field(
            test_desc("src", "Source"),
            FieldValue::Ipv4Addr([10, 0, 0, 1]),
            12..16,
        );
        buf.push_field(
            test_desc("dst", "Destination"),
            FieldValue::Ipv4Addr([10, 0, 0, 2]),
            16..20,
        );
        buf.push_field(test_desc("protocol", "Protocol"), FieldValue::U8(6), 9..10);
        buf.end_layer();

        // TCP
        buf.begin_layer("TCP", None, &[], 34..54);
        buf.push_field(
            test_desc("src_port", "Source Port"),
            FieldValue::U16(12345),
            0..2,
        );
        buf.push_field(
            test_desc("dst_port", "Destination Port"),
            FieldValue::U16(80),
            2..4,
        );
        buf.push_field(test_desc("flags", "Flags"), FieldValue::U8(0x12), 13..14);
        buf.end_layer();

        buf
    }

    /// Build a DissectBuffer with a DNS layer containing nested Array/Object fields.
    fn make_dns_buf() -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..28);
        buf.push_field(test_desc("id", "ID"), FieldValue::U16(0x1234), 0..2);
        buf.push_field(test_desc("qr", "QR"), FieldValue::U8(0), 2..3);

        // questions: Array -> Object { name, type, class }
        let arr_idx = buf.begin_container(
            test_desc("questions", "Questions"),
            FieldValue::Array(0..0),
            12..28,
        );
        let obj_idx = buf.begin_container(
            test_desc("question", "Question"),
            FieldValue::Object(0..0),
            12..28,
        );
        buf.push_field(
            test_desc("name", "Name"),
            FieldValue::Str("example.com"),
            12..24,
        );
        buf.push_field(test_desc("type", "Type"), FieldValue::U16(1), 24..26);
        buf.push_field(test_desc("class", "Class"), FieldValue::U16(1), 26..28);
        buf.end_container(obj_idx);
        buf.end_container(arr_idx);

        buf.end_layer();
        buf
    }

    fn make_test_meta(num: u64) -> PacketMeta {
        PacketMeta {
            number: num,
            timestamp_secs: 1705314600,
            timestamp_usecs: 123456,
            captured_length: 100,
            original_length: 100,
            link_type: 1,
        }
    }

    /// Helper: write packet JSON to a Vec<u8> and parse it for assertion.
    fn write_and_parse(
        buf: &DissectBuffer<'_>,
        data: &[u8],
        meta: &PacketMeta,
        field_config: Option<&FieldConfig>,
    ) -> serde_json::Value {
        let mut out = Vec::new();
        write_packet_json(&mut out, meta, buf, data, field_config).unwrap();
        serde_json::from_slice(&out).unwrap()
    }

    // --- raw field value tests ---

    #[test]
    fn test_write_raw_field_value_integers() {
        let buf = DissectBuffer::new();
        let cases: &[(&FieldValue, &str)] = &[
            (&FieldValue::U8(42), "42"),
            (&FieldValue::U16(8080), "8080"),
            (&FieldValue::U32(100000), "100000"),
            (&FieldValue::U64(1_000_000_000), "1000000000"),
            (&FieldValue::I32(-1), "-1"),
        ];
        for (val, expected) in cases {
            let mut out = Vec::new();
            write_raw_field_value_json(&mut out, val, &buf).unwrap();
            assert_eq!(String::from_utf8(out).unwrap(), *expected);
        }
    }

    #[test]
    fn test_write_raw_field_value_str() {
        let buf = DissectBuffer::new();
        let mut out = Vec::new();
        write_raw_field_value_json(&mut out, &FieldValue::Str("hello"), &buf).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\"hello\"");
    }

    #[test]
    fn test_write_raw_field_value_ipv4() {
        let buf = DissectBuffer::new();
        let mut out = Vec::new();
        write_raw_field_value_json(&mut out, &FieldValue::Ipv4Addr([10, 0, 0, 1]), &buf).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\"10.0.0.1\"");
    }

    #[test]
    fn test_write_raw_field_value_ipv6() {
        let buf = DissectBuffer::new();
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        addr[15] = 0x01;
        let mut out = Vec::new();
        write_raw_field_value_json(&mut out, &FieldValue::Ipv6Addr(addr), &buf).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\"2001:db8::1\"");
    }

    #[test]
    fn test_write_raw_field_value_mac() {
        let buf = DissectBuffer::new();
        let mut out = Vec::new();
        write_raw_field_value_json(
            &mut out,
            &FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
            &buf,
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\"00:11:22:33:44:55\"");
    }

    #[test]
    fn test_write_raw_field_value_bytes() {
        let buf = DissectBuffer::new();
        let mut out = Vec::new();
        write_raw_field_value_json(
            &mut out,
            &FieldValue::Bytes(&[0xde, 0xad, 0xbe, 0xef]),
            &buf,
        )
        .unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\"deadbeef\"");
    }

    #[test]
    fn test_write_raw_field_value_scratch() {
        let mut buf = DissectBuffer::new();
        let range = buf.push_scratch(&[0xAA, 0xBB]);
        let mut out = Vec::new();
        write_raw_field_value_json(&mut out, &FieldValue::Scratch(range), &buf).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "\"aabb\"");
    }

    // --- timestamp tests ---

    #[test]
    fn test_format_timestamp() {
        let ts = format_timestamp(1705314600, 123456);
        assert_eq!(ts, "2024-01-15T10:30:00.123456Z");
    }

    #[test]
    fn test_format_timestamp_epoch() {
        let ts = format_timestamp(0, 0);
        assert_eq!(ts, "1970-01-01T00:00:00.000000Z");
    }

    #[test]
    fn test_format_timestamp_corrupted_large_value() {
        // A corrupted timestamp should not hang; it clamps to year 9999.
        let ts = format_timestamp(u64::MAX / 2, 0);
        assert!(ts.starts_with("9999-12-31T23:59:59."));
    }

    // --- write_packet_json tests ---

    #[test]
    fn test_write_packet_json_single_layer() {
        let buf = make_single_mac_buf();
        let data = [0u8; 14];
        let meta = PacketMeta {
            number: 1,
            timestamp_secs: 0,
            timestamp_usecs: 0,
            captured_length: 14,
            original_length: 14,
            link_type: 1,
        };

        let json = write_and_parse(&buf, &data, &meta, None);
        assert_eq!(json["number"], 1);
        let layers = json["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0]["protocol"], "Ethernet");
        assert_eq!(layers[0]["fields"]["dst_mac"], "ff:ff:ff:ff:ff:ff");
    }

    #[test]
    fn test_write_packet_json_multi_layer() {
        let buf = make_eth_ipv4_tcp_buf();
        let data = [0u8; 100];
        let meta = make_test_meta(1);
        let config = FieldConfig::default_config().unwrap();

        let json = write_and_parse(&buf, &data, &meta, Some(&config));
        assert_eq!(json["number"], 1);
        assert_eq!(json["stack"], "Ethernet:IPv4:TCP");
        let layers = json["layers"].as_array().unwrap();
        assert_eq!(layers.len(), 3);
        assert_eq!(layers[0]["protocol"], "Ethernet");
        assert_eq!(layers[1]["protocol"], "IPv4");
        assert_eq!(layers[2]["protocol"], "TCP");
    }

    #[test]
    fn test_write_packet_json_verbose() {
        let buf = make_eth_ipv4_tcp_buf();
        let data = [0u8; 100];
        let meta = make_test_meta(1);

        let json = write_and_parse(&buf, &data, &meta, None);
        // Verbose mode: all fields present.
        let ipv4 = &json["layers"][1]["fields"];
        assert_eq!(ipv4["src"], "10.0.0.1");
        assert_eq!(ipv4["dst"], "10.0.0.2");
        assert_eq!(ipv4["protocol"], 6);
    }

    #[test]
    fn test_write_packet_json_dns_nested() {
        let buf = make_dns_buf();
        let data = [0u8; 100];
        let meta = make_test_meta(5);
        let config = FieldConfig::default_config().unwrap();

        let json = write_and_parse(&buf, &data, &meta, Some(&config));
        let layers = json["layers"].as_array().unwrap();
        let dns = &layers[0]["fields"];
        assert_eq!(dns["id"], 0x1234);
        let questions = dns["questions"].as_array().unwrap();
        assert_eq!(questions.len(), 1);
        let q = &questions[0];
        assert_eq!(q["name"], "example.com");
        assert_eq!(q["type"], 1);
        assert_eq!(q["class"], 1);
    }

    #[test]
    fn test_verbose_field_filtering() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("IPv4", None, &[], 0..20);
        buf.push_field(
            test_desc("src", "Source"),
            FieldValue::Ipv4Addr([10, 0, 0, 1]),
            12..16,
        );
        buf.push_field(
            test_desc("dst", "Destination"),
            FieldValue::Ipv4Addr([10, 0, 0, 2]),
            16..20,
        );
        buf.push_field(
            test_desc("checksum", "Checksum"),
            FieldValue::U16(0x1234),
            10..12,
        );
        buf.push_field(test_desc("version", "Version"), FieldValue::U8(4), 0..1);
        buf.push_field(test_desc("ihl", "IHL"), FieldValue::U8(5), 0..1);
        buf.end_layer();

        let data = [0u8; 20];
        let meta = PacketMeta {
            number: 1,
            timestamp_secs: 0,
            timestamp_usecs: 0,
            captured_length: 20,
            original_length: 20,
            link_type: 1,
        };

        // Default mode: verbose fields hidden
        let config = FieldConfig::default_config().unwrap();
        let json = write_and_parse(&buf, &data, &meta, Some(&config));
        let fields = &json["layers"][0]["fields"];
        assert!(fields.get("src").is_some());
        assert!(fields.get("dst").is_some());
        assert!(fields.get("checksum").is_none() || fields["checksum"].is_null());
        assert!(fields.get("version").is_none() || fields["version"].is_null());
        assert!(fields.get("ihl").is_none() || fields["ihl"].is_null());

        // Verbose mode: all fields shown
        let json = write_and_parse(&buf, &data, &meta, None);
        let fields = &json["layers"][0]["fields"];
        assert_eq!(fields["src"], "10.0.0.1");
        assert_eq!(fields["dst"], "10.0.0.2");
        assert_eq!(fields["checksum"], 0x1234);
        assert_eq!(fields["version"], 4);
        assert_eq!(fields["ihl"], 5);
    }

    #[test]
    fn test_verbose_group_filtering() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..44);
        buf.push_field(test_desc("id", "ID"), FieldValue::U16(0x1234), 0..2);
        buf.push_field(test_desc("qr", "QR"), FieldValue::U8(1), 2..3);

        // questions array
        let q_arr = buf.begin_container(
            test_desc("questions", "Questions"),
            FieldValue::Array(0..0),
            12..28,
        );
        let q_obj = buf.begin_container(test_desc("q", "Q"), FieldValue::Object(0..0), 12..28);
        buf.push_field(
            test_desc("name", "Name"),
            FieldValue::Str("example.com"),
            12..24,
        );
        buf.push_field(test_desc("type", "Type"), FieldValue::U16(1), 24..26);
        buf.push_field(test_desc("class", "Class"), FieldValue::U16(1), 26..28);
        buf.end_container(q_obj);
        buf.end_container(q_arr);

        // authorities array
        let a_arr = buf.begin_container(
            test_desc("authorities", "Authority Records"),
            FieldValue::Array(0..0),
            28..44,
        );
        let a_obj = buf.begin_container(test_desc("a", "A"), FieldValue::Object(0..0), 28..44);
        buf.push_field(
            test_desc("name", "Name"),
            FieldValue::Str("ns1.example.com"),
            28..40,
        );
        buf.push_field(test_desc("type", "Type"), FieldValue::U16(2), 40..42);
        buf.push_field(test_desc("class", "Class"), FieldValue::U16(1), 42..44);
        buf.end_container(a_obj);
        buf.end_container(a_arr);

        buf.end_layer();

        let data = [0u8; 44];
        let meta = PacketMeta {
            number: 1,
            timestamp_secs: 0,
            timestamp_usecs: 0,
            captured_length: 44,
            original_length: 44,
            link_type: 1,
        };

        // Default: questions shown, authorities hidden
        let config = FieldConfig::default_config().unwrap();
        let json = write_and_parse(&buf, &data, &meta, Some(&config));
        let dns = &json["layers"][0]["fields"];
        assert!(dns.get("questions").is_some());
        assert!(dns.get("authorities").is_none() || dns["authorities"].is_null());

        // Verbose: both shown
        let json = write_and_parse(&buf, &data, &meta, None);
        let dns = &json["layers"][0]["fields"];
        assert!(dns["questions"].is_array());
        assert!(dns["authorities"].is_array());
    }

    #[test]
    fn test_recursive_filtering_hides_nested_fields() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..19);
        buf.push_field(test_desc("id", "ID"), FieldValue::U16(0xABCD), 0..2);

        let arr = buf.begin_container(
            test_desc("answers", "Answers"),
            FieldValue::Array(0..0),
            0..19,
        );
        let obj = buf.begin_container(
            test_desc("answer", "Answer"),
            FieldValue::Object(0..0),
            0..19,
        );
        buf.push_field(
            test_desc("name", "Name"),
            FieldValue::Str("example.com"),
            0..11,
        );
        buf.push_field(test_desc("type", "Type"), FieldValue::U16(1), 11..13);
        buf.push_field(
            test_desc("rdlength", "RD Length"),
            FieldValue::U16(4),
            13..15,
        );
        buf.push_field(
            test_desc("rdata", "RData"),
            FieldValue::Str("1.2.3.4"),
            15..19,
        );
        buf.end_container(obj);
        buf.end_container(arr);
        buf.end_layer();

        let data = [0u8; 19];
        let meta = PacketMeta {
            number: 1,
            timestamp_secs: 0,
            timestamp_usecs: 0,
            captured_length: 19,
            original_length: 19,
            link_type: 1,
        };

        // Default config: rdlength should be filtered
        let config = FieldConfig::default_config().unwrap();
        let json = write_and_parse(&buf, &data, &meta, Some(&config));
        let answers = json["layers"][0]["fields"]["answers"].as_array().unwrap();
        let answer = &answers[0];
        assert!(answer.get("name").is_some());
        assert!(answer.get("type").is_some());
        assert!(answer.get("rdata").is_some());
        assert!(
            answer.get("rdlength").is_none(),
            "rdlength should be hidden"
        );

        // Verbose mode: rdlength shown
        let json = write_and_parse(&buf, &data, &meta, None);
        let answers = json["layers"][0]["fields"]["answers"].as_array().unwrap();
        let answer = &answers[0];
        assert!(answer.get("rdlength").is_some());
    }

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

    #[test]
    fn test_display_fn_emitted_when_base_field_filtered() {
        let config = FieldConfig::default_config().unwrap();

        fn type_display_fn(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
            match v {
                FieldValue::U32(19) => Some("Cause"),
                _ => None,
            }
        }

        let mut buf = DissectBuffer::new();
        buf.begin_layer("PFCP", None, &[], 0..20);

        let arr = buf.begin_container(test_desc("ies", "IEs"), FieldValue::Array(0..0), 0..5);
        let obj = buf.begin_container(test_desc("ie", "IE"), FieldValue::Object(0..0), 0..5);
        buf.push_field(
            test_desc_with_display_fn("type", "Type", type_display_fn),
            FieldValue::U32(19),
            0..2,
        );
        buf.push_field(test_desc("value", "Value"), FieldValue::U8(1), 4..5);
        buf.end_container(obj);
        buf.end_container(arr);
        buf.end_layer();

        let data = [0u8; 20];
        let meta = make_test_meta(1);
        let json = write_and_parse(&buf, &data, &meta, Some(&config));

        let layers = json["layers"].as_array().unwrap();
        let fields = &layers[0]["fields"];
        let ies = fields["ies"].as_array().unwrap();
        let ie = &ies[0];
        assert!(
            ie.get("type").is_none(),
            "base 'type' field should be filtered out"
        );
        assert_eq!(
            ie["type_name"], "Cause",
            "virtual type_name should be present"
        );
        assert_eq!(ie["value"], 1);
    }

    #[test]
    fn test_write_json_escaped() {
        let mut out = Vec::new();
        out.push(b'"');
        write_json_escaped(&mut out, "hello \"world\"\n").unwrap();
        out.push(b'"');
        assert_eq!(String::from_utf8(out).unwrap(), r#""hello \"world\"\n""#);
    }
}
