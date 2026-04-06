//! Memory-mapped pcap loader with header-only index scan.
//!
//! Phase 1 (`build_index`): Delegates to `packet_dissector_pcap` for format
//! parsing, then converts to the compact `PacketIndex` representation.
//!
//! Phase 2 (on demand): Visible rows are dissected via [`extract_row_summary`]
//! using zero-copy mmap slices.  The selected packet is fully dissected via
//! [`dissect_selected`].

use std::fs::File;
use std::path::Path;

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::{DissectBuffer, Layer, Packet};

use crate::field_format::format_field_to_string;

use crate::error::{Result, ResultExt};
use crate::serialize::format_timestamp;

use super::owned_packet::OwnedPacket;
use super::state::{CaptureMap, PacketIndex, RowSummary, SelectedPacket};
use super::tree;

#[cfg(test)]
use packet_dissector_test_alloc::test_desc;

// ---------------------------------------------------------------------------
// Phase 1: mmap + header-only index scan
// ---------------------------------------------------------------------------

/// Open and memory-map a capture file, then build a packet index.
pub fn open_and_index(path: &Path) -> Result<(CaptureMap, Vec<PacketIndex>)> {
    let file = File::open(path).context("failed to open capture file")?;
    let capture = CaptureMap::new(&file).context("failed to mmap capture file")?;
    let indices = build_index(capture.as_bytes())?;
    Ok((capture, indices))
}

/// Open and memory-map a capture file without indexing.
pub fn open_and_mmap(path: &Path) -> Result<CaptureMap> {
    let file = File::open(path).context("failed to open capture file")?;
    CaptureMap::new(&file).context("failed to mmap capture file")
}

/// Parse the file header and return an `IndexState` for chunked indexing.
pub fn start_indexing(data: &[u8]) -> Result<packet_dissector_pcap::IndexState> {
    packet_dissector_pcap::build_index_start(data).map_err(Into::into)
}

/// Parse up to `limit` records and return them as `PacketIndex` entries.
pub fn index_chunk(
    data: &[u8],
    state: &mut packet_dissector_pcap::IndexState,
    limit: usize,
) -> Result<Vec<PacketIndex>> {
    let records = packet_dissector_pcap::build_index_chunk(data, state, limit)
        .map_err(crate::error::DsctError::from)?;
    Ok(convert_records(records))
}

/// Build a packet index from mmap-backed bytes.
///
/// Supports both pcap and pcapng formats.  Delegates to `packet_dissector_pcap`
/// for format parsing.
pub fn build_index(data: &[u8]) -> Result<Vec<PacketIndex>> {
    let records =
        packet_dissector_pcap::build_index(data).map_err(crate::error::DsctError::from)?;
    Ok(convert_records(records))
}

/// Convert pcap library records to the compact TUI index representation.
pub(super) fn convert_records(
    records: Vec<packet_dissector_pcap::PacketRecord>,
) -> Vec<PacketIndex> {
    records
        .into_iter()
        .map(|r| PacketIndex {
            data_offset: r.data_offset,
            captured_len: r.captured_len,
            original_len: r.original_len,
            timestamp_secs: r.timestamp_secs,
            timestamp_usecs: r.timestamp_usecs,
            link_type: r.link_type,
            _pad: 0,
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Phase 2: On-demand dissection
// ---------------------------------------------------------------------------

/// Fully dissect the selected packet and build tree nodes.
pub fn dissect_selected(
    data: &[u8],
    link_type: u32,
    pkt_idx: usize,
    registry: &DissectorRegistry,
) -> SelectedPacket {
    let mut buf = DissectBuffer::new();
    // Partial dissection is acceptable; the tree shows whatever layers succeeded.
    let _ = registry.dissect_with_link_type(data, link_type, &mut buf);
    let packet_view = Packet::new(&buf, data);
    let tree_nodes = tree::build_tree(&packet_view);
    let owned = OwnedPacket::from_dissect_buf(&buf, data);
    SelectedPacket {
        pkt_idx,
        packet: owned,
        tree_nodes,
    }
}

/// Extract a display summary for a packet list row (on-demand dissection).
pub fn extract_row_summary(
    data: &[u8],
    link_type: u32,
    registry: &DissectorRegistry,
) -> RowSummary {
    let mut buf = DissectBuffer::new();
    match registry.dissect_with_link_type(data, link_type, &mut buf) {
        Ok(()) => {
            let protocol = buf
                .layers()
                .last()
                .map(|l| l.display_name.unwrap_or(l.name))
                .unwrap_or("");
            let (source, destination) = extract_addresses(&buf);
            let info = extract_info(&buf, data);
            RowSummary {
                source,
                destination,
                protocol,
                info,
            }
        }
        Err(_) => RowSummary {
            source: String::new(),
            destination: String::new(),
            protocol: "???",
            info: "dissection error".to_string(),
        },
    }
}

/// Format a timestamp from a `PacketIndex` for display.
pub fn format_index_timestamp(index: &PacketIndex) -> String {
    format_timestamp(index.timestamp_secs, index.timestamp_usecs)
}

/// Format a relative timestamp (seconds since `base`).
pub fn format_relative_timestamp(index: &PacketIndex, base: &PacketIndex) -> String {
    let secs = index.timestamp_secs as f64 - base.timestamp_secs as f64
        + (index.timestamp_usecs as f64 - base.timestamp_usecs as f64) / 1_000_000.0;
    format!("{secs:.6}")
}

/// Format a delta timestamp (seconds since `prev`).
pub fn format_delta_timestamp(index: &PacketIndex, prev: &PacketIndex) -> String {
    let secs = index.timestamp_secs as f64 - prev.timestamp_secs as f64
        + (index.timestamp_usecs as f64 - prev.timestamp_usecs as f64) / 1_000_000.0;
    format!("{secs:.6}")
}

// ---------------------------------------------------------------------------
// Summary extraction helpers
// ---------------------------------------------------------------------------

/// Extract source and destination addresses, appending `:port` when available.
fn extract_addresses(buf: &DissectBuffer<'_>) -> (String, String) {
    let extract_pair = |layer: &Layer| {
        (
            buf.field_by_name(layer, "src")
                .map(|f| format_addr(&f.value))
                .unwrap_or_default(),
            buf.field_by_name(layer, "dst")
                .map(|f| format_addr(&f.value))
                .unwrap_or_default(),
        )
    };

    if let Some(layer) = buf.layer_by_name("IPv4") {
        extract_pair(layer)
    } else if let Some(layer) = buf.layer_by_name("IPv6") {
        extract_pair(layer)
    } else if let Some(layer) = buf.layer_by_name("Ethernet") {
        extract_pair(layer)
    } else {
        (String::new(), String::new())
    }
}

fn extract_u16_from_buf(buf: &DissectBuffer<'_>, layer: &Layer, name: &str) -> Option<u16> {
    buf.field_by_name(layer, name).and_then(|f| match &f.value {
        FieldValue::U16(v) => Some(*v),
        _ => None,
    })
}

/// Public accessor for extracting a U16 field from a protocol layer
/// via a `DissectBuffer`.
pub fn extract_u16_field(buf: &DissectBuffer<'_>, layer: &Layer, name: &str) -> Option<u16> {
    extract_u16_from_buf(buf, layer, name)
}

/// Format a `FieldValue` as an address string (public, for stream key construction).
pub fn format_addr_value(value: &FieldValue<'_>) -> String {
    format_addr(value)
}

/// Extract cause_value_name from a GTPv2-C layer's IEs.
///
/// IE structure: `{ type_name: "Cause", value: Object({ cause_value_name: "..." }) }`
fn extract_gtpv2c_cause(buf: &DissectBuffer<'_>, layer: &Layer) -> Option<&'static str> {
    let ies_field = buf.field_by_name(layer, "ies")?;
    let ies_range = match &ies_field.value {
        FieldValue::Array(r) => r,
        _ => return None,
    };
    for elem in buf.nested_fields(ies_range) {
        if let FieldValue::Object(ie_range) = &elem.value {
            let ie_fields = buf.nested_fields(ie_range);
            // Check if this IE's "type_name" field is "Cause".
            let is_cause = ie_fields.iter().any(|f| {
                f.name() == "type_name" && matches!(&f.value, FieldValue::Str(s) if *s == "Cause")
            });
            if is_cause {
                for f in ie_fields {
                    if f.name() == "value"
                        && let FieldValue::Object(inner_range) = &f.value
                    {
                        let inner = buf.nested_fields(inner_range);
                        for vf in inner {
                            if vf.name() == "cause_value"
                                && let Some(df) = vf.descriptor.display_fn
                            {
                                return df(&vf.value, inner);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Extract result_code_name from a Diameter layer's AVPs.
fn extract_diameter_result_code<'a>(buf: &'a DissectBuffer<'_>, layer: &Layer) -> Option<&'a str> {
    let avps_field = buf.field_by_name(layer, "avps")?;
    let avps_range = match &avps_field.value {
        FieldValue::Array(r) => r,
        _ => return None,
    };
    for elem in buf.nested_fields(avps_range) {
        if let FieldValue::Object(obj_range) = &elem.value {
            let fields = buf.nested_fields(obj_range);
            let is_rc = fields.iter().any(|f| {
                f.name() == "name"
                    && matches!(&f.value, FieldValue::Str(s)
                        if *s == "Result-Code" || *s == "Experimental-Result-Code")
            });
            if is_rc {
                for f in fields {
                    if f.name() == "result_code_name"
                        && let FieldValue::Str(s) = &f.value
                    {
                        return Some(*s);
                    }
                }
            }
        }
    }
    None
}

/// Extract the value of an HTTP header by case-insensitive name.
fn extract_http_header<'a>(
    buf: &'a DissectBuffer<'_>,
    layer: &Layer,
    header_name: &str,
) -> Option<&'a str> {
    let headers_field = buf.field_by_name(layer, "headers")?;
    let headers_range = match &headers_field.value {
        FieldValue::Array(r) => r,
        _ => return None,
    };
    for elem in buf.nested_fields(headers_range) {
        if let FieldValue::Object(obj_range) = &elem.value {
            let fields = buf.nested_fields(obj_range);
            let name_match = fields.iter().any(|f| {
                f.name() == "name"
                    && matches!(&f.value, FieldValue::Str(s) if s.eq_ignore_ascii_case(header_name))
            });
            if name_match {
                for f in fields {
                    if f.name() == "value"
                        && let FieldValue::Str(s) = &f.value
                    {
                        return Some(*s);
                    }
                }
            }
        }
    }
    None
}

fn format_addr(value: &FieldValue<'_>) -> String {
    match value {
        FieldValue::Ipv4Addr(a) => format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
        FieldValue::Ipv6Addr(a) => super::tree::format_value(&FieldValue::Ipv6Addr(*a)),
        FieldValue::MacAddr(m) => m.to_string(),
        FieldValue::Str(s) => (*s).to_string(),
        _ => String::new(),
    }
}

/// Extract a one-line info string from the packet.
///
/// Strategy:
/// 1. Protocol-specific logic for DNS and HTTP.
/// 2. TCP flags (since ports are now in Source/Destination).
/// 3. Generic: collect `_name` suffixed fields from the topmost layer
///    (e.g., `command_name`, `type_name`, `result_code_name`).
/// 4. Fallback: first few meaningful fields of the topmost layer.
fn extract_info(buf: &DissectBuffer<'_>, data: &[u8]) -> String {
    // --- DNS: query/response + query name ---
    if let Some(layer) = buf.layer_by_name("DNS")
        && let Some(qr) = buf.field_by_name(layer, "qr")
    {
        let direction = match &qr.value {
            FieldValue::U8(0) => "Query",
            FieldValue::U8(1) => "Response",
            _ => "",
        };
        if let Some(q_field) = buf.field_by_name(layer, "questions")
            && let FieldValue::Array(q_range) = &q_field.value
        {
            let q_children = buf.nested_fields(q_range);
            if let Some(first) = q_children.first()
                && let FieldValue::Object(obj_range) = &first.value
            {
                let fields = buf.nested_fields(obj_range);
                let name_field = fields.iter().find(|f| f.name() == "name");
                let name: Option<String> = name_field.and_then(|f| match &f.value {
                    FieldValue::Str(s) => Some((*s).to_string()),
                    _ => format_field_to_string(f, data, layer, buf.scratch()),
                });
                let name = name.as_deref().unwrap_or("?");
                return format!("{direction} {name}");
            }
        }
        return direction.to_string();
    }

    // --- HTTP: request → "GET /path", response → "200 OK (text/html)" ---
    if let Some(layer) = buf.layer_by_name("HTTP") {
        let method = buf
            .field_by_name(layer, "method")
            .and_then(|f| match &f.value {
                FieldValue::Str(s) => Some(*s),
                _ => None,
            });
        let uri = buf
            .field_by_name(layer, "uri")
            .and_then(|f| match &f.value {
                FieldValue::Str(s) => Some(*s),
                _ => None,
            });
        if let (Some(m), Some(u)) = (method, uri) {
            return format!("{m} {u}");
        }
        if let Some(code) = extract_u16_from_buf(buf, layer, "status_code") {
            let reason = buf
                .field_by_name(layer, "reason_phrase")
                .and_then(|f| match &f.value {
                    FieldValue::Str(s) => Some(*s),
                    _ => None,
                });
            let content_type = extract_http_header(buf, layer, "Content-Type");
            let mut info = match reason {
                Some(r) => format!("{code} {r}"),
                None => format!("{code}"),
            };
            if let Some(ct) = content_type {
                let media = ct.split(';').next().unwrap_or(ct).trim();
                info.push_str(&format!(" ({media})"));
            }
            return info;
        }
    }

    let top_name = buf.layers().last().map(|l| l.name).unwrap_or("");

    // --- TCP: port → port [flags_name] (only when TCP is the topmost layer) ---
    if top_name == "TCP"
        && let Some(layer) = buf.layer_by_name("TCP")
    {
        let sp = extract_u16_from_buf(buf, layer, "src_port").unwrap_or(0);
        let dp = extract_u16_from_buf(buf, layer, "dst_port").unwrap_or(0);
        let flags_name = buf.resolve_display_name(layer, "flags_name");
        return match flags_name {
            Some(f) => format!("{sp} \u{2192} {dp} [{f}]"),
            None => format!("{sp} \u{2192} {dp}"),
        };
    }

    // --- UDP: port → port (only when UDP is the topmost layer) ---
    if top_name == "UDP"
        && let Some(layer) = buf.layer_by_name("UDP")
    {
        let sp = extract_u16_from_buf(buf, layer, "src_port").unwrap_or(0);
        let dp = extract_u16_from_buf(buf, layer, "dst_port").unwrap_or(0);
        return format!("{sp} \u{2192} {dp}");
    }

    // --- SCTP: port → port chunk_type_names (only when SCTP is the topmost layer) ---
    if top_name == "SCTP"
        && let Some(layer) = buf.layer_by_name("SCTP")
    {
        let sp = extract_u16_from_buf(buf, layer, "src_port").unwrap_or(0);
        let dp = extract_u16_from_buf(buf, layer, "dst_port").unwrap_or(0);
        if let Some(chunks_field) = buf.field_by_name(layer, "chunks")
            && let FieldValue::Array(chunks_range) = &chunks_field.value
        {
            let names: Vec<&str> = buf
                .nested_fields(chunks_range)
                .iter()
                .filter_map(|elem| {
                    if let FieldValue::Object(obj_range) = &elem.value {
                        let fields = buf.nested_fields(obj_range);
                        fields.iter().find_map(|f| {
                            if f.name() == "type" {
                                let display_fn = f.descriptor.display_fn?;
                                display_fn(&f.value, fields)
                            } else {
                                None
                            }
                        })
                    } else {
                        None
                    }
                })
                .collect();
            if !names.is_empty() {
                return format!("{sp} \u{2192} {dp} [{}]", names.join(", "));
            }
        }
        return format!("{sp} \u{2192} {dp}");
    }

    // --- GTPv2-C: message type name (+ Cause for responses) ---
    if let Some(layer) = buf.layer_by_name("GTPv2-C")
        && let Some(msg) = buf.resolve_display_name(layer, "message_type_name")
    {
        if msg.contains("Response")
            && let Some(cause) = extract_gtpv2c_cause(buf, layer)
        {
            return format!("{msg} ({cause})");
        }
        return msg.to_string();
    }

    // --- Diameter: command name (+ Result-Code for answers) ---
    if let Some(layer) = buf.layer_by_name("Diameter")
        && let Some(cmd) = buf.resolve_display_name(layer, "command_code_name")
    {
        let is_request = buf
            .field_by_name(layer, "is_request")
            .is_some_and(|f| matches!(f.value, FieldValue::U8(1)));
        if !is_request && let Some(rc) = extract_diameter_result_code(buf, layer) {
            return format!("{cmd} ({rc})");
        }
        return cmd.to_string();
    }

    // --- TLS: content type name (+ handshake type name if applicable) ---
    if let Some(layer) = buf.layer_by_name("TLS") {
        let ct = buf.resolve_display_name(layer, "content_type_name");
        let ht = buf.resolve_display_name(layer, "handshake_type_name");
        match (ct, ht) {
            (Some(ct), Some(ht)) => return format!("{ct}, {ht}"),
            (Some(ct), None) => return ct.to_string(),
            _ => {}
        }
    }

    // --- Generic: display names from topmost layer via display_fn ---
    if let Some(layer) = buf.layers().last() {
        let fields = buf.layer_fields(layer);
        let name_values: Vec<&str> = fields
            .iter()
            .filter_map(|f| {
                let display_fn = f.descriptor.display_fn?;
                let value = display_fn(&f.value, fields)?;
                if value.is_empty() || value == "Unknown" {
                    None
                } else {
                    Some(value)
                }
            })
            .collect();
        if !name_values.is_empty() {
            return name_values.join(" ");
        }
    }

    // --- Fallback: first few fields of topmost layer ---
    if let Some(layer) = buf.layers().last() {
        let parts: Vec<String> = buf
            .layer_fields(layer)
            .iter()
            .filter(|f| f.descriptor.display_fn.is_none())
            .take(3)
            .filter_map(|f| {
                let v = format_field_short(&f.value);
                if v.is_empty() {
                    None
                } else {
                    Some(format!("{}={}", f.name(), v))
                }
            })
            .collect();
        if !parts.is_empty() {
            return parts.join(" ");
        }
    }

    String::new()
}

/// Short string representation of a field value for the Info column fallback.
fn format_field_short(value: &FieldValue<'_>) -> String {
    match value {
        FieldValue::U8(v) => v.to_string(),
        FieldValue::U16(v) => v.to_string(),
        FieldValue::U32(v) => v.to_string(),
        FieldValue::U64(v) => v.to_string(),
        FieldValue::I32(v) => v.to_string(),
        FieldValue::Ipv4Addr(a) => format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
        FieldValue::MacAddr(m) => m.to_string(),
        FieldValue::Str(s) => {
            if s.len() > 30 {
                format!("{}...", &s[..27])
            } else {
                (*s).to_string()
            }
        }
        _ => String::new(),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use packet_dissector_core::field::MacAddr;

    /// Build a minimal pcap in memory (public for use in other test modules).
    pub fn build_pcap_for_test(n: usize) -> Vec<u8> {
        build_pcap_bytes(n)
    }

    /// Build a minimal pcap in memory.
    fn build_pcap_bytes(n: usize) -> Vec<u8> {
        let mut pcap_buf = Vec::new();
        // Global header
        pcap_buf.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
        pcap_buf.extend_from_slice(&2u16.to_le_bytes());
        pcap_buf.extend_from_slice(&4u16.to_le_bytes());
        pcap_buf.extend_from_slice(&0i32.to_le_bytes());
        pcap_buf.extend_from_slice(&0u32.to_le_bytes());
        pcap_buf.extend_from_slice(&65535u32.to_le_bytes());
        pcap_buf.extend_from_slice(&1u32.to_le_bytes()); // Ethernet

        let pkt: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x00,
            0x00, 0x01, 0x0A, 0x00, 0x00, 0x02, 0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
        ];
        for i in 0..n {
            let ts_sec = (i / 1000) as u32;
            let ts_usec = ((i % 1000) * 1000) as u32;
            pcap_buf.extend_from_slice(&ts_sec.to_le_bytes());
            pcap_buf.extend_from_slice(&ts_usec.to_le_bytes());
            pcap_buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            pcap_buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            pcap_buf.extend_from_slice(pkt);
        }
        pcap_buf
    }

    // -- Helper: push fields into a DissectBuffer to simulate old API --

    fn push_field<'a>(buf: &mut DissectBuffer<'a>, name: &'static str, value: FieldValue<'a>) {
        buf.push_field(test_desc(name, name), value, 0..0);
    }

    fn push_real_field<'a>(
        buf: &mut DissectBuffer<'a>,
        fds: &'static [packet_dissector_core::field::FieldDescriptor],
        name: &str,
        value: FieldValue<'a>,
    ) {
        let fd = fds.iter().find(|fd| fd.name == name).unwrap();
        buf.push_field(fd, value, 0..0);
    }

    fn push_field_with_display<'a>(
        buf: &mut DissectBuffer<'a>,
        name: &'static str,
        value: FieldValue<'a>,
        display_fn: packet_dissector_core::field::DisplayFn,
    ) {
        let fd = Box::leak(Box::new(packet_dissector_core::field::FieldDescriptor {
            name,
            display_name: name,
            field_type: packet_dissector_core::field::FieldType::U8,
            optional: false,
            children: None,
            display_fn: Some(display_fn),
            format_fn: None,
        }));
        buf.push_field(fd, value, 0..0);
    }

    /// Find a FieldDescriptor by name in a static descriptor slice.
    fn find_fd(
        fds: &'static [packet_dissector_core::field::FieldDescriptor],
        name: &str,
    ) -> &'static packet_dissector_core::field::FieldDescriptor {
        fds.iter().find(|fd| fd.name == name).unwrap()
    }

    #[test]
    fn build_index_single_packet() {
        let pcap = build_pcap_bytes(1);
        let indices = build_index(&pcap).unwrap();
        assert_eq!(indices.len(), 1);
        assert_eq!(indices[0].captured_len, 42);
        assert_eq!(indices[0].link_type, 1);
        assert_eq!(indices[0].data_offset, 40); // 24 header + 16 record header
    }

    #[test]
    fn build_index_multiple_packets() {
        let pcap = build_pcap_bytes(100);
        let indices = build_index(&pcap).unwrap();
        assert_eq!(indices.len(), 100);
        for i in 1..indices.len() {
            assert!(indices[i].data_offset > indices[i - 1].data_offset);
        }
    }

    #[test]
    fn build_index_empty_file() {
        let result = build_index(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn build_index_bad_magic() {
        let result = build_index(&[0x00; 24]);
        assert!(result.is_err());
    }

    #[test]
    fn extract_row_summary_udp() {
        let pcap = build_pcap_bytes(1);
        let indices = build_index(&pcap).unwrap();
        let data = &pcap[indices[0].data_offset as usize..][..indices[0].captured_len as usize];
        let registry = DissectorRegistry::default();
        let summary = extract_row_summary(data, indices[0].link_type as u32, &registry);
        assert_eq!(summary.source, "10.0.0.1");
        assert_eq!(summary.destination, "10.0.0.2");
        assert_eq!(summary.protocol, "UDP");
        assert_eq!(summary.info, "4096 \u{2192} 4097");
    }

    #[test]
    fn format_index_timestamp_works() {
        let index = PacketIndex {
            data_offset: 0,
            captured_len: 0,
            original_len: 0,
            timestamp_secs: 1000000,
            timestamp_usecs: 500000,
            link_type: 1,
            _pad: 0,
        };
        let ts = format_index_timestamp(&index);
        assert!(!ts.is_empty());
        assert!(ts.contains("500000"));
    }

    #[test]
    fn extract_addresses_ipv4() {
        let mut buf = DissectBuffer::new();
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
        buf.end_layer();
        let (src, dst) = extract_addresses(&buf);
        assert_eq!(src, "10.0.0.1");
        assert_eq!(dst, "10.0.0.2");
    }

    #[test]
    fn extract_addresses_mac_fallback() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Ethernet", None, &[], 0..14);
        buf.push_field(
            test_desc("src", "Source"),
            FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
            6..12,
        );
        buf.push_field(
            test_desc("dst", "Destination"),
            FieldValue::MacAddr(MacAddr([0xff; 6])),
            0..6,
        );
        buf.end_layer();
        let (src, _) = extract_addresses(&buf);
        assert_eq!(src, "00:11:22:33:44:55");
    }

    #[test]
    fn extract_info_empty() {
        let buf = DissectBuffer::new();
        assert!(extract_info(&buf, &[]).is_empty());
    }

    #[test]
    fn format_addr_variants() {
        assert_eq!(format_addr(&FieldValue::Str("x")), "x");
        assert_eq!(format_addr(&FieldValue::U32(0)), "");
    }

    #[test]
    fn extract_info_dns_query() {
        // Build: DNS layer with qr=0, questions=[{name: "example.com"}]
        let name_data: &str = "example.com";
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..0);
        push_field(&mut buf, "qr", FieldValue::U8(0));
        let q_idx = buf.begin_container(
            test_desc("questions", "Questions"),
            FieldValue::Array(0..0),
            0..0,
        );
        let obj_idx = buf.begin_container(test_desc("q", "Q"), FieldValue::Object(0..0), 0..0);
        push_field(&mut buf, "name", FieldValue::Str(name_data));
        buf.end_container(obj_idx);
        buf.end_container(q_idx);
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "Query example.com");
    }

    #[test]
    fn extract_info_dns_response_no_questions() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..0);
        push_field(&mut buf, "qr", FieldValue::U8(1));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "Response");
    }

    #[test]
    fn extract_info_http_request() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("HTTP", None, &[], 0..0);
        push_field(&mut buf, "method", FieldValue::Str("GET"));
        push_field(&mut buf, "uri", FieldValue::Str("/index.html"));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "GET /index.html");
    }

    #[test]
    fn extract_info_http_response_with_content_type() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("HTTP", None, &[], 0..0);
        push_field(&mut buf, "status_code", FieldValue::U16(200));
        push_field(&mut buf, "reason_phrase", FieldValue::Str("OK"));
        let h_idx = buf.begin_container(
            test_desc("headers", "Headers"),
            FieldValue::Array(0..0),
            0..0,
        );
        let obj_idx = buf.begin_container(test_desc("h", "H"), FieldValue::Object(0..0), 0..0);
        push_field(&mut buf, "name", FieldValue::Str("Content-Type"));
        push_field(
            &mut buf,
            "value",
            FieldValue::Str("text/html; charset=utf-8"),
        );
        buf.end_container(obj_idx);
        buf.end_container(h_idx);
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "200 OK (text/html)");
    }

    #[test]
    fn extract_info_http_response_no_reason() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("HTTP", None, &[], 0..0);
        push_field(&mut buf, "status_code", FieldValue::U16(404));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "404");
    }

    #[test]
    fn extract_info_tcp_with_flags() {
        let tcp_fds = packet_dissector::dissectors::tcp::FIELD_DESCRIPTORS;
        let mut buf = DissectBuffer::new();
        buf.begin_layer("TCP", None, &[], 0..20);
        push_field(&mut buf, "src_port", FieldValue::U16(443));
        push_field(&mut buf, "dst_port", FieldValue::U16(52000));
        push_real_field(&mut buf, tcp_fds, "flags", FieldValue::U8(0x12));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "443 \u{2192} 52000 [SYN, ACK]");
    }

    #[test]
    fn extract_info_tcp_without_flags() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("TCP", None, &[], 0..20);
        push_field(&mut buf, "src_port", FieldValue::U16(80));
        push_field(&mut buf, "dst_port", FieldValue::U16(1234));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "80 \u{2192} 1234");
    }

    #[test]
    fn extract_info_sctp_with_chunks() {
        use packet_dissector::dissector::Dissector;
        let sctp_fds = packet_dissector::dissectors::sctp::SctpDissector.field_descriptors();
        let chunk_children = find_fd(sctp_fds, "chunks").children.unwrap();
        let chunk_type_fd = find_fd(chunk_children, "type");

        let mut buf = DissectBuffer::new();
        buf.begin_layer("SCTP", None, &[], 0..12);
        push_field(&mut buf, "src_port", FieldValue::U16(2905));
        push_field(&mut buf, "dst_port", FieldValue::U16(2905));
        let chunks_idx =
            buf.begin_container(test_desc("chunks", "Chunks"), FieldValue::Array(0..0), 0..0);
        // chunk[0]: type=1 (INIT)
        let c0 = buf.begin_container(test_desc("c", "C"), FieldValue::Object(0..0), 0..0);
        buf.push_field(chunk_type_fd, FieldValue::U8(1), 0..0);
        buf.end_container(c0);
        // chunk[1]: type=0 (DATA)
        let c1 = buf.begin_container(test_desc("c", "C"), FieldValue::Object(0..0), 0..0);
        buf.push_field(chunk_type_fd, FieldValue::U8(0), 0..0);
        buf.end_container(c1);
        buf.end_container(chunks_idx);
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "2905 \u{2192} 2905 [INIT, DATA]");
    }

    #[test]
    fn extract_info_sctp_no_chunks() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("SCTP", None, &[], 0..12);
        push_field(&mut buf, "src_port", FieldValue::U16(100));
        push_field(&mut buf, "dst_port", FieldValue::U16(200));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "100 \u{2192} 200");
    }

    #[test]
    fn extract_info_gtpv2c_request() {
        use packet_dissector::dissector::Dissector;
        let gtpv2c_fds = packet_dissector::dissectors::gtpv2c::Gtpv2cDissector.field_descriptors();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("GTPv2-C", None, &[], 0..0);
        push_real_field(&mut buf, gtpv2c_fds, "message_type", FieldValue::U8(32));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "Create Session Request");
    }

    #[test]
    fn extract_info_gtpv2c_response_with_cause() {
        use packet_dissector::dissector::Dissector;
        let gtpv2c_fds = packet_dissector::dissectors::gtpv2c::Gtpv2cDissector.field_descriptors();
        let ie_children = find_fd(gtpv2c_fds, "ies").children.unwrap();

        let mut buf = DissectBuffer::new();
        buf.begin_layer("GTPv2-C", None, &[], 0..0);
        push_real_field(&mut buf, gtpv2c_fds, "message_type", FieldValue::U8(33));
        let ies_idx = buf.begin_container(test_desc("ies", "IEs"), FieldValue::Array(0..0), 0..0);
        let ie_obj = buf.begin_container(test_desc("ie", "IE"), FieldValue::Object(0..0), 0..0);
        push_real_field(&mut buf, ie_children, "type", FieldValue::U32(2));
        push_field(&mut buf, "type_name", FieldValue::Str("Cause"));
        let val_obj =
            buf.begin_container(test_desc("value", "Value"), FieldValue::Object(0..0), 0..0);
        push_field_with_display(
            &mut buf,
            "cause_value",
            FieldValue::U8(16),
            |v, _| match v {
                FieldValue::U8(16) => Some("Request accepted"),
                _ => None,
            },
        );
        buf.end_container(val_obj);
        buf.end_container(ie_obj);
        buf.end_container(ies_idx);
        buf.end_layer();
        assert_eq!(
            extract_info(&buf, &[]),
            "Create Session Response (Request accepted)"
        );
    }

    #[test]
    fn extract_info_diameter_answer_with_result_code() {
        use packet_dissector::dissector::Dissector;
        let dia_fds = packet_dissector::dissectors::diameter::DiameterDissector.field_descriptors();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Diameter", None, &[], 0..0);
        push_real_field(&mut buf, dia_fds, "command_code", FieldValue::U32(272));
        push_field(&mut buf, "is_request", FieldValue::U8(0));
        let avps_idx =
            buf.begin_container(test_desc("avps", "AVPs"), FieldValue::Array(0..0), 0..0);
        let avp_obj = buf.begin_container(test_desc("avp", "AVP"), FieldValue::Object(0..0), 0..0);
        push_field(&mut buf, "name", FieldValue::Str("Result-Code"));
        push_field(
            &mut buf,
            "result_code_name",
            FieldValue::Str("DIAMETER_SUCCESS"),
        );
        buf.end_container(avp_obj);
        buf.end_container(avps_idx);
        buf.end_layer();
        assert_eq!(
            extract_info(&buf, &[]),
            "Credit-Control-Answer (DIAMETER_SUCCESS)"
        );
    }

    #[test]
    fn extract_info_diameter_request() {
        use packet_dissector::dissector::Dissector;
        let dia_fds = packet_dissector::dissectors::diameter::DiameterDissector.field_descriptors();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Diameter", None, &[], 0..0);
        push_real_field(&mut buf, dia_fds, "command_code", FieldValue::U32(272));
        push_field(&mut buf, "is_request", FieldValue::U8(1));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "Credit-Control-Request");
    }

    #[test]
    fn extract_info_tls_handshake() {
        use packet_dissector::dissector::Dissector;
        let tls_fds = packet_dissector::dissectors::tls::TlsDissector.field_descriptors();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("TLS", None, &[], 0..0);
        push_real_field(&mut buf, tls_fds, "content_type", FieldValue::U8(22));
        push_real_field(&mut buf, tls_fds, "handshake_type", FieldValue::U8(1));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "Handshake, Client Hello");
    }

    #[test]
    fn extract_info_tls_content_type_only() {
        use packet_dissector::dissector::Dissector;
        let tls_fds = packet_dissector::dissectors::tls::TlsDissector.field_descriptors();
        let mut buf = DissectBuffer::new();
        buf.begin_layer("TLS", None, &[], 0..0);
        push_real_field(&mut buf, tls_fds, "content_type", FieldValue::U8(23));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "Application Data");
    }

    #[test]
    fn extract_info_generic_name_fields() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("SomeProto", None, &[], 0..0);
        push_field_with_display(&mut buf, "type", FieldValue::U8(1), |_, _| Some("Hello"));
        push_field_with_display(&mut buf, "status", FieldValue::U8(0), |_, _| Some("OK"));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "Hello OK");
    }

    #[test]
    fn extract_info_generic_name_fields_skip_unknown() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("SomeProto", None, &[], 0..0);
        push_field_with_display(&mut buf, "type", FieldValue::U8(0), |_, _| Some("Unknown"));
        push_field(&mut buf, "version", FieldValue::U8(2));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "version=2");
    }

    #[test]
    fn extract_info_fallback_first_fields() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Custom", None, &[], 0..0);
        push_field(&mut buf, "version", FieldValue::U8(1));
        push_field(&mut buf, "length", FieldValue::U16(100));
        push_field(&mut buf, "id", FieldValue::U32(42));
        buf.end_layer();
        assert_eq!(extract_info(&buf, &[]), "version=1 length=100 id=42");
    }

    #[test]
    fn extract_addresses_ipv6() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("IPv6", None, &[], 0..40);
        buf.push_field(
            test_desc("src", "Source"),
            FieldValue::Ipv6Addr([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ]),
            8..24,
        );
        buf.push_field(
            test_desc("dst", "Destination"),
            FieldValue::Ipv6Addr([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
            ]),
            24..40,
        );
        buf.end_layer();
        let (src, dst) = extract_addresses(&buf);
        assert!(src.contains("2001"));
        assert!(dst.contains("2001"));
    }

    #[test]
    fn extract_addresses_no_layers() {
        let buf = DissectBuffer::new();
        let (src, dst) = extract_addresses(&buf);
        assert!(src.is_empty());
        assert!(dst.is_empty());
    }

    #[test]
    fn format_relative_timestamp_same() {
        let base = PacketIndex {
            data_offset: 0,
            captured_len: 0,
            original_len: 0,
            timestamp_secs: 1000,
            timestamp_usecs: 500000,
            link_type: 1,
            _pad: 0,
        };
        assert_eq!(format_relative_timestamp(&base, &base), "0.000000");
    }

    #[test]
    fn format_relative_timestamp_positive() {
        let base = PacketIndex {
            data_offset: 0,
            captured_len: 0,
            original_len: 0,
            timestamp_secs: 1000,
            timestamp_usecs: 0,
            link_type: 1,
            _pad: 0,
        };
        let index = PacketIndex {
            data_offset: 0,
            captured_len: 0,
            original_len: 0,
            timestamp_secs: 1002,
            timestamp_usecs: 500000,
            link_type: 1,
            _pad: 0,
        };
        assert_eq!(format_relative_timestamp(&index, &base), "2.500000");
    }

    #[test]
    fn format_delta_timestamp_works() {
        let prev = PacketIndex {
            data_offset: 0,
            captured_len: 0,
            original_len: 0,
            timestamp_secs: 100,
            timestamp_usecs: 0,
            link_type: 1,
            _pad: 0,
        };
        let curr = PacketIndex {
            data_offset: 0,
            captured_len: 0,
            original_len: 0,
            timestamp_secs: 100,
            timestamp_usecs: 1000,
            link_type: 1,
            _pad: 0,
        };
        assert_eq!(format_delta_timestamp(&curr, &prev), "0.001000");
    }

    #[test]
    fn format_field_short_variants() {
        assert_eq!(format_field_short(&FieldValue::U8(42)), "42");
        assert_eq!(format_field_short(&FieldValue::U16(1000)), "1000");
        assert_eq!(format_field_short(&FieldValue::U32(999)), "999");
        assert_eq!(format_field_short(&FieldValue::U64(123456)), "123456");
        assert_eq!(format_field_short(&FieldValue::I32(-5)), "-5");
        assert_eq!(
            format_field_short(&FieldValue::Ipv4Addr([192, 168, 1, 1])),
            "192.168.1.1"
        );
        assert_eq!(
            format_field_short(&FieldValue::MacAddr(MacAddr([
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
            ]))),
            "aa:bb:cc:dd:ee:ff"
        );
        let long_str = "a".repeat(40);
        let long_ref: &str = &long_str;
        let short = format_field_short(&FieldValue::Str(long_ref));
        assert!(short.len() <= 33);
        assert!(short.ends_with("..."));
        assert_eq!(format_field_short(&FieldValue::Str("hello")), "hello");
        assert!(format_field_short(&FieldValue::Bytes(&[1, 2])).is_empty());
    }

    #[test]
    fn extract_http_header_case_insensitive() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("HTTP", None, &[], 0..0);
        let h_idx = buf.begin_container(
            test_desc("headers", "Headers"),
            FieldValue::Array(0..0),
            0..0,
        );
        let obj = buf.begin_container(test_desc("h", "H"), FieldValue::Object(0..0), 0..0);
        push_field(&mut buf, "name", FieldValue::Str("content-type"));
        push_field(&mut buf, "value", FieldValue::Str("application/json"));
        buf.end_container(obj);
        buf.end_container(h_idx);
        buf.end_layer();
        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(
            extract_http_header(&buf, layer, "Content-Type"),
            Some("application/json")
        );
    }

    #[test]
    fn extract_http_header_not_found() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("HTTP", None, &[], 0..0);
        buf.end_layer();
        let layer = buf.layer_by_name("HTTP").unwrap();
        assert_eq!(extract_http_header(&buf, layer, "X-Missing"), None);
    }

    #[test]
    fn extract_gtpv2c_cause_missing() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("GTPv2-C", None, &[], 0..0);
        buf.end_layer();
        let layer = buf.layer_by_name("GTPv2-C").unwrap();
        assert_eq!(extract_gtpv2c_cause(&buf, layer), None);
    }

    #[test]
    fn extract_diameter_result_code_missing() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Diameter", None, &[], 0..0);
        buf.end_layer();
        let layer = buf.layer_by_name("Diameter").unwrap();
        assert_eq!(extract_diameter_result_code(&buf, layer), None);
    }

    #[test]
    fn extract_u16_field_works() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("TCP", None, &[], 0..0);
        push_field(&mut buf, "src_port", FieldValue::U16(443));
        buf.end_layer();
        let layer = buf.layer_by_name("TCP").unwrap();
        assert_eq!(extract_u16_field(&buf, layer, "src_port"), Some(443));
        assert_eq!(extract_u16_field(&buf, layer, "missing"), None);
    }

    #[test]
    fn extract_u16_field_wrong_type() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("TCP", None, &[], 0..0);
        push_field(&mut buf, "src_port", FieldValue::U32(443));
        buf.end_layer();
        let layer = buf.layer_by_name("TCP").unwrap();
        assert_eq!(extract_u16_field(&buf, layer, "src_port"), None);
    }

    #[test]
    fn format_addr_value_ipv4() {
        assert_eq!(
            format_addr_value(&FieldValue::Ipv4Addr([127, 0, 0, 1])),
            "127.0.0.1"
        );
    }

    #[test]
    fn dissect_selected_returns_tree_nodes() {
        let pcap = build_pcap_bytes(1);
        let indices = build_index(&pcap).unwrap();
        let data = &pcap[indices[0].data_offset as usize..][..indices[0].captured_len as usize];
        let registry = DissectorRegistry::default();
        let sel = dissect_selected(data, indices[0].link_type as u32, 0, &registry);
        assert_eq!(sel.pkt_idx, 0);
        assert!(!sel.tree_nodes.is_empty());
        assert!(!sel.packet.layers.is_empty());
    }
}
