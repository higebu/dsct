//! Shared JSON schema definitions and field metadata helpers.
//!
//! Centralises the output schema literals and helper functions that were
//! previously duplicated between `main.rs` and `mcp/tools.rs`.

use packet_dissector_core::field::{FieldDescriptor, FieldType};

/// Return the JSON schema for the `dsct read` output format.
pub fn read_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "dsct read packet record",
        "description": "A single dissected packet from dsct read output (JSONL mode: one per line).",
        "type": "object",
        "required": ["number", "timestamp", "length", "original_length", "stack", "layers"],
        "properties": {
            "number": {
                "type": "integer",
                "description": "1-based packet number within the capture."
            },
            "timestamp": {
                "type": "string",
                "format": "date-time",
                "description": "ISO 8601 timestamp of the packet."
            },
            "length": {
                "type": "integer",
                "description": "Captured length in bytes."
            },
            "original_length": {
                "type": "integer",
                "description": "Original length on the wire in bytes."
            },
            "stack": {
                "type": "string",
                "description": "Protocol stack summary (e.g., \"Ethernet:IPv4:UDP:DNS\")."
            },
            "layers": {
                "type": "array",
                "description": "Protocol layers from outermost to innermost.",
                "items": {
                    "type": "object",
                    "required": ["protocol", "fields"],
                    "properties": {
                        "protocol": {
                            "type": "string",
                            "description": "Protocol name (e.g., \"IPv4\", \"TCP\", \"DNS\")."
                        },
                        "fields": {
                            "type": "object",
                            "description": "Protocol-specific fields. Use 'dsct fields <protocol>' for details.",
                            "additionalProperties": true
                        }
                    }
                }
            }
        }
    })
}

/// Return the JSON schema for the `dsct stats` output format.
pub fn stats_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "dsct stats output",
        "description": "Capture file statistics from dsct stats.",
        "type": "object",
        "required": ["type", "total_packets", "duration_secs", "protocols"],
        "properties": {
            "type": {
                "type": "string",
                "const": "stats"
            },
            "total_packets": {
                "type": "integer",
                "description": "Total number of packets in the capture."
            },
            "time_start": {
                "type": "string",
                "format": "date-time",
                "description": "ISO 8601 timestamp of the first packet. Omitted when no valid timestamps exist."
            },
            "time_end": {
                "type": "string",
                "format": "date-time",
                "description": "ISO 8601 timestamp of the last packet. Omitted when no valid timestamps exist."
            },
            "duration_secs": {
                "type": "number",
                "description": "Capture duration in seconds."
            },
            "protocols": {
                "type": "object",
                "description": "Protocol name to packet count mapping.",
                "additionalProperties": {
                    "type": "integer"
                }
            },
            "dns": {
                "type": "object",
                "description": "DNS protocol statistics. Present when -p dns is specified."
            },
            "http": {
                "type": "object",
                "description": "HTTP protocol statistics. Present when -p http is specified."
            },
            "tls": {
                "type": "object",
                "description": "TLS protocol statistics. Present when -p tls is specified."
            },
            "dhcp": {
                "type": "object",
                "description": "DHCP protocol statistics. Present when -p dhcp is specified."
            },
            "sip": {
                "type": "object",
                "description": "SIP protocol statistics. Present when -p sip is specified."
            },
            "rtp": {
                "type": "object",
                "description": "RTP protocol statistics. Present when -p rtp is specified."
            },
            "bgp": {
                "type": "object",
                "description": "BGP protocol statistics. Present when -p bgp is specified."
            },
            "ospf": {
                "type": "object",
                "description": "OSPF protocol statistics. Present when -p ospf is specified."
            },
            "radius": {
                "type": "object",
                "description": "RADIUS protocol statistics. Present when -p radius is specified."
            },
            "diameter": {
                "type": "object",
                "description": "Diameter protocol statistics. Present when -p diameter is specified."
            },
            "gtpv2c": {
                "type": "object",
                "description": "GTPv2-C protocol statistics. Present when -p gtpv2c is specified."
            },
            "pfcp": {
                "type": "object",
                "description": "PFCP protocol statistics. Present when -p pfcp is specified."
            },
            "top_talkers": {
                "type": "array",
                "description": "Top IP pairs by traffic volume. Omitted unless --top-talkers is specified."
            },
            "tcp_streams": {
                "type": "array",
                "description": "Per-stream TCP summaries. Omitted unless --stream-summary is specified."
            }
        }
    })
}

/// Convert a [`FieldType`] to a short machine-readable string.
pub fn field_type_str(ft: FieldType) -> &'static str {
    match ft {
        FieldType::U8 => "u8",
        FieldType::U16 => "u16",
        FieldType::U32 => "u32",
        FieldType::U64 => "u64",
        FieldType::I32 => "i32",
        FieldType::Bytes => "bytes",
        FieldType::Ipv4Addr => "ipv4addr",
        FieldType::Ipv6Addr => "ipv6addr",
        FieldType::MacAddr => "macaddr",
        FieldType::Str => "str",
        FieldType::Array => "array",
        FieldType::Object => "object",
    }
}

/// Convert a [`FieldDescriptor`] to a JSON representation for the `fields` command.
pub fn fd_to_json(
    fd: &FieldDescriptor,
    prefix: &str,
    schema_short: &str,
    schema_name: &str,
) -> serde_json::Value {
    let qualified = format!("{}.{}", prefix, fd.name);
    let type_str = field_type_str(fd.field_type);
    let mut entry = serde_json::json!({
        "qualified_name": qualified,
        "display_name": fd.display_name,
        "type": type_str,
        "optional": fd.optional,
        "protocol": schema_short,
        "protocol_name": schema_name,
    });
    if let Some(children) = fd.children {
        let child_entries: Vec<serde_json::Value> = children
            .iter()
            .map(|c| fd_to_json(c, &qualified, schema_short, schema_name))
            .collect();
        entry["children"] = serde_json::Value::Array(child_entries);
    }
    entry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_schema_has_required_fields() {
        let schema = read_schema();
        assert_eq!(schema["title"], "dsct read packet record");
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "number"));
        assert!(required.iter().any(|v| v == "layers"));
    }

    #[test]
    fn stats_schema_has_required_fields() {
        let schema = stats_schema();
        assert_eq!(schema["title"], "dsct stats output");
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "total_packets"));
    }

    #[test]
    fn field_type_str_all_variants() {
        assert_eq!(field_type_str(FieldType::U8), "u8");
        assert_eq!(field_type_str(FieldType::U16), "u16");
        assert_eq!(field_type_str(FieldType::U32), "u32");
        assert_eq!(field_type_str(FieldType::U64), "u64");
        assert_eq!(field_type_str(FieldType::I32), "i32");
        assert_eq!(field_type_str(FieldType::Bytes), "bytes");
        assert_eq!(field_type_str(FieldType::Ipv4Addr), "ipv4addr");
        assert_eq!(field_type_str(FieldType::Ipv6Addr), "ipv6addr");
        assert_eq!(field_type_str(FieldType::MacAddr), "macaddr");
        assert_eq!(field_type_str(FieldType::Str), "str");
        assert_eq!(field_type_str(FieldType::Array), "array");
        assert_eq!(field_type_str(FieldType::Object), "object");
    }
}
