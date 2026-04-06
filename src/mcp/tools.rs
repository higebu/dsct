//! MCP tool implementations for dsct.
//!
//! Each `do_*` function contains the core logic for an MCP tool, returning
//! a [`serde_json::Value`] on success or an error message string on failure.
//! The caller wraps the value in both `structuredContent` and a `content`
//! text fallback for the MCP response.

use std::ops::ControlFlow;
use std::path::PathBuf;
use std::time::Instant;

use packet_dissector::registry::DissectorRegistry;
use serde::Deserialize;

use super::limits::ResourceLimits;
use crate::decode_as;
use crate::error::{DsctError, Result as DsctResult, ResultExt, format_error};
use crate::esp_sa;
use crate::filter::normalize_protocol_name;
use crate::stats;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deserialize a value that is either a single string or an array of strings
/// into a `Vec<String>`.
fn string_or_vec<'de, D>(deserializer: D) -> std::result::Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de;

    struct StringOrVec;

    impl<'de> de::Visitor<'de> for StringOrVec {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a string or an array of strings")
        }

        fn visit_str<E: de::Error>(self, value: &str) -> std::result::Result<Vec<String>, E> {
            Ok(vec![value.to_owned()])
        }

        fn visit_seq<A: de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Vec<String>, A::Error> {
            let mut v = Vec::with_capacity(seq.size_hint().unwrap_or(0));
            while let Some(s) = seq.next_element()? {
                v.push(s);
            }
            Ok(v)
        }
    }

    deserializer.deserialize_any(StringOrVec)
}

// ---------------------------------------------------------------------------
// Parameter structs
// ---------------------------------------------------------------------------

/// Parameters for the `dsct_get_stats` tool.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DsctGetStatsParams {
    /// Path to the pcap/pcapng file.
    pub file: String,
    /// Restrict statistics to these protocols.
    #[serde(default, deserialize_with = "string_or_vec")]
    pub protocols: Vec<String>,
    /// Show top IP pairs by traffic volume.
    #[serde(default)]
    pub top_talkers: bool,
    /// Show per-stream TCP summary.
    #[serde(default)]
    pub stream_summary: bool,
    /// Maximum entries in ranked lists (default 10).
    #[serde(default)]
    pub top: Option<usize>,
    /// Override protocol dissection for a port.
    #[serde(default)]
    pub decode_as: Vec<String>,
    /// ESP Security Association for decryption.
    #[serde(default)]
    pub esp_sa: Vec<String>,
}

/// Parameters for the `dsct_list_fields` tool.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DsctListFieldsParams {
    /// Show fields only for these protocols (e.g. "dns", "ipv4").
    #[serde(default, deserialize_with = "string_or_vec")]
    pub protocols: Vec<String>,
}

/// Parameters for the `dsct_get_schema` tool.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DsctGetSchemaParams {
    /// Command name: "read" or "stats" (defaults to "read").
    #[serde(default)]
    pub command: Option<String>,
}

// ---------------------------------------------------------------------------
// Tool implementations
// ---------------------------------------------------------------------------

/// Get capture file statistics as a JSON value.
pub(crate) fn do_get_stats(
    arguments: serde_json::Value,
    limits: &ResourceLimits,
) -> std::result::Result<serde_json::Value, String> {
    let params: DsctGetStatsParams =
        serde_json::from_value(arguments).map_err(|e| format!("invalid arguments: {e}"))?;
    do_get_stats_inner(params, limits).map_err(|e| format_error(&e))
}

fn do_get_stats_inner(
    params: DsctGetStatsParams,
    limits: &ResourceLimits,
) -> DsctResult<serde_json::Value> {
    let file = PathBuf::from(&params.file);

    let file_meta =
        std::fs::metadata(&file).context(format!("failed to stat file: {}", file.display()))?;
    if file_meta.len() > limits.max_file_size {
        return Err(DsctError::msg(format!(
            "file size ({} bytes) exceeds limit ({} bytes)",
            file_meta.len(),
            limits.max_file_size
        )));
    }

    let top_n = params.top.unwrap_or(10);

    let mut registry = DissectorRegistry::default();
    decode_as::parse_and_apply(&mut registry, &params.decode_as)?;
    esp_sa::parse_and_apply(&registry, &params.esp_sa)?;

    let proto_norm: Vec<String> = params
        .protocols
        .iter()
        .map(|p| normalize_protocol_name(p))
        .collect();
    let enable_tcp_streams =
        params.stream_summary && (proto_norm.is_empty() || proto_norm.iter().any(|p| p == "tcp"));

    let flags =
        stats::StatsFlags::from_protocols(&proto_norm, params.top_talkers, enable_tcp_streams);
    let mut collector = stats::StatsCollector::from_flags(&flags);

    let deadline = Instant::now() + limits.timeout;
    let reader = crate::input::CaptureReader::open(&file).context("failed to open capture file")?;

    let mut packets_seen: u64 = 0;
    let mut dissect_buf = packet_dissector_core::packet::DissectBuffer::new();

    reader.for_each_packet(|meta, data| {
        // Amortise the syscall: check the clock every 1024 packets.
        packets_seen += 1;
        if packets_seen.is_multiple_of(1024) && Instant::now() > deadline {
            return Ok(ControlFlow::Break(()));
        }

        collector.record_meta(meta.timestamp_secs, meta.timestamp_usecs);

        let dissect_buf = dissect_buf.clear_into();
        if registry
            .dissect_with_link_type(data, meta.link_type, dissect_buf)
            .is_ok()
        {
            let packet = packet_dissector_core::packet::Packet::new(dissect_buf, data);
            collector.process_packet(
                &packet,
                meta.timestamp_secs,
                meta.timestamp_usecs,
                meta.original_length,
            );
        }

        Ok(ControlFlow::Continue(()))
    })?;

    let output = collector.finalize(top_n);
    serde_json::to_value(&output).context("failed to serialize stats")
}

/// List supported protocols as a JSON array value.
pub(crate) fn do_list_protocols() -> std::result::Result<serde_json::Value, String> {
    let registry = DissectorRegistry::default();
    let schemas = registry.all_field_schemas();
    let entries: Vec<serde_json::Value> = schemas
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.short_name,
                "full_name": s.name,
            })
        })
        .collect();
    Ok(serde_json::Value::Array(entries))
}

pub(crate) fn do_list_fields(
    arguments: serde_json::Value,
) -> std::result::Result<serde_json::Value, String> {
    let params: DsctListFieldsParams =
        serde_json::from_value(arguments).map_err(|e| format!("invalid arguments: {e}"))?;
    do_list_fields_inner(params).map_err(|e| format_error(&e))
}

fn do_list_fields_inner(params: DsctListFieldsParams) -> DsctResult<serde_json::Value> {
    let registry = DissectorRegistry::default();
    let schemas = registry.all_field_schemas();

    let filter_normalized: Vec<String> = params
        .protocols
        .iter()
        .map(|s| normalize_protocol_name(s))
        .collect();

    let mut entries = Vec::new();
    for s in &schemas {
        let short = normalize_protocol_name(s.short_name);
        if !filter_normalized.is_empty() && !filter_normalized.contains(&short) {
            continue;
        }
        for fd in s.fields {
            entries.push(crate::schema::fd_to_json(
                fd,
                s.short_name,
                s.short_name,
                s.name,
            ));
        }
    }

    Ok(serde_json::Value::Array(entries))
}

/// Get JSON schema for command output as a JSON value.
pub(crate) fn do_get_schema(
    arguments: serde_json::Value,
) -> std::result::Result<serde_json::Value, String> {
    let params: DsctGetSchemaParams =
        serde_json::from_value(arguments).map_err(|e| format!("invalid arguments: {e}"))?;
    do_get_schema_inner(params).map_err(|e| format_error(&e))
}

fn do_get_schema_inner(params: DsctGetSchemaParams) -> DsctResult<serde_json::Value> {
    let cmd = params.command.as_deref().unwrap_or("read");

    match cmd {
        "read" => Ok(crate::schema::read_schema()),
        "stats" => Ok(crate::schema::stats_schema()),
        other => Err(DsctError::invalid_argument(format!(
            "unknown command '{other}'. Available: read, stats"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_protocols_returns_json_array() {
        let result = do_list_protocols();
        let value = result.expect("list_protocols should succeed");
        let arr = value.as_array().expect("should be a JSON array");
        assert!(!arr.is_empty());
        let first = &arr[0];
        assert!(first.get("name").is_some());
        assert!(first.get("full_name").is_some());
    }

    #[test]
    fn list_fields_returns_json_array() {
        let result = do_list_fields(serde_json::json!({}));
        let value = result.expect("list_fields should succeed");
        let arr = value.as_array().expect("should be a JSON array");
        assert!(!arr.is_empty());
    }

    #[test]
    fn list_fields_filtered_by_protocol() {
        let result = do_list_fields(serde_json::json!({"protocols": ["dns"]}));
        let value = result.expect("list_fields should succeed");
        let arr = value.as_array().expect("should be a JSON array");
        assert!(!arr.is_empty());
        for entry in arr {
            assert_eq!(entry["protocol"].as_str().unwrap().to_lowercase(), "dns");
        }
    }

    #[test]
    fn list_fields_filtered_by_protocol_single_string() {
        let result = do_list_fields(serde_json::json!({"protocols": "dns"}));
        let value = result.expect("list_fields should accept a single string");
        let arr = value.as_array().expect("should be a JSON array");
        assert!(!arr.is_empty());
        for entry in arr {
            assert_eq!(entry["protocol"].as_str().unwrap().to_lowercase(), "dns");
        }
    }

    #[test]
    fn get_schema_read() {
        let result = do_get_schema(serde_json::json!({"command": "read"}));
        let value = result.expect("get_schema read should succeed");
        assert_eq!(value["title"], "dsct read packet record");
    }

    #[test]
    fn get_schema_stats() {
        let result = do_get_schema(serde_json::json!({"command": "stats"}));
        let value = result.expect("get_schema stats should succeed");
        assert_eq!(value["title"], "dsct stats output");
    }

    #[test]
    fn get_schema_default_is_read() {
        let result = do_get_schema(serde_json::json!({}));
        let value = result.expect("get_schema default should succeed");
        assert_eq!(value["title"], "dsct read packet record");
    }

    #[test]
    fn get_schema_unknown_returns_error() {
        let result = do_get_schema(serde_json::json!({"command": "nonexistent"}));
        assert!(result.is_err());
    }

    #[test]
    fn get_stats_missing_file_returns_error() {
        let limits = ResourceLimits::default();
        let result = do_get_stats(
            serde_json::json!({
                "file": "/nonexistent/file.pcap",
            }),
            &limits,
        );
        assert!(result.is_err());
    }
}
