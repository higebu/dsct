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
    /// Command name: "read", "stats" or "sql" (defaults to "read").
    #[serde(default)]
    pub command: Option<String>,
}

/// Parameters for the `dsct_query_sql` tool.
#[cfg(feature = "sqlite")]
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DsctQuerySqlParams {
    /// Path to the pcap/pcapng file or to an existing dsct SQLite index.
    pub file: String,
    /// Read-only SQL query. Omitted when `schema` is true.
    #[serde(default)]
    pub sql: Option<String>,
    /// Return the index schema instead of running a query.
    #[serde(default)]
    pub schema: bool,
    /// With `schema: true`, restrict the schema to these table/view names
    /// and return full column detail for them (instead of the default
    /// compact summary of every table).
    #[serde(default, deserialize_with = "string_or_vec")]
    pub tables: Vec<String>,
    /// Maximum rows to return (defaults to the server's default count).
    #[serde(default)]
    pub count: Option<u64>,
    /// Explicit index database path.
    #[serde(default)]
    pub db: Option<String>,
    /// Fail instead of building the index when missing or stale.
    #[serde(default)]
    pub no_build: bool,
    /// Override protocol dissection for a port when building.
    #[serde(default)]
    pub decode_as: Vec<String>,
    /// ESP Security Association for decryption when building.
    #[serde(default)]
    pub esp_sa: Vec<String>,
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
        "sql" => Ok(crate::schema::sql_schema()),
        other => Err(DsctError::invalid_argument(format!(
            "unknown command '{other}'. Available: read, stats, sql"
        ))),
    }
}

/// Run a read-only SQL query against the SQLite index of a capture.
#[cfg(feature = "sqlite")]
pub(crate) fn do_query_sql(
    arguments: serde_json::Value,
    limits: &ResourceLimits,
) -> std::result::Result<serde_json::Value, String> {
    let params: DsctQuerySqlParams =
        serde_json::from_value(arguments).map_err(|e| format!("invalid arguments: {e}"))?;
    do_query_sql_inner(params, limits).map_err(|e| format_error(&e))
}

#[cfg(feature = "sqlite")]
fn do_query_sql_inner(
    params: DsctQuerySqlParams,
    limits: &ResourceLimits,
) -> DsctResult<serde_json::Value> {
    use crate::sqlite::ddl::protocol_tables;
    use crate::sqlite::query::{describe_schema, open_read_only, run_query};
    use crate::sqlite::{IndexRequest, resolve_index};

    if params.file == "-" {
        return Err(DsctError::invalid_argument(
            "stdin input is not supported over MCP; pass a file path",
        ));
    }
    if !params.schema && params.sql.is_none() {
        return Err(DsctError::invalid_argument(
            "'sql' is required unless 'schema' is true",
        ));
    }
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

    let deadline = Instant::now() + limits.timeout;
    let mut dissect_warnings = 0u64;
    let resolved = resolve_index(
        &IndexRequest {
            file: &file,
            db: params.db.as_ref().map(PathBuf::from),
            force: false,
            no_build: params.no_build,
            progress_interval: 0,
            decode_as: &params.decode_as,
            esp_sa: &params.esp_sa,
            deadline: Some(deadline),
        },
        &mut |_, _| dissect_warnings += 1,
        &mut |_| {},
    )?;

    let conn = open_read_only(&resolved.db_path)?;
    // Interrupt long-running queries once the tool deadline has passed.
    conn.progress_handler(10_000, Some(move || Instant::now() > deadline))
        .context("failed to install query timeout handler")?;

    let mut index_info = serde_json::json!({
        "db": resolved.db_path.display().to_string(),
        "built": resolved.build.is_some(),
    });
    if let Some(reason) = &resolved.replaced_reason {
        index_info["replaced_reason"] = serde_json::Value::String(reason.clone());
    }
    if let Some(b) = &resolved.build {
        index_info["packets"] = serde_json::json!(b.packets);
        index_info["flows"] = serde_json::json!(b.flows);
        index_info["dissect_warnings"] = serde_json::json!(dissect_warnings);
    }

    if params.schema {
        let registry = DissectorRegistry::default();
        let table_filter = (!params.tables.is_empty()).then_some(params.tables.as_slice());
        // Bare `schema: true` returns a compact summary (name/kind/
        // column_count only) to stay within LLM context limits; passing
        // `tables` switches to full column detail restricted to those
        // tables/views.
        let compact = table_filter.is_none();
        let mut schema =
            describe_schema(&conn, &protocol_tables(&registry), table_filter, compact)?;
        schema["index"] = index_info;
        return Ok(schema);
    }

    let sql = params.sql.unwrap_or_default();
    let limit = params.count.unwrap_or(limits.default_packet_count);
    let mut out: Vec<u8> = Vec::new();
    let outcome = run_query(&conn, &sql, Some(limit), &mut out)?;
    let rows: Vec<serde_json::Value> = out
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(serde_json::from_slice)
        .collect::<std::result::Result<_, _>>()
        .context("failed to re-parse query output")?;

    Ok(serde_json::json!({
        "rows": rows,
        "row_count": outcome.rows_written,
        "truncated": outcome.truncated_by_limit,
        "index": index_info,
    }))
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
    fn get_schema_sql() {
        let result = do_get_schema(serde_json::json!({"command": "sql"}));
        let value = result.expect("get_schema sql should succeed");
        assert_eq!(value["title"], "dsct sql result row");
    }

    #[cfg(feature = "sqlite")]
    mod query_sql {
        use super::*;

        fn udp_pcap(n: usize) -> Vec<u8> {
            let pkt: [u8; 42] = [
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
                0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x00,
                0x00, 0x01, 0x0A, 0x00, 0x00, 0x02, 0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
            ];
            let mut pcap = Vec::new();
            pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
            pcap.extend_from_slice(&2u16.to_le_bytes());
            pcap.extend_from_slice(&4u16.to_le_bytes());
            pcap.extend_from_slice(&0i32.to_le_bytes());
            pcap.extend_from_slice(&0u32.to_le_bytes());
            pcap.extend_from_slice(&65535u32.to_le_bytes());
            pcap.extend_from_slice(&1u32.to_le_bytes());
            for i in 0..n {
                pcap.extend_from_slice(&(i as u32).to_le_bytes());
                pcap.extend_from_slice(&0u32.to_le_bytes());
                pcap.extend_from_slice(&42u32.to_le_bytes());
                pcap.extend_from_slice(&42u32.to_le_bytes());
                pcap.extend_from_slice(&pkt);
            }
            pcap
        }

        #[test]
        fn query_sql_builds_index_and_returns_rows() {
            let dir = tempfile::tempdir().unwrap();
            let cache_dir = tempfile::tempdir().unwrap();
            let _cache_guard = crate::sqlite::test_support::CacheDirGuard::set(cache_dir.path());
            let cap = dir.path().join("c.pcap");
            std::fs::write(&cap, udp_pcap(3)).unwrap();
            let limits = ResourceLimits::default();

            let result = do_query_sql(
                serde_json::json!({
                    "file": cap.to_str().unwrap(),
                    "sql": "SELECT number, stack FROM packets ORDER BY number",
                    "count": 2,
                }),
                &limits,
            )
            .expect("query should succeed");
            assert_eq!(result["row_count"], 2);
            assert_eq!(result["truncated"], true);
            assert_eq!(result["rows"][0]["number"], 1);
            assert_eq!(result["rows"][0]["stack"], "Ethernet:IPv4:UDP");
            assert_eq!(result["index"]["built"], true);
            assert_eq!(result["index"]["packets"], 3);

            // Second call reuses the index.
            let again = do_query_sql(
                serde_json::json!({
                    "file": cap.to_str().unwrap(),
                    "sql": "SELECT COUNT(*) AS n FROM udp",
                }),
                &limits,
            )
            .unwrap();
            assert_eq!(again["rows"][0]["n"], 3);
            assert_eq!(again["index"]["built"], false);
            assert_eq!(again["truncated"], false);
        }

        #[test]
        fn query_sql_schema_mode() {
            let dir = tempfile::tempdir().unwrap();
            let cache_dir = tempfile::tempdir().unwrap();
            let _cache_guard = crate::sqlite::test_support::CacheDirGuard::set(cache_dir.path());
            let cap = dir.path().join("c.pcap");
            std::fs::write(&cap, udp_pcap(1)).unwrap();
            let limits = ResourceLimits::default();
            let result = do_query_sql(
                serde_json::json!({ "file": cap.to_str().unwrap(), "schema": true }),
                &limits,
            )
            .unwrap();
            assert!(result["tables"].is_array());
            assert_eq!(result["index"]["built"], true);

            // Bare schema: true is compact — no columns array, just counts.
            let entries = result["tables"].as_array().unwrap();
            assert!(!entries.is_empty());
            let udp = entries.iter().find(|t| t["name"] == "udp").unwrap();
            assert!(udp["column_count"].as_u64().unwrap() > 0);
            assert!(udp.get("columns").is_none(), "{udp}");
        }

        #[test]
        fn query_sql_schema_mode_with_tables_returns_full_detail() {
            let dir = tempfile::tempdir().unwrap();
            let cache_dir = tempfile::tempdir().unwrap();
            let _cache_guard = crate::sqlite::test_support::CacheDirGuard::set(cache_dir.path());
            let cap = dir.path().join("c.pcap");
            std::fs::write(&cap, udp_pcap(1)).unwrap();
            let limits = ResourceLimits::default();

            let result = do_query_sql(
                serde_json::json!({
                    "file": cap.to_str().unwrap(),
                    "schema": true,
                    "tables": "udp",
                }),
                &limits,
            )
            .unwrap();
            let entries = result["tables"].as_array().unwrap();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0]["name"], "udp");
            assert!(entries[0]["columns"].is_array());
            assert!(!entries[0]["columns"].as_array().unwrap().is_empty());

            // Unknown table name is a structured invalid-argument error.
            let err = do_query_sql(
                serde_json::json!({
                    "file": cap.to_str().unwrap(),
                    "schema": true,
                    "tables": ["no_such_table"],
                }),
                &limits,
            )
            .unwrap_err();
            assert!(err.contains("no_such_table"), "{err}");
        }

        #[test]
        fn query_sql_rejects_writes_and_missing_args() {
            let dir = tempfile::tempdir().unwrap();
            let cache_dir = tempfile::tempdir().unwrap();
            let _cache_guard = crate::sqlite::test_support::CacheDirGuard::set(cache_dir.path());
            let cap = dir.path().join("c.pcap");
            std::fs::write(&cap, udp_pcap(1)).unwrap();
            let limits = ResourceLimits::default();
            let err = do_query_sql(
                serde_json::json!({ "file": cap.to_str().unwrap(), "sql": "DROP TABLE packets" }),
                &limits,
            )
            .unwrap_err();
            assert!(err.contains("SELECT"));

            let err = do_query_sql(
                serde_json::json!({ "file": cap.to_str().unwrap() }),
                &limits,
            )
            .unwrap_err();
            assert!(err.contains("'sql' is required"));

            let err = do_query_sql(
                serde_json::json!({ "file": "-", "sql": "SELECT 1" }),
                &limits,
            )
            .unwrap_err();
            assert!(err.contains("stdin"));

            let err = do_query_sql(
                serde_json::json!({ "file": "/nonexistent/c.pcap", "sql": "SELECT 1" }),
                &limits,
            )
            .unwrap_err();
            assert!(err.contains("failed to stat file"));
        }

        #[test]
        fn query_sql_no_build_without_index() {
            let dir = tempfile::tempdir().unwrap();
            let cap = dir.path().join("c.pcap");
            std::fs::write(&cap, udp_pcap(1)).unwrap();
            let limits = ResourceLimits::default();
            let err = do_query_sql(
                serde_json::json!({
                    "file": cap.to_str().unwrap(),
                    "sql": "SELECT 1",
                    "no_build": true,
                }),
                &limits,
            )
            .unwrap_err();
            assert!(err.contains("does not exist"));
        }
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
