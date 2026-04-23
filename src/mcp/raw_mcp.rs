//! Minimal MCP server over stdio, without rmcp.
//!
//! Reads JSON-RPC 2.0 requests from stdin (one per line) and writes responses
//! to stdout.  Tool results include `structuredContent` (a JSON object) for
//! machine consumption and a `content` text fallback for older clients.
//!
//! For `dsct_read_packets`, packet objects are streamed directly into the
//! `structuredContent` JSON object's `packets` array — no string escaping
//! needed — so memory usage stays bounded regardless of capture size.
//! The buffer size is configurable via `DSCT_MCP_WRITE_BUFFER_SIZE`.

use std::io::{self, BufRead, Write};

use serde_json::Value;

use super::limits::ResourceLimits;
use crate::error::{Result, ResultExt, format_error};
use crate::json_escape::write_json_escaped;

pub use crate::json_escape::JsonEscapeWriter;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run the raw MCP server on stdin/stdout.
pub fn run(limits: ResourceLimits) -> Result<()> {
    let stdin = io::stdin().lock();
    let mut out = io::BufWriter::with_capacity(limits.write_buffer_size, io::stdout().lock());

    run_on(stdin, &mut out, &limits)
}

/// Core server loop, generic over reader and writer for testability.
fn run_on<R: BufRead, W: Write>(reader: R, w: &mut W, limits: &ResourceLimits) -> Result<()> {
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                // JSON-RPC 2.0 §5.1: Parse error → id must be null.
                write_error(w, &Value::Null, -32700, &format!("parse error: {e}"))?;
                continue;
            }
        };
        handle_message(&req, limits, w)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn handle_message(req: &Value, limits: &ResourceLimits, w: &mut impl Write) -> Result<()> {
    let id = req.get("id"); // None → notification

    // JSON-RPC 2.0 §5.1: "method" must be present and a string.
    // A missing or non-string "method" is an Invalid Request (-32600),
    // distinct from an unrecognised method name (-32601).
    let method = match req.get("method").and_then(Value::as_str) {
        Some(m) => m,
        None => {
            if let Some(id) = id {
                write_error(
                    w,
                    id,
                    -32600,
                    "invalid request: missing or non-string \"method\"",
                )?;
            }
            return Ok(());
        }
    };

    match method {
        "initialize" => {
            if let Some(id) = id {
                let client_version = req
                    .get("params")
                    .and_then(|p| p.get("protocolVersion"))
                    .and_then(Value::as_str);
                write_response(w, id, &initialize_result(client_version))?;
            }
        }
        "notifications/initialized" | "initialized" => {
            // notification — no response
        }
        "tools/list" => {
            if let Some(id) = id {
                write_response(w, id, &tools_list_result())?;
            }
        }
        "tools/call" => {
            if let Some(id) = id {
                handle_tool_call(req, id, limits, w)?;
            }
        }
        "ping" => {
            if let Some(id) = id {
                write_response(w, id, &serde_json::json!({}))?;
            }
        }
        _ => {
            // Unknown method — return error if it has an id.
            if let Some(id) = id {
                write_error(w, id, -32601, "method not found")?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// initialize
// ---------------------------------------------------------------------------

/// Protocol versions this server is willing to speak, newest first.
const SUPPORTED_PROTOCOL_VERSIONS: &[&str] = &["2025-11-25", "2025-03-26", "2024-11-05"];

/// Negotiate the protocol version: echo back the client's version if we
/// support it; otherwise fall back to the latest version we support.
fn negotiate_protocol_version(client_version: Option<&str>) -> &'static str {
    client_version
        .and_then(|v| {
            SUPPORTED_PROTOCOL_VERSIONS
                .iter()
                .find(|&&s| s == v)
                .copied()
        })
        .unwrap_or(SUPPORTED_PROTOCOL_VERSIONS[0])
}

fn initialize_result(client_version: Option<&str>) -> Value {
    let version = negotiate_protocol_version(client_version);
    serde_json::json!({
        "protocolVersion": version,
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": "dsct",
            "version": env!("CARGO_PKG_VERSION")
        },
        "instructions": "dsct is an LLM-friendly packet dissector. \
            Use tools to analyze pcap/pcapng capture files, \
            list supported protocols, and inspect field schemas."
    })
}

// ---------------------------------------------------------------------------
// tools/list
// ---------------------------------------------------------------------------

fn tools_list_result() -> Value {
    serde_json::json!({
        "tools": [
            {
                "name": "dsct_read_packets",
                "description": "Dissect packets from a pcap/pcapng capture file. Returns an object with a packets array of dissected packet objects with protocol layers and fields. IMPORTANT: Call dsct_get_stats first to understand capture size. Then use filter to narrow to relevant protocols and count (start with 50 or fewer) to keep output within context limits. For large captures, use sample_rate to get evenly-distributed packets across the timeline (e.g. sample_rate: total_packets / 50 yields ~50 representative packets).",
                "annotations": { "readOnlyHint": true },
                "inputSchema": read_packets_schema(),
                "outputSchema": {
                    "type": "object",
                    "properties": {
                        "packets": { "type": "array" }
                    },
                    "required": ["packets"]
                }
            },
            {
                "name": "dsct_get_stats",
                "description": "Get protocol statistics from a pcap/pcapng capture file. Returns packet counts, timing, protocol distribution, and optional deep analysis.",
                "annotations": { "readOnlyHint": true },
                "inputSchema": get_stats_schema(),
                "outputSchema": {
                    "type": "object",
                    "required": ["type", "total_packets", "duration_secs", "protocols"],
                    "properties": {
                        "type": { "type": "string" },
                        "total_packets": { "type": "integer" },
                        "duration_secs": { "type": "number" },
                        "protocols": { "type": "object" }
                    }
                }
            },
            {
                "name": "dsct_list_protocols",
                "description": "List all supported protocols with their specification references and layer information.",
                "annotations": { "readOnlyHint": true },
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": false
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {
                        "protocols": { "type": "array" }
                    },
                    "required": ["protocols"]
                }
            },
            {
                "name": "dsct_list_fields",
                "description": "List available field names for protocols. Each entry includes a qualified_name (e.g. 'DNS.questions.name') that can be used directly as the field path in dsct_read_packets filter expressions. Nested fields are shown in a children array. IMPORTANT: Always specify protocols to avoid very large output (~56K tokens for all protocols).",
                "annotations": { "readOnlyHint": true },
                "inputSchema": list_fields_schema(),
                "outputSchema": {
                    "type": "object",
                    "properties": {
                        "fields": { "type": "array" }
                    },
                    "required": ["fields"]
                }
            },
            {
                "name": "dsct_get_schema",
                "description": "Get the JSON schema for dsct command output formats (read or stats).",
                "annotations": { "readOnlyHint": true },
                "inputSchema": get_schema_schema(),
                "outputSchema": {
                    "type": "object"
                }
            }
        ]
    })
}

fn read_packets_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "required": ["file"],
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the pcap/pcapng file."
            },
            "count": {
                "type": "integer",
                "description": "Maximum number of packets to return (default: 1000). Each packet produces roughly 400 bytes of JSON (~100 tokens). Start with 50 or fewer to keep output manageable."
            },
            "offset": {
                "type": "integer",
                "description": "Number of matching packets to skip before output."
            },
            "packet_number": {
                "type": "string",
                "description": "Packet number filter (e.g. \"42\", \"1-100\", \"1,5,10-20\")."
            },
            "filter": {
                "type": "string",
                "description": "SQL-style filter expression (e.g. \"dns\", \"tcp AND ipv4.src = '10.0.0.1'\", \"tcp.dst_port > 1024\", \"(tcp OR udp) AND NOT dns\", \"dns.questions.name = 'example.com'\", \"packet_number BETWEEN 1 AND 100\"). Supports: protocol.field (nested via dots, e.g. dns.questions.name), comparison operators (=, !=, <>, <, <=, >, >=), AND/OR/NOT, parentheses, BETWEEN, IN. The _name suffix resolves display names (e.g. gtpv2c.ies.type_name = 'Cause'). Use dsct_list_protocols to discover protocol names and dsct_list_fields to discover field paths (qualified_name)."
            },
            "decode_as": {
                "type": "array",
                "items": { "type": "string" },
                "default": [],
                "description": "Override protocol dissection for a port (e.g. \"tcp.port=8080:http\")."
            },
            "esp_sa": {
                "type": "array",
                "items": { "type": "string" },
                "default": [],
                "description": "ESP Security Association for decryption. Format: \"spi:null\", \"spi:enc_algo:enc_key_hex\", or \"spi:enc_algo:enc_key_hex:auth_algo:auth_key_hex\"."
            },
            "verbose": {
                "type": "boolean",
                "default": false,
                "description": "Show all fields including low-level details (checksums, header lengths, etc.)."
            },
            "raw_bytes": {
                "type": "boolean",
                "default": false,
                "description": "Include the original packet bytes (link-layer included) as a lowercase hex string under the `raw_bytes` field of each record."
            },
            "sample_rate": {
                "type": "integer",
                "minimum": 1,
                "description": "Output every Nth matching packet for representative sampling (e.g. 100 yields every 100th match)."
            }
        },
        "additionalProperties": false
    })
}

fn get_stats_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "required": ["file"],
        "properties": {
            "file": {
                "type": "string",
                "description": "Path to the pcap/pcapng file."
            },
            "protocols": {
                "type": ["string", "array"],
                "items": { "type": "string" },
                "default": [],
                "description": "Restrict statistics to these protocols."
            },
            "top_talkers": {
                "type": "boolean",
                "default": false,
                "description": "Show top IP pairs by traffic volume."
            },
            "stream_summary": {
                "type": "boolean",
                "default": false,
                "description": "Show per-stream TCP summary."
            },
            "top": {
                "type": "integer",
                "description": "Maximum entries in ranked lists (default 10)."
            },
            "decode_as": {
                "type": "array",
                "items": { "type": "string" },
                "default": [],
                "description": "Override protocol dissection for a port."
            },
            "esp_sa": {
                "type": "array",
                "items": { "type": "string" },
                "default": [],
                "description": "ESP Security Association for decryption. Format: \"spi:null\", \"spi:enc_algo:enc_key_hex\", or \"spi:enc_algo:enc_key_hex:auth_algo:auth_key_hex\"."
            }
        },
        "additionalProperties": false
    })
}

fn list_fields_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "protocols": {
                "type": ["string", "array"],
                "items": { "type": "string" },
                "default": [],
                "description": "Show fields only for these protocols (e.g. \"dns\", \"ipv4\")."
            }
        },
        "additionalProperties": false
    })
}

fn get_schema_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "Command name: \"read\" or \"stats\" (defaults to \"read\")."
            }
        },
        "additionalProperties": false
    })
}

// ---------------------------------------------------------------------------
// tools/call
// ---------------------------------------------------------------------------

fn handle_tool_call(
    req: &Value,
    id: &Value,
    limits: &ResourceLimits,
    w: &mut impl Write,
) -> Result<()> {
    let params = req
        .get("params")
        .cloned()
        .unwrap_or(Value::Object(Default::default()));
    let tool_name = params.get("name").and_then(Value::as_str).unwrap_or("");
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(Value::Object(Default::default()));

    match tool_name {
        "dsct_read_packets" => handle_read_packets_streaming(id, &arguments, limits, w),
        "dsct_get_stats" => {
            let result = super::tools::do_get_stats(arguments, limits);
            write_tool_result(w, id, result)
        }
        "dsct_list_protocols" => {
            let result =
                super::tools::do_list_protocols().map(|v| serde_json::json!({ "protocols": v }));
            write_tool_result(w, id, result)
        }
        "dsct_list_fields" => {
            let result =
                super::tools::do_list_fields(arguments).map(|v| serde_json::json!({ "fields": v }));
            write_tool_result(w, id, result)
        }
        "dsct_get_schema" => {
            let result = super::tools::do_get_schema(arguments);
            write_tool_result(w, id, result)
        }
        _ => {
            let err_result = serde_json::json!({
                "content": [{"type": "text", "text": format!("unknown tool: {tool_name}")}],
                "isError": true
            });
            write_response(w, id, &err_result)
        }
    }
}

// ---------------------------------------------------------------------------
// Streaming read_packets — the core of this module
// ---------------------------------------------------------------------------

/// Handle `dsct_read_packets` by writing JSON-RPC response incrementally.
///
/// Instead of buffering all packet JSON in memory, we:
/// 1. Complete all fallible preparation (file open, filter parsing) first
/// 2. Write the response envelope prefix
/// 3. For each matching packet, serialise and write directly into the
///    `structuredContent` JSON object's `packets` array (no string escaping needed)
/// 4. Close the envelope (even on error, to keep stdout well-formed)
///
/// The `structuredContent` field is a JSON object with a `packets` array.
/// The `content` text fallback contains a summary (packet count).
fn handle_read_packets_streaming(
    id: &Value,
    arguments: &Value,
    limits: &ResourceLimits,
    w: &mut impl Write,
) -> Result<()> {
    use std::ops::ControlFlow;
    use std::path::PathBuf;
    use std::time::Instant;

    use packet_dissector::registry::DissectorRegistry;

    use crate::decode_as;
    use crate::esp_sa;
    use crate::field_config::FieldConfig;
    use crate::filter::PacketNumberFilter;
    use crate::filter_expr::FilterExpr;
    use crate::input::CaptureReader;
    use crate::serialize::write_packet_json;

    // Parse arguments.
    let file: String = arguments
        .get("file")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let count = extract_optional_u64(arguments, "count");
    let offset = extract_optional_u64(arguments, "offset").unwrap_or(0);
    let packet_number = arguments
        .get("packet_number")
        .and_then(Value::as_str)
        .map(String::from);
    let filter_str = arguments
        .get("filter")
        .and_then(Value::as_str)
        .map(String::from);
    let sample_rate = extract_optional_u64(arguments, "sample_rate").unwrap_or(1);
    let decode_as_strs = extract_string_array(arguments, "decode_as");
    let esp_sa_strs = extract_string_array(arguments, "esp_sa");

    // ------------------------------------------------------------------
    // Phase 1: Fallible preparation — errors here produce a clean
    //          JSON-RPC error response (no partial output on stdout).
    // ------------------------------------------------------------------
    if file.is_empty() {
        return write_tool_error(w, id, "\"file\" parameter is required".to_string());
    }
    if sample_rate == 0 {
        return write_tool_error(w, id, "sample_rate must be at least 1".to_string());
    }
    let file_path = PathBuf::from(&file);

    // Enforce file size limit (consistent with do_get_stats).
    match std::fs::metadata(&file_path) {
        Ok(meta) if meta.len() > limits.max_file_size => {
            return write_tool_error(
                w,
                id,
                format!(
                    "file size ({} bytes) exceeds limit ({} bytes)",
                    meta.len(),
                    limits.max_file_size
                ),
            );
        }
        Ok(_) => {}
        Err(e) => {
            return write_tool_error(w, id, format!("failed to stat file: {e}"));
        }
    }
    let verbose = arguments
        .get("verbose")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let raw_bytes = arguments
        .get("raw_bytes")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let field_config = if verbose {
        None
    } else {
        match FieldConfig::default_config() {
            Ok(c) => Some(c),
            Err(e) => {
                return write_tool_error(w, id, format_error(&e));
            }
        }
    };

    let mut registry = DissectorRegistry::default();
    if let Err(e) = decode_as::parse_and_apply(&mut registry, &decode_as_strs) {
        return write_tool_error(w, id, format_error(&e));
    }
    if let Err(e) = esp_sa::parse_and_apply(&registry, &esp_sa_strs) {
        return write_tool_error(w, id, format_error(&e));
    }

    let effective_count = Some(count.unwrap_or(limits.default_packet_count));
    let deadline = Instant::now() + limits.timeout;

    let pn_filter = match packet_number
        .as_deref()
        .map(PacketNumberFilter::parse)
        .transpose()
        .context("invalid packet_number expression")
    {
        Ok(f) => f,
        Err(e) => return write_tool_error(w, id, format_error(&e)),
    };
    let pn_max = pn_filter.as_ref().and_then(PacketNumberFilter::max);

    let filter_expr = match filter_str.as_deref() {
        Some(s) => match FilterExpr::parse(s) {
            Ok(expr) => expr,
            Err(msg) => return write_tool_error(w, id, msg),
        },
        None => None,
    };

    let reader = match CaptureReader::open(&file_path).context("failed to open capture file") {
        Ok(r) => r,
        Err(e) => return write_tool_error(w, id, format_error(&e)),
    };

    // ------------------------------------------------------------------
    // Phase 2: Streaming — the envelope is opened on stdout.
    //          From this point, we MUST close the envelope before
    //          returning, even on error.
    // ------------------------------------------------------------------
    // Open the structuredContent JSON object with a "packets" array.
    write!(
        w,
        r#"{{"jsonrpc":"2.0","id":{},"result":{{"structuredContent":{{"packets":["#,
        id
    )?;

    let mut packets_written = 0u64;
    let mut filter_matches = 0u64;
    let mut results_matched = 0u64;
    let mut packets_seen = 0u64;
    let mut stream_error: Option<String> = None;
    // Pre-allocated buffer for write_packet_json output.  Reused across
    // packets to avoid per-packet heap allocation.
    let mut pkt_buf: Vec<u8> = Vec::with_capacity(4096);

    let mut dissect_buf = packet_dissector_core::packet::DissectBuffer::new();
    let iteration_result = reader.for_each_packet(|meta, data| {
        // Amortise the syscall: check the clock every 1024 packets.
        packets_seen += 1;
        if packets_seen.is_multiple_of(1024) && Instant::now() > deadline {
            return Ok(ControlFlow::Break(()));
        }

        // Packet-number filter (pre-dissect).
        if let Some(ref pnf) = pn_filter
            && !pnf.contains(meta.number)
        {
            if pn_max.is_some_and(|m| meta.number > m) {
                return Ok(ControlFlow::Break(()));
            }
            return Ok(ControlFlow::Continue(()));
        }

        // Dissect (reuse buffer across packets).
        let dissect_buf = dissect_buf.clear_into();
        if registry
            .dissect_with_link_type(data, meta.link_type, dissect_buf)
            .is_err()
        {
            return Ok(ControlFlow::Continue(()));
        }
        let packet = packet_dissector_core::packet::Packet::new(dissect_buf, data);

        // Apply filter expression.
        if let Some(ref expr) = filter_expr
            && !expr.matches_with_number(&packet, meta.number)
        {
            return Ok(ControlFlow::Continue(()));
        }

        // Apply sample rate (every Nth filter-passing packet).
        filter_matches += 1;
        if sample_rate > 1 && !(filter_matches - 1).is_multiple_of(sample_rate) {
            return Ok(ControlFlow::Continue(()));
        }

        results_matched += 1;
        if results_matched <= offset {
            return Ok(ControlFlow::Continue(()));
        }
        if effective_count.is_some_and(|max| packets_written >= max) {
            return Ok(ControlFlow::Break(()));
        }
        // Write comma separator between array elements.
        if packets_written > 0 {
            w.write_all(b",")?;
        }
        // Write packet JSON directly into the structuredContent packets array —
        // no string escaping needed since we're inside a JSON array,
        // not a JSON string.
        pkt_buf.clear();
        write_packet_json(
            &mut pkt_buf,
            &meta,
            dissect_buf,
            data,
            field_config.as_ref(),
            raw_bytes,
        )?;
        w.write_all(&pkt_buf)?;
        packets_written += 1;

        Ok(ControlFlow::Continue(()))
    });

    // Record any error from the packet loop, but always close the envelope.
    if let Err(e) = iteration_result {
        stream_error = Some(format_error(&e));
    }

    // --- Always close the envelope ---
    // Close the structuredContent object and add content text fallback.
    if let Some(ref err_msg) = stream_error {
        // Escape the error message for embedding in a JSON string value.
        write!(w, r#"]}},"content":[{{"type":"text","text":""#)?;
        write_json_escaped(w, err_msg)?;
        write!(w, r#""}}],"isError":true}}}}"#)?;
    } else {
        write!(
            w,
            r#"]}},"content":[{{"type":"text","text":"{packets_written} packets"}}]}}}}"#
        )?;
    }
    writeln!(w)?;
    w.flush()?;

    Ok(())
}

/// Write a tool error response (for errors detected before streaming starts).
fn write_tool_error(w: &mut impl Write, id: &Value, msg: String) -> Result<()> {
    let err_result = serde_json::json!({
        "content": [{"type": "text", "text": msg}],
        "isError": true
    });
    write_response(w, id, &err_result)
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

/// Extract an optional `u64` from `args[key]`, accepting both JSON integers
/// and string representations (e.g. `"42"`).  LLM clients sometimes send
/// numeric parameters as strings, so we parse both forms.
fn extract_optional_u64(args: &Value, key: &str) -> Option<u64> {
    let v = args.get(key)?;
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}

/// Extract a JSON array of strings from `args[key]`, returning an empty vec if
/// the key is missing or not an array.
fn extract_string_array(args: &Value, key: &str) -> Vec<String> {
    args.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

fn write_response(w: &mut impl Write, id: &Value, result: &Value) -> Result<()> {
    let resp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    });
    serde_json::to_writer(&mut *w, &resp)?;
    writeln!(w)?;
    w.flush()?;
    Ok(())
}

fn write_error(w: &mut impl Write, id: &Value, code: i64, message: &str) -> Result<()> {
    let resp = serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    });
    serde_json::to_writer(&mut *w, &resp)?;
    writeln!(w)?;
    w.flush()?;
    Ok(())
}

fn write_tool_result(
    w: &mut impl Write,
    id: &Value,
    result: std::result::Result<Value, String>,
) -> Result<()> {
    let tool_result = match result {
        Ok(value) => {
            let text = serde_json::to_string(&value)?;
            serde_json::json!({
                "structuredContent": value,
                "content": [{"type": "text", "text": text}]
            })
        }
        Err(msg) => serde_json::json!({
            "content": [{"type": "text", "text": msg}],
            "isError": true
        }),
    };
    write_response(w, id, &tool_result)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse the first JSON line from a byte buffer.
    fn parse_response(buf: &[u8]) -> Value {
        let s = std::str::from_utf8(buf).expect("valid UTF-8");
        let line = s.lines().next().expect("at least one line");
        serde_json::from_str(line).expect("valid JSON")
    }

    // -- write helpers ------------------------------------------------

    #[test]
    fn write_response_produces_valid_jsonrpc() {
        let mut buf = Vec::new();
        let id = serde_json::json!(1);
        let result = serde_json::json!({"ok": true});
        write_response(&mut buf, &id, &result).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["ok"], true);
    }

    #[test]
    fn write_error_produces_error_response() {
        let mut buf = Vec::new();
        let id = serde_json::json!(42);
        write_error(&mut buf, &id, -32601, "method not found").unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 42);
        assert_eq!(resp["error"]["code"], -32601);
        assert_eq!(resp["error"]["message"], "method not found");
    }

    #[test]
    fn write_tool_result_ok_has_structured_content() {
        let mut buf = Vec::new();
        let id = serde_json::json!(1);
        let value = serde_json::json!({"key": "value"});
        write_tool_result(&mut buf, &id, Ok(value.clone())).unwrap();
        let resp = parse_response(&buf);
        // structuredContent should be the JSON value directly.
        assert_eq!(resp["result"]["structuredContent"], value);
        // content text fallback should be the serialised JSON.
        let content = &resp["result"]["content"][0];
        assert_eq!(content["type"], "text");
        let text = content["text"].as_str().unwrap();
        let parsed_text: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed_text, value);
        assert!(resp["result"]["isError"].is_null());
    }

    #[test]
    fn write_tool_result_err_has_no_structured_content() {
        let mut buf = Vec::new();
        let id = serde_json::json!(1);
        write_tool_result(&mut buf, &id, Err("boom".to_string())).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["result"]["isError"], true);
        assert_eq!(resp["result"]["content"][0]["text"], "boom");
        assert!(resp["result"]["structuredContent"].is_null());
    }

    #[test]
    fn write_tool_error_sets_is_error() {
        let mut buf = Vec::new();
        let id = serde_json::json!(7);
        write_tool_error(&mut buf, &id, "something failed".to_string()).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["result"]["isError"], true);
        assert_eq!(resp["result"]["content"][0]["text"], "something failed");
    }

    // -- extract_optional_u64 -----------------------------------------

    #[test]
    fn extract_optional_u64_integer() {
        let args = serde_json::json!({"count": 42});
        assert_eq!(extract_optional_u64(&args, "count"), Some(42));
    }

    #[test]
    fn extract_optional_u64_string() {
        let args = serde_json::json!({"count": "42"});
        assert_eq!(extract_optional_u64(&args, "count"), Some(42));
    }

    #[test]
    fn extract_optional_u64_null() {
        let args = serde_json::json!({"count": null});
        assert_eq!(extract_optional_u64(&args, "count"), None);
    }

    #[test]
    fn extract_optional_u64_missing() {
        let args = serde_json::json!({});
        assert_eq!(extract_optional_u64(&args, "count"), None);
    }

    #[test]
    fn extract_optional_u64_invalid_string() {
        let args = serde_json::json!({"count": "abc"});
        assert_eq!(extract_optional_u64(&args, "count"), None);
    }

    #[test]
    fn extract_optional_u64_float() {
        let args = serde_json::json!({"count": 3.0});
        // serde_json stores 3.0 as f64; as_u64() returns None for floats,
        // but the string fallback is not applicable either.
        assert_eq!(extract_optional_u64(&args, "count"), None);
    }

    // -- initialize / tools_list pure functions -----------------------

    #[test]
    fn initialize_result_has_version() {
        let result = initialize_result(None);
        assert_eq!(result["protocolVersion"], "2025-11-25");
        assert!(result["capabilities"]["tools"].is_object());
    }

    #[test]
    fn negotiate_protocol_version_echoes_2025_11_25() {
        assert_eq!(negotiate_protocol_version(Some("2025-11-25")), "2025-11-25");
    }

    #[test]
    fn negotiate_protocol_version_echoes_2025_03_26() {
        assert_eq!(negotiate_protocol_version(Some("2025-03-26")), "2025-03-26");
    }

    #[test]
    fn negotiate_protocol_version_echoes_2024_11_05() {
        assert_eq!(negotiate_protocol_version(Some("2024-11-05")), "2024-11-05");
    }

    #[test]
    fn negotiate_protocol_version_defaults_to_latest_for_unknown() {
        assert_eq!(negotiate_protocol_version(Some("1.0.0")), "2025-11-25");
        assert_eq!(negotiate_protocol_version(None), "2025-11-25");
    }

    #[test]
    fn tools_list_has_five_tools() {
        let result = tools_list_result();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 5);
    }

    #[test]
    fn tools_list_tool_names() {
        let result = tools_list_result();
        let tools = result["tools"].as_array().unwrap();
        let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
        assert!(names.contains(&"dsct_read_packets"));
        assert!(names.contains(&"dsct_get_stats"));
        assert!(names.contains(&"dsct_list_protocols"));
        assert!(names.contains(&"dsct_list_fields"));
        assert!(names.contains(&"dsct_get_schema"));
    }

    #[test]
    fn read_packets_description_mentions_sample_rate() {
        let result = tools_list_result();
        let tools = result["tools"].as_array().unwrap();
        let read_tool = tools
            .iter()
            .find(|t| t["name"] == "dsct_read_packets")
            .expect("dsct_read_packets tool must exist");
        let desc = read_tool["description"].as_str().unwrap();
        assert!(
            desc.contains("sample_rate"),
            "dsct_read_packets description must mention sample_rate for discoverability, got: {desc}"
        );
    }

    #[test]
    fn tools_list_all_tools_have_output_schema() {
        // All tools return JSON objects and must have outputSchema.
        let result = tools_list_result();
        let tools = result["tools"].as_array().unwrap();
        for tool in tools {
            let name = tool["name"].as_str().unwrap();
            assert!(
                tool.get("outputSchema").is_some(),
                "tool {name} should have an outputSchema"
            );
            assert_eq!(
                tool["outputSchema"]["type"].as_str().unwrap(),
                "object",
                "tool {name} outputSchema must have type object"
            );
        }
    }

    #[test]
    fn read_packets_schema_requires_file() {
        let schema = read_packets_schema();
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "file"));
    }

    #[test]
    fn read_packets_schema_has_verbose() {
        let schema = read_packets_schema();
        let verbose = &schema["properties"]["verbose"];
        assert_eq!(verbose["type"], "boolean");
        assert_eq!(verbose["default"], false);
    }

    #[test]
    fn read_packets_schema_has_raw_bytes() {
        let schema = read_packets_schema();
        let raw = &schema["properties"]["raw_bytes"];
        assert_eq!(raw["type"], "boolean");
        assert_eq!(raw["default"], false);
    }

    #[test]
    fn get_stats_schema_has_esp_sa() {
        let schema = get_stats_schema();
        let esp_sa = &schema["properties"]["esp_sa"];
        assert_eq!(esp_sa["type"], "array");
        assert_eq!(esp_sa["items"]["type"], "string");
    }

    // -- handle_message dispatch --------------------------------------

    #[test]
    fn handle_message_initialize() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-11-25", "capabilities": {}}
        });
        handle_message(&req, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["protocolVersion"], "2025-11-25");
        assert!(resp["result"]["serverInfo"]["name"].as_str().is_some());
    }

    #[test]
    fn handle_message_initialize_negotiates_older_version() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2024-11-05", "capabilities": {}}
        });
        handle_message(&req, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["result"]["protocolVersion"], "2024-11-05");
    }

    #[test]
    fn handle_message_initialize_falls_back_for_unknown_version() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "1.0.0", "capabilities": {}}
        });
        handle_message(&req, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["result"]["protocolVersion"], "2025-11-25");
    }

    #[test]
    fn handle_message_initialize_no_version_defaults_to_latest() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize"});
        handle_message(&req, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["result"]["protocolVersion"], "2025-11-25");
    }

    #[test]
    fn handle_message_tools_list() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"});
        handle_message(&req, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["id"], 2);
        let tools = resp["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 5);
    }

    #[test]
    fn handle_message_ping() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "ping"});
        handle_message(&req, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["id"], 3);
        assert!(resp["result"].is_object());
    }

    #[test]
    fn handle_message_unknown_method() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({"jsonrpc": "2.0", "id": 4, "method": "bogus/method"});
        handle_message(&req, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["id"], 4);
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn handle_message_notification_produces_no_output() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"});
        handle_message(&req, &limits, &mut buf).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn handle_message_initialized_notification_no_output() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({"jsonrpc": "2.0", "method": "initialized"});
        handle_message(&req, &limits, &mut buf).unwrap();
        assert!(buf.is_empty());
    }

    #[test]
    fn handle_message_unknown_notification_no_output() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        // No "id" field → notification, even for unknown methods.
        let req = serde_json::json!({"jsonrpc": "2.0", "method": "something/unknown"});
        handle_message(&req, &limits, &mut buf).unwrap();
        assert!(buf.is_empty());
    }

    // -- handle_tool_call ---------------------------------------------

    #[test]
    fn handle_tool_call_unknown_tool() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({
            "params": {"name": "nonexistent_tool", "arguments": {}}
        });
        let id = serde_json::json!(10);
        handle_tool_call(&req, &id, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("unknown tool"));
    }

    #[test]
    fn handle_tool_call_list_protocols() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({
            "params": {"name": "dsct_list_protocols", "arguments": {}}
        });
        let id = serde_json::json!(11);
        handle_tool_call(&req, &id, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["id"], 11);
        // structuredContent should be a JSON object with a "protocols" array.
        let sc = resp["result"]["structuredContent"]
            .as_object()
            .expect("structuredContent should be object");
        let protocols = sc["protocols"]
            .as_array()
            .expect("protocols should be array");
        assert!(!protocols.is_empty());
        // content text fallback should parse to the same value.
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let parsed: Value = serde_json::from_str(text).unwrap();
        assert_eq!(parsed, resp["result"]["structuredContent"]);
    }

    #[test]
    fn handle_tool_call_list_fields() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({
            "params": {"name": "dsct_list_fields", "arguments": {"protocols": ["dns"]}}
        });
        let id = serde_json::json!(12);
        handle_tool_call(&req, &id, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        // structuredContent should be a JSON object with a "fields" array.
        let sc = resp["result"]["structuredContent"]
            .as_object()
            .expect("structuredContent should be object");
        let fields = sc["fields"].as_array().expect("fields should be array");
        assert!(!fields.is_empty());
        // Verify content text matches structuredContent.
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("dns"));
    }

    #[test]
    fn handle_tool_call_get_schema() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({
            "params": {"name": "dsct_get_schema", "arguments": {"command": "read"}}
        });
        let id = serde_json::json!(13);
        handle_tool_call(&req, &id, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert!(resp["result"]["structuredContent"].is_object());
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(!text.is_empty());
    }

    #[test]
    fn handle_tool_call_get_stats_missing_file() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({
            "params": {
                "name": "dsct_get_stats",
                "arguments": {"file": "/nonexistent/file.pcap"}
            }
        });
        let id = serde_json::json!(14);
        handle_tool_call(&req, &id, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["result"]["isError"], true);
    }

    // -- handle_read_packets_streaming --------------------------------

    #[test]
    fn streaming_missing_file_returns_tool_error() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let id = serde_json::json!(20);
        let args = serde_json::json!({"file": "/nonexistent/capture.pcap"});
        handle_read_packets_streaming(&id, &args, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains("failed to stat file") || text.contains("failed to open capture file")
        );
    }

    #[test]
    fn streaming_missing_file_param_returns_tool_error() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let id = serde_json::json!(99);
        let args = serde_json::json!({});
        handle_read_packets_streaming(&id, &args, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["result"]["isError"], true);
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("\"file\" parameter is required"));
    }

    #[test]
    fn streaming_invalid_packet_number_returns_tool_error() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let id = serde_json::json!(21);
        let args = serde_json::json!({"file": "/tmp/x.pcap", "packet_number": "abc!!"});
        handle_read_packets_streaming(&id, &args, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["result"]["isError"], true);
    }

    #[test]
    fn streaming_invalid_decode_as_returns_tool_error() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let id = serde_json::json!(22);
        let args = serde_json::json!({"file": "/tmp/x.pcap", "decode_as": ["invalid"]});
        handle_read_packets_streaming(&id, &args, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["result"]["isError"], true);
    }

    // -- run_on (full server loop) ------------------------------------

    #[test]
    fn run_on_empty_input() {
        let input = b"";
        let mut output = Vec::new();
        let limits = ResourceLimits::default();
        run_on(&input[..], &mut output, &limits).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn run_on_blank_lines_ignored() {
        let input = b"\n  \n\n";
        let mut output = Vec::new();
        let limits = ResourceLimits::default();
        run_on(&input[..], &mut output, &limits).unwrap();
        assert!(output.is_empty());
    }

    #[test]
    fn run_on_malformed_json_returns_parse_error() {
        let input = b"not valid json\n{also bad\n";
        let mut output = Vec::new();
        let limits = ResourceLimits::default();
        run_on(&input[..], &mut output, &limits).unwrap();
        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "expected one error per malformed line");
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("invalid JSON response: {e}: {line}"));
            assert_eq!(v["jsonrpc"], "2.0");
            assert!(v["id"].is_null());
            assert_eq!(v["error"]["code"], -32700);
            assert!(
                v["error"]["message"]
                    .as_str()
                    .unwrap()
                    .contains("parse error")
            );
        }
    }

    #[test]
    fn run_on_initialize_then_ping() {
        let input = br#"{"jsonrpc":"2.0","id":1,"method":"initialize"}
{"jsonrpc":"2.0","id":2,"method":"ping"}
"#;
        let mut output = Vec::new();
        let limits = ResourceLimits::default();
        run_on(&input[..], &mut output, &limits).unwrap();
        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let resp1: Value = serde_json::from_str(lines[0]).unwrap();
        let resp2: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(resp1["id"], 1);
        assert_eq!(resp1["result"]["protocolVersion"], "2025-11-25");
        assert_eq!(resp2["id"], 2);
    }

    // -- streaming with real pcap -------------------------------------

    /// Build a pcap with `n` Ethernet+IPv4+UDP packets.
    fn build_test_pcap(n: usize) -> Vec<u8> {
        let mut pcap = Vec::new();
        pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
        pcap.extend_from_slice(&2u16.to_le_bytes());
        pcap.extend_from_slice(&4u16.to_le_bytes());
        pcap.extend_from_slice(&0i32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&65535u32.to_le_bytes());
        pcap.extend_from_slice(&1u32.to_le_bytes());

        let pkt: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x00,
            0x00, 0x01, 0x0A, 0x00, 0x00, 0x02, 0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
        ];
        for i in 0..n {
            let ts_sec = (i / 1000) as u32;
            let ts_usec = ((i % 1000) * 1000) as u32;
            pcap.extend_from_slice(&ts_sec.to_le_bytes());
            pcap.extend_from_slice(&ts_usec.to_le_bytes());
            pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            pcap.extend_from_slice(pkt);
        }
        pcap
    }

    /// Write a pcap with `pkt_count` packets to a unique temp file.
    fn write_test_pcap_n(pkt_count: usize, label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("dsct_test_{}_{label}_{n}.pcap", std::process::id()));
        std::fs::write(&path, build_test_pcap(pkt_count)).expect("write test pcap");
        path
    }

    /// Shorthand: write a single-packet pcap.
    fn write_test_pcap(label: &str) -> std::path::PathBuf {
        write_test_pcap_n(1, label)
    }

    /// Run `handle_read_packets_streaming` against a test pcap with
    /// `pkt_count` packets and return the parsed response.
    fn run_streaming_n(pkt_count: usize, extra_args: Value) -> Value {
        let pcap_path = write_test_pcap_n(pkt_count, "x");
        let file = pcap_path.to_str().unwrap().to_string();
        let mut args = extra_args;
        args.as_object_mut()
            .unwrap()
            .insert("file".into(), file.into());

        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let id = serde_json::json!(1);
        handle_read_packets_streaming(&id, &args, &limits, &mut buf).unwrap();
        let _ = std::fs::remove_file(&pcap_path);

        let output = String::from_utf8(buf).unwrap();
        let resp: Value = serde_json::from_str(&output)
            .unwrap_or_else(|e| panic!("invalid JSON response: {e}: {output}"));
        assert_eq!(resp["jsonrpc"], "2.0");
        resp
    }

    /// Shorthand: single-packet streaming.
    fn run_streaming(extra_args: Value) -> Value {
        run_streaming_n(1, extra_args)
    }

    #[test]
    fn streaming_valid_pcap_produces_structured_content() {
        let resp = run_streaming(serde_json::json!({}));
        let sc = resp["result"]["structuredContent"]
            .as_object()
            .expect("structuredContent should be an object");
        let arr = sc["packets"]
            .as_array()
            .expect("packets should be an array");
        assert!(!arr.is_empty(), "should contain packet data");
        // Each element should be a valid packet object.
        for pkt in arr {
            assert!(pkt["number"].is_number());
            assert!(pkt["stack"].is_string());
            assert!(pkt["layers"].is_array());
        }
        // content text fallback should have packet count.
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("packets"));
    }

    #[test]
    fn streaming_with_count_limits_output() {
        let resp = run_streaming(serde_json::json!({"count": 1}));
        let arr = resp["result"]["structuredContent"]["packets"]
            .as_array()
            .expect("should be array");
        assert!(arr.len() <= 1, "count=1 should limit to at most 1 packet");
    }

    #[test]
    fn streaming_with_count_as_string_limits_output() {
        let resp = run_streaming(serde_json::json!({"count": "0"}));
        let arr = resp["result"]["structuredContent"]["packets"]
            .as_array()
            .expect("should be array");
        assert!(
            arr.is_empty(),
            "count=\"0\" (string) should return no packets, got {}",
            arr.len()
        );
    }

    #[test]
    fn streaming_with_offset_as_string_skips_packets() {
        let resp = run_streaming(serde_json::json!({"offset": "100"}));
        let arr = resp["result"]["structuredContent"]["packets"]
            .as_array()
            .expect("should be array");
        assert!(
            arr.is_empty(),
            "offset=\"100\" (string) should skip all packets, got {}",
            arr.len()
        );
    }

    #[test]
    fn streaming_with_protocol_filter() {
        let resp = run_streaming(serde_json::json!({"filter": "dns"}));
        let arr = resp["result"]["structuredContent"]["packets"]
            .as_array()
            .expect("should be array");
        assert!(
            arr.is_empty(),
            "no packets should match dns filter, got {}",
            arr.len()
        );
    }

    #[test]
    fn streaming_with_offset_skips_packets() {
        let resp = run_streaming(serde_json::json!({"offset": 100}));
        let arr = resp["result"]["structuredContent"]["packets"]
            .as_array()
            .expect("should be array");
        assert!(
            arr.is_empty(),
            "offset > packet count should produce no packet lines, got {}",
            arr.len()
        );
    }

    #[test]
    fn streaming_with_packet_number_filter() {
        let resp = run_streaming(serde_json::json!({"packet_number": "1"}));
        let arr = resp["result"]["structuredContent"]["packets"]
            .as_array()
            .expect("should be array");
        assert!(
            !arr.is_empty(),
            "packet_number=1 should match the single packet"
        );
    }

    #[test]
    fn streaming_via_tool_call() {
        let pcap_path = write_test_pcap("x");
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({
            "params": {
                "name": "dsct_read_packets",
                "arguments": {"file": pcap_path.to_str().unwrap(), "count": 1}
            }
        });
        let id = serde_json::json!(36);
        handle_tool_call(&req, &id, &limits, &mut buf).unwrap();
        let _ = std::fs::remove_file(&pcap_path);

        let output = String::from_utf8(buf).unwrap();
        let resp: Value = serde_json::from_str(&output).unwrap();
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 36);
        let arr = resp["result"]["structuredContent"]["packets"]
            .as_array()
            .expect("packets should be array");
        assert!(!arr.is_empty());
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("packets"));
    }

    // -- schema functions ---------------------------------------------

    #[test]
    fn get_stats_schema_requires_file() {
        let schema = get_stats_schema();
        let required = schema["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "file"));
    }

    #[test]
    fn list_fields_schema_has_protocols_property() {
        let schema = list_fields_schema();
        assert!(schema["properties"]["protocols"].is_object());
    }

    #[test]
    fn get_schema_schema_has_command_property() {
        let schema = get_schema_schema();
        assert!(schema["properties"]["command"].is_object());
    }

    // -- dsct_read_packets with multi-packet pcap -----------------------

    #[test]
    fn streaming_multi_packet_pcap_returns_all_packets() {
        let resp = run_streaming_n(5, serde_json::json!({}));
        let arr = resp["result"]["structuredContent"]["packets"]
            .as_array()
            .expect("packets should be an array");
        assert_eq!(arr.len(), 5, "should return all 5 packets");

        for (i, pkt) in arr.iter().enumerate() {
            assert_eq!(pkt["number"].as_u64().unwrap(), (i + 1) as u64);
            assert!(pkt["layers"].is_array());
            assert!(pkt["stack"].as_str().unwrap().contains("Ethernet"));
        }
    }

    #[test]
    fn streaming_multi_packet_with_count_and_offset() {
        let resp = run_streaming_n(10, serde_json::json!({"count": 3, "offset": 2}));
        let arr = resp["result"]["structuredContent"]["packets"]
            .as_array()
            .expect("packets should be an array");
        assert_eq!(arr.len(), 3, "should return exactly 3 packets");

        // offset=2 skips packets 1 and 2.
        assert_eq!(arr[0]["number"].as_u64().unwrap(), 3);
        assert_eq!(arr[2]["number"].as_u64().unwrap(), 5);
    }

    #[test]
    fn streaming_via_handle_tool_call_with_multi_packet() {
        let pcap_path = write_test_pcap_n(3, "htc");
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let req = serde_json::json!({
            "params": {
                "name": "dsct_read_packets",
                "arguments": {"file": pcap_path.to_str().unwrap()}
            }
        });
        let id = serde_json::json!(102);
        handle_tool_call(&req, &id, &limits, &mut buf).unwrap();
        let _ = std::fs::remove_file(&pcap_path);

        let resp = parse_response(&buf);
        assert_eq!(resp["id"], 102);

        let arr = resp["result"]["structuredContent"]["packets"]
            .as_array()
            .expect("packets should be an array");
        assert_eq!(arr.len(), 3);

        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        assert!(text.contains("3 packets"));
    }

    #[test]
    fn streaming_multi_packet_udp_filter_matches_all() {
        let resp = run_streaming_n(4, serde_json::json!({"filter": "udp"}));
        let arr = resp["result"]["structuredContent"]["packets"]
            .as_array()
            .expect("packets should be an array");
        assert_eq!(arr.len(), 4, "all packets are UDP, filter should match all");
    }

    #[test]
    fn streaming_invalid_esp_sa_returns_tool_error() {
        let mut buf = Vec::new();
        let limits = ResourceLimits::default();
        let id = serde_json::json!(104);
        let args = serde_json::json!({
            "file": "/tmp/x.pcap",
            "esp_sa": ["not_valid_sa"]
        });
        handle_read_packets_streaming(&id, &args, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["result"]["isError"], true);
    }

    // -- tool description guidance ------------------------------------

    #[test]
    fn read_packets_description_mentions_stats() {
        let result = tools_list_result();
        let tools = result["tools"].as_array().unwrap();
        let rp = tools
            .iter()
            .find(|t| t["name"] == "dsct_read_packets")
            .unwrap();
        let desc = rp["description"].as_str().unwrap();
        assert!(
            desc.contains("dsct_get_stats"),
            "read_packets description should reference dsct_get_stats"
        );
    }

    #[test]
    fn count_param_description_mentions_tokens() {
        let schema = read_packets_schema();
        let desc = schema["properties"]["count"]["description"]
            .as_str()
            .unwrap();
        assert!(
            desc.contains("token"),
            "count description should mention token budget"
        );
    }

    #[test]
    fn filter_description_mentions_discovery_tools() {
        let schema = read_packets_schema();
        let desc = schema["properties"]["filter"]["description"]
            .as_str()
            .unwrap();
        assert!(
            desc.contains("dsct_list_protocols"),
            "filter description should reference dsct_list_protocols"
        );
        assert!(
            desc.contains("dsct_list_fields"),
            "filter description should reference dsct_list_fields"
        );
    }

    #[test]
    fn list_fields_description_warns_about_output_size() {
        let result = tools_list_result();
        let tools = result["tools"].as_array().unwrap();
        let lf = tools
            .iter()
            .find(|t| t["name"] == "dsct_list_fields")
            .unwrap();
        let desc = lf["description"].as_str().unwrap();
        assert!(
            desc.contains("protocols"),
            "list_fields description should mention protocols parameter"
        );
    }

    #[test]
    fn missing_method_returns_invalid_request() {
        let limits = ResourceLimits::default();
        // Request with no "method" field at all.
        let mut buf = Vec::new();
        let req = serde_json::json!({"jsonrpc": "2.0", "id": 1});
        handle_message(&req, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["error"]["code"], -32600);
    }

    #[test]
    fn non_string_method_returns_invalid_request() {
        let limits = ResourceLimits::default();
        // "method" is a number instead of a string.
        let mut buf = Vec::new();
        let req = serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": 42});
        handle_message(&req, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["error"]["code"], -32600);
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let limits = ResourceLimits::default();
        let mut buf = Vec::new();
        let req = serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "nonexistent"});
        handle_message(&req, &limits, &mut buf).unwrap();
        let resp = parse_response(&buf);
        assert_eq!(resp["error"]["code"], -32601);
    }
}
