//! End-to-end integration tests for info-style dsct subcommands.
//!
//! Covers `dsct list`, `dsct fields`, `dsct version`, `dsct schema`, and the
//! `dsct mcp` JSON-RPC handshake. These handlers have inline unit tests in
//! `src/main.rs` and `src/mcp/raw_mcp.rs`, but nothing previously exercised
//! the compiled binary end-to-end at the CLI contract boundary.

use assert_cmd::Command;
use serde_json::Value;

// ---------------------------------------------------------------------------
// list
// ---------------------------------------------------------------------------

#[test]
fn list_outputs_valid_json_array_with_core_protocols() {
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["list"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "dsct list must exit 0; got {:?}",
        output.status
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    let arr = value.as_array().expect("list output must be a JSON array");
    assert!(!arr.is_empty(), "protocol list must not be empty");

    let names: Vec<&str> = arr
        .iter()
        .filter_map(|entry| entry.get("name").and_then(Value::as_str))
        .collect();
    for expected in ["Ethernet", "IPv4", "TCP", "UDP", "DNS"] {
        assert!(
            names.contains(&expected),
            "{expected} must appear in `dsct list`; got {names:?}"
        );
    }

    // Every entry must carry both `name` and `full_name`.
    for entry in arr {
        assert!(
            entry.get("name").is_some(),
            "each list entry must have a `name`"
        );
        assert!(
            entry.get("full_name").is_some(),
            "each list entry must have a `full_name`"
        );
    }
}

// ---------------------------------------------------------------------------
// fields
// ---------------------------------------------------------------------------

#[test]
fn fields_without_arg_outputs_non_empty_json_array() {
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["fields"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    let arr = value.as_array().expect("fields output must be array");
    assert!(
        !arr.is_empty(),
        "fields output must not be empty without a filter"
    );

    // Each entry must expose a stable minimum contract.
    for entry in arr {
        assert!(entry.get("qualified_name").is_some());
        assert!(entry.get("type").is_some());
        assert!(entry.get("protocol").is_some());
    }
}

#[test]
fn fields_with_dns_filter_returns_only_dns_entries() {
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["fields", "dns"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    let arr = value.as_array().expect("fields output must be array");

    assert!(!arr.is_empty(), "DNS field list must not be empty");
    for entry in arr {
        let proto = entry["protocol"].as_str().unwrap_or_default();
        assert_eq!(
            proto.to_ascii_lowercase(),
            "dns",
            "only DNS fields should be returned, got {proto}"
        );
    }
}

#[test]
fn fields_unknown_protocol_returns_empty_array() {
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["fields", "nonexistent_protocol"])
        .output()
        .unwrap();

    // A non-matching filter is not an error; it must return an empty list.
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();
    let arr = value.as_array().expect("fields output must be array");
    assert!(arr.is_empty());
}

// ---------------------------------------------------------------------------
// version
// ---------------------------------------------------------------------------

#[test]
fn version_outputs_expected_keys() {
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["version"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let value: Value = serde_json::from_str(stdout.trim()).unwrap();

    assert_eq!(value["name"], "dsct");
    assert!(
        value["version"].is_string(),
        "version must be a JSON string"
    );
    assert!(
        value["protocols"].is_array(),
        "protocols must be a JSON array"
    );
    assert!(
        value["output_formats"].is_array(),
        "output_formats must be a JSON array"
    );
    assert!(
        value["output_formats"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f == "jsonl"),
        "output_formats must advertise `jsonl`"
    );
}

// ---------------------------------------------------------------------------
// schema
// ---------------------------------------------------------------------------

#[test]
fn schema_without_arg_defaults_to_read_schema() {
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["schema"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["title"], "dsct read packet record");
    assert_eq!(value["type"], "object");
}

#[test]
fn schema_read_and_stats_each_output_distinct_titles() {
    let read = Command::cargo_bin("dsct")
        .unwrap()
        .args(["schema", "read"])
        .output()
        .unwrap();
    let stats = Command::cargo_bin("dsct")
        .unwrap()
        .args(["schema", "stats"])
        .output()
        .unwrap();

    assert!(read.status.success());
    assert!(stats.status.success());

    let read_v: Value = serde_json::from_slice(&read.stdout).unwrap();
    let stats_v: Value = serde_json::from_slice(&stats.stdout).unwrap();

    assert_eq!(read_v["title"], "dsct read packet record");
    assert_eq!(stats_v["title"], "dsct stats output");

    // Sanity check on `required` lists so accidental removal trips this test.
    let read_required = read_v["required"].as_array().unwrap();
    assert!(read_required.iter().any(|v| v == "number"));
    assert!(read_required.iter().any(|v| v == "layers"));

    let stats_required = stats_v["required"].as_array().unwrap();
    assert!(stats_required.iter().any(|v| v == "total_packets"));
}

#[test]
fn schema_unknown_command_errors_with_exit_code_2() {
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["schema", "nonexistent"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));

    let stderr = String::from_utf8(output.stderr).unwrap();
    let value: Value = serde_json::from_str(stderr.trim()).unwrap();
    assert_eq!(value["error"]["code"], "invalid_arguments");
    assert!(value["error"]["message"].is_string());
}

// ---------------------------------------------------------------------------
// mcp
// ---------------------------------------------------------------------------

#[test]
fn mcp_initialize_then_tools_list_roundtrip() {
    // Newline-delimited JSON-RPC requests. `write_stdin` closes stdin on EOF,
    // which causes the MCP server to exit cleanly after handling both.
    let requests = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        "\n",
    );

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["mcp"])
        .write_stdin(requests)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "dsct mcp must exit 0; got {:?}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(
        lines.len(),
        2,
        "expected exactly 2 JSON-RPC responses, got {lines:#?}"
    );

    // First line: initialize response.
    let init: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(init["jsonrpc"], "2.0");
    assert_eq!(init["id"], 1);
    assert!(init["result"]["protocolVersion"].is_string());
    assert_eq!(init["result"]["serverInfo"]["name"], "dsct");
    assert!(init["result"]["serverInfo"]["version"].is_string());

    // Second line: tools/list response.
    let tools: Value = serde_json::from_str(lines[1]).unwrap();
    assert_eq!(tools["jsonrpc"], "2.0");
    assert_eq!(tools["id"], 2);
    let tool_arr = tools["result"]["tools"]
        .as_array()
        .expect("tools/list result.tools must be an array");
    let tool_names: Vec<&str> = tool_arr
        .iter()
        .filter_map(|t| t.get("name").and_then(Value::as_str))
        .collect();

    for expected in [
        "dsct_read_packets",
        "dsct_get_stats",
        "dsct_list_protocols",
        "dsct_list_fields",
        "dsct_get_schema",
    ] {
        assert!(
            tool_names.contains(&expected),
            "{expected} must appear in tools/list; got {tool_names:?}"
        );
    }
}
