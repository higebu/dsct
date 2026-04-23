//! Snapshot / schema-stability tests for `dsct read` and `dsct stats` JSON output.
//!
//! Existing integration tests assert the *presence* of individual fields.
//! This file fixes the top-level **key set and order** of the JSON produced
//! by `write_packet_json` (`src/serialize.rs`) and `StatsOutput`
//! (`src/stats/mod.rs`) so that any accidental rename, reorder, or removal
//! of a top-level key is caught as a regression.
//!
//! `serde_json` is configured with `preserve_order` in `Cargo.toml`, so the
//! key iteration order is deterministic and reflects the write order used by
//! `serialize.rs` / `Serialize` impls.

use assert_cmd::Command;
use serde_json::{Map, Value};
use std::io::Write;
use tempfile::NamedTempFile;

/// Build a minimal pcap containing `n` identical Ethernet+IPv4+UDP packets.
///
/// Matches the format used by `tests/cli_read_test.rs` so we exercise the
/// same shared code path.
fn build_udp_pcap(n: usize) -> Vec<u8> {
    let mut pcap = Vec::new();
    // pcap global header (little-endian, Ethernet link type)
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes()); // version major
    pcap.extend_from_slice(&4u16.to_le_bytes()); // version minor
    pcap.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    pcap.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    pcap.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet link type

    let pkt: &[u8] = &[
        // Ethernet
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
        // IPv4: TTL=64, protocol=17 (UDP), src=10.0.0.1, dst=10.0.0.2
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00,
        0x01, 0x0a, 0x00, 0x00, 0x02, // UDP: sport=4096, dport=4097
        0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
    ];

    for i in 0..n {
        pcap.extend_from_slice(&(i as u32).to_le_bytes()); // ts_sec
        pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // caplen
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // origlen
        pcap.extend_from_slice(pkt);
    }
    pcap
}

fn write_pcap(n: usize) -> NamedTempFile {
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&build_udp_pcap(n)).unwrap();
    tmp
}

/// Return the ordered list of keys in a JSON object value.
fn object_keys(value: &Value) -> Vec<String> {
    value
        .as_object()
        .map(|m: &Map<String, Value>| m.keys().cloned().collect())
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// `dsct read` — packet record schema
// ---------------------------------------------------------------------------

#[test]
fn read_jsonl_top_level_keys_are_stable() {
    let tmp = write_pcap(1);
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success(), "read must exit 0");

    let stdout = String::from_utf8(output.stdout).unwrap();
    let first_line = stdout.lines().next().expect("at least one JSONL line");
    let value: Value = serde_json::from_str(first_line).unwrap();

    // Fix the exact top-level key order. Any rename / reorder / removal trips.
    let expected = [
        "number",
        "timestamp",
        "length",
        "original_length",
        "stack",
        "layers",
    ];
    assert_eq!(
        object_keys(&value),
        expected,
        "read JSONL top-level key order changed"
    );

    // Type invariants.
    assert!(value["number"].is_u64());
    let ts = value["timestamp"].as_str().expect("timestamp is string");
    assert!(
        ts.ends_with('Z') && ts.len() >= 20,
        "timestamp must be ISO 8601 Z-terminated, got {ts:?}"
    );
    assert!(value["length"].is_u64());
    assert!(value["original_length"].is_u64());
    assert!(value["stack"].is_string());
    assert!(value["layers"].is_array());

    // Stack summary must reflect the packet we built.
    assert_eq!(value["stack"], "Ethernet:IPv4:UDP");

    // Every layer must expose `protocol` then `fields`, in that order.
    for layer in value["layers"].as_array().unwrap() {
        let layer_keys = object_keys(layer);
        assert_eq!(
            layer_keys,
            ["protocol", "fields"],
            "layer object key order changed"
        );
        assert!(layer["protocol"].is_string());
        assert!(layer["fields"].is_object());
    }
}

#[test]
fn read_verbose_adds_fields_to_ipv4_layer() {
    let tmp = write_pcap(1);

    // Default run.
    let default_out = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(default_out.status.success());
    let default_line = String::from_utf8(default_out.stdout).unwrap();
    let default_value: Value = serde_json::from_str(default_line.lines().next().unwrap()).unwrap();

    // Verbose run.
    let verbose_out = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "--verbose", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(verbose_out.status.success());
    let verbose_line = String::from_utf8(verbose_out.stdout).unwrap();
    let verbose_value: Value = serde_json::from_str(verbose_line.lines().next().unwrap()).unwrap();

    // Top-level key order must be identical regardless of verbosity.
    assert_eq!(object_keys(&default_value), object_keys(&verbose_value));

    // Find the IPv4 layer in both outputs and compare field counts.
    let ipv4_fields_count = |v: &Value| -> usize {
        v["layers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|l| l["protocol"] == "IPv4")
            .and_then(|l| l["fields"].as_object())
            .map(|fs| fs.len())
            .unwrap_or(0)
    };

    let default_count = ipv4_fields_count(&default_value);
    let verbose_count = ipv4_fields_count(&verbose_value);
    assert!(
        verbose_count > default_count,
        "--verbose must expose more IPv4 fields (default={default_count}, verbose={verbose_count})"
    );
}

#[test]
fn read_raw_bytes_appends_field_at_end() {
    let tmp = write_pcap(1);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "--raw-bytes", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let first_line = stdout.lines().next().expect("at least one JSONL line");
    let value: Value = serde_json::from_str(first_line).unwrap();

    // raw_bytes must be appended after `layers`, preserving the existing
    // top-level key order.
    let expected = [
        "number",
        "timestamp",
        "length",
        "original_length",
        "stack",
        "layers",
        "raw_bytes",
    ];
    assert_eq!(
        object_keys(&value),
        expected,
        "raw_bytes must be appended at the end of the record"
    );
    assert!(value["raw_bytes"].is_string());
}

// ---------------------------------------------------------------------------
// `dsct stats` — StatsOutput schema
// ---------------------------------------------------------------------------

#[test]
fn stats_top_level_keys_are_stable() {
    let tmp = write_pcap(3);
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let value: Value = serde_json::from_slice(&output.stdout).unwrap();

    // StatsOutput field order per `#[derive(Serialize)]`:
    //   type, total_packets, time_start?, time_end?, duration_secs, protocols,
    //   ...protocol_stats (flattened), top_talkers?, tcp_streams?
    // Optional keys are skipped when None; with the UDP-only pcap built above
    // we expect time_start / time_end to be present (ts_sec=0..n).
    let keys = object_keys(&value);
    let expected_prefix = [
        "type",
        "total_packets",
        "time_start",
        "time_end",
        "duration_secs",
        "protocols",
    ];
    assert!(
        keys.starts_with(&expected_prefix.map(String::from)),
        "stats top-level key prefix changed; got {keys:?}"
    );

    // Invariants.
    assert_eq!(value["type"], "stats");
    assert_eq!(value["total_packets"].as_u64().unwrap(), 3);
    assert!(value["duration_secs"].is_number());
    assert!(value["protocols"].is_object());
    let protocols = value["protocols"].as_object().unwrap();
    assert!(
        protocols.contains_key("Ethernet")
            && protocols.contains_key("IPv4")
            && protocols.contains_key("UDP"),
        "protocols map missing expected entries: {protocols:?}"
    );

    // top_talkers / tcp_streams must NOT appear unless their flags are set.
    assert!(!keys.iter().any(|k| k == "top_talkers"));
    assert!(!keys.iter().any(|k| k == "tcp_streams"));
}

#[test]
fn stats_with_top_talkers_flag_adds_key() {
    let tmp = write_pcap(3);
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "--top-talkers", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());

    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        value.get("top_talkers").is_some(),
        "--top-talkers must add top_talkers key; got {value:?}"
    );
    let talkers = value["top_talkers"]
        .as_array()
        .expect("top_talkers must be an array");
    assert!(!talkers.is_empty(), "top_talkers must not be empty");

    // Every talker entry must carry the TalkerEntry contract.
    for entry in talkers {
        let entry_keys = object_keys(entry);
        assert_eq!(
            entry_keys,
            ["src", "dst", "packets", "bytes"],
            "TalkerEntry key order changed"
        );
    }
}
