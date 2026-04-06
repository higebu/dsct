//! Positive-path integration tests for `dsct read`.
//!
//! Validates that the binary produces correct JSONL output for valid captures,
//! including filtering, pagination, and default packet limit behavior.

use assert_cmd::Command;
use tempfile::NamedTempFile;

use std::io::Write;

/// Build a minimal pcap containing `n` identical UDP packets.
fn build_pcap(n: usize) -> Vec<u8> {
    let mut pcap = Vec::new();
    // Global header (pcap little-endian)
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes()); // version major
    pcap.extend_from_slice(&4u16.to_le_bytes()); // version minor
    pcap.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    pcap.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    pcap.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet link type

    // Ethernet + IPv4 + UDP packet (42 bytes)
    let pkt: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst mac
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac
        0x08, 0x00, // ethertype IPv4
        0x45, 0x00, 0x00, 0x1C, // IPv4 header
        0x00, 0x00, 0x00, 0x00, // identification, flags
        0x40, 0x11, 0x00, 0x00, // TTL=64, protocol=UDP
        0x0A, 0x00, 0x00, 0x01, // src IP 10.0.0.1
        0x0A, 0x00, 0x00, 0x02, // dst IP 10.0.0.2
        0x10, 0x00, 0x10, 0x01, // src port 4096, dst port 4097
        0x00, 0x08, 0x00, 0x00, // UDP length, checksum
    ];

    for i in 0..n {
        let ts_sec = i as u32;
        pcap.extend_from_slice(&ts_sec.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        pcap.extend_from_slice(pkt);
    }
    pcap
}

fn write_pcap(n: usize) -> NamedTempFile {
    let pcap = build_pcap(n);
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();
    tmp
}

#[test]
fn read_single_packet_produces_valid_jsonl() {
    let tmp = write_pcap(1);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines.len(), 1);

    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(v["number"], 1);
    assert!(v["timestamp"].is_string());
    assert!(v["length"].is_number());
    assert!(v["stack"].is_string());
    assert!(v["layers"].is_array());
}

#[test]
fn read_count_limits_output() {
    let tmp = write_pcap(10);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "--count", "3", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim().lines().count(), 3);
}

#[test]
fn read_offset_skips_packets() {
    let tmp = write_pcap(5);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "read",
            "--offset",
            "2",
            "--count",
            "2",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines.len(), 2);

    // First output packet should be packet #3 (offset 2 skips #1 and #2)
    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(v["number"], 3);
}

#[test]
fn read_packet_number_selects_specific_packets() {
    let tmp = write_pcap(10);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "-n", "2,5,8", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines.len(), 3);

    let numbers: Vec<u64> = lines
        .iter()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["number"].as_u64().unwrap()
        })
        .collect();
    assert_eq!(numbers, vec![2, 5, 8]);
}

#[test]
fn read_filter_by_protocol() {
    let tmp = write_pcap(3);

    // Filter for UDP — all packets should match since they are all UDP
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "-f", "udp", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim().lines().count(), 3);

    // Filter for DNS — no packets should match
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "-f", "dns", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim().lines().count(), 0);
}

#[test]
fn read_verbose_includes_extra_fields() {
    let tmp = write_pcap(1);

    let default_output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    let verbose_output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "--verbose", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(default_output.status.success());
    assert!(verbose_output.status.success());

    // Verbose output should generally be longer (more fields)
    assert!(verbose_output.stdout.len() >= default_output.stdout.len());
}

#[test]
fn read_stdin_produces_output() {
    let pcap = build_pcap(1);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "-"])
        .write_stdin(pcap)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim().lines().count(), 1);
}

#[test]
fn read_no_limit_outputs_all_packets() {
    let tmp = write_pcap(5);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "--no-limit", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.trim().lines().count(), 5);
}

// -- sample-rate tests --

/// Helper: parse JSONL output and extract packet numbers.
fn packet_numbers(stdout: &str) -> Vec<u64> {
    stdout
        .trim()
        .lines()
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            v["number"].as_u64().unwrap()
        })
        .collect()
}

#[test]
fn sample_rate_outputs_every_nth() {
    let tmp = write_pcap(20);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "read",
            "--sample-rate",
            "5",
            "--no-limit",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let nums = packet_numbers(&String::from_utf8(output.stdout).unwrap());
    assert_eq!(nums, vec![1, 6, 11, 16]);
}

#[test]
fn sample_rate_with_count() {
    let tmp = write_pcap(100);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "read",
            "--sample-rate",
            "10",
            "--count",
            "3",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let nums = packet_numbers(&String::from_utf8(output.stdout).unwrap());
    assert_eq!(nums, vec![1, 11, 21]);
}

#[test]
fn sample_rate_with_offset() {
    let tmp = write_pcap(100);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "read",
            "--sample-rate",
            "10",
            "--offset",
            "2",
            "--count",
            "2",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let nums = packet_numbers(&String::from_utf8(output.stdout).unwrap());
    assert_eq!(nums, vec![21, 31]);
}

#[test]
fn sample_rate_zero_is_error() {
    let tmp = write_pcap(5);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "--sample-rate", "0", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(!output.status.success());
}

#[test]
fn sample_rate_one_is_identity() {
    let tmp = write_pcap(5);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "read",
            "--sample-rate",
            "1",
            "--no-limit",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let nums = packet_numbers(&String::from_utf8(output.stdout).unwrap());
    assert_eq!(nums, vec![1, 2, 3, 4, 5]);
}

#[test]
fn sample_rate_larger_than_total() {
    let tmp = write_pcap(5);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "read",
            "--sample-rate",
            "10",
            "--no-limit",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let nums = packet_numbers(&String::from_utf8(output.stdout).unwrap());
    assert_eq!(nums, vec![1]);
}
