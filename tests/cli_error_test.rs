//! CLI error-path integration tests for `dsct read`.
//!
//! Validates that the binary returns correct exit codes and structured
//! JSON error messages on stderr for various invalid inputs.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::NamedTempFile;

use std::io::Write;

#[test]
fn nonexistent_file_returns_exit_code_3() {
    Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "/nonexistent/file.pcap"])
        .assert()
        .failure()
        .code(3)
        .stderr(predicate::str::contains("file_not_found"));
}

#[test]
fn invalid_decode_as_returns_exit_code_2() {
    // Provide a valid pcap via /dev/null so we get past file open; the
    // invalid decode-as format should trigger an error before packet iteration.
    Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "--decode-as", "invalid_format", "/dev/null"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid_arguments"));
}

#[test]
fn invalid_esp_sa_returns_exit_code_2() {
    Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "--esp-sa", "not_valid", "/dev/null"])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid_arguments"));
}

#[test]
fn read_stdin_dash_with_empty_input_returns_exit_code_4() {
    Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "-"])
        .write_stdin("")
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("invalid_format"));
}

#[test]
fn invalid_packet_number_returns_exit_code_2() {
    // A valid pcap is needed so we reach the --packet-number parse stage.
    let pcap = build_minimal_pcap();
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();

    Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "-n", "abc!!", tmp.path().to_str().unwrap()])
        .assert()
        .failure()
        .code(2)
        .stderr(predicate::str::contains("invalid_arguments"));
}

#[test]
fn truncated_pcap_returns_exit_code_4() {
    // A file that is too small to be a valid pcap should return exit code 4
    // (invalid format).
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(b"too short").unwrap();

    Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", tmp.path().to_str().unwrap()])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("invalid_format"));
}

/// Build a minimal pcap containing one UDP packet.
fn build_minimal_pcap() -> Vec<u8> {
    let mut pcap = Vec::new();
    // Global header
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet

    let pkt: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x02, 0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
    ];
    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
    pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
    pcap.extend_from_slice(pkt);

    pcap
}
