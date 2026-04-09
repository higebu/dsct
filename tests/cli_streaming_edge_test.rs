//! Streaming edge-case integration tests for `dsct read`.
//!
//! Covers pcapng input, truncated packets (`captured_len < original_len`),
//! unsupported link types, partial stdin input, and zero-packet pcap files.

use assert_cmd::Command;
use predicates::prelude::*;
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
fn pcapng_minimum_file_is_read_successfully() {
    // Minimal pcapng: Section Header Block (28 B) + Interface Description
    // Block (20 B), no Enhanced Packet Blocks.
    let mut png = Vec::new();

    // --- SHB ---
    png.extend_from_slice(&0x0A0D_0D0Au32.to_le_bytes()); // block type
    png.extend_from_slice(&28u32.to_le_bytes()); // block total length
    png.extend_from_slice(&0x1A2B_3C4Du32.to_le_bytes()); // byte-order magic
    png.extend_from_slice(&1u16.to_le_bytes()); // major version
    png.extend_from_slice(&0u16.to_le_bytes()); // minor version
    png.extend_from_slice(&(-1i64).to_le_bytes()); // section length
    png.extend_from_slice(&28u32.to_le_bytes()); // trailing block total length

    // --- IDB ---
    png.extend_from_slice(&0x0000_0001u32.to_le_bytes()); // block type
    png.extend_from_slice(&20u32.to_le_bytes()); // block total length
    png.extend_from_slice(&1u16.to_le_bytes()); // link type = Ethernet
    png.extend_from_slice(&0u16.to_le_bytes()); // reserved
    png.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    png.extend_from_slice(&20u32.to_le_bytes()); // trailing block total length

    let mut tmp = NamedTempFile::with_suffix(".pcapng").unwrap();
    tmp.write_all(&png).unwrap();

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "dsct read failed on minimal pcapng: stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.trim().is_empty(), "unexpected stdout: {stdout:?}");
}

#[test]
fn truncated_packet_emits_warning_and_no_panic() {
    // Start from a valid 0-packet pcap global header, then append a record
    // whose captured_len (10) is less than original_len (42). Ten bytes is
    // shorter than an Ethernet header (14) so the fallback dissector fails
    // and exactly one warning line is emitted.
    let mut pcap = build_pcap(0);
    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    pcap.extend_from_slice(&10u32.to_le_bytes()); // captured_len
    pcap.extend_from_slice(&42u32.to_le_bytes()); // original_len
    pcap.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33]);

    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "dsct should not panic on truncated packet: stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.trim().is_empty(),
        "truncated packet should be skipped, got stdout: {stdout:?}"
    );

    let stderr = String::from_utf8(output.stderr).unwrap();
    let warning_lines: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("\"warning\""))
        .collect();
    assert_eq!(
        warning_lines.len(),
        1,
        "expected exactly one structured warning line, stderr = {stderr:?}"
    );
}

#[test]
fn unsupported_link_type_skips_packets_and_continues() {
    // Pcap global header with link_type = 0x7FFF. Two record headers with
    // 5-byte payloads (too short for the fallback Ethernet dissector). dsct
    // must skip both packets with warnings and keep iterating.
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes()); // magic
    pcap.extend_from_slice(&2u16.to_le_bytes()); // major
    pcap.extend_from_slice(&4u16.to_le_bytes()); // minor
    pcap.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    pcap.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    pcap.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    pcap.extend_from_slice(&0x0000_7FFFu32.to_le_bytes()); // link type 0x7FFF

    let junk: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00];
    for i in 0..2u32 {
        pcap.extend_from_slice(&i.to_le_bytes()); // ts_sec
        pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        pcap.extend_from_slice(&(junk.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(junk.len() as u32).to_le_bytes());
        pcap.extend_from_slice(junk);
    }

    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "dsct should keep running on unsupported link type: stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.trim().is_empty(),
        "all packets should be skipped, got stdout: {stdout:?}"
    );

    let stderr = String::from_utf8(output.stderr).unwrap();
    let warning_lines: Vec<&str> = stderr
        .lines()
        .filter(|l| l.contains("\"warning\""))
        .collect();
    assert_eq!(
        warning_lines.len(),
        2,
        "expected one warning per skipped packet, stderr = {stderr:?}"
    );
}

#[test]
fn stdin_partial_pcap_header_returns_exit_code_4() {
    // First 16 bytes of a valid pcap global header — shorter than the 24
    // bytes required. Reader should report invalid format and dsct should
    // exit with code 4.
    let full = build_pcap(0);
    let partial = full[..16].to_vec();

    Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", "-"])
        .write_stdin(partial)
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("invalid_format"));
}

#[test]
fn zero_packet_pcap_exits_clean() {
    let tmp = write_pcap(0);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "dsct read should exit 0 on empty pcap: stderr = {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "stdout should be empty, got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}
