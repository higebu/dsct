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

// -- filter expression end-to-end tests --
//
// These exercise `src/filter_expr.rs` + `src/sql_filter.rs` through the CLI
// against a pcap that mixes TCP, UDP, and DNS so each filter operator has a
// meaningful partition of matching and non-matching packets.

/// Build a pcap with five Ethernet/IPv4 packets that cover TCP, UDP, and DNS.
///
/// | # | L4  | src IP   | dst IP   | src port | dst port |
/// |---|-----|----------|----------|----------|----------|
/// | 1 | TCP | 10.0.0.1 | 10.0.0.2 | 5000     | 80       |
/// | 2 | UDP | 10.0.0.2 | 10.0.0.1 | 12345    | 54321    |
/// | 3 | TCP | 10.0.0.2 | 10.0.0.1 | 443      | 8080     |
/// | 4 | UDP | 10.0.0.3 | 10.0.0.2 | 5353     | 53 (DNS) |
/// | 5 | TCP | 10.0.0.1 | 10.0.0.2 | 6000     | 443      |
fn build_mixed_pcap() -> Vec<u8> {
    let mut pcap = Vec::new();
    // Global header (pcap little-endian, Ethernet link type).
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes()); // version major
    pcap.extend_from_slice(&4u16.to_le_bytes()); // version minor
    pcap.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    pcap.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    pcap.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet link type

    let packets: [Vec<u8>; 5] = [
        tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 5000, 80),
        udp_frame([10, 0, 0, 2], [10, 0, 0, 1], 12345, 54321, &[]),
        tcp_frame([10, 0, 0, 2], [10, 0, 0, 1], 443, 8080),
        dns_frame([10, 0, 0, 3], [10, 0, 0, 2], 5353, 53),
        tcp_frame([10, 0, 0, 1], [10, 0, 0, 2], 6000, 443),
    ];

    for (i, pkt) in packets.iter().enumerate() {
        let ts_sec = (i + 1) as u32;
        pcap.extend_from_slice(&ts_sec.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        pcap.extend_from_slice(pkt);
    }
    pcap
}

fn write_mixed_pcap() -> NamedTempFile {
    let pcap = build_mixed_pcap();
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();
    tmp
}

/// Build an Ethernet + IPv4 frame wrapping the given L4 payload.
fn eth_ipv4_frame(src: [u8; 4], dst: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    // Ethernet header
    frame.extend_from_slice(&[0xff; 6]); // dst mac (broadcast)
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4

    // IPv4 header (no options, 20 bytes)
    let total_len: u16 = 20 + payload.len() as u16;
    frame.push(0x45); // version=4, IHL=5
    frame.push(0x00); // DSCP/ECN
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // identification
    frame.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    frame.push(64); // TTL
    frame.push(protocol);
    frame.extend_from_slice(&0u16.to_be_bytes()); // header checksum (unchecked)
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(payload);
    frame
}

/// Build a full TCP-over-IPv4 frame with a minimal 20-byte TCP header.
fn tcp_frame(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes()); // sequence number
    tcp.extend_from_slice(&0u32.to_be_bytes()); // acknowledgment number
    tcp.push(0x50); // data offset = 5 (20 bytes), reserved = 0
    tcp.push(0x02); // flags: SYN
    tcp.extend_from_slice(&0x2000u16.to_be_bytes()); // window
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
    eth_ipv4_frame(src, dst, 6, &tcp)
}

/// Build a full UDP-over-IPv4 frame with the given payload.
fn udp_frame(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut udp = Vec::new();
    let udp_len: u16 = 8 + payload.len() as u16;
    udp.extend_from_slice(&src_port.to_be_bytes());
    udp.extend_from_slice(&dst_port.to_be_bytes());
    udp.extend_from_slice(&udp_len.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
    udp.extend_from_slice(payload);
    eth_ipv4_frame(src, dst, 17, &udp)
}

/// Build a DNS-over-UDP frame with a minimal query for the name "a".
fn dns_frame(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
    // 12-byte DNS header + single question (QNAME="a", QTYPE=A, QCLASS=IN).
    let dns: &[u8] = &[
        0x12, 0x34, // transaction id
        0x01, 0x00, // flags: standard query, RD=1
        0x00, 0x01, // qdcount = 1
        0x00, 0x00, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
        0x01, b'a', 0x00, // qname: label "a", null terminator
        0x00, 0x01, // qtype = A
        0x00, 0x01, // qclass = IN
    ];
    udp_frame(src, dst, src_port, dst_port, dns)
}

/// Run `dsct read --no-limit -f <expr> <mixed.pcap>` and return matching packet numbers.
fn run_filter(tmp: &NamedTempFile, expr: &str) -> Vec<u64> {
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "read",
            "--no-limit",
            "-f",
            expr,
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "dsct read -f {expr:?} failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    packet_numbers(&stdout)
}

#[test]
fn read_filter_and_protocol_and_field() {
    let tmp = write_mixed_pcap();
    // Only packet #1 is TCP with dst_port = 80.
    assert_eq!(run_filter(&tmp, "tcp AND tcp.dst_port = 80"), vec![1]);
}

#[test]
fn read_filter_or_protocol_or_field() {
    let tmp = write_mixed_pcap();
    // UDP packets (#2, #4) plus TCP packets with src_port > 1024 (#1, #5);
    // #3 is TCP but its src_port (443) fails the threshold.
    assert_eq!(
        run_filter(&tmp, "udp OR tcp.src_port > 1024"),
        vec![1, 2, 4, 5]
    );
}

#[test]
fn read_filter_not_protocol() {
    let tmp = write_mixed_pcap();
    // Only packet #4 carries a DNS layer; the rest should match.
    assert_eq!(run_filter(&tmp, "NOT dns"), vec![1, 2, 3, 5]);
}

#[test]
fn read_filter_ipv4_in_list() {
    let tmp = write_mixed_pcap();
    // Packet #4's src is 10.0.0.3, so it is excluded.
    assert_eq!(
        run_filter(&tmp, "ipv4.src IN ('10.0.0.1', '10.0.0.2')"),
        vec![1, 2, 3, 5]
    );
}

#[test]
fn read_filter_tcp_dst_port_between() {
    let tmp = write_mixed_pcap();
    // #1 (80) and #5 (443) are in range; #3 (8080) is not.
    assert_eq!(
        run_filter(&tmp, "tcp.dst_port BETWEEN 80 AND 443"),
        vec![1, 5]
    );
}

#[test]
fn read_filter_packet_number_between() {
    let tmp = write_mixed_pcap();
    // Virtual column packet_number — exercises the packet-number-only fast path.
    assert_eq!(
        run_filter(&tmp, "packet_number BETWEEN 2 AND 4"),
        vec![2, 3, 4]
    );
}

#[test]
fn read_filter_invalid_sql_returns_exit_code_2() {
    let tmp = write_mixed_pcap();

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "read",
            "-f",
            "tcp.dst_port ==",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));

    let stderr = String::from_utf8(output.stderr).unwrap();
    let err: serde_json::Value = serde_json::from_str(stderr.trim())
        .unwrap_or_else(|e| panic!("stderr is not valid JSON: {e}; stderr={stderr:?}"));
    assert_eq!(err["error"]["code"], "invalid_arguments");
    let msg = err["error"]["message"]
        .as_str()
        .expect("error.message should be a string");
    assert!(!msg.is_empty());
    assert!(
        msg.contains("SQL parse error"),
        "expected SQL parse error message, got: {msg}"
    );
}
