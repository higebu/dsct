//! Integration tests for `dsct read --threads` (parallel filter evaluation).
//!
//! These tests verify that the parallel path produces byte-identical output to
//! the sequential path, that fallback to sequential happens when required, and
//! that all limit/offset/sample-rate interactions are preserved.

use assert_cmd::Command;
use std::io::Write;
use tempfile::NamedTempFile;

// ---------------------------------------------------------------------------
// Pcap generation helpers
// ---------------------------------------------------------------------------

/// A minimal valid Ethernet + IPv4 + UDP packet (42 bytes).
/// `src_ip` and `dst_ip` are the last octets only (first three = 10.0.0).
fn udp_pkt(src_ip_last: u8, dst_ip_last: u8, src_port: u16, dst_port: u16) -> [u8; 42] {
    let mut p = [0u8; 42];
    // Ethernet (14 bytes)
    p[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]); // dst mac
    p[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    p[12..14].copy_from_slice(&[0x08, 0x00]); // ethertype IPv4
    // IPv4 header (20 bytes, starts at p[14])
    p[14] = 0x45; // version=4, IHL=5
    p[15] = 0x00; // DSCP/ECN
    p[16..18].copy_from_slice(&28u16.to_be_bytes()); // total length (20 IP + 8 UDP)
    // p[18..20]: identification = 0
    // p[20..22]: flags+fragment offset = 0
    p[22] = 0x40; // TTL = 64
    p[23] = 0x11; // protocol = 17 (UDP)
    // p[24..26]: checksum = 0 (not validated)
    p[26] = 10;
    p[27] = 0;
    p[28] = 0;
    p[29] = src_ip_last; // src IP = 10.0.0.src_ip_last
    p[30] = 10;
    p[31] = 0;
    p[32] = 0;
    p[33] = dst_ip_last; // dst IP = 10.0.0.dst_ip_last
    // UDP header (8 bytes, starts at p[34])
    p[34..36].copy_from_slice(&src_port.to_be_bytes());
    p[36..38].copy_from_slice(&dst_port.to_be_bytes());
    p[38..40].copy_from_slice(&8u16.to_be_bytes()); // UDP length
    // p[40..42]: checksum = 0
    p
}

/// A minimal Ethernet + IPv4 + TCP segment (54 bytes, SYN or DATA based on flags).
fn tcp_pkt(
    src_ip_last: u8,
    dst_ip_last: u8,
    src_port: u16,
    dst_port: u16,
    flags: u8,
    seq: u32,
) -> Vec<u8> {
    let mut p = vec![0u8; 54];
    // Ethernet (14 bytes)
    p[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    p[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    p[12..14].copy_from_slice(&[0x08, 0x00]);
    // IPv4 (20 bytes, starts at p[14])
    p[14] = 0x45; // version=4, IHL=5
    p[15] = 0x00;
    p[16..18].copy_from_slice(&40u16.to_be_bytes()); // total length = 20 IP + 20 TCP
    // p[18..22]: identification + flags+frag = 0
    p[22] = 0x40; // TTL = 64
    p[23] = 0x06; // protocol = 6 (TCP)
    // p[24..26]: checksum = 0
    p[26] = 10;
    p[27] = 0;
    p[28] = 0;
    p[29] = src_ip_last;
    p[30] = 10;
    p[31] = 0;
    p[32] = 0;
    p[33] = dst_ip_last;
    // TCP (20 bytes, starts at p[34])
    p[34..36].copy_from_slice(&src_port.to_be_bytes());
    p[36..38].copy_from_slice(&dst_port.to_be_bytes());
    p[38..42].copy_from_slice(&seq.to_be_bytes()); // seq number
    p[42..46].copy_from_slice(&0u32.to_be_bytes()); // ack number
    p[46] = 0x50; // data offset = 5 (20 bytes header), reserved bits = 0
    p[47] = flags;
    p[48..50].copy_from_slice(&65535u16.to_be_bytes()); // window size
    p
}

/// A minimal Ethernet + IPv4 + ICMP Echo Request packet (42 bytes).
/// RFC 792 — Echo or Echo Reply Message.
/// <https://www.rfc-editor.org/rfc/rfc792>
fn icmp_echo_pkt(src_ip_last: u8, dst_ip_last: u8, sequence: u16) -> [u8; 42] {
    let mut p = [0u8; 42];
    p[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    p[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    p[12..14].copy_from_slice(&[0x08, 0x00]);
    p[14] = 0x45; // version=4, IHL=5
    p[16..18].copy_from_slice(&28u16.to_be_bytes()); // total length = 20 IP + 8 ICMP
    p[22] = 0x40; // TTL = 64
    p[23] = 0x01; // protocol = 1 (ICMP)
    p[26..30].copy_from_slice(&[10, 0, 0, src_ip_last]);
    p[30..34].copy_from_slice(&[10, 0, 0, dst_ip_last]);
    p[34] = 8; // type = Echo Request
    p[38..40].copy_from_slice(&1u16.to_be_bytes()); // identifier
    p[40..42].copy_from_slice(&sequence.to_be_bytes());
    p
}

/// Build a synthetic pcap with `n_rounds` rounds of:
/// - Several UDP packets (varying src/dst IPs and ports)
/// - A TCP SYN and a TCP data packet with `tcp.dst_port > 1024`
/// - An ICMP Echo Request (the only packets the parallel path handles)
///
/// Total packets = n_rounds * 6.
pub fn build_mixed_pcap(n_rounds: usize) -> Vec<u8> {
    let mut pcap = Vec::new();
    // Global header
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet

    let mut pkt_idx = 0usize;

    for i in 0..n_rounds {
        let ts = (i as u32) * 6;

        // UDP packet 1: 10.0.0.1 -> 10.0.0.2 port 4096->4097
        let u1 = udp_pkt(1, 2, 4096, 4097);
        push_pkt(&mut pcap, ts, 0, &u1);
        pkt_idx += 1;

        // UDP packet 2: 10.0.0.3 -> 10.0.0.4 port 5000->5001
        let u2 = udp_pkt(3, 4, 5000, 5001);
        push_pkt(&mut pcap, ts + 1, 0, &u2);
        pkt_idx += 1;

        // UDP packet 3: 10.0.0.1 -> 10.0.0.5 port 9000->9001
        let u3 = udp_pkt(1, 5, 9000, 9001);
        push_pkt(&mut pcap, ts + 2, 0, &u3);
        pkt_idx += 1;

        // TCP SYN: 10.0.0.10 -> 10.0.0.20 port 12345->2000
        let t1 = tcp_pkt(10, 20, 12345, 2000, 0x02, (pkt_idx as u32) * 100);
        push_pkt(&mut pcap, ts + 3, 0, &t1);
        pkt_idx += 1;

        // TCP data: 10.0.0.10 -> 10.0.0.20 port 12345->2000
        let t2 = tcp_pkt(10, 20, 12345, 2000, 0x18, (pkt_idx as u32) * 100);
        push_pkt(&mut pcap, ts + 4, 0, &t2);
        pkt_idx += 1;

        // ICMP Echo Request: 10.0.0.1 -> 10.0.0.2
        let e1 = icmp_echo_pkt(1, 2, i as u16);
        push_pkt(&mut pcap, ts + 5, 0, &e1);
        pkt_idx += 1;
    }
    let _ = pkt_idx; // suppress warning
    pcap
}

fn push_pkt(buf: &mut Vec<u8>, ts_sec: u32, ts_usec: u32, pkt: &[u8]) {
    buf.extend_from_slice(&ts_sec.to_le_bytes());
    buf.extend_from_slice(&ts_usec.to_le_bytes());
    buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
    buf.extend_from_slice(pkt);
}

fn write_mixed_pcap(n_rounds: usize) -> NamedTempFile {
    let pcap = build_mixed_pcap(n_rounds);
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();
    tmp
}

// ---------------------------------------------------------------------------
// Helpers for running dsct read
// ---------------------------------------------------------------------------

fn dsct_read_stdout(path: &str, extra_args: &[&str]) -> Vec<u8> {
    let mut cmd = Command::cargo_bin("dsct").unwrap();
    cmd.arg("read").arg(path);
    for arg in extra_args {
        cmd.arg(arg);
    }
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "dsct read failed (args={extra_args:?}): {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out.stdout
}

// ---------------------------------------------------------------------------
// Equivalence tests: parallel must produce byte-identical output to sequential
// ---------------------------------------------------------------------------

/// Test that `--threads 4` and `--threads 1` produce the same output for a
/// given filter.
fn assert_parallel_equals_sequential(path: &str, filter: &str) {
    let seq = dsct_read_stdout(path, &["-f", filter, "--no-limit", "--threads", "1"]);
    let par = dsct_read_stdout(path, &["-f", filter, "--no-limit", "--threads", "4"]);
    assert_eq!(
        seq, par,
        "parallel output differs from sequential for filter {filter:?}"
    );
}

#[test]
fn parallel_icmp_filter_equals_sequential() {
    let tmp = write_mixed_pcap(200); // 1200 packets
    let path = tmp.path().to_str().unwrap();
    assert_parallel_equals_sequential(path, "icmp");
    assert_parallel_equals_sequential(path, "icmp AND ipv4.src = '10.0.0.1'");
}

/// UDP, TCP and IPv4 filters may match packets carrying cross-packet state
/// (TCP stream IDs, UDP tunnels with TCP inside, IPFIX templates), so they
/// fall back to the sequential path and still equal `--threads 1`.
#[test]
fn fallback_udp_tcp_ipv4_filters_equal_sequential() {
    let tmp = write_mixed_pcap(200);
    let path = tmp.path().to_str().unwrap();
    assert_parallel_equals_sequential(path, "udp");
    assert_parallel_equals_sequential(path, "tcp.dst_port > 1024");
    assert_parallel_equals_sequential(path, "ipv4.src = '10.0.0.1'");
}

// ---------------------------------------------------------------------------
// Fallback correctness: unsafe filter goes through sequential path
// ---------------------------------------------------------------------------

/// `--threads 4` with an HTTP or DNS filter must succeed and equal
/// `--threads 1` (both go through the sequential path since these protocols
/// are not parallel-safe).
#[test]
fn fallback_http_filter_succeeds_and_equals_sequential() {
    let tmp = write_mixed_pcap(100);
    let path = tmp.path().to_str().unwrap();
    let seq = dsct_read_stdout(path, &["-f", "http", "--no-limit", "--threads", "1"]);
    let par = dsct_read_stdout(path, &["-f", "http", "--no-limit", "--threads", "4"]);
    assert_eq!(seq, par, "fallback http output should equal sequential");
}

#[test]
fn fallback_dns_filter_succeeds_and_equals_sequential() {
    let tmp = write_mixed_pcap(100);
    let path = tmp.path().to_str().unwrap();
    let seq = dsct_read_stdout(path, &["-f", "dns", "--no-limit", "--threads", "1"]);
    let par = dsct_read_stdout(path, &["-f", "dns", "--no-limit", "--threads", "4"]);
    assert_eq!(seq, par, "fallback dns output should equal sequential");
}

/// Two TCP flows: `first` packets of flow A followed by `second` packets of
/// flow B, all ACK-only segments.
fn write_two_flow_tcp_pcap(first: usize, second: usize) -> NamedTempFile {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
    for i in 0..first {
        push_pkt(
            &mut pcap,
            i as u32,
            0,
            &tcp_pkt(1, 2, 1111, 2000, 0x10, i as u32),
        );
    }
    for i in 0..second {
        let ts = (first + i) as u32;
        push_pkt(&mut pcap, ts, 0, &tcp_pkt(1, 2, 2222, 3000, 0x10, i as u32));
    }
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();
    tmp
}

/// `tcp.stream_id` is assigned in encounter order across the whole capture,
/// so a worker that only sees flow B must not number it as the first stream.
/// A TCP filter therefore has to be evaluated sequentially.
#[test]
fn tcp_filter_with_several_flows_equals_sequential() {
    // Flow B spans several reader batches (256 packets each) on its own.
    let tmp = write_two_flow_tcp_pcap(300, 500);
    let path = tmp.path().to_str().unwrap();
    assert_parallel_equals_sequential(path, "tcp.dst_port > 1024");
    assert_parallel_equals_sequential(path, "ipv4.src = '10.0.0.1'");
}

// ---------------------------------------------------------------------------
// Order/limit interplay
// ---------------------------------------------------------------------------

#[test]
fn parallel_count_yields_first_n_matches() {
    let tmp = write_mixed_pcap(200);
    let path = tmp.path().to_str().unwrap();
    // Both should give exactly the first 10 ICMP matches
    let seq = dsct_read_stdout(path, &["-f", "icmp", "--count", "10", "--threads", "1"]);
    let par = dsct_read_stdout(path, &["-f", "icmp", "--count", "10", "--threads", "4"]);
    assert_eq!(
        seq, par,
        "count-limited parallel output differs from sequential"
    );
    let lines: Vec<&[u8]> = seq
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .collect();
    assert_eq!(lines.len(), 10, "expected exactly 10 lines");
}

#[test]
fn parallel_offset_skips_n_matches() {
    let tmp = write_mixed_pcap(200);
    let path = tmp.path().to_str().unwrap();
    let seq = dsct_read_stdout(
        path,
        &[
            "-f",
            "icmp",
            "--offset",
            "5",
            "--no-limit",
            "--threads",
            "1",
        ],
    );
    let par = dsct_read_stdout(
        path,
        &[
            "-f",
            "icmp",
            "--offset",
            "5",
            "--no-limit",
            "--threads",
            "4",
        ],
    );
    assert_eq!(seq, par, "offset parallel output differs from sequential");
}

#[test]
fn parallel_sample_rate_combined_offset_count() {
    let tmp = write_mixed_pcap(400);
    let path = tmp.path().to_str().unwrap();
    // sample every 3rd, offset 2, count 5
    let seq = dsct_read_stdout(
        path,
        &[
            "-f",
            "icmp",
            "-s",
            "3",
            "--offset",
            "2",
            "--count",
            "5",
            "--threads",
            "1",
        ],
    );
    let par = dsct_read_stdout(
        path,
        &[
            "-f",
            "icmp",
            "-s",
            "3",
            "--offset",
            "2",
            "--count",
            "5",
            "--threads",
            "4",
        ],
    );
    assert_eq!(
        seq, par,
        "combined sample/offset/count parallel output differs"
    );
}

// ---------------------------------------------------------------------------
// Error cases
// ---------------------------------------------------------------------------

#[test]
fn parallel_progress_reports_total_processed_packets() {
    // --progress must report packets_processed counting ALL packets read
    // (like the sequential path), not just filter-matching ones.
    // 400 rounds = 2400 packets, 400 of which are ICMP matches.
    let tmp = write_mixed_pcap(400);
    let path = tmp.path().to_str().unwrap();
    let out = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "read",
            path,
            "-f",
            "icmp",
            "--no-limit",
            "--threads",
            "4",
            "--progress",
            "500",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());

    let stderr = String::from_utf8_lossy(&out.stderr);
    let processed: Vec<u64> = stderr
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter_map(|v| v.pointer("/progress/packets_processed")?.as_u64())
        .collect();
    assert!(
        !processed.is_empty(),
        "expected at least one progress report on stderr, got: {stderr}"
    );
    let max = processed.iter().copied().max().unwrap();
    // Only 400 packets match; reaching >= 1500 proves the count covers all
    // processed packets rather than matches only.
    assert!(
        max >= 1500,
        "packets_processed must count all packets (got max {max})"
    );
}

#[test]
fn invalid_decode_as_on_parallel_path_exits_with_code_2() {
    // --decode-as must be validated even on the parallel path; a silent
    // empty-output success (exit 0) would violate the structured-error
    // contract.
    let tmp = write_mixed_pcap(10);
    let path = tmp.path().to_str().unwrap();
    let out = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "read",
            path,
            "-f",
            "icmp",
            "--threads",
            "4",
            "--decode-as",
            "invalid_format",
        ])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit code 2 for invalid --decode-as on parallel path"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).expect("stderr must be JSON");
    assert!(
        v.get("error").is_some(),
        "stderr must contain an 'error' key"
    );
}

#[test]
fn threads_zero_exits_with_code_2() {
    let tmp = write_mixed_pcap(10);
    let path = tmp.path().to_str().unwrap();
    let out = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", path, "-f", "udp", "--threads", "0"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit code 2 for --threads 0"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).expect("stderr must be JSON");
    assert!(
        v.get("error").is_some(),
        "stderr must contain an 'error' key"
    );
}

#[test]
fn dsct_threads_env_unparsable_exits_with_code_2() {
    let tmp = write_mixed_pcap(10);
    let path = tmp.path().to_str().unwrap();
    let out = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", path, "-f", "udp"])
        .env("DSCT_THREADS", "abc")
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "expected exit code 2 for DSCT_THREADS=abc: stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    let v: serde_json::Value = serde_json::from_str(stderr.trim()).expect("stderr must be JSON");
    assert!(v.get("error").is_some());
}

#[test]
fn dsct_threads_env_equals_flag() {
    let tmp = write_mixed_pcap(200);
    let path = tmp.path().to_str().unwrap();
    let via_flag = dsct_read_stdout(path, &["-f", "icmp", "--no-limit", "--threads", "4"]);
    // Use DSCT_THREADS env without --threads flag
    let mut cmd = Command::cargo_bin("dsct").unwrap();
    cmd.arg("read")
        .arg(path)
        .arg("-f")
        .arg("icmp")
        .arg("--no-limit");
    cmd.env("DSCT_THREADS", "4");
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "DSCT_THREADS=4 should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        via_flag, out.stdout,
        "DSCT_THREADS=4 must equal --threads 4"
    );
}

// ---------------------------------------------------------------------------
// Stdin still streams sequentially
// ---------------------------------------------------------------------------

#[test]
fn stdin_with_threads_flag_succeeds_sequentially() {
    let pcap = build_mixed_pcap(20);
    // Run with file to get expected output
    let tmp = write_mixed_pcap(20);
    let path = tmp.path().to_str().unwrap();
    let file_out = dsct_read_stdout(path, &["-f", "udp", "--no-limit", "--threads", "4"]);

    // Run via stdin
    let mut cmd = Command::cargo_bin("dsct").unwrap();
    cmd.args(["read", "-", "-f", "udp", "--no-limit", "--threads", "4"]);
    cmd.write_stdin(pcap);
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "stdin + --threads should succeed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        file_out, out.stdout,
        "stdin output must equal file output for --threads 4"
    );
}
