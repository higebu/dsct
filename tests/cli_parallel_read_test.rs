//! Integration tests for `dsct read --threads` (parallel filter evaluation).
//!
//! These tests verify that the parallel path produces byte-identical output to
//! the sequential path, that packets using cross-packet state are dissected
//! in capture order, and
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
/// (TCP stream IDs, UDP tunnels with TCP inside, IPFIX templates); those
/// packets are dissected in capture order, so the output equals `--threads 1`.
#[test]
fn udp_tcp_ipv4_filters_equal_sequential() {
    let tmp = write_mixed_pcap(200);
    let path = tmp.path().to_str().unwrap();
    assert_parallel_equals_sequential(path, "udp");
    assert_parallel_equals_sequential(path, "tcp.dst_port > 1024");
    assert_parallel_equals_sequential(path, "ipv4.src = '10.0.0.1'");
}

// ---------------------------------------------------------------------------
// Upper-layer filters
// ---------------------------------------------------------------------------

/// `--threads 4` with an HTTP or DNS filter must succeed and equal
/// `--threads 1`.
#[test]
fn http_filter_succeeds_and_equals_sequential() {
    let tmp = write_mixed_pcap(100);
    let path = tmp.path().to_str().unwrap();
    let seq = dsct_read_stdout(path, &["-f", "http", "--no-limit", "--threads", "1"]);
    let par = dsct_read_stdout(path, &["-f", "http", "--no-limit", "--threads", "4"]);
    assert_eq!(seq, par, "http output should equal sequential");
}

#[test]
fn dns_filter_succeeds_and_equals_sequential() {
    let tmp = write_mixed_pcap(100);
    let path = tmp.path().to_str().unwrap();
    let seq = dsct_read_stdout(path, &["-f", "dns", "--no-limit", "--threads", "1"]);
    let par = dsct_read_stdout(path, &["-f", "dns", "--no-limit", "--threads", "4"]);
    assert_eq!(seq, par, "dns output should equal sequential");
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

/// Packets dropped by `--packet-number` still count as processed, as on the
/// sequential path.
#[test]
fn parallel_progress_counts_packets_dropped_by_packet_number() {
    let tmp = write_mixed_pcap(400); // 2400 packets
    let path = tmp.path().to_str().unwrap();
    let max_processed = |threads: &str| {
        let out = Command::cargo_bin("dsct")
            .unwrap()
            .args([
                "read",
                path,
                "-f",
                "udp",
                "--packet-number",
                "2000-2010",
                "--threads",
                threads,
                "--progress",
                "500",
            ])
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8_lossy(&out.stderr)
            .lines()
            .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .filter_map(|v| v.pointer("/progress/packets_processed")?.as_u64())
            .max()
    };
    assert_eq!(max_processed("1"), Some(2000));
    let parallel = max_processed("4").expect("parallel run must report progress");
    assert!(
        parallel >= 1500,
        "packets dropped by --packet-number must be counted (got {parallel})"
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

// ---------------------------------------------------------------------------
// Cross-packet state: optimistic parallel dissection, stateful packets in order
// ---------------------------------------------------------------------------

/// One IPv4 fragment (Ethernet + IPv4) carrying `payload`.
///
/// `offset_units` is the fragment offset in 8-byte units and `more` sets the
/// MF flag (RFC 791, Section 3.1).
/// <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
fn ipv4_fragment(protocol: u8, id: u16, offset_units: u16, more: bool, payload: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 34];
    p[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    p[6..12].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    p[12..14].copy_from_slice(&[0x08, 0x00]);
    p[14] = 0x45;
    p[16..18].copy_from_slice(&(20 + payload.len() as u16).to_be_bytes());
    p[18..20].copy_from_slice(&id.to_be_bytes());
    let flags_frag = offset_units | if more { 0x2000 } else { 0 };
    p[20..22].copy_from_slice(&flags_frag.to_be_bytes());
    p[22] = 0x40;
    p[23] = protocol;
    p[26..30].copy_from_slice(&[10, 0, 0, 7]);
    p[30..34].copy_from_slice(&[10, 0, 0, 8]);
    p.extend_from_slice(payload);
    p
}

/// ICMP Echo Request (RFC 792) with a 32-byte payload, split into a 24-byte
/// and a 16-byte IPv4 fragment.
fn fragmented_icmp(id: u16) -> [Vec<u8>; 2] {
    let mut icmp = vec![8u8, 0, 0, 0, 0, 1, 0, 1];
    icmp.extend((0..32).map(|i| i as u8));
    [
        ipv4_fragment(1, id, 0, true, &icmp[..24]),
        ipv4_fragment(1, id, 3, false, &icmp[24..]),
    ]
}

/// UDP datagram (RFC 768) to port 9999 with a 40-byte payload, split into
/// two 24-byte IPv4 fragments.
fn fragmented_udp(id: u16) -> [Vec<u8>; 2] {
    let mut udp = Vec::new();
    udp.extend_from_slice(&4000u16.to_be_bytes());
    udp.extend_from_slice(&9999u16.to_be_bytes());
    udp.extend_from_slice(&48u16.to_be_bytes());
    udp.extend_from_slice(&0u16.to_be_bytes());
    udp.extend((0..40).map(|i| i as u8));
    [
        ipv4_fragment(17, id, 0, true, &udp[..24]),
        ipv4_fragment(17, id, 3, false, &udp[24..]),
    ]
}

fn pcap_header() -> Vec<u8> {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
    pcap
}

fn write_pcap(packets: &[Vec<u8>]) -> NamedTempFile {
    let mut pcap = pcap_header();
    for (i, pkt) in packets.iter().enumerate() {
        push_pkt(&mut pcap, i as u32, 0, pkt);
    }
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();
    tmp
}

/// Number (1-based) of the first fragment in [`write_fragmented_pcap`].
const FIRST_FRAGMENT_NUMBER: u64 = 256;

/// 255 plain UDP / ICMP packets, then an ICMP Echo Request whose two
/// fragments straddle the 256-packet reader batch boundary, more plain
/// packets, a fragmented UDP datagram, and a plain tail.
fn write_fragmented_pcap() -> NamedTempFile {
    let mut packets: Vec<Vec<u8>> = Vec::new();
    let plain = |i: usize| -> Vec<u8> {
        if i.is_multiple_of(3) {
            icmp_echo_pkt(1, 2, i as u16).to_vec()
        } else {
            udp_pkt(1, 2, 4096, 4097).to_vec()
        }
    };
    for i in 0..(FIRST_FRAGMENT_NUMBER as usize - 1) {
        packets.push(plain(i));
    }
    packets.extend(fragmented_icmp(0x1234));
    for i in 0..300 {
        packets.push(plain(i));
    }
    let [first, last] = fragmented_udp(0x5678);
    packets.push(first);
    for i in 0..10 {
        packets.push(plain(i));
    }
    packets.push(last);
    for i in 0..300 {
        packets.push(plain(i));
    }
    write_pcap(&packets)
}

/// Fragments are reassembled (packet-dissector's `ip-reassembly` feature is
/// enabled), so the last fragment of each datagram carries the upper layer.
#[cfg(feature = "ip-reassembly")]
#[test]
fn fragmented_capture_is_reassembled() {
    let tmp = write_fragmented_pcap();
    let path = tmp.path().to_str().unwrap();
    let out = dsct_read_stdout(
        path,
        &["-f", "udp.dst_port = 9999", "--no-limit", "--threads", "1"],
    );
    let records: Vec<serde_json::Value> = out
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| serde_json::from_slice(l).unwrap())
        .collect();
    assert_eq!(records.len(), 1, "expected the reassembled UDP datagram");
}

#[test]
fn fragmented_capture_equals_sequential() {
    let tmp = write_fragmented_pcap();
    let path = tmp.path().to_str().unwrap();
    assert_parallel_equals_sequential(path, "icmp");
    assert_parallel_equals_sequential(path, "udp");
    assert_parallel_equals_sequential(path, "ipv4");
}

/// `--sample-rate` / `--offset` / `--count` apply to one ordered match stream
/// mixing parallel results and packets dissected in order.
#[test]
fn limits_with_stateful_packets_equal_sequential() {
    let tmp = write_fragmented_pcap();
    let path = tmp.path().to_str().unwrap();
    for args in [
        &["--offset", "200", "--count", "100"][..],
        &["--sample-rate", "3", "--offset", "50", "--count", "150"][..],
        &["--count", "255"][..],
        &["--count", "256"][..],
        &["--packet-number", "200-300,700-900"][..],
    ] {
        let mut seq_args = vec!["-f", "ipv4", "--threads", "1"];
        seq_args.extend_from_slice(args);
        let mut par_args = vec!["-f", "ipv4", "--threads", "4"];
        par_args.extend_from_slice(args);
        assert_eq!(
            dsct_read_stdout(path, &seq_args),
            dsct_read_stdout(path, &par_args),
            "parallel output differs from sequential for {args:?}"
        );
    }
}

/// A filter on cross-packet state (`tcp.stream_id`) sees the stream IDs of
/// the sequential path.
#[test]
fn tcp_stream_id_filter_equals_sequential() {
    let tmp = write_two_flow_tcp_pcap(300, 500);
    let path = tmp.path().to_str().unwrap();
    let seq = dsct_read_stdout(
        path,
        &["-f", "tcp.stream_id = 1", "--no-limit", "--threads", "1"],
    );
    assert!(!seq.is_empty(), "flow B must have stream_id 1");
    assert_parallel_equals_sequential(path, "tcp.stream_id = 1");
}

/// Run the parallel engine directly and report how many packets it
/// dissected again in capture order.
fn parallel_outcome(path: &std::path::Path, filter: &str) -> (Vec<u8>, u64) {
    let mut out = Vec::new();
    let filter = dsct::filter_expr::FilterExpr::parse(filter)
        .unwrap()
        .unwrap();
    let outcome = dsct::parallel_read::run(
        &dsct::parallel_read::ParallelReadOptions {
            path,
            filter: &filter,
            decode_as_args: &[],
            threads: 4,
            sample_rate: 1,
            offset: 0,
            count: None,
            pn_filter: None,
            field_config: None,
            raw_bytes: false,
            progress_interval: 0,
        },
        &packet_dissector::registry::DissectorRegistry::default(),
        &mut out,
        &mut |_, _| {},
        &mut |_, _| {},
    )
    .unwrap();
    (out, outcome.in_order_packets)
}

#[test]
fn stateless_capture_stays_parallel() {
    let packets: Vec<Vec<u8>> = (0..2000)
        .map(|i| {
            if i % 2 == 0 {
                udp_pkt(1, 2, 4096, 4097).to_vec()
            } else {
                icmp_echo_pkt(1, 2, i as u16).to_vec()
            }
        })
        .collect();
    let tmp = write_pcap(&packets);
    let (out, in_order) = parallel_outcome(tmp.path(), "udp");
    assert_eq!(in_order, 0, "no packet uses cross-packet state");
    assert_eq!(
        out.split(|&b| b == b'\n').filter(|l| !l.is_empty()).count(),
        1000
    );
}

/// Only the packets that use cross-packet state are dissected in order;
/// the rest keeps its parallel result.
#[test]
fn only_stateful_packets_are_dissected_in_order() {
    // Two fragmented datagrams of two fragments each.
    let tmp = write_fragmented_pcap();
    let (_, in_order) = parallel_outcome(tmp.path(), "icmp");
    assert_eq!(in_order, 4);

    // Two TCP segments per round of six packets.
    let tmp = write_mixed_pcap(100);
    let (out, in_order) = parallel_outcome(tmp.path(), "icmp");
    assert_eq!(in_order, 200);
    assert_eq!(
        out.split(|&b| b == b'\n').filter(|l| !l.is_empty()).count(),
        100
    );
}

/// TCP capture whose first segment comes after `udp` plain UDP packets.
fn udp_then_tcp_packets(udp: usize, tcp: usize) -> Vec<Vec<u8>> {
    let mut packets: Vec<Vec<u8>> = (0..udp)
        .map(|_| udp_pkt(1, 2, 4096, 4097).to_vec())
        .collect();
    packets.extend((0..tcp).map(|i| tcp_pkt(1, 2, 1111, 2000, 0x10, i as u32)));
    packets
}

/// The capture is read once: a FIFO (or `<(...)`) works, also when packets
/// are dissected again in capture order.
#[cfg(unix)]
#[test]
fn fifo_input_with_stateful_packets_equals_sequential() {
    let tmp = write_pcap(&udp_then_tcp_packets(600, 600));
    let path = tmp.path().to_str().unwrap();
    let expected = dsct_read_stdout(path, &["-f", "tcp", "--no-limit", "--threads", "1"]);
    assert!(!expected.is_empty());

    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("capture.fifo");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRWXU).unwrap();
    let data = std::fs::read(tmp.path()).unwrap();
    let writer_path = fifo.clone();
    let feeder = std::thread::spawn(move || {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .open(writer_path)
            .unwrap();
        // The reader may stop early on error; ignore a broken pipe.
        let _ = f.write_all(&data);
    });
    let out = dsct_read_stdout(
        fifo.to_str().unwrap(),
        &["-f", "tcp", "--no-limit", "--threads", "4"],
    );
    feeder.join().unwrap();
    assert_eq!(out, expected);
}

/// A capture whose last record is truncated: every packet before it is
/// written, then the read error is reported, as with `--threads 1` — both
/// for parallel results and for packets dissected in order.
#[test]
fn truncated_capture_equals_sequential() {
    for (packets, filter) in [
        (udp_then_tcp_packets(2010, 0), "udp"),
        (udp_then_tcp_packets(10, 2000), "tcp"),
    ] {
        let tmp = write_pcap(&packets);
        let mut data = std::fs::read(tmp.path()).unwrap();
        data.truncate(data.len() - 10);
        let mut truncated = NamedTempFile::with_suffix(".pcap").unwrap();
        truncated.write_all(&data).unwrap();
        let path = truncated.path().to_str().unwrap();

        let run = |threads: &str| {
            Command::cargo_bin("dsct")
                .unwrap()
                .args([
                    "read",
                    path,
                    "-f",
                    filter,
                    "--no-limit",
                    "--threads",
                    threads,
                ])
                .output()
                .unwrap()
        };
        let seq = run("1");
        let par = run("4");
        assert_eq!(seq.status.code(), par.status.code(), "{filter}");
        assert_eq!(seq.stderr, par.stderr, "{filter}");
        assert_eq!(
            String::from_utf8_lossy(&par.stdout).lines().count(),
            if filter == "udp" { 2009 } else { 1999 },
            "every complete {filter} packet is written before the error"
        );
        assert_eq!(seq.stdout, par.stdout, "{filter}");
    }
}
