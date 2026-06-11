//! Integration tests for the parallel `dsct read` path.
//!
//! The parallel scan is engaged for file input when `--threads > 1` (or the
//! `DSCT_THREADS` environment variable) and the `--filter` cannot match a
//! TCP-reassembled packet (e.g. `icmp`).  These tests assert that the parallel
//! output is byte-for-byte identical to the sequential (`--threads 1`) output,
//! which is the JSONL CLI contract.

use assert_cmd::Command;
use tempfile::NamedTempFile;

use std::io::Write;

/// Append a pcap global header (little-endian, Ethernet link type).
fn pcap_header() -> Vec<u8> {
    let mut h = Vec::new();
    h.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    h.extend_from_slice(&2u16.to_le_bytes());
    h.extend_from_slice(&4u16.to_le_bytes());
    h.extend_from_slice(&0i32.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes());
    h.extend_from_slice(&65535u32.to_le_bytes());
    h.extend_from_slice(&1u32.to_le_bytes());
    h
}

/// Append one pcap record (`ts_sec` increments per packet for distinct output).
fn push_record(pcap: &mut Vec<u8>, ts_sec: u32, pkt: &[u8]) {
    pcap.extend_from_slice(&ts_sec.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
    pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
    pcap.extend_from_slice(pkt);
}

/// Ethernet + IPv4 + ICMP echo request with a per-packet sequence number, so
/// each packet's dissected output differs and ordering is observable.
fn icmp_packet(seq: u16) -> Vec<u8> {
    let mut pkt = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst mac
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac
        0x08, 0x00, // ethertype IPv4
        0x45, 0x00, 0x00, 0x1c, // version/ihl, dscp, total length (28)
        0x00, 0x00, 0x00, 0x00, // id, flags/frag
        0x40, 0x01, 0x00, 0x00, // ttl=64, protocol=1 (ICMP), checksum
        0x0a, 0x00, 0x00, 0x01, // src 10.0.0.1
        0x0a, 0x00, 0x00, 0x02, // dst 10.0.0.2
    ];
    // ICMP echo request: type 8, code 0, checksum, id=1, seq
    pkt.extend_from_slice(&[0x08, 0x00, 0x00, 0x00, 0x00, 0x01]);
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt
}

/// Ethernet + IPv4 + UDP packet (so `icmp` filters are selective).
fn udp_packet() -> Vec<u8> {
    vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x02, 0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
    ]
}

/// Build a pcap interleaving `icmp_count` ICMP packets with UDP filler.
fn build_mixed_pcap(icmp_count: usize) -> Vec<u8> {
    let mut pcap = pcap_header();
    let mut ts = 0u32;
    let mut seq = 0u16;
    for _ in 0..icmp_count {
        push_record(&mut pcap, ts, &icmp_packet(seq));
        ts += 1;
        seq = seq.wrapping_add(1);
        // One UDP filler packet between ICMP packets.
        push_record(&mut pcap, ts, &udp_packet());
        ts += 1;
    }
    pcap
}

fn write_pcap(bytes: &[u8]) -> NamedTempFile {
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(bytes).unwrap();
    tmp.flush().unwrap();
    tmp
}

/// Run `dsct read` with the given extra args and return stdout.
fn read_stdout(path: &str, extra: &[&str]) -> Vec<u8> {
    let mut args = vec!["read", path];
    args.extend_from_slice(extra);
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(&args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "dsct read failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

#[test]
fn parallel_icmp_matches_sequential_output() {
    let pcap = build_mixed_pcap(800);
    let tmp = write_pcap(&pcap);
    let path = tmp.path().to_str().unwrap();

    let sequential = read_stdout(path, &["--filter", "icmp", "--threads", "1", "--no-limit"]);
    let parallel = read_stdout(path, &["--filter", "icmp", "--threads", "4", "--no-limit"]);

    assert_eq!(
        sequential, parallel,
        "parallel output must be byte-identical to sequential"
    );
    // Sanity: 800 ICMP packets matched.
    let line_count = parallel.iter().filter(|&&b| b == b'\n').count();
    assert_eq!(line_count, 800);
}

#[test]
fn parallel_respects_offset_and_count() {
    let pcap = build_mixed_pcap(500);
    let tmp = write_pcap(&pcap);
    let path = tmp.path().to_str().unwrap();

    let sequential = read_stdout(
        path,
        &[
            "--filter",
            "icmp",
            "--threads",
            "1",
            "--offset",
            "100",
            "--count",
            "50",
        ],
    );
    let parallel = read_stdout(
        path,
        &[
            "--filter",
            "icmp",
            "--threads",
            "8",
            "--offset",
            "100",
            "--count",
            "50",
        ],
    );
    assert_eq!(sequential, parallel);
    assert_eq!(parallel.iter().filter(|&&b| b == b'\n').count(), 50);
}

#[test]
fn parallel_respects_sample_rate() {
    let pcap = build_mixed_pcap(300);
    let tmp = write_pcap(&pcap);
    let path = tmp.path().to_str().unwrap();

    let sequential = read_stdout(
        path,
        &[
            "--filter",
            "icmp",
            "--threads",
            "1",
            "--sample-rate",
            "7",
            "--no-limit",
        ],
    );
    let parallel = read_stdout(
        path,
        &[
            "--filter",
            "icmp",
            "--threads",
            "6",
            "--sample-rate",
            "7",
            "--no-limit",
        ],
    );
    assert_eq!(sequential, parallel);
}

#[test]
fn parallel_with_packet_number_filter() {
    let pcap = build_mixed_pcap(400);
    let tmp = write_pcap(&pcap);
    let path = tmp.path().to_str().unwrap();

    let sequential = read_stdout(
        path,
        &[
            "--filter",
            "icmp",
            "--packet-number",
            "1-200",
            "--threads",
            "1",
            "--no-limit",
        ],
    );
    let parallel = read_stdout(
        path,
        &[
            "--filter",
            "icmp",
            "--packet-number",
            "1-200",
            "--threads",
            "4",
            "--no-limit",
        ],
    );
    assert_eq!(sequential, parallel);
}

#[test]
fn reassembly_sensitive_filter_falls_back_to_sequential() {
    // `udp` can match TCP-adjacent traffic semantics differently under
    // reassembly, so the parallel path must not engage; output must still be
    // correct and identical regardless of the requested thread count.
    let pcap = build_mixed_pcap(300);
    let tmp = write_pcap(&pcap);
    let path = tmp.path().to_str().unwrap();

    let one = read_stdout(path, &["--filter", "udp", "--threads", "1", "--no-limit"]);
    let many = read_stdout(path, &["--filter", "udp", "--threads", "8", "--no-limit"]);
    assert_eq!(one, many);
    assert_eq!(many.iter().filter(|&&b| b == b'\n').count(), 300);
}

#[test]
fn dsct_threads_env_var_matches_flag() {
    let pcap = build_mixed_pcap(400);
    let tmp = write_pcap(&pcap);
    let path = tmp.path().to_str().unwrap();

    let via_flag = read_stdout(path, &["--filter", "icmp", "--threads", "4", "--no-limit"]);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .env("DSCT_THREADS", "4")
        .args(["read", path, "--filter", "icmp", "--no-limit"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(via_flag, output.stdout);
}
