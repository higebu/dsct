//! A closed stdout (`dsct ... | head`) must end every command quietly.
//!
//! Each test hands the child a pipe whose read end is already closed, so the
//! first write to stdout fails with `EPIPE`. dsct must then stop and exit 0
//! without printing anything to stderr — no panic and no error JSON.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use tempfile::NamedTempFile;

/// Build a pcap of `n` Ethernet/IPv4 frames carrying `l4` with IP protocol
/// `proto`.
fn build_pcap(n: usize, proto: u8, l4: &[u8]) -> Vec<u8> {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet

    let mut frame = vec![
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
    ];
    let total_len = (20 + l4.len()) as u16;
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x40, proto, 0x00, 0x00]);
    frame.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    frame.extend_from_slice(l4);

    for i in 0..n {
        pcap.extend_from_slice(&(i as u32).to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&frame);
    }
    pcap
}

/// UDP 4096 -> 4097, no payload.
fn udp_pcap(n: usize) -> NamedTempFile {
    write_tmp(&build_pcap(
        n,
        17,
        &[0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00],
    ))
}

/// ICMP echo request, so `-f icmp --threads` takes the parallel path.
fn icmp_pcap(n: usize) -> NamedTempFile {
    write_tmp(&build_pcap(
        n,
        1,
        &[0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01],
    ))
}

fn write_tmp(bytes: &[u8]) -> NamedTempFile {
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(bytes).unwrap();
    tmp
}

/// Run dsct with `args` and a stdout pipe that has no reader, optionally
/// feeding `stdin`, and assert a silent exit 0.
fn assert_quiet_exit_on_closed_stdout(args: &[&str], stdin: Option<&Path>) {
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_dsct"));
    cmd.args(args).stdout(writer).stderr(Stdio::piped());
    match stdin {
        Some(path) => cmd.stdin(std::fs::File::open(path).unwrap()),
        None => cmd.stdin(Stdio::null()),
    };
    let output = cmd.output().unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{args:?}: stderr: {stderr}");
    assert!(stderr.is_empty(), "{args:?}: stderr: {stderr}");
}

#[test]
fn read_sequential() {
    let pcap = udp_pcap(10);
    assert_quiet_exit_on_closed_stdout(&["read", pcap.path().to_str().unwrap()], None);
}

#[test]
fn read_with_truncation_warning_pending() {
    // More than the default 1000-packet limit: the truncation warning that
    // would follow the output must not be printed either.
    let pcap = udp_pcap(1500);
    assert_quiet_exit_on_closed_stdout(&["read", pcap.path().to_str().unwrap()], None);
}

#[test]
fn read_stdin() {
    let pcap = udp_pcap(10);
    assert_quiet_exit_on_closed_stdout(&["read", "-"], Some(pcap.path()));
}

#[test]
fn read_parallel() {
    let pcap = icmp_pcap(10);
    assert_quiet_exit_on_closed_stdout(
        &[
            "read",
            "-f",
            "icmp",
            "--threads",
            "2",
            pcap.path().to_str().unwrap(),
        ],
        None,
    );
}

#[test]
fn stats() {
    let pcap = udp_pcap(10);
    assert_quiet_exit_on_closed_stdout(&["stats", pcap.path().to_str().unwrap()], None);
}

#[test]
fn list() {
    assert_quiet_exit_on_closed_stdout(&["list"], None);
}

#[test]
fn fields() {
    assert_quiet_exit_on_closed_stdout(&["fields"], None);
    assert_quiet_exit_on_closed_stdout(&["fields", "DNS"], None);
}

#[test]
fn schema() {
    assert_quiet_exit_on_closed_stdout(&["schema"], None);
    assert_quiet_exit_on_closed_stdout(&["schema", "stats"], None);
}

#[test]
fn version() {
    assert_quiet_exit_on_closed_stdout(&["version"], None);
}

#[cfg(feature = "sqlite")]
#[test]
fn index_and_sql() {
    let pcap = udp_pcap(10);
    let dir = tempfile::TempDir::new().unwrap();
    let db = dir.path().join("capture.db");
    let pcap = pcap.path().to_str().unwrap();
    let db = db.to_str().unwrap();

    assert_quiet_exit_on_closed_stdout(&["index", pcap, "--db", db], None);
    assert_quiet_exit_on_closed_stdout(
        &["sql", pcap, "--db", db, "SELECT number FROM packets"],
        None,
    );
    assert_quiet_exit_on_closed_stdout(&["sql", pcap, "--db", db, "--schema"], None);
}
