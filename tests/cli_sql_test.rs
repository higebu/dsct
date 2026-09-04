//! CLI tests for `dsct index` and `dsct sql`.
//!
//! All captures are synthesized inline (no fixtures on disk).  Each test
//! writes its capture into a private temporary directory that is removed
//! together with it. The index database itself now lives in a per-user
//! cache directory rather than next to the capture (see
//! `sqlite::default_db_path`), so every `dsct` invocation here is routed
//! through [`dsct`]/[`sql`], which pin `DSCT_CACHE_DIR` to [`TEST_CACHE_DIR`]
//! — an isolated directory under the system temp dir — instead of letting
//! it fall through to the real `$HOME/.cache/dsct` of whatever machine runs
//! the tests. Different captures never collide there (the cache file name
//! embeds a hash of the capture's canonicalised absolute path), so sharing
//! one directory across every test in this binary is safe.

#![cfg(feature = "sqlite")]

use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::LazyLock;

use assert_cmd::Command;
use serde_json::Value;
use tempfile::TempDir;

/// Shared, isolated `DSCT_CACHE_DIR` for every `dsct` invocation in this
/// test binary (see the module doc comment). Not explicitly cleaned up —
/// statics aren't dropped at process exit — but it lives under the system
/// temp directory, not a real user cache dir, so this is bounded to one
/// leftover directory per test-binary run rather than accumulating in
/// `$HOME/.cache/dsct`.
static TEST_CACHE_DIR: LazyLock<TempDir> = LazyLock::new(|| {
    tempfile::Builder::new()
        .prefix("dsct-cli-sql-test-cache-")
        .tempdir()
        .expect("failed to create shared test cache dir")
});

// ---------------------------------------------------------------------------
// Frame builders
// ---------------------------------------------------------------------------

fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&[0xff; 6]);
    f.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

fn ipv4(src: [u8; 4], dst: [u8; 4], protocol: u8, payload: &[u8]) -> Vec<u8> {
    let total_len = 20 + payload.len() as u16;
    let mut p = Vec::with_capacity(20 + payload.len());
    p.push(0x45);
    p.push(0x00);
    p.extend_from_slice(&total_len.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.push(64);
    p.push(protocol);
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

fn udp(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + payload.len());
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&(8 + payload.len() as u16).to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn tcp(src_port: u16, dst_port: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(20 + payload.len());
    p.extend_from_slice(&src_port.to_be_bytes());
    p.extend_from_slice(&dst_port.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ack.to_be_bytes());
    p.push(0x50);
    p.push(flags);
    p.extend_from_slice(&0xffffu16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

/// VXLAN header (RFC 7348) with the I flag set and the given VNI.
fn vxlan(vni: u32, inner: &[u8]) -> Vec<u8> {
    let mut p = vec![0x08, 0x00, 0x00, 0x00];
    p.extend_from_slice(&vni.to_be_bytes()[1..]);
    p.push(0x00);
    p.extend_from_slice(inner);
    p
}

/// Minimal GRE header (RFC 2784) carrying `ethertype`.
fn gre(ethertype: u16, inner: &[u8]) -> Vec<u8> {
    let mut p = vec![0x00, 0x00];
    p.extend_from_slice(&ethertype.to_be_bytes());
    p.extend_from_slice(inner);
    p
}

/// Plain Ethernet / IPv4 / UDP frame (42 bytes) between 10.0.0.1 and 10.0.0.2.
fn plain_udp_frame() -> Vec<u8> {
    eth(
        0x0800,
        &ipv4([10, 0, 0, 1], [10, 0, 0, 2], 17, &udp(4096, 4097, &[])),
    )
}

/// Ethernet / IPv4 / UDP(4789) / VXLAN(VNI 100) / Ethernet / IPv4 / TCP SYN.
fn vxlan_frame() -> Vec<u8> {
    let inner = eth(
        0x0800,
        &ipv4(
            [10, 1, 0, 5],
            [10, 1, 0, 6],
            6,
            &tcp(1234, 80, 1000, 0, 0x02, &[]),
        ),
    );
    eth(
        0x0800,
        &ipv4(
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            17,
            &udp(40000, 4789, &vxlan(100, &inner)),
        ),
    )
}

/// Ethernet / IPv4 / GRE / IPv4 / UDP with a 5-byte payload.
fn gre_frame() -> Vec<u8> {
    let inner = ipv4([10, 2, 0, 1], [10, 2, 0, 2], 17, &udp(1111, 2222, b"hello"));
    eth(
        0x0800,
        &ipv4([172, 16, 0, 1], [172, 16, 0, 2], 47, &gre(0x0800, &inner)),
    )
}

/// TCP three-way handshake plus one data segment on 10.0.0.1:40000 <-> 10.0.0.2:8080.
fn tcp_stream_frames() -> Vec<Vec<u8>> {
    let c = [10, 0, 0, 1];
    let s = [10, 0, 0, 2];
    vec![
        eth(
            0x0800,
            &ipv4(c, s, 6, &tcp(40000, 8080, 1000, 0, 0x02, &[])),
        ),
        eth(
            0x0800,
            &ipv4(s, c, 6, &tcp(8080, 40000, 5000, 1001, 0x12, &[])),
        ),
        eth(
            0x0800,
            &ipv4(c, s, 6, &tcp(40000, 8080, 1001, 5001, 0x18, b"0123456789")),
        ),
    ]
}

/// DNS query for "example.com" over UDP/53.
fn dns_frame() -> Vec<u8> {
    let mut dns = vec![
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    dns.push(7);
    dns.extend_from_slice(b"example");
    dns.push(3);
    dns.extend_from_slice(b"com");
    dns.push(0);
    dns.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
    eth(
        0x0800,
        &ipv4([10, 0, 0, 1], [10, 0, 0, 53], 17, &udp(53000, 53, &dns)),
    )
}

fn build_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes());
    for (i, f) in frames.iter().enumerate() {
        pcap.extend_from_slice(&(i as u32).to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&(f.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(f.len() as u32).to_le_bytes());
        pcap.extend_from_slice(f);
    }
    pcap
}

/// Write a capture into a fresh temporary directory.
///
/// The file name embeds a per-process-unique counter: all tests share one
/// [`TEST_CACHE_DIR`], and cache-dir database file names are looked up by
/// capture file name prefix (see [`db_candidates`]), so two tests both
/// naming their capture e.g. `capture.pcap` would otherwise be
/// indistinguishable there even though they live in different capture
/// directories.
fn write_capture(frames: &[Vec<u8>]) -> (TempDir, PathBuf) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("capture-{n}.pcap"));
    std::fs::write(&path, build_pcap(frames)).unwrap();
    (dir, path)
}

/// Cache-dir database files dsct has built for `capture` (matched by file
/// name prefix + `.dsct.sqlite` suffix — see `sqlite::default_db_path`).
/// Normally 0 or 1; more would mean a hash collision or leftover state
/// from another test sharing [`TEST_CACHE_DIR`].
fn db_candidates(capture: &Path) -> Vec<PathBuf> {
    let prefix = format!("{}-", capture.file_name().unwrap().to_str().unwrap());
    std::fs::read_dir(TEST_CACHE_DIR.path())
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(&prefix) && n.ends_with(".dsct.sqlite"))
        })
        .collect()
}

/// Whether dsct has built a cache-dir database for `capture`.
fn db_exists_for(capture: &Path) -> bool {
    !db_candidates(capture).is_empty()
}

/// The cache-dir database file dsct built for `capture`. Panics unless
/// there is exactly one.
fn db_path_for(capture: &Path) -> PathBuf {
    let mut candidates = db_candidates(capture);
    assert_eq!(
        candidates.len(),
        1,
        "expected exactly one cache-dir db for {capture:?}, found {candidates:?}"
    );
    candidates.remove(0)
}

// ---------------------------------------------------------------------------
// Command helpers
// ---------------------------------------------------------------------------

fn dsct(args: &[&str]) -> Output {
    Command::cargo_bin("dsct")
        .unwrap()
        .args(args)
        .env("DSCT_CACHE_DIR", TEST_CACHE_DIR.path())
        .output()
        .unwrap()
}

fn sql(capture: &Path, query: &str) -> Output {
    dsct(&["sql", capture.to_str().unwrap(), query])
}

fn rows(output: &Output) -> Vec<Value> {
    assert!(
        output.status.success(),
        "dsct failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn stderr_json(output: &Output) -> Vec<Value> {
    String::from_utf8(output.stderr.clone())
        .unwrap()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

fn assert_invalid_arguments(output: &Output) {
    assert_eq!(output.status.code(), Some(2));
    let errs = stderr_json(output);
    let err = errs.last().expect("structured error on stderr");
    assert_eq!(err["error"]["code"], "invalid_arguments", "{err}");
    assert!(err["error"]["message"].is_string());
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn sql_matches_read_output_and_builds_cache_db() {
    let (_dir, cap) = write_capture(&[plain_udp_frame(), dns_frame(), gre_frame()]);

    let read = dsct(&["read", "--no-limit", cap.to_str().unwrap()]);
    let read_rows = rows(&read);

    let out = sql(&cap, "SELECT number, stack FROM packets ORDER BY number");
    let sql_rows = rows(&out);
    assert_eq!(sql_rows.len(), read_rows.len());
    for (a, b) in sql_rows.iter().zip(read_rows.iter()) {
        assert_eq!(a["number"], b["number"]);
        assert_eq!(a["stack"], b["stack"]);
    }
    assert!(db_exists_for(&cap), "cache-dir index should be created");
    // First build: no rebuild warning.
    assert!(
        stderr_json(&out)
            .iter()
            .all(|w| w["warning"]["code"] != "index_rebuilt")
    );
}

#[test]
fn second_query_reuses_index_and_changed_capture_rebuilds() {
    let (_dir, cap) = write_capture(&[plain_udp_frame()]);
    let first = rows(&sql(&cap, "SELECT COUNT(*) AS n FROM packets"));
    assert_eq!(first[0]["n"], 1);
    let mtime = std::fs::metadata(db_path_for(&cap))
        .unwrap()
        .modified()
        .unwrap();

    let second = sql(&cap, "SELECT COUNT(*) AS n FROM packets");
    assert_eq!(rows(&second)[0]["n"], 1);
    assert!(stderr_json(&second).is_empty(), "no warnings expected");
    assert_eq!(
        std::fs::metadata(db_path_for(&cap))
            .unwrap()
            .modified()
            .unwrap(),
        mtime,
        "index must not be rebuilt when fresh"
    );

    // Append a packet: size changes, so the index is stale.
    std::fs::write(&cap, build_pcap(&[plain_udp_frame(), plain_udp_frame()])).unwrap();
    let third = sql(&cap, "SELECT COUNT(*) AS n FROM packets");
    assert_eq!(rows(&third)[0]["n"], 2);
    let warnings = stderr_json(&third);
    assert!(
        warnings
            .iter()
            .any(|w| w["warning"]["code"] == "index_rebuilt"),
        "expected index_rebuilt warning, got {warnings:?}"
    );
}

#[test]
fn no_build_without_index_is_invalid_arguments() {
    let (_dir, cap) = write_capture(&[plain_udp_frame()]);
    let out = dsct(&["sql", "--no-build", cap.to_str().unwrap(), "SELECT 1"]);
    assert_invalid_arguments(&out);
    assert!(!db_exists_for(&cap));
}

#[test]
fn vxlan_inner_headers_have_depth_one() {
    let (_dir, cap) = write_capture(&[vxlan_frame()]);

    let ip = rows(&sql(
        &cap,
        "SELECT depth, \"src\", \"dst\" FROM ipv4 ORDER BY layer_index",
    ));
    assert_eq!(ip.len(), 2);
    assert_eq!(ip[0]["depth"], 0);
    assert_eq!(ip[0]["src"], "192.168.1.1");
    assert_eq!(ip[1]["depth"], 1);
    assert_eq!(ip[1]["src"], "10.1.0.5");
    assert_eq!(ip[1]["dst"], "10.1.0.6");

    let enc = rows(&sql(
        &cap,
        "SELECT carrier_protocol, carrier_layer_index FROM encapsulations WHERE depth = 1",
    ));
    assert_eq!(enc.len(), 1);
    assert_eq!(enc[0]["carrier_protocol"], "VXLAN");
    assert_eq!(enc[0]["carrier_layer_index"], 3);

    let tcp = rows(&sql(&cap, "SELECT depth, \"dst_port\", flow_id FROM tcp"));
    assert_eq!(tcp[0]["depth"], 1);
    assert_eq!(tcp[0]["dst_port"], 80);
    assert!(tcp[0]["flow_id"].is_number());

    let vni = rows(&sql(&cap, "SELECT \"vni\" FROM vxlan"));
    assert_eq!(vni[0]["vni"], 100);

    let pkt = rows(&sql(&cap, "SELECT stack, max_depth FROM packets"));
    assert_eq!(pkt[0]["stack"], "Ethernet:IPv4:UDP:VXLAN:Ethernet:IPv4:TCP");
    assert_eq!(pkt[0]["max_depth"], 1);
}

#[test]
fn gre_inner_udp_gets_its_own_flow() {
    let (_dir, cap) = write_capture(&[gre_frame()]);
    let udp_rows = rows(&sql(
        &cap,
        "SELECT depth, flow_id, direction, \"src_port\" FROM udp",
    ));
    assert_eq!(udp_rows.len(), 1);
    assert_eq!(udp_rows[0]["depth"], 1);
    assert_eq!(udp_rows[0]["flow_id"], 0);
    assert_eq!(udp_rows[0]["direction"], 0);
    assert_eq!(udp_rows[0]["src_port"], 1111);

    let flows = rows(&sql(
        &cap,
        "SELECT transport, depth, addr_a, port_a, addr_b, port_b, packets FROM flows",
    ));
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0]["transport"], "udp");
    assert_eq!(flows[0]["depth"], 1);
    assert_eq!(flows[0]["addr_a"], "10.2.0.1");
    assert_eq!(flows[0]["port_b"], 2222);

    let enc = rows(&sql(&cap, "SELECT carrier_protocol FROM encapsulations"));
    assert_eq!(enc[0]["carrier_protocol"], "GRE");
}

#[test]
fn tcp_stream_relative_sequence_numbers() {
    let (_dir, cap) = write_capture(&tcp_stream_frames());
    let segs = rows(&sql(
        &cap,
        "SELECT packet_number, direction, seq_rel, ack_rel, payload_len, next_seq, flags_name \
         FROM tcp_segments ORDER BY packet_number",
    ));
    assert_eq!(segs.len(), 3);

    assert_eq!(segs[0]["direction"], 0);
    assert_eq!(segs[0]["seq_rel"], 0);
    assert!(segs[0]["ack_rel"].is_null());
    assert_eq!(segs[0]["payload_len"], 0);
    assert_eq!(segs[0]["next_seq"], 1001);
    assert_eq!(segs[0]["flags_name"], "SYN");

    assert_eq!(segs[1]["direction"], 1);
    assert_eq!(segs[1]["seq_rel"], 0);
    assert_eq!(segs[1]["ack_rel"], 1);
    assert_eq!(segs[1]["next_seq"], 5001);

    assert_eq!(segs[2]["direction"], 0);
    assert_eq!(segs[2]["seq_rel"], 1);
    assert_eq!(segs[2]["ack_rel"], 1);
    assert_eq!(segs[2]["payload_len"], 10);
    assert_eq!(segs[2]["next_seq"], 1011);

    let flows = rows(&sql(
        &cap,
        "SELECT packets, bytes, tcp_stream_id, duration_secs FROM conversations",
    ));
    assert_eq!(flows.len(), 1);
    assert_eq!(flows[0]["packets"], 3);
    assert!(flows[0]["tcp_stream_id"].is_number());
    assert_eq!(flows[0]["duration_secs"], 2);

    // All three segments share one flow id, matching the flow's id.
    let ids = rows(&sql(&cap, "SELECT DISTINCT flow_id FROM tcp"));
    assert_eq!(ids.len(), 1);
}

#[test]
fn dns_questions_are_queryable_with_json_functions() {
    let (_dir, cap) = write_capture(&[dns_frame()]);
    let out = rows(&sql(
        &cap,
        "SELECT p.number, json_extract(q.value, '$.name') AS name, \
                json_extract(q.value, '$.type') AS qtype \
         FROM dns d JOIN packets p ON p.number = d.packet_number, json_each(d.\"questions\") q",
    ));
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["number"], 1);
    assert_eq!(out[0]["name"], "example.com");
    assert_eq!(out[0]["qtype"], 1);

    let id = rows(&sql(&cap, "SELECT \"id\", \"qr\" FROM dns"));
    assert_eq!(id[0]["id"], 0x1234);
    assert_eq!(id[0]["qr"], 0);
}

#[test]
fn default_row_limit_and_count() {
    let frames: Vec<Vec<u8>> = (0..1005).map(|_| plain_udp_frame()).collect();
    let (_dir, cap) = write_capture(&frames);

    let out = sql(&cap, "SELECT number FROM packets");
    assert_eq!(rows(&out).len(), 1000);
    let warnings = stderr_json(&out);
    assert!(
        warnings
            .iter()
            .any(|w| w["warning"]["code"] == "default_limit_reached"),
        "{warnings:?}"
    );

    let out = dsct(&[
        "sql",
        "--count",
        "2",
        cap.to_str().unwrap(),
        "SELECT number FROM packets",
    ]);
    assert_eq!(rows(&out).len(), 2);
    assert!(stderr_json(&out).is_empty());

    let out = dsct(&[
        "sql",
        "--no-limit",
        cap.to_str().unwrap(),
        "SELECT number FROM packets",
    ]);
    assert_eq!(rows(&out).len(), 1005);
    assert!(stderr_json(&out).is_empty());
}

#[test]
fn write_and_multi_statement_queries_are_rejected() {
    let (_dir, cap) = write_capture(&[plain_udp_frame()]);
    for q in [
        "INSERT INTO packets (number) VALUES (99)",
        "DROP TABLE packets",
        "SELECT 1; SELECT 2",
        "PRAGMA journal_mode = WAL",
        "SELECT no_such_column FROM packets",
        "SELECT FROM",
        "",
    ] {
        let out = sql(&cap, q);
        assert_invalid_arguments(&out);
    }
    // The index survived every rejected statement.
    let n = rows(&sql(&cap, "SELECT COUNT(*) AS n FROM packets"));
    assert_eq!(n[0]["n"], 1);
}

#[test]
fn schema_flag_describes_database() {
    let (_dir, cap) = write_capture(&[plain_udp_frame()]);
    let out = dsct(&["sql", "--schema", cap.to_str().unwrap()]);
    assert!(out.status.success());
    let schema: Value = serde_json::from_slice(&out.stdout).unwrap();
    // Keep in sync with `sqlite::SCHEMA_VERSION` in src/sqlite/mod.rs.
    assert_eq!(schema["schema_version"], 2);
    let tables = schema["tables"].as_array().unwrap();
    let names: Vec<&str> = tables.iter().map(|t| t["name"].as_str().unwrap()).collect();
    for expected in [
        "packets",
        "layers",
        "flows",
        "packet_flows",
        "tcp",
        "udp",
        "ipv4",
        "encapsulations",
        "conversations",
        "tcp_segments",
    ] {
        assert!(names.contains(&expected), "missing table {expected}");
    }
    let tcp = tables.iter().find(|t| t["name"] == "tcp").unwrap();
    assert_eq!(tcp["protocol"], "TCP");
    let cols: Vec<&str> = tcp["columns"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert!(cols.contains(&"depth"));
    assert!(cols.contains(&"flow_id"));
    assert!(cols.contains(&"seq_rel"));
    assert_eq!(schema["index"]["packets"], 1);
    assert_eq!(schema["index"]["complete"], true);
    assert!(schema["hints"].is_array());
}

#[test]
fn schema_flag_with_tables_restricts_output() {
    let (_dir, cap) = write_capture(&[plain_udp_frame()]);
    let out = dsct(&[
        "sql",
        "--schema",
        "--tables",
        "tcp,udp",
        cap.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "{out:?}");
    let schema: Value = serde_json::from_slice(&out.stdout).unwrap();
    let tables = schema["tables"].as_array().unwrap();
    let names: Vec<&str> = tables.iter().map(|t| t["name"].as_str().unwrap()).collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"tcp"));
    assert!(names.contains(&"udp"));
    let tcp = tables.iter().find(|t| t["name"] == "tcp").unwrap();
    // The CLI always prints full column detail, even restricted to --tables.
    assert!(!tcp["columns"].as_array().unwrap().is_empty());

    let bad = dsct(&[
        "sql",
        "--schema",
        "--tables",
        "no_such_table",
        cap.to_str().unwrap(),
    ]);
    assert_invalid_arguments(&bad);
}

#[test]
fn query_required_without_schema_flag() {
    let (_dir, cap) = write_capture(&[plain_udp_frame()]);
    let out = dsct(&["sql", cap.to_str().unwrap()]);
    assert_invalid_arguments(&out);
}

#[test]
fn stdin_requires_db_and_builds_into_it() {
    let dir = tempfile::tempdir().unwrap();
    let pcap = build_pcap(&[plain_udp_frame(), plain_udp_frame()]);

    let out = Command::cargo_bin("dsct")
        .unwrap()
        .args(["sql", "-", "SELECT 1"])
        .write_stdin(pcap.clone())
        .output()
        .unwrap();
    assert_invalid_arguments(&out);

    let db = dir.path().join("stdin.sqlite");
    let out = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "sql",
            "--db",
            db.to_str().unwrap(),
            "-",
            "SELECT COUNT(*) AS n FROM packets",
        ])
        .write_stdin(pcap)
        .output()
        .unwrap();
    assert_eq!(rows(&out)[0]["n"], 2);
    assert!(db.exists());
}

#[test]
fn existing_database_can_be_queried_directly() {
    let (_dir, cap) = write_capture(&[plain_udp_frame(), gre_frame()]);
    let index = dsct(&["index", cap.to_str().unwrap()]);
    assert!(index.status.success());
    let info: Value = serde_json::from_slice(&index.stdout).unwrap();
    assert_eq!(info["type"], "index");
    assert_eq!(info["built"], true);
    assert_eq!(info["replaced"], false);
    assert_eq!(info["packets"], 2);
    assert_eq!(info["flows"], 2);
    let db = PathBuf::from(info["db"].as_str().unwrap());
    assert_eq!(db, db_path_for(&cap));
    assert!(
        db.starts_with(TEST_CACHE_DIR.path()),
        "default db path should live in the cache dir: {db:?}"
    );

    // Querying the database file itself never rebuilds, even after the
    // capture disappears.
    std::fs::remove_file(&cap).unwrap();
    let out = rows(&sql(
        &db,
        "SELECT COUNT(*) AS n FROM layers WHERE depth = 1",
    ));
    assert_eq!(out[0]["n"], 2);

    // index on a database file is refused.
    let out = dsct(&["index", db.to_str().unwrap()]);
    assert_invalid_arguments(&out);
}

#[test]
fn index_command_reports_reuse_and_force() {
    let (_dir, cap) = write_capture(&[plain_udp_frame()]);
    let first: Value =
        serde_json::from_slice(&dsct(&["index", cap.to_str().unwrap()]).stdout).unwrap();
    assert_eq!(first["built"], true);

    let second: Value =
        serde_json::from_slice(&dsct(&["index", cap.to_str().unwrap()]).stdout).unwrap();
    assert_eq!(second["built"], false);
    assert_eq!(second["replaced"], false);
    assert!(second.get("packets").is_none());

    let forced: Value =
        serde_json::from_slice(&dsct(&["index", "--force", cap.to_str().unwrap()]).stdout).unwrap();
    assert_eq!(forced["built"], true);
    assert_eq!(forced["replaced"], true);
    assert_eq!(forced["packets"], 1);
}

#[test]
fn index_with_custom_db_path_and_progress() {
    let (dir, cap) = write_capture(&[plain_udp_frame(), plain_udp_frame(), plain_udp_frame()]);
    let db = dir.path().join("custom.sqlite");
    let out = dsct(&[
        "index",
        "--db",
        db.to_str().unwrap(),
        "--progress",
        "2",
        cap.to_str().unwrap(),
    ]);
    assert!(out.status.success());
    assert!(db.exists());
    assert!(!db_exists_for(&cap));
    let progress = stderr_json(&out);
    assert_eq!(progress.len(), 1);
    assert_eq!(progress[0]["progress"]["packets_processed"], 2);

    let out = dsct(&[
        "sql",
        "--db",
        db.to_str().unwrap(),
        cap.to_str().unwrap(),
        "SELECT COUNT(*) AS n FROM packets",
    ]);
    assert_eq!(rows(&out)[0]["n"], 3);
}

#[test]
fn decode_as_changes_index_contents_and_freshness() {
    let frames = vec![eth(
        0x0800,
        &ipv4(
            [10, 0, 0, 1],
            [10, 0, 0, 53],
            17,
            &udp(53000, 5353, &dns_frame()[42..]),
        ),
    )];
    let (_dir, cap) = write_capture(&frames);
    let plain = rows(&sql(&cap, "SELECT stack FROM packets"));
    let with_decode = dsct(&[
        "sql",
        "-d",
        "udp.port=5353:dns",
        cap.to_str().unwrap(),
        "SELECT stack FROM packets",
    ]);
    let decoded = rows(&with_decode);
    assert!(
        stderr_json(&with_decode)
            .iter()
            .any(|w| w["warning"]["code"] == "index_rebuilt"),
        "different --decode-as must rebuild"
    );
    assert_ne!(plain[0]["stack"], decoded[0]["stack"]);
    assert!(decoded[0]["stack"].as_str().unwrap().ends_with("DNS"));

    let bad = dsct(&["sql", "-d", "bogus", cap.to_str().unwrap(), "SELECT 1"]);
    assert_invalid_arguments(&bad);
}

#[test]
fn missing_capture_is_file_not_found() {
    let out = dsct(&["sql", "/nonexistent/dir/capture.pcap", "SELECT 1"]);
    assert_eq!(out.status.code(), Some(3));
    let err = stderr_json(&out);
    assert_eq!(err.last().unwrap()["error"]["code"], "file_not_found");

    let out = dsct(&["index", "/nonexistent/dir/capture.pcap"]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn invalid_capture_is_invalid_format() {
    let dir = tempfile::tempdir().unwrap();
    let cap = dir.path().join("bad.pcap");
    std::fs::write(&cap, b"definitely not a capture file").unwrap();
    let out = sql(&cap, "SELECT 1");
    assert_eq!(out.status.code(), Some(4));
    assert_eq!(
        stderr_json(&out).last().unwrap()["error"]["code"],
        "invalid_format"
    );
    assert!(!db_exists_for(&cap), "no partial index may be left behind");
}

#[test]
fn schema_command_describes_sql_rows() {
    let out = dsct(&["schema", "sql"]);
    assert!(out.status.success());
    let schema: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(schema["title"], "dsct sql result row");
}

#[test]
fn blob_columns_are_hex_strings() {
    // TCP with a 4-byte NOP/NOP/timestamp-less option block: data offset 6.
    let mut seg = tcp(40000, 8080, 1, 0, 0x02, &[]);
    seg[12] = 0x60; // data offset = 6 words
    seg.extend_from_slice(&[0x01, 0x01, 0x01, 0x00]); // NOP, NOP, NOP, EOL
    let frame = eth(0x0800, &ipv4([10, 0, 0, 1], [10, 0, 0, 2], 6, &seg));
    let (_dir, cap) = write_capture(&[frame]);
    let out = rows(&sql(&cap, "SELECT \"options\" FROM tcp"));
    assert_eq!(out[0]["options"], "01010100");
}
