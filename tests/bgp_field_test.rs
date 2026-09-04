//! Regression test for BGP `path_attributes` non-verbose field visibility.
//!
//! `src/default_fields.toml` used to list `"path_attributes.type_name"`, but
//! the BGP dissector's `display_fn` companion for the `type_code` field is
//! actually emitted as `type_code_name` (see `packet-dissector-bgp`'s
//! `PATH_ATTR_CHILDREN`). That meant non-verbose `dsct read` output for BGP
//! never showed which path attribute a `path_attributes` entry was (e.g.
//! `ORIGIN`, `AS_PATH`), only its raw bytes/value. This test builds a
//! minimal BGP UPDATE message (carried over TCP port 179, RFC 4271) with a
//! single ORIGIN path attribute and asserts the non-verbose JSON output
//! names it.

use assert_cmd::Command;
use tempfile::NamedTempFile;

use std::io::Write;

/// Build an Ethernet + IPv4 + TCP frame wrapping `payload`, with TCP
/// `dst_port` fixed to 179 (BGP, RFC 4271) so the registry's port-based
/// dispatch hands the payload to the BGP dissector.
fn bgp_over_tcp_frame(payload: &[u8]) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&40000u16.to_be_bytes()); // src port
    tcp.extend_from_slice(&179u16.to_be_bytes()); // dst port (BGP)
    tcp.extend_from_slice(&0u32.to_be_bytes()); // sequence number
    tcp.extend_from_slice(&0u32.to_be_bytes()); // acknowledgment number
    tcp.push(0x50); // data offset = 5 (20 bytes), reserved = 0
    tcp.push(0x18); // flags: PSH, ACK
    tcp.extend_from_slice(&0x2000u16.to_be_bytes()); // window
    tcp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
    tcp.extend_from_slice(&0u16.to_be_bytes()); // urgent pointer
    tcp.extend_from_slice(payload);

    let mut frame = Vec::new();
    // Ethernet header
    frame.extend_from_slice(&[0xff; 6]); // dst mac (broadcast)
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4

    // IPv4 header (no options, 20 bytes)
    let total_len: u16 = 20 + tcp.len() as u16;
    frame.push(0x45); // version=4, IHL=5
    frame.push(0x00); // DSCP/ECN
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // identification
    frame.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    frame.push(64); // TTL
    frame.push(6); // protocol = TCP
    frame.extend_from_slice(&0u16.to_be_bytes()); // header checksum (unchecked)
    frame.extend_from_slice(&[10, 0, 0, 1]); // src IP
    frame.extend_from_slice(&[10, 0, 0, 2]); // dst IP
    frame.extend_from_slice(&tcp);
    frame
}

/// Build a minimal BGP UPDATE message (RFC 4271, Section 4.3) with no
/// withdrawn routes, a single ORIGIN (type code 1) path attribute of IGP,
/// and no NLRI.
fn bgp_update_message() -> Vec<u8> {
    let path_attrs: Vec<u8> = vec![
        0x40, // flags: well-known, transitive
        1,    // type code: ORIGIN
        1,    // attribute length: 1 byte
        0,    // value: IGP
    ];

    let mut body = Vec::new();
    body.extend_from_slice(&0u16.to_be_bytes()); // withdrawn routes length
    body.extend_from_slice(&(path_attrs.len() as u16).to_be_bytes()); // total path attribute length
    body.extend_from_slice(&path_attrs);
    // No NLRI.

    let mut msg = Vec::new();
    msg.extend_from_slice(&[0xff; 16]); // marker
    let length = (19 + body.len()) as u16;
    msg.extend_from_slice(&length.to_be_bytes());
    msg.push(2); // type: UPDATE
    msg.extend_from_slice(&body);
    msg
}

/// Wrap `frame` bytes as the sole packet of a pcap capture file.
fn build_pcap(frame: &[u8]) -> Vec<u8> {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet link type

    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes());
    pcap.extend_from_slice(frame);
    pcap
}

fn write_bgp_pcap() -> NamedTempFile {
    let frame = bgp_over_tcp_frame(&bgp_update_message());
    let pcap = build_pcap(&frame);
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();
    tmp
}

/// Non-verbose `dsct read` output for a BGP UPDATE must name the path
/// attribute type via `type_code_name` (regression test for the
/// `path_attributes.type_name` -> `path_attributes.type_code_name` fix in
/// `default_fields.toml`).
#[test]
fn bgp_path_attributes_type_code_name_visible_in_default_mode() {
    let tmp = write_bgp_pcap();

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["read", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(lines.len(), 1, "expected exactly one packet: {stdout}");

    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let layers = v["layers"].as_array().expect("layers array");
    let bgp = layers
        .iter()
        .find(|l| l["protocol"] == "BGP")
        .unwrap_or_else(|| panic!("no BGP layer in {v}"));

    let path_attrs = bgp["fields"]["path_attributes"]
        .as_array()
        .unwrap_or_else(|| panic!("no path_attributes array in {bgp}"));
    assert_eq!(path_attrs.len(), 1);
    assert_eq!(
        path_attrs[0]["type_code_name"], "ORIGIN",
        "path_attributes[0] should carry type_code_name=\"ORIGIN\" in \
         non-verbose mode: {bgp}"
    );
}
