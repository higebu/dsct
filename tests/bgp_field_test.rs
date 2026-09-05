//! Regression test for BGP `path_attributes` non-verbose field visibility.
//!
//! `src/default_fields.toml` used to list `"path_attributes.type_name"`, but
//! the BGP dissector's `display_fn` companion for the `type_code` field is
//! actually emitted as `type_code_name` (see `packet-dissector-bgp`'s
//! `PATH_ATTR_CHILDREN`). That meant non-verbose `dsct read` output for BGP
//! never showed which path attribute a `path_attributes` entry was (e.g.
//! `ORIGIN`, `AS_PATH`), only its raw bytes/value. This test runs `dsct
//! read` over the shared minimal BGP UPDATE fixture (carried over TCP port
//! 179, RFC 4271, with a single ORIGIN path attribute) and asserts the
//! non-verbose JSON output names it.

use assert_cmd::Command;
use tempfile::NamedTempFile;

use std::io::Write;

#[path = "../src/test_fixtures.rs"]
mod test_fixtures;

fn write_bgp_pcap() -> NamedTempFile {
    let pcap = test_fixtures::single_packet_pcap(&test_fixtures::bgp_update_frame());
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

/// An UPDATE's address family must be filterable through the BGP layer's
/// top-level `safi` (mirrored from MP_REACH_NLRI by packet-dissector 0.4.1),
/// not only through `path_attributes.value.safi`.
#[test]
fn bgp_update_top_level_safi_filterable() {
    let pcap = test_fixtures::single_packet_pcap(&test_fixtures::bgp_update_mp_reach_frame());
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "read",
            tmp.path().to_str().unwrap(),
            "--filter",
            "bgp.safi = 1 AND bgp.afi = 2",
        ])
        .output()
        .unwrap();

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<&str> = stdout.trim().lines().collect();
    assert_eq!(
        lines.len(),
        1,
        "filter on top-level afi/safi should match: {stdout}"
    );

    let v: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    let bgp = v["layers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|l| l["protocol"] == "BGP")
        .unwrap_or_else(|| panic!("no BGP layer in {v}"));
    assert_eq!(bgp["fields"]["afi"], 2, "{bgp}");
    assert_eq!(bgp["fields"]["safi"], 1, "{bgp}");
    assert_eq!(bgp["fields"]["safi_name"], "Unicast", "{bgp}");
}
