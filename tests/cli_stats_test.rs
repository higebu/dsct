//! Positive-path integration tests for `dsct stats`.
//!
//! Validates that the binary produces correct JSON output for valid captures.

use assert_cmd::Command;
use tempfile::NamedTempFile;

use std::io::Write;

/// Build a minimal pcap with `n` copies of `pkt`.
///
/// Produces a pcap global header (Ethernet link type) followed by `n` packet
/// records, each with a monotonically increasing second-resolution timestamp.
fn pcap_with_packets(pkt: &[u8], n: usize) -> Vec<u8> {
    // 24-byte global header + n × (16-byte record header + payload)
    let mut pcap = Vec::with_capacity(24 + n * (16 + pkt.len()));
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
    for i in 0..n {
        pcap.extend_from_slice(&(i as u32).to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        pcap.extend_from_slice(pkt);
    }
    pcap
}

/// Build a minimal pcap containing `n` identical UDP packets.
fn build_pcap(n: usize) -> Vec<u8> {
    pcap_with_packets(
        &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x00,
            0x00, 0x01, 0x0A, 0x00, 0x00, 0x02, 0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
        ],
        n,
    )
}

fn write_pcap(n: usize) -> NamedTempFile {
    let pcap = build_pcap(n);
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();
    tmp
}

fn write_raw_pcap(data: Vec<u8>) -> NamedTempFile {
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&data).unwrap();
    tmp
}

/// Ethernet + IPv4 + ICMP Echo Request (type=8, code=0): 42 bytes.
const ICMP_ECHO_REQUEST: &[u8] = &[
    // Ethernet
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
    // IPv4: TTL=64, protocol=1 (ICMP), src=10.0.0.1, dst=10.0.0.2
    0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
    0x0a, 0x00, 0x00, 0x02, // ICMP: type=8, code=0, checksum=0, id=1, seq=1
    0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
];

/// Ethernet + IPv6 + ICMPv6 Echo Request (type=128, code=0): 62 bytes.
const ICMPV6_ECHO_REQUEST: &[u8] = &[
    // Ethernet
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x86, 0xdd,
    // IPv6: payload_len=8, next=58 (ICMPv6), hop=64, src=2001:db8::1, dst=2001:db8::2
    0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 0x3a, 0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    // ICMPv6: type=128, code=0, checksum=0, id=1, seq=1
    0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01,
];

fn build_icmp_pcap(n: usize) -> Vec<u8> {
    pcap_with_packets(ICMP_ECHO_REQUEST, n)
}

fn build_icmpv6_pcap(n: usize) -> Vec<u8> {
    pcap_with_packets(ICMPV6_ECHO_REQUEST, n)
}

#[test]
fn stats_produces_valid_json() {
    let tmp = write_pcap(5);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert!(v["total_packets"].is_number());
    assert_eq!(v["total_packets"].as_u64().unwrap(), 5);
    assert!(v["protocols"].is_object());
}

#[test]
fn stats_with_top_talkers() {
    let tmp = write_pcap(3);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "--top-talkers", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["top_talkers"].is_array());
}

/// Build a minimal pcap containing `n` identical NTPv3 client packets.
///
/// Frame: Ethernet + IPv4 + UDP/123 + 48-byte NTP payload.
/// NTP: LI=0, VN=3, Mode=3 (client), Stratum=2.
fn build_ntp_pcap(n: usize) -> Vec<u8> {
    pcap_with_packets(
        &[
            // Ethernet
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            // IPv4 (total length 76 = 20+8+48)
            0x45, 0x00, 0x00, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, // UDP src=123 dst=123 length=56
            0x00, 0x7b, 0x00, 0x7b, 0x00, 0x38, 0x00, 0x00,
            // NTP (48 bytes): LI=0 VN=3 Mode=3→0x1b, Stratum=2, Poll=4, Precision=-23
            0x1b, 0x02, 0x04, 0xe9,
            // Root Delay, Root Dispersion, Reference ID, all timestamps (zeros)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        n,
    )
}

#[test]
fn stats_ntp_produces_distribution() {
    let pcap = build_ntp_pcap(3);
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "--protocol", "ntp", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(v["total_packets"].as_u64().unwrap(), 3);

    let ntp = &v["ntp"];
    assert!(ntp.is_object(), "ntp key must be present");
    assert_eq!(ntp["total_packets"].as_u64().unwrap(), 3);
    assert!(ntp["mode_distribution"].is_array());
    assert!(ntp["stratum_distribution"].is_array());
    assert!(ntp["version_distribution"].is_array());
}

/// Build a minimal pcap containing `n` identical SCTP packets.
///
/// Frame: Ethernet + IPv4 + SCTP (src_port=3868, dst_port=3868).
fn build_sctp_pcap(n: usize) -> Vec<u8> {
    pcap_with_packets(
        &[
            // Ethernet header (14 bytes)
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            // IPv4 header (20 bytes): total length=32, protocol=132 (SCTP)
            0x45, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x40, 0x84, 0x00, 0x00, 0x0A, 0x00,
            0x00, 0x01, 0x0A, 0x00, 0x00, 0x02,
            // SCTP header (12 bytes): src_port=3868, dst_port=3868
            0x0F, 0x1C, 0x0F, 0x1C, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ],
        n,
    )
}

#[test]
fn stats_sctp_protocol() {
    let pcap = build_sctp_pcap(3);
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "sctp", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["total_packets"].as_u64().unwrap(), 3);

    let sctp = &v["sctp"];
    assert!(sctp.is_object(), "expected sctp key in output: {stdout}");
    assert_eq!(sctp["total_packets"].as_u64().unwrap(), 3);
    assert!(sctp["top_src_ports"].is_array());
    assert!(sctp["top_dst_ports"].is_array());
    assert!(sctp["top_port_pairs"].is_array());
}

/// Build a minimal pcap containing a single DHCPv6 Solicit packet.
///
/// Frame: Ethernet (IPv6) → IPv6 (UDP) → UDP (546→547) → DHCPv6 Solicit.
fn build_dhcpv6_pcap() -> Vec<u8> {
    #[rustfmt::skip]
    let pkt: &[u8] = &[
        // Ethernet header
        0x33, 0x33, 0x00, 0x01, 0x00, 0x02,             // dst (multicast)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,             // src
        0x86, 0xDD,                                       // EtherType: IPv6
        // IPv6 header
        0x60, 0x00, 0x00, 0x00,                           // version + traffic class + flow label
        0x00, 0x0C,                                       // payload length (12 = 8 UDP + 4 DHCPv6)
        0x11,                                             // next header: UDP
        0x40,                                             // hop limit
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, // src: fe80::1
        0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x02, // dst: ff02::1:2
        // UDP header
        0x02, 0x22,                                       // src port: 546
        0x02, 0x23,                                       // dst port: 547
        0x00, 0x0C,                                       // length: 12
        0x00, 0x00,                                       // checksum
        // DHCPv6 payload
        0x01,                                             // msg_type: 1 (Solicit)
        0x00, 0x00, 0x01,                                 // transaction_id
    ];
    pcap_with_packets(pkt, 1)
}

#[test]
fn stats_dhcpv6_protocol() {
    let pcap = build_dhcpv6_pcap();
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "dhcpv6", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["total_packets"].as_u64().unwrap(), 1);
    assert!(v["dhcpv6"].is_object(), "dhcpv6 stats should be present");
    assert_eq!(v["dhcpv6"]["total_packets"].as_u64().unwrap(), 1);
    assert!(v["dhcpv6"]["msg_type_distribution"].is_array());
}

#[test]
fn stats_from_stdin() {
    let pcap = build_pcap(2);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-"])
        .write_stdin(pcap)
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(v["total_packets"].as_u64().unwrap(), 2);
}

#[test]
fn stats_with_vxlan_protocol_flag() {
    let tmp = write_pcap(3);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "vxlan", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["vxlan"].is_object());
    assert!(v["vxlan"]["total_packets"].is_number());
    assert!(v["vxlan"]["top_vnis"].is_array());
}

#[test]
fn stats_with_gre_protocol_flag() {
    let tmp = write_pcap(3);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "gre", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["gre"].is_object());
    assert!(v["gre"]["total_packets"].is_number());
    assert!(v["gre"]["protocol_type_distribution"].is_array());
    assert!(v["gre"]["top_keys"].is_array());
}

#[test]
fn stats_with_geneve_protocol_flag() {
    let tmp = write_pcap(3);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "geneve", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["geneve"].is_object());
    assert!(v["geneve"]["total_packets"].is_number());
    assert!(v["geneve"]["protocol_type_distribution"].is_array());
    assert!(v["geneve"]["top_vnis"].is_array());
}

#[test]
fn stats_http2_flag_produces_key() {
    let tmp = write_pcap(3);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "--protocol", "http2", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    // The "http2" key must be present when the protocol flag is requested,
    // even when the capture contains no HTTP/2 frames.
    assert!(v["http2"].is_object(), "expected \"http2\" key in output");
    assert_eq!(v["http2"]["total_frames"].as_u64().unwrap(), 0);
    assert!(v["http2"]["frame_type_distribution"].is_array());
    assert!(v["http2"]["error_code_distribution"].is_array());
    assert!(v["http2"]["top_stream_ids"].is_array());
}

#[test]
fn stats_http2_alias_http_slash_2() {
    let tmp = write_pcap(1);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "stats",
            "--protocol",
            "http/2",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(
        v["http2"].is_object(),
        "expected \"http2\" key for http/2 alias"
    );
}

/// Stack: Ethernet / IPv4 / UDP(2152→2152) / GTPv1-U (G-PDU, TEID=1).
const GTPV1U_PKT: &[u8] = &[
    // Ethernet
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
    // IPv4 (total length = 36 = 20+8+8)
    0x45, 0x00, 0x00, 0x24, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x01,
    0x0A, 0x00, 0x00, 0x02, // UDP src=2152 dst=2152 len=16
    0x08, 0x68, 0x08, 0x68, 0x00, 0x10, 0x00, 0x00,
    // GTPv1-U: flags=0x30, msg_type=255 (G-PDU), len=0, TEID=1
    0x30, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

#[test]
fn stats_gtpv1u_message_type_and_teid() {
    let pcap = pcap_with_packets(GTPV1U_PKT, 3);
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "gtpv1u", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(v["total_packets"].as_u64().unwrap(), 3);

    let gtpv1u = &v["gtpv1u"];
    assert!(gtpv1u.is_object(), "gtpv1u key missing");
    assert_eq!(gtpv1u["total_packets"].as_u64().unwrap(), 3);

    let msg_dist = gtpv1u["message_type_distribution"].as_array().unwrap();
    assert!(
        !msg_dist.is_empty(),
        "message_type_distribution should be non-empty"
    );
    assert_eq!(msg_dist[0]["count"].as_u64().unwrap(), 3);

    let top_teids = gtpv1u["top_teids"].as_array().unwrap();
    assert!(!top_teids.is_empty(), "top_teids should be non-empty");
    assert_eq!(top_teids[0]["count"].as_u64().unwrap(), 3);
}

#[test]
fn stats_icmp_deep_stats() {
    let tmp = write_raw_pcap(build_icmp_pcap(3));

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "icmp", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(v["total_packets"].as_u64().unwrap(), 3);
    assert!(v["protocols"]["ICMP"].is_number());

    let icmp = &v["icmp"];
    assert!(icmp.is_object(), "icmp deep stats should be present");
    assert_eq!(icmp["total_packets"].as_u64().unwrap(), 3);
    assert!(icmp["type_distribution"].is_array());
    assert_eq!(icmp["type_distribution"].as_array().unwrap().len(), 1);
    assert!(icmp["code_distribution"].is_array());
}

#[test]
fn stats_icmp_without_protocol_flag_has_no_deep_stats() {
    let tmp = write_raw_pcap(build_icmp_pcap(2));

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert!(
        v.get("icmp").is_none(),
        "icmp key should not be present without -p icmp"
    );
}

#[test]
fn stats_icmpv6_deep_stats() {
    let tmp = write_raw_pcap(build_icmpv6_pcap(4));

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "icmpv6", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(v["total_packets"].as_u64().unwrap(), 4);
    assert!(v["protocols"]["ICMPv6"].is_number());

    let icmpv6 = &v["icmpv6"];
    assert!(icmpv6.is_object(), "icmpv6 deep stats should be present");
    assert_eq!(icmpv6["total_packets"].as_u64().unwrap(), 4);
    assert!(icmpv6["type_distribution"].is_array());
    assert_eq!(icmpv6["type_distribution"].as_array().unwrap().len(), 1);
    assert!(icmpv6["code_distribution"].is_array());
}

#[test]
fn stats_icmp_and_icmpv6_combined() {
    let mut pcap: Vec<u8> = Vec::with_capacity(24 + 3 * 16 + 2 * 42 + 62);
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
    for (ts, pkt) in [
        (0u32, ICMP_ECHO_REQUEST),
        (1u32, ICMPV6_ECHO_REQUEST),
        (2u32, ICMP_ECHO_REQUEST),
    ] {
        pcap.extend_from_slice(&ts.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        pcap.extend_from_slice(pkt);
    }

    let tmp = write_raw_pcap(pcap);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args([
            "stats",
            "-p",
            "icmp",
            "-p",
            "icmpv6",
            tmp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(v["total_packets"].as_u64().unwrap(), 3);
    assert_eq!(v["icmp"]["total_packets"].as_u64().unwrap(), 2);
    assert_eq!(v["icmpv6"]["total_packets"].as_u64().unwrap(), 1);
}

/// Ethernet/IPv4 ARP request: sender 10.0.0.1 / 00:11:22:33:44:55 → target 10.0.0.2.
#[rustfmt::skip]
const ARP_PKT: &[u8] = &[
    // Ethernet header
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst: broadcast
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src
    0x08, 0x06,                          // EtherType: ARP
    // ARP header
    0x00, 0x01, // hardware type: Ethernet
    0x08, 0x00, // protocol type: IPv4
    0x06,       // hardware address length
    0x04,       // protocol address length
    0x00, 0x01, // operation: Request
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // sender MAC
    0x0a, 0x00, 0x00, 0x01,              // sender IP: 10.0.0.1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC (unknown)
    0x0a, 0x00, 0x00, 0x02,              // target IP: 10.0.0.2
];

fn write_arp_pcap(n: usize) -> NamedTempFile {
    let pcap = pcap_with_packets(ARP_PKT, n);
    let mut tmp = NamedTempFile::with_suffix(".pcap").unwrap();
    tmp.write_all(&pcap).unwrap();
    tmp
}

#[test]
fn stats_arp_produces_protocol_stats() {
    let tmp = write_arp_pcap(3);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "--protocol", "arp", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    assert_eq!(v["total_packets"].as_u64().unwrap(), 3);

    let arp = &v["arp"];
    assert!(arp.is_object(), "protocol_stats.arp must be an object");
    assert_eq!(arp["total_packets"].as_u64().unwrap(), 3);
    assert!(arp["oper_distribution"].is_array());
    assert!(arp["top_spa"].is_array());
    assert!(arp["top_sha"].is_array());
}

#[test]
fn stats_arp_oper_distribution() {
    let tmp = write_arp_pcap(2);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "--protocol", "arp", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let dist = &v["arp"]["oper_distribution"];
    assert!(dist.is_array());
    assert_eq!(dist.as_array().unwrap().len(), 1);
    assert_eq!(dist[0]["count"].as_u64().unwrap(), 2);
}

#[test]
fn stats_arp_top_spa() {
    let tmp = write_arp_pcap(4);

    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "--protocol", "arp", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();

    let top_spa = &v["arp"]["top_spa"];
    assert!(top_spa.is_array());
    let entries = top_spa.as_array().unwrap();
    assert!(!entries.is_empty());
    assert_eq!(entries[0]["name"].as_str().unwrap(), "10.0.0.1");
    assert_eq!(entries[0]["count"].as_u64().unwrap(), 4);
}

#[test]
fn stats_lldp_protocol_flag() {
    let tmp = write_pcap(3);
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "lldp", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["lldp"].is_object(), "expected lldp key: {stdout}");
    assert!(v["lldp"]["total_packets"].is_number());
    assert!(v["lldp"]["tlv_type_distribution"].is_array());
    assert!(v["lldp"]["top_system_names"].is_array());
}

#[test]
fn stats_stun_protocol_flag() {
    let tmp = write_pcap(3);
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "stun", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["stun"].is_object(), "expected stun key: {stdout}");
    assert!(v["stun"]["total_messages"].is_number());
    assert!(v["stun"]["class_distribution"].is_array());
    assert!(v["stun"]["method_distribution"].is_array());
}

#[test]
fn stats_nas5g_protocol_flag() {
    let tmp = write_pcap(3);
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "nas5g", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["nas5g"].is_object(), "expected nas5g key: {stdout}");
    assert!(v["nas5g"]["total_messages"].is_number());
    assert!(v["nas5g"]["epd_distribution"].is_array());
    assert!(v["nas5g"]["mm_message_type_distribution"].is_array());
    assert!(v["nas5g"]["sm_message_type_distribution"].is_array());
}

#[test]
fn stats_igmp_protocol_flag() {
    let tmp = write_pcap(3);
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "igmp", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["igmp"].is_object(), "expected igmp key: {stdout}");
    assert!(v["igmp"]["total_packets"].is_number());
    assert!(v["igmp"]["type_distribution"].is_array());
    assert!(v["igmp"]["top_group_addresses"].is_array());
    assert!(v["igmp"]["version_distribution"].is_array());
}

#[test]
fn stats_mdns_protocol_flag() {
    let tmp = write_pcap(3);
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "mdns", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["mdns"].is_object(), "expected mdns key: {stdout}");
    assert!(v["mdns"]["total_packets"].is_number());
    assert!(v["mdns"]["top_query_names"].is_array());
    assert!(v["mdns"]["service_distribution"].is_array());
}

#[test]
fn stats_ngap_protocol_flag() {
    let tmp = write_pcap(3);
    let output = Command::cargo_bin("dsct")
        .unwrap()
        .args(["stats", "-p", "ngap", tmp.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(v["ngap"].is_object(), "expected ngap key: {stdout}");
    assert!(v["ngap"]["total_messages"].is_number());
    assert!(v["ngap"]["pdu_type_distribution"].is_array());
    assert!(v["ngap"]["procedure_code_distribution"].is_array());
}
