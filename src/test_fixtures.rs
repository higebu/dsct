//! Synthetic capture fixtures shared by unit and integration tests.
//!
//! The same hand-built frames were previously copy-pasted into several test
//! modules, which let them drift apart. They live here instead, and are
//! reached in two ways:
//!
//! - from unit tests inside `src/`, via the `test_fixtures` module declared
//!   in `lib.rs` under `#[cfg(test)]`
//! - from integration tests under `tests/`, via
//!   `#[path = "../src/test_fixtures.rs"] mod test_fixtures;`
//!
//! Because an integration test compiles this file into its own crate, it
//! must depend on `std` only — no `crate::` paths and no external crates.
//!
//! Every address, port and identifier here is synthetic: private-range IPv4
//! addresses (RFC 1918) and locally administered MAC addresses only.

// Each consumer uses a different subset of these helpers.
#![allow(dead_code)]

/// Ethernet / IPv4 / TCP frame carrying `payload` to TCP port 179 (BGP,
/// RFC 4271), so the registry's port-based dispatch hands the payload to
/// the BGP dissector.
///
/// The IPv4 header is a minimal 20-byte header from 10.0.0.1 to 10.0.0.2
/// with an unchecked (zero) checksum.
pub(crate) fn bgp_over_tcp_frame(payload: &[u8]) -> Vec<u8> {
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

    ethernet_ipv4_frame(6, &tcp)
}

/// Minimal BGP UPDATE message (RFC 4271, Section 4.3): no withdrawn
/// routes, a single ORIGIN (type code 1) path attribute of IGP, no NLRI.
///
/// The path attribute object's nested `flags`/`type_code`/`attr_length`
/// field names don't collide with any of BGP's top-level field
/// descriptors, so they are a clean probe for whether nested fields leak
/// into places that should only see top-level ones.
pub(crate) fn bgp_update_message() -> Vec<u8> {
    let path_attrs: [u8; 4] = [
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

/// [`bgp_over_tcp_frame`] wrapping [`bgp_update_message`] — one complete
/// Ethernet / IPv4 / TCP:179 / BGP UPDATE frame.
pub(crate) fn bgp_update_frame() -> Vec<u8> {
    bgp_over_tcp_frame(&bgp_update_message())
}

/// Ethernet / IPv4 / UDP:53 frame carrying a DNS query for `example.com`
/// with an EDNS(0) OPT record (RFC 6891) in the additional section.
///
/// The OPT record carries one edns-tcp-keepalive option (RFC 7828), so the
/// dissected DNS layer has a three-level nested path
/// `additionals` → `edns_options` → `code`, used to exercise deep
/// qualified field paths.
pub(crate) fn dns_edns_query_frame() -> Vec<u8> {
    let mut dns = Vec::new();
    dns.extend_from_slice(&0x1234u16.to_be_bytes()); // transaction id
    dns.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: standard query, RD
    dns.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    dns.extend_from_slice(&0u16.to_be_bytes()); // ancount
    dns.extend_from_slice(&0u16.to_be_bytes()); // nscount
    dns.extend_from_slice(&1u16.to_be_bytes()); // arcount (the OPT record)

    // Question: example.com IN A
    dns.push(7);
    dns.extend_from_slice(b"example");
    dns.push(3);
    dns.extend_from_slice(b"com");
    dns.push(0);
    dns.extend_from_slice(&1u16.to_be_bytes()); // qtype: A
    dns.extend_from_slice(&1u16.to_be_bytes()); // qclass: IN

    // Additional: OPT pseudo-RR (RFC 6891) with one option.
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&11u16.to_be_bytes()); // option code: edns-tcp-keepalive
    rdata.extend_from_slice(&2u16.to_be_bytes()); // option length
    rdata.extend_from_slice(&10u16.to_be_bytes()); // timeout (100ms units)

    dns.push(0); // name: root
    dns.extend_from_slice(&41u16.to_be_bytes()); // type: OPT
    dns.extend_from_slice(&4096u16.to_be_bytes()); // class: UDP payload size
    dns.extend_from_slice(&0u32.to_be_bytes()); // ttl: extended rcode / version / flags
    dns.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    dns.extend_from_slice(&rdata);

    let mut udp = Vec::new();
    udp.extend_from_slice(&12345u16.to_be_bytes()); // src port
    udp.extend_from_slice(&53u16.to_be_bytes()); // dst port (DNS)
    udp.extend_from_slice(&(8 + dns.len() as u16).to_be_bytes()); // length
    udp.extend_from_slice(&0u16.to_be_bytes()); // checksum (unchecked)
    udp.extend_from_slice(&dns);

    ethernet_ipv4_frame(17, &udp)
}

/// Ethernet + IPv4 frame carrying `payload` as IP protocol `protocol`,
/// from 10.0.0.1 to 10.0.0.2 with an unchecked (zero) header checksum.
fn ethernet_ipv4_frame(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    // Ethernet header
    frame.extend_from_slice(&[0xff; 6]); // dst mac (broadcast)
    frame.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]); // src mac
    frame.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype: IPv4

    // IPv4 header (no options, 20 bytes)
    let total_len: u16 = 20 + payload.len() as u16;
    frame.push(0x45); // version = 4, IHL = 5
    frame.push(0x00); // DSCP / ECN
    frame.extend_from_slice(&total_len.to_be_bytes());
    frame.extend_from_slice(&0u16.to_be_bytes()); // identification
    frame.extend_from_slice(&0u16.to_be_bytes()); // flags + fragment offset
    frame.push(64); // TTL
    frame.push(protocol);
    frame.extend_from_slice(&0u16.to_be_bytes()); // header checksum (unchecked)
    frame.extend_from_slice(&[10, 0, 0, 1]); // src IP
    frame.extend_from_slice(&[10, 0, 0, 2]); // dst IP
    frame.extend_from_slice(payload);
    frame
}

/// Wrap `frame` as the sole packet of a little-endian, microsecond-
/// resolution pcap file with Ethernet link type.
pub(crate) fn single_packet_pcap(frame: &[u8]) -> Vec<u8> {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes()); // magic
    pcap.extend_from_slice(&2u16.to_le_bytes()); // version major
    pcap.extend_from_slice(&4u16.to_le_bytes()); // version minor
    pcap.extend_from_slice(&0i32.to_le_bytes()); // thiszone
    pcap.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
    pcap.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
    pcap.extend_from_slice(&1u32.to_le_bytes()); // link type: Ethernet

    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_sec
    pcap.extend_from_slice(&0u32.to_le_bytes()); // ts_usec
    pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // captured length
    pcap.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // original length
    pcap.extend_from_slice(frame);
    pcap
}
