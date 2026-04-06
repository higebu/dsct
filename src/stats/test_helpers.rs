use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::{DissectBuffer, Packet};
use packet_dissector_test_alloc::test_desc;

pub(super) static EMPTY_DATA: [u8; 0] = [];

pub(super) fn pkt<'a>(buf: &'a DissectBuffer<'static>) -> Packet<'a, 'static> {
    Packet::new(buf, &EMPTY_DATA)
}

pub(super) fn build_ipv4_buf(src: [u8; 4], dst: [u8; 4]) -> DissectBuffer<'static> {
    let mut buf = DissectBuffer::new();
    buf.begin_layer("IPv4", None, &[], 0..20);
    buf.push_field(
        test_desc("src", "Source"),
        FieldValue::Ipv4Addr(src),
        12..16,
    );
    buf.push_field(
        test_desc("dst", "Destination"),
        FieldValue::Ipv4Addr(dst),
        16..20,
    );
    buf.end_layer();
    buf
}

pub(super) fn build_vxlan_buf(vni: u32) -> DissectBuffer<'static> {
    let mut buf = DissectBuffer::new();
    buf.begin_layer("VXLAN", None, &[], 0..8);
    buf.push_field(test_desc("vni", "VNI"), FieldValue::U32(vni), 4..7);
    buf.end_layer();
    buf
}

pub(super) fn build_dns_query_buf(
    id: u16,
    name: &'static str,
    qtype: u16,
) -> DissectBuffer<'static> {
    let mut buf = DissectBuffer::new();
    buf.begin_layer("DNS", None, &[], 0..20);
    buf.push_field(test_desc("id", "Transaction ID"), FieldValue::U16(id), 0..2);
    buf.push_field(test_desc("qr", "QR"), FieldValue::U8(0), 2..3);
    let arr = buf.begin_container(
        test_desc("questions", "Questions"),
        FieldValue::Array(0..0),
        12..14,
    );
    let obj = buf.begin_container(test_desc("q", "Q"), FieldValue::Object(0..0), 12..14);
    buf.push_field(test_desc("name", "Name"), FieldValue::Str(name), 12..12);
    buf.push_field(test_desc("type", "Type"), FieldValue::U16(qtype), 12..14);
    buf.end_container(obj);
    buf.end_container(arr);
    buf.end_layer();
    buf
}

pub(super) fn add_ipv4_udp(
    buf: &mut DissectBuffer<'static>,
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
) {
    buf.begin_layer("IPv4", None, &[], 0..20);
    buf.push_field(
        test_desc("src", "Source"),
        FieldValue::Ipv4Addr(src),
        12..16,
    );
    buf.push_field(
        test_desc("dst", "Destination"),
        FieldValue::Ipv4Addr(dst),
        16..20,
    );
    buf.end_layer();
    buf.begin_layer("UDP", None, &[], 20..24);
    buf.push_field(
        test_desc("src_port", "Source Port"),
        FieldValue::U16(sport),
        20..22,
    );
    buf.push_field(
        test_desc("dst_port", "Destination Port"),
        FieldValue::U16(dport),
        22..24,
    );
    buf.end_layer();
}

pub(super) fn add_tcp_layer(
    buf: &mut DissectBuffer<'static>,
    src_port: u16,
    dst_port: u16,
    stream_id: u32,
) {
    buf.begin_layer("TCP", None, &[], 20..40);
    buf.push_field(
        test_desc("src_port", "Source Port"),
        FieldValue::U16(src_port),
        20..22,
    );
    buf.push_field(
        test_desc("dst_port", "Destination Port"),
        FieldValue::U16(dst_port),
        22..24,
    );
    buf.push_field(
        test_desc("stream_id", "Stream ID"),
        FieldValue::U32(stream_id),
        20..40,
    );
    buf.end_layer();
}

pub(super) fn build_gtpv1u_buf(message_type: u8, teid: u32) -> DissectBuffer<'static> {
    let mut buf = DissectBuffer::new();
    buf.begin_layer("GTPv1-U", None, &[], 0..8);
    buf.push_field(
        test_desc("message_type", "Message Type"),
        FieldValue::U8(message_type),
        1..2,
    );
    buf.push_field(test_desc("teid", "TEID"), FieldValue::U32(teid), 4..8);
    buf.end_layer();
    buf
}

/// Build a minimal ICMP-like DissectBuffer with type and code fields.
pub(super) fn build_icmp_like_buf(
    layer: &'static str,
    icmp_type: u8,
    code: u8,
) -> DissectBuffer<'static> {
    let mut buf = DissectBuffer::new();
    buf.begin_layer(layer, None, &[], 0..8);
    buf.push_field(test_desc("type", "Type"), FieldValue::U8(icmp_type), 0..1);
    buf.push_field(test_desc("code", "Code"), FieldValue::U8(code), 1..2);
    buf.end_layer();
    buf
}
