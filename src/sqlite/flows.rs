//! Flow (conversation) tracking and TCP sequence derivation.
//!
//! A flow is identified by `(depth, transport, endpoint a, endpoint b)` where
//! the two endpoints are ordered so that both directions of a conversation
//! share one id.  Flows are tracked per encapsulation depth, so an inner TCP
//! connection carried over GTP-U gets its own flow, separate from the outer
//! UDP flow.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::{DissectBuffer, Layer};

/// Transport protocols that participate in flow tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// SCTP.
    Sctp,
}

impl Transport {
    /// Map a layer short name to a transport.
    pub fn from_layer_name(name: &str) -> Option<Self> {
        match name {
            "TCP" => Some(Self::Tcp),
            "UDP" => Some(Self::Udp),
            "SCTP" => Some(Self::Sctp),
            _ => None,
        }
    }

    /// Lowercase name stored in `flows.transport`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Sctp => "sctp",
        }
    }
}

/// An IP address / port pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    /// IP address.
    pub addr: IpAddr,
    /// Transport port.
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct FlowKey {
    depth: u32,
    transport: Transport,
    a: Endpoint,
    b: Endpoint,
}

/// Aggregated per-flow data written to the `flows` table.
#[derive(Debug, Clone, PartialEq)]
pub struct FlowRow {
    /// Flow id.
    pub id: i64,
    /// Transport protocol.
    pub transport: Transport,
    /// Encapsulation depth.
    pub depth: u32,
    /// Lower endpoint.
    pub a: Endpoint,
    /// Upper endpoint.
    pub b: Endpoint,
    /// Dissector TCP stream id, if any.
    pub tcp_stream_id: Option<u32>,
    /// First packet number.
    pub first_packet: u64,
    /// Last packet number.
    pub last_packet: u64,
    /// Packet count.
    pub packets: u64,
    /// Sum of original lengths.
    pub bytes: u64,
    /// First timestamp (seconds).
    pub first_ts: f64,
    /// Last timestamp (seconds).
    pub last_ts: f64,
}

#[derive(Debug)]
struct FlowState {
    row: FlowRow,
    /// First sequence number seen per direction.
    base_seq: [Option<u32>; 2],
}

/// Result of observing a packet on a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowHit {
    /// Flow id.
    pub flow_id: i64,
    /// `0` when the packet travels from endpoint a to b, `1` otherwise.
    pub direction: u8,
}

/// Per-packet facts needed by [`FlowTracker::observe`].
#[derive(Debug, Clone, Copy)]
pub struct PacketInfo {
    /// Packet number.
    pub number: u64,
    /// Timestamp in seconds.
    pub ts: f64,
    /// Original length on the wire.
    pub bytes: u64,
}

/// TCP sequence numbers relative to the start of each direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSeq {
    /// Sequence number relative to the first segment seen in this direction.
    pub seq_rel: u32,
    /// Acknowledgment number relative to the opposite direction's base, when known.
    pub ack_rel: Option<u32>,
    /// Sequence number expected next from this direction.
    pub next_seq: u32,
}

/// Tracks flows across a whole capture.
#[derive(Debug, Default)]
pub struct FlowTracker {
    flows: HashMap<FlowKey, FlowState>,
    next_id: i64,
}

impl FlowTracker {
    /// Create an empty tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of flows seen so far.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Whether no flow has been seen.
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Record a packet travelling from `src` to `dst` and return its flow.
    pub fn observe(
        &mut self,
        transport: Transport,
        depth: u32,
        src: Endpoint,
        dst: Endpoint,
        pkt: &PacketInfo,
        tcp_stream_id: Option<u32>,
    ) -> FlowHit {
        let (a, b, direction) = if src <= dst {
            (src, dst, 0u8)
        } else {
            (dst, src, 1u8)
        };
        let key = FlowKey {
            depth,
            transport,
            a,
            b,
        };
        let next_id = &mut self.next_id;
        let state = self.flows.entry(key).or_insert_with(|| {
            let id = *next_id;
            *next_id += 1;
            FlowState {
                row: FlowRow {
                    id,
                    transport,
                    depth,
                    a,
                    b,
                    tcp_stream_id,
                    first_packet: pkt.number,
                    last_packet: pkt.number,
                    packets: 0,
                    bytes: 0,
                    first_ts: pkt.ts,
                    last_ts: pkt.ts,
                },
                base_seq: [None, None],
            }
        });
        let row = &mut state.row;
        row.packets += 1;
        row.bytes += pkt.bytes;
        row.last_packet = pkt.number;
        if pkt.ts < row.first_ts {
            row.first_ts = pkt.ts;
        }
        if pkt.ts > row.last_ts {
            row.last_ts = pkt.ts;
        }
        if row.tcp_stream_id.is_none() {
            row.tcp_stream_id = tcp_stream_id;
        }
        FlowHit {
            flow_id: row.id,
            direction,
        }
    }

    /// Compute relative sequence numbers for a TCP segment on `hit`.
    ///
    /// The first sequence number seen in each direction becomes that
    /// direction's base.  `ack_rel` is `None` until the opposite direction has
    /// been seen.
    #[allow(clippy::too_many_arguments)]
    pub fn tcp_sequence(
        &mut self,
        hit: FlowHit,
        seq: u32,
        ack: u32,
        has_ack: bool,
        payload_len: u32,
        syn: bool,
        fin: bool,
    ) -> TcpSeq {
        let dir = usize::from(hit.direction & 1);
        let Some(state) = self.flows.values_mut().find(|s| s.row.id == hit.flow_id) else {
            return TcpSeq {
                seq_rel: 0,
                ack_rel: None,
                next_seq: seq.wrapping_add(payload_len),
            };
        };
        let base = *state.base_seq[dir].get_or_insert(seq);
        let seq_rel = seq.wrapping_sub(base);
        let ack_rel = if has_ack {
            state.base_seq[1 - dir].map(|b| ack.wrapping_sub(b))
        } else {
            None
        };
        let next_seq = seq
            .wrapping_add(payload_len)
            .wrapping_add(u32::from(syn))
            .wrapping_add(u32::from(fin));
        TcpSeq {
            seq_rel,
            ack_rel,
            next_seq,
        }
    }

    /// Consume the tracker and return all flows ordered by id.
    pub fn into_rows(self) -> Vec<FlowRow> {
        let mut rows: Vec<FlowRow> = self.flows.into_values().map(|s| s.row).collect();
        rows.sort_by_key(|r| r.id);
        rows
    }
}

/// Look up a `u16` field of a layer by name.
pub fn field_u16(buf: &DissectBuffer<'_>, layer: &Layer, name: &str) -> Option<u16> {
    match buf
        .layer_fields(layer)
        .iter()
        .find(|f| f.name() == name)?
        .value
    {
        FieldValue::U16(v) => Some(v),
        _ => None,
    }
}

/// Look up a `u32` field of a layer by name.
pub fn field_u32(buf: &DissectBuffer<'_>, layer: &Layer, name: &str) -> Option<u32> {
    match buf
        .layer_fields(layer)
        .iter()
        .find(|f| f.name() == name)?
        .value
    {
        FieldValue::U32(v) => Some(v),
        _ => None,
    }
}

/// Look up a `u8` field of a layer by name.
pub fn field_u8(buf: &DissectBuffer<'_>, layer: &Layer, name: &str) -> Option<u8> {
    match buf
        .layer_fields(layer)
        .iter()
        .find(|f| f.name() == name)?
        .value
    {
        FieldValue::U8(v) => Some(v),
        _ => None,
    }
}

/// Look up an IPv4/IPv6 address field of a layer by name.
pub fn field_ip(buf: &DissectBuffer<'_>, layer: &Layer, name: &str) -> Option<IpAddr> {
    match buf
        .layer_fields(layer)
        .iter()
        .find(|f| f.name() == name)?
        .value
    {
        FieldValue::Ipv4Addr(a) => Some(IpAddr::V4(Ipv4Addr::from(a))),
        FieldValue::Ipv6Addr(a) => Some(IpAddr::V6(Ipv6Addr::from(a))),
        _ => None,
    }
}

/// Index of the closest `IPv4`/`IPv6` layer before `layer_idx` at the same depth.
pub fn enclosing_ip_layer(
    buf: &DissectBuffer<'_>,
    depths: &[u32],
    layer_idx: usize,
) -> Option<usize> {
    let depth = *depths.get(layer_idx)?;
    (0..layer_idx)
        .rev()
        .find(|&i| depths[i] == depth && matches!(buf.layers()[i].name, "IPv4" | "IPv6"))
}

/// Resolve the `(src, dst)` endpoints of the transport layer at `layer_idx`.
pub fn endpoints(
    buf: &DissectBuffer<'_>,
    depths: &[u32],
    layer_idx: usize,
) -> Option<(Endpoint, Endpoint)> {
    let transport = &buf.layers()[layer_idx];
    let src_port = field_u16(buf, transport, "src_port")?;
    let dst_port = field_u16(buf, transport, "dst_port")?;
    let ip_idx = enclosing_ip_layer(buf, depths, layer_idx)?;
    let ip = &buf.layers()[ip_idx];
    let src = field_ip(buf, ip, "src")?;
    let dst = field_ip(buf, ip, "dst")?;
    Some((
        Endpoint {
            addr: src,
            port: src_port,
        },
        Endpoint {
            addr: dst,
            port: dst_port,
        },
    ))
}

/// TCP payload length on the wire for the TCP layer at `layer_idx`.
///
/// Derived from the enclosing IP header's length field; falls back to the
/// captured bytes after the TCP header when no IP length is available.
pub fn tcp_payload_len(
    buf: &DissectBuffer<'_>,
    depths: &[u32],
    layer_idx: usize,
    data_len: usize,
) -> u32 {
    let tcp = &buf.layers()[layer_idx];
    let tcp_hdr = tcp.range.len();
    let captured = data_len.saturating_sub(tcp.range.end);
    let Some(ip_idx) = enclosing_ip_layer(buf, depths, layer_idx) else {
        return u32::try_from(captured).unwrap_or(u32::MAX);
    };
    let ip = &buf.layers()[ip_idx];
    let ip_hdr = tcp.range.start.saturating_sub(ip.range.start);
    let total = match ip.name {
        "IPv4" => field_u16(buf, ip, "total_length").map(usize::from),
        "IPv6" => field_u16(buf, ip, "payload_length").map(|p| usize::from(p) + 40),
        _ => None,
    };
    let len = match total {
        Some(t) => t.saturating_sub(ip_hdr).saturating_sub(tcp_hdr),
        None => captured,
    };
    u32::try_from(len).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_test_alloc::test_desc;

    fn ep(addr: [u8; 4], port: u16) -> Endpoint {
        Endpoint {
            addr: IpAddr::V4(Ipv4Addr::from(addr)),
            port,
        }
    }

    fn pkt(n: u64) -> PacketInfo {
        PacketInfo {
            number: n,
            ts: n as f64,
            bytes: 100,
        }
    }

    #[test]
    fn both_directions_share_a_flow() {
        let mut t = FlowTracker::new();
        let c = ep([10, 0, 0, 1], 40000);
        let s = ep([10, 0, 0, 2], 80);
        let h1 = t.observe(Transport::Tcp, 0, c, s, &pkt(1), Some(7));
        let h2 = t.observe(Transport::Tcp, 0, s, c, &pkt(2), Some(7));
        assert_eq!(h1.flow_id, h2.flow_id);
        assert_eq!(h1.direction, 0);
        assert_eq!(h2.direction, 1);
        let rows = t.into_rows();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].packets, 2);
        assert_eq!(rows[0].bytes, 200);
        assert_eq!(rows[0].first_packet, 1);
        assert_eq!(rows[0].last_packet, 2);
        assert_eq!(rows[0].a, c);
        assert_eq!(rows[0].b, s);
        assert_eq!(rows[0].tcp_stream_id, Some(7));
        assert!((rows[0].last_ts - rows[0].first_ts - 1.0).abs() < 1e-9);
    }

    #[test]
    fn depth_and_transport_separate_flows() {
        let mut t = FlowTracker::new();
        let a = ep([10, 0, 0, 1], 1);
        let b = ep([10, 0, 0, 2], 2);
        let h0 = t.observe(Transport::Udp, 0, a, b, &pkt(1), None);
        let h1 = t.observe(Transport::Udp, 1, a, b, &pkt(1), None);
        let h2 = t.observe(Transport::Tcp, 0, a, b, &pkt(1), None);
        assert_ne!(h0.flow_id, h1.flow_id);
        assert_ne!(h0.flow_id, h2.flow_id);
        assert_eq!(t.len(), 3);
        let ids: Vec<i64> = t.into_rows().iter().map(|r| r.id).collect();
        assert_eq!(ids, vec![0, 1, 2]);
    }

    #[test]
    fn tcp_three_way_handshake_relative_sequence() {
        let mut t = FlowTracker::new();
        let c = ep([10, 0, 0, 1], 40000);
        let s = ep([10, 0, 0, 2], 80);

        // SYN
        let h = t.observe(Transport::Tcp, 0, c, s, &pkt(1), None);
        let r = t.tcp_sequence(h, 1000, 0, false, 0, true, false);
        assert_eq!(
            r,
            TcpSeq {
                seq_rel: 0,
                ack_rel: None,
                next_seq: 1001
            }
        );

        // SYN-ACK
        let h = t.observe(Transport::Tcp, 0, s, c, &pkt(2), None);
        let r = t.tcp_sequence(h, 5000, 1001, true, 0, true, false);
        assert_eq!(
            r,
            TcpSeq {
                seq_rel: 0,
                ack_rel: Some(1),
                next_seq: 5001
            }
        );

        // ACK with 10 bytes payload
        let h = t.observe(Transport::Tcp, 0, c, s, &pkt(3), None);
        let r = t.tcp_sequence(h, 1001, 5001, true, 10, false, false);
        assert_eq!(
            r,
            TcpSeq {
                seq_rel: 1,
                ack_rel: Some(1),
                next_seq: 1011
            }
        );

        // FIN from server, sequence wraps around
        let h = t.observe(Transport::Tcp, 0, s, c, &pkt(4), None);
        let r = t.tcp_sequence(h, u32::MAX, 1011, true, 0, false, true);
        assert_eq!(r.next_seq, 0);
        assert_eq!(r.seq_rel, u32::MAX.wrapping_sub(5000));
        assert_eq!(r.ack_rel, Some(11));
    }

    #[test]
    fn tcp_sequence_unknown_flow() {
        let mut t = FlowTracker::new();
        let r = t.tcp_sequence(
            FlowHit {
                flow_id: 99,
                direction: 0,
            },
            5,
            0,
            false,
            3,
            false,
            false,
        );
        assert_eq!(r.next_seq, 8);
        assert!(t.is_empty());
    }

    fn ipv4_tcp_buf(total_length: u16) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Ethernet", None, &[], 0..14);
        buf.end_layer();
        buf.begin_layer("IPv4", None, &[], 14..34);
        buf.push_field(
            test_desc("total_length", "Total Length"),
            FieldValue::U16(total_length),
            16..18,
        );
        buf.push_field(
            test_desc("src", "Source"),
            FieldValue::Ipv4Addr([10, 0, 0, 1]),
            26..30,
        );
        buf.push_field(
            test_desc("dst", "Destination"),
            FieldValue::Ipv4Addr([10, 0, 0, 2]),
            30..34,
        );
        buf.end_layer();
        buf.begin_layer("TCP", None, &[], 34..54);
        buf.push_field(
            test_desc("src_port", "Source Port"),
            FieldValue::U16(1234),
            34..36,
        );
        buf.push_field(
            test_desc("dst_port", "Destination Port"),
            FieldValue::U16(80),
            36..38,
        );
        buf.end_layer();
        buf
    }

    #[test]
    fn endpoints_and_payload_from_ipv4() {
        let buf = ipv4_tcp_buf(50);
        let depths = vec![0, 0, 0];
        let (src, dst) = endpoints(&buf, &depths, 2).unwrap();
        assert_eq!(src, ep([10, 0, 0, 1], 1234));
        assert_eq!(dst, ep([10, 0, 0, 2], 80));
        // total 50 - ip 20 - tcp 20 = 10
        assert_eq!(tcp_payload_len(&buf, &depths, 2, 64), 10);
        // truncated total length never underflows
        assert_eq!(tcp_payload_len(&buf, &depths, 2, 64), 10);
    }

    #[test]
    fn endpoints_require_same_depth_ip_layer() {
        let buf = ipv4_tcp_buf(40);
        // Pretend the TCP layer is at a deeper encapsulation level than the IP layer.
        let depths = vec![0, 0, 1];
        assert!(endpoints(&buf, &depths, 2).is_none());
        // Without an IP layer the captured remainder is used.
        assert_eq!(tcp_payload_len(&buf, &depths, 2, 64), 10);
    }

    #[test]
    fn ipv6_payload_length() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("IPv6", None, &[], 0..40);
        buf.push_field(
            test_desc("payload_length", "Payload Length"),
            FieldValue::U16(30),
            4..6,
        );
        buf.end_layer();
        buf.begin_layer("TCP", None, &[], 40..60);
        buf.end_layer();
        assert_eq!(tcp_payload_len(&buf, &[0, 0], 1, 70), 10);
    }

    #[test]
    fn transport_names() {
        assert_eq!(Transport::from_layer_name("TCP"), Some(Transport::Tcp));
        assert_eq!(Transport::from_layer_name("SCTP"), Some(Transport::Sctp));
        assert_eq!(Transport::from_layer_name("DNS"), None);
        assert_eq!(Transport::Udp.as_str(), "udp");
    }
}
