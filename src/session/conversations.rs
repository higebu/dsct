//! Conversations: the displayed packets grouped by the innermost transport
//! flow they carry (TCP, UDP or SCTP between two address and port pairs),
//! both directions together.

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;

/// Conversations tracked at most; packets of further flows are only
/// counted (see [`Conversations::untracked_packets`]).
const MAX_CONVERSATIONS: usize = 50_000;

/// One end of a conversation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Endpoint {
    pub addr: IpAddr,
    pub port: u16,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.addr {
            IpAddr::V4(a) => write!(f, "{a}:{}", self.port),
            IpAddr::V6(a) => write!(f, "[{a}]:{}", self.port),
        }
    }
}

/// The packets exchanged between two endpoints over one transport.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    /// Transport protocol short name (`"TCP"`, `"UDP"` or `"SCTP"`).
    pub transport: &'static str,
    /// The lower endpoint.
    pub a: Endpoint,
    /// The higher endpoint.
    pub b: Endpoint,
    /// Packets in either direction.
    pub packets: u64,
    /// Bytes on the wire (original lengths) in either direction.
    pub bytes: u64,
    /// Time of the first packet, in microseconds since the Unix epoch.
    pub first_us: u64,
    /// Time of the last packet, in microseconds since the Unix epoch.
    pub last_us: u64,
    /// Index of the first packet.
    pub first_packet: usize,
}

impl Conversation {
    /// A display filter matching the conversation's packets in both
    /// directions.
    pub fn filter(&self) -> String {
        let family = match self.a.addr {
            IpAddr::V4(_) => "ipv4",
            IpAddr::V6(_) => "ipv6",
        };
        let transport = self.transport.to_lowercase();
        let side = |src: &Endpoint, dst: &Endpoint| {
            format!(
                "({family}.src = '{}' and {transport}.src_port = {} and {family}.dst = '{}' and {transport}.dst_port = {})",
                src.addr, src.port, dst.addr, dst.port
            )
        };
        format!("{} or {}", side(&self.a, &self.b), side(&self.b, &self.a))
    }

    /// Seconds from the first packet to the last.
    pub fn duration_secs(&self) -> f64 {
        (self.last_us - self.first_us) as f64 / 1e6
    }
}

/// The conversations of a set of packets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Conversations {
    /// Most packets first.
    pub list: Vec<Conversation>,
    /// Packets of flows past the first [`MAX_CONVERSATIONS`].
    pub untracked_packets: u64,
}

type Key = (&'static str, Endpoint, Endpoint);

/// Groups packets into conversations.
#[derive(Default)]
pub(crate) struct ConversationCollector {
    index: HashMap<Key, usize>,
    list: Vec<Conversation>,
    untracked_packets: u64,
}

impl ConversationCollector {
    /// Count `packet` (index `pkt_idx`, captured at `time_us`, `len` bytes
    /// on the wire) in its innermost transport flow, if it has one.
    pub(crate) fn add(&mut self, packet: &Packet<'_, '_>, pkt_idx: usize, time_us: u64, len: u64) {
        let Some((transport, src, dst)) = innermost_flow(packet) else {
            return;
        };
        let (a, b) = if src <= dst { (src, dst) } else { (dst, src) };
        let key = (transport, a, b);
        let i = match self.index.get(&key) {
            Some(&i) => i,
            None if self.list.len() >= MAX_CONVERSATIONS => {
                self.untracked_packets += 1;
                return;
            }
            None => {
                self.list.push(Conversation {
                    transport,
                    a,
                    b,
                    packets: 0,
                    bytes: 0,
                    first_us: time_us,
                    last_us: time_us,
                    first_packet: pkt_idx,
                });
                self.index.insert(key, self.list.len() - 1);
                self.list.len() - 1
            }
        };
        let c = &mut self.list[i];
        c.packets += 1;
        c.bytes += len;
        c.first_us = c.first_us.min(time_us);
        c.last_us = c.last_us.max(time_us);
    }

    pub(crate) fn finish(self) -> Conversations {
        let mut list = self.list;
        // Stable: equal counts keep the order they were seen in.
        list.sort_by_key(|c| std::cmp::Reverse(c.packets));
        Conversations {
            list,
            untracked_packets: self.untracked_packets,
        }
    }
}

/// The transport layer of the innermost IP layer, with its two endpoints
/// (source first). A flow that carries another IP layer (a GTP-U or VXLAN
/// tunnel) is not the packet's own: without a transport layer over the
/// innermost IP layer, the packet has no flow.
pub(crate) fn innermost_flow(
    packet: &Packet<'_, '_>,
) -> Option<(&'static str, Endpoint, Endpoint)> {
    let mut addrs: Option<(IpAddr, IpAddr)> = None;
    let mut flow = None;
    for layer in packet.layers() {
        match layer.name {
            "IPv4" | "IPv6" => {
                let addr = |name| match packet.field_by_name(layer, name).map(|f| &f.value) {
                    Some(FieldValue::Ipv4Addr(a)) => Some(IpAddr::from(*a)),
                    Some(FieldValue::Ipv6Addr(a)) => Some(IpAddr::from(*a)),
                    _ => None,
                };
                addrs = addr("src").zip(addr("dst"));
                flow = None;
            }
            transport @ ("TCP" | "UDP" | "SCTP") => {
                let Some((src, dst)) = addrs else {
                    continue;
                };
                let ports = packet
                    .field_u16(layer, "src_port")
                    .zip(packet.field_u16(layer, "dst_port"));
                if let Some((sport, dport)) = ports {
                    flow = Some((
                        transport,
                        Endpoint {
                            addr: src,
                            port: sport,
                        },
                        Endpoint {
                            addr: dst,
                            port: dport,
                        },
                    ));
                }
            }
            _ => {}
        }
    }
    flow
}

#[cfg(test)]
mod tests {
    use packet_dissector::registry::DissectorRegistry;
    use packet_dissector_core::packet::DissectBuffer;

    use super::*;
    use crate::test_fixtures;

    fn add(collector: &mut ConversationCollector, frame: &[u8], pkt_idx: usize, time_us: u64) {
        let registry = DissectorRegistry::default();
        let mut buf = DissectBuffer::new();
        let _ = registry.dissect(frame, &mut buf);
        collector.add(
            &Packet::new(&buf, frame),
            pkt_idx,
            time_us,
            frame.len() as u64,
        );
    }

    #[test]
    fn packets_group_by_flow_in_both_directions() {
        let dns = test_fixtures::dns_edns_query_frame();
        let sip = test_fixtures::sip_options_udp_frame();
        let mut collector = ConversationCollector::default();
        add(&mut collector, &sip, 0, 1_000);
        add(&mut collector, &dns, 1, 2_000);
        add(&mut collector, &dns, 2, 5_000);
        let convs = collector.finish();
        assert_eq!(convs.untracked_packets, 0);
        assert_eq!(convs.list.len(), 2);

        // Most packets first.
        let dns_conv = &convs.list[0];
        assert_eq!(dns_conv.transport, "UDP");
        assert_eq!(dns_conv.a.to_string(), "10.0.0.1:12345");
        assert_eq!(dns_conv.b.to_string(), "10.0.0.2:53");
        assert_eq!(dns_conv.packets, 2);
        assert_eq!(dns_conv.bytes, 2 * dns.len() as u64);
        assert_eq!((dns_conv.first_us, dns_conv.last_us), (2_000, 5_000));
        assert_eq!(dns_conv.first_packet, 1);
        assert!((dns_conv.duration_secs() - 0.003).abs() < 1e-9);
        assert_eq!(convs.list[1].first_packet, 0);
    }

    #[test]
    fn a_conversation_filters_for_both_directions() {
        let c = Conversation {
            transport: "TCP",
            a: Endpoint {
                addr: "10.0.0.1".parse().unwrap(),
                port: 50000,
            },
            b: Endpoint {
                addr: "10.0.0.2".parse().unwrap(),
                port: 80,
            },
            packets: 1,
            bytes: 1,
            first_us: 0,
            last_us: 0,
            first_packet: 0,
        };
        assert_eq!(
            c.filter(),
            "(ipv4.src = '10.0.0.1' and tcp.src_port = 50000 and ipv4.dst = '10.0.0.2' and tcp.dst_port = 80) \
             or (ipv4.src = '10.0.0.2' and tcp.src_port = 80 and ipv4.dst = '10.0.0.1' and tcp.dst_port = 50000)"
        );
        let v6 = Endpoint {
            addr: "2001:db8::1".parse().unwrap(),
            port: 5060,
        };
        assert_eq!(v6.to_string(), "[2001:db8::1]:5060");
    }

    #[test]
    fn packets_without_a_transport_flow_are_skipped() {
        let mut collector = ConversationCollector::default();
        add(&mut collector, &[0u8; 14], 0, 0);
        assert!(collector.finish().list.is_empty());
    }
}
