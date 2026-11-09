//! Who talks to whom: the hosts of the displayed packets and the traffic
//! between each pair of them, by the protocol it carries.
//!
//! Each packet is counted twice: by its innermost IP addresses, and by its
//! outermost ones (the tunnel endpoints of a GTP-U or VXLAN packet; the same
//! as the innermost for an untunneled packet). [`HostGraph::top`] picks the
//! busiest hosts to draw and, for each, how many of its peers are left out.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;

/// Hosts tracked at most per graph; packets of further hosts are only
/// counted (see [`HostGraph::untracked_packets`]).
const MAX_HOSTS: usize = 100_000;
/// Host pairs (per protocol) tracked at most per graph.
const MAX_LINKS: usize = 500_000;

/// Which IP addresses of a packet name its hosts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum AddressLayer {
    /// The innermost IP layer: the hosts of the packet itself.
    #[default]
    Inner,
    /// The outermost IP layer: the tunnel endpoints that carry it.
    Outer,
}

/// What ranks hosts and sizes them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum Measure {
    #[default]
    Packets,
    Bytes,
}

/// One host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Host {
    pub addr: IpAddr,
    /// Packets sent or received.
    pub packets: u64,
    /// Bytes on the wire (original lengths) sent or received.
    pub bytes: u64,
}

impl Host {
    /// The amount of `measure`.
    pub fn amount(&self, measure: Measure) -> u64 {
        match measure {
            Measure::Packets => self.packets,
            Measure::Bytes => self.bytes,
        }
    }
}

/// The traffic between two hosts that carries one protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    /// The lower address.
    pub a: IpAddr,
    /// The higher address.
    pub b: IpAddr,
    /// The protocol over the IP layer's transport (`"SIP"`, `"GTP-U"`), or
    /// the transport (`"TCP"`) or the layer over IP (`"ICMPv6"`) when
    /// nothing is above it.
    pub protocol: &'static str,
    pub packets: u64,
    pub bytes: u64,
    /// Index of the first packet.
    pub first_packet: usize,
}

impl Link {
    /// The amount of `measure`.
    pub fn amount(&self, measure: Measure) -> u64 {
        match measure {
            Measure::Packets => self.packets,
            Measure::Bytes => self.bytes,
        }
    }

    /// The other end of the link from `addr`.
    pub fn peer(&self, addr: IpAddr) -> IpAddr {
        if self.a == addr { self.b } else { self.a }
    }
}

/// The hosts and links of a set of packets, by one [`AddressLayer`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostGraph {
    /// Most packets first.
    pub hosts: Vec<Host>,
    /// Most packets first.
    pub links: Vec<Link>,
    /// Packets between hosts past the first [`MAX_HOSTS`] or of links
    /// past the first [`MAX_LINKS`].
    pub untracked_packets: u64,
}

/// A host to draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrawnHost {
    /// Index into [`HostGraph::hosts`].
    pub host: usize,
    /// Peers of the host that are not drawn.
    pub hidden_peers: usize,
}

/// The part of a [`HostGraph`] to draw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GraphView {
    /// The busiest hosts first, then the ones asked for.
    pub hosts: Vec<DrawnHost>,
    /// Indices into [`HostGraph::links`] with both ends drawn.
    pub links: Vec<usize>,
    /// Hosts not drawn.
    pub hidden_hosts: usize,
    /// Packets of links with an end not drawn.
    pub hidden_packets: u64,
}

/// A peer of a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub addr: IpAddr,
    /// Index into [`HostGraph::links`].
    pub link: usize,
}

impl HostGraph {
    /// The `top` busiest hosts by `measure`, plus `extra` (hosts the user
    /// asked to see), and the links between them.
    pub fn top(&self, top: usize, measure: Measure, extra: &[IpAddr]) -> GraphView {
        let mut ranked: Vec<usize> = (0..self.hosts.len()).collect();
        // Stable: equal amounts keep the packet order.
        ranked.sort_by_key(|&i| std::cmp::Reverse(self.hosts[i].amount(measure)));
        ranked.truncate(top);
        for addr in extra {
            if let Some(i) = self.hosts.iter().position(|h| h.addr == *addr)
                && !ranked.contains(&i)
            {
                ranked.push(i);
            }
        }
        let drawn: HashMap<IpAddr, usize> = ranked
            .iter()
            .enumerate()
            .map(|(slot, &i)| (self.hosts[i].addr, slot))
            .collect();

        let mut view = GraphView {
            hosts: ranked
                .iter()
                .map(|&host| DrawnHost {
                    host,
                    hidden_peers: 0,
                })
                .collect(),
            hidden_hosts: self.hosts.len() - ranked.len(),
            ..GraphView::default()
        };
        // A peer reached over two protocols is still one peer.
        let mut hidden: HashSet<(usize, IpAddr)> = HashSet::new();
        for (i, link) in self.links.iter().enumerate() {
            match (drawn.get(&link.a), drawn.get(&link.b)) {
                (Some(_), Some(_)) => view.links.push(i),
                (Some(&slot), None) => {
                    view.hidden_packets += link.packets;
                    hidden.insert((slot, link.b));
                }
                (None, Some(&slot)) => {
                    view.hidden_packets += link.packets;
                    hidden.insert((slot, link.a));
                }
                (None, None) => view.hidden_packets += link.packets,
            }
        }
        for (slot, _) in hidden {
            view.hosts[slot].hidden_peers += 1;
        }
        view
    }

    /// The links of `addr`, the busiest by `measure` first.
    pub fn peers(&self, addr: IpAddr, measure: Measure) -> Vec<Peer> {
        let mut peers: Vec<Peer> = self
            .links
            .iter()
            .enumerate()
            .filter(|(_, l)| l.a == addr || l.b == addr)
            .map(|(link, l)| Peer {
                addr: l.peer(addr),
                link,
            })
            .collect();
        peers.sort_by_key(|p| std::cmp::Reverse(self.links[p.link].amount(measure)));
        peers
    }

    /// The host at `addr`.
    pub fn host(&self, addr: IpAddr) -> Option<&Host> {
        self.hosts.iter().find(|h| h.addr == addr)
    }
}

/// The hosts of the displayed packets by both address layers.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostGraphs {
    pub inner: HostGraph,
    pub outer: HostGraph,
    /// Whether any packet is tunneled (its layers differ).
    pub tunneled: bool,
    /// Packets without IP addresses.
    pub no_ip_packets: u64,
}

impl HostGraphs {
    /// The graph by `layer`.
    pub fn get(&self, layer: AddressLayer) -> &HostGraph {
        match layer {
            AddressLayer::Inner => &self.inner,
            AddressLayer::Outer => &self.outer,
        }
    }
}

/// A display filter for the packets of host `addr`, at any IP layer.
pub fn host_filter(addr: IpAddr) -> String {
    let family = family(addr);
    format!("{family}.src = '{addr}' or {family}.dst = '{addr}'")
}

/// A display filter for the packets between hosts `a` and `b`.
pub fn pair_filter(a: IpAddr, b: IpAddr) -> String {
    let family = family(a);
    format!(
        "({family}.src = '{a}' and {family}.dst = '{b}') or ({family}.src = '{b}' and {family}.dst = '{a}')"
    )
}

fn family(addr: IpAddr) -> &'static str {
    match addr {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

/// Collects one [`HostGraph`].
#[derive(Default)]
struct GraphCollector {
    hosts: HashMap<IpAddr, usize>,
    links: HashMap<(IpAddr, IpAddr, &'static str), usize>,
    graph: HostGraph,
}

impl GraphCollector {
    fn add(&mut self, hop: Hop, pkt_idx: usize, len: u64) {
        let (a, b) = if hop.src <= hop.dst {
            (hop.src, hop.dst)
        } else {
            (hop.dst, hop.src)
        };
        let key = (a, b, hop.protocol);
        let new_hosts = [a, b]
            .iter()
            .filter(|addr| !self.hosts.contains_key(addr))
            .count();
        let link = match self.links.get(&key) {
            Some(&i) => i,
            None if self.graph.links.len() >= MAX_LINKS
                || self.graph.hosts.len() + new_hosts > MAX_HOSTS =>
            {
                self.graph.untracked_packets += 1;
                return;
            }
            None => {
                self.graph.links.push(Link {
                    a,
                    b,
                    protocol: hop.protocol,
                    packets: 0,
                    bytes: 0,
                    first_packet: pkt_idx,
                });
                self.links.insert(key, self.graph.links.len() - 1);
                self.graph.links.len() - 1
            }
        };
        let l = &mut self.graph.links[link];
        l.packets += 1;
        l.bytes += len;
        // A packet to itself counts once.
        let ends: &[IpAddr] = if a == b { &[a] } else { &[a, b] };
        for &addr in ends {
            let next = self.graph.hosts.len();
            let i = *self.hosts.entry(addr).or_insert(next);
            if i == next {
                self.graph.hosts.push(Host {
                    addr,
                    packets: 0,
                    bytes: 0,
                });
            }
            let h = &mut self.graph.hosts[i];
            h.packets += 1;
            h.bytes += len;
        }
    }

    fn finish(self) -> HostGraph {
        let mut graph = self.graph;
        graph.hosts.sort_by_key(|h| std::cmp::Reverse(h.packets));
        graph.links.sort_by_key(|l| std::cmp::Reverse(l.packets));
        graph
    }
}

/// Groups packets by host, at both address layers.
#[derive(Default)]
pub(crate) struct HostCollector {
    inner: GraphCollector,
    outer: GraphCollector,
    tunneled: bool,
    no_ip_packets: u64,
}

impl HostCollector {
    /// Count `packet` (index `pkt_idx`, `len` bytes on the wire).
    pub(crate) fn add(&mut self, packet: &Packet<'_, '_>, pkt_idx: usize, len: u64) {
        let Some((outer, inner)) = hops(packet) else {
            self.no_ip_packets += 1;
            return;
        };
        if outer != inner {
            self.tunneled = true;
        }
        self.inner.add(inner, pkt_idx, len);
        self.outer.add(outer, pkt_idx, len);
    }

    pub(crate) fn finish(self) -> HostGraphs {
        HostGraphs {
            inner: self.inner.finish(),
            outer: self.outer.finish(),
            tunneled: self.tunneled,
            no_ip_packets: self.no_ip_packets,
        }
    }
}

/// The two hosts of one IP layer and what it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Hop {
    src: IpAddr,
    dst: IpAddr,
    protocol: &'static str,
}

/// The outermost and innermost IP layers of `packet` with both addresses.
fn hops(packet: &Packet<'_, '_>) -> Option<(Hop, Hop)> {
    let layers = packet.layers();
    let mut found = layers.iter().enumerate().filter_map(|(i, layer)| {
        if !matches!(layer.name, "IPv4" | "IPv6") {
            return None;
        }
        let addr = |name| match packet.field_by_name(layer, name).map(|f| &f.value) {
            Some(FieldValue::Ipv4Addr(a)) => Some(IpAddr::from(*a)),
            Some(FieldValue::Ipv6Addr(a)) => Some(IpAddr::from(*a)),
            _ => None,
        };
        let (src, dst) = addr("src").zip(addr("dst"))?;
        let above = layers.get(i + 1).map(|l| l.name);
        let protocol = match above {
            // The protocol over the transport, if any.
            Some(t @ ("TCP" | "UDP" | "SCTP")) => match layers.get(i + 2).map(|l| l.name) {
                Some(p) if !matches!(p, "IPv4" | "IPv6") => p,
                _ => t,
            },
            Some(p) if !matches!(p, "IPv4" | "IPv6") => p,
            _ => layer.name,
        };
        Some(Hop { src, dst, protocol })
    });
    let outer = found.next()?;
    let inner = found.next_back().unwrap_or(outer);
    Some((outer, inner))
}

#[cfg(test)]
mod tests {
    use packet_dissector::registry::DissectorRegistry;
    use packet_dissector_core::packet::DissectBuffer;

    use super::*;
    use crate::test_fixtures;

    fn collect(frames: &[Vec<u8>]) -> HostGraphs {
        let registry = DissectorRegistry::default();
        let mut collector = HostCollector::default();
        for (i, frame) in frames.iter().enumerate() {
            let mut buf = DissectBuffer::new();
            let _ = registry.dissect(frame, &mut buf);
            collector.add(&Packet::new(&buf, frame), i, frame.len() as u64);
        }
        collector.finish()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn link(a: &str, b: &str, protocol: &'static str, packets: u64) -> Link {
        Link {
            a: ip(a),
            b: ip(b),
            protocol,
            packets,
            bytes: packets,
            first_packet: 0,
        }
    }

    fn host(addr: &str, packets: u64) -> Host {
        Host {
            addr: ip(addr),
            packets,
            bytes: packets,
        }
    }

    #[test]
    fn links_are_named_by_the_protocol_over_the_transport() {
        let graphs = collect(&[
            test_fixtures::sip_options_udp_frame(),
            test_fixtures::dns_edns_query_frame(),
            test_fixtures::dns_edns_query_frame(),
        ]);
        assert!(!graphs.tunneled);
        assert_eq!(graphs.inner, graphs.outer);
        let g = &graphs.inner;
        let protocols: Vec<_> = g.links.iter().map(|l| (l.protocol, l.packets)).collect();
        assert_eq!(protocols, [("DNS", 2), ("SIP", 1)]);
        assert_eq!(g.links[0].first_packet, 1);
        let dns = test_fixtures::dns_edns_query_frame().len() as u64;
        assert_eq!(g.links[0].bytes, 2 * dns);
        assert_eq!(g.hosts.len(), 2);
        assert_eq!(g.hosts[0].packets, 3);
    }

    #[test]
    fn a_tunneled_packet_has_inner_and_outer_hosts() {
        let graphs = collect(&[test_fixtures::gtpu_icmp_frame()]);
        assert!(graphs.tunneled);
        let inner = &graphs.inner.links[0];
        assert_eq!((inner.a, inner.b), (ip("192.168.0.1"), ip("192.168.0.2")));
        assert_eq!(inner.protocol, "ICMP");
        let outer = &graphs.outer.links[0];
        assert_eq!((outer.a, outer.b), (ip("10.0.0.1"), ip("10.0.0.2")));
        assert_eq!(outer.protocol, "GTPv1-U");
    }

    #[test]
    fn packets_without_ip_are_counted_apart() {
        let graphs = collect(&[vec![0u8; 14]]);
        assert_eq!(graphs.no_ip_packets, 1);
        assert!(graphs.inner.hosts.is_empty());
    }

    fn sample() -> HostGraph {
        // 10.0.0.1 talks to 2 and 3; 2 to 4 over two protocols.
        HostGraph {
            hosts: vec![
                host("10.0.0.1", 9),
                host("10.0.0.2", 8),
                host("10.0.0.3", 4),
                host("10.0.0.4", 3),
            ],
            links: vec![
                link("10.0.0.1", "10.0.0.2", "SIP", 5),
                link("10.0.0.1", "10.0.0.3", "DNS", 4),
                link("10.0.0.2", "10.0.0.4", "SIP", 2),
                link("10.0.0.2", "10.0.0.4", "RTP", 1),
            ],
            untracked_packets: 0,
        }
    }

    #[test]
    fn the_top_hosts_count_their_peers_not_drawn() {
        let g = sample();
        let view = g.top(2, Measure::Packets, &[]);
        assert_eq!(
            view.hosts,
            [
                DrawnHost {
                    host: 0,
                    hidden_peers: 1
                },
                // Two links to 10.0.0.4 make one peer.
                DrawnHost {
                    host: 1,
                    hidden_peers: 1
                },
            ]
        );
        assert_eq!(view.links, [0]);
        assert_eq!(view.hidden_hosts, 2);
        assert_eq!(view.hidden_packets, 7);

        // A host asked for is drawn too.
        let view = g.top(2, Measure::Packets, &[ip("10.0.0.4"), ip("10.0.0.1")]);
        assert_eq!(view.hosts.len(), 3);
        assert_eq!(view.hosts[2].host, 3);
        assert_eq!(view.hosts[1].hidden_peers, 0);
        assert_eq!(view.links, [0, 2, 3]);
        assert_eq!(view.hidden_hosts, 1);

        let all = g.top(usize::MAX, Measure::Packets, &[]);
        assert_eq!(all.hidden_hosts, 0);
        assert_eq!(all.hidden_packets, 0);
        assert!(all.hosts.iter().all(|h| h.hidden_peers == 0));
    }

    #[test]
    fn hosts_rank_by_the_measure() {
        let mut g = sample();
        g.hosts[3].bytes = 1_000;
        let view = g.top(1, Measure::Bytes, &[]);
        assert_eq!(view.hosts[0].host, 3);
    }

    #[test]
    fn peers_come_busiest_first() {
        let g = sample();
        let peers = g.peers(ip("10.0.0.2"), Measure::Packets);
        let got: Vec<_> = peers
            .iter()
            .map(|p| (p.addr, g.links[p.link].protocol))
            .collect();
        assert_eq!(
            got,
            [
                (ip("10.0.0.1"), "SIP"),
                (ip("10.0.0.4"), "SIP"),
                (ip("10.0.0.4"), "RTP")
            ]
        );
        assert_eq!(g.host(ip("10.0.0.3")).map(|h| h.packets), Some(4));
    }

    #[test]
    fn filters_name_a_host_or_a_pair() {
        assert_eq!(
            host_filter(ip("2001:db8::1")),
            "ipv6.src = '2001:db8::1' or ipv6.dst = '2001:db8::1'"
        );
        assert_eq!(
            pair_filter(ip("10.0.0.1"), ip("10.0.0.2")),
            "(ipv4.src = '10.0.0.1' and ipv4.dst = '10.0.0.2') or (ipv4.src = '10.0.0.2' and ipv4.dst = '10.0.0.1')"
        );
    }
}
