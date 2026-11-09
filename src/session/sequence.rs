//! Sequences: the packets that belong together with a given one, at a
//! chosen grain: its call or transaction (a SIP Call-ID, a DNS
//! transaction), its stream or flow (a TCP stream, a UDP or SCTP flow), or
//! the two hosts talking.
//!
//! [`Session::start_sequence`] scans the displayed packets for one, in
//! chunks driven by [`Session::sequence_tick`], with the in-order results so
//! that keys built from state kept across packets (TCP stream numbers)
//! match the ones the packet list shows.

use std::net::IpAddr;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;

use super::conversations::{Endpoint, innermost_flow};
use super::fields::for_each_value;
use super::{Session, Tick, ordered_pass};

/// How finely packets are grouped into a sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SequenceUnit {
    /// One call or transaction: a SIP Call-ID, a DNS transaction.
    Call,
    /// One TCP stream, or one UDP or SCTP flow.
    Stream,
    /// Everything between two hosts.
    Hosts,
}

impl SequenceUnit {
    /// From the finest grain to the coarsest.
    pub const ALL: [SequenceUnit; 3] = [Self::Call, Self::Stream, Self::Hosts];
}

/// A transport flow, the lower endpoint first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Flow {
    pub transport: &'static str,
    pub a: Endpoint,
    pub b: Endpoint,
}

impl Flow {
    pub(crate) fn new(transport: &'static str, src: Endpoint, dst: Endpoint) -> Self {
        let (a, b) = if src <= dst { (src, dst) } else { (dst, src) };
        Self { transport, a, b }
    }

    fn filter(&self) -> String {
        let family = family(self.a.addr);
        let transport = self.transport.to_lowercase();
        let side = |src: &Endpoint, dst: &Endpoint| {
            format!(
                "({family}.src = '{}' and {transport}.src_port = {} and {family}.dst = '{}' and {transport}.dst_port = {})",
                src.addr, src.port, dst.addr, dst.port
            )
        };
        format!("{} or {}", side(&self.a, &self.b), side(&self.b, &self.a))
    }
}

/// What the packets of one sequence share.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SequenceKey {
    /// A SIP dialog or transaction, by its Call-ID header.
    SipCall(String),
    /// A DNS query and its response: the same ID in the same flow.
    DnsTransaction { id: u16, flow: Flow },
    /// A TCP stream, by its stream number.
    TcpStream(u32),
    /// A UDP or SCTP flow.
    Flow(Flow),
    /// Two hosts, the lower address first.
    Hosts(IpAddr, IpAddr),
}

impl SequenceKey {
    /// The grain of the key.
    pub fn unit(&self) -> SequenceUnit {
        match self {
            Self::SipCall(_) | Self::DnsTransaction { .. } => SequenceUnit::Call,
            Self::TcpStream(_) | Self::Flow(_) => SequenceUnit::Stream,
            Self::Hosts(..) => SequenceUnit::Hosts,
        }
    }

    /// A short name for the sequence (`"SIP call 1234@host"`).
    pub fn label(&self) -> String {
        match self {
            Self::SipCall(id) => format!("SIP call {id}"),
            Self::DnsTransaction { id, .. } => format!("DNS transaction 0x{id:04x}"),
            Self::TcpStream(n) => format!("TCP stream {n}"),
            Self::Flow(f) => format!("{} {} ↔ {}", f.transport, f.a, f.b),
            Self::Hosts(a, b) => format!("Hosts {a} ↔ {b}"),
        }
    }

    /// A display filter for the sequence's packets.
    pub fn filter(&self) -> String {
        match self {
            Self::SipCall(id) => format!("sip.headers.value = '{}'", id.replace('\'', "''")),
            Self::DnsTransaction { id, flow } => format!("dns.id = {id} and ({})", flow.filter()),
            Self::TcpStream(n) => format!("tcp.stream_id = {n}"),
            Self::Flow(f) => f.filter(),
            Self::Hosts(a, b) => {
                let family = family(*a);
                format!(
                    "({family}.src = '{a}' and {family}.dst = '{b}') or ({family}.src = '{b}' and {family}.dst = '{a}')"
                )
            }
        }
    }
}

fn family(addr: IpAddr) -> &'static str {
    match addr {
        IpAddr::V4(_) => "ipv4",
        IpAddr::V6(_) => "ipv6",
    }
}

/// The sequences one packet belongs to, one per grain it has.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SequenceKeys {
    pub call: Option<SequenceKey>,
    pub stream: Option<SequenceKey>,
    pub hosts: Option<SequenceKey>,
}

impl SequenceKeys {
    /// The key at grain `unit`.
    pub fn get(&self, unit: SequenceUnit) -> Option<&SequenceKey> {
        match unit {
            SequenceUnit::Call => self.call.as_ref(),
            SequenceUnit::Stream => self.stream.as_ref(),
            SequenceUnit::Hosts => self.hosts.as_ref(),
        }
    }

    /// The key at grain `unit`, or the next coarser one the packet has, or
    /// else the finest it has.
    pub fn at_or_coarser(&self, unit: SequenceUnit) -> Option<&SequenceKey> {
        let from = SequenceUnit::ALL
            .iter()
            .position(|&u| u == unit)
            .unwrap_or(0);
        SequenceUnit::ALL[from..]
            .iter()
            .chain(SequenceUnit::ALL[..from].iter().rev())
            .find_map(|&u| self.get(u))
    }

    /// Whether `key` is one of these.
    pub fn contains(&self, key: &SequenceKey) -> bool {
        self.get(key.unit()) == Some(key)
    }
}

/// The keys of a dissected packet.
pub fn keys_of(packet: &Packet<'_, '_>) -> SequenceKeys {
    let mut keys = SequenceKeys::default();
    let flow = innermost_flow(packet).map(|(t, src, dst)| Flow::new(t, src, dst));

    // The innermost IP layer gives the hosts.
    let mut hosts = None;
    for layer in packet.layers() {
        if matches!(layer.name, "IPv4" | "IPv6") {
            let addr = |name| match packet.field_by_name(layer, name).map(|f| &f.value) {
                Some(FieldValue::Ipv4Addr(a)) => Some(IpAddr::from(*a)),
                Some(FieldValue::Ipv6Addr(a)) => Some(IpAddr::from(*a)),
                _ => None,
            };
            if let (Some(src), Some(dst)) = (addr("src"), addr("dst")) {
                hosts = Some(if src <= dst { (src, dst) } else { (dst, src) });
            }
        }
    }
    keys.hosts = hosts.map(|(a, b)| SequenceKey::Hosts(a, b));

    let stream_id = packet
        .layers()
        .iter()
        .rev()
        .find(|l| l.name == "TCP")
        .and_then(|l| packet.field_u32(l, "stream_id"));
    keys.stream = match (stream_id, flow) {
        (Some(n), _) => Some(SequenceKey::TcpStream(n)),
        (None, Some(f)) if f.transport != "TCP" => Some(SequenceKey::Flow(f)),
        _ => None,
    };

    // RFC 3261, Section 20.8: Call-ID, compact form "i".
    let mut call_id = None;
    let mut next_is_call_id = false;
    let has_sip = packet.layers().iter().any(|l| l.name == "SIP");
    for_each_value_if(has_sip, packet, |v| match v.path {
        "sip.headers.name" => {
            next_is_call_id = v.value.eq_ignore_ascii_case("call-id") || v.value == "i";
        }
        "sip.headers.value" if next_is_call_id => {
            call_id.get_or_insert_with(|| v.value.trim().to_string());
            next_is_call_id = false;
        }
        _ => {}
    });
    keys.call = match call_id {
        Some(id) => Some(SequenceKey::SipCall(id)),
        None => packet
            .layer_by_name("DNS")
            .and_then(|l| packet.field_u16(l, "id"))
            .zip(flow)
            .map(|(id, flow)| SequenceKey::DnsTransaction { id, flow }),
    };
    keys
}

/// [`for_each_value`] over `packet` when `wanted`: walking every field is
/// only worth it for the packets that may hold the value looked for.
fn for_each_value_if(
    wanted: bool,
    packet: &Packet<'_, '_>,
    visit: impl FnMut(super::fields::FieldValueRef<'_>),
) {
    if wanted {
        for_each_value(packet, visit);
    }
}

/// Rows scanned per [`Session::sequence_tick`].
const SEQUENCE_CHUNK: usize = 5_000;

/// The sequence being highlighted, and how far the displayed packets have
/// been scanned for it.
#[derive(Debug, Clone)]
pub struct SequenceScan {
    pub key: SequenceKey,
    /// Displayed rows checked so far, from the first.
    pub scanned: usize,
    /// Indices of the packets found so far, in capture order.
    pub members: Vec<usize>,
    /// Counts the scans started, so that results built from an earlier
    /// scan can tell they are stale.
    pub generation: u64,
}

impl SequenceScan {
    /// Whether every displayed packet has been checked.
    pub fn complete(&self, displayed: usize) -> bool {
        self.scanned >= displayed
    }

    /// Whether packet `pkt_idx`, at displayed `row`, is in the sequence;
    /// `None` until its row has been checked.
    pub fn contains(&self, row: usize, pkt_idx: usize) -> Option<bool> {
        (row < self.scanned).then(|| self.members.binary_search(&pkt_idx).is_ok())
    }
}

impl Session {
    /// The sequences packet `pkt_idx` belongs to; `None` while it waits
    /// for the in-order pass.
    pub fn sequence_keys(&self, pkt_idx: usize) -> Option<SequenceKeys> {
        let index = self.indices.get(pkt_idx)?;
        let data = self.capture.packet_data(index)?;
        ordered_pass::with_packet(
            &self.registry,
            self.ordered.as_ref(),
            pkt_idx,
            data,
            u32::from(index.link_type),
            |packet| packet.map(|(p, _)| keys_of(&p)),
        )
    }

    /// Scan the displayed packets for the sequence `key`, replacing the
    /// one scanned before.
    pub fn start_sequence(&mut self, key: SequenceKey) {
        self.sequence_generation += 1;
        self.sequence = Some(SequenceScan {
            key,
            scanned: 0,
            members: Vec::new(),
            generation: self.sequence_generation,
        });
    }

    /// Stop highlighting a sequence.
    pub fn clear_sequence(&mut self) {
        self.sequence = None;
    }

    /// Check the next displayed packets for the sequence. `Running` while
    /// rows are left (or the next one waits for the in-order pass), `Done`
    /// once all were checked, `Idle` without a sequence or when done.
    pub fn sequence_tick(&mut self) -> Tick<()> {
        let displayed = self.filtered.count_ones();
        let Some(scan) = &self.sequence else {
            return Tick::Idle;
        };
        if scan.complete(displayed) {
            return Tick::Idle;
        }
        let (key, from) = (scan.key.clone(), scan.scanned);
        let end = (from + SEQUENCE_CHUNK).min(displayed);
        let mut found = Vec::new();
        let mut scanned = from;
        for pkt_idx in self.filtered.iter_from(from).take(end - from) {
            match self.sequence_keys(pkt_idx) {
                Some(keys) => {
                    if keys.contains(&key) {
                        found.push(pkt_idx);
                    }
                }
                // Waits for the in-order pass.
                None if self.ordered.is_some() => break,
                None => {}
            }
            scanned += 1;
        }
        let Some(scan) = &mut self.sequence else {
            return Tick::Idle;
        };
        scan.members.extend(found);
        scan.scanned = scanned;
        if scan.complete(displayed) {
            Tick::Done(())
        } else {
            Tick::Running
        }
    }

    /// The sequence being highlighted.
    pub fn sequence(&self) -> Option<&SequenceScan> {
        self.sequence.as_ref()
    }

    /// The displayed row of the sequence's next (`forward`) or previous
    /// packet from displayed `row`, among those found so far.
    pub fn sequence_step(&self, row: usize, forward: bool) -> Option<usize> {
        let scan = self.sequence.as_ref()?;
        let pkt_idx = self.filtered.select(row)?;
        let at = scan.members.partition_point(|&m| m < pkt_idx);
        let next = if forward {
            let skip = usize::from(scan.members.get(at) == Some(&pkt_idx));
            scan.members.get(at + skip)
        } else {
            at.checked_sub(1).and_then(|i| scan.members.get(i))
        }?;
        Some(self.filtered.rank(*next))
    }
}

#[cfg(test)]
mod tests {
    use packet_dissector::registry::DissectorRegistry;
    use packet_dissector_core::packet::DissectBuffer;

    use super::super::tests::test_session;
    use super::*;
    use crate::test_fixtures;

    fn keys(frame: &[u8]) -> SequenceKeys {
        let registry = DissectorRegistry::default();
        let mut buf = DissectBuffer::new();
        let _ = registry.dissect(frame, &mut buf);
        keys_of(&Packet::new(&buf, frame))
    }

    #[test]
    fn a_sip_message_has_a_call_a_flow_and_hosts() {
        let k = keys(&test_fixtures::sip_options_udp_frame());
        assert_eq!(k.call, Some(SequenceKey::SipCall("fixture-1".to_string())));
        assert_eq!(
            k.call.as_ref().unwrap().filter(),
            "sip.headers.value = 'fixture-1'"
        );
        let Some(SequenceKey::Flow(flow)) = &k.stream else {
            panic!("no flow: {k:?}");
        };
        assert_eq!(flow.transport, "UDP");
        assert_eq!(
            k.stream.as_ref().unwrap().label(),
            "UDP 10.0.0.1:5060 ↔ 10.0.0.2:5060"
        );
        assert_eq!(
            k.hosts.as_ref().unwrap().filter(),
            "(ipv4.src = '10.0.0.1' and ipv4.dst = '10.0.0.2') or (ipv4.src = '10.0.0.2' and ipv4.dst = '10.0.0.1')"
        );
        assert!(k.contains(k.call.as_ref().unwrap()));
        assert_eq!(k.at_or_coarser(SequenceUnit::Call), k.call.as_ref());
    }

    #[test]
    fn a_dns_query_is_a_transaction() {
        let k = keys(&test_fixtures::dns_edns_query_frame());
        let Some(key @ SequenceKey::DnsTransaction { id, .. }) = &k.call else {
            panic!("no transaction: {k:?}");
        };
        assert_eq!(*id, 0x1234);
        assert_eq!(key.label(), "DNS transaction 0x1234");
        assert!(
            key.filter()
                .starts_with("dns.id = 4660 and ((ipv4.src = '10.0.0.1'")
        );
    }

    #[test]
    fn a_tcp_packet_is_in_its_stream() {
        let k = keys(&test_fixtures::bgp_update_frame());
        assert_eq!(k.call, None);
        assert_eq!(k.stream, Some(SequenceKey::TcpStream(0)));
        assert_eq!(k.stream.as_ref().unwrap().filter(), "tcp.stream_id = 0");
        // Without a call, the stream is the finest grain.
        assert_eq!(k.at_or_coarser(SequenceUnit::Call), k.stream.as_ref());
        assert_eq!(k.at_or_coarser(SequenceUnit::Hosts), k.hosts.as_ref());
        // Without hosts either way, the finest the packet has.
        let only_stream = SequenceKeys {
            stream: k.stream.clone(),
            ..Default::default()
        };
        assert_eq!(
            only_stream.at_or_coarser(SequenceUnit::Hosts),
            k.stream.as_ref()
        );
    }

    #[test]
    fn a_tunnelled_packet_is_grouped_by_its_inner_hosts() {
        let k = keys(&test_fixtures::gtpu_icmp_frame());
        // The GTP-U tunnel's UDP flow is not the ICMP packet's own.
        assert_eq!(k.stream, None);
        assert_eq!(
            k.hosts,
            Some(SequenceKey::Hosts(
                "192.168.0.1".parse().unwrap(),
                "192.168.0.2".parse().unwrap()
            ))
        );
        assert_eq!(k.at_or_coarser(SequenceUnit::Stream), k.hosts.as_ref());
    }

    #[test]
    fn sequences_are_scanned_over_the_displayed_packets() {
        // Every test_session packet is the same UDP datagram, one flow.
        let (mut session, _tmp) = test_session(3);
        assert!(matches!(session.sequence_tick(), Tick::Idle));
        let key = session
            .sequence_keys(0)
            .and_then(|k| k.stream)
            .expect("a flow");
        session.start_sequence(key.clone());
        assert_eq!(session.sequence().unwrap().contains(0, 0), None);
        assert!(matches!(session.sequence_tick(), Tick::Done(())));
        let scan = session.sequence().unwrap();
        assert_eq!(scan.members, [0, 1, 2]);
        assert_eq!(scan.contains(1, 1), Some(true));
        assert_eq!(session.sequence_step(0, true), Some(1));
        assert_eq!(session.sequence_step(2, true), None);
        assert_eq!(session.sequence_step(2, false), Some(1));
        assert_eq!(session.sequence_step(0, false), None);

        // Another key matches nothing.
        session.start_sequence(SequenceKey::TcpStream(7));
        while let Tick::Running = session.sequence_tick() {}
        assert!(session.sequence().unwrap().members.is_empty());
        session.clear_sequence();
        assert!(session.sequence().is_none());
    }
}
