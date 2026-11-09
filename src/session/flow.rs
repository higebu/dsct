//! The highlighted sequence as a sequence diagram: who sent each of its
//! packets to whom, and what it was.
//!
//! [`Session::start_flow`] follows the sequence being highlighted (see
//! [`super::sequence`]): [`Session::flow_tick`] turns the packets found so
//! far into rows, and starts over when another sequence is highlighted or
//! the same one is scanned again (after a filter change).

use std::fmt;
use std::net::IpAddr;

use packet_dissector_core::field::FieldValue;
use packet_dissector_core::packet::Packet;

use super::conversations::innermost_transport;
use super::fields::timestamp_us;
use super::problems::{ProblemKind, problems_of};
use super::sequence::SequenceKey;
use super::{Session, Tick, loader, ordered_pass};

/// Rows drawn at most: a longer diagram is not read.
pub const MAX_FLOW_ROWS: usize = 5_000;
/// Rows built per [`Session::flow_tick`].
const FLOW_CHUNK: usize = 2_000;

/// One end of a message: a host, and its port when the message has one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FlowEnd {
    pub addr: IpAddr,
    pub port: Option<u16>,
}

impl fmt::Display for FlowEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.addr, self.port) {
            (IpAddr::V4(a), Some(p)) => write!(f, "{a}:{p}"),
            (IpAddr::V6(a), Some(p)) => write!(f, "[{a}]:{p}"),
            (a, None) => write!(f, "{a}"),
        }
    }
}

/// One packet of the diagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowRow {
    pub pkt_idx: usize,
    /// Microseconds since the Unix epoch.
    pub time_us: u64,
    /// The innermost IP layer's source, with the transport's port.
    pub src: FlowEnd,
    pub dst: FlowEnd,
    /// What the packet list shows as Info.
    pub label: String,
    /// The packet's top protocol.
    pub protocol: &'static str,
    /// A response reporting a failure.
    pub error: bool,
    /// A TCP segment sent again.
    pub retransmission: bool,
}

/// The rows of the sequence being highlighted.
#[derive(Debug, Clone)]
pub struct FlowScan {
    pub key: SequenceKey,
    /// The sequence scan the rows come from.
    generation: u64,
    /// Members of the sequence turned into rows (or skipped) so far.
    done: usize,
    /// In capture order, at most [`MAX_FLOW_ROWS`].
    pub rows: Vec<FlowRow>,
    /// Packets of the sequence past [`MAX_FLOW_ROWS`].
    pub more: usize,
}

impl FlowScan {
    /// The hosts of the rows, in the order they first appear.
    pub fn hosts(&self) -> Vec<IpAddr> {
        let mut hosts: Vec<IpAddr> = Vec::new();
        for row in &self.rows {
            for addr in [row.src.addr, row.dst.addr] {
                if !hosts.contains(&addr) {
                    hosts.push(addr);
                }
            }
        }
        hosts
    }

    /// The ports `addr` used, in the order they first appear.
    pub fn ports(&self, addr: IpAddr) -> Vec<u16> {
        let mut ports = Vec::new();
        for end in self.rows.iter().flat_map(|r| [r.src, r.dst]) {
            if end.addr == addr
                && let Some(p) = end.port
                && !ports.contains(&p)
            {
                ports.push(p);
            }
        }
        ports
    }
}

/// The row of a dissected packet, if it has IP addresses.
pub fn row_of(packet: &Packet<'_, '_>, pkt_idx: usize, time_us: u64, ok: bool) -> Option<FlowRow> {
    let (src, dst) = innermost_addrs(packet)?;
    let ports = innermost_transport(packet)
        .filter(|(_, _, s, d)| s.addr == src && d.addr == dst)
        .map(|(_, _, s, d)| (s.port, d.port));
    let problems = problems_of(packet, ok, pkt_idx);
    Some(FlowRow {
        pkt_idx,
        time_us,
        src: FlowEnd {
            addr: src,
            port: ports.map(|p| p.0),
        },
        dst: FlowEnd {
            addr: dst,
            port: ports.map(|p| p.1),
        },
        label: loader::extract_info(packet.buf(), packet.data()),
        protocol: packet.layers().last().map_or("", |l| l.name),
        error: problems
            .iter()
            .any(|p| p.kind == ProblemKind::ErrorResponse),
        retransmission: problems
            .iter()
            .any(|p| p.kind == ProblemKind::Retransmission),
    })
}

/// The addresses of the innermost IP layer.
fn innermost_addrs(packet: &Packet<'_, '_>) -> Option<(IpAddr, IpAddr)> {
    packet
        .layers()
        .iter()
        .rev()
        .filter(|l| matches!(l.name, "IPv4" | "IPv6"))
        .find_map(|layer| {
            let addr = |name| match packet.field_by_name(layer, name).map(|f| &f.value) {
                Some(FieldValue::Ipv4Addr(a)) => Some(IpAddr::from(*a)),
                Some(FieldValue::Ipv6Addr(a)) => Some(IpAddr::from(*a)),
                _ => None,
            };
            addr("src").zip(addr("dst"))
        })
}

impl Session {
    /// Draw the highlighted sequence, now and whenever it changes.
    pub fn start_flow(&mut self) {
        self.flow_on = true;
    }

    /// Stop drawing the sequence.
    pub fn stop_flow(&mut self) {
        self.flow_on = false;
        self.flow = None;
    }

    /// The rows built so far, when the sequence is drawn and there is one.
    pub fn flow(&self) -> Option<&FlowScan> {
        let flow = self.flow.as_ref()?;
        let scan = self.sequence.as_ref()?;
        (self.flow_on && flow.generation == scan.generation).then_some(flow)
    }

    /// Whether the sequence is drawn (even while none is highlighted).
    pub fn flow_on(&self) -> bool {
        self.flow_on
    }

    /// Turn the next packets of the sequence into rows. `Running` while
    /// some are left, `Done` once all were, `Idle` when not drawing or done.
    pub fn flow_tick(&mut self) -> Tick<()> {
        if !self.flow_on {
            return Tick::Idle;
        }
        let Some(scan) = &self.sequence else {
            return Tick::Idle;
        };
        let flow = match &mut self.flow {
            Some(flow) if flow.generation == scan.generation => flow,
            slot => slot.insert(FlowScan {
                key: scan.key.clone(),
                generation: scan.generation,
                done: 0,
                rows: Vec::new(),
                more: 0,
            }),
        };
        let members = &scan.members;
        let complete = scan.complete(self.filtered.count_ones());
        if flow.done >= members.len() {
            // Done, or waiting for the sequence scan.
            return if complete { Tick::Idle } else { Tick::Running };
        }
        let end = (flow.done + FLOW_CHUNK).min(members.len());
        let mut done = flow.done;
        let mut rows = Vec::new();
        let mut more = 0;
        for &pkt_idx in &members[flow.done..end] {
            if flow.rows.len() + rows.len() >= MAX_FLOW_ROWS {
                more += 1;
                done += 1;
                continue;
            }
            let Some(index) = self.indices.get(pkt_idx) else {
                done += 1;
                continue;
            };
            let Some(data) = self.capture.packet_data(index) else {
                done += 1;
                continue;
            };
            let time_us = timestamp_us(index.timestamp_secs, index.timestamp_usecs);
            let row = ordered_pass::with_packet(
                &self.registry,
                self.ordered.as_ref(),
                pkt_idx,
                data,
                u32::from(index.link_type),
                |packet| packet.map(|(p, ok)| row_of(&p, pkt_idx, time_us, ok)),
            );
            match row {
                Some(row) => rows.extend(row),
                // Waits for the in-order pass.
                None if self.ordered.is_some() => break,
                None => {}
            }
            done += 1;
        }
        let Some(flow) = &mut self.flow else {
            return Tick::Idle;
        };
        flow.rows.extend(rows);
        flow.more += more;
        flow.done = done;
        if complete && done >= members.len() {
            Tick::Done(())
        } else {
            Tick::Running
        }
    }
}

#[cfg(test)]
mod tests {
    use packet_dissector::registry::DissectorRegistry;
    use packet_dissector_core::packet::DissectBuffer;

    use super::super::tests::session_of;
    use super::*;
    use crate::test_fixtures;

    fn row(frame: &[u8]) -> Option<FlowRow> {
        let registry = DissectorRegistry::default();
        let mut buf = DissectBuffer::new();
        let ok = registry.dissect(frame, &mut buf).is_ok();
        row_of(&Packet::new(&buf, frame), 3, 42, ok)
    }

    #[test]
    fn a_row_names_the_inner_hosts_and_what_was_sent() {
        let r = row(&test_fixtures::sip_response_udp_frame(486, "Busy Here")).unwrap();
        // The fixture's addresses, whichever way the message goes.
        assert_eq!(r.src.to_string(), "10.0.0.1:5060");
        assert_eq!(r.dst.to_string(), "10.0.0.2:5060");
        assert_eq!(r.protocol, "SIP");
        assert!(r.label.contains("486 Busy Here"), "{}", r.label);
        assert!(r.error);
        assert!(!r.retransmission);
        assert_eq!((r.pkt_idx, r.time_us), (3, 42));

        // Tunneled: the inner hosts; ICMP has no ports.
        let r = row(&test_fixtures::gtpu_icmp_frame()).unwrap();
        assert_eq!(r.src.to_string(), "192.168.0.1");
        assert_eq!(r.dst.port, None);
        assert!(row(&[0u8; 14]).is_none());
    }

    #[test]
    fn the_flow_follows_the_highlighted_sequence() {
        let frames = [
            test_fixtures::gtpu_udp_frame(true, b"hello"),
            test_fixtures::gtpu_icmp_frame(),
            test_fixtures::gtpu_udp_frame(false, b"world"),
        ];
        let (mut session, _tmp) = session_of(&frames);
        assert!(matches!(session.flow_tick(), Tick::Idle));
        session.start_flow();
        assert!(session.flow_on());
        assert!(session.flow().is_none());

        let key = session.sequence_keys(0).unwrap().stream.unwrap();
        session.start_sequence(key.clone());
        while !matches!(session.sequence_tick(), Tick::Idle) {}
        while !matches!(session.flow_tick(), Tick::Idle) {}
        let flow = session.flow().unwrap();
        assert_eq!(flow.key, key);
        let pkts: Vec<_> = flow.rows.iter().map(|r| r.pkt_idx).collect();
        assert_eq!(pkts, [0, 2]);
        let hosts: Vec<_> = flow.hosts().iter().map(ToString::to_string).collect();
        assert_eq!(hosts, ["192.168.0.1", "192.168.0.2"]);
        assert_eq!(flow.ports("192.168.0.2".parse().unwrap()), [9999]);

        // The same sequence scanned again starts the rows over.
        session.start_sequence(key);
        assert!(session.flow().is_none());
        while !matches!(session.sequence_tick(), Tick::Idle) {}
        while !matches!(session.flow_tick(), Tick::Idle) {}
        assert_eq!(session.flow().unwrap().rows.len(), 2);

        session.stop_flow();
        assert!(!session.flow_on());
        assert!(session.flow().is_none());
    }
}
