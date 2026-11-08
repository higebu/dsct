//! Problems among the displayed packets: packets the dissectors could not
//! read to the end, error responses, and TCP retransmissions.
//!
//! [`Session::start_problems`] scans the displayed packets in chunks driven
//! by [`Session::problems_tick`], with the in-order results (a
//! retransmission is only known from the packets before it).

use packet_dissector_core::packet::Packet;

use super::{Session, Tick, ordered_pass};

/// What is wrong with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProblemKind {
    /// The dissectors stopped part way through the packet.
    Malformed,
    /// A response reporting a failure.
    ErrorResponse,
    /// A TCP segment sent again, or captured twice.
    Retransmission,
}

impl ProblemKind {
    /// In the order they are listed, the most serious first.
    pub const ALL: [ProblemKind; 3] = [Self::Malformed, Self::ErrorResponse, Self::Retransmission];

    /// The heading of the kind.
    pub fn title(self) -> &'static str {
        match self {
            Self::Malformed => "Malformed",
            Self::ErrorResponse => "Error responses",
            Self::Retransmission => "TCP retransmissions",
        }
    }

    /// What the kind covers.
    pub fn description(self) -> &'static str {
        match self {
            Self::Malformed => "Packets the dissectors could not read to the end",
            Self::ErrorResponse => "SIP and HTTP 4xx–6xx, DNS responses with an error code",
            Self::Retransmission => "Segments sent again, or captured twice",
        }
    }

    /// A display filter for the kind's packets, when one can be written.
    pub fn filter(self) -> Option<&'static str> {
        match self {
            Self::Malformed => None,
            Self::ErrorResponse => Some(
                "sip.status_code >= 400 or http.status_code >= 400 or (dns.qr = 1 and dns.rcode != 0)",
            ),
            Self::Retransmission => Some("tcp.retransmission = 1"),
        }
    }
}

/// One problem of one packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub pkt_idx: usize,
    pub kind: ProblemKind,
    /// The protocol concerned (`"SIP"`).
    pub protocol: &'static str,
    /// What happened (`"486 Busy Here"`).
    pub text: String,
}

/// The problems of a dissected packet, in [`ProblemKind`] order.
pub fn problems_of(packet: &Packet<'_, '_>, dissected: bool, pkt_idx: usize) -> Vec<Problem> {
    let mut out = Vec::new();
    let problem = |kind, protocol, text: String| Problem {
        pkt_idx,
        kind,
        protocol,
        text,
    };
    if !dissected {
        let last = packet.layers().last().map_or("the link layer", |l| l.name);
        out.push(problem(
            ProblemKind::Malformed,
            packet.layers().last().map_or("", |l| l.name),
            format!("could not be read past {last}"),
        ));
    }
    for layer in packet.layers() {
        let code = |name| packet.field_u16(layer, name);
        let label = |name| packet.field_str(layer, name).unwrap_or("");
        match layer.name {
            // RFC 3261, Section 21: 4xx–6xx are failures.
            "SIP" => {
                if let Some(c) = code("status_code").filter(|&c| c >= 400) {
                    out.push(problem(
                        ProblemKind::ErrorResponse,
                        "SIP",
                        format!("{c} {}", label("reason_phrase")).trim().to_string(),
                    ));
                }
            }
            // RFC 9110, Section 15: 4xx client and 5xx server errors.
            "HTTP" => {
                if let Some(c) = code("status_code").filter(|&c| c >= 400) {
                    out.push(problem(
                        ProblemKind::ErrorResponse,
                        "HTTP",
                        format!("{c} {}", label("reason_phrase")).trim().to_string(),
                    ));
                }
            }
            // RFC 1035, Section 4.1.1: RCODE 0 is "No error condition".
            "DNS" => {
                let response = packet.field_u8(layer, "qr") == Some(1);
                if let Some(rcode) = packet
                    .field_u8(layer, "rcode")
                    .filter(|&r| response && r != 0)
                {
                    let name = packet
                        .resolve_display_name(layer, "rcode_name")
                        .map_or_else(|| format!("RCODE {rcode}"), str::to_string);
                    out.push(problem(ProblemKind::ErrorResponse, "DNS", name));
                }
            }
            "TCP" if packet.field_u8(layer, "retransmission") == Some(1) => {
                out.push(problem(
                    ProblemKind::Retransmission,
                    "TCP",
                    "retransmission".to_string(),
                ));
            }
            _ => {}
        }
    }
    out.sort_by_key(|p| p.kind);
    out
}

/// Rows checked per [`Session::problems_tick`].
const PROBLEMS_CHUNK: usize = 2_000;

/// The problems found among the displayed packets so far.
#[derive(Debug, Clone, Default)]
pub struct ProblemScan {
    /// Displayed rows checked so far, from the first.
    pub scanned: usize,
    /// In capture order.
    pub problems: Vec<Problem>,
}

impl ProblemScan {
    /// Whether every displayed packet has been checked.
    pub fn complete(&self, displayed: usize) -> bool {
        self.scanned >= displayed
    }

    /// The most serious problem of packet `pkt_idx`.
    pub fn of_packet(&self, pkt_idx: usize) -> Option<&Problem> {
        let at = self.problems.partition_point(|p| p.pkt_idx < pkt_idx);
        self.problems.get(at).filter(|p| p.pkt_idx == pkt_idx)
    }

    /// The problems of kind `kind`.
    pub fn of_kind(&self, kind: ProblemKind) -> impl Iterator<Item = &Problem> {
        self.problems.iter().filter(move |p| p.kind == kind)
    }

    /// Packets with at least one problem.
    pub fn packets(&self) -> usize {
        let mut count = 0;
        let mut last = None;
        for p in &self.problems {
            if last != Some(p.pkt_idx) {
                count += 1;
                last = Some(p.pkt_idx);
            }
        }
        count
    }
}

impl Session {
    /// Look for problems among the displayed packets, from the first.
    pub fn start_problems(&mut self) {
        self.problems = Some(ProblemScan::default());
    }

    /// The problems found so far, if they are being looked for.
    pub fn problems(&self) -> Option<&ProblemScan> {
        self.problems.as_ref()
    }

    /// Check the next displayed packets for problems. `Running` while rows
    /// are left (or the next one waits for the in-order pass), `Done` once
    /// all were checked, `Idle` when not looking or done.
    pub fn problems_tick(&mut self) -> Tick<()> {
        let displayed = self.filtered.count_ones();
        let Some(scan) = &self.problems else {
            return Tick::Idle;
        };
        if scan.complete(displayed) {
            return Tick::Idle;
        }
        let from = scan.scanned;
        let end = (from + PROBLEMS_CHUNK).min(displayed);
        let mut found = Vec::new();
        let mut scanned = from;
        for pkt_idx in self.filtered.iter_from(from).take(end - from) {
            let Some(index) = self.indices.get(pkt_idx) else {
                scanned += 1;
                continue;
            };
            let Some(data) = self.capture.packet_data(index) else {
                scanned += 1;
                continue;
            };
            let problems = ordered_pass::with_packet(
                &self.registry,
                self.ordered.as_ref(),
                pkt_idx,
                data,
                u32::from(index.link_type),
                |packet| packet.map(|(p, ok)| problems_of(&p, ok, pkt_idx)),
            );
            match problems {
                Some(p) => found.extend(p),
                // Waits for the in-order pass.
                None if self.ordered.is_some() => break,
                None => {}
            }
            scanned += 1;
        }
        let Some(scan) = &mut self.problems else {
            return Tick::Idle;
        };
        scan.problems.extend(found);
        scan.scanned = scanned;
        if scan.complete(displayed) {
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

    use super::super::tests::test_session;
    use super::*;
    use crate::test_fixtures;

    fn problems(frame: &[u8]) -> Vec<Problem> {
        let registry = DissectorRegistry::default();
        let mut buf = DissectBuffer::new();
        let ok = registry.dissect(frame, &mut buf).is_ok();
        problems_of(&Packet::new(&buf, frame), ok, 7)
    }

    #[test]
    fn a_failed_sip_response_is_an_error_response() {
        let frame = test_fixtures::sip_response_udp_frame(486, "Busy Here");
        let p = problems(&frame);
        assert_eq!(
            p,
            [Problem {
                pkt_idx: 7,
                kind: ProblemKind::ErrorResponse,
                protocol: "SIP",
                text: "486 Busy Here".to_string(),
            }]
        );
        assert!(problems(&test_fixtures::sip_response_udp_frame(200, "OK")).is_empty());
        assert!(problems(&test_fixtures::sip_options_udp_frame()).is_empty());
    }

    #[test]
    fn a_truncated_packet_is_malformed() {
        let mut frame = test_fixtures::dns_edns_query_frame();
        frame.truncate(frame.len() - 10);
        let p = problems(&frame);
        assert_eq!(p[0].kind, ProblemKind::Malformed);
        assert!(p[0].text.starts_with("could not be read past "), "{p:?}");
    }

    #[test]
    fn kinds_have_titles_and_filters() {
        assert_eq!(ProblemKind::ALL[0].title(), "Malformed");
        assert_eq!(ProblemKind::Malformed.filter(), None);
        assert_eq!(
            ProblemKind::Retransmission.filter(),
            Some("tcp.retransmission = 1")
        );
        assert!(!ProblemKind::ErrorResponse.description().is_empty());
    }

    #[test]
    fn problems_are_scanned_over_the_displayed_packets() {
        let (mut session, _tmp) = test_session(3);
        assert!(matches!(session.problems_tick(), Tick::Idle));
        session.start_problems();
        assert!(matches!(session.problems_tick(), Tick::Done(())));
        let scan = session.problems().unwrap();
        assert!(scan.complete(3));
        // The test packets are well-formed UDP datagrams.
        assert!(scan.problems.is_empty());
        assert_eq!(scan.packets(), 0);
        assert!(scan.of_packet(0).is_none());
    }

    #[test]
    fn a_scan_finds_a_packet_and_counts_packets_once() {
        let scan = ProblemScan {
            scanned: 3,
            problems: vec![
                Problem {
                    pkt_idx: 1,
                    kind: ProblemKind::Malformed,
                    protocol: "SIP",
                    text: String::new(),
                },
                Problem {
                    pkt_idx: 1,
                    kind: ProblemKind::ErrorResponse,
                    protocol: "SIP",
                    text: String::new(),
                },
                Problem {
                    pkt_idx: 2,
                    kind: ProblemKind::Retransmission,
                    protocol: "TCP",
                    text: String::new(),
                },
            ],
        };
        assert_eq!(scan.packets(), 2);
        assert_eq!(
            scan.of_packet(1).map(|p| p.kind),
            Some(ProblemKind::Malformed)
        );
        assert_eq!(scan.of_packet(0), None);
        assert_eq!(scan.of_kind(ProblemKind::Retransmission).count(), 1);
    }
}
