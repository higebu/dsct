//! Follow Stream: the payload of one TCP stream, or UDP or SCTP flow, as
//! the messages each side sent.
//!
//! Consecutive segments from one side make one message, until the
//! dissectors finish a message in one of them (a SIP request, an HTTP
//! response) or the other side speaks. Each UDP or SCTP datagram is a
//! message of its own. TCP retransmissions are kept apart, so that they do
//! not repeat bytes inside a message.

use packet_dissector_core::packet::{DissectBuffer, Layer, Packet};

use super::conversations::{Endpoint, innermost_transport};
use super::fields::timestamp_us;
use super::problems::{ProblemKind, problems_of};
use super::sequence::{Flow, SequenceKey};
use super::state::{StreamBuildProgress, StreamKey, StreamLine};
use super::{Session, Tick, loader};

/// Payload bytes kept per stream at most; the bytes of later messages are
/// counted, not kept (see [`FollowedStream::truncated_bytes`]).
const MAX_STREAM_BYTES: usize = 32 << 20;
/// Characters of a heading at most.
const MAX_HEADING: usize = 200;

/// What one side sent at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamMessage {
    /// Sent by the client (the sender of the stream's first packet).
    pub is_client: bool,
    /// Index of the first packet.
    pub first_packet: usize,
    /// Index of the last packet.
    pub last_packet: usize,
    /// Packets carrying the message.
    pub packets: usize,
    /// Time of the first packet, in microseconds since the Unix epoch.
    pub time_us: u64,
    /// Payload bytes, kept or not.
    pub bytes: u64,
    /// The payload kept (all of it, unless the stream is too large).
    pub payload: Vec<u8>,
    /// The dissected message's first line (`"SIP/2.0 200 OK"`), or its
    /// Info for a binary protocol; `None` when nothing dissected it.
    pub heading: Option<String>,
    /// Whether the message reports a failure (see [`ProblemKind`]).
    pub error: bool,
    /// A TCP segment sent again: its bytes were already in the stream.
    pub retransmission: bool,
}

impl StreamMessage {
    /// Whether the payload reads as text: printable ASCII and whitespace,
    /// with at most one byte in ten otherwise.
    pub fn is_text(&self) -> bool {
        let printable = self
            .payload
            .iter()
            .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace())
            .count();
        printable * 10 >= self.payload.len() * 9
    }

    /// The payload as lines of text, unprintable bytes shown as `.`.
    pub fn text_lines(&self) -> impl Iterator<Item = String> + '_ {
        payload_to_ascii(&self.payload)
            .lines()
            .map(str::to_string)
            .collect::<Vec<_>>()
            .into_iter()
    }
}

/// A collected stream, ready to display.
pub struct FollowedStream {
    /// Title string (e.g., "TCP Stream #0: 10.0.0.1:443 ↔ 10.0.0.2:52014").
    pub title: String,
    /// The messages in capture order, retransmissions among them.
    pub messages: Vec<StreamMessage>,
    /// Payload bytes not kept, past [`MAX_STREAM_BYTES`].
    pub truncated_bytes: u64,
    /// A display filter for the stream's packets.
    pub filter: String,
}

impl FollowedStream {
    /// The payload as lines of text with their direction, without
    /// retransmissions.
    pub fn lines(&self) -> Vec<StreamLine> {
        self.messages
            .iter()
            .filter(|m| !m.retransmission)
            .flat_map(|m| {
                m.text_lines().map(move |text| StreamLine {
                    text,
                    is_client: m.is_client,
                })
            })
            .collect()
    }

    /// Whether most messages are binary, so better shown as hex.
    pub fn mostly_binary(&self) -> bool {
        let binary = self.messages.iter().filter(|m| !m.is_text()).count();
        binary * 2 > self.messages.len()
    }
}

/// Groups the payload of a stream's packets into messages.
#[derive(Default)]
pub(crate) struct MessageBuilder {
    messages: Vec<StreamMessage>,
    /// The message later segments from the same side add to.
    open: Option<usize>,
    kept: usize,
    truncated_bytes: u64,
}

impl MessageBuilder {
    /// Add the payload of packet `pkt_idx`.
    fn add(&mut self, packet: &Packet<'_, '_>, part: Part<'_>) {
        let open = self
            .open
            .filter(|&i| !part.retransmission && self.messages[i].is_client == part.is_client);
        let i = match open {
            Some(i) => i,
            None => {
                self.messages.push(StreamMessage {
                    is_client: part.is_client,
                    first_packet: part.pkt_idx,
                    last_packet: part.pkt_idx,
                    packets: 0,
                    time_us: part.time_us,
                    bytes: 0,
                    payload: Vec::new(),
                    heading: None,
                    error: false,
                    retransmission: part.retransmission,
                });
                self.messages.len() - 1
            }
        };
        let keep = part.payload.len().min(MAX_STREAM_BYTES - self.kept);
        self.kept += keep;
        self.truncated_bytes += (part.payload.len() - keep) as u64;
        let m = &mut self.messages[i];
        m.payload.extend_from_slice(&part.payload[..keep]);
        m.bytes += part.payload.len() as u64;
        m.packets += 1;
        m.last_packet = part.pkt_idx;
        if part.retransmission {
            return;
        }
        let done = part.message_done || !part.stream;
        if done {
            m.heading = heading(&m.payload).or_else(|| part.dissected.then(|| info(packet)));
            m.error = problems_of(packet, true, part.pkt_idx)
                .iter()
                .any(|p| p.kind == ProblemKind::ErrorResponse);
        }
        self.open = (!done).then_some(i);
    }

    fn finish(self) -> (Vec<StreamMessage>, u64) {
        let mut messages = self.messages;
        // Messages left open (a binary stream, the last of a capture):
        // their text says what they are, when they are text.
        for m in &mut messages {
            if m.heading.is_none() && !m.retransmission {
                m.heading = heading(&m.payload);
            }
        }
        (messages, self.truncated_bytes)
    }
}

/// The payload of one packet of a stream.
struct Part<'a> {
    pkt_idx: usize,
    time_us: u64,
    is_client: bool,
    payload: &'a [u8],
    /// A byte stream (TCP), whose messages may span packets.
    stream: bool,
    retransmission: bool,
    /// A layer over the transport finished a message in this packet.
    message_done: bool,
    /// Something dissected the payload.
    dissected: bool,
}

/// The first line of `payload` when it is short printable text (a request
/// or status line).
fn heading(payload: &[u8]) -> Option<String> {
    let end = payload
        .iter()
        .position(|&b| b == b'\n')
        .unwrap_or(payload.len());
    let line = payload[..end]
        .strip_suffix(b"\r")
        .unwrap_or(&payload[..end]);
    let text = std::str::from_utf8(line).ok()?;
    (!text.trim().is_empty()
        && text.len() <= MAX_HEADING
        && text
            .bytes()
            .all(|b| b.is_ascii_graphic() || b == b' ' || b == b'\t'))
    .then(|| text.trim_end().to_string())
}

/// The Info of a dissected binary message.
fn info(packet: &Packet<'_, '_>) -> String {
    loader::extract_info(packet.buf(), packet.data())
}

/// Whether a layer over the transport `layer` finished a message: one that
/// is not only a placeholder for a message still being reassembled.
fn message_done(packet: &Packet<'_, '_>, transport: &Layer) -> bool {
    let layers = packet.layers();
    let Some(at) = layers.iter().position(|l| std::ptr::eq(l, transport)) else {
        return false;
    };
    layers[at + 1..]
        .iter()
        .any(|l| packet.field_by_name(l, "reassembly_in_progress").is_none())
}

impl Session {
    /// Start collecting the stream the selected packet belongs to: the
    /// TCP stream, or UDP or SCTP flow, over its innermost IP layer (so a
    /// tunneled packet follows its own flow, not the tunnel's).
    ///
    /// Does nothing without a selected packet. Returns `Err` with a message
    /// when the stream cannot be collected yet or at all.
    pub fn start_follow_stream(&mut self) -> Result<(), String> {
        let Some(sel) = self.selected.as_ref() else {
            return Ok(());
        };
        if sel.pending {
            return Err("Wait until the packet is dissected in capture order".to_string());
        }
        let buf = sel.packet.to_dissect_buf();
        let packet = Packet::new(&buf, &sel.packet.data);
        let Some((key, title)) = stream_key(&packet) else {
            return Err("The selected packet has no TCP, UDP or SCTP flow".to_string());
        };
        let registry = self.scan_registry().map_err(|e| format!("Error: {e}"))?;
        self.stream_build_progress = Some(StreamBuildProgress {
            stream_key: key,
            cursor: 0,
            messages: MessageBuilder::default(),
            client: None,
            title,
            registry,
        });
        Ok(())
    }

    /// Number of packets to scan per stream-build tick.
    const STREAM_CHUNK_SIZE: usize = 10_000;

    /// Whether a stream is being collected.
    pub fn stream_running(&self) -> bool {
        self.stream_build_progress.is_some()
    }

    /// Stop collecting the stream.
    pub fn cancel_stream(&mut self) {
        self.stream_build_progress = None;
    }

    /// Process one chunk of the in-progress stream build.
    pub fn stream_tick(&mut self) -> Tick<FollowedStream> {
        let total = self.indices.len();
        let progress = match &mut self.stream_build_progress {
            Some(p) => p,
            None => return Tick::Idle,
        };

        let end = (progress.cursor + Self::STREAM_CHUNK_SIZE).min(total);
        let mut dissect_buf = DissectBuffer::new();
        for i in progress.cursor..end {
            let index = &self.indices[i];
            let data = match self.capture.packet_data(index) {
                Some(d) => d,
                None => continue,
            };
            let buf = dissect_buf.clear_into();
            // A packet that fails part way still has its flow and payload.
            let _ = progress
                .registry
                .dissect_with_link_type(data, index.link_type as u32, buf);

            let packet = Packet::new(buf, data);
            let Some((layer, transport, src, dst)) = innermost_transport(&packet) else {
                continue;
            };
            let matches = match &progress.stream_key {
                StreamKey::TcpStreamId(id) => {
                    transport == "TCP" && packet.field_u32(layer, "stream_id") == Some(*id)
                }
                StreamKey::Flow { .. } => {
                    stream_key_of(&packet, layer, transport, src, dst) == progress.stream_key
                }
            };
            if !matches {
                continue;
            }
            // The first packet's sender is the client.
            let is_client = *progress.client.get_or_insert(src) == src;
            let payload = data.get(layer.range.end..).unwrap_or_default();
            if payload.is_empty() {
                continue;
            }
            let stream = transport == "TCP";
            let at = packet
                .layers()
                .iter()
                .position(|l| std::ptr::eq(l, layer))
                .unwrap_or(0);
            progress.messages.add(
                &packet,
                Part {
                    pkt_idx: i,
                    time_us: timestamp_us(index.timestamp_secs, index.timestamp_usecs),
                    is_client,
                    payload,
                    stream,
                    retransmission: stream && packet.field_u8(layer, "retransmission") == Some(1),
                    message_done: message_done(&packet, layer),
                    dissected: packet.layers().len() > at + 1,
                },
            );
        }
        progress.cursor = end;

        if progress.cursor >= total
            && let Some(p) = std::mem::take(&mut self.stream_build_progress)
        {
            let (messages, truncated_bytes) = p.messages.finish();
            let filter = match p.stream_key {
                StreamKey::TcpStreamId(n) => SequenceKey::TcpStream(n).filter(),
                StreamKey::Flow { transport, a, b } => {
                    SequenceKey::Flow(Flow::new(transport, a, b)).filter()
                }
            };
            return Tick::Done(FollowedStream {
                title: p.title,
                filter,
                messages,
                truncated_bytes,
            });
        }
        Tick::Running
    }
}

/// The stream of `packet` and its title.
fn stream_key(packet: &Packet<'_, '_>) -> Option<(StreamKey, String)> {
    let (layer, transport, src, dst) = innermost_transport(packet)?;
    let key = stream_key_of(packet, layer, transport, src, dst);
    let title = match key {
        StreamKey::TcpStreamId(id) => format!("TCP Stream #{id}: {src} \u{2194} {dst}"),
        StreamKey::Flow { .. } => format!("{transport} Stream: {src} \u{2194} {dst}"),
    };
    Some((key, title))
}

/// The stream of a packet whose innermost transport is `layer`: its TCP
/// stream number, or else its flow.
fn stream_key_of(
    packet: &Packet<'_, '_>,
    layer: &Layer,
    transport: &'static str,
    src: Endpoint,
    dst: Endpoint,
) -> StreamKey {
    if transport == "TCP"
        && let Some(id) = packet.field_u32(layer, "stream_id")
    {
        return StreamKey::TcpStreamId(id);
    }
    let (a, b) = if src <= dst { (src, dst) } else { (dst, src) };
    StreamKey::Flow { transport, a, b }
}

/// Convert raw bytes to ASCII, replacing non-printable characters with `.`.
fn payload_to_ascii(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::super::Tick;
    use super::super::tests::{session_of, test_session};
    use super::payload_to_ascii;

    #[test]
    fn follow_stream_collects_the_udp_flow() {
        let (mut session, _tmp) = test_session(3);
        assert!(matches!(session.stream_tick(), Tick::Idle));
        session.load_packet(0);
        session.start_follow_stream().unwrap();
        assert!(session.stream_running());
        let stream = loop {
            match session.stream_tick() {
                Tick::Running => {}
                Tick::Done(stream) => break stream,
                Tick::Idle => panic!("no stream collected"),
            }
        };
        assert!(stream.title.starts_with("UDP Stream"), "{}", stream.title);
        assert!(!session.stream_running());
    }

    fn collect(session: &mut super::super::Session) -> super::FollowedStream {
        loop {
            match session.stream_tick() {
                Tick::Running => {}
                Tick::Done(stream) => break stream,
                Tick::Idle => panic!("no stream collected"),
            }
        }
    }

    #[test]
    fn a_tunneled_packet_follows_its_inner_flow() {
        use crate::test_fixtures::{gtpu_icmp_frame, gtpu_udp_frame};
        let (mut session, _tmp) = session_of(&[
            gtpu_udp_frame(true, b"hello\r\n"),
            gtpu_icmp_frame(),
            gtpu_udp_frame(false, b"world\r\n"),
        ]);
        session.load_packet(2);
        session.start_follow_stream().unwrap();
        let stream = collect(&mut session);
        assert_eq!(
            stream.title,
            "UDP Stream: 192.168.0.2:9999 \u{2194} 192.168.0.1:40000"
        );
        let lines = stream.lines();
        let lines: Vec<_> = lines
            .iter()
            .map(|l| (l.text.as_str(), l.is_client))
            .collect();
        assert!(
            stream.filter.contains("udp.src_port = 40000"),
            "{}",
            stream.filter
        );
        // The first packet's sender is the client; the ICMP packet, in the
        // same tunnel, is not part of the flow.
        assert_eq!(lines, [("hello", true), ("world", false)]);
    }

    #[test]
    fn segments_join_into_messages_and_retransmissions_stay_apart() {
        use crate::test_fixtures::tcp_ipv4_frame as tcp;
        const SYN: u8 = 0x02;
        const SYN_ACK: u8 = 0x12;
        const PSH_ACK: u8 = 0x18;
        let (cli, srv) = (([10, 0, 0, 1], 40000), ([10, 0, 0, 2], 80));
        let req1: &[u8] = b"GET /index.html HTTP/1.1\r\nHo";
        let req2: &[u8] = b"st: example\r\n\r\n";
        let resp: &[u8] = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let get_a: &[u8] = b"GET /a HTTP/1.1\r\nHost: example\r\n\r\n";
        let get_b: &[u8] = b"GET /b HTTP/1.1\r\nHost: example\r\n\r\n";
        let c = 1001 + (req1.len() + req2.len()) as u32;
        let s = 9001 + resp.len() as u32;
        let (mut session, _tmp) = session_of(&[
            tcp(cli, srv, 1000, 0, SYN, &[]),
            tcp(srv, cli, 9000, 1001, SYN_ACK, &[]),
            tcp(cli, srv, 1001, 9001, PSH_ACK, req1),
            tcp(cli, srv, 1001 + req1.len() as u32, 9001, PSH_ACK, req2),
            tcp(cli, srv, 1001, 9001, PSH_ACK, req1),
            tcp(srv, cli, 9001, c, PSH_ACK, resp),
            tcp(cli, srv, c, s, PSH_ACK, get_a),
            tcp(cli, srv, c + get_a.len() as u32, s, PSH_ACK, get_b),
        ]);
        session.load_packet(2);
        session.start_follow_stream().unwrap();
        let stream = collect(&mut session);
        let got: Vec<_> = stream
            .messages
            .iter()
            .map(|m| {
                (
                    m.is_client,
                    m.first_packet,
                    m.packets,
                    m.heading.as_deref().unwrap_or(""),
                    m.error,
                    m.retransmission,
                )
            })
            .collect();
        assert_eq!(
            got,
            [
                (true, 2, 2, "GET /index.html HTTP/1.1", false, false),
                (true, 4, 1, "", false, true),
                (false, 5, 1, "HTTP/1.1 404 Not Found", true, false),
                (true, 6, 1, "GET /a HTTP/1.1", false, false),
                (true, 7, 1, "GET /b HTTP/1.1", false, false),
            ]
        );
        let first = &stream.messages[0];
        assert_eq!(first.payload, [req1, req2].concat());
        assert_eq!(first.bytes, (req1.len() + req2.len()) as u64);
        assert!(first.is_text());
        assert!(!stream.mostly_binary());
        // The lines leave the retransmission out.
        assert_eq!(stream.lines().len(), 3 * 4);
        assert_eq!(stream.truncated_bytes, 0);
        assert_eq!(stream.filter, "tcp.stream_id = 0");
    }

    #[test]
    fn binary_payload_has_no_heading() {
        let (mut session, _tmp) = session_of(&[gtpu_udp_frame_binary()]);
        session.load_packet(0);
        session.start_follow_stream().unwrap();
        let stream = collect(&mut session);
        assert_eq!(stream.messages.len(), 1);
        assert_eq!(stream.messages[0].heading, None);
        assert!(!stream.messages[0].is_text());
        assert!(stream.mostly_binary());
    }

    fn gtpu_udp_frame_binary() -> Vec<u8> {
        crate::test_fixtures::gtpu_udp_frame(true, &[0, 1, 2, 3, 0xff, 0xfe, 0x10, 0x80])
    }

    #[test]
    fn a_packet_without_an_inner_flow_cannot_be_followed() {
        let (mut session, _tmp) = session_of(&[crate::test_fixtures::gtpu_icmp_frame()]);
        session.load_packet(0);
        assert!(session.start_follow_stream().is_err());
        assert!(!session.stream_running());
    }

    #[test]
    fn follow_stream_without_selection_does_nothing() {
        let (mut session, _tmp) = test_session(0);
        assert_eq!(session.start_follow_stream(), Ok(()));
        assert!(!session.stream_running());
    }

    #[test]
    fn cancel_stream_stops_the_collection() {
        let (mut session, _tmp) = test_session(3);
        session.load_packet(0);
        session.start_follow_stream().unwrap();
        session.cancel_stream();
        assert!(!session.stream_running());
        assert!(matches!(session.stream_tick(), Tick::Idle));
    }

    #[test]
    fn payload_to_ascii_converts() {
        assert_eq!(payload_to_ascii(b"Hello\x00\x01"), "Hello..");
        assert_eq!(payload_to_ascii(b"AB\nCD"), "AB\nCD");
        assert_eq!(payload_to_ascii(b"\t \r"), "\t \r");
    }

    #[test]
    fn payload_to_ascii_all_nonprintable() {
        assert_eq!(payload_to_ascii(&[0, 1, 2, 3]), "....");
    }

    #[test]
    fn payload_to_ascii_empty() {
        assert_eq!(payload_to_ascii(&[]), "");
    }

    #[test]
    fn payload_to_ascii_mixed_ascii_and_control() {
        assert_eq!(payload_to_ascii(b"A\x01B\x02C"), "A.B.C");
    }

    #[test]
    fn payload_to_ascii_preserves_whitespace() {
        assert_eq!(payload_to_ascii(b"\t\n\r "), "\t\n\r ");
    }
}
