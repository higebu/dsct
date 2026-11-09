//! Follow Stream collection.

use packet_dissector_core::packet::{DissectBuffer, Layer, Packet};

use super::conversations::{Endpoint, innermost_transport};
use super::state::{StreamBuildProgress, StreamKey, StreamLine};
use super::{Session, Tick};

/// A collected stream, ready to display.
pub struct FollowedStream {
    /// Title string (e.g., "TCP Stream: 10.0.0.1:443 ↔ 10.0.0.2:52014").
    pub title: String,
    /// Payload lines in capture order.
    pub lines: Vec<StreamLine>,
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
            lines: Vec::new(),
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
            if !payload.is_empty() {
                let text = payload_to_ascii(payload);
                for line in text.lines() {
                    progress.lines.push(StreamLine {
                        text: line.to_string(),
                        is_client,
                    });
                }
            }
        }
        progress.cursor = end;

        if progress.cursor >= total
            && let Some(p) = std::mem::take(&mut self.stream_build_progress)
        {
            return Tick::Done(FollowedStream {
                title: p.title,
                lines: p.lines,
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
        let lines: Vec<_> = stream
            .lines
            .iter()
            .map(|l| (l.text.as_str(), l.is_client))
            .collect();
        // The first packet's sender is the client; the ICMP packet, in the
        // same tunnel, is not part of the flow.
        assert_eq!(lines, [("hello", true), ("world", false)]);
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
