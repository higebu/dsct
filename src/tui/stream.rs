//! Follow Stream building and display logic.

use packet_dissector_core::packet::DissectBuffer;

use super::app::App;
use super::loader;
use super::state::{StreamBuildProgress, StreamKey, StreamLine, StreamViewState};

impl App {
    /// Start building a follow-stream view for the selected packet.
    pub(super) fn start_follow_stream(&mut self) {
        if let Some((key, title, protocol)) = self.extract_stream_key() {
            self.stream_build_progress = Some(StreamBuildProgress {
                stream_key: key,
                cursor: 0,
                lines: Vec::new(),
                client_addr: None,
                title,
                protocol,
            });
        }
    }

    /// Extract a stream key from the currently selected packet.
    fn extract_stream_key(&self) -> Option<(StreamKey, String, &'static str)> {
        let sel = self.selected.as_ref()?;
        let packet = &sel.packet;

        // Try TCP first (has stream_id).
        if let Some(tcp) = packet.layer_by_name("TCP")
            && let Some(f) = packet.field_by_name(tcp, "stream_id")
        {
            let fv = f.value.to_field_value(packet);
            if let packet_dissector_core::field::FieldValue::U32(id) = fv {
                let (src, dst) = self.selected_endpoints_owned(packet);
                let sp = owned_u16(packet, tcp, "src_port").unwrap_or(0);
                let dp = owned_u16(packet, tcp, "dst_port").unwrap_or(0);
                let title = format!("TCP Stream #{id}: {src}:{sp} \u{2194} {dst}:{dp}");
                return Some((StreamKey::TcpStreamId(id), title, "TCP"));
            }
        }

        // UDP
        if let Some(udp) = packet.layer_by_name("UDP") {
            let sp = owned_u16(packet, udp, "src_port").unwrap_or(0);
            let dp = owned_u16(packet, udp, "dst_port").unwrap_or(0);
            let (src, dst) = self.selected_endpoints_owned(packet);
            let (key, title) = Self::make_tuple_key(&src, &dst, sp, dp, "UDP");
            return Some((key, title, "UDP"));
        }

        // SCTP
        if let Some(sctp) = packet.layer_by_name("SCTP") {
            let sp = owned_u16(packet, sctp, "src_port").unwrap_or(0);
            let dp = owned_u16(packet, sctp, "dst_port").unwrap_or(0);
            let (src, dst) = self.selected_endpoints_owned(packet);
            let (key, title) = Self::make_tuple_key(&src, &dst, sp, dp, "SCTP");
            return Some((key, title, "SCTP"));
        }

        None
    }

    fn selected_endpoints_owned(
        &self,
        packet: &super::owned_packet::OwnedPacket,
    ) -> (String, String) {
        for name in ["IPv4", "IPv6"] {
            if let Some(layer) = packet.layer_by_name(name) {
                let src = packet
                    .field_by_name(layer, "src")
                    .map(|f| loader::format_addr_value(&f.value.to_field_value(packet)))
                    .unwrap_or_default();
                let dst = packet
                    .field_by_name(layer, "dst")
                    .map(|f| loader::format_addr_value(&f.value.to_field_value(packet)))
                    .unwrap_or_default();
                return (src, dst);
            }
        }
        (String::new(), String::new())
    }

    fn make_tuple_key(
        src: &str,
        dst: &str,
        sp: u16,
        dp: u16,
        protocol: &'static str,
    ) -> (StreamKey, String) {
        let (addr_lo, addr_hi, port_lo, port_hi) = if (src, sp) <= (dst, dp) {
            (src.to_string(), dst.to_string(), sp, dp)
        } else {
            (dst.to_string(), src.to_string(), dp, sp)
        };
        let title = format!("{protocol} Stream: {src}:{sp} \u{2194} {dst}:{dp}");
        (
            StreamKey::Tuple {
                addr_lo,
                addr_hi,
                port_lo,
                port_hi,
                protocol,
            },
            title,
        )
    }

    /// Number of packets to scan per stream-build tick.
    const STREAM_CHUNK_SIZE: usize = 10_000;

    /// Process one chunk of the in-progress stream build.
    /// Returns `true` while the scan is still running.
    pub fn stream_tick(&mut self) -> bool {
        let total = self.indices.len();
        let progress = match &mut self.stream_build_progress {
            Some(p) => p,
            None => return false,
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
            if self
                .registry
                .dissect_with_link_type(data, index.link_type as u32, buf)
                .is_err()
            {
                continue;
            }

            let matches = match &progress.stream_key {
                StreamKey::TcpStreamId(target_id) => {
                    buf.layer_by_name("TCP").is_some_and(|tcp| {
                        buf.field_by_name(tcp, "stream_id").is_some_and(|f| {
                            matches!(f.value, packet_dissector_core::field::FieldValue::U32(id) if id == *target_id)
                        })
                    })
                }
                StreamKey::Tuple {
                    addr_lo,
                    addr_hi,
                    port_lo,
                    port_hi,
                    protocol,
                } => {
                    if let Some(layer) = buf.layer_by_name(protocol) {
                        let sp =
                            loader::extract_u16_field(buf, layer, "src_port").unwrap_or(0);
                        let dp =
                            loader::extract_u16_field(buf, layer, "dst_port").unwrap_or(0);
                        let (src, dst) = extract_ip_addrs(buf);
                        let (a_lo, a_hi, p_lo, p_hi) =
                            if (&src, sp) <= (&dst, dp) {
                                (&src, &dst, sp, dp)
                            } else {
                                (&dst, &src, dp, sp)
                            };
                        a_lo == addr_lo && a_hi == addr_hi && p_lo == *port_lo && p_hi == *port_hi
                    } else {
                        false
                    }
                }
            };

            if matches {
                // Determine direction.
                let (src_addr, _) = extract_ip_addrs(buf);
                let is_client = if let Some(ref client) = progress.client_addr {
                    &src_addr == client
                } else {
                    progress.client_addr = Some(src_addr.clone());
                    true
                };

                // Extract payload: bytes after the transport layer.
                let transport_end = buf
                    .layer_by_name(progress.protocol)
                    .map(|l| l.range.end)
                    .unwrap_or(0);
                if transport_end < data.len() {
                    let payload = &data[transport_end..];
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
            }
        }
        progress.cursor = end;

        if progress.cursor >= total {
            if let Some(p) = std::mem::take(&mut self.stream_build_progress) {
                self.stream_view = Some(StreamViewState {
                    lines: p.lines,
                    scroll_offset: 0,
                    title: p.title,
                });
            }
            return false;
        }
        true
    }
}

/// Extract IP source and destination addresses from a DissectBuffer.
fn extract_ip_addrs(buf: &DissectBuffer<'_>) -> (String, String) {
    for name in ["IPv4", "IPv6"] {
        if let Some(layer) = buf.layer_by_name(name) {
            let src = buf
                .field_by_name(layer, "src")
                .map(|f| super::loader::format_addr_value(&f.value))
                .unwrap_or_default();
            let dst = buf
                .field_by_name(layer, "dst")
                .map(|f| super::loader::format_addr_value(&f.value))
                .unwrap_or_default();
            return (src, dst);
        }
    }
    (String::new(), String::new())
}

/// Extract a u16 from an OwnedPacket field.
fn owned_u16(
    packet: &super::owned_packet::OwnedPacket,
    layer: &packet_dissector_core::packet::Layer,
    name: &str,
) -> Option<u16> {
    let f = packet.field_by_name(layer, name)?;
    match f.value.to_field_value(packet) {
        packet_dissector_core::field::FieldValue::U16(v) => Some(v),
        _ => None,
    }
}

/// Convert raw bytes to ASCII, replacing non-printable characters with `.`.
pub(super) fn payload_to_ascii(data: &[u8]) -> String {
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

#[cfg(all(test, feature = "tui"))]
mod tests {
    use super::super::test_util::make_test_app;
    use super::payload_to_ascii;

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

    #[test]
    fn start_follow_stream_noop_without_selection() {
        let mut app = make_test_app(0);
        assert!(app.selected.is_none());
        app.start_follow_stream();
        assert!(app.stream_build_progress.is_none());
    }

    #[test]
    fn follow_stream_udp_produces_state() {
        let mut app = make_test_app(3);
        app.start_follow_stream();
        assert!(app.stream_build_progress.is_some());
        while app.stream_tick() {}
        let sv = app.stream_view.as_ref().expect("stream_view set");
        assert!(
            sv.title.contains("UDP Stream"),
            "unexpected title: {}",
            sv.title
        );
    }
}
