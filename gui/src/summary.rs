//! One-line summaries shown beside each protocol layer in the detail tree,
//! built only from the layer's own fields so no protocol is special-cased:
//! `src → dst` and `src_port → dst_port` where a layer has them.

use dsct::session::loader::format_addr_value;
use dsct::session::owned_packet::OwnedPacket;
use dsct::session::tree::format_value;
use packet_dissector_core::packet::Layer;

/// Summary of `layer`, or `None` when it has no endpoint fields.
pub fn layer_summary(packet: &OwnedPacket, layer: &Layer) -> Option<String> {
    let pair = |a: &str, b: &str, addr: bool| {
        let fmt = |name: &str| {
            let field = packet.field_by_name(layer, name)?;
            let value = field.value.to_field_value(packet);
            Some(if addr {
                format_addr_value(&value)
            } else {
                format_value(&value)
            })
        };
        Some(format!("{} → {}", fmt(a)?, fmt(b)?))
    };
    let parts: Vec<String> = [
        pair("src", "dst", true),
        pair("src_port", "dst_port", false),
    ]
    .into_iter()
    .flatten()
    .collect();
    (!parts.is_empty()).then(|| parts.join(" · "))
}

/// Summaries of every layer of `packet`, in layer order (the order of the
/// detail tree's top-level nodes).
pub fn layer_summaries(packet: &OwnedPacket) -> Vec<Option<String>> {
    packet
        .layers
        .iter()
        .map(|layer| layer_summary(packet, layer))
        .collect()
}

#[cfg(test)]
mod tests {
    use packet_dissector::registry::DissectorRegistry;
    use packet_dissector_core::packet::DissectBuffer;

    use super::*;

    /// Ethernet + IPv4 + UDP 1000 → 53 with a 4-byte payload.
    fn frame() -> Vec<u8> {
        let mut p = vec![0x02, 0, 0, 0, 0, 0x02, 0x02, 0, 0, 0, 0, 0x01, 0x08, 0x00];
        p.extend_from_slice(&[
            0x45, 0, 0, 32, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ]);
        p.extend_from_slice(&[0x03, 0xe8, 0x13, 0x88, 0, 12, 0, 0]);
        p.extend_from_slice(b"ping");
        p
    }

    #[test]
    fn summaries_show_endpoints_per_layer() {
        let data = frame();
        let registry = DissectorRegistry::default();
        let mut buf = DissectBuffer::new();
        registry.dissect_with_link_type(&data, 1, &mut buf).unwrap();
        let packet = OwnedPacket::from_dissect_buf(&buf, &data);
        let summaries = layer_summaries(&packet);
        assert_eq!(summaries.len(), packet.layers.len());
        assert_eq!(
            summaries[0].as_deref(),
            Some("02:00:00:00:00:01 → 02:00:00:00:00:02")
        );
        assert_eq!(summaries[1].as_deref(), Some("10.0.0.1 → 10.0.0.2"));
        assert_eq!(summaries[2].as_deref(), Some("1000 → 5000"));
    }
}
