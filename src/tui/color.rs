//! Protocol-based color theme for the TUI.

use ratatui::style::Color;

/// Palette of visually distinct colors for dark-background terminals.
/// White is intentionally excluded so every protocol gets a colored row.
const PALETTE: &[Color] = &[
    Color::LightBlue,
    Color::LightCyan,
    Color::LightGreen,
    Color::LightMagenta,
    Color::LightRed,
    Color::LightYellow,
    Color::Cyan,
    Color::Green,
    Color::Magenta,
    Color::Yellow,
    Color::Blue,
    Color::Red,
];

/// Return a deterministic text color for the given protocol name.
///
/// The same protocol name always maps to the same color.  Colors are
/// derived by hashing the protocol name and indexing into a fixed palette,
/// so no manual per-protocol mapping is required.
pub fn protocol_color(protocol: &str) -> Color {
    // FNV-1a 32-bit hash — fast, zero dependencies, good avalanche effect.
    let hash = protocol
        .bytes()
        .fold(2166136261u32, |h, b| (h ^ b as u32).wrapping_mul(16777619));
    PALETTE[hash as usize % PALETTE.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_protocol_always_same_color() {
        assert_eq!(protocol_color("TCP"), protocol_color("TCP"));
        assert_eq!(protocol_color("DNS"), protocol_color("DNS"));
        assert_eq!(
            protocol_color("UnknownProto"),
            protocol_color("UnknownProto")
        );
    }

    #[test]
    fn color_is_never_white() {
        for proto in &[
            "TCP",
            "UDP",
            "DNS",
            "HTTP",
            "TLS",
            "ICMP",
            "ICMPv6",
            "ARP",
            "DHCP",
            "DHCPv6",
            "SIP",
            "GTPv1-U",
            "GTPv2-C",
            "UnknownProto",
            "OSPF",
            "BGP",
            "SCTP",
            "RADIUS",
        ] {
            assert_ne!(protocol_color(proto), Color::White, "protocol: {proto}");
        }
    }

    #[test]
    fn color_is_in_palette() {
        for proto in &["TCP", "UDP", "DNS", "HTTP", "QUIC", "SomeNewProto"] {
            let c = protocol_color(proto);
            assert!(PALETTE.contains(&c), "protocol: {proto}, color: {c:?}");
        }
    }

    #[test]
    fn distinct_protocols_not_all_same_color() {
        let colors: Vec<Color> = ["TCP", "UDP", "DNS", "HTTP", "TLS", "ICMP"]
            .iter()
            .map(|p| protocol_color(p))
            .collect();
        let unique: std::collections::HashSet<_> = colors.iter().collect();
        assert!(unique.len() > 1, "all protocols got the same color");
    }
}
