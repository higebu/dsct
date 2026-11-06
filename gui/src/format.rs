//! Text shown by the views, kept free of GPUI so it can be unit tested.

use std::ops::Range;

/// Bytes shown per hex dump line.
pub const HEX_BYTES_PER_LINE: usize = 16;

/// Number of hex dump lines for `len` bytes.
pub fn hex_line_count(len: usize) -> usize {
    len.div_ceil(HEX_BYTES_PER_LINE)
}

/// One byte of a hex dump line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexCell {
    /// Two hex digits.
    pub hex: String,
    /// The byte as printable ASCII, or `.`.
    pub ascii: char,
    /// Whether the byte lies in the highlighted range.
    pub highlighted: bool,
}

/// One line of a hex dump.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexLine {
    /// Offset of the first byte, as 4 hex digits.
    pub offset: String,
    /// The bytes of the line (at most [`HEX_BYTES_PER_LINE`]).
    pub cells: Vec<HexCell>,
}

/// Line `line` of the hex dump of `data`, highlighting `highlight`.
pub fn hex_line(data: &[u8], line: usize, highlight: Option<&Range<usize>>) -> HexLine {
    let start = line * HEX_BYTES_PER_LINE;
    let end = (start + HEX_BYTES_PER_LINE).min(data.len());
    let cells = (start..end)
        .map(|i| {
            let b = data[i];
            HexCell {
                hex: format!("{b:02x}"),
                ascii: if b.is_ascii_graphic() || b == b' ' {
                    b as char
                } else {
                    '.'
                },
                highlighted: highlight.is_some_and(|r| r.contains(&i)),
            }
        })
        .collect();
    HexLine {
        offset: format!("{start:04x}"),
        cells,
    }
}

/// The hex dump line holding the first highlighted byte, to scroll to.
pub fn first_highlighted_line(highlight: &Range<usize>) -> usize {
    highlight.start / HEX_BYTES_PER_LINE
}

/// Hues (in turns) of the protocols seen most, chosen apart from each other
/// so the rows of a typical capture are told apart at a glance.
const COMMON_HUES: &[(&str, f32)] = &[
    ("TCP", 0.75),
    ("UDP", 0.58),
    ("DNS", 0.50),
    ("HTTP", 0.33),
    ("HTTP2", 0.28),
    ("TLS", 0.08),
    ("QUIC", 0.13),
    ("ARP", 0.17),
    ("ICMP", 0.92),
    ("ICMPv6", 0.95),
];

/// Number of hues the remaining protocols are spread over.
const OTHER_HUES: usize = 16;

/// Hue (0.0–1.0) tinting the rows of `protocol`, or `None` for rows without
/// a protocol yet (placeholders).
///
/// Common protocols have fixed hues ([`COMMON_HUES`]); any other name is
/// hashed (FNV-1a) into one of [`OTHER_HUES`] evenly spaced hues, so the same
/// name always gets the same tint without a table of every protocol.
pub fn protocol_hue(protocol: &str) -> Option<f32> {
    if protocol.is_empty() {
        return None;
    }
    if let Some((_, hue)) = COMMON_HUES.iter().find(|(name, _)| *name == protocol) {
        return Some(*hue);
    }
    let hash = protocol
        .bytes()
        .fold(2166136261u32, |h, b| (h ^ b as u32).wrapping_mul(16777619));
    Some((hash as usize % OTHER_HUES) as f32 / OTHER_HUES as f32)
}

/// Progress as a whole percentage, for the status bar.
pub fn percent(fraction: f64) -> u32 {
    (fraction.clamp(0.0, 1.0) * 100.0).round() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_count_rounds_up() {
        assert_eq!(hex_line_count(0), 0);
        assert_eq!(hex_line_count(1), 1);
        assert_eq!(hex_line_count(16), 1);
        assert_eq!(hex_line_count(17), 2);
    }

    #[test]
    fn hex_line_formats_offset_bytes_and_ascii() {
        let data: Vec<u8> = (0x40..0x40 + 20).collect();
        let line = hex_line(&data, 1, None);
        assert_eq!(line.offset, "0010");
        assert_eq!(line.cells.len(), 4);
        assert_eq!(line.cells[0].hex, "50");
        assert_eq!(line.cells[0].ascii, 'P');
        assert!(line.cells.iter().all(|c| !c.highlighted));
    }

    #[test]
    fn hex_line_replaces_unprintable_bytes() {
        let line = hex_line(&[0x00, b'A', 0x7f, b' '], 0, None);
        let ascii: String = line.cells.iter().map(|c| c.ascii).collect();
        assert_eq!(ascii, ".A. ");
    }

    #[test]
    fn hex_line_highlights_the_range() {
        let data = [0u8; 32];
        let line = hex_line(&data, 0, Some(&(14..18)));
        let marked: Vec<usize> = line
            .cells
            .iter()
            .enumerate()
            .filter(|(_, c)| c.highlighted)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(marked, [14, 15]);
        let next = hex_line(&data, 1, Some(&(14..18)));
        assert!(next.cells[0].highlighted && next.cells[1].highlighted);
        assert!(!next.cells[2].highlighted);
        assert_eq!(first_highlighted_line(&(14..18)), 0);
        assert_eq!(first_highlighted_line(&(17..18)), 1);
    }

    #[test]
    fn protocol_hue_is_stable_and_in_range() {
        let common = ["TCP", "UDP", "DNS", "HTTP", "TLS", "QUIC", "ARP", "ICMP"];
        let hues: Vec<f32> = common.iter().map(|n| protocol_hue(n).unwrap()).collect();
        for (i, a) in hues.iter().enumerate() {
            for b in &hues[i + 1..] {
                assert_ne!(a, b, "common protocols share a tint");
            }
        }
        for name in common.iter().chain(&["SIP", "GTPv2-C", "NGAP", "x"]) {
            let hue = protocol_hue(name).unwrap();
            assert!((0.0..1.0).contains(&hue), "{name}: {hue}");
            assert_eq!(protocol_hue(name), Some(hue));
        }
        assert_eq!(protocol_hue(""), None);
    }

    #[test]
    fn percent_is_clamped() {
        assert_eq!(percent(-1.0), 0);
        assert_eq!(percent(0.256), 26);
        assert_eq!(percent(2.0), 100);
    }
}
