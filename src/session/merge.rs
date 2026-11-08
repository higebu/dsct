//! Writing pcapng files: chosen packets of a capture, and the displayed
//! packets of several captures merged by time; and the packet nearest in
//! time to another.

use std::io::{self, Write};

use super::Session;
use super::fields::timestamp_us;

impl Session {
    /// Capture time of packet `pkt_idx`, in microseconds since the Unix
    /// epoch.
    pub fn packet_time_us(&self, pkt_idx: usize) -> Option<u64> {
        let index = self.indices.get(pkt_idx)?;
        Some(timestamp_us(index.timestamp_secs, index.timestamp_usecs))
    }

    /// The displayed row whose packet is nearest in time to `t_us`, and the
    /// signed distance in microseconds (packet time − `t_us`). The earliest
    /// such row wins a tie.
    pub fn nearest_row(&self, t_us: u64) -> Option<(usize, i64)> {
        let mut best: Option<(usize, i64)> = None;
        for (row, idx) in self.filtered.iter_from(0).enumerate() {
            let Some(t) = self.packet_time_us(idx) else {
                continue;
            };
            let delta = t as i64 - t_us as i64;
            if best.is_none_or(|(_, d)| delta.unsigned_abs() < d.unsigned_abs()) {
                best = Some((row, delta));
            }
        }
        best
    }
}

/// pcapng block types (draft-ietf-opsawg-pcapng, Section 4).
const SHB: u32 = 0x0A0D_0D0A;
const IDB: u32 = 0x0000_0001;
const EPB: u32 = 0x0000_0006;
const BYTE_ORDER_MAGIC: u32 = 0x1A2B_3C4D;

/// Write one pcapng block: type, total length, `body` padded to 32 bits,
/// total length again.
fn write_block(out: &mut impl Write, block_type: u32, body: &[u8]) -> io::Result<()> {
    let padded = body.len().div_ceil(4) * 4;
    let total = u32::try_from(12 + padded)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pcapng block too large"))?;
    out.write_all(&block_type.to_le_bytes())?;
    out.write_all(&total.to_le_bytes())?;
    out.write_all(body)?;
    out.write_all(&[0u8; 3][..padded - body.len()])?;
    out.write_all(&total.to_le_bytes())
}

/// Write the displayed packets of `sessions` into `out` as one pcapng file,
/// in capture-time order (packets with the same time keep the order of
/// `sessions`, then of their capture). Each source keeps its link types
/// through an interface per (session, link type).
///
/// Returns, for each packet written, the index in `sessions` it came from.
pub fn write_merged_pcapng(sessions: &[&Session], out: &mut impl Write) -> io::Result<Vec<u8>> {
    if sessions.len() > usize::from(u8::MAX) + 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "too many captures to merge",
        ));
    }
    // Every packet to write: (time, source, index in its session).
    let mut packets: Vec<(u64, u8, usize)> = Vec::new();
    for (source, session) in sessions.iter().enumerate() {
        for idx in session.filtered.iter_from(0) {
            if let Some(t) = session.packet_time_us(idx) {
                packets.push((t, source as u8, idx));
            }
        }
    }
    // Stable: ties keep source, then capture order.
    packets.sort_by_key(|&(t, source, idx)| (t, source, idx));
    write_packets(sessions, &packets, out)
}

impl Session {
    /// Write the packets at `pkt_indices` (in that order) into `out` as a
    /// pcapng file, keeping their link types and timestamps.
    ///
    /// Returns how many packets were written.
    pub fn write_pcapng(&self, pkt_indices: &[usize], out: &mut impl Write) -> io::Result<usize> {
        let packets: Vec<(u64, u8, usize)> = pkt_indices
            .iter()
            .filter_map(|&idx| Some((self.packet_time_us(idx)?, 0, idx)))
            .collect();
        Ok(write_packets(&[self], &packets, out)?.len())
    }
}

/// Write `packets` — (time, source, index in its session) — of `sessions`
/// into `out` as one pcapng file, in that order, with an interface per
/// (source, link type) at the default microsecond resolution.
fn write_packets(
    sessions: &[&Session],
    packets: &[(u64, u8, usize)],
    out: &mut impl Write,
) -> io::Result<Vec<u8>> {
    // Section Header Block: byte-order magic, version 1.0, unknown length.
    let mut shb = Vec::with_capacity(16);
    shb.extend_from_slice(&BYTE_ORDER_MAGIC.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&u64::MAX.to_le_bytes());
    write_block(out, SHB, &shb)?;

    let mut interfaces: Vec<(u8, u16)> = Vec::new();
    let mut sources = Vec::with_capacity(packets.len());
    for &(t, source, idx) in packets {
        let session = sessions[usize::from(source)];
        let Some(index) = session.indices.get(idx) else {
            continue;
        };
        let Some(data) = session.capture.packet_data(index) else {
            continue;
        };
        let key = (source, index.link_type);
        let interface = match interfaces.iter().position(|&k| k == key) {
            Some(i) => i,
            None => {
                let mut idb = Vec::with_capacity(8);
                idb.extend_from_slice(&index.link_type.to_le_bytes());
                idb.extend_from_slice(&0u16.to_le_bytes());
                idb.extend_from_slice(&0u32.to_le_bytes()); // no snap length
                write_block(out, IDB, &idb)?;
                interfaces.push(key);
                interfaces.len() - 1
            }
        };
        let mut epb = Vec::with_capacity(20 + data.len());
        epb.extend_from_slice(&(interface as u32).to_le_bytes());
        epb.extend_from_slice(&((t >> 32) as u32).to_le_bytes());
        epb.extend_from_slice(&(t as u32).to_le_bytes());
        epb.extend_from_slice(&(data.len() as u32).to_le_bytes());
        epb.extend_from_slice(&index.original_len.to_le_bytes());
        epb.extend_from_slice(data);
        write_block(out, EPB, &epb)?;
        sources.push(source);
    }
    Ok(sources)
}

#[cfg(test)]
mod tests {
    use packet_dissector::registry::DissectorRegistry;

    use super::super::loader;
    use super::super::tests::test_session;
    use super::*;

    /// A session over a pcap with `times` (µs) as its packets' timestamps.
    fn session_at(times: &[u64]) -> (Session, tempfile::NamedTempFile) {
        let mut pcap = loader::tests::build_pcap_for_test(times.len());
        // Rewrite each record's timestamp (records follow the 24-byte header).
        let mut off = 24;
        for &t in times {
            pcap[off..off + 4].copy_from_slice(&((t / 1_000_000) as u32).to_le_bytes());
            pcap[off + 4..off + 8].copy_from_slice(&((t % 1_000_000) as u32).to_le_bytes());
            let len = u32::from_le_bytes(pcap[off + 8..off + 12].try_into().unwrap()) as usize;
            off += 16 + len;
        }
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&pcap).unwrap();
        let capture = loader::open_and_mmap(tmp.path()).unwrap();
        let indices = loader::build_index(capture.as_bytes()).unwrap();
        let session = Session::new(
            capture,
            indices,
            DissectorRegistry::default(),
            tmp.path(),
            vec![],
        );
        (session, tmp)
    }

    #[test]
    fn nearest_row_finds_the_closest_packet_in_time() {
        let (session, _tmp) = session_at(&[1_000, 2_000, 5_000]);
        assert_eq!(session.packet_time_us(1), Some(2_000));
        assert_eq!(session.nearest_row(2_100), Some((1, -100)));
        assert_eq!(session.nearest_row(4_000), Some((2, 1_000)));
        assert_eq!(session.nearest_row(0), Some((0, 1_000)));
        // A tie keeps the earlier row.
        assert_eq!(session.nearest_row(1_500), Some((0, -500)));

        let (empty, _tmp) = test_session(0);
        assert_eq!(empty.nearest_row(0), None);
    }

    #[test]
    fn merge_orders_packets_by_time_and_reads_back() {
        let (a, _ta) = session_at(&[1_000, 3_000, 5_000]);
        let (b, _tb) = session_at(&[2_000, 3_000, 6_000]);
        let mut out = Vec::new();
        let sources = write_merged_pcapng(&[&a, &b], &mut out).unwrap();
        assert_eq!(sources, [0, 1, 0, 1, 0, 1]);

        let indices = loader::build_index(&out).unwrap();
        let times: Vec<u64> = indices
            .iter()
            .map(|i| timestamp_us(i.timestamp_secs, i.timestamp_usecs))
            .collect();
        assert_eq!(times, [1_000, 2_000, 3_000, 3_000, 5_000, 6_000]);
        assert!(indices.iter().all(|i| i.link_type == 1));
        // The packets are the same bytes.
        let first = &out[indices[0].data_offset as usize..][..indices[0].captured_len as usize];
        assert_eq!(first, a.capture.packet_data(&a.indices[0]).unwrap());
    }

    #[test]
    fn chosen_packets_are_written_in_their_order() {
        let (a, _ta) = session_at(&[1_000, 2_000, 3_000]);
        let mut out = Vec::new();
        assert_eq!(a.write_pcapng(&[2, 0, 9], &mut out).unwrap(), 2);
        let indices = loader::build_index(&out).unwrap();
        let times: Vec<u64> = indices
            .iter()
            .map(|i| timestamp_us(i.timestamp_secs, i.timestamp_usecs))
            .collect();
        assert_eq!(times, [3_000, 1_000]);
    }

    #[test]
    fn merge_takes_only_the_displayed_packets() {
        let (mut a, _ta) = session_at(&[1_000, 2_000, 3_000]);
        let (b, _tb) = session_at(&[1_500]);
        a.apply_filter("packet_number = 2").unwrap();
        while a.filter_running() {
            let _ = a.filter_tick();
        }
        let mut out = Vec::new();
        assert_eq!(write_merged_pcapng(&[&a, &b], &mut out).unwrap(), [1, 0]);
    }
}
