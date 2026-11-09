//! Capture and job state types shared by every frontend.

use std::ops::Range;

use super::filter_bitmap::FilterBitmap;
use super::owned_packet::OwnedPacket;

/// Minimal index entry per packet — only position and pcap header fields.
///
/// At 32 bytes per packet, a 1M-packet capture uses ~32 MB of index memory.
/// All display data (source, destination, protocol, info) is derived on demand
/// by dissecting the mmap-backed raw bytes for visible rows only.
#[derive(Clone)]
pub struct PacketIndex {
    /// Byte offset of the packet *data* (not the record header) in the file.
    pub data_offset: u64,
    /// Captured length in bytes.
    pub captured_len: u32,
    /// Original (on-wire) length in bytes.
    pub original_len: u32,
    /// Timestamp seconds since the Unix epoch.
    pub timestamp_secs: u64,
    /// Sub-second part of the timestamp in microseconds.
    pub timestamp_usecs: u32,
    /// Link-layer type (needed for dissection).
    pub link_type: u16,
    /// Padding for alignment.
    pub _pad: u16,
}

/// Live capture mode state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveMode {
    /// Actively streaming from stdin; new packets appear live.
    Live,
    /// User paused; background buffering continues but UI is frozen.
    Paused,
    /// stdin EOF reached; capture is complete (behaves like normal file mode).
    Complete,
}

/// Memory-mapped capture file providing zero-copy access to packet data.
pub struct CaptureMap {
    mmap: memmap2::Mmap,
    /// Held open for live mode re-mmap. `None` for static file mode.
    file: Option<std::fs::File>,
}

#[allow(unsafe_code)]
impl CaptureMap {
    /// Create a `CaptureMap` from an open file (static file mode).
    ///
    /// # Safety
    ///
    /// This uses `unsafe` internally for the mmap call.  The file must not be
    /// truncated or modified by external processes while the mapping is alive.
    pub fn new(file: &std::fs::File) -> std::io::Result<Self> {
        // SAFETY: The file is opened read-only and we hold no mutable
        // references to the mapped region.  The caller must ensure the file is
        // not truncated by external processes while this mapping is alive.
        // On most platforms the OS prevents truncation of files that have
        // active read-only mappings.
        let mmap = unsafe { memmap2::MmapOptions::new().map(file)? };
        Ok(Self { mmap, file: None })
    }

    /// Create a `CaptureMap` for live capture mode, retaining the file handle
    /// so that the mmap can be refreshed as the file grows.
    pub fn new_live(file: std::fs::File) -> std::io::Result<Self> {
        let file_len = file.metadata()?.len();
        let mmap = if file_len == 0 {
            // The temp file is empty at startup (no data from stdin yet).
            // Linux mmap(2) rejects zero-length mappings, so use an anonymous
            // empty mapping as a placeholder until `refresh()` creates a real
            // file-backed mapping once data arrives.
            memmap2::MmapMut::map_anon(0)?.make_read_only()?
        } else {
            // SAFETY: The file is append-only: the background `StdinCopier`
            // thread writes sequentially and we only read bytes up to a
            // previously observed file length.  We re-mmap via `refresh()`
            // before accessing newly written bytes, so no data race on the
            // mapped region occurs.
            unsafe { memmap2::MmapOptions::new().map(&file)? }
        };
        Ok(Self {
            mmap,
            file: Some(file),
        })
    }

    /// Re-map the file if it has grown.  Returns `true` if the mmap was
    /// refreshed (i.e. new data is available), `false` if unchanged.
    ///
    /// No-op in static file mode (always returns `Ok(false)`).
    pub fn refresh(&mut self) -> std::io::Result<bool> {
        let file = match &self.file {
            Some(f) => f,
            None => return Ok(false),
        };
        let file_len = file.metadata()?.len() as usize;
        if file_len < self.mmap.len() {
            // File was truncated.  The append-only invariant is violated;
            // surface it instead of leaving a stale mmap that could SIGBUS
            // on the next `packet_data()` read.
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "capture file was truncated; mmap append-only invariant violated",
            ));
        }
        if file_len == self.mmap.len() {
            return Ok(false);
        }
        // SAFETY: The file is append-only.  We have just confirmed
        // `file_len > self.mmap.len()` above (the truncation case returned
        // `Err`), so the new mapping is strictly larger than the old one.
        // We drop the old mmap before creating a fresh read-only mapping of
        // the new file size.  Existing byte offsets remain valid because
        // truncation is rejected on the error path above.
        let new_mmap = unsafe { memmap2::MmapOptions::new().map(file)? };
        self.mmap = new_mmap;
        Ok(true)
    }

    /// Return the raw bytes of a packet as a zero-copy slice into the mmap.
    ///
    /// Returns `None` if the index refers to a region beyond the current mmap
    /// (can happen briefly in live capture before a refresh).
    pub fn packet_data(&self, index: &PacketIndex) -> Option<&[u8]> {
        let start = index.data_offset as usize;
        let end = start + index.captured_len as usize;
        self.mmap.get(start..end)
    }

    /// Return the entire mmap as a byte slice (for index scanning).
    pub fn as_bytes(&self) -> &[u8] {
        &self.mmap
    }
}

/// Cached display summary for a packet list row.
pub struct RowSummary {
    /// Best source address.
    pub source: String,
    /// Best destination address.
    pub destination: String,
    /// Topmost protocol short name.
    pub protocol: &'static str,
    /// Tunnelling protocols the packet is carried in, outermost first
    /// (`["GTPv1-U"]`): layers below the topmost one whose dissector
    /// declares [`ProtocolLayer::Tunnel`](packet_dissector_core::dissector::ProtocolLayer::Tunnel).
    pub tunnels: Vec<&'static str>,
    /// Protocol-specific info string.
    pub info: String,
}

/// Full data for the currently selected packet, loaded on demand.
pub struct SelectedPacket {
    /// Index into `indices` for this packet.
    pub pkt_idx: usize,
    /// Fully dissected packet (all layers and fields), owned for long-term storage.
    pub packet: OwnedPacket,
    /// Pre-built tree nodes for the detail pane.
    pub tree_nodes: Vec<TreeNode>,
    /// Whether this is a placeholder shown until the in-order dissection
    /// pass reaches the packet (see [`super::ordered_pass`]).
    pub pending: bool,
}

/// A flattened tree node for the protocol detail pane.
pub struct TreeNode {
    /// Display label (e.g., "Source: 10.0.0.1" or "▼ Ethernet II").
    pub label: String,
    /// Nesting depth (0 = protocol layer header).
    pub depth: usize,
    /// Whether this node is expanded (only meaningful for parent nodes).
    pub expanded: bool,
    /// Byte range in the raw packet that this node spans.
    pub byte_range: Range<usize>,
    /// Number of direct children.
    pub children_count: usize,
    /// Whether this is a protocol layer header (vs a field).
    pub is_layer: bool,
    /// The field and value a filter selects this node by (a protocol for a
    /// layer header); `None` for containers and values a filter cannot
    /// compare.
    pub filter: Option<super::fields::FieldRef>,
}

/// Progress state for chunked initial file indexing.
///
/// While this is `Some`, new packets are being indexed in chunks each tick.
/// The user can interact with already-indexed packets during this time.
pub struct IndexProgress {
    /// Resumable indexing state from `packet_dissector_pcap`.
    pub state: packet_dissector_pcap::IndexState,
    /// Total file size in bytes (for progress fraction calculation).
    pub total_bytes: usize,
}

impl IndexProgress {
    /// Fraction complete (0.0 to 1.0) based on byte position.
    pub fn fraction(&self) -> f64 {
        if self.total_bytes == 0 {
            1.0
        } else {
            self.state.byte_offset as f64 / self.total_bytes as f64
        }
    }
}

/// Progress state for a chunked filter scan.
pub struct FilterProgress {
    /// The parsed filter expression.
    pub expr: Option<crate::filter_expr::FilterExpr>,
    /// Next packet index to scan.
    pub cursor: usize,
    /// Accumulated matching indices as a bitmap.
    pub results: FilterBitmap,
    /// Registry the scan dissects with.  Every scan starts from a fresh one,
    /// so its result does not depend on what the display dissected before.
    pub registry: packet_dissector::registry::DissectorRegistry,
    /// Set when finishing a parallel scan: only these packets are dissected.
    pub in_order: Option<InOrderScan>,
}

/// The part of a parallel filter scan left to do in capture order: the
/// packets whose dissection used cross-packet state.
pub struct InOrderScan {
    /// Matches among the packets the parallel scan resolved.
    pub matches: FilterBitmap,
    /// The packets to dissect in order.
    pub in_order: FilterBitmap,
    /// Number of packets of `in_order` dissected so far.
    pub done: usize,
    /// Matches among the packets of `in_order` dissected so far.
    pub found: FilterBitmap,
}

impl FilterProgress {
    /// Fraction complete (0.0 to 1.0).  While finishing a parallel scan this
    /// is the share of the in-order packets dissected so far.
    pub fn fraction(&self, total: usize) -> f64 {
        if let Some(scan) = &self.in_order {
            let listed = scan.in_order.count_ones();
            return if listed == 0 {
                1.0
            } else {
                scan.done as f64 / listed as f64
            };
        }
        if total == 0 {
            1.0
        } else {
            self.cursor as f64 / total as f64
        }
    }
}

/// Progress state for a chunked stats collection.
pub struct StatsProgress {
    /// Next filtered index to process.
    pub cursor: usize,
    /// The stats collector accumulating results.
    pub collector: crate::stats::StatsCollector,
    /// Fresh registry for this scan, so the result does not depend on the
    /// packets displayed before.
    pub registry: packet_dissector::registry::DissectorRegistry,
    /// The displayed packets by conversation.
    pub(crate) conversations: super::conversations::ConversationCollector,
    /// The displayed packets by host.
    pub(crate) hosts: super::hosts::HostCollector,
}

impl StatsProgress {
    /// Fraction complete (0.0 to 1.0).
    pub fn fraction(&self, total: usize) -> f64 {
        if total == 0 {
            1.0
        } else {
            self.cursor as f64 / total as f64
        }
    }
}

/// Key identifying a bidirectional stream (for UDP/SCTP without built-in stream IDs).
#[derive(Clone, PartialEq, Eq)]
pub enum StreamKey {
    /// TCP stream identified by dissector-assigned sequential ID.
    TcpStreamId(u32),
    /// UDP/SCTP stream identified by canonicalized 4-tuple.
    Tuple {
        /// Smaller IP address (as string for simplicity).
        addr_lo: String,
        /// Larger IP address.
        addr_hi: String,
        /// Port corresponding to addr_lo.
        port_lo: u16,
        /// Port corresponding to addr_hi.
        port_hi: u16,
        /// Protocol name ("UDP" or "SCTP").
        protocol: &'static str,
    },
}

/// A single line in the Follow Stream view.
pub struct StreamLine {
    /// Display text (ASCII with non-printable chars replaced by `.`).
    pub text: String,
    /// Direction: true = client → server, false = server → client.
    pub is_client: bool,
}

/// Progress for chunked stream collection (large captures).
pub struct StreamBuildProgress {
    /// Stream key to match.
    pub stream_key: StreamKey,
    /// Next packet index to scan.
    pub cursor: usize,
    /// Accumulated stream lines.
    pub lines: Vec<StreamLine>,
    /// Client address (first packet's source) for direction detection.
    pub client_addr: Option<String>,
    /// Title for the stream view.
    pub title: String,
    /// Protocol layer name ("TCP", "UDP", "SCTP").
    pub protocol: &'static str,
    /// Fresh registry for this scan, so TCP stream IDs are assigned in
    /// capture order as in the detail pane.
    pub registry: packet_dissector::registry::DissectorRegistry,
}

impl StreamBuildProgress {
    /// Fraction complete (0.0 to 1.0).
    pub fn fraction(&self, total: usize) -> f64 {
        if total == 0 {
            1.0
        } else {
            self.cursor as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_index_size() {
        assert_eq!(std::mem::size_of::<PacketIndex>(), 32);
    }

    #[test]
    fn index_progress_fraction() {
        let progress = IndexProgress {
            state: packet_dissector_pcap::IndexState {
                byte_offset: 500,
                format: packet_dissector_pcap::IndexFormat::Pcap {
                    is_le: true,
                    link_type: 1,
                },
                done: false,
            },
            total_bytes: 1000,
        };
        assert!((progress.fraction() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn index_progress_fraction_zero_total() {
        let progress = IndexProgress {
            state: packet_dissector_pcap::IndexState {
                byte_offset: 0,
                format: packet_dissector_pcap::IndexFormat::Pcap {
                    is_le: true,
                    link_type: 1,
                },
                done: true,
            },
            total_bytes: 0,
        };
        assert!((progress.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn capture_map_new_live_and_refresh() {
        use std::io::Write;

        // Build a minimal pcap with 2 packets.
        let pcap_2 = super::super::loader::tests::build_pcap_for_test(2);
        let pcap_5 = super::super::loader::tests::build_pcap_for_test(5);

        // Write the first 2 packets to a temp file.
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&pcap_2).unwrap();
        tmp.flush().unwrap();

        let file = tmp.as_file().try_clone().unwrap();
        let mut capture = CaptureMap::new_live(file).unwrap();
        assert_eq!(capture.as_bytes().len(), pcap_2.len());

        // No growth → refresh returns false.
        assert!(!capture.refresh().unwrap());

        // Append more packets (overwrite with 5-packet pcap).
        tmp.as_file().set_len(0).unwrap();
        use std::io::Seek;
        tmp.seek(std::io::SeekFrom::Start(0)).unwrap();
        tmp.write_all(&pcap_5).unwrap();
        tmp.flush().unwrap();

        // File grew → refresh returns true.
        assert!(capture.refresh().unwrap());
        assert_eq!(capture.as_bytes().len(), pcap_5.len());

        // Same size → refresh returns false.
        assert!(!capture.refresh().unwrap());
    }

    #[test]
    fn capture_map_static_refresh_is_noop() {
        let pcap = super::super::loader::tests::build_pcap_for_test(1);
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut tmp.as_file(), &pcap).unwrap();

        let file = std::fs::File::open(tmp.path()).unwrap();
        let mut capture = CaptureMap::new(&file).unwrap();
        // Static mode: refresh is always false.
        assert!(!capture.refresh().unwrap());
    }

    #[test]
    fn capture_map_new_live_empty_file() {
        use std::io::Write;

        // new_live on an empty temp file must succeed (live capture starts
        // before any pcap data arrives from stdin).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let file = tmp.as_file().try_clone().unwrap();
        let mut capture = CaptureMap::new_live(file).unwrap();
        assert_eq!(capture.as_bytes().len(), 0);

        // No data yet → refresh returns false.
        assert!(!capture.refresh().unwrap());

        // Write pcap data to the underlying temp file.
        let pcap = super::super::loader::tests::build_pcap_for_test(1);
        std::io::Write::write_all(&mut tmp.as_file(), &pcap).unwrap();
        tmp.as_file().flush().unwrap();

        // File grew → refresh creates a real file-backed mapping.
        assert!(capture.refresh().unwrap());
        assert_eq!(capture.as_bytes().len(), pcap.len());
    }

    #[test]
    fn capture_map_new_live_iterative_append_offset_invariant() {
        use std::io::Write;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let file = tmp.as_file().try_clone().unwrap();
        let mut capture = CaptureMap::new_live(file).unwrap();

        let pcap = super::super::loader::tests::build_pcap_for_test(10);
        let chunk = 16usize;
        let mut prev_len = 0usize;
        let mut written = 0usize;

        let mut i = 0;
        while written < pcap.len() {
            let lo = i * chunk;
            let hi = (lo + chunk).min(pcap.len());
            tmp.as_file().write_all(&pcap[lo..hi]).unwrap();
            tmp.as_file().flush().unwrap();
            written = hi;
            i += 1;

            let _ = capture.refresh().unwrap();
            let mmap_len = capture.as_bytes().len();

            // Core invariant: any byte we have written so far is addressable
            // through the mmap (i.e. observed offset never exceeds len).
            assert!(
                written <= mmap_len,
                "observed offset {written} exceeds mmap len {mmap_len}"
            );
            // And the mmap length is non-decreasing across refreshes.
            assert!(
                mmap_len >= prev_len,
                "mmap shrunk from {prev_len} to {mmap_len}"
            );
            prev_len = mmap_len;
        }

        assert_eq!(capture.as_bytes().len(), pcap.len());
    }

    #[test]
    fn capture_map_refresh_rejects_truncation() {
        use std::io::Write;

        let pcap = super::super::loader::tests::build_pcap_for_test(5);
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&pcap).unwrap();
        tmp.flush().unwrap();

        let file = tmp.as_file().try_clone().unwrap();
        let mut capture = CaptureMap::new_live(file).unwrap();
        assert_eq!(capture.as_bytes().len(), pcap.len());

        // Shrink the underlying file to half its size.
        let new_len = (pcap.len() / 2) as u64;
        tmp.as_file().set_len(new_len).unwrap();
        tmp.as_file().flush().unwrap();

        // refresh() must not panic and must surface InvalidData.
        let result = capture.refresh();
        assert!(
            result.is_err(),
            "refresh() should reject truncation; got {result:?}"
        );
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidData);

        // We deliberately do NOT touch `capture.as_bytes()[new_len..]`: the
        // stale tail pages would SIGBUS.  This test only enforces "no panic,
        // surfaces InvalidData".
    }
}
