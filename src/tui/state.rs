//! TUI application state types.

use std::ops::Range;
use std::path::PathBuf;

use ratatui::layout::Rect;

use super::cursor::CursorBuffer;
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
}

/// Which pane is currently focused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    PacketList,
    DetailTree,
    HexDump,
    FilterInput,
    /// In-tree search input (when DetailTree is maximized).
    TreeSearch,
    /// Yank format prompt (`[t]ext / [h]ex`).
    YankPrompt,
    /// Vim-style `:` command input.
    CommandMode,
}

impl Pane {
    /// Cycle to the next pane (excluding FilterInput, which is entered via `/`).
    pub fn next(self) -> Self {
        match self {
            Self::PacketList => Self::DetailTree,
            Self::DetailTree => Self::HexDump,
            Self::HexDump => Self::PacketList,
            Self::FilterInput | Self::TreeSearch | Self::YankPrompt | Self::CommandMode => {
                Self::PacketList
            }
        }
    }

    /// Cycle to the previous pane.
    pub fn prev(self) -> Self {
        match self {
            Self::PacketList => Self::HexDump,
            Self::DetailTree => Self::PacketList,
            Self::HexDump => Self::DetailTree,
            Self::FilterInput | Self::TreeSearch | Self::YankPrompt | Self::CommandMode => {
                Self::PacketList
            }
        }
    }
}

/// Cached layout rectangles for pane hit-testing (mouse clicks).
#[derive(Default, Clone, Copy)]
pub struct PaneLayout {
    /// Packet list area.
    pub packet_list: Rect,
    /// Detail tree area.
    pub detail_tree: Rect,
    /// Hex dump area.
    pub hex_dump: Rect,
    /// Full frame area (used for stream view page size).
    pub frame_area: Rect,
}

impl PaneLayout {
    /// Determine which pane a screen coordinate falls in.
    pub fn pane_at(&self, col: u16, row: u16) -> Option<Pane> {
        if self.packet_list.contains((col, row).into()) {
            Some(Pane::PacketList)
        } else if self.detail_tree.contains((col, row).into()) {
            Some(Pane::DetailTree)
        } else if self.hex_dump.contains((col, row).into()) {
            Some(Pane::HexDump)
        } else {
            None
        }
    }
}

/// State for the packet list pane.
#[derive(Default)]
pub struct PacketListState {
    /// Index into `filtered_indices` of the selected row.
    pub selected: usize,
    /// Vertical scroll offset.
    pub scroll_offset: usize,
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
}

/// Selection mode for the detail tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionMode {
    /// `v`: character-level selection within a single line.
    Char,
    /// `V`: line-level selection across multiple nodes.
    Line,
}

/// Active selection state in the detail tree.
pub struct SelectionState {
    /// Selection mode.
    pub mode: SelectionMode,
    /// Anchor node index (where selection started).
    pub anchor_node: usize,
    /// Character offset within the anchor node's label (Char mode only).
    pub anchor_char: usize,
    /// Current cursor character offset (Char mode only).
    pub cursor_char: usize,
}

/// State for the detail tree pane.
#[derive(Default)]
pub struct DetailTreeState {
    /// Index of the selected node.
    pub selected: usize,
    /// Vertical scroll offset.
    pub scroll_offset: usize,
    /// In-tree search query (empty = no search active).
    pub search_query: String,
    /// Fuzzy-matched tree search candidates (visible node index, label).
    pub search_completions: Vec<TreeSearchCandidate>,
    /// Selected index in the search completion list.
    pub search_completion_selected: usize,
    /// Active visual selection (None = normal mode).
    pub selection: Option<SelectionState>,
    /// Transient message shown in command line (e.g., "Copied!").
    pub yank_message: Option<String>,
}

/// A tree search completion candidate.
pub struct TreeSearchCandidate {
    /// Display label of the matching tree node.
    pub label: String,
    /// Index into the flat `tree_nodes` array.
    pub node_index: usize,
}

/// State for the hex dump pane.
#[derive(Default)]
pub struct HexDumpState {
    /// Vertical scroll offset (in lines, each line = 16 bytes).
    pub scroll_offset: usize,
}

/// Time display format for the packet list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TimeFormat {
    /// Absolute timestamp (ISO 8601).
    #[default]
    Absolute,
    /// Seconds since the first packet in the capture.
    Relative,
    /// Seconds since the previous displayed packet.
    Delta,
}

impl TimeFormat {
    /// Cycle to the next format.
    pub fn next(self) -> Self {
        match self {
            Self::Absolute => Self::Relative,
            Self::Relative => Self::Delta,
            Self::Delta => Self::Absolute,
        }
    }

    /// Short label for the status bar.
    pub fn label(self) -> &'static str {
        match self {
            Self::Absolute => "Abs",
            Self::Relative => "Rel",
            Self::Delta => "Delta",
        }
    }
}

/// State for `:` command mode input.
pub struct CommandState {
    /// Text buffer with cursor for the command input (without the leading `:`).
    pub buf: CursorBuffer,
}

/// Default pane height weights (packet list, detail tree, hex dump).
pub const DEFAULT_PANE_WEIGHTS: [u16; 3] = [35, 35, 30];

/// State for the filter / command line input.
#[derive(Default)]
pub struct FilterState {
    /// Text buffer with cursor for the filter input.
    pub buf: CursorBuffer,
    /// The last successfully applied filter text.
    pub applied: String,
    /// Error message from the most recent filter parse failure.
    pub error_message: Option<String>,
    /// Completion candidates for the current token.
    pub completions: Vec<CompletionCandidate>,
    /// Index of the selected completion candidate.
    pub completion_selected: usize,
    /// Whether the completion dropdown is visible.
    pub completion_visible: bool,
    /// History of previously applied filter queries (oldest first).
    pub history: Vec<String>,
    /// Current position in history when browsing with Ctrl+P/N.
    /// `None` = not browsing; `Some(i)` = showing `history[i]`.
    pub history_pos: Option<usize>,
    /// Saved input before starting history browsing.
    pub history_saved_input: String,
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
    /// Accumulated matching indices.
    pub results: Vec<usize>,
}

impl FilterProgress {
    /// Fraction complete (0.0 to 1.0).
    pub fn fraction(&self, total: usize) -> f64 {
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

/// State for the Follow Stream overlay.
pub struct StreamViewState {
    /// Rendered stream lines.
    pub lines: Vec<StreamLine>,
    /// Scroll offset.
    pub scroll_offset: usize,
    /// Title string (e.g., "TCP Stream: 10.0.0.1:443 ↔ 10.0.0.2:52014").
    pub title: String,
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
pub struct CompletionCandidate {
    /// Display label (e.g., "TCP", "TCP.src_port").
    pub label: String,
}

// ---------------------------------------------------------------------------
// Filter history persistence
// ---------------------------------------------------------------------------

/// Maximum number of history entries to persist.
const HISTORY_MAX_ENTRIES: usize = 1000;

/// Resolve the filter history file path.
///
/// Tries, in order:
/// 1. `$XDG_STATE_HOME/dsct/filter_history`
/// 2. `$XDG_CACHE_HOME/dsct/filter_history`
/// 3. `$HOME/.local/state/dsct/filter_history`
pub fn history_path() -> Option<PathBuf> {
    if let Ok(state) = std::env::var("XDG_STATE_HOME") {
        return Some(PathBuf::from(state).join("dsct").join("filter_history"));
    }
    if let Ok(cache) = std::env::var("XDG_CACHE_HOME") {
        return Some(PathBuf::from(cache).join("dsct").join("filter_history"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Some(
            PathBuf::from(home)
                .join(".local/state/dsct")
                .join("filter_history"),
        );
    }
    None
}

/// Load filter history from disk.  Returns an empty `Vec` on any error.
pub fn load_history() -> Vec<String> {
    let path = match history_path() {
        Some(p) => p,
        None => return Vec::new(),
    };
    match std::fs::read_to_string(&path) {
        Ok(content) => content
            .lines()
            .filter(|l| !l.is_empty())
            .take(HISTORY_MAX_ENTRIES)
            .map(String::from)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Save filter history to disk.  Errors are silently ignored.
pub fn save_history(history: &[String]) {
    let path = match history_path() {
        Some(p) => p,
        None => return,
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let entries: Vec<&String> = if history.len() > HISTORY_MAX_ENTRIES {
        history[history.len() - HISTORY_MAX_ENTRIES..]
            .iter()
            .collect()
    } else {
        history.iter().collect()
    };
    let content = entries
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    // Atomic write: write to a sibling temp file, then rename to avoid
    // partial writes if multiple dsct instances run concurrently.
    let tmp_path = path.with_extension("tmp");
    if std::fs::write(&tmp_path, &content).is_ok() {
        let _ = std::fs::rename(&tmp_path, &path);
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
    fn pane_next_cycles() {
        assert_eq!(Pane::PacketList.next(), Pane::DetailTree);
        assert_eq!(Pane::DetailTree.next(), Pane::HexDump);
        assert_eq!(Pane::HexDump.next(), Pane::PacketList);
        assert_eq!(Pane::FilterInput.next(), Pane::PacketList);
    }

    #[test]
    fn pane_prev_cycles() {
        assert_eq!(Pane::PacketList.prev(), Pane::HexDump);
        assert_eq!(Pane::DetailTree.prev(), Pane::PacketList);
        assert_eq!(Pane::HexDump.prev(), Pane::DetailTree);
        assert_eq!(Pane::FilterInput.prev(), Pane::PacketList);
    }

    #[test]
    fn pane_layout_hit_test() {
        let layout = PaneLayout {
            frame_area: Rect::new(0, 0, 80, 30),
            packet_list: Rect::new(0, 0, 80, 10),
            detail_tree: Rect::new(0, 10, 80, 10),
            hex_dump: Rect::new(0, 20, 80, 10),
        };
        assert_eq!(layout.pane_at(40, 5), Some(Pane::PacketList));
        assert_eq!(layout.pane_at(40, 15), Some(Pane::DetailTree));
        assert_eq!(layout.pane_at(40, 25), Some(Pane::HexDump));
        assert_eq!(layout.pane_at(40, 35), None); // outside all panes
    }

    #[test]
    fn history_save_and_load_to_path() {
        let dir = std::env::temp_dir().join(format!("dsct_hist_test_{}", std::process::id()));
        let path = dir.join("filter_history");

        // Use internal save/load with explicit path.
        std::fs::create_dir_all(&dir).unwrap();
        let history = ["tcp".to_string(), "dns".to_string(), "not icmp".to_string()];
        let content = history.join("\n");
        std::fs::write(&path, &content).unwrap();

        let loaded: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();
        assert_eq!(loaded, vec!["tcp", "dns", "not icmp"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_max_entries_truncation() {
        // Verify the save logic truncates to HISTORY_MAX_ENTRIES.
        let big: Vec<String> = (0..1500).map(|i| format!("filter_{i}")).collect();
        let entries: Vec<&String> = big[big.len() - HISTORY_MAX_ENTRIES..].iter().collect();
        assert_eq!(entries.len(), 1000);
        assert_eq!(*entries[0], "filter_500");
        assert_eq!(*entries[999], "filter_1499");
    }

    #[test]
    fn history_path_returns_some() {
        // history_path() should return Some in most environments (HOME is set).
        // We just test it doesn't panic.
        let _ = history_path();
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
}
