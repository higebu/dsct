//! TUI application state and core accessors.

use std::num::NonZeroUsize;

use lru::LruCache;
use packet_dissector::registry::DissectorRegistry;

use super::completion::CompletionEngine;
use super::live::StdinCopier;
use super::loader;
use super::state::{
    CaptureMap, CommandState, DEFAULT_PANE_WEIGHTS, DetailTreeState, FilterProgress, FilterState,
    HexDumpState, IndexProgress, LiveMode, PacketIndex, PacketListState, Pane, PaneLayout,
    RowSummary, SelectedPacket, StatsProgress, StreamBuildProgress, StreamViewState, TimeFormat,
    TreeNode,
};

/// Maximum number of cached row summaries.
#[allow(clippy::unwrap_used)]
const SUMMARY_CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(2000).unwrap();

/// Top-level application state.
pub struct App {
    /// Capture file name (for status line display).
    pub file_name: String,
    /// Memory-mapped capture file.
    pub capture: CaptureMap,
    /// Minimal index of all packets (32 bytes each).
    pub indices: Vec<PacketIndex>,
    /// Indices into `indices` matching the current filter.
    pub filtered_indices: Vec<usize>,
    /// Dissector registry (for on-demand dissection).
    pub registry: DissectorRegistry,
    /// Fuzzy completion engine for filter input.
    pub completion_engine: CompletionEngine,
    /// LRU cache of dissected row summaries.
    pub summary_cache: LruCache<usize, RowSummary>,
    /// The currently selected packet's full data (loaded on demand).
    pub selected: Option<SelectedPacket>,
    /// Currently focused pane.
    pub active_pane: Pane,
    /// Packet list pane state.
    pub packet_list: PacketListState,
    /// Protocol detail tree pane state.
    pub detail_tree: DetailTreeState,
    /// Hex dump pane state.
    pub hex_dump: HexDumpState,
    /// Filter input state.
    pub filter: FilterState,
    /// In-progress filter scan (None = idle).
    pub filter_progress: Option<FilterProgress>,
    /// Maximized pane (None = normal layout).
    pub maximized_pane: Option<Pane>,
    /// Per-pane height weights [packet_list, detail_tree, hex_dump].
    pub pane_weights: [u16; 3],
    /// Pending digit input for number+G jump.
    pub pending_count: String,
    /// Whether the help overlay is visible.
    pub show_help: bool,
    /// Time display format.
    pub time_format: TimeFormat,
    /// Follow Stream view (None = not showing).
    pub stream_view: Option<StreamViewState>,
    /// In-progress stream collection (chunked).
    pub stream_build_progress: Option<StreamBuildProgress>,
    /// `:` command mode state (None = inactive).
    pub command: Option<CommandState>,
    /// In-progress stats collection (None = idle).
    pub stats_progress: Option<StatsProgress>,
    /// Completed stats output (shown as overlay).
    pub stats_output: Option<crate::stats::StatsOutput>,
    /// Cached pane layout rectangles (updated each render).
    pub pane_layout: PaneLayout,
    /// Whether the application is still running.
    pub running: bool,
    /// Live capture mode (None for static file mode).
    pub live_mode: Option<LiveMode>,
    /// Background stdin copier (None for static file mode).
    pub stdin_copier: Option<StdinCopier>,
    /// Number of bytes already indexed (for incremental live indexing).
    pub indexed_bytes: usize,
    /// In-progress initial file indexing (None = idle or complete).
    pub index_progress: Option<IndexProgress>,
    /// Background indexer thread (None = idle or complete).
    pub bg_indexer: Option<super::bg_indexer::BackgroundIndexer>,
}

impl App {
    /// Create a new App from a capture map and index.
    pub fn new(
        capture: CaptureMap,
        indices: Vec<PacketIndex>,
        registry: DissectorRegistry,
        file_path: &std::path::Path,
    ) -> Self {
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file_path.display().to_string());
        let completion_engine = CompletionEngine::from_registry(&registry);
        let filtered_indices: Vec<usize> = (0..indices.len()).collect();
        let loaded_history = super::state::load_history();
        let mut app = Self {
            file_name,
            capture,
            indices,
            filtered_indices,
            registry,
            completion_engine,
            summary_cache: LruCache::new(SUMMARY_CACHE_CAPACITY),
            selected: None,
            active_pane: Pane::PacketList,
            packet_list: PacketListState::default(),
            detail_tree: DetailTreeState::default(),
            hex_dump: HexDumpState::default(),
            filter: FilterState::default(),
            filter_progress: None,
            maximized_pane: None,
            pane_weights: DEFAULT_PANE_WEIGHTS,
            pending_count: String::new(),
            show_help: false,
            stream_view: None,
            stream_build_progress: None,
            command: None,
            stats_progress: None,
            stats_output: None,
            time_format: TimeFormat::default(),
            pane_layout: PaneLayout::default(),
            running: true,
            live_mode: None,
            stdin_copier: None,
            indexed_bytes: 0,
            index_progress: None,
            bg_indexer: None,
        };
        app.filter.history = loaded_history;
        app.load_selected();
        app
    }

    /// Create a new App for live stdin capture mode.
    pub fn new_live(
        capture: CaptureMap,
        indices: Vec<PacketIndex>,
        registry: DissectorRegistry,
        copier: StdinCopier,
    ) -> Self {
        let completion_engine = CompletionEngine::from_registry(&registry);
        // Start at 0 so the first live_tick() ingests any data that was
        // already in the mmap (e.g. written before CaptureMap::new_live).
        let indexed_bytes = 0;
        let filtered_indices: Vec<usize> = (0..indices.len()).collect();
        let loaded_history = super::state::load_history();
        let mut app = Self {
            file_name: "<stdin>".to_string(),
            capture,
            indices,
            filtered_indices,
            registry,
            completion_engine,
            summary_cache: LruCache::new(SUMMARY_CACHE_CAPACITY),
            selected: None,
            active_pane: Pane::PacketList,
            packet_list: PacketListState::default(),
            detail_tree: DetailTreeState::default(),
            hex_dump: HexDumpState::default(),
            filter: FilterState::default(),
            filter_progress: None,
            maximized_pane: None,
            pane_weights: DEFAULT_PANE_WEIGHTS,
            pending_count: String::new(),
            show_help: false,
            stream_view: None,
            stream_build_progress: None,
            command: None,
            stats_progress: None,
            stats_output: None,
            time_format: TimeFormat::default(),
            pane_layout: PaneLayout::default(),
            running: true,
            live_mode: Some(LiveMode::Live),
            stdin_copier: Some(copier),
            indexed_bytes,
            index_progress: None,
            bg_indexer: None,
        };
        app.filter.history = loaded_history;
        app.load_selected();
        app
    }

    /// Number of displayed (filtered) packets.
    pub fn displayed_count(&self) -> usize {
        self.filtered_indices.len()
    }

    /// Total number of packets in the capture.
    pub fn total_count(&self) -> usize {
        self.indices.len()
    }

    /// Get the selected packet number (1-based), or 0 if nothing selected.
    pub fn selected_number(&self) -> u64 {
        self.filtered_indices
            .get(self.packet_list.selected)
            .map(|&idx| idx as u64 + 1)
            .unwrap_or(0)
    }

    /// Get the raw bytes of the selected packet from the mmap (zero-copy).
    pub fn selected_raw_bytes(&self) -> Option<&[u8]> {
        let sel = self.selected.as_ref()?;
        let index = self.indices.get(sel.pkt_idx)?;
        self.capture.packet_data(index)
    }

    /// Get the byte range highlighted by the currently selected tree node.
    pub fn selected_byte_range(&self) -> Option<std::ops::Range<usize>> {
        let sel = self.selected.as_ref()?;
        sel.tree_nodes
            .get(self.detail_tree.selected)
            .map(|node| node.byte_range.clone())
    }

    /// Get or compute a row summary for the given packet index.
    ///
    /// Uses the summary cache to avoid re-dissecting packets that have already
    /// been rendered.
    pub fn get_or_dissect_summary(&mut self, pkt_idx: usize) -> &RowSummary {
        if !self.summary_cache.contains(&pkt_idx)
            && let Some(index) = self.indices.get(pkt_idx)
            && let Some(data) = self.capture.packet_data(index)
        {
            let summary = loader::extract_row_summary(data, index.link_type as u32, &self.registry);
            self.summary_cache.put(pkt_idx, summary);
        }
        static DEFAULT: RowSummary = RowSummary {
            source: String::new(),
            destination: String::new(),
            protocol: "",
            info: String::new(),
        };
        self.summary_cache.get(&pkt_idx).unwrap_or(&DEFAULT)
    }

    /// Load the full data for the currently selected packet from the mmap.
    pub(super) fn load_selected(&mut self) {
        self.detail_tree.selected = 0;
        self.detail_tree.scroll_offset = 0;

        if let Some(&pkt_idx) = self.filtered_indices.get(self.packet_list.selected) {
            if let Some(index) = self.indices.get(pkt_idx) {
                if let Some(data) = self.capture.packet_data(index) {
                    self.selected = Some(loader::dissect_selected(
                        data,
                        index.link_type as u32,
                        pkt_idx,
                        &self.registry,
                    ));
                } else {
                    self.selected = None;
                }
            } else {
                self.selected = None;
            }
        } else {
            self.selected = None;
        }
    }

    // -- Chunked file indexing ------------------------------------------------

    /// Number of records to index per tick (used for synchronous fallback).
    const INDEX_CHUNK_SIZE: usize = 5_000;

    /// Maximum wall-clock time to spend indexing per tick before yielding back
    /// to the event loop.  Targeting ~60 fps keeps the UI responsive.
    const INDEX_TIME_BUDGET: std::time::Duration = std::time::Duration::from_millis(16);

    /// Maximum number of entries to pre-allocate on first tick.
    ///
    /// Caps the upfront allocation to ~32 MB (indices) + ~8 MB (filtered)
    /// regardless of file size.  The vecs grow naturally beyond this if needed.
    const MAX_PREALLOC: usize = 1_000_000;

    /// Drive one tick of file indexing.
    ///
    /// When a [`BackgroundIndexer`] is active, this drains results from the
    /// background thread's channel — the main thread never does indexing work
    /// itself, keeping the event loop fully responsive.
    ///
    /// Falls back to synchronous chunked indexing via [`IndexProgress`] when
    /// no background indexer is present (e.g. live capture mode).
    pub fn index_tick(&mut self) {
        if self.bg_indexer.is_some() {
            self.bg_index_tick();
        } else {
            self.sync_index_tick();
        }
    }

    /// Drain results from the background indexer thread.
    fn bg_index_tick(&mut self) {
        let bg = match &self.bg_indexer {
            Some(b) => b,
            None => return,
        };

        let (new_records, done) = bg.drain();

        if !new_records.is_empty() {
            // Capped pre-allocation on first batch.
            if self.indices.is_empty() {
                let estimate = (bg.total_bytes / 80).min(Self::MAX_PREALLOC);
                self.indices.reserve(estimate);
                self.filtered_indices.reserve(estimate);
            }

            let old_count = self.indices.len();
            let new_count = new_records.len();
            self.indices.extend(new_records);
            self.filtered_indices
                .extend(old_count..old_count + new_count);

            // Select the first packet as soon as we have data.
            if old_count == 0 && !self.indices.is_empty() && self.selected.is_none() {
                self.load_selected();
            }
        }

        if done {
            self.bg_indexer = None;
        }
    }

    /// Synchronous chunked indexing fallback (used when no background thread
    /// is available, e.g. during live capture incremental re-indexing).
    fn sync_index_tick(&mut self) {
        let progress = match &mut self.index_progress {
            Some(p) => p,
            None => return,
        };

        // Capped pre-allocation on the first tick.
        if self.indices.is_empty() {
            let estimate = (progress.total_bytes / 80).min(Self::MAX_PREALLOC);
            self.indices.reserve(estimate);
            self.filtered_indices.reserve(estimate);
        }

        let deadline = std::time::Instant::now() + Self::INDEX_TIME_BUDGET;

        loop {
            let progress = match &mut self.index_progress {
                Some(p) => p,
                None => return,
            };

            let data = self.capture.as_bytes();
            let new_records =
                match loader::index_chunk(data, &mut progress.state, Self::INDEX_CHUNK_SIZE) {
                    Ok(records) => records,
                    Err(_) => {
                        // Indexing failed; finalize with what we have.
                        self.index_progress = None;
                        if !self.indices.is_empty() {
                            self.load_selected();
                        }
                        return;
                    }
                };

            let old_count = self.indices.len();
            let new_count = new_records.len();
            self.indices.extend(new_records);

            // Extend filtered_indices (no filter is active during initial indexing).
            self.filtered_indices
                .extend(old_count..old_count + new_count);

            // Read `done` before releasing the mutable borrow on `index_progress`
            // so that `self.load_selected()` can borrow `self` mutably.
            let done = progress.state.done;

            // Select the first packet as soon as we have some data.
            if old_count == 0 && !self.indices.is_empty() && self.selected.is_none() {
                self.load_selected();
            }

            if done {
                self.index_progress = None;
                return;
            }

            if std::time::Instant::now() >= deadline {
                break;
            }
        }
    }

    // -- Live capture support ------------------------------------------------

    /// Check the background copier for EOF and transition to Complete if so.
    pub fn check_eof(&mut self) {
        if let Some(ref copier) = self.stdin_copier
            && copier.eof.load(std::sync::atomic::Ordering::Acquire)
        {
            self.live_mode = Some(LiveMode::Complete);
            // Do a final refresh to pick up any remaining data.
            // Refresh failure is benign; the next tick will retry.
            let _ = self.capture.refresh();
            self.ingest_new_packets();
        }
    }

    /// Drive one tick of live capture: refresh mmap, ingest new packets, and
    /// optionally auto-scroll.  Called from the event loop when
    /// `live_mode == Live`.
    pub fn live_tick(&mut self) {
        if self.live_mode != Some(LiveMode::Live) {
            return;
        }

        // Check for EOF first.
        if let Some(ref copier) = self.stdin_copier
            && copier.eof.load(std::sync::atomic::Ordering::Acquire)
        {
            self.live_mode = Some(LiveMode::Complete);
        }

        // Check if the file has grown.
        let new_bytes = self
            .stdin_copier
            .as_ref()
            .map(|c| c.bytes_written.load(std::sync::atomic::Ordering::Acquire) as usize)
            .unwrap_or(0);
        if new_bytes <= self.indexed_bytes {
            return;
        }

        // Refresh the mmap to see new data, then re-index.
        // We call ingest even if refresh() returns false: the initial mmap
        // created by new_live() may already contain unindexed data (e.g.
        // after wait_for_first_data).
        // Refresh failure is benign; ingest_new_packets tolerates stale data.
        let _ = self.capture.refresh();
        self.ingest_new_packets();
    }

    /// Re-index the capture data and append any new packets found.
    fn ingest_new_packets(&mut self) {
        let data = self.capture.as_bytes();
        if data.len() < 4 {
            return;
        }
        let all_indices = match loader::build_index(data) {
            Ok(idx) => idx,
            Err(_) => return,
        };

        let old_count = self.indices.len();
        let old_displayed = self.filtered_indices.len();
        let was_at_bottom =
            old_displayed == 0 || self.packet_list.selected >= old_displayed.saturating_sub(1);

        if all_indices.len() > old_count {
            let new_packets = &all_indices[old_count..];
            self.indices.extend_from_slice(new_packets);

            // If no filter is active, extend filtered_indices with the new ones.
            if self.filter.applied.is_empty() {
                let start = old_count;
                let end = self.indices.len();
                self.filtered_indices.extend(start..end);
            }
        }

        self.indexed_bytes = data.len();

        // Auto-scroll: if user was at the bottom, follow new packets.
        if was_at_bottom
            && self.live_mode == Some(LiveMode::Live)
            && !self.filtered_indices.is_empty()
        {
            self.packet_list.selected = self.filtered_indices.len() - 1;
            self.load_selected();
        }
    }
}

/// Iterator over visible (non-collapsed) tree nodes.
pub fn visible_nodes(nodes: &[TreeNode]) -> impl Iterator<Item = (usize, &TreeNode)> {
    let mut skip_depth: Option<usize> = None;
    nodes.iter().enumerate().filter(move |(_, node)| {
        if let Some(d) = skip_depth {
            if node.depth > d {
                return false;
            }
            skip_depth = None;
        }
        if !node.expanded && node.children_count > 0 {
            skip_depth = Some(node.depth);
        }
        true
    })
}

#[cfg(test)]
mod tests {
    use super::super::state::{DEFAULT_PANE_WEIGHTS, SelectionMode, StreamLine, StreamViewState};
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    /// Create a test App using an mmap over a pcap built in memory.
    fn make_test_app(n: usize) -> App {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let c = COUNTER.fetch_add(1, Ordering::Relaxed);

        let pcap = super::super::loader::tests::build_pcap_for_test(n);
        let path =
            std::env::temp_dir().join(format!("dsct_app_test_{}_{}_{c}", n, std::process::id()));
        std::fs::write(&path, &pcap).unwrap();

        let file = std::fs::File::open(&path).unwrap();
        let capture = CaptureMap::new(&file).unwrap();
        let indices = loader::build_index(capture.as_bytes()).unwrap();

        let app = App::new(
            capture,
            indices,
            DissectorRegistry::default(),
            std::path::Path::new("test.pcap"),
        );
        let _ = std::fs::remove_file(&path);
        app
    }

    #[test]
    fn new_app_selects_first_packet() {
        let app = make_test_app(5);
        assert_eq!(app.packet_list.selected, 0);
        assert_eq!(app.displayed_count(), 5);
        assert_eq!(app.total_count(), 5);
        assert!(app.running);
        assert!(app.selected.is_some());
    }

    #[test]
    fn handle_key_q_quits() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(!app.running);
    }

    #[test]
    fn handle_key_j_moves_down() {
        let mut app = make_test_app(5);
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 1);
    }

    #[test]
    fn handle_key_tab_cycles_panes() {
        let mut app = make_test_app(1);
        assert_eq!(app.active_pane, Pane::PacketList);
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::DetailTree);
    }

    #[test]
    fn move_to_top_and_bottom() {
        let mut app = make_test_app(10);
        app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 9);
        app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 0);
    }

    #[test]
    fn page_down_and_page_up() {
        let mut app = make_test_app(50);
        app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 20);
        app.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 0);
    }

    #[test]
    fn filter_input_typing() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        assert_eq!(app.filter.buf.input, "udp");
    }

    #[test]
    fn filter_apply_and_clear() {
        let mut app = make_test_app(3);
        // Filter for UDP (all test packets are UDP)
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        // Drive chunked filter to completion.
        while app.filter_tick() {}
        assert_eq!(app.displayed_count(), 3);

        // Filter for nonexistent protocol
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.filter.buf.input = "zzz".into();
        app.filter.buf.cursor = 3;
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        while app.filter_tick() {}
        assert_eq!(app.displayed_count(), 0);

        // Clear filter
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.filter.buf.input.clear();
        app.filter.buf.cursor = 0;
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        // Empty filter completes immediately, no tick needed.
        assert_eq!(app.displayed_count(), 3);
    }

    #[test]
    fn empty_app_handles_keys() {
        let mut app = make_test_app(0);
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 0);
        assert!(app.selected.is_none());
    }

    #[test]
    fn selected_raw_bytes_works() {
        let app = make_test_app(1);
        let raw = app.selected_raw_bytes();
        assert!(raw.is_some());
        assert_eq!(raw.unwrap().len(), 42);
    }

    #[test]
    fn summary_cache_works() {
        let mut app = make_test_app(5);
        // First call — cache miss, dissects
        let s = app.get_or_dissect_summary(0);
        assert_eq!(s.source, "10.0.0.1");
        assert_eq!(app.summary_cache.len(), 1);
        // Second call — cache hit
        let _ = app.get_or_dissect_summary(0);
        assert_eq!(app.summary_cache.len(), 1);
    }

    #[test]
    fn visible_nodes_hides_collapsed_children() {
        let nodes = vec![
            TreeNode {
                label: "Layer".into(),
                depth: 0,
                expanded: false,
                byte_range: 0..10,
                children_count: 2,
                is_layer: true,
            },
            TreeNode {
                label: "Field1".into(),
                depth: 1,
                expanded: false,
                byte_range: 0..4,
                children_count: 0,
                is_layer: false,
            },
        ];
        assert_eq!(visible_nodes(&nodes).count(), 1);
    }

    #[test]
    fn scroll_offset_follows_selection_via_render() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = make_test_app(100);
        let backend = TestBackend::new(120, 20); // ~12 visible rows after borders/header
        let mut terminal = Terminal::new(backend).unwrap();

        // Initial render — offset should be 0
        terminal
            .draw(|f| super::super::ui::render(f, &mut app))
            .unwrap();
        assert_eq!(app.packet_list.scroll_offset, 0);

        // Move selection past visible area
        for _ in 0..20 {
            app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        }
        // Render to trigger scroll adjustment
        terminal
            .draw(|f| super::super::ui::render(f, &mut app))
            .unwrap();
        assert_eq!(app.packet_list.selected, 20);
        // scroll_offset should have advanced so selected is visible
        assert!(app.packet_list.scroll_offset > 0);
        assert!(app.packet_list.selected < app.packet_list.scroll_offset + 20);
    }

    // -- Pane zoom --

    #[test]
    fn zoom_toggle() {
        let mut app = make_test_app(1);
        assert!(app.maximized_pane.is_none());
        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        assert_eq!(app.maximized_pane, Some(Pane::PacketList));
        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        assert!(app.maximized_pane.is_none());
    }

    #[test]
    fn tab_updates_zoom() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::DetailTree);
        assert_eq!(app.maximized_pane, Some(Pane::DetailTree));
    }

    // -- Tree expand/collapse all --

    #[test]
    fn expand_collapse_all() {
        let mut app = make_test_app(1);
        // Initially all collapsed.
        let all_collapsed = app
            .selected
            .as_ref()
            .unwrap()
            .tree_nodes
            .iter()
            .all(|n| !n.expanded);
        assert!(all_collapsed);

        // Expand all.
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        let any_expanded = app
            .selected
            .as_ref()
            .unwrap()
            .tree_nodes
            .iter()
            .any(|n| n.expanded && n.children_count > 0);
        assert!(any_expanded);

        // Collapse all.
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));
        let all_collapsed = app
            .selected
            .as_ref()
            .unwrap()
            .tree_nodes
            .iter()
            .filter(|n| n.children_count > 0)
            .all(|n| !n.expanded);
        assert!(all_collapsed);
    }

    // -- Time format --

    #[test]
    fn time_format_cycle() {
        let mut app = make_test_app(1);
        assert_eq!(app.time_format, TimeFormat::Absolute);
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.time_format, TimeFormat::Relative);
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.time_format, TimeFormat::Delta);
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.time_format, TimeFormat::Absolute);
    }

    // -- Help --

    #[test]
    fn help_toggle() {
        let mut app = make_test_app(1);
        assert!(!app.show_help);
        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert!(app.show_help);
        // Any key dismisses help.
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert!(!app.show_help);
    }

    // -- Packet number jump --

    #[test]
    fn digit_g_jump() {
        let mut app = make_test_app(50);
        // Type "25" then G.
        app.handle_key(KeyEvent::new(KeyCode::Char('2'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('5'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE));
        // Packet 25 is 1-based → index 24.
        assert_eq!(app.packet_list.selected, 24);
    }

    // -- Command mode --

    #[test]
    fn command_mode_quit() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::CommandMode);
        app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(!app.running);
    }

    #[test]
    fn command_mode_escape() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::PacketList);
        assert!(app.command.is_none());
    }

    #[test]
    fn command_write_saves_pcap() {
        let mut app = make_test_app(3);
        let path = std::env::temp_dir().join(format!("dsct_save_test_{}.pcap", std::process::id()));
        let path_str = path.display().to_string();

        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        for c in format!("w {path_str}").chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        // File should exist and be parseable.
        let data = std::fs::read(&path).unwrap();
        let records = packet_dissector_pcap::build_index(&data).unwrap();
        assert_eq!(records.len(), 3);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn command_unknown_shows_error() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        for c in "foo".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            app.detail_tree
                .yank_message
                .as_ref()
                .unwrap()
                .contains("Unknown command")
        );
    }

    // -- Filter history --

    #[test]
    fn filter_history_ctrl_p_n() {
        let mut app = make_test_app(3);

        // Apply two filters to build history.
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.filter.buf.input = "udp".into();
        app.filter.buf.cursor = 3;
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        while app.filter_tick() {}

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.filter.buf.input = "tcp".into();
        app.filter.buf.cursor = 3;
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        while app.filter_tick() {}

        assert_eq!(app.filter.history.len(), 2);

        // Enter filter mode, browse history.
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        assert_eq!(app.filter.buf.input, "tcp");
        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::CONTROL));
        assert_eq!(app.filter.buf.input, "udp");
        app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::CONTROL));
        assert_eq!(app.filter.buf.input, "tcp");
    }

    // -- Ctrl+U clears filter input --

    #[test]
    fn ctrl_u_clears_input() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        assert_eq!(app.filter.buf.input, "ab");
        app.handle_key(KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL));
        assert!(app.filter.buf.input.is_empty());
    }

    // -- Backspace exits filter when empty --

    #[test]
    fn backspace_exits_empty_filter() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::FilterInput);
        app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::PacketList);
    }

    // -- Visual selection --

    #[test]
    fn visual_line_selection() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('V'), KeyModifiers::SHIFT));
        assert!(app.detail_tree.selection.is_some());
        let sel = app.detail_tree.selection.as_ref().unwrap();
        assert_eq!(sel.mode, SelectionMode::Line);

        // Escape cancels.
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.detail_tree.selection.is_none());
    }

    #[test]
    fn visual_char_selection() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
        assert!(app.detail_tree.selection.is_some());
        let sel = app.detail_tree.selection.as_ref().unwrap();
        assert_eq!(sel.mode, SelectionMode::Char);

        // Escape cancels.
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.detail_tree.selection.is_none());
    }

    // -- Pane resize --

    #[test]
    fn pane_resize() {
        let mut app = make_test_app(1);
        let original = app.pane_weights;
        app.handle_key(KeyEvent::new(KeyCode::Char('+'), KeyModifiers::NONE));
        assert_ne!(app.pane_weights, original);
        app.handle_key(KeyEvent::new(KeyCode::Char('='), KeyModifiers::NONE));
        assert_eq!(app.pane_weights, DEFAULT_PANE_WEIGHTS);
    }

    // -- UI render with TestBackend --

    #[test]
    fn render_help_overlay() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = make_test_app(3);
        app.show_help = true;

        let backend = TestBackend::new(80, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| super::super::ui::render(f, &mut app))
            .unwrap();

        // Check that "Help" appears in the buffer.
        let buf = terminal.backend().buffer().clone();
        let text: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf.cell((x, y)).unwrap().symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("Help"));
        assert!(text.contains("j/k"));
    }

    #[test]
    fn render_command_mode() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| super::super::ui::render(f, &mut app))
            .unwrap();

        // Check ":w" appears in the buffer (command line area).
        let buf = terminal.backend().buffer().clone();
        let last_line: String = (0..buf.area.width)
            .map(|x| {
                buf.cell((x, buf.area.height - 1))
                    .unwrap()
                    .symbol()
                    .to_string()
            })
            .collect();
        assert!(last_line.contains(":w"));
    }

    #[test]
    fn render_filter_applied_in_command_line() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = make_test_app(3);
        app.filter.applied = "udp".into();

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| super::super::ui::render(f, &mut app))
            .unwrap();

        let buf = terminal.backend().buffer().clone();
        let last_line: String = (0..buf.area.width)
            .map(|x| {
                buf.cell((x, buf.area.height - 1))
                    .unwrap()
                    .symbol()
                    .to_string()
            })
            .collect();
        assert!(last_line.contains("/udp"));
    }

    // -- payload_to_ascii --

    #[test]
    fn payload_to_ascii_converts() {
        assert_eq!(
            super::super::stream::payload_to_ascii(b"Hello\x00\x01"),
            "Hello.."
        );
        assert_eq!(super::super::stream::payload_to_ascii(b"AB\nCD"), "AB\nCD");
        assert_eq!(super::super::stream::payload_to_ascii(b"\t \r"), "\t \r");
    }

    // -- visible_nodes edge cases --

    #[test]
    fn visible_nodes_all_expanded() {
        let nodes = vec![
            TreeNode {
                label: "Layer".into(),
                depth: 0,
                expanded: true,
                byte_range: 0..10,
                children_count: 1,
                is_layer: true,
            },
            TreeNode {
                label: "Field".into(),
                depth: 1,
                expanded: false,
                byte_range: 0..4,
                children_count: 0,
                is_layer: false,
            },
        ];
        assert_eq!(visible_nodes(&nodes).count(), 2);
    }

    #[test]
    fn visible_nodes_empty() {
        let nodes: Vec<TreeNode> = vec![];
        assert_eq!(visible_nodes(&nodes).count(), 0);
    }

    // -- Tree navigation (h/l) --

    #[test]
    fn tree_expand_and_collapse() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::DetailTree;

        // 'l' on a collapsed node should expand it
        app.handle_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE));
        let expanded = app
            .selected
            .as_ref()
            .unwrap()
            .tree_nodes
            .get(app.detail_tree.selected)
            .map(|n| n.expanded)
            .unwrap_or(false);
        assert!(expanded);

        // 'h' on an expanded node should collapse it
        app.handle_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE));
        let expanded = app
            .selected
            .as_ref()
            .unwrap()
            .tree_nodes
            .get(app.detail_tree.selected)
            .map(|n| n.expanded)
            .unwrap_or(true);
        assert!(!expanded);
    }

    #[test]
    fn tree_l_enters_child_when_expanded() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::DetailTree;

        // Expand first
        app.handle_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE));
        let sel_before = app.detail_tree.selected;
        // l again should move into child
        app.handle_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE));
        // selected should have changed (moved to a child)
        assert_ne!(app.detail_tree.selected, sel_before);
    }

    #[test]
    fn tree_h_moves_to_parent() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::DetailTree;

        // Expand and move into child
        app.handle_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE));
        let child_idx = app.detail_tree.selected;
        assert!(child_idx > 0);

        // h should move back to parent
        app.handle_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE));
        assert!(app.detail_tree.selected < child_idx);
    }

    // -- Toggle tree node with Enter --

    #[test]
    fn toggle_tree_node_enter() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::DetailTree;

        // Enter toggles expand on node with children
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let expanded = app
            .selected
            .as_ref()
            .unwrap()
            .tree_nodes
            .first()
            .map(|n| n.expanded)
            .unwrap_or(false);
        assert!(expanded);

        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        let collapsed = app
            .selected
            .as_ref()
            .unwrap()
            .tree_nodes
            .first()
            .map(|n| !n.expanded)
            .unwrap_or(false);
        assert!(collapsed);
    }

    // -- Stream view key handling --

    #[test]
    fn stream_view_navigation() {
        let mut app = make_test_app(1);
        app.stream_view = Some(StreamViewState {
            lines: (0..50)
                .map(|i| StreamLine {
                    text: format!("line {i}"),
                    is_client: i % 2 == 0,
                })
                .collect(),
            scroll_offset: 0,
            title: "Test Stream".into(),
        });

        // j scrolls down
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.stream_view.as_ref().unwrap().scroll_offset, 1);

        // k scrolls up
        app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        assert_eq!(app.stream_view.as_ref().unwrap().scroll_offset, 0);

        // G goes to end
        app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE));
        assert_eq!(app.stream_view.as_ref().unwrap().scroll_offset, 49);

        // g goes to start
        app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        assert_eq!(app.stream_view.as_ref().unwrap().scroll_offset, 0);

        // PageDown
        app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.stream_view.as_ref().unwrap().scroll_offset, 20);

        // PageUp
        app.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert_eq!(app.stream_view.as_ref().unwrap().scroll_offset, 0);

        // q closes stream view
        app.handle_key(KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE));
        assert!(app.stream_view.is_none());
    }

    #[test]
    fn stream_view_esc_closes() {
        let mut app = make_test_app(1);
        app.stream_view = Some(StreamViewState {
            lines: vec![],
            scroll_offset: 0,
            title: "Test".into(),
        });
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.stream_view.is_none());
    }

    // -- Command mode cursor movement --

    #[test]
    fn command_mode_cursor_movement() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        // Type "abc"
        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
        assert_eq!(app.command.as_ref().unwrap().buf.cursor, 3);

        // Left arrow
        app.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        assert_eq!(app.command.as_ref().unwrap().buf.cursor, 2);

        // Right arrow
        app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(app.command.as_ref().unwrap().buf.cursor, 3);

        // Backspace
        app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(app.command.as_ref().unwrap().buf.input, "ab");
    }

    #[test]
    fn command_mode_backspace_empty_exits() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert!(app.command.is_none());
        assert_eq!(app.active_pane, Pane::PacketList);
    }

    #[test]
    fn command_wq_saves_and_quits() {
        let mut app = make_test_app(2);
        let path = std::env::temp_dir().join(format!("dsct_wq_test_{}.pcap", std::process::id()));
        let path_str = path.display().to_string();

        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        for c in format!("wq {path_str}").chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert!(!app.running);
        let data = std::fs::read(&path).unwrap();
        let records = packet_dissector_pcap::build_index(&data).unwrap();
        assert_eq!(records.len(), 2);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn command_w_no_path_shows_error() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('w'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(
            app.detail_tree
                .yank_message
                .as_ref()
                .unwrap()
                .contains("Usage")
        );
    }

    // -- BackTab cycles panes backward --

    #[test]
    fn backtab_cycles_panes() {
        let mut app = make_test_app(1);
        assert_eq!(app.active_pane, Pane::PacketList);
        app.handle_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT));
        assert_eq!(app.active_pane, Pane::HexDump);
    }

    // -- Move in DetailTree and HexDump --

    #[test]
    fn detail_tree_jk_navigation() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::DetailTree;
        // Expand to have children visible
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE));

        let initial = app.detail_tree.selected;
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert!(app.detail_tree.selected > initial);
        app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        assert_eq!(app.detail_tree.selected, initial);
    }

    #[test]
    fn hex_dump_scroll() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::HexDump;
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.hex_dump.scroll_offset, 1);
        app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        assert_eq!(app.hex_dump.scroll_offset, 0);
    }

    #[test]
    fn hex_dump_scroll_clamps_at_bottom() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::HexDump;
        let raw_len = app.selected_raw_bytes().unwrap().len();
        let max = raw_len.div_ceil(16).saturating_sub(1);

        // Scroll down many times beyond the max
        for _ in 0..max + 10 {
            app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        }
        assert_eq!(app.hex_dump.scroll_offset, max);
    }

    #[test]
    fn hex_dump_page_down_clamps_at_bottom() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::HexDump;
        let raw_len = app.selected_raw_bytes().unwrap().len();
        let max = raw_len.div_ceil(16).saturating_sub(1);

        // Page down many times beyond the max
        for _ in 0..max + 10 {
            app.handle_key(KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL));
        }
        assert!(app.hex_dump.scroll_offset <= max);
    }

    #[test]
    fn hex_dump_g_and_upper_g() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::HexDump;
        app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE));
        assert!(app.hex_dump.scroll_offset > 0);
        app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        assert_eq!(app.hex_dump.scroll_offset, 0);
    }

    // -- Detail tree top/bottom --

    #[test]
    fn detail_tree_g_upper_g() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::DetailTree;
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE)); // expand all
        app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE));
        let at_bottom = app.detail_tree.selected;
        assert!(at_bottom > 0);
        app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        assert_eq!(app.detail_tree.selected, 0);
    }

    // -- Yank prompt --

    #[test]
    fn yank_prompt_esc_cancels() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::YankPrompt);
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::DetailTree);
    }

    #[test]
    fn yank_prompt_t_copies_text() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::DetailTree);
        assert!(
            app.detail_tree
                .yank_message
                .as_ref()
                .unwrap()
                .contains("Copied")
        );
    }

    #[test]
    fn yank_prompt_h_copies_hex() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::DetailTree);
        assert!(
            app.detail_tree
                .yank_message
                .as_ref()
                .unwrap()
                .contains("hex")
        );
    }

    // -- Filter cursor movement --

    #[test]
    fn filter_cursor_left_right() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        assert_eq!(app.filter.buf.cursor, 2);

        app.handle_key(KeyEvent::new(KeyCode::Left, KeyModifiers::NONE));
        assert_eq!(app.filter.buf.cursor, 1);
        app.handle_key(KeyEvent::new(KeyCode::Right, KeyModifiers::NONE));
        assert_eq!(app.filter.buf.cursor, 2);
    }

    // -- Filter Esc exits --

    #[test]
    fn filter_esc_exits() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::FilterInput);
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::PacketList);
    }

    // -- selected_number --

    #[test]
    fn selected_number_one_based() {
        let app = make_test_app(5);
        assert_eq!(app.selected_number(), 1);
    }

    // -- selected_byte_range --

    #[test]
    fn selected_byte_range_returns_range() {
        let app = make_test_app(1);
        let range = app.selected_byte_range();
        assert!(range.is_some());
    }

    // -- Page down/up in detail tree --

    #[test]
    fn detail_tree_page_down_up() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::DetailTree;
        app.handle_key(KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE)); // expand all

        app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        let after_pgdn = app.detail_tree.selected;
        app.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert!(app.detail_tree.selected < after_pgdn || after_pgdn == 0);
    }

    // -- Pane resize from different panes --

    #[test]
    fn pane_resize_from_detail_tree() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::DetailTree;
        let original = app.pane_weights;
        app.handle_key(KeyEvent::new(KeyCode::Char('+'), KeyModifiers::NONE));
        assert_ne!(app.pane_weights, original);
        assert!(app.pane_weights[1] > original[1]);
    }

    #[test]
    fn pane_resize_minus() {
        let mut app = make_test_app(1);
        let original = app.pane_weights;
        app.handle_key(KeyEvent::new(KeyCode::Char('-'), KeyModifiers::NONE));
        assert!(app.pane_weights[0] < original[0]);
    }

    // -- stream_tick with fake stream build --

    #[test]
    fn stream_tick_completes_on_no_progress() {
        let mut app = make_test_app(3);
        // No stream build in progress → returns false
        assert!(!app.stream_tick());
    }

    // -- Line selection yank --

    #[test]
    fn line_selection_jk_moves() {
        let mut app = make_test_app(5);
        app.handle_key(KeyEvent::new(KeyCode::Char('V'), KeyModifiers::SHIFT));
        // j should move selection in line mode
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 1);
    }

    // -- Char selection movement --

    #[test]
    fn char_selection_hl_moves() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
        let initial_anchor = app.detail_tree.selection.as_ref().unwrap().anchor_char;
        // Should not panic when moving
        app.handle_key(KeyEvent::new(KeyCode::Char('l'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE));
        // anchor_char should have changed on 'h'
        let after = app.detail_tree.selection.as_ref().unwrap().anchor_char;
        // h decreases or stays at 0
        assert!(after <= initial_anchor);
    }

    #[test]
    fn char_selection_y_copies() {
        let mut app = make_test_app(1);
        app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        assert!(app.detail_tree.selection.is_none());
        assert!(
            app.detail_tree
                .yank_message
                .as_ref()
                .unwrap()
                .contains("Copied")
        );
    }

    // -- Tree search in maximized view --

    #[test]
    fn tree_search_in_maximized_detail() {
        let mut app = make_test_app(1);
        app.maximized_pane = Some(Pane::DetailTree);
        app.active_pane = Pane::DetailTree;

        // '/' enters tree search in maximized detail view
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::TreeSearch);

        // Type a search query
        app.handle_key(KeyEvent::new(KeyCode::Char('E'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('t'), KeyModifiers::NONE));
        assert_eq!(app.detail_tree.search_query, "Et");

        // Backspace removes char
        app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(app.detail_tree.search_query, "E");

        // Esc exits tree search
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::DetailTree);
    }

    #[test]
    fn tree_search_backspace_on_empty_exits() {
        let mut app = make_test_app(1);
        app.maximized_pane = Some(Pane::DetailTree);
        app.active_pane = Pane::DetailTree;
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::DetailTree);
    }

    // -- Summary cache eviction --

    #[test]
    fn summary_cache_evicts_lru_on_overflow() {
        let mut app = make_test_app(5);
        // Fill cache with entries
        for i in 0..5 {
            let _ = app.get_or_dissect_summary(i);
        }
        assert_eq!(app.summary_cache.len(), 5);
        // LRU eviction keeps the cache bounded without full wipe
        assert!(app.summary_cache.len() <= SUMMARY_CACHE_CAPACITY.get());
    }

    // -- jump_to_packet_number edge cases --

    #[test]
    fn jump_to_packet_number_zero_ignored() {
        let mut app = make_test_app(10);
        app.handle_key(KeyEvent::new(KeyCode::Char('0'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE));
        // Should stay at 0 (jump to 0 is ignored)
        assert_eq!(app.packet_list.selected, 0);
    }

    // -- Render zoomed pane --

    #[test]
    fn render_zoomed_pane() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = make_test_app(3);
        app.maximized_pane = Some(Pane::PacketList);

        let backend = TestBackend::new(80, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| super::super::ui::render(f, &mut app))
            .unwrap();
        // Should not panic and should render
    }

    // -- Render stream view --

    #[test]
    fn render_stream_view() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = make_test_app(1);
        app.stream_view = Some(StreamViewState {
            lines: vec![
                StreamLine {
                    text: "Hello".into(),
                    is_client: true,
                },
                StreamLine {
                    text: "World".into(),
                    is_client: false,
                },
            ],
            scroll_offset: 0,
            title: "TCP Stream #0".into(),
        });

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| super::super::ui::render(f, &mut app))
            .unwrap();

        let buf = terminal.backend().buffer().clone();
        let text: String = (0..buf.area.height)
            .map(|y| {
                (0..buf.area.width)
                    .map(|x| buf.cell((x, y)).unwrap().symbol().to_string())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("TCP Stream"));
    }

    // -- Render yank prompt --

    #[test]
    fn render_yank_prompt() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = make_test_app(1);
        app.active_pane = Pane::YankPrompt;

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| super::super::ui::render(f, &mut app))
            .unwrap();
        // Should not panic
    }

    // -- Mouse support --

    fn make_mouse_event(
        kind: crossterm::event::MouseEventKind,
        col: u16,
        row: u16,
    ) -> crossterm::event::MouseEvent {
        crossterm::event::MouseEvent {
            kind,
            column: col,
            row,
            modifiers: crossterm::event::KeyModifiers::empty(),
        }
    }

    #[test]
    fn click_selects_pane() {
        use crossterm::event::{MouseButton, MouseEventKind};

        let mut app = make_test_app(5);
        // Set up pane layout as if rendered in an 80x30 terminal.
        app.pane_layout = PaneLayout {
            packet_list: ratatui::layout::Rect::new(0, 0, 80, 10),
            detail_tree: ratatui::layout::Rect::new(0, 10, 80, 10),
            hex_dump: ratatui::layout::Rect::new(0, 20, 80, 8),
            frame_area: ratatui::layout::Rect::new(0, 0, 80, 30),
        };

        app.active_pane = Pane::PacketList;
        app.handle_mouse(make_mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            40,
            15,
        ));
        assert_eq!(app.active_pane, Pane::DetailTree);

        app.handle_mouse(make_mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            40,
            25,
        ));
        assert_eq!(app.active_pane, Pane::HexDump);

        app.handle_mouse(make_mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            40,
            5,
        ));
        assert_eq!(app.active_pane, Pane::PacketList);
    }

    #[test]
    fn click_selects_packet_row() {
        use crossterm::event::{MouseButton, MouseEventKind};

        let mut app = make_test_app(10);
        app.pane_layout = PaneLayout {
            packet_list: ratatui::layout::Rect::new(0, 0, 80, 12),
            detail_tree: ratatui::layout::Rect::new(0, 12, 80, 8),
            hex_dump: ratatui::layout::Rect::new(0, 20, 80, 8),
            frame_area: ratatui::layout::Rect::new(0, 0, 80, 30),
        };
        assert_eq!(app.packet_list.selected, 0);

        // Click on row 3 inside the packet list (row 0 is border, so y=4 → row_in_view=3).
        app.handle_mouse(make_mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            10,
            4,
        ));
        assert_eq!(app.packet_list.selected, 3);
    }

    #[test]
    fn scroll_wheel_moves_selection() {
        use crossterm::event::MouseEventKind;

        let mut app = make_test_app(10);
        assert_eq!(app.packet_list.selected, 0);

        app.handle_mouse(make_mouse_event(MouseEventKind::ScrollDown, 0, 0));
        assert_eq!(app.packet_list.selected, 1);

        app.handle_mouse(make_mouse_event(MouseEventKind::ScrollUp, 0, 0));
        assert_eq!(app.packet_list.selected, 0);
    }

    #[test]
    fn mouse_dismissed_help() {
        use crossterm::event::{MouseButton, MouseEventKind};

        let mut app = make_test_app(1);
        app.show_help = true;
        app.handle_mouse(make_mouse_event(
            MouseEventKind::Down(MouseButton::Left),
            0,
            0,
        ));
        assert!(!app.show_help);
    }

    // -- Live capture tests -------------------------------------------------

    fn make_live_test_app() -> (App, tempfile::NamedTempFile) {
        use std::io::Write;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU64};

        let pcap = super::super::loader::tests::build_pcap_for_test(3);
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&pcap).unwrap();
        tmp.flush().unwrap();

        let file = tmp.as_file().try_clone().unwrap();
        let capture = CaptureMap::new_live(file).unwrap();
        let indices = loader::build_index(capture.as_bytes()).unwrap();

        let copier = super::super::live::StdinCopier {
            bytes_written: Arc::new(AtomicU64::new(pcap.len() as u64)),
            eof: Arc::new(AtomicBool::new(false)),
            handle: None,
        };

        let app = App::new_live(capture, indices, DissectorRegistry::default(), copier);
        (app, tmp)
    }

    #[test]
    fn live_mode_initial_state() {
        let (app, _tmp) = make_live_test_app();
        assert_eq!(app.live_mode, Some(super::super::state::LiveMode::Live));
        assert_eq!(app.file_name, "<stdin>");
        assert_eq!(app.total_count(), 3);
        assert_eq!(app.displayed_count(), 3);
    }

    #[test]
    fn live_pause_and_resume() {
        use super::super::state::LiveMode;

        let (mut app, _tmp) = make_live_test_app();
        assert_eq!(app.live_mode, Some(LiveMode::Live));

        // Press 'p' → Paused.
        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        assert_eq!(app.live_mode, Some(LiveMode::Paused));

        // Press 'p' again → still Paused (idempotent).
        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        assert_eq!(app.live_mode, Some(LiveMode::Paused));

        // Press 'r' → Live.
        app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        assert_eq!(app.live_mode, Some(LiveMode::Live));

        // Press 'r' again → still Live (idempotent).
        app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        assert_eq!(app.live_mode, Some(LiveMode::Live));
    }

    #[test]
    fn live_pause_resume_ignored_in_complete() {
        use super::super::state::LiveMode;

        let (mut app, _tmp) = make_live_test_app();
        app.live_mode = Some(LiveMode::Complete);

        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        assert_eq!(app.live_mode, Some(LiveMode::Complete));

        app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        assert_eq!(app.live_mode, Some(LiveMode::Complete));
    }

    #[test]
    fn live_pause_resume_ignored_in_file_mode() {
        let mut app = make_test_app(5);
        assert_eq!(app.live_mode, None);

        app.handle_key(KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE));
        assert_eq!(app.live_mode, None);

        app.handle_key(KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE));
        assert_eq!(app.live_mode, None);
    }

    #[test]
    fn live_tick_ingests_new_packets() {
        use std::io::{Seek, Write};

        let (mut app, mut tmp) = make_live_test_app();
        assert_eq!(app.total_count(), 3);

        // Grow the file by rewriting with 6 packets.
        let pcap_6 = super::super::loader::tests::build_pcap_for_test(6);
        tmp.as_file().set_len(0).unwrap();
        tmp.seek(std::io::SeekFrom::Start(0)).unwrap();
        tmp.write_all(&pcap_6).unwrap();
        tmp.flush().unwrap();

        // Update the copier's bytes_written so live_tick sees growth.
        if let Some(ref copier) = app.stdin_copier {
            copier
                .bytes_written
                .store(pcap_6.len() as u64, std::sync::atomic::Ordering::Release);
        }

        app.live_tick();

        assert_eq!(app.total_count(), 6);
        assert_eq!(app.displayed_count(), 6);
    }

    #[test]
    fn live_tick_skipped_when_paused() {
        use super::super::state::LiveMode;
        use std::io::{Seek, Write};

        let (mut app, mut tmp) = make_live_test_app();
        app.live_mode = Some(LiveMode::Paused);

        // Grow the file.
        let pcap_6 = super::super::loader::tests::build_pcap_for_test(6);
        tmp.as_file().set_len(0).unwrap();
        tmp.seek(std::io::SeekFrom::Start(0)).unwrap();
        tmp.write_all(&pcap_6).unwrap();
        tmp.flush().unwrap();

        if let Some(ref copier) = app.stdin_copier {
            copier
                .bytes_written
                .store(pcap_6.len() as u64, std::sync::atomic::Ordering::Release);
        }

        app.live_tick();

        // Paused → no new packets ingested.
        assert_eq!(app.total_count(), 3);
    }

    #[test]
    fn check_eof_transitions_to_complete() {
        use super::super::state::LiveMode;

        let (mut app, _tmp) = make_live_test_app();
        assert_eq!(app.live_mode, Some(LiveMode::Live));

        // Signal EOF.
        if let Some(ref copier) = app.stdin_copier {
            copier.eof.store(true, std::sync::atomic::Ordering::Release);
        }

        app.check_eof();
        assert_eq!(app.live_mode, Some(LiveMode::Complete));
    }

    #[test]
    fn live_tick_auto_scroll_when_at_bottom() {
        use std::io::{Seek, Write};

        let (mut app, mut tmp) = make_live_test_app();
        // Move to bottom.
        app.packet_list.selected = app.displayed_count() - 1;

        // Grow the file.
        let pcap_6 = super::super::loader::tests::build_pcap_for_test(6);
        tmp.as_file().set_len(0).unwrap();
        tmp.seek(std::io::SeekFrom::Start(0)).unwrap();
        tmp.write_all(&pcap_6).unwrap();
        tmp.flush().unwrap();

        if let Some(ref copier) = app.stdin_copier {
            copier
                .bytes_written
                .store(pcap_6.len() as u64, std::sync::atomic::Ordering::Release);
        }

        app.live_tick();

        // Should auto-scroll to new bottom.
        assert_eq!(app.displayed_count(), 6);
        assert_eq!(app.packet_list.selected, 5);
    }

    #[test]
    fn live_tick_no_auto_scroll_when_scrolled_up() {
        use std::io::{Seek, Write};

        let (mut app, mut tmp) = make_live_test_app();
        // Stay at first packet (not at bottom).
        app.packet_list.selected = 0;

        let pcap_6 = super::super::loader::tests::build_pcap_for_test(6);
        tmp.as_file().set_len(0).unwrap();
        tmp.seek(std::io::SeekFrom::Start(0)).unwrap();
        tmp.write_all(&pcap_6).unwrap();
        tmp.flush().unwrap();

        if let Some(ref copier) = app.stdin_copier {
            copier
                .bytes_written
                .store(pcap_6.len() as u64, std::sync::atomic::Ordering::Release);
        }

        app.live_tick();

        // Should NOT auto-scroll; selection stays at 0.
        assert_eq!(app.displayed_count(), 6);
        assert_eq!(app.packet_list.selected, 0);
    }

    // -- Packet list j/k navigation --

    #[test]
    fn packet_list_j_moves_down() {
        let mut app = make_test_app(5);
        assert_eq!(app.packet_list.selected, 0);
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 1);
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 2);
    }

    #[test]
    fn packet_list_k_moves_up() {
        let mut app = make_test_app(5);
        // Move down first, then up.
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 2);
        app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 1);
    }

    #[test]
    fn packet_list_k_at_top_stays_at_zero() {
        let mut app = make_test_app(5);
        assert_eq!(app.packet_list.selected, 0);
        app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 0);
    }

    #[test]
    fn packet_list_j_at_bottom_stays_at_last() {
        let mut app = make_test_app(3);
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 2);
        // Already at last packet, j should not go further.
        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 2);
    }

    // -- Tab pane cycling --

    #[test]
    fn tab_cycles_panes_forward() {
        let mut app = make_test_app(1);
        assert_eq!(app.active_pane, Pane::PacketList);

        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::DetailTree);

        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::HexDump);

        app.handle_key(KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::PacketList);
    }

    #[test]
    fn backtab_cycles_panes_backward_full() {
        let mut app = make_test_app(1);
        assert_eq!(app.active_pane, Pane::PacketList);

        app.handle_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT));
        assert_eq!(app.active_pane, Pane::HexDump);

        app.handle_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT));
        assert_eq!(app.active_pane, Pane::DetailTree);

        app.handle_key(KeyEvent::new(KeyCode::BackTab, KeyModifiers::SHIFT));
        assert_eq!(app.active_pane, Pane::PacketList);
    }

    // -- Filter input enter/exit --

    #[test]
    fn slash_enters_filter_esc_exits() {
        let mut app = make_test_app(1);
        assert_eq!(app.active_pane, Pane::PacketList);

        // '/' enters filter input mode.
        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::FilterInput);

        // Escape exits back to PacketList.
        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::PacketList);
    }

    #[test]
    fn slash_in_maximized_detail_tree_enters_tree_search() {
        let mut app = make_test_app(1);
        app.active_pane = Pane::DetailTree;
        app.maximized_pane = Some(Pane::DetailTree);

        app.handle_key(KeyEvent::new(KeyCode::Char('/'), KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::TreeSearch);

        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert_eq!(app.active_pane, Pane::DetailTree);
    }

    // -- Page movement (Ctrl+F / Ctrl+B) --

    #[test]
    fn ctrl_f_pages_down_in_packet_list() {
        let mut app = make_test_app(50);
        assert_eq!(app.packet_list.selected, 0);

        app.handle_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL));
        assert_eq!(app.packet_list.selected, 20);
    }

    #[test]
    fn ctrl_b_pages_up_in_packet_list() {
        let mut app = make_test_app(50);
        // Go to bottom, then page up.
        app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 49);

        app.handle_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::CONTROL));
        assert_eq!(app.packet_list.selected, 29);
    }

    #[test]
    fn ctrl_f_then_ctrl_b_round_trips() {
        let mut app = make_test_app(50);
        assert_eq!(app.packet_list.selected, 0);

        app.handle_key(KeyEvent::new(KeyCode::Char('f'), KeyModifiers::CONTROL));
        assert_eq!(app.packet_list.selected, 20);

        app.handle_key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::CONTROL));
        assert_eq!(app.packet_list.selected, 0);
    }

    #[test]
    fn page_down_clamps_at_end() {
        let mut app = make_test_app(5);
        // 5 packets, page size=20 → should clamp to index 4.
        app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 4);
    }

    #[test]
    fn page_up_clamps_at_start() {
        let mut app = make_test_app(5);
        // At 0, page up should stay at 0.
        app.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 0);
    }

    /// Replicate the real `run_live()` flow: start with an empty temp file
    /// and empty indices, then write data and call live_tick() to ingest.
    #[test]
    fn live_tick_from_empty_file() {
        use std::io::Write;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU64};

        // 1. Create empty temp file + empty CaptureMap (same as run_live).
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let file = tmp.as_file().try_clone().unwrap();
        let capture = CaptureMap::new_live(file).unwrap();
        assert_eq!(capture.as_bytes().len(), 0);

        let copier = super::super::live::StdinCopier {
            bytes_written: Arc::new(AtomicU64::new(0)),
            eof: Arc::new(AtomicBool::new(false)),
            handle: None,
        };

        let indices = Vec::new();
        let mut app = App::new_live(capture, indices, DissectorRegistry::default(), copier);
        assert_eq!(app.total_count(), 0);
        assert_eq!(app.displayed_count(), 0);

        // 2. Simulate stdin copier writing pcap data to the temp file.
        let pcap = super::super::loader::tests::build_pcap_for_test(3);
        std::io::Write::write_all(&mut tmp.as_file(), &pcap).unwrap();
        tmp.as_file().flush().unwrap();

        // Update bytes_written (copier would do this).
        if let Some(ref copier) = app.stdin_copier {
            copier
                .bytes_written
                .store(pcap.len() as u64, std::sync::atomic::Ordering::Release);
        }

        // 3. live_tick should detect new data and ingest packets.
        app.live_tick();

        assert_eq!(app.total_count(), 3);
        assert_eq!(app.displayed_count(), 3);
    }

    #[test]
    fn on_resize_clamps_scroll_offsets() {
        let mut app = make_test_app(5);
        // Move selection to the last packet.
        for _ in 0..4 {
            app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        }
        assert_eq!(app.packet_list.selected, 4);

        // Artificially set scroll offsets beyond valid range.
        app.packet_list.scroll_offset = 100;
        app.hex_dump.scroll_offset = 999;
        app.detail_tree.scroll_offset = 999;

        app.on_resize();

        // scroll_offset should be clamped to at most total - 1.
        assert!(app.packet_list.scroll_offset <= 4);
        assert_eq!(app.packet_list.selected, 4);
        // Hex dump and detail tree offsets should also be clamped.
        assert!(app.hex_dump.scroll_offset < 999);
        assert!(app.detail_tree.scroll_offset < 999);
        // pane_layout should be reset.
        assert_eq!(
            app.pane_layout.packet_list,
            ratatui::layout::Rect::default()
        );
    }

    #[test]
    fn on_resize_empty_app() {
        let mut app = make_test_app(0);
        app.packet_list.scroll_offset = 10;
        app.hex_dump.scroll_offset = 5;
        app.detail_tree.scroll_offset = 5;

        app.on_resize();

        assert_eq!(app.packet_list.scroll_offset, 0);
        assert_eq!(app.hex_dump.scroll_offset, 0);
        assert_eq!(app.detail_tree.scroll_offset, 0);
    }

    /// Regression: when wait_for_first_data() returns, data is already
    /// present in the file before CaptureMap::new_live() creates the mmap.
    /// live_tick() must still ingest these packets even though refresh()
    /// returns false (the mmap already covers the file).
    #[test]
    fn live_tick_data_present_before_mmap() {
        use std::io::Write;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU64};

        // 1. Write pcap data BEFORE creating the CaptureMap.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let pcap = super::super::loader::tests::build_pcap_for_test(5);
        std::io::Write::write_all(&mut tmp.as_file(), &pcap).unwrap();
        tmp.as_file().flush().unwrap();

        let file = tmp.as_file().try_clone().unwrap();
        let capture = CaptureMap::new_live(file).unwrap();
        // The mmap already contains all data.
        assert_eq!(capture.as_bytes().len(), pcap.len());

        let copier = super::super::live::StdinCopier {
            bytes_written: Arc::new(AtomicU64::new(pcap.len() as u64)),
            eof: Arc::new(AtomicBool::new(false)),
            handle: None,
        };

        let mut app = App::new_live(capture, Vec::new(), DissectorRegistry::default(), copier);
        assert_eq!(app.total_count(), 0);

        // 2. live_tick should ingest the pre-existing data.
        app.live_tick();
        assert_eq!(app.total_count(), 5);
        assert_eq!(app.displayed_count(), 5);
    }

    // -- Dynamic page size tests ----------------------------------------------

    #[test]
    fn page_down_uses_pane_height() {
        let mut app = make_test_app(100);
        // Packet list pane height = 20 → page_size = 20 - 2 = 18.
        app.pane_layout = PaneLayout {
            packet_list: ratatui::layout::Rect::new(0, 0, 80, 20),
            detail_tree: ratatui::layout::Rect::new(0, 20, 80, 15),
            hex_dump: ratatui::layout::Rect::new(0, 35, 80, 15),
            frame_area: ratatui::layout::Rect::new(0, 0, 80, 50),
        };
        app.active_pane = Pane::PacketList;
        app.packet_list.selected = 0;
        app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 18);
    }

    #[test]
    fn page_up_uses_pane_height() {
        let mut app = make_test_app(100);
        app.pane_layout = PaneLayout {
            packet_list: ratatui::layout::Rect::new(0, 0, 80, 20),
            detail_tree: ratatui::layout::Rect::new(0, 20, 80, 15),
            hex_dump: ratatui::layout::Rect::new(0, 35, 80, 15),
            frame_area: ratatui::layout::Rect::new(0, 0, 80, 50),
        };
        app.active_pane = Pane::PacketList;
        app.packet_list.selected = 50;
        app.handle_key(KeyEvent::new(KeyCode::PageUp, KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 32);
    }

    #[test]
    fn page_size_falls_back_when_layout_not_set() {
        let mut app = make_test_app(100);
        // Default PaneLayout has zero-sized rects → fallback to 20.
        app.active_pane = Pane::PacketList;
        app.packet_list.selected = 0;
        app.handle_key(KeyEvent::new(KeyCode::PageDown, KeyModifiers::NONE));
        assert_eq!(app.packet_list.selected, 20);
    }

    #[test]
    fn stream_view_page_size_uses_frame_area() {
        let mut app = make_test_app(5);
        // Frame area height = 40 → page_size = 40 - 2 = 38.
        app.pane_layout.frame_area = ratatui::layout::Rect::new(0, 0, 80, 40);
        assert_eq!(app.stream_view_page_size(), 38);
    }

    #[test]
    fn stream_view_page_size_fallback() {
        let app = make_test_app(5);
        // Default frame_area has height 0 → fallback to 20.
        assert_eq!(app.stream_view_page_size(), 20);
    }
}
