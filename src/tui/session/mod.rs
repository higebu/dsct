//! Frontend-agnostic capture session.
//!
//! A [`Session`] owns everything about one open capture that does not depend
//! on how it is presented: the memory-mapped file, the packet index, the
//! filter result, on-demand dissection with its row cache, and the chunked
//! jobs that run over the capture (indexing, the in-order dissection pass,
//! live ingestion, filter scans, Follow Stream, and stats).
//!
//! It holds no view state.  A frontend keeps its own selection, scroll
//! offsets, and focus, drives the session from its event loop with the
//! `*_tick` methods, and reacts to what they report (for example by resetting
//! its selection when a filter finishes).

mod filter_scan;
mod stats_collect;
mod stream;

use std::collections::HashSet;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use lru::LruCache;
use packet_dissector::registry::DissectorRegistry;

use super::bg_indexer::BackgroundIndexer;
use super::completion::CompletionEngine;
use super::filter_bitmap::FilterBitmap;
use super::live::StdinCopier;
use super::loader;
use super::ordered_pass::{self, OrderedPass, Status};
use super::parallel_scan::ParallelFilterScan;
use super::state::{
    CaptureMap, FilterProgress, IndexProgress, LiveMode, PacketIndex, RowSummary, SelectedPacket,
    StatsProgress, StreamBuildProgress,
};

pub use filter_scan::FilterOutcome;
#[cfg(test)]
pub(super) use stream::payload_to_ascii;

/// Maximum number of cached row summaries.
#[allow(clippy::unwrap_used)]
pub(crate) const SUMMARY_CACHE_CAPACITY: NonZeroUsize = NonZeroUsize::new(2000).unwrap();

/// State of a chunked job after driving it one step.
#[derive(Debug, Clone, PartialEq)]
pub enum Tick<T> {
    /// No job of this kind is running.
    Idle,
    /// The job made progress and is still running.
    Running,
    /// The job finished during this step.
    Done(T),
}

/// What [`Session::ordered_tick`] changed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OrderedTick {
    /// Whether anything shown from the session changed.
    pub changed: bool,
    /// The in-order pass stopped with this error; packets are dissected on
    /// demand from now on.
    pub error: Option<String>,
    /// The selected packet's in-order result became available: reload it
    /// with [`Session::load_packet`].
    pub reload_selected: bool,
}

/// One open capture and the jobs running over it.
pub struct Session {
    /// Capture file name (for status line display).
    pub file_name: String,
    /// Memory-mapped capture file.
    pub capture: CaptureMap,
    /// Minimal index of all packets (32 bytes each).
    pub indices: Vec<PacketIndex>,
    /// Bitmap of packets matching the current filter (one bit per packet).
    pub filtered: FilterBitmap,
    /// Dissector registry (for on-demand dissection).
    pub registry: DissectorRegistry,
    /// Fuzzy completion engine for filter input.
    pub completion_engine: CompletionEngine,
    /// LRU cache of dissected row summaries.
    pub summary_cache: LruCache<usize, RowSummary>,
    /// The currently selected packet's full data (loaded on demand).
    pub selected: Option<SelectedPacket>,
    /// The filter expression currently applied (empty = no filter).
    pub applied_filter: String,
    /// In-progress filter scan (None = idle).
    pub filter_progress: Option<FilterProgress>,
    /// In-progress parallel filter scan (None = idle).
    pub parallel_scan: Option<ParallelFilterScan>,
    /// Path of the capture file (None in live mode).
    pub capture_path: Option<PathBuf>,
    /// Decode-as arguments for rebuilding registries in parallel workers.
    pub decode_as_args: Vec<String>,
    /// In-progress stream collection (chunked).
    pub stream_build_progress: Option<StreamBuildProgress>,
    /// In-progress stats collection (None = idle).
    pub stats_progress: Option<StatsProgress>,
    /// Live capture mode (None for static file mode).
    pub live_mode: Option<LiveMode>,
    /// Background stdin copier (None for static file mode).
    pub stdin_copier: Option<StdinCopier>,
    /// Number of bytes already indexed (for incremental live indexing).
    pub indexed_bytes: usize,
    /// In-progress initial file indexing (None = idle or complete).
    pub index_progress: Option<IndexProgress>,
    /// Background indexer thread (None = idle or complete).
    pub bg_indexer: Option<BackgroundIndexer>,
    /// In-order dissection pass providing the results of packets whose
    /// dissection uses cross-packet state (None = dissect everything on
    /// demand with `registry`).
    pub ordered: Option<OrderedPass>,
    /// Packet list rows cached as placeholders waiting for `ordered`.
    pub pending_rows: HashSet<usize>,
}

impl Session {
    /// Create a session for a capture file.
    pub fn new(
        capture: CaptureMap,
        indices: Vec<PacketIndex>,
        registry: DissectorRegistry,
        file_path: &Path,
        decode_as_args: Vec<String>,
    ) -> Self {
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| file_path.display().to_string());
        Self::with_source(
            file_name,
            capture,
            indices,
            registry,
            Some(file_path.to_path_buf()),
            decode_as_args,
            None,
        )
    }

    /// Create a session for a live capture copied from stdin by `copier`.
    pub fn new_live(
        capture: CaptureMap,
        indices: Vec<PacketIndex>,
        registry: DissectorRegistry,
        copier: StdinCopier,
        decode_as_args: Vec<String>,
    ) -> Self {
        Self::with_source(
            "<stdin>".to_string(),
            capture,
            indices,
            registry,
            None,
            decode_as_args,
            Some(copier),
        )
    }

    fn with_source(
        file_name: String,
        capture: CaptureMap,
        indices: Vec<PacketIndex>,
        registry: DissectorRegistry,
        capture_path: Option<PathBuf>,
        decode_as_args: Vec<String>,
        stdin_copier: Option<StdinCopier>,
    ) -> Self {
        let completion_engine = CompletionEngine::from_registry(&registry);
        let filtered = FilterBitmap::all_set(indices.len());
        let live_mode = stdin_copier.as_ref().map(|_| LiveMode::Live);
        Self {
            file_name,
            capture,
            indices,
            filtered,
            registry,
            completion_engine,
            summary_cache: LruCache::new(SUMMARY_CACHE_CAPACITY),
            selected: None,
            applied_filter: String::new(),
            filter_progress: None,
            parallel_scan: None,
            capture_path,
            decode_as_args,
            stream_build_progress: None,
            stats_progress: None,
            live_mode,
            stdin_copier,
            // Start at 0 so the first live_tick() ingests any data that was
            // already in the mmap (e.g. written before CaptureMap::new_live).
            indexed_bytes: 0,
            index_progress: None,
            bg_indexer: None,
            ordered: None,
            pending_rows: HashSet::new(),
        }
    }

    /// Number of displayed (filtered) packets.
    pub fn displayed_count(&self) -> usize {
        self.filtered.count_ones()
    }

    /// Total number of packets in the capture.
    pub fn total_count(&self) -> usize {
        self.indices.len()
    }

    /// Get the raw bytes of the selected packet from the mmap (zero-copy).
    pub fn selected_raw_bytes(&self) -> Option<&[u8]> {
        let sel = self.selected.as_ref()?;
        let index = self.indices.get(sel.pkt_idx)?;
        self.capture.packet_data(index)
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
            let (summary, pending) = ordered_pass::row_summary(
                &self.registry,
                self.ordered.as_ref(),
                pkt_idx,
                data,
                index.link_type as u32,
            );
            if pending {
                self.pending_rows.insert(pkt_idx);
            }
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

    /// Dissect the packet shown at `row` of the filtered list and make it the
    /// selected packet (None when `row` is out of range).
    pub fn load_packet(&mut self, row: usize) {
        self.selected = self.filtered.select(row).and_then(|pkt_idx| {
            let index = self.indices.get(pkt_idx)?;
            let data = self.capture.packet_data(index)?;
            Some(ordered_pass::selected_packet(
                &self.registry,
                self.ordered.as_ref(),
                pkt_idx,
                data,
                index.link_type as u32,
            ))
        });
    }

    /// A fresh registry configured like `registry`, for scans that dissect
    /// packets in capture order and must not see the state the on-demand
    /// display dissection left in `registry`.
    pub fn scan_registry(&self) -> crate::error::Result<DissectorRegistry> {
        super::new_registry(&self.decode_as_args)
    }

    // -- In-order dissection pass ---------------------------------------------

    /// Drive the in-order dissection pass: feed it newly indexed packets and
    /// drop placeholders whose results are ready.
    pub fn ordered_tick(&mut self) -> OrderedTick {
        let mut tick = OrderedTick::default();
        let Some(pass) = &mut self.ordered else {
            return tick;
        };
        pass.feed(&self.indices);
        let pass = &*pass;

        if let Some(e) = pass.take_error() {
            tick.error = Some(e);
            tick.changed = true;
        }
        let summary_cache = &mut self.summary_cache;
        self.pending_rows.retain(|&pkt_idx| {
            if pass.status(pkt_idx) == Status::Pending {
                return true;
            }
            tick.changed |= summary_cache.pop(&pkt_idx).is_some();
            false
        });
        tick.reload_selected = self
            .selected
            .as_ref()
            .is_some_and(|sel| sel.pending && pass.status(sel.pkt_idx) != Status::Pending);
        tick.changed |= tick.reload_selected;
        tick
    }

    /// Whether the event loop must keep calling [`ordered_tick`](Self::ordered_tick):
    /// packets are left to feed or placeholders are shown.
    pub fn ordered_needs_tick(&self) -> bool {
        let Some(pass) = &self.ordered else {
            return false;
        };
        !pass.fully_fed(self.indices.len())
            || !self.pending_rows.is_empty()
            || self.selected.as_ref().is_some_and(|sel| sel.pending)
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

    /// Whether the capture is still being indexed.
    pub fn is_indexing(&self) -> bool {
        self.index_progress.is_some() || self.bg_indexer.is_some()
    }

    /// Drive one tick of file indexing.
    ///
    /// When a [`BackgroundIndexer`] is active, this drains results from the
    /// background thread's channel — the main thread never does indexing work
    /// itself, keeping the event loop fully responsive.
    ///
    /// Falls back to synchronous chunked indexing via [`IndexProgress`] when
    /// no background indexer is present (e.g. live capture mode).
    ///
    /// Returns `true` when the selected packet must be reloaded with
    /// [`load_packet`](Self::load_packet): the first packets arrived, or
    /// indexing failed and stopped with what it had.
    pub fn index_tick(&mut self) -> bool {
        if self.bg_indexer.is_some() {
            self.bg_index_tick()
        } else {
            self.sync_index_tick()
        }
    }

    /// Drain results from the background indexer thread.
    fn bg_index_tick(&mut self) -> bool {
        let bg = match &self.bg_indexer {
            Some(b) => b,
            None => return false,
        };

        let (new_records, done) = bg.drain();
        let mut reload = false;

        if !new_records.is_empty() {
            // Capped pre-allocation on first batch.
            if self.indices.is_empty() {
                let estimate = (bg.total_bytes / 80).min(Self::MAX_PREALLOC);
                self.indices.reserve(estimate);
                self.filtered.reserve(estimate);
            }

            let old_count = self.indices.len();
            let new_count = new_records.len();
            self.indices.extend(new_records);
            // No filter is active during initial indexing: every new packet is
            // displayed, so set the corresponding bits (identity growth).
            self.filtered
                .push_set_range(old_count..old_count + new_count);

            // Select the first packet as soon as we have data.
            reload = old_count == 0 && !self.indices.is_empty() && self.selected.is_none();
        }

        if done {
            self.bg_indexer = None;
        }
        reload
    }

    /// Synchronous chunked indexing fallback (used when no background thread
    /// is available, e.g. during live capture incremental re-indexing).
    fn sync_index_tick(&mut self) -> bool {
        let progress = match &mut self.index_progress {
            Some(p) => p,
            None => return false,
        };

        // Capped pre-allocation on the first tick.
        if self.indices.is_empty() {
            let estimate = (progress.total_bytes / 80).min(Self::MAX_PREALLOC);
            self.indices.reserve(estimate);
            self.filtered.reserve(estimate);
        }

        let deadline = std::time::Instant::now() + Self::INDEX_TIME_BUDGET;
        let mut reload = false;

        loop {
            let progress = match &mut self.index_progress {
                Some(p) => p,
                None => return reload,
            };

            let data = self.capture.as_bytes();
            let new_records =
                match loader::index_chunk(data, &mut progress.state, Self::INDEX_CHUNK_SIZE) {
                    Ok(records) => records,
                    Err(_) => {
                        // Indexing failed; finalize with what we have.
                        self.index_progress = None;
                        return reload || !self.indices.is_empty();
                    }
                };

            let old_count = self.indices.len();
            let new_count = new_records.len();
            self.indices.extend(new_records);

            // Set bits for the new packets (no filter is active during initial
            // indexing).
            self.filtered
                .push_set_range(old_count..old_count + new_count);

            let done = progress.state.done;

            // Select the first packet as soon as we have some data.
            if old_count == 0 && !self.indices.is_empty() && self.selected.is_none() {
                reload = true;
            }

            if done {
                self.index_progress = None;
                return reload;
            }

            if std::time::Instant::now() >= deadline {
                break;
            }
        }
        reload
    }

    // -- Live capture support ------------------------------------------------

    /// Check the background copier for EOF and transition to Complete if so.
    ///
    /// Returns `true` when the capture was re-indexed (see
    /// [`live_tick`](Self::live_tick)).
    pub fn check_eof(&mut self) -> bool {
        if let Some(ref copier) = self.stdin_copier
            && copier.eof.load(std::sync::atomic::Ordering::Acquire)
        {
            self.live_mode = Some(LiveMode::Complete);
            // Do a final refresh to pick up any remaining data.
            // Refresh failure is benign; the next tick will retry.
            let _ = self.capture.refresh();
            return self.ingest_new_packets();
        }
        false
    }

    /// Drive one tick of live capture: refresh the mmap and ingest new
    /// packets.  Does nothing unless `live_mode == Live`.
    ///
    /// Returns `true` when the capture was re-indexed; a frontend that follows
    /// the newest packet should then move its selection.
    pub fn live_tick(&mut self) -> bool {
        if self.live_mode != Some(LiveMode::Live) {
            return false;
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
            return false;
        }

        // Refresh the mmap to see new data, then re-index.
        // We call ingest even if refresh() returns false: the initial mmap
        // created by new_live() may already contain unindexed data (e.g.
        // after wait_for_first_data).
        // Refresh failure is benign; ingest_new_packets tolerates stale data.
        let _ = self.capture.refresh();
        self.ingest_new_packets()
    }

    /// Re-index the capture data and append any new packets found.
    ///
    /// Returns `true` when the capture was re-indexed.
    fn ingest_new_packets(&mut self) -> bool {
        let data = self.capture.as_bytes();
        if data.len() < 4 {
            return false;
        }
        let all_indices = match loader::build_index(data) {
            Ok(idx) => idx,
            Err(_) => return false,
        };

        let old_count = self.indices.len();
        if all_indices.len() > old_count {
            let new_packets = &all_indices[old_count..];
            self.indices.extend_from_slice(new_packets);

            let start = old_count;
            let end = self.indices.len();
            if self.applied_filter.is_empty() {
                // No filter active: display the new packets (set their bits).
                self.filtered.push_set_range(start..end);
            } else {
                // A filter is active: new packets are not in the view, but the
                // universe must still grow so rank/select stay consistent.
                self.filtered.extend_universe(end);
            }
        }

        self.indexed_bytes = data.len();
        true
    }
}
