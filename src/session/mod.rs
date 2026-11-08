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

pub mod bg_indexer;
pub mod completion;
pub mod conversations;
mod field_jobs;
pub mod fields;
pub mod filter_bitmap;
mod filter_scan;
pub mod live;
pub mod loader;
pub mod merge;
pub mod ordered_pass;
pub mod owned_packet;
mod packet_codec;
pub mod parallel_scan;
pub mod problems;
pub mod responses;
pub mod sequence;
pub mod state;
mod stats_collect;
mod stream;
pub mod tree;

use std::collections::{HashMap, HashSet};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};

use lru::LruCache;
use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::dissector::ProtocolLayer;

use self::bg_indexer::BackgroundIndexer;
use self::completion::CompletionEngine;
use self::filter_bitmap::FilterBitmap;
use self::live::StdinCopier;
use self::ordered_pass::{OrderedPass, Status};
use self::parallel_scan::ParallelFilterScan;
use self::state::{
    CaptureMap, FilterProgress, IndexProgress, LiveMode, PacketIndex, RowSummary, SelectedPacket,
    StatsProgress, StreamBuildProgress,
};
use crate::decode_as;
use crate::error::Result;

pub use field_jobs::{FieldStatsJob, HistogramJob};
pub use filter_scan::FilterOutcome;
pub use stats_collect::StatsReport;
pub use stream::FollowedStream;

/// Return the XDG-compliant cache directory for dsct temporary files.
///
/// Resolution order:
/// 1. `$XDG_CACHE_HOME/dsct`
/// 2. `$HOME/.cache/dsct`
/// 3. `None` (caller should fall back to the system temp directory)
pub fn cache_dir() -> Option<PathBuf> {
    if let Ok(cache) = std::env::var("XDG_CACHE_HOME") {
        return Some(PathBuf::from(cache).join("dsct"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Some(PathBuf::from(home).join(".cache/dsct"));
    }
    None
}

/// A registry configured by the `--decode-as` arguments.
pub fn new_registry(decode_as_args: &[String]) -> Result<DissectorRegistry> {
    let mut registry = DissectorRegistry::default();
    decode_as::parse_and_apply(&mut registry, decode_as_args)?;
    Ok(registry)
}

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
    /// In-progress field value count (None = idle).
    pub field_stats_progress: Option<FieldStatsJob>,
    /// In-progress histogram split (None = idle).
    pub histogram_progress: Option<HistogramJob>,
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
    /// Stack position of each protocol `registry` can dissect.
    layer_of: HashMap<&'static str, ProtocolLayer>,
    /// The sequence highlighted among the displayed packets.
    sequence: Option<sequence::SequenceScan>,
    /// The problems found among the displayed packets.
    problems: Option<problems::ProblemScan>,
    /// Packets the user marked, by index.
    marked: std::collections::BTreeSet<usize>,
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

    /// Open the capture file at `file`.
    ///
    /// The session starts with an empty index: a background thread indexes
    /// the file (drive it with [`index_tick`](Self::index_tick)) and another
    /// dissects it in capture order (drive it with
    /// [`ordered_tick`](Self::ordered_tick)), so a frontend can show the
    /// first packets while a large file is still being read.
    pub fn open(file: &Path, decode_as_args: Vec<String>) -> Result<Self> {
        let registry = new_registry(&decode_as_args)?;

        // Memory-map the file for display/dissection on the caller's thread.
        let capture = loader::open_and_mmap(file)?;
        let total_bytes = capture.as_bytes().len();

        // Index in the background so the frontend stays responsive even for
        // very large capture files.
        let bg_indexer = BackgroundIndexer::spawn(file, total_bytes)?;

        // Dissect the capture in order in the background, for packets whose
        // dissection uses state kept across packets.
        let ordered = OrderedPass::spawn(
            loader::open_and_mmap(file)?,
            new_registry(&decode_as_args)?,
            cache_dir().as_deref(),
        )?;

        let mut session = Self::new(capture, Vec::new(), registry, file, decode_as_args);
        session.bg_indexer = Some(bg_indexer);
        session.ordered = Some(ordered);
        Ok(session)
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
        let layer_of = fields::protocol_layers(&registry);
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
            field_stats_progress: None,
            histogram_progress: None,
            live_mode,
            stdin_copier,
            // Start at 0 so the first live_tick() ingests any data that was
            // already in the mmap (e.g. written before CaptureMap::new_live).
            indexed_bytes: 0,
            index_progress: None,
            bg_indexer: None,
            ordered: None,
            pending_rows: HashSet::new(),
            layer_of,
            sequence: None,
            problems: None,
            marked: std::collections::BTreeSet::new(),
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
                &self.layer_of,
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
            tunnels: Vec::new(),
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
    pub fn scan_registry(&self) -> Result<DissectorRegistry> {
        new_registry(&self.decode_as_args)
    }

    /// Dissect packets with `decode_as_args` (`--decode-as` rules) from now
    /// on: rebuild the dissectors, restart the in-order pass, drop cached
    /// rows and the selection, stop the jobs that read packets, and apply
    /// the current filter again.
    ///
    /// The frontend reloads what it shows, selecting a packet again with
    /// [`load_packet`](Self::load_packet). On error (invalid rules, or the
    /// capture cannot be read again) the session is left as it was.
    pub fn set_decode_as(&mut self, decode_as_args: Vec<String>) -> Result<()> {
        let registry = new_registry(&decode_as_args)?;
        let ordered = match (&self.ordered, &self.capture_path) {
            (Some(_), Some(path)) => Some(OrderedPass::spawn(
                loader::open_and_mmap(path)?,
                new_registry(&decode_as_args)?,
                cache_dir().as_deref(),
            )?),
            _ => None,
        };
        self.completion_engine = CompletionEngine::from_registry(&registry);
        self.layer_of = fields::protocol_layers(&registry);
        self.registry = registry;
        self.ordered = ordered;
        self.decode_as_args = decode_as_args;
        self.summary_cache.clear();
        self.pending_rows.clear();
        self.selected = None;
        self.stream_build_progress = None;
        self.stats_progress = None;
        self.field_stats_progress = None;
        self.histogram_progress = None;
        // Keys can change with the dissectors: scan the sequence again.
        if let Some(key) = self.sequence.take().map(|s| s.key) {
            self.start_sequence(key);
        }
        if self.problems.is_some() {
            self.start_problems();
        }
        self.cancel_filter();
        let filter = self.applied_filter.clone();
        // The filter was valid when applied, so only a failed scan (reported
        // by `filter_tick`) can follow.
        let _ = self.apply_filter(&filter);
        Ok(())
    }

    // -- Marks -----------------------------------------------------------------

    /// Mark packet `pkt_idx`, or unmark it if it was marked. Returns whether
    /// it is marked now.
    pub fn toggle_mark(&mut self, pkt_idx: usize) -> bool {
        if self.marked.remove(&pkt_idx) {
            false
        } else {
            self.marked.insert(pkt_idx);
            true
        }
    }

    /// Whether packet `pkt_idx` is marked.
    pub fn is_marked(&self, pkt_idx: usize) -> bool {
        self.marked.contains(&pkt_idx)
    }

    /// The marked packets, in capture order.
    pub fn marked(&self) -> impl Iterator<Item = usize> + '_ {
        self.marked.iter().copied()
    }

    /// Unmark every packet.
    pub fn clear_marks(&mut self) {
        self.marked.clear();
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

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::io::Write;
    use std::time::{Duration, Instant};

    use super::*;

    /// Serialize tests that mutate environment variables.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A pcap file with `n` UDP packets.
    fn write_pcap(n: usize) -> tempfile::NamedTempFile {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&loader::tests::build_pcap_for_test(n))
            .unwrap();
        tmp.flush().unwrap();
        tmp
    }

    /// An indexed session over a pcap file with `n` UDP packets, without
    /// background threads.  Keep the file alive while using the session.
    pub(super) fn test_session(n: usize) -> (Session, tempfile::NamedTempFile) {
        let tmp = write_pcap(n);
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

    /// [`Session::open`] with the cache directory in a temp directory.
    fn open(path: &Path, decode_as_args: Vec<String>) -> Result<Session> {
        let _lock = env_lock();
        let cache = tempfile::tempdir().unwrap();
        unsafe {
            std::env::set_var("XDG_CACHE_HOME", cache.path());
        }
        let session = Session::open(path, decode_as_args);
        unsafe {
            std::env::remove_var("XDG_CACHE_HOME");
        }
        session
    }

    /// Call [`Session::index_tick`] until indexing ends, returning how many
    /// ticks asked to reload the selection.
    fn finish_indexing(session: &mut Session) -> usize {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut reloads = 0;
        while session.is_indexing() {
            assert!(Instant::now() < deadline, "indexing did not finish");
            if session.index_tick() {
                reloads += 1;
                session.load_packet(0);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        reloads
    }

    #[test]
    fn open_indexes_and_dissects_in_the_background() {
        let tmp = write_pcap(5);
        let mut session = open(tmp.path(), vec![]).unwrap();
        assert!(session.is_indexing());
        assert_eq!(session.total_count(), 0);
        assert!(session.ordered.is_some());

        assert_eq!(finish_indexing(&mut session), 1);
        assert_eq!(session.total_count(), 5);
        assert_eq!(session.displayed_count(), 5);
        assert_eq!(session.selected.as_ref().map(|s| s.pkt_idx), Some(0));
        assert!(!session.index_tick());

        let deadline = Instant::now() + Duration::from_secs(30);
        while session.ordered_needs_tick() {
            assert!(Instant::now() < deadline, "pass did not finish");
            assert_eq!(session.ordered_tick().error, None);
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn open_rejects_invalid_decode_as() {
        let tmp = write_pcap(1);
        assert!(open(tmp.path(), vec!["not-a-decode-as".to_string()]).is_err());
    }

    #[test]
    fn set_decode_as_rebuilds_the_dissectors_and_reapplies_the_filter() {
        let (mut session, _tmp) = test_session(3);
        assert!(session.registry.get_by_udp_port(4097).is_none());
        session.apply_filter("udp").unwrap();
        while session.filter_running() {
            let _ = session.filter_tick();
        }
        let _ = session.get_or_dissect_summary(0);
        session.load_packet(0);

        let rule = "udp.port=4097:dns".to_string();
        session.set_decode_as(vec![rule.clone()]).unwrap();
        assert_eq!(session.decode_as_args, std::slice::from_ref(&rule));
        assert!(session.registry.get_by_udp_port(4097).is_some());
        assert!(session.summary_cache.is_empty());
        assert!(session.selected.is_none());
        assert_eq!(session.applied_filter, "udp");
        while session.filter_running() {
            let _ = session.filter_tick();
        }
        assert_eq!(session.displayed_count(), 3);

        // Invalid rules leave the session as it was.
        assert!(session.set_decode_as(vec!["bad".to_string()]).is_err());
        assert_eq!(session.decode_as_args, [rule]);
    }

    #[test]
    fn set_decode_as_restarts_the_ordered_pass() {
        let tmp = write_pcap(5);
        let mut session = open(tmp.path(), vec![]).unwrap();
        finish_indexing(&mut session);
        while session.ordered_needs_tick() {
            let _ = session.ordered_tick();
        }
        session
            .set_decode_as(vec!["udp.port=4097:dns".to_string()])
            .unwrap();
        assert!(session.ordered.is_some());
        assert!(session.ordered_needs_tick());
    }

    #[test]
    fn packets_are_marked_and_unmarked() {
        let (mut session, _tmp) = test_session(3);
        assert!(session.toggle_mark(2));
        assert!(session.toggle_mark(0));
        assert!(session.is_marked(2));
        assert_eq!(session.marked().collect::<Vec<_>>(), [0, 2]);
        assert!(!session.toggle_mark(2));
        assert!(!session.is_marked(2));
        session.clear_marks();
        assert_eq!(session.marked().count(), 0);
    }

    #[test]
    fn open_rejects_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(open(&dir.path().join("missing.pcap"), vec![]).is_err());
    }

    #[test]
    fn sync_index_tick_indexes_the_mapped_capture() {
        let tmp = write_pcap(7);
        let capture = loader::open_and_mmap(tmp.path()).unwrap();
        let total_bytes = capture.as_bytes().len();
        let state = loader::start_indexing(capture.as_bytes()).unwrap();
        let mut session = Session::new(
            capture,
            Vec::new(),
            DissectorRegistry::default(),
            tmp.path(),
            vec![],
        );
        session.index_progress = Some(IndexProgress { state, total_bytes });

        assert_eq!(finish_indexing(&mut session), 1);
        assert_eq!(session.total_count(), 7);
        assert_eq!(session.displayed_count(), 7);
        assert!(!session.index_tick());
    }

    #[test]
    fn ordered_tick_without_a_pass_changes_nothing() {
        let tmp = write_pcap(2);
        let capture = loader::open_and_mmap(tmp.path()).unwrap();
        let indices = loader::build_index(capture.as_bytes()).unwrap();
        let mut session = Session::new(
            capture,
            indices,
            DissectorRegistry::default(),
            tmp.path(),
            vec![],
        );
        assert_eq!(session.ordered_tick(), OrderedTick::default());
        assert!(!session.ordered_needs_tick());
        assert!(!session.is_indexing());
        assert!(!session.index_tick());
        // Not a live capture.
        assert!(!session.live_tick());
        assert!(!session.check_eof());
    }

    #[test]
    fn cache_dir_prefers_xdg_cache_home() {
        let _lock = env_lock();
        unsafe {
            std::env::set_var("XDG_CACHE_HOME", "/tmp/xdg-test-cache");
            std::env::set_var("HOME", "/home/dummy");
        }
        let dir = cache_dir();
        assert_eq!(dir, Some(PathBuf::from("/tmp/xdg-test-cache/dsct")));
        unsafe {
            std::env::remove_var("XDG_CACHE_HOME");
            std::env::remove_var("HOME");
        }
    }

    #[test]
    fn cache_dir_falls_back_to_home() {
        let _lock = env_lock();
        unsafe {
            std::env::remove_var("XDG_CACHE_HOME");
            std::env::set_var("HOME", "/home/dummy");
        }
        let dir = cache_dir();
        assert_eq!(dir, Some(PathBuf::from("/home/dummy/.cache/dsct")));
        unsafe {
            std::env::remove_var("HOME");
        }
    }

    #[test]
    fn cache_dir_returns_none_without_env() {
        let _lock = env_lock();
        unsafe {
            std::env::remove_var("XDG_CACHE_HOME");
            std::env::remove_var("HOME");
        }
        let dir = cache_dir();
        assert_eq!(dir, None);
    }
}
