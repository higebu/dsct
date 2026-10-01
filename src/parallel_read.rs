//! Pipeline-parallel filter evaluation for the `dsct read` command.
//!
//! When input is a file (not stdin) and a filter is given, packets are
//! distributed across N worker threads for dissection and filtering.  The
//! merger re-assembles results in original packet order so the output is
//! byte-identical to the sequential path.
//!
//! # Cross-packet state
//!
//! Some dissectors keep state across packets (TCP stream tracking and
//! reassembly, HTTP/2 HPACK, NetFlow v9 / IPFIX templates, IP fragment
//! reassembly).  Each worker owns an independent [`DissectorRegistry`], so it
//! cannot reproduce that state.  Dissection is therefore optimistic:
//!
//! * A packet whose dissection did not touch such state
//!   ([`DissectBuffer::used_cross_packet_state`] is `false`) depends only on
//!   its bytes and the registry configuration, and leaves no trace for later
//!   packets, so the worker's result is exact wherever the packet lies.
//! * A packet whose dissection did touch it is marked by the worker, and the
//!   merger dissects it again with the caller's registry, in capture order
//!   among all marked packets.  Unmarked packets never touch the state, so
//!   that registry goes through exactly the state changes the sequential
//!   path makes, and the result is identical to `--threads 1`.
//!
//! A capture without stateful packets thus runs fully in parallel; in a TCP
//! capture the merger re-dissects every TCP packet itself, which bounds the
//! speed-up by the share of stateless packets.  `--sample-rate`, `--offset`
//! and `--count` apply to the merged, ordered match stream.
//!
//! # Architecture
//!
//! ```text
//!  Reader thread ──batch──> Worker 0 channel ──results──> Merger
//!                ──batch──> Worker 1 channel ──results──> (calling thread)
//!                ──batch──> Worker N-1 channel ──results──>
//! ```
//!
//! 1. **Reader** (dedicated thread): reads packets with
//!    [`CaptureReader::for_each_packet`], applies the packet-number pre-filter
//!    and early-exit, copies bytes into arena batches, and sends batches
//!    round-robin to per-worker bounded channels.  A shared [`AtomicBool`] stop
//!    flag lets the merger abort the reader when the count limit is reached.
//!    The capture is read once, so the input need not be seekable.
//!
//! 2. **Workers** (N threads): each owns a [`DissectorRegistry`] with the
//!    `decode-as` overrides and a parsed copy of the filter, both built before
//!    the thread starts, and reuses one [`DissectBuffer`].  For each packet it
//!    dissects, evaluates the filter, and on match serialises via
//!    [`write_packet_json`] into bytes; a packet that used cross-packet state
//!    becomes a marker instead.  Results are sent in packet order, together
//!    with the batch when it holds a marked packet.  A worker whose batch
//!    held a marked packet replaces its registry, so worker state stays
//!    bounded by one batch.  A worker whose batch was almost entirely marked
//!    passes its next few batches on undissected, all marked, so captures
//!    that are mostly stateful (all TCP, say) do not pay for dissecting
//!    twice.
//!
//! 3. **Merger** (calling thread): receives result batches strictly in
//!    round-robin worker order to preserve global packet order, dissects the
//!    marked packets, applies `sample_rate`, `offset`, and `count` on the
//!    ordered match stream, writes matched JSON to the supplied writer, and
//!    calls the progress and warning callbacks.  On reaching the count limit
//!    it sets the stop flag and drains all threads cleanly before returning.
//!
//! # Batch format
//!
//! Each batch holds at most 256 packets or 1 MiB of raw
//! packet data, whichever comes first, in one shared buffer.  Results for
//! each batch are a `Vec` of per-packet entries (matches, warnings and
//! markers).
//!
//! # Robustness
//!
//! * No `unwrap` / `expect` in production code paths.
//! * Worker setup errors are reported before any thread starts.
//! * Worker threads exit cleanly when their input channel is disconnected
//!   (reader dropped the sender).
//! * The merger stops at the first closed worker channel (end of input).
//! * All threads are joined before returning so output is fully flushed.

use std::io;
use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::{DissectBuffer, Packet};

use crate::decode_as;
use crate::error::{DsctError, Result};
use crate::field_config::FieldConfig;
use crate::filter::PacketNumberFilter;
use crate::filter_expr::FilterExpr;
use crate::input::CaptureReader;
use crate::serialize::{PacketMeta, write_packet_json};

/// Maximum packets per batch sent to a worker.
const BATCH_PACKETS: usize = 256;

/// Maximum raw bytes per batch (1 MiB).
const BATCH_BYTES: usize = 1 << 20;

/// Bounded channel capacity per worker (number of pending batches).
const CHAN_CAPACITY: usize = 4;

/// A worker whose batch had at least this share (in percent) of packets
/// that used cross-packet state hands its next [`SKIP_BATCHES`] batches to
/// the merger undissected: the merger dissects them in order anyway, and
/// dissecting them twice only takes CPU from the merger.
const MOSTLY_IN_ORDER_PERCENT: usize = 90;

/// See [`MOSTLY_IN_ORDER_PERCENT`].
const SKIP_BATCHES: u32 = 7;

/// Options for the parallel read engine.
///
/// All fields are derived from the `dsct read` CLI arguments and passed
/// through without mutation.
pub struct ParallelReadOptions<'a> {
    /// Path to the capture file (must not be stdin `"-"`).
    pub path: &'a Path,
    /// Parsed filter expression; each worker gets a clone.
    pub filter: &'a FilterExpr,
    /// `--decode-as` arguments to apply to each per-worker registry.
    pub decode_as_args: &'a [String],
    /// Number of worker threads (must be ≥ 2; caller enforces this).
    pub threads: usize,
    /// Emit every Nth filter-matching result; 1 = no sampling.
    pub sample_rate: u64,
    /// Skip the first `offset` filter-matching results.
    pub offset: u64,
    /// Stop after emitting this many results (`None` = unlimited).
    pub count: Option<u64>,
    /// Optional packet-number pre-filter (applied before dissection).
    pub pn_filter: Option<PacketNumberFilter>,
    /// Field visibility configuration for JSON output; `None` = verbose.
    pub field_config: Option<&'a FieldConfig>,
    /// When `true`, include `raw_bytes` hex in each output record.
    pub raw_bytes: bool,
    /// Emit a progress callback every this many packets processed (0 = disabled).
    pub progress_interval: u64,
}

/// Options for [`run_sequential`].
///
/// The same knobs as [`ParallelReadOptions`], minus the parallel-only ones,
/// with the filter already parsed.
pub struct SequentialReadOptions<'a> {
    /// Parsed filter expression (`None` = every packet matches).
    pub filter: Option<&'a FilterExpr>,
    /// Emit every Nth filter-matching result; 1 = no sampling.
    pub sample_rate: u64,
    /// Skip the first `offset` filter-matching results.
    pub offset: u64,
    /// Stop after emitting this many results (`None` = unlimited).
    pub count: Option<u64>,
    /// Optional packet-number pre-filter (applied before dissection).
    pub pn_filter: Option<&'a PacketNumberFilter>,
    /// Field visibility configuration for JSON output; `None` = verbose.
    pub field_config: Option<&'a FieldConfig>,
    /// When `true`, include `raw_bytes` hex in each output record.
    pub raw_bytes: bool,
    /// Emit a progress callback every this many packets processed (0 = disabled).
    pub progress_interval: u64,
}

/// Outcome reported after a successful run.
///
/// Provides enough information for the caller to emit a truncation warning.
#[derive(Debug, Default)]
pub struct ReadOutcome {
    /// Total packets read, including those the packet-number filter dropped.
    pub packets_processed: u64,
    /// Number of JSON records written to the writer.
    pub packets_written: u64,
    /// `true` if the run stopped because the count limit was reached (not EOF).
    pub truncated_by_limit: bool,
    /// Number of packets [`run`] dissected again in capture order because
    /// their dissection used cross-packet state (0 when every result came
    /// from the parallel workers).  Always 0 for [`run_sequential`].
    pub in_order_packets: u64,
}

/// `--sample-rate` / `--offset` / `--count` applied to the ordered match
/// stream.
#[derive(Clone, Copy)]
struct Limits {
    sample_rate: u64,
    offset: u64,
    count: Option<u64>,
}

/// Running totals of one read, shared by the worker results and in-order
/// dissection so the limits apply to one ordered match stream.
#[derive(Default)]
struct Tally {
    outcome: ReadOutcome,
    /// Packets that passed the filter.
    filter_matches: u64,
    /// Filter matches kept after sampling.
    results_matched: u64,
}

impl Tally {
    /// Account for one filter match; returns `true` when it must be written
    /// (it survives sampling and lies past the offset).
    fn admit(&mut self, limits: Limits) -> bool {
        self.filter_matches += 1;
        if limits.sample_rate > 1 && !(self.filter_matches - 1).is_multiple_of(limits.sample_rate) {
            return false;
        }
        self.results_matched += 1;
        self.results_matched > limits.offset
    }

    /// Account for one written record; returns `true` when the count limit
    /// has been reached.
    fn wrote(&mut self, limits: Limits) -> bool {
        self.outcome.packets_written += 1;
        let reached = limits
            .count
            .is_some_and(|max| self.outcome.packets_written >= max);
        if reached {
            self.outcome.truncated_by_limit = true;
        }
        reached
    }
}

/// Dissects, filters and writes packets in capture order with one registry.
struct InOrder<'r> {
    registry: &'r DissectorRegistry,
    filter: Option<&'r FilterExpr>,
    field_config: Option<&'r FieldConfig>,
    raw_bytes: bool,
    limits: Limits,
    dissect_buf: DissectBuffer<'static>,
    /// Reusable output buffer: write_packet_json writes many small
    /// fragments, so batching them first avoids per-fragment dynamic
    /// dispatch when the writer is a `dyn Write`.
    pkt_buf: Vec<u8>,
}

impl InOrder<'_> {
    /// Process one packet; returns `Break` once the count limit is reached.
    fn packet<W: io::Write + ?Sized>(
        &mut self,
        meta: &PacketMeta,
        data: &[u8],
        tally: &mut Tally,
        writer: &mut W,
        warn: &mut dyn FnMut(u64, &str),
    ) -> Result<ControlFlow<()>> {
        let buf = self.dissect_buf.clear_into();
        if let Err(e) = self
            .registry
            .dissect_with_link_type(data, meta.link_type, buf)
        {
            warn(meta.number, &format!("{e}"));
            return Ok(ControlFlow::Continue(()));
        }
        if let Some(expr) = self.filter
            && !expr.matches_with_number(&Packet::new(buf, data), meta.number)
        {
            return Ok(ControlFlow::Continue(()));
        }
        if !tally.admit(self.limits) {
            return Ok(ControlFlow::Continue(()));
        }

        self.pkt_buf.clear();
        write_packet_json(
            &mut self.pkt_buf,
            meta,
            buf,
            data,
            self.field_config,
            self.raw_bytes,
        )?;
        self.pkt_buf.push(b'\n');
        writer.write_all(&self.pkt_buf)?;
        Ok(if tally.wrote(self.limits) {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        })
    }
}

// ---------------------------------------------------------------------------
// Internal message types
// ---------------------------------------------------------------------------

/// One batch of raw packets sent from the reader to a worker.
///
/// Packet bytes share one buffer, so a batch costs a few allocations rather
/// than one per packet.
#[derive(Default)]
struct InputBatch {
    /// Packets read since the previous batch that the packet-number filter
    /// dropped; counted in `packets_processed` like the sequential path does.
    skipped: u64,
    metas: Vec<PacketMeta>,
    /// End offset in `data` of each packet; packet `i` starts where packet
    /// `i - 1` ends.
    ends: Vec<usize>,
    data: Vec<u8>,
}

impl InputBatch {
    fn with_capacity(packets: usize) -> Self {
        Self {
            skipped: 0,
            metas: Vec::with_capacity(packets),
            ends: Vec::with_capacity(packets),
            data: Vec::new(),
        }
    }

    fn push(&mut self, meta: PacketMeta, data: &[u8]) {
        self.data.extend_from_slice(data);
        self.ends.push(self.data.len());
        self.metas.push(meta);
    }

    fn len(&self) -> usize {
        self.metas.len()
    }

    /// Whether the batch carries neither packets nor skipped-packet counts.
    fn is_empty(&self) -> bool {
        self.metas.is_empty() && self.skipped == 0
    }

    /// Packets the batch accounts for: its own plus the skipped ones.
    fn processed(&self) -> u64 {
        self.metas.len() as u64 + self.skipped
    }

    /// Packet `i` of the batch.
    fn get(&self, i: usize) -> Option<(&PacketMeta, &[u8])> {
        let meta = self.metas.get(i)?;
        let start = if i == 0 { 0 } else { self.ends[i - 1] };
        Some((meta, &self.data[start..self.ends[i]]))
    }

    /// All packets of the batch, in order.
    fn iter(&self) -> impl Iterator<Item = (&PacketMeta, &[u8])> {
        (0..self.len()).filter_map(|i| self.get(i))
    }
}

/// One result entry produced by a worker.
enum WorkerEntry {
    /// A packet that matched the filter; contains serialised JSON bytes
    /// (no trailing newline — the merger adds it).
    Match(Vec<u8>),
    /// Dissection failed for this packet number.
    Warning { number: u64, message: String },
    /// Serialisation failed for a matched packet.  The merger treats this as
    /// fatal, mirroring the sequential path where `write_packet_json` errors
    /// propagate via `?`.
    Fatal { number: u64, message: String },
    /// Dissecting packet `index` of the batch used cross-packet state; the
    /// merger must dissect it in capture order.
    InOrder { index: usize },
}

/// One batch of results sent from a worker back to the merger.
struct OutputBatch {
    /// Number of input packets this batch represents (matching or not), used
    /// by the merger for `packets_processed` accounting.
    packets: u64,
    /// Per-packet entries (matches, warnings, markers) in packet order.
    entries: Vec<WorkerEntry>,
    /// The input batch, handed back only when an entry is
    /// [`WorkerEntry::InOrder`].
    in_order: Option<InputBatch>,
}

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Run parallel filter evaluation and write matching JSONL records to `writer`.
///
/// Packets whose dissection used cross-packet state are dissected again in
/// capture order with `registry` (see the [module docs](self)), so the output
/// is identical to [`run_sequential`] over the same capture with the same
/// registry.
///
/// The caller is responsible for ensuring that:
/// - `opts.path` names a capture file (not `"-"`); it is read once, so it
///   need not be seekable.
/// - `opts.decode_as_args` have been validated.
/// - `registry` is configured exactly like the per-worker registries
///   (default dissectors plus `opts.decode_as_args`) and has not dissected
///   any packet yet.
/// - `opts.threads >= 2`.
///
/// Callbacks:
/// - `warn(packet_number, message)` — called in packet order for per-packet
///   dissection warnings.
/// - `progress(packets_processed, packets_written)` — called whenever
///   `packets_processed` crosses a multiple of `opts.progress_interval`.
///   This fires at batch granularity, so at most once per batch even when a
///   batch crosses several interval boundaries.
pub fn run<W: io::Write>(
    opts: &ParallelReadOptions<'_>,
    registry: &DissectorRegistry,
    writer: &mut W,
    warn: &mut dyn FnMut(u64, &str),
    progress: &mut dyn FnMut(u64, u64),
) -> Result<ReadOutcome> {
    let mut in_order = InOrder {
        registry,
        filter: Some(opts.filter),
        field_config: opts.field_config,
        raw_bytes: opts.raw_bytes,
        limits: Limits {
            sample_rate: opts.sample_rate,
            offset: opts.offset,
            count: opts.count,
        },
        dissect_buf: DissectBuffer::new(),
        pkt_buf: Vec::with_capacity(4096),
    };
    let n = opts.threads;

    // Build every worker's registry up front, so a setup error is reported
    // here instead of silently ending a worker (and the output).
    let mut workers = Vec::with_capacity(n);
    for _ in 0..n {
        workers.push(WorkerContext {
            registry: worker_registry(opts.decode_as_args)?,
            filter: opts.filter.clone(),
            decode_as_args: opts.decode_as_args.to_vec(),
            field_config: opts.field_config.cloned(),
            raw_bytes: opts.raw_bytes,
        });
    }

    // Build per-worker input/output channels.
    let mut input_txs: Vec<mpsc::SyncSender<InputBatch>> = Vec::with_capacity(n);
    let mut output_rxs: Vec<mpsc::Receiver<OutputBatch>> = Vec::with_capacity(n);

    // Shared stop flag: set by merger when count limit reached.
    let stop = Arc::new(AtomicBool::new(false));

    // -----------------------------------------------------------------------
    // Spawn N workers
    // -----------------------------------------------------------------------
    let mut worker_handles = Vec::with_capacity(n);
    for ctx in workers {
        let (itx, irx) = mpsc::sync_channel::<InputBatch>(CHAN_CAPACITY);
        let (otx, orx) = mpsc::sync_channel::<OutputBatch>(CHAN_CAPACITY);
        input_txs.push(itx);
        output_rxs.push(orx);

        let handle = std::thread::Builder::new()
            .name("dsct-worker".into())
            .spawn(move || worker_fn(irx, otx, ctx))
            .map_err(|e| DsctError::msg(format!("failed to spawn worker thread: {e}")))?;
        worker_handles.push(handle);
    }

    // -----------------------------------------------------------------------
    // Spawn reader thread
    // -----------------------------------------------------------------------
    let path_owned = opts.path.to_path_buf();
    let pn_filter_clone = opts.pn_filter.clone();
    let stop_reader = Arc::clone(&stop);

    let reader_handle = std::thread::Builder::new()
        .name("dsct-reader".into())
        .spawn(move || reader_fn(path_owned, pn_filter_clone, input_txs, stop_reader))
        .map_err(|e| DsctError::msg(format!("failed to spawn reader thread: {e}")))?;

    // -----------------------------------------------------------------------
    // Merger (runs on the calling thread)
    // -----------------------------------------------------------------------
    let mut tally = Tally::default();
    let merged = merger_fn(
        &mut in_order,
        &mut tally,
        opts.progress_interval,
        &mut output_rxs,
        writer,
        warn,
        progress,
        &stop,
    );

    // -----------------------------------------------------------------------
    // Join all threads — must happen even on error to avoid resource leaks.
    // Dropping output_rxs causes workers to exit their send loops, which drains
    // their input channels, unblocking the reader.
    // -----------------------------------------------------------------------
    stop.store(true, Ordering::Relaxed);
    drop(output_rxs);

    let reader_result = reader_handle
        .join()
        .map_err(|_| DsctError::msg("reader thread panicked"))?;

    // A panicked worker silently truncates the merged stream (its output
    // channel just disconnects), so surface it as an explicit error instead
    // of reporting partial output as success.
    let mut worker_panicked = false;
    for handle in worker_handles {
        if handle.join().is_err() {
            worker_panicked = true;
        }
    }

    merged?;
    reader_result?;
    if worker_panicked {
        return Err(DsctError::msg(
            "a worker thread panicked; output may be incomplete",
        ));
    }
    Ok(tally.outcome)
}

/// Read `reader` packet by packet with one `registry` and write matching
/// JSONL records to `writer`.
///
/// This is the `--threads 1` / stdin path of `dsct read`.  The callbacks
/// behave as in [`run`], except that `progress` fires per packet.
pub fn run_sequential<W: io::Write + ?Sized>(
    reader: CaptureReader,
    registry: &DissectorRegistry,
    opts: &SequentialReadOptions<'_>,
    writer: &mut W,
    warn: &mut dyn FnMut(u64, &str),
    progress: &mut dyn FnMut(u64, u64),
) -> Result<ReadOutcome> {
    let mut in_order = InOrder {
        registry,
        filter: opts.filter,
        field_config: opts.field_config,
        raw_bytes: opts.raw_bytes,
        limits: Limits {
            sample_rate: opts.sample_rate,
            offset: opts.offset,
            count: opts.count,
        },
        dissect_buf: DissectBuffer::new(),
        pkt_buf: Vec::with_capacity(4096),
    };
    let pn_max = opts.pn_filter.and_then(PacketNumberFilter::max);
    let mut tally = Tally::default();

    reader.for_each_packet(|meta, data| {
        tally.outcome.packets_processed += 1;

        // --- progress reporting ---
        if opts.progress_interval > 0
            && tally
                .outcome
                .packets_processed
                .is_multiple_of(opts.progress_interval)
        {
            progress(
                tally.outcome.packets_processed,
                tally.outcome.packets_written,
            );
        }

        // --- packet-number filter (pre-dissect, lightweight) ---
        if let Some(pnf) = opts.pn_filter
            && !pnf.contains(meta.number)
        {
            // Early exit once we've passed all specified packet numbers.
            if pn_max.is_some_and(|m| meta.number > m) {
                return Ok(ControlFlow::Break(()));
            }
            return Ok(ControlFlow::Continue(()));
        }

        in_order.packet(&meta, data, &mut tally, writer, warn)
    })?;
    Ok(tally.outcome)
}

// ---------------------------------------------------------------------------
// Reader thread
// ---------------------------------------------------------------------------

fn reader_fn(
    path: std::path::PathBuf,
    pn_filter: Option<PacketNumberFilter>,
    input_txs: Vec<mpsc::SyncSender<InputBatch>>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let reader =
        CaptureReader::open(&path).map_err(|e| e.context("failed to open capture file"))?;
    let n = input_txs.len();
    let pn_max = pn_filter.as_ref().and_then(PacketNumberFilter::max);
    let mut worker_idx = 0usize;
    let mut current_batch = InputBatch::with_capacity(BATCH_PACKETS);

    let read = reader.for_each_packet(|meta, data| {
        if stop.load(Ordering::Relaxed) {
            return Ok(ControlFlow::Break(()));
        }

        // Packet-number pre-filter (mirrors sequential logic exactly).
        if let Some(ref pnf) = pn_filter
            && !pnf.contains(meta.number)
        {
            current_batch.skipped += 1;
            if pn_max.is_some_and(|m| meta.number > m) {
                return Ok(ControlFlow::Break(()));
            }
        } else {
            current_batch.push(meta, data);
        }

        // Skipped packets count towards the batch size too, so progress keeps
        // flowing while the packet-number filter drops most packets.
        if current_batch.processed() >= BATCH_PACKETS as u64
            || current_batch.data.len() >= BATCH_BYTES
        {
            let batch =
                std::mem::replace(&mut current_batch, InputBatch::with_capacity(BATCH_PACKETS));
            if input_txs[worker_idx].send(batch).is_err() {
                // Worker exited — stop flag should also be set.
                return Ok(ControlFlow::Break(()));
            }
            worker_idx = (worker_idx + 1) % n;
        }

        Ok(ControlFlow::Continue(()))
    });

    // Flush last partial batch, also when reading failed part-way: the
    // sequential path writes every packet before a read error too.
    if !current_batch.is_empty() && !stop.load(Ordering::Relaxed) {
        // Ignore send error — receiver may have disconnected if stop was set.
        let _ = input_txs[worker_idx].send(current_batch);
    }

    // Dropping input_txs closes all worker input channels → workers exit.
    read
}

// ---------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------

/// A registry configured like the caller's: default dissectors plus the
/// `decode-as` overrides.
fn worker_registry(decode_as_args: &[String]) -> Result<DissectorRegistry> {
    let mut registry = DissectorRegistry::default();
    decode_as::parse_and_apply(&mut registry, decode_as_args)?;
    Ok(registry)
}

/// Per-worker state moved into the worker thread.
struct WorkerContext {
    registry: DissectorRegistry,
    filter: FilterExpr,
    /// Used to replace `registry` after it took on cross-packet state.
    decode_as_args: Vec<String>,
    field_config: Option<FieldConfig>,
    raw_bytes: bool,
}

fn worker_fn(
    irx: mpsc::Receiver<InputBatch>,
    otx: mpsc::SyncSender<OutputBatch>,
    mut ctx: WorkerContext,
) {
    let mut dissect_buf = DissectBuffer::new();
    let mut json_buf: Vec<u8> = Vec::with_capacity(4096);
    let mut skip_batches = 0u32;

    for batch in &irx {
        if skip_batches > 0 {
            // Dissecting a packet in order is always correct, so the whole
            // batch can go to the merger.
            skip_batches -= 1;
            let out = OutputBatch {
                packets: batch.processed(),
                entries: (0..batch.len())
                    .map(|index| WorkerEntry::InOrder { index })
                    .collect(),
                in_order: Some(batch),
            };
            if otx.send(out).is_err() {
                break;
            }
            continue;
        }

        let mut entries: Vec<WorkerEntry> = Vec::new();
        let mut fatal = false;

        for (index, (meta, data)) in batch.iter().enumerate() {
            let dbuf = dissect_buf.clear_into();
            let result = ctx
                .registry
                .dissect_with_link_type(data, meta.link_type, dbuf);
            if dbuf.used_cross_packet_state() {
                // The result depends on (or changes) state this registry
                // cannot reproduce; the merger dissects the packet in order.
                entries.push(WorkerEntry::InOrder { index });
                continue;
            }
            if let Err(e) = result {
                entries.push(WorkerEntry::Warning {
                    number: meta.number,
                    message: format!("{e}"),
                });
                continue;
            }
            let packet = Packet::new(dbuf, data);

            if !ctx.filter.matches_with_number(&packet, meta.number) {
                continue;
            }

            json_buf.clear();
            match write_packet_json(
                &mut json_buf,
                meta,
                dbuf,
                data,
                ctx.field_config.as_ref(),
                ctx.raw_bytes,
            ) {
                Ok(()) => entries.push(WorkerEntry::Match(json_buf.clone())),
                Err(e) => {
                    // Fatal: the merger aborts the whole run on this entry,
                    // mirroring the sequential path.  Send what we have and
                    // exit the worker.
                    entries.push(WorkerEntry::Fatal {
                        number: meta.number,
                        message: format!("{e}"),
                    });
                    fatal = true;
                    break;
                }
            }
        }

        let in_order_count = entries
            .iter()
            .filter(|e| matches!(e, WorkerEntry::InOrder { .. }))
            .count();
        let has_in_order = in_order_count > 0;
        if in_order_count * 100 >= batch.len() * MOSTLY_IN_ORDER_PERCENT {
            skip_batches = SKIP_BATCHES;
        }
        if has_in_order && !fatal {
            // Drop the state this batch built up (it is never used, since
            // every packet that touched it goes to the merger) so worker
            // memory does not grow with the capture.
            match worker_registry(&ctx.decode_as_args) {
                Ok(registry) => ctx.registry = registry,
                Err(e) => {
                    // Validated before the worker started; report rather
                    // than continue with a polluted registry.
                    entries.push(WorkerEntry::Fatal {
                        number: batch.metas.last().map_or(0, |m| m.number),
                        message: format!("{e}"),
                    });
                    fatal = true;
                }
            }
        }

        let out = OutputBatch {
            packets: batch.processed(),
            entries,
            in_order: has_in_order.then_some(batch),
        };
        if otx.send(out).is_err() || fatal {
            // Merger dropped the receiver (count limit reached), or the run
            // is aborting; exit cleanly.
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Merger (runs on calling thread)
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn merger_fn<W: io::Write>(
    in_order: &mut InOrder<'_>,
    tally: &mut Tally,
    progress_interval: u64,
    output_rxs: &mut [mpsc::Receiver<OutputBatch>],
    writer: &mut W,
    warn: &mut dyn FnMut(u64, &str),
    progress: &mut dyn FnMut(u64, u64),
    stop: &AtomicBool,
) -> Result<()> {
    let n = output_rxs.len();
    let limits = in_order.limits;
    let mut worker_idx = 0usize;
    // packets_processed value at the last progress report, for interval
    // boundary-crossing detection.
    let mut progress_marker = 0u64;

    // Receive from workers in strict round-robin order (same order the reader
    // sent batches to them), preserving global packet order.
    loop {
        let Ok(batch) = output_rxs[worker_idx].recv() else {
            // Channel closed: either stop flag is set (expected EOF / limit)
            // or all workers finished (EOF).  Either way, we are done.
            return Ok(());
        };
        tally.outcome.packets_processed = tally
            .outcome
            .packets_processed
            .saturating_add(batch.packets);

        for entry in batch.entries {
            match entry {
                WorkerEntry::Warning { number, message } => {
                    warn(number, &message);
                }
                WorkerEntry::Fatal { number, message } => {
                    stop.store(true, Ordering::Relaxed);
                    return Err(DsctError::msg(format!(
                        "failed to serialize packet {number}: {message}"
                    )));
                }
                WorkerEntry::Match(json_bytes) => {
                    if !tally.admit(limits) {
                        continue;
                    }
                    writer.write_all(&json_bytes)?;
                    writer.write_all(b"\n")?;
                    if tally.wrote(limits) {
                        stop.store(true, Ordering::Relaxed);
                        return Ok(());
                    }
                }
                WorkerEntry::InOrder { index } => {
                    let Some((meta, data)) = batch.in_order.as_ref().and_then(|b| b.get(index))
                    else {
                        stop.store(true, Ordering::Relaxed);
                        return Err(DsctError::msg(
                            "internal: worker marked a packet without handing over its batch",
                        ));
                    };
                    tally.outcome.in_order_packets += 1;
                    if in_order.packet(meta, data, tally, writer, warn)?.is_break() {
                        stop.store(true, Ordering::Relaxed);
                        return Ok(());
                    }
                }
            }
        }

        // Progress reporting at batch granularity: fire when
        // packets_processed crossed a multiple of the interval since
        // the last report (sequential semantics, batched).
        let processed = tally.outcome.packets_processed;
        if progress_interval > 0
            && processed / progress_interval > progress_marker / progress_interval
        {
            progress_marker = processed;
            progress(processed, tally.outcome.packets_written);
        }

        worker_idx = (worker_idx + 1) % n;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(number: u64) -> PacketMeta {
        PacketMeta {
            number,
            timestamp_secs: 0,
            timestamp_usecs: 0,
            captured_length: 0,
            original_length: 0,
            link_type: 1,
        }
    }

    /// `count` undissectable (empty) packets numbered from `first`.
    fn packets(first: u64, count: u64) -> InputBatch {
        let mut batch = InputBatch::default();
        for n in first..first + count {
            batch.push(meta(n), &[]);
        }
        batch
    }

    struct Merged {
        result: Result<()>,
        out: Vec<u8>,
        tally: Tally,
        warnings: Vec<u64>,
        reports: Vec<(u64, u64)>,
        stop: bool,
    }

    /// Run the merger over `batches`, received round-robin from
    /// `batches.len()` workers (one batch each, in order).
    fn merge(batches: Vec<OutputBatch>, progress_interval: u64, count: Option<u64>) -> Merged {
        let registry = DissectorRegistry::default();
        let mut in_order = InOrder {
            registry: &registry,
            filter: None,
            field_config: None,
            raw_bytes: false,
            limits: Limits {
                sample_rate: 1,
                offset: 0,
                count,
            },
            dissect_buf: DissectBuffer::new(),
            pkt_buf: Vec::new(),
        };
        let mut rxs = Vec::new();
        for batch in batches {
            let (tx, rx) = mpsc::sync_channel::<OutputBatch>(1);
            tx.send(batch).unwrap();
            rxs.push(rx);
        }
        let stop = AtomicBool::new(false);
        let mut tally = Tally::default();
        let mut out = Vec::new();
        let mut warnings = Vec::new();
        let mut reports = Vec::new();
        let result = merger_fn(
            &mut in_order,
            &mut tally,
            progress_interval,
            &mut rxs,
            &mut out,
            &mut |number, _| warnings.push(number),
            &mut |processed, written| reports.push((processed, written)),
            &stop,
        );
        Merged {
            result,
            out,
            tally,
            warnings,
            reports,
            stop: stop.load(Ordering::Relaxed),
        }
    }

    #[test]
    fn merger_aborts_on_fatal_entry() {
        let merged = merge(
            vec![OutputBatch {
                packets: 1,
                entries: vec![WorkerEntry::Fatal {
                    number: 7,
                    message: "boom".into(),
                }],
                in_order: None,
            }],
            0,
            None,
        );
        assert!(merged.result.is_err(), "Fatal entry must abort the merge");
        assert!(merged.stop, "stop flag must be set");
    }

    #[test]
    fn merger_progress_counts_all_packets() {
        // Two batches of 300 packets with no matching entries: progress must
        // fire once the 500-packet interval boundary is crossed, with
        // packets_processed counting all packets (not just matches).
        let batch = || OutputBatch {
            packets: 300,
            entries: Vec::new(),
            in_order: None,
        };
        let merged = merge(vec![batch(), batch()], 500, None);
        merged.result.unwrap();
        assert_eq!(merged.tally.outcome.packets_processed, 600);
        assert_eq!(merged.tally.outcome.packets_written, 0);
        assert_eq!(merged.reports, vec![(600, 0)]);
        assert_eq!(merged.tally.outcome.in_order_packets, 0);
    }

    #[test]
    fn merger_dissects_marked_packets_in_place() {
        // Batch 1 (packets 1-3): packet 2 is marked.  Batch 2 (packets 4-5):
        // packet 4 is marked.  Marked packets are empty, so in-order
        // dissection reports each as a warning, in packet order with the
        // worker results.
        let merged = merge(
            vec![
                OutputBatch {
                    packets: 3,
                    entries: vec![
                        WorkerEntry::Match(b"1".to_vec()),
                        WorkerEntry::InOrder { index: 1 },
                        WorkerEntry::Warning {
                            number: 3,
                            message: "w".into(),
                        },
                    ],
                    in_order: Some(packets(1, 3)),
                },
                OutputBatch {
                    packets: 2,
                    entries: vec![
                        WorkerEntry::InOrder { index: 0 },
                        WorkerEntry::Match(b"5".to_vec()),
                    ],
                    in_order: Some(packets(4, 2)),
                },
            ],
            0,
            None,
        );
        merged.result.unwrap();
        assert_eq!(merged.out, b"1\n5\n");
        assert_eq!(merged.warnings, vec![2, 3, 4]);
        assert_eq!(merged.tally.outcome.in_order_packets, 2);
        assert_eq!(merged.tally.outcome.packets_processed, 5);
        assert_eq!(merged.tally.outcome.packets_written, 2);
    }

    #[test]
    fn merger_count_limit_stops_before_later_marked_packet() {
        let merged = merge(
            vec![OutputBatch {
                packets: 3,
                entries: vec![
                    WorkerEntry::Match(b"1".to_vec()),
                    WorkerEntry::Match(b"2".to_vec()),
                    WorkerEntry::InOrder { index: 2 },
                ],
                in_order: Some(packets(1, 3)),
            }],
            0,
            Some(2),
        );
        merged.result.unwrap();
        assert_eq!(merged.out, b"1\n2\n");
        assert!(merged.tally.outcome.truncated_by_limit);
        assert!(merged.stop);
        assert!(merged.warnings.is_empty(), "packet 3 must not be dissected");
    }

    #[test]
    fn merger_rejects_marker_without_batch() {
        let merged = merge(
            vec![OutputBatch {
                packets: 1,
                entries: vec![WorkerEntry::InOrder { index: 0 }],
                in_order: None,
            }],
            0,
            None,
        );
        assert!(merged.result.is_err());
    }
}
