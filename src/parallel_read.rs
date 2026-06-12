//! Pipeline-parallel filter evaluation for the `dsct read` command.
//!
//! When the filter expression is
//! [`parallel-safe`](crate::filter_expr::FilterExpr::is_parallel_safe)
//! and input is a file (not stdin), packets are distributed across N worker
//! threads for dissection and filtering.  The merger re-assembles results in
//! original packet order so the output is byte-identical to the sequential
//! path.
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
//!    and early-exit, copies bytes into small arena batches, and sends batches
//!    round-robin to per-worker bounded channels.  A shared [`AtomicBool`] stop
//!    flag lets the merger abort the reader when the count limit is reached.
//!
//! 2. **Workers** (N threads): each builds its own [`DissectorRegistry`] plus
//!    optional `decode-as` overrides, parses its own copy of the filter string,
//!    and reuses one [`DissectBuffer`].  For each packet it dissects, evaluates
//!    the filter, and on match serialises via [`write_packet_json`] into bytes.
//!    Results are sent in the same batch order they were received.
//!
//! 3. **Merger** (calling thread): receives result batches strictly in
//!    round-robin worker order to preserve global packet order.  Applies
//!    `sample_rate`, `offset`, and `count` on the ordered match stream, writes
//!    matched JSON to the supplied writer, and calls the progress and warning
//!    callbacks.  On reaching the count limit it sets the stop flag and drains
//!    all threads cleanly before returning.
//!
//! # Batch format
//!
//! Each batch is a `Vec<(PacketMeta, Vec<u8>)>` — at most 256 packets or
//! 1 MiB of raw packet data, whichever comes first.  Results for each batch
//! are a `Vec` of per-packet entries (matches or warnings).
//!
//! # Robustness
//!
//! * No `unwrap` / `expect` in production code paths.
//! * Worker threads exit cleanly when their input channel is disconnected
//!   (reader dropped the sender).
//! * The merger handles worker channel disconnection by stopping cleanly.
//! * All threads are joined before returning so output is fully flushed.

use std::io;
use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::DissectBuffer;

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

/// Options for the parallel read engine.
///
/// All fields are derived from the `dsct read` CLI arguments and passed
/// through without mutation.
pub struct ParallelReadOptions<'a> {
    /// Path to the capture file (must not be stdin `"-"`).
    pub path: &'a Path,
    /// Raw filter string (already verified as parallel-safe by the caller).
    pub filter_str: &'a str,
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

/// Outcome reported after a successful run.
///
/// Provides enough information for the caller to emit a truncation warning.
pub struct ReadOutcome {
    /// Total packets read from the file (after packet-number filtering).
    /// Note: because workers do not report non-matching packets back to the
    /// merger, this count reflects only matched-or-warned packets.  It is
    /// provided primarily for truncation detection.
    pub packets_processed: u64,
    /// Number of JSON records written to the writer.
    pub packets_written: u64,
    /// `true` if the run stopped because the count limit was reached (not EOF).
    pub truncated_by_limit: bool,
}

// ---------------------------------------------------------------------------
// Internal message types
// ---------------------------------------------------------------------------

/// One batch of raw packets sent from the reader to a worker.
type InputBatch = Vec<(PacketMeta, Vec<u8>)>;

/// One result entry produced by a worker.
enum WorkerEntry {
    /// A packet that matched the filter; contains serialised JSON bytes
    /// (no trailing newline — the merger adds it).
    Match(Vec<u8>),
    /// Dissection failed for this packet number.
    Warning { number: u64, message: String },
}

/// One batch of results sent from a worker back to the merger.
type OutputBatch = Vec<WorkerEntry>;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Run parallel filter evaluation and write matching JSONL records to `writer`.
///
/// The caller is responsible for ensuring that:
/// - `opts.path` is a regular file (not `"-"`).
/// - The filter has already been parsed and verified as
///   [`parallel_safe`](FilterExpr::is_parallel_safe).
/// - `opts.threads >= 2`.
///
/// Callbacks:
/// - `warn(packet_number, message)` — called in packet order for per-packet
///   dissection warnings.
/// - `progress(packets_processed, packets_written)` — called approximately
///   every `opts.progress_interval` output records (at batch granularity).
pub fn run<W: io::Write>(
    opts: &ParallelReadOptions<'_>,
    writer: &mut W,
    warn: &mut dyn FnMut(u64, &str),
    progress: &mut dyn FnMut(u64, u64),
) -> Result<ReadOutcome> {
    let n = opts.threads;

    // Build per-worker input/output channels.
    let mut input_txs: Vec<mpsc::SyncSender<InputBatch>> = Vec::with_capacity(n);
    let mut input_rxs: Vec<mpsc::Receiver<InputBatch>> = Vec::with_capacity(n);
    let mut output_txs: Vec<mpsc::SyncSender<OutputBatch>> = Vec::with_capacity(n);
    let mut output_rxs: Vec<mpsc::Receiver<OutputBatch>> = Vec::with_capacity(n);

    for _ in 0..n {
        let (itx, irx) = mpsc::sync_channel::<InputBatch>(CHAN_CAPACITY);
        let (otx, orx) = mpsc::sync_channel::<OutputBatch>(CHAN_CAPACITY);
        input_txs.push(itx);
        input_rxs.push(irx);
        output_txs.push(otx);
        output_rxs.push(orx);
    }

    // Shared stop flag: set by merger when count limit reached.
    let stop = Arc::new(AtomicBool::new(false));

    // -----------------------------------------------------------------------
    // Spawn N workers
    // -----------------------------------------------------------------------
    let mut worker_handles = Vec::with_capacity(n);

    let filter_str = opts.filter_str.to_owned();
    let decode_as_args_owned: Vec<String> = opts.decode_as_args.to_vec();
    let field_config_clone: Option<FieldConfig> = opts.field_config.cloned();
    let raw_bytes = opts.raw_bytes;

    // output_txs will be drained into workers; move them one by one.
    let mut output_txs_iter = output_txs.into_iter();

    for irx in input_rxs {
        let otx = output_txs_iter
            .next()
            .ok_or_else(|| DsctError::msg("internal: output_txs exhausted"))?;
        let fs = filter_str.clone();
        let da = decode_as_args_owned.clone();
        let fc = field_config_clone.clone();

        let handle = std::thread::Builder::new()
            .name("dsct-worker".into())
            .spawn(move || worker_fn(irx, otx, fs, da, fc, raw_bytes))
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
    let outcome = merger_fn(opts, &mut output_rxs, writer, warn, progress, &stop);

    // -----------------------------------------------------------------------
    // Join all threads — must happen even on error to avoid resource leaks.
    // Dropping output_rxs causes workers to exit their send loops, which drains
    // their input channels, unblocking the reader.
    // -----------------------------------------------------------------------
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

    let outcome = outcome?;
    reader_result?;
    if worker_panicked {
        return Err(DsctError::msg(
            "a worker thread panicked; output may be incomplete",
        ));
    }
    Ok(outcome)
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
    let mut current_batch: InputBatch = Vec::with_capacity(BATCH_PACKETS);
    let mut current_batch_bytes: usize = 0;

    reader.for_each_packet(|meta, data| {
        if stop.load(Ordering::Relaxed) {
            return Ok(ControlFlow::Break(()));
        }

        // Packet-number pre-filter (mirrors sequential logic exactly).
        if let Some(ref pnf) = pn_filter
            && !pnf.contains(meta.number)
        {
            if pn_max.is_some_and(|m| meta.number > m) {
                return Ok(ControlFlow::Break(()));
            }
            return Ok(ControlFlow::Continue(()));
        }

        current_batch.push((meta, data.to_vec()));
        current_batch_bytes += data.len();

        if current_batch.len() >= BATCH_PACKETS || current_batch_bytes >= BATCH_BYTES {
            let batch = std::mem::replace(&mut current_batch, Vec::with_capacity(BATCH_PACKETS));
            current_batch_bytes = 0;
            if input_txs[worker_idx].send(batch).is_err() {
                // Worker exited — stop flag should also be set.
                return Ok(ControlFlow::Break(()));
            }
            worker_idx = (worker_idx + 1) % n;
        }

        Ok(ControlFlow::Continue(()))
    })?;

    // Flush last partial batch.
    if !current_batch.is_empty() && !stop.load(Ordering::Relaxed) {
        // Ignore send error — receiver may have disconnected if stop was set.
        let _ = input_txs[worker_idx].send(current_batch);
    }

    // Dropping input_txs closes all worker input channels → workers exit.
    Ok(())
}

// ---------------------------------------------------------------------------
// Worker thread
// ---------------------------------------------------------------------------

fn worker_fn(
    irx: mpsc::Receiver<InputBatch>,
    otx: mpsc::SyncSender<OutputBatch>,
    filter_str: String,
    decode_as_args: Vec<String>,
    field_config: Option<FieldConfig>,
    raw_bytes: bool,
) {
    let mut registry = DissectorRegistry::default();
    if decode_as::parse_and_apply(&mut registry, &decode_as_args).is_err() {
        // decode-as args were validated before spawning; this should not occur.
        return;
    }

    let expr: Option<FilterExpr> = match FilterExpr::parse(&filter_str) {
        Ok(e) => e,
        Err(_) => return,
    };

    let mut dissect_buf = DissectBuffer::new();
    let mut json_buf: Vec<u8> = Vec::with_capacity(4096);

    for batch in &irx {
        let mut results: OutputBatch = Vec::with_capacity(batch.len());

        for (meta, data) in &batch {
            let dbuf = dissect_buf.clear_into();
            if let Err(e) = registry.dissect_with_link_type(data, meta.link_type, dbuf) {
                results.push(WorkerEntry::Warning {
                    number: meta.number,
                    message: format!("{e}"),
                });
                continue;
            }
            let packet = packet_dissector_core::packet::Packet::new(dbuf, data.as_slice());

            if let Some(ref e) = expr
                && !e.matches_with_number(&packet, meta.number)
            {
                continue;
            }

            json_buf.clear();
            if write_packet_json(
                &mut json_buf,
                meta,
                dbuf,
                data.as_slice(),
                field_config.as_ref(),
                raw_bytes,
            )
            .is_ok()
            {
                results.push(WorkerEntry::Match(json_buf.clone()));
            }
        }

        if otx.send(results).is_err() {
            // Merger dropped the receiver (count limit reached); exit cleanly.
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Merger (runs on calling thread)
// ---------------------------------------------------------------------------

fn merger_fn<W: io::Write>(
    opts: &ParallelReadOptions<'_>,
    output_rxs: &mut [mpsc::Receiver<OutputBatch>],
    writer: &mut W,
    warn: &mut dyn FnMut(u64, &str),
    progress: &mut dyn FnMut(u64, u64),
    stop: &AtomicBool,
) -> Result<ReadOutcome> {
    let n = output_rxs.len();
    let sample_rate = opts.sample_rate;
    let offset = opts.offset;
    let count = opts.count;
    let progress_interval = opts.progress_interval;

    let mut packets_processed = 0u64;
    let mut packets_written = 0u64;
    let mut filter_matches = 0u64;
    let mut results_matched = 0u64;
    let mut truncated_by_limit = false;
    let mut worker_idx = 0usize;

    // Receive from workers in strict round-robin order (same order the reader
    // sent batches to them), preserving global packet order.
    'outer: loop {
        match output_rxs[worker_idx].recv() {
            Err(_) => {
                // Channel closed: either stop flag is set (expected EOF / limit)
                // or all workers finished (EOF).  Either way, we are done.
                break 'outer;
            }
            Ok(batch) => {
                // Count packets represented in this batch for progress reporting.
                let batch_count = batch.len() as u64;
                packets_processed = packets_processed.saturating_add(batch_count);

                for entry in batch {
                    match entry {
                        WorkerEntry::Warning { number, message } => {
                            warn(number, &message);
                        }
                        WorkerEntry::Match(json_bytes) => {
                            filter_matches += 1;
                            if sample_rate > 1 && !(filter_matches - 1).is_multiple_of(sample_rate)
                            {
                                continue;
                            }
                            results_matched += 1;
                            if results_matched <= offset {
                                continue;
                            }
                            writer.write_all(&json_bytes)?;
                            writer.write_all(b"\n")?;
                            packets_written += 1;

                            if let Some(max) = count
                                && packets_written >= max
                            {
                                truncated_by_limit = true;
                                stop.store(true, Ordering::Relaxed);
                                break 'outer;
                            }
                        }
                    }
                }

                // Progress reporting at batch granularity.
                if progress_interval > 0
                    && packets_written > 0
                    && packets_written.is_multiple_of(progress_interval)
                {
                    progress(packets_processed, packets_written);
                }

                worker_idx = (worker_idx + 1) % n;
            }
        }
    }

    Ok(ReadOutcome {
        packets_processed,
        packets_written,
        truncated_by_limit,
    })
}
