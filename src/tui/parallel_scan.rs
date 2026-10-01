//! Parallel filter scan using per-worker capture file handles.
//!
//! Splits the packet index into chunks and evaluates the filter expression on
//! each chunk concurrently.  Each worker opens the capture file independently
//! and creates its own [`DissectorRegistry`], avoiding shared mutable state.
//!
//! Workers cannot reproduce state kept across packets (TCP streams, IP
//! fragment reassembly, ...), so the scan is optimistic.  A packet whose
//! dissection did not use such state
//! ([`DissectBuffer::used_cross_packet_state`]) gives the same result in any
//! registry, so its worker result is kept.  A packet whose dissection did is
//! listed instead, and the caller dissects the listed packets in capture
//! order with one fresh registry ([`ScanPoll::InOrder`]).  Unlisted packets
//! never touch the state, so this equals a sequential scan from the start
//! with a fresh registry.

use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::{DissectBuffer, Packet};

use crate::filter_expr::FilterExpr;

use super::filter_bitmap::FilterBitmap;
use super::state::{CaptureMap, PacketIndex};

/// Number of packets processed by each worker per chunk.
const CHUNK_SIZE: usize = 8192;

/// A worker whose chunk had at least this share (in percent) of packets that
/// used cross-packet state lists its next [`SKIP_CHUNKS`] chunks without
/// dissecting them: they are dissected in order anyway.
const MOSTLY_IN_ORDER_PERCENT: usize = 90;

/// See [`MOSTLY_IN_ORDER_PERCENT`].
const SKIP_CHUNKS: u32 = 3;

/// A result chunk from a worker thread.
struct ChunkResult {
    /// Chunk index (for ordering).
    chunk_id: usize,
    /// Matching packet indices within the original snapshot, in order,
    /// among the packets whose dissection did not use cross-packet state.
    matches: Vec<usize>,
    /// Index runs of the packets that must be dissected in order, in order.
    in_order: Vec<Range<usize>>,
}

/// Result of polling a [`ParallelFilterScan`] via [`ParallelFilterScan::drain`].
pub(super) enum ScanPoll {
    /// Workers are still producing results.
    Running,
    /// Scan finished; contains the matching packets as a bitmap.
    Complete(FilterBitmap),
    /// Scan finished, but the packets in `in_order` used cross-packet state:
    /// the caller must dissect them in capture order with one fresh registry
    /// and merge their matches with `matches`.
    InOrder {
        /// Matches among the packets not in `in_order`.
        matches: FilterBitmap,
        /// The packets to dissect in order.
        in_order: FilterBitmap,
    },
    /// All workers exited before the scan completed (e.g. the capture file
    /// could not be reopened).  The caller must fall back to sequential
    /// scanning; the parallel scan can never finish.
    Failed,
}

/// A parallel filter scan that distributes work across N worker threads.
///
/// Each worker opens the capture file independently, builds a fresh
/// [`DissectorRegistry`], and evaluates the filter over its assigned chunks.
/// Results arrive out of order via a channel and are reassembled in order
/// when the scan is complete.
pub(super) struct ParallelFilterScan {
    receiver: mpsc::Receiver<ChunkResult>,
    cancel: Arc<AtomicBool>,
    /// Total number of packets being scanned.
    pub total: usize,
    scanned: Arc<AtomicUsize>,
    chunks_total: usize,
    chunks_done: usize,
    chunk_results: Vec<Option<ChunkResult>>,
}

impl ParallelFilterScan {
    /// Start a parallel filter scan.
    ///
    /// Spawns `thread_count` worker threads.  Each worker opens `file_path`,
    /// builds a [`DissectorRegistry`] configured with `decode_as_args`, parses
    /// the filter string, and scans its assigned chunks.
    ///
    /// Returns `Err` if a worker thread cannot be spawned.
    pub fn new(
        file_path: PathBuf,
        decode_as_args: Vec<String>,
        indices: Arc<[PacketIndex]>,
        filter_str: String,
        thread_count: usize,
    ) -> std::io::Result<Self> {
        let total = indices.len();
        let chunks_total = total.div_ceil(CHUNK_SIZE);

        let (tx, rx) = mpsc::channel::<ChunkResult>();
        let cancel = Arc::new(AtomicBool::new(false));
        let scanned = Arc::new(AtomicUsize::new(0));

        // Work-stealing cursor: the next chunk index to process.
        let next_chunk = Arc::new(AtomicUsize::new(0));

        for worker_id in 0..thread_count {
            let tx = tx.clone();
            let cancel = Arc::clone(&cancel);
            let scanned = Arc::clone(&scanned);
            let next_chunk = Arc::clone(&next_chunk);
            let indices = Arc::clone(&indices);
            let file_path = file_path.clone();
            let decode_as_args = decode_as_args.clone();
            let filter_str = filter_str.clone();

            std::thread::Builder::new()
                .name(format!("filter-worker-{worker_id}"))
                .spawn(move || {
                    worker_thread(WorkerContext {
                        file_path,
                        decode_as_args,
                        indices,
                        filter_str,
                        next_chunk,
                        cancel,
                        scanned,
                        tx,
                        chunks_total,
                    });
                })
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }

        // Drop our copy of the sender; workers hold theirs.
        drop(tx);

        Ok(Self {
            receiver: rx,
            cancel,
            total,
            scanned,
            chunks_total,
            chunks_done: 0,
            chunk_results: (0..chunks_total).map(|_| None).collect(),
        })
    }

    /// Progress fraction in `0.0..=1.0`.
    pub fn fraction(&self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        let done = self.scanned.load(Ordering::Relaxed);
        (done as f64 / self.total as f64).min(1.0)
    }

    /// Drain available results non-blockingly.
    ///
    /// Returns [`ScanPoll::Complete`] or [`ScanPoll::InOrder`] once every
    /// chunk has been scanned, [`ScanPoll::Running`] while workers are still
    /// producing results, or [`ScanPoll::Failed`] when every worker exited
    /// (channel disconnected) before all chunks were delivered — for example
    /// because the capture file could not be reopened.
    pub fn drain(&mut self) -> ScanPoll {
        // Collect all currently available results.
        let mut disconnected = false;
        loop {
            match self.receiver.try_recv() {
                Ok(result) => {
                    let chunk_id = result.chunk_id;
                    if let Some(slot) = self.chunk_results.get_mut(chunk_id) {
                        *slot = Some(result);
                        self.chunks_done += 1;
                    }
                }
                Err(mpsc::TryRecvError::Empty) => break,
                Err(mpsc::TryRecvError::Disconnected) => {
                    // All senders dropped: every worker has exited.  Any
                    // results sent before the disconnect have already been
                    // received above.
                    disconnected = true;
                    break;
                }
            }
        }

        if self.chunks_done >= self.chunks_total {
            // All chunks received — concatenate in order.  Chunk results
            // arrive ordered and each chunk's lists are increasing, so the
            // concatenations are strictly increasing (append-friendly).
            let chunks = || self.chunk_results.iter().flatten();
            let matches = FilterBitmap::from_sorted_indices(
                self.total,
                chunks().flat_map(|c| c.matches.iter().copied()),
            );
            let mut in_order = FilterBitmap::new();
            for run in chunks().flat_map(|c| c.in_order.iter()) {
                in_order.push_set_range(run.clone());
            }
            if in_order.is_empty() {
                return ScanPoll::Complete(matches);
            }
            in_order.extend_universe(self.total);
            ScanPoll::InOrder { matches, in_order }
        } else if disconnected {
            // Workers are gone but chunks are missing — the scan can never
            // complete.  Signal the caller to fall back to sequential scanning.
            ScanPoll::Failed
        } else {
            ScanPoll::Running
        }
    }

    /// Signal worker threads to stop processing.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release);
    }
}

impl Drop for ParallelFilterScan {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}

/// Shared context passed to each worker thread.
struct WorkerContext {
    file_path: PathBuf,
    decode_as_args: Vec<String>,
    indices: Arc<[PacketIndex]>,
    filter_str: String,
    next_chunk: Arc<AtomicUsize>,
    cancel: Arc<AtomicBool>,
    scanned: Arc<AtomicUsize>,
    tx: mpsc::Sender<ChunkResult>,
    chunks_total: usize,
}

/// A registry configured with the `decode-as` overrides, or `None` if they
/// do not apply (they were validated at startup, so this does not happen).
fn worker_registry(decode_as_args: &[String]) -> Option<DissectorRegistry> {
    let mut registry = DissectorRegistry::default();
    crate::decode_as::parse_and_apply(&mut registry, decode_as_args).ok()?;
    Some(registry)
}

/// Entry point for a single worker thread.
///
/// Any setup failure ends the worker without results; the scan then reports
/// [`ScanPoll::Failed`] and the caller scans sequentially.
fn worker_thread(ctx: WorkerContext) {
    // Open an independent file handle and mmap for this worker.
    let file = match std::fs::File::open(&ctx.file_path) {
        Ok(f) => f,
        Err(_) => return,
    };
    let capture = match CaptureMap::new(&file) {
        Ok(c) => c,
        Err(_) => return,
    };

    // Build an independent registry for this worker.
    let Some(mut registry) = worker_registry(&ctx.decode_as_args) else {
        return;
    };

    // Parse the filter expression.
    let expr = match FilterExpr::parse(&ctx.filter_str) {
        Ok(Some(e)) => e,
        _ => return,
    };

    let total = ctx.indices.len();
    let mut dissect_buf = DissectBuffer::new();
    let mut skip_chunks = 0u32;

    loop {
        if ctx.cancel.load(Ordering::Acquire) {
            return;
        }

        let chunk_id = ctx.next_chunk.fetch_add(1, Ordering::AcqRel);
        if chunk_id >= ctx.chunks_total {
            return;
        }

        let start = chunk_id * CHUNK_SIZE;
        let end = (start + CHUNK_SIZE).min(total);
        let mut matches = Vec::new();
        let mut in_order = Vec::new();

        if skip_chunks > 0 {
            // Dissecting a packet in order is always correct.
            skip_chunks -= 1;
            in_order.push(start..end);
        } else {
            for i in start..end {
                let number = (i as u64) + 1;
                let index = &ctx.indices[i];
                if let Some(data) = capture.packet_data(index) {
                    let buf = dissect_buf.clear_into();
                    let dissected =
                        registry.dissect_with_link_type(data, index.link_type as u32, buf);
                    if buf.used_cross_packet_state() {
                        match in_order.last_mut() {
                            Some(run) if run.end == i => run.end = i + 1,
                            _ => in_order.push(i..i + 1),
                        }
                        continue;
                    }
                    if dissected.is_ok() {
                        let packet = Packet::new(buf, data);
                        if expr.matches_with_number(&packet, number) {
                            matches.push(i);
                        }
                    }
                }
            }
            if !in_order.is_empty() {
                // Drop the state this chunk built up; it is never used, since
                // every packet that touched it is dissected in order.
                let Some(fresh) = worker_registry(&ctx.decode_as_args) else {
                    return;
                };
                registry = fresh;
            }
            let listed: usize = in_order.iter().map(ExactSizeIterator::len).sum();
            if listed * 100 >= (end - start) * MOSTLY_IN_ORDER_PERCENT {
                skip_chunks = SKIP_CHUNKS;
            }
        }

        ctx.scanned.fetch_add(end - start, Ordering::Release);

        let result = ChunkResult {
            chunk_id,
            matches,
            in_order,
        };
        if ctx.tx.send(result).is_err() {
            return;
        }
    }
}

#[cfg(all(test, feature = "tui"))]
pub(in crate::tui) mod tests {
    use super::*;
    use std::io::Write;

    use packet_dissector::registry::DissectorRegistry;

    use super::super::loader;
    use super::super::state::CaptureMap;

    /// Build a pcap with `udp_count` UDP packets then `tcp_count` TCP packets.
    pub(in crate::tui) fn build_mixed_pcap_for_test(udp_count: usize, tcp_count: usize) -> Vec<u8> {
        let mut pcap_buf = Vec::new();
        // Global header: magic, version 2.4, Ethernet link type
        pcap_buf.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
        pcap_buf.extend_from_slice(&2u16.to_le_bytes());
        pcap_buf.extend_from_slice(&4u16.to_le_bytes());
        pcap_buf.extend_from_slice(&0i32.to_le_bytes());
        pcap_buf.extend_from_slice(&0u32.to_le_bytes());
        pcap_buf.extend_from_slice(&65535u32.to_le_bytes());
        pcap_buf.extend_from_slice(&1u32.to_le_bytes()); // Ethernet

        // Minimal Ethernet+IPv4+UDP packet (42 bytes)
        let udp_pkt: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x00,
            0x00, 0x01, 0x0A, 0x00, 0x00, 0x02, 0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
        ];

        // Minimal Ethernet+IPv4+TCP packet (54 bytes)
        let tcp_pkt: &[u8] = &[
            // Ethernet
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            // IPv4
            0x45, 0x00, 0x00, 0x28, 0x00, 0x00, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x00, 0x02,
            // TCP: src=80, dst=12345, seq/ack=0, flags=SYN
            0x00, 0x50, 0x30, 0x39, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02,
            0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        let pkt_count = udp_count + tcp_count;
        for i in 0..pkt_count {
            let ts_sec = (i / 1000) as u32;
            let ts_usec = ((i % 1000) * 1000) as u32;
            let pkt = if i < udp_count { udp_pkt } else { tcp_pkt };
            pcap_buf.extend_from_slice(&ts_sec.to_le_bytes());
            pcap_buf.extend_from_slice(&ts_usec.to_le_bytes());
            pcap_buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            pcap_buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            pcap_buf.extend_from_slice(pkt);
        }
        pcap_buf
    }

    fn write_temp_pcap(data: &[u8]) -> (tempfile::NamedTempFile, CaptureMap, Vec<PacketIndex>) {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(data).unwrap();
        tmp.flush().unwrap();
        let file = std::fs::File::open(tmp.path()).unwrap();
        let capture = CaptureMap::new(&file).unwrap();
        let indices = loader::build_index(capture.as_bytes()).unwrap();
        (tmp, capture, indices)
    }

    /// Drive `scan` until it stops running.
    fn drive(scan: &mut ParallelFilterScan) -> ScanPoll {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            match scan.drain() {
                ScanPoll::Running => {
                    assert!(std::time::Instant::now() < deadline, "scan never finished");
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                done => return done,
            }
        }
    }

    #[test]
    fn parallel_scan_udp_filter_matches_sequential() {
        let pcap = build_mixed_pcap_for_test(10, 5);
        let (tmp, capture, indices) = write_temp_pcap(&pcap);
        let indices_arc: Arc<[PacketIndex]> = indices.into();

        // Sequential reference result.
        let mut seq_results = Vec::new();
        {
            let registry = DissectorRegistry::default();
            let mut dissect_buf = DissectBuffer::new();
            let expr = FilterExpr::parse("udp").unwrap().unwrap();
            for (i, index) in indices_arc.iter().enumerate() {
                if let Some(data) = capture.packet_data(index) {
                    let buf = dissect_buf.clear_into();
                    if registry
                        .dissect_with_link_type(data, index.link_type as u32, buf)
                        .is_ok()
                    {
                        let packet = Packet::new(buf, data);
                        if expr.matches_with_number(&packet, (i as u64) + 1) {
                            seq_results.push(i);
                        }
                    }
                }
            }
        }

        // Parallel result.
        let mut scan = ParallelFilterScan::new(
            tmp.path().to_path_buf(),
            vec![],
            indices_arc,
            "udp".to_string(),
            2,
        )
        .unwrap();

        // The TCP packets use cross-packet state (stream tracking), so the
        // parallel scan lists them for in-order dissection.
        let ScanPoll::InOrder { matches, in_order } = drive(&mut scan) else {
            panic!("expected the TCP packets to be listed for in-order dissection");
        };
        assert_eq!(
            in_order.iter().collect::<Vec<_>>(),
            (10..15).collect::<Vec<_>>()
        );
        let matches: Vec<usize> = matches.iter().collect();
        assert_eq!(matches, seq_results, "parallel and sequential must agree");
        assert_eq!(matches.len(), 10, "expected 10 UDP packets");
    }

    #[test]
    fn parallel_scan_lists_stateful_packets_across_chunks() {
        // The TCP packets start in the third chunk and fill the fourth one,
        // which makes the worker that scanned it skip its next chunks.
        let udp = 2 * CHUNK_SIZE + 100;
        let tcp = 3 * CHUNK_SIZE;
        let mut pcap = build_mixed_pcap_for_test(udp, tcp);
        // Append UDP packets after the TCP ones.
        let tail = build_mixed_pcap_for_test(CHUNK_SIZE, 0);
        pcap.extend_from_slice(&tail[24..]);
        let (tmp, _capture, indices) = write_temp_pcap(&pcap);
        let mut scan = ParallelFilterScan::new(
            tmp.path().to_path_buf(),
            vec![],
            indices.into(),
            "udp OR tcp".to_string(),
            4,
        )
        .unwrap();
        let ScanPoll::InOrder { matches, in_order } = drive(&mut scan) else {
            panic!("expected the TCP packets to be listed");
        };
        // Every TCP packet is listed; skipped chunks may list UDP packets
        // too, which in-order dissection handles just as well.
        let tcp_range = udp..udp + tcp;
        assert!(tcp_range.clone().all(|i| in_order.contains(i)));
        // Every packet is either a parallel match (UDP) or listed.
        let total = udp + tcp + CHUNK_SIZE;
        assert_eq!(matches.count_ones() + in_order.count_ones(), total);
        assert!(matches.iter().all(|i| !tcp_range.contains(&i)));
        assert_eq!(in_order.universe(), total);
    }

    #[test]
    fn parallel_scan_without_state_completes() {
        let pcap = build_mixed_pcap_for_test(CHUNK_SIZE + 10, 0);
        let (tmp, _capture, indices) = write_temp_pcap(&pcap);
        let mut scan = ParallelFilterScan::new(
            tmp.path().to_path_buf(),
            vec![],
            indices.into(),
            "udp".to_string(),
            4,
        )
        .unwrap();
        let ScanPoll::Complete(results) = drive(&mut scan) else {
            panic!("a capture without cross-packet state must stay parallel");
        };
        assert_eq!(results.count_ones(), CHUNK_SIZE + 10);
    }

    #[test]
    fn parallel_scan_all_match_ipv4_src() {
        let pcap = loader::tests::build_pcap_for_test(20);
        let (tmp, _capture, indices) = write_temp_pcap(&pcap);
        let indices_arc: Arc<[PacketIndex]> = indices.into();

        let mut scan = ParallelFilterScan::new(
            tmp.path().to_path_buf(),
            vec![],
            indices_arc,
            "ipv4.src = '10.0.0.1'".to_string(),
            2,
        )
        .unwrap();

        let results = loop {
            match scan.drain() {
                ScanPoll::Complete(r) => break r,
                ScanPoll::Failed => panic!("parallel scan failed"),
                ScanPoll::InOrder { .. } => panic!("UDP-only capture must stay parallel"),
                ScanPoll::Running => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        };

        assert_eq!(
            results.count_ones(),
            20,
            "all 20 packets should match ipv4.src"
        );
    }

    #[test]
    fn parallel_scan_fraction_advances() {
        let pcap = loader::tests::build_pcap_for_test(100);
        let (tmp, _capture, indices) = write_temp_pcap(&pcap);
        let indices_arc: Arc<[PacketIndex]> = indices.into();

        let mut scan = ParallelFilterScan::new(
            tmp.path().to_path_buf(),
            vec![],
            indices_arc,
            "udp".to_string(),
            1,
        )
        .unwrap();

        // Drive to completion.
        loop {
            match scan.drain() {
                ScanPoll::Complete(_) => break,
                ScanPoll::Failed => panic!("parallel scan failed"),
                ScanPoll::InOrder { .. } => panic!("UDP-only capture must stay parallel"),
                ScanPoll::Running => std::thread::sleep(std::time::Duration::from_millis(5)),
            }
        }

        let frac = scan.fraction();
        assert!((0.0..=1.0).contains(&frac), "fraction should be in [0,1]");
    }

    #[test]
    fn parallel_scan_failed_when_file_missing() {
        // Workers cannot open the capture file: every worker exits without
        // delivering a chunk.  drain() must report Failed instead of running
        // forever (regression test for an infinite filter_tick loop).
        let pcap = loader::tests::build_pcap_for_test(20);
        let (_tmp, _capture, indices) = write_temp_pcap(&pcap);
        let indices_arc: Arc<[PacketIndex]> = indices.into();

        let mut scan = ParallelFilterScan::new(
            std::path::PathBuf::from("/nonexistent/dsct_missing.pcap"),
            vec![],
            indices_arc,
            "udp".to_string(),
            2,
        )
        .unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            match scan.drain() {
                ScanPoll::Failed => break,
                ScanPoll::Complete(_) | ScanPoll::InOrder { .. } => {
                    panic!("scan must not complete without workers")
                }
                ScanPoll::Running => {
                    assert!(
                        std::time::Instant::now() < deadline,
                        "drain() never reported Failed"
                    );
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
            }
        }
    }
}
