//! Parallel filter scan using per-worker capture file handles.
//!
//! Splits the packet index into chunks and evaluates the filter expression on
//! each chunk concurrently.  Each worker opens the capture file independently
//! and creates its own [`DissectorRegistry`], avoiding shared mutable state.

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

/// A result chunk from a worker thread.
///
/// Contains the chunk index (for ordering) and the matching packet indices
/// within the original snapshot.
type ChunkResult = (usize, Vec<usize>);

/// Result of polling a [`ParallelFilterScan`] via [`ParallelFilterScan::drain`].
pub(super) enum ScanPoll {
    /// Workers are still producing results.
    Running,
    /// Scan finished; contains the matching packets as a bitmap.
    Complete(FilterBitmap),
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
    chunk_results: Vec<Option<Vec<usize>>>,
}

impl ParallelFilterScan {
    /// Start a parallel filter scan.
    ///
    /// Spawns `thread_count` worker threads.  Each worker opens `file_path`,
    /// builds a [`DissectorRegistry`] configured with `decode_as_args`, parses
    /// the filter string, and scans its assigned chunks.
    ///
    /// Returns `Err` if the first worker fails to open the capture file.
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
            chunk_results: vec![None; chunks_total],
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
    /// Returns [`ScanPoll::Complete`] with the matching packet bitmap when
    /// the scan is complete, [`ScanPoll::Running`] while workers are still
    /// producing results, or [`ScanPoll::Failed`] when every worker exited
    /// (channel disconnected) before all chunks were delivered — for example
    /// because the capture file could not be reopened.
    pub fn drain(&mut self) -> ScanPoll {
        // Collect all currently available results.
        let mut disconnected = false;
        loop {
            match self.receiver.try_recv() {
                Ok((chunk_id, matches)) => {
                    if chunk_id < self.chunk_results.len() {
                        self.chunk_results[chunk_id] = Some(matches);
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
            // All chunks received — concatenate in order into a bitmap.  Chunk
            // results arrive ordered and each chunk's matches are increasing,
            // so the concatenation is strictly increasing (append-friendly).
            let ordered = self
                .chunk_results
                .iter()
                .flatten()
                .flat_map(|matches| matches.iter().copied());
            let result = FilterBitmap::from_sorted_indices(self.total, ordered);
            ScanPoll::Complete(result)
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

/// Entry point for a single worker thread.
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
    let mut registry = DissectorRegistry::default();
    if crate::decode_as::parse_and_apply(&mut registry, &ctx.decode_as_args).is_err() {
        return;
    }

    // Parse the filter expression.
    let expr = match FilterExpr::parse(&ctx.filter_str) {
        Ok(Some(e)) => e,
        _ => return,
    };

    let total = ctx.indices.len();
    let mut dissect_buf = DissectBuffer::new();

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

        for i in start..end {
            let number = (i as u64) + 1;
            let index = &ctx.indices[i];
            if let Some(data) = capture.packet_data(index) {
                let buf = dissect_buf.clear_into();
                if registry
                    .dissect_with_link_type(data, index.link_type as u32, buf)
                    .is_ok()
                {
                    let packet = Packet::new(buf, data);
                    if expr.matches_with_number(&packet, number) {
                        matches.push(i);
                    }
                }
            }
        }

        ctx.scanned.fetch_add(end - start, Ordering::Release);

        if ctx.tx.send((chunk_id, matches)).is_err() {
            return;
        }
    }
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use super::*;
    use std::io::Write;

    use packet_dissector::registry::DissectorRegistry;

    use super::super::loader;
    use super::super::state::CaptureMap;

    /// Build a pcap with `udp_count` UDP packets then `tcp_count` TCP packets.
    fn build_mixed_pcap_for_test(udp_count: usize, tcp_count: usize) -> Vec<u8> {
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

        let par_bitmap = loop {
            match scan.drain() {
                ScanPoll::Complete(r) => break r,
                ScanPoll::Failed => panic!("parallel scan failed"),
                ScanPoll::Running => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        };

        let par_results: Vec<usize> = par_bitmap.iter().collect();
        assert_eq!(
            par_results, seq_results,
            "parallel and sequential must agree"
        );
        assert_eq!(par_results.len(), 10, "expected 10 UDP packets");
        // The bitmap universe must cover every scanned packet.
        assert_eq!(par_bitmap.universe(), 15);
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
                ScanPoll::Complete(_) => panic!("scan must not complete without workers"),
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
