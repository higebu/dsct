//! Background thread for pcap file indexing.
//!
//! Moves the CPU-intensive index scan off the main (UI) thread so that key
//! presses, mouse events, and rendering are never blocked by indexing work.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;

use crate::error::Result;

use super::loader;
use super::state::PacketIndex;

/// A batch of newly indexed packet records sent from the background thread.
pub(super) struct IndexBatch {
    /// Newly indexed packet records.
    pub records: Vec<PacketIndex>,
    /// Whether indexing is complete.
    pub done: bool,
}

/// Drives pcap indexing on a background thread, delivering results to the main
/// thread via a channel.
pub(super) struct BackgroundIndexer {
    receiver: mpsc::Receiver<IndexBatch>,
    cancel: Arc<AtomicBool>,
    /// Current byte offset (updated from received batches).
    pub byte_offset: Arc<AtomicUsize>,
    /// Total file size in bytes.
    pub total_bytes: usize,
    _handle: std::thread::JoinHandle<()>,
}

impl BackgroundIndexer {
    /// Number of records to process per batch in the background thread.
    const CHUNK_SIZE: usize = 10_000;

    /// Maximum number of batches to drain per tick.
    ///
    /// Caps the work done in a single `drain()` call so the main thread stays
    /// responsive to key events during indexing.  20 batches × 10 000 records
    /// = 200 000 records per tick — plenty to keep the UI up-to-date while
    /// bounding the memcpy overhead to a few milliseconds.
    const MAX_DRAIN_BATCHES: usize = 20;

    /// Spawn a background indexing thread for the given capture file.
    ///
    /// Opens a second memory-map of the file so the main thread's
    /// [`CaptureMap`] is not shared across threads.
    #[allow(unsafe_code)]
    pub fn spawn(path: &Path, total_bytes: usize) -> Result<Self> {
        let file =
            std::fs::File::open(path).map_err(|e| crate::error::DsctError::msg(e.to_string()))?;
        // SAFETY: The file is opened read-only. The mapping lives inside the
        // spawned thread and is dropped when the thread exits.
        let mmap = unsafe {
            memmap2::MmapOptions::new()
                .map(&file)
                .map_err(|e| crate::error::DsctError::msg(e.to_string()))?
        };

        let (tx, rx) = mpsc::channel();
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = Arc::clone(&cancel);
        let byte_offset = Arc::new(AtomicUsize::new(0));
        let byte_offset_clone = Arc::clone(&byte_offset);

        let handle = std::thread::Builder::new()
            .name("bg-indexer".into())
            .spawn(move || {
                Self::indexer_thread(mmap, tx, cancel_clone, byte_offset_clone);
            })
            .map_err(|e| crate::error::DsctError::msg(e.to_string()))?;

        Ok(Self {
            receiver: rx,
            cancel,
            byte_offset,
            total_bytes,
            _handle: handle,
        })
    }

    /// Drain available batches from the channel without blocking.
    ///
    /// Returns the collected records and whether indexing is complete.
    /// At most [`Self::MAX_DRAIN_BATCHES`] batches are consumed per call so
    /// that the main thread can poll for key events between drains.
    pub fn drain(&self) -> (Vec<PacketIndex>, bool) {
        let mut all_records = Vec::new();
        let mut done = false;

        for _ in 0..Self::MAX_DRAIN_BATCHES {
            match self.receiver.try_recv() {
                Ok(batch) => {
                    all_records.extend(batch.records);
                    done = batch.done;
                    if done {
                        break;
                    }
                }
                Err(_) => break,
            }
        }

        (all_records, done)
    }

    /// Progress fraction (0.0 to 1.0) based on byte position.
    pub fn fraction(&self) -> f64 {
        if self.total_bytes == 0 {
            1.0
        } else {
            self.byte_offset.load(Ordering::Relaxed) as f64 / self.total_bytes as f64
        }
    }

    /// The background indexing thread entry point.
    fn indexer_thread(
        mmap: memmap2::Mmap,
        tx: mpsc::Sender<IndexBatch>,
        cancel: Arc<AtomicBool>,
        byte_offset: Arc<AtomicUsize>,
    ) {
        let data = &mmap[..];

        let mut state = match packet_dissector_pcap::build_index_start(data) {
            Ok(s) => s,
            Err(_) => {
                let _ = tx.send(IndexBatch {
                    records: Vec::new(),
                    done: true,
                });
                return;
            }
        };

        loop {
            if cancel.load(Ordering::Acquire) {
                return;
            }

            match packet_dissector_pcap::build_index_chunk(data, &mut state, Self::CHUNK_SIZE) {
                Ok(records) => {
                    let pkt_indices = loader::convert_records(records);
                    let is_done = state.done;

                    byte_offset.store(state.byte_offset, Ordering::Release);

                    if tx
                        .send(IndexBatch {
                            records: pkt_indices,
                            done: is_done,
                        })
                        .is_err()
                    {
                        // Receiver dropped (app quit); stop.
                        return;
                    }

                    if is_done {
                        return;
                    }
                }
                Err(_) => {
                    byte_offset.store(state.byte_offset, Ordering::Release);
                    let _ = tx.send(IndexBatch {
                        records: Vec::new(),
                        done: true,
                    });
                    return;
                }
            }
        }
    }
}

impl Drop for BackgroundIndexer {
    fn drop(&mut self) {
        // Signal the background thread to stop.
        self.cancel.store(true, Ordering::Release);
        // We intentionally do not join — the thread will notice the cancel flag
        // and exit on its own.  Joining could stall teardown if the thread is
        // mid-chunk.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to build a `BackgroundIndexer` from a pre-loaded channel
    /// (no real background thread).
    fn fake_indexer(batches: Vec<IndexBatch>) -> BackgroundIndexer {
        let (tx, rx) = mpsc::channel();
        for batch in batches {
            tx.send(batch).unwrap();
        }
        drop(tx);
        BackgroundIndexer {
            receiver: rx,
            cancel: Arc::new(AtomicBool::new(false)),
            byte_offset: Arc::new(AtomicUsize::new(0)),
            total_bytes: 0,
            _handle: std::thread::spawn(|| {}),
        }
    }

    fn make_batch(n: usize, done: bool) -> IndexBatch {
        IndexBatch {
            records: vec![
                PacketIndex {
                    data_offset: 0,
                    captured_len: 0,
                    original_len: 0,
                    timestamp_secs: 0,
                    timestamp_usecs: 0,
                    link_type: 1,
                    _pad: 0,
                };
                n
            ],
            done,
        }
    }

    #[test]
    fn drain_respects_batch_limit() {
        // Send more batches than MAX_DRAIN_BATCHES.
        let total_batches = BackgroundIndexer::MAX_DRAIN_BATCHES + 10;
        let batches: Vec<_> = (0..total_batches).map(|_| make_batch(100, false)).collect();
        let indexer = fake_indexer(batches);

        let (records, done) = indexer.drain();
        // Should have drained exactly MAX_DRAIN_BATCHES × 100 records.
        assert_eq!(records.len(), BackgroundIndexer::MAX_DRAIN_BATCHES * 100);
        assert!(!done);

        // A second drain picks up the remaining 10 batches.
        let (records2, done2) = indexer.drain();
        assert_eq!(records2.len(), 10 * 100);
        assert!(!done2);
    }

    #[test]
    fn drain_stops_at_done_batch() {
        let batches = vec![
            make_batch(50, false),
            make_batch(50, true),
            make_batch(50, false), // should not be consumed
        ];
        let indexer = fake_indexer(batches);

        let (records, done) = indexer.drain();
        assert_eq!(records.len(), 100);
        assert!(done);

        // The third batch remains in the channel.
        let (records2, _) = indexer.drain();
        assert_eq!(records2.len(), 50);
    }

    #[test]
    fn drain_empty_channel_returns_nothing() {
        let indexer = fake_indexer(vec![]);
        let (records, done) = indexer.drain();
        assert!(records.is_empty());
        assert!(!done);
    }

    #[test]
    fn spawn_returns_error_for_nonexistent_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does_not_exist.pcap");
        let result = BackgroundIndexer::spawn(&missing, 0);
        assert!(
            result.is_err(),
            "spawn should return Err for a missing path, not panic"
        );
    }

    #[test]
    fn spawn_returns_error_for_unmappable_path() {
        // A directory path opens successfully on Linux but mmap(2) on a
        // directory fd returns ENODEV ("No such device").  memmap2 surfaces
        // this as an Err, and BackgroundIndexer::spawn wraps it into a
        // DsctError via `.map_err(|e| DsctError::msg(e.to_string()))?`.
        // The test asserts that the error from the unsafe mmap block is
        // propagated rather than panicking.
        let dir = tempfile::tempdir().unwrap();
        let result = BackgroundIndexer::spawn(dir.path(), 0);
        assert!(
            result.is_err(),
            "spawn should return Err when mmap fails, not panic"
        );
    }

    #[test]
    fn bg_thread_exits_cleanly_when_receiver_dropped() {
        use std::io::Write;
        use std::sync::mpsc::RecvTimeoutError;
        use std::time::Duration;

        // 25_000 packets > 2 * CHUNK_SIZE so the bg thread is very likely
        // still in its send loop when we drop the receiver.  Even if it
        // already finished (very small input race), the test still passes
        // — any clean exit path satisfies the assertion.
        let pcap = super::super::loader::tests::build_pcap_for_test(25_000);
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&pcap).unwrap();
        tmp.flush().unwrap();

        let mut indexer = BackgroundIndexer::spawn(tmp.path(), pcap.len()).unwrap();

        // Steal the real handle and receiver, leaving placeholders behind
        // so that `std::mem::forget(indexer)` below doesn't leave dangling
        // fields.
        let dummy_handle = std::thread::spawn(|| {});
        let handle = std::mem::replace(&mut indexer._handle, dummy_handle);

        let (_dummy_tx, dummy_rx) = mpsc::channel::<IndexBatch>();
        let receiver = std::mem::replace(&mut indexer.receiver, dummy_rx);

        // Suppress BackgroundIndexer::Drop so the cancel flag is never set.
        // We want to verify that *receiver drop alone* is sufficient for
        // clean termination, independent of the cancel signal.
        std::mem::forget(indexer);

        // Drop the real receiver: the bg thread's next tx.send() now fails.
        drop(receiver);

        // Join via a helper thread so we can enforce a timeout — a hung or
        // panicking bg thread must fail the test, not stall cargo.
        let (done_tx, done_rx) = mpsc::channel::<std::thread::Result<()>>();
        std::thread::spawn(move || {
            let r = handle.join();
            let _ = done_tx.send(r);
        });

        match done_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(join_result) => {
                assert!(
                    join_result.is_ok(),
                    "bg thread panicked instead of exiting cleanly: {join_result:?}"
                );
            }
            Err(RecvTimeoutError::Timeout) => {
                panic!("bg thread did not exit within 5s of receiver drop")
            }
            Err(RecvTimeoutError::Disconnected) => {
                panic!("join helper thread died before reporting a result")
            }
        }
    }
}
