//! Filter application and chunked filter scanning.

use std::sync::Arc;

use packet_dissector_core::packet::{DissectBuffer, Packet};

use super::app::App;
use super::parallel_scan::{ParallelFilterScan, ScanPoll};
use super::state::FilterProgress;
use crate::filter_expr::FilterExpr;

impl App {
    pub(super) fn apply_filter(&mut self) {
        self.filter.error_message = None;

        let expr = match FilterExpr::parse(&self.filter.buf.input) {
            Ok(expr) => expr,
            Err(msg) => {
                self.filter.error_message = Some(msg);
                return;
            }
        };

        self.filter.applied = self.filter.buf.input.clone();

        if expr.is_none() {
            // Empty filter ��� show all packets immediately.
            self.filtered_indices = (0..self.indices.len()).collect();
            self.summary_cache.clear();
            self.packet_list.selected = 0;
            self.packet_list.scroll_offset = 0;
            self.load_selected();
            self.hex_dump.scroll_offset = 0;
            return;
        }

        // Decide whether to use parallel or sequential scanning.
        let use_parallel = self.try_start_parallel_scan(expr.as_ref());

        if !use_parallel {
            // Sequential path.
            self.parallel_scan = None;
            self.filter_progress = Some(FilterProgress {
                expr,
                cursor: 0,
                results: Vec::new(),
            });
        }
    }

    /// Attempt to start a parallel filter scan.
    ///
    /// Returns `true` if parallel scanning was started, `false` if the filter
    /// is ineligible or parallel scanning could not be initialised (caller
    /// should fall back to sequential).
    fn try_start_parallel_scan(&mut self, expr: Option<&FilterExpr>) -> bool {
        let expr = match expr {
            Some(e) => e,
            None => return false,
        };

        // Conditions required for parallel scanning:
        // 1. Filter is not packet-number-only (those don't need dissection at all).
        if expr.is_packet_number_only() {
            return false;
        }
        // 2. Filter expression is parallel-safe (no cross-packet state).
        if !expr.is_parallel_safe() {
            return false;
        }
        // 3. Static file mode only (live mode uses a growing file that workers
        //    cannot safely mmap independently).
        let capture_path = match &self.capture_path {
            Some(p) => p.clone(),
            None => return false,
        };
        if self.live_mode.is_some() {
            return false;
        }
        // 4. At least one packet to scan.
        if self.indices.is_empty() {
            return false;
        }

        // 5. Resolve thread count; fall back to sequential on error.
        let thread_count = match crate::parallel::resolve_thread_count(None) {
            Ok(n) => n,
            Err(_) => return false,
        };
        // With only one thread the overhead is not worth it.
        if thread_count <= 1 {
            return false;
        }

        // Build index snapshot as an Arc<[PacketIndex]>.
        let indices_arc: Arc<[super::state::PacketIndex]> = self.indices.as_slice().into();
        let filter_str = self.filter.buf.input.clone();
        let decode_as_args = self.decode_as_args.clone();

        match ParallelFilterScan::new(
            capture_path,
            decode_as_args,
            indices_arc,
            filter_str,
            thread_count,
        ) {
            Ok(scan) => {
                self.filter_progress = None;
                self.parallel_scan = Some(scan);
                true
            }
            Err(_) => false,
        }
    }

    /// Number of packets to scan per tick during filter progress.
    const FILTER_CHUNK_SIZE: usize = 10_000;

    /// Process one chunk of the in-progress filter scan.
    ///
    /// Handles both the sequential ([`FilterProgress`]) and parallel
    /// ([`ParallelFilterScan`]) paths.  Returns `true` while a scan is
    /// still running.
    pub fn filter_tick(&mut self) -> bool {
        // Check parallel path first.
        if self.parallel_scan.is_some() {
            return self.parallel_filter_tick();
        }
        self.sequential_filter_tick()
    }

    /// Drive one tick of the parallel filter scan.
    ///
    /// If every worker exited before the scan completed (e.g. the capture file
    /// could not be reopened), falls back to a sequential scan of the same
    /// filter so the scan always terminates.
    fn parallel_filter_tick(&mut self) -> bool {
        let scan = match &mut self.parallel_scan {
            Some(s) => s,
            None => return false,
        };

        match scan.drain() {
            ScanPoll::Complete(results) => {
                self.parallel_scan = None;
                self.finalize_filter(results);
                false
            }
            ScanPoll::Running => true,
            ScanPoll::Failed => {
                // The applied filter parsed successfully in apply_filter(), so
                // re-parsing cannot fail here; `Ok(None)` (empty input) cannot
                // occur either because the parallel path requires a non-empty
                // expression.
                let expr = FilterExpr::parse(&self.filter.applied).ok().flatten();
                self.parallel_scan = None;
                self.filter_progress = Some(FilterProgress {
                    expr,
                    cursor: 0,
                    results: Vec::new(),
                });
                true
            }
        }
    }

    /// Drive one chunk of the sequential filter scan.
    fn sequential_filter_tick(&mut self) -> bool {
        let total = self.indices.len();
        let progress = match &mut self.filter_progress {
            Some(p) => p,
            None => return false,
        };

        let end = (progress.cursor + Self::FILTER_CHUNK_SIZE).min(total);
        // Fast path: packet-number-only filters don't need dissection.
        let pn_only = progress
            .expr
            .as_ref()
            .is_some_and(|e| e.is_packet_number_only());

        let mut dissect_buf = DissectBuffer::new();
        for i in progress.cursor..end {
            let number = (i as u64) + 1; // 1-based packet number
            let matches = if let Some(expr) = &progress.expr {
                if pn_only {
                    let buf = dissect_buf.clear_into();
                    let empty_pkt = Packet::new(buf, &[]);
                    expr.matches_with_number(&empty_pkt, number)
                } else {
                    let index = &self.indices[i];
                    if let Some(data) = self.capture.packet_data(index) {
                        let buf = dissect_buf.clear_into();
                        if self
                            .registry
                            .dissect_with_link_type(data, index.link_type as u32, buf)
                            .is_ok()
                        {
                            let packet = Packet::new(buf, data);
                            expr.matches_with_number(&packet, number)
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
            } else {
                true
            };
            if matches {
                progress.results.push(i);
            }
        }
        progress.cursor = end;

        if progress.cursor >= total {
            // Scan complete — take results and finalize.
            let results = match std::mem::take(&mut self.filter_progress) {
                Some(fp) => fp.results,
                None => Vec::new(),
            };
            self.finalize_filter(results);
            return false;
        }
        true
    }

    /// Apply completed filter results and update the UI state.
    fn finalize_filter(&mut self, results: Vec<usize>) {
        self.filtered_indices = results;
        self.summary_cache.clear();
        self.packet_list.selected = 0;
        self.packet_list.scroll_offset = 0;
        self.load_selected();
        self.hex_dump.scroll_offset = 0;
    }

    /// Returns the current filter scan fraction (0.0–1.0), or `None` if idle.
    ///
    /// Used by the UI to display a progress indicator for both sequential and
    /// parallel scans.
    pub fn filter_fraction(&self) -> Option<f64> {
        if let Some(scan) = &self.parallel_scan {
            return Some(scan.fraction());
        }
        if let Some(progress) = &self.filter_progress {
            let total = self.indices.len();
            return Some(progress.fraction(total));
        }
        None
    }
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use std::io::Write;

    use packet_dissector::registry::DissectorRegistry;

    use super::super::app::App;
    use super::super::loader;
    use super::super::state::CaptureMap;
    use super::super::test_util::make_test_app;

    #[test]
    fn apply_filter_empty_shows_all() {
        let mut app = make_test_app(3);
        app.filter.buf.input.clear();
        app.filter.buf.cursor = 0;
        app.apply_filter();
        assert!(app.filter_progress.is_none());
        assert_eq!(app.filtered_indices.len(), app.indices.len());
        assert_eq!(app.displayed_count(), 3);
    }

    #[test]
    fn apply_filter_parse_error_sets_message() {
        let mut app = make_test_app(3);
        app.filter.buf.input = "udp.port ==".into();
        app.filter.buf.cursor = app.filter.buf.input.len();
        app.apply_filter();
        assert!(app.filter.error_message.is_some());
        assert!(app.filter_progress.is_none());
    }

    #[test]
    fn filter_tick_runs_to_completion() {
        let mut app = make_test_app(3);
        app.filter.buf.input = "udp".into();
        app.filter.buf.cursor = 3;
        app.apply_filter();
        // Either empty path or chunked path — drive until done.
        while app.filter_tick() {}
        assert!(app.filter_progress.is_none());
        // Fixture packets are all UDP.
        assert_eq!(app.displayed_count(), 3);
    }

    #[test]
    fn filter_tick_returns_false_when_idle() {
        let mut app = make_test_app(1);
        assert!(app.filter_progress.is_none());
        assert!(!app.filter_tick());
    }

    /// Drive a running filter scan (parallel or sequential) to completion.
    ///
    /// Uses a wall-clock deadline rather than a tick count: under heavy test
    /// parallelism, worker threads may not be scheduled for a while, so a
    /// fixed number of non-blocking ticks is racy.
    fn drive_filter_to_completion(app: &mut App) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if app.filter_progress.is_none() && app.parallel_scan.is_none() {
                break;
            }
            app.filter_tick();
            if app.parallel_scan.is_some() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "filter scan did not complete"
                );
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
    }

    /// Build an App backed by a real temp file path so `capture_path` is set.
    fn make_test_app_with_path(n: usize) -> (App, tempfile::NamedTempFile) {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let c = COUNTER.fetch_add(1, Ordering::Relaxed);

        let pcap = loader::tests::build_pcap_for_test(n);
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&pcap).unwrap();
        tmp.flush().unwrap();
        let _ = c;

        let file = std::fs::File::open(tmp.path()).unwrap();
        let capture = CaptureMap::new(&file).unwrap();
        let indices = loader::build_index(capture.as_bytes()).unwrap();

        let app = App::new(
            capture,
            indices,
            DissectorRegistry::default(),
            tmp.path(),
            vec![],
        );
        (app, tmp)
    }

    #[test]
    fn parallel_filter_completes_correctly() {
        // Build a larger pcap so there's enough work for parallel to engage
        // (assuming physical CPU count > 1 on CI; if only 1 CPU falls back to
        // sequential — that path is tested by filter_tick_runs_to_completion).
        let (mut app, _tmp) = make_test_app_with_path(100);

        app.filter.buf.input = "udp".into();
        app.filter.buf.cursor = 3;
        app.apply_filter();

        // Drive whichever path was chosen to completion.
        drive_filter_to_completion(&mut app);
        // All 100 test packets are UDP.
        assert_eq!(app.displayed_count(), 100);
    }

    #[test]
    fn parallel_scan_failure_falls_back_to_sequential() {
        // Force the parallel path to fail by pointing capture_path at a file
        // that workers cannot open.  filter_tick must fall back to the
        // sequential scan and still terminate with correct results
        // (regression test for an infinite filter_tick loop).
        let (mut app, _tmp) = make_test_app_with_path(50);
        app.capture_path = Some(std::path::PathBuf::from("/nonexistent/dsct_missing.pcap"));

        app.filter.buf.input = "udp".into();
        app.filter.buf.cursor = 3;
        app.apply_filter();

        drive_filter_to_completion(&mut app);
        // All 50 test packets are UDP; the in-memory mmap is still valid.
        assert_eq!(app.displayed_count(), 50);
    }

    #[test]
    fn unsafe_filter_uses_sequential_path() {
        let (mut app, _tmp) = make_test_app_with_path(5);

        app.filter.buf.input = "http".into();
        app.filter.buf.cursor = 4;
        app.apply_filter();

        // "http" is not parallel-safe; must use sequential path.
        assert!(
            app.parallel_scan.is_none(),
            "http filter must use sequential path"
        );
        assert!(
            app.filter_progress.is_some(),
            "http filter must set filter_progress"
        );
    }
}
