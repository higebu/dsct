//! Filter application and chunked filter scanning.

use std::sync::Arc;

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::{DissectBuffer, Packet};

use super::app::App;
use super::filter_bitmap::FilterBitmap;
use super::parallel_scan::{ParallelFilterScan, ScanPoll};
use super::state::{CaptureMap, FilterProgress, InOrderScan, PacketIndex};
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
            // Empty filter — show all packets immediately.
            self.filtered = FilterBitmap::all_set(self.indices.len());
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
            self.start_sequential_scan(expr, None);
        }
    }

    /// Start (or continue, with `in_order`) a chunked sequential scan on a
    /// fresh registry.
    fn start_sequential_scan(&mut self, expr: Option<FilterExpr>, in_order: Option<InOrderScan>) {
        self.parallel_scan = None;
        let mut registry = DissectorRegistry::default();
        if let Err(e) = crate::decode_as::parse_and_apply(&mut registry, &self.decode_as_args) {
            // Validated at startup; report instead of scanning with a
            // differently configured registry, and leave no filter applied.
            self.filter_progress = None;
            self.filter.applied.clear();
            self.finalize_filter(FilterBitmap::all_set(self.indices.len()));
            self.filter.error_message = Some(format!("{e}"));
            return;
        }
        self.filter_progress = Some(FilterProgress {
            expr,
            cursor: 0,
            results: FilterBitmap::new(),
            registry,
            in_order,
        });
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
        // 2. Static file mode only (live mode uses a growing file that workers
        //    cannot safely mmap independently).
        let capture_path = match &self.capture_path {
            Some(p) => p.clone(),
            None => return false,
        };
        if self.live_mode.is_some() {
            return false;
        }
        // 3. At least one packet to scan.
        if self.indices.is_empty() {
            return false;
        }

        // 4. Resolve thread count; fall back to sequential on error.
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
    /// When packets used cross-packet state, continues by dissecting those
    /// packets in order, keeping the parallel results of the others.  If
    /// every worker exited before the scan completed (e.g. the capture file
    /// could not be reopened), falls back to a sequential scan of the same
    /// filter from the start so the scan always terminates.
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
            ScanPoll::InOrder { matches, in_order } => {
                // The applied filter parsed successfully in apply_filter(), so
                // re-parsing cannot fail here; `Ok(None)` (empty input) cannot
                // occur either because the parallel path requires a non-empty
                // expression.
                let expr = FilterExpr::parse(&self.filter.applied).ok().flatten();
                let in_order = InOrderScan {
                    matches,
                    in_order,
                    done: 0,
                    found: FilterBitmap::new(),
                };
                self.start_sequential_scan(expr, Some(in_order));
                true
            }
            ScanPoll::Failed => {
                let expr = FilterExpr::parse(&self.filter.applied).ok().flatten();
                self.start_sequential_scan(expr, None);
                true
            }
        }
    }

    /// Drive one chunk of the sequential filter scan.
    fn sequential_filter_tick(&mut self) -> bool {
        let total = self.indices.len();
        let Some(progress) = &mut self.filter_progress else {
            return false;
        };
        let FilterProgress {
            expr,
            cursor,
            results,
            registry,
            in_order,
        } = progress;
        let mut dissect_buf = DissectBuffer::new();

        if let Some(scan) = in_order {
            // Only the listed packets need dissecting, in capture order.
            let InOrderScan {
                matches,
                in_order: listed,
                done,
                found,
            } = scan;
            for i in listed.iter_from(*done).take(Self::FILTER_CHUNK_SIZE) {
                if packet_matches(
                    expr.as_ref(),
                    registry,
                    &self.capture,
                    &self.indices,
                    i,
                    &mut dissect_buf,
                ) {
                    found.push(i);
                }
                *done += 1;
            }
            if *done >= listed.count_ones() {
                *results = FilterBitmap::from_sorted_indices(
                    total,
                    merge_sorted(matches.iter(), found.iter()),
                );
                *cursor = total;
            }
        } else {
            let end = (*cursor + Self::FILTER_CHUNK_SIZE).min(total);
            for i in *cursor..end {
                if packet_matches(
                    expr.as_ref(),
                    registry,
                    &self.capture,
                    &self.indices,
                    i,
                    &mut dissect_buf,
                ) {
                    results.push(i);
                }
            }
            *cursor = end;
        }

        if *cursor >= total {
            // Scan complete — take results and finalize.
            let mut results = match std::mem::take(&mut self.filter_progress) {
                Some(fp) => fp.results,
                None => FilterBitmap::new(),
            };
            // Cover every scanned packet, including trailing non-matches, so
            // rank/select stay consistent over the full universe.
            results.extend_universe(total);
            self.finalize_filter(results);
            return false;
        }
        true
    }

    /// Apply completed filter results and update the UI state.
    fn finalize_filter(&mut self, results: FilterBitmap) {
        self.filtered = results;
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

/// Merge two increasing, disjoint index sequences into one.
fn merge_sorted(
    a: impl Iterator<Item = usize>,
    b: impl Iterator<Item = usize>,
) -> impl Iterator<Item = usize> {
    let mut a = a.peekable();
    let mut b = b.peekable();
    std::iter::from_fn(move || match (a.peek(), b.peek()) {
        (Some(&x), Some(&y)) if x < y => a.next(),
        (Some(_), Some(_)) | (None, Some(_)) => b.next(),
        (Some(_), None) => a.next(),
        (None, None) => None,
    })
}

/// Whether packet `i` matches `expr` (`None` matches everything), dissecting
/// it with `registry` unless the filter only looks at packet numbers.
fn packet_matches(
    expr: Option<&FilterExpr>,
    registry: &DissectorRegistry,
    capture: &CaptureMap,
    indices: &[PacketIndex],
    i: usize,
    dissect_buf: &mut DissectBuffer<'static>,
) -> bool {
    let Some(expr) = expr else {
        return true;
    };
    let number = (i as u64) + 1; // 1-based packet number
    // Fast path: packet-number-only filters don't need dissection.
    if expr.is_packet_number_only() {
        let buf = dissect_buf.clear_into();
        return expr.matches_with_number(&Packet::new(buf, &[]), number);
    }
    let Some(data) = capture.packet_data(&indices[i]) else {
        return false;
    };
    let buf = dissect_buf.clear_into();
    if registry
        .dissect_with_link_type(data, indices[i].link_type as u32, buf)
        .is_err()
    {
        return false;
    }
    expr.matches_with_number(&Packet::new(buf, data), number)
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
        assert_eq!(app.filtered.count_ones(), app.indices.len());
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
    fn sequential_scan_bitmap_matches_expected_indices() {
        // make_test_app's capture_path ("test.pcap") cannot be reopened by
        // workers, so the scan finalizes via the sequential fallback.
        let mut app = make_test_app(10);
        app.filter.buf.input = "udp".into();
        app.filter.buf.cursor = 3;
        app.apply_filter();
        drive_filter_to_completion(&mut app);

        // All 10 fixture packets are UDP → every bit set.
        let collected: Vec<usize> = app.filtered.iter().collect();
        assert_eq!(collected, (0..10).collect::<Vec<_>>());
        // The bitmap universe must cover every scanned packet, not just matches.
        assert_eq!(app.filtered.universe(), 10);
        assert_eq!(app.filtered.rank(10), 10);
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

    /// Build an App over `udp` UDP packets followed by `tcp` TCP packets,
    /// backed by a real temp file so the parallel scan can run.
    fn make_mixed_app_with_path(udp: usize, tcp: usize) -> (App, tempfile::NamedTempFile) {
        let pcap = super::super::parallel_scan::tests::build_mixed_pcap_for_test(udp, tcp);
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&pcap).unwrap();
        tmp.flush().unwrap();
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
    fn upper_layer_filter_starts_parallel_scan() {
        // No protocol list gates the parallel scan any more; cross-packet
        // state is detected per packet while scanning.
        let (mut app, _tmp) = make_test_app_with_path(5);
        app.filter.buf.input = "http".into();
        app.filter.buf.cursor = 4;
        app.apply_filter();
        if crate::parallel::resolve_thread_count(None).is_ok_and(|n| n > 1) {
            assert!(
                app.parallel_scan.is_some(),
                "http filter must scan in parallel"
            );
        }
        drive_filter_to_completion(&mut app);
        assert_eq!(app.displayed_count(), 0);
    }

    #[test]
    fn stateful_packets_dissected_in_order_give_same_result() {
        for filter in ["tcp", "udp", "tcp.stream_id = 0"] {
            let (mut app, _tmp) = make_mixed_app_with_path(30, 20);
            app.filter.buf.input = filter.into();
            app.filter.buf.cursor = filter.len();
            app.apply_filter();
            drive_filter_to_completion(&mut app);
            let parallel: Vec<usize> = app.filtered.iter().collect();
            assert_eq!(app.filtered.universe(), 50, "{filter}");

            // Reference: the sequential scan from the first packet.
            let (mut app, _tmp) = make_mixed_app_with_path(30, 20);
            app.filter.buf.input = filter.into();
            app.filter.applied = filter.into();
            app.filter_progress = Some(super::super::state::FilterProgress {
                expr: crate::filter_expr::FilterExpr::parse(filter).unwrap(),
                cursor: 0,
                results: super::super::filter_bitmap::FilterBitmap::new(),
                registry: DissectorRegistry::default(),
                in_order: None,
            });
            drive_filter_to_completion(&mut app);
            let sequential: Vec<usize> = app.filtered.iter().collect();
            assert_eq!(parallel, sequential, "{filter}");
            assert!(!sequential.is_empty(), "{filter}");
        }
    }
}
