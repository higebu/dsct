//! Filter application for the TUI: runs the scan in the [`Session`] and
//! resets the views when the filtered list changes.
//!
//! [`Session`]: crate::session::Session

use super::app::App;
use crate::session::{FilterOutcome, Tick};

impl App {
    pub(super) fn apply_filter(&mut self) {
        self.filter.error_message = None;
        match self.session.apply_filter(&self.filter.buf.input) {
            Err(msg) => self.filter.error_message = Some(msg),
            Ok(Some(outcome)) => self.finish_filter(outcome),
            Ok(None) => {}
        }
    }

    /// Process one chunk of the in-progress filter scan.
    ///
    /// Returns `true` while a scan is still running.
    pub fn filter_tick(&mut self) -> bool {
        match self.session.filter_tick() {
            Tick::Idle => false,
            Tick::Running => true,
            Tick::Done(outcome) => {
                self.finish_filter(outcome);
                false
            }
        }
    }

    /// Show the new filtered list from its first packet.
    fn finish_filter(&mut self, outcome: FilterOutcome) {
        self.packet_list.selected = 0;
        self.packet_list.scroll_offset = 0;
        self.load_selected();
        self.hex_dump.scroll_offset = 0;
        if let FilterOutcome::Failed(msg) = outcome {
            self.filter.error_message = Some(msg);
        }
    }
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use std::io::Write;

    use packet_dissector::registry::DissectorRegistry;

    use super::super::app::App;
    use super::super::test_util::make_test_app;
    use crate::session::loader;
    use crate::session::state::CaptureMap;

    #[test]
    fn apply_filter_empty_shows_all() {
        let mut app = make_test_app(3);
        app.filter.buf.input.clear();
        app.filter.buf.cursor = 0;
        app.apply_filter();
        assert!(app.session.filter_progress.is_none());
        assert_eq!(app.session.filtered.count_ones(), app.session.indices.len());
        assert_eq!(app.displayed_count(), 3);
    }

    #[test]
    fn apply_filter_parse_error_sets_message() {
        let mut app = make_test_app(3);
        app.filter.buf.input = "udp.port ==".into();
        app.filter.buf.cursor = app.filter.buf.input.len();
        app.apply_filter();
        assert!(app.filter.error_message.is_some());
        assert!(app.session.filter_progress.is_none());
    }

    #[test]
    fn filter_tick_runs_to_completion() {
        let mut app = make_test_app(3);
        app.filter.buf.input = "udp".into();
        app.filter.buf.cursor = 3;
        app.apply_filter();
        // Either empty path or chunked path — drive until done.
        while app.filter_tick() {}
        assert!(app.session.filter_progress.is_none());
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
        let collected: Vec<usize> = app.session.filtered.iter().collect();
        assert_eq!(collected, (0..10).collect::<Vec<_>>());
        // The bitmap universe must cover every scanned packet, not just matches.
        assert_eq!(app.session.filtered.universe(), 10);
        assert_eq!(app.session.filtered.rank(10), 10);
    }

    #[test]
    fn filter_tick_returns_false_when_idle() {
        let mut app = make_test_app(1);
        assert!(app.session.filter_progress.is_none());
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
            if app.session.filter_progress.is_none() && app.session.parallel_scan.is_none() {
                break;
            }
            app.filter_tick();
            if app.session.parallel_scan.is_some() {
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
        app.session.capture_path = Some(std::path::PathBuf::from("/nonexistent/dsct_missing.pcap"));

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
        let pcap = crate::session::parallel_scan::tests::build_mixed_pcap_for_test(udp, tcp);
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
                app.session.parallel_scan.is_some(),
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
            let parallel: Vec<usize> = app.session.filtered.iter().collect();
            assert_eq!(app.session.filtered.universe(), 50, "{filter}");

            // Reference: the sequential scan from the first packet.
            let (mut app, _tmp) = make_mixed_app_with_path(30, 20);
            app.filter.buf.input = filter.into();
            app.session.applied_filter = filter.into();
            app.session.filter_progress = Some(crate::session::state::FilterProgress {
                expr: crate::filter_expr::FilterExpr::parse(filter).unwrap(),
                cursor: 0,
                results: crate::session::filter_bitmap::FilterBitmap::new(),
                registry: DissectorRegistry::default(),
                in_order: None,
            });
            drive_filter_to_completion(&mut app);
            let sequential: Vec<usize> = app.session.filtered.iter().collect();
            assert_eq!(parallel, sequential, "{filter}");
            assert!(!sequential.is_empty(), "{filter}");
        }
    }
}
