//! Chunked filter scanning over the capture.

use std::sync::Arc;

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::{DissectBuffer, Packet};

use super::filter_bitmap::FilterBitmap;
use super::parallel_scan::{ParallelFilterScan, ScanPoll};
use super::state::{CaptureMap, FilterProgress, InOrderScan, PacketIndex};
use super::{Session, Tick};
use crate::filter_expr::{FilterExpr, RecordInfo};

/// How a filter scan ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterOutcome {
    /// [`Session::filtered`] holds the result of the applied filter.
    Applied,
    /// The scan could not run: no filter is applied any more, every packet
    /// is displayed, and this explains why.
    Failed(String),
}

impl Session {
    /// Apply the filter expression `input`.
    ///
    /// Returns `Err` with a message when `input` does not parse; nothing
    /// changes then.  Otherwise `input` becomes [`applied_filter`](Self::applied_filter)
    /// and the result is `Ok(Some(_))` when the filter took effect at once,
    /// or `Ok(None)` when a scan started that [`filter_tick`](Self::filter_tick)
    /// drives to completion.
    ///
    /// Whenever the filter takes effect, the summary cache is cleared and
    /// row numbers refer to the new filtered list.
    pub fn apply_filter(&mut self, input: &str) -> Result<Option<FilterOutcome>, String> {
        let expr = FilterExpr::parse(input)?;

        self.applied_filter = input.to_string();

        if expr.is_none() {
            // Empty filter — show all packets immediately.
            self.finalize_filter(FilterBitmap::all_set(self.indices.len()));
            return Ok(Some(FilterOutcome::Applied));
        }

        // Decide whether to use parallel or sequential scanning.
        if self.try_start_parallel_scan(expr.as_ref()) {
            return Ok(None);
        }
        Ok(self.start_sequential_scan(expr, None))
    }

    /// Whether a filter scan (sequential or parallel) is running.
    pub fn filter_running(&self) -> bool {
        self.filter_progress.is_some() || self.parallel_scan.is_some()
    }

    /// Stop the running filter scan, keeping the previous filter result.
    pub fn cancel_filter(&mut self) {
        if let Some(scan) = &self.parallel_scan {
            scan.cancel();
        }
        self.parallel_scan = None;
        self.filter_progress = None;
    }

    /// Start (or continue, with `in_order`) a chunked sequential scan on a
    /// fresh registry.
    ///
    /// Returns `Some(Failed)` when the scan cannot start.
    fn start_sequential_scan(
        &mut self,
        expr: Option<FilterExpr>,
        in_order: Option<InOrderScan>,
    ) -> Option<FilterOutcome> {
        self.parallel_scan = None;
        let mut registry = DissectorRegistry::default();
        if let Err(e) = crate::decode_as::parse_and_apply(&mut registry, &self.decode_as_args) {
            // Validated at startup; report instead of scanning with a
            // differently configured registry, and leave no filter applied.
            self.filter_progress = None;
            self.applied_filter.clear();
            self.finalize_filter(FilterBitmap::all_set(self.indices.len()));
            return Some(FilterOutcome::Failed(format!("{e}")));
        }
        self.filter_progress = Some(FilterProgress {
            expr,
            cursor: 0,
            results: FilterBitmap::new(),
            registry,
            in_order,
        });
        None
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
        if expr.is_metadata_only() {
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
        let indices_arc: Arc<[PacketIndex]> = self.indices.as_slice().into();
        let filter_str = self.applied_filter.clone();
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
    /// ([`ParallelFilterScan`]) paths.
    pub fn filter_tick(&mut self) -> Tick<FilterOutcome> {
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
    fn parallel_filter_tick(&mut self) -> Tick<FilterOutcome> {
        let scan = match &mut self.parallel_scan {
            Some(s) => s,
            None => return Tick::Idle,
        };

        let restart = match scan.drain() {
            ScanPoll::Complete(results) => {
                self.parallel_scan = None;
                self.finalize_filter(results);
                return Tick::Done(FilterOutcome::Applied);
            }
            ScanPoll::Running => return Tick::Running,
            ScanPoll::InOrder { matches, in_order } => Some(InOrderScan {
                matches,
                in_order,
                done: 0,
                found: FilterBitmap::new(),
            }),
            ScanPoll::Failed => None,
        };
        // The applied filter parsed successfully in apply_filter(), so
        // re-parsing cannot fail here; `Ok(None)` (empty input) cannot occur
        // either because the parallel path requires a non-empty expression.
        let expr = FilterExpr::parse(&self.applied_filter).ok().flatten();
        match self.start_sequential_scan(expr, restart) {
            Some(failed) => Tick::Done(failed),
            None => Tick::Running,
        }
    }

    /// Drive one chunk of the sequential filter scan.
    fn sequential_filter_tick(&mut self) -> Tick<FilterOutcome> {
        let total = self.indices.len();
        let Some(progress) = &mut self.filter_progress else {
            return Tick::Idle;
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
            return Tick::Done(FilterOutcome::Applied);
        }
        Tick::Running
    }

    /// Replace the filter result; cached rows refer to the old list.
    fn finalize_filter(&mut self, results: FilterBitmap) {
        self.filtered = results;
        self.summary_cache.clear();
        // The displayed packets changed: look for the sequence among them.
        if let Some(key) = self.sequence().map(|s| s.key.clone()) {
            self.start_sequence(key);
        }
        if self.problems().is_some() {
            self.start_problems();
        }
    }

    /// Returns the current filter scan fraction (0.0–1.0), or `None` if idle.
    ///
    /// Used to display a progress indicator for both sequential and parallel
    /// scans.
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
    let index = &indices[i];
    let record = RecordInfo::new((i as u64) + 1, index.timestamp_secs, index.timestamp_usecs);
    // Fast path: packet-number and timestamp filters don't need dissection.
    if expr.is_metadata_only() {
        let buf = dissect_buf.clear_into();
        return expr.matches_record(&Packet::new(buf, &[]), record);
    }
    let Some(data) = capture.packet_data(index) else {
        return false;
    };
    let buf = dissect_buf.clear_into();
    if registry
        .dissect_with_link_type(data, index.link_type as u32, buf)
        .is_err()
    {
        return false;
    }
    expr.matches_record(&Packet::new(buf, data), record)
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::super::tests::test_session as session;
    use super::super::{Session, Tick};
    use super::FilterOutcome;

    /// Drive the filter scan started by `started` to its outcome.
    fn finish(session: &mut Session, started: Option<FilterOutcome>) -> FilterOutcome {
        if let Some(outcome) = started {
            return outcome;
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(session.filter_running());
            assert!(session.filter_fraction().is_some());
            match session.filter_tick() {
                Tick::Done(outcome) => return outcome,
                Tick::Running => {}
                Tick::Idle => panic!("scan stopped without an outcome"),
            }
            assert!(Instant::now() < deadline, "scan did not finish");
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    #[test]
    fn parse_error_changes_nothing() {
        let (mut session, _tmp) = session(3);
        assert!(session.apply_filter("udp.port ==").is_err());
        assert!(session.applied_filter.is_empty());
        assert!(!session.filter_running());
        assert_eq!(session.displayed_count(), 3);
    }

    #[test]
    fn empty_filter_applies_at_once() {
        let (mut session, _tmp) = session(3);
        assert_eq!(session.apply_filter(""), Ok(Some(FilterOutcome::Applied)));
        assert!(!session.filter_running());
        assert_eq!(session.filter_fraction(), None);
        assert_eq!(session.displayed_count(), 3);
    }

    #[test]
    fn scan_replaces_the_filtered_list() {
        let (mut session, _tmp) = session(4);
        session.get_or_dissect_summary(0);
        let started = session.apply_filter("tcp").unwrap();
        assert_eq!(finish(&mut session, started), FilterOutcome::Applied);
        assert_eq!(session.applied_filter, "tcp");
        assert_eq!(session.displayed_count(), 0);
        assert!(session.summary_cache.is_empty());
        assert!(!session.filter_running());
        assert_eq!(session.filter_tick(), Tick::Idle);
    }

    #[test]
    fn packet_number_filter_skips_dissection() {
        let (mut session, _tmp) = session(5);
        let started = session
            .apply_filter("packet_number BETWEEN 1 AND 2")
            .unwrap();
        assert_eq!(finish(&mut session, started), FilterOutcome::Applied);
        assert_eq!(session.filtered.iter().collect::<Vec<_>>(), [0, 1]);
    }

    /// When the scan cannot build its registry, no filter stays applied and
    /// every packet is displayed.
    #[test]
    fn scan_that_cannot_start_reports_failure() {
        let (mut session, _tmp) = session(3);
        session.decode_as_args = vec!["not-a-decode-as".to_string()];
        let started = session.apply_filter("udp").unwrap();
        let FilterOutcome::Failed(msg) = finish(&mut session, started) else {
            panic!("scan did not fail");
        };
        assert!(!msg.is_empty());
        assert!(session.applied_filter.is_empty());
        assert_eq!(session.displayed_count(), 3);
        assert!(!session.filter_running());
    }

    #[test]
    fn cancel_keeps_the_previous_result() {
        let (mut session, _tmp) = session(3);
        if session.apply_filter("tcp").unwrap().is_none() {
            assert!(session.filter_running());
            session.cancel_filter();
        }
        assert!(!session.filter_running());
        assert_eq!(session.filter_fraction(), None);
        assert_eq!(session.filter_tick(), Tick::Idle);
        assert_eq!(session.displayed_count(), 3);
    }
}
