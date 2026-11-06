//! Stats for the TUI: collects them in the [`Session`] and shows the
//! result in the stats overlay.
//!
//! [`Session`]: super::session::Session

use super::app::App;
use super::session::Tick;

impl App {
    /// Start collecting stats over the displayed packets.
    pub(super) fn start_stats(&mut self) {
        if let Err(msg) = self.session.start_stats() {
            self.detail_tree.yank_message = Some(msg);
        }
    }

    /// Process one chunk of the in-progress stats collection.
    ///
    /// Returns `true` while the collection is still running.
    pub fn stats_tick(&mut self) -> bool {
        match self.session.stats_tick() {
            Tick::Idle => false,
            Tick::Running => true,
            Tick::Done(output) => {
                self.stats_output = Some(output);
                false
            }
        }
    }
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use super::super::state::StatsProgress;
    use super::super::test_util::make_test_app;
    use crate::stats::{StatsCollector, StatsFlags};

    #[test]
    fn stats_tick_idle_returns_false() {
        let mut app = make_test_app(3);
        assert!(app.session.stats_progress.is_none());
        assert!(!app.stats_tick());
        assert!(app.stats_output.is_none());
    }

    #[test]
    fn stats_tick_runs_to_completion() {
        let mut app = make_test_app(5);
        app.session.stats_progress = Some(StatsProgress {
            cursor: 0,
            collector: StatsCollector::from_flags(&StatsFlags::all_protocols(true, true)),
            registry: packet_dissector::registry::DissectorRegistry::default(),
        });
        while app.stats_tick() {}
        let out = app.stats_output.as_ref().expect("stats_output set");
        assert_eq!(out.total_packets, 5);
    }
}
