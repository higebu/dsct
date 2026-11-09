//! Follow Stream for the TUI: starts the collection in the [`Session`]
//! and shows the result in the Follow Stream overlay.
//!
//! [`Session`]: crate::session::Session

use super::app::App;
use super::state::StreamViewState;
use crate::session::Tick;

impl App {
    /// Start building a follow-stream view for the selected packet.
    pub(super) fn start_follow_stream(&mut self) {
        if let Err(msg) = self.session.start_follow_stream() {
            self.detail_tree.yank_message = Some(msg);
        }
    }

    /// Process one chunk of the in-progress stream build.
    /// Returns `true` while the scan is still running.
    pub fn stream_tick(&mut self) -> bool {
        match self.session.stream_tick() {
            Tick::Idle => false,
            Tick::Running => true,
            Tick::Done(stream) => {
                self.stream_view = Some(StreamViewState {
                    lines: stream.lines(),
                    scroll_offset: 0,
                    title: stream.title,
                });
                false
            }
        }
    }
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use super::super::test_util::make_test_app;

    #[test]
    fn start_follow_stream_noop_without_selection() {
        let mut app = make_test_app(0);
        assert!(app.session.selected.is_none());
        app.start_follow_stream();
        assert!(app.session.stream_build_progress.is_none());
    }

    #[test]
    fn follow_stream_udp_produces_state() {
        let mut app = make_test_app(3);
        app.start_follow_stream();
        assert!(app.session.stream_build_progress.is_some());
        while app.stream_tick() {}
        let sv = app.stream_view.as_ref().expect("stream_view set");
        assert!(
            sv.title.contains("UDP Stream"),
            "unexpected title: {}",
            sv.title
        );
    }
}
