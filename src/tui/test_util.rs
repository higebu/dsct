//! Shared test helpers for TUI unit tests.
//!
//! This module is compiled only during tests with the `tui` feature enabled.
//! It provides a small fixture builder (`make_test_app`) that wraps an
//! in-memory pcap built by [`crate::tui::loader::tests::build_pcap_for_test`],
//! plus a ratatui `TestBackend` helper for substring assertions on rendered
//! widget output.

#![cfg(all(test, feature = "tui"))]

use std::sync::atomic::{AtomicU32, Ordering};

use packet_dissector::registry::DissectorRegistry;
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::TestBackend;

use super::app::App;
use super::loader;
use super::state::CaptureMap;

/// Build a test [`App`] backed by an in-memory pcap with `n` UDP packets.
///
/// The pcap is written to a uniquely-named temp file, mmapped, indexed, and
/// then the temp file is immediately unlinked.  The mmap keeps the data alive
/// for the lifetime of the returned [`App`].
pub(super) fn make_test_app(n: usize) -> App {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed);

    let pcap = loader::tests::build_pcap_for_test(n);
    let path =
        std::env::temp_dir().join(format!("dsct_tui_testutil_{n}_{}_{c}", std::process::id()));
    std::fs::write(&path, &pcap).unwrap();

    let file = std::fs::File::open(&path).unwrap();
    let capture = CaptureMap::new(&file).unwrap();
    let indices = loader::build_index(capture.as_bytes()).unwrap();

    let app = App::new(
        capture,
        indices,
        DissectorRegistry::default(),
        std::path::Path::new("test.pcap"),
        vec![],
    );
    let _ = std::fs::remove_file(&path);
    app
}

/// Render `draw` into a fresh [`TestBackend`] of the given dimensions and
/// return the cell grid joined as newline-separated strings for substring
/// assertions.
pub(super) fn render_to_string(width: u16, height: u16, draw: impl FnOnce(&mut Frame)) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal.draw(draw).unwrap();
    let buf = terminal.backend().buffer().clone();
    (0..buf.area.height)
        .map(|y| {
            (0..buf.area.width)
                .map(|x| buf.cell((x, y)).unwrap().symbol().to_string())
                .collect::<String>()
        })
        .collect::<Vec<_>>()
        .join("\n")
}
