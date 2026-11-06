//! Interactive TUI for exploring pcap/pcapng capture files.
//!
//! Uses memory-mapped I/O (memmap2) and lazy dissection for minimal memory use:
//! - Index scan reads only pcap record headers (~32 bytes per packet in memory).
//! - Packet list rows are dissected on demand for visible rows only, with an
//!   LRU cache for smooth scrolling.
//! - The selected packet is fully dissected to build the protocol detail tree.
//! - Hex dump reads directly from the mmap (zero-copy).
//! - Packets whose dissection depends on earlier packets (TCP streams,
//!   reassembly, ...) are shown from a background pass that dissects the
//!   capture in order (`ordered_pass`), so the display does not depend on
//!   the order packets are viewed in.

mod app;
mod clipboard;
mod color;
mod cursor;
mod event;
mod filter_apply;
mod keys;
mod state;
mod stats_collect;
mod stream;
#[cfg(all(test, feature = "tui"))]
mod test_util;
mod ui;
mod widgets;

use std::path::PathBuf;

use crate::error::{DsctError, Result};
use crate::session::live::StdinCopier;
use crate::session::ordered_pass::OrderedPass;
use crate::session::state::CaptureMap;
use crate::session::{Session, cache_dir, new_registry};

/// Entry point for `dsct tui <file>`.
pub fn run(file: PathBuf, decode_as_args: Vec<String>) -> Result<()> {
    // Start the TUI immediately with an empty index; packets will appear
    // incrementally as the background threads deliver results.
    let app = app::App::from_session(Session::open(&file, decode_as_args)?);

    let mut terminal = event::init_terminal()?;
    let result = event::run_event_loop(&mut terminal, app);
    let _ = event::restore_terminal(&mut terminal);
    result
}

/// Entry point for `dsct tui -` (live stdin capture).
pub fn run_live(decode_as_args: Vec<String>) -> Result<()> {
    let registry = new_registry(&decode_as_args)?;

    // Create a temp file that will be automatically deleted on drop.
    // Prefer $XDG_CACHE_HOME/dsct/ over the system temp directory.
    let temp_file = if let Some(dir) = cache_dir() {
        std::fs::create_dir_all(&dir)?;
        tempfile::NamedTempFile::new_in(dir)?
    } else {
        tempfile::NamedTempFile::new()?
    };
    let file = temp_file.as_file().try_clone()?;

    // Save the original stdin (pipe fd) without redirecting yet — the
    // upstream process (e.g. `sudo tcpdump`) may still need the terminal
    // for authentication prompts.
    let pipe_read = dup_stdin()?;

    // Spawn background thread to copy the pipe into the temp file.
    let copier = StdinCopier::spawn(pipe_read, &file)?;

    // Wait briefly for the first data to arrive before taking over the
    // terminal.  This allows upstream programs like `sudo` to complete
    // password prompts before we enter raw mode and the alternate screen.
    //
    // The timeout prevents an indefinite hang when the upstream program
    // buffers its output (e.g. tcpdump uses stdio full-buffering on pipes
    // and may not flush the pcap header until the buffer fills).  After
    // the timeout the TUI starts anyway; packets will appear once the
    // upstream flushes.
    eprint!("Waiting for capture data on stdin...");
    match wait_for_first_data(&copier) {
        WaitResult::Data => eprintln!(" ready."),
        WaitResult::Timeout => {
            eprintln!(" starting (data will appear when the upstream program flushes).");
        }
        WaitResult::Eof => {
            eprintln!();
            return Err(DsctError::msg(
                "stdin closed before any capture data was received",
            ));
        }
    }

    // Now redirect fd 0 to /dev/tty so crossterm can read keyboard events.
    redirect_stdin_to_tty()?;

    // Enter the alternate screen immediately so that any stderr output from
    // upstream processes (e.g. tcpdump's "listening on eth0…" message) is
    // hidden before we spend time setting up the capture state.
    let mut terminal = event::init_terminal()?;

    let result = (|| {
        let ordered = OrderedPass::spawn(
            CaptureMap::new_live(file.try_clone()?)?,
            new_registry(&decode_as_args)?,
            cache_dir().as_deref(),
        )?;
        // Create a live-mode mmap (initially empty or near-empty).
        let capture = CaptureMap::new_live(file)?;
        let indices = Vec::new();

        let mut app = app::App::new_live(capture, indices, registry, copier, decode_as_args);
        app.session.ordered = Some(ordered);
        event::run_event_loop(&mut terminal, app)
    })();

    let _ = event::restore_terminal(&mut terminal);
    // temp_file is dropped here, auto-deleting the temp file.
    drop(temp_file);
    result
}

/// Outcome of [`wait_for_first_data`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaitResult {
    /// At least one byte of capture data has arrived.
    Data,
    /// Timed out before any data arrived.
    Timeout,
    /// The pipe was closed (EOF) without any data.
    Eof,
}

/// Maximum time to wait for the first byte of capture data.
///
/// 5 seconds is long enough for a typical `sudo` password prompt to complete,
/// yet short enough that the user is not left staring at a blank terminal when
/// the upstream program (e.g. `tcpdump`) buffers its output.
const FIRST_DATA_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Wait until the copier has received data, the pipe closes, or a timeout
/// expires — whichever comes first.
fn wait_for_first_data(copier: &StdinCopier) -> WaitResult {
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    let deadline = Instant::now() + FIRST_DATA_TIMEOUT;
    loop {
        if copier.bytes_written.load(Ordering::Acquire) > 0 {
            return WaitResult::Data;
        }
        if copier.eof.load(Ordering::Acquire) {
            return WaitResult::Eof;
        }
        if Instant::now() >= deadline {
            return WaitResult::Timeout;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// Duplicate the original stdin fd so we can read from the pipe later.
///
/// This does NOT redirect fd 0 — the terminal stays available for upstream
/// processes (e.g. `sudo` password prompts).
#[cfg(unix)]
fn dup_stdin() -> Result<std::fs::File> {
    let pipe_fd = rustix::io::dup(rustix::stdio::stdin())?;
    Ok(std::fs::File::from(pipe_fd))
}

#[cfg(not(unix))]
fn dup_stdin() -> Result<std::fs::File> {
    Err(DsctError::msg(
        "reading from stdin pipe is not supported on this platform",
    ))
}

/// Replace fd 0 with `/dev/tty` so crossterm can enable raw mode and read
/// keyboard events from the real terminal.
#[cfg(unix)]
fn redirect_stdin_to_tty() -> Result<()> {
    let tty = std::fs::File::open("/dev/tty")?;
    rustix::stdio::dup2_stdin(&tty)?;
    Ok(())
}

#[cfg(not(unix))]
fn redirect_stdin_to_tty() -> Result<()> {
    Err(DsctError::msg(
        "reading from stdin pipe is not supported on this platform",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    /// Helper to create a StdinCopier with controllable atomics (no real thread).
    fn fake_copier(bytes: u64, eof: bool) -> StdinCopier {
        let bw = Arc::new(AtomicU64::new(bytes));
        let done = Arc::new(AtomicBool::new(eof));
        StdinCopier {
            bytes_written: bw,
            eof: done,
            handle: None,
        }
    }

    #[test]
    fn wait_returns_data_when_bytes_present() {
        let copier = fake_copier(100, false);
        assert_eq!(wait_for_first_data(&copier), WaitResult::Data);
    }

    #[test]
    fn wait_returns_eof_without_data() {
        let copier = fake_copier(0, true);
        assert_eq!(wait_for_first_data(&copier), WaitResult::Eof);
    }

    #[test]
    fn wait_unblocks_when_data_arrives() {
        let copier = fake_copier(0, false);
        let bw = Arc::clone(&copier.bytes_written);

        let handle = std::thread::spawn(move || wait_for_first_data(&copier));

        // Simulate data arriving after a short delay.
        std::thread::sleep(std::time::Duration::from_millis(100));
        bw.store(24, Ordering::Release);

        assert_eq!(handle.join().unwrap(), WaitResult::Data);
    }

    #[test]
    fn wait_returns_timeout_when_no_data() {
        // Override the constant by testing the function directly — it uses
        // FIRST_DATA_TIMEOUT (5 s) which is too long for a unit test, so we
        // verify the *logic* by checking that it eventually returns Timeout
        // when neither data nor EOF arrives.  To keep the test fast we spawn
        // a thread and join with a generous wall-clock limit.
        let copier = fake_copier(0, false);
        let handle = std::thread::spawn(move || {
            let start = std::time::Instant::now();
            let result = wait_for_first_data(&copier);
            (result, start.elapsed())
        });

        let (result, elapsed) = handle.join().unwrap();
        assert_eq!(result, WaitResult::Timeout);
        // Should have waited roughly FIRST_DATA_TIMEOUT (5 s), not forever.
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "waited too long: {elapsed:?}"
        );
    }
}
