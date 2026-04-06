//! Terminal setup, event loop, and teardown.

use std::io;

use crossterm::event::{self, DisableMouseCapture, EnableMouseCapture, Event};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;

use crate::error::Result;

use super::app::App;
use super::ui;

/// Enter raw mode, switch to the alternate screen, and create a ratatui
/// [`Terminal`].
///
/// Call [`restore_terminal`] when you are done to undo the changes.
pub fn init_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let terminal = Terminal::new(backend)?;
    Ok(terminal)
}

/// Undo the changes made by [`init_terminal`]: leave the alternate screen,
/// disable mouse capture, show the cursor, and restore canonical mode.
pub fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableMouseCapture,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    Ok(())
}

/// Run the event loop on an already-initialised terminal.
///
/// The caller is responsible for calling [`init_terminal`] before and
/// [`restore_terminal`] after this function.
pub fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    mut app: App,
) -> Result<()> {
    event_loop(terminal, &mut app)
}

fn event_loop(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> Result<()> {
    use super::state::LiveMode;

    let mut last_render = std::time::Instant::now();

    loop {
        // Throttle rendering during indexing to ~60 fps so we spend more
        // time indexing and less time redrawing.
        let indexing_active = app.index_progress.is_some() || app.bg_indexer.is_some();
        let should_render =
            !indexing_active || last_render.elapsed() >= std::time::Duration::from_millis(16);
        if should_render {
            terminal.draw(|f| ui::render(f, app))?;
            last_render = std::time::Instant::now();
        }

        // Drive chunked file indexing (non-blocking — user can interact).
        let was_indexing = indexing_active;
        if was_indexing {
            app.index_tick();
        }

        let indexing_now = app.index_progress.is_some() || app.bg_indexer.is_some();

        // Indexing just finished — loop back to redraw immediately so the
        // user sees the final packet list instead of a stale "Indexing"
        // screen while we block on event::read().
        if was_indexing && !indexing_now {
            continue;
        }

        // If a filter scan is in progress, drive it in chunks.
        if app.filter_progress.is_some() {
            if event::poll(std::time::Duration::from_millis(0))?
                && let Event::Key(key) = event::read()?
                && key.code == crossterm::event::KeyCode::Esc
            {
                app.filter_progress = None;
                continue;
            }
            app.filter_tick();
            continue;
        }

        // If a stats collection is in progress, drive it in chunks.
        if app.stats_progress.is_some() {
            if event::poll(std::time::Duration::from_millis(0))?
                && let Event::Key(key) = event::read()?
                && key.code == crossterm::event::KeyCode::Esc
            {
                app.stats_progress = None;
                continue;
            }
            app.stats_tick();
            continue;
        }

        // If a stream build is in progress, drive it in chunks.
        if app.stream_build_progress.is_some() {
            if event::poll(std::time::Duration::from_millis(0))?
                && let Event::Key(key) = event::read()?
                && key.code == crossterm::event::KeyCode::Esc
            {
                app.stream_build_progress = None;
                continue;
            }
            app.stream_tick();
            continue;
        }

        // Live capture: drive tick and use poll-based event reading.
        if app.live_mode.is_some() {
            if matches!(app.live_mode, Some(LiveMode::Live)) {
                app.live_tick();
            } else if matches!(app.live_mode, Some(LiveMode::Paused)) {
                // Still check for EOF while paused.
                app.check_eof();
            }

            let timeout = match app.live_mode {
                Some(LiveMode::Live) => std::time::Duration::from_millis(200),
                Some(LiveMode::Paused) => std::time::Duration::from_millis(500),
                _ => std::time::Duration::from_secs(60),
            };

            if event::poll(timeout)? {
                match event::read()? {
                    Event::Key(key) => app.handle_key(key),
                    Event::Mouse(mouse) => app.handle_mouse(mouse),
                    Event::Resize(_, _) => app.on_resize(),
                    _ => {}
                }
            }
        } else if indexing_now {
            // File indexing in progress: use a short poll timeout so the OS
            // scheduler can run the background indexer thread efficiently.
            // 1 ms is imperceptible to the user but avoids a tight CPU spin.
            if event::poll(std::time::Duration::from_millis(1))? {
                match event::read()? {
                    Event::Key(key) => app.handle_key(key),
                    Event::Mouse(mouse) => app.handle_mouse(mouse),
                    Event::Resize(_, _) => app.on_resize(),
                    _ => {}
                }
            }
        } else {
            // Static file mode: blocking event read.
            match event::read()? {
                Event::Key(key) => app.handle_key(key),
                Event::Mouse(mouse) => app.handle_mouse(mouse),
                Event::Resize(_, _) => app.on_resize(),
                _ => {}
            }
        }

        if !app.running {
            break;
        }
    }
    super::state::save_history(&app.filter.history);
    Ok(())
}
