//! Background stdin-to-tempfile copier for live capture mode.

use std::io::{Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Reads stdin in a background thread and writes to a temporary file.
///
/// The TUI polls [`bytes_written`](StdinCopier::bytes_written) to detect new
/// data and [`eof`](StdinCopier::eof) to detect end-of-stream.
pub struct StdinCopier {
    /// Total bytes written to the temp file so far.
    pub bytes_written: Arc<AtomicU64>,
    /// Set to `true` when stdin reaches EOF or an error occurs.
    pub eof: Arc<AtomicBool>,
    pub(crate) handle: Option<std::thread::JoinHandle<()>>,
}

impl StdinCopier {
    /// Spawn a background thread that copies `source` into `temp_file`.
    ///
    /// `source` is typically the original stdin pipe fd (saved before
    /// redirecting fd 0 to `/dev/tty`). The caller should pass a
    /// `try_clone()`d file handle for `temp_file` so that the TUI thread
    /// can independently mmap the same file.
    pub fn spawn(source: std::fs::File, temp_file: &std::fs::File) -> std::io::Result<Self> {
        let bytes_written = Arc::new(AtomicU64::new(0));
        let eof = Arc::new(AtomicBool::new(false));

        let bw = Arc::clone(&bytes_written);
        let done = Arc::clone(&eof);
        let mut file = temp_file.try_clone()?;

        let handle = std::thread::Builder::new()
            .name("stdin-copier".into())
            .spawn(move || {
                let mut reader = source;
                let mut buf = vec![0u8; 64 * 1024];
                let mut total: u64 = 0;

                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            if file.write_all(&buf[..n]).is_err() {
                                break;
                            }
                            // Flush so mmap sees the data.
                            let _ = file.flush();
                            total += n as u64;
                            bw.store(total, Ordering::Release);
                        }
                        Err(_) => break,
                    }
                }
                done.store(true, Ordering::Release);
            })?;

        Ok(Self {
            bytes_written,
            eof,
            handle: Some(handle),
        })
    }
}

impl Drop for StdinCopier {
    fn drop(&mut self) {
        // Detach the copier thread instead of joining it.  The thread is
        // likely blocked on `reader.read()` waiting for data from the
        // upstream pipe (e.g. tcpdump).  Joining would hang until that
        // process closes the pipe.  Detaching lets the process exit
        // immediately; the OS cleans up the thread.
        drop(self.handle.take());
    }
}
