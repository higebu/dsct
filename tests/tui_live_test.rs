//! Integration tests for `dsct tui -` (live stdin capture).
//!
//! Each test launches the dsct binary inside a pseudo-terminal (pty) with
//! a pipe connected to stdin, simulating `some_cmd | dsct tui -`.
//!
//! These tests are Unix-only and require the `tui` feature.

#![cfg(all(unix, feature = "tui"))]

use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::poll::{PollFd, PollFlags, PollTimeout};
use nix::pty::openpty;

/// ANSI escape sequence for entering the alternate screen buffer.
const ALT_SCREEN: &[u8] = b"\x1b[?1049h";

/// Build a minimal valid pcap (global header + `n` Ethernet/IPv4/TCP packets).
fn build_pcap(n: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    // pcap global header (24 bytes)
    buf.extend_from_slice(&0xA1B2_C3D4_u32.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&65535u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET

    #[rustfmt::skip]
    let eth_ip_tcp: &[u8] = &[
        // Ethernet (14 bytes)
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x08, 0x00,
        // IPv4 (20 bytes)
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x01, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0x0A, 0x00, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x02,
        // TCP (20 bytes)
        0x00, 0x50, 0x04, 0xD2,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0xFF, 0xFF,
        0x00, 0x00, 0x00, 0x00,
    ];

    for _ in 0..n {
        let len = eth_ip_tcp.len() as u32;
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(eth_ip_tcp);
    }
    buf
}

/// Read available data from `fd` using `poll()`.
///
/// Returns when no data arrives for `timeout` or `max_time` elapses.
fn read_available(fd: &OwnedFd, timeout: Duration, max_time: Duration) -> Vec<u8> {
    let mut buf = Vec::new();
    let deadline = Instant::now() + max_time;
    let mut tmp = [0u8; 8192];

    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let poll_ms = timeout.min(remaining).as_millis().min(i32::MAX as u128) as i32;
        if poll_ms == 0 {
            break;
        }
        let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
        let poll_timeout = if poll_ms > u16::MAX as i32 {
            PollTimeout::MAX
        } else {
            PollTimeout::from(poll_ms as u16)
        };
        match nix::poll::poll(&mut fds, poll_timeout) {
            Ok(0) => break,
            Ok(_) => match nix::unistd::read(fd, &mut tmp) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            },
            Err(_) => break,
        }
    }
    buf
}

/// Keep reading from `fd` until `needle` appears or `max_time` elapses.
///
/// Unlike [`read_available`], this does NOT stop on a single poll timeout —
/// it keeps polling (draining output) until the pattern is found or the
/// absolute deadline is exceeded.
fn read_until(fd: &OwnedFd, needle: &[u8], max_time: Duration) -> Vec<u8> {
    let mut buf = Vec::new();
    let deadline = Instant::now() + max_time;
    let mut tmp = [0u8; 8192];

    while Instant::now() < deadline {
        if contains(&buf, needle) {
            let drain = read_available(fd, Duration::from_millis(200), Duration::from_millis(500));
            buf.extend_from_slice(&drain);
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let poll_ms = remaining.as_millis().min(500).min(i32::MAX as u128) as i32;
        if poll_ms == 0 {
            break;
        }
        let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
        let poll_timeout = if poll_ms > u16::MAX as i32 {
            PollTimeout::MAX
        } else {
            PollTimeout::from(poll_ms as u16)
        };
        match nix::poll::poll(&mut fds, poll_timeout) {
            Ok(0) => continue,
            Ok(_) => match nix::unistd::read(fd, &mut tmp) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(_) => break,
            },
            Err(_) => break,
        }
    }
    buf
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// RAII guard that spawns dsct in a pty and cleans up on drop.
struct DsctChild {
    child: std::process::Child,
    master: OwnedFd,
}

impl DsctChild {
    /// Spawn `dsct tui -` with `pipe_r` as stdin, pty as stdout/stderr.
    fn spawn(pipe_r: OwnedFd) -> Self {
        let pty = openpty(None, None).expect("openpty failed");

        // Set terminal window size.
        let ws = nix::libc::winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: TIOCSWINSZ with a valid winsize struct is a well-defined ioctl.
        unsafe {
            nix::libc::ioctl(pty.master.as_raw_fd(), nix::libc::TIOCSWINSZ, &ws);
        }

        let master_raw = pty.master.as_raw_fd();
        let dsct_bin = assert_cmd::cargo::cargo_bin("dsct");

        let mut cmd = Command::new(&dsct_bin);
        cmd.args(["tui", "-"]);
        cmd.stdin(pipe_r);
        // Both stdout and stderr go to the pty slave.
        let slave_dup = nix::unistd::dup(&pty.slave).expect("dup failed");
        cmd.stdout(pty.slave);
        cmd.stderr(slave_dup);

        // SAFETY: Standard POSIX pty session setup between fork and exec.
        // All operations (close, setsid, ioctl TIOCSCTTY) are well-defined
        // and async-signal-safe.
        unsafe {
            cmd.pre_exec(move || {
                // Close master pty in child — only the parent reads from it.
                nix::libc::close(master_raw);
                nix::unistd::setsid().map_err(std::io::Error::from)?;
                // Set the pty slave (fd 1) as the controlling terminal.
                if nix::libc::ioctl(1, nix::libc::TIOCSCTTY as nix::libc::c_ulong, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = cmd.spawn().expect("failed to spawn dsct");
        DsctChild {
            child,
            master: pty.master,
        }
    }

    fn read(&self, timeout: Duration, max_time: Duration) -> Vec<u8> {
        read_available(&self.master, timeout, max_time)
    }

    fn wait_for(&self, needle: &[u8], max_time: Duration) -> Vec<u8> {
        read_until(&self.master, needle, max_time)
    }

    fn send_key(&self, key: &[u8]) {
        let _ = nix::unistd::write(&self.master, key);
    }
}

impl Drop for DsctChild {
    fn drop(&mut self) {
        // Drain the pty master to unblock dsct if it's stuck writing to the
        // full pty output buffer (macOS pty buffer is ~4KB).
        let _ = read_available(
            &self.master,
            Duration::from_millis(50),
            Duration::from_millis(200),
        );
        // Send 'q' to exit dsct TUI gracefully.
        self.send_key(b"q");
        // Drain output again — dsct may write exit sequences.
        let _ = read_available(
            &self.master,
            Duration::from_millis(100),
            Duration::from_millis(500),
        );
        if let Ok(Some(_)) = self.child.try_wait() {
            return;
        }
        // Force kill if still alive.
        let _ = self.child.kill();
        // Drain once more — the killed process may flush output.
        let _ = read_available(
            &self.master,
            Duration::from_millis(100),
            Duration::from_millis(300),
        );
        for _ in 0..10 {
            std::thread::sleep(Duration::from_millis(50));
            if let Ok(Some(_)) = self.child.try_wait() {
                return;
            }
        }
    }
}

/// TUI starts promptly when pcap data is available immediately.
#[test]
fn tui_live_immediate_data() {
    let (pipe_r, pipe_w) = nix::unistd::pipe().expect("pipe failed");
    let child = DsctChild::spawn(pipe_r);

    // Write data immediately.
    nix::unistd::write(&pipe_w, &build_pcap(3)).expect("write failed");
    drop(pipe_w);

    // Wait for the alternate screen — keep reading so the pty buffer
    // stays drained.  On macOS the pty output buffer is small (~4 KB);
    // if the parent doesn't read, dsct blocks on terminal.draw().
    let output = child.wait_for(ALT_SCREEN, Duration::from_secs(10));

    assert!(
        contains(&output, ALT_SCREEN),
        "TUI should enter alternate screen when data is immediate"
    );
    assert!(
        output.len() > 100,
        "TUI should produce substantial output (got {} bytes)",
        output.len()
    );
}

/// TUI starts after timeout even when data is delayed (tcpdump buffering).
#[test]
fn tui_live_delayed_data() {
    let (pipe_r, pipe_w) = nix::unistd::pipe().expect("pipe failed");
    let child = DsctChild::spawn(pipe_r);

    // Do NOT write data yet — simulate tcpdump buffering.
    // Wait for the "Waiting" message (appears immediately).
    let early = child.wait_for(b"Waiting", Duration::from_secs(5));
    assert!(
        contains(&early, b"Waiting"),
        "Should show 'Waiting' message before data arrives"
    );
    assert!(
        !contains(&early, ALT_SCREEN),
        "Should NOT enter TUI before timeout"
    );

    // Wait for the 5-second timeout to expire and the TUI to start.
    // Keep draining so the pty buffer doesn't fill up.
    let after_timeout = child.wait_for(ALT_SCREEN, Duration::from_secs(10));
    assert!(
        contains(&after_timeout, ALT_SCREEN),
        "TUI should start after timeout even without data"
    );

    // Now send data — it should be ingested.
    nix::unistd::write(&pipe_w, &build_pcap(3)).expect("write failed");
    drop(pipe_w);

    let final_output = child.read(Duration::from_millis(500), Duration::from_secs(3));

    let total_len = after_timeout.len() + final_output.len();
    assert!(
        total_len > 100,
        "TUI should produce output after timeout + data (got {} bytes)",
        total_len
    );
}

/// dsct exits with error when pipe closes without any data.
#[test]
fn tui_live_eof_before_data() {
    let (pipe_r, pipe_w) = nix::unistd::pipe().expect("pipe failed");
    // Close write end immediately — EOF.
    drop(pipe_w);

    let mut child = DsctChild::spawn(pipe_r);

    // Read immediately — on macOS the pty master loses buffered data once
    // all slave fds close (i.e. when the child exits), so we must be
    // polling before that happens.
    let output = child.wait_for(b"stdin closed", Duration::from_secs(5));

    assert!(
        !contains(&output, ALT_SCREEN),
        "TUI should NOT start on immediate EOF"
    );
    assert!(
        contains(&output, b"stdin closed"),
        "Should report that stdin closed before data. Got {} bytes: {:?}",
        output.len(),
        String::from_utf8_lossy(&output)
    );

    // Allow the child a moment to finish exiting.
    std::thread::sleep(Duration::from_millis(500));

    // Process should have exited.
    let status = child.child.try_wait().expect("try_wait failed");
    assert!(status.is_some(), "Process should have exited");
}
