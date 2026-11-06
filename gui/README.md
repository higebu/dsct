# dsct-gui

An experimental desktop GUI for dsct, built with [GPUI](https://github.com/zed-industries/zed)
through [GPUI Kit](https://github.com/longbridge/gpui-kit). It shows a capture
with the same engine as `dsct tui` (`dsct::session`): packets are indexed and
dissected in the background, so large files open at once.

- Packet table (virtual scrolling) with rows tinted by protocol, filtered
  with dsct's filter syntax
- Protocol detail tree and hex dump, linked both ways and operable from the
  keyboard
- Follow Stream (TCP/UDP/SCTP) and Stats for the displayed packets
- Open a file with **Open…** (⌘O), by dropping it on the window, or as an
  argument: `dsct-gui capture.pcap`

This directory is a Cargo workspace of its own, so GPUI's dependencies stay
out of dsct's `Cargo.lock`. It is not published to crates.io.

## Try it on macOS

### Download a build

Every pull request and push to `main` that touches the GUI or `src/` runs the
[GUI workflow](../.github/workflows/gui.yml). Open the run, download the
`dsct-macos-arm64` artifact (Apple Silicon), unzip it, and open `dsct.dmg`.

The app is ad-hoc signed, not notarized, so macOS blocks the first launch of
a downloaded copy. Copy `dsct.app` out of the disk image and either
right-click it and choose **Open**, or clear the quarantine flag:

```bash
xattr -dr com.apple.quarantine /Applications/dsct.app
```

### Build it yourself

Requirements: macOS 12 or later, the Xcode Command Line Tools
(`xcode-select --install`), and Rust stable.

```bash
gui/scripts/bundle-macos.sh
open gui/target/release/bundle/dsct.app
```

The script builds a release binary and writes `dsct.app` and `dsct.dmg` to
`gui/target/release/bundle/`. Pass `--target x86_64-apple-darwin` to build for
Intel Macs (after `rustup target add x86_64-apple-darwin`).

To run without bundling:

```bash
cd gui
cargo run --release -- path/to/capture.pcap
```

GPUI's Metal shaders are compiled when the app starts (the `runtime_shaders`
feature), so Xcode's Metal toolchain is not needed to build.

### What to check

1. Without a file, the window shows "Open a capture file" with an
   **Open…** button. Open a capture (or drop one on the window): the packet
   count in the status bar grows while it is indexed, and the first packet
   is selected.
2. Type a filter such as `tcp` or `dns`: "Enter to apply" appears until you
   press Enter, then the table and the `N / M packets` count update. An
   invalid filter outlines the input in red and shows the error under it.
3. Rows are tinted by protocol (TCP, UDP, DNS, HTTP, … each in its own
   color), and the selected row stands out in blue. **Time** (⌘T) switches
   between seconds since the first packet, since the previous packet, and
   the date and time.
4. Keyboard only: ↑/↓ in the table, then Tab to **Details** (blue outline):
   ↑/↓ move, → expands, ← collapses or goes to the parent, Enter toggles.
   Tab again to **Bytes**: ←/→ and ↑/↓ move a cursor, and the field under it
   is selected and revealed in the tree. ⌘1/⌘2/⌘3 jump to each pane.
5. Clicking a field highlights its bytes; clicking a byte selects its field.
6. **Follow Stream** and **Stats** open tabs in the bottom panel. Stream
   lines are marked → (client to server, red) and ← (server to client,
   blue); Stats shows the protocols and top talkers as tables. The copy
   button copies the tab as text (the stream with its markers, the stats as
   JSON); × or Esc closes the panel.
7. Once a capture is loaded and nothing runs, the app stays idle (no CPU
   use in Activity Monitor).

## Linux

The app also builds on Linux (X11/Wayland). Install GPUI's build
dependencies first:

```bash
sudo apt-get install libxkbcommon-dev libxkbcommon-x11-dev libwayland-dev libfreetype-dev libfontconfig-dev
cd gui
cargo run --release -- path/to/capture.pcap
```

## Development

```bash
cd gui
cargo fmt -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```
