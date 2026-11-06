# dsct-gui

An experimental desktop GUI for dsct, built with [GPUI](https://github.com/zed-industries/zed)
through [GPUI Kit](https://github.com/longbridge/gpui-kit). It shows a capture
with the same engine as `dsct tui` (`dsct::session`): packets are indexed and
dissected in the background, so large files open at once.

- Packet table (virtual scrolling), filtered with dsct's filter syntax
- Protocol detail tree; selecting a field highlights its bytes in the hex dump
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

1. Open a capture: the packet count in the status bar grows while it is
   indexed, and the first packet is selected.
2. Type a filter such as `tcp` or `dns` and press Enter: the table and the
   `N / M packets` count update. An invalid filter shows the error in red in
   the status bar.
3. Select a packet, expand a layer with ▶, and click a field: its bytes are
   highlighted in the hex dump.
4. **Follow Stream** on a TCP/UDP packet shows the payload in the bottom
   panel (client in red, server in blue). **Stats** shows the stats of the
   displayed packets as JSON.

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
