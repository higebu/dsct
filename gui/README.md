# dsct-gui

An experimental desktop GUI for dsct, built with [GPUI](https://github.com/zed-industries/zed)
through [GPUI Kit](https://github.com/longbridge/gpui-kit). It shows a capture
with the same engine as `dsct tui` (`dsct::session`): packets are indexed and
dissected in the background, so large files open at once.

- A dark, editor-style window: title bar with a command palette (⌘K), a
  fields sidebar, and a status bar
- Fields sidebar with the top values of each field
- Chart of the displayed packets over time
- Packet table (virtual scrolling) with a colored mark per protocol,
  filtered with dsct's filter syntax
- Protocol detail tree and hex dump, linked both ways and operable from the
  keyboard
- Follow Stream (TCP/UDP/SCTP), and Stats for the displayed packets:
  requests and their results, and conversations
- Selecting a packet dims the packets outside its call, stream or host pair
- Problems: malformed packets, error responses and TCP retransmissions,
  marked in the packet list
- Mark packets (⌘M) and export the displayed or marked ones as pcapng
- Decode As: dissect a TCP or UDP port as another protocol, from a port in
  the detail tree or the filter bar
- Several captures in tabs: filter them all at once, show two side by side
  linked by time, or merge two into one by time
- Open files with **Open…** (⌘O), by dropping them on the window, or as
  arguments: `dsct-gui client.pcap server.pcap`

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
(`xcode-select --install`), and Rust 1.95 or later (`rustup update stable`).

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

1. Open a capture (**Open…**, or drop it on the window): packets, the
   fields sidebar and the chart fill in.
2. Filter from the filter bar, the command palette (⌘K), a value in the
   sidebar or detail tree, or a range of the chart.
3. Follow Stream (⇧⌘F) and Stats (⇧⌘S) open in the bottom dock.
4. Once nothing runs, the app stays idle (no CPU use).

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
