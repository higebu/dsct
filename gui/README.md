# dsct-gui

An experimental desktop GUI for dsct, built with [GPUI](https://github.com/zed-industries/zed)
through [GPUI Kit](https://github.com/longbridge/gpui-kit). It shows a capture
with the same engine as `dsct tui` (`dsct::session`): packets are indexed and
dissected in the background, so large files open at once.

- A dark, editor-style window: title bar with a command palette (⌘K), a
  fields sidebar, and a status bar
- A fields sidebar: the values each field takes in the displayed packets
  (counted over the first 5,000 by default), with pinned and frequent
  fields first and every field by stack position (Application, Transport,
  Network, Link) and protocol. A value filters for or out, and a field can
  become a column or split the chart
- A chart of the displayed packets over time above the packet list, split
  by top protocol, by the protocol at one layer, or by a field
- Packet table (virtual scrolling) with a colored mark per protocol,
  filtered with dsct's filter syntax
- Protocol detail tree and hex dump, linked both ways and operable from the
  keyboard; a selected value filters for or out (or right-click it)
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
   **Open…** button. Open a capture (or drop one on the window): the status
   bar shows indexing progress, then the first packet is selected, the
   sidebar lists the fields, and the chart above the packets fills in.
2. ⌘K opens the command palette: type to narrow the actions (↑/↓, Enter,
   Esc), a packet number to jump to it, or any text to apply it as a
   filter.
3. In the sidebar, click a field (`ipv4.dst` under Frequent) for its top
   values: the magnifier with + narrows the filter to a value, the one
   with − excludes it. **Add as
   column** shows the field in the packet list; **Split chart by** colors
   the chart by its values (or pick a split from the menu beside "split
   by"). Pin a field to keep it at the top; the sliders menu at the top
   of the sidebar sets how many packets are counted. Click a bar of the chart to go to its first packet.
   Type a filter yourself: "Enter to apply" shows until you press Enter,
   and an invalid one outlines the input in red with the error under it.
4. Each row's protocol has its own color (TCP, UDP, DNS, HTTP, …), and the
   selected row is marked in blue. **Time** (⌘T) switches between seconds
   since the first packet, since the previous one, and the date and time.
5. Keyboard only: ↑/↓ in the table, then Tab to **Details** (blue outline):
   ↑/↓ move, → expands, ← collapses or goes to the parent, Enter toggles.
   Layers show a one-line summary (`10.0.0.1 → 93.184.216.34`) and values
   are colored by type. The selected value has filter buttons and a ⋯ menu
   (also on right-click). Tab again to **Bytes**: arrows move a cursor, and
   the field under it is selected in the tree. ⌘1/⌘2/⌘3 jump to each pane.
6. **Follow Stream** (⇧⌘F) and **Stats** (⇧⌘S) open tabs in the bottom dock
   (⌘J). Stream lines are marked → (client to server, orange) and ←
   (server to client, blue); Stats shows tables. The copy button copies the
   tab as text; × or Esc closes it.
7. Once a capture is loaded and nothing runs, the app stays idle (no CPU
   use in Activity Monitor).

The sidebar counts values over a sample (the first 5,000 displayed packets
unless set otherwise), so it is quick on any capture; the chart dissects
every displayed packet in the background.

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
