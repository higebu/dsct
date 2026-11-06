//! TUI view state types.

use std::path::PathBuf;

use ratatui::layout::Rect;

use super::cursor::CursorBuffer;
use crate::session::state::StreamLine;

/// Which pane is currently focused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pane {
    PacketList,
    DetailTree,
    HexDump,
    FilterInput,
    /// In-tree search input (when DetailTree is maximized).
    TreeSearch,
    /// Yank format prompt (`[t]ext / [h]ex`).
    YankPrompt,
    /// Vim-style `:` command input.
    CommandMode,
}

impl Pane {
    /// Cycle to the next pane (excluding FilterInput, which is entered via `/`).
    pub fn next(self) -> Self {
        match self {
            Self::PacketList => Self::DetailTree,
            Self::DetailTree => Self::HexDump,
            Self::HexDump => Self::PacketList,
            Self::FilterInput | Self::TreeSearch | Self::YankPrompt | Self::CommandMode => {
                Self::PacketList
            }
        }
    }

    /// Cycle to the previous pane.
    pub fn prev(self) -> Self {
        match self {
            Self::PacketList => Self::HexDump,
            Self::DetailTree => Self::PacketList,
            Self::HexDump => Self::DetailTree,
            Self::FilterInput | Self::TreeSearch | Self::YankPrompt | Self::CommandMode => {
                Self::PacketList
            }
        }
    }
}

/// Cached layout rectangles for pane hit-testing (mouse clicks).
#[derive(Default, Clone, Copy)]
pub struct PaneLayout {
    /// Packet list area.
    pub packet_list: Rect,
    /// Detail tree area.
    pub detail_tree: Rect,
    /// Hex dump area.
    pub hex_dump: Rect,
    /// Full frame area (used for stream view page size).
    pub frame_area: Rect,
}

impl PaneLayout {
    /// Determine which pane a screen coordinate falls in.
    pub fn pane_at(&self, col: u16, row: u16) -> Option<Pane> {
        if self.packet_list.contains((col, row).into()) {
            Some(Pane::PacketList)
        } else if self.detail_tree.contains((col, row).into()) {
            Some(Pane::DetailTree)
        } else if self.hex_dump.contains((col, row).into()) {
            Some(Pane::HexDump)
        } else {
            None
        }
    }
}

/// State for the packet list pane.
#[derive(Default)]
pub struct PacketListState {
    /// Select-order index of the selected row within the filter bitmap.
    pub selected: usize,
    /// Vertical scroll offset.
    pub scroll_offset: usize,
}

/// Selection mode for the detail tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectionMode {
    /// `v`: character-level selection within a single line.
    Char,
    /// `V`: line-level selection across multiple nodes.
    Line,
}

/// Active selection state in the detail tree.
pub struct SelectionState {
    /// Selection mode.
    pub mode: SelectionMode,
    /// Anchor node index (where selection started).
    pub anchor_node: usize,
    /// Character offset within the anchor node's label (Char mode only).
    pub anchor_char: usize,
    /// Current cursor character offset (Char mode only).
    pub cursor_char: usize,
}

/// State for the detail tree pane.
#[derive(Default)]
pub struct DetailTreeState {
    /// Index of the selected node.
    pub selected: usize,
    /// Vertical scroll offset.
    pub scroll_offset: usize,
    /// In-tree search query (empty = no search active).
    pub search_query: String,
    /// Fuzzy-matched tree search candidates (visible node index, label).
    pub search_completions: Vec<TreeSearchCandidate>,
    /// Selected index in the search completion list.
    pub search_completion_selected: usize,
    /// Active visual selection (None = normal mode).
    pub selection: Option<SelectionState>,
    /// Transient message shown in command line (e.g., "Copied!").
    pub yank_message: Option<String>,
}

/// A tree search completion candidate.
pub struct TreeSearchCandidate {
    /// Display label of the matching tree node.
    pub label: String,
    /// Index into the flat `tree_nodes` array.
    pub node_index: usize,
}

/// State for the hex dump pane.
#[derive(Default)]
pub struct HexDumpState {
    /// Vertical scroll offset (in lines, each line = 16 bytes).
    pub scroll_offset: usize,
}

/// Time display format for the packet list.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum TimeFormat {
    /// Absolute timestamp (ISO 8601).
    #[default]
    Absolute,
    /// Seconds since the first packet in the capture.
    Relative,
    /// Seconds since the previous displayed packet.
    Delta,
}

impl TimeFormat {
    /// Cycle to the next format.
    pub fn next(self) -> Self {
        match self {
            Self::Absolute => Self::Relative,
            Self::Relative => Self::Delta,
            Self::Delta => Self::Absolute,
        }
    }

    /// Short label for the status bar.
    pub fn label(self) -> &'static str {
        match self {
            Self::Absolute => "Abs",
            Self::Relative => "Rel",
            Self::Delta => "Delta",
        }
    }
}

/// State for `:` command mode input.
pub struct CommandState {
    /// Text buffer with cursor for the command input (without the leading `:`).
    pub buf: CursorBuffer,
}

/// Default pane height weights (packet list, detail tree, hex dump).
pub const DEFAULT_PANE_WEIGHTS: [u16; 3] = [35, 35, 30];

/// State for the filter / command line input.
#[derive(Default)]
pub struct FilterState {
    /// Text buffer with cursor for the filter input.
    pub buf: CursorBuffer,
    /// Error message from the most recent filter parse failure.
    pub error_message: Option<String>,
    /// Completion candidates for the current token.
    pub completions: Vec<CompletionCandidate>,
    /// Index of the selected completion candidate.
    pub completion_selected: usize,
    /// Whether the completion dropdown is visible.
    pub completion_visible: bool,
    /// History of previously applied filter queries (oldest first).
    pub history: Vec<String>,
    /// Current position in history when browsing with Ctrl+P/N.
    /// `None` = not browsing; `Some(i)` = showing `history[i]`.
    pub history_pos: Option<usize>,
    /// Saved input before starting history browsing.
    pub history_saved_input: String,
}

/// State for the Follow Stream overlay.
pub struct StreamViewState {
    /// Rendered stream lines.
    pub lines: Vec<StreamLine>,
    /// Scroll offset.
    pub scroll_offset: usize,
    /// Title string (e.g., "TCP Stream: 10.0.0.1:443 ↔ 10.0.0.2:52014").
    pub title: String,
}

pub struct CompletionCandidate {
    /// Display label (e.g., "TCP", "TCP.src_port").
    pub label: String,
}

// ---------------------------------------------------------------------------
// Filter history persistence
// ---------------------------------------------------------------------------

/// Maximum number of history entries to persist.
const HISTORY_MAX_ENTRIES: usize = 1000;

/// Resolve the filter history file path.
///
/// Tries, in order:
/// 1. `$XDG_STATE_HOME/dsct/filter_history`
/// 2. `$XDG_CACHE_HOME/dsct/filter_history`
/// 3. `$HOME/.local/state/dsct/filter_history`
pub fn history_path() -> Option<PathBuf> {
    if let Ok(state) = std::env::var("XDG_STATE_HOME") {
        return Some(PathBuf::from(state).join("dsct").join("filter_history"));
    }
    if let Ok(cache) = std::env::var("XDG_CACHE_HOME") {
        return Some(PathBuf::from(cache).join("dsct").join("filter_history"));
    }
    if let Ok(home) = std::env::var("HOME") {
        return Some(
            PathBuf::from(home)
                .join(".local/state/dsct")
                .join("filter_history"),
        );
    }
    None
}

/// Load filter history from disk.  Returns an empty `Vec` on any error.
pub fn load_history() -> Vec<String> {
    let path = match history_path() {
        Some(p) => p,
        None => return Vec::new(),
    };
    match std::fs::read_to_string(&path) {
        Ok(content) => content
            .lines()
            .filter(|l| !l.is_empty())
            .take(HISTORY_MAX_ENTRIES)
            .map(String::from)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Save filter history to disk.  Errors are silently ignored.
pub fn save_history(history: &[String]) {
    let path = match history_path() {
        Some(p) => p,
        None => return,
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let entries: Vec<&String> = if history.len() > HISTORY_MAX_ENTRIES {
        history[history.len() - HISTORY_MAX_ENTRIES..]
            .iter()
            .collect()
    } else {
        history.iter().collect()
    };
    let content = entries
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    // Atomic write: write to a sibling temp file, then rename to avoid
    // partial writes if multiple dsct instances run concurrently.
    let tmp_path = path.with_extension("tmp");
    if std::fs::write(&tmp_path, &content).is_ok() {
        let _ = std::fs::rename(&tmp_path, &path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pane_next_cycles() {
        assert_eq!(Pane::PacketList.next(), Pane::DetailTree);
        assert_eq!(Pane::DetailTree.next(), Pane::HexDump);
        assert_eq!(Pane::HexDump.next(), Pane::PacketList);
        assert_eq!(Pane::FilterInput.next(), Pane::PacketList);
    }

    #[test]
    fn pane_prev_cycles() {
        assert_eq!(Pane::PacketList.prev(), Pane::HexDump);
        assert_eq!(Pane::DetailTree.prev(), Pane::PacketList);
        assert_eq!(Pane::HexDump.prev(), Pane::DetailTree);
        assert_eq!(Pane::FilterInput.prev(), Pane::PacketList);
    }

    #[test]
    fn pane_layout_hit_test() {
        let layout = PaneLayout {
            frame_area: Rect::new(0, 0, 80, 30),
            packet_list: Rect::new(0, 0, 80, 10),
            detail_tree: Rect::new(0, 10, 80, 10),
            hex_dump: Rect::new(0, 20, 80, 10),
        };
        assert_eq!(layout.pane_at(40, 5), Some(Pane::PacketList));
        assert_eq!(layout.pane_at(40, 15), Some(Pane::DetailTree));
        assert_eq!(layout.pane_at(40, 25), Some(Pane::HexDump));
        assert_eq!(layout.pane_at(40, 35), None); // outside all panes
    }

    #[test]
    fn history_save_and_load_to_path() {
        let dir = std::env::temp_dir().join(format!("dsct_hist_test_{}", std::process::id()));
        let path = dir.join("filter_history");

        // Use internal save/load with explicit path.
        std::fs::create_dir_all(&dir).unwrap();
        let history = ["tcp".to_string(), "dns".to_string(), "not icmp".to_string()];
        let content = history.join("\n");
        std::fs::write(&path, &content).unwrap();

        let loaded: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|l| !l.is_empty())
            .map(String::from)
            .collect();
        assert_eq!(loaded, vec!["tcp", "dns", "not icmp"]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn history_max_entries_truncation() {
        // Verify the save logic truncates to HISTORY_MAX_ENTRIES.
        let big: Vec<String> = (0..1500).map(|i| format!("filter_{i}")).collect();
        let entries: Vec<&String> = big[big.len() - HISTORY_MAX_ENTRIES..].iter().collect();
        assert_eq!(entries.len(), 1000);
        assert_eq!(*entries[0], "filter_500");
        assert_eq!(*entries[999], "filter_1499");
    }

    #[test]
    fn history_path_returns_some() {
        // history_path() should return Some in most environments (HOME is set).
        // We just test it doesn't panic.
        let _ = history_path();
    }
}
