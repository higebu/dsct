//! Key handling and navigation for the TUI application.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::app::{App, visible_nodes};
use super::clipboard;
use super::completion;
use super::cursor::CursorBuffer;
use super::state::{
    CommandState, CompletionCandidate, DEFAULT_PANE_WEIGHTS, LiveMode, Pane, SelectionMode,
    SelectionState,
};

impl App {
    /// Handle a key event, updating state accordingly.
    pub fn handle_key(&mut self, key: KeyEvent) {
        // Clear yank message on any key press.
        self.detail_tree.yank_message = None;

        // Dismiss help overlay on any key.
        if self.show_help {
            self.show_help = false;
            return;
        }

        // Dismiss stats overlay on any key.
        if self.stats_output.is_some() {
            self.stats_output = None;
            return;
        }

        // Stream view keys.
        if self.stream_view.is_some() {
            self.handle_stream_view_key(key);
            return;
        }

        match self.active_pane {
            Pane::FilterInput => self.handle_filter_key(key),
            Pane::TreeSearch => self.handle_tree_search_key(key),
            Pane::YankPrompt => self.handle_yank_prompt_key(key),
            Pane::CommandMode => self.handle_command_mode_key(key),
            _ => {
                // If a visual selection is active, handle selection keys.
                if self.detail_tree.selection.is_some() {
                    self.handle_selection_key(key);
                } else {
                    self.handle_normal_key(key);
                }
            }
        }
    }

    /// Handle a mouse event, updating state accordingly.
    pub fn handle_mouse(&mut self, mouse: crossterm::event::MouseEvent) {
        use crossterm::event::{MouseButton, MouseEventKind};

        // Dismiss help overlay on any click.
        if self.show_help {
            self.show_help = false;
            return;
        }

        // Ignore mouse during overlays.
        if self.stream_view.is_some()
            || self.filter_progress.is_some()
            || self.stream_build_progress.is_some()
        {
            return;
        }

        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(pane) = self.pane_layout.pane_at(mouse.column, mouse.row) {
                    // Switch to the clicked pane (only for content panes).
                    if matches!(pane, Pane::PacketList | Pane::DetailTree | Pane::HexDump) {
                        self.active_pane = pane;
                    }

                    // Click on a specific packet row in the packet list.
                    if pane == Pane::PacketList {
                        let area = self.pane_layout.packet_list;
                        // Rows inside the border start at area.y + 1.
                        if mouse.row > area.y && mouse.row < area.y + area.height.saturating_sub(1)
                        {
                            let row_in_view = (mouse.row - area.y - 1) as usize;
                            let target = self.packet_list.scroll_offset + row_in_view;
                            if target < self.displayed_count() {
                                self.packet_list.selected = target;
                                self.load_selected();
                                self.hex_dump.scroll_offset = 0;
                            }
                        }
                    }
                }
            }
            MouseEventKind::ScrollUp => {
                self.move_up();
            }
            MouseEventKind::ScrollDown => {
                self.move_down();
            }
            _ => {}
        }
    }

    /// Handle a terminal resize event by clamping scroll offsets so they
    /// stay within bounds of the new visible area. The actual layout
    /// rectangles in `pane_layout` are recalculated during the next render
    /// call; this method just ensures scroll positions are sane.
    pub fn on_resize(&mut self) {
        // Clamp packet list scroll offset.
        let total = self.displayed_count();
        if total == 0 {
            self.packet_list.scroll_offset = 0;
        } else {
            self.packet_list.scroll_offset =
                self.packet_list.scroll_offset.min(total.saturating_sub(1));
        }
        // Ensure selected is still valid.
        if total > 0 {
            self.packet_list.selected = self.packet_list.selected.min(total - 1);
        }

        // Clamp hex dump scroll offset. Without knowing the exact new inner
        // height we cannot compute a tight upper bound, but we can at least
        // ensure it doesn't exceed the total hex lines for the selected packet.
        if let Some(raw) = self.selected_raw_bytes() {
            let total_lines = raw.len().div_ceil(16);
            if total_lines == 0 {
                self.hex_dump.scroll_offset = 0;
            } else {
                self.hex_dump.scroll_offset = self
                    .hex_dump
                    .scroll_offset
                    .min(total_lines.saturating_sub(1));
            }
        } else {
            self.hex_dump.scroll_offset = 0;
        }

        // Clamp detail tree scroll offset.
        if let Some(sel) = &self.selected {
            let tree_len = sel.tree_nodes.len();
            if tree_len == 0 {
                self.detail_tree.scroll_offset = 0;
            } else {
                self.detail_tree.scroll_offset = self
                    .detail_tree
                    .scroll_offset
                    .min(tree_len.saturating_sub(1));
            }
        } else {
            self.detail_tree.scroll_offset = 0;
        }

        // Clamp stream view scroll offset if open.
        if let Some(sv) = &mut self.stream_view {
            let lines_len = sv.lines.len();
            if lines_len == 0 {
                sv.scroll_offset = 0;
            } else {
                sv.scroll_offset = sv.scroll_offset.min(lines_len.saturating_sub(1));
            }
        }

        // Invalidate cached pane layout so stale rects are not used for
        // hit-testing before the next render.
        self.pane_layout = super::state::PaneLayout::default();
    }

    fn handle_normal_key(&mut self, key: KeyEvent) {
        // Digit accumulation for number+G jump.
        if let KeyCode::Char(c @ '0'..='9') = key.code {
            self.pending_count.push(c);
            return;
        }

        let pending = std::mem::take(&mut self.pending_count);

        match key.code {
            KeyCode::Char('q') => self.running = false,
            KeyCode::Char(':') => {
                self.command = Some(CommandState {
                    buf: CursorBuffer::new(),
                });
                self.active_pane = Pane::CommandMode;
            }
            KeyCode::Char('?') => self.show_help = true,
            KeyCode::Char('t') => self.time_format = self.time_format.next(),
            KeyCode::Char('/') => {
                if self.maximized_pane == Some(Pane::DetailTree) {
                    // In-tree search when DetailTree is maximized.
                    self.active_pane = Pane::TreeSearch;
                    self.detail_tree.search_query.clear();
                } else {
                    self.active_pane = Pane::FilterInput;
                    self.filter.buf.input = self.filter.applied.clone();
                    self.filter.buf.cursor = self.filter.buf.input.len();
                }
            }
            KeyCode::Tab => {
                let next = self.active_pane.next();
                self.active_pane = next;
                if self.maximized_pane.is_some() {
                    self.maximized_pane = Some(next);
                }
            }
            KeyCode::BackTab => {
                let prev = self.active_pane.prev();
                self.active_pane = prev;
                if self.maximized_pane.is_some() {
                    self.maximized_pane = Some(prev);
                }
            }
            KeyCode::Char('z') => {
                if self.maximized_pane.is_some() {
                    self.maximized_pane = None;
                } else {
                    self.maximized_pane = Some(self.active_pane);
                }
            }
            KeyCode::Char('+') => self.adjust_pane_weight(5),
            KeyCode::Char('-') => self.adjust_pane_weight(-5),
            KeyCode::Char('=') => self.pane_weights = DEFAULT_PANE_WEIGHTS,
            KeyCode::Char('j') | KeyCode::Down => self.move_down(),
            KeyCode::Char('k') | KeyCode::Up => self.move_up(),
            KeyCode::Char('g') | KeyCode::Home => self.move_to_top(),
            KeyCode::Char('G') | KeyCode::End => {
                if !pending.is_empty() {
                    self.jump_to_packet_number(&pending);
                } else {
                    self.move_to_bottom();
                }
            }
            KeyCode::Char('l') | KeyCode::Right => self.tree_expand_or_enter(),
            KeyCode::Char('h') | KeyCode::Left => self.tree_collapse_or_parent(),
            KeyCode::Char('v') => self.start_char_selection(),
            KeyCode::Char('V') => self.start_line_selection(),
            KeyCode::Char('y') => self.yank_current_line(),
            KeyCode::Char('e') => self.toggle_tree_expand_all(),
            KeyCode::Char('n') => self.tree_search_next(),
            KeyCode::Char('N') => self.tree_search_prev(),
            KeyCode::Enter | KeyCode::Char(' ') => self.toggle_tree_node(),
            KeyCode::Char('p') if self.live_mode == Some(LiveMode::Live) => {
                self.live_mode = Some(LiveMode::Paused);
            }
            KeyCode::Char('r') if self.live_mode == Some(LiveMode::Paused) => {
                self.live_mode = Some(LiveMode::Live);
            }
            KeyCode::Char('f') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.start_follow_stream();
            }
            KeyCode::PageDown | KeyCode::Char('f')
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    || key.code == KeyCode::PageDown =>
            {
                self.page_down();
            }
            KeyCode::PageUp | KeyCode::Char('b')
                if key.modifiers.contains(KeyModifiers::CONTROL) || key.code == KeyCode::PageUp =>
            {
                self.page_up();
            }
            _ => {}
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.filter.completion_visible = false;
                self.active_pane = Pane::PacketList;
            }
            KeyCode::Enter => {
                self.filter.completion_visible = false;
                // Save to history (avoid duplicating the most recent entry).
                let query = self.filter.buf.input.clone();
                if !query.is_empty() && self.filter.history.last().is_none_or(|h| h != &query) {
                    self.filter.history.push(query);
                }
                self.filter.history_pos = None;
                self.apply_filter();
                self.active_pane = Pane::PacketList;
            }
            KeyCode::Tab => {
                // Accept selected completion.
                if self.filter.completion_visible
                    && self.filter.completion_selected < self.filter.completions.len()
                {
                    let label = self.filter.completions[self.filter.completion_selected]
                        .label
                        .clone();
                    let (token_start, token) =
                        completion::current_token(&self.filter.buf.input, self.filter.buf.cursor);

                    if token.contains('=') {
                        // Value completion: keep "key=" prefix in the raw input,
                        // find "=" position in the actual input, replace after it.
                        let raw_before =
                            &self.filter.buf.input[token_start..self.filter.buf.cursor];
                        if let Some(eq_pos_in_raw) = raw_before.find('=') {
                            let replace_start = token_start + eq_pos_in_raw + 1;
                            let before = &self.filter.buf.input[..replace_start];
                            let after = &self.filter.buf.input[self.filter.buf.cursor..];
                            self.filter.buf.input = format!("{before}{label}{after}");
                            self.filter.buf.cursor = replace_start + label.len();
                        }
                    } else {
                        // Protocol/field name completion: replace entire token.
                        let before = &self.filter.buf.input[..token_start];
                        let after = &self.filter.buf.input[self.filter.buf.cursor..];
                        self.filter.buf.input = format!("{before}{label}{after}");
                        self.filter.buf.cursor = token_start + label.len();
                    }
                    self.filter.completion_visible = false;
                }
                self.update_completions();
            }
            KeyCode::Down
                if self.filter.completion_visible && !self.filter.completions.is_empty() =>
            {
                self.filter.completion_selected =
                    (self.filter.completion_selected + 1).min(self.filter.completions.len() - 1);
            }
            KeyCode::Up if self.filter.completion_visible => {
                self.filter.completion_selected = self.filter.completion_selected.saturating_sub(1);
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                // Ctrl+U: clear input (like Vim/readline).
                self.filter.buf.input.clear();
                self.filter.buf.cursor = 0;
                self.update_completions();
            }
            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                // Ctrl+P: previous history entry.
                self.filter_history_prev();
            }
            KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                // Ctrl+N: next history entry.
                self.filter_history_next();
            }
            KeyCode::Char(c) => {
                self.filter.buf.insert_char(c);
                self.filter.history_pos = None;
                self.update_completions();
            }
            KeyCode::Backspace => {
                if self.filter.buf.backspace() {
                    self.update_completions();
                } else if self.filter.buf.is_empty() {
                    // Empty input + Backspace → exit filter mode (like Vim)
                    self.active_pane = Pane::PacketList;
                    self.filter.completion_visible = false;
                }
            }
            KeyCode::Left => {
                self.filter.buf.move_left();
            }
            KeyCode::Right => {
                self.filter.buf.move_right();
            }
            _ => {}
        }
    }

    fn handle_tree_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.detail_tree.search_completions.clear();
                self.active_pane = Pane::DetailTree;
            }
            KeyCode::Enter | KeyCode::Tab => {
                // Jump to selected completion candidate.
                if let Some(candidate) = self
                    .detail_tree
                    .search_completions
                    .get(self.detail_tree.search_completion_selected)
                {
                    self.detail_tree.selected = candidate.node_index;
                }
                self.detail_tree.search_completions.clear();
                self.active_pane = Pane::DetailTree;
            }
            KeyCode::Down if !self.detail_tree.search_completions.is_empty() => {
                self.detail_tree.search_completion_selected =
                    (self.detail_tree.search_completion_selected + 1)
                        .min(self.detail_tree.search_completions.len() - 1);
            }
            KeyCode::Up => {
                self.detail_tree.search_completion_selected = self
                    .detail_tree
                    .search_completion_selected
                    .saturating_sub(1);
            }
            KeyCode::Backspace => {
                if self.detail_tree.search_query.is_empty() {
                    self.detail_tree.search_completions.clear();
                    self.active_pane = Pane::DetailTree;
                } else {
                    self.detail_tree.search_query.pop();
                    self.update_tree_search_completions();
                }
            }
            KeyCode::Char(c) => {
                self.detail_tree.search_query.push(c);
                self.update_tree_search_completions();
            }
            _ => {}
        }
    }

    fn update_tree_search_completions(&mut self) {
        use nucleo_matcher::pattern::{Atom, AtomKind, CaseMatching, Normalization};
        use nucleo_matcher::{Config, Matcher};

        self.detail_tree.search_completion_selected = 0;

        let query = &self.detail_tree.search_query;
        if query.is_empty() {
            self.detail_tree.search_completions.clear();
            return;
        }

        let sel = match &self.selected {
            Some(s) => s,
            None => {
                self.detail_tree.search_completions.clear();
                return;
            }
        };

        // Collect all visible node labels with their indices.
        let vis: Vec<(usize, &str)> = visible_nodes(&sel.tree_nodes)
            .map(|(i, n)| (i, n.label.as_str()))
            .collect();
        let labels: Vec<&str> = vis.iter().map(|(_, l)| *l).collect();

        let mut matcher = Matcher::new(Config::DEFAULT);
        let atom = Atom::new(
            query,
            CaseMatching::Ignore,
            Normalization::Smart,
            AtomKind::Fuzzy,
            false,
        );

        let mut matches: Vec<_> = atom
            .match_list(&labels, &mut matcher)
            .into_iter()
            .map(|(label, score)| {
                let node_index = vis
                    .iter()
                    .find(|(_, l)| *l == *label)
                    .map(|(i, _)| *i)
                    .unwrap_or(0);
                (label.to_string(), node_index, score)
            })
            .collect();
        matches.sort_by_key(|b| std::cmp::Reverse(b.2));

        use super::state::TreeSearchCandidate;
        self.detail_tree.search_completions = matches
            .into_iter()
            .take(8)
            .map(|(label, node_index, _)| TreeSearchCandidate { label, node_index })
            .collect();
    }

    /// Jump to the next tree node matching the search query.
    fn tree_search_next(&mut self) {
        let query = self.detail_tree.search_query.to_ascii_lowercase();
        if query.is_empty() {
            return;
        }
        let sel = match &self.selected {
            Some(s) => s,
            None => return,
        };
        let vis = visible_nodes(&sel.tree_nodes)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        let cur_pos = vis
            .iter()
            .position(|&i| i == self.detail_tree.selected)
            .unwrap_or(0);
        // Search forward from current position, wrapping around.
        for offset in 1..=vis.len() {
            let idx = vis[(cur_pos + offset) % vis.len()];
            if sel.tree_nodes[idx]
                .label
                .to_ascii_lowercase()
                .contains(&query)
            {
                self.detail_tree.selected = idx;
                return;
            }
        }
    }

    /// Jump to the previous tree node matching the search query.
    fn tree_search_prev(&mut self) {
        let query = self.detail_tree.search_query.to_ascii_lowercase();
        if query.is_empty() {
            return;
        }
        let sel = match &self.selected {
            Some(s) => s,
            None => return,
        };
        let vis = visible_nodes(&sel.tree_nodes)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        let cur_pos = vis
            .iter()
            .position(|&i| i == self.detail_tree.selected)
            .unwrap_or(0);
        // Search backward from current position, wrapping around.
        for offset in 1..=vis.len() {
            let idx = vis[(cur_pos + vis.len() - offset) % vis.len()];
            if sel.tree_nodes[idx]
                .label
                .to_ascii_lowercase()
                .contains(&query)
            {
                self.detail_tree.selected = idx;
                return;
            }
        }
    }

    // -- Visual selection and yank --

    fn start_char_selection(&mut self) {
        if let Some(sel) = &self.selected {
            let idx = self.detail_tree.selected;
            if let Some(node) = sel.tree_nodes.get(idx) {
                self.detail_tree.selection = Some(SelectionState {
                    mode: SelectionMode::Char,
                    anchor_node: idx,
                    anchor_char: 0,
                    cursor_char: node.label.chars().count(),
                });
            }
        }
    }

    fn start_line_selection(&mut self) {
        let idx = self.detail_tree.selected;
        self.detail_tree.selection = Some(SelectionState {
            mode: SelectionMode::Line,
            anchor_node: idx,
            anchor_char: 0,
            cursor_char: 0,
        });
    }

    fn yank_current_line(&mut self) {
        if self.selected.is_some() {
            self.active_pane = Pane::YankPrompt;
        }
    }

    fn handle_selection_key(&mut self, key: KeyEvent) {
        let mode = match &self.detail_tree.selection {
            Some(s) => s.mode,
            None => return,
        };

        match key.code {
            KeyCode::Esc => {
                self.detail_tree.selection = None;
            }
            KeyCode::Char('y') | KeyCode::Enter => {
                if mode == SelectionMode::Char {
                    self.copy_char_selection();
                    self.detail_tree.selection = None;
                } else {
                    // Line mode → show format prompt.
                    self.active_pane = Pane::YankPrompt;
                }
            }
            KeyCode::Char('h') | KeyCode::Left => {
                if mode == SelectionMode::Char
                    && let Some(s) = &mut self.detail_tree.selection
                {
                    s.anchor_char = s.anchor_char.saturating_sub(1);
                }
            }
            KeyCode::Char('l') | KeyCode::Right => {
                if mode == SelectionMode::Char
                    && let Some(sel) = &self.selected
                {
                    let max_len = sel
                        .tree_nodes
                        .get(self.detail_tree.selected)
                        .map(|n| n.label.chars().count())
                        .unwrap_or(0);
                    if let Some(s) = &mut self.detail_tree.selection {
                        s.cursor_char = (s.cursor_char + 1).min(max_len);
                    }
                }
            }
            KeyCode::Char('j') | KeyCode::Down if mode == SelectionMode::Line => {
                self.move_down();
            }
            KeyCode::Char('k') | KeyCode::Up if mode == SelectionMode::Line => {
                self.move_up();
            }
            _ => {}
        }
    }

    fn handle_yank_prompt_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('t') => {
                self.copy_as_text();
                self.detail_tree.selection = None;
                self.active_pane = Pane::DetailTree;
            }
            KeyCode::Char('h') => {
                self.copy_as_hex();
                self.detail_tree.selection = None;
                self.active_pane = Pane::DetailTree;
            }
            KeyCode::Esc => {
                self.detail_tree.selection = None;
                self.active_pane = Pane::DetailTree;
            }
            _ => {}
        }
    }

    fn copy_char_selection(&mut self) {
        let sel_state = match &self.detail_tree.selection {
            Some(s) if s.mode == SelectionMode::Char => s,
            _ => return,
        };
        if let Some(sel) = &self.selected
            && let Some(node) = sel.tree_nodes.get(sel_state.anchor_node)
        {
            let start = sel_state.anchor_char;
            let end = sel_state.cursor_char;
            let (lo, hi) = if start <= end {
                (start, end)
            } else {
                (end, start)
            };
            let text: String = node.label.chars().skip(lo).take(hi - lo).collect();
            clipboard::copy_to_clipboard(&text);
            self.detail_tree.yank_message = Some("Copied!".into());
        }
    }

    fn copy_as_text(&mut self) {
        let sel = match &self.selected {
            Some(s) => s,
            None => return,
        };

        let text = if let Some(sel_state) = &self.detail_tree.selection {
            if sel_state.mode == SelectionMode::Line {
                // Collect labels from anchor to current selection.
                let vis = visible_nodes(&sel.tree_nodes)
                    .map(|(i, _)| i)
                    .collect::<Vec<_>>();
                let a = vis.iter().position(|&i| i == sel_state.anchor_node);
                let b = vis.iter().position(|&i| i == self.detail_tree.selected);
                if let (Some(a), Some(b)) = (a, b) {
                    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                    vis[lo..=hi]
                        .iter()
                        .filter_map(|&i| sel.tree_nodes.get(i).map(|n| n.label.as_str()))
                        .collect::<Vec<_>>()
                        .join("\n")
                } else {
                    return;
                }
            } else {
                return;
            }
        } else {
            // y → t: yank single line text.
            sel.tree_nodes
                .get(self.detail_tree.selected)
                .map(|n| n.label.clone())
                .unwrap_or_default()
        };

        clipboard::copy_to_clipboard(&text);
        self.detail_tree.yank_message = Some("Copied!".into());
    }

    fn copy_as_hex(&mut self) {
        let raw = match self.selected_raw_bytes() {
            Some(b) => b,
            None => return,
        };

        let range = if let Some(sel_state) = &self.detail_tree.selection {
            if sel_state.mode == SelectionMode::Line {
                let Some(sel) = self.selected.as_ref() else {
                    return;
                };
                let vis = visible_nodes(&sel.tree_nodes)
                    .map(|(i, _)| i)
                    .collect::<Vec<_>>();
                let a = vis.iter().position(|&i| i == sel_state.anchor_node);
                let b = vis.iter().position(|&i| i == self.detail_tree.selected);
                if let (Some(a), Some(b)) = (a, b) {
                    let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
                    let min = vis[lo..=hi]
                        .iter()
                        .filter_map(|&i| sel.tree_nodes.get(i).map(|n| n.byte_range.start))
                        .min()
                        .unwrap_or(0);
                    let max = vis[lo..=hi]
                        .iter()
                        .filter_map(|&i| sel.tree_nodes.get(i).map(|n| n.byte_range.end))
                        .max()
                        .unwrap_or(0);
                    min..max
                } else {
                    return;
                }
            } else {
                return;
            }
        } else {
            // y → h: yank single line hex.
            match self.selected_byte_range() {
                Some(r) => r,
                None => return,
            }
        };

        if range.start < raw.len() && range.end <= raw.len() {
            let hex: String = raw[range].iter().map(|b| format!("{b:02x}")).collect();
            clipboard::copy_to_clipboard(&hex);
            self.detail_tree.yank_message = Some("Copied hex!".into());
        }
    }

    fn handle_stream_view_key(&mut self, key: KeyEvent) {
        let page_size = self.stream_view_page_size();
        let sv = match &mut self.stream_view {
            Some(v) => v,
            None => return,
        };
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.stream_view = None;
            }
            KeyCode::Char('j') | KeyCode::Down if sv.scroll_offset + 1 < sv.lines.len() => {
                sv.scroll_offset += 1;
            }
            KeyCode::Char('k') | KeyCode::Up => {
                sv.scroll_offset = sv.scroll_offset.saturating_sub(1);
            }
            KeyCode::Char('g') | KeyCode::Home => {
                sv.scroll_offset = 0;
            }
            KeyCode::Char('G') | KeyCode::End => {
                sv.scroll_offset = sv.lines.len().saturating_sub(1);
            }
            KeyCode::PageDown => {
                sv.scroll_offset =
                    (sv.scroll_offset + page_size).min(sv.lines.len().saturating_sub(1));
            }
            KeyCode::PageUp => {
                sv.scroll_offset = sv.scroll_offset.saturating_sub(page_size);
            }
            _ => {}
        }
    }

    // -- Command mode --

    fn handle_command_mode_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.command = None;
                self.active_pane = Pane::PacketList;
            }
            KeyCode::Enter => {
                self.active_pane = Pane::PacketList;
                self.execute_command();
            }
            KeyCode::Backspace => {
                if let Some(cmd) = &mut self.command
                    && !cmd.buf.backspace()
                    && cmd.buf.is_empty()
                {
                    self.command = None;
                    self.active_pane = Pane::PacketList;
                }
            }
            KeyCode::Left => {
                if let Some(cmd) = &mut self.command {
                    cmd.buf.move_left();
                }
            }
            KeyCode::Right => {
                if let Some(cmd) = &mut self.command {
                    cmd.buf.move_right();
                }
            }
            KeyCode::Char(c) => {
                if let Some(cmd) = &mut self.command {
                    cmd.buf.insert_char(c);
                }
            }
            _ => {}
        }
    }

    fn execute_command(&mut self) {
        let input = self.command.take().map(|c| c.buf.input).unwrap_or_default();
        let input = input.trim();
        if input.is_empty() {
            return;
        }
        let (cmd, args) = input
            .split_once(' ')
            .map(|(c, a)| (c, a.trim()))
            .unwrap_or((input, ""));

        match cmd {
            "w" | "write" => {
                if args.is_empty() {
                    self.detail_tree.yank_message = Some("Usage: :w <path>".into());
                } else {
                    match self.save_filtered_pcap(args) {
                        Ok(n) => {
                            self.detail_tree.yank_message =
                                Some(format!("Saved {n} packets to {args}"));
                        }
                        Err(e) => {
                            self.detail_tree.yank_message = Some(format!("Error: {e}"));
                        }
                    }
                }
            }
            "q" | "quit" => self.running = false,
            "wq" => {
                if !args.is_empty() {
                    match self.save_filtered_pcap(args) {
                        Ok(n) => {
                            self.detail_tree.yank_message =
                                Some(format!("Saved {n} packets to {args}"));
                        }
                        Err(e) => {
                            self.detail_tree.yank_message = Some(format!("Error: {e}"));
                            return;
                        }
                    }
                }
                self.running = false;
            }
            "stats" => {
                self.stats_output = None;
                self.stats_progress = Some(super::state::StatsProgress {
                    cursor: 0,
                    collector: crate::stats::StatsCollector::from_flags(
                        &crate::stats::StatsFlags::all_protocols(true, true),
                    ),
                });
            }
            _ => {
                self.detail_tree.yank_message = Some(format!("Unknown command: {cmd}"));
            }
        }
    }

    fn save_filtered_pcap(&self, path: &str) -> std::io::Result<usize> {
        let file = std::fs::File::create(path)?;

        let link_type = self
            .filtered_indices
            .first()
            .and_then(|&i| self.indices.get(i))
            .map(|idx| idx.link_type as u32)
            .unwrap_or(1);

        let mut writer = packet_dissector_pcap::PcapWriter::new(file, link_type)
            .map_err(|e| std::io::Error::other(e.to_string()))?;

        for &pkt_idx in &self.filtered_indices {
            let index = &self.indices[pkt_idx];
            let data = match self.capture.packet_data(index) {
                Some(d) => d,
                None => continue,
            };
            let record = packet_dissector_pcap::PacketRecord {
                data_offset: index.data_offset,
                captured_len: index.captured_len,
                original_len: index.original_len,
                timestamp_secs: index.timestamp_secs,
                timestamp_usecs: index.timestamp_usecs,
                link_type: index.link_type,
            };
            writer
                .write_packet(&record, data)
                .map_err(|e| std::io::Error::other(e.to_string()))?;
        }
        let count = writer.count();
        writer
            .finish()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(count)
    }

    fn filter_history_prev(&mut self) {
        if self.filter.history.is_empty() {
            return;
        }
        let new_pos = match self.filter.history_pos {
            None => {
                // Start browsing: save current input, jump to last entry.
                self.filter.history_saved_input = self.filter.buf.input.clone();
                self.filter.history.len() - 1
            }
            Some(pos) if pos > 0 => pos - 1,
            Some(pos) => pos, // Already at oldest.
        };
        self.filter.history_pos = Some(new_pos);
        self.filter.buf.input = self.filter.history[new_pos].clone();
        self.filter.buf.cursor = self.filter.buf.input.len();
        self.update_completions();
    }

    fn filter_history_next(&mut self) {
        let pos = match self.filter.history_pos {
            Some(p) => p,
            None => return, // Not browsing.
        };
        if pos + 1 >= self.filter.history.len() {
            // Past the newest entry → restore saved input.
            self.filter.history_pos = None;
            self.filter.buf.input = std::mem::take(&mut self.filter.history_saved_input);
        } else {
            self.filter.history_pos = Some(pos + 1);
            self.filter.buf.input = self.filter.history[pos + 1].clone();
        }
        self.filter.buf.cursor = self.filter.buf.input.len();
        self.update_completions();
    }

    fn update_completions(&mut self) {
        let (_, token) = completion::current_token(&self.filter.buf.input, self.filter.buf.cursor);

        let items = if let Some((key, value_query)) = token.split_once('=') {
            // After "=" → value completion by scanning capture packets.
            // Split at first dot: protocol.field_path (field_path may contain dots)
            if let Some((protocol, field)) = key.split_once('.') {
                completion::CompletionEngine::complete_value(
                    protocol,
                    field,
                    value_query,
                    &self.capture,
                    &self.indices,
                    &self.registry,
                )
            } else {
                Vec::new()
            }
        } else {
            // Protocol name or field name completion.
            self.completion_engine
                .complete(&token, &self.capture, &self.indices, &self.registry)
        };

        self.filter.completions = items
            .into_iter()
            .map(|c| CompletionCandidate { label: c.label })
            .collect();
        self.filter.completion_selected = 0;
        self.filter.completion_visible = !self.filter.completions.is_empty();
    }

    /// Return the flat-array indices of all currently visible tree nodes.
    fn visible_node_indices(&self) -> Vec<usize> {
        self.selected
            .as_ref()
            .map(|sel| visible_nodes(&sel.tree_nodes).map(|(idx, _)| idx).collect())
            .unwrap_or_default()
    }

    /// Find the position of `detail_tree.selected` within the visible node list.
    fn tree_cursor_pos(&self, vis: &[usize]) -> Option<usize> {
        vis.iter().position(|&i| i == self.detail_tree.selected)
    }

    fn move_down(&mut self) {
        match self.active_pane {
            Pane::PacketList => {
                if self.packet_list.selected + 1 < self.displayed_count() {
                    self.packet_list.selected += 1;
                    self.load_selected();
                    self.hex_dump.scroll_offset = 0;
                }
            }
            Pane::DetailTree => {
                let vis = self.visible_node_indices();
                if let Some(pos) = self.tree_cursor_pos(&vis)
                    && pos + 1 < vis.len()
                {
                    self.detail_tree.selected = vis[pos + 1];
                }
            }
            Pane::HexDump => {
                if let Some(raw) = self.selected_raw_bytes() {
                    let max = raw.len().div_ceil(16).saturating_sub(1);
                    if self.hex_dump.scroll_offset < max {
                        self.hex_dump.scroll_offset += 1;
                    }
                }
            }
            Pane::FilterInput | Pane::TreeSearch | Pane::YankPrompt | Pane::CommandMode => {}
        }
    }

    fn move_up(&mut self) {
        match self.active_pane {
            Pane::PacketList => {
                if self.packet_list.selected > 0 {
                    self.packet_list.selected -= 1;
                    self.load_selected();
                    self.hex_dump.scroll_offset = 0;
                }
            }
            Pane::DetailTree => {
                let vis = self.visible_node_indices();
                if let Some(pos) = self.tree_cursor_pos(&vis)
                    && pos > 0
                {
                    self.detail_tree.selected = vis[pos - 1];
                }
            }
            Pane::HexDump => {
                self.hex_dump.scroll_offset = self.hex_dump.scroll_offset.saturating_sub(1);
            }
            Pane::FilterInput | Pane::TreeSearch | Pane::YankPrompt | Pane::CommandMode => {}
        }
    }

    fn move_to_top(&mut self) {
        match self.active_pane {
            Pane::PacketList => {
                if self.packet_list.selected != 0 {
                    self.packet_list.selected = 0;
                    self.packet_list.scroll_offset = 0;
                    self.load_selected();
                    self.hex_dump.scroll_offset = 0;
                }
            }
            Pane::DetailTree => {
                let vis = self.visible_node_indices();
                if let Some(&first) = vis.first() {
                    self.detail_tree.selected = first;
                }
            }
            Pane::HexDump => {
                self.hex_dump.scroll_offset = 0;
            }
            Pane::FilterInput | Pane::TreeSearch | Pane::YankPrompt | Pane::CommandMode => {}
        }
    }

    fn move_to_bottom(&mut self) {
        match self.active_pane {
            Pane::PacketList => {
                let count = self.displayed_count();
                if count > 0 && self.packet_list.selected != count - 1 {
                    self.packet_list.selected = count - 1;
                    self.load_selected();
                    self.hex_dump.scroll_offset = 0;
                }
            }
            Pane::DetailTree => {
                let vis = self.visible_node_indices();
                if let Some(&last) = vis.last() {
                    self.detail_tree.selected = last;
                }
            }
            Pane::HexDump => {
                if let Some(raw) = self.selected_raw_bytes() {
                    let total_lines = raw.len().div_ceil(16);
                    self.hex_dump.scroll_offset = total_lines.saturating_sub(1);
                }
            }
            Pane::FilterInput | Pane::TreeSearch | Pane::YankPrompt | Pane::CommandMode => {}
        }
    }

    /// Returns the visible line count for the active pane, derived from the
    /// stored layout rectangles. Falls back to 20 when layout has not been
    /// computed yet (height == 0).
    fn page_size_for_pane(&self, pane: Pane) -> usize {
        let h = match pane {
            Pane::PacketList => self.pane_layout.packet_list.height,
            Pane::DetailTree => self.pane_layout.detail_tree.height,
            Pane::HexDump => self.pane_layout.hex_dump.height,
            _ => 0,
        };
        let size = h.saturating_sub(2) as usize;
        if size == 0 { 20 } else { size }
    }

    /// Returns the visible line count for the stream view overlay, derived
    /// from the stored frame area. Falls back to 20 when not yet computed.
    pub(super) fn stream_view_page_size(&self) -> usize {
        let h = self.pane_layout.frame_area.height.saturating_sub(2) as usize;
        if h == 0 { 20 } else { h }
    }

    fn page_down(&mut self) {
        let page_size = self.page_size_for_pane(self.active_pane);
        match self.active_pane {
            Pane::PacketList => {
                let count = self.displayed_count();
                if count > 0 {
                    let new_sel = (self.packet_list.selected + page_size).min(count - 1);
                    if new_sel != self.packet_list.selected {
                        self.packet_list.selected = new_sel;
                        self.load_selected();
                        self.hex_dump.scroll_offset = 0;
                    }
                }
            }
            Pane::DetailTree => {
                let vis = self.visible_node_indices();
                if let Some(pos) = self.tree_cursor_pos(&vis) {
                    let new_pos = (pos + page_size).min(vis.len().saturating_sub(1));
                    self.detail_tree.selected = vis[new_pos];
                }
            }
            Pane::HexDump => {
                if let Some(raw) = self.selected_raw_bytes() {
                    let max = raw.len().div_ceil(16).saturating_sub(1);
                    self.hex_dump.scroll_offset =
                        (self.hex_dump.scroll_offset + page_size).min(max);
                }
            }
            Pane::FilterInput | Pane::TreeSearch | Pane::YankPrompt | Pane::CommandMode => {}
        }
    }

    fn page_up(&mut self) {
        let page_size = self.page_size_for_pane(self.active_pane);
        match self.active_pane {
            Pane::PacketList => {
                if self.packet_list.selected > 0 {
                    let new_sel = self.packet_list.selected.saturating_sub(page_size);
                    if new_sel != self.packet_list.selected {
                        self.packet_list.selected = new_sel;
                        self.load_selected();
                        self.hex_dump.scroll_offset = 0;
                    }
                }
            }
            Pane::DetailTree => {
                let vis = self.visible_node_indices();
                if let Some(pos) = self.tree_cursor_pos(&vis) {
                    let new_pos = pos.saturating_sub(page_size);
                    self.detail_tree.selected = vis[new_pos];
                }
            }
            Pane::HexDump => {
                self.hex_dump.scroll_offset = self.hex_dump.scroll_offset.saturating_sub(page_size);
            }
            Pane::FilterInput | Pane::TreeSearch | Pane::YankPrompt | Pane::CommandMode => {}
        }
    }

    fn toggle_tree_node(&mut self) {
        if self.active_pane != Pane::DetailTree {
            return;
        }
        if let Some(sel) = &mut self.selected {
            let idx = self.detail_tree.selected;
            if idx < sel.tree_nodes.len() && sel.tree_nodes[idx].children_count > 0 {
                sel.tree_nodes[idx].expanded = !sel.tree_nodes[idx].expanded;
            }
        }
    }

    /// Toggle expand/collapse all tree nodes.
    ///
    /// If any node is expanded, collapse all. Otherwise, expand all.
    fn toggle_tree_expand_all(&mut self) {
        if let Some(sel) = &mut self.selected {
            let any_expanded = sel
                .tree_nodes
                .iter()
                .any(|n| n.expanded && n.children_count > 0);
            let target = !any_expanded;
            for node in &mut sel.tree_nodes {
                if node.children_count > 0 {
                    node.expanded = target;
                }
            }

            // After collapsing, ensure the cursor is on a visible node.
            if !target {
                let vis: Vec<usize> = visible_nodes(&sel.tree_nodes).map(|(i, _)| i).collect();
                if !vis.contains(&self.detail_tree.selected) {
                    // Move to the nearest visible ancestor (last visible node before selected).
                    self.detail_tree.selected = vis
                        .iter()
                        .rev()
                        .find(|&&i| i < self.detail_tree.selected)
                        .copied()
                        .unwrap_or(vis.first().copied().unwrap_or(0));
                }
            }
        }
    }

    /// In DetailTree: expand node or move into first child.
    fn tree_expand_or_enter(&mut self) {
        if self.active_pane != Pane::DetailTree {
            return;
        }
        if let Some(sel) = &mut self.selected {
            let idx = self.detail_tree.selected;
            if idx < sel.tree_nodes.len() && sel.tree_nodes[idx].children_count > 0 {
                if !sel.tree_nodes[idx].expanded {
                    sel.tree_nodes[idx].expanded = true;
                } else {
                    // Already expanded → move to first child (next node).
                    let vis = visible_nodes(&sel.tree_nodes)
                        .map(|(i, _)| i)
                        .collect::<Vec<_>>();
                    if let Some(pos) = vis.iter().position(|&i| i == idx)
                        && pos + 1 < vis.len()
                    {
                        self.detail_tree.selected = vis[pos + 1];
                    }
                }
            }
        }
    }

    /// In DetailTree: collapse node or move to parent.
    fn tree_collapse_or_parent(&mut self) {
        if self.active_pane != Pane::DetailTree {
            return;
        }
        if let Some(sel) = &mut self.selected {
            let idx = self.detail_tree.selected;
            if idx < sel.tree_nodes.len() {
                if sel.tree_nodes[idx].expanded && sel.tree_nodes[idx].children_count > 0 {
                    // Collapse current node.
                    sel.tree_nodes[idx].expanded = false;
                } else {
                    // Move to parent: find previous node with depth - 1.
                    let target_depth = sel.tree_nodes[idx].depth.saturating_sub(1);
                    if sel.tree_nodes[idx].depth > 0 {
                        let vis = visible_nodes(&sel.tree_nodes)
                            .map(|(i, _)| i)
                            .collect::<Vec<_>>();
                        if let Some(pos) = vis.iter().position(|&i| i == idx) {
                            for &vi in vis[..pos].iter().rev() {
                                if sel.tree_nodes[vi].depth == target_depth {
                                    self.detail_tree.selected = vi;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Adjust the active pane's height weight by `delta`.
    fn adjust_pane_weight(&mut self, delta: i16) {
        let pane_idx = match self.active_pane {
            Pane::PacketList => 0,
            Pane::DetailTree => 1,
            Pane::HexDump => 2,
            Pane::FilterInput | Pane::TreeSearch | Pane::YankPrompt | Pane::CommandMode => return,
        };

        let current = self.pane_weights[pane_idx] as i16;
        let new_weight = (current + delta).clamp(10, 80) as u16;
        let actual_delta = new_weight as i16 - current;

        if actual_delta == 0 {
            return;
        }

        self.pane_weights[pane_idx] = new_weight;

        // Distribute the change to the other two panes.
        let others: Vec<usize> = (0..3).filter(|&i| i != pane_idx).collect();
        let half = actual_delta / 2;
        let remainder = actual_delta - half;

        self.pane_weights[others[0]] =
            (self.pane_weights[others[0]] as i16 - half).clamp(10, 80) as u16;
        self.pane_weights[others[1]] =
            (self.pane_weights[others[1]] as i16 - remainder).clamp(10, 80) as u16;
    }

    /// Jump to a specific packet by 1-based number.
    fn jump_to_packet_number(&mut self, num_str: &str) {
        if let Ok(num) = num_str.parse::<usize>() {
            if num == 0 {
                return;
            }
            // num is 1-based global packet number → find in filtered_indices.
            let target_idx = num - 1; // 0-based index into `indices`
            if let Some(pos) = self.filtered_indices.iter().position(|&i| i == target_idx) {
                self.packet_list.selected = pos;
                self.load_selected();
            } else if target_idx < self.indices.len() {
                // Packet exists but not in current filter — jump to nearest.
                let nearest = self
                    .filtered_indices
                    .iter()
                    .enumerate()
                    .min_by_key(|&(_, &i)| (i as isize - target_idx as isize).unsigned_abs());
                if let Some((pos, _)) = nearest {
                    self.packet_list.selected = pos;
                    self.load_selected();
                }
            }
        }
    }
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use super::super::state::{StreamLine, StreamViewState};
    use super::super::test_util::make_test_app;
    use super::*;
    use crossterm::event::{
        KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };

    fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind,
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    #[test]
    fn mouse_scroll_moves_selection() {
        let mut app = make_test_app(5);
        app.handle_mouse(mouse(MouseEventKind::ScrollDown, 0, 0));
        assert_eq!(app.packet_list.selected, 1);
        app.handle_mouse(mouse(MouseEventKind::ScrollDown, 0, 0));
        assert_eq!(app.packet_list.selected, 2);
        app.handle_mouse(mouse(MouseEventKind::ScrollUp, 0, 0));
        assert_eq!(app.packet_list.selected, 1);
    }

    #[test]
    fn mouse_click_selects_row() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let mut app = make_test_app(10);
        // Render once so pane_layout is populated for hit-testing.
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| super::super::ui::render(f, &mut app))
            .unwrap();

        let area = app.pane_layout.packet_list;
        // Click 4 rows inside the packet list (area.y + 1 is the first row).
        let target_row = area.y + 1 + 3;
        app.handle_mouse(mouse(
            MouseEventKind::Down(MouseButton::Left),
            area.x + 2,
            target_row,
        ));
        assert_eq!(app.active_pane, Pane::PacketList);
        assert_eq!(app.packet_list.selected, 3);
    }

    #[test]
    fn on_resize_clamps_offsets() {
        let mut app = make_test_app(3);
        app.packet_list.scroll_offset = 999;
        app.detail_tree.scroll_offset = 999;
        app.hex_dump.scroll_offset = 999;
        app.on_resize();
        assert!(app.packet_list.scroll_offset < app.displayed_count());
        // pane_layout is invalidated to default (all-zero rects).
        assert_eq!(app.pane_layout.packet_list.width, 0);
    }

    #[test]
    fn command_stats_starts_stats_progress() {
        let mut app = make_test_app(3);
        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        for c in "stats".chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));
        assert!(app.stats_progress.is_some());
    }

    #[test]
    fn command_wq_saves_and_quits() {
        let mut app = make_test_app(2);
        let path = std::env::temp_dir().join(format!(
            "dsct_keys_wq_{}_{}.pcap",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let path_str = path.display().to_string();

        app.handle_key(KeyEvent::new(KeyCode::Char(':'), KeyModifiers::NONE));
        for c in format!("wq {path_str}").chars() {
            app.handle_key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE));
        }
        app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE));

        assert!(!app.running);
        assert!(path.exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stream_view_navigation_keys() {
        let mut app = make_test_app(1);
        app.stream_view = Some(StreamViewState {
            lines: (0..10)
                .map(|i| StreamLine {
                    text: format!("line {i}"),
                    is_client: i % 2 == 0,
                })
                .collect(),
            scroll_offset: 0,
            title: "test".into(),
        });

        app.handle_key(KeyEvent::new(KeyCode::Char('j'), KeyModifiers::NONE));
        assert_eq!(app.stream_view.as_ref().unwrap().scroll_offset, 1);

        app.handle_key(KeyEvent::new(KeyCode::Char('G'), KeyModifiers::NONE));
        assert_eq!(app.stream_view.as_ref().unwrap().scroll_offset, 9);

        app.handle_key(KeyEvent::new(KeyCode::Char('k'), KeyModifiers::NONE));
        assert_eq!(app.stream_view.as_ref().unwrap().scroll_offset, 8);

        app.handle_key(KeyEvent::new(KeyCode::Char('g'), KeyModifiers::NONE));
        assert_eq!(app.stream_view.as_ref().unwrap().scroll_offset, 0);

        app.handle_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        assert!(app.stream_view.is_none());
    }
}
