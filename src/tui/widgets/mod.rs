//! TUI widget modules.

pub mod command_line;
pub mod detail_tree;
pub mod hex_dump;
pub mod packet_list;
pub mod status_bar;
pub mod stream_view;

#[cfg(all(test, feature = "tui"))]
mod tests {
    // This file only re-exports submodules; behavior tests live in each
    // submodule's own `mod tests` block.
    #[test]
    fn module_compiles() {}
}
