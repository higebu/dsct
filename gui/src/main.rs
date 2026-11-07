//! dsct desktop GUI: explore a pcap/pcapng capture with a packet table, a
//! protocol detail tree, and a hex dump, on top of `dsct::session`.

mod app;
mod bottom;
mod decode_as;
mod fields_view;
mod format;
mod packet_table;
mod palette;
mod panes;
mod sidebar;
mod summary;
mod tabs;
mod theme;
mod timeline;
mod tree_nav;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use dsct::session::Session;
use gpui_kit::component::TitleBar;
use gpui_kit::*;

use crate::app::{DsctApp, HEX_CONTEXT, TABLE_CONTEXT, TREE_CONTEXT};
use crate::decode_as::{CloseDecodeAs, DecodeAsDown, DecodeAsUp};
use crate::palette::{ClosePalette, PaletteDown, PaletteUp};

/// The open capture, shared by the window and the packet table.
pub type SharedSession = Rc<RefCell<Option<Session>>>;

actions!(
    dsct_gui,
    [
        Open,
        Quit,
        OpenPalette,
        FollowStream,
        ShowStats,
        ToggleDock,
        ToggleSidebar,
        CycleTimeFormat,
        CloseBottom,
        FocusNextPane,
        FocusPrevPane,
        FocusPackets,
        FocusDetails,
        FocusBytes,
        SelectPrev,
        SelectNext,
        Expand,
        Collapse,
        ToggleNode,
        CloseTab,
        NextTab,
        PrevTab,
    ]
);

/// `mac` on macOS, `other` elsewhere: the platform's command modifier in
/// GPUI key binding syntax.
const fn platform_key(mac: &'static str, other: &'static str) -> &'static str {
    if cfg!(target_os = "macos") {
        mac
    } else {
        other
    }
}

/// How the shortcut `modifier + key` is written for the user.
pub fn shortcut(key: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("⌘{key}")
    } else {
        format!("Ctrl+{key}")
    }
}

/// How the shortcut `shift + modifier + key` is written for the user.
pub fn shortcut_shift(key: &str) -> String {
    if cfg!(target_os = "macos") {
        format!("⇧⌘{key}")
    } else {
        format!("Ctrl+Shift+{key}")
    }
}

/// Bind the application's keys.
fn bind_keys(cx: &mut App) {
    let mut bindings = vec![
        KeyBinding::new(platform_key("cmd-o", "ctrl-o"), Open, None),
        KeyBinding::new(platform_key("cmd-q", "ctrl-q"), Quit, None),
        KeyBinding::new(platform_key("cmd-k", "ctrl-k"), OpenPalette, None),
        KeyBinding::new(
            platform_key("cmd-shift-p", "ctrl-shift-p"),
            OpenPalette,
            None,
        ),
        KeyBinding::new(
            platform_key("cmd-shift-f", "ctrl-shift-f"),
            FollowStream,
            None,
        ),
        KeyBinding::new(platform_key("cmd-shift-s", "ctrl-shift-s"), ShowStats, None),
        KeyBinding::new(platform_key("cmd-j", "ctrl-j"), ToggleDock, None),
        KeyBinding::new(platform_key("cmd-b", "ctrl-b"), ToggleSidebar, None),
        KeyBinding::new(platform_key("cmd-t", "ctrl-t"), CycleTimeFormat, None),
        KeyBinding::new(platform_key("cmd-w", "ctrl-w"), CloseTab, None),
        KeyBinding::new("ctrl-tab", NextTab, None),
        KeyBinding::new("ctrl-shift-tab", PrevTab, None),
        KeyBinding::new(platform_key("cmd-shift-]", "ctrl-pagedown"), NextTab, None),
        KeyBinding::new(platform_key("cmd-shift-[", "ctrl-pageup"), PrevTab, None),
        KeyBinding::new(platform_key("cmd-1", "ctrl-1"), FocusPackets, None),
        KeyBinding::new(platform_key("cmd-2", "ctrl-2"), FocusDetails, None),
        KeyBinding::new(platform_key("cmd-3", "ctrl-3"), FocusBytes, None),
        KeyBinding::new("up", SelectPrev, Some(TREE_CONTEXT)),
        KeyBinding::new("down", SelectNext, Some(TREE_CONTEXT)),
        KeyBinding::new("left", Collapse, Some(TREE_CONTEXT)),
        KeyBinding::new("right", Expand, Some(TREE_CONTEXT)),
        KeyBinding::new("enter", ToggleNode, Some(TREE_CONTEXT)),
        KeyBinding::new("space", ToggleNode, Some(TREE_CONTEXT)),
        KeyBinding::new("up", SelectPrev, Some(HEX_CONTEXT)),
        KeyBinding::new("down", SelectNext, Some(HEX_CONTEXT)),
        KeyBinding::new("left", Collapse, Some(HEX_CONTEXT)),
        KeyBinding::new("right", Expand, Some(HEX_CONTEXT)),
    ];
    // Tab moves between panes; in the table this replaces moving between
    // cells, which row selection does not use. Bound after gpui-component's
    // own bindings, so these win.
    for context in [TABLE_CONTEXT, TREE_CONTEXT, HEX_CONTEXT] {
        bindings.push(KeyBinding::new("tab", FocusNextPane, Some(context)));
        bindings.push(KeyBinding::new("shift-tab", FocusPrevPane, Some(context)));
        bindings.push(KeyBinding::new("escape", CloseBottom, Some(context)));
    }
    // In the palette's input, arrows move the selection and Escape closes
    // it (instead of the input's own handling of those keys).
    // (`CommandPalette` is `palette::PALETTE_CONTEXT`.)
    let palette_input = "CommandPalette > Input";
    bindings.push(KeyBinding::new("up", PaletteUp, Some(palette_input)));
    bindings.push(KeyBinding::new("down", PaletteDown, Some(palette_input)));
    bindings.push(KeyBinding::new("escape", ClosePalette, Some(palette_input)));
    let decode_input = "DecodeAs > Input";
    bindings.push(KeyBinding::new("up", DecodeAsUp, Some(decode_input)));
    bindings.push(KeyBinding::new("down", DecodeAsDown, Some(decode_input)));
    bindings.push(KeyBinding::new("escape", CloseDecodeAs, Some(decode_input)));
    cx.bind_keys(bindings);
}

fn main() {
    // `dsct-gui [FILE]...`, each in a tab; macOS passes `-psn_*` when
    // launched from Finder.
    let paths: Vec<PathBuf> = std::env::args_os()
        .skip(1)
        .filter(|a| !a.to_string_lossy().starts_with("-psn_"))
        .map(PathBuf::from)
        .collect();

    // Register the icon catalog (filter, clock, chart, chevrons, …).
    gpui_kit::application()
        .with_assets(gpui_kit::assets::AllAssets)
        .run(move |cx| {
            gpui_kit::init(cx);
            theme::apply(cx);

            bind_keys(cx);
            cx.on_action(|_: &Quit, cx| cx.quit());
            cx.set_menus(vec![
                Menu {
                    name: "dsct".into(),
                    items: vec![MenuItem::action("Quit dsct", Quit)],
                    disabled: false,
                },
                Menu {
                    name: "File".into(),
                    items: vec![
                        MenuItem::action("Open…", Open),
                        MenuItem::action("Close Tab", CloseTab),
                        MenuItem::separator(),
                        MenuItem::action("Command Palette…", OpenPalette),
                    ],
                    disabled: false,
                },
                Menu {
                    name: "View".into(),
                    items: vec![
                        MenuItem::action("Toggle Sidebar", ToggleSidebar),
                        MenuItem::action("Toggle Bottom Dock", ToggleDock),
                        MenuItem::action("Change Time Format", CycleTimeFormat),
                        MenuItem::action("Next Tab", NextTab),
                        MenuItem::action("Previous Tab", PrevTab),
                        MenuItem::separator(),
                        MenuItem::action("Follow Stream", FollowStream),
                        MenuItem::action("Stats", ShowStats),
                    ],
                    disabled: false,
                },
            ]);

            let bounds = Bounds::centered(None, size(px(1280.), px(860.)), cx);
            // The window draws its own title bar (TitleBar in the view).
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                ..TitleBar::window_options()
            };
            let opened = gpui_kit::open_window(options, cx, |window, cx| {
                cx.new(|cx| DsctApp::new(paths, window, cx))
            });
            if let Err(e) = opened {
                eprintln!("dsct-gui: cannot open a window: {e}");
                cx.quit();
                return;
            }
            cx.on_window_closed(|cx, _| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
            cx.activate(true);
        });
}
