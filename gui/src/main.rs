//! dsct desktop GUI: explore a pcap/pcapng capture with a packet table, a
//! protocol detail tree, and a hex dump, on top of `dsct::session`.

mod app;
mod bottom;
mod format;
mod packet_table;
mod panes;
mod tree_nav;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use dsct::session::Session;
use gpui_kit::component::Theme;
use gpui_kit::*;

use crate::app::{DsctApp, HEX_CONTEXT, TABLE_CONTEXT, TREE_CONTEXT};

/// The open capture, shared by the window and the packet table.
pub type SharedSession = Rc<RefCell<Option<Session>>>;

actions!(
    dsct_gui,
    [
        Open,
        Quit,
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

/// Bind the application's keys.
fn bind_keys(cx: &mut App) {
    let mut bindings = vec![
        KeyBinding::new(platform_key("cmd-o", "ctrl-o"), Open, None),
        KeyBinding::new(platform_key("cmd-q", "ctrl-q"), Quit, None),
        KeyBinding::new(platform_key("cmd-t", "ctrl-t"), CycleTimeFormat, None),
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
    cx.bind_keys(bindings);
}

fn main() {
    // `dsct-gui [FILE]`; macOS passes `-psn_*` when launched from Finder.
    let path = std::env::args_os()
        .skip(1)
        .find(|a| !a.to_string_lossy().starts_with("-psn_"))
        .map(PathBuf::from);

    // Register the bundled icons (close, copy, chevrons, …).
    gpui_kit::application()
        .with_assets(gpui_kit::assets::Assets)
        .run(move |cx| {
            gpui_kit::init(cx);
            // The selected packet row must stand out from the protocol tints.
            Theme::update(cx, |theme| {
                theme.table_active = theme.blue.opacity(panes::SELECTION_ALPHA);
                theme.table_active_border = theme.blue;
            });

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
                        MenuItem::separator(),
                        MenuItem::action("Change Time Format", CycleTimeFormat),
                    ],
                    disabled: false,
                },
            ]);

            let bounds = Bounds::centered(None, size(px(1280.), px(860.)), cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(bounds)),
                titlebar: Some(TitlebarOptions {
                    title: Some("dsct".into()),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let opened = gpui_kit::open_window(options, cx, |window, cx| {
                cx.new(|cx| DsctApp::new(path, window, cx))
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
