//! dsct desktop GUI: explore a pcap/pcapng capture with a packet table, a
//! protocol detail tree, and a hex dump, on top of `dsct::session`.

mod app;
mod format;
mod packet_table;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use dsct::session::Session;
use gpui_kit::*;

use crate::app::DsctApp;

/// The open capture, shared by the window and the packet table.
pub type SharedSession = Rc<RefCell<Option<Session>>>;

actions!(dsct_gui, [Open, Quit]);

fn main() {
    // `dsct-gui [FILE]`; macOS passes `-psn_*` when launched from Finder.
    let path = std::env::args_os()
        .skip(1)
        .find(|a| !a.to_string_lossy().starts_with("-psn_"))
        .map(PathBuf::from);

    gpui_kit::application().run(move |cx| {
        gpui_kit::init(cx);

        #[cfg(target_os = "macos")]
        cx.bind_keys([
            KeyBinding::new("cmd-o", Open, None),
            KeyBinding::new("cmd-q", Quit, None),
        ]);
        #[cfg(not(target_os = "macos"))]
        cx.bind_keys([
            KeyBinding::new("ctrl-o", Open, None),
            KeyBinding::new("ctrl-q", Quit, None),
        ]);
        cx.on_action(|_: &Quit, cx| cx.quit());
        cx.set_menus(vec![
            Menu {
                name: "dsct".into(),
                items: vec![MenuItem::action("Quit dsct", Quit)],
                disabled: false,
            },
            Menu {
                name: "File".into(),
                items: vec![MenuItem::action("Open…", Open)],
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
