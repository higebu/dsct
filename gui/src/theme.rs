//! The app's dark, editor-style theme: one palette applied to the
//! gpui-component theme, plus the colors views use directly.

use gpui_kit::component::{Theme, ThemeMode};
use gpui_kit::{App, Hsla, rgb};

/// A palette color.
fn c(hex: u32) -> Hsla {
    rgb(hex).into()
}

/// Window chrome: title bar, status bar.
pub fn chrome() -> Hsla {
    c(0x121418)
}
/// Sidebar and dock panels.
pub fn panel() -> Hsla {
    c(0x16191e)
}
/// The main content surface.
pub fn surface() -> Hsla {
    c(0x1a1d23)
}
/// Popovers and the command palette.
pub fn elevated() -> Hsla {
    c(0x1d2027)
}
/// Hairline separators.
pub fn border() -> Hsla {
    c(0x262a31)
}
/// Input and button outlines.
pub fn border_strong() -> Hsla {
    c(0x2f343d)
}
/// Body text.
pub fn text() -> Hsla {
    c(0xd7dbe2)
}
/// Emphasized text (selection, headings).
pub fn text_bright() -> Hsla {
    c(0xe6e9ef)
}
/// Secondary text: labels, counts. 5.4:1 on the surface.
pub fn text_muted() -> Hsla {
    c(0x8e96a3)
}
/// De-emphasized data (zero bytes, offsets, `=`): dimmer than muted text
/// but still 4.7:1 on the surface, since it is read too.
pub fn text_faint() -> Hsla {
    c(0x808896)
}
/// The accent: focus, selection, active tab.
pub fn accent() -> Hsla {
    c(0x6ea8fe)
}
/// Selected rows, nodes, and bytes.
pub fn selection() -> Hsla {
    accent().opacity(0.18)
}
/// Drop target while a file is dragged over the window.
pub fn drop_target() -> Hsla {
    accent().opacity(0.12)
}
/// Hover over rows.
pub fn hover() -> Hsla {
    c(0xffffff).opacity(0.035)
}

/// Syntax colors, also used for protocols and value types.
pub fn teal() -> Hsla {
    c(0x5ccfe6)
}
pub fn purple() -> Hsla {
    c(0xc39af5)
}
pub fn green() -> Hsla {
    c(0x8bd49c)
}
pub fn orange() -> Hsla {
    c(0xf0a45d)
}
pub fn blue() -> Hsla {
    c(0x73b8ff)
}
pub fn yellow() -> Hsla {
    c(0xe5c07b)
}
pub fn red() -> Hsla {
    c(0xf07178)
}

/// Switch gpui-component to the dark mode and paint it with the palette.
pub fn apply(cx: &mut App) {
    Theme::change(ThemeMode::Dark, None, cx);
    Theme::update(cx, |t| {
        t.background = surface();
        t.foreground = text();
        t.border = border();
        t.muted = panel();
        t.muted_foreground = text_muted();
        t.input = border_strong();
        t.ring = accent();
        t.caret = accent();
        t.selection = accent().opacity(0.3);
        t.accent = c(0x20242b);
        t.accent_foreground = text_bright();
        t.primary = accent();
        t.primary_hover = c(0x86b6fe);
        t.primary_active = c(0x5b97f0);
        t.primary_foreground = c(0x0b1220);
        t.secondary = c(0x20242b);
        t.secondary_hover = c(0x262a32);
        t.secondary_active = c(0x2b3039);
        t.secondary_foreground = text();
        t.danger = red();
        t.red = red();
        t.blue = blue();
        t.green = green();
        t.popover = elevated();
        t.popover_foreground = text();
        t.colors.list = surface();
        t.list_hover = hover();
        t.list_active = selection();
        t.list_active_border = accent();
        t.table = surface();
        t.table_head = surface();
        t.table_head_foreground = text_muted();
        t.table_even = surface();
        t.table_hover = hover();
        t.table_active = selection();
        t.table_active_border = accent();
        t.table_row_border = c(0x1f2329);
        t.title_bar = chrome();
        t.title_bar_border = border();
        t.status_bar = chrome();
        t.status_bar_border = border();
        t.tab_bar = panel();
        t.tab = panel();
        t.tab_active = surface();
        t.tab_foreground = text_muted();
        t.tab_active_foreground = text_bright();
        t.scrollbar = c(0x000000).opacity(0.0);
        t.scrollbar_thumb = c(0xffffff).opacity(0.12);
        t.scrollbar_thumb_hover = c(0xffffff).opacity(0.2);
        t.drop_target = accent().opacity(0.12);
        t.overlay = c(0x08090b).opacity(0.55);
        t.window_border = border();
    });
}

/// The color of a protocol swatch.
pub fn swatch(swatch: crate::format::Swatch) -> Hsla {
    use crate::format::Swatch;
    match swatch {
        Swatch::Teal => teal(),
        Swatch::Purple => purple(),
        Swatch::Green => green(),
        Swatch::Orange => orange(),
        Swatch::Blue => blue(),
        Swatch::Yellow => yellow(),
        Swatch::Red => red(),
    }
}

/// The color of a detail tree value of this kind.
pub fn value(kind: crate::format::ValueKind) -> Hsla {
    use crate::format::ValueKind;
    match kind {
        ValueKind::Number => orange(),
        ValueKind::Bool => purple(),
        ValueKind::Address => teal(),
        ValueKind::Muted => text_muted(),
        ValueKind::Text => green(),
    }
}
