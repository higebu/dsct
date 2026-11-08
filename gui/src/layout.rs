//! Where the panes go: details below the packet list or to its right,
//! whether the Bytes pane is open, and the sizes the user dragged them to,
//! kept across runs in `$XDG_CONFIG_HOME/dsct/gui.json` (or
//! `~/.config/dsct/gui.json`).

use std::path::PathBuf;
use std::time::Duration;

use gpui_kit::*;
use serde_json::{Value, json};

use crate::app::DsctApp;

/// Height of the packet list (details below) by default.
const LIST_SIZE: f32 = 360.;
/// Width of the details (details to the right) by default.
const DETAILS_SIZE: f32 = 480.;
/// Smallest size kept for a pane, so a stored size never hides it.
const MIN_SIZE: f32 = 120.;
/// How long after the last resize the layout is saved.
const SAVE_DELAY: Duration = Duration::from_millis(800);

/// The panes' arrangement.
#[derive(Debug, Clone, PartialEq)]
pub struct Layout {
    /// Details to the right of the packet list instead of below it.
    pub details_right: bool,
    /// Whether the Bytes pane is shown beside the details.
    pub bytes_open: bool,
    /// Height of the packet list, details below.
    pub list_size: f32,
    /// Width of the details, details to the right.
    pub details_size: f32,
}

impl Default for Layout {
    fn default() -> Self {
        Self {
            details_right: false,
            bytes_open: false,
            list_size: LIST_SIZE,
            details_size: DETAILS_SIZE,
        }
    }
}

impl Layout {
    /// The layout saved by an earlier run, or the default one.
    pub fn load() -> Self {
        path()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map_or_else(Self::default, |text| Self::from_json(&text))
    }

    /// Read a saved layout; missing or invalid keys keep their default.
    pub fn from_json(text: &str) -> Self {
        let mut layout = Self::default();
        let Ok(v) = serde_json::from_str::<Value>(text) else {
            return layout;
        };
        if let Some(b) = v.get("details_right").and_then(Value::as_bool) {
            layout.details_right = b;
        }
        if let Some(b) = v.get("bytes_open").and_then(Value::as_bool) {
            layout.bytes_open = b;
        }
        let size = |key: &str| {
            v.get(key)
                .and_then(Value::as_f64)
                .map(|s| (s as f32).max(MIN_SIZE))
        };
        if let Some(s) = size("list_size") {
            layout.list_size = s;
        }
        if let Some(s) = size("details_size") {
            layout.details_size = s;
        }
        layout
    }

    pub fn to_json(&self) -> String {
        json!({
            "details_right": self.details_right,
            "bytes_open": self.bytes_open,
            "list_size": self.list_size,
            "details_size": self.details_size,
        })
        .to_string()
    }

    fn save(&self) {
        let Some(path) = path() else {
            return;
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        // The layout is a convenience: a failed save keeps the old one.
        let _ = std::fs::write(path, self.to_json());
    }
}

/// Where the layout is saved.
fn path() -> Option<PathBuf> {
    let dir = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
    Some(dir.join("dsct").join("gui.json"))
}

impl DsctApp {
    /// Save the layout a moment after the last change (a drag resizes many
    /// times).
    pub(crate) fn save_layout_soon(&mut self, cx: &mut Context<Self>) {
        self.layout_generation += 1;
        let generation = self.layout_generation;
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(SAVE_DELAY).await;
            let _ = this.update(cx, |app, _| {
                if app.layout_generation == generation {
                    app.layout.save();
                }
            });
        })
        .detach();
    }

    /// The packet list was resized to `size` (height, or width of the
    /// details when they are on the right).
    pub(crate) fn layout_resized(&mut self, size: f32, cx: &mut Context<Self>) {
        let size = size.max(MIN_SIZE);
        let stored = if self.layout.details_right {
            &mut self.layout.details_size
        } else {
            &mut self.layout.list_size
        };
        if (*stored - size).abs() >= 1. {
            *stored = size;
            self.save_layout_soon(cx);
        }
    }

    /// Show or hide the Bytes pane.
    pub(crate) fn toggle_bytes(&mut self, cx: &mut Context<Self>) {
        self.layout.bytes_open = !self.layout.bytes_open;
        self.save_layout_soon(cx);
        cx.notify();
    }

    /// Put the details to the right of the packet list, or below it.
    pub(crate) fn toggle_details_side(&mut self, cx: &mut Context<Self>) {
        self.layout.details_right = !self.layout.details_right;
        self.save_layout_soon(cx);
        cx.notify();
    }
}

#[cfg(test)]
mod tests {
    use super::Layout;

    #[test]
    fn a_saved_layout_reads_back() {
        let layout = Layout {
            details_right: true,
            bytes_open: true,
            list_size: 300.,
            details_size: 520.,
        };
        assert_eq!(Layout::from_json(&layout.to_json()), layout);
    }

    #[test]
    fn missing_or_bad_keys_keep_their_default() {
        assert_eq!(Layout::from_json("not json"), Layout::default());
        let partial = Layout::from_json(r#"{"bytes_open": true, "list_size": 5}"#);
        assert!(partial.bytes_open);
        assert!(!partial.details_right);
        // Too small to see: the smallest size kept.
        assert_eq!(partial.list_size, 120.);
        assert_eq!(partial.details_size, Layout::default().details_size);
    }
}
