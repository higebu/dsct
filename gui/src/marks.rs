//! Marking packets, and saving the displayed or the marked packets as a
//! pcapng file.

use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};

use gpui_kit::*;

use crate::app::DsctApp;

/// Which packets to save.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportSet {
    Displayed,
    Marked,
}

impl ExportSet {
    fn suffix(self) -> &'static str {
        match self {
            Self::Displayed => "displayed",
            Self::Marked => "marked",
        }
    }
}

/// The file name offered for saving `set` of the capture `file_name`
/// (`"capture-marked.pcapng"`).
pub fn suggested_name(file_name: &str, set: ExportSet) -> String {
    let stem = Path::new(file_name)
        .file_stem()
        .map_or("capture".into(), |s| s.to_string_lossy());
    format!("{stem}-{}.pcapng", set.suffix())
}

impl DsctApp {
    /// Mark the selected packet, or unmark it.
    pub(crate) fn toggle_mark(&mut self, cx: &mut Context<Self>) {
        let marked = self.selected_row.and_then(|row| {
            let mut guard = self.session.borrow_mut();
            let session = guard.as_mut()?;
            let pkt_idx = session.filtered.select(row)?;
            Some(session.toggle_mark(pkt_idx))
        });
        if marked.is_some() {
            self.refresh_table(cx);
            cx.notify();
        }
    }

    /// Ask where to save `set` of the active capture, then write it.
    pub(crate) fn export_packets(
        &mut self,
        set: ExportSet,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let Some((packets, dir, name)) = self.session.borrow().as_ref().map(|s| {
            let packets: Vec<usize> = match set {
                ExportSet::Displayed => s.filtered.iter_from(0).collect(),
                ExportSet::Marked => s.marked().collect(),
            };
            let dir = s
                .capture_path
                .as_deref()
                .and_then(Path::parent)
                .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
            (packets, dir, suggested_name(&s.file_name, set))
        }) else {
            return;
        };
        if packets.is_empty() {
            self.message = Some((
                match set {
                    ExportSet::Displayed => "No packets are displayed.".to_string(),
                    ExportSet::Marked => {
                        format!(
                            "No packets are marked ({} marks one).",
                            crate::shortcut("M")
                        )
                    }
                },
                true,
            ));
            cx.notify();
            return;
        }
        let path = cx.prompt_for_new_path(&dir, Some(&name));
        cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(path))) = path.await else {
                return;
            };
            let _ = this.update_in(cx, |app, _, cx| {
                let result = app.session.borrow().as_ref().map(|s| {
                    let file = std::fs::File::create(&path)?;
                    let mut out = BufWriter::new(file);
                    let written = s.write_pcapng(&packets, &mut out)?;
                    out.flush()?;
                    Ok::<usize, std::io::Error>(written)
                });
                app.message = match result {
                    Some(Ok(n)) => {
                        Some((format!("Saved {n} packets to {}", path.display()), false))
                    }
                    Some(Err(e)) => Some((format!("Could not save {}: {e}", path.display()), true)),
                    None => None,
                };
                cx.notify();
            });
        })
        .detach();
    }
}

#[cfg(test)]
mod tests {
    use super::{ExportSet, suggested_name};

    #[test]
    fn saved_files_are_named_after_the_capture() {
        assert_eq!(
            suggested_name("ims.pcap", ExportSet::Marked),
            "ims-marked.pcapng"
        );
        assert_eq!(
            suggested_name("a.b.pcapng", ExportSet::Displayed),
            "a.b-displayed.pcapng"
        );
        assert_eq!(
            suggested_name("", ExportSet::Marked),
            "capture-marked.pcapng"
        );
    }
}
