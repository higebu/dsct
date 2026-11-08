//! Highlighting the sequence of the selected packet: the packets of its
//! call, stream or host pair stay bright and the others are dimmed (see
//! `dsct::session::sequence`).

use dsct::session::sequence::{SequenceKeys, SequenceUnit};
use gpui_kit::assets::IconName as AssetIcon;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};
use gpui_kit::component::{Icon, Sizable as _, h_flex};
use gpui_kit::*;

use crate::app::DsctApp;
use crate::theme;

/// Characters of a sequence name shown on its button at most.
const MAX_LABEL: usize = 56;

/// Whether sequences are highlighted, and at which grain.
pub struct SequenceView {
    pub on: bool,
    /// The grain preferred; a packet without it uses the next coarser one.
    pub unit: SequenceUnit,
    /// The sequences the selected packet belongs to.
    pub keys: Option<SequenceKeys>,
}

impl Default for SequenceView {
    fn default() -> Self {
        Self {
            on: true,
            unit: SequenceUnit::Call,
            keys: None,
        }
    }
}

/// `label` cut to [`MAX_LABEL`] characters.
fn short(label: &str) -> String {
    if label.chars().count() > MAX_LABEL {
        let cut: String = label.chars().take(MAX_LABEL - 1).collect();
        format!("{cut}…")
    } else {
        label.to_string()
    }
}

impl DsctApp {
    /// Highlight the sequence of the selected packet (or nothing).
    pub(crate) fn update_sequence(&mut self, cx: &mut Context<Self>) {
        let mut guard = self.session.borrow_mut();
        let Some(session) = guard.as_mut() else {
            return;
        };
        let keys = if self.sequence.on {
            self.selected_row
                .and_then(|row| session.filtered.select(row))
                .and_then(|pkt_idx| session.sequence_keys(pkt_idx))
        } else {
            None
        };
        let key = keys
            .as_ref()
            .and_then(|k| k.at_or_coarser(self.sequence.unit))
            .cloned();
        match key {
            Some(key) if session.sequence().map(|s| &s.key) != Some(&key) => {
                session.start_sequence(key);
            }
            Some(_) => {}
            None => session.clear_sequence(),
        }
        self.sequence.keys = keys;
        drop(guard);
        self.refresh_table(cx);
        self.ensure_ticking(cx);
        cx.notify();
    }

    /// Redraw the table's rows (their dimming changed).
    pub(crate) fn refresh_table(&mut self, cx: &mut Context<Self>) {
        self.table.update(cx, |_, cx| cx.notify());
    }

    /// Group packets at `unit` from now on.
    pub(crate) fn set_sequence_unit(&mut self, unit: SequenceUnit, cx: &mut Context<Self>) {
        self.sequence.unit = unit;
        self.sequence.on = true;
        self.update_sequence(cx);
    }

    /// Turn the highlighting of sequences on or off.
    pub(crate) fn set_sequence_on(&mut self, on: bool, cx: &mut Context<Self>) {
        self.sequence.on = on;
        self.update_sequence(cx);
    }

    /// Select the sequence's next (`forward`) or previous packet.
    fn step_sequence(&mut self, forward: bool, cx: &mut Context<Self>) {
        let row = self.selected_row.and_then(|row| {
            self.session
                .borrow()
                .as_ref()
                .and_then(|s| s.sequence_step(row, forward))
        });
        if let Some(row) = row {
            self.select_row(row, cx);
            self.sync_table_selection(cx);
            self.table
                .update(cx, |table, cx| table.scroll_to_row(row, cx));
        }
    }

    /// Show only the sequence's packets, within the current filter.
    fn show_sequence_only(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.session.borrow().as_ref().and_then(|s| {
            let filter = s.sequence()?.key.filter();
            let current = s.applied_filter.trim();
            Some(if current.is_empty() {
                filter
            } else {
                format!("({current}) and ({filter})")
            })
        });
        if let Some(text) = text {
            self.set_filter(&text, window, cx);
        }
    }

    /// The bar under the filter naming the highlighted sequence.
    pub(crate) fn render_sequence_bar(&self, cx: &mut Context<Self>) -> Option<AnyElement> {
        if !self.sequence.on {
            return None;
        }
        let guard = self.session.borrow();
        let session = guard.as_ref()?;
        let scan = session.sequence()?;
        let key = scan.key.clone();
        let count = scan.members.len();
        let more = if scan.complete(session.displayed_count()) {
            ""
        } else {
            "+"
        };
        drop(guard);

        let weak = cx.entity().downgrade();
        let keys = self.sequence.keys.clone().unwrap_or_default();
        let current = key.clone();
        let units = Button::new("sequence-unit")
            .label(short(&key.label()))
            .xsmall()
            .outline()
            .tooltip("Group packets by call, stream or hosts")
            .dropdown_menu(move |mut menu, _, _| {
                menu = menu.item(PopupMenuItem::label("GROUP BY"));
                for unit in SequenceUnit::ALL {
                    let Some(k) = keys.get(unit) else {
                        continue;
                    };
                    let weak = weak.clone();
                    menu = menu.item(
                        PopupMenuItem::new(short(&k.label()))
                            .checked(*k == current)
                            .on_click(move |_, _, cx| {
                                let _ = weak.update(cx, |app, cx| app.set_sequence_unit(unit, cx));
                            }),
                    );
                }
                menu
            });
        let icon_button = |id: &'static str, icon: AssetIcon, tip: &'static str| {
            Button::new(id)
                .icon(Icon::new(icon))
                .xsmall()
                .ghost()
                .tooltip(tip)
        };
        Some(
            h_flex()
                .flex_shrink_0()
                .flex_wrap()
                .gap_2()
                .px_3()
                .py_1()
                .border_t_1()
                .border_color(theme::border())
                .bg(theme::accent().opacity(0.06))
                .text_sm()
                .child(
                    Icon::new(AssetIcon::Rows3)
                        .xsmall()
                        .text_color(theme::accent()),
                )
                .child(div().text_color(theme::text_muted()).child("Sequence"))
                .child(units)
                .child(div().text_color(theme::text_muted()).child(format!(
                    "{count}{more} {}",
                    if count == 1 && more.is_empty() {
                        "packet"
                    } else {
                        "packets"
                    }
                )))
                .child(div().flex_1())
                .child(
                    icon_button(
                        "sequence-prev",
                        AssetIcon::ChevronLeft,
                        "Previous packet in the sequence",
                    )
                    .on_click(cx.listener(|this, _, _, cx| this.step_sequence(false, cx))),
                )
                .child(
                    icon_button(
                        "sequence-next",
                        AssetIcon::ChevronRight,
                        "Next packet in the sequence",
                    )
                    .on_click(cx.listener(|this, _, _, cx| this.step_sequence(true, cx))),
                )
                .child(
                    Button::new("sequence-only")
                        .label("Only these")
                        .xsmall()
                        .outline()
                        .tooltip(format!("Filter: {}", key.filter()))
                        .on_click(
                            cx.listener(|this, _, window, cx| this.show_sequence_only(window, cx)),
                        ),
                )
                .child(
                    icon_button("sequence-off", AssetIcon::X, "Stop highlighting sequences")
                        .on_click(cx.listener(|this, _, _, cx| this.set_sequence_on(false, cx))),
                )
                .into_any_element(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::short;

    #[test]
    fn long_names_are_cut() {
        assert_eq!(short("TCP stream 3"), "TCP stream 3");
        let long = "x".repeat(80);
        let cut = short(&long);
        assert_eq!(cut.chars().count(), 56);
        assert!(cut.ends_with('…'));
    }
}
