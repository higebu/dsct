//! The fields sidebar: the values the displayed packets' fields take,
//! counted over a sample, with pinned and key fields first and every
//! field by stack position and protocol. Each value filters for or out,
//! and each field can become a column or split the chart.

use std::collections::HashSet;

use dsct::session::fields::{FieldRef, FieldStats, FieldSummary, Split};
use gpui_kit::assets::IconName as AssetIcon;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputState};
use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};
use gpui_kit::component::{Icon, IconName, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use packet_dissector_core::dissector::ProtocolLayer;

use crate::app::DsctApp;
use crate::fields_view::{self, SampleSize};
use crate::timeline::MonoFont as _;
use crate::{format, theme};

/// The sidebar's width.
const WIDTH: f32 = 280.;

/// Which list an expanded field is in, so it expands in that list only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Pinned,
    Key,
    ByLayer,
}

/// The sidebar's state.
pub struct FieldsPanel {
    /// Value counts of the current sample.
    pub stats: Option<FieldStats>,
    /// The counts no longer match the displayed packets or the sample size.
    pub stale: bool,
    pub sample: SampleSize,
    /// Count over packets spread across the displayed ones rather than the
    /// first ones.
    pub spread: bool,
    /// Pinned field paths, in the order they were pinned.
    pub pinned: Vec<String>,
    pub expanded: Option<(Section, String)>,
    /// Stack positions expanded or collapsed against their default.
    pub toggled_layers: HashSet<Option<ProtocolLayer>>,
    pub open_protocols: HashSet<&'static str>,
    pub search: Entity<InputState>,
}

impl FieldsPanel {
    pub fn new(search: Entity<InputState>) -> Self {
        Self {
            stats: None,
            stale: true,
            sample: SampleSize::default(),
            spread: true,
            pinned: Vec::new(),
            expanded: None,
            toggled_layers: HashSet::new(),
            open_protocols: HashSet::new(),
            search,
        }
    }

    /// Forget the counts of the previous capture (pins stay).
    pub fn reset(&mut self) {
        self.stats = None;
        self.stale = true;
        self.expanded = None;
    }

    fn layer_open(&self, layer: Option<ProtocolLayer>) -> bool {
        fields_view::layer_open_by_default(layer) != self.toggled_layers.contains(&layer)
    }
}

/// A small heading over a list.
fn section(title: &'static str, note: Option<String>) -> Div {
    h_flex()
        .px_3()
        .pt_3()
        .pb_1()
        .gap_1p5()
        .text_xs()
        .child(
            div()
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(theme::text_muted())
                .child(title),
        )
        .children(note.map(|n| div().text_color(theme::text_muted()).child(n)))
}

fn hint(text: impl Into<SharedString>) -> Div {
    div()
        .px_3()
        .py_1()
        .text_xs()
        .text_color(theme::text_muted())
        .child(text.into())
}

impl DsctApp {
    /// Narrow the applied filter to `field`'s value, or exclude it.
    pub(crate) fn refine(
        &mut self,
        field: &FieldRef,
        exclude: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let current = self
            .session
            .borrow()
            .as_ref()
            .map(|s| s.applied_filter.clone())
            .unwrap_or_default();
        let text = dsct::session::fields::refine_filter(&current, &field.clause(), exclude);
        self.set_filter(&text, window, cx);
    }

    pub(crate) fn toggle_pin(&mut self, path: &str, cx: &mut Context<Self>) {
        let pinned = &mut self.fields.pinned;
        match pinned.iter().position(|p| p == path) {
            Some(i) => {
                pinned.remove(i);
            }
            None => pinned.push(path.to_string()),
        }
        cx.notify();
    }

    fn toggle_expanded(&mut self, section: Section, path: &str, cx: &mut Context<Self>) {
        let key = (section, path.to_string());
        self.fields.expanded = if self.fields.expanded.as_ref() == Some(&key) {
            None
        } else {
            Some(key)
        };
        cx.notify();
    }

    fn set_sample(&mut self, sample: SampleSize, spread: bool, cx: &mut Context<Self>) {
        if self.fields.sample == sample && self.fields.spread == spread {
            return;
        }
        self.fields.sample = sample;
        self.fields.spread = spread;
        if let Some(session) = self.session.borrow_mut().as_mut() {
            session.cancel_field_stats();
        }
        self.fields.stale = true;
        self.ensure_ticking(cx);
        cx.notify();
    }

    /// The row of one field, and its top values when expanded.
    fn field_row(
        &self,
        section: Section,
        field: &FieldSummary,
        sampled: u64,
        columns: &[String],
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let mono = cx.theme_mono_font();
        let path = field.path.clone();
        let expanded = self.fields.expanded.as_ref() == Some(&(section, path.clone()));
        let pinned = self.fields.pinned.contains(&path);
        let is_column = columns.contains(&path);
        let id = SharedString::from(format!("{section:?}-{path}"));
        // Under a protocol in "By layer", fields sit one level deeper.
        let indent = if section == Section::ByLayer { 34. } else { 6. };

        let row = h_flex()
            .id(id.clone())
            .ml(px(indent))
            .mr_1p5()
            .h(px(26.))
            .pl_2()
            .pr_0p5()
            .gap_2()
            .rounded(px(5.))
            .when(expanded, |d| d.bg(theme::selection()))
            .when(!expanded, |d| d.hover(|d| d.bg(theme::hover())))
            .cursor_pointer()
            .child(
                div()
                    .w(px(30.))
                    .flex_shrink_0()
                    .font_family(mono.clone())
                    .text_xs()
                    .text_color(theme::value(match field.kind {
                        dsct::session::fields::FieldKind::Number => format::ValueKind::Number,
                        dsct::session::fields::FieldKind::Address => format::ValueKind::Address,
                        dsct::session::fields::FieldKind::Text => format::ValueKind::Text,
                    }))
                    .child(fields_view::kind_badge(field.kind)),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .font_family(mono.clone())
                    .text_xs()
                    .text_color(theme::text())
                    .child(path.clone()),
            )
            .when(is_column, |d| {
                d.child(
                    div()
                        .text_xs()
                        .text_color(theme::text_muted())
                        .child("column"),
                )
            })
            .child(
                div()
                    .font_family(mono.clone())
                    .text_xs()
                    .text_color(theme::text_muted())
                    .child(fields_view::grouped(field.packets)),
            )
            .child({
                let path = path.clone();
                Button::new(SharedString::from(format!("pin-{id}")))
                    .icon(Icon::new(AssetIcon::Pin).text_color(if pinned {
                        theme::accent()
                    } else {
                        theme::text_faint()
                    }))
                    .xsmall()
                    .ghost()
                    .tooltip(if pinned { "Unpin" } else { "Pin to the top" })
                    .on_click(cx.listener(move |this, _, _, cx| {
                        cx.stop_propagation();
                        this.toggle_pin(&path, cx);
                    }))
            })
            .on_click({
                let path = path.clone();
                cx.listener(move |this, _, _, cx| this.toggle_expanded(section, &path, cx))
            });

        if !expanded {
            return row.into_any_element();
        }

        let palette = [
            theme::teal(),
            theme::purple(),
            theme::orange(),
            theme::green(),
            theme::blue(),
        ];
        let values = field
            .top
            .iter()
            .take(fields_view::TOP_VALUES)
            .enumerate()
            .map(|(i, v)| {
                let color = palette[i % palette.len()];
                let share = fields_view::share(v.packets, sampled);
                let reference = FieldRef {
                    path: path.clone(),
                    value: Some(v.value.clone()),
                };
                let exclude = reference.clone();
                h_flex()
                    .gap_0p5()
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .gap_1()
                            .child(
                                h_flex()
                                    .gap_1p5()
                                    .text_xs()
                                    .font_family(mono.clone())
                                    .child(
                                        div()
                                            .flex_1()
                                            .min_w_0()
                                            .overflow_hidden()
                                            .whitespace_nowrap()
                                            .text_ellipsis()
                                            .text_color(theme::text_bright())
                                            .child(fields_view::value_text(v)),
                                    )
                                    .child(
                                        div()
                                            .text_color(theme::text())
                                            .child(fields_view::grouped(v.packets)),
                                    )
                                    .child(
                                        div()
                                            .w(px(44.))
                                            .text_right()
                                            .text_color(theme::text_muted())
                                            .child(fields_view::percent_text(v.packets, sampled)),
                                    ),
                            )
                            .child(
                                div()
                                    .h(px(3.))
                                    .w_full()
                                    .rounded(px(2.))
                                    .bg(theme::border())
                                    .child(
                                        div().h_full().rounded(px(2.)).bg(color).w(relative(share)),
                                    ),
                            ),
                    )
                    .child(
                        Button::new(("for", i))
                            .icon(Icon::new(AssetIcon::ZoomIn))
                            .xsmall()
                            .ghost()
                            .tooltip("Filter for this value")
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.refine(&reference, false, window, cx)
                            })),
                    )
                    .child(
                        Button::new(("out", i))
                            .icon(Icon::new(AssetIcon::ZoomOut))
                            .xsmall()
                            .ghost()
                            .tooltip("Filter out this value")
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.refine(&exclude, true, window, cx)
                            })),
                    )
            });

        let column_path = path.clone();
        let split_path = path.clone();
        let detail = v_flex()
            .mt_1()
            .mb_2()
            .ml(px(if section == Section::ByLayer {
                42.
            } else {
                36.
            }))
            .mr_1p5()
            .p_2p5()
            .gap_2()
            .rounded(px(8.))
            .border_1()
            .border_color(theme::border())
            .bg(theme::elevated())
            .child(
                div()
                    .text_xs()
                    .text_color(theme::text_muted())
                    .child(fields_view::values_title(field, sampled)),
            )
            .children(values)
            .child(
                h_flex()
                    .gap_1p5()
                    .child(
                        Button::new("add-column")
                            .label(if is_column {
                                "Remove column"
                            } else {
                                "Add as column"
                            })
                            .xsmall()
                            .outline()
                            .flex_1()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.toggle_column(&column_path, cx)
                            })),
                    )
                    .child(
                        Button::new("split-chart")
                            .label("Split chart by")
                            .xsmall()
                            .outline()
                            .flex_1()
                            .on_click(cx.listener(move |this, _, _, cx| {
                                this.set_split(Split::Field(split_path.clone()), cx)
                            })),
                    ),
            );
        v_flex().child(row).child(detail).into_any_element()
    }

    fn render_by_layer(
        &self,
        stats: &FieldStats,
        query: &str,
        columns: &[String],
        cx: &mut Context<Self>,
    ) -> Vec<AnyElement> {
        let mono = cx.theme_mono_font();
        let searching = !query.is_empty();
        let mut out = Vec::new();
        for group in fields_view::by_layer(stats, query) {
            let layer = group.layer;
            let open = searching || self.fields.layer_open(layer);
            let names = group
                .protocols
                .iter()
                .map(|p| p.name)
                .collect::<Vec<_>>()
                .join(", ");
            out.push(
                h_flex()
                    .id(SharedString::from(format!(
                        "layer-{}",
                        fields_view::layer_title(layer)
                    )))
                    .mx_1p5()
                    .mt_0p5()
                    .h(px(26.))
                    .px_1()
                    .gap_1p5()
                    .rounded(px(5.))
                    .hover(|d| d.bg(theme::hover()))
                    .cursor_pointer()
                    .text_xs()
                    .child(
                        Icon::new(if open {
                            IconName::ChevronDown
                        } else {
                            IconName::ChevronRight
                        })
                        .xsmall()
                        .text_color(theme::text_muted()),
                    )
                    .child(
                        div()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(theme::text())
                            .child(fields_view::layer_title(layer)),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_ellipsis()
                            .text_color(theme::text_muted())
                            .when(!open, |d| d.child(names)),
                    )
                    .child(
                        div()
                            .font_family(mono.clone())
                            .text_color(theme::text_muted())
                            .child(fields_view::grouped(group.packets)),
                    )
                    .on_click(cx.listener(move |this, _, _, cx| {
                        let toggled = &mut this.fields.toggled_layers;
                        if !toggled.remove(&layer) {
                            toggled.insert(layer);
                        }
                        cx.notify();
                    }))
                    .into_any_element(),
            );
            if !open {
                continue;
            }
            for protocol in group.protocols {
                let name = protocol.name;
                let protocol_open = searching || self.fields.open_protocols.contains(name);
                let color =
                    format::protocol_swatch(name).map_or(theme::text_muted(), theme::swatch);
                let group_id = SharedString::from(format!("proto-{name}"));
                let reference = FieldRef {
                    path: dsct::filter::normalize_protocol_name(name),
                    value: None,
                };
                out.push(
                    h_flex()
                        .id(group_id.clone())
                        .group(group_id.clone())
                        .ml(px(20.))
                        .mr_1p5()
                        .h(px(26.))
                        .px_1()
                        .gap_2()
                        .rounded(px(5.))
                        .hover(|d| d.bg(theme::hover()))
                        .cursor_pointer()
                        .when(!protocol.fields.is_empty(), |d| {
                            d.child(
                                Icon::new(if protocol_open {
                                    IconName::ChevronDown
                                } else {
                                    IconName::ChevronRight
                                })
                                .xsmall()
                                .text_color(theme::text_muted()),
                            )
                        })
                        .when(protocol.fields.is_empty(), |d| d.child(div().w(px(12.))))
                        .child(div().size(px(8.)).rounded(px(2.)).bg(color))
                        .child(
                            div()
                                .flex_1()
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(theme::text())
                                .child(name),
                        )
                        .child(
                            div()
                                .opacity(0.)
                                .group_hover(group_id.clone(), |s| s.opacity(1.))
                                .child(
                                    Button::new(SharedString::from(format!("filter-{name}")))
                                        .icon(Icon::new(AssetIcon::ZoomIn))
                                        .xsmall()
                                        .ghost()
                                        .tooltip(format!("Filter for {name}"))
                                        .on_click(cx.listener(move |this, _, window, cx| {
                                            cx.stop_propagation();
                                            this.refine(&reference, false, window, cx)
                                        })),
                                ),
                        )
                        .child(
                            div()
                                .text_xs()
                                .font_family(mono.clone())
                                .text_color(theme::text_muted())
                                .child(fields_view::grouped(protocol.packets)),
                        )
                        .on_click(cx.listener(move |this, _, _, cx| {
                            let open = &mut this.fields.open_protocols;
                            if !open.remove(name) {
                                open.insert(name);
                            }
                            cx.notify();
                        }))
                        .into_any_element(),
                );
                if protocol_open {
                    for field in protocol.fields {
                        out.push(self.field_row(
                            Section::ByLayer,
                            field,
                            stats.sampled,
                            columns,
                            cx,
                        ));
                    }
                }
            }
        }
        out
    }

    pub(crate) fn render_sidebar(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let query = self.fields.search.read(cx).value().trim().to_string();
        let columns = self.columns(cx);
        let indexing = self
            .session
            .borrow()
            .as_ref()
            .is_some_and(|s| s.is_indexing() || s.filter_running());

        let weak = cx.entity().downgrade();
        let current = self.fields.sample;
        let spread = self.fields.spread;
        let has_pins = !self.fields.pinned.is_empty();
        let customize = Button::new("customize-fields")
            .icon(Icon::new(AssetIcon::SlidersHorizontal))
            .xsmall()
            .ghost()
            .tooltip("Customize the sidebar")
            .dropdown_menu(move |mut menu, _, _| {
                menu = menu.item(PopupMenuItem::label("COUNT VALUES OVER"));
                for sample in SampleSize::ALL {
                    let weak = weak.clone();
                    menu = menu.item(
                        PopupMenuItem::new(sample.label())
                            .checked(sample == current)
                            .on_click(move |_, _, cx| {
                                let _ =
                                    weak.update(cx, |app, cx| app.set_sample(sample, spread, cx));
                            }),
                    );
                }
                menu = menu.separator().item(PopupMenuItem::label("TAKEN FROM"));
                for (label, choice) in [
                    ("Across the displayed packets", true),
                    ("The first displayed packets", false),
                ] {
                    let weak = weak.clone();
                    menu = menu.item(
                        PopupMenuItem::new(label)
                            .checked(choice == spread && current != SampleSize::All)
                            .disabled(current == SampleSize::All)
                            .on_click(move |_, _, cx| {
                                let _ =
                                    weak.update(cx, |app, cx| app.set_sample(current, choice, cx));
                            }),
                    );
                }
                let weak = weak.clone();
                menu.separator().item(
                    PopupMenuItem::new("Reset pinned fields")
                        .disabled(!has_pins)
                        .on_click(move |_, _, cx| {
                            let _ = weak.update(cx, |app, cx| {
                                app.fields.pinned.clear();
                                cx.notify();
                            });
                        }),
                )
            });

        let header = h_flex()
            .pl_3()
            .pr_1p5()
            .pt_2p5()
            .pb_1p5()
            .gap_1p5()
            .text_xs()
            .child(
                div()
                    .flex_1()
                    .font_weight(FontWeight::SEMIBOLD)
                    .text_color(theme::text_muted())
                    .child("FIELDS"),
            )
            .children(self.fields.stats.as_ref().map(|s| {
                div()
                    .text_color(theme::text_muted())
                    .child(format!("{} fields", s.fields.len()))
            }))
            .child(customize);

        let mut list: Vec<AnyElement> = Vec::new();
        match self.fields.stats.as_ref() {
            None => list.push(
                hint(if indexing {
                    "Fields are counted once the packets are read."
                } else {
                    "Counting field values…"
                })
                .pt_2()
                .into_any_element(),
            ),
            Some(stats) => {
                list.push(hint(fields_view::sample_note(stats)).into_any_element());

                let pinned: Vec<&FieldSummary> = self
                    .fields
                    .pinned
                    .iter()
                    .filter(|p| fields_view::matches(p, &query))
                    .filter_map(|p| stats.field(p))
                    .collect();
                list.push(
                    section("PINNED", Some(self.fields.pinned.len().to_string()))
                        .into_any_element(),
                );
                if self.fields.pinned.is_empty() {
                    list.push(hint("Pin a field to keep it here.").into_any_element());
                } else if pinned.is_empty() {
                    list.push(hint("No pinned field in these packets.").into_any_element());
                }
                for field in pinned {
                    list.push(self.field_row(Section::Pinned, field, stats.sampled, &columns, cx));
                }

                let key = fields_view::key_fields(stats, &self.fields.pinned, &query);
                if !key.is_empty() {
                    list.push(section("KEY FIELDS", None).into_any_element());
                    for field in key {
                        list.push(self.field_row(Section::Key, field, stats.sampled, &columns, cx));
                    }
                }

                list.push(section("BY LAYER", None).into_any_element());
                let layers = self.render_by_layer(stats, &query, &columns, cx);
                if layers.is_empty() {
                    list.push(hint("No field matches.").into_any_element());
                }
                list.extend(layers);
            }
        }

        v_flex()
            .w(px(WIDTH))
            .flex_shrink_0()
            .h_full()
            .bg(theme::panel())
            .border_r_1()
            .border_color(theme::border())
            .text_sm()
            .child(header)
            .child(
                div()
                    .px_2()
                    .pb_1()
                    .child(Input::new(&self.fields.search).small().cleanable(true)),
            )
            .child(
                v_flex()
                    .id("fields")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .pb_3()
                    .children(list),
            )
            .into_any_element()
    }
}
