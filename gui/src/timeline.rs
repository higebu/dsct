//! The chart of the displayed packets over time, above the packet list,
//! split by protocol or by a field.

use dsct::session::fields::{Bucket, Histogram, SeriesKey, Split};
use gpui_kit::component::button::Button;
use gpui_kit::component::menu::{DropdownMenu as _, PopupMenuItem};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::component::{Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;
use packet_dissector_core::dissector::ProtocolLayer;

use crate::app::DsctApp;
use crate::{format, theme};

/// Bars in the chart.
pub const BUCKETS: usize = 60;

/// Height of the tallest bar.
const BAR_HEIGHT: f32 = 36.;

/// Series in the legend at most.
const LEGEND: usize = 5;

/// The protocol splits, as the menu lists them.
pub const LAYER_SPLITS: [(&str, Option<ProtocolLayer>); 5] = [
    ("Top protocol", None),
    ("Application layer", Some(ProtocolLayer::Application)),
    ("Transport layer", Some(ProtocolLayer::Transport)),
    ("Network layer", Some(ProtocolLayer::Network)),
    ("Link layer", Some(ProtocolLayer::Link)),
];

/// The chart's state in the window.
pub struct Timeline {
    pub split: Split,
    pub histogram: Option<Histogram>,
    /// The histogram no longer matches the displayed packets or the split.
    pub stale: bool,
}

impl Default for Timeline {
    fn default() -> Self {
        Self {
            split: Split::TopProtocol,
            histogram: None,
            stale: true,
        }
    }
}

/// The split as the chart header names it.
pub fn split_label(split: &Split) -> String {
    match split {
        Split::TopProtocol => "top protocol".to_string(),
        Split::Layer(layer) => format!(
            "{} layer",
            crate::fields_view::layer_title(Some(*layer)).to_lowercase()
        ),
        Split::Field(path) => path.clone(),
    }
}

fn layer_split(layer: Option<ProtocolLayer>) -> Split {
    layer.map_or(Split::TopProtocol, Split::Layer)
}

/// Fields offered in the split menu: the pinned ones, the columns, and the
/// field the chart is split by, each once.
pub fn field_choices(pinned: &[String], columns: &[String], split: &Split) -> Vec<String> {
    let mut paths: Vec<String> = Vec::new();
    let current = match split {
        Split::Field(path) => Some(path),
        _ => None,
    };
    for path in pinned.iter().chain(columns).chain(current) {
        if !paths.contains(path) {
            paths.push(path.clone());
        }
    }
    paths
}

/// A series as the legend names it.
pub fn series_name(key: &SeriesKey) -> String {
    match key {
        SeriesKey::Value(v) => v.clone(),
        SeriesKey::Other => "Other".to_string(),
        SeriesKey::Missing => "—".to_string(),
    }
}

/// Heights of a bar's segments (in series order), scaled so `peak` packets
/// is `max` tall; a non-empty segment is at least 1 px.
pub fn segment_heights(counts: &[u64], peak: u64, max: f32) -> Vec<f32> {
    counts
        .iter()
        .map(|&c| {
            if c == 0 || peak == 0 {
                0.
            } else {
                (c as f32 / peak as f32 * max).max(1.)
            }
        })
        .collect()
}

/// A time offset in µs as the axis shows it.
pub fn offset_label(us: u64) -> String {
    let secs = us as f64 / 1e6;
    if secs < 10. {
        format!("{secs:.2} s")
    } else if secs < 120. {
        format!("{secs:.1} s")
    } else {
        let total = secs as u64;
        format!("{}:{:02} min", total / 60, total % 60)
    }
}

/// The colors of the series of a histogram.
fn series_colors(histogram: &Histogram) -> Vec<Hsla> {
    let palette = [
        theme::teal(),
        theme::purple(),
        theme::orange(),
        theme::green(),
        theme::blue(),
        theme::yellow(),
    ];
    let by_protocol = !matches!(histogram.split, Split::Field(_));
    histogram
        .series
        .iter()
        .enumerate()
        .map(|(i, s)| match &s.key {
            SeriesKey::Value(v) if by_protocol => {
                format::protocol_swatch(v).map_or(palette[i % palette.len()], theme::swatch)
            }
            SeriesKey::Value(_) => palette[i % palette.len()],
            SeriesKey::Other => theme::border_strong(),
            SeriesKey::Missing => theme::border(),
        })
        .collect()
}

fn bucket_counts(histogram: &Histogram, bucket: &Bucket) -> Vec<u64> {
    if histogram.complete {
        bucket.split.clone()
    } else {
        vec![bucket.packets]
    }
}

impl DsctApp {
    pub(crate) fn set_split(&mut self, split: Split, cx: &mut Context<Self>) {
        if self.timeline.split == split {
            return;
        }
        if let Some(session) = self.session.borrow_mut().as_mut() {
            session.cancel_histogram();
        }
        self.timeline.split = split;
        self.timeline.stale = true;
        self.ensure_ticking(cx);
        cx.notify();
    }

    pub(crate) fn render_timeline(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let histogram = self.timeline.histogram.as_ref()?;
        let first_us = self.session.borrow().as_ref().and_then(|s| {
            s.indices
                .first()
                .map(|i| dsct::session::fields::timestamp_us(i.timestamp_secs, i.timestamp_usecs))
        })?;
        let mono = cx.theme_mono_font();
        let colors = series_colors(histogram);
        let peak = histogram
            .buckets
            .iter()
            .map(|b| b.packets)
            .max()
            .unwrap_or(0);
        let start = histogram.start_us.saturating_sub(first_us);

        let weak = cx.entity().downgrade();
        let pinned = self.fields.pinned.clone();
        let columns = self.columns(cx);
        let split = self.timeline.split.clone();
        let menu = Button::new("split-by")
            .label(split_label(&self.timeline.split))
            .xsmall()
            .outline()
            .dropdown_menu(move |mut menu, _, _| {
                menu = menu.item(PopupMenuItem::label("PROTOCOL"));
                for (label, layer) in LAYER_SPLITS {
                    let choice = layer_split(layer);
                    let weak = weak.clone();
                    let checked = choice == split;
                    menu = menu.item(PopupMenuItem::new(label).checked(checked).on_click(
                        move |_, _, cx| {
                            let choice = choice.clone();
                            let _ = weak.update(cx, |app, cx| app.set_split(choice, cx));
                        },
                    ));
                }
                let fields = field_choices(&pinned, &columns, &split);
                if !fields.is_empty() {
                    menu = menu.separator().item(PopupMenuItem::label("FIELD"));
                }
                for path in fields {
                    let choice = Split::Field(path.clone());
                    let checked = choice == split;
                    let weak = weak.clone();
                    menu = menu.item(PopupMenuItem::new(path).checked(checked).on_click(
                        move |_, _, cx| {
                            let choice = choice.clone();
                            let _ = weak.update(cx, |app, cx| app.set_split(choice, cx));
                        },
                    ));
                }
                menu
            });

        let legend: Vec<AnyElement> = if histogram.complete {
            histogram
                .series
                .iter()
                .zip(&colors)
                .take(LEGEND)
                .map(|(s, &color)| {
                    h_flex()
                        .gap_1p5()
                        .child(div().size(px(8.)).rounded(px(2.)).bg(color))
                        .child(
                            div()
                                .max_w(px(160.))
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .font_family(mono.clone())
                                .text_color(theme::text())
                                .child(series_name(&s.key)),
                        )
                        .child(
                            div()
                                .font_family(mono.clone())
                                .child(crate::fields_view::grouped(s.packets)),
                        )
                        .into_any_element()
                })
                .collect()
        } else {
            vec![div().child("Splitting…").into_any_element()]
        };

        let bucket_us = histogram.bucket_us;
        let bars = histogram.buckets.iter().enumerate().map(|(i, bucket)| {
            let counts = bucket_counts(histogram, bucket);
            let heights = segment_heights(&counts, peak, BAR_HEIGHT);
            let segment_colors: Vec<Hsla> = if histogram.complete {
                colors.clone()
            } else {
                vec![theme::border_strong()]
            };
            let from = start + bucket_us * i as u64;
            let tip = format!(
                "{} – {} · {} packets",
                offset_label(from),
                offset_label(from + bucket_us),
                crate::fields_view::grouped(bucket.packets)
            );
            let first = bucket.first_packet;
            v_flex()
                .id(("bar", i))
                .flex_1()
                .h(px(BAR_HEIGHT))
                .justify_end()
                .gap(px(1.))
                .rounded(px(2.))
                .when(first.is_some(), |d| {
                    d.cursor_pointer().hover(|d| d.bg(theme::hover()))
                })
                .children(
                    // The first series at the bottom.
                    heights
                        .into_iter()
                        .zip(segment_colors)
                        .rev()
                        .filter(|(h, _)| *h > 0.)
                        .map(|(h, color)| div().w_full().h(px(h)).rounded(px(1.)).bg(color)),
                )
                .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(idx) = first {
                        this.go_to_packet(idx as u64 + 1, cx);
                    }
                }))
        });

        let end = start + bucket_us * histogram.buckets.len() as u64;
        Some(
            v_flex()
                .flex_shrink_0()
                .px_3()
                .pt_2()
                .pb_1p5()
                .gap_1p5()
                .border_b_1()
                .border_color(theme::border())
                .text_xs()
                .text_color(theme::text_muted())
                .child(
                    h_flex()
                        .flex_wrap()
                        .gap_2p5()
                        .child(
                            div()
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(theme::text())
                                .child("Packets over time"),
                        )
                        .child("split by")
                        .child(menu)
                        .child(div().flex_1())
                        .children(legend),
                )
                .child(h_flex().items_end().gap(px(2.)).children(bars))
                .child(
                    h_flex()
                        .font_family(mono)
                        .child(offset_label(start))
                        .child(div().flex_1())
                        .child("Click a bar to go to its first packet")
                        .child(div().flex_1())
                        .child(offset_label(end)),
                )
                .into_any_element(),
        )
    }
}

/// The theme's monospace font, for counts and times.
pub(crate) trait MonoFont {
    fn theme_mono_font(&self) -> SharedString;
}

impl<T> MonoFont for Context<'_, T> {
    fn theme_mono_font(&self) -> SharedString {
        use gpui_kit::component::ActiveTheme as _;
        self.theme().mono_font_family.clone()
    }
}

#[cfg(test)]
mod tests {
    use dsct::session::fields::{SeriesKey, Split};
    use packet_dissector_core::dissector::ProtocolLayer;

    use super::{field_choices, offset_label, segment_heights, series_name, split_label};

    #[test]
    fn labels() {
        assert_eq!(split_label(&Split::TopProtocol), "top protocol");
        assert_eq!(
            split_label(&Split::Layer(ProtocolLayer::Transport)),
            "transport layer"
        );
        assert_eq!(split_label(&Split::Field("ipv4.dst".into())), "ipv4.dst");
        assert_eq!(series_name(&SeriesKey::Missing), "—");
        assert_eq!(offset_label(1_500_000), "1.50 s");
        assert_eq!(offset_label(45_000_000), "45.0 s");
        assert_eq!(offset_label(185_000_000), "3:05 min");
    }

    #[test]
    fn segments_scale_to_the_peak() {
        assert_eq!(segment_heights(&[10, 5, 0], 20, 40.), vec![20., 10., 0.]);
        // A single packet next to a large peak stays visible.
        assert_eq!(segment_heights(&[1], 1000, 36.), vec![1.]);
        assert_eq!(segment_heights(&[3], 0, 36.), vec![0.]);
    }

    #[test]
    fn field_choices_are_listed_once() {
        let pinned = vec!["ipv4.dst".to_string(), "dns.qname".to_string()];
        let columns = vec!["dns.qname".to_string(), "tcp.flags".to_string()];
        assert_eq!(
            field_choices(&pinned, &columns, &Split::Field("udp.dst_port".into())),
            ["ipv4.dst", "dns.qname", "tcp.flags", "udp.dst_port"]
        );
        assert!(field_choices(&[], &[], &Split::TopProtocol).is_empty());
    }
}
