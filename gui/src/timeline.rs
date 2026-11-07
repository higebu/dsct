//! The chart of the displayed packets over time, above the packet list,
//! split by protocol or by a field.

use dsct::session::fields::{Bucket, Histogram, SeriesKey, Split};
use gpui_kit::component::button::{Button, ButtonVariants as _};
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
    /// Bars selected by dragging across them: where the drag started and
    /// where it is (or ended).
    pub brush: Option<(usize, usize)>,
    /// The mouse button is held down on the bars.
    pub dragging: bool,
}

impl Default for Timeline {
    fn default() -> Self {
        Self {
            split: Split::TopProtocol,
            histogram: None,
            stale: true,
            brush: None,
            dragging: false,
        }
    }
}

/// The bars from `a` to `b`, in order.
pub fn ordered(a: usize, b: usize) -> (usize, usize) {
    (a.min(b), a.max(b))
}

/// Packets in bars `lo..=hi`.
pub fn range_packets(histogram: &Histogram, lo: usize, hi: usize) -> u64 {
    histogram
        .buckets
        .iter()
        .take(hi + 1)
        .skip(lo)
        .map(|b| b.packets)
        .sum()
}

/// The filter clause selecting the time of bars `lo..=hi`.
pub fn range_clause(histogram: &Histogram, lo: usize, hi: usize) -> String {
    let from = histogram.start_us + histogram.bucket_us * lo as u64;
    let to = histogram.start_us + histogram.bucket_us * (hi as u64 + 1) - 1;
    let iso = |us: u64| dsct::serialize::format_timestamp(us / 1_000_000, (us % 1_000_000) as u32);
    format!("timestamp BETWEEN '{}' AND '{}'", iso(from), iso(to))
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

    /// The mouse went down on bar `i`.
    fn brush_start(&mut self, i: usize, cx: &mut Context<Self>) {
        self.timeline.brush = Some((i, i));
        self.timeline.dragging = true;
        cx.notify();
    }

    /// The mouse moved over bar `i`.
    fn brush_move(&mut self, i: usize, cx: &mut Context<Self>) {
        if let (true, Some((start, end))) = (self.timeline.dragging, self.timeline.brush)
            && end != i
        {
            self.timeline.brush = Some((start, i));
            cx.notify();
        }
    }

    /// The mouse went up: a click on one bar goes to its first packet, a
    /// drag keeps the bars it covered selected.
    fn brush_end(&mut self, cx: &mut Context<Self>) {
        if !std::mem::take(&mut self.timeline.dragging) {
            return;
        }
        if let Some((start, end)) = self.timeline.brush
            && start == end
        {
            self.timeline.brush = None;
            let first = self
                .timeline
                .histogram
                .as_ref()
                .and_then(|h| h.buckets.get(start)?.first_packet);
            if let Some(idx) = first {
                self.go_to_packet(idx as u64 + 1, cx);
            }
        }
        cx.notify();
    }

    /// Narrow the filter to the selected bars' time.
    fn filter_to_brush(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some((a, b)) = self.timeline.brush.take() else {
            return;
        };
        let Some(histogram) = self.timeline.histogram.as_ref() else {
            return;
        };
        let (lo, hi) = ordered(a, b);
        let clause = range_clause(histogram, lo, hi);
        let current = self
            .session
            .borrow()
            .as_ref()
            .map(|s| s.applied_filter.clone())
            .unwrap_or_default();
        let text = dsct::session::fields::refine_filter(&current, &clause, false);
        self.set_filter(&text, window, cx);
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
        let brush = self.timeline.brush.map(|(a, b)| ordered(a, b));
        let selecting = brush.is_some_and(|(lo, hi)| hi > lo);
        let bars = histogram.buckets.iter().enumerate().map(|(i, bucket)| {
            let in_brush = selecting && brush.is_some_and(|(lo, hi)| (lo..=hi).contains(&i));
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
            v_flex()
                .id(("bar", i))
                .flex_1()
                .h(px(BAR_HEIGHT))
                .justify_end()
                .gap(px(1.))
                .rounded(px(2.))
                .cursor_pointer()
                .when(in_brush, |d| d.bg(theme::selection()))
                // Bars outside the selection fade.
                .when(selecting && !in_brush, |d| d.opacity(0.35))
                .when(!in_brush, |d| d.hover(|d| d.bg(theme::hover())))
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
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, _, _, cx| this.brush_start(i, cx)),
                )
                .on_mouse_move(
                    cx.listener(move |this, _: &MouseMoveEvent, _, cx| this.brush_move(i, cx)),
                )
                .on_mouse_up(
                    MouseButton::Left,
                    cx.listener(|this, _, _, cx| this.brush_end(cx)),
                )
        });

        let footer_middle: AnyElement = match brush {
            Some((lo, hi)) if selecting => {
                let packets = range_packets(histogram, lo, hi);
                h_flex()
                    .gap_2()
                    .font_family(cx.theme_mono_font())
                    .child(
                        div().text_color(theme::text()).child(format!(
                            "{} – {} · {} packets",
                            offset_label(start + bucket_us * lo as u64),
                            offset_label(start + bucket_us * (hi as u64 + 1)),
                            crate::fields_view::grouped(packets)
                        )),
                    )
                    .when(!self.timeline.dragging, |d| {
                        d.child(
                            Button::new("filter-range")
                                .label("Filter to this range")
                                .xsmall()
                                .outline()
                                .on_click(cx.listener(|this, _, window, cx| {
                                    this.filter_to_brush(window, cx)
                                })),
                        )
                        .child(
                            Button::new("clear-range")
                                .icon(gpui_kit::component::IconName::Close)
                                .xsmall()
                                .ghost()
                                .tooltip("Clear the selection")
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.timeline.brush = None;
                                    cx.notify();
                                })),
                        )
                    })
                    .into_any_element()
            }
            _ => div()
                .child("Click a bar to go to its first packet · drag across bars to select a time range")
                .into_any_element(),
        };

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
                .child(
                    h_flex()
                        .id("bars")
                        .items_end()
                        .gap(px(2.))
                        .children(bars)
                        // A drag released past the bars still ends.
                        .on_mouse_up_out(
                            MouseButton::Left,
                            cx.listener(|this, _, _, cx| this.brush_end(cx)),
                        ),
                )
                .child(
                    h_flex()
                        .gap_2()
                        .child(div().font_family(mono.clone()).child(offset_label(start)))
                        .child(div().flex_1())
                        .child(footer_middle)
                        .child(div().flex_1())
                        .child(div().font_family(mono).child(offset_label(end))),
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

    use dsct::session::fields::{Bucket, Histogram};

    use super::{
        field_choices, offset_label, ordered, range_clause, range_packets, segment_heights,
        series_name, split_label,
    };

    #[test]
    fn ranges_cover_whole_bars() {
        let bucket = |packets| Bucket {
            packets,
            split: Vec::new(),
            first_packet: None,
        };
        let histogram = Histogram {
            split: Split::TopProtocol,
            // 2023-11-14T22:13:20Z, 0.5 s bars.
            start_us: 1_700_000_000_000_000,
            bucket_us: 500_000,
            buckets: vec![bucket(1), bucket(2), bucket(3), bucket(4)],
            series: Vec::new(),
            complete: false,
        };
        assert_eq!(ordered(3, 1), (1, 3));
        assert_eq!(range_packets(&histogram, 1, 2), 5);
        assert_eq!(
            range_clause(&histogram, 1, 2),
            "timestamp BETWEEN '2023-11-14T22:13:20.500000Z' AND '2023-11-14T22:13:21.499999Z'"
        );
    }

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
