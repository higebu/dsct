//! The bottom panel: Follow Stream and Stats results, as tabs.

use std::ops::Range;

use dsct::stats::StatsOutput;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{ActiveTheme as _, IconName, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::DsctApp;
use crate::format;

/// Number of top talkers listed.
const TOP_TALKERS: usize = 10;

/// A collected stream: title and lines, `true` for client → server.
pub struct StreamView {
    pub title: String,
    pub lines: Vec<(String, bool)>,
}

/// Which result the panel shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BottomTab {
    #[default]
    Stream,
    Stats,
}

/// The last Follow Stream and Stats results, and whether they are shown.
#[derive(Default)]
pub struct BottomPanel {
    pub open: bool,
    pub tab: BottomTab,
    pub stream: Option<StreamView>,
    pub stats: Option<StatsOutput>,
}

impl BottomPanel {
    /// Show a newly collected stream.
    pub fn show_stream(&mut self, stream: StreamView) {
        self.stream = Some(stream);
        self.tab = BottomTab::Stream;
        self.open = true;
    }

    /// Show newly collected stats.
    pub fn show_stats(&mut self, stats: StatsOutput) {
        self.stats = Some(stats);
        self.tab = BottomTab::Stats;
        self.open = true;
    }

    fn has(&self, tab: BottomTab) -> bool {
        match tab {
            BottomTab::Stream => self.stream.is_some(),
            BottomTab::Stats => self.stats.is_some(),
        }
    }

    /// The shown result as text, for the clipboard.
    fn copy_text(&self) -> Option<String> {
        match self.tab {
            BottomTab::Stream => self.stream.as_ref().map(|s| format::stream_text(&s.lines)),
            BottomTab::Stats => self
                .stats
                .as_ref()
                .and_then(|s| serde_json::to_string_pretty(s).ok()),
        }
    }
}

impl DsctApp {
    pub(crate) fn render_bottom(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        if !self.bottom.open || !self.bottom.has(self.bottom.tab) {
            return None;
        }
        let theme = cx.theme();
        let (border, muted, red, blue) =
            (theme.border, theme.muted_foreground, theme.red, theme.blue);

        let tabs = [(BottomTab::Stream, "Stream"), (BottomTab::Stats, "Stats")]
            .into_iter()
            .filter(|(tab, _)| self.bottom.has(*tab))
            .map(|(tab, label)| {
                let active = self.bottom.tab == tab;
                div()
                    .id(label)
                    .px_3()
                    .py_1()
                    .border_b_2()
                    .border_color(if active { blue } else { transparent_black() })
                    .when(active, |d| d.font_weight(FontWeight::SEMIBOLD))
                    .when(!active, |d| d.text_color(muted))
                    .child(label)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.bottom.tab = tab;
                        cx.notify();
                    }))
            })
            .collect::<Vec<_>>();

        let legend = (self.bottom.tab == BottomTab::Stream).then(|| {
            h_flex()
                .gap_3()
                .text_sm()
                .child(div().text_color(red).child(format!(
                    "{} client to server",
                    format::direction_marker(true)
                )))
                .child(div().text_color(blue).child(format!(
                    "{} server to client",
                    format::direction_marker(false)
                )))
        });

        let header = h_flex()
            .px_2()
            .gap_2()
            .border_b_1()
            .border_color(border)
            .children(tabs)
            .child(div().flex_1())
            .children(legend)
            .child(
                Button::new("copy-bottom")
                    .icon(IconName::Copy)
                    .small()
                    .ghost()
                    .tooltip("Copy")
                    .on_click(cx.listener(|this, _, _, cx| {
                        if let Some(text) = this.bottom.copy_text() {
                            cx.write_to_clipboard(ClipboardItem::new_string(text));
                        }
                    })),
            )
            .child(
                Button::new("close-bottom")
                    .icon(IconName::Close)
                    .small()
                    .ghost()
                    .tooltip("Close (Esc)")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.bottom.open = false;
                        cx.notify();
                    })),
            );

        let body = match self.bottom.tab {
            BottomTab::Stream => self.render_stream(cx).into_any_element(),
            BottomTab::Stats => self.render_stats(cx).into_any_element(),
        };
        Some(
            v_flex()
                .size_full()
                .child(header)
                .child(div().flex_1().min_h_0().child(body))
                .into_any_element(),
        )
    }

    fn render_stream(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let mono = theme.mono_font_family.clone();
        let (title, count) = self
            .bottom
            .stream
            .as_ref()
            .map_or((String::new(), 0), |s| (s.title.clone(), s.lines.len()));
        v_flex()
            .size_full()
            .child(
                div()
                    .px_2()
                    .py_1()
                    .text_sm()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(title),
            )
            .child(
                uniform_list(
                    "stream-lines",
                    count,
                    cx.processor(|this, range: Range<usize>, _, cx| {
                        let (red, blue) = (cx.theme().red, cx.theme().blue);
                        let Some(stream) = this.bottom.stream.as_ref() else {
                            return Vec::new();
                        };
                        range
                            .filter_map(|i| {
                                let (text, client) = stream.lines.get(i)?;
                                let color = if *client { red } else { blue };
                                Some(
                                    h_flex()
                                        .px_2()
                                        .gap_2()
                                        .text_color(color)
                                        .child(
                                            div()
                                                .w(px(16.))
                                                .flex_shrink_0()
                                                .child(format::direction_marker(*client)),
                                        )
                                        .child(div().whitespace_nowrap().child(text.clone())),
                                )
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .font_family(mono)
                .flex_1(),
            )
    }

    fn render_stats(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (muted, border, bar) = (
            theme.muted_foreground,
            theme.border,
            theme.blue.opacity(0.35),
        );
        let mono = theme.mono_font_family.clone();
        let Some(stats) = self.bottom.stats.as_ref() else {
            return div().id("stats");
        };

        let mut summary = vec![format!("{} packets", stats.total_packets)];
        summary.push(format!("{:.3} s", stats.duration_secs));
        if let (Some(start), Some(end)) = (&stats.time_start, &stats.time_end) {
            summary.push(format!("{start} – {end}"));
        }

        let heading = |text: &'static str| {
            div()
                .pt_3()
                .pb_1()
                .text_sm()
                .font_weight(FontWeight::SEMIBOLD)
                .child(text)
        };
        let row = move || {
            h_flex()
                .gap_3()
                .py(px(3.))
                .border_b_1()
                .border_color(border)
        };
        let num = |w: f32, text: String| {
            div()
                .w(px(w))
                .flex_shrink_0()
                .text_right()
                .font_family(mono.clone())
                .child(text)
        };

        let protocols = format::protocol_shares(&stats.protocols, stats.total_packets)
            .into_iter()
            .map(|(name, count, share)| {
                row()
                    .child(div().w(px(140.)).flex_shrink_0().child(name))
                    .child(num(80., count.to_string()))
                    .child(num(64., format!("{:.1}%", share * 100.)))
                    .child(
                        div().w(px(160.)).h(px(8.)).child(
                            div()
                                .h_full()
                                .w(px((share * 160.) as f32))
                                .rounded(px(2.))
                                .bg(bar),
                        ),
                    )
            })
            .collect::<Vec<_>>();

        let talkers = stats
            .top_talkers
            .iter()
            .flatten()
            .take(TOP_TALKERS)
            .map(|t| {
                row()
                    .child(div().w(px(200.)).flex_shrink_0().child(t.src.clone()))
                    .child(div().w(px(200.)).flex_shrink_0().child(t.dst.clone()))
                    .child(num(80., t.packets.to_string()))
                    .child(num(100., t.bytes.to_string()))
            })
            .collect::<Vec<_>>();

        let header = |cols: &[(&'static str, f32, bool)]| {
            h_flex()
                .gap_3()
                .text_xs()
                .text_color(muted)
                .children(cols.iter().map(|(label, w, right)| {
                    div()
                        .w(px(*w))
                        .flex_shrink_0()
                        .when(*right, |d| d.text_right())
                        .child(*label)
                }))
        };

        div()
            .id("stats")
            .size_full()
            .overflow_y_scroll()
            .px_3()
            .pb_3()
            .child(
                div()
                    .pt_2()
                    .text_sm()
                    .text_color(muted)
                    .child(format!("Displayed packets · {}", summary.join(" · "))),
            )
            .child(heading("Protocols"))
            .child(header(&[
                ("Protocol", 140., false),
                ("Packets", 80., true),
                ("Share", 64., true),
            ]))
            .children(protocols)
            .when(!talkers.is_empty(), |d| {
                d.child(heading("Top talkers"))
                    .child(header(&[
                        ("Source", 200., false),
                        ("Destination", 200., false),
                        ("Packets", 80., true),
                        ("Bytes", 100., true),
                    ]))
                    .children(talkers)
            })
    }
}
