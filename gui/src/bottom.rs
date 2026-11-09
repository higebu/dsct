//! The bottom panel: Follow Stream, Stats, Graph and Problems, as tabs.

use dsct::session::StatsReport;
use dsct::session::responses::{self, Responses};
use dsct::session::sequence::SequenceUnit;
use gpui_kit::assets::IconName as AssetIcon;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{
    ActiveTheme as _, Disableable as _, Icon, IconName, Sizable as _, h_flex, v_flex,
};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::DsctApp;
use crate::{fields_view, format, theme};

/// Conversations listed at most.
const MAX_CONVERSATIONS: usize = 200;

/// Collected stats, with the requests and responses read from them.
pub struct StatsView {
    pub report: StatsReport,
    pub responses: Vec<Responses>,
}

/// Which result the panel shows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum BottomTab {
    #[default]
    Stream,
    Stats,
    Graph,
    Problems,
}

/// The last Follow Stream and Stats results, and whether they are shown.
#[derive(Default)]
pub struct BottomPanel {
    pub open: bool,
    pub tab: BottomTab,
    pub stream: Option<crate::stream_view::StreamView>,
    pub stats: Option<StatsView>,
    pub graph: crate::graph::GraphState,
    /// The tab to show when the stats being collected are done.
    pub stats_tab: Option<BottomTab>,
}

impl BottomPanel {
    /// Show a newly collected stream.
    pub fn show_stream(&mut self, stream: dsct::session::FollowedStream) {
        self.stream = Some(crate::stream_view::StreamView::new(stream));
        self.tab = BottomTab::Stream;
        self.open = true;
    }

    /// Show newly collected stats.
    pub fn show_stats(&mut self, report: StatsReport) {
        self.stats = Some(StatsView {
            responses: responses::responses(&report.output),
            report,
        });
        self.graph.reset();
        self.tab = self.stats_tab.take().unwrap_or(BottomTab::Stats);
        self.open = true;
    }

    fn has(&self, tab: BottomTab) -> bool {
        match tab {
            BottomTab::Stream => self.stream.is_some(),
            BottomTab::Stats | BottomTab::Graph => self.stats.is_some(),
            BottomTab::Problems => true,
        }
    }

    /// The shown result as text, for the clipboard.
    fn copy_text(&self) -> Option<String> {
        match self.tab {
            BottomTab::Stream => self.stream.as_ref().map(|s| s.copy_text()),
            BottomTab::Stats => self
                .stats
                .as_ref()
                .and_then(|s| serde_json::to_string_pretty(&s.report.output).ok()),
            BottomTab::Graph | BottomTab::Problems => None,
        }
    }
}

impl DsctApp {
    pub(crate) fn render_bottom(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        if !self.bottom.open || !self.bottom.has(self.bottom.tab) {
            return None;
        }
        // Client to server in orange, server to client in blue: told apart
        // by lightness and by the → / ← markers, not by hue alone.
        let (border, muted, out, back, accent) = (
            theme::border(),
            theme::text_muted(),
            theme::orange(),
            theme::blue(),
            theme::accent(),
        );

        let tabs = [
            (BottomTab::Stream, "Stream"),
            (BottomTab::Stats, "Stats"),
            (BottomTab::Graph, "Graph"),
            (BottomTab::Problems, "Problems"),
        ]
        .into_iter()
        .filter(|(tab, _)| self.bottom.has(*tab))
        .map(|(tab, label)| {
            let active = self.bottom.tab == tab;
            div()
                .id(label)
                .px_3()
                .py_1()
                .border_b_2()
                .border_color(if active { accent } else { transparent_black() })
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
                .child(div().text_color(out).child(format!(
                    "{} client to server",
                    format::direction_marker(true)
                )))
                .child(div().text_color(back).child(format!(
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
            BottomTab::Graph => self.render_graph(cx).into_any_element(),
            BottomTab::Problems => self.render_problems(cx).into_any_element(),
        };
        Some(
            v_flex()
                .size_full()
                .child(header)
                .child(div().flex_1().min_h_0().child(body))
                .into_any_element(),
        )
    }

    fn render_stats(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (muted, border) = (theme.muted_foreground, theme.border);
        let mono = theme.mono_font_family.clone();
        let Some(stats) = self.bottom.stats.as_ref() else {
            return div().id("stats");
        };
        let output = &stats.report.output;
        // Conversation start times count from the capture's first packet.
        let t0 = self
            .session
            .borrow()
            .as_ref()
            .and_then(|s| s.packet_time_us(0))
            .unwrap_or(0);

        let mut summary = vec![format!("{} packets", output.total_packets)];
        summary.push(format!("{:.3} s", output.duration_secs));
        if let (Some(start), Some(end)) = (&output.time_start, &output.time_end) {
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
                .min_h(px(28.))
                .py(px(2.))
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

        let replies = stats
            .responses
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let swatch = format::protocol_swatch(r.protocol).map_or(muted, theme::swatch);
                let outcomes = r.outcomes.iter().enumerate().map(|(j, o)| {
                    let label = format!("{} {}", o.label, fields_view::grouped(o.count));
                    let button = Button::new(("outcome", i * 1000 + j))
                        .label(label)
                        .xsmall()
                        .when(o.error, |b| b.warning().outline())
                        .when(!o.error, |b| b.outline());
                    match o.filter.clone() {
                        Some(filter) => {
                            button
                                .tooltip(format!("Filter: {filter}"))
                                .on_click(cx.listener(move |this, _, window, cx| {
                                    this.set_filter(&filter, window, cx)
                                }))
                        }
                        None => button.disabled(true),
                    }
                });
                let time = r.response_time.as_ref().map_or("—".to_string(), |t| {
                    format!(
                        "median {} · p95 {}",
                        format::duration(t.median),
                        format::duration(t.p95)
                    )
                });
                row()
                    .child(
                        h_flex()
                            .w(px(90.))
                            .flex_shrink_0()
                            .gap_2()
                            .child(div().size(px(7.)).rounded(px(2.)).bg(swatch))
                            .child(r.protocol),
                    )
                    .child(num(70., fields_view::grouped(r.requests)))
                    .child(
                        h_flex()
                            .flex_1()
                            .min_w_0()
                            .flex_wrap()
                            .gap_1()
                            .children(outcomes),
                    )
                    .child(
                        div()
                            .w(px(180.))
                            .flex_shrink_0()
                            .text_right()
                            .font_family(mono.clone())
                            .text_color(if r.response_time.is_some() {
                                theme::text()
                            } else {
                                muted
                            })
                            .child(time),
                    )
            })
            .collect::<Vec<_>>();

        let convs = &stats.report.conversations;
        let conversations = convs
            .list
            .iter()
            .take(MAX_CONVERSATIONS)
            .enumerate()
            .map(|(i, c)| {
                let filter = c.filter();
                let first = c.first_packet as u64 + 1;
                let icon_button = |id: &'static str, icon: AssetIcon, tip: &'static str| {
                    Button::new((id, i))
                        .icon(Icon::new(icon))
                        .xsmall()
                        .ghost()
                        .tooltip(tip)
                };
                row()
                    .child(
                        div()
                            .w(px(44.))
                            .flex_shrink_0()
                            .text_color(
                                format::protocol_swatch(c.transport).map_or(muted, theme::swatch),
                            )
                            .child(c.transport),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_ellipsis()
                            .font_family(mono.clone())
                            .child(format!("{} ↔ {}", c.a, c.b)),
                    )
                    .child(num(70., fields_view::grouped(c.packets)))
                    .child(num(90., fields_view::grouped(c.bytes)))
                    .child(num(
                        80.,
                        format!("{:.3}", c.first_us.saturating_sub(t0) as f64 / 1e6),
                    ))
                    .child(num(80., format!("{:.3}", c.duration_secs())))
                    .child(
                        h_flex()
                            .w(px(110.))
                            .flex_shrink_0()
                            .justify_end()
                            .child(
                                icon_button(
                                    "conv-filter",
                                    AssetIcon::Funnel,
                                    "Filter for this conversation",
                                )
                                .on_click(cx.listener(
                                    move |this, _, window, cx| this.set_filter(&filter, window, cx),
                                )),
                            )
                            .child(
                                icon_button(
                                    "conv-highlight",
                                    AssetIcon::Rows3,
                                    "Highlight this conversation in the packet list",
                                )
                                .on_click(cx.listener(
                                    move |this, _, _, cx| {
                                        this.sequence.unit = SequenceUnit::Stream;
                                        this.sequence.on = true;
                                        this.go_to_packet(first, cx);
                                        this.update_sequence(cx);
                                    },
                                )),
                            )
                            .child(
                                icon_button(
                                    "conv-follow",
                                    AssetIcon::ArrowLeftRight,
                                    "Follow this stream",
                                )
                                .on_click(cx.listener(
                                    move |this, _, _, cx| {
                                        this.go_to_packet(first, cx);
                                        this.follow_stream(cx);
                                    },
                                )),
                            ),
                    )
            })
            .collect::<Vec<_>>();
        let more = convs.list.len().saturating_sub(MAX_CONVERSATIONS);
        let untracked = convs.untracked_packets;

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
            .when(!replies.is_empty(), |d| {
                d.child(heading("Requests and responses"))
                    .child(header(&[
                        ("Protocol", 90., false),
                        ("Requests", 70., true),
                        ("Results", 200., false),
                    ]))
                    .children(replies)
            })
            .child(heading("Conversations"))
            .child(header(&[("", 44., false), ("Endpoints", 320., false)]))
            .children(conversations)
            .when(more > 0 || untracked > 0, |d| {
                let mut notes = Vec::new();
                if more > 0 {
                    notes.push(format!("{more} more conversations"));
                }
                if untracked > 0 {
                    notes.push(format!(
                        "{} packets in flows not tracked",
                        fields_view::grouped(untracked)
                    ));
                }
                d.child(
                    div()
                        .pt_2()
                        .text_sm()
                        .text_color(muted)
                        .child(notes.join(" · ")),
                )
            })
            .when(convs.list.is_empty(), |d| {
                d.child(
                    div()
                        .pt_2()
                        .text_sm()
                        .text_color(muted)
                        .child("No TCP, UDP or SCTP flows."),
                )
            })
    }
}
