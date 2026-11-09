//! The Flow tab: the highlighted sequence as a sequence diagram, one column
//! per host and one arrow per packet (see `dsct::session::flow`).

use std::net::IpAddr;
use std::ops::Range;

use dsct::session::flow::{FlowRow, MAX_FLOW_ROWS};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{ActiveTheme as _, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::DsctApp;
use crate::bottom::BottomTab;
use crate::{fields_view, format, theme};

/// Height of a message row.
const ROW: f32 = 30.;
/// Width of the time column.
const TIME: f32 = 96.;

/// How the Flow tab shows times.
#[derive(Default)]
pub struct FlowView {
    /// Since the previous message instead of since the first.
    pub since_previous: bool,
    pub scroll: UniformListScrollHandle,
    /// Bring the selected packet's row into view once its row exists.
    pub reveal: bool,
}

/// Where column `i` of `n` is, as a fraction of the diagram's width.
fn column(i: usize, n: usize) -> f32 {
    (i as f32 + 0.5) / n.max(1) as f32
}

/// Seconds as `12.345` or `+0.002`.
fn seconds(us: u64, plus: bool) -> String {
    let s = us as f64 / 1e6;
    if plus {
        format!("+{s:.3}")
    } else {
        format!("{s:.3}")
    }
}

/// The color of a message's arrow.
fn color(row: &FlowRow) -> Hsla {
    if row.error {
        theme::orange()
    } else {
        format::protocol_swatch(row.protocol).map_or(theme::text_muted(), theme::swatch)
    }
}

/// The diagram as text, for the clipboard.
pub fn flow_text(rows: &[FlowRow]) -> String {
    let t0 = rows.first().map_or(0, |r| r.time_us);
    rows.iter()
        .map(|r| {
            format!(
                "{:>10}  {} → {}  {}\n",
                seconds(r.time_us.saturating_sub(t0), false),
                r.src,
                r.dst,
                r.label
            )
        })
        .collect()
}

/// One row to paint: the lifelines and the arrow.
struct Arrow {
    columns: usize,
    from: f32,
    to: f32,
    color: Hsla,
    dashed: bool,
}

fn paint_arrow(a: &Arrow, bounds: Bounds<Pixels>, window: &mut Window) {
    let (ox, oy) = (f32::from(bounds.origin.x), f32::from(bounds.origin.y));
    let (w, h) = (f32::from(bounds.size.width), f32::from(bounds.size.height));
    let lifeline = theme::text_faint();
    for i in 0..a.columns {
        let x = ox + column(i, a.columns) * w;
        let mut path = PathBuilder::stroke(px(1.)).dash_array(&[px(3.), px(3.)]);
        path.move_to(point(px(x), px(oy)));
        path.line_to(point(px(x), px(oy + h)));
        if let Ok(path) = path.build() {
            window.paint_path(path, lifeline);
        }
    }
    let y = oy + h - 8.;
    let x1 = ox + a.from * w;
    // A message to the same host loops out to the right.
    let x2 = if (a.to - a.from).abs() < 1e-6 {
        x1 + 28.
    } else {
        ox + a.to * w
    };
    let dir = if x2 >= x1 { 1. } else { -1. };
    let mut line = PathBuilder::stroke(px(1.6));
    if a.dashed {
        line = line.dash_array(&[px(4.), px(4.)]);
    }
    line.move_to(point(px(x1), px(y)));
    line.line_to(point(px(x2 - dir * 6.), px(y)));
    if let Ok(path) = line.build() {
        window.paint_path(path, a.color);
    }
    let mut head = PathBuilder::fill();
    head.move_to(point(px(x2), px(y)));
    head.line_to(point(px(x2 - dir * 8.), px(y - 4.)));
    head.line_to(point(px(x2 - dir * 8.), px(y + 4.)));
    head.close();
    if let Ok(path) = head.build() {
        window.paint_path(path, a.color);
    }
}

impl DsctApp {
    /// Draw the sequence of the selected packet in the Flow tab.
    pub(crate) fn open_flow(&mut self, cx: &mut Context<Self>) {
        if !self.sequence.on {
            self.sequence.on = true;
            self.update_sequence(cx);
        }
        if let Some(session) = self.session.borrow_mut().as_mut() {
            session.start_flow();
        }
        self.bottom.flow_open = true;
        self.bottom.flow.reveal = true;
        self.bottom.tab = BottomTab::Flow;
        self.bottom.open = true;
        self.ensure_ticking(cx);
        cx.notify();
    }

    pub(crate) fn render_flow(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let mono = cx.theme().mono_font_family.clone();
        let (muted, border) = (theme::text_muted(), theme::border());
        let guard = self.session.borrow();
        let Some(session) = guard.as_ref() else {
            return div().id("flow");
        };
        let Some(flow) = session.flow() else {
            let hint = if self.sequence.on {
                "Select a packet: its call, stream or host pair is drawn here."
            } else {
                "Turn on sequences (the Sequence bar) to draw the selected packet's."
            };
            return div()
                .id("flow")
                .size_full()
                .p_3()
                .text_sm()
                .text_color(muted)
                .child(hint);
        };
        let hosts = flow.hosts();
        let n = hosts.len();
        let count = flow.rows.len();
        let complete = session
            .sequence()
            .is_some_and(|s| s.complete(session.displayed_count()));
        let selected_pkt = self
            .selected_row
            .and_then(|row| session.filtered.select(row));
        let selected_at =
            selected_pkt.and_then(|p| flow.rows.binary_search_by_key(&p, |r| r.pkt_idx).ok());
        let selected = selected_at.map(|i| &flow.rows[i]);
        if self.bottom.flow.reveal
            && let Some(i) = selected_at
        {
            self.bottom.flow.reveal = false;
            self.bottom
                .flow
                .scroll
                .scroll_to_item(i, ScrollStrategy::Center);
        }
        let t0 = flow.rows.first().map_or(0, |r| r.time_us);
        let copy = flow_text(&flow.rows);
        let since_previous = self.bottom.flow.since_previous;

        let segment = |id: &'static str, label: &'static str, on: bool| {
            Button::new(id)
                .label(label)
                .xsmall()
                .when(on, |b| b.primary())
                .when(!on, |b| b.outline())
        };
        let mut summary = format!(
            "{}{} packets",
            fields_view::grouped(count as u64),
            if complete { "" } else { "+" }
        );
        if flow.more > 0 {
            summary = format!(
                "the first {} packets of {}",
                fields_view::grouped(MAX_FLOW_ROWS as u64),
                fields_view::grouped((count + flow.more) as u64)
            );
        }
        let toolbar = h_flex()
            .flex_wrap()
            .gap_3()
            .px_3()
            .py_1()
            .border_b_1()
            .border_color(border)
            .text_sm()
            .child(
                div()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(flow.key.label()),
            )
            .child(div().text_color(muted).child(summary))
            .child(div().flex_1())
            .child(
                h_flex()
                    .gap_1()
                    .child(
                        segment("flow-since-first", "Since first", !since_previous).on_click(
                            cx.listener(|this, _, _, cx| {
                                this.bottom.flow.since_previous = false;
                                cx.notify();
                            }),
                        ),
                    )
                    .child(
                        segment("flow-since-previous", "Since previous", since_previous).on_click(
                            cx.listener(|this, _, _, cx| {
                                this.bottom.flow.since_previous = true;
                                cx.notify();
                            }),
                        ),
                    ),
            )
            .child(
                Button::new("flow-copy")
                    .label("Copy as text")
                    .xsmall()
                    .outline()
                    .on_click(move |_, _, cx| {
                        cx.write_to_clipboard(ClipboardItem::new_string(copy.clone()))
                    }),
            );

        // Hosts across the top.
        let header = h_flex()
            .h(px(46.))
            .flex_shrink_0()
            .border_b_1()
            .border_color(border)
            .child(
                div()
                    .w(px(TIME))
                    .flex_shrink_0()
                    .pl_3()
                    .text_xs()
                    .text_color(muted)
                    .child("TIME"),
            )
            .child(
                div()
                    .relative()
                    .flex_1()
                    .h_full()
                    .children(hosts.iter().enumerate().map(|(i, addr)| {
                        let ports = flow.ports(*addr);
                        let ports = match ports.len() {
                            0 => String::new(),
                            1 => format!("port {}", ports[0]),
                            k => format!("{k} ports"),
                        };
                        v_flex()
                            .absolute()
                            .left(relative(column(i, n)))
                            .ml(px(-110.))
                            .w(px(220.))
                            .top(px(5.))
                            .items_center()
                            .child(
                                div()
                                    .max_w(px(210.))
                                    .px_2()
                                    .rounded(px(6.))
                                    .border_1()
                                    .border_color(theme::border_strong())
                                    .bg(theme::elevated())
                                    .font_family(mono.clone())
                                    .text_xs()
                                    .text_color(theme::text_bright())
                                    .overflow_hidden()
                                    .whitespace_nowrap()
                                    .text_ellipsis()
                                    .child(addr.to_string()),
                            )
                            .child(div().text_xs().text_color(muted).child(ports))
                    })),
            );

        let rows = uniform_list(
            "flow-rows",
            count,
            cx.processor(move |this, range: Range<usize>, _, cx| {
                let guard = this.session.borrow();
                let Some(session) = guard.as_ref() else {
                    return Vec::new();
                };
                let Some(flow) = session.flow() else {
                    return Vec::new();
                };
                let hosts: Vec<IpAddr> = flow.hosts();
                let n = hosts.len();
                let col = |addr: IpAddr| hosts.iter().position(|h| *h == addr).unwrap_or(0);
                let selected_pkt = this
                    .selected_row
                    .and_then(|row| session.filtered.select(row));
                let since_previous = this.bottom.flow.since_previous;
                let mono = cx.theme().mono_font_family.clone();
                let t0 = flow.rows.first().map_or(0, |r| r.time_us);
                range
                    .filter_map(|i| {
                        let row = flow.rows.get(i)?;
                        let (from, to) =
                            (column(col(row.src.addr), n), column(col(row.dst.addr), n));
                        let time = if since_previous {
                            let prev = i
                                .checked_sub(1)
                                .map_or(row.time_us, |p| flow.rows[p].time_us);
                            seconds(row.time_us.saturating_sub(prev), i > 0)
                        } else {
                            seconds(row.time_us.saturating_sub(t0), false)
                        };
                        let (lo, hi) = if (from - to).abs() < 1e-6 {
                            (from, (from + 0.25).min(1.))
                        } else {
                            (from.min(to), from.max(to))
                        };
                        let arrow = Arrow {
                            columns: n,
                            from,
                            to,
                            color: color(row),
                            dashed: row.retransmission,
                        };
                        let label = if row.retransmission && !row.label.starts_with('[') {
                            format!("[Retransmission] {}", row.label)
                        } else {
                            row.label.clone()
                        };
                        let pkt_idx = row.pkt_idx;
                        let is_selected = selected_pkt == Some(pkt_idx);
                        Some(
                            h_flex()
                                .id(("flow-row", i))
                                .w_full()
                                .h(px(ROW))
                                .cursor_pointer()
                                .when(is_selected, |d| d.bg(theme::selection()))
                                .when(!is_selected, |d| d.hover(|d| d.bg(theme::hover())))
                                .opacity(if row.retransmission { 0.55 } else { 1. })
                                .child(
                                    div()
                                        .w(px(TIME))
                                        .flex_shrink_0()
                                        .pl_3()
                                        .text_xs()
                                        .font_family(mono.clone())
                                        .text_color(theme::text_muted())
                                        .child(time),
                                )
                                .child(
                                    div()
                                        .relative()
                                        .flex_1()
                                        .h_full()
                                        .child(
                                            canvas(
                                                |_, _, _| (),
                                                move |bounds, (), window, _| {
                                                    paint_arrow(&arrow, bounds, window)
                                                },
                                            )
                                            .absolute()
                                            .size_full(),
                                        )
                                        .child(
                                            div()
                                                .absolute()
                                                .left(relative(lo))
                                                .w(relative(hi - lo))
                                                .top(px(1.))
                                                .px_2()
                                                .text_center()
                                                .text_xs()
                                                .font_family(mono.clone())
                                                .overflow_hidden()
                                                .whitespace_nowrap()
                                                .text_ellipsis()
                                                .text_color(if row.error {
                                                    theme::orange()
                                                } else {
                                                    theme::text()
                                                })
                                                .child(label),
                                        ),
                                )
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.go_to_packet(pkt_idx as u64 + 1, cx)
                                })),
                        )
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .track_scroll(&self.bottom.flow.scroll)
        .flex_1();

        let detail = selected.map(|row| {
            let field = |label: &'static str, value: String| {
                h_flex()
                    .gap_2()
                    .child(
                        div()
                            .w(px(64.))
                            .flex_shrink_0()
                            .text_color(muted)
                            .child(label),
                    )
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .font_family(mono.clone())
                            .child(value),
                    )
            };
            v_flex()
                .gap_2()
                .child(
                    div()
                        .font_family(mono.clone())
                        .text_color(if row.error {
                            theme::orange()
                        } else {
                            theme::text_bright()
                        })
                        .child(row.label.clone()),
                )
                .child(field("Packet", format!("#{}", row.pkt_idx + 1)))
                .child(field(
                    "Time",
                    format!("{} s", seconds(row.time_us.saturating_sub(t0), false)),
                ))
                .child(field("From", row.src.to_string()))
                .child(field("To", row.dst.to_string()))
                .child(field("Protocol", row.protocol.to_string()))
                .child(
                    h_flex().gap_2().pt_1().child(
                        Button::new("flow-follow")
                            .label("Follow stream")
                            .xsmall()
                            .outline()
                            .on_click(cx.listener(|this, _, _, cx| this.follow_stream(cx))),
                    ),
                )
        });
        let side = v_flex()
            .w(px(300.))
            .flex_shrink_0()
            .h_full()
            .gap_2()
            .px_3()
            .py_2()
            .border_l_1()
            .border_color(border)
            .text_sm()
            .child(div().text_xs().text_color(muted).child("SELECTED MESSAGE"))
            .children(detail)
            .when(selected.is_none(), |d| {
                d.child(
                    div()
                        .text_color(muted)
                        .child("The selected packet is not in this sequence."),
                )
            });
        let footer = h_flex()
            .flex_wrap()
            .gap_3()
            .px_3()
            .py_1()
            .border_t_1()
            .border_color(border)
            .text_xs()
            .text_color(muted)
            .child(div().flex_1().min_w_0().child(
                "Columns: the hosts of the sequence (inner addresses) · click a message to select its packet",
            ))
            .child("Dashed: retransmission")
            .child(div().text_color(theme::orange()).child("Orange: error response"));

        drop(guard);
        div().id("flow").size_full().child(
            v_flex().size_full().child(toolbar).child(
                h_flex()
                    .flex_1()
                    .min_h_0()
                    .child(
                        v_flex()
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .overflow_hidden()
                            .child(header)
                            .child(rows)
                            .child(footer),
                    )
                    .child(side),
            ),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{column, flow_text, seconds};
    use dsct::session::flow::{FlowEnd, FlowRow};

    #[test]
    fn columns_spread_over_the_width() {
        assert_eq!(column(0, 1), 0.5);
        assert_eq!(column(0, 4), 0.125);
        assert_eq!(column(3, 4), 0.875);
    }

    #[test]
    fn times_read_as_seconds() {
        assert_eq!(seconds(1_500, false), "0.002");
        assert_eq!(seconds(2_000_000, true), "+2.000");
    }

    #[test]
    fn the_text_form_lists_each_message() {
        let row = FlowRow {
            pkt_idx: 0,
            time_us: 1_000_000,
            src: FlowEnd {
                addr: "192.0.2.1".parse().unwrap(),
                port: Some(5060),
            },
            dst: FlowEnd {
                addr: "192.0.2.2".parse().unwrap(),
                port: Some(5060),
            },
            label: "Request: INVITE sip:bob@example.com".into(),
            protocol: "SIP",
            error: false,
            retransmission: false,
        };
        let text = flow_text(&[row]);
        assert_eq!(
            text,
            "     0.000  192.0.2.1:5060 → 192.0.2.2:5060  Request: INVITE sip:bob@example.com\n"
        );
    }
}
