//! The Stream tab: a followed stream as the messages each side sent, with
//! the dissected first line as their heading, as text or hex (see
//! `dsct::session::FollowedStream`).

use std::collections::HashSet;
use std::ops::Range;

use dsct::session::{FollowedStream, StreamMessage};
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{ActiveTheme as _, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::DsctApp;
use crate::{fields_view, format, theme};

/// Lines of a message shown before "Show more".
const COLLAPSED: usize = 12;
/// Height of every row of the message list.
const ROW: f32 = 22.;
/// Bytes per hex line.
const HEX_WIDTH: usize = 16;
/// Characters of a line shown at most.
const MAX_LINE: usize = 400;

/// One row of the message list.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Row {
    Header(usize),
    Line(usize, String),
    More(usize, usize),
    Gap,
}

/// A followed stream and how it is shown.
pub struct StreamView {
    pub stream: FollowedStream,
    pub hex: bool,
    pub show_retransmissions: bool,
    expanded: HashSet<usize>,
    pub selected: Option<usize>,
    rows: Vec<Row>,
    /// Row of each shown message's header, by message.
    header_row: Vec<Option<usize>>,
    /// The messages listed in the outline.
    outline: Vec<usize>,
    pub scroll: UniformListScrollHandle,
}

impl StreamView {
    pub fn new(stream: FollowedStream) -> Self {
        let hex = stream.mostly_binary();
        let mut view = Self {
            stream,
            hex,
            show_retransmissions: false,
            expanded: HashSet::new(),
            selected: None,
            rows: Vec::new(),
            header_row: Vec::new(),
            outline: Vec::new(),
            scroll: UniformListScrollHandle::new(),
        };
        view.rebuild();
        view
    }

    /// Lay the rows out again after a display choice changed.
    fn rebuild(&mut self) {
        self.rows.clear();
        self.outline.clear();
        self.header_row = vec![None; self.stream.messages.len()];
        for (i, m) in self.stream.messages.iter().enumerate() {
            if m.retransmission && !self.show_retransmissions {
                continue;
            }
            self.outline.push(i);
            self.header_row[i] = Some(self.rows.len());
            self.rows.push(Row::Header(i));
            let lines = message_lines(m, self.hex);
            let shown = if self.expanded.contains(&i) || lines.len() <= COLLAPSED + 1 {
                lines.len()
            } else {
                COLLAPSED
            };
            let hidden = lines.len() - shown;
            self.rows
                .extend(lines.into_iter().take(shown).map(|l| Row::Line(i, l)));
            if hidden > 0 {
                self.rows.push(Row::More(i, hidden));
            }
            self.rows.push(Row::Gap);
        }
    }

    /// The stream as text, for the clipboard.
    pub fn copy_text(&self) -> String {
        let lines: Vec<(String, bool)> = self
            .stream
            .lines()
            .into_iter()
            .map(|l| (l.text, l.is_client))
            .collect();
        format::stream_text(&lines)
    }

    fn retransmissions(&self) -> usize {
        self.stream
            .messages
            .iter()
            .filter(|m| m.retransmission)
            .count()
    }
}

/// The lines a message shows: its text without the heading, or its hex.
fn message_lines(m: &StreamMessage, hex: bool) -> Vec<String> {
    if hex {
        return m
            .payload
            .chunks(HEX_WIDTH)
            .enumerate()
            .map(|(i, chunk)| hex_line(i * HEX_WIDTH, chunk))
            .collect();
    }
    let mut lines: Vec<String> = m
        .text_lines()
        .map(|l| {
            if l.chars().count() > MAX_LINE {
                let cut: String = l.chars().take(MAX_LINE).collect();
                format!("{cut}…")
            } else {
                l
            }
        })
        .collect();
    // The heading is the first line.
    if m.heading.is_some() && !lines.is_empty() && m.is_text() {
        lines.remove(0);
    }
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    lines
}

/// `chunk` at `offset` as hex and ASCII (`0010  47 45 54 …  GET …`).
fn hex_line(offset: usize, chunk: &[u8]) -> String {
    let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
    let ascii: String = chunk
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                b as char
            } else {
                '.'
            }
        })
        .collect();
    format!(
        "{offset:04x}  {:<width$}  {ascii}",
        hex.join(" "),
        width = HEX_WIDTH * 3 - 1
    )
}

/// What a message says it is: its heading, or its size.
fn title(m: &StreamMessage) -> String {
    match &m.heading {
        Some(h) => h.clone(),
        None => format!("{} bytes", fields_view::grouped(m.bytes)),
    }
}

/// The packets of a message (`#37–38`), numbered from 1.
fn packets(m: &StreamMessage) -> String {
    if m.first_packet == m.last_packet {
        format!("#{}", m.first_packet + 1)
    } else {
        format!("#{}–{}", m.first_packet + 1, m.last_packet + 1)
    }
}

/// Seconds as `+0.031 s`.
fn delta(us: u64) -> String {
    format!("+{:.3}", us as f64 / 1e6)
}

impl DsctApp {
    fn stream_view(&mut self) -> Option<&mut StreamView> {
        self.bottom.stream.as_mut()
    }

    fn stream_set_hex(&mut self, hex: bool, cx: &mut Context<Self>) {
        if let Some(v) = self.stream_view() {
            v.hex = hex;
            v.rebuild();
        }
        cx.notify();
    }

    fn stream_toggle_retransmissions(&mut self, cx: &mut Context<Self>) {
        if let Some(v) = self.stream_view() {
            v.show_retransmissions = !v.show_retransmissions;
            v.rebuild();
        }
        cx.notify();
    }

    fn stream_expand(&mut self, msg: usize, cx: &mut Context<Self>) {
        if let Some(v) = self.stream_view() {
            v.expanded.insert(msg);
            v.rebuild();
        }
        cx.notify();
    }

    /// Select message `msg`, its first packet, and show it.
    fn stream_select(&mut self, msg: usize, scroll: bool, cx: &mut Context<Self>) {
        let Some(v) = self.stream_view() else {
            return;
        };
        v.selected = Some(msg);
        if scroll && let Some(row) = v.header_row.get(msg).copied().flatten() {
            v.scroll.scroll_to_item(row, ScrollStrategy::Top);
        }
        let first = v.stream.messages.get(msg).map(|m| m.first_packet);
        if let Some(pkt_idx) = first {
            self.go_to_packet(pkt_idx as u64 + 1, cx);
        }
        cx.notify();
    }

    pub(crate) fn render_stream(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let mono = cx.theme().mono_font_family.clone();
        let (muted, border) = (theme::text_muted(), theme::border());
        let Some(view) = self.bottom.stream.as_ref() else {
            return div().id("stream");
        };
        let stream = &view.stream;
        let shown = view.outline.len();
        let bytes: u64 = view.outline.iter().map(|&i| stream.messages[i].bytes).sum();
        let mut summary = format!(
            "{} messages · {} bytes",
            fields_view::grouped(shown as u64),
            fields_view::grouped(bytes)
        );
        if stream.truncated_bytes > 0 {
            summary.push_str(&format!(
                " · the last {} bytes not kept",
                fields_view::grouped(stream.truncated_bytes)
            ));
        }
        let segment = |id: &'static str, label: &'static str, on: bool| {
            Button::new(id)
                .label(label)
                .xsmall()
                .when(on, |b| b.primary())
                .when(!on, |b| b.outline())
        };
        let filter = stream.filter.clone();
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
                    .font_family(mono.clone())
                    .child(stream.title.clone()),
            )
            .child(div().text_color(muted).child(summary))
            .child(div().flex_1())
            .child(
                h_flex()
                    .gap_1()
                    .child(
                        segment("stream-text", "Text", !view.hex)
                            .on_click(cx.listener(|this, _, _, cx| this.stream_set_hex(false, cx))),
                    )
                    .child(
                        segment("stream-hex", "Hex", view.hex)
                            .on_click(cx.listener(|this, _, _, cx| this.stream_set_hex(true, cx))),
                    ),
            )
            .child(
                Button::new("stream-only")
                    .label("Only this stream")
                    .xsmall()
                    .outline()
                    .tooltip(format!("Filter: {filter}"))
                    .on_click(
                        cx.listener(move |this, _, window, cx| {
                            this.set_filter(&filter, window, cx)
                        }),
                    ),
            );

        let retransmissions = view.retransmissions();
        let outline = v_flex()
            .w(px(280.))
            .flex_shrink_0()
            .h_full()
            .border_r_1()
            .border_color(border)
            .child(
                div()
                    .px_3()
                    .pt_2()
                    .pb_1()
                    .text_xs()
                    .text_color(muted)
                    .child("MESSAGES"),
            )
            .child(
                uniform_list(
                    "stream-outline",
                    shown,
                    cx.processor(|this, range: Range<usize>, _, cx| {
                        let Some(view) = this.bottom.stream.as_ref() else {
                            return Vec::new();
                        };
                        let mono = cx.theme().mono_font_family.clone();
                        range
                            .filter_map(|n| {
                                let i = *view.outline.get(n)?;
                                let m = &view.stream.messages[i];
                                let prev = n
                                    .checked_sub(1)
                                    .and_then(|p| view.outline.get(p))
                                    .map_or(m.time_us, |&p| view.stream.messages[p].time_us);
                                let selected = view.selected == Some(i);
                                Some(
                                    h_flex()
                                        .id(("stream-outline-row", n))
                                        .w_full()
                                        .h(px(26.))
                                        .px_3()
                                        .gap_2()
                                        .text_sm()
                                        .cursor_pointer()
                                        .when(selected, |d| {
                                            d.bg(theme::selection())
                                                .border_l_2()
                                                .border_color(theme::accent())
                                        })
                                        .when(!selected, |d| d.hover(|d| d.bg(theme::hover())))
                                        .opacity(if m.retransmission { 0.55 } else { 1. })
                                        .child(
                                            div()
                                                .w(px(28.))
                                                .flex_shrink_0()
                                                .text_right()
                                                .text_xs()
                                                .font_family(mono.clone())
                                                .text_color(theme::text_muted())
                                                .child((n + 1).to_string()),
                                        )
                                        .child(
                                            div()
                                                .flex_shrink_0()
                                                .text_color(side(m.is_client))
                                                .child(format::direction_marker(m.is_client)),
                                        )
                                        .child(
                                            div()
                                                .flex_1()
                                                .min_w_0()
                                                .overflow_hidden()
                                                .whitespace_nowrap()
                                                .text_ellipsis()
                                                .text_color(heading_color(m))
                                                .child(short(m)),
                                        )
                                        .child(
                                            div()
                                                .flex_shrink_0()
                                                .text_xs()
                                                .font_family(mono.clone())
                                                .text_color(theme::text_muted())
                                                .child(delta(m.time_us.saturating_sub(prev))),
                                        )
                                        .on_click(cx.listener(move |this, _, _, cx| {
                                            this.stream_select(i, true, cx)
                                        })),
                                )
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .flex_1(),
            )
            .when(retransmissions > 0, |d| {
                let showing = view.show_retransmissions;
                d.child(
                    h_flex()
                        .gap_2()
                        .px_3()
                        .py_2()
                        .border_t_1()
                        .border_color(border)
                        .text_xs()
                        .text_color(muted)
                        .child(div().flex_1().child(format!(
                            "{retransmissions} retransmitted segments {}",
                            if showing { "shown" } else { "hidden" }
                        )))
                        .child(
                            Button::new("stream-retrans")
                                .label(if showing { "Hide" } else { "Show" })
                                .xsmall()
                                .outline()
                                .on_click(cx.listener(|this, _, _, cx| {
                                    this.stream_toggle_retransmissions(cx)
                                })),
                        ),
                )
            });

        let count = view.rows.len();
        let messages = uniform_list(
            "stream-messages",
            count,
            cx.processor(|this, range: Range<usize>, _, cx| {
                let Some(view) = this.bottom.stream.as_ref() else {
                    return Vec::new();
                };
                let mono = cx.theme().mono_font_family.clone();
                range
                    .filter_map(|r| {
                        let row = view.rows.get(r)?;
                        Some(render_row(view, r, row, &mono, cx))
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .track_scroll(&view.scroll)
        .flex_1()
        .px_3()
        .py_2();

        div().id("stream").size_full().child(
            v_flex().size_full().child(toolbar).child(
                h_flex()
                    .flex_1()
                    .min_h_0()
                    .child(outline)
                    .child(v_flex().flex_1().min_w_0().h_full().child(messages).child(
                        div().px_3().py_1().border_t_1().border_color(border).text_xs().text_color(muted).child(
                            "Segments of one message are joined; headings are the dissected first lines. Click a message to select its first packet.",
                        ),
                    )),
            ),
        )
    }
}

/// The client's color (orange) or the server's (blue).
fn side(client: bool) -> Hsla {
    if client {
        theme::orange()
    } else {
        theme::blue()
    }
}

fn heading_color(m: &StreamMessage) -> Hsla {
    if m.error {
        theme::orange()
    } else {
        theme::text_bright()
    }
}

/// The heading without the protocol version (`REGISTER sip:…`, `200 OK`).
fn short(m: &StreamMessage) -> String {
    let t = title(m);
    if m.retransmission {
        return format!("[Retransmission] {t}");
    }
    let t = t
        .strip_suffix(" SIP/2.0")
        .or_else(|| t.strip_suffix(" HTTP/1.1"))
        .or_else(|| t.strip_suffix(" HTTP/1.0"))
        .unwrap_or(&t);
    match t.split_once(' ') {
        Some((version, rest)) if version.starts_with("SIP/") || version.starts_with("HTTP/") => {
            rest.to_string()
        }
        _ => t.to_string(),
    }
}

fn render_row(
    view: &StreamView,
    r: usize,
    row: &Row,
    mono: &SharedString,
    cx: &mut Context<DsctApp>,
) -> AnyElement {
    let msg = match row {
        Row::Header(i) | Row::Line(i, _) | Row::More(i, _) => *i,
        Row::Gap => return div().h(px(ROW)).into_any_element(),
    };
    let m = &view.stream.messages[msg];
    let selected = view.selected == Some(msg);
    // The client's messages on the left, the server's indented.
    let card = div()
        .h(px(ROW))
        .flex()
        .items_center()
        .gap_3()
        .px_3()
        .border_l_2()
        .border_color(side(m.is_client))
        .bg(if selected {
            theme::selection()
        } else {
            theme::elevated()
        })
        .when(m.is_client, |d| d.mr(relative(0.12)))
        .when(!m.is_client, |d| d.ml(relative(0.12)))
        .opacity(if m.retransmission { 0.55 } else { 1. });
    let card = match row {
        Row::Header(_) => {
            let mut meta = vec![packets(m)];
            if let Some(prev) = view.outline.iter().take_while(|&&i| i != msg).last() {
                meta.push(format!(
                    "{} s",
                    delta(
                        m.time_us
                            .saturating_sub(view.stream.messages[*prev].time_us)
                    )
                ));
            }
            meta.push(format!("{} B", fields_view::grouped(m.bytes)));
            if m.packets > 1 {
                meta.push(format!("{} segments", m.packets));
            }
            card.child(
                div()
                    .flex_shrink_0()
                    .text_xs()
                    .text_color(side(m.is_client))
                    .child(if m.is_client {
                        "→ client"
                    } else {
                        "← server"
                    }),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .font_family(mono.clone())
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(heading_color(m))
                    .child(if m.retransmission {
                        format!("[Retransmission] {}", title(m))
                    } else {
                        title(m)
                    }),
            )
            .when(m.error, |d| {
                d.child(
                    div()
                        .flex_shrink_0()
                        .px_1()
                        .rounded(px(4.))
                        .bg(theme::orange().opacity(0.16))
                        .text_xs()
                        .text_color(theme::orange())
                        .child("error"),
                )
            })
            .child(
                div()
                    .flex_shrink_0()
                    .text_xs()
                    .text_color(theme::text_muted())
                    .child(meta.join(" · ")),
            )
        }
        Row::Line(_, text) => card.child(
            div()
                .flex_1()
                .min_w_0()
                .overflow_hidden()
                .whitespace_nowrap()
                .text_ellipsis()
                .font_family(mono.clone())
                .text_sm()
                .text_color(theme::text())
                .child(text.clone()),
        ),
        Row::More(_, hidden) => card.child(
            div()
                .text_xs()
                .text_color(theme::accent())
                .child(format!("Show {hidden} more lines")),
        ),
        Row::Gap => card,
    };
    let expand = matches!(row, Row::More(..));
    div()
        .id(("stream-row", r))
        .w_full()
        .cursor_pointer()
        .child(card)
        .on_click(cx.listener(move |this, _, _, cx| {
            if expand {
                this.stream_expand(msg, cx);
            } else {
                this.stream_select(msg, false, cx);
            }
        }))
        .into_any_element()
}

#[cfg(test)]
mod tests {
    use super::{hex_line, message_lines, short};
    use dsct::session::StreamMessage;

    fn message(payload: &[u8], heading: Option<&str>) -> StreamMessage {
        StreamMessage {
            is_client: true,
            first_packet: 0,
            last_packet: 1,
            packets: 2,
            time_us: 0,
            bytes: payload.len() as u64,
            payload: payload.to_vec(),
            heading: heading.map(str::to_string),
            error: false,
            retransmission: false,
        }
    }

    #[test]
    fn the_heading_is_not_repeated_in_the_body() {
        let m = message(
            b"SIP/2.0 200 OK\r\nCSeq: 1 REGISTER\r\n\r\n",
            Some("SIP/2.0 200 OK"),
        );
        assert_eq!(message_lines(&m, false), ["CSeq: 1 REGISTER"]);
        assert_eq!(short(&m), "200 OK");
        let req = message(b"GET / HTTP/1.1\r\n", Some("GET / HTTP/1.1"));
        assert_eq!(short(&req), "GET /");
    }

    #[test]
    fn hex_lines_show_offset_bytes_and_text() {
        assert_eq!(
            hex_line(16, b"GET \x00"),
            format!("0010  47 45 54 20 00{}  GET .", " ".repeat(47 - 14))
        );
        let m = message(&[0u8; 20], None);
        assert_eq!(message_lines(&m, true).len(), 2);
        assert_eq!(short(&m), "20 bytes");
    }
}
