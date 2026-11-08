//! Problems: malformed packets, error responses and TCP retransmissions
//! among the displayed packets, marked in the packet list and listed in the
//! bottom panel (see `dsct::session::problems`).

use dsct::session::problems::ProblemKind;
use gpui_kit::assets::IconName as AssetIcon;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{ActiveTheme as _, Icon, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::DsctApp;
use crate::bottom::BottomTab;
use crate::{fields_view, format, theme};

/// Problems listed per kind at most.
const MAX_LISTED: usize = 100;

/// The mark of a kind: red for packets that could not be read, orange for
/// failures reported by the protocol, yellow for retransmissions.
pub fn color(kind: ProblemKind) -> Hsla {
    match kind {
        ProblemKind::Malformed => theme::red(),
        ProblemKind::ErrorResponse => theme::orange(),
        ProblemKind::Retransmission => theme::yellow(),
    }
}

/// `count` packets, with `+` while the scan goes on.
pub fn count_text(count: usize, complete: bool) -> String {
    if complete {
        fields_view::grouped(count as u64)
    } else {
        format!("{}+", fields_view::grouped(count as u64))
    }
}

impl DsctApp {
    /// Open the bottom panel on the problems.
    pub(crate) fn show_problems(&mut self, cx: &mut Context<Self>) {
        self.bottom.tab = BottomTab::Problems;
        self.bottom.open = true;
        cx.notify();
    }

    /// Select packet `pkt_idx` and keep it in view.
    fn go_to_problem(&mut self, pkt_idx: usize, cx: &mut Context<Self>) {
        self.go_to_packet(pkt_idx as u64 + 1, cx);
        if let Some(row) = self.selected_row {
            self.table
                .update(cx, |table, cx| table.scroll_to_row(row, cx));
        }
    }

    /// The filter bar button: how many displayed packets have a problem.
    pub(crate) fn render_problems_button(
        &self,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let (count, complete) = self
            .session
            .borrow()
            .as_ref()
            .and_then(|s| {
                let scan = s.problems()?;
                Some((scan.packets(), scan.complete(s.displayed_count())))
            })
            .unwrap_or((0, true));
        Button::new("problems")
            .icon(Icon::new(AssetIcon::TriangleAlert))
            .label(format!("Problems {}", count_text(count, complete)))
            .small()
            .outline()
            .when(count > 0, |b| b.warning())
            .tooltip("Malformed packets, error responses and TCP retransmissions")
            .on_click(cx.listener(|this, _, _, cx| this.show_problems(cx)))
    }

    pub(crate) fn render_problems(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let theme = cx.theme();
        let (muted, border) = (theme.muted_foreground, theme.border);
        let mono = theme.mono_font_family.clone();
        let guard = self.session.borrow();
        let Some(scan) = guard.as_ref().and_then(|s| s.problems()) else {
            return div().id("problems");
        };
        let complete = scan.complete(guard.as_ref().map_or(0, |s| s.displayed_count()));
        let packets = scan.packets();

        let mut list = Vec::new();
        for kind in ProblemKind::ALL {
            let all: Vec<_> = scan.of_kind(kind).collect();
            let count = all.len();
            let heading = h_flex()
                .gap_3()
                .h(px(30.))
                .px_3()
                .border_t_1()
                .border_color(border)
                .when(count == 0, |d| d.text_color(muted))
                .child(div().size(px(8.)).rounded_full().bg(if count == 0 {
                    muted
                } else {
                    color(kind)
                }))
                .child(
                    div()
                        .w(px(150.))
                        .flex_shrink_0()
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(kind.title()),
                )
                .child(
                    div()
                        .w(px(56.))
                        .flex_shrink_0()
                        .text_right()
                        .font_family(mono.clone())
                        .child(count_text(count, complete)),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .text_ellipsis()
                        .text_color(muted)
                        .child(kind.description()),
                )
                .children(kind.filter().filter(|_| count > 0).map(|filter| {
                    Button::new(("problem-filter", kind as usize))
                        .label("Show these")
                        .xsmall()
                        .outline()
                        .tooltip(format!("Filter: {filter}"))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.set_filter(filter, window, cx)
                        }))
                }));
            list.push(heading.into_any_element());
            for (i, p) in all.iter().take(MAX_LISTED).enumerate() {
                let pkt_idx = p.pkt_idx;
                let protocol_color =
                    format::protocol_swatch(p.protocol).map_or(muted, theme::swatch);
                list.push(
                    h_flex()
                        .id(("problem", kind as usize * 1_000_000 + i))
                        .gap_3()
                        .h(px(26.))
                        .px_3()
                        .cursor_pointer()
                        .hover(|d| d.bg(theme::hover()))
                        .child(div().w(px(8.)).flex_shrink_0())
                        .child(
                            div()
                                .w(px(150.))
                                .flex_shrink_0()
                                .font_family(mono.clone())
                                .text_color(muted)
                                .child(format!("Packet {}", pkt_idx + 1)),
                        )
                        .child(
                            div()
                                .w(px(56.))
                                .flex_shrink_0()
                                .text_right()
                                .text_color(protocol_color)
                                .child(p.protocol),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w_0()
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .text_ellipsis()
                                .child(p.text.clone()),
                        )
                        .on_click(
                            cx.listener(move |this, _, _, cx| this.go_to_problem(pkt_idx, cx)),
                        )
                        .into_any_element(),
                );
            }
            if count > MAX_LISTED {
                list.push(
                    div()
                        .px_3()
                        .pb_1()
                        .pl(px(193.))
                        .text_sm()
                        .text_color(muted)
                        .child(format!(
                            "{} more",
                            fields_view::grouped((count - MAX_LISTED) as u64)
                        ))
                        .into_any_element(),
                );
            }
        }
        drop(guard);

        v_flex()
            .id("problems")
            .size_full()
            .overflow_y_scroll()
            .pb_3()
            .child(
                div()
                    .px_3()
                    .py_2()
                    .text_sm()
                    .text_color(muted)
                    .child(if complete {
                        format!(
                            "Displayed packets · {} with a problem",
                            fields_view::grouped(packets as u64)
                        )
                    } else {
                        format!(
                            "Displayed packets · {} with a problem so far",
                            fields_view::grouped(packets as u64)
                        )
                    }),
            )
            .children(list)
    }
}

#[cfg(test)]
mod tests {
    use super::count_text;

    #[test]
    fn counts_show_a_plus_while_scanning() {
        assert_eq!(count_text(1234, true), "1,234");
        assert_eq!(count_text(3, false), "3+");
    }
}
