//! The sidebar: the open capture, its protocols, and its top talkers, each
//! a quick filter.

use gpui_kit::component::button::Button;
use gpui_kit::component::{Icon, IconName, Sizable as _, h_flex, v_flex};
use gpui_kit::*;

use crate::app::DsctApp;
use crate::{format, theme};

/// Protocols listed at most.
const MAX_PROTOCOLS: usize = 14;

/// The sidebar's width.
const WIDTH: f32 = 232.;

/// A filter that matches the packets of `src` → `dst`.
fn talker_filter(src: &str, dst: &str) -> String {
    let ip = if src.contains(':') { "ipv6" } else { "ipv4" };
    format!("{ip}.src = '{src}' AND {ip}.dst = '{dst}'")
}

impl DsctApp {
    fn section(title: &'static str) -> impl IntoElement {
        div()
            .px_3()
            .pt_4()
            .pb_1p5()
            .text_xs()
            .font_weight(FontWeight::SEMIBOLD)
            .text_color(theme::text_muted())
            .child(title)
    }

    pub(crate) fn render_sidebar(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let (file, total, has_filter) = match self.session.borrow().as_ref() {
            Some(s) => (
                s.file_name.clone(),
                s.total_count(),
                !s.applied_filter.is_empty(),
            ),
            None => (String::new(), 0, false),
        };
        let mono = cx.theme_mono_font();

        let capture = h_flex()
            .mx_1p5()
            .px_2()
            .py_1()
            .gap_2()
            .rounded(px(5.))
            .bg(theme::selection())
            .text_color(theme::text_bright())
            .child(
                Icon::new(IconName::FileText)
                    .small()
                    .text_color(theme::text_muted()),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .child(file),
            )
            .child(
                div()
                    .text_xs()
                    .font_family(mono.clone())
                    .text_color(theme::text_muted())
                    .child(total.to_string()),
            );

        let overview: AnyElement = match &self.overview.stats {
            Some(stats) => {
                let protocols = format::protocol_shares(&stats.protocols, stats.total_packets)
                    .into_iter()
                    .take(MAX_PROTOCOLS)
                    .map(|(name, count, _)| {
                        let color = format::protocol_swatch(&name)
                            .map_or(theme::text_muted(), theme::swatch);
                        let filter = name.to_lowercase();
                        h_flex()
                            .id(SharedString::from(format!("proto-{name}")))
                            .mx_1p5()
                            .px_2()
                            .h(px(26.))
                            .gap_2()
                            .rounded(px(5.))
                            .hover(|d| d.bg(theme::hover()))
                            .cursor_pointer()
                            .child(div().size(px(8.)).rounded(px(2.)).bg(color))
                            .child(div().flex_1().child(name))
                            .child(
                                div()
                                    .text_xs()
                                    .font_family(mono.clone())
                                    .text_color(theme::text_muted())
                                    .child(count.to_string()),
                            )
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.set_filter(&filter, window, cx)
                            }))
                    })
                    .collect::<Vec<_>>();
                let talkers = stats
                    .top_talkers
                    .iter()
                    .flatten()
                    .enumerate()
                    .map(|(i, t)| {
                        let filter = talker_filter(&t.src, &t.dst);
                        v_flex()
                            .id(("talker", i))
                            .mx_1p5()
                            .px_2()
                            .py_1()
                            .rounded(px(5.))
                            .hover(|d| d.bg(theme::hover()))
                            .cursor_pointer()
                            .font_family(mono.clone())
                            .text_xs()
                            .child(div().text_color(theme::text()).child(t.src.clone()))
                            .child(
                                div()
                                    .text_color(theme::text_muted())
                                    .child(format!("→ {} · {}", t.dst, t.packets)),
                            )
                            .on_click(cx.listener(move |this, _, window, cx| {
                                this.set_filter(&filter, window, cx)
                            }))
                    })
                    .collect::<Vec<_>>();
                v_flex()
                    .child(Self::section("PROTOCOLS"))
                    .children(protocols)
                    .child(Self::section("TOP TALKERS"))
                    .children(talkers)
                    .into_any_element()
            }
            None if self.overview.job => div()
                .px_3()
                .pt_4()
                .text_xs()
                .text_color(theme::text_muted())
                .child("Building overview…")
                .into_any_element(),
            None if has_filter => div()
                .px_3()
                .pt_4()
                .text_xs()
                .text_color(theme::text_muted())
                .child("Clear the filter to build the overview of the whole capture.")
                .into_any_element(),
            None => v_flex()
                .px_3()
                .pt_4()
                .gap_2()
                .text_xs()
                .text_color(theme::text_muted())
                .child("Protocols and top talkers need every packet dissected.")
                .child(
                    Button::new("compute-overview")
                        .label("Build overview")
                        .small()
                        .outline()
                        .on_click(cx.listener(|this, _, _, cx| this.compute_overview(cx))),
                )
                .into_any_element(),
        };

        v_flex()
            .id("sidebar")
            .w(px(WIDTH))
            .flex_shrink_0()
            .h_full()
            .overflow_y_scroll()
            .pb_3()
            .bg(theme::panel())
            .border_r_1()
            .border_color(theme::border())
            .text_sm()
            .child(Self::section("CAPTURE"))
            .child(capture)
            .child(overview)
            .into_any_element()
    }
}

/// The theme's monospace font, for counts and addresses.
trait MonoFont {
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
    use super::talker_filter;

    #[test]
    fn talker_filters_use_the_address_family() {
        assert_eq!(
            talker_filter("10.0.0.1", "8.8.8.8"),
            "ipv4.src = '10.0.0.1' AND ipv4.dst = '8.8.8.8'"
        );
        assert_eq!(
            talker_filter("fe80::1", "fe80::2"),
            "ipv6.src = 'fe80::1' AND ipv6.dst = 'fe80::2'"
        );
    }
}
