//! The Graph tab: the hosts of the displayed packets and the traffic
//! between them (see `dsct::session::hosts`). Only the busiest hosts are
//! drawn; each drawn host counts its peers left out (+N), and its peers
//! list names them, so that one can be added to the graph.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::rc::Rc;

use dsct::session::hosts::{self, AddressLayer, GraphView, HostGraphs, Measure};
use gpui_kit::assets::IconName as AssetIcon;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::tooltip::Tooltip;
use gpui_kit::component::{ActiveTheme as _, Icon, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::DsctApp;
use crate::{fields_view, format, theme};

/// How many hosts can be drawn: more would not be readable.
pub const TOPS: [usize; 4] = [10, 25, 50, 100];
/// Peers listed for the selected host at most.
const MAX_PEERS: usize = 100;
/// Layout steps.
const STEPS: usize = 300;
/// Smallest and largest node diameters.
const MIN_NODE: f32 = 14.;
const MAX_NODE: f32 = 46.;

/// What the Graph tab shows, and how it was laid out.
#[derive(Default)]
pub struct GraphState {
    pub layer: AddressLayer,
    /// Index into [`TOPS`].
    pub top: usize,
    pub measure: Measure,
    pub selected: Option<IpAddr>,
    /// Hosts added from a peers list.
    pub extra: Vec<IpAddr>,
    drawn: Option<Drawn>,
    /// The host being dragged, by its place in the view.
    drag: Option<usize>,
    /// Where the graph was last painted, to place a dragged host.
    bounds: Rc<Cell<Option<Bounds<Pixels>>>>,
}

/// The hosts drawn and where.
struct Drawn {
    key: Key,
    view: GraphView,
    /// Position of each host of the view, in `0..=1` both ways.
    pos: Vec<(f32, f32)>,
    /// Address of each host of the view.
    addrs: Vec<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Key {
    layer: AddressLayer,
    top: usize,
    measure: Measure,
    extra: Vec<IpAddr>,
}

impl GraphState {
    /// Forget the graph of earlier stats.
    pub fn reset(&mut self) {
        *self = Self {
            layer: self.layer,
            top: self.top,
            measure: self.measure,
            ..Self::default()
        };
    }

    /// Lay the graph out again if what is drawn changed. Hosts drawn
    /// before (a host was added) stay where they were.
    fn update(&mut self, graphs: &HostGraphs) {
        let key = Key {
            layer: self.layer,
            top: self.top,
            measure: self.measure,
            extra: self.extra.clone(),
        };
        if self.drawn.as_ref().is_some_and(|d| d.key == key) {
            return;
        }
        let graph = graphs.get(self.layer);
        let view = graph.top(TOPS[self.top], self.measure, &self.extra);
        let addrs: Vec<IpAddr> = view
            .hosts
            .iter()
            .map(|h| graph.hosts[h.host].addr)
            .collect();
        let keep = self.drawn.take().filter(|d| {
            d.key.layer == key.layer && d.key.top == key.top && d.key.measure == key.measure
        });
        let before: HashMap<IpAddr, (f32, f32)> = keep
            .map(|d| d.addrs.into_iter().zip(d.pos).collect())
            .unwrap_or_default();
        let slot: HashMap<IpAddr, usize> = addrs.iter().enumerate().map(|(i, a)| (*a, i)).collect();
        let edges: Vec<(usize, usize)> = view
            .links
            .iter()
            .map(|&l| (slot[&graph.links[l].a], slot[&graph.links[l].b]))
            .filter(|(a, b)| a != b)
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        let fixed: Vec<Option<(f32, f32)>> = addrs.iter().map(|a| before.get(a).copied()).collect();
        let pos = layout(&edges, &fixed);
        if self.selected.is_none_or(|s| !slot.contains_key(&s)) {
            self.selected = addrs.first().copied();
        }
        self.drawn = Some(Drawn {
            key,
            view,
            pos,
            addrs,
        });
        self.drag = None;
    }
}

/// Place `fixed.len()` nodes joined by `edges` in the unit square, by a
/// force-directed layout (T. M. J. Fruchterman and E. M. Reingold, "Graph
/// drawing by force-directed placement", 1991): nodes push each other away,
/// edges pull their ends together. Nodes with a position keep it.
pub fn layout(edges: &[(usize, usize)], fixed: &[Option<(f32, f32)>]) -> Vec<(f32, f32)> {
    let n = fixed.len();
    if n == 0 {
        return Vec::new();
    }
    // A sunflower spiral: the busiest host in the middle, the others
    // spread evenly around it.
    let golden = std::f32::consts::PI * (3. - 5f32.sqrt());
    let mut pos: Vec<(f32, f32)> = (0..n)
        .map(|i| {
            fixed[i].unwrap_or_else(|| {
                let r = 0.45 * ((i as f32 + 0.5) / n as f32).sqrt();
                let a = i as f32 * golden;
                (0.5 + r * a.cos(), 0.5 + r * a.sin())
            })
        })
        .collect();
    let all_free = fixed.iter().all(Option::is_none);
    let k = 0.8 * (1. / n as f32).sqrt();
    let mut temperature = 0.1;
    for _ in 0..STEPS {
        let mut disp = vec![(0f32, 0f32); n];
        for i in 0..n {
            for j in i + 1..n {
                let (dx, dy) = (pos[i].0 - pos[j].0, pos[i].1 - pos[j].1);
                let d = (dx * dx + dy * dy).sqrt().max(0.005);
                let f = k * k / d;
                disp[i].0 += dx / d * f;
                disp[i].1 += dy / d * f;
                disp[j].0 -= dx / d * f;
                disp[j].1 -= dy / d * f;
            }
        }
        for &(a, b) in edges {
            let (dx, dy) = (pos[a].0 - pos[b].0, pos[a].1 - pos[b].1);
            let d = (dx * dx + dy * dy).sqrt().max(0.005);
            let f = d * d / k;
            disp[a].0 -= dx / d * f;
            disp[a].1 -= dy / d * f;
            disp[b].0 += dx / d * f;
            disp[b].1 += dy / d * f;
        }
        for i in 0..n {
            if fixed[i].is_some() {
                continue;
            }
            // A pull to the middle keeps unconnected hosts in view.
            disp[i].0 += (0.5 - pos[i].0) * k;
            disp[i].1 += (0.5 - pos[i].1) * k;
            let len = (disp[i].0 * disp[i].0 + disp[i].1 * disp[i].1).sqrt();
            if len > 0. {
                let step = len.min(temperature);
                pos[i].0 = (pos[i].0 + disp[i].0 / len * step).clamp(0., 1.);
                pos[i].1 = (pos[i].1 + disp[i].1 / len * step).clamp(0., 1.);
            }
        }
        temperature = (temperature * 0.98).max(0.002);
    }
    if all_free && n > 1 {
        // Fill the area.
        let (mut lo, mut hi) = ((f32::MAX, f32::MAX), (f32::MIN, f32::MIN));
        for &(x, y) in &pos {
            lo = (lo.0.min(x), lo.1.min(y));
            hi = (hi.0.max(x), hi.1.max(y));
        }
        let span = |a: f32, b: f32| if b - a > 1e-3 { b - a } else { 1. };
        let (w, h) = (span(lo.0, hi.0), span(lo.1, hi.1));
        for p in &mut pos {
            *p = ((p.0 - lo.0) / w, (p.1 - lo.1) / h);
        }
    }
    pos
}

/// Where a position in `0..=1` is in the graph area, as a fraction: room
/// is kept at the edges for the nodes and their labels.
fn place(p: (f32, f32)) -> (f32, f32) {
    (0.07 + 0.86 * p.0, 0.08 + 0.78 * p.1)
}

/// The position in `0..=1` of the point `at` of `bounds`.
fn unplace(at: Point<Pixels>, bounds: Bounds<Pixels>) -> (f32, f32) {
    let fx = f32::from(at.x - bounds.origin.x) / f32::from(bounds.size.width).max(1.);
    let fy = f32::from(at.y - bounds.origin.y) / f32::from(bounds.size.height).max(1.);
    (
        ((fx - 0.07) / 0.86).clamp(0., 1.),
        ((fy - 0.08) / 0.78).clamp(0., 1.),
    )
}

/// The diameter of a node with `amount` of the largest `max`.
fn node_size(amount: u64, max: u64) -> f32 {
    MIN_NODE + (MAX_NODE - MIN_NODE) * (amount as f32 / max.max(1) as f32).sqrt()
}

fn swatch(protocol: &str) -> Hsla {
    format::protocol_swatch(protocol).map_or(theme::text_muted(), theme::swatch)
}

impl DsctApp {
    fn graph_select(&mut self, addr: IpAddr, cx: &mut Context<Self>) {
        self.bottom.graph.selected = Some(addr);
        cx.notify();
    }

    /// Draw `addr`, a peer that was left out, and select it.
    fn graph_add(&mut self, addr: IpAddr, cx: &mut Context<Self>) {
        let graph = &mut self.bottom.graph;
        if !graph.extra.contains(&addr) {
            graph.extra.push(addr);
        }
        graph.selected = Some(addr);
        cx.notify();
    }

    fn graph_drag(&mut self, at: Point<Pixels>, cx: &mut Context<Self>) {
        let graph = &mut self.bottom.graph;
        let (Some(i), Some(bounds)) = (graph.drag, graph.bounds.get()) else {
            return;
        };
        if let Some(p) = graph.drawn.as_mut().and_then(|d| d.pos.get_mut(i)) {
            *p = unplace(at, bounds);
            cx.notify();
        }
    }

    pub(crate) fn render_graph(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let mono = cx.theme().mono_font_family.clone();
        let (muted, border, text) = (theme::text_muted(), theme::border(), theme::text());
        let Some(stats) = self.bottom.stats.as_ref() else {
            return div().id("graph");
        };
        let graphs = &stats.report.hosts;
        self.bottom.graph.update(graphs);
        let state = &self.bottom.graph;
        let graph = graphs.get(state.layer);
        let Some(drawn) = state.drawn.as_ref() else {
            return div().id("graph");
        };
        let (measure, selected) = (state.measure, state.selected);

        // Toolbar.
        let segment = |id: &'static str, label: &'static str, on: bool| {
            Button::new(id)
                .label(label)
                .xsmall()
                .when(on, |b| b.primary())
                .when(!on, |b| b.outline())
        };
        let layers = graphs.tunneled.then(|| {
            h_flex()
                .gap_1()
                .child(
                    segment(
                        "graph-inner",
                        "Inner addresses",
                        state.layer == AddressLayer::Inner,
                    )
                    .tooltip("The hosts of the packets themselves")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.bottom.graph.layer = AddressLayer::Inner;
                        cx.notify();
                    })),
                )
                .child(
                    segment(
                        "graph-outer",
                        "Outer (tunnel) addresses",
                        state.layer == AddressLayer::Outer,
                    )
                    .tooltip("The tunnel endpoints that carry them")
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.bottom.graph.layer = AddressLayer::Outer;
                        cx.notify();
                    })),
                )
        });
        let next_top = (state.top + 1 < TOPS.len()).then(|| state.top + 1);
        let tops = h_flex()
            .gap_1()
            .children(TOPS.iter().enumerate().map(|(i, n)| {
                segment_owned(("graph-top", i), format!("Top {n}"), state.top == i).on_click(
                    cx.listener(move |this, _, _, cx| {
                        this.bottom.graph.top = i;
                        cx.notify();
                    }),
                )
            }));
        let measures = h_flex()
            .gap_1()
            .child(div().text_color(muted).child("Size by"))
            .child(
                segment("graph-packets", "Packets", measure == Measure::Packets).on_click(
                    cx.listener(|this, _, _, cx| {
                        this.bottom.graph.measure = Measure::Packets;
                        cx.notify();
                    }),
                ),
            )
            .child(
                segment("graph-bytes", "Bytes", measure == Measure::Bytes).on_click(cx.listener(
                    |this, _, _, cx| {
                        this.bottom.graph.measure = Measure::Bytes;
                        cx.notify();
                    },
                )),
            );
        let mut protocols: Vec<&'static str> = drawn
            .view
            .links
            .iter()
            .map(|&l| graph.links[l].protocol)
            .collect();
        protocols.sort_unstable();
        protocols.dedup();
        let legend = h_flex()
            .flex_wrap()
            .gap_3()
            .children(protocols.into_iter().map(|p| {
                h_flex()
                    .gap_1()
                    .child(div().w(px(14.)).h(px(3.)).rounded(px(2.)).bg(swatch(p)))
                    .child(p)
            }));
        let toolbar = h_flex()
            .flex_wrap()
            .gap_3()
            .px_3()
            .py_1()
            .border_b_1()
            .border_color(border)
            .text_sm()
            .children(layers)
            .child(tops)
            .child(measures)
            .child(div().flex_1())
            .child(legend);

        // Links, painted under the nodes.
        let slot: HashMap<IpAddr, usize> = drawn
            .addrs
            .iter()
            .enumerate()
            .map(|(i, a)| (*a, i))
            .collect();
        let near: HashSet<IpAddr> = drawn
            .view
            .links
            .iter()
            .map(|&l| &graph.links[l])
            .filter(|l| Some(l.a) == selected || Some(l.b) == selected)
            .flat_map(|l| [l.a, l.b])
            .collect();
        let max_link = drawn
            .view
            .links
            .iter()
            .map(|&l| graph.links[l].amount(measure))
            .max()
            .unwrap_or(1);
        let mut side_by_side: HashMap<(usize, usize), usize> = HashMap::new();
        let lines: Vec<Line> = drawn
            .view
            .links
            .iter()
            .filter_map(|&l| {
                let link = &graph.links[l];
                let (a, b) = (slot[&link.a], slot[&link.b]);
                if a == b {
                    return None;
                }
                let nth = side_by_side.entry((a, b)).or_insert(0);
                let offset = *nth as f32 * 5.;
                *nth += 1;
                let touches = Some(link.a) == selected || Some(link.b) == selected;
                Some(Line {
                    from: place(drawn.pos[a]),
                    to: place(drawn.pos[b]),
                    offset,
                    width: 1.5 + 6. * link.amount(measure) as f32 / max_link.max(1) as f32,
                    color: swatch(link.protocol).opacity(if touches { 0.9 } else { 0.2 }),
                })
            })
            .collect();
        let bounds_cell = state.bounds.clone();
        let links = canvas(
            move |bounds, _, _| bounds_cell.set(Some(bounds)),
            move |bounds, (), window, _| paint_lines(&lines, bounds, window),
        )
        .absolute()
        .size_full();

        // Nodes, their labels and their +N.
        let max_host = drawn
            .view
            .hosts
            .iter()
            .map(|h| graph.hosts[h.host].amount(measure))
            .max()
            .unwrap_or(1);
        let mut nodes: Vec<AnyElement> = Vec::new();
        for (i, h) in drawn.view.hosts.iter().enumerate() {
            let host = &graph.hosts[h.host];
            let addr = host.addr;
            let size = node_size(host.amount(measure), max_host);
            let (x, y) = place(drawn.pos[i]);
            let is_sel = Some(addr) == selected;
            let bright = is_sel || near.contains(&addr) || selected.is_none();
            let opacity = if bright { 1. } else { 0.45 };
            let added = state.extra.contains(&addr);
            nodes.push(
                div()
                    .id(("graph-node", i))
                    .absolute()
                    .left(relative(x))
                    .top(relative(y))
                    .ml(px(-size / 2.))
                    .mt(px(-size / 2.))
                    .size(px(size))
                    .rounded_full()
                    .border_2()
                    .when(added, |d| d.border_dashed())
                    .border_color(if is_sel {
                        theme::text_bright()
                    } else if bright {
                        theme::text_muted()
                    } else {
                        theme::border_strong()
                    })
                    .bg(if is_sel {
                        theme::accent()
                    } else {
                        theme::elevated()
                    })
                    .opacity(opacity)
                    .cursor_pointer()
                    .tooltip(move |window, cx| Tooltip::new(addr.to_string()).build(window, cx))
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            this.bottom.graph.drag = Some(i);
                            this.graph_select(addr, cx);
                        }),
                    )
                    .into_any_element(),
            );
            nodes.push(
                div()
                    .absolute()
                    .left(relative(x))
                    .top(relative(y))
                    .ml(px(-110.))
                    .mt(px(size / 2. + 2.))
                    .w(px(220.))
                    .text_center()
                    .text_xs()
                    .font_family(mono.clone())
                    .whitespace_nowrap()
                    .overflow_hidden()
                    .text_ellipsis()
                    .text_color(if is_sel { theme::text_bright() } else { text })
                    .opacity(opacity)
                    .child(addr.to_string())
                    .into_any_element(),
            );
            if h.hidden_peers > 0 {
                nodes.push(
                    div()
                        .absolute()
                        .left(relative(x))
                        .top(relative(y))
                        .ml(px(size * 0.3))
                        .mt(px(-size / 2. - 9.))
                        .px(px(5.))
                        .h(px(16.))
                        .flex()
                        .items_center()
                        .rounded(px(8.))
                        .border_1()
                        .border_color(theme::border_strong())
                        .bg(theme::panel())
                        .text_color(text)
                        .text_xs()
                        .font_family(mono.clone())
                        .opacity(opacity)
                        .child(format!("+{}", h.hidden_peers))
                        .into_any_element(),
                );
            }
        }

        // Hosts past the top N: how many, and a way to draw more.
        let not_shown = (drawn.view.hidden_hosts > 0).then(|| {
            let tip = format!(
                "Hosts past the top {}. The +N on a host counts its peers among them.",
                TOPS[state.top]
            );
            h_flex()
                .id("graph-not-shown")
                .flex_shrink_0()
                .gap_2()
                .child(div().text_color(text).child(format!(
                    "Not shown: {} hosts, {} packets",
                    fields_view::grouped(drawn.view.hidden_hosts as u64),
                    fields_view::grouped(drawn.view.hidden_packets)
                )))
                .tooltip(move |window, cx| Tooltip::new(tip.clone()).build(window, cx))
                .children(next_top.map(|next| {
                    Button::new("graph-more")
                        .label(format!("Show top {}", TOPS[next]))
                        .xsmall()
                        .outline()
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.bottom.graph.top = next;
                            cx.notify();
                        }))
                }))
        });
        let mut notes = vec![
            "Click a host to see its peers · +N: peers not drawn · drag a host to move it"
                .to_string(),
        ];
        if graphs.no_ip_packets > 0 {
            notes.push(format!(
                "{} packets without IP addresses",
                fields_view::grouped(graphs.no_ip_packets)
            ));
        }
        if graph.untracked_packets > 0 {
            notes.push(format!(
                "{} packets of hosts not tracked",
                fields_view::grouped(graph.untracked_packets)
            ));
        }

        let plot = div()
            .id("graph-plot")
            .relative()
            .flex_1()
            .min_h_0()
            .w_full()
            .overflow_hidden()
            .child(links)
            .children(nodes)
            .when(drawn.view.hosts.is_empty(), |d| {
                d.child(
                    div()
                        .p_3()
                        .text_sm()
                        .text_color(muted)
                        .child("No packets with IP addresses."),
                )
            })
            .on_mouse_move(cx.listener(|this, e: &MouseMoveEvent, _, cx| {
                if e.pressed_button == Some(MouseButton::Left) {
                    this.graph_drag(e.position, cx);
                } else {
                    this.bottom.graph.drag = None;
                }
            }))
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _, _, _| this.bottom.graph.drag = None),
            );
        let footer = h_flex()
            .flex_shrink_0()
            .flex_wrap()
            .gap_3()
            .px_3()
            .py_1()
            .border_t_1()
            .border_color(border)
            .text_xs()
            .text_color(muted)
            .child(div().flex_1().min_w_0().child(notes.join(" · ")))
            .children(not_shown);
        let area = v_flex()
            .flex_1()
            .min_w_0()
            .h_full()
            .bg(theme::surface())
            .child(plot)
            .child(footer);

        let side = selected
            .and_then(|addr| graph.host(addr))
            .map(|host| self.render_graph_host(host.addr, cx));

        div().id("graph").size_full().child(
            v_flex().size_full().child(toolbar).child(
                h_flex()
                    .flex_1()
                    .min_h_0()
                    .items_start()
                    .child(area)
                    .children(side),
            ),
        )
    }

    /// The selected host: its traffic and its peers, drawn or not.
    fn render_graph_host(&self, addr: IpAddr, cx: &mut Context<Self>) -> AnyElement {
        let mono = cx.theme().mono_font_family.clone();
        let (muted, border) = (theme::text_muted(), theme::border());
        let Some(stats) = self.bottom.stats.as_ref() else {
            return div().into_any_element();
        };
        let state = &self.bottom.graph;
        let graph = stats.report.hosts.get(state.layer);
        let Some(host) = graph.host(addr) else {
            return div().into_any_element();
        };
        let drawn: HashSet<IpAddr> = state
            .drawn
            .as_ref()
            .map(|d| d.addrs.iter().copied().collect())
            .unwrap_or_default();
        let peers = graph.peers(addr, state.measure);
        let peer_count = peers.iter().map(|p| p.addr).collect::<HashSet<_>>().len();
        let more = peers.len().saturating_sub(MAX_PEERS);

        let stat = |value: u64, label: &'static str| {
            h_flex()
                .gap_1()
                .child(
                    div()
                        .font_family(mono.clone())
                        .text_color(theme::text())
                        .child(fields_view::grouped(value)),
                )
                .child(div().text_color(muted).child(label))
        };
        let rows = peers.iter().take(MAX_PEERS).enumerate().map(|(i, p)| {
            let link = &graph.links[p.link];
            let peer = p.addr;
            let is_drawn = drawn.contains(&peer);
            let filter = hosts::pair_filter(link.a, link.b);
            h_flex()
                .id(("graph-peer", i))
                .gap_2()
                .h(px(28.))
                .border_b_1()
                .border_color(border)
                .cursor_pointer()
                .hover(|d| d.bg(theme::hover()))
                .text_color(if is_drawn { theme::text() } else { muted })
                .child(
                    div()
                        .flex_shrink_0()
                        .size(px(8.))
                        .rounded_full()
                        .border_1()
                        .border_color(muted)
                        .when(is_drawn, |d| d.bg(theme::text_muted()))
                        .when(!is_drawn, |d| d.border_dashed()),
                )
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .overflow_hidden()
                        .whitespace_nowrap()
                        .text_ellipsis()
                        .font_family(mono.clone())
                        .child(peer.to_string()),
                )
                .child(
                    h_flex()
                        .w(px(76.))
                        .flex_shrink_0()
                        .gap_1()
                        .text_color(swatch(link.protocol))
                        .child(div().size(px(7.)).rounded(px(2.)).bg(swatch(link.protocol)))
                        .child(
                            div()
                                .overflow_hidden()
                                .whitespace_nowrap()
                                .text_ellipsis()
                                .child(link.protocol),
                        ),
                )
                .child(
                    div()
                        .w(px(60.))
                        .flex_shrink_0()
                        .text_right()
                        .font_family(mono.clone())
                        .child(fields_view::grouped(link.amount(state.measure))),
                )
                .child(
                    Button::new(("graph-peer-filter", i))
                        .icon(Icon::new(AssetIcon::Funnel))
                        .xsmall()
                        .ghost()
                        .tooltip(format!("Filter: {filter}"))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.set_filter(&filter, window, cx)
                        })),
                )
                .tooltip(move |window, cx| {
                    let tip = if is_drawn {
                        format!("Select {peer}")
                    } else {
                        "Not drawn: select to add it to the graph".to_string()
                    };
                    Tooltip::new(tip).build(window, cx)
                })
                .on_click(cx.listener(move |this, _, _, cx| {
                    if is_drawn {
                        this.graph_select(peer, cx);
                    } else {
                        this.graph_add(peer, cx);
                    }
                }))
        });
        let filter = hosts::host_filter(addr);
        let unit = match state.measure {
            Measure::Packets => "Packets",
            Measure::Bytes => "Bytes",
        };

        v_flex()
            .id("graph-host")
            .w(px(380.))
            .flex_shrink_0()
            .h_full()
            .overflow_y_scroll()
            .gap_2()
            .px_3()
            .py_2()
            .border_l_1()
            .border_color(border)
            .text_sm()
            .child(div().text_xs().text_color(muted).child("SELECTED HOST"))
            .child(
                div()
                    .font_family(mono.clone())
                    .text_color(theme::text_bright())
                    .child(addr.to_string()),
            )
            .child(
                h_flex()
                    .gap_4()
                    .child(stat(host.packets, "packets"))
                    .child(stat(host.bytes, "bytes"))
                    .child(stat(
                        peer_count as u64,
                        if peer_count == 1 { "peer" } else { "peers" },
                    )),
            )
            .child(
                h_flex().child(
                    Button::new("graph-filter-host")
                        .icon(Icon::new(AssetIcon::Funnel))
                        .label("Filter to this host")
                        .xsmall()
                        .outline()
                        .tooltip(format!("Filter: {filter}"))
                        .on_click(cx.listener(move |this, _, window, cx| {
                            this.set_filter(&filter, window, cx)
                        })),
                ),
            )
            .child(
                h_flex()
                    .gap_2()
                    .pt_2()
                    .text_xs()
                    .text_color(muted)
                    .border_b_1()
                    .border_color(border)
                    .child(div().w(px(8.)))
                    .child(div().flex_1().child("Peer"))
                    .child(div().w(px(76.)).child("Protocol"))
                    .child(div().w(px(60.)).text_right().child(unit))
                    .child(div().w(px(24.))),
            )
            .children(rows)
            .when(more > 0, |d| {
                d.child(
                    div()
                        .text_xs()
                        .text_color(muted)
                        .child(format!("{more} more links")),
                )
            })
            .child(
                h_flex()
                    .gap_2()
                    .pt_1()
                    .text_xs()
                    .text_color(muted)
                    .child(
                        div()
                            .flex_shrink_0()
                            .size(px(8.))
                            .rounded_full()
                            .border_1()
                            .border_dashed()
                            .border_color(muted),
                    )
                    .child("Peers not drawn are listed too. Select one to add it to the graph."),
            )
            .into_any_element()
    }
}

fn segment_owned(id: impl Into<ElementId>, label: String, on: bool) -> Button {
    Button::new(id)
        .label(label)
        .xsmall()
        .when(on, |b| b.primary())
        .when(!on, |b| b.outline())
}

/// One link to paint, between two places in the graph area.
struct Line {
    from: (f32, f32),
    to: (f32, f32),
    /// Pixels to the side, for a second protocol between the same hosts.
    offset: f32,
    width: f32,
    color: Hsla,
}

fn paint_lines(lines: &[Line], bounds: Bounds<Pixels>, window: &mut Window) {
    let (w, h) = (f32::from(bounds.size.width), f32::from(bounds.size.height));
    let (ox, oy) = (f32::from(bounds.origin.x), f32::from(bounds.origin.y));
    for line in lines {
        let (x1, y1) = (ox + line.from.0 * w, oy + line.from.1 * h);
        let (x2, y2) = (ox + line.to.0 * w, oy + line.to.1 * h);
        let (dx, dy) = (x2 - x1, y2 - y1);
        let len = (dx * dx + dy * dy).sqrt().max(1.);
        let (sx, sy) = (-dy / len * line.offset, dx / len * line.offset);
        let mut path = PathBuilder::stroke(px(line.width));
        path.move_to(point(px(x1 + sx), px(y1 + sy)));
        path.line_to(point(px(x2 + sx), px(y2 + sy)));
        if let Ok(path) = path.build() {
            window.paint_path(path, line.color);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{layout, node_size, unplace};
    use gpui_kit::{Bounds, point, px, size};

    fn dist(a: (f32, f32), b: (f32, f32)) -> f32 {
        ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt()
    }

    #[test]
    fn linked_hosts_end_up_closer_than_others() {
        // A star around 0, and 5 alone.
        let edges = [(0, 1), (0, 2), (0, 3), (0, 4)];
        let pos = layout(&edges, &[None; 6]);
        assert_eq!(pos.len(), 6);
        assert!(
            pos.iter()
                .all(|p| (0. ..=1.).contains(&p.0) && (0. ..=1.).contains(&p.1))
        );
        let to_hub: f32 = (1..5).map(|i| dist(pos[0], pos[i])).sum::<f32>() / 4.;
        assert!(to_hub < dist(pos[0], pos[5]), "{pos:?}");
        // The same every time.
        assert_eq!(pos, layout(&edges, &[None; 6]));
    }

    #[test]
    fn placed_hosts_stay_where_they_are() {
        let fixed = [Some((0.2, 0.3)), Some((0.8, 0.7)), None];
        let pos = layout(&[(0, 2), (1, 2)], &fixed);
        assert_eq!(pos[0], (0.2, 0.3));
        assert_eq!(pos[1], (0.8, 0.7));
        assert!(layout(&[], &[]).is_empty());
    }

    #[test]
    fn nodes_grow_with_the_square_root_of_their_amount() {
        assert_eq!(node_size(100, 100), super::MAX_NODE);
        assert_eq!(node_size(0, 100), super::MIN_NODE);
        let quarter = node_size(25, 100);
        assert!((quarter - (super::MIN_NODE + super::MAX_NODE) / 2.).abs() < 1e-3);
    }

    #[test]
    fn a_dragged_point_maps_back_into_the_square() {
        let bounds = Bounds::new(point(px(100.), px(50.)), size(px(1000.), px(500.)));
        let mid = unplace(point(px(600.), px(50. + 0.47 * 500.)), bounds);
        assert!((mid.0 - 0.5).abs() < 1e-3 && (mid.1 - 0.5).abs() < 1e-3);
        assert_eq!(unplace(point(px(0.), px(0.)), bounds), (0., 0.));
    }
}
