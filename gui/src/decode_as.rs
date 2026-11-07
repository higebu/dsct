//! Decode As: dissect the packets on a TCP or UDP port as a protocol the
//! user picks, in every tab (dsct's `--decode-as` rules), and the panel
//! that sets them.

use gpui_kit::assets::IconName as AssetIcon;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputEvent, InputState};
use gpui_kit::component::{Icon, IconName, Sizable as _, h_flex, v_flex};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::*;

use crate::app::{DsctApp, Pane};
use crate::tabs::Slot;
use crate::theme;

/// Context of the panel; its inputs' arrow keys move the selection.
pub const DECODE_AS_CONTEXT: &str = "DecodeAs";

/// Protocols listed at most.
const MAX_ITEMS: usize = 8;

/// The port table a rule applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Udp,
}

impl Transport {
    /// The `--decode-as` table name.
    fn table(self) -> &'static str {
        match self {
            Transport::Tcp => "tcp.port",
            Transport::Udp => "udp.port",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Transport::Tcp => "TCP",
            Transport::Udp => "UDP",
        }
    }

    /// Suffix of the protocol names specific to this transport (`dns.tcp`).
    fn suffix(self) -> &'static str {
        match self {
            Transport::Tcp => ".tcp",
            Transport::Udp => ".udp",
        }
    }
}

/// Packets on `ports` of `transport` are dissected as `protocol`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub transport: Transport,
    pub ports: Vec<u16>,
    /// Registry name, possibly transport-specific (`sip.udp`).
    pub protocol: String,
}

impl Rule {
    /// The rule as a `--decode-as` argument.
    pub fn arg(&self) -> String {
        let ports: Vec<String> = self.ports.iter().map(u16::to_string).collect();
        format!(
            "{}={}:{}",
            self.transport.table(),
            ports.join(","),
            self.protocol
        )
    }

    /// The rule as shown: `TCP 8000, 8001 → SIP`.
    pub fn label(&self) -> String {
        let ports: Vec<String> = self.ports.iter().map(u16::to_string).collect();
        format!(
            "{} {} → {}",
            self.transport.label(),
            ports.join(", "),
            choice_of(&self.protocol).to_uppercase()
        )
    }
}

/// The `--decode-as` arguments of `rules`.
pub fn args(rules: &[Rule]) -> Vec<String> {
    rules.iter().map(Rule::arg).collect()
}

/// Add `rule` to `rules`. Its ports leave the rules that named them, and
/// it joins a rule for the same transport and protocol.
pub fn add_rule(rules: &mut Vec<Rule>, rule: Rule) {
    for r in rules.iter_mut().filter(|r| r.transport == rule.transport) {
        r.ports.retain(|p| !rule.ports.contains(p));
    }
    rules.retain(|r| !r.ports.is_empty());
    match rules
        .iter_mut()
        .find(|r| r.transport == rule.transport && r.protocol == rule.protocol)
    {
        Some(r) => {
            r.ports.extend(rule.ports);
            r.ports.sort_unstable();
        }
        None => rules.push(rule),
    }
}

/// Ports typed as `8000, 8001` (commas or spaces between them).
pub fn parse_ports(text: &str) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for part in text.split([',', ' ']).filter(|p| !p.is_empty()) {
        match part.parse::<u16>() {
            Ok(port) if port > 0 => ports.push(port),
            _ => return Err(format!("Not a port: {part}")),
        }
    }
    if ports.is_empty() {
        return Err("Enter a port".to_string());
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// The transport and port of a port field of the detail tree
/// (`tcp.dst_port` = `8000`).
pub fn port_field(path: &str, value: &str) -> Option<(Transport, u16)> {
    let transport = match path {
        "tcp.src_port" | "tcp.dst_port" => Transport::Tcp,
        "udp.src_port" | "udp.dst_port" => Transport::Udp,
        _ => return None,
    };
    let digits: String = value.chars().take_while(char::is_ascii_digit).collect();
    Some((transport, digits.parse().ok()?))
}

/// A registry name without its transport suffix (`sip.udp` → `sip`).
fn choice_of(name: &str) -> &str {
    name.strip_suffix(".tcp")
        .or_else(|| name.strip_suffix(".udp"))
        .unwrap_or(name)
}

/// The protocols to choose from: the registry's names, a protocol with
/// TCP and UDP variants listed once.
pub fn choices(names: &[String]) -> Vec<String> {
    let mut out: Vec<String> = names.iter().map(|n| choice_of(n).to_string()).collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// The registry name for `choice` over `transport`: its variant for that
/// transport when there is one.
pub fn resolve(names: &[String], choice: &str, transport: Transport) -> String {
    let specific = format!("{choice}{}", transport.suffix());
    if names.contains(&specific) {
        specific
    } else {
        choice.to_string()
    }
}

/// The choices containing `query` (ignoring case), those starting with it
/// first.
pub fn matching<'a>(choices: &'a [String], query: &str) -> Vec<&'a String> {
    let q = query.trim().to_lowercase();
    let mut found: Vec<&String> = choices.iter().filter(|c| c.contains(&q)).collect();
    found.sort_by_key(|c| !c.starts_with(&q));
    found
}

/// The open Decode As panel.
pub struct DecodeAsPanel {
    transport: Transport,
    ports: Entity<InputState>,
    search: Entity<InputState>,
    selected: usize,
    error: Option<String>,
    _subscriptions: Vec<Subscription>,
}

actions!(dsct_decode_as, [DecodeAsUp, DecodeAsDown, CloseDecodeAs]);

impl DsctApp {
    /// Open the Decode As panel, for `port` when given (from a port field).
    pub(crate) fn open_decode_as(
        &mut self,
        port: Option<(Transport, u16)>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        if self.protocols.is_empty() {
            self.protocols = match dsct::session::new_registry(&[]) {
                Ok(registry) => registry
                    .available_decode_as_protocols()
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                Err(e) => {
                    self.message = Some((e.to_string(), true));
                    return cx.notify();
                }
            };
        }
        let ports_text = port.map(|(_, p)| p.to_string()).unwrap_or_default();
        let ports = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("8000, 8001")
                .default_value(ports_text)
        });
        let search = cx.new(|cx| InputState::new(window, cx).placeholder("Search protocols"));
        let subscriptions = vec![
            cx.subscribe_in(&ports, window, |this, _, event: &InputEvent, window, cx| {
                if let InputEvent::PressEnter { .. } = event
                    && let Some(panel) = &this.decode_panel
                {
                    let handle = panel.search.read(cx).focus_handle(cx);
                    window.focus(&handle, cx);
                }
            }),
            cx.subscribe_in(
                &search,
                window,
                |this, _, event: &InputEvent, window, cx| match event {
                    InputEvent::PressEnter { .. } => this.apply_decode_choice(None, window, cx),
                    InputEvent::Change => {
                        if let Some(panel) = this.decode_panel.as_mut() {
                            panel.selected = 0;
                        }
                        cx.notify();
                    }
                    _ => {}
                },
            ),
        ];
        // With the port known, the protocol is what is left to type.
        let focus = if port.is_some() { &search } else { &ports };
        let handle = focus.read(cx).focus_handle(cx);
        window.focus(&handle, cx);
        self.decode_panel = Some(DecodeAsPanel {
            transport: port.map_or(Transport::Tcp, |(t, _)| t),
            ports,
            search,
            selected: 0,
            error: None,
            _subscriptions: subscriptions,
        });
        cx.notify();
    }

    pub(crate) fn close_decode_as(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.decode_panel.take().is_some() && self.session.borrow().is_some() {
            self.focus_pane(Pane::Packets, window, cx);
        }
        cx.notify();
    }

    /// The protocols matching the panel's search.
    fn decode_choices(&self, cx: &App) -> Vec<String> {
        let Some(panel) = &self.decode_panel else {
            return Vec::new();
        };
        let all = choices(&self.protocols);
        let query = panel.search.read(cx).value().to_string();
        matching(&all, &query)
            .into_iter()
            .take(MAX_ITEMS)
            .cloned()
            .collect()
    }

    fn move_decode_choice(&mut self, down: bool, cx: &mut Context<Self>) {
        let count = self.decode_choices(cx).len();
        if let Some(panel) = self.decode_panel.as_mut()
            && count > 0
        {
            panel.selected = if down {
                (panel.selected + 1) % count
            } else {
                (panel.selected + count - 1) % count
            };
        }
        cx.notify();
    }

    /// Decode the panel's ports as choice `index` (the selected one when
    /// `None`), in every tab.
    fn apply_decode_choice(
        &mut self,
        index: Option<usize>,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        let found = self.decode_choices(cx);
        let Some(panel) = self.decode_panel.as_mut() else {
            return;
        };
        let ports = match parse_ports(&panel.ports.read(cx).value()) {
            Ok(ports) => ports,
            Err(msg) => {
                panel.error = Some(msg);
                return cx.notify();
            }
        };
        let Some(choice) = found.get(index.unwrap_or(panel.selected)) else {
            panel.error = Some("No protocol matches".to_string());
            return cx.notify();
        };
        let rule = Rule {
            transport: panel.transport,
            ports,
            protocol: resolve(&self.protocols, choice, panel.transport),
        };
        let mut rules = self.decode_rules.clone();
        add_rule(&mut rules, rule);
        self.close_decode_as(window, cx);
        self.set_decode_rules(rules, cx);
    }

    /// Dissect every tab with `rules` from now on.
    pub(crate) fn set_decode_rules(&mut self, rules: Vec<Rule>, cx: &mut Context<Self>) {
        let decode_as = args(&rules);
        self.decode_rules = rules;
        let mut failed = None;
        {
            let mut guard = self.session.borrow_mut();
            if let Some(session) = guard.as_mut() {
                match session.set_decode_as(decode_as.clone()) {
                    Ok(()) => {
                        Self::invalidate_field_jobs(&mut self.fields, &mut self.timeline, session);
                        // Without a filter scan the rows stay where they
                        // were; after one, the tick selects a packet again.
                        if !session.filter_running()
                            && let Some(row) = self.selected_row
                        {
                            session.load_packet(row);
                        }
                        self.tree.reset(session);
                    }
                    Err(e) => failed = Some(e.to_string()),
                }
            }
        }
        for slot in &mut self.tabs {
            let Slot::Parked(tab) = slot else {
                continue;
            };
            let mut guard = tab.session.borrow_mut();
            let Some(session) = guard.as_mut() else {
                continue;
            };
            if let Err(e) = session.set_decode_as(decode_as.clone()) {
                failed = Some(e.to_string());
                continue;
            }
            tab.field_stale = true;
            tab.timeline.stale = true;
            if session.filter_running() {
                tab.selected_row = None;
            } else if let Some(row) = tab.selected_row {
                session.load_packet(row);
            }
            tab.tree.reset(session);
            drop(guard);
            tab.table.update(cx, |table, cx| table.refresh(cx));
        }
        self.table.update(cx, |table, cx| table.refresh(cx));
        if let Some(msg) = failed {
            self.message = Some((format!("Decode As: {msg}"), true));
        }
        self.ensure_ticking(cx);
        cx.notify();
    }

    /// Stop decoding by rule `index`.
    fn remove_decode_rule(&mut self, index: usize, cx: &mut Context<Self>) {
        let mut rules = self.decode_rules.clone();
        if index < rules.len() {
            rules.remove(index);
            self.set_decode_rules(rules, cx);
        }
    }

    /// The filter bar's button for the panel, naming the rules in effect.
    pub(crate) fn render_decode_as_button(
        &self,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let label = match self.decode_rules.as_slice() {
            [] => "Decode As".to_string(),
            [rule] => format!("Decode As: {}", rule.label()),
            rules => format!("Decode As: {} rules", rules.len()),
        };
        Button::new("decode-as")
            .icon(Icon::new(AssetIcon::Binary))
            .label(label)
            .small()
            .when(self.decode_rules.is_empty(), |b| b.outline())
            .when(!self.decode_rules.is_empty(), |b| b.primary())
            .tooltip("Dissect a TCP or UDP port as another protocol")
            .on_click(cx.listener(|this, _, window, cx| this.open_decode_as(None, window, cx)))
    }

    pub(crate) fn render_decode_as(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let found = self.decode_choices(cx);
        let panel = self.decode_panel.as_ref()?;
        let selected = panel.selected.min(found.len().saturating_sub(1));
        let transport = panel.transport;
        let segment = |id: &'static str, t: Transport| {
            Button::new(id)
                .label(t.label())
                .small()
                .when(t == transport, |b| b.primary())
                .when(t != transport, |b| b.ghost())
                .on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(panel) = this.decode_panel.as_mut() {
                        panel.transport = t;
                    }
                    cx.notify();
                }))
        };
        let label = |text: &'static str| {
            div()
                .w(px(64.))
                .flex_shrink_0()
                .text_xs()
                .text_color(theme::text_muted())
                .child(text)
        };
        let rows = found.into_iter().enumerate().map(|(i, name)| {
            let resolved = resolve(&self.protocols, &name, transport);
            h_flex()
                .id(("decode-choice", i))
                .h(px(30.))
                .px_3()
                .gap_3()
                .rounded(px(6.))
                .when(i == selected, |d| d.bg(theme::selection()))
                .hover(|d| d.bg(theme::hover()))
                .child(div().flex_1().child(name.to_uppercase()))
                .when(resolved != name, |d| {
                    d.child(
                        div()
                            .text_xs()
                            .text_color(theme::text_muted())
                            .child(resolved),
                    )
                })
                .on_click(cx.listener(move |this, _, window, cx| {
                    this.apply_decode_choice(Some(i), window, cx)
                }))
        });
        let rules = self.decode_rules.iter().enumerate().map(|(i, rule)| {
            h_flex()
                .h(px(28.))
                .px_3()
                .gap_2()
                .child(div().flex_1().text_sm().child(rule.label()))
                .child(
                    Button::new(("decode-remove", i))
                        .icon(IconName::Close)
                        .xsmall()
                        .ghost()
                        .tooltip("Stop decoding these ports")
                        .on_click(
                            cx.listener(move |this, _, _, cx| this.remove_decode_rule(i, cx)),
                        ),
                )
        });
        let has_rules = !self.decode_rules.is_empty();
        let (ports, search, error) = (
            panel.ports.clone(),
            panel.search.clone(),
            panel.error.clone(),
        );
        Some(
            div()
                .id("decode-as-overlay")
                .absolute()
                .inset_0()
                .bg(theme::chrome().opacity(0.6))
                .flex()
                .justify_center()
                .items_start()
                .pt(px(72.))
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(|this, _, window, cx| this.close_decode_as(window, cx)),
                )
                .child(
                    v_flex()
                        .id("decode-as")
                        .key_context(DECODE_AS_CONTEXT)
                        .w(px(480.))
                        .bg(theme::elevated())
                        .border_1()
                        .border_color(theme::border_strong())
                        .rounded(px(10.))
                        .shadow_lg()
                        .overflow_hidden()
                        .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
                        .on_action(cx.listener(|this, _: &DecodeAsUp, _, cx| {
                            this.move_decode_choice(false, cx)
                        }))
                        .on_action(cx.listener(|this, _: &DecodeAsDown, _, cx| {
                            this.move_decode_choice(true, cx)
                        }))
                        .on_action(cx.listener(|this, _: &CloseDecodeAs, window, cx| {
                            this.close_decode_as(window, cx)
                        }))
                        .child(
                            div()
                                .px_3()
                                .pt_3()
                                .text_sm()
                                .font_weight(FontWeight::SEMIBOLD)
                                .text_color(theme::text_bright())
                                .child("Decode As"),
                        )
                        .child(
                            v_flex()
                                .p_3()
                                .gap_2()
                                .border_b_1()
                                .border_color(theme::border())
                                .child(
                                    h_flex()
                                        .gap_2()
                                        .child(label("Port"))
                                        .child(
                                            h_flex()
                                                .gap_0p5()
                                                .p_0p5()
                                                .rounded(px(6.))
                                                .border_1()
                                                .border_color(theme::border())
                                                .child(segment("decode-tcp", Transport::Tcp))
                                                .child(segment("decode-udp", Transport::Udp)),
                                        )
                                        .child(div().flex_1().child(Input::new(&ports).small())),
                                )
                                .child(
                                    h_flex()
                                        .gap_2()
                                        .child(label("Protocol"))
                                        .child(div().flex_1().child(Input::new(&search).small())),
                                )
                                .children(error.map(|msg| {
                                    div().text_sm().text_color(theme::red()).child(msg)
                                })),
                        )
                        .child(v_flex().p_1().gap(px(1.)).children(rows))
                        .when(has_rules, |d| {
                            d.child(
                                v_flex()
                                    .py_1()
                                    .border_t_1()
                                    .border_color(theme::border())
                                    .child(
                                        div()
                                            .px_3()
                                            .py_1()
                                            .text_xs()
                                            .text_color(theme::text_muted())
                                            .child("IN EFFECT IN EVERY TAB"),
                                    )
                                    .children(rules),
                            )
                        })
                        .child(
                            h_flex()
                                .px_3()
                                .py_2()
                                .gap_4()
                                .border_t_1()
                                .border_color(theme::border())
                                .text_xs()
                                .text_color(theme::text_muted())
                                .child("↑↓ to move")
                                .child("↵ to decode")
                                .child("esc to close"),
                        ),
                )
                .into_any_element(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Rule, Transport, add_rule, args, choices, matching, parse_ports, port_field, resolve,
    };

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn rule(transport: Transport, ports: &[u16], protocol: &str) -> Rule {
        Rule {
            transport,
            ports: ports.to_vec(),
            protocol: protocol.to_string(),
        }
    }

    #[test]
    fn rules_become_decode_as_args_and_labels() {
        let r = rule(Transport::Tcp, &[8000, 8001], "sip");
        assert_eq!(r.arg(), "tcp.port=8000,8001:sip");
        assert_eq!(r.label(), "TCP 8000, 8001 → SIP");
        let r = rule(Transport::Udp, &[8000], "sip.udp");
        assert_eq!(r.arg(), "udp.port=8000:sip.udp");
        assert_eq!(r.label(), "UDP 8000 → SIP");
    }

    #[test]
    fn a_port_keeps_the_latest_protocol() {
        let mut rules = vec![rule(Transport::Tcp, &[8000], "sip")];
        add_rule(&mut rules, rule(Transport::Tcp, &[8001], "sip"));
        assert_eq!(rules, [rule(Transport::Tcp, &[8000, 8001], "sip")]);
        add_rule(&mut rules, rule(Transport::Udp, &[8000], "sip.udp"));
        add_rule(&mut rules, rule(Transport::Tcp, &[8000], "http"));
        assert_eq!(
            rules,
            [
                rule(Transport::Tcp, &[8001], "sip"),
                rule(Transport::Udp, &[8000], "sip.udp"),
                rule(Transport::Tcp, &[8000], "http"),
            ]
        );
        // A rule left without ports goes away.
        add_rule(&mut rules, rule(Transport::Tcp, &[8001], "http"));
        assert_eq!(
            args(&rules),
            ["udp.port=8000:sip.udp", "tcp.port=8000,8001:http"]
        );
    }

    #[test]
    fn ports_are_parsed_from_a_list() {
        assert_eq!(parse_ports("8001, 8000 8001"), Ok(vec![8000, 8001]));
        assert_eq!(parse_ports(" "), Err("Enter a port".to_string()));
        assert_eq!(parse_ports("80,x"), Err("Not a port: x".to_string()));
        assert_eq!(parse_ports("70000"), Err("Not a port: 70000".to_string()));
        assert_eq!(parse_ports("0"), Err("Not a port: 0".to_string()));
    }

    #[test]
    fn port_fields_name_their_transport() {
        assert_eq!(
            port_field("tcp.dst_port", "8000"),
            Some((Transport::Tcp, 8000))
        );
        assert_eq!(
            port_field("udp.src_port", "5060 (SIP)"),
            Some((Transport::Udp, 5060))
        );
        assert_eq!(port_field("ipv4.ttl", "64"), None);
        assert_eq!(port_field("tcp.dst_port", "x"), None);
    }

    #[test]
    fn transport_variants_are_one_choice() {
        let all = names(&["bfd", "bfd.echo", "dns", "dns.tcp", "sip", "sip.udp"]);
        assert_eq!(choices(&all), ["bfd", "bfd.echo", "dns", "sip"]);
        assert_eq!(resolve(&all, "sip", Transport::Udp), "sip.udp");
        assert_eq!(resolve(&all, "sip", Transport::Tcp), "sip");
        assert_eq!(resolve(&all, "dns", Transport::Tcp), "dns.tcp");
        assert_eq!(resolve(&all, "dns", Transport::Udp), "dns");
    }

    #[test]
    fn matching_puts_prefixes_first() {
        let all = names(&["http", "http2", "sip", "stun"]);
        assert_eq!(matching(&all, "S"), ["sip", "stun"]);
        assert_eq!(matching(&all, "tp"), ["http", "http2"]);
        assert_eq!(matching(&all, "t"), ["http", "http2", "stun"]);
        assert_eq!(matching(&all, "2"), ["http2"]);
        assert_eq!(matching(&all, "").len(), 4);
    }
}
