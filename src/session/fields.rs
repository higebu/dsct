//! Field values as the filter reads them.
//!
//! A frontend uses this module to list the values a capture's fields take
//! (sampled over the displayed packets), to show one field of each packet as
//! a column, to chart the displayed packets over time split by protocol or
//! by field, and to turn a value back into a filter clause.
//!
//! Every value here is written the way a filter compares it: numbers in
//! decimal, addresses in their usual text form, and byte fields through
//! their formatter (a DNS name, for example). Byte fields without a
//! formatter cannot be compared by a filter, so they are left out.

use std::collections::HashMap;

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::dissector::ProtocolLayer;
use packet_dissector_core::field::{Field, FieldValue};
use packet_dissector_core::packet::{Layer, Packet};

use crate::field_format::format_field_to_string;
use crate::field_iter::top_level_fields;
use crate::filter::normalize_protocol_name;

/// What kind of value a field holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldKind {
    /// An integer.
    Number,
    /// An IPv4, IPv6 or MAC address.
    Address,
    /// Text, or bytes shown through the field's formatter.
    Text,
}

/// One value of a field in a dissected packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldValueRef<'a> {
    /// Short name of the layer the field belongs to (`"IPv4"`).
    pub protocol: &'static str,
    /// Filter path of the field (`"ipv4.src"`, `"dns.questions.name"`).
    pub path: &'a str,
    /// The value as a filter compares it (`"10.0.0.1"`, `"53"`).
    pub value: String,
    /// The name the field's dissector gives the value (`"A"` for DNS type
    /// 1), if any.
    pub label: Option<&'static str>,
    /// What kind of value it is.
    pub kind: FieldKind,
}

/// Call `visit` with every value of every field of `packet`, in layer and
/// field order.
///
/// Containers are not values themselves: an object's fields are visited
/// under `path.field`, and an array's elements under the array's own path
/// (a filter on that path matches any element).
pub fn for_each_value(packet: &Packet<'_, '_>, mut visit: impl FnMut(FieldValueRef<'_>)) {
    let mut path = String::new();
    for layer in packet.layers() {
        path.clear();
        path.push_str(&normalize_protocol_name(layer.name));
        walk_layer(packet, layer, &mut path, &mut visit);
    }
}

/// The first value of the field at `path` in `packet`, or `None` when the
/// packet has no such field.
pub fn first_value(packet: &Packet<'_, '_>, path: &str) -> Option<String> {
    let (protocol, _) = path.split_once('.')?;
    let mut buf = String::new();
    for layer in packet.layers() {
        let name = normalize_protocol_name(layer.name);
        if name != protocol {
            continue;
        }
        buf.clear();
        buf.push_str(&name);
        let mut found = None;
        walk_layer(packet, layer, &mut buf, &mut |v: FieldValueRef<'_>| {
            if found.is_none() && v.path == path {
                found = Some(shown_value(&v.value, v.label));
            }
        });
        if found.is_some() {
            return found;
        }
    }
    None
}

/// A value for display: `"1 (A)"` when the dissector names it, else the
/// value itself.
pub fn shown_value(value: &str, label: Option<&str>) -> String {
    match label {
        Some(label) if label != value => format!("{value} ({label})"),
        _ => value.to_string(),
    }
}

fn walk_layer(
    packet: &Packet<'_, '_>,
    layer: &Layer,
    path: &mut String,
    visit: &mut dyn FnMut(FieldValueRef<'_>),
) {
    let fields = packet.layer_fields(layer);
    for field in top_level_fields(fields, layer.field_range.start) {
        walk_field(packet, layer, field, fields, path, visit);
    }
}

fn walk_field(
    packet: &Packet<'_, '_>,
    layer: &Layer,
    field: &Field<'_>,
    siblings: &[Field<'_>],
    path: &mut String,
    visit: &mut dyn FnMut(FieldValueRef<'_>),
) {
    let len = path.len();
    path.push('.');
    path.push_str(field.name());
    match &field.value {
        FieldValue::Object(range) => {
            let children = packet.nested_fields(range);
            for child in top_level_fields(children, range.start) {
                walk_field(packet, layer, child, children, path, visit);
            }
        }
        FieldValue::Array(range) => {
            let elements = packet.nested_fields(range);
            for element in top_level_fields(elements, range.start) {
                match &element.value {
                    FieldValue::Object(range) => {
                        let children = packet.nested_fields(range);
                        for child in top_level_fields(children, range.start) {
                            walk_field(packet, layer, child, children, path, visit);
                        }
                    }
                    // An array of arrays has no filter path to its values.
                    FieldValue::Array(_) => {}
                    _ => visit_value(packet, layer, element, elements, path, visit),
                }
            }
        }
        _ => visit_value(packet, layer, field, siblings, path, visit),
    }
    path.truncate(len);
}

fn visit_value(
    packet: &Packet<'_, '_>,
    layer: &Layer,
    field: &Field<'_>,
    siblings: &[Field<'_>],
    path: &str,
    visit: &mut dyn FnMut(FieldValueRef<'_>),
) {
    if let Some((value, kind)) = filter_value(packet, layer, field) {
        let label = field
            .descriptor
            .display_fn
            .and_then(|display| display(&field.value, siblings));
        visit(FieldValueRef {
            protocol: layer.name,
            path,
            value,
            label,
            kind,
        });
    }
}

/// `field`'s value in the form a filter compares, or `None` when a filter
/// cannot compare it.
pub(crate) fn filter_value(
    packet: &Packet<'_, '_>,
    layer: &Layer,
    field: &Field<'_>,
) -> Option<(String, FieldKind)> {
    let value = match &field.value {
        FieldValue::U8(n) => (n.to_string(), FieldKind::Number),
        FieldValue::U16(n) => (n.to_string(), FieldKind::Number),
        FieldValue::U32(n) => (n.to_string(), FieldKind::Number),
        FieldValue::U64(n) => (n.to_string(), FieldKind::Number),
        FieldValue::I32(n) => (n.to_string(), FieldKind::Number),
        FieldValue::Ipv4Addr(a) => (std::net::Ipv4Addr::from(*a).to_string(), FieldKind::Address),
        FieldValue::Ipv6Addr(a) => (std::net::Ipv6Addr::from(*a).to_string(), FieldKind::Address),
        FieldValue::MacAddr(m) => (m.to_string(), FieldKind::Address),
        FieldValue::Str(s) => ((*s).to_string(), FieldKind::Text),
        FieldValue::Bytes(_) | FieldValue::Scratch(_) => (
            format_field_to_string(field, packet.data(), layer, packet.buf().scratch())?,
            FieldKind::Text,
        ),
        FieldValue::Object(_) | FieldValue::Array(_) => return None,
    };
    Some(value)
}

/// A field (or a protocol) and a value of it, as a filter selects it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRef {
    /// Filter path (`"ipv4.src"`), or a protocol name alone (`"ipv4"`).
    pub path: String,
    /// The value to compare against; `None` selects the packets that have
    /// the protocol at all.
    pub value: Option<String>,
}

impl FieldRef {
    /// The filter clause that selects this value: `ipv4.src = '10.0.0.1'`,
    /// or `ipv4` for a protocol.
    pub fn clause(&self) -> String {
        let path = self
            .path
            .split('.')
            .map(quote_identifier)
            .collect::<Vec<_>>()
            .join(".");
        match &self.value {
            Some(value) => format!("{path} = '{}'", value.replace('\'', "''")),
            None => path,
        }
    }
}

/// Words the filter reads as literals rather than identifiers.
const LITERAL_KEYWORDS: [&str; 3] = ["null", "true", "false"];

/// Quote a path segment when the filter would not read it as an
/// identifier (the BSD loopback protocol is `null`, for example).
fn quote_identifier(segment: &str) -> String {
    let plain = !LITERAL_KEYWORDS
        .iter()
        .any(|k| segment.eq_ignore_ascii_case(k))
        && segment
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && segment
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_');
    if plain {
        segment.to_string()
    } else {
        format!("\"{}\"", segment.replace('"', "\"\""))
    }
}

/// Narrow the filter `current` to the packets that match `clause`, or that
/// do not when `exclude` is set.
///
/// Excluding is `NOT clause`, so packets without the field are kept.
pub fn refine_filter(current: &str, clause: &str, exclude: bool) -> String {
    let clause = if exclude {
        format!("NOT {clause}")
    } else {
        clause.to_string()
    };
    match current.trim() {
        "" => clause,
        current => format!("({current}) AND {clause}"),
    }
}

/// The stack position each registered protocol declares, by short name.
pub fn protocol_layers(registry: &DissectorRegistry) -> HashMap<&'static str, ProtocolLayer> {
    registry
        .all_protocol_info()
        .into_iter()
        .filter_map(|info| Some((info.short_name, info.layer?)))
        .collect()
}

// --- Sampled value counts ---------------------------------------------------

/// Distinct values counted per field at most; later new values are not
/// counted, so a field with more values than this has approximate top
/// values.
const MAX_VALUES_PER_FIELD: usize = 4096;

/// Values kept per field in [`FieldSummary::top`].
const TOP_VALUES: usize = 10;

/// How many sampled packets had one value of a field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueCount {
    /// The value as a filter compares it.
    pub value: String,
    /// The name the dissector gives the value, if any.
    pub label: Option<&'static str>,
    /// Sampled packets with this value.
    pub packets: u64,
}

/// The values one field took in the sampled packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldSummary {
    /// Filter path (`"ipv4.src"`).
    pub path: String,
    /// Short name of the field's protocol (`"IPv4"`).
    pub protocol: &'static str,
    /// What kind of value the field holds.
    pub kind: FieldKind,
    /// Sampled packets that have the field.
    pub packets: u64,
    /// Distinct values counted.
    pub distinct: usize,
    /// Whether the field had more distinct values than were counted.
    pub distinct_capped: bool,
    /// The most frequent values, most frequent first.
    pub top: Vec<ValueCount>,
}

/// How many sampled packets had a protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolSummary {
    /// Short name (`"IPv4"`).
    pub name: &'static str,
    /// The stack position the protocol declares.
    pub layer: Option<ProtocolLayer>,
    /// Sampled packets that have the protocol.
    pub packets: u64,
}

/// How many sampled packets had any protocol at one stack position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerSummary {
    /// The stack position.
    pub layer: ProtocolLayer,
    /// Sampled packets with at least one protocol at this position.
    pub packets: u64,
}

/// Which displayed packets field values are counted over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sample {
    /// The first `n` displayed packets.
    First(usize),
    /// `n` displayed packets spread evenly from the first to the last.
    Spread(usize),
    /// Every displayed packet.
    All,
}

impl Sample {
    /// How many of `displayed` packets this sample takes.
    pub fn count(self, displayed: usize) -> usize {
        match self {
            Sample::First(n) | Sample::Spread(n) => n.min(displayed),
            Sample::All => displayed,
        }
    }

    /// The displayed position (0-based) of the `k`-th sampled packet out of
    /// `count` taken from `displayed`.
    pub fn position(self, k: usize, count: usize, displayed: usize) -> usize {
        match self {
            Sample::Spread(_) if count < displayed => {
                (k as u128 * displayed as u128 / count as u128) as usize
            }
            _ => k,
        }
    }
}

/// Value counts over a sample of the displayed packets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldStats {
    /// Which packets were counted.
    pub sample: Sample,
    /// Packets sampled.
    pub sampled: u64,
    /// Packets displayed when the sample was taken.
    pub displayed: u64,
    /// Protocols seen, in the order they first appeared.
    pub protocols: Vec<ProtocolSummary>,
    /// Stack positions seen, in the order they first appeared.
    pub layers: Vec<LayerSummary>,
    /// Fields seen, in the order they first appeared.
    pub fields: Vec<FieldSummary>,
}

impl FieldStats {
    /// The summary of the field at `path`.
    pub fn field(&self, path: &str) -> Option<&FieldSummary> {
        self.fields.iter().find(|f| f.path == path)
    }
}

struct ValueAcc {
    label: Option<&'static str>,
    packets: u64,
    last_packet: u64,
}

struct FieldAcc {
    protocol: &'static str,
    kind: FieldKind,
    packets: u64,
    last_packet: u64,
    values: HashMap<String, ValueAcc>,
    capped: bool,
}

/// Counts field values packet by packet.
pub(crate) struct FieldStatsCollector {
    sampled: u64,
    layer_of: HashMap<&'static str, ProtocolLayer>,
    /// Per stack position: packets, last packet counted.
    layers: Vec<(ProtocolLayer, u64, u64)>,
    protocols: Vec<(&'static str, u64, u64)>,
    protocol_index: HashMap<&'static str, usize>,
    paths: Vec<String>,
    fields: Vec<FieldAcc>,
    field_index: HashMap<String, usize>,
}

impl FieldStatsCollector {
    /// A collector that places protocols with `layer_of` (see
    /// [`protocol_layers`]).
    pub(crate) fn new(layer_of: HashMap<&'static str, ProtocolLayer>) -> Self {
        Self {
            sampled: 0,
            layer_of,
            layers: Vec::new(),
            protocols: Vec::new(),
            protocol_index: HashMap::new(),
            paths: Vec::new(),
            fields: Vec::new(),
            field_index: HashMap::new(),
        }
    }

    /// Count the protocols and field values of one packet. A value that
    /// occurs several times in a packet counts once.
    pub(crate) fn add(&mut self, packet: &Packet<'_, '_>) {
        self.sampled += 1;
        let n = self.sampled;
        for layer in packet.layers() {
            let i = *self.protocol_index.entry(layer.name).or_insert_with(|| {
                self.protocols.push((layer.name, 0, 0));
                self.protocols.len() - 1
            });
            let (_, packets, last) = &mut self.protocols[i];
            if *last != n {
                *last = n;
                *packets += 1;
            }
            if let Some(&layer) = self.layer_of.get(layer.name) {
                let i = match self.layers.iter().position(|(l, _, _)| *l == layer) {
                    Some(i) => i,
                    None => {
                        self.layers.push((layer, 0, 0));
                        self.layers.len() - 1
                    }
                };
                let (_, packets, last) = &mut self.layers[i];
                if *last != n {
                    *last = n;
                    *packets += 1;
                }
            }
        }
        for_each_value(packet, |v| {
            let i = match self.field_index.get(v.path) {
                Some(&i) => i,
                None => {
                    self.paths.push(v.path.to_string());
                    self.fields.push(FieldAcc {
                        protocol: v.protocol,
                        kind: v.kind,
                        packets: 0,
                        last_packet: 0,
                        values: HashMap::new(),
                        capped: false,
                    });
                    self.field_index
                        .insert(v.path.to_string(), self.fields.len() - 1);
                    self.fields.len() - 1
                }
            };
            let field = &mut self.fields[i];
            if field.last_packet != n {
                field.last_packet = n;
                field.packets += 1;
            }
            let full = field.values.len() >= MAX_VALUES_PER_FIELD;
            match field.values.get_mut(&v.value) {
                Some(acc) => {
                    if acc.last_packet != n {
                        acc.last_packet = n;
                        acc.packets += 1;
                    }
                }
                None if full => field.capped = true,
                None => {
                    field.values.insert(
                        v.value,
                        ValueAcc {
                            label: v.label,
                            packets: 1,
                            last_packet: n,
                        },
                    );
                }
            }
        });
    }

    pub(crate) fn finish(self, sample: Sample, displayed: u64) -> FieldStats {
        let layer_of = &self.layer_of;
        let protocols = self
            .protocols
            .into_iter()
            .map(|(name, packets, _)| ProtocolSummary {
                name,
                layer: layer_of.get(name).copied(),
                packets,
            })
            .collect();
        let layers = self
            .layers
            .into_iter()
            .map(|(layer, packets, _)| LayerSummary { layer, packets })
            .collect();
        let fields = self
            .paths
            .into_iter()
            .zip(self.fields)
            .map(|(path, acc)| {
                let distinct = acc.values.len();
                let mut top: Vec<ValueCount> = acc
                    .values
                    .into_iter()
                    .map(|(value, v)| ValueCount {
                        value,
                        label: v.label,
                        packets: v.packets,
                    })
                    .collect();
                top.sort_by(|a, b| {
                    b.packets
                        .cmp(&a.packets)
                        .then_with(|| a.value.cmp(&b.value))
                });
                top.truncate(TOP_VALUES);
                FieldSummary {
                    path,
                    protocol: acc.protocol,
                    kind: acc.kind,
                    packets: acc.packets,
                    distinct,
                    distinct_capped: acc.capped,
                    top,
                }
            })
            .collect();
        FieldStats {
            sample,
            sampled: self.sampled,
            displayed,
            protocols,
            layers,
            fields,
        }
    }
}

// --- Histogram ----------------------------------------------------------------

/// What splits the bars of a [`Histogram`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Split {
    /// Each packet's topmost protocol.
    TopProtocol,
    /// The innermost protocol each packet has at this stack position.
    Layer(ProtocolLayer),
    /// The first value of the field at this filter path.
    Field(String),
}

/// The key of one series of a [`Histogram`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeriesKey {
    /// Packets with this protocol or value.
    Value(String),
    /// Packets with any value outside the top series.
    Other,
    /// Packets without the protocol layer or field.
    Missing,
}

/// One series of a [`Histogram`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Series {
    /// What the series counts.
    pub key: SeriesKey,
    /// Packets in the series.
    pub packets: u64,
}

/// One bar of a [`Histogram`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bucket {
    /// Displayed packets in the bucket.
    pub packets: u64,
    /// Packets per series, in [`Histogram::series`] order (empty until the
    /// split is computed).
    pub split: Vec<u64>,
    /// Index of the bucket's first packet in capture order.
    pub first_packet: Option<usize>,
}

/// The displayed packets over time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Histogram {
    /// What splits the bars.
    pub split: Split,
    /// Timestamp of the earliest displayed packet, in microseconds since the
    /// Unix epoch.
    pub start_us: u64,
    /// Width of one bucket in microseconds.
    pub bucket_us: u64,
    /// The bars, earliest first.
    pub buckets: Vec<Bucket>,
    /// The series, largest first; then [`SeriesKey::Other`] and
    /// [`SeriesKey::Missing`] when they have packets.
    pub series: Vec<Series>,
    /// Whether the split has been computed.
    pub complete: bool,
}

/// Series shown by value at most; the rest are merged into
/// [`SeriesKey::Other`].
const TOP_SERIES: usize = 6;

/// Distinct keys counted at most; packets with later new keys count as
/// [`SeriesKey::Other`].
const MAX_KEYS: usize = 1024;

/// A packet timestamp in microseconds since the Unix epoch.
pub fn timestamp_us(secs: u64, usecs: u32) -> u64 {
    secs.saturating_mul(1_000_000)
        .saturating_add(u64::from(usecs))
}

impl Histogram {
    /// The timeline of the packets `times()` yields (index in capture
    /// order, timestamp in µs), in `buckets` bars, without a split yet.
    /// `times` is called twice: once for the time range, once to count.
    pub(crate) fn timeline<I: Iterator<Item = (usize, u64)>>(
        split: Split,
        buckets: usize,
        times: impl Fn() -> I,
    ) -> Self {
        let buckets = buckets.max(1);
        let (start, end) = times().fold((u64::MAX, 0), |(lo, hi), (_, t)| (lo.min(t), hi.max(t)));
        let mut histogram = Self {
            split,
            start_us: if start == u64::MAX { 0 } else { start },
            bucket_us: 1,
            buckets: vec![
                Bucket {
                    packets: 0,
                    split: Vec::new(),
                    first_packet: None,
                };
                buckets
            ],
            series: Vec::new(),
            complete: false,
        };
        if start == u64::MAX {
            return histogram;
        }
        let span = end - start + 1;
        histogram.bucket_us = span.div_ceil(buckets as u64).max(1);
        for (idx, t) in times() {
            let b = histogram.bucket_of(t);
            let bucket = &mut histogram.buckets[b];
            bucket.packets += 1;
            if bucket.first_packet.is_none_or(|first| idx < first) {
                bucket.first_packet = Some(idx);
            }
        }
        histogram
    }

    /// The bucket a timestamp falls in.
    pub fn bucket_of(&self, t: u64) -> usize {
        let i = (t.saturating_sub(self.start_us) / self.bucket_us) as usize;
        i.min(self.buckets.len().saturating_sub(1))
    }
}

/// Counts the split of a [`Histogram`] packet by packet.
pub(crate) struct SplitCollector {
    split: Split,
    keys: Vec<String>,
    key_index: HashMap<String, usize>,
    /// Packets per key per bucket (`counts[key][bucket]`).
    counts: Vec<Vec<u64>>,
    other: Vec<u64>,
    missing: Vec<u64>,
    layers: HashMap<&'static str, ProtocolLayer>,
}

impl SplitCollector {
    pub(crate) fn new(
        split: Split,
        buckets: usize,
        layers: HashMap<&'static str, ProtocolLayer>,
    ) -> Self {
        Self {
            split,
            keys: Vec::new(),
            key_index: HashMap::new(),
            counts: Vec::new(),
            other: vec![0; buckets],
            missing: vec![0; buckets],
            layers,
        }
    }

    /// The key `packet` counts under: `None` when it lacks the protocol or
    /// field.
    fn key(&self, packet: &Packet<'_, '_>) -> Option<String> {
        match &self.split {
            Split::TopProtocol => packet.layers().last().map(|l| l.name.to_string()),
            Split::Layer(layer) => packet
                .layers()
                .iter()
                .rev()
                .find(|l| self.layers.get(l.name) == Some(layer))
                .map(|l| l.name.to_string()),
            Split::Field(path) => first_value(packet, path),
        }
    }

    pub(crate) fn add(&mut self, bucket: usize, packet: &Packet<'_, '_>) {
        let Some(key) = self.key(packet) else {
            self.missing[bucket] += 1;
            return;
        };
        let i = match self.key_index.get(&key) {
            Some(&i) => i,
            None if self.keys.len() >= MAX_KEYS => {
                self.other[bucket] += 1;
                return;
            }
            None => {
                self.keys.push(key.clone());
                self.key_index.insert(key, self.keys.len() - 1);
                self.counts.push(vec![0; self.other.len()]);
                self.keys.len() - 1
            }
        };
        self.counts[i][bucket] += 1;
    }

    /// Write the split into `histogram`.
    pub(crate) fn finish(self, histogram: &mut Histogram) {
        let mut ranked: Vec<(u64, String, Vec<u64>)> = self
            .keys
            .into_iter()
            .zip(self.counts)
            .map(|(key, counts)| (counts.iter().sum(), key, counts))
            .collect();
        ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        let mut other = self.other;
        let mut columns: Vec<(SeriesKey, Vec<u64>)> = Vec::new();
        for (i, (_, key, counts)) in ranked.into_iter().enumerate() {
            if i < TOP_SERIES {
                columns.push((SeriesKey::Value(key), counts));
            } else {
                for (o, c) in other.iter_mut().zip(counts) {
                    *o += c;
                }
            }
        }
        if other.iter().any(|&c| c > 0) {
            columns.push((SeriesKey::Other, other));
        }
        if self.missing.iter().any(|&c| c > 0) {
            columns.push((SeriesKey::Missing, self.missing));
        }
        histogram.series = columns
            .iter()
            .map(|(key, counts)| Series {
                key: key.clone(),
                packets: counts.iter().sum(),
            })
            .collect();
        for (b, bucket) in histogram.buckets.iter_mut().enumerate() {
            bucket.split = columns.iter().map(|(_, counts)| counts[b]).collect();
        }
        histogram.complete = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::packet::DissectBuffer;

    use crate::filter_expr::FilterExpr;
    use crate::test_fixtures;

    /// Frames that exercise flat, nested-object and array-of-object fields.
    fn frames() -> Vec<Vec<u8>> {
        vec![
            test_fixtures::dns_edns_query_frame(),
            test_fixtures::bgp_update_frame(),
            test_fixtures::bgp_update_mp_reach_frame(),
        ]
    }

    fn dissect<'a>(registry: &DissectorRegistry, frame: &'a [u8]) -> DissectBuffer<'a> {
        let mut buf = DissectBuffer::new();
        registry.dissect_with_link_type(frame, 1, &mut buf).unwrap();
        buf
    }

    fn values(packet: &Packet<'_, '_>) -> Vec<(String, String, Option<&'static str>)> {
        let mut out = Vec::new();
        for_each_value(packet, |v| {
            out.push((v.path.to_string(), v.value, v.label));
        });
        out
    }

    #[test]
    fn values_use_filter_paths() {
        let registry = DissectorRegistry::default();
        let frame = test_fixtures::dns_edns_query_frame();
        let buf = dissect(&registry, &frame);
        let packet = Packet::new(&buf, &frame);
        let values = values(&packet);
        let has = |path: &str, value: &str| values.iter().any(|(p, v, _)| p == path && v == value);
        assert!(has("ipv4.src", "10.0.0.1"));
        assert!(has("udp.dst_port", "53"));
        assert!(has("dns.questions.name", "example.com"));
        assert!(has("dns.additionals.edns_options.code", "11"));
        assert!(has("ethernet.src", "00:11:22:33:44:55"));
    }

    #[test]
    fn every_value_round_trips_through_a_filter() {
        let registry = DissectorRegistry::default();
        for frame in frames() {
            let buf = dissect(&registry, &frame);
            let packet = Packet::new(&buf, &frame);
            let values = values(&packet);
            assert!(!values.is_empty());
            for (path, value, _) in values {
                let field = FieldRef {
                    path: path.clone(),
                    value: Some(value.clone()),
                };
                let clause = field.clause();
                let expr = FilterExpr::parse(&clause)
                    .unwrap_or_else(|e| panic!("{clause}: {e}"))
                    .unwrap();
                assert!(expr.matches(&packet), "{clause} does not match");
                let negated = FilterExpr::parse(&refine_filter("", &clause, true))
                    .unwrap()
                    .unwrap();
                assert!(!negated.matches(&packet), "NOT {clause} matches");
            }
        }
    }

    #[test]
    fn every_registered_field_path_parses_as_a_clause() {
        let registry = DissectorRegistry::default();
        let mut failures = Vec::new();
        for schema in registry.all_field_schemas() {
            let protocol = normalize_protocol_name(schema.short_name);
            for fd in schema.fields {
                let field = FieldRef {
                    path: format!("{protocol}.{}", fd.name),
                    value: Some("1".to_string()),
                };
                let clause = field.clause();
                if let Err(e) = FilterExpr::parse(&clause) {
                    failures.push(format!("{clause}: {e}"));
                }
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }

    #[test]
    fn first_value_finds_nested_fields() {
        let registry = DissectorRegistry::default();
        let frame = test_fixtures::dns_edns_query_frame();
        let buf = dissect(&registry, &frame);
        let packet = Packet::new(&buf, &frame);
        assert_eq!(
            first_value(&packet, "dns.questions.name").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            first_value(&packet, "ipv4.dst").as_deref(),
            Some("10.0.0.2")
        );
        assert_eq!(first_value(&packet, "tcp.dst_port"), None);
        assert_eq!(first_value(&packet, "dns"), None);
    }

    #[test]
    fn clauses_quote_values_and_odd_identifiers() {
        let field = FieldRef {
            path: "http.uri".to_string(),
            value: Some("/it's".to_string()),
        };
        assert_eq!(field.clause(), "http.uri = '/it''s'");
        let protocol = FieldRef {
            path: "dns".to_string(),
            value: None,
        };
        assert_eq!(protocol.clause(), "dns");
        assert_eq!(quote_identifier("8021q"), "\"8021q\"");
        assert_eq!(quote_identifier("null"), "\"null\"");
        for clause in ["\"null\"", "\"null\".family = '2'"] {
            assert!(FilterExpr::parse(clause).unwrap().is_some(), "{clause}");
        }
    }

    #[test]
    fn refine_filter_combines_with_the_current_filter() {
        assert_eq!(refine_filter("", "dns", false), "dns");
        assert_eq!(refine_filter("  ", "dns", true), "NOT dns");
        assert_eq!(
            refine_filter("tcp OR udp", "ipv4.src = '1.2.3.4'", true),
            "(tcp OR udp) AND NOT ipv4.src = '1.2.3.4'"
        );
    }

    #[test]
    fn shown_value_adds_the_label() {
        assert_eq!(shown_value("1", Some("A")), "1 (A)");
        assert_eq!(shown_value("x", Some("x")), "x");
        assert_eq!(shown_value("1", None), "1");
    }

    #[test]
    fn collector_counts_each_value_once_per_packet() {
        let registry = DissectorRegistry::default();
        let dns = test_fixtures::dns_edns_query_frame();
        let bgp = test_fixtures::bgp_update_frame();
        let mut collector = FieldStatsCollector::new(protocol_layers(&registry));
        for frame in [&dns, &dns, &bgp] {
            let buf = dissect(&registry, frame);
            collector.add(&Packet::new(&buf, frame));
        }
        let stats = collector.finish(Sample::All, 5);
        assert_eq!(stats.sampled, 3);
        assert_eq!(stats.displayed, 5);

        let ipv4 = stats.protocols.iter().find(|p| p.name == "IPv4").unwrap();
        assert_eq!(
            (ipv4.packets, ipv4.layer),
            (3, Some(ProtocolLayer::Network))
        );
        let dns_proto = stats.protocols.iter().find(|p| p.name == "DNS").unwrap();
        assert_eq!(dns_proto.layer, Some(ProtocolLayer::Application));
        assert_eq!(dns_proto.packets, 2);
        let application = stats
            .layers
            .iter()
            .find(|l| l.layer == ProtocolLayer::Application)
            .unwrap();
        // DNS twice, BGP once.
        assert_eq!(application.packets, 3);
        assert_eq!(stats.layers[0].layer, ProtocolLayer::Link);

        let src = stats.field("ipv4.src").unwrap();
        assert_eq!(
            (src.packets, src.distinct, src.kind),
            (3, 1, FieldKind::Address)
        );
        assert_eq!(src.top[0].packets, 3);
        let qname = stats.field("dns.questions.name").unwrap();
        assert_eq!(qname.packets, 2);
        assert_eq!(qname.top[0].value, "example.com");
        assert_eq!(stats.fields[0].protocol, "Ethernet");
    }

    #[test]
    fn samples_take_first_or_spread_positions() {
        assert_eq!(Sample::First(3).count(10), 3);
        assert_eq!(Sample::Spread(30).count(10), 10);
        assert_eq!(Sample::All.count(10), 10);
        let spread: Vec<usize> = (0..4)
            .map(|k| Sample::Spread(4).position(k, 4, 10))
            .collect();
        assert_eq!(spread, [0, 2, 5, 7]);
        let first: Vec<usize> = (0..4)
            .map(|k| Sample::First(4).position(k, 4, 10))
            .collect();
        assert_eq!(first, [0, 1, 2, 3]);
        assert_eq!(Sample::Spread(10).position(9, 10, 10), 9);
    }

    #[test]
    fn timeline_buckets_packets_by_time() {
        let times = [
            (0, 1_000_000),
            (1, 1_000_500),
            (2, 1_009_999),
            (5, 1_004_000),
        ];
        let h = Histogram::timeline(Split::TopProtocol, 10, || times.iter().copied());
        assert_eq!(h.start_us, 1_000_000);
        assert_eq!(h.bucket_us, 1_000);
        assert_eq!(h.buckets.len(), 10);
        assert_eq!(h.buckets[0].packets, 2);
        assert_eq!(h.buckets[4].packets, 1);
        assert_eq!(h.buckets[4].first_packet, Some(5));
        assert_eq!(h.buckets[9].packets, 1);
        assert!(!h.complete);

        let empty = Histogram::timeline(Split::TopProtocol, 4, std::iter::empty);
        assert_eq!(empty.buckets.iter().map(|b| b.packets).sum::<u64>(), 0);
    }

    #[test]
    fn split_ranks_series_and_keeps_missing_last() {
        let registry = DissectorRegistry::default();
        let dns = test_fixtures::dns_edns_query_frame();
        let bgp = test_fixtures::bgp_update_frame();
        let times = [(0, 0), (1, 1), (2, 2)];
        for (split, expected) in [
            (
                Split::TopProtocol,
                vec![
                    SeriesKey::Value("DNS".into()),
                    SeriesKey::Value("BGP".into()),
                ],
            ),
            (
                Split::Layer(ProtocolLayer::Transport),
                vec![
                    SeriesKey::Value("UDP".into()),
                    SeriesKey::Value("TCP".into()),
                ],
            ),
            (
                Split::Field("udp.dst_port".into()),
                vec![SeriesKey::Value("53".into()), SeriesKey::Missing],
            ),
        ] {
            let mut h = Histogram::timeline(split.clone(), 3, || times.iter().copied());
            let mut collector = SplitCollector::new(split, 3, protocol_layers(&registry));
            for (i, frame) in [&dns, &dns, &bgp].into_iter().enumerate() {
                let buf = dissect(&registry, frame);
                collector.add(i, &Packet::new(&buf, frame));
            }
            collector.finish(&mut h);
            assert!(h.complete);
            let keys: Vec<SeriesKey> = h.series.iter().map(|s| s.key.clone()).collect();
            assert_eq!(keys, expected);
            assert_eq!(h.series[0].packets, 2);
            assert_eq!(h.buckets[2].split, vec![0, 1]);
        }
    }

    #[test]
    fn split_merges_small_series_into_other() {
        let mut h = Histogram::timeline(Split::TopProtocol, 1, || [(0, 0)].into_iter());
        let mut collector = SplitCollector::new(Split::TopProtocol, 1, HashMap::new());
        for i in 0..(TOP_SERIES + 2) {
            let key = format!("k{i}");
            collector
                .key_index
                .insert(key.clone(), collector.keys.len());
            collector.keys.push(key);
            collector.counts.push(vec![i as u64 + 1]);
        }
        collector.finish(&mut h);
        assert_eq!(h.series.len(), TOP_SERIES + 1);
        assert_eq!(
            h.series[0].key,
            SeriesKey::Value(format!("k{}", TOP_SERIES + 1))
        );
        // The two smallest (1 + 2 packets) are merged.
        assert_eq!(
            h.series.last(),
            Some(&Series {
                key: SeriesKey::Other,
                packets: 3
            })
        );
    }
}
