//! Fuzzy completion engine for filter input.
//!
//! Uses nucleo-matcher for high-quality fuzzy matching of protocol names and
//! field names.  The completion source is built once from the dissector
//! registry at startup.

use std::collections::HashSet;

use nucleo_matcher::pattern::{Atom, AtomKind, CaseMatching, Normalization};
use nucleo_matcher::{Config, Matcher};
use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::field::{Field, FieldValue};
use packet_dissector_core::packet::{DissectBuffer, Layer};

use crate::field_format::format_field_to_string;
use crate::filter::protocol_names_match;

use super::state::{CaptureMap, PacketIndex};

#[cfg(test)]
use packet_dissector_test_alloc::test_desc;

/// A single completion candidate with display label and match score.
pub struct CompletionItem {
    /// Display text (e.g., "TCP", "TCP.src_port").
    pub label: String,
    /// Match score (higher = better match). Used for sort order.
    pub score: u16,
}

/// Completion data source built from the dissector registry.
pub struct CompletionEngine {
    /// Protocol short names: ["TCP", "UDP", "DNS", ...]
    protocols: Vec<String>,
    /// All qualified field names: ["TCP.src_port", "TCP.dst_port", "IPv4.src", ...]
    all_fields: Vec<String>,
}

impl CompletionEngine {
    /// Build the completion engine from the dissector registry.
    pub fn from_registry(registry: &DissectorRegistry) -> Self {
        let schemas = registry.all_field_schemas();

        let mut protocols = Vec::with_capacity(schemas.len());
        let mut all_fields = Vec::new();

        for schema in &schemas {
            protocols.push(schema.short_name.to_string());
            for fd in schema.fields {
                all_fields.push(format!("{}.{}", schema.short_name, fd.name));
                // Add virtual `_name` companion for fields with a display_fn.
                if fd.display_fn.is_some() {
                    all_fields.push(format!("{}.{}_name", schema.short_name, fd.name));
                }
                // Also add child fields for nested types.
                if let Some(children) = fd.children {
                    for child in children {
                        all_fields
                            .push(format!("{}.{}.{}", schema.short_name, fd.name, child.name));
                        if child.display_fn.is_some() {
                            all_fields.push(format!(
                                "{}.{}.{}_name",
                                schema.short_name, fd.name, child.name
                            ));
                        }
                    }
                }
            }
        }

        // Also add "and" and "or" keywords.
        Self {
            protocols,
            all_fields,
        }
    }

    /// Compute completion candidates for the current token being typed.
    ///
    /// The token is the word at the cursor position in the filter input.
    /// Returns candidates sorted by match score (best first).
    ///
    /// When static field descriptors have no match for a deeply nested path
    /// (e.g., `GTPv2-C.ies.value.`), falls back to scanning capture packets
    /// to discover actual field names dynamically.
    pub fn complete(
        &self,
        token: &str,
        capture: &CaptureMap,
        indices: &[PacketIndex],
        registry: &DissectorRegistry,
    ) -> Vec<CompletionItem> {
        if token.is_empty() || token.contains('=') {
            return Vec::new();
        }

        let mut matcher = Matcher::new(Config::DEFAULT);
        let atom = Atom::new(
            token,
            CaseMatching::Ignore,
            Normalization::Smart,
            AtomKind::Fuzzy,
            false,
        );

        let candidates: &[String] = if token.contains('.') {
            &self.all_fields
        } else {
            &self.protocols
        };

        let mut items: Vec<CompletionItem> = atom
            .match_list(candidates, &mut matcher)
            .into_iter()
            .map(|(label, score)| CompletionItem {
                label: label.to_string(),
                score,
            })
            .collect();

        // Fallback: if no static matches and the path is nested (2+ dots),
        // scan capture packets to discover field paths dynamically.
        if items.is_empty() && token.matches('.').count() >= 2 {
            let dynamic = discover_field_paths(token, capture, indices, registry);
            if !dynamic.is_empty() {
                let atom2 = Atom::new(
                    token,
                    CaseMatching::Ignore,
                    Normalization::Smart,
                    AtomKind::Fuzzy,
                    false,
                );
                items = atom2
                    .match_list(&dynamic, &mut matcher)
                    .into_iter()
                    .map(|(label, score)| CompletionItem {
                        label: label.to_string(),
                        score,
                    })
                    .collect();
            }
        }

        items.sort_by(|a, b| b.score.cmp(&a.score));
        items
    }

    /// Compute value completion candidates by scanning packets in the capture.
    ///
    /// Samples up to `SAMPLE_SIZE` packets, dissects them, and collects unique
    /// values for the specified `protocol.field`.  Returns candidates fuzzy-matched
    /// against `value_query`.
    pub fn complete_value(
        protocol: &str,
        field: &str,
        value_query: &str,
        capture: &CaptureMap,
        indices: &[PacketIndex],
        registry: &DissectorRegistry,
    ) -> Vec<CompletionItem> {
        const SAMPLE_SIZE: usize = 1000;

        let mut seen: HashSet<String> = HashSet::new();
        let sample_count = indices.len().min(SAMPLE_SIZE);

        let mut dissect_buf = DissectBuffer::new();
        for index in indices.iter().take(sample_count) {
            let data = match capture.packet_data(index) {
                Some(d) => d,
                None => continue,
            };
            let buf = dissect_buf.clear_into();
            if registry
                .dissect_with_link_type(data, index.link_type as u32, buf)
                .is_ok()
                && let Some(layer) = buf
                    .layers()
                    .iter()
                    .find(|l| protocol_names_match(l.name, protocol))
            {
                // Try direct field first, then nested path traversal.
                if let Some(f) = buf.field_by_name(layer, field) {
                    let v = format_field_for_completion(f, data, layer, buf);
                    if !v.is_empty() {
                        seen.insert(v);
                    }
                } else if let Some(base_name) = field.strip_suffix("_name") {
                    // Virtual `_name` field: resolve via display_fn on the base field.
                    if let Some(base_field) = buf.field_by_name(layer, base_name) {
                        if let Some(display_fn) = base_field.descriptor.display_fn {
                            let siblings = buf.layer_fields(layer);
                            if let Some(display_value) = display_fn(&base_field.value, siblings) {
                                seen.insert(display_value.to_string());
                            }
                        }
                    } else {
                        collect_nested_values(
                            buf.layer_fields(layer),
                            field,
                            &mut seen,
                            buf,
                            data,
                            layer,
                        );
                    }
                } else {
                    collect_nested_values(
                        buf.layer_fields(layer),
                        field,
                        &mut seen,
                        buf,
                        data,
                        layer,
                    );
                }
            }
        }

        if seen.is_empty() {
            return Vec::new();
        }

        if value_query.is_empty() {
            // No query yet — show all seen values sorted alphabetically.
            let mut items: Vec<CompletionItem> = seen
                .into_iter()
                .map(|label| CompletionItem { label, score: 0 })
                .collect();
            items.sort_by(|a, b| a.label.cmp(&b.label));
            return items;
        }

        let mut matcher = Matcher::new(Config::DEFAULT);
        let atom = Atom::new(
            value_query,
            CaseMatching::Ignore,
            Normalization::Smart,
            AtomKind::Fuzzy,
            false,
        );
        let candidates: Vec<String> = seen.into_iter().collect();
        let mut items: Vec<CompletionItem> = atom
            .match_list(&candidates, &mut matcher)
            .into_iter()
            .map(|(label, score)| CompletionItem {
                label: label.to_string(),
                score,
            })
            .collect();
        items.sort_by(|a, b| b.score.cmp(&a.score));
        items
    }
}

/// Discover field paths dynamically by scanning capture packets.
///
/// Given a partial token like `"GTPv2-C.ies.value.cau"`, extracts the protocol
/// (`GTPv2-C`) and the known path prefix (`ies.value`), then samples packets
/// to find all field names below that prefix.  Returns fully-qualified paths
/// like `"GTPv2-C.ies.value.cause_value"`, `"GTPv2-C.ies.value.cause_value_name"`.
fn discover_field_paths(
    token: &str,
    capture: &CaptureMap,
    indices: &[PacketIndex],
    registry: &DissectorRegistry,
) -> Vec<String> {
    const SAMPLE_SIZE: usize = 500;

    // Split: "GTPv2-C.ies.value.cau" → protocol="GTPv2-C", rest="ies.value.cau"
    let (protocol, _rest) = match token.split_once('.') {
        Some(pair) => pair,
        None => return Vec::new(),
    };

    let mut paths: HashSet<String> = HashSet::new();
    let sample_count = indices.len().min(SAMPLE_SIZE);

    let mut dissect_buf = DissectBuffer::new();
    for index in indices.iter().take(sample_count) {
        let data = match capture.packet_data(index) {
            Some(d) => d,
            None => continue,
        };
        let buf = dissect_buf.clear_into();
        if registry
            .dissect_with_link_type(data, index.link_type as u32, buf)
            .is_ok()
            && let Some(layer) = buf
                .layers()
                .iter()
                .find(|l| protocol_names_match(l.name, protocol))
        {
            let prefix = protocol.to_string();
            for field in buf.layer_fields(layer) {
                collect_field_paths(
                    &field.value,
                    &format!("{prefix}.{}", field.name()),
                    &mut paths,
                    buf,
                );
            }
        }
    }

    // Remove paths containing repeated ".value.value." segments — these come
    // from Grouped IEs that nest sub-IEs with their own "value" field.
    // The shorter path (without the repetition) already covers those fields.
    paths
        .into_iter()
        .filter(|p| !p.contains(".value.value."))
        .collect()
}

/// Recursively collect all field paths from a value tree.
fn collect_field_paths(
    fv: &FieldValue<'_>,
    prefix: &str,
    paths: &mut HashSet<String>,
    buf: &DissectBuffer<'_>,
) {
    match fv {
        FieldValue::Object(range) => {
            for f in buf.nested_fields(range) {
                let path = format!("{prefix}.{}", f.name());
                paths.insert(path.clone());
                collect_field_paths(&f.value, &path, paths, buf);
            }
        }
        FieldValue::Array(range) => {
            for elem in buf.nested_fields(range) {
                collect_field_paths(&elem.value, prefix, paths, buf);
            }
        }
        _ => {}
    }
}

/// Traverse a nested field path (e.g., `"ies.type_name"`) and collect all matching values.
///
/// Handles Array (iterates all elements) and Object (navigates by field name) nesting.
fn collect_nested_values(
    fields: &[Field<'_>],
    path: &str,
    seen: &mut HashSet<String>,
    buf: &DissectBuffer<'_>,
    data: &[u8],
    layer: &Layer,
) {
    let (head, tail) = match path.split_once('.') {
        Some((h, t)) => (h, Some(t)),
        None => (path, None),
    };

    for field in fields {
        if field.name() == head {
            match tail {
                Some(rest) => {
                    collect_nested_value(&field.value, rest, seen, buf, data, layer);
                }
                None => {
                    let v = format_field_for_completion(field, data, layer, buf);
                    if !v.is_empty() {
                        seen.insert(v);
                    }
                }
            }
        }
    }
}

/// Recurse into a FieldValue to continue nested path traversal.
fn collect_nested_value(
    fv: &FieldValue<'_>,
    path: &str,
    seen: &mut HashSet<String>,
    buf: &DissectBuffer<'_>,
    data: &[u8],
    layer: &Layer,
) {
    match fv {
        FieldValue::Object(range) => {
            collect_nested_values(buf.nested_fields(range), path, seen, buf, data, layer)
        }
        FieldValue::Array(range) => {
            for elem in buf.nested_fields(range) {
                collect_nested_value(&elem.value, path, seen, buf, data, layer);
            }
        }
        _ => {}
    }
}

/// Format a field for completion, using its `format_fn` when available.
fn format_field_for_completion(
    field: &Field<'_>,
    data: &[u8],
    layer: &Layer,
    buf: &DissectBuffer<'_>,
) -> String {
    if let FieldValue::Bytes(_) | FieldValue::Scratch(_) = &field.value
        && let Some(s) = format_field_to_string(field, data, layer, buf.scratch())
    {
        return s;
    }
    format_value_for_completion(&field.value)
}

/// Format a field value as a short string for value completion candidates.
fn format_value_for_completion(value: &FieldValue<'_>) -> String {
    match value {
        FieldValue::U8(v) => v.to_string(),
        FieldValue::U16(v) => v.to_string(),
        FieldValue::U32(v) => v.to_string(),
        FieldValue::U64(v) => v.to_string(),
        FieldValue::I32(v) => v.to_string(),
        FieldValue::Ipv4Addr(a) => format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]),
        FieldValue::Ipv6Addr(a) => format!("{}", std::net::Ipv6Addr::from(*a)),
        FieldValue::MacAddr(m) => m.to_string(),
        FieldValue::Str(s) => (*s).to_string(),
        FieldValue::Bytes(b) => {
            // Try UTF-8 first; fall back to hex for binary data.
            match core::str::from_utf8(b) {
                Ok(s) if s.chars().all(|c| !c.is_control()) => s.to_string(),
                _ => String::new(),
            }
        }
        _ => String::new(),
    }
}

/// Extract the current token (word at cursor) from the filter input for completion.
///
/// Uses forward scanning with the same space-handling rules as the filter
/// tokenizer: spaces after `=` are part of the value unless followed by
/// `and`/`or`.  Double quotes in values are stripped for matching.
///
/// Returns `(token_start_byte_offset, token_text_for_matching)`.
pub fn current_token(input: &str, cursor: usize) -> (usize, String) {
    let text = &input[..cursor.min(input.len())];
    let bytes = text.as_bytes();
    let mut token_start = 0;
    let mut pos = 0;

    while pos < bytes.len() {
        // Skip whitespace between tokens.
        while pos < bytes.len() && bytes[pos] == b' ' {
            pos += 1;
        }
        if pos >= bytes.len() {
            token_start = pos;
            break;
        }

        let start = pos;
        let mut has_eq = false;

        // Consume one token.
        while pos < bytes.len() {
            if bytes[pos] == b'=' {
                has_eq = true;
                pos += 1;
            } else if bytes[pos] == b'"' {
                pos += 1;
                while pos < bytes.len() && bytes[pos] != b'"' {
                    pos += 1;
                }
                if pos < bytes.len() {
                    pos += 1;
                }
            } else if bytes[pos] == b' ' {
                if !has_eq {
                    break;
                }
                // Space in value — peek for and/or.
                let rest = &text[pos..];
                let next = rest.split_whitespace().next().unwrap_or("");
                if next.eq_ignore_ascii_case("and") || next.eq_ignore_ascii_case("or") {
                    break;
                }
                pos += 1;
            } else {
                pos += 1;
            }
        }

        token_start = start;
    }

    let raw = &text[token_start..];

    // Strip double quotes from value for matching.
    let token = if let Some((key, val)) = raw.split_once('=') {
        let stripped = val.replace('"', "");
        format!("{key}={stripped}")
    } else {
        raw.to_string()
    };

    (token_start, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create empty capture data for tests that only need static completion.
    fn empty_ctx() -> (CaptureMap, Vec<PacketIndex>, DissectorRegistry) {
        use crate::tui::loader::tests::build_pcap_for_test;
        let pcap = build_pcap_for_test(0);
        let mut f = std::fs::File::create("/tmp/dsct_test_completion.pcap").unwrap();
        std::io::Write::write_all(&mut f, &pcap).unwrap();
        let f = std::fs::File::open("/tmp/dsct_test_completion.pcap").unwrap();
        let capture = CaptureMap::new(&f).unwrap();
        (capture, Vec::new(), DissectorRegistry::default())
    }

    #[test]
    fn current_token_at_start() {
        let (start, token) = current_token("tcp", 3);
        assert_eq!(start, 0);
        assert_eq!(token, "tcp");
    }

    #[test]
    fn current_token_after_space() {
        let (start, token) = current_token("tcp and ipv", 11);
        assert_eq!(start, 8);
        assert_eq!(token, "ipv");
    }

    #[test]
    fn current_token_empty() {
        let (start, token) = current_token("", 0);
        assert_eq!(start, 0);
        assert_eq!(token, "");
    }

    #[test]
    fn current_token_at_space() {
        let (start, token) = current_token("tcp ", 4);
        assert_eq!(start, 4);
        assert_eq!(token, "");
    }

    #[test]
    fn complete_empty_returns_empty() {
        let engine = CompletionEngine {
            protocols: vec!["TCP".into(), "UDP".into()],
            all_fields: vec![],
        };
        let items = {
            let (c, i, r) = empty_ctx();
            engine.complete("", &c, &i, &r)
        };
        assert!(items.is_empty());
    }

    #[test]
    fn complete_protocol() {
        let engine = CompletionEngine {
            protocols: vec!["TCP".into(), "UDP".into(), "TLS".into(), "DNS".into()],
            all_fields: vec![],
        };
        let items = {
            let (c, i, r) = empty_ctx();
            engine.complete("tc", &c, &i, &r)
        };
        assert!(!items.is_empty());
        assert_eq!(items[0].label, "TCP");
    }

    #[test]
    fn complete_field() {
        let engine = CompletionEngine {
            protocols: vec!["TCP".into()],
            all_fields: vec![
                "TCP.src_port".into(),
                "TCP.dst_port".into(),
                "TCP.seq".into(),
            ],
        };
        let items = {
            let (c, i, r) = empty_ctx();
            engine.complete("TCP.s", &c, &i, &r)
        };
        assert!(!items.is_empty());
        // Should match src_port and seq
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"TCP.src_port"));
        assert!(labels.contains(&"TCP.seq"));
    }

    #[test]
    fn complete_after_equals_returns_empty() {
        let engine = CompletionEngine {
            protocols: vec!["TCP".into()],
            all_fields: vec!["TCP.src_port".into()],
        };
        let items = {
            let (c, i, r) = empty_ctx();
            engine.complete("TCP.src_port=80", &c, &i, &r)
        };
        assert!(items.is_empty());
    }

    #[test]
    fn from_registry_builds() {
        let registry = DissectorRegistry::default();
        let engine = CompletionEngine::from_registry(&registry);
        assert!(!engine.protocols.is_empty());
        assert!(!engine.all_fields.is_empty());
    }

    #[test]
    fn from_registry_includes_display_fn_name_fields() {
        let registry = DissectorRegistry::default();
        let engine = CompletionEngine::from_registry(&registry);
        // Fields with display_fn should have corresponding _name entries.
        let has_name_field = engine.all_fields.iter().any(|f| f.ends_with("_name"));
        assert!(
            has_name_field,
            "expected at least one _name virtual field in completion candidates"
        );
    }

    #[test]
    fn current_token_value_with_spaces() {
        // "proto.field=Create Session" → entire thing is one token
        let (start, token) = current_token("proto.field=Create Session", 26);
        assert_eq!(start, 0);
        assert_eq!(token, "proto.field=Create Session");
    }

    #[test]
    fn current_token_value_with_spaces_after_and() {
        // "tcp and proto.field=Create Session" → token is "proto.field=Create Session"
        let (start, token) = current_token("tcp and proto.field=Create Session", 34);
        assert_eq!(start, 8);
        assert_eq!(token, "proto.field=Create Session");
    }

    #[test]
    fn current_token_quoted_value() {
        // proto.field="Create Session" → quotes stripped for matching
        let (start, token) = current_token(r#"proto.field="Create Session""#, 28);
        assert_eq!(start, 0);
        assert_eq!(token, "proto.field=Create Session");
    }

    #[test]
    fn current_token_partial_quoted_value() {
        // proto.field="Crea → quotes stripped, partial value
        let (start, token) = current_token(r#"proto.field="Crea"#, 17);
        assert_eq!(start, 0);
        assert_eq!(token, "proto.field=Crea");
    }

    // -- collect_field_paths --

    #[test]
    fn collect_field_paths_flat() {
        let buf = DissectBuffer::new();
        let mut paths = HashSet::new();
        let fv = FieldValue::U32(42);
        collect_field_paths(&fv, "TCP.src_port", &mut paths, &buf);
        assert!(paths.is_empty());
    }

    #[test]
    fn collect_field_paths_object() {
        let mut buf = DissectBuffer::new();
        buf.push_field(test_desc("name", "Name"), FieldValue::Str("test"), 0..0);
        buf.push_field(test_desc("type", "Type"), FieldValue::U16(1), 0..0);
        let fv = FieldValue::Object(0..2);
        let mut paths = HashSet::new();
        collect_field_paths(&fv, "DNS.questions", &mut paths, &buf);
        assert!(paths.contains("DNS.questions.name"));
        assert!(paths.contains("DNS.questions.type"));
    }

    #[test]
    fn collect_field_paths_array() {
        let mut buf = DissectBuffer::new();
        // Array element [0] is an Object containing "inner"
        let obj_idx =
            buf.begin_container(test_desc("elem", "Elem"), FieldValue::Object(0..0), 0..0);
        buf.push_field(test_desc("inner", "Inner"), FieldValue::U8(0), 0..0);
        buf.end_container(obj_idx);
        let fv = FieldValue::Array(0..2);
        let mut paths = HashSet::new();
        collect_field_paths(&fv, "Proto.arr", &mut paths, &buf);
        assert!(paths.contains("Proto.arr.inner"));
    }

    // -- collect_nested_values --

    /// Create a dummy layer spanning all fields in the buffer.
    fn dummy_layer(buf: &DissectBuffer<'_>) -> Layer {
        Layer {
            name: "Test",
            display_name: None,
            field_descriptors: &[],
            field_range: 0..buf.fields().len() as u32,
            range: 0..0,
        }
    }

    #[test]
    fn collect_nested_values_leaf() {
        let mut buf = DissectBuffer::new();
        buf.push_field(test_desc("port", "Port"), FieldValue::U16(443), 0..0);
        let fields = buf.fields();
        let data: &[u8] = &[];
        let layer = dummy_layer(&buf);
        let mut seen = HashSet::new();
        collect_nested_values(fields, "port", &mut seen, &buf, data, &layer);
        assert!(seen.contains("443"));
    }

    #[test]
    fn collect_nested_values_deep() {
        let mut buf = DissectBuffer::new();
        let obj = buf.begin_container(test_desc("outer", "Outer"), FieldValue::Object(0..0), 0..0);
        buf.push_field(
            test_desc("inner", "Inner"),
            FieldValue::Str("deep_val"),
            0..0,
        );
        buf.end_container(obj);
        let fields = &buf.fields()[0..1]; // just the "outer" field
        let data: &[u8] = &[];
        let layer = dummy_layer(&buf);
        let mut seen = HashSet::new();
        collect_nested_values(fields, "outer.inner", &mut seen, &buf, data, &layer);
        assert!(seen.contains("deep_val"));
    }

    #[test]
    fn collect_nested_values_array() {
        let mut buf = DissectBuffer::new();
        let arr = buf.begin_container(test_desc("items", "Items"), FieldValue::Array(0..0), 0..0);
        let o0 = buf.begin_container(test_desc("e", "E"), FieldValue::Object(0..0), 0..0);
        buf.push_field(test_desc("val", "Val"), FieldValue::Str("a"), 0..0);
        buf.end_container(o0);
        let o1 = buf.begin_container(test_desc("e", "E"), FieldValue::Object(0..0), 0..0);
        buf.push_field(test_desc("val", "Val"), FieldValue::Str("b"), 0..0);
        buf.end_container(o1);
        buf.end_container(arr);
        let fields = &buf.fields()[0..1]; // just the "items" array field
        let data: &[u8] = &[];
        let layer = dummy_layer(&buf);
        let mut seen = HashSet::new();
        collect_nested_values(fields, "items.val", &mut seen, &buf, data, &layer);
        assert!(seen.contains("a"));
        assert!(seen.contains("b"));
    }

    // -- format_value_for_completion --

    #[test]
    fn format_value_for_completion_variants() {
        assert_eq!(format_value_for_completion(&FieldValue::U8(1)), "1");
        assert_eq!(format_value_for_completion(&FieldValue::U16(80)), "80");
        assert_eq!(format_value_for_completion(&FieldValue::U32(999)), "999");
        assert_eq!(format_value_for_completion(&FieldValue::U64(42)), "42");
        assert_eq!(format_value_for_completion(&FieldValue::I32(-1)), "-1");
        assert_eq!(
            format_value_for_completion(&FieldValue::Ipv4Addr([10, 0, 0, 1])),
            "10.0.0.1"
        );
        assert_eq!(
            format_value_for_completion(&FieldValue::Str("hello")),
            "hello"
        );
        assert!(format_value_for_completion(&FieldValue::Bytes(&[1])).is_empty());
    }

    // -- complete_value with real packets --

    #[test]
    fn complete_value_with_packets() {
        use crate::tui::loader;
        use crate::tui::loader::tests::build_pcap_for_test;
        let pcap = build_pcap_for_test(3);
        let tmp_path = format!("/tmp/dsct_test_cv_{}.pcap", std::process::id());
        let mut f = std::fs::File::create(&tmp_path).unwrap();
        std::io::Write::write_all(&mut f, &pcap).unwrap();
        let f = std::fs::File::open(&tmp_path).unwrap();
        let capture = CaptureMap::new(&f).unwrap();
        let indices = loader::build_index(capture.as_bytes()).unwrap();
        let registry = DissectorRegistry::default();

        let items =
            CompletionEngine::complete_value("UDP", "src_port", "", &capture, &indices, &registry);
        // Test packets have UDP src_port=4096
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"4096"));
        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn complete_value_no_match_returns_empty() {
        use crate::tui::loader;
        use crate::tui::loader::tests::build_pcap_for_test;
        let pcap = build_pcap_for_test(3);
        let tmp_path = format!("/tmp/dsct_test_cv_nomatch_{}.pcap", std::process::id());
        let mut f = std::fs::File::create(&tmp_path).unwrap();
        std::io::Write::write_all(&mut f, &pcap).unwrap();
        let f = std::fs::File::open(&tmp_path).unwrap();
        let capture = CaptureMap::new(&f).unwrap();
        let indices = loader::build_index(capture.as_bytes()).unwrap();
        let registry = DissectorRegistry::default();

        // Non-existent protocol
        let items = CompletionEngine::complete_value(
            "NONEXISTENT",
            "field",
            "",
            &capture,
            &indices,
            &registry,
        );
        assert!(items.is_empty());

        // Non-existent field
        let items = CompletionEngine::complete_value(
            "UDP",
            "nonexistent_field",
            "",
            &capture,
            &indices,
            &registry,
        );
        assert!(items.is_empty());

        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn complete_value_prefix_filters() {
        use crate::tui::loader;
        use crate::tui::loader::tests::build_pcap_for_test;
        let pcap = build_pcap_for_test(3);
        let tmp_path = format!("/tmp/dsct_test_cv_prefix_{}.pcap", std::process::id());
        let mut f = std::fs::File::create(&tmp_path).unwrap();
        std::io::Write::write_all(&mut f, &pcap).unwrap();
        let f = std::fs::File::open(&tmp_path).unwrap();
        let capture = CaptureMap::new(&f).unwrap();
        let indices = loader::build_index(capture.as_bytes()).unwrap();
        let registry = DissectorRegistry::default();

        // With matching prefix
        let items = CompletionEngine::complete_value(
            "UDP", "src_port", "40", &capture, &indices, &registry,
        );
        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert!(labels.contains(&"4096"), "expected 4096 in {labels:?}");

        // With non-matching prefix
        let items = CompletionEngine::complete_value(
            "UDP", "src_port", "zzz", &capture, &indices, &registry,
        );
        assert!(items.is_empty());

        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn complete_value_deduplicates() {
        use crate::tui::loader;
        use crate::tui::loader::tests::build_pcap_for_test;
        // Multiple packets with the same src_port should yield one entry
        let pcap = build_pcap_for_test(5);
        let tmp_path = format!("/tmp/dsct_test_cv_dedup_{}.pcap", std::process::id());
        let mut f = std::fs::File::create(&tmp_path).unwrap();
        std::io::Write::write_all(&mut f, &pcap).unwrap();
        let f = std::fs::File::open(&tmp_path).unwrap();
        let capture = CaptureMap::new(&f).unwrap();
        let indices = loader::build_index(capture.as_bytes()).unwrap();
        let registry = DissectorRegistry::default();

        let items =
            CompletionEngine::complete_value("UDP", "src_port", "", &capture, &indices, &registry);
        // All 5 packets have the same src_port, so only 1 unique value
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].label, "4096");

        let _ = std::fs::remove_file(&tmp_path);
    }

    #[test]
    fn format_value_for_completion_ipv6() {
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        addr[1] = 0x01;
        addr[2] = 0x0d;
        addr[3] = 0xb8;
        addr[15] = 1;
        assert_eq!(
            format_value_for_completion(&FieldValue::Ipv6Addr(addr)),
            "2001:db8::1"
        );
    }

    #[test]
    fn format_value_for_completion_bytes_utf8() {
        assert_eq!(
            format_value_for_completion(&FieldValue::Bytes(b"hello")),
            "hello"
        );
    }

    #[test]
    fn format_value_for_completion_bytes_binary_is_empty() {
        assert!(format_value_for_completion(&FieldValue::Bytes(&[0xFF, 0x00])).is_empty());
    }

    // -- discover_field_paths --

    #[test]
    fn discover_field_paths_no_dot_returns_empty() {
        let (c, i, r) = empty_ctx();
        let paths = discover_field_paths("nodot", &c, &i, &r);
        assert!(paths.is_empty());
    }

    // -- current_token with "or" keyword --

    #[test]
    fn current_token_after_or() {
        let (start, token) = current_token("tcp or ud", 9);
        assert_eq!(start, 7);
        assert_eq!(token, "ud");
    }
}
