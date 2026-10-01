//! Configuration for default field visibility.
//!
//! Controls which fields are shown in non-verbose (default) mode.
//! When verbose mode is enabled, all fields are shown regardless of this config.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use serde::Deserialize;

use crate::error::{DsctError, Result, ResultExt};

/// Default field configuration embedded at compile time.
const DEFAULT_CONFIG: &str = include_str!("default_fields.toml");

/// Configuration that determines which fields are visible in non-verbose mode.
///
/// Each protocol specifies an include list (`fields`). Only fields matching
/// the listed patterns are shown. Protocols not present in the config show
/// all fields.
///
/// Patterns may use dot notation to target nested sub-fields:
/// - `"src"` — matches the top-level field `src`
/// - `"answers"` — matches the top-level container `answers`
/// - `"answers.name"` — matches `name` inside `answers`
/// - `"answers.*"` — matches all sub-fields inside `answers`
///
/// When a container field is included but has no nested patterns defined,
/// all of its sub-fields are shown (e.g., SRv6 `segments_structure`).
#[derive(Debug, Clone)]
pub struct FieldConfig {
    protocols: HashMap<String, FieldFilter>,
}

/// Per-protocol field filter with top-level and nested patterns.
#[derive(Debug, Clone)]
struct FieldFilter {
    /// Patterns for top-level field names (no dots).
    top_level: PatternSet,
    /// Patterns for nested sub-fields, keyed by parent field name.
    /// E.g., `"answers.name"` is stored as `nested["answers"]` containing `"name"`.
    nested: HashMap<String, PatternSet>,
}

/// A set of patterns for matching field names.
#[derive(Debug, Clone)]
struct PatternSet {
    /// When `true`, all names match (used for `"parent.*"` patterns).
    match_all: bool,
    exact: HashSet<String>,
    prefixes: Vec<String>,
    suffixes: Vec<String>,
}

impl PatternSet {
    fn matches(&self, name: &str) -> bool {
        self.match_all
            || self.exact.contains(name)
            || self.prefixes.iter().any(|p| name.starts_with(p.as_str()))
            || self.suffixes.iter().any(|s| name.ends_with(s.as_str()))
    }
}

/// Raw TOML representation for deserialization.
#[derive(Deserialize)]
struct RawConfig {
    #[serde(flatten)]
    protocols: HashMap<String, RawProtocol>,
}

#[derive(Deserialize)]
struct RawProtocol {
    fields: Option<Vec<String>>,
}

impl FieldConfig {
    /// Load the embedded default configuration.
    pub fn default_config() -> Result<Self> {
        Self::from_toml(DEFAULT_CONFIG).context("failed to parse embedded default_fields.toml")
    }

    /// Load configuration from a file path.
    pub fn from_path(path: &Path) -> Result<Self> {
        let content =
            std::fs::read_to_string(path).context(format!("reading {}", path.display()))?;
        Self::from_toml(&content).context(format!("parsing field config from {}", path.display()))
    }

    fn from_toml(toml_str: &str) -> Result<Self> {
        let raw: RawConfig = toml::from_str(toml_str)?;
        let mut protocols = Vec::with_capacity(raw.protocols.len());
        for (name, raw_proto) in raw.protocols {
            let fields = raw_proto.fields.ok_or_else(|| {
                DsctError::msg(format!("protocol '{name}': must specify 'fields'"))
            })?;
            protocols.push((name, fields));
        }
        Self::from_protocol_patterns(protocols)
    }

    /// Build a config directly from patterns already grouped by protocol
    /// (using the same key a layer's `Layer::name` would have, e.g.
    /// `"BGP"`, `"TCP"`), reusing the same per-protocol pattern syntax as
    /// `default_fields.toml`'s `fields` lists.
    ///
    /// Used to build a [`FieldConfig`] on the fly from a request parameter
    /// (e.g. `dsct_read_packets`'s `fields`) rather than from the embedded
    /// TOML.
    pub fn from_protocol_patterns<I>(protocols: I) -> Result<Self>
    where
        I: IntoIterator<Item = (String, Vec<String>)>,
    {
        let mut map = HashMap::new();
        for (name, patterns) in protocols {
            let filter = parse_field_filter(patterns)?;
            map.insert(name, filter);
        }
        Ok(Self { protocols: map })
    }

    /// Overwrite (or insert) this config's per-protocol filters with those
    /// from `other`, keeping this config's existing filter for any
    /// protocol `other` doesn't mention.
    ///
    /// Used to layer an explicit per-request override (e.g.
    /// `dsct_read_packets`'s `fields` parameter) onto the default or
    /// verbose field visibility without discarding it for protocols the
    /// override doesn't name.
    pub fn merge_overrides(&mut self, other: FieldConfig) {
        self.protocols.extend(other.protocols);
    }

    /// Returns `true` if the given top-level field name should be shown.
    ///
    /// If the protocol is not in the config, all fields are shown.
    pub fn should_include(&self, protocol: &str, name: &str) -> bool {
        match self.protocols.get(protocol) {
            None => true,
            Some(filter) => filter.top_level.matches(name),
        }
    }

    /// Returns `true` if a nested sub-field should be shown.
    ///
    /// `parent` is the name of the containing field (e.g., `"answers"`).
    /// If the protocol has no nested patterns for `parent`, all sub-fields
    /// are shown (the container was included without restricting children).
    pub fn should_include_nested(&self, protocol: &str, parent: &str, name: &str) -> bool {
        match self.protocols.get(protocol) {
            None => true,
            Some(filter) => match filter.nested.get(parent) {
                None => true,
                Some(patterns) => patterns.matches(name),
            },
        }
    }
}

/// Parse a list of pattern strings into a [`FieldFilter`].
///
/// Patterns without dots go into `top_level`. Patterns with a single dot
/// (e.g., `"answers.name"`) are split into parent + child and stored in `nested`.
fn parse_field_filter(patterns: Vec<String>) -> Result<FieldFilter> {
    let mut top_patterns = Vec::new();
    let mut nested_patterns: HashMap<String, Vec<String>> = HashMap::new();

    let mut match_all_parents: HashSet<String> = HashSet::new();

    for p in patterns {
        if let Some((parent, child)) = p.split_once('.') {
            if parent.is_empty() {
                return Err(DsctError::msg(format!(
                    "invalid pattern \"{p}\": parent name before '.' must not be empty"
                )));
            }
            if child.is_empty() {
                return Err(DsctError::msg(format!(
                    "invalid pattern \"{p}\": child name after '.' must not be empty"
                )));
            }
            if child.contains('.') {
                return Err(DsctError::msg(format!(
                    "invalid pattern \"{p}\": only one level of dot nesting is supported"
                )));
            }
            if child == "*" {
                match_all_parents.insert(parent.to_string());
            } else {
                nested_patterns
                    .entry(parent.to_string())
                    .or_default()
                    .push(child.to_string());
            }
        } else {
            top_patterns.push(p);
        }
    }

    let top_level = parse_patterns(top_patterns)?;
    let mut nested = HashMap::with_capacity(nested_patterns.len() + match_all_parents.len());
    for parent in match_all_parents {
        // "parent.*" → PatternSet that matches everything.
        // Any explicit "parent.field" patterns are merged but redundant.
        nested_patterns.remove(&parent);
        nested.insert(
            parent,
            PatternSet {
                match_all: true,
                exact: HashSet::new(),
                prefixes: Vec::new(),
                suffixes: Vec::new(),
            },
        );
    }
    for (parent, child_patterns) in nested_patterns {
        nested.insert(parent, parse_patterns(child_patterns)?);
    }

    Ok(FieldFilter { top_level, nested })
}

/// Parse a list of pattern strings into a [`PatternSet`].
///
/// Valid forms:
/// - exact: no `*` (e.g., `"src"`)
/// - prefix: `"foo*"` (non-empty prefix, single trailing `*`)
/// - suffix: `"*bar"` (non-empty suffix, single leading `*`)
///
/// Returns an error for unsupported patterns such as `"*"`, `"foo*bar"`, or `"*foo*"`.
fn parse_patterns(patterns: Vec<String>) -> Result<PatternSet> {
    let mut exact = HashSet::new();
    let mut prefixes = Vec::new();
    let mut suffixes = Vec::new();

    for p in patterns {
        if p == "*" {
            return Err(DsctError::msg(
                "unsupported wildcard pattern \"*\": use a more specific prefix or suffix pattern",
            ));
        }

        if let Some(prefix) = p.strip_suffix('*') {
            if prefix.is_empty() || prefix.contains('*') {
                return Err(DsctError::msg(format!(
                    "unsupported wildcard pattern \"{p}\": only a single trailing '*' is allowed"
                )));
            }
            prefixes.push(prefix.to_string());
        } else if let Some(suffix) = p.strip_prefix('*') {
            if suffix.is_empty() || suffix.contains('*') {
                return Err(DsctError::msg(format!(
                    "unsupported wildcard pattern \"{p}\": only a single leading '*' is allowed"
                )));
            }
            suffixes.push(suffix.to_string());
        } else if p.contains('*') {
            return Err(DsctError::msg(format!(
                "unsupported wildcard pattern \"{p}\": patterns may only be exact, 'prefix*', or '*suffix'"
            )));
        } else {
            exact.insert(p);
        }
    }

    Ok(PatternSet {
        match_all: false,
        exact,
        prefixes,
        suffixes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Collects the children of every descriptor named `name`, at any depth.
    #[cfg(feature = "tcp")]
    fn collect_children_named<'a>(
        fields: &'a [packet_dissector_core::field::FieldDescriptor],
        name: &str,
        out: &mut Vec<&'a [packet_dissector_core::field::FieldDescriptor]>,
    ) {
        for fd in fields {
            if let Some(children) = fd.children {
                if fd.name == name {
                    out.push(children);
                }
                collect_children_named(children, name, out);
            }
        }
    }

    /// Protocols in `default_fields.toml` whose field schema dsct cannot read
    /// yet, so their patterns cannot be checked.
    ///
    /// Since packet-dissector 0.6.1 `all_field_schemas()` also reports the
    /// dissectors behind dispatchers (HTTP, HTTP/2, L2TP, RTP, NAS-5G, ...),
    /// so every section is checked.  The test fails once an entry here gains
    /// a non-empty schema, so the entry is removed and its patterns get
    /// checked.
    #[cfg(feature = "tcp")]
    const PROTOCOLS_WITHOUT_SCHEMA: &[(&str, &str)] = &[];

    /// Returns a message for every pattern in `config_toml` that matches no
    /// field, skipping the protocols in `without_schema`.
    ///
    /// Every exact (non-wildcard) pattern in `default_fields.toml` must name
    /// a field the dissector can emit, or the value it was meant to show is
    /// silently hidden in non-verbose output. The container of a nested
    /// pattern (`parent.child`, `parent.*`, `parent.prefix*`) must exist too.
    ///
    /// A pattern names either a field in the descriptor tree or a `_name`
    /// companion, which the serializer synthesizes from a descriptor's
    /// `display_fn` as `"<base field name>_name"` (see
    /// `emit_virtual_name_field` in `serialize.rs`). Nested patterns
    /// (`parent.child`) filter by the immediate parent's name, so the parent
    /// may sit at any depth of the tree (e.g. TLS `extensions` inside
    /// `handshake_messages`). This catches drift between
    /// `default_fields.toml` and the dissector crates after a bump.
    ///
    /// TCP reassembly also gives an intermediate segment a thin layer named
    /// after the upper protocol that holds only the TCP
    /// `reassembly_in_progress` and `segment_count` descriptors
    /// (packet-dissector `TcpReassemblyService::add_reassembly_fields`), so
    /// those two names are accepted as top-level fields of any protocol.
    #[cfg(feature = "tcp")]
    fn stale_patterns(config_toml: &str, without_schema: &[(&str, &str)]) -> Vec<String> {
        use packet_dissector::registry::DissectorRegistry;
        use packet_dissector_core::field::FieldDescriptor;

        let raw: RawConfig = toml::from_str(config_toml).unwrap();
        let registry = DissectorRegistry::default();
        let schemas = registry.all_field_schemas();

        let reassembly_fields = {
            use packet_dissector::dissectors::tcp::{
                FD_REASSEMBLY_IN_PROGRESS, FD_SEGMENT_COUNT, FIELD_DESCRIPTORS,
            };
            [
                FIELD_DESCRIPTORS[FD_REASSEMBLY_IN_PROGRESS].name,
                FIELD_DESCRIPTORS[FD_SEGMENT_COUNT].name,
            ]
        };

        let mut failures = Vec::new();

        for (name, _) in without_schema {
            if !raw.protocols.contains_key(*name) {
                failures.push(format!(
                    "PROTOCOLS_WITHOUT_SCHEMA entry \"{name}\" is not a default_fields.toml section"
                ));
            }
        }

        for (protocol, raw_proto) in &raw.protocols {
            let Some(fields) = &raw_proto.fields else {
                continue;
            };
            let schema = schemas
                .iter()
                .find(|s| s.short_name == protocol && !s.fields.is_empty());
            let excluded = without_schema.iter().any(|(name, _)| name == protocol);
            let schema = match (schema, excluded) {
                (Some(schema), false) => schema,
                (None, true) => continue,
                (Some(_), true) => {
                    failures.push(format!(
                        "[{protocol}] now has a field schema: remove it from PROTOCOLS_WITHOUT_SCHEMA"
                    ));
                    continue;
                }
                // The dissector is compiled out in this feature set.
                (None, false) => continue,
            };

            for pattern in fields {
                let (parent, last_segment) = match pattern.split_once('.') {
                    Some((p, c)) => (Some(p), c),
                    None => (None, pattern.as_str()),
                };
                let scopes: Vec<&[FieldDescriptor]> = match parent {
                    None => vec![schema.fields],
                    Some(parent_name) => {
                        let mut found = Vec::new();
                        collect_children_named(schema.fields, parent_name, &mut found);
                        found
                    }
                };
                if scopes.is_empty() {
                    failures.push(format!(
                        "[{protocol}] pattern \"{pattern}\": no container field \"{}\"",
                        parent.unwrap_or_default()
                    ));
                    continue;
                }
                // The parent of a wildcard pattern is checked above; the
                // wildcard itself may legitimately match nothing yet.
                if last_segment.contains('*') {
                    continue;
                }

                let exists = (parent.is_none() && reassembly_fields.contains(&last_segment))
                    || scopes.iter().any(|children| {
                        children.iter().any(|fd| {
                            fd.name == last_segment
                                || last_segment
                                    .strip_suffix("_name")
                                    .is_some_and(|base| fd.name == base && fd.display_fn.is_some())
                        })
                    });
                if !exists {
                    failures.push(format!(
                        "[{protocol}] pattern \"{pattern}\": no field or _name companion \"{last_segment}\" in the {} descriptor tree",
                        parent.unwrap_or(protocol.as_str())
                    ));
                }
            }
        }

        failures.sort();
        failures
    }

    #[cfg(feature = "tcp")]
    #[test]
    fn exact_patterns_name_existing_fields() {
        let failures = stale_patterns(DEFAULT_CONFIG, PROTOCOLS_WITHOUT_SCHEMA);
        assert!(
            failures.is_empty(),
            "default_fields.toml has patterns that match no field:\n{}",
            failures.join("\n")
        );
    }

    /// Fields of the sections written without a schema that default output
    /// must not hide: decoded content (L2TP AVPs, NAS-5G IEs), error and
    /// diagnostic fields (HTTP/2 HPACK errors, GOAWAY debug data, missing
    /// mandatory NAS IEs) and frame metadata.
    #[cfg(all(
        feature = "http",
        feature = "http2",
        feature = "l2tp",
        feature = "l2tpv3",
        feature = "rtp",
        feature = "nas5g"
    ))]
    #[test]
    fn dispatched_sections_show_key_fields() {
        let config = FieldConfig::default_config().unwrap();
        let top = [
            ("HTTP", "content_type"),
            ("HTTP2", "debug_data"),
            ("HTTP2", "hpack_error"),
            ("HTTP2", "priority_weight"),
            ("HTTP2", "origins"),
            ("HTTP2", "alt_svc_field_value"),
            ("L2TP", "version"),
            ("L2TP", "message_type"),
            ("L2TP", "message_type_name"),
            ("L2TP", "avps"),
            ("NAS-5G", "information_elements"),
            ("NAS-5G", "ciphered_nas_message"),
            ("NAS-5G", "missing_mandatory_ie"),
            ("NAS-5G", "undecoded_octets"),
            ("NAS-5G", "raw_nas_message"),
            ("HTTP", "chunk_count"),
            ("L2TPv3", "message_type_name"),
        ];
        for (proto, field) in top {
            assert!(
                config.should_include(proto, field),
                "[{proto}] {field} is hidden"
            );
        }
        let nested = [
            ("L2TP", "avps", "result_code"),
            ("L2TP", "avps", "typed_value_name"),
            ("L2TPv3-UDP", "avps", "typed_value"),
            ("L2TPv3-UDP", "avps", "typed_value_name"),
            ("L2TPv3-UDP", "avps", "error_message"),
            ("L2TPv3", "avps", "result_code"),
            ("NAS-5G", "information_elements", "cause_name"),
        ];
        let registry = packet_dissector::registry::DissectorRegistry::default();
        let schemas = registry.all_field_schemas();
        for (proto, parent, field) in nested {
            // The sub-field must exist (as a field or a `_name` companion),
            // or the check below would pass vacuously.
            let children = schemas
                .iter()
                .filter(|s| s.short_name == proto)
                .flat_map(|s| s.fields.iter())
                .filter(|fd| fd.name == parent)
                .find_map(|fd| fd.children)
                .expect("the container exists in the schema");
            assert!(
                children.iter().any(|fd| fd.name == field
                    || field
                        .strip_suffix("_name")
                        .is_some_and(|base| fd.name == base && fd.display_fn.is_some())),
                "[{proto}] {parent} has no sub-field {field}"
            );
            assert!(
                config.should_include(proto, parent)
                    && config.should_include_nested(proto, parent, field),
                "[{proto}] {parent}.{field} is hidden"
            );
        }
    }

    /// Whether `name` is shown at the top level (`parent` is `None`) or
    /// inside the container named `parent`.
    #[cfg(feature = "tcp")]
    fn is_shown(config: &FieldConfig, proto: &str, parent: Option<&str>, name: &str) -> bool {
        match parent {
            None => config.should_include(proto, name),
            Some(parent) => config.should_include_nested(proto, parent, name),
        }
    }

    /// Walks `fields` and, for every shown descriptor with a `display_fn`,
    /// counts its `_name` companion in `companions` and records it in
    /// `hidden` when the config hides it. Recurses into shown containers.
    ///
    /// Mirrors the serializer's filtering: a top-level field is checked with
    /// `should_include`, and a sub-field of an Object or of an Array of
    /// Objects with `should_include_nested` keyed by its immediate
    /// container's name, at any depth (see `write_field_json` in
    /// `serialize.rs`).
    #[cfg(feature = "tcp")]
    fn collect_hidden_companions(
        config: &FieldConfig,
        proto: &str,
        parent: Option<&str>,
        fields: &[packet_dissector_core::field::FieldDescriptor],
        companions: &mut usize,
        hidden: &mut Vec<String>,
    ) {
        for fd in fields {
            if !is_shown(config, proto, parent, fd.name) {
                continue;
            }
            if fd.display_fn.is_some() {
                *companions += 1;
                let name = format!("{}_name", fd.name);
                if !is_shown(config, proto, parent, &name) {
                    hidden.push(match parent {
                        None => format!("[{proto}] {name}"),
                        Some(parent) => format!("[{proto}] {parent}.{name}"),
                    });
                }
            }
            if let Some(children) = fd.children {
                collect_hidden_companions(
                    config,
                    proto,
                    Some(fd.name),
                    children,
                    companions,
                    hidden,
                );
            }
        }
    }

    /// Every field that default output shows and that has a `display_fn`
    /// also shows its `_name` companion, in every `default_fields.toml`
    /// section, so default output has no bare code without its name.
    ///
    /// Sections whose dissector is compiled out in this feature set are
    /// skipped, as in `exact_patterns_name_existing_fields`. Protocols
    /// without a section show every field, companions included.
    #[cfg(feature = "tcp")]
    #[test]
    fn shown_fields_show_name_companions() {
        let config = FieldConfig::default_config().unwrap();
        let registry = packet_dissector::registry::DissectorRegistry::default();
        let schemas = registry.all_field_schemas();

        // Sections whose schema dsct could not read before packet-dissector
        // 0.6.1 must keep reporting one, or they would be skipped silently.
        #[cfg(all(
            feature = "http",
            feature = "http2",
            feature = "l2tp",
            feature = "l2tpv3",
            feature = "rtp",
            feature = "nas5g"
        ))]
        for section in [
            "HTTP",
            "HTTP2",
            "L2TP",
            "L2TPv3-UDP",
            "L2TPv3",
            "RTP",
            "NAS-5G",
        ] {
            assert!(
                schemas
                    .iter()
                    .any(|s| s.short_name == section && !s.fields.is_empty()),
                "[{section}] has no field schema"
            );
        }

        let mut companions = 0;
        let mut hidden = Vec::new();
        for schema in &schemas {
            let proto = schema.short_name;
            if config.protocols.contains_key(proto) {
                collect_hidden_companions(
                    &config,
                    proto,
                    None,
                    schema.fields,
                    &mut companions,
                    &mut hidden,
                );
            }
        }
        assert!(companions > 0, "no shown field has a display_fn");
        hidden.sort();
        hidden.dedup();
        assert!(
            hidden.is_empty(),
            "default_fields.toml hides _name companions:\n{}",
            hidden.join("\n")
        );
    }

    /// The checker itself reports each kind of stale entry.
    #[cfg(feature = "tcp")]
    #[test]
    fn stale_patterns_reports_each_kind_of_drift() {
        let config = r#"
            [DNS]
            fields = [
              "id",
              "questions.name",
              "answers.rdata_*",
              "reassembly_in_progress",
              "nope",
              "nope_name",
              "questions.nope",
              "nosuch.*",
            ]

            [IPv4]
            fields = ["src"]

            [NoSchema]
            fields = ["unchecked"]

            [NotCompiledIn]
            fields = ["unchecked"]
        "#;
        let without_schema = [("IPv4", "test"), ("NoSchema", "test"), ("Missing", "test")];

        assert_eq!(
            stale_patterns(config, &without_schema),
            [
                "PROTOCOLS_WITHOUT_SCHEMA entry \"Missing\" is not a default_fields.toml section",
                "[DNS] pattern \"nope\": no field or _name companion \"nope\" in the DNS descriptor tree",
                "[DNS] pattern \"nope_name\": no field or _name companion \"nope_name\" in the DNS descriptor tree",
                "[DNS] pattern \"nosuch.*\": no container field \"nosuch\"",
                "[DNS] pattern \"questions.nope\": no field or _name companion \"nope\" in the questions descriptor tree",
                "[IPv4] now has a field schema: remove it from PROTOCOLS_WITHOUT_SCHEMA",
            ]
        );
    }

    #[test]
    fn default_config_parses() {
        let config = FieldConfig::default_config().unwrap();
        // Smoke test: known protocols should be present.
        assert!(config.protocols.contains_key("IPv4"));
        assert!(config.protocols.contains_key("DNS"));
        assert!(config.protocols.contains_key("DHCP"));
    }

    #[test]
    fn include_exact_match() {
        let config = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = ["src", "dst"]
            "#,
        )
        .unwrap();
        assert!(config.should_include("TestProto", "src"));
        assert!(config.should_include("TestProto", "dst"));
        assert!(!config.should_include("TestProto", "checksum"));
    }

    #[test]
    fn prefix_pattern() {
        let config = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = ["option_*"]
            "#,
        )
        .unwrap();
        assert!(config.should_include("TestProto", "option_overload"));
        assert!(config.should_include("TestProto", "option_foo"));
        assert!(!config.should_include("TestProto", "message_type"));
    }

    #[test]
    fn suffix_pattern() {
        let config = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = ["*_port"]
            "#,
        )
        .unwrap();
        assert!(config.should_include("TestProto", "src_port"));
        assert!(config.should_include("TestProto", "dst_port"));
        assert!(!config.should_include("TestProto", "port_number"));
    }

    #[test]
    fn nested_dot_patterns() {
        let config = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = ["id", "answers", "answers.name", "answers.type"]
            "#,
        )
        .unwrap();
        // Top-level
        assert!(config.should_include("TestProto", "id"));
        assert!(config.should_include("TestProto", "answers"));
        assert!(!config.should_include("TestProto", "checksum"));
        // Nested — "answers" has explicit patterns
        assert!(config.should_include_nested("TestProto", "answers", "name"));
        assert!(config.should_include_nested("TestProto", "answers", "type"));
        assert!(!config.should_include_nested("TestProto", "answers", "rdlength"));
    }

    #[test]
    fn nested_no_patterns_shows_all() {
        let config = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = ["container"]
            "#,
        )
        .unwrap();
        // "container" has no nested patterns → all sub-fields shown
        assert!(config.should_include_nested("TestProto", "container", "anything"));
        assert!(config.should_include_nested("TestProto", "container", "whatever"));
    }

    #[test]
    fn unknown_protocol_shows_all() {
        let config = FieldConfig::from_toml(
            r#"
            [IPv4]
            fields = ["src"]
            "#,
        )
        .unwrap();
        assert!(config.should_include("UnknownProto", "anything"));
        assert!(config.should_include_nested("UnknownProto", "parent", "child"));
    }

    #[test]
    fn from_protocol_patterns_builds_a_working_config() {
        let config = FieldConfig::from_protocol_patterns([
            ("BGP".to_owned(), vec!["nlri".to_owned()]),
            (
                "TCP".to_owned(),
                vec!["src_port".to_owned(), "*_port".to_owned()],
            ),
        ])
        .unwrap();
        assert!(config.should_include("BGP", "nlri"));
        assert!(!config.should_include("BGP", "path_attributes"));
        assert!(config.should_include("TCP", "dst_port"));
        assert!(!config.should_include("TCP", "flags"));
        // Untouched protocol: shows everything, same as an unknown protocol.
        assert!(config.should_include("IPv4", "anything"));
    }

    #[test]
    fn from_protocol_patterns_propagates_pattern_errors() {
        let result = FieldConfig::from_protocol_patterns([(
            "BGP".to_owned(),
            vec!["path_attributes.foo.bar".to_owned()],
        )]);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("only one level of dot nesting")
        );
    }

    #[test]
    fn merge_overrides_replaces_named_protocols_and_keeps_others() {
        let mut base = FieldConfig::from_toml(
            r#"
            [BGP]
            fields = ["type_name"]
            [TCP]
            fields = ["src_port", "dst_port"]
            "#,
        )
        .unwrap();
        let override_cfg =
            FieldConfig::from_protocol_patterns([("BGP".to_owned(), vec!["nlri".to_owned()])])
                .unwrap();

        base.merge_overrides(override_cfg);

        // BGP: fully replaced by the override.
        assert!(base.should_include("BGP", "nlri"));
        assert!(!base.should_include("BGP", "type_name"));
        // TCP: untouched, still the original default.
        assert!(base.should_include("TCP", "src_port"));
        assert!(!base.should_include("TCP", "flags"));
    }

    #[test]
    fn missing_fields_is_error() {
        let result = FieldConfig::from_toml(
            r#"
            [TestProto]
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn default_config_ipv4_verbose_fields_hidden() {
        let config = FieldConfig::default_config().unwrap();
        assert!(config.should_include("IPv4", "src"));
        assert!(config.should_include("IPv4", "dst"));
        assert!(config.should_include("IPv4", "ttl"));
        assert!(config.should_include("IPv4", "protocol"));
        assert!(!config.should_include("IPv4", "version"));
        assert!(!config.should_include("IPv4", "ihl"));
        assert!(!config.should_include("IPv4", "checksum"));
    }

    #[test]
    fn default_config_tcp_fields() {
        let config = FieldConfig::default_config().unwrap();
        assert!(config.should_include("TCP", "src_port"));
        assert!(config.should_include("TCP", "dst_port"));
        assert!(config.should_include("TCP", "flags"));
        assert!(config.should_include("TCP", "flags_name"));
        assert!(config.should_include("TCP", "stream_id"));
        assert!(config.should_include("TCP", "reassembly_in_progress"));
        assert!(!config.should_include("TCP", "checksum"));
        assert!(!config.should_include("TCP", "window_size"));
    }

    #[test]
    fn default_config_dns_fields() {
        let config = FieldConfig::default_config().unwrap();
        // Top-level fields
        assert!(config.should_include("DNS", "id"));
        assert!(config.should_include("DNS", "qr"));
        assert!(config.should_include("DNS", "opcode"));
        assert!(config.should_include("DNS", "rcode"));
        assert!(config.should_include("DNS", "questions"));
        assert!(config.should_include("DNS", "answers"));
        assert!(!config.should_include("DNS", "aa"));
        assert!(!config.should_include("DNS", "qdcount"));
        assert!(!config.should_include("DNS", "authorities"));
        // Nested: answers has explicit patterns
        assert!(config.should_include_nested("DNS", "answers", "name"));
        assert!(config.should_include_nested("DNS", "answers", "type"));
        assert!(config.should_include_nested("DNS", "answers", "class"));
        assert!(config.should_include_nested("DNS", "answers", "ttl"));
        assert!(config.should_include_nested("DNS", "answers", "rdata"));
        // rdata_* prefix pattern matches all typed rdata sub-fields
        assert!(config.should_include_nested("DNS", "answers", "rdata_preference"));
        assert!(config.should_include_nested("DNS", "answers", "rdata_exchange"));
        assert!(config.should_include_nested("DNS", "answers", "rdata_address"));
        assert!(!config.should_include_nested("DNS", "answers", "rdlength"));
        // Nested: questions has explicit patterns
        assert!(config.should_include_nested("DNS", "questions", "name"));
        assert!(config.should_include_nested("DNS", "questions", "type"));
        assert!(config.should_include_nested("DNS", "questions", "class"));
    }

    #[test]
    fn default_config_dhcp_fields() {
        let config = FieldConfig::default_config().unwrap();
        assert!(config.should_include("DHCP", "xid"));
        assert!(config.should_include("DHCP", "yiaddr"));
        assert!(config.should_include("DHCP", "dhcp_message_type"));
        assert!(config.should_include("DHCP", "server_identifier"));
        assert!(!config.should_include("DHCP", "op"));
        assert!(!config.should_include("DHCP", "htype"));
        assert!(!config.should_include("DHCP", "option_overload"));
    }

    #[test]
    fn default_config_icmp_suffix_pattern() {
        let config = FieldConfig::default_config().unwrap();
        assert!(config.should_include("ICMP", "type"));
        assert!(config.should_include("ICMP", "code"));
        assert!(config.should_include("ICMP", "originate_timestamp"));
        assert!(config.should_include("ICMP", "receive_timestamp"));
        assert!(config.should_include("ICMP", "transmit_timestamp"));
        assert!(!config.should_include("ICMP", "checksum"));
        assert!(!config.should_include("ICMP", "data"));
    }

    #[test]
    fn default_config_srv6_nested_all_shown() {
        let config = FieldConfig::default_config().unwrap();
        assert!(config.should_include("SRv6", "segments_structure"));
        // No nested patterns → all sub-fields shown
        assert!(config.should_include_nested("SRv6", "segments_structure", "locator_block_length"));
        assert!(config.should_include_nested("SRv6", "segments_structure", "anything"));
    }

    #[test]
    fn bare_wildcard_is_error() {
        let result = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = ["*"]
            "#,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unsupported wildcard pattern")
        );
    }

    #[test]
    fn middle_wildcard_is_error() {
        let result = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = ["foo*bar"]
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn double_wildcard_prefix_is_error() {
        let result = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = ["*foo*"]
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn default_config_http_fields() {
        let config = FieldConfig::default_config().unwrap();
        // Key application-layer fields should be visible
        assert!(config.should_include("HTTP", "method"));
        assert!(config.should_include("HTTP", "uri"));
        assert!(config.should_include("HTTP", "version"));
        assert!(config.should_include("HTTP", "status_code"));
        assert!(config.should_include("HTTP", "reason_phrase"));
        assert!(config.should_include("HTTP", "headers"));
        assert!(config.should_include("HTTP", "content_length"));
        // Reassembly metadata visible on intermediate segments
        assert!(config.should_include("HTTP", "reassembly_in_progress"));
        assert!(config.should_include("HTTP", "segment_count"));
        // Internal flag omitted in non-verbose mode
        assert!(!config.should_include("HTTP", "is_response"));
    }

    #[test]
    fn default_config_sctp_verbose_groups_hidden() {
        let config = FieldConfig::default_config().unwrap();
        assert!(config.should_include("SCTP", "src_port"));
        assert!(config.should_include("SCTP", "dst_port"));
        assert!(!config.should_include("SCTP", "verification_tag"));
        assert!(!config.should_include("SCTP", "checksum"));
    }

    #[test]
    fn empty_parent_in_dot_pattern_is_error() {
        let result = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = [".name"]
            "#,
        );
        assert!(result.is_err());
    }

    #[test]
    fn empty_child_in_dot_pattern_is_error() {
        let result = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = ["answers."]
            "#,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("child name after '.' must not be empty")
        );
    }

    #[test]
    fn multiple_dots_is_error() {
        let result = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = ["options.type.code"]
            "#,
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("only one level of dot nesting")
        );
    }

    #[test]
    fn nested_wildcard_matches_all() {
        let config = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = ["answers", "answers.*"]
            "#,
        )
        .unwrap();
        assert!(config.should_include("TestProto", "answers"));
        assert!(config.should_include_nested("TestProto", "answers", "name"));
        assert!(config.should_include_nested("TestProto", "answers", "type"));
        assert!(config.should_include_nested("TestProto", "answers", "rdlength"));
        assert!(config.should_include_nested("TestProto", "answers", "anything"));
    }

    #[test]
    fn nested_wildcard_overrides_explicit_patterns() {
        let config = FieldConfig::from_toml(
            r#"
            [TestProto]
            fields = ["answers", "answers.name", "answers.*"]
            "#,
        )
        .unwrap();
        // "answers.*" should make everything match, even though explicit patterns exist
        assert!(config.should_include_nested("TestProto", "answers", "rdlength"));
    }
}
