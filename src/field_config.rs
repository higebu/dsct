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
#[derive(Debug)]
pub struct FieldConfig {
    protocols: HashMap<String, FieldFilter>,
}

/// Per-protocol field filter with top-level and nested patterns.
#[derive(Debug)]
struct FieldFilter {
    /// Patterns for top-level field names (no dots).
    top_level: PatternSet,
    /// Patterns for nested sub-fields, keyed by parent field name.
    /// E.g., `"answers.name"` is stored as `nested["answers"]` containing `"name"`.
    nested: HashMap<String, PatternSet>,
}

/// A set of patterns for matching field names.
#[derive(Debug)]
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
        let mut protocols = HashMap::with_capacity(raw.protocols.len());

        for (name, raw_proto) in raw.protocols {
            let fields = raw_proto.fields.ok_or_else(|| {
                DsctError::msg(format!("protocol '{name}': must specify 'fields'"))
            })?;
            let filter = parse_field_filter(fields)?;
            protocols.insert(name, filter);
        }

        Ok(Self { protocols })
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
