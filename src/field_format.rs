//! Utility for formatting field values via their custom format function.
//!
//! Fields that store raw bytes at dissection time (e.g. DNS domain names) rely
//! on a format function to produce a human-readable string at serialization
//! time.  This module provides a helper to invoke that function and return the
//! result as a plain [`String`], which is useful outside of the JSON serializer
//! (TUI info lines, statistics collection, filter matching).

use packet_dissector_core::field::{Field, FormatContext};
use packet_dissector_core::packet::Layer;

/// Invoke a field's format function and return the unquoted result as a
/// [`String`].
///
/// Returns `None` if the field has no `format_fn`, if the function errors, or
/// if the output is not valid UTF-8.
///
/// The `format_fn` writes a JSON value (e.g. `"example.com"` with quotes), so
/// surrounding double-quotes are stripped from the result.
pub fn format_field_to_string(
    field: &Field<'_>,
    data: &[u8],
    layer: &Layer,
    scratch: &[u8],
) -> Option<String> {
    let format_fn = field.descriptor.format_fn?;
    let ctx = FormatContext {
        packet_data: data,
        scratch,
        layer_range: layer.range.start as u32..layer.range.end as u32,
        field_range: field.range.start as u32..field.range.end as u32,
    };
    let mut out = Vec::new();
    format_fn(&field.value, &ctx, &mut out).ok()?;
    let s = String::from_utf8(out).ok()?;
    // Strip surrounding JSON quotes produced by the format_fn.
    if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
        Some(s[1..s.len() - 1].to_string())
    } else {
        Some(s)
    }
}
