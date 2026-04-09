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

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::{
        FieldDescriptor, FieldType, FieldValue, FormatContext, FormatFn,
    };
    use packet_dissector_core::packet::{DissectBuffer, Packet};
    use packet_dissector_test_alloc::test_desc;

    /// Build a `&'static FieldDescriptor` whose `format_fn` is set to the
    /// given function pointer. `test_desc` cannot inject a `format_fn`, so
    /// tests that need one leak a descriptor built with the public builder.
    fn desc_with_format_fn(format_fn: FormatFn) -> &'static FieldDescriptor {
        Box::leak(Box::new(
            FieldDescriptor::new("f", "Field", FieldType::Bytes).with_format_fn(format_fn),
        ))
    }

    /// Build a single-field `DissectBuffer`, extract the sole layer and field,
    /// and invoke `format_field_to_string` against them.
    fn run(desc: &'static FieldDescriptor) -> Option<String> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Test", None, &[], 0..1);
        buf.push_field(desc, FieldValue::U8(0), 0..1);
        buf.end_layer();
        let packet = Packet::new(&buf, &[]);
        let layer = &packet.layers()[0];
        let field = &packet.layer_fields(layer)[0];
        format_field_to_string(field, &[], layer, &[])
    }

    fn fmt_quoted(
        _v: &FieldValue<'_>,
        _ctx: &FormatContext<'_>,
        w: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        w.write_all(b"\"example.com\"")
    }

    fn fmt_number(
        _v: &FieldValue<'_>,
        _ctx: &FormatContext<'_>,
        w: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        w.write_all(b"42")
    }

    fn fmt_err(
        _v: &FieldValue<'_>,
        _ctx: &FormatContext<'_>,
        _w: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        Err(std::io::Error::other("boom"))
    }

    fn fmt_non_utf8(
        _v: &FieldValue<'_>,
        _ctx: &FormatContext<'_>,
        w: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        w.write_all(&[0xFF, 0xFE, 0xFD])
    }

    #[test]
    fn returns_none_when_format_fn_missing() {
        // `test_desc` always sets `format_fn: None`.
        assert_eq!(run(test_desc("f", "Field")), None);
    }

    #[test]
    fn strips_surrounding_json_quotes() {
        assert_eq!(
            run(desc_with_format_fn(fmt_quoted)),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn keeps_bare_numeric_output() {
        assert_eq!(
            run(desc_with_format_fn(fmt_number)),
            Some("42".to_string())
        );
    }

    #[test]
    fn returns_none_when_format_fn_errors() {
        assert_eq!(run(desc_with_format_fn(fmt_err)), None);
    }

    #[test]
    fn returns_none_for_non_utf8_output() {
        assert_eq!(run(desc_with_format_fn(fmt_non_utf8)), None);
    }
}
