//! Conversion of dissected field values into SQLite values.
//!
//! Scalar fields map directly onto SQLite storage classes.  Fields with a
//! `format_fn` (e.g. DNS names stored as raw bytes) are rendered through the
//! same JSON writer as `dsct read` and the resulting token is decoded, so the
//! database always contains the value a `dsct read -v` user would see.
//! Container fields (`Array` / `Object`) are stored as JSON text so they can
//! be queried with SQLite's `json_extract` / `json_each`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Range;

use packet_dissector_core::field::{Field, FieldValue};
use packet_dissector_core::packet::DissectBuffer;
use rusqlite::ToSql;
use rusqlite::types::{ToSqlOutput, Value, ValueRef};

use crate::error::Result;
use crate::serialize::{write_field_json, write_field_value_json};

/// A SQLite storage-class value, independent of the database driver.
#[derive(Debug, Clone, PartialEq)]
pub enum SqlValue {
    /// SQL `NULL`.
    Null,
    /// 64-bit signed integer.
    Integer(i64),
    /// 64-bit float.
    Real(f64),
    /// UTF-8 text.
    Text(String),
    /// Raw bytes.
    Blob(Vec<u8>),
}

impl ToSql for SqlValue {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(match self {
            SqlValue::Null => ToSqlOutput::Owned(Value::Null),
            SqlValue::Integer(v) => ToSqlOutput::Owned(Value::Integer(*v)),
            SqlValue::Real(v) => ToSqlOutput::Owned(Value::Real(*v)),
            SqlValue::Text(s) => ToSqlOutput::Borrowed(ValueRef::Text(s.as_bytes())),
            SqlValue::Blob(b) => ToSqlOutput::Borrowed(ValueRef::Blob(b)),
        })
    }
}

impl From<u64> for SqlValue {
    fn from(v: u64) -> Self {
        i64::try_from(v).map_or_else(|_| SqlValue::Text(v.to_string()), SqlValue::Integer)
    }
}

impl From<u32> for SqlValue {
    fn from(v: u32) -> Self {
        SqlValue::Integer(i64::from(v))
    }
}

impl From<i64> for SqlValue {
    fn from(v: i64) -> Self {
        SqlValue::Integer(v)
    }
}

impl From<&str> for SqlValue {
    fn from(v: &str) -> Self {
        SqlValue::Text(v.to_owned())
    }
}

impl From<String> for SqlValue {
    fn from(v: String) -> Self {
        SqlValue::Text(v)
    }
}

impl<T: Into<SqlValue>> From<Option<T>> for SqlValue {
    fn from(v: Option<T>) -> Self {
        v.map_or(SqlValue::Null, Into::into)
    }
}

/// Decode a single JSON token produced by the packet serializer.
///
/// - a quoted string becomes [`SqlValue::Text`] (JSON escapes resolved)
/// - an integer literal becomes [`SqlValue::Integer`]
/// - any other number becomes [`SqlValue::Real`]
/// - `null` becomes [`SqlValue::Null`]
/// - anything else is stored verbatim as text
pub fn decode_json_token(token: &[u8]) -> SqlValue {
    if token.first() == Some(&b'"') {
        return match serde_json::from_slice::<String>(token) {
            Ok(s) => SqlValue::Text(s),
            Err(_) => SqlValue::Text(String::from_utf8_lossy(token).into_owned()),
        };
    }
    let text = String::from_utf8_lossy(token);
    let trimmed = text.trim();
    if trimmed == "null" {
        return SqlValue::Null;
    }
    if let Ok(i) = trimmed.parse::<i64>() {
        return SqlValue::Integer(i);
    }
    if let Ok(f) = trimmed.parse::<f64>()
        && f.is_finite()
    {
        return SqlValue::Real(f);
    }
    SqlValue::Text(trimmed.to_owned())
}

/// Convert a scalar (non-container) field into a [`SqlValue`].
///
/// `scratch` is a reusable buffer for rendering `format_fn` output.
pub fn scalar_value(
    field: &Field<'_>,
    buf: &DissectBuffer<'_>,
    data: &[u8],
    layer_range: &Range<usize>,
    scratch: &mut Vec<u8>,
) -> Result<SqlValue> {
    if field.descriptor.format_fn.is_some() {
        scratch.clear();
        write_field_value_json(scratch, field, buf, data, layer_range)?;
        return Ok(decode_json_token(scratch));
    }
    Ok(match &field.value {
        FieldValue::U8(v) => SqlValue::Integer(i64::from(*v)),
        FieldValue::U16(v) => SqlValue::Integer(i64::from(*v)),
        FieldValue::U32(v) => SqlValue::Integer(i64::from(*v)),
        FieldValue::U64(v) => SqlValue::from(*v),
        FieldValue::I32(v) => SqlValue::Integer(i64::from(*v)),
        FieldValue::Str(s) => SqlValue::Text((*s).to_owned()),
        FieldValue::Ipv4Addr(a) => SqlValue::Text(Ipv4Addr::from(*a).to_string()),
        FieldValue::Ipv6Addr(a) => SqlValue::Text(Ipv6Addr::from(*a).to_string()),
        FieldValue::MacAddr(m) => SqlValue::Text(m.to_string()),
        FieldValue::Bytes(b) => SqlValue::Blob(b.to_vec()),
        FieldValue::Scratch(range) => {
            SqlValue::Blob(buf.scratch()[range.start as usize..range.end as usize].to_vec())
        }
        FieldValue::Array(_) | FieldValue::Object(_) => SqlValue::Null,
    })
}

/// Render a container field (`Array` / `Object`) as JSON text.
///
/// Uses the same writer as `dsct read -v`, so nested structures look exactly
/// like the JSONL output.
pub fn container_json(
    protocol: &str,
    field: &Field<'_>,
    buf: &DissectBuffer<'_>,
    data: &[u8],
    layer_range: &Range<usize>,
    scratch: &mut Vec<u8>,
) -> Result<SqlValue> {
    scratch.clear();
    write_field_json(
        scratch,
        protocol,
        field.name(),
        field,
        buf,
        data,
        layer_range,
        None,
    )?;
    Ok(SqlValue::Text(
        String::from_utf8_lossy(scratch).into_owned(),
    ))
}

/// Convert any field (scalar or container) into a [`SqlValue`].
pub fn field_value(
    protocol: &str,
    field: &Field<'_>,
    buf: &DissectBuffer<'_>,
    data: &[u8],
    layer_range: &Range<usize>,
    scratch: &mut Vec<u8>,
) -> Result<SqlValue> {
    match field.value {
        FieldValue::Array(_) | FieldValue::Object(_) => {
            container_json(protocol, field, buf, data, layer_range, scratch)
        }
        _ => scalar_value(field, buf, data, layer_range, scratch),
    }
}

/// Resolve the `display_fn` companion value (`<name>_name`) of a field.
pub fn display_value(field: &Field<'_>, siblings: &[Field<'_>]) -> SqlValue {
    field
        .descriptor
        .display_fn
        .and_then(|f| f(&field.value, siblings))
        .map_or(SqlValue::Null, |s| SqlValue::Text(s.to_owned()))
}

/// Lowercase hex encoding of a byte slice.
pub fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::{FieldDescriptor, FieldType, FormatContext, MacAddr};
    use packet_dissector_test_alloc::test_desc;

    fn single_field_buf(
        desc: &'static FieldDescriptor,
        value: FieldValue<'static>,
    ) -> DissectBuffer<'static> {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Test", None, &[], 0..4);
        buf.push_field(desc, value, 0..4);
        buf.end_layer();
        buf
    }

    fn first_scalar(buf: &DissectBuffer<'_>) -> Result<SqlValue> {
        let layer = &buf.layers()[0];
        let field = &buf.layer_fields(layer)[0];
        let mut scratch = Vec::new();
        scalar_value(field, buf, &[0u8; 4], &layer.range, &mut scratch)
    }

    #[test]
    fn integers_and_addresses() {
        let buf = single_field_buf(test_desc("a", "A"), FieldValue::U16(8080));
        assert_eq!(first_scalar(&buf).unwrap(), SqlValue::Integer(8080));

        let buf = single_field_buf(test_desc("a", "A"), FieldValue::I32(-5));
        assert_eq!(first_scalar(&buf).unwrap(), SqlValue::Integer(-5));

        let buf = single_field_buf(test_desc("a", "A"), FieldValue::U64(u64::MAX));
        assert_eq!(
            first_scalar(&buf).unwrap(),
            SqlValue::Text(u64::MAX.to_string())
        );

        let buf = single_field_buf(test_desc("a", "A"), FieldValue::Ipv4Addr([10, 0, 0, 1]));
        assert_eq!(
            first_scalar(&buf).unwrap(),
            SqlValue::Text("10.0.0.1".into())
        );

        let mut v6 = [0u8; 16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        v6[15] = 1;
        let buf = single_field_buf(test_desc("a", "A"), FieldValue::Ipv6Addr(v6));
        assert_eq!(
            first_scalar(&buf).unwrap(),
            SqlValue::Text("2001::1".into())
        );

        let buf = single_field_buf(
            test_desc("a", "A"),
            FieldValue::MacAddr(MacAddr([0, 0x11, 0x22, 0x33, 0x44, 0x55])),
        );
        assert_eq!(
            first_scalar(&buf).unwrap(),
            SqlValue::Text("00:11:22:33:44:55".into())
        );
    }

    #[test]
    fn bytes_and_scratch_are_blobs() {
        let buf = single_field_buf(test_desc("a", "A"), FieldValue::Bytes(&[1, 2, 3]));
        assert_eq!(first_scalar(&buf).unwrap(), SqlValue::Blob(vec![1, 2, 3]));

        let mut buf = DissectBuffer::new();
        let range = buf.push_scratch(&[0xAA, 0xBB]);
        buf.begin_layer("Test", None, &[], 0..0);
        buf.push_field(test_desc("s", "S"), FieldValue::Scratch(range), 0..0);
        buf.end_layer();
        assert_eq!(
            first_scalar(&buf).unwrap(),
            SqlValue::Blob(vec![0xAA, 0xBB])
        );
    }

    fn fmt_quoted(
        _v: &FieldValue<'_>,
        _ctx: &FormatContext<'_>,
        w: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        w.write_all(b"\"exa\\\"mple.com\"")
    }

    fn fmt_number(
        _v: &FieldValue<'_>,
        _ctx: &FormatContext<'_>,
        w: &mut dyn std::io::Write,
    ) -> std::io::Result<()> {
        w.write_all(b"42")
    }

    #[test]
    fn format_fn_output_is_decoded() {
        let desc: &'static FieldDescriptor = Box::leak(Box::new(
            FieldDescriptor::new("f", "F", FieldType::Bytes).with_format_fn(fmt_quoted),
        ));
        let buf = single_field_buf(desc, FieldValue::Bytes(&[0]));
        assert_eq!(
            first_scalar(&buf).unwrap(),
            SqlValue::Text("exa\"mple.com".into())
        );

        let desc: &'static FieldDescriptor = Box::leak(Box::new(
            FieldDescriptor::new("f", "F", FieldType::Bytes).with_format_fn(fmt_number),
        ));
        let buf = single_field_buf(desc, FieldValue::Bytes(&[0]));
        assert_eq!(first_scalar(&buf).unwrap(), SqlValue::Integer(42));
    }

    #[test]
    fn decode_json_token_variants() {
        assert_eq!(decode_json_token(b"null"), SqlValue::Null);
        assert_eq!(decode_json_token(b"-7"), SqlValue::Integer(-7));
        assert_eq!(decode_json_token(b"1.5"), SqlValue::Real(1.5));
        assert_eq!(
            decode_json_token(b"\"a\\nb\""),
            SqlValue::Text("a\nb".into())
        );
        assert_eq!(decode_json_token(b"true"), SqlValue::Text("true".into()));
    }

    #[test]
    fn container_renders_json() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..10);
        let arr = buf.begin_container(test_desc("questions", "Q"), FieldValue::Array(0..0), 0..10);
        let obj = buf.begin_container(test_desc("q", "Q"), FieldValue::Object(0..0), 0..10);
        buf.push_field(
            test_desc("name", "Name"),
            FieldValue::Str("example.com"),
            0..5,
        );
        buf.push_field(test_desc("type", "Type"), FieldValue::U16(1), 5..7);
        buf.end_container(obj);
        buf.end_container(arr);
        buf.end_layer();

        let layer = &buf.layers()[0];
        let field = &buf.layer_fields(layer)[0];
        let mut scratch = Vec::new();
        let v = field_value("DNS", field, &buf, &[0u8; 10], &layer.range, &mut scratch).unwrap();
        assert_eq!(
            v,
            SqlValue::Text(r#"[{"name":"example.com","type":1}]"#.into())
        );
    }

    #[test]
    fn display_value_uses_display_fn() {
        fn flags_display(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
            match v {
                FieldValue::U8(2) => Some("SYN"),
                _ => None,
            }
        }
        let desc: &'static FieldDescriptor = Box::leak(Box::new(FieldDescriptor {
            name: "flags",
            display_name: "Flags",
            field_type: FieldType::U8,
            optional: false,
            children: None,
            display_fn: Some(flags_display),
            format_fn: None,
        }));
        let buf = single_field_buf(desc, FieldValue::U8(2));
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        assert_eq!(
            display_value(&fields[0], fields),
            SqlValue::Text("SYN".into())
        );

        let buf = single_field_buf(desc, FieldValue::U8(0));
        let layer = &buf.layers()[0];
        let fields = buf.layer_fields(layer);
        assert_eq!(display_value(&fields[0], fields), SqlValue::Null);
    }

    #[test]
    fn hex_string_lowercase() {
        assert_eq!(hex_string(&[0xde, 0xad, 0x01]), "dead01");
        assert_eq!(hex_string(&[]), "");
    }

    #[test]
    fn option_conversion() {
        assert_eq!(SqlValue::from(None::<u32>), SqlValue::Null);
        assert_eq!(SqlValue::from(Some(3u32)), SqlValue::Integer(3));
    }
}
