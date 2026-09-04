//! Iteration helper for walking only the top-level entries of a flat field
//! slice, skipping nested container children.
//!
//! [`packet_dissector_core::packet::DissectBuffer`] stores every field —
//! including the children of `Array`/`Object` containers — in one flat
//! buffer. A container's children sit contiguously right after the
//! container's own placeholder entry, and `DissectBuffer::layer_fields`
//! (and `DissectBuffer::nested_fields`) simply slice into that flat
//! buffer. That means a plain `for f in fields` over such a slice walks
//! parents *and* their nested children as if they were siblings.
//!
//! Any call site that wants only the direct children of a layer or
//! container — as opposed to every field nested arbitrarily deep inside it
//! — must skip past each container's own nested range. [`top_level_fields`]
//! does that in one place so the skip logic isn't duplicated (and doesn't
//! drift) across the serializer, the SQLite ingest pipeline, and the filter
//! engine.

use packet_dissector_core::field::{Field, FieldValue};

/// Iterate only the top-level entries of `fields`, skipping the nested
/// children of any `Array`/`Object` sub-field.
///
/// `fields` is a flat slice as returned by `DissectBuffer::layer_fields` or
/// `DissectBuffer::nested_fields` — `fields[0]` corresponds to absolute
/// buffer index `base`. `base` is needed because `FieldValue::Array` and
/// `FieldValue::Object` carry *absolute* indices into the whole
/// `DissectBuffer`, not indices relative to `fields`. Pass
/// `layer.field_range.start` for a layer's fields, or an `Array`/`Object`
/// field's own range `.start` for a container's children.
///
/// This is allocation-free: it walks `fields` by index rather than
/// collecting into a `Vec`, so it's safe to use on the serializer's hot
/// path.
pub fn top_level_fields<'a, 'pkt>(
    fields: &'a [Field<'pkt>],
    base: u32,
) -> TopLevelFields<'a, 'pkt> {
    TopLevelFields {
        fields,
        base,
        idx: 0,
    }
}

/// Iterator returned by [`top_level_fields`].
#[derive(Clone)]
pub struct TopLevelFields<'a, 'pkt> {
    fields: &'a [Field<'pkt>],
    base: u32,
    idx: usize,
}

impl<'a, 'pkt> Iterator for TopLevelFields<'a, 'pkt> {
    type Item = &'a Field<'pkt>;

    fn next(&mut self) -> Option<Self::Item> {
        let f = self.fields.get(self.idx)?;
        self.idx = match &f.value {
            FieldValue::Array(range) | FieldValue::Object(range) => {
                // Container children are stored right after the container
                // itself; `range.end` is the absolute index one past the
                // last nested child, so subtracting `base` gives the index
                // into `fields` to resume at.
                (range.end - self.base) as usize
            }
            _ => self.idx + 1,
        };
        Some(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_test_alloc::test_desc;

    /// Build a flat field slice mimicking a layer with a scalar field, an
    /// Object container with two nested children, and a trailing scalar
    /// field — the shape that exposed the top-level/nested confusion.
    fn sample_fields() -> Vec<Field<'static>> {
        vec![
            Field {
                descriptor: test_desc("a", "A"),
                value: FieldValue::U8(1),
                range: 0..1,
            },
            Field {
                descriptor: test_desc("container", "Container"),
                value: FieldValue::Object(2..4),
                range: 1..3,
            },
            Field {
                descriptor: test_desc("child1", "Child 1"),
                value: FieldValue::U8(2),
                range: 1..2,
            },
            Field {
                descriptor: test_desc("child2", "Child 2"),
                value: FieldValue::U8(3),
                range: 2..3,
            },
            Field {
                descriptor: test_desc("b", "B"),
                value: FieldValue::U8(4),
                range: 3..4,
            },
        ]
    }

    #[test]
    fn skips_nested_container_children() {
        let fields = sample_fields();
        let names: Vec<&str> = top_level_fields(&fields, 0).map(|f| f.name()).collect();
        assert_eq!(names, vec!["a", "container", "b"]);
    }

    #[test]
    fn handles_nonzero_base() {
        // Same shape, but as if this slice started at absolute buffer
        // index 10 (e.g. a layer that isn't the first in the buffer).
        let mut fields = sample_fields();
        if let FieldValue::Object(ref mut r) = fields[1].value {
            *r = 12..14;
        }
        let names: Vec<&str> = top_level_fields(&fields, 10).map(|f| f.name()).collect();
        assert_eq!(names, vec!["a", "container", "b"]);
    }

    #[test]
    fn empty_slice_yields_nothing() {
        let fields: Vec<Field<'static>> = Vec::new();
        assert_eq!(top_level_fields(&fields, 0).count(), 0);
    }

    #[test]
    fn no_containers_yields_all_fields() {
        let fields = vec![
            Field {
                descriptor: test_desc("a", "A"),
                value: FieldValue::U8(1),
                range: 0..1,
            },
            Field {
                descriptor: test_desc("b", "B"),
                value: FieldValue::U8(2),
                range: 1..2,
            },
        ];
        let names: Vec<&str> = top_level_fields(&fields, 0).map(|f| f.name()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }
}
