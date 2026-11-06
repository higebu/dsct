//! Compact binary encoding of a dissected packet.
//!
//! The in-order dissection pass ([`super::ordered_pass`]) keeps the results
//! of packets whose dissection used state kept across packets.  It stores
//! them in this encoding, which holds everything an [`OwnedPacket`] holds
//! except the packet bytes themselves (those stay in the capture file).
//!
//! The `&'static` parts of a result (layer names and field descriptors)
//! cannot be written out, so the writer interns them ([`Interner`]) and
//! writes their index; the reader resolves the index through the matching
//! [`Tables`].  Integers are LEB128 varints.
//!
//! [`decode`] validates every index and range, so a damaged record yields
//! `None` instead of a panic.

use std::collections::HashMap;
use std::ops::Range;

use packet_dissector_core::field::{FieldDescriptor, MacAddr};
use packet_dissector_core::packet::{DissectBuffer, Layer};

use super::owned_packet::{BytesSource, OwnedField, OwnedFieldValue, OwnedPacket, owned_value};

/// The `&'static` parts of a [`Layer`].
#[derive(Clone, Copy)]
pub(super) struct LayerMeta {
    name: &'static str,
    display_name: Option<&'static str>,
    field_descriptors: &'static [FieldDescriptor],
}

/// Identity of a [`LayerMeta`]: the addresses and lengths of its parts.
type LayerKey = (usize, usize, Option<(usize, usize)>, usize, usize);

impl LayerMeta {
    fn of(layer: &Layer) -> Self {
        Self {
            name: layer.name,
            display_name: layer.display_name,
            field_descriptors: layer.field_descriptors,
        }
    }

    fn key(&self) -> LayerKey {
        (
            self.name.as_ptr() as usize,
            self.name.len(),
            self.display_name.map(|d| (d.as_ptr() as usize, d.len())),
            self.field_descriptors.as_ptr() as usize,
            self.field_descriptors.len(),
        )
    }
}

/// Interned `&'static` values, indexed by the ids [`Interner`] assigns.
#[derive(Default)]
pub(super) struct Tables {
    descriptors: Vec<&'static FieldDescriptor>,
    layers: Vec<LayerMeta>,
}

impl Tables {
    /// Append the entries an [`Interner`] added since the last call.
    pub(super) fn extend(&mut self, new: Tables) {
        self.descriptors.extend(new.descriptors);
        self.layers.extend(new.layers);
    }
}

/// Writer-side interning of the `&'static` parts of dissection results.
#[derive(Default)]
pub(super) struct Interner {
    descriptor_ids: HashMap<usize, u32>,
    layer_ids: HashMap<LayerKey, u32>,
    /// Entries added since the last [`take_new`](Self::take_new).
    new: Tables,
}

impl Interner {
    fn descriptor(&mut self, d: &'static FieldDescriptor) -> u32 {
        let next = self.descriptor_ids.len() as u32;
        *self
            .descriptor_ids
            .entry(d as *const FieldDescriptor as usize)
            .or_insert_with(|| {
                self.new.descriptors.push(d);
                next
            })
    }

    fn layer(&mut self, meta: LayerMeta) -> u32 {
        let next = self.layer_ids.len() as u32;
        *self.layer_ids.entry(meta.key()).or_insert_with(|| {
            self.new.layers.push(meta);
            next
        })
    }

    /// Take the entries added since the last call, in id order, so that the
    /// reader's [`Tables`] can be extended with them.
    pub(super) fn take_new(&mut self) -> Tables {
        std::mem::take(&mut self.new)
    }
}

// Value tags.
const TAG_U8: u8 = 0;
const TAG_U16: u8 = 1;
const TAG_U32: u8 = 2;
const TAG_U64: u8 = 3;
const TAG_I32: u8 = 4;
const TAG_BYTES: u8 = 5;
const TAG_STR: u8 = 6;
const TAG_IPV4: u8 = 7;
const TAG_IPV6: u8 = 8;
const TAG_MAC: u8 = 9;
const TAG_ARRAY: u8 = 10;
const TAG_OBJECT: u8 = 11;
const TAG_SCRATCH: u8 = 12;

// Byte source tags.
const SRC_DATA: u8 = 0;
const SRC_AUX: u8 = 1;

fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn put_range(out: &mut Vec<u8>, r: &Range<usize>) {
    put_varint(out, r.start as u64);
    put_varint(out, r.end as u64);
}

fn put_range32(out: &mut Vec<u8>, r: &Range<u32>) {
    put_varint(out, u64::from(r.start));
    put_varint(out, u64::from(r.end));
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    put_varint(out, b.len() as u64);
    out.extend_from_slice(b);
}

fn put_source(out: &mut Vec<u8>, src: &BytesSource) {
    let (tag, r) = match src {
        BytesSource::Data(r) => (SRC_DATA, r),
        BytesSource::AuxData(r) => (SRC_AUX, r),
    };
    out.push(tag);
    put_range(out, r);
}

/// Append the encoding of the result in `buf` for the packet `data` to
/// `out`. `ok` records whether the dissection returned `Ok`.
pub(super) fn encode(
    buf: &DissectBuffer<'_>,
    data: &[u8],
    ok: bool,
    interner: &mut Interner,
    out: &mut Vec<u8>,
) {
    // Converting the values may append to the auxiliary data, so do it
    // before writing that.
    let mut aux = buf.aux_data();
    let values: Vec<OwnedFieldValue> = buf
        .fields()
        .iter()
        .map(|f| owned_value(&f.value, data, buf, &mut aux))
        .collect();

    out.push(u8::from(ok));
    put_bytes(out, &aux);
    put_bytes(out, buf.scratch());

    put_varint(out, buf.layers().len() as u64);
    for layer in buf.layers() {
        put_varint(out, u64::from(interner.layer(LayerMeta::of(layer))));
        put_range(out, &layer.range);
        put_range32(out, &layer.field_range);
    }

    put_varint(out, buf.fields().len() as u64);
    for (field, value) in buf.fields().iter().zip(values) {
        put_varint(out, u64::from(interner.descriptor(field.descriptor)));
        put_range(out, &field.range);
        match value {
            OwnedFieldValue::U8(v) => {
                out.push(TAG_U8);
                put_varint(out, u64::from(v));
            }
            OwnedFieldValue::U16(v) => {
                out.push(TAG_U16);
                put_varint(out, u64::from(v));
            }
            OwnedFieldValue::U32(v) => {
                out.push(TAG_U32);
                put_varint(out, u64::from(v));
            }
            OwnedFieldValue::U64(v) => {
                out.push(TAG_U64);
                put_varint(out, v);
            }
            OwnedFieldValue::I32(v) => {
                out.push(TAG_I32);
                out.extend_from_slice(&v.to_le_bytes());
            }
            OwnedFieldValue::Bytes(src) => {
                out.push(TAG_BYTES);
                put_source(out, &src);
            }
            OwnedFieldValue::Str(src) => {
                out.push(TAG_STR);
                put_source(out, &src);
            }
            OwnedFieldValue::Ipv4Addr(a) => {
                out.push(TAG_IPV4);
                out.extend_from_slice(&a);
            }
            OwnedFieldValue::Ipv6Addr(a) => {
                out.push(TAG_IPV6);
                out.extend_from_slice(&a);
            }
            OwnedFieldValue::MacAddr(m) => {
                out.push(TAG_MAC);
                out.extend_from_slice(&m.0);
            }
            OwnedFieldValue::Array(r) => {
                out.push(TAG_ARRAY);
                put_range32(out, &r);
            }
            OwnedFieldValue::Object(r) => {
                out.push(TAG_OBJECT);
                put_range32(out, &r);
            }
            OwnedFieldValue::Scratch(r) => {
                out.push(TAG_SCRATCH);
                put_range32(out, &r);
            }
        }
    }
}

/// A decoded result: the packet and whether its dissection returned `Ok`.
pub(super) struct StoredPacket {
    /// Whether the dissection returned `Ok` (layers may be partial if not).
    pub ok: bool,
    /// The dissected packet.
    pub packet: OwnedPacket,
}

/// Cursor over an encoded record.
struct Reader<'a> {
    bytes: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Option<u8> {
        let (&b, rest) = self.bytes.split_first()?;
        self.bytes = rest;
        Some(b)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.bytes.len() {
            return None;
        }
        let (head, rest) = self.bytes.split_at(n);
        self.bytes = rest;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }

    fn varint(&mut self) -> Option<u64> {
        let mut v = 0u64;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            v |= u64::from(b & 0x7f).checked_shl(shift)?;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        None
    }

    fn usize(&mut self) -> Option<usize> {
        usize::try_from(self.varint()?).ok()
    }

    fn u32(&mut self) -> Option<u32> {
        u32::try_from(self.varint()?).ok()
    }

    fn range(&mut self) -> Option<Range<usize>> {
        let start = self.usize()?;
        let end = self.usize()?;
        Some(start..end)
    }

    /// A range that must lie within `0..len`.
    fn range32_within(&mut self, len: usize) -> Option<Range<u32>> {
        let start = self.u32()?;
        let end = self.u32()?;
        (start <= end && end as usize <= len).then_some(start..end)
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.usize()?;
        self.take(n)
    }

    fn source(&mut self, data_len: usize, aux_len: usize) -> Option<BytesSource> {
        let tag = self.u8()?;
        let r = self.range()?;
        let limit = match tag {
            SRC_DATA => data_len,
            SRC_AUX => aux_len,
            _ => return None,
        };
        if r.start > r.end || r.end > limit {
            return None;
        }
        Some(if tag == SRC_DATA {
            BytesSource::Data(r)
        } else {
            BytesSource::AuxData(r)
        })
    }
}

/// Decode a record written by [`encode`] for the packet `data`.
///
/// Returns `None` if the record is damaged or refers to an id missing from
/// `tables`.
pub(super) fn decode(bytes: &[u8], data: &[u8], tables: &Tables) -> Option<StoredPacket> {
    let mut r = Reader { bytes };
    let ok = match r.u8()? {
        0 => false,
        1 => true,
        _ => return None,
    };
    let aux_data = r.bytes()?.to_vec();
    let scratch = r.bytes()?.to_vec();

    let layer_count = r.usize()?;
    let mut layers = Vec::with_capacity(layer_count.min(r.bytes.len()));
    let mut layer_field_ranges = Vec::with_capacity(layers.capacity());
    for _ in 0..layer_count {
        let meta = *tables.layers.get(r.usize()?)?;
        let range = r.range()?;
        let field_start = r.u32()?;
        let field_end = r.u32()?;
        layer_field_ranges.push((field_start, field_end));
        layers.push(Layer {
            name: meta.name,
            display_name: meta.display_name,
            field_descriptors: meta.field_descriptors,
            range,
            field_range: field_start..field_end,
        });
    }

    let field_count = r.usize()?;
    let mut fields = Vec::with_capacity(field_count.min(r.bytes.len()));
    for _ in 0..field_count {
        let descriptor = *tables.descriptors.get(r.usize()?)?;
        let range = r.range()?;
        let value = match r.u8()? {
            TAG_U8 => OwnedFieldValue::U8(u8::try_from(r.varint()?).ok()?),
            TAG_U16 => OwnedFieldValue::U16(u16::try_from(r.varint()?).ok()?),
            TAG_U32 => OwnedFieldValue::U32(r.u32()?),
            TAG_U64 => OwnedFieldValue::U64(r.varint()?),
            TAG_I32 => OwnedFieldValue::I32(i32::from_le_bytes(r.array()?)),
            TAG_BYTES => OwnedFieldValue::Bytes(r.source(data.len(), aux_data.len())?),
            TAG_STR => {
                let src = r.source(data.len(), aux_data.len())?;
                let s = match &src {
                    BytesSource::Data(range) => &data[range.clone()],
                    BytesSource::AuxData(range) => &aux_data[range.clone()],
                };
                std::str::from_utf8(s).ok()?;
                OwnedFieldValue::Str(src)
            }
            TAG_IPV4 => OwnedFieldValue::Ipv4Addr(r.array()?),
            TAG_IPV6 => OwnedFieldValue::Ipv6Addr(r.array()?),
            TAG_MAC => OwnedFieldValue::MacAddr(MacAddr(r.array()?)),
            TAG_ARRAY => OwnedFieldValue::Array(r.range32_within(field_count)?),
            TAG_OBJECT => OwnedFieldValue::Object(r.range32_within(field_count)?),
            TAG_SCRATCH => OwnedFieldValue::Scratch(r.range32_within(scratch.len())?),
            _ => return None,
        };
        fields.push(OwnedField {
            descriptor,
            value,
            range,
        });
    }

    if !r.bytes.is_empty()
        || layer_field_ranges
            .iter()
            .any(|&(start, end)| start > end || end as usize > fields.len())
    {
        return None;
    }

    Some(StoredPacket {
        ok,
        packet: OwnedPacket {
            data: data.to_vec(),
            aux_data,
            layers,
            fields,
            scratch,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::{FieldType, FieldValue};

    static U8_DESC: FieldDescriptor = FieldDescriptor::new("u8", "U8", FieldType::U8);
    static U16_DESC: FieldDescriptor = FieldDescriptor::new("u16", "U16", FieldType::U16);
    static U32_DESC: FieldDescriptor = FieldDescriptor::new("u32", "U32", FieldType::U32);
    static U64_DESC: FieldDescriptor = FieldDescriptor::new("u64", "U64", FieldType::U64);
    static I32_DESC: FieldDescriptor = FieldDescriptor::new("i32", "I32", FieldType::I32);
    static BYTES_DESC: FieldDescriptor = FieldDescriptor::new("bytes", "Bytes", FieldType::Bytes);
    static STR_DESC: FieldDescriptor = FieldDescriptor::new("str", "Str", FieldType::Str);
    static V4_DESC: FieldDescriptor = FieldDescriptor::new("v4", "V4", FieldType::Ipv4Addr);
    static V6_DESC: FieldDescriptor = FieldDescriptor::new("v6", "V6", FieldType::Ipv6Addr);
    static MAC_DESC: FieldDescriptor = FieldDescriptor::new("mac", "Mac", FieldType::MacAddr);
    static ARR_DESC: FieldDescriptor = FieldDescriptor::new("arr", "Arr", FieldType::Array);
    static OBJ_DESC: FieldDescriptor = FieldDescriptor::new("obj", "Obj", FieldType::Object);
    static SCR_DESC: FieldDescriptor = FieldDescriptor::new("scr", "Scr", FieldType::Bytes);
    static LAYER_DESCS: [FieldDescriptor; 1] = [FieldDescriptor::new("u8", "U8", FieldType::U8)];

    // A `static`, so every use refers to the same bytes.
    static DATA: &[u8] = b"\x01\x02hello world\x03\x04";

    /// A buffer with every value kind, nested containers, scratch and
    /// auxiliary data, and two layers.
    fn sample(buf: &mut DissectBuffer<'static>) {
        buf.begin_layer("First", Some("First v1"), &LAYER_DESCS, 0..4);
        buf.push_field(&U8_DESC, FieldValue::U8(7), 0..1);
        buf.push_field(&U16_DESC, FieldValue::U16(0xbeef), 0..2);
        buf.push_field(&U32_DESC, FieldValue::U32(u32::MAX), 0..4);
        buf.push_field(&U64_DESC, FieldValue::U64(u64::MAX), 0..4);
        buf.push_field(&I32_DESC, FieldValue::I32(-5), 0..4);
        buf.push_field(&BYTES_DESC, FieldValue::Bytes(&DATA[0..2]), 0..2);
        buf.end_layer();
        buf.begin_layer("Second", None, &[], 2..DATA.len());
        let hello = std::str::from_utf8(&DATA[2..7]).unwrap();
        buf.push_field(&STR_DESC, FieldValue::Str(hello), 2..7);
        // A string that is not in the packet (e.g. an HPACK static name).
        buf.push_field(&STR_DESC, FieldValue::Str(":path"), 2..7);
        buf.push_field(&V4_DESC, FieldValue::Ipv4Addr([10, 0, 0, 1]), 2..6);
        buf.push_field(&V6_DESC, FieldValue::Ipv6Addr([0xfe; 16]), 2..6);
        buf.push_field(
            &MAC_DESC,
            FieldValue::MacAddr(MacAddr([2, 0, 0, 0, 0, 1])),
            2..8,
        );
        let arr = buf.begin_container(&ARR_DESC, FieldValue::Array(0..0), 2..7);
        let obj = buf.begin_container(&OBJ_DESC, FieldValue::Object(0..0), 2..7);
        buf.push_field(&U8_DESC, FieldValue::U8(1), 2..3);
        buf.end_container(obj);
        buf.end_container(arr);
        let scratch = buf.push_scratch(&[9, 8, 7]);
        buf.push_field(&SCR_DESC, FieldValue::Scratch(scratch), 2..3);
        // Fields refer to auxiliary data only through dissector internals;
        // the bytes themselves must still round-trip.
        buf.push_aux_data(b"reassembled");
        buf.end_layer();
    }

    fn roundtrip(buf: &DissectBuffer<'_>, data: &[u8], ok: bool) -> StoredPacket {
        let mut interner = Interner::default();
        let mut out = Vec::new();
        encode(buf, data, ok, &mut interner, &mut out);
        let mut tables = Tables::default();
        tables.extend(interner.take_new());
        decode(&out, data, &tables).expect("decodes")
    }

    #[test]
    fn roundtrip_matches_owned_packet() {
        let mut buf = DissectBuffer::new();
        sample(&mut buf);
        let expected = OwnedPacket::from_dissect_buf(&buf, DATA);
        let got = roundtrip(&buf, DATA, true);
        assert!(got.ok);
        assert_eq!(got.packet.data, expected.data);
        assert_eq!(got.packet.aux_data, expected.aux_data);
        assert_eq!(got.packet.scratch, expected.scratch);
        assert_eq!(got.packet.layers, expected.layers);
        assert_eq!(got.packet.fields.len(), expected.fields.len());
        for (g, e) in got.packet.fields.iter().zip(&expected.fields) {
            assert!(std::ptr::eq(g.descriptor, e.descriptor));
            assert_eq!(g.range, e.range);
            assert_eq!(
                g.value.to_field_value(&got.packet),
                e.value.to_field_value(&expected)
            );
        }
    }

    #[test]
    fn roundtrip_keeps_values_outside_the_packet() {
        let mut buf = DissectBuffer::new();
        sample(&mut buf);
        let got = roundtrip(&buf, DATA, true);
        let values: Vec<_> = got
            .packet
            .fields
            .iter()
            .map(|f| f.value.to_field_value(&got.packet))
            .collect();
        assert!(values.contains(&FieldValue::Str(":path")), "{values:?}");
    }

    #[test]
    fn roundtrip_keeps_error_flag() {
        let mut buf = DissectBuffer::new();
        sample(&mut buf);
        assert!(!roundtrip(&buf, DATA, false).ok);
    }

    #[test]
    fn interner_assigns_ids_once_across_records() {
        let mut buf = DissectBuffer::new();
        sample(&mut buf);
        let mut interner = Interner::default();
        let mut first = Vec::new();
        encode(&buf, DATA, true, &mut interner, &mut first);
        let mut tables = Tables::default();
        tables.extend(interner.take_new());
        let descriptors = tables.descriptors.len();

        let mut second = Vec::new();
        encode(&buf, DATA, true, &mut interner, &mut second);
        let new = interner.take_new();
        assert!(new.descriptors.is_empty() && new.layers.is_empty());
        assert_eq!(first, second);
        assert_eq!(descriptors, 13);
        assert_eq!(tables.layers.len(), 2);
    }

    #[test]
    fn damaged_records_are_rejected() {
        let mut buf = DissectBuffer::new();
        sample(&mut buf);
        let mut interner = Interner::default();
        let mut out = Vec::new();
        encode(&buf, DATA, true, &mut interner, &mut out);
        let mut tables = Tables::default();
        tables.extend(interner.take_new());

        // Every truncation fails cleanly.
        for len in 0..out.len() {
            assert!(decode(&out[..len], DATA, &tables).is_none(), "len {len}");
        }
        // Trailing bytes.
        let mut long = out.clone();
        long.push(0);
        assert!(decode(&long, DATA, &tables).is_none());
        // Missing interned entries.
        assert!(decode(&out, DATA, &Tables::default()).is_none());
        // A shorter packet than the byte ranges refer to.
        assert!(decode(&out, &DATA[..4], &tables).is_none());
        // Arbitrary single-byte damage never panics.
        for i in 0..out.len() {
            let mut bad = out.clone();
            bad[i] ^= 0xff;
            let _ = decode(&bad, DATA, &tables);
        }
    }
}
