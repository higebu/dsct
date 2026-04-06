//! Owned packet representation for long-term storage (TUI selected packet).
//!
//! [`OwnedPacket`] stores a fully owned copy of a dissected packet that can
//! outlive the [`DissectBuffer`](packet_dissector_core::packet::DissectBuffer).
//! Borrowed `Bytes`/`Str` field values are converted to byte-range references
//! into the owned data buffer.

use std::ops::Range;

use packet_dissector_core::field::{FieldDescriptor, FieldValue, MacAddr};
use packet_dissector_core::packet::{DissectBuffer, Layer};

/// A fully owned packet that can outlive the `DissectBuffer`.
///
/// Stores a copy of the packet data alongside layers and fields.
pub struct OwnedPacket {
    /// Owned copy of the original packet bytes.
    pub data: Vec<u8>,
    /// Owned copy of the auxiliary data buffer (TCP reassembly / ESP decryption).
    pub aux_data: Vec<u8>,
    /// Protocol layers (identical to `DissectBuffer::layers`).
    pub layers: Vec<Layer>,
    /// Owned fields with borrowed references resolved to ranges.
    pub fields: Vec<OwnedField>,
    /// Scratch buffer.
    pub scratch: Vec<u8>,
}

/// An owned field where `Bytes`/`Str` references are stored as ranges into
/// `OwnedPacket.data` (or `OwnedPacket.aux_data`).
pub struct OwnedField {
    /// Reference to the static field descriptor.
    pub descriptor: &'static FieldDescriptor,
    /// The owned value.
    pub value: OwnedFieldValue,
    /// Byte range in the original packet that this field corresponds to.
    pub range: Range<usize>,
}

/// Owned field value where borrowed variants are replaced with byte ranges.
pub enum OwnedFieldValue {
    /// An 8-bit unsigned integer.
    U8(u8),
    /// A 16-bit unsigned integer.
    U16(u16),
    /// A 32-bit unsigned integer.
    U32(u32),
    /// A 64-bit unsigned integer.
    U64(u64),
    /// A 32-bit signed integer.
    I32(i32),
    /// Byte range into `OwnedPacket.data` or `OwnedPacket.aux_data`.
    Bytes(BytesSource),
    /// Byte range into `OwnedPacket.data` or `OwnedPacket.aux_data` (valid UTF-8).
    Str(BytesSource),
    /// An IPv4 address (4 bytes, network byte order).
    Ipv4Addr([u8; 4]),
    /// An IPv6 address (16 bytes).
    Ipv6Addr([u8; 16]),
    /// A MAC address (6 bytes).
    MacAddr(MacAddr),
    /// Flat-buffer range for array children (same as `FieldValue::Array`).
    Array(Range<u32>),
    /// Flat-buffer range for object children (same as `FieldValue::Object`).
    Object(Range<u32>),
    /// Scratch buffer range (same as `FieldValue::Scratch`).
    Scratch(Range<u32>),
}

/// Identifies which buffer a `Bytes`/`Str` value references.
pub enum BytesSource {
    /// Range into `OwnedPacket.data`.
    Data(Range<usize>),
    /// Range into `OwnedPacket.aux_data`.
    AuxData(Range<usize>),
}

impl OwnedPacket {
    /// Convert a `DissectBuffer` and packet data into a fully owned packet.
    pub fn from_dissect_buf(buf: &DissectBuffer<'_>, data: &[u8]) -> Self {
        let owned_data: Vec<u8> = data.to_vec();
        let owned_aux: Vec<u8> = buf.aux_data();
        let data_range = data.as_ptr_range();

        let fields: Vec<OwnedField> = buf
            .fields()
            .iter()
            .map(|f| {
                let value = convert_field_value(&f.value, data_range.start, data.len(), buf);
                OwnedField {
                    descriptor: f.descriptor,
                    value,
                    range: f.range.clone(),
                }
            })
            .collect();

        OwnedPacket {
            data: owned_data,
            aux_data: owned_aux,
            layers: buf.layers().to_vec(),
            fields,
            scratch: buf.scratch().to_vec(),
        }
    }

    /// Get a layer's owned fields from the flat buffer.
    pub fn layer_fields(&self, layer: &Layer) -> &[OwnedField] {
        &self.fields[layer.field_range.start as usize..layer.field_range.end as usize]
    }

    /// Get nested fields (children of an Array or Object).
    pub fn nested_fields(&self, range: &Range<u32>) -> &[OwnedField] {
        &self.fields[range.start as usize..range.end as usize]
    }

    /// Get the first layer matching the given short protocol name.
    pub fn layer_by_name(&self, name: &str) -> Option<&Layer> {
        self.layers.iter().find(|l| l.name == name)
    }

    /// Look up a field by name within a layer.
    pub fn field_by_name(&self, layer: &Layer, name: &str) -> Option<&OwnedField> {
        self.layer_fields(layer).iter().find(|f| f.name() == name)
    }

    /// Resolve a `Bytes`/`Str` source to actual bytes.
    pub fn resolve_bytes<'a>(&'a self, source: &BytesSource) -> &'a [u8] {
        match source {
            BytesSource::Data(range) => &self.data[range.clone()],
            BytesSource::AuxData(range) => &self.aux_data[range.clone()],
        }
    }

    /// Resolve a `Str` source to a string slice.
    pub fn resolve_str<'a>(&'a self, source: &BytesSource) -> &'a str {
        let bytes = self.resolve_bytes(source);
        // We only store Str sources from valid UTF-8 data.
        let s = std::str::from_utf8(bytes).unwrap_or("");
        debug_assert!(
            !s.is_empty() || bytes.is_empty(),
            "Str source contained invalid UTF-8"
        );
        s
    }

    /// Resolve scratch buffer bytes.
    pub fn resolve_scratch(&self, range: &Range<u32>) -> &[u8] {
        &self.scratch[range.start as usize..range.end as usize]
    }

    /// Resolve a virtual `_name` field within a layer.
    pub fn resolve_display_name(&self, layer: &Layer, name: &str) -> Option<&'static str> {
        let base_name = name.strip_suffix("_name")?;
        let fields = self.layer_fields(layer);
        let base_field = fields.iter().find(|f| f.name() == base_name)?;
        let display_fn = base_field.descriptor.display_fn?;
        // Convert to a temporary FieldValue for the display_fn call.
        let temp_value = base_field.value.to_field_value(self);
        let temp_fields: Vec<packet_dissector_core::field::Field<'_>> = fields
            .iter()
            .map(|f| packet_dissector_core::field::Field {
                descriptor: f.descriptor,
                value: f.value.to_field_value(self),
                range: f.range.clone(),
            })
            .collect();
        display_fn(&temp_value, &temp_fields)
    }
}

impl OwnedField {
    /// Machine-readable field name.
    pub fn name(&self) -> &'static str {
        self.descriptor.name
    }

    /// Human-readable display name.
    pub fn display_name(&self) -> &'static str {
        self.descriptor.display_name
    }
}

impl OwnedFieldValue {
    /// Convert back to a borrowed `FieldValue` for display_fn calls etc.
    pub fn to_field_value<'a>(&'a self, packet: &'a OwnedPacket) -> FieldValue<'a> {
        match self {
            OwnedFieldValue::U8(v) => FieldValue::U8(*v),
            OwnedFieldValue::U16(v) => FieldValue::U16(*v),
            OwnedFieldValue::U32(v) => FieldValue::U32(*v),
            OwnedFieldValue::U64(v) => FieldValue::U64(*v),
            OwnedFieldValue::I32(v) => FieldValue::I32(*v),
            OwnedFieldValue::Bytes(src) => FieldValue::Bytes(packet.resolve_bytes(src)),
            OwnedFieldValue::Str(src) => FieldValue::Str(packet.resolve_str(src)),
            OwnedFieldValue::Ipv4Addr(a) => FieldValue::Ipv4Addr(*a),
            OwnedFieldValue::Ipv6Addr(a) => FieldValue::Ipv6Addr(*a),
            OwnedFieldValue::MacAddr(m) => FieldValue::MacAddr(*m),
            OwnedFieldValue::Array(r) => FieldValue::Array(r.clone()),
            OwnedFieldValue::Object(r) => FieldValue::Object(r.clone()),
            OwnedFieldValue::Scratch(r) => FieldValue::Scratch(r.clone()),
        }
    }
}

/// Convert a borrowed `FieldValue` to an `OwnedFieldValue`, resolving
/// `Bytes`/`Str` references into ranges.
fn convert_field_value(
    value: &FieldValue<'_>,
    data_base: *const u8,
    data_len: usize,
    buf: &DissectBuffer<'_>,
) -> OwnedFieldValue {
    match value {
        FieldValue::U8(v) => OwnedFieldValue::U8(*v),
        FieldValue::U16(v) => OwnedFieldValue::U16(*v),
        FieldValue::U32(v) => OwnedFieldValue::U32(*v),
        FieldValue::U64(v) => OwnedFieldValue::U64(*v),
        FieldValue::I32(v) => OwnedFieldValue::I32(*v),
        FieldValue::Bytes(b) => {
            let src = resolve_ptr_range(b.as_ptr(), b.len(), data_base, data_len, buf);
            OwnedFieldValue::Bytes(src)
        }
        FieldValue::Str(s) => {
            let b = s.as_bytes();
            let src = resolve_ptr_range(b.as_ptr(), b.len(), data_base, data_len, buf);
            OwnedFieldValue::Str(src)
        }
        FieldValue::Ipv4Addr(a) => OwnedFieldValue::Ipv4Addr(*a),
        FieldValue::Ipv6Addr(a) => OwnedFieldValue::Ipv6Addr(*a),
        FieldValue::MacAddr(m) => OwnedFieldValue::MacAddr(*m),
        FieldValue::Array(r) => OwnedFieldValue::Array(r.clone()),
        FieldValue::Object(r) => OwnedFieldValue::Object(r.clone()),
        FieldValue::Scratch(r) => OwnedFieldValue::Scratch(r.clone()),
    }
}

/// Determine if a pointer+length falls within the data buffer or aux buffer
/// and return the corresponding `BytesSource`.
fn resolve_ptr_range(
    ptr: *const u8,
    len: usize,
    data_base: *const u8,
    data_len: usize,
    buf: &DissectBuffer<'_>,
) -> BytesSource {
    let addr = ptr as usize;
    let data_start = data_base as usize;
    let data_end = data_start + data_len;

    if addr >= data_start && addr < data_end {
        let offset = addr - data_start;
        return BytesSource::Data(offset..offset + len);
    }

    if let Some(range) = buf.resolve_aux_ptr_range(ptr, len) {
        return BytesSource::AuxData(range);
    }

    // Fallback: data range (shouldn't happen in practice).
    BytesSource::Data(0..0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::FieldType;

    static TEST_DESC: FieldDescriptor = FieldDescriptor::new("test", "Test", FieldType::U16);

    #[test]
    fn from_dissect_buf_empty() {
        let buf = DissectBuffer::new();
        let data: &[u8] = &[];
        let owned = OwnedPacket::from_dissect_buf(&buf, data);
        assert!(owned.layers.is_empty());
        assert!(owned.fields.is_empty());
    }

    #[test]
    fn from_dissect_buf_preserves_layers() {
        let data = [0u8; 14];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Ethernet", None, &[], 0..14);
        buf.push_field(&TEST_DESC, FieldValue::U16(0x0800), 12..14);
        buf.end_layer();

        let owned = OwnedPacket::from_dissect_buf(&buf, &data);
        assert_eq!(owned.layers.len(), 1);
        assert_eq!(owned.layers[0].name, "Ethernet");
        assert_eq!(owned.fields.len(), 1);
        assert!(matches!(
            owned.fields[0].value,
            OwnedFieldValue::U16(0x0800)
        ));
    }

    #[test]
    fn from_dissect_buf_resolves_bytes() {
        let data: &[u8] = &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
        let mut buf = DissectBuffer::new();

        static BYTES_DESC: FieldDescriptor =
            FieldDescriptor::new("payload", "Payload", FieldType::Bytes);

        buf.begin_layer("Test", None, &[], 0..6);
        buf.push_field(&BYTES_DESC, FieldValue::Bytes(&data[2..5]), 2..5);
        buf.end_layer();

        let owned = OwnedPacket::from_dissect_buf(&buf, data);
        match &owned.fields[0].value {
            OwnedFieldValue::Bytes(src) => {
                assert_eq!(owned.resolve_bytes(src), &[0x22, 0x33, 0x44]);
            }
            _ => panic!("expected Bytes"),
        }
    }

    #[test]
    fn from_dissect_buf_resolves_str() {
        let data: &[u8] = b"hello world";
        let mut buf = DissectBuffer::new();

        static STR_DESC: FieldDescriptor = FieldDescriptor::new("msg", "Message", FieldType::Str);

        buf.begin_layer("Test", None, &[], 0..11);
        let s = std::str::from_utf8(&data[6..11]).unwrap();
        buf.push_field(&STR_DESC, FieldValue::Str(s), 6..11);
        buf.end_layer();

        let owned = OwnedPacket::from_dissect_buf(&buf, data);
        match &owned.fields[0].value {
            OwnedFieldValue::Str(src) => {
                assert_eq!(owned.resolve_str(src), "world");
            }
            _ => panic!("expected Str"),
        }
    }

    #[test]
    fn layer_by_name_works() {
        let data = [0u8; 14];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Ethernet", None, &[], 0..14);
        buf.end_layer();
        buf.begin_layer("IPv4", None, &[], 14..34);
        buf.end_layer();

        let owned = OwnedPacket::from_dissect_buf(&buf, &data);
        assert!(owned.layer_by_name("IPv4").is_some());
        assert!(owned.layer_by_name("TCP").is_none());
    }

    #[test]
    fn field_by_name_works() {
        let data = [0u8; 14];
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Test", None, &[], 0..14);
        buf.push_field(&TEST_DESC, FieldValue::U16(42), 0..2);
        buf.end_layer();

        let owned = OwnedPacket::from_dissect_buf(&buf, &data);
        let layer = owned.layer_by_name("Test").unwrap();
        let field = owned.field_by_name(layer, "test").unwrap();
        assert!(matches!(field.value, OwnedFieldValue::U16(42)));
    }

    #[test]
    fn to_field_value_roundtrip() {
        let data: &[u8] = b"test data here";
        let mut buf = DissectBuffer::new();

        static STR_DESC: FieldDescriptor = FieldDescriptor::new("val", "Value", FieldType::Str);

        buf.begin_layer("Test", None, &[], 0..14);
        let s = std::str::from_utf8(&data[5..9]).unwrap();
        buf.push_field(&STR_DESC, FieldValue::Str(s), 5..9);
        buf.end_layer();

        let owned = OwnedPacket::from_dissect_buf(&buf, data);
        let fv = owned.fields[0].value.to_field_value(&owned);
        assert_eq!(fv, FieldValue::Str("data"));
    }
}
