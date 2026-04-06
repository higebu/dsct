//! Build a flat tree of [`TreeNode`]s from a dissected [`Packet`].

use packet_dissector_core::field::{Field, FieldValue};
use packet_dissector_core::packet::{DissectBuffer, Layer, Packet};

use crate::field_format::format_field_to_string;

use super::state::TreeNode;

#[cfg(test)]
use packet_dissector_test_alloc::test_desc;

/// Build a flat list of tree nodes from a packet's protocol layers.
///
/// Each protocol layer becomes a parent node (depth 0) and its fields become
/// children (depth 1+). `Object` and `Array` field values are recursively expanded.
/// All layer nodes start expanded.
pub fn build_tree(packet: &Packet<'_, '_>) -> Vec<TreeNode> {
    let buf = packet.buf();
    let data = packet.data();
    let mut nodes = Vec::new();
    for layer in buf.layers() {
        let all_fields = buf.layer_fields(layer);
        // Collect top-level field indices (skip children of containers).
        let top_level = collect_top_level_indices(all_fields, layer.field_range.start);
        let top_fields: Vec<&Field<'_>> = top_level.iter().map(|&i| &all_fields[i]).collect();
        let display_fn_count = top_fields
            .iter()
            .filter(|f| {
                f.descriptor
                    .display_fn
                    .is_some_and(|df| df(&f.value, all_fields).is_some())
            })
            .count();
        let fields_count = top_fields.len() + display_fn_count;
        nodes.push(TreeNode {
            label: layer.protocol_name().to_string(),
            depth: 0,
            expanded: false,
            byte_range: layer.range.clone(),
            children_count: fields_count,
            is_layer: true,
        });
        for &field in &top_fields {
            push_field(&mut nodes, field, 1, buf, data, layer);
            push_display_fn_node(&mut nodes, field, all_fields, 1);
        }
    }
    nodes
}

/// Collect indices of top-level fields (not children of containers).
fn collect_top_level_indices(fields: &[Field<'_>], base: u32) -> Vec<usize> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < fields.len() {
        result.push(i);
        match &fields[i].value {
            FieldValue::Array(range) | FieldValue::Object(range) => {
                // Skip all children of this container.
                let children_end = (range.end - base) as usize;
                i = children_end;
            }
            _ => {
                i += 1;
            }
        }
    }
    result
}

/// Emit a virtual `_name` node from a field's `display_fn`, if present.
fn push_display_fn_node(
    nodes: &mut Vec<TreeNode>,
    field: &Field<'_>,
    siblings: &[Field<'_>],
    depth: usize,
) {
    if let Some(display_fn) = field.descriptor.display_fn
        && let Some(display_value) = display_fn(&field.value, siblings)
    {
        let label = format!("{} Name: {display_value}", field.display_name());
        nodes.push(TreeNode {
            label,
            depth,
            expanded: false,
            byte_range: field.range.clone(),
            children_count: 0,
            is_layer: false,
        });
    }
}

fn push_field(
    nodes: &mut Vec<TreeNode>,
    field: &Field<'_>,
    depth: usize,
    buf: &DissectBuffer<'_>,
    data: &[u8],
    layer: &Layer,
) {
    let formatted = format_field(field, data, layer, buf);
    let label = format!("{}: {}", field.display_name(), formatted);
    let children_count = count_children(&field.value, buf);
    nodes.push(TreeNode {
        label,
        depth,
        expanded: false,
        byte_range: field.range.clone(),
        children_count,
        is_layer: false,
    });

    // Recurse into container types.
    match &field.value {
        FieldValue::Object(range) => {
            let fields = buf.nested_fields(range);
            for child in fields {
                push_field(nodes, child, depth + 1, buf, data, layer);
                push_display_fn_node(nodes, child, fields, depth + 1);
            }
        }
        FieldValue::Array(range) => {
            let elements = buf.nested_fields(range);
            let mut idx = 0;
            let mut i = 0;
            while i < elements.len() {
                let elem = &elements[i];
                match &elem.value {
                    FieldValue::Object(obj_range) => {
                        let obj_fields = buf.nested_fields(obj_range);
                        let dfn_count = display_fn_count(obj_fields);
                        nodes.push(TreeNode {
                            label: format!("[{idx}]"),
                            depth: depth + 1,
                            expanded: true,
                            byte_range: elem.range.clone(),
                            children_count: obj_fields.len() + dfn_count,
                            is_layer: false,
                        });
                        for child in obj_fields {
                            push_field(nodes, child, depth + 2, buf, data, layer);
                            push_display_fn_node(nodes, child, obj_fields, depth + 2);
                        }
                        // Skip past the container's children in the flat buffer
                        i = obj_range.end as usize - range.start as usize;
                    }
                    _ => {
                        let formatted = format_field(elem, data, layer, buf);
                        nodes.push(TreeNode {
                            label: format!("[{idx}]: {}", formatted),
                            depth: depth + 1,
                            expanded: false,
                            byte_range: elem.range.clone(),
                            children_count: 0,
                            is_layer: false,
                        });
                        i += 1;
                    }
                }
                idx += 1;
            }
        }
        _ => {}
    }
}

/// Count the number of fields in an object that have a `display_fn` producing a value.
fn display_fn_count(fields: &[Field<'_>]) -> usize {
    fields
        .iter()
        .filter(|f| {
            f.descriptor
                .display_fn
                .is_some_and(|df| df(&f.value, fields).is_some())
        })
        .count()
}

fn count_children(value: &FieldValue<'_>, buf: &DissectBuffer<'_>) -> usize {
    match value {
        FieldValue::Object(range) => {
            let fields = buf.nested_fields(range);
            fields.len() + display_fn_count(fields)
        }
        FieldValue::Array(range) => {
            // Count top-level array elements (each Object element is one item,
            // not the flattened count of all nested fields).
            let children = buf.nested_fields(range);
            let mut count = 0;
            let mut i = 0;
            while i < children.len() {
                count += 1;
                match &children[i].value {
                    FieldValue::Object(obj_range) => {
                        i = (obj_range.end - range.start) as usize;
                    }
                    _ => {
                        i += 1;
                    }
                }
            }
            count
        }
        _ => 0,
    }
}

/// Format a field for display, using its `format_fn` when available.
fn format_field(field: &Field<'_>, data: &[u8], layer: &Layer, buf: &DissectBuffer<'_>) -> String {
    if let FieldValue::Bytes(_) | FieldValue::Scratch(_) = &field.value
        && let Some(s) = format_field_to_string(field, data, layer, buf.scratch())
    {
        return s;
    }
    format_value(&field.value)
}

/// Format a [`FieldValue`] for display in the tree view.
pub fn format_value(value: &FieldValue<'_>) -> String {
    match value {
        FieldValue::U8(v) => v.to_string(),
        FieldValue::U16(v) => v.to_string(),
        FieldValue::U32(v) => v.to_string(),
        FieldValue::U64(v) => v.to_string(),
        FieldValue::I32(v) => v.to_string(),
        FieldValue::Ipv4Addr(addr) => {
            format!("{}.{}.{}.{}", addr[0], addr[1], addr[2], addr[3])
        }
        FieldValue::Ipv6Addr(addr) => format_ipv6(addr),
        FieldValue::MacAddr(mac) => mac.to_string(),
        FieldValue::Str(s) => (*s).to_string(),
        FieldValue::Bytes(bytes) => {
            if bytes.len() <= 16 {
                bytes
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":")
            } else {
                let prefix: String = bytes[..16]
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":");
                format!("{prefix}... ({} bytes)", bytes.len())
            }
        }
        FieldValue::Object(_) => "{...}".to_string(),
        FieldValue::Array(_) => "[...]".to_string(),
        FieldValue::Scratch(_) => "<scratch>".to_string(),
    }
}

/// Format a 16-byte IPv6 address using :: compression.
fn format_ipv6(addr: &[u8; 16]) -> String {
    let groups: [u16; 8] =
        std::array::from_fn(|i| u16::from_be_bytes([addr[i * 2], addr[i * 2 + 1]]));

    // Find the longest run of consecutive zeros for :: compression.
    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let mut cur_start = 0usize;
    let mut cur_len = 0usize;

    for (i, &g) in groups.iter().enumerate() {
        if g == 0 {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_start = cur_start;
                best_len = cur_len;
            }
        } else {
            cur_len = 0;
        }
    }

    if best_len < 2 {
        // No compression.
        return groups
            .iter()
            .map(|g| format!("{g:x}"))
            .collect::<Vec<_>>()
            .join(":");
    }

    let mut parts = Vec::new();
    let mut i = 0;
    while i < 8 {
        if i == best_start {
            if i == 0 {
                parts.push(String::new());
            }
            parts.push(String::new());
            i += best_len;
            if i == 8 {
                parts.push(String::new());
            }
        } else {
            parts.push(format!("{:x}", groups[i]));
            i += 1;
        }
    }
    parts.join(":")
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::MacAddr;

    fn make_packet<'a>(buf: &'a DissectBuffer<'a>, data: &'a [u8]) -> Packet<'a, 'a> {
        Packet::new(buf, data)
    }

    #[test]
    fn build_tree_empty_packet() {
        let buf = DissectBuffer::new();
        let data: &[u8] = &[];
        let packet = make_packet(&buf, data);
        let nodes = build_tree(&packet);
        assert!(nodes.is_empty());
    }

    #[test]
    fn build_tree_single_layer() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Ethernet", None, &[], 0..14);
        buf.push_field(
            test_desc("src", "Source"),
            FieldValue::MacAddr(MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55])),
            6..12,
        );
        buf.push_field(
            test_desc("dst", "Destination"),
            FieldValue::MacAddr(MacAddr([0xff; 6])),
            0..6,
        );
        buf.end_layer();

        let data: &[u8] = &[0u8; 14];
        let packet = make_packet(&buf, data);
        let nodes = build_tree(&packet);
        assert_eq!(nodes.len(), 3);
        assert!(nodes[0].is_layer);
        assert_eq!(nodes[0].label, "Ethernet");
        assert_eq!(nodes[0].children_count, 2);
        assert!(!nodes[1].is_layer);
        assert!(nodes[1].label.contains("Source"));
        assert!(nodes[1].label.contains("00:11:22:33:44:55"));
    }

    #[test]
    fn format_ipv4_value() {
        assert_eq!(
            format_value(&FieldValue::Ipv4Addr([10, 0, 0, 1])),
            "10.0.0.1"
        );
    }

    #[test]
    fn format_ipv6_loopback() {
        let mut addr = [0u8; 16];
        addr[15] = 1;
        assert_eq!(format_ipv6(&addr), "::1");
    }

    #[test]
    fn format_ipv6_no_compression() {
        let addr = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05,
            0x00, 0x06,
        ];
        assert_eq!(format_ipv6(&addr), "2001:db8:1:2:3:4:5:6");
    }

    #[test]
    fn format_bytes_short() {
        assert_eq!(
            format_value(&FieldValue::Bytes(&[0x0a, 0x0b, 0x0c])),
            "0a:0b:0c"
        );
    }

    #[test]
    fn format_bytes_long_truncated() {
        let s = format_value(&FieldValue::Bytes(&[0u8; 32]));
        assert!(s.contains("..."));
        assert!(s.contains("32 bytes"));
    }

    #[test]
    fn format_value_integers() {
        assert_eq!(format_value(&FieldValue::U8(42)), "42");
        assert_eq!(format_value(&FieldValue::U16(1024)), "1024");
        assert_eq!(format_value(&FieldValue::U32(65536)), "65536");
        assert_eq!(format_value(&FieldValue::U64(1_000_000)), "1000000");
        assert_eq!(format_value(&FieldValue::I32(-1)), "-1");
    }

    #[test]
    fn format_value_str() {
        assert_eq!(format_value(&FieldValue::Str("hello")), "hello");
    }

    #[test]
    fn format_value_object() {
        assert_eq!(format_value(&FieldValue::Object(0..0)), "{...}");
    }

    #[test]
    fn format_value_array() {
        assert_eq!(format_value(&FieldValue::Array(0..0)), "[...]");
    }

    #[test]
    fn build_tree_with_object_field() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Test", None, &[], 0..10);
        let obj = buf.begin_container(
            test_desc("nested", "Nested"),
            FieldValue::Object(0..0),
            0..2,
        );
        buf.push_field(test_desc("a", "A"), FieldValue::U8(1), 0..1);
        buf.push_field(test_desc("b", "B"), FieldValue::U8(2), 1..2);
        buf.end_container(obj);
        buf.end_layer();

        let data: &[u8] = &[0u8; 10];
        let packet = make_packet(&buf, data);
        let nodes = build_tree(&packet);
        assert_eq!(nodes.len(), 4);
        assert_eq!(nodes[1].children_count, 2);
        assert_eq!(nodes[1].depth, 1);
        assert_eq!(nodes[2].depth, 2);
        assert!(nodes[2].label.contains("A: 1"));
        assert!(nodes[3].label.contains("B: 2"));
    }

    #[test]
    fn build_tree_with_array_of_objects() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("DNS", None, &[], 0..28);
        let arr = buf.begin_container(
            test_desc("questions", "Questions"),
            FieldValue::Array(0..0),
            0..16,
        );
        let obj = buf.begin_container(test_desc("q", "Q"), FieldValue::Object(0..0), 0..16);
        buf.push_field(
            test_desc("name", "Name"),
            FieldValue::Str("example.com"),
            0..11,
        );
        buf.end_container(obj);
        buf.end_container(arr);
        buf.end_layer();

        let data: &[u8] = &[0u8; 28];
        let packet = make_packet(&buf, data);
        let nodes = build_tree(&packet);
        assert_eq!(nodes.len(), 4);
        assert!(nodes[2].label.contains("[0]"));
        assert!(nodes[3].label.contains("Name: example.com"));
    }

    #[test]
    fn build_tree_with_array_of_scalars() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Test", None, &[], 0..10);
        let arr = buf.begin_container(test_desc("values", "Values"), FieldValue::Array(0..0), 0..2);
        buf.push_field(test_desc("v0", "V0"), FieldValue::U8(10), 0..1);
        buf.push_field(test_desc("v1", "V1"), FieldValue::U8(20), 1..2);
        buf.end_container(arr);
        buf.end_layer();

        let data: &[u8] = &[0u8; 10];
        let packet = make_packet(&buf, data);
        let nodes = build_tree(&packet);
        assert_eq!(nodes.len(), 4);
        assert!(nodes[2].label.contains("[0]: 10"));
        assert!(nodes[3].label.contains("[1]: 20"));
    }

    fn test_desc_with_display_fn(
        name: &'static str,
        display_name: &'static str,
        display_fn: fn(&FieldValue<'_>, &[Field<'_>]) -> Option<&'static str>,
    ) -> &'static packet_dissector_core::field::FieldDescriptor {
        Box::leak(Box::new(packet_dissector_core::field::FieldDescriptor {
            name,
            display_name,
            field_type: packet_dissector_core::field::FieldType::U32,
            optional: false,
            children: None,
            display_fn: Some(display_fn),
            format_fn: None,
        }))
    }

    #[test]
    fn build_tree_display_fn_in_array_of_objects() {
        fn type_display_fn(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
            match v {
                FieldValue::U32(19) => Some("Cause"),
                _ => None,
            }
        }

        let mut buf = DissectBuffer::new();
        buf.begin_layer("PFCP", None, &[], 0..20);
        let ies = buf.begin_container(
            test_desc("ies", "Information Elements"),
            FieldValue::Array(0..0),
            0..5,
        );
        let ie0 = buf.begin_container(test_desc("ie", "IE"), FieldValue::Object(0..0), 0..5);
        buf.push_field(
            test_desc_with_display_fn("type", "Type", type_display_fn),
            FieldValue::U32(19),
            0..2,
        );
        buf.push_field(test_desc("length", "Length"), FieldValue::U16(1), 2..4);
        buf.end_container(ie0);
        buf.end_container(ies);
        buf.end_layer();

        let data: &[u8] = &[0u8; 20];
        let packet = make_packet(&buf, data);
        let nodes = build_tree(&packet);
        assert_eq!(nodes.len(), 6);
        assert_eq!(nodes[2].children_count, 3);
        assert!(nodes[2].label.contains("[0]"));
        assert!(nodes[3].label.contains("Type: 19"));
        assert!(nodes[4].label.contains("Type Name: Cause"));
        assert!(nodes[5].label.contains("Length: 1"));
    }

    #[test]
    fn build_tree_display_fn_in_nested_object() {
        fn type_display_fn(v: &FieldValue<'_>, _: &[Field<'_>]) -> Option<&'static str> {
            match v {
                FieldValue::U8(6) => Some("TCP"),
                _ => None,
            }
        }

        let mut buf = DissectBuffer::new();
        buf.begin_layer("Test", None, &[], 0..10);
        let obj = buf.begin_container(
            test_desc("nested", "Nested"),
            FieldValue::Object(0..0),
            0..1,
        );
        buf.push_field(
            test_desc_with_display_fn("protocol", "Protocol", type_display_fn),
            FieldValue::U8(6),
            0..1,
        );
        buf.end_container(obj);
        buf.end_layer();

        let data: &[u8] = &[0u8; 10];
        let packet = make_packet(&buf, data);
        let nodes = build_tree(&packet);
        assert_eq!(nodes.len(), 4);
        assert_eq!(nodes[1].children_count, 2);
        assert!(nodes[2].label.contains("Protocol: 6"));
        assert!(nodes[3].label.contains("Protocol Name: TCP"));
    }

    #[test]
    fn format_ipv6_all_zeros() {
        assert_eq!(format_ipv6(&[0u8; 16]), "::");
    }

    #[test]
    fn format_ipv6_middle_compression() {
        let addr = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
        ];
        assert_eq!(format_ipv6(&addr), "2001:db8::1");
    }

    #[test]
    fn build_tree_multiple_layers() {
        let mut buf = DissectBuffer::new();
        buf.begin_layer("Ethernet", None, &[], 0..14);
        buf.end_layer();
        buf.begin_layer("IPv4", None, &[], 14..34);
        buf.push_field(
            test_desc("src", "Source"),
            FieldValue::Ipv4Addr([10, 0, 0, 1]),
            14..18,
        );
        buf.end_layer();

        let data: &[u8] = &[0u8; 34];
        let packet = make_packet(&buf, data);
        let nodes = build_tree(&packet);
        assert_eq!(nodes.len(), 3);
        assert!(nodes[0].is_layer);
        assert!(nodes[1].is_layer);
        assert!(!nodes[2].is_layer);
    }
}
