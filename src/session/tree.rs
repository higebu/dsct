//! Build a flat tree of [`TreeNode`]s from a dissected [`Packet`].

use packet_dissector_core::field::{Field, FieldValue};
use packet_dissector_core::packet::{DissectBuffer, Layer, Packet};

use crate::field_format::format_field_to_string;
use crate::field_iter::top_level_fields;
use crate::filter::normalize_protocol_name;

use super::fields::{FieldRef, filter_value};
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
    let mut nodes = Vec::new();
    let mut path = String::new();
    for layer in buf.layers() {
        let all_fields = buf.layer_fields(layer);
        let top_fields: Vec<&Field<'_>> =
            top_level_fields(all_fields, layer.field_range.start).collect();
        path.clear();
        path.push_str(&normalize_protocol_name(layer.name));
        nodes.push(TreeNode {
            label: layer.protocol_name().to_string(),
            depth: 0,
            expanded: false,
            byte_range: layer.range.clone(),
            children_count: top_fields.len() + display_fn_count(&top_fields, all_fields),
            is_layer: true,
            filter: Some(FieldRef {
                path: path.clone(),
                value: None,
            }),
        });
        for &field in &top_fields {
            push_field(&mut nodes, field, all_fields, 1, packet, layer, &mut path);
        }
    }
    nodes
}

/// Emit a virtual `_name` node from a field's `display_fn`, if present.
/// `path` is the field's own filter path.
fn push_display_fn_node(
    nodes: &mut Vec<TreeNode>,
    field: &Field<'_>,
    siblings: &[Field<'_>],
    depth: usize,
    path: &str,
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
            filter: Some(FieldRef {
                path: format!("{path}_name"),
                value: Some(display_value.to_string()),
            }),
        });
    }
}

/// Emit the node of `field` (one of `siblings`), its `_name` node, and the
/// nodes of its children. `path` holds the filter path of the container.
fn push_field(
    nodes: &mut Vec<TreeNode>,
    field: &Field<'_>,
    siblings: &[Field<'_>],
    depth: usize,
    packet: &Packet<'_, '_>,
    layer: &Layer,
    path: &mut String,
) {
    let buf = packet.buf();
    let len = path.len();
    path.push('.');
    path.push_str(field.name());

    let formatted = format_field(field, packet.data(), layer, buf);
    nodes.push(TreeNode {
        label: format!("{}: {}", field.display_name(), formatted),
        depth,
        expanded: false,
        byte_range: field.range.clone(),
        children_count: count_children(&field.value, buf),
        is_layer: false,
        filter: field_ref(packet, layer, field, path),
    });
    push_display_fn_node(nodes, field, siblings, depth, path);

    // Recurse into container types, visiting only each container's direct
    // children: their own children follow them in the flat buffer.
    match &field.value {
        FieldValue::Object(range) => {
            let fields = buf.nested_fields(range);
            for child in top_level_fields(fields, range.start) {
                push_field(nodes, child, fields, depth + 1, packet, layer, path);
            }
        }
        FieldValue::Array(range) => {
            let elements = buf.nested_fields(range);
            for (idx, elem) in top_level_fields(elements, range.start).enumerate() {
                match &elem.value {
                    FieldValue::Object(obj_range) => {
                        let obj_fields = buf.nested_fields(obj_range);
                        let children: Vec<&Field<'_>> =
                            top_level_fields(obj_fields, obj_range.start).collect();
                        nodes.push(TreeNode {
                            label: format!("[{idx}]"),
                            depth: depth + 1,
                            expanded: true,
                            byte_range: elem.range.clone(),
                            children_count: children.len()
                                + display_fn_count(&children, obj_fields),
                            is_layer: false,
                            filter: None,
                        });
                        for child in children {
                            push_field(nodes, child, obj_fields, depth + 2, packet, layer, path);
                        }
                    }
                    _ => {
                        let formatted = format_field(elem, packet.data(), layer, buf);
                        nodes.push(TreeNode {
                            label: format!("[{idx}]: {formatted}"),
                            depth: depth + 1,
                            expanded: false,
                            byte_range: elem.range.clone(),
                            children_count: count_children(&elem.value, buf),
                            is_layer: false,
                            // A filter on the array's path matches any element.
                            filter: field_ref(packet, layer, elem, path),
                        });
                    }
                }
            }
        }
        _ => {}
    }
    path.truncate(len);
}

/// The filter reference of a scalar field at `path`, if a filter can
/// compare its value.
fn field_ref(
    packet: &Packet<'_, '_>,
    layer: &Layer,
    field: &Field<'_>,
    path: &str,
) -> Option<FieldRef> {
    let (value, _) = filter_value(packet, layer, field)?;
    Some(FieldRef {
        path: path.to_string(),
        value: Some(value),
    })
}

/// Count the fields among `fields` (direct children of one container, from
/// the flat slice `siblings`) whose `display_fn` produces a value.
fn display_fn_count(fields: &[&Field<'_>], siblings: &[Field<'_>]) -> usize {
    fields
        .iter()
        .filter(|f| {
            f.descriptor
                .display_fn
                .is_some_and(|df| df(&f.value, siblings).is_some())
        })
        .count()
}

/// Number of child nodes of a field: an object's direct fields (and their
/// `_name` nodes), or an array's elements.
fn count_children(value: &FieldValue<'_>, buf: &DissectBuffer<'_>) -> usize {
    match value {
        FieldValue::Object(range) => {
            let fields = buf.nested_fields(range);
            let children: Vec<&Field<'_>> = top_level_fields(fields, range.start).collect();
            children.len() + display_fn_count(&children, fields)
        }
        FieldValue::Array(range) => top_level_fields(buf.nested_fields(range), range.start).count(),
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

/// Iterator over visible (non-collapsed) tree nodes.
pub fn visible_nodes(nodes: &[TreeNode]) -> impl Iterator<Item = (usize, &TreeNode)> {
    let mut skip_depth: Option<usize> = None;
    nodes.iter().enumerate().filter(move |(_, node)| {
        if let Some(d) = skip_depth {
            if node.depth > d {
                return false;
            }
            skip_depth = None;
        }
        if !node.expanded && node.children_count > 0 {
            skip_depth = Some(node.depth);
        }
        true
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visible_nodes_hides_collapsed_children() {
        let nodes = vec![
            TreeNode {
                label: "Layer".into(),
                depth: 0,
                expanded: false,
                byte_range: 0..10,
                children_count: 2,
                is_layer: true,
                filter: None,
            },
            TreeNode {
                label: "Field1".into(),
                depth: 1,
                expanded: false,
                byte_range: 0..4,
                children_count: 0,
                is_layer: false,
                filter: None,
            },
        ];
        assert_eq!(visible_nodes(&nodes).count(), 1);
    }

    #[test]
    fn visible_nodes_all_expanded() {
        let nodes = vec![
            TreeNode {
                label: "Layer".into(),
                depth: 0,
                expanded: true,
                byte_range: 0..10,
                children_count: 1,
                is_layer: true,
                filter: None,
            },
            TreeNode {
                label: "Field".into(),
                depth: 1,
                expanded: false,
                byte_range: 0..4,
                children_count: 0,
                is_layer: false,
                filter: None,
            },
        ];
        assert_eq!(visible_nodes(&nodes).count(), 2);
    }

    #[test]
    fn visible_nodes_empty() {
        let nodes: Vec<TreeNode> = vec![];
        assert_eq!(visible_nodes(&nodes).count(), 0);
    }
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

    fn dns_edns_tree() -> Vec<TreeNode> {
        let registry = packet_dissector::registry::DissectorRegistry::default();
        let frame = crate::test_fixtures::dns_edns_query_frame();
        let mut buf = DissectBuffer::new();
        registry
            .dissect_with_link_type(&frame, 1, &mut buf)
            .unwrap();
        build_tree(&Packet::new(&buf, &frame))
    }

    #[test]
    fn nested_fields_appear_once_under_their_container() {
        let nodes = dns_edns_tree();
        let codes: Vec<&TreeNode> = nodes.iter().filter(|n| n.label == "Code: 11").collect();
        assert_eq!(
            codes.len(),
            1,
            "{:#?}",
            nodes.iter().map(|n| &n.label).collect::<Vec<_>>()
        );
        let record = nodes
            .iter()
            .position(|n| n.label == "Additional Records: [...]")
            .unwrap();
        // The record's "[0]" lists its own fields only.
        let element = &nodes[record + 1];
        assert_eq!(element.label, "[0]");
        let direct = nodes[record + 2..]
            .iter()
            .take_while(|n| n.depth > element.depth)
            .filter(|n| n.depth == element.depth + 1)
            .count();
        assert_eq!(element.children_count, direct);
    }

    #[test]
    fn tree_nodes_filter_for_their_own_packet() {
        let registry = packet_dissector::registry::DissectorRegistry::default();
        for frame in [
            crate::test_fixtures::dns_edns_query_frame(),
            crate::test_fixtures::bgp_update_frame(),
            crate::test_fixtures::bgp_update_mp_reach_frame(),
        ] {
            let mut buf = DissectBuffer::new();
            registry
                .dissect_with_link_type(&frame, 1, &mut buf)
                .unwrap();
            let packet = Packet::new(&buf, &frame);
            let nodes = build_tree(&packet);
            assert!(
                nodes
                    .iter()
                    .filter(|n| n.is_layer)
                    .all(|n| n.filter.is_some())
            );
            for node in &nodes {
                let Some(field) = &node.filter else { continue };
                let clause = field.clause();
                let expr = crate::filter_expr::FilterExpr::parse(&clause)
                    .unwrap_or_else(|e| panic!("{clause}: {e}"))
                    .unwrap();
                assert!(expr.matches(&packet), "{} → {clause}", node.label);
            }
        }
        let nodes = dns_edns_tree();
        let filter = |label: &str| {
            nodes
                .iter()
                .find(|n| n.label == label)
                .and_then(|n| n.filter.as_ref())
                .map(FieldRef::clause)
        };
        assert_eq!(
            filter("Name: example.com").as_deref(),
            Some("dns.questions.name = 'example.com'")
        );
        assert_eq!(
            filter("Code Name: TCP-KEEPALIVE").as_deref(),
            Some("dns.additionals.edns_options.code_name = 'TCP-KEEPALIVE'")
        );
        assert_eq!(filter("DNS").as_deref(), Some("dns"));
        assert_eq!(filter("[0]"), None);
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
