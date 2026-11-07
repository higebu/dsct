//! Keyboard navigation over the protocol detail tree, kept free of GPUI so
//! it can be unit tested.
//!
//! The tree is the flat, depth-annotated node list `dsct::session::tree`
//! builds: a node's children follow it with a greater depth.

use dsct::session::state::TreeNode;

/// The node containing node `idx`, or `None` for a top-level node.
pub fn parent(nodes: &[TreeNode], idx: usize) -> Option<usize> {
    let depth = nodes.get(idx)?.depth;
    nodes[..idx].iter().rposition(|n| n.depth < depth)
}

/// The deepest node whose bytes contain `byte`, preferring the narrowest
/// range when several nodes at that depth do.
pub fn innermost_at(nodes: &[TreeNode], byte: usize) -> Option<usize> {
    nodes
        .iter()
        .enumerate()
        .filter(|(_, n)| n.byte_range.contains(&byte))
        .max_by(|(ai, a), (bi, b)| {
            a.depth
                .cmp(&b.depth)
                .then(b.byte_range.len().cmp(&a.byte_range.len()))
                // Among equals, the first node in tree order.
                .then(bi.cmp(ai))
        })
        .map(|(i, _)| i)
}

/// Expand every node containing node `idx`, so it is visible.
pub fn expand_ancestors(nodes: &mut [TreeNode], idx: usize) {
    let mut current = idx;
    while let Some(p) = parent(nodes, current) {
        nodes[p].expanded = true;
        current = p;
    }
}

/// What a key press in the tree does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeMove {
    /// Select this node (an index into the node list).
    Select(usize),
    /// Expand or collapse this node, keeping the selection.
    Toggle(usize),
    /// Nothing to do.
    None,
}

/// The node above or below `selected` among the `visible` nodes (indices
/// into the node list, in display order). Without a selection, the first
/// visible node is selected.
pub fn step(visible: &[usize], selected: Option<usize>, down: bool) -> TreeMove {
    let Some(selected) = selected else {
        return visible
            .first()
            .map_or(TreeMove::None, |&i| TreeMove::Select(i));
    };
    let Some(pos) = visible.iter().position(|&i| i == selected) else {
        return visible
            .first()
            .map_or(TreeMove::None, |&i| TreeMove::Select(i));
    };
    let next = if down {
        visible.get(pos + 1)
    } else {
        pos.checked_sub(1).and_then(|p| visible.get(p))
    };
    next.map_or(TreeMove::None, |&i| TreeMove::Select(i))
}

/// Right arrow: expand a collapsed parent, or go to the first child of an
/// expanded one.
pub fn right(nodes: &[TreeNode], selected: usize) -> TreeMove {
    let Some(node) = nodes.get(selected) else {
        return TreeMove::None;
    };
    match (node.children_count > 0, node.expanded) {
        (false, _) => TreeMove::None,
        (true, false) => TreeMove::Toggle(selected),
        (true, true) => TreeMove::Select(selected + 1),
    }
}

/// Left arrow: collapse an expanded parent, or go to the node containing
/// this one.
pub fn left(nodes: &[TreeNode], selected: usize) -> TreeMove {
    let Some(node) = nodes.get(selected) else {
        return TreeMove::None;
    };
    if node.children_count > 0 && node.expanded {
        return TreeMove::Toggle(selected);
    }
    parent(nodes, selected).map_or(TreeMove::None, TreeMove::Select)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(depth: usize, range: std::ops::Range<usize>, children: usize) -> TreeNode {
        TreeNode {
            label: String::new(),
            depth,
            expanded: false,
            byte_range: range,
            children_count: children,
            is_layer: depth == 0,
            filter: None,
        }
    }

    /// Ethernet [0..14) { dst, src }, IPv4 [14..34) { ttl, flags { df } }.
    fn tree() -> Vec<TreeNode> {
        vec![
            node(0, 0..14, 2),  // 0 Ethernet
            node(1, 0..6, 0),   // 1 dst
            node(1, 6..12, 0),  // 2 src
            node(0, 14..34, 2), // 3 IPv4
            node(1, 22..23, 0), // 4 ttl
            node(1, 20..22, 1), // 5 flags
            node(2, 20..21, 0), // 6 df
        ]
    }

    #[test]
    fn parent_walks_up_one_level() {
        let t = tree();
        assert_eq!(parent(&t, 0), None);
        assert_eq!(parent(&t, 2), Some(0));
        assert_eq!(parent(&t, 4), Some(3));
        assert_eq!(parent(&t, 6), Some(5));
        assert_eq!(parent(&t, 99), None);
    }

    #[test]
    fn innermost_prefers_the_deepest_node() {
        let t = tree();
        assert_eq!(innermost_at(&t, 7), Some(2));
        assert_eq!(innermost_at(&t, 20), Some(6));
        assert_eq!(innermost_at(&t, 21), Some(5));
        assert_eq!(innermost_at(&t, 30), Some(3));
        assert_eq!(innermost_at(&t, 40), None);
    }

    #[test]
    fn expand_ancestors_opens_the_path() {
        let mut t = tree();
        expand_ancestors(&mut t, 6);
        assert!(t[5].expanded && t[3].expanded);
        assert!(!t[0].expanded);
    }

    #[test]
    fn step_moves_within_the_visible_nodes() {
        let visible = [0, 3, 4];
        assert_eq!(step(&visible, None, true), TreeMove::Select(0));
        assert_eq!(step(&visible, Some(0), true), TreeMove::Select(3));
        assert_eq!(step(&visible, Some(3), false), TreeMove::Select(0));
        assert_eq!(step(&visible, Some(4), true), TreeMove::None);
        assert_eq!(step(&visible, Some(0), false), TreeMove::None);
        // A selection that was collapsed away restarts at the top.
        assert_eq!(step(&visible, Some(6), true), TreeMove::Select(0));
        assert_eq!(step(&[], None, true), TreeMove::None);
    }

    #[test]
    fn right_expands_then_enters() {
        let mut t = tree();
        assert_eq!(right(&t, 0), TreeMove::Toggle(0));
        t[0].expanded = true;
        assert_eq!(right(&t, 0), TreeMove::Select(1));
        assert_eq!(right(&t, 1), TreeMove::None);
    }

    #[test]
    fn left_collapses_then_leaves() {
        let mut t = tree();
        t[3].expanded = true;
        assert_eq!(left(&t, 3), TreeMove::Toggle(3));
        assert_eq!(left(&t, 4), TreeMove::Select(3));
        t[3].expanded = false;
        assert_eq!(left(&t, 3), TreeMove::None);
    }
}
