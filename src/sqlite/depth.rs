//! Encapsulation depth computation.
//!
//! The dissector produces a flat list of layers (outermost first).  Tunnelled
//! packets simply repeat their link/network layers later in the list, e.g.
//! `Ethernet:IPv4:UDP:VXLAN:Ethernet:IPv4:TCP`.  This module assigns an
//! *encapsulation depth* to every layer without a tunnel-protocol whitelist:
//!
//! - depth starts at `0`
//! - an `Ethernet` layer that follows any link or network layer of the current
//!   depth starts a new depth (VXLAN, Geneve, L2TPv3, ...)
//! - an `IPv4`/`IPv6` layer that follows a network layer of the current depth
//!   starts a new depth (GRE, GTP-U, IP-in-IP, ESP, MPLS, ...)

/// Link-layer protocol names that start a new depth when repeated.
const LINK_LAYERS: &[&str] = &["Ethernet"];

/// Network-layer protocol names that start a new depth when repeated.
const NETWORK_LAYERS: &[&str] = &["IPv4", "IPv6"];

/// Compute the encapsulation depth of every layer.
///
/// `names` are the protocol short names (`Layer::name`) in outer-to-inner
/// order.  The returned vector has the same length as `names`.
pub fn compute_depths<'a>(names: impl IntoIterator<Item = &'a str>) -> Vec<u32> {
    let mut depth = 0u32;
    let mut seen_l2 = false;
    let mut seen_l3 = false;
    let mut out = Vec::new();
    for name in names {
        let is_l2 = LINK_LAYERS.contains(&name);
        let is_l3 = NETWORK_LAYERS.contains(&name);
        if (is_l2 && (seen_l2 || seen_l3)) || (is_l3 && seen_l3) {
            depth += 1;
            seen_l2 = false;
            seen_l3 = false;
        }
        seen_l2 |= is_l2;
        seen_l3 |= is_l3;
        out.push(depth);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn depths(stack: &str) -> Vec<u32> {
        compute_depths(stack.split(':'))
    }

    #[test]
    fn plain_packet_is_depth_zero() {
        assert_eq!(depths("Ethernet:IPv4:TCP:HTTP"), vec![0, 0, 0, 0]);
    }

    #[test]
    fn vxlan_inner_ethernet_starts_new_depth() {
        assert_eq!(
            depths("Ethernet:IPv4:UDP:VXLAN:Ethernet:IPv4:TCP"),
            vec![0, 0, 0, 0, 1, 1, 1]
        );
    }

    #[test]
    fn gre_inner_ip_starts_new_depth() {
        assert_eq!(depths("Ethernet:IPv4:GRE:IPv4:UDP"), vec![0, 0, 0, 1, 1]);
    }

    #[test]
    fn ip_in_ip() {
        assert_eq!(depths("Ethernet:IPv4:IPv4:ICMP"), vec![0, 0, 1, 1]);
    }

    #[test]
    fn gtpu_without_link_layer() {
        assert_eq!(
            depths("IPv4:UDP:GTPv1-U:IPv4:UDP:DNS"),
            vec![0, 0, 0, 1, 1, 1]
        );
    }

    #[test]
    fn double_encapsulation() {
        assert_eq!(
            depths("Ethernet:IPv4:GRE:IPv4:UDP:VXLAN:Ethernet:IPv6:TCP"),
            vec![0, 0, 0, 1, 1, 1, 2, 2, 2]
        );
    }

    #[test]
    fn empty_input() {
        assert!(compute_depths(std::iter::empty()).is_empty());
    }
}
