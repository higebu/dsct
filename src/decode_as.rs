//! Parse and apply `--decode-as` CLI overrides.
//!
//! Format: `<table>=<port[,port…]>:<protocol>`
//!
//! Examples:
//! - `tcp.port=8080:http`
//! - `tcp.port=8080,8443,9090:http`
//! - `udp.port=5353:dns`

use packet_dissector::registry::DissectorRegistry;

use crate::error::{DsctError, Result};

/// A parsed `--decode-as` directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeAs {
    /// Dispatch table name (`tcp.port` or `udp.port`).
    pub table: String,
    /// One or more port numbers.
    pub ports: Vec<u16>,
    /// Protocol short name (e.g., `http`, `dns`).
    pub protocol: String,
}

impl DecodeAs {
    /// Parse a single `--decode-as` value.
    ///
    /// Accepted format: `<table>=<port[,port…]>:<protocol>`
    pub fn parse(s: &str) -> Result<Self> {
        let (table_ports, protocol) = s.rsplit_once(':').ok_or_else(|| {
            DsctError::invalid_argument(format!("invalid --decode-as format: missing ':' in {s:?}"))
        })?;

        let (table, ports_str) = table_ports.split_once('=').ok_or_else(|| {
            DsctError::invalid_argument(format!("invalid --decode-as format: missing '=' in {s:?}"))
        })?;

        let table = table.trim().to_lowercase();
        let protocol = protocol.trim().to_lowercase();

        if table != "tcp.port" && table != "udp.port" {
            return Err(DsctError::invalid_argument(format!(
                "unsupported decode-as table {table:?}; supported: tcp.port, udp.port"
            )));
        }

        if protocol.is_empty() {
            return Err(DsctError::invalid_argument(format!(
                "invalid --decode-as format: protocol name is empty in {s:?}"
            )));
        }

        let ports: Vec<u16> = ports_str
            .split(',')
            .map(|p| {
                p.trim().parse::<u16>().map_err(|_| {
                    DsctError::invalid_argument(format!("invalid port number {p:?} in {s:?}"))
                })
            })
            .collect::<Result<Vec<_>>>()?;

        if ports.is_empty() {
            return Err(DsctError::invalid_argument(format!(
                "invalid --decode-as format: no ports specified in {s:?}"
            )));
        }

        Ok(Self {
            table,
            ports,
            protocol,
        })
    }
}

/// Parse `--decode-as` arguments and apply them to a registry.
///
/// Dissector instances are created via the registry's factory map, which is
/// populated by [`DissectorRegistry::default()`] for all port-dispatched
/// protocols.  This eliminates the need for a separate hard-coded mapping.
pub fn parse_and_apply(registry: &mut DissectorRegistry, args: &[String]) -> Result<()> {
    let directives: Vec<DecodeAs> = args
        .iter()
        .map(|s| DecodeAs::parse(s))
        .collect::<Result<Vec<_>>>()?;
    for directive in &directives {
        for &port in &directive.ports {
            let dissector = registry
                .create_dissector_by_name(&directive.protocol)
                .ok_or_else(|| {
                    let available = registry.available_decode_as_protocols();
                    DsctError::invalid_argument(format!(
                        "unknown protocol {:?} in --decode-as; available: {}",
                        directive.protocol,
                        available.join(", ")
                    ))
                })?;
            match directive.table.as_str() {
                "tcp.port" => {
                    registry.register_by_tcp_port_or_replace(port, dissector);
                }
                "udp.port" => {
                    registry.register_by_udp_port_or_replace(port, dissector);
                }
                _ => {
                    return Err(DsctError::invalid_argument(format!(
                        "unsupported decode-as table {:?}",
                        directive.table
                    )));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Parsing tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_single_tcp_port() {
        let d = DecodeAs::parse("tcp.port=8080:http").unwrap();
        assert_eq!(d.table, "tcp.port");
        assert_eq!(d.ports, vec![8080]);
        assert_eq!(d.protocol, "http");
    }

    #[test]
    fn parse_multiple_tcp_ports() {
        let d = DecodeAs::parse("tcp.port=8080,8443,9090:http").unwrap();
        assert_eq!(d.table, "tcp.port");
        assert_eq!(d.ports, vec![8080, 8443, 9090]);
        assert_eq!(d.protocol, "http");
    }

    #[test]
    fn parse_udp_port() {
        let d = DecodeAs::parse("udp.port=5353:dns").unwrap();
        assert_eq!(d.table, "udp.port");
        assert_eq!(d.ports, vec![5353]);
        assert_eq!(d.protocol, "dns");
    }

    #[test]
    fn parse_with_whitespace() {
        let d = DecodeAs::parse("tcp.port = 8080 , 8443 : http").unwrap();
        assert_eq!(d.table, "tcp.port");
        assert_eq!(d.ports, vec![8080, 8443]);
        assert_eq!(d.protocol, "http");
    }

    #[test]
    fn parse_case_insensitive() {
        let d = DecodeAs::parse("TCP.PORT=8080:HTTP").unwrap();
        assert_eq!(d.table, "tcp.port");
        assert_eq!(d.protocol, "http");
    }

    #[test]
    fn parse_error_missing_colon() {
        let err = DecodeAs::parse("tcp.port=8080").unwrap_err();
        assert!(err.to_string().contains("missing ':'"));
    }

    #[test]
    fn parse_error_missing_equals() {
        let err = DecodeAs::parse("tcp.port:http").unwrap_err();
        assert!(err.to_string().contains("missing '='"));
    }

    #[test]
    fn parse_error_unsupported_table() {
        let err = DecodeAs::parse("sctp.port=80:http").unwrap_err();
        assert!(err.to_string().contains("unsupported"));
    }

    #[test]
    fn parse_error_invalid_port() {
        let err = DecodeAs::parse("tcp.port=abc:http").unwrap_err();
        assert!(err.to_string().contains("invalid port"));
    }

    #[test]
    fn parse_error_empty_protocol() {
        let err = DecodeAs::parse("tcp.port=80:").unwrap_err();
        assert!(err.to_string().contains("protocol name is empty"));
    }

    // -----------------------------------------------------------------------
    // Apply tests
    // -----------------------------------------------------------------------

    #[test]
    fn apply_tcp_port_override() {
        let mut registry = DissectorRegistry::default();
        assert!(registry.get_by_tcp_port(8080).is_none());

        let args = vec!["tcp.port=8080:http".to_string()];
        parse_and_apply(&mut registry, &args).unwrap();

        assert_eq!(registry.get_by_tcp_port(8080).unwrap().short_name(), "HTTP");
    }

    #[test]
    fn apply_multiple_ports_single_directive() {
        let mut registry = DissectorRegistry::default();

        let args = vec!["tcp.port=8080,8443,9090:http".to_string()];
        parse_and_apply(&mut registry, &args).unwrap();

        assert_eq!(registry.get_by_tcp_port(8080).unwrap().short_name(), "HTTP");
        assert_eq!(registry.get_by_tcp_port(8443).unwrap().short_name(), "HTTP");
        assert_eq!(registry.get_by_tcp_port(9090).unwrap().short_name(), "HTTP");
    }

    #[test]
    fn apply_unknown_protocol_errors() {
        let mut registry = DissectorRegistry::default();
        let args = vec!["tcp.port=8080:nonexistent".to_string()];
        let err = parse_and_apply(&mut registry, &args).unwrap_err();
        assert!(err.to_string().contains("unknown protocol"));
    }

    #[test]
    fn apply_udp_port() {
        let mut registry = DissectorRegistry::default();

        let args = vec!["udp.port=5353:dns".to_string()];
        parse_and_apply(&mut registry, &args).unwrap();

        assert_eq!(registry.get_by_udp_port(5353).unwrap().short_name(), "DNS");
    }

    #[cfg(all(feature = "tls", feature = "tcp"))]
    #[test]
    fn apply_tls_on_nonstandard_port() {
        let mut registry = DissectorRegistry::default();
        let args = vec!["tcp.port=8443:tls".to_string()];
        parse_and_apply(&mut registry, &args).unwrap();
        assert_eq!(registry.get_by_tcp_port(8443).unwrap().short_name(), "TLS");
    }

    #[cfg(all(feature = "sip", feature = "udp"))]
    #[test]
    fn apply_sip_on_nonstandard_port() {
        let mut registry = DissectorRegistry::default();
        let args = vec!["udp.port=5080:sip".to_string()];
        parse_and_apply(&mut registry, &args).unwrap();
        assert_eq!(registry.get_by_udp_port(5080).unwrap().short_name(), "SIP");
    }

    #[test]
    fn apply_override_existing_port() {
        let mut registry = DissectorRegistry::default();
        assert_eq!(registry.get_by_tcp_port(53).unwrap().short_name(), "DNS");

        let args = vec!["tcp.port=53:http".to_string()];
        parse_and_apply(&mut registry, &args).unwrap();

        assert_eq!(registry.get_by_tcp_port(53).unwrap().short_name(), "HTTP");
    }

    #[test]
    fn parse_error_port_overflow() {
        // u16 max is 65535; 99999 should fail.
        let err = DecodeAs::parse("tcp.port=99999:http").unwrap_err();
        assert!(err.to_string().contains("invalid port"));
    }

    #[test]
    fn parse_error_zero_port() {
        // Port 0 is technically valid in u16 but let's verify it parses.
        let d = DecodeAs::parse("tcp.port=0:http").unwrap();
        assert_eq!(d.ports, vec![0]);
    }

    #[test]
    fn parse_extra_colons_uses_last_segment_as_protocol() {
        // rsplit_once(':') splits on the last colon, so "http:extra"
        // yields table_ports="tcp.port=80:http" and protocol="extra".
        // The table_ports then fails at the '=' split since "tcp.port=80:http"
        // has a colon before the '='. Actually, split_once('=') splits on
        // first '=', so table="tcp.port", ports_str="80:http".
        // Port parsing will fail on "80:http".
        let err = DecodeAs::parse("tcp.port=80:http:extra").unwrap_err();
        assert!(err.to_string().contains("invalid port"));
    }
}
