//! MCP (Model Context Protocol) server for dsct.
//!
//! Exposes packet dissection capabilities as MCP tools over stdio transport.
//! Start with `dsct mcp`.
//!
//! This module currently provides:
//! - `raw_mcp`: Custom minimal server that streams `read_packets` output
//!   incrementally to stdout.

pub mod limits;
pub mod raw_mcp;
mod tools;

use self::limits::ResourceLimits;
use crate::error::Result;

/// Start the MCP server on stdio.
///
/// Uses the custom raw implementation that streams packet data directly to
/// stdout, keeping memory usage bounded regardless of capture size.
pub fn cmd_mcp() -> Result<()> {
    let limits = ResourceLimits::from_env();
    raw_mcp::run(limits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_mcp_uses_default_limits() {
        // Smoke test: ResourceLimits::from_env() doesn't panic.
        let _limits = ResourceLimits::from_env();
    }
}
