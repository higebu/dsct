//! Shared resource-limit constants for CLI and MCP.

/// Default maximum number of packets to output when no explicit count is given.
///
/// 1 000 packets produce ~400 KB of JSON output, which fits comfortably within
/// typical LLM context windows (~100 K tokens).
pub const DEFAULT_PACKET_COUNT: u64 = 1_000;
