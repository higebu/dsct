//! Resource limits for MCP tool execution.
//!
//! Prevents resource exhaustion when processing large pcap files.
//! All limits are configurable via environment variables.

use std::time::Duration;

use crate::limits::DEFAULT_PACKET_COUNT;

/// Default timeout for heavy tool execution in seconds.
///
/// A 4 GB capture (~40 M packets) needs ~40 s for `stats` and much less for
/// `read` with the default count.  300 s provides ample headroom.
const DEFAULT_TIMEOUT_SECS: u64 = 300;

/// Default write buffer size for stdout (64 KB).
///
/// The MCP server wraps its stdout in a [`std::io::BufWriter`] with this
/// capacity to amortise syscalls when streaming packet data.
const DEFAULT_WRITE_BUFFER_SIZE: usize = 64 * 1024;

/// Default maximum file size (10 GB).
const DEFAULT_MAX_FILE_SIZE: u64 = 10 * 1024 * 1024 * 1024;

/// Resource limits applied to MCP tool execution.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    /// Default packet count when `count` is not specified.
    pub default_packet_count: u64,
    /// Timeout per tool execution.
    pub timeout: Duration,
    /// Write buffer size for stdout (bytes).
    pub write_buffer_size: usize,
    /// Maximum capture file size in bytes.
    pub max_file_size: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            default_packet_count: DEFAULT_PACKET_COUNT,
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            write_buffer_size: DEFAULT_WRITE_BUFFER_SIZE,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
        }
    }
}

impl ResourceLimits {
    /// Build [`ResourceLimits`] from environment variables, falling back to
    /// defaults for any variable that is absent or unparseable.
    ///
    /// | Variable | Default | Description |
    /// |----------|---------|-------------|
    /// | `DSCT_MCP_DEFAULT_COUNT` | 1 000 | Default packet count for read |
    /// | `DSCT_MCP_TIMEOUT` | 300 | Timeout in seconds |
    /// | `DSCT_MCP_WRITE_BUFFER_SIZE` | 65 536 | Stdout write buffer in bytes |
    /// | `DSCT_MCP_MAX_FILE_SIZE` | 10 737 418 240 | Max file size in bytes |
    pub fn from_env() -> Self {
        let defaults = Self::default();
        Self {
            default_packet_count: parse_env("DSCT_MCP_DEFAULT_COUNT")
                .unwrap_or(defaults.default_packet_count),
            timeout: parse_env::<u64>("DSCT_MCP_TIMEOUT")
                .map(Duration::from_secs)
                .unwrap_or(defaults.timeout),
            write_buffer_size: parse_env("DSCT_MCP_WRITE_BUFFER_SIZE")
                .unwrap_or(defaults.write_buffer_size),
            max_file_size: parse_env("DSCT_MCP_MAX_FILE_SIZE").unwrap_or(defaults.max_file_size),
        }
    }
}

/// Parse an environment variable into `T`, returning `None` when absent or
/// unparseable.
fn parse_env<T: std::str::FromStr>(key: &str) -> Option<T> {
    std::env::var(key).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_values() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.default_packet_count, DEFAULT_PACKET_COUNT);
        assert_eq!(limits.timeout, Duration::from_secs(300));
        assert_eq!(limits.write_buffer_size, 64 * 1024);
    }

    #[test]
    fn parse_env_returns_none_for_missing_var() {
        // Use a unique key unlikely to be set in the environment.
        let result = parse_env::<usize>("DSCT_TEST_NONEXISTENT_VAR_12345");
        assert!(result.is_none());
    }

    #[test]
    fn from_env_returns_defaults_in_clean_environment() {
        // In test environments where DSCT_MCP_* vars are not set,
        // from_env() should return the same values as default().
        let limits = ResourceLimits::from_env();
        let defaults = ResourceLimits::default();
        if std::env::var("DSCT_MCP_DEFAULT_COUNT").is_err() {
            assert_eq!(limits.default_packet_count, defaults.default_packet_count);
        }
        if std::env::var("DSCT_MCP_TIMEOUT").is_err() {
            assert_eq!(limits.timeout, defaults.timeout);
        }
    }
}
