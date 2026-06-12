#![deny(missing_docs)]
#![deny(unsafe_code)]
//! dsct — LLM-friendly packet dissector library.
//!
//! This library crate exposes internal modules so that benchmarks and
//! integration tests can exercise individual components (e.g.
//! `JsonEscapeWriter`, `write_packet_json`) without going through the
//! full CLI or MCP entry-points.
//!
//! All modules are `#[doc(hidden)]` — they are implementation details of the
//! dsct binary and are not intended as a stable public API.

#[doc(hidden)]
pub mod decode_as;
#[doc(hidden)]
pub mod error;
#[doc(hidden)]
pub mod esp_sa;
#[doc(hidden)]
pub mod field_config;
#[doc(hidden)]
pub mod field_format;
#[doc(hidden)]
pub mod filter;
#[doc(hidden)]
pub mod filter_expr;
#[doc(hidden)]
pub mod input;
#[doc(hidden)]
pub mod json_escape;
#[doc(hidden)]
pub mod limits;
#[doc(hidden)]
pub mod mcp;
#[doc(hidden)]
pub mod output;
#[doc(hidden)]
pub mod parallel;
#[doc(hidden)]
pub mod parallel_read;
#[doc(hidden)]
pub mod schema;
#[doc(hidden)]
pub mod serialize;
#[doc(hidden)]
pub mod sql_filter;
#[doc(hidden)]
pub mod stats;
#[cfg(feature = "tui")]
#[doc(hidden)]
pub mod tui;
