//! Output formatting utilities.
//!
//! Currently only JSONL format is supported. The `jsonl` sub-module is
//! retained for the summary writer used by the MCP server, but the CLI
//! writes packets directly via [`crate::serialize::write_packet_json`].

pub mod jsonl;
