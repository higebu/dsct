//! JSONL output utilities.
//!
//! Provides helpers for writing JSONL-formatted output. Currently only used
//! by the MCP streaming code path; the CLI writes packets directly via
//! [`crate::serialize::write_packet_json`].
