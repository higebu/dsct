//! dsct — LLM-friendly packet dissector CLI.

use dsct::decode_as;
use dsct::esp_sa;
use dsct::field_config;
use dsct::filter;
use dsct::filter_expr;
use dsct::input;
use dsct::limits;
use dsct::mcp;
use dsct::schema;
use dsct::serialize;
use dsct::stats;

use std::io::{self, Write};
use std::ops::ControlFlow;
use std::path::PathBuf;
use std::process;
use std::time::Instant;

use clap::{Parser, Subcommand};
use packet_dissector::registry::DissectorRegistry;

use crate::field_config::FieldConfig;
use crate::filter::{PacketNumberFilter, normalize_protocol_name};
use crate::filter_expr::FilterExpr;
use crate::input::CaptureReader;
use crate::serialize::write_packet_json;
use dsct::error::{DsctError, Result, ResultExt, format_error};

/// LLM-friendly packet dissector CLI.
#[derive(Parser)]
#[command(name = "dsct", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Options for the `dsct read` command.
#[derive(clap::Args)]
struct ReadOptions {
    /// Path to the pcap/pcapng file (use "-" for stdin).
    file: PathBuf,

    /// Output at most N matching results (after offset and all filters).
    /// Default: 1000. Use --no-limit to read all packets.
    #[arg(short, long)]
    count: Option<u64>,

    /// Read all packets without the default 1000-packet limit.
    #[arg(long, conflicts_with = "count")]
    no_limit: bool,

    /// Skip the first N matching results before output.
    /// Works on filtered results, consistent with --count.
    /// To paginate: --offset 100 --count 50 yields results 101-150.
    #[arg(long)]
    offset: Option<u64>,

    /// Output every Nth matching result for representative sampling.
    /// Applied after --filter and --packet-number, before --offset and --count.
    #[arg(short = 's', long)]
    sample_rate: Option<u64>,

    /// Select specific packets by file packet number (1-based).
    /// Accepts single numbers, ranges, and comma-separated lists.
    /// Examples: "42", "1-100", "1,5,10-20".
    #[arg(short = 'n', long)]
    packet_number: Option<String>,

    /// SQL-style filter expression.
    /// Examples: "tcp", "ipv4.src = '10.0.0.1'",
    /// "tcp AND tcp.dst_port > 1024", "(tcp OR udp) AND NOT dns",
    /// "packet_number BETWEEN 1 AND 100".
    #[arg(short = 'f', long)]
    filter: Option<String>,

    /// Show all fields including low-level details (checksums, header lengths, etc.).
    #[arg(short, long, conflicts_with = "field_config")]
    verbose: bool,

    /// Path to a custom TOML field configuration file.
    /// Overrides the built-in default field visibility settings.
    #[arg(long, conflicts_with = "verbose")]
    field_config: Option<PathBuf>,

    /// Report progress to stderr every N packets (as JSON).
    #[arg(long)]
    progress: Option<u64>,

    /// Override protocol dissection for a port.
    /// Format: `table=port[,port…]:protocol`.
    /// Supported tables: tcp.port, udp.port.
    /// Examples: `tcp.port=8080:http`, `tcp.port=8080,8443:http`, `udp.port=5353:dns`.
    #[arg(short, long = "decode-as", num_args = 1)]
    decode_as: Vec<String>,

    /// ESP Security Association for decryption (repeatable).
    /// Supported formats:
    /// - `spi:null` — no encryption/authentication; ESP payload is not decrypted.
    /// - `spi:enc_algo:enc_key_hex` — AEAD algorithms (e.g. `aes-128-gcm`, `aes-256-gcm`).
    /// - `spi:enc_algo:enc_key_hex:auth_algo:auth_key_hex` — non-AEAD (separate cipher + auth).
    ///
    /// For AEAD algorithms, `enc_key_hex` must have the correct length for the algorithm and
    /// must include any implicit salt. For AES-GCM in IPsec this means key + 4-byte salt:
    /// 20 bytes for `aes-128-gcm` and 36 bytes for `aes-256-gcm`.
    ///
    /// Examples:
    /// - `0xDEADBEEF:null`
    /// - `0x1234:aes-128-gcm:0x00112233445566778899AABBCCDDEEFF00112233`
    /// - `0x1234:aes-256-cbc:0xKEY:hmac-sha1-96:0xKEY`
    #[arg(long = "esp-sa", num_args = 1)]
    esp_sa: Vec<String>,

    /// Include the original packet bytes (link-layer included) as a
    /// lowercase hex string under the `raw_bytes` field of each record.
    #[arg(long)]
    raw_bytes: bool,
}

/// Options for the `dsct stats` command.
#[derive(clap::Args)]
struct StatsOptions {
    /// Path to the pcap/pcapng file (use "-" for stdin).
    file: PathBuf,

    /// Enable protocol-specific deep statistics. When omitted, only the
    /// basic overview is shown. Example: -p dns -p tcp.
    #[arg(short, long)]
    protocol: Vec<String>,

    /// Show top IP pairs by traffic volume.
    #[arg(long)]
    top_talkers: bool,

    /// Show per-stream summary (TCP streams; if no -p is given, TCP is enabled automatically).
    #[arg(long)]
    stream_summary: bool,

    /// Maximum number of entries in ranked lists (default: 10).
    #[arg(long, default_value = "10")]
    top: usize,

    /// Report progress to stderr every N packets (as JSON).
    #[arg(long)]
    progress: Option<u64>,

    /// Override protocol dissection for a port.
    /// Format: `table=port[,port…]:protocol`.
    /// Supported tables: tcp.port, udp.port.
    /// Examples: `tcp.port=8080:http`, `tcp.port=8080,8443:http`, `udp.port=5353:dns`.
    #[arg(short, long = "decode-as", num_args = 1)]
    decode_as: Vec<String>,
}

#[derive(Subcommand)]
enum Command {
    /// Read and dissect a pcap/pcapng capture file.
    Read(ReadOptions),

    /// Show capture file statistics (protocol counts, timing, optional deep analysis).
    Stats(StatsOptions),

    /// List supported protocols.
    List,

    /// Show available field names for use with --filter.
    Fields {
        /// Show fields only for these protocols (e.g., "dns", "ipv4").
        #[arg(num_args = 0..)]
        protocol: Vec<String>,
    },

    /// Show version and capability information.
    Version,

    /// Show the JSON schema for a command's output.
    Schema {
        /// Command name to show schema for (e.g., "read", "stats").
        command: Option<String>,
    },

    /// Start an MCP (Model Context Protocol) server over stdio.
    Mcp,

    /// Open an interactive TUI for exploring a pcap/pcapng capture file.
    /// Use "-" to read from stdin (live capture mode).
    #[cfg(feature = "tui")]
    Tui {
        /// Path to the pcap/pcapng file, or "-" for stdin.
        file: String,

        /// Override protocol dissection for a port.
        /// Format: `table=port[,port…]:protocol`.
        /// Supported tables: tcp.port, udp.port.
        #[arg(short, long = "decode-as", num_args = 1)]
        decode_as: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Command::Read(opts) => cmd_read(opts),
        Command::Stats(opts) => cmd_stats(opts),
        Command::List => cmd_list(),
        Command::Fields { protocol } => cmd_fields(protocol),
        Command::Version => cmd_version(),
        Command::Schema { command } => cmd_schema(command),
        Command::Mcp => mcp::cmd_mcp(),
        #[cfg(feature = "tui")]
        Command::Tui { file, decode_as } => {
            if file == "-" {
                dsct::tui::run_live(decode_as)
            } else {
                dsct::tui::run(PathBuf::from(file), decode_as)
            }
        }
    };

    if let Err(e) = result {
        let code = exit_code_for_error(&e);
        emit_error(&e);
        process::exit(code);
    }
}

// ---------------------------------------------------------------------------
// Error handling helpers
// ---------------------------------------------------------------------------

/// Classify an error into a process exit code.
fn exit_code_for_error(e: &DsctError) -> i32 {
    e.category().exit_code()
}

/// Emit an error message to stderr as structured JSON.
fn emit_error(e: &DsctError) {
    let code = classify_error_code(e);
    let msg = format_error(e);
    // Errors writing to stderr are intentionally ignored; there is no fallback error channel.
    let _ = serde_json::to_writer(
        io::stderr(),
        &serde_json::json!({"error": {"code": code, "message": msg}}),
    );
    eprintln!();
}

/// Classify an error into a short machine-readable code string.
fn classify_error_code(e: &DsctError) -> &'static str {
    e.category().code()
}

/// Emit a per-packet warning to stderr as structured JSON.
fn emit_warning(packet_number: u64, message: &str) {
    let _ = serde_json::to_writer(
        io::stderr(),
        &serde_json::json!({"warning": {"packet": packet_number, "message": message}}),
    );
    eprintln!();
}

/// Emit a progress report to stderr.
fn emit_progress(packets_processed: u64, packets_written: u64, elapsed: &Instant) {
    let secs = elapsed.elapsed().as_secs_f64();
    let _ = serde_json::to_writer(
        io::stderr(),
        &serde_json::json!({
            "progress": {
                "packets_processed": packets_processed,
                "packets_written": packets_written,
                "elapsed_secs": (secs * 10.0).round() / 10.0,
            }
        }),
    );
    eprintln!();
}

/// Emit a truncation warning when the default packet limit is reached.
fn emit_truncation_warning(limit: u64) {
    let message = format!(
        "output truncated at default limit of {limit} packets; \
         use --count N or --no-limit to override"
    );
    let _ = serde_json::to_writer(
        io::stderr(),
        &serde_json::json!({"warning": {"message": message, "code": "default_limit_reached"}}),
    );
    eprintln!();
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

fn cmd_read(opts: ReadOptions) -> Result<()> {
    let ReadOptions {
        file,
        count,
        no_limit,
        offset,
        sample_rate,
        packet_number,
        filter: filter_str,
        verbose,
        field_config: field_config_path,
        progress,
        decode_as: decode_as_args,
        esp_sa: esp_sa_args,
        raw_bytes,
    } = opts;
    // Resolve effective count: explicit --count, default limit, or unlimited.
    let (count, is_default_limit) = if no_limit {
        (None, false)
    } else if let Some(c) = count {
        (Some(c), false)
    } else {
        (Some(limits::DEFAULT_PACKET_COUNT), true)
    };
    let field_config = if verbose {
        None
    } else if let Some(path) = field_config_path {
        Some(FieldConfig::from_path(&path)?)
    } else {
        Some(FieldConfig::default_config()?)
    };

    let mut registry = DissectorRegistry::default();
    decode_as::parse_and_apply(&mut registry, &decode_as_args).invalid_argument()?;
    esp_sa::parse_and_apply(&registry, &esp_sa_args).invalid_argument()?;

    let sample_rate = match sample_rate {
        Some(0) => {
            return Err(DsctError::invalid_argument(
                "--sample-rate must be at least 1",
            ));
        }
        Some(r) => r,
        None => 1,
    };
    let offset = offset.unwrap_or(0);
    let pn_filter = packet_number
        .as_deref()
        .map(PacketNumberFilter::parse)
        .transpose()
        .context("invalid --packet-number expression")
        .invalid_argument()?;
    let pn_max = pn_filter.as_ref().and_then(PacketNumberFilter::max);

    // Parse filter expression
    let filter_expr = match filter_str.as_deref() {
        Some(s) => FilterExpr::parse(s).map_err(DsctError::invalid_argument)?,
        None => None,
    };

    let is_stdin = file.as_os_str() == "-";
    let stdout = io::stdout();
    let mut writer: Box<dyn Write> = if is_stdin {
        Box::new(io::LineWriter::new(stdout.lock()))
    } else {
        Box::new(io::BufWriter::new(stdout.lock()))
    };

    let mut packets_processed = 0u64;
    let mut packets_written = 0u64;
    let mut filter_matches = 0u64;
    let mut results_matched = 0u64;
    let mut truncated_by_limit = false;
    let start_time = Instant::now();
    // Reusable buffer for JSONL mode: write_packet_json writes many small
    // fragments, so batching them into a Vec<u8> first avoids dynamic dispatch
    // overhead from Box<dyn Write>.
    let mut pkt_buf: Vec<u8> = Vec::with_capacity(4096);

    let reader = CaptureReader::open(&file).context("failed to open capture file")?;

    let mut dissect_buf = packet_dissector_core::packet::DissectBuffer::new();
    reader.for_each_packet(|meta, data| {
        packets_processed += 1;

        // --- progress reporting ---
        if let Some(interval) = progress
            && interval > 0
            && packets_processed.is_multiple_of(interval)
        {
            emit_progress(packets_processed, packets_written, &start_time);
        }

        // --- packet-number filter (pre-dissect, lightweight) ---
        if let Some(ref pnf) = pn_filter
            && !pnf.contains(meta.number)
        {
            // Early exit once we've passed all specified packet numbers.
            if pn_max.is_some_and(|m| meta.number > m) {
                return Ok(ControlFlow::Break(()));
            }
            return Ok(ControlFlow::Continue(()));
        }

        // --- dissect (reuse buffer across packets) ---
        let dissect_buf = dissect_buf.clear_into();
        if let Err(e) = registry.dissect_with_link_type(data, meta.link_type, dissect_buf) {
            emit_warning(meta.number, &format!("{e}"));
            return Ok(ControlFlow::Continue(()));
        }
        let packet = packet_dissector_core::packet::Packet::new(dissect_buf, data);

        // --- apply filter expression ---
        if let Some(ref expr) = filter_expr
            && !expr.matches_with_number(&packet, meta.number)
        {
            return Ok(ControlFlow::Continue(()));
        }

        // --- apply sample rate (every Nth filter-passing packet) ---
        filter_matches += 1;
        if sample_rate > 1 && !(filter_matches - 1).is_multiple_of(sample_rate) {
            return Ok(ControlFlow::Continue(()));
        }

        // --- apply result-based offset (consistent with --count) ---
        results_matched += 1;
        if results_matched <= offset {
            return Ok(ControlFlow::Continue(()));
        }
        // Write to a reusable buffer first, then flush to the writer
        // in a single write_all call.  This avoids per-field dynamic
        // dispatch overhead when the writer is Box<dyn Write>.
        pkt_buf.clear();
        write_packet_json(
            &mut pkt_buf,
            &meta,
            dissect_buf,
            data,
            field_config.as_ref(),
            raw_bytes,
        )?;
        pkt_buf.push(b'\n');
        writer.write_all(&pkt_buf)?;
        packets_written += 1;

        if let Some(max) = count
            && packets_written >= max
        {
            truncated_by_limit = true;
            return Ok(ControlFlow::Break(()));
        }

        Ok(ControlFlow::Continue(()))
    })?;

    // Warn only when the default limit actually truncated output (i.e. the
    // loop broke due to the count limit, not because we reached EOF).
    if is_default_limit && truncated_by_limit {
        emit_truncation_warning(limits::DEFAULT_PACKET_COUNT);
    }

    writer.flush()?;

    Ok(())
}

/// Determine which protocol-specific collectors to enable based on the `-p` flags.
///
/// Build [`stats::StatsFlags`] from CLI arguments.
fn build_stats_flags(
    protocols: &[String],
    stream_summary: bool,
    top_talkers: bool,
) -> stats::StatsFlags {
    let proto_norm: Vec<String> = protocols
        .iter()
        .map(|p| normalize_protocol_name(p))
        .collect();
    let enable_tcp_streams =
        stream_summary && (proto_norm.is_empty() || proto_norm.iter().any(|p| p == "tcp"));
    stats::StatsFlags::from_protocols(&proto_norm, top_talkers, enable_tcp_streams)
}

fn cmd_stats(opts: StatsOptions) -> Result<()> {
    let StatsOptions {
        file,
        protocol: protocols,
        top_talkers,
        stream_summary,
        top: top_n,
        progress,
        decode_as: decode_as_args,
    } = opts;
    let mut registry = DissectorRegistry::default();
    decode_as::parse_and_apply(&mut registry, &decode_as_args).invalid_argument()?;

    let start_time = Instant::now();

    let flags = build_stats_flags(&protocols, stream_summary, top_talkers);
    let mut collector = stats::StatsCollector::from_flags(&flags);

    let reader = CaptureReader::open(&file).context("failed to open capture file")?;

    let mut total_processed = 0u64;
    let mut dissect_buf = packet_dissector_core::packet::DissectBuffer::new();
    reader.for_each_packet(|meta, data| {
        total_processed += 1;

        if let Some(interval) = progress
            && interval > 0
            && total_processed.is_multiple_of(interval)
        {
            emit_progress(total_processed, 0, &start_time);
        }

        collector.record_meta(meta.timestamp_secs, meta.timestamp_usecs);

        let dissect_buf = dissect_buf.clear_into();
        if let Err(e) = registry.dissect_with_link_type(data, meta.link_type, dissect_buf) {
            emit_warning(meta.number, &format!("{e}"));
        } else {
            let packet = packet_dissector_core::packet::Packet::new(dissect_buf, data);
            collector.process_packet(
                &packet,
                meta.timestamp_secs,
                meta.timestamp_usecs,
                meta.original_length,
            );
        }

        Ok(ControlFlow::Continue(()))
    })?;

    let output = collector.finalize(top_n);

    let stdout = io::stdout();
    let mut writer = io::BufWriter::new(stdout.lock());

    serde_json::to_writer(&mut writer, &output)?;
    writeln!(writer)?;

    writer.flush()?;
    Ok(())
}

fn cmd_fields(protocol_filter: Vec<String>) -> Result<()> {
    let registry = DissectorRegistry::default();
    let schemas = registry.all_field_schemas();

    let filter_norm: Vec<String> = protocol_filter
        .iter()
        .map(|s| normalize_protocol_name(s))
        .collect();

    let mut entries = Vec::new();
    for s in &schemas {
        let short = normalize_protocol_name(s.short_name);
        if !filter_norm.is_empty() && !filter_norm.contains(&short) {
            continue;
        }
        for fd in s.fields {
            entries.push(schema::fd_to_json(fd, s.short_name, s.short_name, s.name));
        }
    }
    println!("{}", serde_json::to_string(&entries)?);

    Ok(())
}

fn cmd_list() -> Result<()> {
    let registry = DissectorRegistry::default();
    let schemas = registry.all_field_schemas();

    let entries: Vec<serde_json::Value> = schemas
        .iter()
        .map(|s| {
            serde_json::json!({
                "name": s.short_name,
                "full_name": s.name,
            })
        })
        .collect();
    println!("{}", serde_json::to_string(&entries)?);

    Ok(())
}

fn cmd_version() -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");

    let registry = DissectorRegistry::default();
    let schemas = registry.all_field_schemas();
    let protocol_names: Vec<&str> = schemas.iter().map(|s| s.short_name).collect();

    let info = serde_json::json!({
        "name": "dsct",
        "version": version,
        "protocols": protocol_names,
        "output_formats": ["jsonl"],
    });
    println!("{}", serde_json::to_string(&info)?);

    Ok(())
}

fn cmd_schema(command: Option<String>) -> Result<()> {
    let cmd = command.as_deref().unwrap_or("read");

    let value = match cmd {
        "read" => schema::read_schema(),
        "stats" => schema::stats_schema(),
        other => {
            return Err(DsctError::invalid_argument(format!(
                "unknown command '{other}'. Available: read, stats"
            )));
        }
    };
    println!("{}", serde_json::to_string_pretty(&value)?);

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exit_code_for_io_not_found() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err = DsctError::from(io_err);
        assert_eq!(exit_code_for_error(&err), 3);
    }

    #[test]
    fn test_exit_code_for_io_permission_denied() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err = DsctError::from(io_err);
        assert_eq!(exit_code_for_error(&err), 3);
    }

    #[test]
    fn test_exit_code_for_generic_error() {
        let err = DsctError::msg("something went wrong");
        assert_eq!(exit_code_for_error(&err), 1);
    }

    #[test]
    fn test_exit_code_for_invalid_arguments() {
        let err = DsctError::invalid_argument("invalid --decode-as value");
        assert_eq!(exit_code_for_error(&err), 2);
    }

    #[test]
    fn test_classify_error_code_not_found() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let err = DsctError::from(io_err);
        assert_eq!(classify_error_code(&err), "file_not_found");
    }

    #[test]
    fn test_classify_error_code_permission_denied() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let err = DsctError::from(io_err);
        assert_eq!(classify_error_code(&err), "permission_denied");
    }

    #[test]
    fn test_classify_error_code_generic() {
        let err = DsctError::msg("generic error");
        assert_eq!(classify_error_code(&err), "error");
    }

    #[test]
    fn test_cmd_schema_read() {
        let result = cmd_schema(Some("read".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_schema_stats() {
        let result = cmd_schema(Some("stats".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_schema_default() {
        let result = cmd_schema(None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_schema_unknown() {
        let result = cmd_schema(Some("nonexistent".to_string()));
        assert!(result.is_err());
    }

    #[test]
    fn test_cmd_version() {
        let result = cmd_version();
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_list() {
        let result = cmd_list();
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_list_contains_expected_protocols() {
        let registry = DissectorRegistry::default();
        let schemas = registry.all_field_schemas();
        let names: Vec<&str> = schemas.iter().map(|s| s.short_name).collect();
        for expected in ["HTTP", "BGP", "DNS", "TCP", "NTP", "BFD"] {
            assert!(
                names.contains(&expected),
                "{expected} must appear in protocol list"
            );
        }
    }

    #[test]
    fn test_cmd_fields() {
        let result = cmd_fields(vec![]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_cmd_fields_filtered() {
        let result = cmd_fields(vec!["dns".to_string()]);
        assert!(result.is_ok());
    }

    // -----------------------------------------------------------------------
    // build_stats_flags tests
    // -----------------------------------------------------------------------

    #[test]
    fn resolve_flags_no_protocols_disables_dns() {
        let f = build_stats_flags(&[], false, false);
        assert!(
            !f.protocols.contains("dns"),
            "DNS deep stats should NOT be enabled by default"
        );
        assert!(!f.tcp_streams);
    }

    #[test]
    fn resolve_flags_explicit_dns() {
        let f = build_stats_flags(&["dns".to_string()], false, false);
        assert!(f.protocols.contains("dns"));
    }

    #[test]
    fn resolve_flags_dns_case_insensitive() {
        let f = build_stats_flags(&["DNS".to_string()], false, false);
        assert!(f.protocols.contains("dns"));
    }

    #[test]
    fn resolve_flags_stream_summary_no_protocol() {
        let f = build_stats_flags(&[], true, false);
        assert!(!f.protocols.contains("dns"));
        assert!(
            f.tcp_streams,
            "TCP streams enabled when --stream-summary and no -p filter"
        );
    }

    #[test]
    fn resolve_flags_stream_summary_with_tcp() {
        let f = build_stats_flags(&["tcp".to_string()], true, false);
        assert!(f.tcp_streams);
    }

    #[test]
    fn resolve_flags_stream_summary_with_dns_only() {
        let f = build_stats_flags(&["dns".to_string()], true, false);
        assert!(f.protocols.contains("dns"));
        assert!(
            !f.tcp_streams,
            "TCP streams not enabled when -p dns and --stream-summary"
        );
    }

    #[test]
    fn resolve_flags_http_tls_dhcp_sip() {
        let f = build_stats_flags(
            &[
                "http".to_string(),
                "tls".to_string(),
                "dhcp".to_string(),
                "sip".to_string(),
            ],
            false,
            true,
        );
        assert!(f.protocols.contains("http"));
        assert!(f.protocols.contains("tls"));
        assert!(f.protocols.contains("dhcp"));
        assert!(f.protocols.contains("sip"));
        assert!(f.top_talkers);
    }
}
