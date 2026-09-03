//! Building the SQLite index from a capture.
//!
//! The capture is dissected once, sequentially (the dissector registry keeps
//! TCP reassembly state across packets), and every layer is written to its
//! protocol table.  The database is built in a temporary file next to the
//! target path and renamed into place only after the build completes, so a
//! crash or interruption never leaves a half-written index behind.

use std::collections::HashMap;
use std::ops::ControlFlow;
use std::path::{Path, PathBuf};
use std::time::Instant;

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::DissectBuffer;
use rusqlite::{Connection, params_from_iter};

use super::ddl::{self, TableSpec};
use super::depth::compute_depths;
use super::flows::{self, FlowTracker, PacketInfo, Transport};
use super::meta::{self, IndexMeta};
use super::value::{self, SqlValue};
use crate::decode_as;
use crate::error::{DsctError, Result, ResultExt};
use crate::esp_sa;
use crate::input::CaptureReader;
use crate::serialize::format_timestamp;

/// Options for [`build_index`].
#[derive(Debug, Clone)]
pub struct IndexOptions<'a> {
    /// Capture file path, or `-` for stdin.
    pub capture: &'a Path,
    /// Destination database path.
    pub db_path: &'a Path,
    /// `--decode-as` arguments.
    pub decode_as: &'a [String],
    /// `--esp-sa` arguments.
    pub esp_sa: &'a [String],
    /// Emit a progress callback every N packets (0 = never).
    pub progress_interval: u64,
    /// Abort the build (with an error) once this instant has passed.
    pub deadline: Option<Instant>,
}

/// Summary of a completed build.
#[derive(Debug, Clone, PartialEq)]
pub struct BuildOutcome {
    /// Packets stored.
    pub packets: u64,
    /// Flows stored.
    pub flows: u64,
    /// Wall-clock build time in seconds.
    pub elapsed_secs: f64,
}

/// Temporary path used while building `db_path`.
fn temp_path(db_path: &Path) -> PathBuf {
    let mut name = db_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(format!(".tmp-{}", std::process::id()));
    db_path.with_file_name(name)
}

/// Build the index for `opts.capture` at `opts.db_path`, replacing any
/// existing file.
///
/// `warn` receives per-packet dissection warnings; `progress` is invoked
/// every `progress_interval` packets with the number processed so far.
pub fn build_index(
    opts: &IndexOptions<'_>,
    warn: &mut dyn FnMut(u64, &str),
    progress: &mut dyn FnMut(u64),
) -> Result<BuildOutcome> {
    let start = Instant::now();

    let mut registry = DissectorRegistry::default();
    decode_as::parse_and_apply(&mut registry, opts.decode_as).invalid_argument()?;
    esp_sa::parse_and_apply(&registry, opts.esp_sa).invalid_argument()?;
    let index_meta = IndexMeta::for_capture(opts.capture, &registry, opts.decode_as, opts.esp_sa)?;
    let tables = ddl::protocol_tables(&registry);

    // Open the capture before touching the filesystem so that a missing
    // capture is reported without leaving a temporary database behind.
    let reader = CaptureReader::open(opts.capture).context("failed to open capture file")?;

    let tmp = temp_path(opts.db_path);
    if tmp.exists() {
        std::fs::remove_file(&tmp).context(format!(
            "failed to remove stale temp file: {}",
            tmp.display()
        ))?;
    }
    let conn = Connection::open(&tmp).context(format!(
        "failed to create index database: {}",
        tmp.display()
    ))?;

    let result = build_into(
        &conn,
        &registry,
        &tables,
        &index_meta,
        reader,
        opts,
        warn,
        progress,
    );
    let close_result = conn.close().map_err(|(_, e)| e);

    let (packets, flow_count) =
        match result.and_then(|counts| close_result.map(|()| counts).map_err(Into::into)) {
            Ok(counts) => counts,
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                return Err(e);
            }
        };

    if let Err(e) = std::fs::rename(&tmp, opts.db_path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(DsctError::from(e).context(format!(
            "failed to move index into place: {}",
            opts.db_path.display()
        )));
    }

    Ok(BuildOutcome {
        packets,
        flows: flow_count,
        elapsed_secs: start.elapsed().as_secs_f64(),
    })
}

/// Convert a stored value into JSON for the `extra` column.
fn sql_value_to_json(v: &SqlValue, container: bool) -> serde_json::Value {
    match v {
        SqlValue::Null => serde_json::Value::Null,
        SqlValue::Integer(i) => serde_json::Value::from(*i),
        SqlValue::Real(f) => serde_json::Value::from(*f),
        SqlValue::Text(s) if container => {
            serde_json::from_str(s).unwrap_or_else(|_| serde_json::Value::String(s.clone()))
        }
        SqlValue::Text(s) => serde_json::Value::String(s.clone()),
        SqlValue::Blob(b) => serde_json::Value::String(value::hex_string(b)),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_into(
    conn: &Connection,
    registry: &DissectorRegistry,
    tables: &[TableSpec],
    index_meta: &IndexMeta,
    reader: CaptureReader,
    opts: &IndexOptions<'_>,
    warn: &mut dyn FnMut(u64, &str),
    progress: &mut dyn FnMut(u64),
) -> Result<(u64, u64)> {
    conn.execute_batch(
        "PRAGMA journal_mode = OFF;
         PRAGMA synchronous = OFF;
         PRAGMA temp_store = MEMORY;
         PRAGMA cache_size = -65536;
         PRAGMA locking_mode = EXCLUSIVE;",
    )?;
    conn.set_prepared_statement_cache_capacity(tables.len() + 16);
    ddl::create_schema(conn, tables)?;
    meta::write(conn, index_meta)?;
    conn.execute_batch("BEGIN")?;

    let table_index: HashMap<&'static str, usize> = tables
        .iter()
        .enumerate()
        .map(|(i, t)| (t.protocol, i))
        .collect();
    let insert_sql: Vec<String> = tables.iter().map(TableSpec::insert_sql).collect();

    let mut tracker = FlowTracker::new();
    let mut dissect_buf = DissectBuffer::new();
    let mut values: Vec<SqlValue> = Vec::new();
    let mut scratch: Vec<u8> = Vec::with_capacity(1024);
    let mut stack = String::with_capacity(64);
    let mut packets_processed = 0u64;
    let progress_interval = opts.progress_interval;
    let deadline = opts.deadline;

    reader.for_each_packet(|pkt_meta, data| {
        packets_processed += 1;
        if progress_interval > 0 && packets_processed.is_multiple_of(progress_interval) {
            progress(packets_processed);
        }
        // Amortise the clock read: check the deadline every 1024 packets.
        if let Some(deadline) = deadline
            && packets_processed.is_multiple_of(1024)
            && Instant::now() > deadline
        {
            return Err(DsctError::msg(format!(
                "index build timed out after {packets_processed} packets"
            )));
        }
        let ts = pkt_meta.timestamp_secs as f64 + f64::from(pkt_meta.timestamp_usecs) / 1_000_000.0;
        let timestamp = format_timestamp(pkt_meta.timestamp_secs, pkt_meta.timestamp_usecs);

        let buf = dissect_buf.clear_into();
        if let Err(e) = registry.dissect_with_link_type(data, pkt_meta.link_type, buf) {
            let msg = e.to_string();
            warn(pkt_meta.number, &msg);
            conn.prepare_cached(
                "INSERT INTO packets (number, ts_secs, ts_usecs, timestamp, ts, captured_length, \
                 original_length, link_type, stack, layer_count, max_depth, dissect_error) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, '', 0, 0, ?9)",
            )?
            .execute((
                SqlValue::from(pkt_meta.number),
                SqlValue::from(pkt_meta.timestamp_secs),
                SqlValue::from(pkt_meta.timestamp_usecs),
                SqlValue::Text(timestamp),
                SqlValue::Real(ts),
                SqlValue::from(pkt_meta.captured_length),
                SqlValue::from(pkt_meta.original_length),
                SqlValue::from(pkt_meta.link_type),
                SqlValue::Text(msg),
            ))?;
            return Ok(ControlFlow::Continue(()));
        }

        let layers = buf.layers();
        let depths = compute_depths(layers.iter().map(|l| l.name));
        stack.clear();
        for (i, layer) in layers.iter().enumerate() {
            if i > 0 {
                stack.push(':');
            }
            stack.push_str(layer.protocol_name());
        }
        conn.prepare_cached(
            "INSERT INTO packets (number, ts_secs, ts_usecs, timestamp, ts, captured_length, \
             original_length, link_type, stack, layer_count, max_depth, dissect_error) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL)",
        )?
        .execute((
            SqlValue::from(pkt_meta.number),
            SqlValue::from(pkt_meta.timestamp_secs),
            SqlValue::from(pkt_meta.timestamp_usecs),
            SqlValue::Text(timestamp),
            SqlValue::Real(ts),
            SqlValue::from(pkt_meta.captured_length),
            SqlValue::from(pkt_meta.original_length),
            SqlValue::from(pkt_meta.link_type),
            SqlValue::Text(stack.clone()),
            SqlValue::from(layers.len() as u64),
            SqlValue::from(depths.iter().copied().max().unwrap_or(0)),
        ))?;

        let pkt_info = PacketInfo {
            number: pkt_meta.number,
            ts,
            bytes: u64::from(pkt_meta.original_length),
        };

        for (i, layer) in layers.iter().enumerate() {
            let depth = depths[i];
            conn.prepare_cached(
                "INSERT INTO layers (packet_number, layer_index, depth, protocol, protocol_name, \
                 \"offset\", length) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            )?
            .execute((
                SqlValue::from(pkt_meta.number),
                SqlValue::from(i as u64),
                SqlValue::from(depth),
                SqlValue::from(layer.name),
                SqlValue::from(layer.protocol_name()),
                SqlValue::from(layer.range.start as u64),
                SqlValue::from(layer.range.len() as u64),
            ))?;

            let Some(&ti) = table_index.get(layer.name) else {
                continue;
            };
            let spec = &tables[ti];
            values.clear();
            values.resize(spec.columns.len(), SqlValue::Null);
            values[0] = SqlValue::from(pkt_meta.number);
            values[1] = SqlValue::from(i as u64);
            values[2] = SqlValue::from(depth);

            let fields = buf.layer_fields(layer);
            let mut extra: Option<serde_json::Map<String, serde_json::Value>> = None;
            for f in fields {
                let v = value::field_value(layer.name, f, buf, data, &layer.range, &mut scratch)?;
                match spec.field_columns.get(f.name()) {
                    Some(&ci) if values[ci] == SqlValue::Null => {
                        values[ci] = v;
                        if let Some(&nc) = spec.name_columns.get(f.name()) {
                            values[nc] = value::display_value(f, fields);
                        }
                    }
                    _ => {
                        let container = matches!(
                            f.value,
                            packet_dissector_core::field::FieldValue::Array(_)
                                | packet_dissector_core::field::FieldValue::Object(_)
                        );
                        extra
                            .get_or_insert_with(serde_json::Map::new)
                            .insert(f.name().to_owned(), sql_value_to_json(&v, container));
                    }
                }
            }
            if let Some(extra) = extra {
                values[spec.extra_column] = SqlValue::Text(
                    serde_json::to_string(&serde_json::Value::Object(extra)).unwrap_or_default(),
                );
            }

            if let (Some(fc), Some(transport)) =
                (spec.flow_column, Transport::from_layer_name(layer.name))
            {
                let tcp_stream_id = if transport == Transport::Tcp {
                    flows::field_u32(buf, layer, "stream_id")
                } else {
                    None
                };
                let hit = flows::endpoints(buf, &depths, i).map(|(src, dst)| {
                    tracker.observe(transport, depth, src, dst, &pkt_info, tcp_stream_id)
                });
                if let Some(hit) = hit {
                    values[fc] = SqlValue::from(hit.flow_id);
                    values[fc + 1] = SqlValue::from(u64::from(hit.direction));
                    conn.prepare_cached(
                        "INSERT INTO packet_flows (packet_number, layer_index, flow_id, direction) \
                         VALUES (?1, ?2, ?3, ?4)",
                    )?
                    .execute((
                        SqlValue::from(pkt_meta.number),
                        SqlValue::from(i as u64),
                        SqlValue::from(hit.flow_id),
                        SqlValue::from(u64::from(hit.direction)),
                    ))?;
                }
                if let Some(tc) = spec.tcp_column {
                    let payload_len = flows::tcp_payload_len(buf, &depths, i, data.len());
                    values[tc] = SqlValue::from(payload_len);
                    if let Some(hit) = hit {
                        let seq = flows::field_u32(buf, layer, "seq").unwrap_or(0);
                        let ack = flows::field_u32(buf, layer, "ack").unwrap_or(0);
                        let flags = flows::field_u8(buf, layer, "flags").unwrap_or(0);
                        let r = tracker.tcp_sequence(
                            hit,
                            seq,
                            ack,
                            flags & 0x10 != 0,
                            payload_len,
                            flags & 0x02 != 0,
                            flags & 0x01 != 0,
                        );
                        values[tc + 1] = SqlValue::from(r.seq_rel);
                        values[tc + 2] = SqlValue::from(r.ack_rel);
                        values[tc + 3] = SqlValue::from(r.next_seq);
                    }
                }
            }

            conn.prepare_cached(&insert_sql[ti])?
                .execute(params_from_iter(values.iter()))?;
        }
        Ok(ControlFlow::Continue(()))
    })?;

    let flow_rows = tracker.into_rows();
    let flow_count = flow_rows.len() as u64;
    {
        let mut stmt = conn.prepare(
            "INSERT INTO flows (id, transport, depth, addr_a, port_a, addr_b, port_b, \
             tcp_stream_id, first_packet, last_packet, packets, bytes, first_ts, last_ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        )?;
        for f in &flow_rows {
            stmt.execute((
                SqlValue::from(f.id),
                SqlValue::from(f.transport.as_str()),
                SqlValue::from(f.depth),
                SqlValue::from(f.a.addr.to_string()),
                SqlValue::from(u64::from(f.a.port)),
                SqlValue::from(f.b.addr.to_string()),
                SqlValue::from(u64::from(f.b.port)),
                SqlValue::from(f.tcp_stream_id),
                SqlValue::from(f.first_packet),
                SqlValue::from(f.last_packet),
                SqlValue::from(f.packets),
                SqlValue::from(f.bytes),
                SqlValue::Real(f.first_ts),
                SqlValue::Real(f.last_ts),
            ))?;
        }
    }
    conn.execute_batch("COMMIT")?;
    for stmt in ddl::index_ddl(tables) {
        conn.execute_batch(&stmt)?;
    }
    meta::mark_complete(conn, packets_processed, flow_count)?;
    Ok((packets_processed, flow_count))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Ethernet / IPv4 / UDP frame (42 bytes), same as the CLI tests.
    fn udp_frame() -> Vec<u8> {
        vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x00,
            0x00, 0x01, 0x0A, 0x00, 0x00, 0x02, 0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
        ]
    }

    fn build_pcap(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut pcap = Vec::new();
        pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
        pcap.extend_from_slice(&2u16.to_le_bytes());
        pcap.extend_from_slice(&4u16.to_le_bytes());
        pcap.extend_from_slice(&0i32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&65535u32.to_le_bytes());
        pcap.extend_from_slice(&1u32.to_le_bytes());
        for (i, f) in frames.iter().enumerate() {
            pcap.extend_from_slice(&(i as u32).to_le_bytes());
            pcap.extend_from_slice(&500_000u32.to_le_bytes());
            pcap.extend_from_slice(&(f.len() as u32).to_le_bytes());
            pcap.extend_from_slice(&(f.len() as u32).to_le_bytes());
            pcap.extend_from_slice(f);
        }
        pcap
    }

    fn write_capture(dir: &Path, frames: &[Vec<u8>]) -> PathBuf {
        let path = dir.join("cap.pcap");
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&build_pcap(frames)).unwrap();
        path
    }

    fn build(capture: &Path, db: &Path) -> Result<BuildOutcome> {
        let opts = IndexOptions {
            capture,
            db_path: db,
            decode_as: &[],
            esp_sa: &[],
            progress_interval: 0,
            deadline: None,
        };
        build_index(&opts, &mut |_, _| {}, &mut |_| {})
    }

    #[test]
    fn builds_udp_capture() {
        let dir = tempfile::tempdir().unwrap();
        let cap = write_capture(dir.path(), &[udp_frame(), udp_frame(), udp_frame()]);
        let db = dir.path().join("cap.sqlite");
        let outcome = build(&cap, &db).unwrap();
        assert_eq!(outcome.packets, 3);
        assert_eq!(outcome.flows, 1);
        assert!(db.exists());
        assert!(!temp_path(&db).exists());

        let conn = Connection::open(&db).unwrap();
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM packets", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 3);
        let stack: String = conn
            .query_row("SELECT stack FROM packets WHERE number = 1", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(stack, "Ethernet:IPv4:UDP");
        let layers: i64 = conn
            .query_row("SELECT COUNT(*) FROM layers WHERE depth = 0", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(layers, 9);
        let (src, ttl): (String, i64) = conn
            .query_row(
                "SELECT \"src\", \"ttl\" FROM ipv4 WHERE packet_number = 2",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(src, "10.0.0.1");
        assert_eq!(ttl, 64);
        let (flow_id, direction, dst_port): (i64, i64, i64) = conn
            .query_row(
                "SELECT flow_id, direction, \"dst_port\" FROM udp WHERE packet_number = 3",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(flow_id, 0);
        assert_eq!(direction, 0);
        assert_eq!(dst_port, 4097);
        let (packets, transport): (i64, String) = conn
            .query_row("SELECT packets, transport FROM flows", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(packets, 3);
        assert_eq!(transport, "udp");
        let timestamp: String = conn
            .query_row("SELECT timestamp FROM packets WHERE number = 2", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(timestamp, "1970-01-01T00:00:01.500000Z");
        let stored = meta::read(&conn).unwrap().unwrap();
        assert!(stored.complete);
        assert_eq!(stored.packet_count, 3);
        assert!(check_fresh(&cap, &db));
    }

    fn check_fresh(cap: &Path, db: &Path) -> bool {
        let registry = DissectorRegistry::default();
        let expected = IndexMeta::for_capture(cap, &registry, &[], &[]).unwrap();
        meta::check(db, &expected).unwrap() == meta::Freshness::Fresh
    }

    #[test]
    fn dissect_failure_is_recorded_as_warning() {
        let dir = tempfile::tempdir().unwrap();
        // A frame too short for an Ethernet header.
        let cap = write_capture(dir.path(), &[vec![0u8; 4], udp_frame()]);
        let db = dir.path().join("cap.sqlite");
        let mut warnings = Vec::new();
        let opts = IndexOptions {
            capture: &cap,
            db_path: &db,
            decode_as: &[],
            esp_sa: &[],
            progress_interval: 1,
            deadline: None,
        };
        let mut ticks = 0;
        let outcome = build_index(
            &opts,
            &mut |n, m| warnings.push((n, m.to_owned())),
            &mut |_| ticks += 1,
        )
        .unwrap();
        assert_eq!(outcome.packets, 2);
        assert_eq!(ticks, 2);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].0, 1);
        let conn = Connection::open(&db).unwrap();
        let err: Option<String> = conn
            .query_row(
                "SELECT dissect_error FROM packets WHERE number = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(err.is_some());
        let ok: Option<String> = conn
            .query_row(
                "SELECT dissect_error FROM packets WHERE number = 2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(ok.is_none());
    }

    #[test]
    fn missing_capture_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("cap.sqlite");
        let err = build(&dir.path().join("missing.pcap"), &db).unwrap_err();
        assert_eq!(err.category(), crate::error::ErrorCategory::FileNotFound);
        assert!(!db.exists());
        assert!(!temp_path(&db).exists());
    }

    #[test]
    fn invalid_capture_removes_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let cap = dir.path().join("bad.pcap");
        std::fs::write(&cap, b"not a pcap file at all").unwrap();
        let db = dir.path().join("cap.sqlite");
        let err = build(&cap, &db).unwrap_err();
        assert_eq!(err.category(), crate::error::ErrorCategory::InvalidFormat);
        assert!(!db.exists());
        assert!(!temp_path(&db).exists());
    }

    #[test]
    fn rebuild_replaces_existing_database() {
        let dir = tempfile::tempdir().unwrap();
        let cap = write_capture(dir.path(), &[udp_frame()]);
        let db = dir.path().join("cap.sqlite");
        build(&cap, &db).unwrap();
        let cap2 = write_capture(dir.path(), &[udp_frame(), udp_frame()]);
        let outcome = build(&cap2, &db).unwrap();
        assert_eq!(outcome.packets, 2);
    }

    #[test]
    fn expired_deadline_aborts_build() {
        let dir = tempfile::tempdir().unwrap();
        let frames: Vec<Vec<u8>> = (0..1024).map(|_| udp_frame()).collect();
        let cap = write_capture(dir.path(), &frames);
        let db = dir.path().join("cap.sqlite");
        let opts = IndexOptions {
            capture: &cap,
            db_path: &db,
            decode_as: &[],
            esp_sa: &[],
            progress_interval: 0,
            deadline: Some(Instant::now() - std::time::Duration::from_secs(1)),
        };
        let err = build_index(&opts, &mut |_, _| {}, &mut |_| {}).unwrap_err();
        assert!(err.to_string().contains("timed out"));
        assert!(!db.exists());
        assert!(!temp_path(&db).exists());
    }

    #[test]
    fn invalid_decode_as_is_invalid_argument() {
        let dir = tempfile::tempdir().unwrap();
        let cap = write_capture(dir.path(), &[udp_frame()]);
        let db = dir.path().join("cap.sqlite");
        let bad = vec!["nonsense".to_owned()];
        let opts = IndexOptions {
            capture: &cap,
            db_path: &db,
            decode_as: &bad,
            esp_sa: &[],
            progress_interval: 0,
            deadline: None,
        };
        let err = build_index(&opts, &mut |_, _| {}, &mut |_| {}).unwrap_err();
        assert_eq!(
            err.category(),
            crate::error::ErrorCategory::InvalidArguments
        );
    }
}
