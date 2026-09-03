//! Read-only SQL execution and schema discovery.
//!
//! Queries run against a connection opened with `SQLITE_OPEN_READ_ONLY`.  In
//! addition, the statement text must start with `SELECT`, `WITH`, `VALUES`
//! or `EXPLAIN`, SQLite must report it as read-only, and trailing statements
//! are rejected, so the index can never be modified through `dsct sql`.

use std::io::Write;
use std::path::Path;

use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags};

use super::ddl::{self, TableSpec};
use super::meta;
use super::value::hex_string;
use crate::error::{DsctError, Result, ResultExt};
use crate::json_escape::write_json_escaped;

/// Statement keywords accepted by [`validate_query`].
const ALLOWED_KEYWORDS: &[&str] = &["SELECT", "WITH", "VALUES", "EXPLAIN"];

/// Result of [`run_query`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryOutcome {
    /// Rows written to the output.
    pub rows_written: u64,
    /// Whether output stopped because the row limit was reached.
    pub truncated_by_limit: bool,
}

/// Open an index database read-only.
pub fn open_read_only(db_path: &Path) -> Result<Connection> {
    Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .context(format!(
        "failed to open index database: {}",
        db_path.display()
    ))
}

/// Return the first SQL keyword of `sql`, skipping whitespace and comments.
pub fn leading_keyword(sql: &str) -> Option<String> {
    let mut rest = sql;
    loop {
        rest = rest.trim_start();
        if let Some(after) = rest.strip_prefix("--") {
            rest = after.split_once('\n').map_or("", |(_, r)| r);
        } else if let Some(after) = rest.strip_prefix("/*") {
            rest = after.split_once("*/").map_or("", |(_, r)| r);
        } else {
            break;
        }
    }
    let word: String = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if word.is_empty() {
        None
    } else {
        Some(word.to_ascii_uppercase())
    }
}

/// Reject anything that is not a `SELECT`-style query.
pub fn validate_query(sql: &str) -> Result<()> {
    match leading_keyword(sql) {
        Some(kw) if ALLOWED_KEYWORDS.contains(&kw.as_str()) => Ok(()),
        Some(kw) => Err(DsctError::invalid_argument(format!(
            "only SELECT queries are allowed, got '{kw}'"
        ))),
        None => Err(DsctError::invalid_argument("empty SQL query")),
    }
}

/// Write one SQLite value as a JSON token.
fn write_value<W: Write>(w: &mut W, v: ValueRef<'_>) -> Result<()> {
    match v {
        ValueRef::Null => w.write_all(b"null")?,
        ValueRef::Integer(i) => write!(w, "{i}")?,
        ValueRef::Real(f) => {
            if f.is_finite() {
                write!(w, "{f}")?;
            } else {
                w.write_all(b"null")?;
            }
        }
        ValueRef::Text(bytes) => {
            w.write_all(b"\"")?;
            write_json_escaped(w, &String::from_utf8_lossy(bytes))?;
            w.write_all(b"\"")?;
        }
        ValueRef::Blob(bytes) => {
            w.write_all(b"\"")?;
            w.write_all(hex_string(bytes).as_bytes())?;
            w.write_all(b"\"")?;
        }
    }
    Ok(())
}

/// Execute `sql` and write each result row as a JSON object line.
///
/// `limit` caps the number of rows written; reaching it sets
/// [`QueryOutcome::truncated_by_limit`].
pub fn run_query(
    conn: &Connection,
    sql: &str,
    limit: Option<u64>,
    w: &mut dyn Write,
) -> Result<QueryOutcome> {
    validate_query(sql)?;
    let mut stmt = conn
        .prepare(sql)
        .context("invalid SQL query")
        .invalid_argument()?;
    if !stmt.readonly() {
        return Err(DsctError::invalid_argument(
            "only read-only SELECT queries are allowed",
        ));
    }
    let columns: Vec<Vec<u8>> = stmt
        .column_names()
        .iter()
        .map(|name| {
            let mut escaped = Vec::with_capacity(name.len() + 3);
            escaped.push(b'"');
            // Column names are plain identifiers; escaping keeps odd aliases safe.
            let _ = write_json_escaped(&mut escaped, name);
            escaped.extend_from_slice(b"\":");
            escaped
        })
        .collect();

    let mut rows = stmt
        .query([])
        .context("failed to execute SQL query")
        .invalid_argument()?;
    let mut rows_written = 0u64;
    let mut truncated_by_limit = false;
    let mut line: Vec<u8> = Vec::with_capacity(256);
    while let Some(row) = rows.next()? {
        line.clear();
        line.push(b'{');
        for (i, col) in columns.iter().enumerate() {
            if i > 0 {
                line.push(b',');
            }
            line.extend_from_slice(col);
            write_value(&mut line, row.get_ref(i)?)?;
        }
        line.extend_from_slice(b"}\n");
        w.write_all(&line)?;
        rows_written += 1;
        if let Some(max) = limit
            && rows_written >= max
        {
            truncated_by_limit = true;
            break;
        }
    }
    Ok(QueryOutcome {
        rows_written,
        truncated_by_limit,
    })
}

/// Describe the database layout as JSON for `dsct sql --schema`.
///
/// `tables` are the protocol table specifications of the current build,
/// used to attach field descriptions to columns.
pub fn describe_schema(conn: &Connection, tables: &[TableSpec]) -> Result<serde_json::Value> {
    let stored = meta::read(conn)?;
    let mut stmt = conn.prepare(
        "SELECT name, type FROM sqlite_master \
         WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' \
         ORDER BY CASE type WHEN 'table' THEN 0 ELSE 1 END, name",
    )?;
    let objects: Vec<(String, String)> = stmt
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;

    let mut out = Vec::with_capacity(objects.len());
    for (name, kind) in objects {
        let spec = tables.iter().find(|t| t.name == name);
        let mut cols_stmt =
            conn.prepare(&format!("PRAGMA table_info({})", ddl::quote_ident(&name)))?;
        let columns: Vec<serde_json::Value> = cols_stmt
            .query_map([], |r| {
                let col: String = r.get(1)?;
                let ty: String = r.get(2)?;
                Ok((col, ty))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|(col, ty)| {
                let description = spec
                    .and_then(|s| s.columns.iter().find(|c| c.name == col))
                    .map(|c| c.description.clone())
                    .or_else(|| ddl::describe_base_column(&name, &col).map(str::to_owned));
                let mut v = serde_json::json!({ "name": col, "type": ty });
                if let Some(d) = description {
                    v["description"] = serde_json::Value::String(d);
                }
                v
            })
            .collect();
        let mut entry = serde_json::json!({
            "name": name,
            "kind": kind,
            "columns": columns,
        });
        if let Some(s) = spec {
            entry["protocol"] = serde_json::Value::String(s.protocol.to_owned());
            entry["description"] = serde_json::Value::String(format!(
                "One row per {} layer ({})",
                s.protocol, s.protocol_name
            ));
        } else if let Some(d) = describe_object(&name) {
            entry["description"] = serde_json::Value::String(d.to_owned());
        }
        out.push(entry);
    }

    let mut result = serde_json::json!({
        "schema_version": super::SCHEMA_VERSION,
        "tables": out,
        "hints": [
            "Every protocol table has one row per layer keyed by (packet_number, layer_index); join packets ON packets.number = packet_number.",
            "depth = 0 is the outermost packet; tunnelled inner headers (VXLAN, GRE, GTP-U, IP-in-IP, ...) have depth >= 1. Use the encapsulations view to find the carrier protocol.",
            "Follow a conversation with flow_id (tcp/udp/sctp tables, flows, conversations); tcp_segments exposes relative sequence numbers.",
            "Array/Object fields are stored as JSON text: use json_extract(col, '$.name') or json_each(col).",
            "Quote column names that collide with SQL keywords, e.g. \"type\", \"class\", \"group\", \"offset\".",
        ],
    });
    if let Some(s) = stored {
        result["index"] = serde_json::json!({
            "dsct_version": s.meta.dsct_version,
            "source_path": s.meta.source_path,
            "complete": s.complete,
            "packets": s.packet_count,
            "flows": s.flow_count,
            "decode_as": s.meta.decode_as,
            "esp_sa": s.meta.esp_sa,
        });
    }
    Ok(result)
}

/// Description of a base table or view.
fn describe_object(name: &str) -> Option<&'static str> {
    Some(match name {
        "meta" => "Index metadata (key/value)",
        "packets" => "One row per packet with timestamp, lengths and protocol stack",
        "layers" => "One row per dissected layer with encapsulation depth",
        "flows" => "One row per transport conversation (per depth); both directions share an id",
        "packet_flows" => "Maps transport layers to flows with their direction",
        "encapsulations" => "For each tunnelled depth of a packet, the carrier (tunnel) protocol",
        "conversations" => "flows with duration_secs",
        "tcp_segments" => "TCP segments joined with packets, including relative sequence numbers",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCategory;

    fn sample_db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE t (id INTEGER, name TEXT, score REAL, data BLOB, missing TEXT);
             INSERT INTO t VALUES (1, 'a\"b', 1.5, X'DEAD', NULL);
             INSERT INTO t VALUES (2, 'c', 2, X'', 'x');
             INSERT INTO t VALUES (3, 'd', 3, NULL, NULL);",
        )
        .unwrap();
        conn
    }

    fn run(conn: &Connection, sql: &str, limit: Option<u64>) -> (String, Result<QueryOutcome>) {
        let mut out = Vec::new();
        let r = run_query(conn, sql, limit, &mut out);
        (String::from_utf8(out).unwrap(), r)
    }

    #[test]
    fn rows_are_json_lines() {
        let conn = sample_db();
        let (out, r) = run(
            &conn,
            "SELECT id, name, score, data, missing FROM t ORDER BY id",
            None,
        );
        let r = r.unwrap();
        assert_eq!(r.rows_written, 3);
        assert!(!r.truncated_by_limit);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(
            lines[0],
            r#"{"id":1,"name":"a\"b","score":1.5,"data":"dead","missing":null}"#
        );
        assert_eq!(
            lines[1],
            r#"{"id":2,"name":"c","score":2,"data":"","missing":"x"}"#
        );
        let v: serde_json::Value = serde_json::from_str(lines[2]).unwrap();
        assert_eq!(v["id"], 3);
        assert!(v["data"].is_null());
    }

    #[test]
    fn limit_truncates() {
        let conn = sample_db();
        let (out, r) = run(&conn, "SELECT id FROM t", Some(2));
        let r = r.unwrap();
        assert_eq!(r.rows_written, 2);
        assert!(r.truncated_by_limit);
        assert_eq!(out.lines().count(), 2);
    }

    #[test]
    fn write_statements_rejected() {
        let conn = sample_db();
        for sql in [
            "INSERT INTO t VALUES (9, 'z', 0, NULL, NULL)",
            "DROP TABLE t",
            "PRAGMA journal_mode = WAL",
            "ATTACH DATABASE ':memory:' AS x",
            "  -- comment\n /* c */ DELETE FROM t",
            "",
        ] {
            let (_, r) = run(&conn, sql, None);
            let err = r.unwrap_err();
            assert_eq!(err.category(), ErrorCategory::InvalidArguments, "{sql}");
        }
        let n: i64 = conn
            .query_row("SELECT COUNT(*) FROM t", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 3);
    }

    #[test]
    fn multiple_statements_rejected() {
        let conn = sample_db();
        let (_, r) = run(&conn, "SELECT 1; SELECT 2", None);
        assert_eq!(r.unwrap_err().category(), ErrorCategory::InvalidArguments);
    }

    #[test]
    fn syntax_and_unknown_column_errors_are_invalid_arguments() {
        let conn = sample_db();
        let (_, r) = run(&conn, "SELECT nope FROM t", None);
        let err = r.unwrap_err();
        assert_eq!(err.category(), ErrorCategory::InvalidArguments);
        assert!(crate::error::format_error(&err).contains("no such column"));
        let (_, r) = run(&conn, "SELECT FROM WHERE", None);
        assert_eq!(r.unwrap_err().category(), ErrorCategory::InvalidArguments);
    }

    #[test]
    fn with_and_explain_are_allowed() {
        let conn = sample_db();
        let (out, r) = run(
            &conn,
            "WITH x AS (SELECT id FROM t) SELECT COUNT(*) AS n FROM x",
            None,
        );
        assert_eq!(r.unwrap().rows_written, 1);
        assert_eq!(out.trim(), r#"{"n":3}"#);
        let (_, r) = run(&conn, "EXPLAIN QUERY PLAN SELECT id FROM t", None);
        assert!(r.unwrap().rows_written >= 1);
    }

    #[test]
    fn leading_keyword_skips_comments() {
        assert_eq!(leading_keyword("  select 1").as_deref(), Some("SELECT"));
        assert_eq!(
            leading_keyword("-- a\n/* b */\nWITH x AS (SELECT 1) SELECT 1").as_deref(),
            Some("WITH")
        );
        assert_eq!(leading_keyword("/* unterminated"), None);
        assert_eq!(leading_keyword("   "), None);
    }

    #[test]
    fn non_finite_real_is_null() {
        let conn = Connection::open_in_memory().unwrap();
        let (out, r) = run(&conn, "SELECT 1e999 AS inf, 2.5 AS x", None);
        r.unwrap();
        assert_eq!(out.trim(), r#"{"inf":null,"x":2.5}"#);
    }

    #[test]
    fn read_only_open_rejects_writes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.sqlite");
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE t (a)")
            .unwrap();
        let conn = open_read_only(&path).unwrap();
        assert!(conn.execute_batch("INSERT INTO t VALUES (1)").is_err());
        assert!(open_read_only(Path::new("/nonexistent/db.sqlite")).is_err());
    }

    #[test]
    fn describe_schema_lists_tables_and_views() {
        let registry = packet_dissector::registry::DissectorRegistry::default();
        let tables = ddl::protocol_tables(&registry);
        let conn = Connection::open_in_memory().unwrap();
        ddl::create_schema(&conn, &tables).unwrap();
        let schema = describe_schema(&conn, &tables).unwrap();
        let names: Vec<&str> = schema["tables"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        for expected in [
            "packets",
            "layers",
            "flows",
            "tcp",
            "ipv4",
            "encapsulations",
            "tcp_segments",
        ] {
            assert!(names.contains(&expected), "missing {expected}");
        }
        let tcp = schema["tables"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "tcp")
            .unwrap();
        assert_eq!(tcp["kind"], "table");
        assert_eq!(tcp["protocol"], "TCP");
        let cols: Vec<&str> = tcp["columns"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["name"].as_str().unwrap())
            .collect();
        assert!(cols.contains(&"depth"));
        assert!(cols.contains(&"seq_rel"));
        let seq_col = tcp["columns"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "seq")
            .unwrap();
        assert!(seq_col["description"].as_str().unwrap().contains("u32"));
        assert!(schema["hints"].is_array());
        // The meta table exists but nothing was written yet.
        assert_eq!(schema["index"]["complete"], false);
    }
}
