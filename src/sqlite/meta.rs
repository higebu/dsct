//! Index metadata and staleness checks.
//!
//! The `meta` table records how a database was produced.  A database is
//! reused only when every recorded value matches what the current dsct build
//! would produce for the same capture file; otherwise it is rebuilt.

use std::path::Path;

use packet_dissector::registry::DissectorRegistry;
use rusqlite::{Connection, OpenFlags, OptionalExtension};

use super::SCHEMA_VERSION;
use crate::error::{Result, ResultExt};

/// Metadata describing how an index was built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexMeta {
    /// Database layout version ([`SCHEMA_VERSION`]).
    pub schema_version: u32,
    /// dsct version that built the index.
    pub dsct_version: String,
    /// Sorted, comma-separated protocol short names of the build.
    pub protocols: String,
    /// Capture path as given on the command line (informational).
    pub source_path: String,
    /// Capture file size in bytes (`None` for stdin).
    pub source_size: Option<u64>,
    /// Capture modification time in nanoseconds since the epoch (`None` for stdin).
    pub source_mtime_ns: Option<u128>,
    /// `--decode-as` arguments.
    pub decode_as: Vec<String>,
    /// `--esp-sa` arguments.
    pub esp_sa: Vec<String>,
}

/// Sorted, comma-separated list of protocol short names in the registry.
pub fn protocol_list(registry: &DissectorRegistry) -> String {
    let mut names: Vec<&str> = registry
        .all_field_schemas()
        .iter()
        .map(|s| s.short_name)
        .collect();
    names.sort_unstable();
    names.dedup();
    names.join(",")
}

impl IndexMeta {
    /// Metadata the current build would produce for `capture`.
    pub fn for_capture(
        capture: &Path,
        registry: &DissectorRegistry,
        decode_as: &[String],
        esp_sa: &[String],
    ) -> Result<Self> {
        let (source_size, source_mtime_ns) = if capture.as_os_str() == "-" {
            (None, None)
        } else {
            let md = std::fs::metadata(capture).context(format!(
                "failed to stat capture file: {}",
                capture.display()
            ))?;
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_nanos());
            (Some(md.len()), mtime)
        };
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            dsct_version: env!("CARGO_PKG_VERSION").to_owned(),
            protocols: protocol_list(registry),
            source_path: capture.display().to_string(),
            source_size,
            source_mtime_ns,
            decode_as: decode_as.to_vec(),
            esp_sa: esp_sa.to_vec(),
        })
    }

    /// Explain why `stored` does not match `self`, or `None` when it matches.
    ///
    /// `source_path` is informational and never compared.
    pub fn mismatch_reason(&self, stored: &IndexMeta) -> Option<String> {
        if self.schema_version != stored.schema_version {
            return Some(format!(
                "schema version changed ({} -> {})",
                stored.schema_version, self.schema_version
            ));
        }
        if self.dsct_version != stored.dsct_version {
            return Some(format!(
                "dsct version changed ({} -> {})",
                stored.dsct_version, self.dsct_version
            ));
        }
        if self.protocols != stored.protocols {
            return Some("protocol set changed".to_owned());
        }
        if self.source_size != stored.source_size || self.source_mtime_ns != stored.source_mtime_ns
        {
            return Some("capture file changed (size or modification time)".to_owned());
        }
        if self.decode_as != stored.decode_as {
            return Some("--decode-as options changed".to_owned());
        }
        if self.esp_sa != stored.esp_sa {
            return Some("--esp-sa options changed".to_owned());
        }
        None
    }
}

/// Metadata read back from an existing database.
#[derive(Debug, Clone, PartialEq)]
pub struct StoredMeta {
    /// Build metadata.
    pub meta: IndexMeta,
    /// Whether the build finished.
    pub complete: bool,
    /// Number of packets stored (0 when incomplete).
    pub packet_count: u64,
    /// Number of flows stored (0 when incomplete).
    pub flow_count: u64,
}

fn put(conn: &Connection, key: &str, value: &str) -> rusqlite::Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO meta (key, value) VALUES (?1, ?2)",
        (key, value),
    )?;
    Ok(())
}

fn get(conn: &Connection, key: &str) -> rusqlite::Result<Option<String>> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        .optional()
}

/// Write build metadata (without marking the index complete).
pub fn write(conn: &Connection, meta: &IndexMeta) -> rusqlite::Result<()> {
    put(conn, "schema_version", &meta.schema_version.to_string())?;
    put(conn, "dsct_version", &meta.dsct_version)?;
    put(conn, "protocols", &meta.protocols)?;
    put(conn, "source_path", &meta.source_path)?;
    put(
        conn,
        "source_size",
        &meta.source_size.map_or(String::new(), |v| v.to_string()),
    )?;
    put(
        conn,
        "source_mtime_ns",
        &meta
            .source_mtime_ns
            .map_or(String::new(), |v| v.to_string()),
    )?;
    put(
        conn,
        "decode_as",
        &serde_json::to_string(&meta.decode_as).unwrap_or_default(),
    )?;
    put(
        conn,
        "esp_sa",
        &serde_json::to_string(&meta.esp_sa).unwrap_or_default(),
    )?;
    put(conn, "complete", "0")?;
    Ok(())
}

/// Record the final counts and mark the index complete.
pub fn mark_complete(
    conn: &Connection,
    packet_count: u64,
    flow_count: u64,
) -> rusqlite::Result<()> {
    put(conn, "packet_count", &packet_count.to_string())?;
    put(conn, "flow_count", &flow_count.to_string())?;
    put(conn, "complete", "1")?;
    Ok(())
}

/// Read metadata from a database; `None` when it has no `meta` table.
pub fn read(conn: &Connection) -> rusqlite::Result<Option<StoredMeta>> {
    let has_meta: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'meta'",
        [],
        |r| r.get(0),
    )?;
    if has_meta == 0 {
        return Ok(None);
    }
    let parse_list = |s: Option<String>| -> Vec<String> {
        s.and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    };
    let meta = IndexMeta {
        schema_version: get(conn, "schema_version")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        dsct_version: get(conn, "dsct_version")?.unwrap_or_default(),
        protocols: get(conn, "protocols")?.unwrap_or_default(),
        source_path: get(conn, "source_path")?.unwrap_or_default(),
        source_size: get(conn, "source_size")?.and_then(|s| s.parse().ok()),
        source_mtime_ns: get(conn, "source_mtime_ns")?.and_then(|s| s.parse().ok()),
        decode_as: parse_list(get(conn, "decode_as")?),
        esp_sa: parse_list(get(conn, "esp_sa")?),
    };
    let complete = get(conn, "complete")?.as_deref() == Some("1");
    let packet_count = get(conn, "packet_count")?
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let flow_count = get(conn, "flow_count")?
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok(Some(StoredMeta {
        meta,
        complete,
        packet_count,
        flow_count,
    }))
}

/// Result of a staleness check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Freshness {
    /// The database exists and matches `expected`.
    Fresh,
    /// No database exists at the path.
    Missing,
    /// The database exists but must be rebuilt, with the reason.
    Stale(String),
}

/// Check whether the database at `db_path` can be reused for `expected`.
pub fn check(db_path: &Path, expected: &IndexMeta) -> Result<Freshness> {
    if !db_path.exists() {
        return Ok(Freshness::Missing);
    }
    if !super::is_sqlite_file(db_path)? {
        return Ok(Freshness::Stale(
            "existing file is not a SQLite database".into(),
        ));
    }
    let conn = Connection::open_with_flags(
        db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let stored = match read(&conn) {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(Freshness::Stale("not a dsct index (no meta table)".into())),
        Err(e) => return Ok(Freshness::Stale(format!("unreadable index metadata: {e}"))),
    };
    if !stored.complete {
        return Ok(Freshness::Stale("previous build did not complete".into()));
    }
    Ok(match expected.mismatch_reason(&stored.meta) {
        Some(reason) => Freshness::Stale(reason),
        None => Freshness::Fresh,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_meta() -> IndexMeta {
        IndexMeta {
            schema_version: SCHEMA_VERSION,
            dsct_version: "1.2.3".into(),
            protocols: "IPv4,TCP".into(),
            source_path: "/tmp/a.pcap".into(),
            source_size: Some(10),
            source_mtime_ns: Some(20),
            decode_as: vec!["tcp.port=8080:http".into()],
            esp_sa: vec![],
        }
    }

    #[test]
    fn write_and_read_round_trip() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            .unwrap();
        let meta = sample_meta();
        write(&conn, &meta).unwrap();
        let stored = read(&conn).unwrap().unwrap();
        assert_eq!(stored.meta, meta);
        assert!(!stored.complete);
        mark_complete(&conn, 42, 3).unwrap();
        let stored = read(&conn).unwrap().unwrap();
        assert!(stored.complete);
        assert_eq!(stored.packet_count, 42);
        assert_eq!(stored.flow_count, 3);
    }

    #[test]
    fn read_without_meta_table() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(read(&conn).unwrap().is_none());
    }

    #[test]
    fn mismatch_reasons() {
        let a = sample_meta();
        assert!(a.mismatch_reason(&a).is_none());

        let mut b = a.clone();
        b.source_path = "/elsewhere.pcap".into();
        assert!(a.mismatch_reason(&b).is_none(), "path is informational");

        b = a.clone();
        b.source_size = Some(11);
        assert!(
            a.mismatch_reason(&b)
                .unwrap()
                .contains("capture file changed")
        );

        b = a.clone();
        b.dsct_version = "0.0.1".into();
        assert!(a.mismatch_reason(&b).unwrap().contains("dsct version"));

        b = a.clone();
        b.protocols = "TCP".into();
        assert!(a.mismatch_reason(&b).unwrap().contains("protocol set"));

        b = a.clone();
        b.decode_as.clear();
        assert!(a.mismatch_reason(&b).unwrap().contains("decode-as"));

        b = a.clone();
        b.esp_sa.push("x".into());
        assert!(a.mismatch_reason(&b).unwrap().contains("esp-sa"));

        b = a.clone();
        b.schema_version += 1;
        assert!(a.mismatch_reason(&b).unwrap().contains("schema version"));
    }

    #[test]
    fn check_missing_and_garbage() {
        let expected = sample_meta();
        assert_eq!(
            check(Path::new("/nonexistent/x.sqlite"), &expected).unwrap(),
            Freshness::Missing
        );
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"garbage garbage garbage garbage").unwrap();
        assert!(matches!(
            check(tmp.path(), &expected).unwrap(),
            Freshness::Stale(_)
        ));
    }

    #[test]
    fn check_incomplete_and_fresh() {
        let expected = sample_meta();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                .unwrap();
            write(&conn, &expected).unwrap();
        }
        assert!(matches!(
            check(&path, &expected).unwrap(),
            Freshness::Stale(ref r) if r.contains("did not complete")
        ));
        {
            let conn = Connection::open(&path).unwrap();
            mark_complete(&conn, 1, 0).unwrap();
        }
        assert_eq!(check(&path, &expected).unwrap(), Freshness::Fresh);

        let mut other = expected.clone();
        other.source_size = Some(99);
        assert!(matches!(check(&path, &other).unwrap(), Freshness::Stale(_)));
    }

    #[test]
    fn for_capture_reads_file_metadata() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(tmp.path(), b"abc").unwrap();
        let registry = DissectorRegistry::default();
        let meta = IndexMeta::for_capture(tmp.path(), &registry, &[], &[]).unwrap();
        assert_eq!(meta.source_size, Some(3));
        assert!(meta.source_mtime_ns.is_some());
        assert!(meta.protocols.contains("TCP"));
        assert_eq!(meta.schema_version, SCHEMA_VERSION);

        let stdin = IndexMeta::for_capture(Path::new("-"), &registry, &[], &[]).unwrap();
        assert_eq!(stdin.source_size, None);
        assert_eq!(stdin.source_mtime_ns, None);

        assert!(
            IndexMeta::for_capture(Path::new("/nonexistent/cap.pcap"), &registry, &[], &[])
                .is_err()
        );
    }
}
