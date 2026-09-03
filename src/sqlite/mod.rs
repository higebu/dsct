//! SQLite index of dissected captures.
//!
//! `dsct index` dissects a capture once and stores the result in a SQLite
//! database; `dsct sql` then answers arbitrary read-only `SELECT` queries
//! against it without re-parsing the capture.
//!
//! The database layout is generated from the dissector field schemas: one
//! wide table per protocol (one row per layer), plus `packets`, `layers`,
//! `flows` and `packet_flows` tables and a few convenience views.  See
//! [`ddl`] for the schema, [`depth`] for encapsulation depth and [`flows`]
//! for stream tracking.

pub mod ddl;
pub mod depth;
pub mod flows;
pub mod ingest;
pub mod meta;
pub mod query;
pub mod value;

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use packet_dissector::registry::DissectorRegistry;

use crate::decode_as;
use crate::error::{DsctError, Result, ResultExt};
use crate::esp_sa;
use ingest::{BuildOutcome, IndexOptions, build_index};
use meta::{Freshness, IndexMeta};

/// Version of the database layout produced by this build of dsct.
///
/// Bump whenever the generated schema changes incompatibly; existing
/// databases with a different version are rebuilt.
pub const SCHEMA_VERSION: u32 = 1;

/// File-name suffix appended to the capture path for the sidecar database.
pub const DB_SUFFIX: &str = ".dsct.sqlite";

/// The 16-byte header every SQLite 3 database starts with.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Default sidecar database path for a capture file (`<capture>.dsct.sqlite`).
pub fn default_db_path(capture: &Path) -> PathBuf {
    let mut name = capture.as_os_str().to_os_string();
    name.push(DB_SUFFIX);
    PathBuf::from(name)
}

/// Return `true` when the file at `path` starts with the SQLite 3 magic header.
///
/// A missing or short file yields `Ok(false)`; other I/O errors propagate.
pub fn is_sqlite_file(path: &Path) -> std::io::Result<bool> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    let mut header = [0u8; 16];
    let mut read = 0;
    while read < header.len() {
        let n = file.read(&mut header[read..])?;
        if n == 0 {
            return Ok(false);
        }
        read += n;
    }
    Ok(&header == SQLITE_MAGIC)
}

/// How to locate (and if needed build) the index for a capture.
#[derive(Debug, Clone)]
pub struct IndexRequest<'a> {
    /// Capture file, `-` for stdin, or an existing dsct SQLite database.
    pub file: &'a Path,
    /// Explicit database path (`--db`).
    pub db: Option<PathBuf>,
    /// Rebuild even when the existing index is fresh.
    pub force: bool,
    /// Fail instead of building when the index is missing or stale.
    pub no_build: bool,
    /// Progress callback interval in packets (0 = never).
    pub progress_interval: u64,
    /// `--decode-as` arguments used when building.
    pub decode_as: &'a [String],
    /// `--esp-sa` arguments used when building.
    pub esp_sa: &'a [String],
    /// Abort a build once this instant has passed.
    pub deadline: Option<Instant>,
}

/// Outcome of [`resolve_index`].
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedIndex {
    /// Database to query.
    pub db_path: PathBuf,
    /// Build summary when a build ran.
    pub build: Option<BuildOutcome>,
    /// Why an existing index was replaced (`None` for a first build or no build).
    pub replaced_reason: Option<String>,
}

/// Locate the index for `req.file`, building it when required.
///
/// - stdin (`-`) always builds into `req.db` (which is required)
/// - a `file` that is itself a SQLite database is used as-is
/// - otherwise the sidecar (or `req.db`) is reused when fresh, rebuilt when
///   missing or stale, or reported as an `invalid_arguments` error under
///   `no_build`
///
/// `warn` and `progress` are forwarded to [`build_index`].
pub fn resolve_index(
    req: &IndexRequest<'_>,
    warn: &mut dyn FnMut(u64, &str),
    progress: &mut dyn FnMut(u64),
) -> Result<ResolvedIndex> {
    let is_stdin = req.file.as_os_str() == "-";
    let mut replaced_reason = None;

    let db_path = if is_stdin {
        if req.no_build {
            return Err(DsctError::invalid_argument(
                "--no-build cannot be combined with stdin input",
            ));
        }
        req.db.clone().ok_or_else(|| {
            DsctError::invalid_argument("--db is required when reading the capture from stdin")
        })?
    } else {
        if req.db.is_none() && is_sqlite_file(req.file)? {
            if req.force {
                return Err(DsctError::invalid_argument(format!(
                    "{} is a SQLite database; pass the capture file to rebuild its index",
                    req.file.display()
                )));
            }
            return Ok(ResolvedIndex {
                db_path: req.file.to_path_buf(),
                build: None,
                replaced_reason: None,
            });
        }
        let db_path = req.db.clone().unwrap_or_else(|| default_db_path(req.file));

        // Validate dissection options up front (they also determine freshness).
        let mut registry = DissectorRegistry::default();
        decode_as::parse_and_apply(&mut registry, req.decode_as).invalid_argument()?;
        esp_sa::parse_and_apply(&registry, req.esp_sa).invalid_argument()?;
        let expected = IndexMeta::for_capture(req.file, &registry, req.decode_as, req.esp_sa)?;

        match meta::check(&db_path, &expected)? {
            Freshness::Fresh if !req.force => {
                return Ok(ResolvedIndex {
                    db_path,
                    build: None,
                    replaced_reason: None,
                });
            }
            Freshness::Fresh => replaced_reason = Some("--force".to_owned()),
            Freshness::Missing => {}
            Freshness::Stale(reason) => {
                if req.no_build {
                    return Err(DsctError::invalid_argument(format!(
                        "index {} is stale ({reason}); run `dsct index` or drop --no-build",
                        db_path.display()
                    )));
                }
                replaced_reason = Some(reason);
            }
        }
        if req.no_build {
            return Err(DsctError::invalid_argument(format!(
                "index {} does not exist; run `dsct index` or drop --no-build",
                db_path.display()
            )));
        }
        db_path
    };

    let outcome = build_index(
        &IndexOptions {
            capture: req.file,
            db_path: &db_path,
            decode_as: req.decode_as,
            esp_sa: req.esp_sa,
            progress_interval: req.progress_interval,
            deadline: req.deadline,
        },
        warn,
        progress,
    )?;
    Ok(ResolvedIndex {
        db_path,
        build: Some(outcome),
        replaced_reason,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_db_path_appends_suffix() {
        assert_eq!(
            default_db_path(Path::new("/tmp/cap.pcap")),
            PathBuf::from("/tmp/cap.pcap.dsct.sqlite")
        );
    }

    #[test]
    fn is_sqlite_file_detects_magic() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(SQLITE_MAGIC).unwrap();
        tmp.write_all(&[0u8; 100]).unwrap();
        assert!(is_sqlite_file(tmp.path()).unwrap());
    }

    #[test]
    fn is_sqlite_file_rejects_other_content() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"not a database at all").unwrap();
        assert!(!is_sqlite_file(tmp.path()).unwrap());
    }

    /// Minimal pcap with `n` Ethernet/IPv4/UDP packets.
    fn udp_pcap(n: usize) -> Vec<u8> {
        let pkt: [u8; 42] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x00,
            0x00, 0x01, 0x0A, 0x00, 0x00, 0x02, 0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
        ];
        let mut pcap = Vec::new();
        pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
        pcap.extend_from_slice(&2u16.to_le_bytes());
        pcap.extend_from_slice(&4u16.to_le_bytes());
        pcap.extend_from_slice(&0i32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&65535u32.to_le_bytes());
        pcap.extend_from_slice(&1u32.to_le_bytes());
        for i in 0..n {
            pcap.extend_from_slice(&(i as u32).to_le_bytes());
            pcap.extend_from_slice(&0u32.to_le_bytes());
            pcap.extend_from_slice(&42u32.to_le_bytes());
            pcap.extend_from_slice(&42u32.to_le_bytes());
            pcap.extend_from_slice(&pkt);
        }
        pcap
    }

    fn request<'a>(file: &'a Path, db: Option<PathBuf>) -> IndexRequest<'a> {
        IndexRequest {
            file,
            db,
            force: false,
            no_build: false,
            progress_interval: 0,
            decode_as: &[],
            esp_sa: &[],
            deadline: None,
        }
    }

    fn resolve(req: &IndexRequest<'_>) -> Result<ResolvedIndex> {
        resolve_index(req, &mut |_, _| {}, &mut |_| {})
    }

    #[test]
    fn resolve_builds_reuses_and_rebuilds() {
        let dir = tempfile::tempdir().unwrap();
        let cap = dir.path().join("c.pcap");
        std::fs::write(&cap, udp_pcap(1)).unwrap();

        let first = resolve(&request(&cap, None)).unwrap();
        assert_eq!(first.db_path, default_db_path(&cap));
        assert_eq!(first.build.as_ref().map(|b| b.packets), Some(1));
        assert!(first.replaced_reason.is_none());

        let second = resolve(&request(&cap, None)).unwrap();
        assert!(second.build.is_none());
        assert!(second.replaced_reason.is_none());

        let mut forced = request(&cap, None);
        forced.force = true;
        let third = resolve(&forced).unwrap();
        assert!(third.build.is_some());
        assert_eq!(third.replaced_reason.as_deref(), Some("--force"));

        std::fs::write(&cap, udp_pcap(2)).unwrap();
        let mut no_build = request(&cap, None);
        no_build.no_build = true;
        let err = resolve(&no_build).unwrap_err();
        assert_eq!(
            err.category(),
            crate::error::ErrorCategory::InvalidArguments
        );
        let fourth = resolve(&request(&cap, None)).unwrap();
        assert_eq!(fourth.build.as_ref().map(|b| b.packets), Some(2));
        assert!(fourth.replaced_reason.is_some());
    }

    #[test]
    fn resolve_database_file_is_used_directly() {
        let dir = tempfile::tempdir().unwrap();
        let cap = dir.path().join("c.pcap");
        std::fs::write(&cap, udp_pcap(1)).unwrap();
        let built = resolve(&request(&cap, None)).unwrap();

        let direct = resolve(&request(&built.db_path, None)).unwrap();
        assert_eq!(direct.db_path, built.db_path);
        assert!(direct.build.is_none());

        let mut forced = request(&built.db_path, None);
        forced.force = true;
        assert!(resolve(&forced).is_err());
    }

    #[test]
    fn resolve_stdin_rules() {
        let mut req = request(Path::new("-"), None);
        assert!(resolve(&req).is_err());
        req.no_build = true;
        req.db = Some(PathBuf::from("/tmp/x.sqlite"));
        assert!(resolve(&req).is_err());
    }

    #[test]
    fn resolve_no_build_missing_index() {
        let dir = tempfile::tempdir().unwrap();
        let cap = dir.path().join("c.pcap");
        std::fs::write(&cap, udp_pcap(1)).unwrap();
        let mut req = request(&cap, None);
        req.no_build = true;
        let err = resolve(&req).unwrap_err();
        assert!(err.to_string().contains("does not exist"));
        assert!(!default_db_path(&cap).exists());
    }

    #[test]
    fn is_sqlite_file_short_and_missing() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"SQL").unwrap();
        assert!(!is_sqlite_file(tmp.path()).unwrap());
        assert!(!is_sqlite_file(Path::new("/nonexistent/dsct.sqlite")).unwrap());
    }
}
