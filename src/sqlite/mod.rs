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
///
/// v2: fixed `extra` column ingest to skip nested container children when
/// walking a layer's fields (see `field_iter::top_level_fields`) — nested
/// fields (e.g. a BGP capability's `code`/`value`) no longer leak into
/// `extra` under their bare names.
pub const SCHEMA_VERSION: u32 = 2;

/// File-name suffix appended to the capture path (or used inside the cache
/// directory) for the database file.
pub const DB_SUFFIX: &str = ".dsct.sqlite";

/// The 16-byte header every SQLite 3 database starts with.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// Resolve the per-user cache directory dsct's database files live in from
/// explicit values, without touching process environment.
///
/// Resolution order: `dsct_cache_dir` as given, else `xdg_cache_home/dsct`,
/// else `home/.cache/dsct`. An empty string for any of these is treated as
/// unset (a variable set to `""` should not silently relocate the cache to
/// the process's current directory). Returns `None` when none can be
/// determined, in which case callers fall back to the historical sidecar
/// path next to the capture.
fn resolve_cache_dir(
    dsct_cache_dir: Option<&str>,
    xdg_cache_home: Option<&str>,
    home: Option<&str>,
) -> Option<PathBuf> {
    if let Some(dir) = dsct_cache_dir.filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    if let Some(dir) = xdg_cache_home.filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(dir).join("dsct"));
    }
    if let Some(home) = home.filter(|s| !s.is_empty()) {
        return Some(PathBuf::from(home).join(".cache").join("dsct"));
    }
    None
}

/// The per-user cache directory for dsct's database files.
///
/// Resolution order: `$DSCT_CACHE_DIR`, else `$XDG_CACHE_HOME/dsct`, else
/// `$HOME/.cache/dsct`. `None` when none of these environment variables is
/// set.
fn cache_dir() -> Option<PathBuf> {
    let dsct_cache_dir = std::env::var("DSCT_CACHE_DIR").ok();
    let xdg_cache_home = std::env::var("XDG_CACHE_HOME").ok();
    let home = std::env::var("HOME").ok();
    resolve_cache_dir(
        dsct_cache_dir.as_deref(),
        xdg_cache_home.as_deref(),
        home.as_deref(),
    )
}

/// FNV-1a 64-bit hash (<https://datatracker.ietf.org/doc/html/draft-eastlake-fnv>).
///
/// Dependency-free and stable across platforms/runs for identical byte
/// input — used to derive a collision-resistant, deterministic suffix for
/// cache database file names.
fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET_BASIS;
    for &b in bytes {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

/// Build the database path for `capture` given an explicit cache directory
/// (or `None` to fall back to the sidecar path). Split out from
/// [`default_db_path`] so tests can exercise the path-construction logic
/// without mutating process-wide environment variables (which would race
/// against other tests running in parallel).
fn db_path_in(capture: &Path, cache_dir: Option<&Path>) -> PathBuf {
    let Some(dir) = cache_dir else {
        let mut name = capture.as_os_str().to_os_string();
        name.push(DB_SUFFIX);
        return PathBuf::from(name);
    };

    // Canonicalise when the capture exists (resolves symlinks/`..`/relative
    // components so the same capture always hashes to the same path);
    // otherwise fall back to a purely lexical absolute path so a
    // not-yet-existing `--db`-less target (e.g. before the first build)
    // still resolves deterministically.
    let abs = std::fs::canonicalize(capture)
        .or_else(|_| std::path::absolute(capture))
        .unwrap_or_else(|_| capture.to_path_buf());
    let hash = fnv1a64(abs.as_os_str().as_encoded_bytes());

    let file_name = capture
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "capture".to_owned());

    dir.join(format!("{file_name}-{hash:016x}{DB_SUFFIX}"))
}

/// Default database path for a capture file.
///
/// When a cache directory can be determined (`$DSCT_CACHE_DIR`, else
/// `$XDG_CACHE_HOME/dsct`, else `$HOME/.cache/dsct`), the
/// database lives there as `<capture file name>-<16 hex chars>.dsct.sqlite`,
/// where the hex suffix is an FNV-1a 64 hash of the canonicalised absolute
/// capture path — stable for a given capture and collision-free across
/// captures that share a file name in different directories. Otherwise,
/// falls back to the historical sidecar path next to the capture
/// (`<capture>.dsct.sqlite`).
pub fn default_db_path(capture: &Path) -> PathBuf {
    db_path_in(capture, cache_dir().as_deref())
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

/// Test-only support for sandboxing `DSCT_CACHE_DIR` around tests that
/// exercise the *default* (no explicit `--db`/`db`) database path
/// resolution in-process — e.g. `resolve_index` or `dsct_query_sql`
/// without a `db` argument.
///
/// Without this, such a test would resolve into the real
/// `$XDG_CACHE_HOME`/`$HOME/.cache/dsct` of whatever machine runs `cargo
/// test`, leaving stray `.dsct.sqlite` files behind (the test's own
/// `tempfile::tempdir()` only cleans up the capture, not a database that
/// landed outside it). Used by both `sqlite::mod` and `mcp::tools` tests,
/// hence `pub(crate)` rather than private to this module's `tests` block.
#[cfg(test)]
pub(crate) mod test_support {
    use std::path::Path;
    use std::sync::{Mutex, MutexGuard};

    /// Serializes tests that mutate `DSCT_CACHE_DIR` so they can't race
    /// each other (or a concurrent read of it via [`super::cache_dir`]).
    fn env_lock() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// RAII guard: sets `DSCT_CACHE_DIR` to `dir` for its lifetime (holding
    /// [`env_lock`] the whole time) and unsets it again on drop.
    #[must_use = "the env var is restored when this guard drops; assign it to a binding"]
    pub(crate) struct CacheDirGuard {
        _lock: MutexGuard<'static, ()>,
    }

    impl CacheDirGuard {
        #[allow(unsafe_code)]
        pub(crate) fn set(dir: &Path) -> Self {
            let lock = env_lock();
            // SAFETY: `env_lock` serializes every test that reads or
            // writes `DSCT_CACHE_DIR`, so no other thread observes a
            // partially-updated environment while this guard is held.
            unsafe {
                std::env::set_var("DSCT_CACHE_DIR", dir);
            }
            Self { _lock: lock }
        }
    }

    impl Drop for CacheDirGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            // SAFETY: see `set`.
            unsafe {
                std::env::remove_var("DSCT_CACHE_DIR");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn default_db_path_falls_back_to_sidecar_without_cache_dir() {
        assert_eq!(
            db_path_in(Path::new("/tmp/cap.pcap"), None),
            PathBuf::from("/tmp/cap.pcap.dsct.sqlite")
        );
    }

    #[test]
    fn default_db_path_lives_in_cache_dir_when_given() {
        let dir = tempfile::tempdir().unwrap();
        let capture = dir.path().join("cap.pcap");
        std::fs::write(&capture, b"not a real pcap, just needs to exist").unwrap();

        let cache = Path::new("/tmp/dsct-cache-test");
        let db = db_path_in(&capture, Some(cache));

        assert_eq!(db.parent(), Some(cache));
        let name = db.file_name().unwrap().to_str().unwrap();
        assert!(
            name.starts_with("cap.pcap-"),
            "expected name to start with the capture's file name: {name}"
        );
        assert!(
            name.ends_with(DB_SUFFIX),
            "expected name to end with {DB_SUFFIX}: {name}"
        );
        // "cap.pcap-" + 16 hex chars + ".dsct.sqlite"
        assert_eq!(name.len(), "cap.pcap-".len() + 16 + DB_SUFFIX.len());
    }

    #[test]
    fn default_db_path_is_stable_for_the_same_capture() {
        let dir = tempfile::tempdir().unwrap();
        let capture = dir.path().join("cap.pcap");
        std::fs::write(&capture, b"contents").unwrap();

        let cache = Path::new("/tmp/dsct-cache-test");
        assert_eq!(
            db_path_in(&capture, Some(cache)),
            db_path_in(&capture, Some(cache))
        );
    }

    #[test]
    fn default_db_path_does_not_collide_across_directories() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let cap_a = dir_a.path().join("cap.pcap");
        let cap_b = dir_b.path().join("cap.pcap");
        std::fs::write(&cap_a, b"a").unwrap();
        std::fs::write(&cap_b, b"b").unwrap();

        let cache = Path::new("/tmp/dsct-cache-test");
        let db_a = db_path_in(&cap_a, Some(cache));
        let db_b = db_path_in(&cap_b, Some(cache));

        assert_ne!(
            db_a, db_b,
            "captures with the same file name in different directories must \
             not collide in the cache dir"
        );
    }

    #[test]
    fn default_db_path_handles_a_capture_that_does_not_exist_yet() {
        // Canonicalize fails when the path doesn't exist; db_path_in must
        // still resolve deterministically via the lexical-absolute fallback
        // rather than panicking or erroring.
        let cache = Path::new("/tmp/dsct-cache-test");
        let db = db_path_in(Path::new("does-not-exist.pcap"), Some(cache));
        assert_eq!(db.parent(), Some(cache));
        assert!(
            db.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("does-not-exist.pcap-")
        );
    }

    #[test]
    fn resolve_cache_dir_prefers_dsct_cache_dir() {
        assert_eq!(
            resolve_cache_dir(Some("/custom/cache"), Some("/xdg/cache"), Some("/home/u")),
            Some(PathBuf::from("/custom/cache"))
        );
    }

    #[test]
    fn resolve_cache_dir_falls_back_to_xdg_cache_home() {
        assert_eq!(
            resolve_cache_dir(None, Some("/xdg/cache"), Some("/home/u")),
            Some(PathBuf::from("/xdg/cache/dsct"))
        );
    }

    #[test]
    fn resolve_cache_dir_falls_back_to_home() {
        assert_eq!(
            resolve_cache_dir(None, None, Some("/home/u")),
            Some(PathBuf::from("/home/u/.cache/dsct"))
        );
    }

    #[test]
    fn resolve_cache_dir_none_when_nothing_set() {
        assert_eq!(resolve_cache_dir(None, None, None), None);
    }

    #[test]
    fn resolve_cache_dir_treats_empty_string_as_unset() {
        assert_eq!(
            resolve_cache_dir(Some(""), Some(""), Some("/home/u")),
            Some(PathBuf::from("/home/u/.cache/dsct"))
        );
        assert_eq!(resolve_cache_dir(Some(""), Some(""), Some("")), None);
    }

    #[test]
    fn fnv1a64_matches_known_test_vectors() {
        // Standard FNV-1a 64 test vectors.
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a64(b"a"), 0xaf63_dc4c_8601_ec8c);
        assert_eq!(fnv1a64(b"foobar"), 0x8594_4171_f739_67e8);
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
        let cache_dir = tempfile::tempdir().unwrap();
        let _cache_guard = test_support::CacheDirGuard::set(cache_dir.path());
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
        let cache_dir = tempfile::tempdir().unwrap();
        let _cache_guard = test_support::CacheDirGuard::set(cache_dir.path());
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
