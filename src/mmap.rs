//! Read-only memory mapping of capture files.
//!
//! Used by the parallel `dsct read` path so that worker threads can share
//! zero-copy `&[u8]` views of a multi-gigabyte capture without each holding a
//! private heap copy.  The streaming path ([`crate::input::CaptureReader`]) is
//! still used for stdin and the sequential fast path.

use std::fs::File;
use std::path::Path;

use crate::error::{Result, ResultExt};

/// A read-only memory-mapped file providing a zero-copy byte slice.
#[allow(unsafe_code)]
pub struct MappedFile {
    mmap: memmap2::Mmap,
}

#[allow(unsafe_code)]
impl MappedFile {
    /// Open and memory-map `path` read-only.
    ///
    /// # Safety
    ///
    /// Uses `unsafe` internally for the `mmap` call.  The file is opened
    /// read-only and the mapping is never mutated.  As with the TUI's
    /// `CaptureMap`, the caller must ensure the file is not truncated by another
    /// process while the mapping is alive; most platforms prevent truncation of
    /// files that have active read-only mappings.
    pub fn open(path: &Path) -> Result<Self> {
        let file =
            File::open(path).context(format!("failed to open capture file: {}", path.display()))?;
        // SAFETY: the file is opened read-only and we hand out only shared
        // (`&[u8]`) views of the mapping, never a mutable reference.
        let mmap = unsafe { memmap2::MmapOptions::new().map(&file) }
            .context("failed to memory-map capture file")?;
        Ok(Self { mmap })
    }

    /// Return the mapped file contents as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.mmap
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn maps_file_contents() {
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(b"hello mmap").unwrap();
        tmp.flush().unwrap();
        let mapped = MappedFile::open(tmp.path()).unwrap();
        assert_eq!(mapped.as_bytes(), b"hello mmap");
    }

    #[test]
    fn open_missing_file_errors() {
        let result = MappedFile::open(Path::new("/tmp/dsct_nonexistent_mmap_test.pcap"));
        assert!(result.is_err());
    }
}
