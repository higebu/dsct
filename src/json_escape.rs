//! Lookup-table based JSON string escaping.
//!
//! Provides `write_json_escaped` for one-shot escaping and
//! [`JsonEscapeWriter`] as a [`Write`](std::io::Write) adapter that
//! transparently escapes all bytes written through it.
//!
//! Neither function writes surrounding `"` quotes — callers are responsible
//! for emitting delimiters.

use std::io::{self, Write};

/// Escape-class for each byte value 0x00..=0xFF.
/// 0 = no escaping needed, otherwise the second byte of the `\X` sequence
/// (or `b'u'` for `\u00XX` unicode escapes).
const ESCAPE_TABLE: [u8; 256] = {
    let mut t = [0u8; 256];
    // Control characters 0x00..=0x1F → \u00XX
    let mut i = 0u8;
    while i < 0x20 {
        t[i as usize] = b'u';
        i += 1;
    }
    // Well-known short escapes override the unicode form
    t[b'"' as usize] = b'"';
    t[b'\\' as usize] = b'\\';
    t[b'\n' as usize] = b'n';
    t[b'\r' as usize] = b'r';
    t[b'\t' as usize] = b't';
    t[0x08] = b'b'; // backspace
    t[0x0c] = b'f'; // form feed
    t
};

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Write an escape sequence for byte `b` (which must have a non-zero entry
/// in [`ESCAPE_TABLE`]) to `w`.
#[inline]
pub(crate) fn write_escape<W: Write>(w: &mut W, b: u8, esc: u8) -> io::Result<()> {
    if esc == b'u' {
        w.write_all(&[
            b'\\',
            b'u',
            b'0',
            b'0',
            HEX_DIGITS[(b >> 4) as usize],
            HEX_DIGITS[(b & 0xf) as usize],
        ])
    } else {
        w.write_all(&[b'\\', esc])
    }
}

/// A [`Write`] adapter that JSON-escapes all bytes written through it.
///
/// Uses a 256-byte lookup table to identify characters that need escaping
/// and flushes unescaped chunks with `write_all` for efficiency.
pub struct JsonEscapeWriter<W> {
    inner: W,
}

impl<W: Write> JsonEscapeWriter<W> {
    /// Wrap `inner` so that all bytes written through this writer are
    /// JSON-escaped.
    pub fn new(inner: W) -> Self {
        Self { inner }
    }
}

impl<W: Write> Write for JsonEscapeWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut start = 0;
        for (i, &b) in buf.iter().enumerate() {
            let esc = ESCAPE_TABLE[b as usize];
            if esc == 0 {
                continue;
            }
            if start < i {
                self.inner.write_all(&buf[start..i])?;
            }
            write_escape(&mut self.inner, b, esc)?;
            start = i + 1;
        }
        if start < buf.len() {
            self.inner.write_all(&buf[start..])?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Write `data` to `w`, escaping characters for embedding inside a JSON string
/// value (the surrounding `"` are NOT written).
pub(crate) fn write_json_escaped<W: Write>(w: &mut W, data: &str) -> io::Result<()> {
    let bytes = data.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let esc = ESCAPE_TABLE[b as usize];
        if esc == 0 {
            continue;
        }
        if start < i {
            w.write_all(&bytes[start..i])?;
        }
        write_escape(w, b, esc)?;
        start = i + 1;
    }
    if start < bytes.len() {
        w.write_all(&bytes[start..])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_escapes() {
        let mut buf = Vec::new();
        write_json_escaped(&mut buf, "hello \"world\"\nfoo\\bar").unwrap();
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            r#"hello \"world\"\nfoo\\bar"#
        );
    }

    #[test]
    fn control_chars() {
        let mut buf = Vec::new();
        write_json_escaped(&mut buf, "\x00\x1f").unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "\\u0000\\u001f");
    }

    #[test]
    fn writer_adapter() {
        let mut buf = Vec::new();
        {
            let mut ew = JsonEscapeWriter::new(&mut buf);
            ew.write_all(b"hello \"world\"\n").unwrap();
        }
        assert_eq!(String::from_utf8(buf).unwrap(), r#"hello \"world\"\n"#);
    }
}
