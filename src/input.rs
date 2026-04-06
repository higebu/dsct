//! Pcap and pcapng file reading.
//!
//! Wraps [`packet_dissector_pcap`] to provide a high-level callback-based API
//! for iterating over packets in a capture file.  Supports reading from files
//! and from stdin (`"-"`).

use std::fs::File;
use std::io::{self, Read};
use std::ops::ControlFlow;
use std::path::Path;

use crate::error::{DsctError, Result, ResultExt};
use crate::serialize::PacketMeta;

/// An abstraction over pcap and pcapng capture files.
///
/// Uses [`packet_dissector_pcap::stream_packets`] to read packets one at a
/// time, keeping only one packet's data in memory.
pub struct CaptureReader {
    /// Boxed reader providing the capture data.
    reader: Box<dyn Read>,
}

impl CaptureReader {
    /// Open a capture file, auto-detecting the format.
    ///
    /// If `path` is `"-"`, reads from stdin. Otherwise opens the file at
    /// `path`.
    pub fn open(path: &Path) -> Result<Self> {
        let reader: Box<dyn Read> = if path.as_os_str() == "-" {
            Box::new(io::stdin().lock())
        } else {
            let file = File::open(path)
                .context(format!("failed to open capture file: {}", path.display()))?;
            Box::new(file)
        };
        Ok(Self { reader })
    }

    /// Create a `CaptureReader` from raw bytes (for testing).
    #[cfg(test)]
    fn from_bytes(data: Vec<u8>) -> Self {
        Self {
            reader: Box::new(std::io::Cursor::new(data)),
        }
    }

    /// Iterate over all packets, calling `f` for each one.
    ///
    /// `f` receives the packet metadata (including link type) and a borrowed
    /// slice of raw packet bytes. Return `Ok(ControlFlow::Break(()))` to stop
    /// iteration early, or `Ok(ControlFlow::Continue(()))` to continue to the
    /// next packet.
    pub fn for_each_packet<F>(self, mut f: F) -> Result<()>
    where
        F: FnMut(PacketMeta, &[u8]) -> Result<ControlFlow<()>>,
    {
        let mut counter = 0u64;
        let mut error: Option<DsctError> = None;

        let stream_result =
            packet_dissector_pcap::stream_packets(self.reader, |record, pkt_data| {
                counter += 1;
                let meta = PacketMeta {
                    number: counter,
                    timestamp_secs: record.timestamp_secs,
                    timestamp_usecs: record.timestamp_usecs,
                    captured_length: record.captured_len,
                    original_length: record.original_len,
                    link_type: record.link_type as u32,
                };

                match f(meta, pkt_data) {
                    Ok(flow) => flow,
                    Err(e) => {
                        error = Some(e);
                        ControlFlow::Break(())
                    }
                }
            });

        if let Some(e) = error {
            return Err(e);
        }

        stream_result.map_err(|e| DsctError::from(e).context("invalid capture file"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal pcap with `n` dummy packets.
    fn build_pcap(n: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        // Global header (24 bytes, little-endian)
        buf.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes()); // magic
        buf.extend_from_slice(&2u16.to_le_bytes()); // major
        buf.extend_from_slice(&4u16.to_le_bytes()); // minor
        buf.extend_from_slice(&0i32.to_le_bytes()); // thiszone
        buf.extend_from_slice(&0u32.to_le_bytes()); // sigfigs
        buf.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        buf.extend_from_slice(&1u32.to_le_bytes()); // Ethernet

        let pkt: &[u8] = &[0xff; 42];
        for i in 0..n {
            buf.extend_from_slice(&(i as u32).to_le_bytes()); // ts_sec
            buf.extend_from_slice(&((i * 1000) as u32).to_le_bytes()); // ts_usec
            buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // incl_len
            buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes()); // orig_len
            buf.extend_from_slice(pkt);
        }
        buf
    }

    #[test]
    fn open_nonexistent_file_errors() {
        let result = CaptureReader::open(Path::new("/tmp/nonexistent_dsct_test_file.pcap"));
        assert!(result.is_err());
    }

    #[test]
    fn from_bytes_empty_errors() {
        let reader = CaptureReader::from_bytes(vec![]);
        let result = reader.for_each_packet(|_, _| Ok(ControlFlow::Continue(())));
        assert!(result.is_err());
    }

    #[test]
    fn from_bytes_invalid_magic_errors() {
        let reader = CaptureReader::from_bytes(vec![0x00; 24]);
        let result = reader.for_each_packet(|_, _| Ok(ControlFlow::Continue(())));
        assert!(result.is_err());
    }

    #[test]
    fn for_each_packet_counts_all() {
        let pcap = build_pcap(5);
        let reader = CaptureReader::from_bytes(pcap);
        let mut count = 0u64;
        reader
            .for_each_packet(|meta, data| {
                count += 1;
                assert_eq!(meta.number, count);
                assert_eq!(data.len(), 42);
                assert_eq!(meta.captured_length, 42);
                assert_eq!(meta.original_length, 42);
                assert_eq!(meta.link_type, 1);
                Ok(ControlFlow::Continue(()))
            })
            .unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn for_each_packet_timestamps() {
        let pcap = build_pcap(3);
        let reader = CaptureReader::from_bytes(pcap);
        let mut timestamps = Vec::new();
        reader
            .for_each_packet(|meta, _| {
                timestamps.push((meta.timestamp_secs, meta.timestamp_usecs));
                Ok(ControlFlow::Continue(()))
            })
            .unwrap();
        assert_eq!(timestamps[0], (0, 0));
        assert_eq!(timestamps[1], (1, 1000));
        assert_eq!(timestamps[2], (2, 2000));
    }

    #[test]
    fn for_each_packet_early_stop() {
        let pcap = build_pcap(10);
        let reader = CaptureReader::from_bytes(pcap);
        let mut count = 0u64;
        reader
            .for_each_packet(|_, _| {
                count += 1;
                if count >= 3 {
                    Ok(ControlFlow::Break(()))
                } else {
                    Ok(ControlFlow::Continue(()))
                }
            })
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn for_each_packet_callback_error_propagates() {
        let pcap = build_pcap(5);
        let reader = CaptureReader::from_bytes(pcap);
        let result = reader.for_each_packet(|meta, _| {
            if meta.number == 3 {
                Err(DsctError::msg("test error"))
            } else {
                Ok(ControlFlow::Continue(()))
            }
        });
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("test error"));
    }

    #[test]
    fn for_each_packet_empty_capture() {
        let pcap = build_pcap(0);
        let reader = CaptureReader::from_bytes(pcap);
        let mut count = 0u64;
        reader
            .for_each_packet(|_, _| {
                count += 1;
                Ok(ControlFlow::Continue(()))
            })
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn for_each_packet_with_clear_into_reuse() {
        use packet_dissector_core::packet::DissectBuffer;

        let pcap = build_pcap(5);
        let reader = CaptureReader::from_bytes(pcap);
        let mut dissect_buf = DissectBuffer::new();
        let mut count = 0u64;
        reader
            .for_each_packet(|meta, data| {
                count += 1;
                let buf = dissect_buf.clear_into();
                // The buffer should be empty after clear_into.
                assert_eq!(buf.field_count(), 0);
                assert_eq!(buf.layers().len(), 0);
                assert_eq!(meta.number, count);
                assert_eq!(data.len(), 42);
                Ok(ControlFlow::Continue(()))
            })
            .unwrap();
        assert_eq!(count, 5);
    }

    #[test]
    fn open_valid_file() {
        let pcap = build_pcap(2);
        let path =
            std::env::temp_dir().join(format!("dsct_input_test_{}.pcap", std::process::id()));
        std::fs::write(&path, &pcap).unwrap();

        let reader = CaptureReader::open(&path).unwrap();
        let mut count = 0u64;
        reader
            .for_each_packet(|_, _| {
                count += 1;
                Ok(ControlFlow::Continue(()))
            })
            .unwrap();
        assert_eq!(count, 2);
        let _ = std::fs::remove_file(&path);
    }
}
