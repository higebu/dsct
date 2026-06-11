//! Parallel filter evaluation across packet-index chunks.
//!
//! The `packet-dissector` `Dissector` trait is `Send` but **not** `Sync`, and a
//! [`DissectorRegistry`] carries per-instance TCP reassembly state.  The design
//! is therefore *registry-per-thread*: this module splits a packet index into
//! contiguous chunks, hands each chunk to a worker thread that owns a freshly
//! built registry and [`DissectBuffer`], and merges the matching packet indices
//! back together in ascending (packet-number) order.
//!
//! # Reassembly and correctness
//!
//! TCP stream reassembly is **stateful and order-dependent**: when a multi
//! segment application PDU completes, the dissection of the *completing* segment
//! depends on having seen the earlier segments of the same stream.  Splitting a
//! stream across worker threads breaks that, so callers must only use the
//! parallel path for filters whose result is independent of reassembly state.
//! See [`crate::filter_expr::FilterExpr::match_is_reassembly_independent`] and
//! [`crate::filter_expr::FilterExpr::output_is_reassembly_free`].

use std::thread;

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::{DissectBuffer, Packet};

use crate::filter_expr::FilterExpr;

/// Environment variable that overrides the default worker-thread count.
pub const THREADS_ENV: &str = "DSCT_THREADS";

/// Minimal per-packet information required to dissect a packet during a
/// parallel filter scan.
///
/// Implemented for the CLI's `packet_dissector_pcap::PacketRecord` and the
/// TUI's `PacketIndex`, so both code paths share the same scan engine.
pub trait ScanIndex: Sync {
    /// Byte offset of the packet data within the capture buffer.
    fn scan_data_offset(&self) -> usize;
    /// Captured length of the packet data in bytes.
    fn scan_captured_len(&self) -> usize;
    /// Link-layer type used to dispatch dissection.
    fn scan_link_type(&self) -> u32;
}

impl ScanIndex for packet_dissector_pcap::PacketRecord {
    fn scan_data_offset(&self) -> usize {
        self.data_offset as usize
    }
    fn scan_captured_len(&self) -> usize {
        self.captured_len as usize
    }
    fn scan_link_type(&self) -> u32 {
        self.link_type as u32
    }
}

/// Resolve the worker-thread count.
///
/// Resolution order:
/// 1. An explicit `override_threads` (e.g. a CLI flag), clamped to at least 1.
/// 2. The [`THREADS_ENV`] environment variable, if it parses to `>= 1`.
/// 3. The number of available CPUs ([`std::thread::available_parallelism`]).
/// 4. A final fallback of `1`.
pub fn resolve_threads(override_threads: Option<usize>) -> usize {
    if let Some(n) = override_threads {
        return n.max(1);
    }
    if let Ok(s) = std::env::var(THREADS_ENV)
        && let Ok(n) = s.trim().parse::<usize>()
        && n >= 1
    {
        return n;
    }
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// Evaluate `expr` against a single contiguous range `[start, end)` of
/// `records`, returning the matching indices in ascending order.
fn scan_range<R: ScanIndex>(
    data: &[u8],
    records: &[R],
    start: usize,
    end: usize,
    expr: &FilterExpr,
    registry: &DissectorRegistry,
) -> Vec<usize> {
    let mut out = Vec::new();
    let mut dissect_buf = DissectBuffer::new();
    for (local, rec) in records[start..end].iter().enumerate() {
        let i = start + local;
        let number = (i as u64) + 1; // 1-based packet number
        let offset = rec.scan_data_offset();
        let Some(pkt_data) = data.get(offset..offset + rec.scan_captured_len()) else {
            continue;
        };
        let buf = dissect_buf.clear_into();
        // Partial/failed dissection counts as a non-match, mirroring the
        // sequential filter paths (which skip packets that fail to dissect).
        if registry
            .dissect_with_link_type(pkt_data, rec.scan_link_type(), buf)
            .is_ok()
        {
            let packet = Packet::new(buf, pkt_data);
            if expr.matches_with_number(&packet, number) {
                out.push(i);
            }
        }
    }
    out
}

/// Evaluate `expr` against every record in parallel and return the indices of
/// matching packets in ascending (packet-number) order.
///
/// `make_registry` builds a fresh, fully-configured [`DissectorRegistry`] for
/// each worker thread.  Because registries cannot be shared across threads, a
/// new one is constructed per worker; callers should apply the same
/// `--decode-as` / `--esp-sa` configuration used on the main thread so results
/// match the sequential path exactly.
///
/// The merge is order-preserving: each worker processes one contiguous range
/// and returns its matches in order, and the ranges are concatenated in range
/// order, so the result is globally sorted without an explicit sort.
pub fn filter_indices<R: ScanIndex>(
    data: &[u8],
    records: &[R],
    expr: &FilterExpr,
    threads: usize,
    make_registry: &(dyn Fn() -> DissectorRegistry + Sync),
) -> Vec<usize> {
    let total = records.len();
    if total == 0 {
        return Vec::new();
    }
    let threads = threads.max(1).min(total);

    if threads == 1 {
        let registry = make_registry();
        return scan_range(data, records, 0, total, expr, &registry);
    }

    // Split into `threads` contiguous, roughly equal chunks.
    let chunk = total.div_ceil(threads);
    let mut bounds = Vec::with_capacity(threads);
    let mut start = 0;
    while start < total {
        let end = (start + chunk).min(total);
        bounds.push((start, end));
        start = end;
    }

    let per_worker: Vec<Vec<usize>> = thread::scope(|scope| {
        let handles: Vec<_> = bounds
            .iter()
            .map(|&(start, end)| {
                scope.spawn(move || {
                    let registry = make_registry();
                    scan_range(data, records, start, end, expr, &registry)
                })
            })
            .collect();
        // Propagate a worker panic to the main thread instead of silently
        // dropping that chunk's results.  Swallowing the panic (e.g. with
        // `unwrap_or_default()`) would emit fewer packets than actually match
        // with exit code 0, violating the byte-identical / packet-number-order
        // output contract.  Re-panicking surfaces the failure visibly.
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    });

    let mut out = Vec::with_capacity(per_worker.iter().map(Vec::len).sum());
    for matches in per_worker {
        out.extend(matches);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet/IPv4/UDP pcap with `n` packets.
    ///
    /// The single embedded packet is the same fixture used elsewhere in the
    /// crate (UDP, src 10.0.0.1 -> dst 10.0.0.2).
    fn build_udp_pcap(n: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
        buf.extend_from_slice(&2u16.to_le_bytes());
        buf.extend_from_slice(&4u16.to_le_bytes());
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(&65535u32.to_le_bytes());
        buf.extend_from_slice(&1u32.to_le_bytes()); // Ethernet
        let pkt: &[u8] = &[
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
            0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x00,
            0x00, 0x01, 0x0A, 0x00, 0x00, 0x02, 0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
        ];
        for i in 0..n {
            buf.extend_from_slice(&((i / 1000) as u32).to_le_bytes());
            buf.extend_from_slice(&(((i % 1000) * 1000) as u32).to_le_bytes());
            buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
            buf.extend_from_slice(pkt);
        }
        buf
    }

    fn default_registry() -> DissectorRegistry {
        DissectorRegistry::default()
    }

    /// Naive single-threaded reference implementation, used to validate the
    /// parallel engine independently of its own `threads == 1` path.
    fn reference_indices(
        data: &[u8],
        records: &[packet_dissector_pcap::PacketRecord],
        expr: &FilterExpr,
    ) -> Vec<usize> {
        let registry = DissectorRegistry::default();
        let mut buf = DissectBuffer::new();
        let mut out = Vec::new();
        for (i, rec) in records.iter().enumerate() {
            let off = rec.data_offset as usize;
            let data_slice = &data[off..off + rec.captured_len as usize];
            let b = buf.clear_into();
            if registry
                .dissect_with_link_type(data_slice, rec.link_type as u32, b)
                .is_ok()
            {
                let packet = Packet::new(b, data_slice);
                if expr.matches_with_number(&packet, (i as u64) + 1) {
                    out.push(i);
                }
            }
        }
        out
    }

    #[test]
    fn resolve_threads_explicit_override() {
        assert_eq!(resolve_threads(Some(4)), 4);
        // Zero is clamped up to 1.
        assert_eq!(resolve_threads(Some(0)), 1);
    }

    #[test]
    fn resolve_threads_default_is_positive() {
        assert!(resolve_threads(None) >= 1);
    }

    #[test]
    fn empty_records_yields_empty() {
        let data = build_udp_pcap(0);
        let records = packet_dissector_pcap::build_index(&data).unwrap();
        let expr = FilterExpr::parse("udp").unwrap().unwrap();
        let out = filter_indices(&data, &records, &expr, 4, &default_registry);
        assert!(out.is_empty());
    }

    #[test]
    fn all_match_protocol_filter() {
        let data = build_udp_pcap(2500);
        let records = packet_dissector_pcap::build_index(&data).unwrap();
        let expr = FilterExpr::parse("udp").unwrap().unwrap();
        let out = filter_indices(&data, &records, &expr, 8, &default_registry);
        // Every fixture packet is UDP.
        assert_eq!(out.len(), 2500);
        assert!(
            out.windows(2).all(|w| w[0] < w[1]),
            "indices must be ascending"
        );
    }

    #[test]
    fn parallel_matches_sequential_for_various_thread_counts() {
        let data = build_udp_pcap(5000);
        let records = packet_dissector_pcap::build_index(&data).unwrap();
        let expr = FilterExpr::parse("ipv4.src = '10.0.0.1'").unwrap().unwrap();
        let reference = reference_indices(&data, &records, &expr);
        for threads in [1usize, 2, 3, 4, 7, 16, 1000] {
            let out = filter_indices(&data, &records, &expr, threads, &default_registry);
            assert_eq!(out, reference, "mismatch with {threads} threads");
        }
    }

    #[test]
    fn parallel_matches_sequential_no_match_filter() {
        let data = build_udp_pcap(1234);
        let records = packet_dissector_pcap::build_index(&data).unwrap();
        let expr = FilterExpr::parse("tcp").unwrap().unwrap();
        let reference = reference_indices(&data, &records, &expr);
        assert!(reference.is_empty());
        let out = filter_indices(&data, &records, &expr, 8, &default_registry);
        assert_eq!(out, reference);
    }

    #[test]
    fn parallel_matches_sequential_packet_number_filter() {
        let data = build_udp_pcap(300);
        let records = packet_dissector_pcap::build_index(&data).unwrap();
        let expr = FilterExpr::parse("packet_number BETWEEN 50 AND 100")
            .unwrap()
            .unwrap();
        let reference = reference_indices(&data, &records, &expr);
        let out = filter_indices(&data, &records, &expr, 5, &default_registry);
        assert_eq!(out, reference);
        // 1-based 50..=100 -> zero-based 49..=99.
        assert_eq!(out.first(), Some(&49));
        assert_eq!(out.last(), Some(&99));
    }
}
