//! Benchmarks comparing sequential and parallel filter evaluation.
//!
//! Measures [`dsct::parallel::filter_indices`] over a synthetic capture at a
//! few worker-thread counts, so the speedup from registry-per-thread parallel
//! scanning can be tracked.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};

use dsct::filter_expr::FilterExpr;
use dsct::parallel;
use packet_dissector::registry::DissectorRegistry;

/// Build a pcap with `n` Ethernet/IPv4/UDP packets.
fn build_pcap(n: usize) -> Vec<u8> {
    let mut pcap = Vec::new();
    pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    pcap.extend_from_slice(&2u16.to_le_bytes());
    pcap.extend_from_slice(&4u16.to_le_bytes());
    pcap.extend_from_slice(&0i32.to_le_bytes());
    pcap.extend_from_slice(&0u32.to_le_bytes());
    pcap.extend_from_slice(&65535u32.to_le_bytes());
    pcap.extend_from_slice(&1u32.to_le_bytes());
    let pkt: &[u8] = &[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00, 0x45,
        0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x01,
        0x0a, 0x00, 0x00, 0x02, 0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
    ];
    for i in 0..n {
        pcap.extend_from_slice(&((i / 1000) as u32).to_le_bytes());
        pcap.extend_from_slice(&(((i % 1000) * 1000) as u32).to_le_bytes());
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        pcap.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        pcap.extend_from_slice(pkt);
    }
    pcap
}

fn bench_filter(c: &mut Criterion) {
    let packets = 100_000;
    let data = build_pcap(packets);
    let records = packet_dissector_pcap::build_index(&data).unwrap();
    let expr = FilterExpr::parse("ipv4.src = '10.0.0.1'").unwrap().unwrap();
    let make_registry = DissectorRegistry::default;

    let max_threads = parallel::resolve_threads(None);

    // Distinct, ascending thread counts (avoid duplicate benchmark IDs when
    // `available_parallelism` coincides with a listed value).
    let mut thread_counts: Vec<usize> = vec![1, 2, 4, max_threads]
        .into_iter()
        .filter(|&t| t <= max_threads)
        .collect();
    thread_counts.sort_unstable();
    thread_counts.dedup();

    let mut group = c.benchmark_group("filter_indices");
    group.throughput(criterion::Throughput::Elements(packets as u64));
    for threads in thread_counts {
        group.bench_function(format!("threads_{threads}"), |b| {
            b.iter(|| {
                let out = parallel::filter_indices(
                    black_box(&data),
                    black_box(&records),
                    black_box(&expr),
                    threads,
                    &make_registry,
                );
                black_box(out.len())
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_filter);
criterion_main!(benches);
