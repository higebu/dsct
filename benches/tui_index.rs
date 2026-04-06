//! Benchmark for TUI index scan (Phase 1 loading).
//!
//! Measures time and throughput for building the packet index from pcap files
//! of varying sizes.

use std::io::Write;
use std::path::Path;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use dsct::tui::loader::build_index;

/// Build a minimal pcap file with `n` Ethernet+IPv4+UDP packets (42 bytes each).
fn write_test_pcap(path: &Path, n: usize) {
    let mut f = std::fs::File::create(path).expect("create pcap");

    // Global header (24 bytes)
    f.write_all(&0xA1B2C3D4u32.to_le_bytes()).unwrap();
    f.write_all(&2u16.to_le_bytes()).unwrap();
    f.write_all(&4u16.to_le_bytes()).unwrap();
    f.write_all(&0i32.to_le_bytes()).unwrap();
    f.write_all(&0u32.to_le_bytes()).unwrap();
    f.write_all(&65535u32.to_le_bytes()).unwrap();
    f.write_all(&1u32.to_le_bytes()).unwrap();

    let pkt: &[u8] = &[
        // Ethernet (14)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
        // IPv4 (20)
        0x45, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, 0x0A, 0x00, 0x00,
        0x01, 0x0A, 0x00, 0x00, 0x02, // UDP (8)
        0x10, 0x00, 0x10, 0x01, 0x00, 0x08, 0x00, 0x00,
    ];
    let pkt_len = pkt.len() as u32;

    for i in 0..n {
        let ts_sec = (i / 1000) as u32;
        let ts_usec = ((i % 1000) * 1000) as u32;
        f.write_all(&ts_sec.to_le_bytes()).unwrap();
        f.write_all(&ts_usec.to_le_bytes()).unwrap();
        f.write_all(&pkt_len.to_le_bytes()).unwrap();
        f.write_all(&pkt_len.to_le_bytes()).unwrap();
        f.write_all(pkt).unwrap();
    }
}

fn bench_build_index(c: &mut Criterion) {
    let mut group = c.benchmark_group("tui_index");

    for &n in &[1_000, 10_000, 100_000] {
        let path =
            std::env::temp_dir().join(format!("bask_bench_index_{n}_{}.pcap", std::process::id()));
        write_test_pcap(&path, n);

        let file_size = std::fs::metadata(&path).unwrap().len();
        let data = std::fs::read(&path).unwrap();

        group.throughput(Throughput::Bytes(file_size));
        group.bench_with_input(BenchmarkId::new("build_index", n), &n, |b, _| {
            b.iter(|| {
                let result = build_index(&data).unwrap();
                assert_eq!(result.len(), n);
            });
        });

        let _ = std::fs::remove_file(&path);
    }

    group.finish();
}

criterion_group!(benches, bench_build_index);
criterion_main!(benches);
