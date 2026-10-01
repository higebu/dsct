//! Benchmark for parallel filter evaluation (`dsct read --threads`).
//!
//! Generates synthetic pcaps and measures the throughput of the parallel read
//! engine at threads=1 vs threads=4, writing matched records to
//! [`io::sink()`]:
//!
//! - `icmp_filter`: ICMP and UDP packets, none of which uses cross-packet
//!   state, so the whole run stays parallel.
//! - `half_tcp`: ICMP and TCP packets; every TCP packet uses TCP stream
//!   state, so the merger dissects it again in capture order (measures how
//!   the speed-up shrinks with the share of stateful packets).

use std::io;
use std::path::Path;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use dsct::filter_expr::FilterExpr;
use dsct::input::CaptureReader;
use dsct::parallel_read::{ParallelReadOptions, SequentialReadOptions, run, run_sequential};
use packet_dissector::registry::DissectorRegistry;

// ---------------------------------------------------------------------------
// Pcap generation
// ---------------------------------------------------------------------------

/// Build a synthetic pcap with `n` packets alternating ICMP and either TCP
/// or UDP.
///
/// Even-indexed packets: Ethernet + IPv4 + ICMP Echo Request (42 bytes).
/// Odd-indexed packets:  Ethernet + IPv4 + TCP (54 bytes) when `with_tcp`,
/// else Ethernet + IPv4 + UDP (42 bytes).
fn build_bench_pcap(n: usize, with_tcp: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(24 + n * 60);

    // Global header
    buf.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
    buf.extend_from_slice(&2u16.to_le_bytes());
    buf.extend_from_slice(&4u16.to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&65535u32.to_le_bytes());
    buf.extend_from_slice(&1u32.to_le_bytes()); // Ethernet

    // ICMP Echo Request template (42 bytes): Eth + IPv4 (ICMP, 10.0.0.1→10.0.0.2)
    let icmp: &[u8] = &[
        // Ethernet (14 bytes)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst mac
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac
        0x08, 0x00, // ethertype IPv4
        // IPv4 (20 bytes)
        0x45, 0x00, 0x00, 0x1c, // version/IHL, DSCP, total length (28)
        0x00, 0x00, 0x00, 0x00, // id, flags+frag
        0x40, 0x01, 0x00, 0x00, // TTL=64, proto=ICMP, checksum=0
        0x0a, 0x00, 0x00, 0x01, // src 10.0.0.1
        0x0a, 0x00, 0x00, 0x02, // dst 10.0.0.2
        // ICMP Echo Request (8 bytes, RFC 792)
        0x08, 0x00, // type 8, code 0
        0x00, 0x00, // checksum
        0x00, 0x01, // identifier
        0x00, 0x01, // sequence number
    ];

    // TCP SYN packet template (54 bytes): Eth + IPv4 (TCP, 10.0.0.3→10.0.0.4)
    let tcp: &[u8] = &[
        // Ethernet (14 bytes)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
        // IPv4 (20 bytes)
        0x45, 0x00, 0x00, 0x28, // total length = 40
        0x00, 0x00, 0x00, 0x00, 0x40, 0x06, 0x00, 0x00, // TTL=64, proto=TCP
        0x0a, 0x00, 0x00, 0x03, // src 10.0.0.3
        0x0a, 0x00, 0x00, 0x04, // dst 10.0.0.4
        // TCP (20 bytes)
        0x30, 0x39, // src port 12345
        0x07, 0xd0, // dst port 2000
        0x00, 0x00, 0x00, 0x01, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02, // data offset=5, SYN
        0xff, 0xff, // window
        0x00, 0x00, // checksum
        0x00, 0x00, // urgent
    ];

    // UDP datagram template (42 bytes): Eth + IPv4 (UDP, 10.0.0.3→10.0.0.4)
    let udp: &[u8] = &[
        // Ethernet (14 bytes)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x08, 0x00,
        // IPv4 (20 bytes)
        0x45, 0x00, 0x00, 0x1c, // total length = 28
        0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00, // TTL=64, proto=UDP
        0x0a, 0x00, 0x00, 0x03, // src 10.0.0.3
        0x0a, 0x00, 0x00, 0x04, // dst 10.0.0.4
        // UDP (8 bytes, RFC 768)
        0x10, 0x00, // src port 4096
        0x10, 0x01, // dst port 4097
        0x00, 0x08, // length
        0x00, 0x00, // checksum
    ];
    let other = if with_tcp { tcp } else { udp };

    for i in 0..n {
        let pkt = if i % 2 == 0 { icmp } else { other };
        let ts_sec = (i / 1_000_000) as u32;
        let ts_usec = (i % 1_000_000) as u32;
        buf.extend_from_slice(&ts_sec.to_le_bytes());
        buf.extend_from_slice(&ts_usec.to_le_bytes());
        buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        buf.extend_from_slice(&(pkt.len() as u32).to_le_bytes());
        buf.extend_from_slice(pkt);
    }

    buf
}

/// Write a bench pcap to `path` and return the file size in bytes.
fn write_bench_pcap(path: &Path, n: usize, with_tcp: bool) -> u64 {
    let data = build_bench_pcap(n, with_tcp);
    std::fs::write(path, &data).expect("write bench pcap");
    data.len() as u64
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

fn bench_parallel_read(c: &mut Criterion) {
    const N: usize = 20_000; // ~20 k packets; each is 42 or 54 bytes

    let mut group = c.benchmark_group("parallel_read");
    group.sample_size(10);

    for (name, with_tcp) in [("icmp_filter", false), ("half_tcp", true)] {
        let path = std::env::temp_dir().join(format!(
            "dsct_bench_parallel_{name}_{N}_{}.pcap",
            std::process::id()
        ));
        let file_size = write_bench_pcap(&path, N, with_tcp);
        group.throughput(Throughput::Bytes(file_size));

        let filter = FilterExpr::parse("icmp")
            .ok()
            .flatten()
            .expect("valid bench filter");
        for &threads in &[1usize, 4usize] {
            group.bench_with_input(
                BenchmarkId::new(name, format!("threads={threads}")),
                &threads,
                |b, &t| {
                    b.iter(|| {
                        let mut sink = io::sink();
                        run(
                            &ParallelReadOptions {
                                path: &path,
                                filter: &filter,
                                decode_as_args: &[],
                                threads: t,
                                sample_rate: 1,
                                offset: 0,
                                count: None,
                                pn_filter: None,
                                field_config: None, // verbose mode
                                raw_bytes: false,
                                progress_interval: 0,
                            },
                            &DissectorRegistry::default(),
                            &mut sink,
                            &mut |_, _| {},
                            &mut |_, _| {},
                        )
                        .expect("parallel_read::run failed in benchmark");
                    });
                },
            );
        }

        // Baseline: the plain sequential path (`--threads 1`).
        group.bench_function(BenchmarkId::new(name, "sequential"), |b| {
            b.iter(|| {
                let mut sink = io::sink();
                run_sequential(
                    CaptureReader::open(&path).expect("open bench pcap"),
                    &DissectorRegistry::default(),
                    &SequentialReadOptions {
                        filter: Some(&filter),
                        sample_rate: 1,
                        offset: 0,
                        count: None,
                        pn_filter: None,
                        field_config: None,
                        raw_bytes: false,
                        progress_interval: 0,
                    },
                    &mut sink,
                    &mut |_, _| {},
                    &mut |_, _| {},
                )
                .expect("parallel_read::run_sequential failed in benchmark");
            });
        });

        let _ = std::fs::remove_file(&path);
    }

    group.finish();
}

criterion_group!(benches, bench_parallel_read);
criterion_main!(benches);
