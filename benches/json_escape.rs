//! Microbenchmarks for JSON escape overhead in the MCP streaming path.
//!
//! Measures the cost of `write_packet_json` under different configurations:
//!
//! 1. **direct** — writes to `Vec<u8>` (equivalent to CLI JSONL path).
//! 2. **escape** — writes through `JsonEscapeWriter<Vec<u8>>` (many small writes).
//! 3. **buffered_escape** — writes through `BufWriter<JsonEscapeWriter<Vec<u8>>>`.
//! 4. **pkt_buf_escape** — writes to a reusable `Vec<u8>`, then passes the whole
//!    buffer through `JsonEscapeWriter` in a single `write_all` (current MCP).

use std::hint::black_box;
use std::io::{BufWriter, Write};

use criterion::{Criterion, criterion_group, criterion_main};
use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::DissectBuffer;

use dsct::mcp::raw_mcp::JsonEscapeWriter;
use dsct::serialize::{PacketMeta, write_packet_json};

// ---------------------------------------------------------------------------
// Test packet builders
// ---------------------------------------------------------------------------

/// Ethernet(14) + IPv4(20) + TCP(20) = 54 bytes.
fn build_eth_ipv4_tcp() -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&40u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.push(64);
    pkt.push(6);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[10, 0, 0, 1]);
    pkt.extend_from_slice(&[10, 0, 0, 2]);
    pkt.extend_from_slice(&54321u16.to_be_bytes());
    pkt.extend_from_slice(&80u16.to_be_bytes());
    pkt.extend_from_slice(&1u32.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.push(0x50);
    pkt.push(0x02);
    pkt.extend_from_slice(&65535u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt
}

/// Ethernet(14) + IPv4(20) + UDP(8) + DNS query for example.com.
fn build_eth_ipv4_udp_dns() -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    pkt.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    pkt.extend_from_slice(&0x0800u16.to_be_bytes());
    let ipv4_start = pkt.len();
    pkt.push(0x45);
    pkt.push(0x00);
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 4]);
    pkt.push(64);
    pkt.push(17);
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&[192, 168, 1, 1]);
    pkt.extend_from_slice(&[8, 8, 8, 8]);
    let udp_start = pkt.len();
    pkt.extend_from_slice(&12345u16.to_be_bytes());
    pkt.extend_from_slice(&53u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 2]);
    pkt.extend_from_slice(&0xABCDu16.to_be_bytes());
    pkt.extend_from_slice(&0x0100u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&[0x00; 6]);
    pkt.push(7);
    pkt.extend_from_slice(b"example");
    pkt.push(3);
    pkt.extend_from_slice(b"com");
    pkt.push(0);
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());
    let total_len = (pkt.len() - ipv4_start) as u16;
    pkt[ipv4_start + 2..ipv4_start + 4].copy_from_slice(&total_len.to_be_bytes());
    let udp_len = (pkt.len() - udp_start) as u16;
    pkt[udp_start + 4..udp_start + 6].copy_from_slice(&udp_len.to_be_bytes());
    pkt
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

struct TestPacket {
    meta: PacketMeta,
    raw: Vec<u8>,
}

fn prepare_packets() -> Vec<TestPacket> {
    vec![build_eth_ipv4_tcp(), build_eth_ipv4_udp_dns()]
        .into_iter()
        .enumerate()
        .map(|(i, raw)| {
            let meta = PacketMeta {
                number: (i + 1) as u64,
                timestamp_secs: 1711324800,
                timestamp_usecs: 123456,
                captured_length: raw.len() as u32,
                original_length: raw.len() as u32,
                link_type: 1,
            };
            TestPacket { meta, raw }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn bench_json_escape(c: &mut Criterion) {
    let registry = DissectorRegistry::default();
    let test_packets = prepare_packets();
    let mut dissect_buf = DissectBuffer::new();

    // Pre-dissect and keep buffers for serialize-only benchmarks.
    // We dissect into separate DissectBuffers so each can be borrowed independently.
    let mut tcp_buf = DissectBuffer::new();
    registry
        .dissect(&test_packets[0].raw, &mut tcp_buf)
        .unwrap();
    let mut dns_buf = DissectBuffer::new();
    registry
        .dissect(&test_packets[1].raw, &mut dns_buf)
        .unwrap();

    let mut buf = Vec::with_capacity(8192);
    let mut pkt_buf = Vec::with_capacity(4096);

    // --- TCP packet ---
    let mut group = c.benchmark_group("json_escape/tcp");
    let tcp_meta = &test_packets[0].meta;
    let tcp_data = &test_packets[0].raw;

    group.bench_function("direct", |b| {
        b.iter(|| {
            buf.clear();
            write_packet_json(
                &mut buf,
                black_box(tcp_meta),
                black_box(&tcp_buf),
                black_box(tcp_data),
                None,
                false,
            )
            .unwrap();
            black_box(&buf);
        });
    });

    group.bench_function("escape", |b| {
        b.iter(|| {
            buf.clear();
            let mut ew = JsonEscapeWriter::new(&mut buf);
            write_packet_json(
                &mut ew,
                black_box(tcp_meta),
                black_box(&tcp_buf),
                black_box(tcp_data),
                None,
                false,
            )
            .unwrap();
            black_box(&buf);
        });
    });

    group.bench_function("buffered_escape", |b| {
        b.iter(|| {
            buf.clear();
            {
                let mut ew = JsonEscapeWriter::new(&mut buf);
                let mut bw = BufWriter::with_capacity(4096, &mut ew);
                write_packet_json(
                    &mut bw,
                    black_box(tcp_meta),
                    black_box(&tcp_buf),
                    black_box(tcp_data),
                    None,
                    false,
                )
                .unwrap();
                bw.flush().unwrap();
            }
            black_box(&buf);
        });
    });

    group.bench_function("pkt_buf_escape", |b| {
        b.iter(|| {
            buf.clear();
            pkt_buf.clear();
            write_packet_json(
                &mut pkt_buf,
                black_box(tcp_meta),
                black_box(&tcp_buf),
                black_box(tcp_data),
                None,
                false,
            )
            .unwrap();
            let mut ew = JsonEscapeWriter::new(&mut buf);
            ew.write_all(&pkt_buf).unwrap();
            black_box(&buf);
        });
    });

    group.finish();

    // --- DNS packet ---
    let mut group = c.benchmark_group("json_escape/dns");
    let dns_meta = &test_packets[1].meta;
    let dns_data = &test_packets[1].raw;

    group.bench_function("direct", |b| {
        b.iter(|| {
            buf.clear();
            write_packet_json(
                &mut buf,
                black_box(dns_meta),
                black_box(&dns_buf),
                black_box(dns_data),
                None,
                false,
            )
            .unwrap();
            black_box(&buf);
        });
    });

    group.bench_function("escape", |b| {
        b.iter(|| {
            buf.clear();
            let mut ew = JsonEscapeWriter::new(&mut buf);
            write_packet_json(
                &mut ew,
                black_box(dns_meta),
                black_box(&dns_buf),
                black_box(dns_data),
                None,
                false,
            )
            .unwrap();
            black_box(&buf);
        });
    });

    group.bench_function("buffered_escape", |b| {
        b.iter(|| {
            buf.clear();
            {
                let mut ew = JsonEscapeWriter::new(&mut buf);
                let mut bw = BufWriter::with_capacity(4096, &mut ew);
                write_packet_json(
                    &mut bw,
                    black_box(dns_meta),
                    black_box(&dns_buf),
                    black_box(dns_data),
                    None,
                    false,
                )
                .unwrap();
                bw.flush().unwrap();
            }
            black_box(&buf);
        });
    });

    group.bench_function("pkt_buf_escape", |b| {
        b.iter(|| {
            buf.clear();
            pkt_buf.clear();
            write_packet_json(
                &mut pkt_buf,
                black_box(dns_meta),
                black_box(&dns_buf),
                black_box(dns_data),
                None,
                false,
            )
            .unwrap();
            let mut ew = JsonEscapeWriter::new(&mut buf);
            ew.write_all(&pkt_buf).unwrap();
            black_box(&buf);
        });
    });

    group.finish();

    // --- Batch: 100 iterations × 2 packets = 200 writes ---
    let mut group = c.benchmark_group("json_escape/batch_200");

    group.bench_function("direct", |b| {
        b.iter(|| {
            buf.clear();
            for _ in 0..100 {
                for tp in &test_packets {
                    dissect_buf.clear();
                    registry.dissect(&tp.raw, &mut dissect_buf).unwrap();
                    write_packet_json(
                        &mut buf,
                        black_box(&tp.meta),
                        black_box(&dissect_buf),
                        black_box(&tp.raw),
                        None,
                        false,
                    )
                    .unwrap();
                    buf.push(b'\n');
                }
            }
            black_box(&buf);
        });
    });

    group.bench_function("pkt_buf_escape", |b| {
        b.iter(|| {
            buf.clear();
            let mut ew = JsonEscapeWriter::new(&mut buf);
            for _ in 0..100 {
                for tp in &test_packets {
                    dissect_buf.clear();
                    registry.dissect(&tp.raw, &mut dissect_buf).unwrap();
                    pkt_buf.clear();
                    write_packet_json(
                        &mut pkt_buf,
                        black_box(&tp.meta),
                        black_box(&dissect_buf),
                        black_box(&tp.raw),
                        None,
                        false,
                    )
                    .unwrap();
                    ew.write_all(&pkt_buf).unwrap();
                    ew.write_all(b"\\n").unwrap();
                }
            }
            black_box(&buf);
        });
    });

    group.finish();

    // --- Raw escape throughput ---
    let mut group = c.benchmark_group("json_escape/raw_throughput");

    let mut sample_json = Vec::new();
    write_packet_json(
        &mut sample_json,
        &test_packets[0].meta,
        &tcp_buf,
        &test_packets[0].raw,
        None,
        false,
    )
    .unwrap();
    sample_json.push(b'\n');
    write_packet_json(
        &mut sample_json,
        &test_packets[1].meta,
        &dns_buf,
        &test_packets[1].raw,
        None,
        false,
    )
    .unwrap();
    sample_json.push(b'\n');
    group.throughput(criterion::Throughput::Bytes(sample_json.len() as u64));

    group.bench_function("escape_prebuilt", |b| {
        b.iter(|| {
            buf.clear();
            let mut ew = JsonEscapeWriter::new(&mut buf);
            ew.write_all(black_box(&sample_json)).unwrap();
            black_box(&buf);
        });
    });

    group.finish();
}

criterion_group!(benches, bench_json_escape);
criterion_main!(benches);
