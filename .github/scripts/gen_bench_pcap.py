#!/usr/bin/env python3
"""Generate a pcap file containing DNS query packets for benchmarking.

Each packet is an Ethernet + IPv4 + UDP + DNS A-record query for example.com,
matching the structure in benches/json_escape.rs build_eth_ipv4_udp_dns().

Usage:
    python3 gen_bench_pcap.py <output_path> [packet_count]
"""

import struct
import sys


def build_dns_query_packet() -> bytes:
    """Build an Ethernet/IPv4/UDP/DNS query packet for example.com."""
    # DNS payload
    dns = struct.pack(
        "!HHHHHH",
        0xABCD,  # Transaction ID
        0x0100,  # Flags: standard query
        1,       # Questions
        0,       # Answer RRs
        0,       # Authority RRs
        0,       # Additional RRs
    )
    # QNAME: 7example3com0
    dns += b"\x07example\x03com\x00"
    dns += struct.pack("!HH", 1, 1)  # QTYPE=A, QCLASS=IN

    udp_len = 8 + len(dns)
    udp = struct.pack(
        "!HHHH",
        12345,    # Source port
        53,       # Destination port
        udp_len,  # Length
        0,        # Checksum (0 = not computed)
    ) + dns

    ipv4_total = 20 + len(udp)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,           # Version + IHL
        0x00,           # DSCP/ECN
        ipv4_total,     # Total length
        0,              # Identification
        0,              # Flags + Fragment offset
        64,             # TTL
        17,             # Protocol (UDP)
        0,              # Header checksum (0 = not computed)
        bytes([192, 168, 1, 1]),  # Source IP
        bytes([8, 8, 8, 8]),      # Destination IP
    )

    ethernet = struct.pack(
        "!6s6sH",
        b"\xaa\xbb\xcc\xdd\xee\xff",  # Destination MAC
        b"\x11\x22\x33\x44\x55\x66",  # Source MAC
        0x0800,                         # EtherType (IPv4)
    )

    return ethernet + ipv4 + udp


def write_pcap(path: str, n: int) -> None:
    """Write a pcap file with n DNS query packets."""
    pkt = build_dns_query_packet()
    pkt_len = len(pkt)

    with open(path, "wb") as f:
        # Global header (24 bytes)
        f.write(struct.pack("<IHHiIII",
            0xA1B2C3D4,  # Magic number
            2,            # Version major
            4,            # Version minor
            0,            # Thiszone
            0,            # Sigfigs
            65535,        # Snaplen
            1,            # Network (Ethernet)
        ))

        for i in range(n):
            ts_sec = i // 1000
            ts_usec = (i % 1000) * 1000
            # Packet record header (16 bytes)
            f.write(struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len))
            f.write(pkt)


def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <output_path> [packet_count]", file=sys.stderr)
        sys.exit(1)

    output_path = sys.argv[1]
    count = int(sys.argv[2]) if len(sys.argv) >= 3 else 1000

    write_pcap(output_path, count)
    print(f"Wrote {count} DNS query packets to {output_path}")


if __name__ == "__main__":
    main()
