---
name: analyze-packets
description: Analyze pcap/pcapng packet captures using dsct MCP tools. Use when analyzing network traffic, inspecting packets, debugging protocols, or working with pcap files.
---

Analyze pcap/pcapng files using the dsct MCP tools (`dsct_read_packets`,
`dsct_get_stats`, `dsct_list_protocols`, `dsct_list_fields`, `dsct_get_schema`).

## Workflow

1. **Get stats first** — Call `dsct_get_stats` with `file` to understand total
   packet count, duration, and protocol distribution. Add `top_talkers: true`
   for IP pair analysis or `stream_summary: true` for per-stream TCP summary.

2. **Discover field names** — Call `dsct_list_fields` with `protocols` set to
   the specific protocol(s) of interest (from the stats output). **Always
   specify `protocols`** — omitting it returns all fields across 50+ protocols
   (~56K tokens).

3. **Read packets with targeted filters** — Call `dsct_read_packets` with
   `filter` and a small `count` (start with 20–50). Each packet is roughly
   100 tokens. Use `offset` to paginate through results.

4. **Iterate** — Refine filters, adjust `count`, use `packet_number` to
   inspect specific packets, or enable `verbose: true` for low-level details.

## Large captures (>500K packets)

If `total_packets` > 500,000, do NOT read packets without a filter.
Always narrow down first:

- Use `dsct_get_stats` with `stream_summary: true` to find anomalous streams
- Filter by a specific protocol before reading (e.g., `icmp`, `dns`)
- Use `packet_number` ranges to sample across the timeline rather than reading
  sequentially with `offset` — sequential pagination through millions of packets
  wastes tool calls and context

**Timeline sampling strategy:**

Use `sample_rate` to get evenly-distributed packets across the entire capture
without manual `packet_number` arithmetic:

1. Note the total packet count from stats
2. Set `sample_rate` to `total_packets / 50` to get ~50 evenly-spaced packets
   across the full timeline (e.g., 1M packets → `sample_rate: 20000`)
3. Once an anomaly is found, narrow to `packet_number` ranges around that point
   to pinpoint when the incident began and ended

## Incident investigation fast path

For failure/incident analysis, start with these targeted filters before general
exploration:

1. `icmp` — ICMP errors (port unreachable, host unreachable, TTL exceeded)
2. `tcp AND tcp.flags = 4` — TCP resets

Read only 20–50 packets per filter to identify error patterns, then use the
timestamps found to narrow `packet_number` ranges for deeper investigation.

## Protocol name resolution

If unsure whether a protocol name is valid in a filter, call
`dsct_list_protocols` first. Protocol names are normalized (case-insensitive,
non-alphanumeric characters stripped), so `HTTP/2` → `http2`,
`Diameter` → `diameter`.

## Tool reference

| Tool | Required | Key optional params |
| --- | --- | --- |
| `dsct_get_stats` | `file` | `protocols`, `top_talkers`, `stream_summary`, `top`, `decode_as` |
| `dsct_read_packets` | `file` | `filter`, `count`, `offset`, `packet_number`, `sample_rate`, `verbose`, `decode_as` |
| `dsct_list_protocols` | — | — |
| `dsct_list_fields` | — | `protocols` (always specify!) |
| `dsct_get_schema` | — | `command` (`"read"` or `"stats"`) |

## Filter syntax

Used in the `filter` parameter of `dsct_read_packets`. Filters use SQL
expression syntax:

- **Protocol match**: `dns`, `tcp`, `http`
- **Field comparison**: `ipv4.src = '10.0.0.1'`, `tcp.dst_port > 1024`
- **Operators**: `=`, `!=`, `<>`, `>`, `<`, `>=`, `<=`
- **Boolean**: `AND`, `OR`, `NOT`
- **Grouping**: parentheses — `(tcp OR udp) AND NOT dns`
- **Range**: `tcp.dst_port BETWEEN 80 AND 443`
- **Set**: `tcp.dst_port IN (22, 80, 443)`
- **Packet numbers in filter**: `packet_number BETWEEN 1 AND 100`
- **Packet numbers via parameter**: use the `packet_number` parameter —
  e.g. `"42"`, `"1-100"`, `"1,5,10-20"`

### Nested fields

Fields can be nested with dots: `protocol.parent.child`. Call
`dsct_list_fields` with the protocol to see the full hierarchy — each entry's
`qualified_name` is exactly the filter path. Common examples:

| Filter path | Meaning |
| --- | --- |
| `dns.questions.name = 'example.com'` | DNS query name |
| `http.request.method = 'GET'` | HTTP request method |
| `icmp.invoking_packet.version = 4` | Nested header field |
| `dns.answers.type = 1` | DNS answer record type |

The `_name` suffix is a virtual field that resolves the display name of the
base field (e.g., `type_name` looks up the display name of `type`).

### Examples

```text
dns
tcp AND ipv4.src = '10.0.0.1'
dns OR (tcp AND ipv4.dst = '8.8.8.8')
NOT dns
tcp.dst_port > 1024
dns.questions.name = 'example.com'
http.request.method = 'GET'
packet_number BETWEEN 1 AND 100 AND tcp
```

Protocol names are normalized (case-insensitive, non-alphanumeric stripped),
so `HTTP/2` matches `http2`.

## Tips

- Always call `dsct_get_stats` before `dsct_read_packets` to understand
  capture size and pick appropriate filters.
- Start with `count: 20`–`50` to avoid flooding the context window.
- Use `verbose: true` only when low-level details (checksums, header lengths)
  are specifically needed.
- `decode_as` overrides protocol detection for non-standard ports
  (e.g. `["tcp.port=8080:http"]`).
- Field values in filters are matched against the raw JSON output (often numeric,
  not display strings). Read a few packets first to check actual field values.
- Use `sample_rate` for representative sampling across the full capture
  (e.g. `sample_rate: 100` outputs every 100th matching packet). Applied after
  filters, before `offset` and `count`.
- Default limit is 1000 packets when `count` is omitted.
- Per-tool timeout is 300 seconds. Both limits are configurable via environment
  variables (`DSCT_MCP_DEFAULT_COUNT`, `DSCT_MCP_TIMEOUT`).

## Output format

- `dsct_read_packets` returns `{"packets": [...]}` where each packet has
  `number`, `timestamp`, `length`, `stack`, and `layers` (array of protocol
  objects with `fields`).
- `dsct_get_stats` returns `{"total_packets", "duration_secs", "protocols", ...}`.
- Call `dsct_get_schema` with `command: "read"` or `command: "stats"` for the
  full JSON schema.
