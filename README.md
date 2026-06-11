# dsct

[![crates.io](https://img.shields.io/crates/v/dsct.svg)](https://crates.io/crates/dsct)
[![docs.rs](https://docs.rs/dsct/badge.svg)](https://docs.rs/dsct)
[![MSRV](https://img.shields.io/badge/rustc-1.88+-blue.svg)](https://blog.rust-lang.org/2025/06/26/Rust-1.88.0/)
[![CI](https://github.com/higebu/dsct/actions/workflows/ci.yml/badge.svg)](https://github.com/higebu/dsct/actions/workflows/ci.yml)
[![codecov](https://codecov.io/github/higebu/dsct/graph/badge.svg?token=EaeOxnsedN)](https://codecov.io/github/higebu/dsct)

`dsct` is a packet dissector CLI for LLMs and large captures.

It is built around two ideas:

- machine-readable output by default
- predictable memory use on big `pcap` / `pcapng` files

`dsct read` streams packet records as JSONL, `dsct stats` scans captures in a single pass, and the optional TUI opens large files with memory mapping and on-demand dissection instead of decoding the whole capture up front.

## Why dsct

### LLM-friendly by default

- `dsct read` emits JSONL packet records
- `dsct stats`, `dsct list`, `dsct fields`, `dsct version`, and `dsct schema` emit JSON
- errors, warnings, and progress updates are structured JSON on stderr
- capabilities and schemas can be discovered from the CLI itself

### Works well on large captures

- `read` and `stats` process captures one packet at a time
- stdin is supported, so `tcpdump -w - | dsct ...` works naturally
- no human-oriented table parsing is required before automation can start

### MCP server built in

`dsct mcp` starts a [Model Context Protocol](https://modelcontextprotocol.io/) server over stdio. AI agents can call tools like `dsct_read_packets` and `dsct_get_stats` directly, without shelling out to the CLI.

### Low-memory TUI for large files

The optional TUI is designed for large captures too:

- capture files are opened with memory-mapped I/O
- indexing starts from packet headers instead of fully decoding every packet
- packet list rows are dissected on demand for visible rows
- the selected packet is decoded in detail only when needed
- the hex view reads directly from the mapped file

## Installation

CLI only:

```bash
cargo install dsct
```

With the optional TUI:

```bash
cargo install dsct --features tui
```

```bash
brew install higebu/tap/dsct
```

## AI coding agent plugins

Install as a plugin via the marketplace to get the MCP server and the
`analyze-packets` skill automatically:

**Claude Code**

```bash
claude plugin marketplace add higebu/dsct
claude plugin install dsct@dsct
```

**GitHub Copilot CLI**

```bash
copilot plugin marketplace add higebu/dsct
copilot plugin install dsct@dsct
```

**OpenAI Codex CLI**

Add the MCP server, then install the `analyze-packets` skill inside Codex:

```bash
codex mcp add dsct -- dsct mcp
```

```text
$skill-installer higebu/dsct skills/analyze-packets
```

**Gemini CLI**

```bash
gemini extensions install https://github.com/higebu/dsct
```

## Quick start

Get a capture overview:

```bash
dsct stats capture.pcap
```

Read packets as JSONL:

```bash
dsct read capture.pcap
```

By default, `dsct read` outputs at most **1 000 packets**. Use `--count` to
change the limit or `--no-limit` to remove it:

```bash
dsct read capture.pcap --count 50
dsct read capture.pcap --no-limit
```

Filter packets:

```bash
dsct read capture.pcap -f dns --count 10
dsct read capture.pcap -f "dns AND dns.qr = 'Query'"
```

Filter expressions use SQL syntax with `AND`, `OR`, `NOT`, parentheses, and
comparison operators (`=`, `!=`, `>`, `<`, `>=`, `<=`):

```bash
dsct read capture.pcap -f "dns OR (tcp AND ipv4.src = '10.0.0.1')"
dsct read capture.pcap -f "tcp.dst_port > 1024 AND NOT dns"
```

Sample evenly across the capture:

```bash
dsct read capture.pcap --sample-rate 100
dsct read capture.pcap -f dns --sample-rate 10 --count 50
```

Read from a pipe:

```bash
tcpdump -w - -c 1000 | dsct read -
tcpdump -w - -i eth0 udp port 53 | dsct read - -f dns
```

Include the original packet bytes (link-layer included) as a hex string under
`raw_bytes` for downstream parsing or reconstruction:

```bash
dsct read capture.pcap --raw-bytes --count 1
```

#### Parallel filtering

For large capture **files** (not stdin), `dsct read` can evaluate a filter
across multiple worker threads. The thread count defaults to the number of
available CPUs and can be overridden with the `--threads` flag or the
`DSCT_THREADS` environment variable:

```bash
dsct read capture.pcap -f icmp --threads 8
DSCT_THREADS=8 dsct read capture.pcap -f icmp
```

Parallelism is engaged conservatively to preserve the exact JSONL output: only
file input with a filter whose matches can never be a TCP segment (e.g. `icmp`,
`arp`, `igmp`, `icmpv6`) uses the parallel path. Because TCP reassembly is
stateful and order-dependent, all other filters — and stdin streaming, the
no-filter fast path, and `--progress` — fall back to the single-threaded
streaming path. Output order is always packet-number order regardless of the
thread count.

Inspect available fields and schemas:

```bash
dsct fields dns
dsct schema read
```

Open the TUI for a large file (when built with `--features tui`):

```bash
dsct tui capture.pcap
```

In the TUI, press `?` to open the built-in help overlay and `q` to quit.

Filtering a multi-gigabyte capture in the TUI uses all available CPU cores when
the filter's match decision is independent of TCP reassembly (transport-layer
and below — e.g. `tcp`, `udp`, `ipv4.src = ...`, `tcp.port = 443`). Set
`DSCT_THREADS` to override the worker count. Application-layer filters that rely
on TCP reassembly (e.g. `http`, `tls`) use the incremental single-threaded scan.

## Typical workflow

```bash
# 1. Discover supported protocols
dsct list

# 2. Inspect available filter fields
dsct fields dns

# 3. Read matching packets as JSONL
dsct read capture.pcap -f "dns AND dns.qr = 'Query'" --count 20

# 4. Get capture-wide statistics
dsct stats capture.pcap --top-talkers
```

## Commands

| Command | What it does |
| --- | --- |
| `dsct read <FILE>` | Stream packet records as JSONL |
| `dsct stats <FILE>` | Emit capture statistics as JSON |
| `dsct list` | List supported protocols as JSON |
| `dsct fields [PROTOCOL...]` | List filterable fields as JSON |
| `dsct schema [COMMAND]` | Show JSON Schema for command output |
| `dsct version` | Show version and capability information as JSON |
| `dsct mcp` | Start an MCP server over stdio |
| `dsct tui <FILE>` | Open the interactive TUI for a capture file (`tui` feature only) |

Run `--help` on any command for the full option list.

## MCP tools

`dsct mcp` exposes the following tools over the Model Context Protocol:

| Tool | Description |
| --- | --- |
| `dsct_read_packets` | Dissect packets from a pcap/pcapng capture file. Returns an array of dissected packet objects with protocol layers and fields. |
| `dsct_get_stats` | Get protocol statistics from a capture file. Returns packet counts, timing, protocol distribution, and optional deep analysis. |
| `dsct_list_protocols` | List all supported protocols with their specification references and layer information. |
| `dsct_list_fields` | List available field names for protocols. Fields can be used with `dsct_read_packets` for filtering. |
| `dsct_get_schema` | Get the JSON schema for command output formats (`read` or `stats`). |

### Key parameters

**`dsct_read_packets`**: `file` (required), `filter`, `count`, `offset`, `packet_number`, `decode_as`, `esp_sa`, `verbose`

**`dsct_get_stats`**: `file` (required), `protocol`, `top_talkers`, `stream_summary`, `top`, `decode_as`, `esp_sa`

**`dsct_list_fields`**: `protocol`

**`dsct_get_schema`**: `command` (`"read"` or `"stats"`)

### Configuration example

Add `dsct` to your MCP client (e.g. Claude Desktop):

```json
{
  "mcpServers": {
    "dsct": {
      "command": "dsct",
      "args": ["mcp"]
    }
  }
}
```

### Default limits

When `count` is omitted, `dsct_read_packets` returns at most **1 000 packets**
(configurable via `DSCT_MCP_DEFAULT_COUNT`). `dsct_get_stats` processes the
entire capture by default. All tool calls are subject to a per-execution
timeout; on timeout the server returns a JSON-RPC error and no partial output
is sent.

### Environment variables

Resource limits can be tuned via environment variables:

| Variable | Default | Description |
| --- | --- | --- |
| `DSCT_MCP_DEFAULT_COUNT` | 1000 | Default packet count when `count` is not specified |
| `DSCT_MCP_TIMEOUT` | 300 | Timeout per tool execution in seconds |
| `DSCT_MCP_WRITE_BUFFER_SIZE` | 65536 | Stdout write buffer size in bytes |
| `DSCT_MCP_MAX_FILE_SIZE` | 10737418240 | Maximum capture file size in bytes |

## Output

`dsct read` emits one JSON object per line:

```jsonl
{"number":1,"timestamp":"2024-01-15T10:30:00.123456Z","length":71,"original_length":71,"stack":"Ethernet:IPv4:UDP:DNS","layers":[{"protocol":"Ethernet","fields":{"dst":"ff:ff:ff:ff:ff:ff","src":"00:11:22:33:44:55","ethertype":2048,"ethertype_name":"IPv4"}},{"protocol":"IPv4","fields":{"ttl":64,"protocol":17,"src":"10.0.0.1","dst":"10.0.0.2"}},{"protocol":"UDP","fields":{"src_port":12345,"dst_port":53}},{"protocol":"DNS","fields":{"id":4660,"qr":0,"opcode":0,"rcode":0,"questions":[{"name":"example.com","type":1,"class":1}]}}]}
```

The other commands emit a single JSON object or array on stdout.

## Supported protocols

The default build currently includes 50+ protocol dissectors across link, network, transport, tunneling, and application layers.

Use `dsct list` to see the exact protocol set in your build.

## Errors

Errors and warnings are emitted as structured JSON on stderr.

Example:

```json
{"error":{"code":"file_not_found","message":"failed to open capture file: test.pcap"}}
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Success |
| `1` | General error |
| `2` | Invalid arguments |
| `3` | File not found or permission denied |
| `4` | Invalid capture format |

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
