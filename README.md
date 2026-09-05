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

Speed up filter evaluation on large files with `--threads`:

```bash
dsct read capture.pcap -f "udp" --no-limit --threads 4
DSCT_THREADS=4 dsct read capture.pcap -f "tcp.dst_port > 1024" --no-limit
```

`--threads` distributes dissection and filter evaluation across N worker
threads when the filter is stateless (L2–L4 protocols: `tcp`, `udp`, `ipv4`,
etc.).  Filters that require TCP reassembly such as `http`, `dns`, `tls`, and
`tcp.stream_id` automatically fall back to sequential processing regardless of
`--threads`.  Stdin input always uses the sequential path.

Query a capture with SQL (the SQLite index is built on first use and reused
afterwards):

```bash
dsct sql capture.pcap "SELECT number, stack FROM packets WHERE max_depth > 0 LIMIT 10"
dsct sql capture.pcap "SELECT * FROM tcp_segments WHERE flow_id = 0 ORDER BY packet_number"
dsct sql capture.pcap --schema
```

See [SQL queries](#sql-queries) for the database layout.

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
| `dsct index <FILE>` | Build (or refresh) the SQLite index used by `dsct sql` |
| `dsct sql <FILE> <QUERY>` | Run a read-only SQL query against the capture's SQLite index, rows as JSONL |
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
| `dsct_list_protocols` | List all supported protocols (`name`, `full_name`). |
| `dsct_list_fields` | List available field names for protocols. `qualified_name` is the path to use in `dsct_read_packets` `filter`/`fields`. |
| `dsct_get_schema` | Get the JSON schema for command output formats (`read`, `stats` or `sql`). |
| `dsct_query_sql` | Run a read-only SQL query against the capture's SQLite index (built on first use). Returns result rows plus index status; `schema: true` returns the table layout. |

### Protocol versions

The server speaks both protocol eras and picks one per request:

- **`2026-07-28`** (stateless): declare the version on every request via
  `params._meta` (`io.modelcontextprotocol/protocolVersion` and
  `io.modelcontextprotocol/clientCapabilities` are required), and probe with
  `server/discover`. `ping` is not served in this era.
- **`2025-11-25` / `2025-03-26` / `2024-11-05`** (legacy): negotiate via the
  `initialize` handshake as before.

### Key parameters

**`dsct_read_packets`**: `file` (required), `filter`, `count`, `offset`, `packet_number`, `decode_as`, `esp_sa`, `verbose`, `layers`, `fields`

- `layers`: protocol names to keep in each packet's `layers` array (`"BGP"` or
  `["IPv4", "TCP", "BGP"]`); `stack` is unaffected.
- `fields`: qualified field paths to keep (`"BGP.nlri"`,
  `"BGP.path_attributes.value.nlri.route_type"`); protocols not listed keep
  their default fields. The last segment accepts the `default_fields.toml`
  patterns (`prefix*`, `*suffix`).

Both are MCP-only and useful for large protocols such as BGP.

**`dsct_query_sql`**: `file` (required), `sql`, `schema`, `tables`, `count`, `db`, `no_build`, `decode_as`, `esp_sa`

- `schema: true` returns a compact list of tables and views; add
  `tables` (`"tcp"` or `["tcp", "bgp"]`) for full column detail.

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
| `DSCT_THREADS` | physical CPU count | Worker threads for `dsct read --filter` (see `--threads`) |
| `DSCT_CACHE_DIR` | `$XDG_CACHE_HOME/dsct`, else `$HOME/.cache/dsct` | Directory for `dsct sql`/`dsct index` database files (see [SQL queries](#sql-queries)) |

## Output

`dsct read` emits one JSON object per line:

```jsonl
{"number":1,"timestamp":"2024-01-15T10:30:00.123456Z","length":71,"original_length":71,"stack":"Ethernet:IPv4:UDP:DNS","layers":[{"protocol":"Ethernet","fields":{"dst":"ff:ff:ff:ff:ff:ff","src":"00:11:22:33:44:55","ethertype":2048,"ethertype_name":"IPv4"}},{"protocol":"IPv4","fields":{"ttl":64,"protocol":17,"src":"10.0.0.1","dst":"10.0.0.2"}},{"protocol":"UDP","fields":{"src_port":12345,"dst_port":53}},{"protocol":"DNS","fields":{"id":4660,"qr":0,"opcode":0,"rcode":0,"questions":[{"name":"example.com","type":1,"class":1}]}}]}
```

`dsct sql` emits one JSON object per result row, keyed by column name:

```jsonl
{"packet_number":2,"depth":1,"carrier_protocol":"VXLAN","carrier_layer_index":3}
```

SQLite `INTEGER` and `REAL` values become JSON numbers, `TEXT` becomes a
string, `BLOB` becomes a lowercase hex string and `NULL` becomes `null`.

The other commands emit a single JSON object or array on stdout.

## SQL queries

`dsct sql` dissects a capture once, stores every layer in a SQLite database,
and answers `SELECT` queries against it. The database is built on the first
query (or explicitly with `dsct index`) and reused as long as the capture, the
dsct version and the dissection options are unchanged; otherwise it is rebuilt
and a `{"warning":{"code":"index_rebuilt",...}}` line is written to stderr.

```bash
dsct index capture.pcap                 # build now (prints {"type":"index",...})
dsct sql capture.pcap --schema          # tables, columns, descriptions, hints
dsct sql capture.pcap "SELECT protocol, COUNT(*) AS n FROM layers GROUP BY protocol ORDER BY n DESC"
dsct sql ~/.cache/dsct/capture.pcap-3f2a9c1d8e4b0716.dsct.sqlite "SELECT COUNT(*) FROM packets"  # query an index directly
tcpdump -w - -c 1000 | dsct sql - --db /tmp/live.sqlite "SELECT * FROM conversations"
```

- The index lives in `$DSCT_CACHE_DIR`, else `$XDG_CACHE_HOME/dsct`, else
  `$HOME/.cache/dsct`, as `<name>-<hash of the capture path>.dsct.sqlite`;
  override with `--db PATH`. Reading from stdin requires `--db` and always
  rebuilds.
- `--schema` prints the table and view definitions; `--tables tcp,udp` narrows
  it.
- Like `dsct read`, output stops after **1 000 rows** by default; use
  `--count N` or `--no-limit`.
- Expect the index to take roughly one to three times the size of the capture.
  Flow tracking keeps one small entry per conversation in memory while building.

### Tables

| Table / view | Contents |
| --- | --- |
| `packets` | One row per packet: `number`, `timestamp`, `ts`, lengths, `link_type`, `stack`, `max_depth`, `dissect_error` |
| `layers` | One row per dissected layer: `packet_number`, `layer_index`, `depth`, `protocol`, `protocol_name`, `offset`, `length` |
| `<protocol>` | One table per protocol (`ipv4`, `tcp`, `dns`, `gtpv1u`, ...): one row per layer with a column per field, keyed by `packet_number`, `layer_index`, `depth` |
| `flows` | One row per transport conversation per depth: endpoints, packet/byte counts, first/last packet and time, `tcp_stream_id` |
| `packet_flows` | Maps transport layers to flows with `direction` (`0` = `addr_a` → `addr_b`, `1` = reverse) |
| `encapsulations` | View: for every tunnelled depth of a packet, the carrier protocol (`VXLAN`, `GRE`, `GTPv1-U`, ...) |
| `conversations` | View: `flows` plus `duration_secs` |
| `tcp_segments` | View: TCP rows joined with `packets`, including `seq_rel`, `ack_rel`, `next_seq`, `payload_len`, `flags_name` |

Protocol table names are the lowercase, alphanumeric form of the protocol name
(`GTPv1-U` → `gtpv1u`, `HTTP/2` → `http2`). Field columns keep their `dsct read`
names; fields with a display name also get a `<name>_name` text column
(`flags_name`, `ethertype_name`). Quote column names that collide with SQL
keywords (`"type"`, `"class"`, `"group"`, `"offset"`). Array and object fields
are stored as JSON text. Run `dsct sql <FILE> --schema` to list everything.

### Encapsulated and nested packets

Every layer carries an encapsulation `depth`: `0` for the outer packet, `1`
for the first tunnelled packet (VXLAN, Geneve, GRE, GTP-U, IP-in-IP, L2TP,
MPLS, decrypted ESP, ...), `2` for a tunnel inside a tunnel, and so on. Inner
headers are ordinary rows in the same protocol tables:

```bash
# Inner IPv4 headers carried inside tunnels
dsct sql capture.pcap "SELECT packet_number, \"src\", \"dst\" FROM ipv4 WHERE depth = 1"

# Which tunnel protocol carries each inner packet
dsct sql capture.pcap "SELECT carrier_protocol, COUNT(*) FROM encapsulations GROUP BY carrier_protocol"

# Inner TCP flows carried over GTP-U, joined with the outer tunnel endpoints
dsct sql capture.pcap "SELECT t.packet_number, o.\"src\" AS outer_src, i.\"src\" AS inner_src, t.\"dst_port\" \
  FROM tcp t JOIN ipv4 i ON i.packet_number = t.packet_number AND i.depth = t.depth \
  JOIN ipv4 o ON o.packet_number = t.packet_number AND o.depth = 0 WHERE t.depth = 1"

# Nested fields via SQLite JSON functions
dsct sql capture.pcap "SELECT p.number, json_extract(q.value, '$.name') AS qname \
  FROM dns d JOIN packets p ON p.number = d.packet_number, json_each(d.\"questions\") q"
```

### Following streams and sequences

`tcp`, `udp` and `sctp` rows carry a dsct-assigned `flow_id` (per depth) and a
`direction`; both directions of a conversation share one id. TCP rows also get
`payload_len`, `seq_rel` / `ack_rel` (relative to the first segment seen in each
direction) and `next_seq`:

```bash
# Busiest conversations
dsct sql capture.pcap "SELECT * FROM conversations ORDER BY bytes DESC LIMIT 10"

# Follow one TCP stream in order
dsct sql capture.pcap "SELECT packet_number, direction, seq_rel, ack_rel, payload_len, flags_name \
  FROM tcp_segments WHERE flow_id = 3 ORDER BY packet_number"

# Retransmissions: a data segment that starts before the end of an earlier segment in the same direction
dsct sql capture.pcap "SELECT DISTINCT a.packet_number FROM tcp_segments a JOIN tcp_segments b \
  ON a.flow_id = b.flow_id AND a.direction = b.direction AND b.packet_number < a.packet_number \
  WHERE a.payload_len > 0 AND b.payload_len > 0 AND a.seq_rel < b.seq_rel + b.payload_len"
```

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
| `2` | Invalid arguments (including rejected or malformed SQL queries) |
| `3` | File not found or permission denied |
| `4` | Invalid capture format |

## License

Licensed under either of [Apache License 2.0](LICENSE-APACHE) or [MIT License](LICENSE-MIT) at your option.
