# dsct — Gemini CLI Extension

`dsct` is an LLM-friendly packet dissector with a built-in MCP server.

## MCP tools

Use the `analyze-packets` skill for full workflow guidance.

| Tool | Purpose |
| --- | --- |
| `dsct_get_stats` | Capture overview: packet count, duration, protocol distribution |
| `dsct_read_packets` | Stream dissected packets as JSON with filtering and sampling |
| `dsct_list_protocols` | List all supported protocols |
| `dsct_list_fields` | List filterable field names for specific protocols |
| `dsct_get_schema` | JSON Schema for `read` or `stats` output |

## Quick guidance

- Always call `dsct_get_stats` before `dsct_read_packets` to size the capture.
- Start with `count: 50` when reading packets; each packet is ~100 tokens.
- Use `protocols` in `dsct_list_fields` — omitting it returns ~56K tokens.
- Use `sample_rate` to get evenly-distributed packets from large captures.
