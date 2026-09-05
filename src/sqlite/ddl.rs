//! Database schema generation.
//!
//! The base tables (`meta`, `packets`, `layers`, `flows`, `packet_flows`)
//! are fixed.  One wide table per protocol is generated from the dissector
//! field schemas ([`DissectorRegistry::all_field_schemas`]): every top-level
//! [`FieldDescriptor`] becomes a column, fields with a `display_fn` get an
//! additional `<name>_name` text column, and the transport tables (`tcp`,
//! `udp`, `sctp`) carry dsct-computed flow columns.

use std::collections::{HashMap, HashSet};

use packet_dissector::registry::{DissectorRegistry, ProtocolFieldSchema};
use packet_dissector_core::field::{FieldDescriptor, FieldType};
use rusqlite::Connection;

use crate::filter::normalize_protocol_name;
use crate::schema::field_type_str;

/// Names of the fixed (non-protocol) tables.
pub const BASE_TABLES: &[&str] = &["meta", "packets", "layers", "flows", "packet_flows"];

/// Column names reserved by dsct in every protocol table.
const RESERVED_COLUMNS: &[&str] = &[
    "packet_number",
    "layer_index",
    "depth",
    "extra",
    "flow_id",
    "direction",
    "payload_len",
    "seq_rel",
    "ack_rel",
    "next_seq",
];

/// `(name, type, description)` of the key columns shared by all protocol tables.
const KEY_COLUMNS: [(&str, &str, &str); 3] = [
    (
        "packet_number",
        "INTEGER",
        "1-based packet number (joins packets.number)",
    ),
    (
        "layer_index",
        "INTEGER",
        "0-based position of this layer within the packet (joins layers.layer_index)",
    ),
    (
        "depth",
        "INTEGER",
        "Encapsulation depth: 0 = outermost, 1 = first tunnelled packet, ...",
    ),
];

const EXTRA_COLUMN: (&str, &str, &str) = (
    "extra",
    "TEXT",
    "JSON object with fields that have no dedicated column (NULL when none)",
);

/// Flow columns added to `tcp`, `udp` and `sctp`.
const FLOW_COLUMNS: [(&str, &str, &str); 2] = [
    (
        "flow_id",
        "INTEGER",
        "dsct flow id (joins flows.id); NULL when no IP layer precedes this layer at the same depth",
    ),
    (
        "direction",
        "INTEGER",
        "0 = addr_a:port_a -> addr_b:port_b, 1 = reverse (see flows)",
    ),
];

/// Sequence-tracking columns added to `tcp`.
const TCP_DERIVED_COLUMNS: [(&str, &str, &str); 4] = [
    (
        "payload_len",
        "INTEGER",
        "TCP payload length on the wire derived from the enclosing IP header",
    ),
    (
        "seq_rel",
        "INTEGER",
        "Sequence number relative to the first segment seen in this direction",
    ),
    (
        "ack_rel",
        "INTEGER",
        "Acknowledgment number relative to the first sequence number seen in the opposite direction (NULL until known)",
    ),
    (
        "next_seq",
        "INTEGER",
        "seq + payload_len (+1 for SYN, +1 for FIN), modulo 2^32",
    ),
];

/// Where a protocol-table column gets its value from during ingestion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnSource {
    /// Key column (`packet_number`, `layer_index`, `depth`).
    Key,
    /// Value of the field with the given descriptor index.
    Field(usize),
    /// `display_fn` companion of the field with the given descriptor index.
    DisplayName(usize),
    /// JSON object of unknown fields.
    Extra,
    /// Flow id / direction computed by dsct.
    Flow,
    /// TCP sequence columns computed by dsct.
    TcpDerived,
}

/// One column of a generated protocol table.
#[derive(Debug, Clone)]
pub struct ColumnSpec {
    /// Column name (unquoted).
    pub name: String,
    /// SQLite type affinity keyword.
    pub sql_type: &'static str,
    /// Human-readable description for `--schema`.
    pub description: String,
    /// Value source.
    pub source: ColumnSource,
}

/// A generated protocol table.
#[derive(Debug, Clone)]
pub struct TableSpec {
    /// Table name (unquoted, e.g. `tcp`).
    pub name: String,
    /// Protocol short name as used in `Layer::name` (e.g. `TCP`).
    pub protocol: &'static str,
    /// Full protocol name (e.g. `Transmission Control Protocol`).
    pub protocol_name: &'static str,
    /// Field descriptors of the protocol.
    pub descriptors: &'static [FieldDescriptor],
    /// Columns in table order.
    pub columns: Vec<ColumnSpec>,
    /// Field name → index into `columns` of its value column.
    pub field_columns: HashMap<&'static str, usize>,
    /// Field name → index into `columns` of its `<name>_name` column.
    pub name_columns: HashMap<&'static str, usize>,
    /// Index into `columns` of the `extra` column.
    pub extra_column: usize,
    /// Index of `flow_id` (followed by `direction`), when present.
    pub flow_column: Option<usize>,
    /// Index of `payload_len` (followed by `seq_rel`, `ack_rel`, `next_seq`), when present.
    pub tcp_column: Option<usize>,
}

impl TableSpec {
    /// `CREATE TABLE` statement for this table.
    pub fn create_sql(&self) -> String {
        let mut cols: Vec<String> = Vec::with_capacity(self.columns.len() + 1);
        for c in &self.columns {
            let not_null = if c.source == ColumnSource::Key {
                " NOT NULL"
            } else {
                ""
            };
            cols.push(format!(
                "{} {}{}",
                quote_ident(&c.name),
                c.sql_type,
                not_null
            ));
        }
        cols.push("PRIMARY KEY (\"packet_number\", \"layer_index\")".to_owned());
        format!(
            "CREATE TABLE {} (\n  {}\n)",
            quote_ident(&self.name),
            cols.join(",\n  ")
        )
    }

    /// `INSERT` statement with one positional parameter per column.
    pub fn insert_sql(&self) -> String {
        let names: Vec<String> = self.columns.iter().map(|c| quote_ident(&c.name)).collect();
        let params: Vec<&str> = std::iter::repeat_n("?", self.columns.len()).collect();
        format!(
            "INSERT INTO {} ({}) VALUES ({})",
            quote_ident(&self.name),
            names.join(", "),
            params.join(", ")
        )
    }

    /// Return `true` if the table has a column with the given name.
    pub fn has_column(&self, name: &str) -> bool {
        self.columns.iter().any(|c| c.name == name)
    }
}

/// Quote an SQL identifier with double quotes.
pub fn quote_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Table name for a protocol short name (e.g. `GTPv1-U` → `gtpv1u`).
///
/// Names that would collide with a base table are prefixed with `proto_`.
pub fn table_name(short_name: &str) -> String {
    let n = normalize_protocol_name(short_name);
    if n.is_empty() || BASE_TABLES.contains(&n.as_str()) || VIEW_NAMES.contains(&n.as_str()) {
        format!("proto_{n}")
    } else {
        n
    }
}

/// SQLite type affinity for a dissector field type.
pub fn sql_type_for(ft: FieldType) -> &'static str {
    match ft {
        FieldType::U8 | FieldType::U16 | FieldType::U32 | FieldType::U64 | FieldType::I32 => {
            "INTEGER"
        }
        // BLOB affinity stores every value as-is (no coercion), which is what
        // a field whose runtime type varies per packet needs.
        FieldType::Bytes | FieldType::Any => "BLOB",
        FieldType::Ipv4Addr
        | FieldType::Ipv6Addr
        | FieldType::MacAddr
        | FieldType::Str
        | FieldType::Array
        | FieldType::Object => "TEXT",
    }
}

/// Pick a unique, non-reserved column name.
fn unique_column_name(base: &str, used: &mut HashSet<String>) -> Option<String> {
    [base.to_owned(), format!("field_{base}")]
        .into_iter()
        .find(|c| !RESERVED_COLUMNS.contains(&c.as_str()) && used.insert(c.clone()))
}

/// Build the table specification for one protocol schema.
pub fn table_for_schema(schema: &ProtocolFieldSchema) -> TableSpec {
    let mut columns = Vec::new();
    let mut used: HashSet<String> = HashSet::new();
    let mut field_columns = HashMap::new();
    let mut name_columns = HashMap::new();

    for (name, ty, desc) in KEY_COLUMNS {
        used.insert(name.to_owned());
        columns.push(ColumnSpec {
            name: name.to_owned(),
            sql_type: ty,
            description: desc.to_owned(),
            source: ColumnSource::Key,
        });
    }

    for (i, fd) in schema.fields.iter().enumerate() {
        if field_columns.contains_key(fd.name) {
            continue; // duplicate descriptor name: first wins
        }
        let Some(col_name) = unique_column_name(fd.name, &mut used) else {
            continue;
        };
        let mut description = format!("{} ({})", fd.display_name, field_type_str(fd.field_type));
        if matches!(fd.field_type, FieldType::Array | FieldType::Object) {
            description.push_str("; JSON text, query with json_extract()/json_each()");
        } else if fd.field_type == FieldType::Any {
            description.push_str("; type varies per packet, structured values are JSON text");
        }
        if fd.optional {
            description.push_str("; optional");
        }
        field_columns.insert(fd.name, columns.len());
        columns.push(ColumnSpec {
            name: col_name,
            sql_type: sql_type_for(fd.field_type),
            description,
            source: ColumnSource::Field(i),
        });
        if fd.display_fn.is_some()
            && let Some(name_col) = unique_column_name(&format!("{}_name", fd.name), &mut used)
        {
            name_columns.insert(fd.name, columns.len());
            columns.push(ColumnSpec {
                name: name_col,
                sql_type: "TEXT",
                description: format!("Display name for {}", fd.name),
                source: ColumnSource::DisplayName(i),
            });
        }
    }

    let extra_column = columns.len();
    columns.push(ColumnSpec {
        name: EXTRA_COLUMN.0.to_owned(),
        sql_type: EXTRA_COLUMN.1,
        description: EXTRA_COLUMN.2.to_owned(),
        source: ColumnSource::Extra,
    });

    let is_transport = matches!(schema.short_name, "TCP" | "UDP" | "SCTP");
    let flow_column = is_transport.then(|| {
        let idx = columns.len();
        for (name, ty, desc) in FLOW_COLUMNS {
            columns.push(ColumnSpec {
                name: name.to_owned(),
                sql_type: ty,
                description: desc.to_owned(),
                source: ColumnSource::Flow,
            });
        }
        idx
    });
    let tcp_column = (schema.short_name == "TCP").then(|| {
        let idx = columns.len();
        for (name, ty, desc) in TCP_DERIVED_COLUMNS {
            columns.push(ColumnSpec {
                name: name.to_owned(),
                sql_type: ty,
                description: desc.to_owned(),
                source: ColumnSource::TcpDerived,
            });
        }
        idx
    });

    TableSpec {
        name: table_name(schema.short_name),
        protocol: schema.short_name,
        protocol_name: schema.name,
        descriptors: schema.fields,
        columns,
        field_columns,
        name_columns,
        extra_column,
        flow_column,
        tcp_column,
    }
}

/// Build table specifications for every protocol in the registry, sorted by
/// table name.
pub fn protocol_tables(registry: &DissectorRegistry) -> Vec<TableSpec> {
    let mut tables: Vec<TableSpec> = registry
        .all_field_schemas()
        .iter()
        .map(table_for_schema)
        .collect();
    tables.sort_by(|a, b| a.name.cmp(&b.name));
    tables.dedup_by(|a, b| a.name == b.name);
    tables
}

/// Names of the convenience views.
pub const VIEW_NAMES: &[&str] = &["encapsulations", "conversations", "tcp_segments"];

/// DDL for the fixed tables.
pub const BASE_DDL: &str = r#"
CREATE TABLE meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
CREATE TABLE packets (
  number INTEGER PRIMARY KEY,
  ts_secs INTEGER NOT NULL,
  ts_usecs INTEGER NOT NULL,
  timestamp TEXT NOT NULL,
  ts REAL NOT NULL,
  captured_length INTEGER NOT NULL,
  original_length INTEGER NOT NULL,
  link_type INTEGER NOT NULL,
  stack TEXT NOT NULL,
  layer_count INTEGER NOT NULL,
  max_depth INTEGER NOT NULL,
  dissect_error TEXT
);
CREATE TABLE layers (
  packet_number INTEGER NOT NULL,
  layer_index INTEGER NOT NULL,
  depth INTEGER NOT NULL,
  protocol TEXT NOT NULL,
  protocol_name TEXT NOT NULL,
  "offset" INTEGER NOT NULL,
  length INTEGER NOT NULL,
  PRIMARY KEY (packet_number, layer_index)
);
CREATE TABLE flows (
  id INTEGER PRIMARY KEY,
  transport TEXT NOT NULL,
  depth INTEGER NOT NULL,
  addr_a TEXT NOT NULL,
  port_a INTEGER NOT NULL,
  addr_b TEXT NOT NULL,
  port_b INTEGER NOT NULL,
  tcp_stream_id INTEGER,
  first_packet INTEGER NOT NULL,
  last_packet INTEGER NOT NULL,
  packets INTEGER NOT NULL,
  bytes INTEGER NOT NULL,
  first_ts REAL NOT NULL,
  last_ts REAL NOT NULL
);
CREATE TABLE packet_flows (
  packet_number INTEGER NOT NULL,
  layer_index INTEGER NOT NULL,
  flow_id INTEGER NOT NULL,
  direction INTEGER NOT NULL,
  PRIMARY KEY (packet_number, layer_index)
);
CREATE VIEW encapsulations AS
  SELECT l.packet_number, l.depth,
         c.protocol AS carrier_protocol, c.layer_index AS carrier_layer_index
  FROM layers l
  JOIN layers c
    ON c.packet_number = l.packet_number
   AND c.layer_index = (
     SELECT MAX(x.layer_index) FROM layers x
     WHERE x.packet_number = l.packet_number
       AND x.layer_index < l.layer_index
       AND x.depth = l.depth - 1)
  WHERE l.depth > 0
    AND l.layer_index = (
      SELECT MIN(y.layer_index) FROM layers y
      WHERE y.packet_number = l.packet_number AND y.depth = l.depth);
CREATE VIEW conversations AS
  SELECT f.id, f.transport, f.depth, f.addr_a, f.port_a, f.addr_b, f.port_b,
         f.tcp_stream_id, f.packets, f.bytes, f.first_packet, f.last_packet,
         f.first_ts, f.last_ts, (f.last_ts - f.first_ts) AS duration_secs
  FROM flows f;
"#;

/// View over the `tcp` table for following sequence numbers.
const TCP_SEGMENTS_VIEW: &str = r#"
CREATE VIEW tcp_segments AS
  SELECT p.number AS packet_number, p.timestamp, p.ts, t.depth, t.flow_id, t.direction,
         t."seq" AS seq, t."ack" AS ack, t.seq_rel, t.ack_rel, t.payload_len, t.next_seq,
         t."flags" AS flags, t."flags_name" AS flags_name, t."stream_id" AS stream_id
  FROM tcp t JOIN packets p ON p.number = t.packet_number;
"#;

/// Create every table and view in a fresh database.
pub fn create_schema(conn: &Connection, tables: &[TableSpec]) -> rusqlite::Result<()> {
    conn.execute_batch(BASE_DDL)?;
    for t in tables {
        conn.execute_batch(&t.create_sql())?;
    }
    let has_tcp_view_columns = tables.iter().any(|t| {
        t.name == "tcp"
            && t.tcp_column.is_some()
            && ["seq", "ack", "flags", "flags_name", "stream_id"]
                .iter()
                .all(|c| t.has_column(c))
    });
    if has_tcp_view_columns {
        conn.execute_batch(TCP_SEGMENTS_VIEW)?;
    }
    Ok(())
}

/// Index statements, to be run after bulk insertion.
pub fn index_ddl(tables: &[TableSpec]) -> Vec<String> {
    let mut ddl = vec![
        "CREATE INDEX idx_layers_protocol ON layers(protocol)".to_owned(),
        "CREATE INDEX idx_layers_packet_depth ON layers(packet_number, depth)".to_owned(),
        "CREATE INDEX idx_packets_ts ON packets(ts)".to_owned(),
        "CREATE INDEX idx_packet_flows_flow ON packet_flows(flow_id)".to_owned(),
    ];
    let wanted: &[(&str, &[&str])] = &[
        ("ipv4", &["src", "dst"]),
        ("ipv6", &["src", "dst"]),
        ("tcp", &["flow_id", "stream_id"]),
        ("udp", &["flow_id"]),
        ("sctp", &["flow_id"]),
    ];
    for (table, cols) in wanted {
        let Some(t) = tables.iter().find(|t| t.name == *table) else {
            continue;
        };
        for col in *cols {
            if t.has_column(col) {
                ddl.push(format!(
                    "CREATE INDEX {} ON {}({})",
                    quote_ident(&format!("idx_{table}_{col}")),
                    quote_ident(table),
                    quote_ident(col)
                ));
            }
        }
    }
    ddl
}

/// Description of a column of a base table or view, for `--schema` output.
pub fn describe_base_column(table: &str, column: &str) -> Option<&'static str> {
    let desc = match (table, column) {
        ("meta", "key") => "Metadata key (schema_version, dsct_version, source_path, ...)",
        ("meta", "value") => "Metadata value",
        ("packets", "number") => "1-based packet number within the capture",
        ("packets", "ts_secs") => "Capture timestamp, seconds since the Unix epoch",
        ("packets", "ts_usecs") => "Sub-second part of the timestamp in microseconds",
        ("packets", "timestamp") => "ISO 8601 timestamp (same as dsct read)",
        ("packets", "ts") => "Timestamp as floating-point seconds since the Unix epoch",
        ("packets", "captured_length") => "Number of bytes captured",
        ("packets", "original_length") => "Original length on the wire",
        ("packets", "link_type") => "pcap link-layer header type",
        ("packets", "stack") => "Protocol stack summary, e.g. Ethernet:IPv4:UDP:DNS",
        ("packets", "layer_count") => "Number of dissected layers",
        ("packets", "max_depth") => "Highest encapsulation depth in the packet",
        ("packets", "dissect_error") => "Dissection error message, NULL on success",
        ("layers", "packet_number") => "Packet number (joins packets.number)",
        ("layers", "layer_index") => "0-based position of the layer, outermost first",
        ("layers", "depth") => "Encapsulation depth: 0 = outermost",
        ("layers", "protocol") => {
            "Protocol short name, e.g. IPv4 (table name is its lowercase form)"
        }
        ("layers", "protocol_name") => "Version-qualified display name, e.g. TLSv1.2",
        ("layers", "offset") => "Byte offset of the layer header in the packet",
        ("layers", "length") => "Byte length of the layer header",
        ("flows", "id") => "Flow id (referenced by tcp/udp/sctp.flow_id)",
        ("flows", "transport") => "tcp, udp or sctp",
        ("flows", "depth") => "Encapsulation depth of the flow",
        ("flows", "addr_a") => "Lower endpoint address (direction 0 = a -> b)",
        ("flows", "port_a") => "Lower endpoint port",
        ("flows", "addr_b") => "Upper endpoint address",
        ("flows", "port_b") => "Upper endpoint port",
        ("flows", "tcp_stream_id") => "Dissector TCP stream_id (NULL for udp/sctp)",
        ("flows", "first_packet") => "First packet number of the flow",
        ("flows", "last_packet") => "Last packet number of the flow",
        ("flows", "packets") => "Packet count",
        ("flows", "bytes") => "Sum of original packet lengths",
        ("flows", "first_ts") => "Timestamp of the first packet (seconds)",
        ("flows", "last_ts") => "Timestamp of the last packet (seconds)",
        ("packet_flows", "packet_number") => "Packet number",
        ("packet_flows", "layer_index") => "Layer index of the transport layer",
        ("packet_flows", "flow_id") => "Flow id (joins flows.id)",
        ("packet_flows", "direction") => "0 = a -> b, 1 = b -> a",
        ("encapsulations", "packet_number") => "Packet number",
        ("encapsulations", "depth") => "Inner depth (>= 1)",
        ("encapsulations", "carrier_protocol") => {
            "Tunnel protocol carrying this depth, e.g. VXLAN, GRE, GTPv1-U"
        }
        ("encapsulations", "carrier_layer_index") => "Layer index of the carrier protocol",
        ("conversations", "duration_secs") => "last_ts - first_ts",
        ("conversations", _) => return describe_base_column("flows", column),
        ("tcp_segments", "packet_number") => "Packet number",
        ("tcp_segments", "timestamp") => "ISO 8601 timestamp",
        ("tcp_segments", "ts") => "Timestamp as floating-point seconds",
        ("tcp_segments", "seq") => "Raw sequence number",
        ("tcp_segments", "ack") => "Raw acknowledgment number",
        ("tcp_segments", "flags") => "TCP flags byte",
        ("tcp_segments", "flags_name") => "TCP flags as text, e.g. SYN, ACK",
        ("tcp_segments", "stream_id") => "Dissector TCP stream_id",
        ("tcp_segments", _) => {
            return TCP_DERIVED_COLUMNS
                .iter()
                .chain(FLOW_COLUMNS.iter())
                .chain(KEY_COLUMNS.iter())
                .find(|(n, _, _)| *n == column)
                .map(|(_, _, d)| *d);
        }
        _ => return None,
    };
    Some(desc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use packet_dissector_core::field::FieldValue;

    fn desc(name: &'static str, ft: FieldType) -> FieldDescriptor {
        FieldDescriptor::new(name, name, ft)
    }

    #[test]
    fn table_name_normalizes_and_avoids_base_tables() {
        assert_eq!(table_name("GTPv1-U"), "gtpv1u");
        assert_eq!(table_name("HTTP/2"), "http2");
        assert_eq!(table_name("IPv4"), "ipv4");
        assert_eq!(table_name("Packets"), "proto_packets");
        assert_eq!(table_name("Flows"), "proto_flows");
    }

    #[test]
    fn quote_ident_escapes_quotes() {
        assert_eq!(quote_ident("type"), "\"type\"");
        assert_eq!(quote_ident("a\"b"), "\"a\"\"b\"");
    }

    #[test]
    fn sql_types() {
        assert_eq!(sql_type_for(FieldType::U64), "INTEGER");
        assert_eq!(sql_type_for(FieldType::Bytes), "BLOB");
        assert_eq!(sql_type_for(FieldType::Any), "BLOB");
        assert_eq!(sql_type_for(FieldType::Ipv6Addr), "TEXT");
        assert_eq!(sql_type_for(FieldType::Array), "TEXT");
    }

    #[test]
    fn reserved_and_duplicate_field_names_are_renamed() {
        static FIELDS: &[FieldDescriptor] = &[
            FieldDescriptor::new("depth", "Depth", FieldType::U8),
            FieldDescriptor::new("type", "Type", FieldType::U8),
            FieldDescriptor::new("type", "Type again", FieldType::U16),
        ];
        let schema = ProtocolFieldSchema {
            name: "Test Protocol",
            short_name: "Test",
            fields: FIELDS,
        };
        let t = table_for_schema(&schema);
        let names: Vec<&str> = t.columns.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(
            names,
            vec![
                "packet_number",
                "layer_index",
                "depth",
                "field_depth",
                "type",
                "extra"
            ]
        );
        assert_eq!(t.field_columns["depth"], 3);
        assert_eq!(t.field_columns["type"], 4);
        assert!(t.flow_column.is_none());
        assert!(t.tcp_column.is_none());
        let sql = t.create_sql();
        assert!(sql.contains("\"field_depth\" INTEGER"));
        assert!(sql.contains("\"type\" INTEGER"));
        assert!(sql.contains("PRIMARY KEY (\"packet_number\", \"layer_index\")"));
    }

    #[test]
    fn display_fn_adds_name_column() {
        fn display(
            _: &FieldValue<'_>,
            _: &[packet_dissector_core::field::Field<'_>],
        ) -> Option<&'static str> {
            Some("x")
        }
        static FIELDS: &[FieldDescriptor] = &[FieldDescriptor {
            name: "flags",
            display_name: "Flags",
            field_type: FieldType::U8,
            optional: false,
            children: None,
            display_fn: Some(display),
            format_fn: None,
        }];
        let schema = ProtocolFieldSchema {
            name: "TCP",
            short_name: "TCP",
            fields: FIELDS,
        };
        let t = table_for_schema(&schema);
        assert_eq!(t.name, "tcp");
        assert_eq!(t.columns[t.name_columns["flags"]].name, "flags_name");
        assert_eq!(t.columns[t.name_columns["flags"]].sql_type, "TEXT");
        let flow = t.flow_column.unwrap();
        assert_eq!(t.columns[flow].name, "flow_id");
        assert_eq!(t.columns[flow + 1].name, "direction");
        let tcp = t.tcp_column.unwrap();
        assert_eq!(t.columns[tcp].name, "payload_len");
        assert_eq!(t.columns[tcp + 3].name, "next_seq");
        let insert = t.insert_sql();
        assert_eq!(insert.matches('?').count(), t.columns.len());
    }

    #[test]
    fn registry_tables_create_in_memory() {
        let registry = DissectorRegistry::default();
        let tables = protocol_tables(&registry);
        assert!(tables.iter().any(|t| t.name == "tcp"));
        assert!(tables.iter().any(|t| t.name == "ipv4"));
        let conn = Connection::open_in_memory().unwrap();
        create_schema(&conn, &tables).unwrap();
        for ddl in index_ddl(&tables) {
            conn.execute_batch(&ddl).unwrap();
        }
        let n: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'view' AND name = 'tcp_segments'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(n, 1);
    }

    #[test]
    fn base_column_descriptions() {
        assert!(describe_base_column("packets", "stack").is_some());
        assert!(describe_base_column("conversations", "addr_a").is_some());
        assert!(describe_base_column("tcp_segments", "seq_rel").is_some());
        assert!(describe_base_column("nope", "x").is_none());
    }

    #[test]
    fn descriptor_helper_is_used() {
        let d = desc("x", FieldType::Str);
        assert_eq!(sql_type_for(d.field_type), "TEXT");
    }
}
