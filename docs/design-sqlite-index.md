# 設計: SQLite インデックスと `dsct sql`

## 背景

`dsct read` は毎回 pcap を先頭からストリーミング dissect する。同じキャプチャに
対して条件を変えて何度も検索したい場合は毎回フルスキャンになり、`--filter` は
WHERE 句相当の式しか書けない（JOIN / 集計 / ORDER BY 不可）。

`dsct index` / `dsct sql` は dissect 結果を一度だけ SQLite に格納し、以降は
読み取り専用の `SELECT` で問い合わせる。特に次の 3 点を目標にしている。

- カプセル化パケット（VXLAN / Geneve / GRE / GTP-U / IP-in-IP / L2TP / MPLS /
  復号後 ESP）のインナーヘッダを「深さ (`depth`)」付きで問い合わせできる
- ネストしたフィールド（DNS `questions` など Array / Object）を SQLite の JSON
  関数で辿れる
- ストリーム / シーケンス追跡（TCP/UDP/SCTP のフロー ID、方向、相対 seq/ack、
  次 seq）が SQL だけで行える

## ライブラリ選定

`rusqlite`（`bundled` + `hooks`）を feature `sqlite`（既定で有効）として採用。
pure Rust の候補は Turso Database（旧 limbo）のみだが、1.0 前で SQL 対応が
partial、公式 Rust バインディングが async 前提、依存が重いため見送った。
rusqlite への依存は `src/sqlite/ingest.rs`（書き込み）、`src/sqlite/query.rs`
（読み取り）、`src/error.rs` の `From` 実装に閉じ込め、DDL 生成・depth 計算・
フロー追跡・値変換は rusqlite 非依存の純粋関数として実装している。

## モジュール構成

```text
src/sqlite/mod.rs    -- default_db_path / is_sqlite_file / resolve_index（構築の要否判定）
src/sqlite/ddl.rs    -- all_field_schemas() からプロトコル別テーブル DDL を生成、基本テーブル・ビュー・索引
src/sqlite/depth.rs  -- compute_depths: レイヤ名列からカプセル化深さを算出
src/sqlite/value.rs  -- FieldValue → SqlValue 変換（format_fn 出力の JSON デコード、コンテナの JSON 化）
src/sqlite/flows.rs  -- FlowTracker: 5 タプル正規化、TCP 相対 seq/ack/next_seq、payload_len
src/sqlite/meta.rs   -- meta テーブルの読み書きと鮮度判定
src/sqlite/ingest.rs -- build_index: 一時ファイルに構築して rename
src/sqlite/query.rs  -- 読み取り専用実行、行の JSONL 出力、--schema 用のスキーマ記述
```

## スキーマ（`schema_version = 2`）

- `meta(key, value)`: `schema_version`, `dsct_version`, `protocols`（ソート済み
  短名）, `source_path`, `source_size`, `source_mtime_ns`, `decode_as`, `esp_sa`,
  `packet_count`, `flow_count`, `complete`
- `packets(number PK, ts_secs, ts_usecs, timestamp, ts REAL, captured_length,
  original_length, link_type, stack, layer_count, max_depth, dissect_error)`
- `layers(packet_number, layer_index, depth, protocol, protocol_name, "offset",
  length)`：`protocol` は `Layer::name`（短名）、`protocol_name` は
  `protocol_name()`（`TLSv1.2` 等）
- プロトコル別ワイドテーブル：テーブル名は `normalize_protocol_name(short_name)`
  （基本テーブル名と衝突する場合は `proto_` 接頭辞）。列は
  `packet_number, layer_index, depth` + 最上位 `FieldDescriptor` ごとの列
  （`display_fn` を持つ列には `<name>_name TEXT` を追加）+ `extra TEXT`
  （記述子に無い実行時フィールドの JSON。あくまで最上位フィールドのみが対象で、
  Array/Object の子要素はここには含まれない — `field_iter::top_level_fields` で
  ネストした子フィールドをスキップしてから列/`extra` への割り当てを行う）。
  予約名と衝突するフィールドは
  `field_<name>`。`TCP`/`UDP`/`SCTP` には `flow_id, direction`、`TCP` にはさらに
  `payload_len, seq_rel, ack_rel, next_seq`
- `flows(id PK, transport, depth, addr_a, port_a, addr_b, port_b,
  tcp_stream_id, first_packet, last_packet, packets, bytes, first_ts, last_ts)`
- `packet_flows(packet_number, layer_index, flow_id, direction)`
- ビュー：`encapsulations`（内側 depth ごとの直前のトンネル層）、
  `conversations`（`flows` + `duration_secs`）、`tcp_segments`（`tcp` × `packets`）
- 索引はバルク挿入後に作成：`layers(protocol)`, `layers(packet_number, depth)`,
  `packets(ts)`, `ipv4/ipv6("src"/"dst")`, `tcp/udp/sctp(flow_id)`,
  `tcp("stream_id")`, `packet_flows(flow_id)`

型対応：整数型 → INTEGER（`u64` が `i64` に収まらなければ 10 進 TEXT）、
Str / IPv4 / IPv6 / MAC → TEXT、Bytes / Scratch → BLOB、Array / Object → JSON
TEXT。`format_fn` を持つ値は `dsct read` と同じ JSON 描画を 1 トークンとして
デコードする（引用文字列 → TEXT、整数 → INTEGER、小数 → REAL）。

## `depth` の算出

レイヤ配列を外→内に走査し、`depth`, `seen_l2`, `seen_l3` を持つ。

```text
depth = 0; seen_l2 = false; seen_l3 = false
for layer in layers:
    if layer.name == "Ethernet" and (seen_l2 or seen_l3):
        depth += 1; seen_l2 = false; seen_l3 = false
    elif layer.name in {"IPv4","IPv6"} and seen_l3:
        depth += 1; seen_l2 = false; seen_l3 = false
    seen_l2 |= layer.name == "Ethernet"
    seen_l3 |= layer.name in {"IPv4","IPv6"}
    layer.depth = depth
```

トンネルプロトコルのホワイトリストを持たないため、内側に Ethernet または IP を
運ぶあらゆるカプセル化に対応する。運搬層は「同じパケットで直前の depth の最後の
レイヤ」であり、`encapsulations` ビューで導出する。

## フロー追跡

- 対象は `TCP` / `UDP` / `SCTP` レイヤ。IP は「同じ depth で当該層より前の最後の
  `IPv4`/`IPv6` 層」。無ければ `flow_id` は NULL
- キー `(depth, transport, endpoint_a, endpoint_b)`。`(addr, port)` の辞書順で
  a/b を正規化し、`direction = 0` なら送信元が a 側
- TCP：`payload_len` は IP の `total_length`（IPv6 は `payload_length + 40`）から
  IP ヘッダ長（`tcp.range.start - ip.range.start`）と TCP ヘッダ長を引いた値。
  `seq_rel` は方向ごとの初見 seq を基準、`ack_rel` は逆方向の基準（未確定なら
  NULL）、`next_seq = seq + payload_len + SYN + FIN`（mod 2^32）
- ディセクタの `tcp.stream_id` は `flows.tcp_stream_id` にそのまま記録する
  （ディセクタ側は追跡数に上限があるため、`flow_id` を主キーとして使う）

## 構築と鮮度判定

1. `CaptureReader::open` でキャプチャを開く（存在しなければ一時ファイルを作らず
   に失敗）
2. `<db>.tmp-<pid>` に `journal_mode=OFF, synchronous=OFF` で構築し、完了後
   `rename`。失敗時は一時ファイルを削除する
3. `meta.complete = 1` を最後に書く。`resolve_index` は `meta` の各値が現在の
   ビルドと一致し、かつ `complete` のときだけ再利用する
4. stdin 入力は `--db` 必須で常に再構築。`FILE` 自体が SQLite DB なら構築せず
   そのまま問い合わせる

## 安全性

- DB は `SQLITE_OPEN_READ_ONLY` で開く
- 先頭キーワードが `SELECT` / `WITH` / `VALUES` / `EXPLAIN` 以外なら拒否
- `sqlite3_stmt_readonly` が偽なら拒否、複文（rusqlite `MultipleStatement`）も拒否
- いずれも `invalid_arguments`（exit 2）として構造化エラーで報告する
