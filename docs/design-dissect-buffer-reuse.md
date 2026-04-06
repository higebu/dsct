# 設計案: DissectBuffer の再利用

## 背景

`DissectBuffer::new()` はパケットごとに 4 つの `Vec` をヒープ確保する:

```rust
pub fn new() -> Self {
    Self {
        layers: Vec::with_capacity(8),
        fields: Vec::with_capacity(64),
        scratch: Vec::with_capacity(256),
        aux_data_len: 0,
        aux_chunks: Vec::new(),
    }
}
```

`clear()` を使えばキャパシティを保持したまま内容だけリセットできるが、現在の
API 構造ではライフタイム制約により再利用が不可能。

## 問題の根本原因

### FieldValue のゼロコピー借用

`FieldValue<'pkt>` は `Bytes(&'pkt [u8])` と `Str(&'pkt str)` でパケット
データを直接参照する。この `'pkt` が `DissectBuffer<'pkt>` 全体に伝播する:

```rust
pub struct DissectBuffer<'pkt> {
    fields: Vec<Field<'pkt>>,  // ← 'pkt がここに現れる
    // ...
}
```

### &mut DissectBuffer の不変性 (Invariance)

`dissect_with_link_type` のシグネチャ:

```rust
fn dissect_with_link_type<'pkt>(
    &self,
    data: &'pkt [u8],
    link_type: u32,
    buf: &mut DissectBuffer<'pkt>,
) -> Result<(), PacketError>
```

`&mut T<'a>` は `'a` に対して不変 (invariant)。つまり:
- `DissectBuffer<'long>` を `&mut DissectBuffer<'short>` として渡せない
- パケットデータ `data: &'pkt [u8]` のライフタイムと buf の `'pkt` は**完全一致**が必要

### for_each_packet のクロージャスコープ

```rust
// stream_packets の内部:
loop {
    let pkt_data: &[u8] = read_next_packet(&mut internal_buf);
    //          ^^^^^ ライフタイムはこのループイテレーション内のみ
    f(&record, pkt_data);
    // ここで pkt_data が無効化 → DissectBuffer 内の参照も無効
}
```

クロージャ外の `DissectBuffer` はクロージャ内の `pkt_data` より長命なので、
不変性によりコンパイラが拒否する。

## 案

### 案 A: `for_each_packet` に `DissectBuffer` を渡す API (推奨)

`CaptureReader` の API を拡張し、DissectBuffer の生成と再利用をコールバックの
外側で管理する。

```rust
// packet-dissector-pcap 側の変更
pub fn stream_packets_with_buf<R, F>(
    reader: R,
    buf: &mut DissectBuffer<'_>,  // 呼び出し側で生成
    f: F,
) -> Result<(), PcapError>
where
    R: Read,
    F: FnMut(&PacketRecord, &DissectBuffer<'_>) -> ControlFlow<()>,
{
    let mut pkt_buf = Vec::new();
    loop {
        let record = match read_record(&mut reader, &mut pkt_buf)? {
            Some(r) => r,
            None => break,
        };
        buf.clear();
        registry.dissect(&pkt_buf, buf)?;
        if f(&record, buf).is_break() {
            break;
        }
    }
}
```

**ポイント:**
- `DissectBuffer` と `pkt_data` が同じスコープ内で同一ライフタイムを持つ
- `clear()` → `dissect()` → コールバック呼び出しが同一スコープ内で完結
- コールバックは `&DissectBuffer` (不変参照) を受け取るだけ

**dsct 側の利用:**

```rust
// input.rs
pub fn for_each_dissected<F>(
    self,
    registry: &DissectorRegistry,
    mut f: F,
) -> Result<()>
where
    F: FnMut(PacketMeta, &DissectBuffer<'_>, &[u8]) -> Result<ControlFlow<()>>,
{
    let mut buf = DissectBuffer::new();
    let mut counter = 0u64;
    // ...
    stream_packets(self.reader, |record, pkt_data| {
        counter += 1;
        buf.clear();
        if let Err(e) = registry.dissect_with_link_type(
            pkt_data, record.link_type, &mut buf
        ) {
            // handle error
            return ControlFlow::Continue(());
        }
        let meta = PacketMeta { /* ... */ };
        match f(meta, &buf, pkt_data) {
            Ok(flow) => flow,
            Err(e) => { /* ... */ ControlFlow::Break(()) }
        }
    });
}
```

**トレードオフ:**
- ✅ ゼロコピーを維持
- ✅ `packet-dissector-pcap` 側の変更が小さい（新関数追加のみ）
- ✅ `dsct` 側は `for_each_dissected` に移行するだけ
- ⚠️ `stream_packets` の内部で dissect を呼ぶため、`DissectorRegistry` を
  pcap クレートに渡すか、dsct 側で `stream_packets` を直接使う必要がある

**推奨する実装方針:**

pcap クレートを変更せず、dsct の `for_each_packet` 内部で解決できる:

```rust
// input.rs — dsct 側のみの変更
pub fn for_each_packet<F>(self, mut f: F) -> Result<()>
where
    F: FnMut(PacketMeta, &[u8]) -> Result<ControlFlow<()>>,
{
    // 既存実装 (変更なし)
}

/// Dissect-aware iteration: reuses a single DissectBuffer across packets.
pub fn for_each_dissected<F>(
    self,
    registry: &DissectorRegistry,
    mut f: F,
) -> Result<()>
where
    F: for<'pkt> FnMut(
        PacketMeta,
        &Packet<'_, 'pkt>,
    ) -> Result<ControlFlow<()>>,
{
    let mut dissect_buf = DissectBuffer::new();
    let mut counter = 0u64;
    let mut error: Option<DsctError> = None;

    let stream_result =
        packet_dissector_pcap::stream_packets(self.reader, |record, pkt_data| {
            counter += 1;
            dissect_buf.clear();

            let meta = PacketMeta { /* ... */ };

            if let Err(e) = registry.dissect_with_link_type(
                pkt_data, record.link_type as u32, &mut dissect_buf
            ) {
                // 必要に応じてエラー処理
                return ControlFlow::Continue(());
            }
            let packet = Packet::new(&dissect_buf, pkt_data);

            match f(meta, &packet) {
                Ok(flow) => flow,
                Err(e) => {
                    error = Some(e);
                    ControlFlow::Break(())
                }
            }
        });
    // ...
}
```

**これが動作する理由:**

`stream_packets` に渡すクロージャ内部で `dissect_buf`, `pkt_data`,
`Packet` が全て同一スコープに存在する。`dissect_buf` はクロージャに
`&mut` でキャプチャされ、`pkt_data` はコールバック引数。Rust の
ライフタイム推論により:

1. `dissect_buf.clear()` で既存の借用を全て無効化
2. `dissect_with_link_type(pkt_data, ..., &mut dissect_buf)` で
   `dissect_buf` に `pkt_data` のライフタイムが結び付く
3. `Packet::new(&dissect_buf, pkt_data)` で読み取り専用ビューを作成
4. `f(meta, &packet)` でユーザーコールバックに渡す
5. コールバック戻り後、`packet` がドロップ → `dissect_buf` の借用解放
6. 次のイテレーションで `clear()` が呼べる

### 案 B: OwnedDissectBuffer (ゼロコピーを諦める)

`packet-dissector-core` に `'static` な所有型バッファを追加する:

```rust
pub struct OwnedDissectBuffer {
    layers: Vec<Layer>,
    fields: Vec<OwnedField>,      // Bytes/Str をコピー済み
    scratch: Vec<u8>,
    data: Vec<u8>,                 // パケットデータのコピー
}

pub enum OwnedFieldValue {
    U8(u8),
    U16(u16),
    // ...
    Bytes(Vec<u8>),               // 所有
    Str(String),                  // 所有
    // ...
}
```

**トレードオフ:**
- ✅ ライフタイム制約が完全に消える
- ✅ クロージャ外に持ち出せる
- ❌ `Bytes`/`Str` の毎パケットコピーコスト
- ❌ `packet-dissector-core` に大きな型追加が必要
- ❌ 既存 API との二重管理

**用途が限定的:** TUI の `OwnedPacket` が既にこのアプローチを独自実装している
(`src/tui/owned_packet.rs`)。汎用化する価値があるかは利用頻度次第。

### 案 C: mmap ベースのインデックスアクセス

`build_index` で全パケットのオフセットを取得し、mmap されたファイル全体から
各パケットをスライスする:

```rust
let data: &[u8] = mmap_file(path)?;
let index: Vec<PacketRecord> = build_index(data)?;
let mut buf = DissectBuffer::new();

for record in &index {
    let pkt_data = &data[record.data_offset..][..record.captured_len as usize];
    buf.clear();
    registry.dissect_with_link_type(pkt_data, record.link_type, &mut buf)?;
    let packet = Packet::new(&buf, pkt_data);
    // use packet...
}
```

**トレードオフ:**
- ✅ ゼロコピー + バッファ再利用の両立
- ✅ `packet-dissector` 側の変更不要
- ❌ mmap 必須 → stdin 入力 (`-`) に使えない
- ❌ 大きなファイルでインデックス構築のメモリコスト
- ❌ シーク可能なファイル限定

**用途:** TUI モードでは既に mmap + index を使っている。CLI の `read`/`stats`
にも `--file` 入力時のみ適用可能。

## 推奨

**案 A (`for_each_dissected`) を推奨。**

理由:
1. `packet-dissector` 側の変更なしで dsct 内だけで完結する
2. ゼロコピーを維持したままバッファ再利用を実現
3. stdin 入力もファイル入力も両方サポート
4. 既存の `for_each_packet` と共存可能（段階的移行）
5. ライフタイムの整合性が静的に保証される

## 実装手順

1. `src/input.rs` に `for_each_dissected` メソッドを追加
2. `cmd_read` を `for_each_dissected` に移行
3. `cmd_stats` を `for_each_dissected` に移行
4. ベンチマークで効果を測定 (`cargo bench`)
5. `for_each_packet` は MCP 等の他用途向けに残す
