//! In-order dissection pass for the packet list and detail pane.
//!
//! Some dissections depend on packets dissected earlier with the same
//! registry: TCP stream IDs and reassembly, HTTP/2 HPACK, NetFlow v9 /
//! IPFIX templates and IP fragment reassembly
//! ([`DissectBuffer::used_cross_packet_state`]).  The TUI dissects the rows
//! and the selected packet on demand, in whatever order the user views them,
//! so for those packets the result would depend on the view order.
//!
//! [`OrderedPass`] dissects the whole capture once, in capture order, with
//! its own registry on a background thread — as `dsct read` does — and keeps
//! the result of every packet whose dissection used cross-packet state.  The
//! display uses that result for those packets and its own on-demand
//! dissection for all others, whose result does not depend on any state (the
//! dissection path up to the first stateful dissector depends on the packet
//! bytes only, so a packet that did not use state in capture order uses none
//! in any order).
//!
//! The kept results are encoded with [`super::packet_codec`] and appended to
//! a temporary spill file, so memory use stays at 8 bytes per packet (the
//! file offset) no matter how many packets use cross-packet state.
//!
//! The main thread feeds the pass with the packet index as it grows (initial
//! indexing, live capture) through a bounded channel ([`OrderedPass::feed`]).

use std::fs::File;
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::DissectBuffer;

use crate::error::{DsctError, Result};

use super::loader;
use super::packet_codec::{self, Interner, StoredPacket, Tables};
use super::state::{CaptureMap, PacketIndex, RowSummary, SelectedPacket};

/// Number of packets sent to the pass per channel message.
const FEED_BATCH: usize = 4096;

/// Number of batches the channel buffers (64 Ki packets, 2 MiB of index).
const FEED_QUEUE: usize = 16;

/// Offset entry of a packet whose dissection used no cross-packet state.
const STATELESS: u64 = 0;

/// Where the display gets a packet's dissection result from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Status {
    /// The pass has not reached the packet yet.
    Pending,
    /// The packet's dissection uses no cross-packet state: dissect it on
    /// demand.
    Stateless,
    /// The pass kept the packet's in-order result: [`OrderedPass::load`] it.
    Stateful,
    /// The pass stopped (I/O error) before reaching the packet: dissect it
    /// on demand.
    Unavailable,
}

/// State shared between the pass thread and the main thread.
#[derive(Default)]
struct Shared {
    /// One entry per packet dissected so far, in capture order:
    /// [`STATELESS`], or the spill file offset of the kept result plus one.
    offsets: Vec<u64>,
    /// Interned values referenced by the kept results.
    tables: Tables,
    /// Whether the pass thread has stopped.
    stopped: bool,
    /// Error to report to the user, not reported yet.
    error: Option<String>,
}

/// Handle to the in-order dissection pass of one capture.
pub(super) struct OrderedPass {
    shared: Arc<Mutex<Shared>>,
    /// `None` once the pass thread is gone.
    feeder: Option<SyncSender<Vec<PacketIndex>>>,
    /// Number of packets sent to the pass.
    fed: usize,
    /// Read handle of the spill file (its own file offset).
    reader: File,
    /// Owns the spill file where its name could not be removed while it is
    /// open (not Unix); it is deleted on drop.
    _spill: Option<tempfile::NamedTempFile>,
}

/// Marks the pass as stopped when dropped.
struct StopGuard<'a>(&'a Mutex<Shared>);

impl Drop for StopGuard<'_> {
    fn drop(&mut self) {
        let mut shared = lock(self.0);
        shared.stopped = true;
        if std::thread::panicking() {
            shared.error = Some("in-order dissection stopped unexpectedly".to_string());
        }
    }
}

fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    // The pass thread holds the lock only to publish plain data; a panic
    // there leaves it consistent.
    shared.lock().unwrap_or_else(PoisonError::into_inner)
}

impl OrderedPass {
    /// Start the pass over `capture` (which may still grow, as in live
    /// capture), dissecting with `registry`.  The spill file is created in
    /// `spill_dir`, or the system temp directory if that fails or is `None`.
    pub(super) fn spawn(
        capture: CaptureMap,
        registry: DissectorRegistry,
        spill_dir: Option<&Path>,
    ) -> Result<Self> {
        let in_dir = spill_dir.and_then(|dir| {
            std::fs::create_dir_all(dir).ok()?;
            tempfile::NamedTempFile::new_in(dir).ok()
        });
        let spill = match in_dir {
            Some(spill) => spill,
            None => tempfile::NamedTempFile::new()?,
        };
        let writer = spill.as_file().try_clone()?;
        let reader = spill.reopen()?;
        // On Unix, remove the name right away: the open handles keep the
        // data, and nothing is left behind if dsct is killed.
        #[cfg(unix)]
        let spill = {
            spill.close()?;
            None
        };
        #[cfg(not(unix))]
        let spill = Some(spill);

        let shared = Arc::new(Mutex::new(Shared::default()));
        let (tx, rx) = mpsc::sync_channel(FEED_QUEUE);
        let thread_shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("ordered-pass".into())
            .spawn(move || {
                // However the thread ends (I/O error, panic, or the App
                // dropping the sender), packets it has not reached are
                // dissected on demand from then on.
                let _stopped = StopGuard(&thread_shared);
                if let Err(e) = run(&rx, capture, &registry, writer, &thread_shared) {
                    lock(&thread_shared).error = Some(format!("in-order dissection stopped: {e}"));
                }
            })
            .map_err(|e| DsctError::msg(format!("failed to start the in-order pass: {e}")))?;

        Ok(Self {
            shared,
            feeder: Some(tx),
            fed: 0,
            reader,
            _spill: spill,
        })
    }

    /// Send the packets of `indices` not sent yet, as far as the channel
    /// has room, without blocking.  Call again as the index grows and the
    /// pass makes progress.
    pub(super) fn feed(&mut self, indices: &[PacketIndex]) {
        while self.fed < indices.len() {
            let Some(tx) = &self.feeder else {
                return;
            };
            let end = indices.len().min(self.fed + FEED_BATCH);
            match tx.try_send(indices[self.fed..end].to_vec()) {
                Ok(()) => self.fed = end,
                Err(TrySendError::Full(_)) => return,
                Err(TrySendError::Disconnected(_)) => {
                    self.feeder = None;
                    lock(&self.shared).stopped = true;
                    return;
                }
            }
        }
    }

    /// Whether every packet of an index of `total` packets has been sent.
    pub(super) fn fully_fed(&self, total: usize) -> bool {
        self.fed >= total || self.feeder.is_none()
    }

    /// Number of packets dissected so far.
    #[cfg(test)]
    pub(super) fn processed(&self) -> usize {
        lock(&self.shared).offsets.len()
    }

    /// Where to get the result of packet `pkt_idx` from.
    pub(super) fn status(&self, pkt_idx: usize) -> Status {
        let shared = lock(&self.shared);
        match shared.offsets.get(pkt_idx) {
            Some(&STATELESS) => Status::Stateless,
            Some(_) => Status::Stateful,
            None if shared.stopped => Status::Unavailable,
            None => Status::Pending,
        }
    }

    /// Load the in-order result of packet `pkt_idx`, whose bytes are
    /// `data`.  Returns `None` unless its [`status`](Self::status) is
    /// [`Status::Stateful`] and the kept result can be read back (a failure
    /// to read it back is reported through [`take_error`](Self::take_error)).
    pub(super) fn load(&self, pkt_idx: usize, data: &[u8]) -> Option<StoredPacket> {
        let offset = match lock(&self.shared).offsets.get(pkt_idx) {
            Some(&entry) if entry != STATELESS => entry - 1,
            _ => return None,
        };
        let record = match self.read_record(offset) {
            Ok(record) => record,
            Err(e) => {
                lock(&self.shared).error = Some(format!(
                    "failed to read the in-order result of packet {}: {e}",
                    pkt_idx + 1
                ));
                return None;
            }
        };
        let mut shared = lock(&self.shared);
        // The tables were published together with the offset.
        let stored = packet_codec::decode(&record, data, &shared.tables);
        if stored.is_none() {
            shared.error = Some(format!(
                "the in-order result of packet {} is damaged",
                pkt_idx + 1
            ));
        }
        stored
    }

    fn read_record(&self, offset: u64) -> std::io::Result<Vec<u8>> {
        let mut reader = &self.reader;
        reader.seek(SeekFrom::Start(offset))?;
        let mut len = [0u8; 4];
        reader.read_exact(&mut len)?;
        let mut record = vec![0u8; u32::from_le_bytes(len) as usize];
        reader.read_exact(&mut record)?;
        Ok(record)
    }

    /// Take the error to report to the user, if any: the pass stopped
    /// early, or a kept result could not be read back.  The packets
    /// concerned are dissected on demand.
    pub(super) fn take_error(&self) -> Option<String> {
        lock(&self.shared).error.take()
    }
}

/// A packet's result as the display gets it.
enum Display<'r, 'pkt> {
    /// Dissected on demand; the flag tells whether dissection returned `Ok`.
    Dissected(&'r DissectBuffer<'pkt>, bool),
    /// Kept by the in-order pass.
    Stored(StoredPacket),
    /// Waiting for the in-order pass.
    Pending,
}

/// Get the result to display for packet `pkt_idx` (bytes `data`) and pass
/// it to `show`.
///
/// Without a pass, or after it stopped early, packets are dissected on
/// demand with `registry` whatever their state use.
fn resolve<R>(
    registry: &DissectorRegistry,
    pass: Option<&OrderedPass>,
    pkt_idx: usize,
    data: &[u8],
    link_type: u32,
    show: impl FnOnce(Display<'_, '_>) -> R,
) -> R {
    // Known stateful: skip the on-demand dissection, which would also grow
    // the state kept in `registry` for nothing.
    if let Some(pass) = pass
        && pass.status(pkt_idx) == Status::Stateful
        && let Some(stored) = pass.load(pkt_idx, data)
    {
        return show(Display::Stored(stored));
    }
    let mut buf = DissectBuffer::new();
    let ok = registry
        .dissect_with_link_type(data, link_type, &mut buf)
        .is_ok();
    if buf.used_cross_packet_state()
        && let Some(pass) = pass
    {
        match pass.status(pkt_idx) {
            Status::Pending => return show(Display::Pending),
            Status::Stateful => {
                if let Some(stored) = pass.load(pkt_idx, data) {
                    return show(Display::Stored(stored));
                }
            }
            Status::Stateless | Status::Unavailable => {}
        }
    }
    show(Display::Dissected(&buf, ok))
}

/// The detail pane view of packet `pkt_idx`.
pub(super) fn selected_packet(
    registry: &DissectorRegistry,
    pass: Option<&OrderedPass>,
    pkt_idx: usize,
    data: &[u8],
    link_type: u32,
) -> SelectedPacket {
    resolve(registry, pass, pkt_idx, data, link_type, |d| match d {
        Display::Dissected(buf, _) => loader::selected_from_buf(buf, data, pkt_idx),
        Display::Stored(stored) => loader::selected_from_owned(stored.packet, pkt_idx),
        Display::Pending => loader::pending_selected(data, pkt_idx),
    })
}

/// The packet list row of packet `pkt_idx`, and whether it is a placeholder
/// waiting for the in-order pass.
pub(super) fn row_summary(
    registry: &DissectorRegistry,
    pass: Option<&OrderedPass>,
    pkt_idx: usize,
    data: &[u8],
    link_type: u32,
) -> (RowSummary, bool) {
    resolve(registry, pass, pkt_idx, data, link_type, |d| match d {
        Display::Dissected(buf, ok) => (loader::row_summary_from_buf(buf, data, ok), false),
        Display::Stored(stored) => {
            let buf = stored.packet.to_dissect_buf();
            (
                loader::row_summary_from_buf(&buf, &stored.packet.data, stored.ok),
                false,
            )
        }
        Display::Pending => (loader::pending_row_summary(), true),
    })
}

/// Body of the pass thread: dissect the packets sent through `rx` in order
/// until the sender is dropped.
fn run(
    rx: &Receiver<Vec<PacketIndex>>,
    mut capture: CaptureMap,
    registry: &DissectorRegistry,
    writer: File,
    shared: &Mutex<Shared>,
) -> std::io::Result<()> {
    let mut writer = BufWriter::with_capacity(1 << 16, writer);
    let mut position = 0u64;
    let mut interner = Interner::default();
    let mut record = Vec::new();
    let mut dissect_buf = DissectBuffer::new();
    let mut offsets = Vec::with_capacity(FEED_BATCH);

    while let Ok(batch) = rx.recv() {
        offsets.clear();
        for index in &batch {
            if capture.packet_data(index).is_none() {
                // Live capture: the file has grown since it was mapped.
                capture.refresh()?;
            }
            let Some(data) = capture.packet_data(index) else {
                // Unreadable for the main thread too; it shows nothing.
                offsets.push(STATELESS);
                continue;
            };
            let buf = dissect_buf.clear_into();
            let ok = registry
                .dissect_with_link_type(data, u32::from(index.link_type), buf)
                .is_ok();
            if !buf.used_cross_packet_state() {
                offsets.push(STATELESS);
                continue;
            }
            record.clear();
            packet_codec::encode(buf, data, ok, &mut interner, &mut record);
            let len = u32::try_from(record.len())
                .map_err(|_| std::io::Error::other("dissection result too large"))?;
            writer.write_all(&len.to_le_bytes())?;
            writer.write_all(&record)?;
            offsets.push(position + 1);
            position += 4 + u64::from(len);
        }
        // Publish only what the reader can read back.
        writer.flush()?;
        let mut shared = lock(shared);
        shared.tables.extend(interner.take_new());
        shared.offsets.extend_from_slice(&offsets);
    }
    Ok(())
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use std::io::Write;

    use packet_dissector::registry::DissectorRegistry;
    use packet_dissector_core::packet::{DissectBuffer, Packet};

    use super::super::app::App;
    use super::super::loader;
    use super::super::state::CaptureMap;
    use super::super::tree;
    use super::{OrderedPass, Status};

    // -- Fixture -------------------------------------------------------------

    /// Ethernet + IPv4 header (20 bytes, no options) for `payload`.
    ///
    /// `flags_frag` is the IPv4 Flags + Fragment Offset word (RFC 791,
    /// Section 3.1). <https://www.rfc-editor.org/rfc/rfc791#section-3.1>
    fn ipv4_frame(
        src: [u8; 4],
        dst: [u8; 4],
        protocol: u8,
        id: u16,
        flags_frag: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // dst MAC
        p.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x01]); // src MAC
        p.extend_from_slice(&[0x08, 0x00]); // EtherType IPv4
        p.push(0x45);
        p.push(0);
        p.extend_from_slice(&(20 + payload.len() as u16).to_be_bytes());
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&flags_frag.to_be_bytes());
        p.push(64); // TTL
        p.push(protocol);
        p.extend_from_slice(&[0, 0]); // checksum (unchecked)
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(payload);
        p
    }

    /// One TCP segment (RFC 9293, Section 3.1) with a 20-byte header.
    fn tcp_frame(
        src: ([u8; 4], u16),
        dst: ([u8; 4], u16),
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend_from_slice(&src.1.to_be_bytes());
        tcp.extend_from_slice(&dst.1.to_be_bytes());
        tcp.extend_from_slice(&seq.to_be_bytes());
        tcp.extend_from_slice(&ack.to_be_bytes());
        tcp.push(0x50); // data offset 5
        tcp.push(flags);
        tcp.extend_from_slice(&0xffffu16.to_be_bytes()); // window
        tcp.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent pointer
        tcp.extend_from_slice(payload);
        ipv4_frame(src.0, dst.0, 6, 0, 0x4000, &tcp)
    }

    const SYN: u8 = 0x02;
    const PSH_ACK: u8 = 0x18;

    /// Two interleaved TCP flows (one carrying an HTTP request split across
    /// two segments), a fragmented ICMP Echo Request, a fragmented UDP
    /// datagram and a plain UDP datagram.
    fn stateful_frames() -> Vec<Vec<u8>> {
        let a_cli = ([10, 0, 0, 1], 40000);
        let a_srv = ([10, 0, 0, 2], 80);
        let b_cli = ([10, 0, 0, 3], 40001);
        let b_srv = ([10, 0, 0, 4], 7000);
        let req1: &[u8] = b"GET /index.html HTTP/1.1\r\nHo";
        let req2: &[u8] = b"st: example\r\n\r\n";

        // ICMP Echo Request (RFC 792) with 32 data bytes, split 24 + 16.
        let mut icmp = vec![8u8, 0, 0, 0, 0, 1, 0, 1];
        icmp.extend((0..32).map(|i| i as u8));
        // UDP datagram (RFC 768) with 40 data bytes, split 24 + 24.
        let mut udp = Vec::new();
        udp.extend_from_slice(&4000u16.to_be_bytes());
        udp.extend_from_slice(&9999u16.to_be_bytes());
        udp.extend_from_slice(&48u16.to_be_bytes());
        udp.extend_from_slice(&[0, 0]);
        udp.extend((0..40).map(|i| i as u8));
        let mut plain_udp = Vec::new();
        plain_udp.extend_from_slice(&5000u16.to_be_bytes());
        plain_udp.extend_from_slice(&5001u16.to_be_bytes());
        plain_udp.extend_from_slice(&12u16.to_be_bytes());
        plain_udp.extend_from_slice(&[0, 0, 1, 2, 3, 4]);

        let h1 = [10, 0, 0, 7];
        let h2 = [10, 0, 0, 8];
        vec![
            tcp_frame(a_cli, a_srv, 1000, 0, SYN, &[]),
            tcp_frame(b_cli, b_srv, 5000, 0, SYN, &[]),
            tcp_frame(a_cli, a_srv, 1001, 1, PSH_ACK, req1),
            ipv4_frame(h1, h2, 1, 77, 0x2000, &icmp[..24]),
            tcp_frame(b_cli, b_srv, 5001, 1, PSH_ACK, b"hello-b"),
            ipv4_frame(h1, h2, 17, 78, 0x2000, &udp[..24]),
            tcp_frame(a_cli, a_srv, 1001 + req1.len() as u32, 1, PSH_ACK, req2),
            ipv4_frame(h1, h2, 1, 77, 3, &icmp[24..]),
            ipv4_frame(h1, h2, 17, 78, 3, &udp[24..]),
            ipv4_frame(h1, h2, 17, 79, 0, &plain_udp),
        ]
    }

    /// Write `frames` as an Ethernet pcap to a fresh temp file.
    fn write_pcap(frames: &[Vec<u8>]) -> tempfile::NamedTempFile {
        let mut pcap = Vec::new();
        pcap.extend_from_slice(&0xA1B2C3D4u32.to_le_bytes());
        pcap.extend_from_slice(&2u16.to_le_bytes());
        pcap.extend_from_slice(&4u16.to_le_bytes());
        pcap.extend_from_slice(&0i32.to_le_bytes());
        pcap.extend_from_slice(&0u32.to_le_bytes());
        pcap.extend_from_slice(&65535u32.to_le_bytes());
        pcap.extend_from_slice(&1u32.to_le_bytes()); // LINKTYPE_ETHERNET
        for (i, f) in frames.iter().enumerate() {
            pcap.extend_from_slice(&(i as u32).to_le_bytes());
            pcap.extend_from_slice(&0u32.to_le_bytes());
            pcap.extend_from_slice(&(f.len() as u32).to_le_bytes());
            pcap.extend_from_slice(&(f.len() as u32).to_le_bytes());
            pcap.extend_from_slice(f);
        }
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        tmp.write_all(&pcap).unwrap();
        tmp
    }

    // -- What the TUI shows, and what `dsct read` dissects --------------------

    /// What the TUI shows for one packet: the detail tree labels and the
    /// packet list row.
    #[derive(Debug, Clone, PartialEq)]
    struct Shown {
        tree: Vec<(usize, String)>,
        row: (String, String, String, String),
        /// The detail pane's packet in `dsct read`'s JSON format.
        json: String,
    }

    /// `buf` (the dissection of packet `pkt_idx` with bytes `data`) as
    /// `dsct read` writes it.
    fn read_json(pkt_idx: usize, buf: &DissectBuffer<'_>, data: &[u8]) -> String {
        let meta = crate::serialize::PacketMeta {
            number: pkt_idx as u64 + 1,
            timestamp_secs: pkt_idx as u64,
            timestamp_usecs: 0,
            captured_length: data.len() as u32,
            original_length: data.len() as u32,
            link_type: 1,
        };
        let mut out = Vec::new();
        crate::serialize::write_packet_json(&mut out, &meta, buf, data, None, false).unwrap();
        String::from_utf8(out).unwrap()
    }

    /// An [`App`] for the capture at `path` with an in-order pass that has
    /// not been fed yet.
    fn open_app(path: &std::path::Path) -> App {
        let file = std::fs::File::open(path).unwrap();
        let capture = CaptureMap::new(&file).unwrap();
        let indices = loader::build_index(capture.as_bytes()).unwrap();
        let mut app = App::new(capture, indices, DissectorRegistry::default(), path, vec![]);
        let pass_capture = CaptureMap::new(&file).unwrap();
        app.ordered =
            Some(OrderedPass::spawn(pass_capture, DissectorRegistry::default(), None).unwrap());
        app
    }

    /// Drive the pass until it has dissected every packet.
    fn finish_pass(app: &mut App) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            app.ordered_tick();
            let pass = app.ordered.as_ref().unwrap();
            if pass.processed() == app.indices.len() {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "pass did not finish");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        app.ordered_tick();
    }

    fn shown(app: &mut App, pkt_idx: usize) -> Shown {
        app.packet_list.selected = pkt_idx;
        app.load_selected();
        let sel = app.selected.as_ref().unwrap();
        assert_eq!(sel.pkt_idx, pkt_idx);
        assert!(!sel.pending);
        let json = read_json(pkt_idx, &sel.packet.to_dissect_buf(), &sel.packet.data);
        let tree = sel
            .tree_nodes
            .iter()
            .map(|n| (n.depth, n.label.clone()))
            .collect();
        app.summary_cache.clear();
        let s = app.get_or_dissect_summary(pkt_idx);
        Shown {
            tree,
            row: (
                s.source.clone(),
                s.destination.clone(),
                s.protocol.to_string(),
                s.info.clone(),
            ),
            json,
        }
    }

    /// Dissect every packet in capture order with one fresh registry, as
    /// `dsct read` does, and return what the TUI should show for each.
    fn sequential_reference(path: &std::path::Path) -> Vec<Shown> {
        let data = std::fs::read(path).unwrap();
        let indices = loader::build_index(&data).unwrap();
        let tree_registry = DissectorRegistry::default();
        let row_registry = DissectorRegistry::default();
        indices
            .iter()
            .enumerate()
            .map(|(i, index)| {
                let start = index.data_offset as usize;
                let pkt = &data[start..start + index.captured_len as usize];
                let mut buf = DissectBuffer::new();
                let _ = tree_registry.dissect_with_link_type(pkt, index.link_type as u32, &mut buf);
                let tree = tree::build_tree(&Packet::new(&buf, pkt))
                    .into_iter()
                    .map(|n| (n.depth, n.label))
                    .collect();
                let s = loader::extract_row_summary(pkt, index.link_type as u32, &row_registry);
                Shown {
                    tree,
                    row: (s.source, s.destination, s.protocol.to_string(), s.info),
                    json: read_json(i, &buf, pkt),
                }
            })
            .collect()
    }

    fn labels(s: &Shown) -> Vec<&str> {
        s.tree.iter().map(|(_, l)| l.as_str()).collect()
    }

    #[test]
    fn reference_exercises_cross_packet_state() {
        let tmp = write_pcap(&stateful_frames());
        let reference = sequential_reference(tmp.path());
        // The request is reassembled into the second segment's HTTP layer.
        assert!(
            reference[6].json.contains(r#""uri":"/index.html""#),
            "{}",
            reference[6].json
        );
        // Flow B is the second TCP stream.
        assert!(
            labels(&reference[4]).contains(&"Stream ID: 1"),
            "{:?}",
            reference[4]
        );
        // The second segment of flow A completes the HTTP request.
        assert!(
            labels(&reference[6]).contains(&"HTTP"),
            "{:?}",
            reference[6]
        );
        // The completing fragments carry the reassembled ICMP / UDP layers.
        assert!(
            labels(&reference[7]).contains(&"ICMP"),
            "{:?}",
            reference[7]
        );
        assert!(labels(&reference[8]).contains(&"UDP"), "{:?}", reference[8]);
    }

    /// Showing the packets in any order gives the same detail tree and list
    /// row as dissecting the capture in order (`dsct read`).
    #[test]
    fn display_is_independent_of_view_order() {
        let tmp = write_pcap(&stateful_frames());
        let reference = sequential_reference(tmp.path());
        let n = reference.len();

        let orders: Vec<Vec<usize>> = vec![
            (0..n).collect(),
            (0..n).rev().collect(),
            vec![8, 7, 6, 4, 2, 9, 0, 1, 3, 5],
            // The same packets twice.
            vec![6, 6, 7, 7, 8, 8, 4, 4],
        ];
        for order in orders {
            let mut app = open_app(tmp.path());
            finish_pass(&mut app);
            for &i in &order {
                let got = shown(&mut app, i);
                assert_eq!(got, reference[i], "packet {i} in view order {order:?}");
            }
        }
    }

    /// View packets before the pass reached them, which dissects them on
    /// demand with the display registry: flow B before flow A, and both HTTP
    /// segments.
    fn pollute(app: &mut App) {
        for i in [4, 1, 6, 2, 8, 7] {
            app.packet_list.selected = i;
            app.load_selected();
            assert!(app.selected.as_ref().unwrap().pending);
            let _ = app.get_or_dissect_summary(i);
        }
    }

    fn follow(app: &mut App, pkt_idx: usize) -> (String, Vec<String>) {
        app.stream_view = None;
        app.packet_list.selected = pkt_idx;
        app.load_selected();
        app.start_follow_stream();
        while app.stream_tick() {}
        let view = app.stream_view.as_ref().expect("stream view");
        let text = view.lines.iter().map(|l| l.text.clone()).collect();
        (view.title.clone(), text)
    }

    /// Follow Stream finds the packets of the stream ID shown in the detail
    /// pane (assigned in capture order), whatever was viewed before.
    #[test]
    fn follow_stream_uses_capture_order_stream_ids() {
        let tmp = write_pcap(&stateful_frames());
        let mut app = open_app(tmp.path());
        pollute(&mut app);
        finish_pass(&mut app);

        let (title, text) = follow(&mut app, 4);
        assert!(title.starts_with("TCP Stream #1"), "{title}");
        assert_eq!(text, ["hello-b"]);
        let (title, text) = follow(&mut app, 2);
        assert!(title.starts_with("TCP Stream #0"), "{title}");
        assert_eq!(text, ["GET /index.html HTTP/1.1", "Ho", "st: example", ""]);
        // Following it again gives the same.
        assert_eq!(follow(&mut app, 2).1, text);
    }

    fn stats_json(app: &mut App) -> serde_json::Value {
        app.stats_output = None;
        app.start_stats();
        while app.stats_tick() {}
        serde_json::to_value(app.stats_output.as_ref().expect("stats")).unwrap()
    }

    /// `:stats` gives the same result whatever was viewed before.
    #[test]
    fn stats_do_not_depend_on_view_order() {
        let tmp = write_pcap(&stateful_frames());
        let mut fresh = open_app(tmp.path());
        let expected = stats_json(&mut fresh);

        let mut app = open_app(tmp.path());
        pollute(&mut app);
        finish_pass(&mut app);
        assert_eq!(stats_json(&mut app), expected);
        // Running it twice does not change it either.
        assert_eq!(stats_json(&mut app), expected);
    }

    /// Before the pass reaches a packet whose dissection uses cross-packet
    /// state, the TUI shows a placeholder instead of an order-dependent
    /// result, and replaces it once the result is ready.  Other packets show
    /// at once.
    #[test]
    fn placeholder_until_the_pass_reaches_a_stateful_packet() {
        let tmp = write_pcap(&stateful_frames());
        let reference = sequential_reference(tmp.path());
        let mut app = open_app(tmp.path());

        // Plain UDP: no cross-packet state.
        assert_eq!(shown(&mut app, 9), reference[9]);

        app.packet_list.selected = 6;
        app.load_selected();
        let sel = app.selected.as_ref().unwrap();
        assert!(sel.pending);
        assert_eq!(sel.tree_nodes.len(), 1);
        assert_eq!(sel.tree_nodes[0].label, loader::PENDING_TEXT);
        assert_eq!(app.get_or_dissect_summary(7).info, loader::PENDING_TEXT);
        assert!(app.ordered_needs_tick());

        finish_pass(&mut app);
        assert!(!app.ordered_needs_tick());
        let sel = app.selected.as_ref().unwrap();
        assert!(!sel.pending);
        let labels: Vec<&str> = sel.tree_nodes.iter().map(|n| n.label.as_str()).collect();
        assert_eq!(labels, self::labels(&reference[6]));
        // The placeholder row was dropped from the cache and is redone.
        assert!(app.pending_rows.is_empty());
        assert!(app.summary_cache.peek(&7).is_none());
        let s = app.get_or_dissect_summary(7);
        assert_eq!(s.info, reference[7].row.3);
    }

    /// The pass keeps results only for packets whose dissection used
    /// cross-packet state.
    #[test]
    fn pass_keeps_only_stateful_results() {
        let tmp = write_pcap(&stateful_frames());
        let mut app = open_app(tmp.path());
        finish_pass(&mut app);
        let pass = app.ordered.as_ref().unwrap();
        let statuses: Vec<Status> = (0..10).map(|i| pass.status(i)).collect();
        use Status::{Stateful as F, Stateless as L};
        assert_eq!(statuses, [F, F, F, F, F, F, F, F, F, L]);
        assert_eq!(pass.status(10), Status::Pending);
    }

    /// Once the pass has stopped, packets it did not reach are dissected on
    /// demand instead of waiting forever.
    #[test]
    fn stopped_pass_falls_back_to_on_demand_dissection() {
        let tmp = write_pcap(&stateful_frames());
        let mut app = open_app(tmp.path());
        app.packet_list.selected = 6;
        app.load_selected();
        assert!(app.selected.as_ref().unwrap().pending);

        // Dropping the sender ends the pass thread.
        app.ordered.as_mut().unwrap().feeder = None;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while app.ordered.as_ref().unwrap().status(6) != Status::Unavailable {
            assert!(std::time::Instant::now() < deadline, "pass did not stop");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert!(app.ordered_tick());
        let sel = app.selected.as_ref().unwrap();
        assert!(!sel.pending);
        assert!(sel.tree_nodes.iter().any(|n| n.label == "TCP"));
        assert!(!app.ordered_needs_tick());
    }

    /// Errors of the pass are reported to the user once.
    #[test]
    fn pass_errors_are_reported() {
        let tmp = write_pcap(&stateful_frames());
        let mut app = open_app(tmp.path());
        super::lock(&app.ordered.as_ref().unwrap().shared).error = Some("disk full".to_string());
        assert!(app.ordered_tick());
        let msg = app.detail_tree.yank_message.take().unwrap();
        assert!(msg.contains("disk full"), "{msg}");
        app.ordered_tick();
        assert!(app.detail_tree.yank_message.is_none());
    }

    /// A panic in the pass thread marks the pass stopped, with an error.
    #[test]
    fn panicking_pass_thread_reports_an_error() {
        let shared = std::sync::Mutex::new(super::Shared::default());
        std::thread::scope(|s| {
            let r = s
                .spawn(|| {
                    let _guard = super::StopGuard(&shared);
                    panic!("dissector bug");
                })
                .join();
            assert!(r.is_err());
        });
        let shared = super::lock(&shared);
        assert!(shared.stopped);
        assert!(shared.error.is_some());
    }

    /// Follow Stream on a placeholder says why nothing happens.
    #[test]
    fn follow_stream_waits_for_the_pass() {
        let tmp = write_pcap(&stateful_frames());
        let mut app = open_app(tmp.path());
        app.packet_list.selected = 2;
        app.load_selected();
        assert!(app.selected.as_ref().unwrap().pending);
        app.start_follow_stream();
        assert!(app.stream_build_progress.is_none());
        assert!(app.detail_tree.yank_message.is_some());
    }
}
