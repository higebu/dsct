//! Chunked jobs over the displayed packets that read field values: sampled
//! value counts and the time histogram, plus one field of one packet for a
//! column.

use packet_dissector::registry::DissectorRegistry;
use packet_dissector_core::packet::{DissectBuffer, Packet};

use super::fields::{
    FieldStats, FieldStatsCollector, Histogram, Sample, Split, SplitCollector, protocol_layers,
    timestamp_us,
};
use super::{Session, Tick, ordered_pass};

/// An in-progress [`Session::start_field_stats`] job.
pub struct FieldStatsJob {
    sample: Sample,
    /// Sampled packets counted so far.
    cursor: usize,
    /// Packets to sample.
    end: usize,
    displayed: usize,
    collector: FieldStatsCollector,
    registry: DissectorRegistry,
}

/// An in-progress [`Session::start_histogram`] job.
pub struct HistogramJob {
    cursor: usize,
    histogram: Histogram,
    collector: SplitCollector,
    registry: DissectorRegistry,
}

impl Session {
    /// Packets dissected per tick by the field jobs.
    const FIELD_CHUNK_SIZE: usize = 2_000;

    /// Start counting field values over `sample` of the displayed packets.
    ///
    /// Returns `Err` with a message when the job cannot start.
    pub fn start_field_stats(&mut self, sample: Sample) -> Result<(), String> {
        let registry = self.scan_registry().map_err(|e| format!("Error: {e}"))?;
        let displayed = self.filtered.count_ones();
        self.field_stats_progress = Some(FieldStatsJob {
            sample,
            cursor: 0,
            end: sample.count(displayed),
            displayed,
            collector: FieldStatsCollector::new(protocol_layers(&registry)),
            registry,
        });
        Ok(())
    }

    /// Whether field values are being counted.
    pub fn field_stats_running(&self) -> bool {
        self.field_stats_progress.is_some()
    }

    /// Stop counting field values.
    pub fn cancel_field_stats(&mut self) {
        self.field_stats_progress = None;
    }

    /// Process one chunk of the field value count.
    pub fn field_stats_tick(&mut self) -> Tick<FieldStats> {
        let Some(job) = &mut self.field_stats_progress else {
            return Tick::Idle;
        };
        let end = (job.cursor + Self::FIELD_CHUNK_SIZE).min(job.end);
        let mut dissect_buf = DissectBuffer::new();
        let packets: Vec<usize> = match job.sample {
            Sample::Spread(_) if job.end < job.displayed => (job.cursor..end)
                .filter_map(|k| {
                    self.filtered
                        .select(job.sample.position(k, job.end, job.displayed))
                })
                .collect(),
            _ => self
                .filtered
                .iter_from(job.cursor)
                .take(end - job.cursor)
                .collect(),
        };
        for idx in packets {
            let index = &self.indices[idx];
            let Some(data) = self.capture.packet_data(index) else {
                continue;
            };
            let buf = dissect_buf.clear_into();
            // A packet that fails part way still has the layers before the
            // error.
            let _ = job
                .registry
                .dissect_with_link_type(data, u32::from(index.link_type), buf);
            job.collector.add(&Packet::new(buf, data));
        }
        job.cursor = end;
        if job.cursor >= job.end
            && let Some(job) = self.field_stats_progress.take()
        {
            return Tick::Done(job.collector.finish(job.sample, job.displayed as u64));
        }
        Tick::Running
    }

    /// Start charting the displayed packets over time in `buckets` bars,
    /// split by `split`.
    ///
    /// The returned histogram has the bars but not the split yet; ticks of
    /// [`histogram_tick`](Self::histogram_tick) compute the split over every
    /// displayed packet.
    pub fn start_histogram(&mut self, split: Split, buckets: usize) -> Result<Histogram, String> {
        let registry = self.scan_registry().map_err(|e| format!("Error: {e}"))?;
        let (indices, filtered) = (&self.indices, &self.filtered);
        let times = || {
            filtered.iter_from(0).map(|idx| {
                let index = &indices[idx];
                (
                    idx,
                    timestamp_us(index.timestamp_secs, index.timestamp_usecs),
                )
            })
        };
        let histogram = Histogram::timeline(split.clone(), buckets, times);
        let collector =
            SplitCollector::new(split, histogram.buckets.len(), protocol_layers(&registry));
        self.histogram_progress = Some(HistogramJob {
            cursor: 0,
            histogram: histogram.clone(),
            collector,
            registry,
        });
        Ok(histogram)
    }

    /// Whether the histogram split is being computed.
    pub fn histogram_running(&self) -> bool {
        self.histogram_progress.is_some()
    }

    /// Stop computing the histogram split.
    pub fn cancel_histogram(&mut self) {
        self.histogram_progress = None;
    }

    /// Process one chunk of the histogram split.
    pub fn histogram_tick(&mut self) -> Tick<Histogram> {
        let total = self.filtered.count_ones();
        let Some(job) = &mut self.histogram_progress else {
            return Tick::Idle;
        };
        let end = (job.cursor + Self::FIELD_CHUNK_SIZE).min(total);
        let mut dissect_buf = DissectBuffer::new();
        for idx in self.filtered.iter_from(job.cursor).take(end - job.cursor) {
            let index = &self.indices[idx];
            let Some(data) = self.capture.packet_data(index) else {
                continue;
            };
            let buf = dissect_buf.clear_into();
            let _ = job
                .registry
                .dissect_with_link_type(data, u32::from(index.link_type), buf);
            let bucket = job
                .histogram
                .bucket_of(timestamp_us(index.timestamp_secs, index.timestamp_usecs));
            job.collector.add(bucket, &Packet::new(buf, data));
        }
        job.cursor = end;
        if job.cursor >= total
            && let Some(job) = self.histogram_progress.take()
        {
            let mut histogram = job.histogram;
            job.collector.finish(&mut histogram);
            return Tick::Done(histogram);
        }
        Tick::Running
    }

    /// The first value of the field at `path` in packet `pkt_idx`, as the
    /// packet list shows it (`"1 (A)"` when the dissector names the value).
    ///
    /// `None` when the packet has no such field, or while it waits for the
    /// in-order pass.
    pub fn field_value(&self, pkt_idx: usize, path: &str) -> Option<String> {
        let index = self.indices.get(pkt_idx)?;
        let data = self.capture.packet_data(index)?;
        ordered_pass::first_field_value(
            &self.registry,
            self.ordered.as_ref(),
            pkt_idx,
            data,
            u32::from(index.link_type),
            path,
        )
    }
}

#[cfg(test)]
mod tests {
    use packet_dissector_core::dissector::ProtocolLayer;

    use super::super::fields::SeriesKey;
    use super::super::tests::test_session;
    use super::*;

    fn finish<T>(mut tick: impl FnMut() -> Tick<T>) -> T {
        loop {
            match tick() {
                Tick::Running => {}
                Tick::Done(out) => return out,
                Tick::Idle => panic!("job not running"),
            }
        }
    }

    #[test]
    fn field_stats_sample_the_first_displayed_packets() {
        let (mut session, _tmp) = test_session(5);
        assert!(matches!(session.field_stats_tick(), Tick::Idle));
        session.start_field_stats(Sample::First(3)).unwrap();
        assert!(session.field_stats_running());
        let stats = finish(|| session.field_stats_tick());
        assert!(!session.field_stats_running());
        assert_eq!((stats.sampled, stats.displayed), (3, 5));
        let port = stats.field("udp.dst_port").unwrap();
        assert_eq!(port.packets, 3);
        assert_eq!(port.top[0].value, "4097");
        let udp = stats.protocols.iter().find(|p| p.name == "UDP").unwrap();
        assert_eq!(udp.layer, Some(ProtocolLayer::Transport));

        session.start_field_stats(Sample::All).unwrap();
        assert_eq!(finish(|| session.field_stats_tick()).sampled, 5);
    }

    #[test]
    fn field_stats_spread_over_the_displayed_packets() {
        // Which positions are taken is covered by `Sample::position`'s test.
        let (mut session, _tmp) = test_session(10);
        session.start_field_stats(Sample::Spread(4)).unwrap();
        let stats = finish(|| session.field_stats_tick());
        assert_eq!(stats.sample, Sample::Spread(4));
        assert_eq!((stats.sampled, stats.displayed), (4, 10));
        session.start_field_stats(Sample::Spread(40)).unwrap();
        assert_eq!(finish(|| session.field_stats_tick()).sampled, 10);
    }

    #[test]
    fn field_stats_can_be_cancelled() {
        let (mut session, _tmp) = test_session(2);
        session.start_field_stats(Sample::All).unwrap();
        session.cancel_field_stats();
        assert!(!session.field_stats_running());
        assert!(matches!(session.field_stats_tick(), Tick::Idle));
    }

    #[test]
    fn field_jobs_fail_with_invalid_decode_as() {
        let (mut session, _tmp) = test_session(1);
        session.decode_as_args = vec!["not-a-decode-as".to_string()];
        assert!(session.start_field_stats(Sample::All).is_err());
        assert!(session.start_histogram(Split::TopProtocol, 4).is_err());
        assert!(!session.field_stats_running());
        assert!(!session.histogram_running());
    }

    #[test]
    fn histogram_splits_the_displayed_packets() {
        // test_session packets are 1 ms apart.
        let (mut session, _tmp) = test_session(4);
        let timeline = session.start_histogram(Split::TopProtocol, 4).unwrap();
        assert!(!timeline.complete);
        assert_eq!(timeline.bucket_us, 751);
        assert_eq!(
            timeline
                .buckets
                .iter()
                .map(|b| b.packets)
                .collect::<Vec<_>>(),
            vec![1, 1, 1, 1]
        );
        assert_eq!(timeline.buckets[2].first_packet, Some(2));
        assert!(session.histogram_running());
        let histogram = finish(|| session.histogram_tick());
        assert!(histogram.complete);
        assert_eq!(histogram.series.len(), 1);
        assert_eq!(histogram.series[0].key, SeriesKey::Value("UDP".into()));
        assert_eq!(histogram.series[0].packets, 4);
        assert_eq!(histogram.buckets[3].split, vec![1]);

        session.start_histogram(Split::TopProtocol, 4).unwrap();
        session.cancel_histogram();
        assert!(matches!(session.histogram_tick(), Tick::Idle));
    }

    #[test]
    fn field_value_reads_one_packet() {
        let (session, _tmp) = test_session(2);
        assert_eq!(
            session.field_value(1, "ipv4.src").as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(session.field_value(1, "tcp.dst_port"), None);
        assert_eq!(session.field_value(9, "ipv4.src"), None);
    }
}
