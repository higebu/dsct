//! Compact bitmap storage for TUI filter results.
//!
//! Replaces a `Vec<usize>` of matching packet indices with a packed bitmap
//! (one bit per packet) plus a per-block cumulative popcount index.  For a
//! capture of `N` packets the bitmap costs `N / 8` bytes regardless of the
//! match rate, versus `8 * matches` bytes for the old `Vec<usize>`.  At 100M
//! packets with a high match rate this is the difference between ~12.5MB and
//! ~800MB.
//!
//! The block index accelerates rank/select to `O(log blocks + block size)`:
//!
//! - [`FilterBitmap::select`] finds the position of the n-th set bit, replacing
//!   `filtered_indices[n]`.
//! - [`FilterBitmap::rank`] counts set bits before an index, replacing
//!   `filtered_indices.iter().position(...)`.
//!
//! Bits are only ever appended in increasing order in the incremental paths
//! (background indexing, live capture, sequential scan), so the block index is
//! maintained incrementally in amortized `O(1)` per word.

/// Number of `u64` words per block in the cumulative popcount index.
///
/// 8 words = 512 bits per block.  Larger blocks shrink the `blocks` vector but
/// lengthen the in-block scan during select/rank.
const WORDS_PER_BLOCK: usize = 8;

/// A packed bitmap of matching packet indices with a rank/select index.
///
/// Bit `i` being set means packet `i` matches the active filter.  The
/// `universe` is the number of packet slots covered; bits in `0..universe` may
/// be set or clear, and bits at or beyond `universe` are always clear.
#[derive(Debug, Clone, Default)]
pub struct FilterBitmap {
    /// Bit storage; bit `i` lives in `words[i / 64]` at position `i % 64`.
    words: Vec<u64>,
    /// Cumulative count of set bits *before* each finalized block of
    /// [`WORDS_PER_BLOCK`] words.  `blocks[b]` is the number of set bits in
    /// words `0..b * WORDS_PER_BLOCK`.  Only blocks whose words are all
    /// finalized (no longer being appended to) are recorded, so `blocks` may be
    /// shorter than the total number of blocks; the trailing partial block is
    /// always scanned directly.  `blocks[0]` is always 0.
    blocks: Vec<u64>,
    /// Number of packet slots covered (bits live in `0..universe`).
    universe: usize,
    /// Total number of set bits (`O(1)` length).
    ones: usize,
}

impl FilterBitmap {
    /// Create an empty bitmap covering zero packets.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a bitmap with every bit set over `0..n` (the identity / no-filter
    /// case).  Equivalent to the old `(0..n).collect::<Vec<usize>>()`.
    pub fn all_set(n: usize) -> Self {
        let mut bitmap = Self::new();
        bitmap.push_set_range(0..n);
        bitmap
    }

    /// Build a bitmap from sorted, strictly-increasing set-bit indices.
    ///
    /// `universe` is the total number of packet slots covered; every index
    /// yielded must be `< universe` and greater than the previous index.
    pub fn from_sorted_indices(universe: usize, indices: impl Iterator<Item = usize>) -> Self {
        let mut bitmap = Self::new();
        for idx in indices {
            // Advance the universe up to (but not including) idx without setting
            // bits, then set the bit at idx.
            bitmap.set_extend(idx);
        }
        bitmap.extend_universe(universe);
        bitmap
    }

    /// Total number of set bits.  `O(1)`.
    pub fn count_ones(&self) -> usize {
        self.ones
    }

    /// Number of packet slots covered by the bitmap.
    pub fn universe(&self) -> usize {
        self.universe
    }

    /// Returns `true` when no bits are set.
    pub fn is_empty(&self) -> bool {
        self.ones == 0
    }

    /// Reserve capacity for at least `additional` more packet slots.
    ///
    /// Only the word storage is reserved; the block index grows lazily.
    pub fn reserve(&mut self, additional: usize) {
        let needed_words = self.universe.saturating_add(additional).div_ceil(64);
        if needed_words > self.words.capacity() {
            self.words.reserve(needed_words - self.words.len());
        }
    }

    /// Returns `true` when bit `idx` is set.
    pub fn contains(&self, idx: usize) -> bool {
        if idx >= self.universe {
            return false;
        }
        let word = idx / 64;
        let bit = idx % 64;
        (self.words[word] >> bit) & 1 == 1
    }

    /// Number of set bits strictly before `idx`.
    ///
    /// `rank(idx)` is the count of matching packets with index `< idx`.  When
    /// `idx` is itself a set bit, `rank` returns its position in select order.
    /// `O(log blocks + WORDS_PER_BLOCK)`.
    pub fn rank(&self, idx: usize) -> usize {
        let idx = idx.min(self.universe);
        if idx == 0 {
            return 0;
        }
        let word = idx / 64;
        let bit = idx % 64;
        // Start from the nearest recorded (finalized) block boundary at or
        // before `word`.
        let block = (word / WORDS_PER_BLOCK).min(self.blocks.len().saturating_sub(1));
        let mut count = self.blocks.get(block).copied().unwrap_or(0) as usize;
        let block_word_start = block * WORDS_PER_BLOCK;
        for w in block_word_start..word {
            count += self.words[w].count_ones() as usize;
        }
        if bit > 0 {
            let mask = (1u64 << bit) - 1;
            count += (self.words[word] & mask).count_ones() as usize;
        }
        count
    }

    /// Index of the `n`-th set bit (0-based), or `None` if `n >= count_ones()`.
    ///
    /// Replaces `filtered_indices[n]`.  `O(log blocks + WORDS_PER_BLOCK)`.
    pub fn select(&self, n: usize) -> Option<usize> {
        if n >= self.ones {
            return None;
        }
        let target = n as u64;
        // Find the last recorded block whose cumulative count is <= target,
        // then scan forward word by word.  The target bit always exists
        // (`n < ones`), so the scan terminates within `words`.
        let block = self
            .blocks
            .partition_point(|&c| c <= target)
            .saturating_sub(1);
        let mut remaining = target - self.blocks[block];
        let mut word = block * WORDS_PER_BLOCK;
        loop {
            let pc = self.words[word].count_ones() as u64;
            if remaining < pc {
                let bit = select_in_word(self.words[word], remaining as u32);
                return Some(word * 64 + bit as usize);
            }
            remaining -= pc;
            word += 1;
        }
    }

    /// Index of the first set bit, or `None` when empty.
    pub fn first(&self) -> Option<usize> {
        self.select(0)
    }

    /// Find the set bit nearest to `target` (by absolute index distance).
    ///
    /// On a tie (equal distance to a set bit below and above `target`) the
    /// lower packet index is returned, matching the previous
    /// `min_by_key(|&i| abs_diff)` behavior which kept the earlier display
    /// position.  Returns `None` when the bitmap is empty.
    pub fn nearest(&self, target: usize) -> Option<usize> {
        if self.ones == 0 {
            return None;
        }
        // Number of set bits in 0..=target is rank(target+1); the set bit at or
        // before target is at select order rank(target+1) - 1.
        let below_rank = self.rank(target.saturating_add(1));
        let below = if below_rank > 0 {
            self.select(below_rank - 1)
        } else {
            None
        };
        // The first set bit strictly after target is at select order
        // rank(target+1) (which counts bits <= target).
        let above = self.select(below_rank);
        match (below, above) {
            (Some(b), Some(a)) => {
                let db = target - b;
                let da = a - target;
                // Tie keeps the lower index (the one at or before target).
                if db <= da { Some(b) } else { Some(a) }
            }
            (Some(b), None) => Some(b),
            (None, Some(a)) => Some(a),
            (None, None) => None,
        }
    }

    /// Iterate over set-bit positions in increasing order.
    pub fn iter(&self) -> Iter<'_> {
        Iter {
            bitmap: self,
            word: 0,
            current: self.words.first().copied().unwrap_or(0),
        }
    }

    /// Iterate over set-bit positions starting from the `n`-th set bit.
    ///
    /// Equivalent to `iter().skip(n)` but `O(log blocks + WORDS_PER_BLOCK)` to
    /// position, used for windowed rendering of visible rows.
    pub fn iter_from(&self, n: usize) -> Iter<'_> {
        match self.select(n) {
            Some(start) => {
                let word = start / 64;
                let bit = start % 64;
                // Mask off bits below `start` in the starting word.
                let masked = self.words[word] & (!0u64 << bit);
                Iter {
                    bitmap: self,
                    word,
                    current: masked,
                }
            }
            None => Iter {
                bitmap: self,
                word: self.words.len(),
                current: 0,
            },
        }
    }

    /// Extend the universe to cover `new_universe` packet slots without setting
    /// any new bits.  Shrinks are ignored (the universe only grows).
    pub fn extend_universe(&mut self, new_universe: usize) {
        if new_universe <= self.universe {
            return;
        }
        self.grow_words(new_universe);
        self.universe = new_universe;
        self.sync_blocks();
    }

    /// Append a contiguous run of set bits over `range`, extending the universe
    /// to `range.end`.
    ///
    /// `range.start` must be `>= universe` (bits are only appended in
    /// increasing order).  A `start > universe` advances the universe over the
    /// gap without setting those bits.
    pub fn push_set_range(&mut self, range: std::ops::Range<usize>) {
        let std::ops::Range { start, end } = range;
        if start >= end {
            self.extend_universe(start);
            return;
        }
        debug_assert!(
            start >= self.universe,
            "push_set_range start {start} < universe {}",
            self.universe
        );
        self.grow_words(end);
        for idx in start..end {
            let word = idx / 64;
            let bit = idx % 64;
            self.words[word] |= 1u64 << bit;
        }
        self.ones += end - start;
        self.universe = self.universe.max(end);
        self.sync_blocks();
    }

    /// Set the single bit at `idx`, advancing the universe to `idx + 1`.
    ///
    /// `idx` must be `>= universe` (append-only).  Used by sequential scans
    /// that push strictly-increasing matching indices.
    pub fn push(&mut self, idx: usize) {
        self.set_extend(idx);
    }

    /// Set the single bit at `idx`, advancing the universe to `idx + 1`.
    ///
    /// `idx` must be `>= universe` (append-only).
    fn set_extend(&mut self, idx: usize) {
        debug_assert!(
            idx >= self.universe,
            "set_extend idx {idx} < universe {}",
            self.universe
        );
        self.grow_words(idx + 1);
        let word = idx / 64;
        let bit = idx % 64;
        self.words[word] |= 1u64 << bit;
        self.ones += 1;
        self.universe = idx + 1;
        self.sync_blocks();
    }

    /// Grow `words` to cover at least `new_universe` bits.
    fn grow_words(&mut self, new_universe: usize) {
        let needed_words = new_universe.div_ceil(64);
        if needed_words > self.words.len() {
            self.words.resize(needed_words, 0);
        }
    }

    /// Fold every now-finalized block into the `blocks` prefix-sum index.
    ///
    /// A block is *finalized* once a strictly later word has been written,
    /// guaranteeing no further bits will be appended to it (appends are
    /// monotonic).  This runs in amortized `O(1)` per word: each word's
    /// popcount is folded exactly once.
    fn sync_blocks(&mut self) {
        if self.blocks.is_empty() {
            // blocks[0]: no set bits before the first block.
            self.blocks.push(0);
        }
        // The last word (index words.len()-1) may still receive bits, so only
        // blocks composed entirely of words before it are finalized.
        let finalized_words = self.words.len().saturating_sub(1);
        let finalized_blocks = finalized_words / WORDS_PER_BLOCK;
        while self.blocks.len() <= finalized_blocks {
            let b = self.blocks.len();
            let prev = self.blocks[b - 1];
            let start = (b - 1) * WORDS_PER_BLOCK;
            let end = start + WORDS_PER_BLOCK;
            let mut sum = prev;
            for w in start..end {
                sum += self.words[w].count_ones() as u64;
            }
            self.blocks.push(sum);
        }
    }
}

/// Select the position of the `n`-th set bit (0-based) within a single word.
///
/// `n` must be `< word.count_ones()`.
fn select_in_word(word: u64, n: u32) -> u32 {
    let mut remaining = n;
    let mut w = word;
    loop {
        let tz = w.trailing_zeros();
        if remaining == 0 {
            return tz;
        }
        remaining -= 1;
        // Clear the lowest set bit.
        w &= w - 1;
    }
}

/// Iterator over set-bit positions of a [`FilterBitmap`].
pub struct Iter<'a> {
    bitmap: &'a FilterBitmap,
    /// Index of the word currently being consumed in `current`.
    word: usize,
    /// Remaining set bits of the current word (already shifted/masked).
    current: u64,
}

impl Iterator for Iter<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        loop {
            if self.current != 0 {
                let bit = self.current.trailing_zeros() as usize;
                self.current &= self.current - 1;
                return Some(self.word * 64 + bit);
            }
            self.word += 1;
            if self.word >= self.bitmap.words.len() {
                return None;
            }
            self.current = self.bitmap.words[self.word];
        }
    }
}

impl<'a> IntoIterator for &'a FilterBitmap {
    type Item = usize;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

#[cfg(all(test, feature = "tui"))]
mod tests {
    use super::*;

    /// Deterministic linear congruential generator (no dev-dependency).
    struct Lcg(u64);

    impl Lcg {
        fn new(seed: u64) -> Self {
            Lcg(seed)
        }

        fn next_u64(&mut self) -> u64 {
            // Numerical Recipes LCG constants.
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
    }

    /// Reference implementation: a sorted Vec of set-bit indices.
    fn reference(universe: usize, bits: &[usize]) -> FilterBitmap {
        FilterBitmap::from_sorted_indices(universe, bits.iter().copied())
    }

    #[test]
    fn empty_bitmap() {
        let bm = FilterBitmap::new();
        assert_eq!(bm.count_ones(), 0);
        assert!(bm.is_empty());
        assert_eq!(bm.select(0), None);
        assert_eq!(bm.first(), None);
        assert_eq!(bm.rank(0), 0);
        assert_eq!(bm.rank(100), 0);
        assert!(!bm.contains(0));
        assert_eq!(bm.iter().count(), 0);
        assert_eq!(bm.nearest(5), None);
    }

    #[test]
    fn all_set_matches_range() {
        let bm = FilterBitmap::all_set(1000);
        assert_eq!(bm.count_ones(), 1000);
        assert_eq!(bm.universe(), 1000);
        assert!(!bm.is_empty());
        let collected: Vec<usize> = bm.iter().collect();
        assert_eq!(collected, (0..1000).collect::<Vec<_>>());
        for i in 0..1000 {
            assert_eq!(bm.select(i), Some(i));
            assert_eq!(bm.rank(i), i);
            assert!(bm.contains(i));
        }
        assert_eq!(bm.select(1000), None);
    }

    #[test]
    fn all_set_zero() {
        let bm = FilterBitmap::all_set(0);
        assert_eq!(bm.count_ones(), 0);
        assert_eq!(bm.universe(), 0);
        assert!(bm.is_empty());
    }

    #[test]
    fn select_rank_contains_against_reference() {
        let universe = 5000;
        // Densities: 0%, sparse, ~50%, dense, 100%.
        for &density_pct in &[0u64, 1, 13, 50, 87, 100] {
            let mut lcg = Lcg::new(0xDEAD_BEEF ^ density_pct);
            let mut bits = Vec::new();
            for i in 0..universe {
                if density_pct == 100 || (density_pct > 0 && lcg.next_u64() % 100 < density_pct) {
                    bits.push(i);
                }
            }
            let bm = reference(universe, &bits);
            assert_eq!(bm.count_ones(), bits.len(), "density {density_pct}");
            assert_eq!(bm.universe(), universe);

            // select equivalence.
            for (n, &expected) in bits.iter().enumerate() {
                assert_eq!(
                    bm.select(n),
                    Some(expected),
                    "select {n} density {density_pct}"
                );
            }
            assert_eq!(bm.select(bits.len()), None);

            // contains equivalence.
            let set: std::collections::HashSet<usize> = bits.iter().copied().collect();
            for i in 0..universe {
                assert_eq!(
                    bm.contains(i),
                    set.contains(&i),
                    "contains {i} density {density_pct}"
                );
            }

            // rank equivalence: rank(idx) == number of bits < idx.
            for &probe in &[0usize, 1, 64, 511, 512, 513, 2000, 4999, 5000] {
                let expected = bits.iter().filter(|&&b| b < probe).count();
                assert_eq!(
                    bm.rank(probe),
                    expected,
                    "rank {probe} density {density_pct}"
                );
            }

            // iter equivalence.
            let collected: Vec<usize> = bm.iter().collect();
            assert_eq!(collected, bits, "iter density {density_pct}");

            // iter_from equivalence.
            if !bits.is_empty() {
                let n = bits.len() / 2;
                let from: Vec<usize> = bm.iter_from(n).collect();
                assert_eq!(from, bits[n..].to_vec(), "iter_from density {density_pct}");
            }
            assert_eq!(bm.iter_from(bits.len()).count(), 0);
        }
    }

    #[test]
    fn append_range_growth_equivalence() {
        // Build by appending contiguous matching runs and gaps.
        let mut bm = FilterBitmap::new();
        bm.push_set_range(0..100); // match 0..100
        bm.extend_universe(200); // 100..200 scanned, no match
        bm.push_set_range(200..250); // match 200..250
        bm.extend_universe(1000); // tail scanned, no match

        let mut expected: Vec<usize> = (0..100).collect();
        expected.extend(200..250);
        assert_eq!(bm.iter().collect::<Vec<_>>(), expected);
        assert_eq!(bm.count_ones(), 150);
        assert_eq!(bm.universe(), 1000);
        for (n, &e) in expected.iter().enumerate() {
            assert_eq!(bm.select(n), Some(e));
        }
    }

    #[test]
    fn universe_extension_without_bits() {
        let mut bm = FilterBitmap::new();
        bm.extend_universe(5000);
        assert_eq!(bm.count_ones(), 0);
        assert_eq!(bm.universe(), 5000);
        assert!(bm.is_empty());
        assert_eq!(bm.select(0), None);
        assert_eq!(bm.rank(5000), 0);
    }

    #[test]
    fn from_sorted_indices_equivalence() {
        let bits = [3usize, 64, 65, 200, 511, 512, 1023, 1024, 4096];
        let bm = FilterBitmap::from_sorted_indices(5000, bits.iter().copied());
        assert_eq!(bm.iter().collect::<Vec<_>>(), bits.to_vec());
        assert_eq!(bm.universe(), 5000);
        for (n, &e) in bits.iter().enumerate() {
            assert_eq!(bm.select(n), Some(e));
            assert_eq!(bm.rank(e), n);
        }
    }

    #[test]
    fn nearest_behavior() {
        let bits = [10usize, 20, 30];
        let bm = reference(100, &bits);
        // Exact hit.
        assert_eq!(bm.nearest(20), Some(20));
        // Closer below.
        assert_eq!(bm.nearest(12), Some(10));
        // Closer above.
        assert_eq!(bm.nearest(28), Some(30));
        // Tie: equidistant between 10 and 20 -> lower index (10).
        assert_eq!(bm.nearest(15), Some(10));
        // Before all.
        assert_eq!(bm.nearest(0), Some(10));
        // After all.
        assert_eq!(bm.nearest(99), Some(30));
    }

    #[test]
    fn nearest_against_reference_min_by_key() {
        let universe = 3000;
        let mut lcg = Lcg::new(0x1234_5678);
        let mut bits = Vec::new();
        for i in 0..universe {
            if lcg.next_u64() % 100 < 20 {
                bits.push(i);
            }
        }
        let bm = reference(universe, &bits);
        for target in (0..universe).step_by(7) {
            // Reference: min_by_key on abs diff, ties keep earlier (lower) index.
            let expected = bits
                .iter()
                .enumerate()
                .min_by_key(|&(_, &i)| (i as isize - target as isize).unsigned_abs())
                .map(|(_, &i)| i);
            assert_eq!(bm.nearest(target), expected, "nearest {target}");
        }
    }
}
