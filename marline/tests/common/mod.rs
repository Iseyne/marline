//! Deterministic dataset generator for end-to-end tests.
//!
//! The corpus is built from a fixed seed: the same seed always yields the same
//! bytes. It covers the data classes relevant to deduplication / delta
//! compression: exact duplicates, near-duplicates (versions with edits),
//! unrelated documents, and boundary sizes. Pipeline-agnostic: works for both
//! SBC and Palantir.

/// Corpus options.
#[derive(Clone, Debug, PartialEq)]
pub struct Options {
    /// Number of logical documents (groups of similar content).
    pub docs: usize,
    /// Versions per group, including the base.
    pub versions: usize,
    /// Base document size in bytes.
    pub size: usize,
    /// Fraction of bytes edited in versions (0.0..=1.0).
    pub mutate_fraction: f64,
    /// Whether to include boundary sizes (empty, 1 byte, ~16K/32K).
    pub edge_cases: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { docs: 4, versions: 4, size: 256 * 1024, mutate_fraction: 0.03, edge_cases: true }
    }
}

/// A ready-to-use corpus.
#[derive(Clone, Debug, PartialEq)]
pub struct Corpus {
    /// Groups of similar documents: the first element is the base, the rest are versions.
    pub similar_groups: Vec<Vec<Vec<u8>>>,
    /// Unrelated documents (must not form pairs).
    pub unrelated: Vec<Vec<u8>>,
    /// Boundary sizes.
    pub edge_cases: Vec<Vec<u8>>,
}

impl Corpus {
    /// Total size of all documents.
    pub fn total_bytes(&self) -> usize {
        self.similar_groups
            .iter()
            .flatten()
            .chain(&self.unrelated)
            .chain(&self.edge_cases)
            .map(Vec::len)
            .sum()
    }

    /// All documents flattened (order is stable for a given seed).
    pub fn all(&self) -> Vec<Vec<u8>> {
        let mut all = Vec::new();
        for group in &self.similar_groups {
            all.extend(group.iter().cloned());
        }
        all.extend(self.unrelated.iter().cloned());
        all.extend(self.edge_cases.iter().cloned());
        all
    }
}

struct Rng {
    state: u64,
}

impl Rng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn next_usize(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = Vec::with_capacity(len);
        while v.len() < len {
            for b in self.next_u64().to_le_bytes() {
                if v.len() < len {
                    v.push(b);
                }
            }
        }
        v
    }
}

/// Builds a corpus from a seed.
pub fn build(seed: u64, opts: &Options) -> Corpus {
    let mut base_rng = Rng::new(seed);

    let similar_groups = (0..opts.docs)
        .map(|doc| {
            let base = base_rng.bytes(opts.size);
            let mut group = Vec::with_capacity(opts.versions);
            group.push(base.clone());
            for version in 1..opts.versions {
                let version_seed = seed
                    ^ ((doc as u64 + 1) << 32)
                    ^ (version as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15);
                group.push(mutate(&base, version_seed, opts.mutate_fraction));
            }
            group
        })
        .collect();

    let unrelated = (0..opts.docs)
        .map(|i| {
            let mut rng = Rng::new(seed ^ (0xDEAD_BEEF + i as u64).wrapping_mul(0x9E37_79B9));
            rng.bytes(opts.size / 2 + i)
        })
        .collect();

    let edge_cases = if opts.edge_cases {
        let mut rng = Rng::new(seed ^ 0x1234_5678);
        vec![
            Vec::new(),
            vec![0u8],
            rng.bytes(16 * 1024),
            rng.bytes(32 * 1024 + 1),
            vec![0xAB; 64 * 1024],
        ]
    } else {
        Vec::new()
    };

    Corpus { similar_groups, unrelated, edge_cases }
}

/// Applies deterministic edits (replace/insert/delete) to the base.
///
/// Edits are confined to a randomly placed contiguous window covering a small
/// fraction of the document, like real near-duplicates (a few changed
/// regions). Scattering edits across the whole document would perturb every
/// rolling-hash mark and defeat similarity hashing entirely.
fn mutate(base: &[u8], seed: u64, fraction: f64) -> Vec<u8> {
    let mut out = base.to_vec();
    if out.is_empty() {
        return out;
    }

    let mut rng = Rng::new(seed);
    let window_len = (base.len() / 16).max(64).min(base.len());
    let window_start = rng.next_usize(base.len() - window_len + 1);
    let window_end = window_start + window_len;
    let edits = ((window_len as f64 * fraction) as usize).clamp(1, window_len);

    for _ in 0..edits {
        let idx_in_window = rng.next_usize(window_len);
        let idx = window_start + idx_in_window;
        match rng.next_usize(3) {
            0 => {
                let n = 1 + rng.next_usize(4).min(window_end - idx);
                for b in out.iter_mut().skip(idx).take(n) {
                    *b = (rng.next_u64() & 0xff) as u8;
                }
            }
            1 => {
                let insert_idx = rng.next_usize(window_len + 1);
                let block_len = 1 + rng.next_usize(16);
                let block = rng.bytes(block_len);
                out.splice(window_start + insert_idx..window_start + insert_idx, block);
            }
            _ => {
                if window_end - idx > 1 {
                    let n = 1 + rng.next_usize(8).min(window_end - idx - 1);
                    out.drain(idx..idx + n);
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_is_deterministic() {
        let a = build(7, &Options::default());
        let b = build(7, &Options::default());
        assert_eq!(a, b);
    }

    #[test]
    fn corpus_differs_by_seed() {
        assert_ne!(build(7, &Options::default()), build(8, &Options::default()));
    }

    #[test]
    fn corpus_has_all_classes() {
        let c = build(7, &Options::default());
        assert!(!c.similar_groups.is_empty());
        assert!(!c.unrelated.is_empty());
        assert!(!c.edge_cases.is_empty());
        assert!(c.total_bytes() > 0);
        let group = &c.similar_groups[0];
        assert!(group.len() >= 2);
        assert_ne!(group[0], group[1], "a version must differ from its base");
    }

    #[test]
    fn mutate_keeps_length_bounded() {
        let base = Rng::new(1).bytes(64 * 1024);
        let version = mutate(&base, 99, 0.01);
        let ratio = version.len() as f64 / base.len() as f64;
        assert!((ratio - 1.0).abs() < 0.1, "length must not drift far: {ratio}");
    }
}
