// End-to-end Palantir pipeline tests over the synthetic corpus from `common`.
//
// Drives the `PalantirScrubber` chunk-by-chunk, exactly like the online backup
// flow: a base chunk is indexed first, then similar versions are stored as
// deltas relative to it. `unrelated` documents must not be rewritten into
// deltas. Every stored entry is decoded back and must match its source.
mod common;

use chunkfs::hashers::Sha256Hasher;
use chunkfs::{DataContainer, Hasher, Scrub};
use common::{build, Options};
use marline_index::heuristic_index::SearchConfig;
use marline_palantir::encoder::GdeltaEncoder;
use marline_palantir::lifecycle_manager::LifecycleManager;
use marline_palantir::palantir_scrubber::PalantirScrubber;
use marline_palantir::sf_generator::PalantirHasher;
use marline_palantir::types::TierConfig;
use marline_scrub::decoder::{Decoder, GdeltaDecoder};
use std::collections::HashMap;

type H = [u8; 32];

/// Prints a small aligned key/value block under a title.
fn report(title: &str, rows: &[(&str, String)]) {
    eprintln!("==== {title} ====");
    for (label, value) in rows {
        eprintln!("  {label:<22} {value}");
    }
    eprintln!("--------------------");
}

/// Formats a byte count with space-separated digit groups for readability.
fn fmt_size(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

fn hash_data(data: &[u8]) -> H {
    Sha256Hasher::default().hash(data)
}

fn make_scrubber() -> PalantirScrubber<PalantirHasher, H, GdeltaEncoder, 3> {
    let sf_gen = PalantirHasher::new(7, vec![4, 3, 2]);
    let tier_config = TierConfig::new([4, 3, 2]);
    PalantirScrubber::new(
        sf_gen,
        GdeltaEncoder,
        tier_config,
        LifecycleManager::<3>::default_configs(),
        SearchConfig::default(),
    )
}

/// Stores a single document in the scrubber, advancing the index.
/// Returns the produced target bytes for that chunk.
fn store_doc(
    scrubber: &mut PalantirScrubber<PalantirHasher, H, GdeltaEncoder, 3>,
    doc: &[u8],
) -> Vec<u8> {
    let hash = hash_data(doc);
    let mut database: HashMap<H, DataContainer<H>> = HashMap::new();
    database.insert(hash, DataContainer::from(doc.to_vec()));
    let mut target_map: HashMap<H, Vec<u8>> = HashMap::new();
    scrubber.scrub(&mut database, &mut target_map).unwrap();
    target_map.into_iter().next().map(|(_, v)| v).unwrap()
}

/// Decodes a stored target back into source bytes.
///
/// Palantir's `get_manifest` resolves the parent chain to its terminal raw
/// chunk and encodes every delta relative to that root, while `delta_bases`
/// remembers only the immediately-matched parent. So reconstruction decodes
/// each delta against the *terminal* raw chunk, not against the stored bytes
/// of the intermediate parent.
fn decode_from_target(
    scrubber: &PalantirScrubber<PalantirHasher, H, GdeltaEncoder, 3>,
    targets: &HashMap<H, Vec<u8>>,
    hash: H,
) -> Vec<u8> {
    let mut cursor = hash;
    while let Some(&base) = scrubber.delta_bases().get(&cursor) {
        cursor = base;
    }
    if cursor == hash {
        return targets.get(&hash).expect("terminal chunk must be stored").clone();
    }

    let root_data = targets.get(&cursor).expect("terminal base chunk must be stored raw");
    let delta = targets.get(&hash).expect("delta chunk must be stored");
    if delta.len() < 16 {
        // gdelta passes chunks shorter than one word through as raw bytes yet
        // Palantir still records them in `delta_bases`.
        delta.clone()
    } else {
        GdeltaDecoder::new(false).decode_chunk(root_data.clone(), delta)
    }
}

#[test]
fn similar_group_stores_versions_as_recoverable_deltas() {
    let corpus = build(42, &Options::default());
    let group = &corpus.similar_groups[0];
    let base = &group[0];
    let versions = &group[1..];

    let mut scrubber = make_scrubber();

    // Base goes in first, stored raw.
    let base_hash = hash_data(base);
    let base_stored = store_doc(&mut scrubber, base);
    assert_eq!(base_stored, *base, "base chunk must be stored raw");

    let mut targets: HashMap<H, Vec<u8>> = HashMap::new();
    targets.insert(base_hash, base.clone());

    let mut deltas = 0;
    for version in versions {
        let version_hash = hash_data(version);
        let stored = store_doc(&mut scrubber, version);
        targets.insert(version_hash, stored);
        if scrubber.delta_bases().contains_key(&version_hash) {
            deltas += 1;
        }
    }

    assert!(
        deltas >= versions.len().saturating_sub(1),
        "expected nearly all versions stored as deltas, got {deltas}/{} (base {} bytes, v0 {} bytes)",
        versions.len(),
        base.len(),
        versions[0].len()
    );

    let mut ok = 0;
    for version in versions {
        let decoded = decode_from_target(&scrubber, &targets, hash_data(version));
        assert_eq!(&decoded, version, "delta chain must reconstruct the version");
        ok += 1;
    }

    let delta_bytes: usize = versions.iter().map(|v| targets[&hash_data(v)].len()).sum();
    let orig_bytes: usize = versions.iter().map(|v| v.len()).sum();
    let saving = 100.0 * (1.0 - delta_bytes as f64 / orig_bytes as f64);
    report(
        "Palantir — similar group deltas",
        &[
            ("base bytes", fmt_size(base.len())),
            ("versions", versions.len().to_string()),
            ("deltas stored", deltas.to_string()),
            ("decoded OK", ok.to_string()),
            ("delta bytes", fmt_size(delta_bytes)),
            ("original bytes", fmt_size(orig_bytes)),
            ("saving", format!("{saving:.1}%")),
        ],
    );
}

#[test]
fn unrelated_documents_are_stored_raw_and_roundtrip() {
    let corpus = build(42, &Options::default());
    let mut scrubber = make_scrubber();
    let mut targets: HashMap<H, Vec<u8>> = HashMap::new();

    let mut stored_bytes: usize = 0;
    for doc in &corpus.unrelated {
        let hash = hash_data(doc);
        let stored = store_doc(&mut scrubber, doc);
        targets.insert(hash, stored);
        stored_bytes += doc.len();
        assert!(
            !scrubber.delta_bases().contains_key(&hash),
            "unrelated document must not be stored as a delta"
        );
        assert_eq!(&targets[&hash], doc, "unrelated document must be stored raw");
    }

    report(
        "Palantir — unrelated documents",
        &[
            ("docs", corpus.unrelated.len().to_string()),
            ("stored raw bytes", fmt_size(stored_bytes)),
            ("deltas", scrubber.delta_stored().to_string()),
        ],
    );
}

#[test]
fn mixed_corpus_roundtrips_end_to_end() {
    let opts = Options { edge_cases: false, ..Options::default() };
    let corpus = build(42, &opts);
    let docs = corpus.all();
    let mut scrubber = make_scrubber();
    let mut targets: HashMap<H, Vec<u8>> = HashMap::new();

    // Feed everything in the generator's stable order.
    for doc in &docs {
        let hash = hash_data(doc);
        let stored = store_doc(&mut scrubber, doc);
        targets.insert(hash, stored);
    }

    // Decode every single chunk through its (possibly empty) delta chain and
    // verify it reproduces the source exactly.
    for (i, doc) in docs.iter().enumerate() {
        let hash = hash_data(doc);
        let decoded = decode_from_target(&scrubber, &targets, hash);
        if &decoded != doc {
            panic!(
                "doc {i} ({} bytes, in delta_bases: {}) failed to round-trip: got {} bytes",
                doc.len(),
                scrubber.delta_bases().contains_key(&hash),
                decoded.len()
            );
        }
    }

    let total_bytes: usize = docs.iter().map(Vec::len).sum();
    report(
        "Palantir — mixed corpus round-trip",
        &[
            ("docs", docs.len().to_string()),
            ("total bytes", fmt_size(total_bytes)),
            ("deltas stored", scrubber.delta_stored().to_string()),
            ("round-trip OK", docs.len().to_string()),
        ],
    );
}
