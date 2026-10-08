use crate::decoder::Decoder;
use crate::encoder::{
    count_delta_chunks_with_hash, encode_insert_instruction, get_parent_data, Encoder,
};
use crate::sbc_scrubber::ClusterPoint;
use crate::{ChunkType, SBCHash, SBCKey, SBCMap};
use chunkfs::Data;
use chunkfs::Database;
use marline_sketcher::speedsketch;
use std::cmp::min;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zstd::stream;

pub struct GdeltaEncoder {
    zstd_flag: bool,
}

/// Everything a delta chunk is encoded against, built once per cluster: the bytes of the base
/// chunk, the key it is stored under, its fingerprint table and its sketch.
struct BaseChunk<'a, Hash: SBCHash> {
    data: &'a [u8],
    sbc_hash: Hash,
    word_hash_offsets: HashMap<u64, usize>,
    sketch: u64,
}

impl Default for GdeltaEncoder {
    fn default() -> Self {
        Self::new(false)
    }
}

impl GdeltaEncoder {
    pub fn new(zstd_flag: bool) -> Self {
        GdeltaEncoder { zstd_flag }
    }

    /// Encodes `chunk_data` against `base` as a list of INSERT and COPY instructions.
    ///
    /// `sketch_input` is the sketch of the input chunk and `base.sketch` the sketch of the base
    /// chunk. When the class bit of a word differs in the two sketches, that word has no
    /// counterpart in the base chunk, so it is left to the enclosing insertion and the fingerprint
    /// table is not probed at all.
    fn delta_code(chunk_data: &[u8], base: &BaseChunk<impl SBCHash>, sketch_input: u64) -> Vec<u8> {
        let parent_data = base.data;
        let word_size: usize = speedsketch::WORD_SIZE;
        let move_bts: usize = 64 / word_size;
        let mut delta_code = Vec::with_capacity(chunk_data.len());

        // A chunk shorter than a word has no fingerprint, nothing can be copied from it.
        if chunk_data.len() < word_size {
            encode_insert_instruction(chunk_data.to_vec(), &mut delta_code);
            return delta_code;
        }

        let mask_bts: usize = ((parent_data.len() as f64).log2() as usize).max(1);
        let mut anchor: usize = 0;
        let mut fp = 0u64;

        for j in 0..(word_size - 1) {
            fp = (fp << move_bts).wrapping_add(GEAR[chunk_data[j] as usize]);
        }
        let mut j = 0;
        while j < (chunk_data.len() - word_size + 1) {
            fp = (fp << move_bts).wrapping_add(GEAR[chunk_data[j + word_size - 1] as usize]);
            let word_hash: u64 = fp >> (64 - mask_bts);

            // Differing class bits prove the word is absent from the base chunk, so the
            // lookup is skipped and the word becomes an insertion.
            if speedsketch::class_bit_matches(fp, sketch_input, base.sketch) {
                if let Some(&offset) = base.word_hash_offsets.get(&word_hash) {
                    let mut equal_part_len: usize = 0;
                    for k in 0..min(parent_data.len() - offset, chunk_data.len() - j) {
                        if parent_data[offset + k] != chunk_data[j + k] {
                            break;
                        }
                        equal_part_len += 1;
                    }

                    if equal_part_len >= word_size {
                        //Insert instruction
                        let insert_data_len: usize = j - anchor;
                        if insert_data_len > 0 {
                            let insert_data = &chunk_data[anchor..(anchor + insert_data_len)];
                            let insert_instruction = &mut insert_data_len.to_ne_bytes()[..3];
                            insert_instruction[2] += 1 << 7;
                            delta_code.extend_from_slice(insert_instruction);
                            delta_code.extend_from_slice(insert_data);
                        }

                        // Copy instruction
                        let copy_instruction_len = &equal_part_len.to_ne_bytes()[..3];
                        let copy_instruction_offset = &offset.to_ne_bytes()[..3];
                        delta_code.extend_from_slice(copy_instruction_len);
                        delta_code.extend_from_slice(copy_instruction_offset);

                        anchor = j + equal_part_len;
                        j = anchor - 1; // Update j to skip the matched part
                        if j < chunk_data.len() - word_size {
                            for k in anchor..(anchor + word_size - 1) {
                                fp = (fp << move_bts).wrapping_add(GEAR[chunk_data[k] as usize]);
                            }
                        }
                    }
                }
            }

            if j >= chunk_data.len() - word_size {
                let insert_data_len: usize = chunk_data.len() - anchor;
                let insert_data = &chunk_data[anchor..(anchor + insert_data_len)];
                let insert_instruction = &mut insert_data_len.to_ne_bytes()[..3];
                insert_instruction[2] += 1 << 7;
                delta_code.extend_from_slice(insert_instruction);
                delta_code.extend_from_slice(insert_data);
            }
            j += 1
        }

        delta_code
    }

    fn encode_delta_chunk<D: Decoder, Hash: SBCHash>(
        &self,
        target_map: Arc<Mutex<&mut SBCMap<D, Hash>>>,
        chunk_data: &[u8],
        hash: Hash,
        base: &BaseChunk<Hash>,
    ) -> (usize, usize, SBCKey<Hash>) {
        // Sketch of the input chunk. Reused from the hashing stage when the hasher already
        // produced one, computed here otherwise.
        let sketch_input = hash.sketch().unwrap_or_else(|| speedsketch::sketch(chunk_data));
        let mut delta_code = GdeltaEncoder::delta_code(chunk_data, base, sketch_input);

        let mut target_map_lock = target_map.lock().unwrap();
        let number_delta_chunk = count_delta_chunks_with_hash(&target_map_lock, &hash);
        let sbc_hash = SBCKey {
            hash,
            chunk_type: ChunkType::Delta {
                parent_hash: base.sbc_hash.clone(),
                number: number_delta_chunk,
            },
        };
        if self.zstd_flag {
            delta_code = stream::encode_all(delta_code.as_slice(), 0).unwrap();
        }
        let processed_data = delta_code.len();
        let _ = target_map_lock.insert(sbc_hash.clone(), delta_code);
        (0, processed_data, sbc_hash)
    }
}

impl Encoder for GdeltaEncoder {
    fn encode_cluster<D: Decoder, Hash: SBCHash>(
        &self,
        target_map: Arc<Mutex<&mut SBCMap<D, Hash>>>,
        cluster: &mut [ClusterPoint<Hash>],
        parent_hash: Hash,
    ) -> (usize, usize) {
        let mut processed_data = 0;
        let parent_chunk = get_parent_data(target_map.clone(), parent_hash.clone(), cluster);
        let mut data_left = parent_chunk.data_left;
        let parent_data = parent_chunk.parent_data;
        let parent_sbc_hash = parent_chunk.parent_hash;
        let word_size: usize = speedsketch::WORD_SIZE;
        let move_bts: usize = 64 / word_size;
        let mut word_hash_offsets: HashMap<u64, usize> = HashMap::new();
        let mask_bts: usize = ((parent_data.len() as f64).log2() as usize).max(1);
        let base_words: usize = parent_data.len().saturating_sub(word_size - 1);
        let mut fp: u64 = 0;

        // Sketch of the base chunk, built in the very same pass over the base chunk that
        // fills the fingerprint table: every word that lands in the table must set its class bit,
        // otherwise the exclusion could drop a word that is really there.
        let mut base_sketch: u64 = 0;

        for i in 0..base_words.min(word_size - 1) {
            fp = (fp << move_bts).wrapping_add(GEAR[parent_data[i] as usize]);
        }

        for i in 0..base_words {
            fp = (fp << move_bts).wrapping_add(GEAR[parent_data[i + word_size - 1] as usize]);
            let word_hash: u64 = fp >> (64 - mask_bts);
            word_hash_offsets.insert(word_hash, i);
            if speedsketch::is_proxy(fp) {
                base_sketch |= 1u64 << speedsketch::class_of(fp);
            }
        }

        let base = BaseChunk {
            data: parent_data.as_slice(),
            sbc_hash: parent_sbc_hash,
            word_hash_offsets,
            sketch: base_sketch,
        };

        for (chunk_id, (hash, data_container)) in cluster.iter_mut().enumerate() {
            if parent_chunk.index > -1 && chunk_id == parent_chunk.index as usize {
                continue;
            }
            let mut target_hash = SBCKey::default();
            match data_container.extract() {
                Data::Chunk(data) => {
                    let (left, processed, sbc_hash) =
                        self.encode_delta_chunk(target_map.clone(), data, hash.clone(), &base);
                    data_left += left;
                    processed_data += processed;
                    target_hash = sbc_hash;
                }
                Data::TargetChunk(_) => {}
            }
            data_container.make_target(vec![target_hash]);
        }
        (data_left, processed_data)
    }
}

/// Compute delta between `new_chunk` and `base_chunk` using gdelta algorithm.
/// Returns delta as byte vector (INSERT/COPY instructions).
pub fn gdelta_diff(new_chunk: &[u8], base_chunk: &[u8]) -> Vec<u8> {
    let word_size: usize = 16;
    if new_chunk.len() < word_size || base_chunk.len() < word_size {
        return new_chunk.to_vec();
    }
    let move_bts: usize = 64 / word_size;
    let mask_bts: usize = (base_chunk.len() as f64).log2() as usize;
    let mut word_hash_offsets: HashMap<u64, usize> = HashMap::with_capacity(base_chunk.len());
    let mut fp: u64 = 0;

    for i in 0..(word_size - 1) {
        fp = (fp << move_bts).wrapping_add(GEAR[base_chunk[i] as usize]);
    }

    for i in word_size..(base_chunk.len() - word_size + 1) {
        fp = (fp << move_bts).wrapping_add(GEAR[base_chunk[i + word_size - 1] as usize]);
        let word_hash: u64 = fp >> (64 - mask_bts);
        word_hash_offsets.insert(word_hash, i);
    }

    let mut delta_code = Vec::new();
    let mut anchor: usize = 0;
    let mut fp = 0u64;

    for j in 0..(word_size - 1) {
        fp = (fp << move_bts).wrapping_add(GEAR[new_chunk[j] as usize]);
    }

    let mut j = 0;
    while j + word_size <= new_chunk.len() {
        fp = (fp << move_bts).wrapping_add(GEAR[new_chunk[j + word_size - 1] as usize]);
        let word_hash: u64 = fp >> (64 - mask_bts);

        if let Some(&offset) = word_hash_offsets.get(&word_hash) {
            let mut equal_part_len: usize = 0;
            for k in 0..min(base_chunk.len() - offset, new_chunk.len() - j) {
                if base_chunk[offset + k] != new_chunk[j + k] {
                    break;
                }
                equal_part_len += 1;
            }

            if equal_part_len >= word_size {
                let insert_data_len = j - anchor;
                if insert_data_len > 0 {
                    let insert_data = &new_chunk[anchor..(anchor + insert_data_len)];
                    let mut insert_instruction = insert_data_len.to_ne_bytes();
                    insert_instruction[2] |= 1 << 7;
                    delta_code.extend_from_slice(&insert_instruction[..3]);
                    delta_code.extend_from_slice(insert_data);
                }

                let copy_instruction_len = &equal_part_len.to_ne_bytes()[..3];
                let copy_instruction_offset = &offset.to_ne_bytes()[..3];
                delta_code.extend_from_slice(copy_instruction_len);
                delta_code.extend_from_slice(copy_instruction_offset);

                anchor = j + equal_part_len;
                j = anchor - 1;
                if j < new_chunk.len() - word_size {
                    for k in anchor..(anchor + word_size - 1) {
                        fp = (fp << move_bts).wrapping_add(GEAR[new_chunk[k] as usize]);
                    }
                }
            }
        }

        if j >= new_chunk.len() - word_size {
            let insert_data_len = new_chunk.len() - anchor;
            let insert_data = &new_chunk[anchor..(anchor + insert_data_len)];
            let mut insert_instruction = insert_data_len.to_ne_bytes();
            insert_instruction[2] |= 1 << 7;
            delta_code.extend_from_slice(&insert_instruction[..3]);
            delta_code.extend_from_slice(insert_data);
        }

        j += 1;
    }

    delta_code
}

/// Compute delta between `new_chunk` and `base_chunk` using gdelta algorithm.
/// Returns delta as byte vector (INSERT/COPY instructions).
pub fn gdelta_diff_new(
    new_chunk: &[u8],
    base_chunk: &[u8],
    manifest: &HashMap<u64, u32>,
) -> Vec<u8> {
    let base_len = base_chunk.len();

    let new_len = new_chunk.len();
    let word_size: usize = 16;
    if new_len < word_size || base_len < word_size {
        return new_chunk.to_vec();
    }
    let move_bts: usize = 64 / word_size;
    let mask_bts: usize = (base_chunk.len() as f64).log2() as usize;

    let mut delta_code = Vec::new();
    let mut anchor: usize = 0;
    let mut fp = 0u64;

    for j in 0..(word_size - 1) {
        fp = (fp << move_bts).wrapping_add(GEAR[new_chunk[j] as usize]);
    }

    let mut j = 0;
    while j + word_size <= new_len {
        fp = (fp << move_bts).wrapping_add(GEAR[new_chunk[j + word_size - 1] as usize]);
        let word_hash: u64 = fp >> (64 - mask_bts);

        if let Some(&offset) = manifest.get(&(word_hash)) {
            let mut equal_part_len: usize = 0;
            for k in 0..min(base_len - offset as usize, new_len - j) {
                if base_chunk[offset as usize + k] != new_chunk[j + k] {
                    break;
                }
                equal_part_len += 1;
            }

            if equal_part_len >= word_size {
                let insert_data_len = j - anchor;
                if insert_data_len > 0 {
                    let insert_data = &new_chunk[anchor..(anchor + insert_data_len)];
                    let mut insert_instruction = insert_data_len.to_ne_bytes();
                    insert_instruction[2] |= 1 << 7;
                    delta_code.extend_from_slice(&insert_instruction[..3]);
                    delta_code.extend_from_slice(insert_data);
                }

                let copy_instruction_len = &equal_part_len.to_ne_bytes()[..3];
                let copy_instruction_offset = &offset.to_ne_bytes()[..3];
                delta_code.extend_from_slice(copy_instruction_len);
                delta_code.extend_from_slice(copy_instruction_offset);

                anchor = j + equal_part_len;
                j = anchor - 1;
                if j < new_len - word_size {
                    for k in anchor..(anchor + word_size - 1) {
                        fp = (fp << move_bts).wrapping_add(GEAR[new_chunk[k] as usize]);
                    }
                }
            }
        }

        if j >= new_len - word_size {
            let insert_data_len = new_len - anchor;
            let insert_data = &new_chunk[anchor..(anchor + insert_data_len)];
            let mut insert_instruction = insert_data_len.to_ne_bytes();
            insert_instruction[2] |= 1 << 7;
            delta_code.extend_from_slice(&insert_instruction[..3]);
            delta_code.extend_from_slice(insert_data);
        }

        j += 1;
    }

    delta_code
}

// Gear table taken from https://github.com/nlfiedler/fastcdc-rs
#[rustfmt::skip]
// Gdelta fingerprints and the SpeedSketch fingerprints must come out of the very same gear
// table, otherwise a word of the base chunk could miss the class bit in its sketch and the
// exclusion would drop a word that is really there. Keep a single definition and re-export it, so that
// the other encoders can keep importing it from here.
pub(crate) use marline_sketcher::GEAR;
