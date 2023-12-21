#![allow(dead_code)]
use openssl::sha;

use crate::{helpers::u256, json_types::ArweaveBlockHeader};

//The key to initialize the RandomX state from, for RandomX packing.
pub const RANDOMX_PACKING_KEY: &[u8] = b"default arweave 2.5 pack key";
// pub const RANDOMX_PACKING_ROUNDS_2_5: usize = 8*20;
pub const RANDOMX_PACKING_ROUNDS_2_6: usize = 8 * 45;

pub const RANDOMX_HASH_SIZE: usize = 32;
pub const RANDOMX_ENTROPY_SIZE: usize = 256 * 1024; //256KiB

pub const FORK_2_5_HEIGHT: u64 = 812970;
pub const FORK_2_6_HEIGHT: u64 = 1132210;
pub const FORK_2_7_HEIGHT: u64 = 1275480;

pub const MIN_SPORA_DIFFICULTY: u64 = 2;

pub const RETARGET_BLOCKS: u64 = 10;
pub const TARGET_TIME: u64 = 120;
pub const RETARGET_TOLERANCE_UPPER_BOUND: u64 = (TARGET_TIME * RETARGET_BLOCKS) + TARGET_TIME;
pub const RETARGET_TOLERANCE_LOWER_BOUND: u64 = (TARGET_TIME * RETARGET_BLOCKS) - TARGET_TIME;

pub const JOIN_CLOCK_TOLERANCE: u64 = 15;
pub const CLOCK_DRIFT_MAX: u64 = 5;

// Reset the nonce limiter (vdf) once every 1200 steps/seconds or every ~20 min
pub const NONCE_LIMITER_RESET_FREQUENCY: usize = 10 * 120;

// 25 checkpoints 40 ms each = 1000 ms
pub static NUM_CHECKPOINTS_IN_VDF_STEP: usize = 25;

// Typical ryzen 5900X iterations for 1 sec
pub static VDF_SHA_1S: u64 = 15_000_000;

// 90% of 4 TB.
pub static PARTITION_SIZE: u64 = 3600000000000;

// The size of a recall range. The first range is randomly chosen from the given
// mining partition. The second range is chosen from the entire weave.
pub static RECALL_RANGE_SIZE: u32 = 100 * 1024 * 1024; // e.g. 104857600

// Maximum size of a single data chunk, in bytes.
pub static DATA_CHUNK_SIZE: u32 = 256 * 1024;

// The original plan was to cap the proof at 262144 (also the maximum chunk size).
// The maximum tree depth is then (262144 - 64) / (32 + 32 + 32) = 2730.
// Later we added support for offset rebases by recognizing the extra 32 bytes,
// possibly at every branching point, as indicating a rebase. To preserve the depth maximum,
// we now cap the size at 2730 * (96 + 32) + 65 = 349504.
pub const MAX_DATA_PATH_SIZE: usize = 349504;

// We may have at most 1000 transactions + 1000 padding nodes => depth=11
// => at most 11 * 96 + 64 bytes worth of the proof. Due to its small size, we
// extend it somewhat for better future-compatibility.
pub const MAX_TX_PATH_SIZE: usize = 2176;

// The presence of the absolute end offset in the key makes sure packing of
// every chunk is unique, even when the same chunk is present in the same
// transaction or across multiple transactions or blocks. The presence of the
// transaction root in the key ensures one cannot find data that has certain
// patterns after packing. The presence of the reward address, combined with the
// 2.6 mining mechanics, puts a relatively low cap on the performance of a
// single dataset replica, essentially incentivizing miners to create more weave
// replicas per invested dollar.
pub fn get_chunk_entropy_input(
    chunk_offset: u256,
    tx_root: &[u8; 32],
    reward_address: &[u8; 32],
) -> [u8; 32] {
    let mut chunk_offset_bytes: [u8; 32] = [0; 32];
    chunk_offset.to_big_endian(&mut chunk_offset_bytes);

    let mut hasher = sha::Sha256::new();
    hasher.update(&chunk_offset_bytes);
    hasher.update(tx_root);
    hasher.update(reward_address);
    hasher.finish().into()
}

/// Takes the `global_step_number` and calculates how many steps previous an
/// entropy reset would have happened, returning the steps since a reset.
pub fn get_vdf_steps_since_reset(global_step_number: u64) -> usize {
    let reset_interval = NONCE_LIMITER_RESET_FREQUENCY as f64;
    let num_vdf_resets = global_step_number as f64 / reset_interval;
    let remainder: f64 = num_vdf_resets.fract(); // Capture right of the decimal
    (remainder * reset_interval).round() as usize
}

pub struct SeedData {
    pub seed: [u8; 48],
    pub next_seed: [u8; 48],
    pub partition_upper_bound: u64,
    pub next_partition_upper_bound: u64,
    pub vdf_difficulty: u64,
}

/// Gets the seed data for step_number, takes into account the reset step.
/// Note: next_vdf_difficulty is not part of the seed data as it is computed
/// using the block_time_history - which is a heavier operation handled separate
/// from the (quick) seed data retrieval
pub fn get_seed_data(step_number: u64, previous_block: &ArweaveBlockHeader) -> SeedData {
    let previous_info = &previous_block.nonce_limiter_info;

    assert!(step_number > previous_info.global_step_number);

    let steps_since_reset = get_vdf_steps_since_reset(step_number) as u64;
    let steps_this_block = step_number - previous_info.global_step_number;

    // println!("\nsteps_since_reset: {}\nsteps_this_block: {}", steps_since_reset, steps_this_block);

    // Was the entropy reset step crossed during this block
    if steps_this_block > steps_since_reset {
        // If so, the seed data should be the next_seed from the previous block
        SeedData {
            seed: previous_info.next_seed,
            next_seed: previous_block.indep_hash,
            partition_upper_bound: previous_info.next_zone_upper_bound,
            next_partition_upper_bound: previous_block.weave_size,
            vdf_difficulty: previous_info.next_vdf_difficulty.unwrap_or(VDF_SHA_1S),
        }
    } else {
        //...if not, just preserve the current seed data from the previous block
        SeedData {
            seed: previous_info.seed,
            next_seed: previous_info.next_seed,
            partition_upper_bound: previous_info.zone_upper_bound,
            next_partition_upper_bound: previous_info.next_zone_upper_bound,
            vdf_difficulty: previous_info.vdf_difficulty.unwrap_or(VDF_SHA_1S),
        }
    }
}

/// (ar_block.erl) Return {RecallRange1Start, RecallRange2Start} - the start offsets
/// of the two recall ranges.
 pub fn get_recall_range(h0: &[u8;32], partition_number: u64, partition_upper_bound: u64) -> (u256, u256) {
    // Decode the first 8 bytes of H0 to an unsigned integer (big-endian)
    let recall_range1_offset =
        u64::from_be_bytes(h0.get(0..8).unwrap_or(&[0; 8]).try_into().unwrap());

    // Calculate RecallRange1Start
    let recall_range1_start = partition_number * PARTITION_SIZE
        + recall_range1_offset % std::cmp::min(PARTITION_SIZE, partition_upper_bound);

    // Decode the entire H0 to an unsigned integer (big-endian)
	let recall_range2_start = u256::from_big_endian(h0) % u256::from(partition_upper_bound);

    (u256::from(recall_range1_start), recall_range2_start)
}