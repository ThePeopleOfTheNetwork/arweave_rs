#![allow(dead_code)]
use arweave_randomx_rs::*;
use openssl::sha;
 
use crate::arweave_types::*;

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

// The threshold was determined on the mainnet at the 2.5 fork block. The chunks
// submitted after the threshold must adhere to stricter validation rules.
pub const STRICT_DATA_SPLIT_THRESHOLD: u128 = 30607159107830;

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
pub const RECALL_RANGE_SIZE: u32 = 100 * 1024 * 1024; // e.g. 104857600

// Maximum size of a single data chunk, in bytes.
pub const DATA_CHUNK_SIZE: u32 = 256 * 1024;

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

/// The presence of the absolute end offset in the key makes sure packing of
/// every chunk is unique, even when the same chunk is present in the same
/// transaction or across multiple transactions or blocks. The presence of the
/// transaction root in the key ensures one cannot find data that has certain
/// patterns after packing. The presence of the reward address, combined with the
/// 2.6 mining mechanics, puts a relatively low cap on the performance of a
/// single dataset replica, essentially incentivizing miners to create more weave
/// replicas per invested dollar.
pub fn get_chunk_entropy_input(
    chunk_offset: U256,
    tx_root: &H256,
    reward_addr: &H256
) -> [u8; 32] {
    let mut chunk_offset_bytes: [u8; 32] = [0; 32];
    chunk_offset.to_big_endian(&mut chunk_offset_bytes);

    let mut hasher = sha::Sha256::new();
    hasher.update(&chunk_offset_bytes);
    hasher.update(tx_root.as_bytes());
    hasher.update(reward_addr.as_bytes());
    hasher.finish()
}

/// Return the smallest multiple of 256 KiB counting from StrictDataSplitThreshold
/// bigger than or equal to Offset.
pub fn get_byte_offset(offset: U256, block_start_offset: u128, block_end_offset: u128) -> u128 {
    if block_end_offset >= STRICT_DATA_SPLIT_THRESHOLD {
        let new_offset = offset.as_u128() + 1;
        let diff = new_offset - STRICT_DATA_SPLIT_THRESHOLD;
        STRICT_DATA_SPLIT_THRESHOLD
            + ((diff - 1) / DATA_CHUNK_SIZE as u128 + 1) * DATA_CHUNK_SIZE as u128
            - DATA_CHUNK_SIZE as u128
            - block_start_offset
    } else {
        offset.as_u128() - block_start_offset
    }
}

/// Generate a chunk ID used to construct the Merkle tree from the tx data chunks.
pub fn generate_chunk_id(chunk: &[u8]) -> [u8; 32] {
    let mut hasher = sha::Sha256::new();
    hasher.update(&chunk);
    hasher.finish()
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
    pub seed: H384,
    pub next_seed: H384,
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

/// The reference erlang implementation refers to this as ar_block:compute_h0
/// In the erlang reference implementation this hash is known as H0
pub fn compute_mining_hash(
    vdf_output: H256,
    partition_number: u32,
    vdf_seed: H384,
    mining_address: H256,
    randomx_vm: Option<&RandomXVM>,
) -> [u8; 32] {
    let pn: U256 = U256::from(partition_number);
    let mut partition_bytes: [u8; 32] = [0u8; 32];
    pn.to_big_endian(&mut partition_bytes);

    let mut input = Vec::new();
    input.append(&mut vdf_output.to_vec());
    input.append(&mut partition_bytes.to_vec());
    input.append(&mut vdf_seed[..32].to_vec()); // Use first 32 bytes of vdf_seed
    input.append(&mut mining_address.to_vec());

    // These variables extend the life of the created RandomX instance outside
    // the scope of the [None] match arm below
    let vm: &RandomXVM;
    let vm_storage: Option<RandomXVM>;

    // If needed, lazy initialize a RandomXVM and borrow a reference to it
    match randomx_vm {
        Some(existing_vm) => {
            vm = existing_vm;
        }
        None => {
            // Creates a disposable RandomXVM instance for use in this function
            vm_storage = Some(create_randomx_vm(
                RandomXMode::FastHashing,
                RANDOMX_PACKING_KEY,
            ));
            vm = vm_storage.as_ref().unwrap();
        }
    };

    let mining_hash = vm.calculate_hash(&input).unwrap();
    let hash_array: [u8; 32] = mining_hash.try_into().unwrap();
    hash_array
}

/// (ar_block.erl) Return {RecallRange1Start, RecallRange2Start} - the start offsets
/// of the two recall ranges.
pub fn get_recall_range(
    h0: &[u8; 32],
    partition_number: u64,
    partition_upper_bound: u64,
) -> (U256, U256) {
    // Decode the first 8 bytes of H0 to an unsigned integer (big-endian)
    let recall_range1_offset =
        u64::from_be_bytes(h0.get(0..8).unwrap_or(&[0; 8]).try_into().unwrap());

    // Calculate RecallRange1Start
    let recall_range1_start = partition_number * PARTITION_SIZE
        + recall_range1_offset % std::cmp::min(PARTITION_SIZE, partition_upper_bound);

    // Decode the entire H0 to an unsigned integer (big-endian)
    let recall_range2_start = U256::from_big_endian(h0) % U256::from(partition_upper_bound);

    (U256::from(recall_range1_start), recall_range2_start)
}
