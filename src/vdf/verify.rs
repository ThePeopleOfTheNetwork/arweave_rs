use rayon::prelude::*;
use serde::{Deserialize, Deserializer};
use serde_derive::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use uint::construct_uint;

// Definition of the U256 type
construct_uint! {
    /// 256-bit unsigned integer.
    #[cfg_attr(feature = "scale-info", derive(TypeInfo))]
    pub struct U256(4);
}

/// NonceLImiterInput holds the nonce_limiter_info from the Arweave block header
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct NonceLimiterInfo {
    output: String,
    global_step_number: u64,
    seed: String,
    next_seed: String,
    zone_upper_bound: u64,
    next_zone_upper_bound: u64,
    prev_output: String,
    last_step_checkpoints: Vec<String>,
    checkpoints: Vec<String>,
    #[serde(default, deserialize_with = "optional_string_to_usize")]
    vdf_difficulty: Option<usize>,
    #[serde(default, deserialize_with = "optional_string_to_usize")]
    next_vdf_difficulty: Option<usize>,
}

/// serde helper method to convert a JSON `string` value to a `usize`

fn optional_string_to_usize<'de, D>(deserializer: D) -> Result<Option<usize>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt_val: Option<Value> = Option::deserialize(deserializer)?;

    match opt_val {
        Some(Value::String(s)) => s
            .parse::<usize>()
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(_) => Err(serde::de::Error::custom("Invalid type")),
        None => Ok(None),
    }
}

/// Utility traits to decode base64_url encoded hashes into their constituent bytes
pub trait DecodeHash: Sized {
    fn from(base64_url_string: &str) -> Result<Self, String>;
}

impl DecodeHash for [u8; 32] {
    fn from(base64_url_string: &str) -> Result<Self, String> {
        base64_url::decode(base64_url_string)
            .map_err(|e| e.to_string())
            .and_then(|bytes| bytes.try_into().map_err(|_| "Length mismatch".to_string()))
    }
}

impl DecodeHash for [u8; 48] {
    fn from(base64_url_string: &str) -> Result<Self, String> {
        base64_url::decode(base64_url_string)
            .map_err(|e| e.to_string())
            .and_then(|bytes| bytes.try_into().map_err(|_| "Length mismatch".to_string()))
    }
}

// 25 checkpoints 40 ms each = 1000 ms
pub static NUM_CHECKPOINTS_IN_VDF_STEP: usize = 25;

// erlang consensus constants
// ================================================
// static VDF_CHECKPOINT_COUNT_IN_STEP: usize = 25;
// static VDF_BYTE_SIZE: usize = 32;
// const SALT_SIZE: usize = 32;
// const VDF_SHA_HASH_SIZE: usize = 32;

// Typical ryzen 5900X iterations for 1 sec
static VDF_SHA_1S: usize = 15_000_000;

// Reset the nonce limiter (vdf) once every 1200 steps/seconds or every ~20 min
pub const NONCE_LIMITER_RESET_FREQUENCY: usize = 10 * 120;

pub fn get_vdf_steps_since_reset(global_step_number: u64) -> usize {
    let reset_interval = NONCE_LIMITER_RESET_FREQUENCY as f64;
    let num_vdf_resets = global_step_number as f64 / reset_interval;
    let remainder: f64 = num_vdf_resets.fract(); // Capture right of the decimal
    (remainder * reset_interval).round() as usize
}

/// Derives a salt value from the step_number for checkpoint hashing
///
/// # Arguments
///
/// * `step_number` - The step the checkpoint belongs to, add 1 to the salt for
/// each subsequent checkpoint calculation.
pub fn step_number_to_salt_number(step_number: usize) -> usize {
    match step_number {
        0 => 0,
        _ => (step_number - 1) * NUM_CHECKPOINTS_IN_VDF_STEP + 1,
    }
}

fn get_vdf_difficulty(nonce_info: &NonceLimiterInfo) -> usize {
    match nonce_info.vdf_difficulty {
        Some(diff) => diff,
        None => VDF_SHA_1S / NUM_CHECKPOINTS_IN_VDF_STEP,
    }
}

/// Takes a checkpoint seed and applies the SHA384 block hash seed to it as
/// entropy. First it SHA256 hashes the `reset_seed` then SHA256 hashes the
/// output together with the `seed` hash.
///
/// /// # Arguments
///
/// * `seed` - The bytes of a SHA256 checkpoint hash
/// * `reset_seed` - The bytes of a SHA384 block hash used as entropy
///
/// # Returns
///
/// A new SHA256 seed hash containing the `reset_seed` entropy to use for
/// calculating checkpoints after the reset.
pub fn apply_reset_seed(seed: [u8; 32], reset_seed: [u8; 48]) -> [u8; 32] {
    let mut hasher = Sha256::new();

    // First hash the reset_seed (a sha348 block hash)
    hasher.update(&reset_seed);
    let reset_hash = hasher.finalize_reset();

    // Then merge the current seed with the SHA256 has of the block hash.
    hasher.update(&seed);
    hasher.update(&reset_hash);
    hasher.finalize_reset().into()
}

/// Calculates a VDF checkpoint by sequentially hashing a salt+seed, by the
/// specified number of iterations.
///
/// # Arguments
///
/// * `salt` - VDF checkpoints are salted with an auto incrementing salt counter.
/// * `seed` - Initial seed (often the output of a previous checkpoint).
/// * `checkpoint_count` - Can be used to calculate more than one checkpoint in sequence.
/// * `num_iterations` - The number of times to sequentially SHA256 hash between checkpoints.
///
/// # Returns
///
/// - `Vec<[u8;32]>` A Vec containing the calculated checkpoint hashes `checkpoint_count` in length.
pub fn vdf_sha2(
    salt: U256,
    seed: [u8; 32],
    num_checkpoints: usize,
    num_iterations: usize,
) -> Vec<[u8; 32]> {
    let mut local_salt = salt;
    let mut local_seed: [u8; 32] = seed;
    let mut salt_bytes: [u8; 32] = [0; 32];
    let mut checkpoints: Vec<[u8; 32]> = vec![[0; 32]; num_checkpoints];

    let mut hasher = Sha256::new();
    for checkpoint_idx in 0..num_checkpoints {
        //  initial checkpoint hash
        // -----------------------------------------------------------------
        if checkpoint_idx != 0 {
            // If the index is > 0, use the previous checkpoint as the seed
            local_seed = checkpoints[checkpoint_idx - 1];
        }

        // BigEndian to match erlang
        local_salt.to_big_endian(&mut salt_bytes);

        // Hash salt+seed
        hasher.update(&salt_bytes);
        hasher.update(local_seed);
        let mut hash_bytes = hasher.finalize_reset();

        // subsequent hash iterations (if needed)
        // -----------------------------------------------------------------
        for _ in 1..num_iterations {
            hasher.update(&salt_bytes);
            hasher.update(&hash_bytes);
            hash_bytes = hasher.finalize_reset();
        }

        // Store the result at the correct checkpoint index
        checkpoints[checkpoint_idx] = hash_bytes.into();

        // Increment the salt for the next checkpoint calculation
        local_salt = local_salt + 1;
    }
    checkpoints
}

/// Validate the last_step_checkpoints from the nonce_info to see if they are
/// valid. Verifies each checkpoint in parallel across as many cores as are
/// available.
///
/// # Arguments
///
/// * `nonce_info` - The NonceLimiterInput from the block header to validate.
///
/// # Returns
///
/// - `bool` - `true` if the checkpoints are valid, false otherwise.
pub fn last_step_checkpoints_is_valid(nonce_info: &NonceLimiterInfo) -> bool {
    let num_iterations = get_vdf_difficulty(nonce_info);
    let global_step_number: usize = nonce_info.global_step_number as usize;

    let seed_hash_string = nonce_info.checkpoints.get(1).unwrap();
    let mut _seed: [u8; 32] = DecodeHash::from(&seed_hash_string).unwrap();

    let mut checkpoint_hashes: Vec<[u8; 32]> = nonce_info
        .last_step_checkpoints
        .par_iter()
        .map(|cp_string| {
            let expected_hash = DecodeHash::from(&cp_string).unwrap();
            expected_hash
        })
        .collect();

    // If the vdf reset happened on this step, apply the entropy to the seed
    if (global_step_number as f64 / NUM_CHECKPOINTS_IN_VDF_STEP as f64).fract() == 0.0 {
        let reset_seed = DecodeHash::from(&nonce_info.seed).unwrap();
        _seed = apply_reset_seed(_seed, reset_seed);
    }

    // Prepend the seed
    checkpoint_hashes.push(_seed);

    // Reverse the list so the checkpoints match an incrementing index from 0
    checkpoint_hashes.reverse();

    let cp = checkpoint_hashes.clone();

    // Calculate all checkpoints in parallel with par_iter()
    let test: Vec<[u8; 32]> = (0..NUM_CHECKPOINTS_IN_VDF_STEP)
        .into_par_iter()
        .map(|i| {
            let salt: U256 = (step_number_to_salt_number(global_step_number - 1) + i).into();
            let res = vdf_sha2(salt, cp[i], 1, num_iterations);
            res[0]
        })
        .collect();

    let mut test: Vec<String> = test
        .par_iter()
        .map(|hash| base64_url::encode(hash))
        .collect();

    // Reverse our calculated checkpoints so they are the same order as the blocks
    test.reverse();

    let is_valid =  test == nonce_info.last_step_checkpoints;

    if is_valid == false {
        // Compare the original list with the calculated one
        let mismatches: Vec<(usize, &String, &String)> = nonce_info
            .last_step_checkpoints
            .iter()
            .zip(&test)
            .enumerate()
            .filter(|(_i, (a, b))| a != b)
            .map(|(i, (a, b))| (i, a, b))
            .collect();

        for (index, a, b) in mismatches {
            println!(
                "Mismatched hashes at index {}: expected {} got {}",
                index, a, b
            );
        }
    }
    is_valid
}

/// Validate the checkpoints from the nonce_info to see if they are valid.
/// Verifies each step in parallel across as many cores as are available.
///
/// # Arguments
///
/// * `nonce_info` - The NonceLimiterInput from the block header to validate.
///
/// # Returns
///
/// - `bool` - `true` if the checkpoints are valid, false otherwise.
pub fn checkpoints_is_valid(nonce_info: &NonceLimiterInfo) -> bool {
    let num_iterations = get_vdf_difficulty(nonce_info);

    let previous_seed = DecodeHash::from(&nonce_info.prev_output).unwrap();
    let reset_seed = DecodeHash::from(&nonce_info.seed).unwrap();

    // Convert all of the url encoded step hashes to bytes
    let mut step_hashes: Vec<[u8; 32]> = nonce_info
        .checkpoints
        .par_iter()
        .map(|cp_string| {
            let expected_hash = DecodeHash::from(cp_string).unwrap();
            expected_hash
        })
        .collect();

    // Add the seed from the previous nonce info to the steps
    step_hashes.push(previous_seed);

    // Reverse the step hashes so they can be iterated from oldest to most recent
    step_hashes.reverse();

    //z7ggG3WV9oITD2OgpSU66j0Jt_q9nk0V4c9g7bPcyK0

    // Make a read only copy for parallel iterating
    let steps = step_hashes.clone();
    let steps_since_reset = get_vdf_steps_since_reset(nonce_info.global_step_number);
    let reset_index = steps.len() - steps_since_reset - 2; // -2 here because we need the step before the reset (-1), and -1 because we added a hash to steps;

    // Calculate the step number of the first step in the blocks sequence
    let start_step_number = nonce_info.global_step_number as usize - nonce_info.checkpoints.len();

    // We must calculate the steps sequentially because we only have the first
    // and last checkpoint of each step, but we can do the steps in parallel
    let test: Vec<[u8; 32]> = (0..steps.len() - 1)
        .into_par_iter()
        .map(|i| {
            let salt: U256 = (step_number_to_salt_number(start_step_number + i)).into();
            let mut seed = steps[i];
            if i == reset_index {
                // println!(
                //     "reset_index: {i}, reset_seed: {}",
                //     base64_url::encode(&seed)
                // );
                seed = apply_reset_seed(seed, reset_seed);
            }
            let checkpoints = vdf_sha2(salt, seed, NUM_CHECKPOINTS_IN_VDF_STEP, num_iterations);
            *checkpoints.last().unwrap()
        })
        .collect();

    let mut test: Vec<String> = test
        .par_iter()
        .map(|hash| base64_url::encode(hash))
        .collect();

    test.reverse();

    let is_valid = test == nonce_info.checkpoints;

    if is_valid == false {
        // Compare the original list with the calculated one
        let mismatches: Vec<(usize, &String, &String)> = nonce_info
            .checkpoints
            .iter()
            .zip(&test)
            .enumerate()
            .filter(|(_i, (a, b))| a != b)
            .map(|(i, (a, b))| (i, a, b))
            .collect();

        for (index, a, b) in mismatches {
            println!(
                "Mismatched hashes at index {}: expected {} got {}",
                index, a, b
            );
        }
    }
    is_valid
}
