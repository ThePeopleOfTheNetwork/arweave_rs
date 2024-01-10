#![allow(dead_code)]
use rayon::prelude::*;
use openssl::sha;
use primitive_types::U256;
use crate::{json_types::NonceLimiterInfo, helpers::{consensus::*, hashes::{H256, H384}}};

// erlang consensus constants
// ================================================
// static VDF_CHECKPOINT_COUNT_IN_STEP: usize = 25;
// static VDF_BYTE_SIZE: usize = 32;
// const SALT_SIZE: usize = 32;
// const VDF_SHA_HASH_SIZE: usize = 32;


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

/// Between Arweave v2.6 and v2.7 the vdf difficulty was stored in a constant so
/// when parsing NonceLimiterInfo where there is no `vdf_difficulty` header,
/// this method returns the correct constant difficulty.
fn get_vdf_difficulty(nonce_info: &NonceLimiterInfo) -> usize {
    match nonce_info.vdf_difficulty {
        Some(diff) => diff as usize,
        None => VDF_SHA_1S as usize / NUM_CHECKPOINTS_IN_VDF_STEP,
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
pub fn apply_reset_seed(seed: H256, reset_seed: H384) -> H256 {
    let mut hasher = sha::Sha256::new();

    // First hash the reset_seed (a sha348 block hash)
    // (You can see this logic in ar_nonce_limiter:mix_seed)
    hasher.update(&reset_seed.as_bytes());
    let reset_hash = hasher.finish();

    // Then merge the current seed with the SHA256 has of the block hash.
    let mut hasher = sha::Sha256::new();
    hasher.update(&seed.as_bytes());
    hasher.update(&reset_hash);
    H256::from(hasher.finish())
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
    seed: H256,
    num_checkpoints: usize,
    num_iterations: usize,
) -> Vec<H256> {
    let mut local_salt: U256 = salt;
    let mut local_seed: H256 = seed;
    let mut salt_bytes: H256 = H256::zero();
    let mut checkpoints: Vec<H256> = vec![H256::default(); num_checkpoints];

    for checkpoint_idx in 0..num_checkpoints {
        //  initial checkpoint hash
        // -----------------------------------------------------------------
        if checkpoint_idx != 0 {
            // If the index is > 0, use the previous checkpoint as the seed
            local_seed = checkpoints[checkpoint_idx - 1];
        }

        // BigEndian to match erlang
        local_salt.to_big_endian(salt_bytes.as_mut());

        // Hash salt+seed
        let mut hasher = sha::Sha256::new();
        hasher.update(&salt_bytes.as_bytes());
        hasher.update(&local_seed.as_bytes());
        let mut hash_bytes = H256::from(hasher.finish());

        // subsequent hash iterations (if needed)
        // -----------------------------------------------------------------
        for _ in 1..num_iterations {
            let mut hasher = sha::Sha256::new();
            hasher.update(&salt_bytes.as_bytes());
            hasher.update(&hash_bytes.as_bytes());
            hash_bytes = H256::from(hasher.finish());
        }
        
        // Store the result at the correct checkpoint index
        checkpoints[checkpoint_idx] = hash_bytes;

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
    
    let mut _seed = *nonce_info.checkpoints.get(1).unwrap();
    let mut checkpoint_hashes = nonce_info.last_step_checkpoints.clone();

    // If the vdf reset happened on this step, apply the entropy to the seed
    if (global_step_number as f64 / NUM_CHECKPOINTS_IN_VDF_STEP as f64).fract() == 0.0 {
        let reset_seed = nonce_info.seed;
        _seed = apply_reset_seed(_seed, reset_seed);
    }

    // Prepend the seed
    checkpoint_hashes.push(_seed);

    // Reverse the list so the checkpoints match an incrementing index from 0
    checkpoint_hashes.reverse();

    let cp = checkpoint_hashes.clone();

    // Calculate all checkpoints in parallel with par_iter()
    let mut test: Vec<H256> = (0..NUM_CHECKPOINTS_IN_VDF_STEP)
        .into_par_iter()
        .map(|i| {
            let salt: U256 = (step_number_to_salt_number(global_step_number - 1) + i).into();
            let res = vdf_sha2(salt, cp[i], 1, num_iterations);
            res[0]
        })
        .collect();

    // Reverse our calculated checkpoints so they are the same order as the blocks
    test.reverse();

    let is_valid =  test == nonce_info.last_step_checkpoints;

    if !is_valid {
        // Compare the original list with the calculated one
        let mismatches: Vec<(usize, &H256, &H256)> = nonce_info
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
                index, base64_url::encode(a), base64_url::encode(b)
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

    let previous_seed = nonce_info.prev_output;
    let reset_seed = nonce_info.seed;

    // Create a working copy of the step hashes (called checkpoints in the json)
    let mut step_hashes = nonce_info.checkpoints.clone();

    // Add the seed from the previous nonce info to the steps
    step_hashes.push(previous_seed);

    // Reverse the step hashes so they can be iterated from oldest to most recent
    step_hashes.reverse();

    // Make a read only copy for parallel iterating
    let steps = step_hashes.clone();
    let steps_since_reset = get_vdf_steps_since_reset(nonce_info.global_step_number);
    let reset_index = steps.len() - steps_since_reset - 2; // -2 here because we need the step before the reset (-1), and -1 because we added a hash to steps;

    // Calculate the step number of the first step in the blocks sequence
    let start_step_number = nonce_info.global_step_number as usize - nonce_info.checkpoints.len();

    // We must calculate the checkpoint iterations sequentially because we only 
    // have the first and last checkpoint of each step, but we can do the steps
    // in parallel
    let mut test: Vec<H256> = (0..steps.len() - 1)
        .into_par_iter()
        .map(|i| {
            let salt: U256 = (step_number_to_salt_number(start_step_number + i)).into();
            let mut seed = steps[i];
            if i == reset_index {
                seed = apply_reset_seed(seed, reset_seed);
            }
            let checkpoints = vdf_sha2(salt, seed, NUM_CHECKPOINTS_IN_VDF_STEP, num_iterations);
            *checkpoints.last().unwrap()
        })
        .collect();

    test.reverse();

    let is_valid = test == nonce_info.checkpoints;

    if !is_valid {
        // Compare the original list with the calculated one
        let mismatches: Vec<(usize, &H256, &H256)> = nonce_info
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
                index, base64_url::encode(a), base64_url::encode(b)
            );
        }
    }
    is_valid
}
