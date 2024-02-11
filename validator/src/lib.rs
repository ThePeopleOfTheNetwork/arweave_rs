//! Validates all of the Arweave block header fields follow Arweave consensus
//! rules.
#![allow(dead_code)]
use arweave_rs_randomx::RandomXVM;
use arweave_rs_types::{*, consensus::*};
use color_eyre::eyre::{eyre, Result};
use arweave_rs_indexes::*;
use merkle::*;
use openssl::sha;
use arweave_rs_packing::{*, feistel::*};

pub mod merkle;

/// Sequentially performs all of the checks required to validate an Arweave 
/// block starting with the simplest (least expensive) checks and finishing with
/// the most involved checks. Note: This excludes the VDF checkpoint validation
/// which is performed separately.
pub fn pre_validate_block(
    block_header: &ArweaveBlockHeader,
    previous_block_header: &ArweaveBlockHeader,
    block_index: &BlockIndex<Initialized>,
    randomx_vm: Option<&RandomXVM>,
) -> Result<[u8; 32]> {
    // =========================================================================
    // Arweave 2.7 checks
    // =========================================================================
    let block_height = block_header.height;

    // Validate previous block poa and poa2 proof sizes
    if !proof_size_is_valid(&previous_block_header.poa, block_height - 1) {
        return Err(eyre!("previous blocks PoA proof has invalid size"));
    }

    if !proof_size_is_valid(&previous_block_header.poa2, block_height - 1) {
        return Err(eyre!("previous blocks PoA2 proof has invalid size"));
    }

    // Validate current blocks poa and poa2 proof sizes
    if !proof_size_is_valid(&block_header.poa, block_height) {
        return Err(eyre!("PoA proof has invalid size"));
    }

    if !proof_size_is_valid(&block_header.poa2, block_height) {
        return Err(eyre!("PoA2 proof has invalid size"));
    }

    // Validate the chunk_hash to see if it matches the poa chunk
    let chunk = &block_header.poa.chunk;
    if !chunk_hash_is_valid(&block_header.chunk_hash, chunk, block_height) {
        return Err(eyre!("chunk_hash does not match poa.chunk bytes"));
    }

    // Validate chunk2_hash to see that it matches the poa2 chunk if present
    if block_header.chunk2_hash.is_some() {
        let chunk = &block_header.poa2.chunk;
        let chunk2_hash = block_header.chunk2_hash.unwrap_or_default();
        if !chunk_hash_is_valid(&chunk2_hash, chunk, block_height) {
            return Err(eyre!("chunk2_hash does not match poa2.chunk bytes"));
        }
    }

    // =========================================================================
    // General Arweave checks
    // =========================================================================

    // Compute the block_hash and validate it against block_header.indep_hash
    if !block_hash_is_valid(block_header) {
        return Err(eyre!("indep_hash does not match calculated block_hash"));
    }

    // ==============================
    // Recently proposed block checks
    // ------------------------------
    // Validate timestamp

    // Validate existing Solution hash - has the solution  already been
    // validated? (possibly report a double signing)

    // Validate VDF step is within range of current

    // ==============================

    // Validate the previous blocks indep_hash is the parent of the current
    if block_header.previous_block != previous_block_header.indep_hash {
        return Err(eyre!("previous blocks indep_hash is not the parent block"));
    }

    // Validate last re-target
    if !last_retarget_is_valid(block_header, previous_block_header) {
        return Err(eyre!("last_retarget is invalid"));
    }

    // Validate difficulty
    if !difficulty_is_valid(block_header, previous_block_header) {
        return Err(eyre!("block difficulty is invalid"));
    }

    // Validate cumulative difficulty
    if !cumulative_diff_is_valid(block_header, previous_block_header) {
        return Err(eyre!("cumulative_diff is invalid"));
    }

    // Validate "quick" PoW
    let quick_pow_result = quick_pow_is_valid(block_header, previous_block_header, randomx_vm);

    let (mining_hash, solution_hash) = match quick_pow_result {
        Ok(tuple) => tuple,
        Err(err) => return Err(err),
    };

    // Validate Nonce Limiter seed data (ar_nonce_limiter:get_seed_data)
    if !seed_data_is_valid(block_header, previous_block_header) {
        return Err(eyre!("seed_data is invalid"));
    }

    // Nonce Limiter: Block partition number below upper bound
    if !partition_number_is_valid(block_header) {
        return Err(eyre!("partition_number is invalid"));
    }

    // Nonce Limiter: Nonce is below Max Nonce limit
    if !nonce_is_valid(block_header) {
        return Err(eyre!("nonce is invalid"));
    }

    // Prevalidate PoA - recall range (mining_hash = H0)
    let (recall_byte_1, recall_byte_2) = match recall_bytes_is_valid(block_header, &mining_hash) {
        Ok(tuple) => tuple,
        Err(err) => return Err(err),
    };

    // POA merkle proofs / chunk validation
    if !poa_is_valid(
        &block_header.poa,
        recall_byte_1,
        block_index,
        &block_header.reward_addr,
        randomx_vm,
    ) {
        return Err(eyre!("poa is invalid"));
    }

    // POA2 merkle proofs / chunk validation (if neccessary)
    if let Some(recall_byte_2) = recall_byte_2 {
        if !poa_is_valid(
            &block_header.poa2,
            recall_byte_2,
            block_index,
            &block_header.reward_addr,
            randomx_vm,
        ) {
            return Err(eyre!("poa2 is invalid"));
        }
    }

    Ok(solution_hash)
}

fn compute_solution_hash(mining_hash: &[u8; 32], hash_preimage: &H256) -> [u8; 32] {
    let mut hasher = sha::Sha256::new();
    hasher.update(mining_hash);
    hasher.update(hash_preimage.as_bytes());
    hasher.finish()
}

fn proof_size_is_valid(poa_data: &PoaData, block_height: u64) -> bool {
    // Don't do this validation check on pre 2.7 blocks
    if block_height < FORK_2_7_HEIGHT {
        return true;
    }

    let tx_path = &poa_data.tx_path;
    let data_path = &poa_data.data_path;
    let chunk = &poa_data.chunk;

    tx_path.len() <= MAX_TX_PATH_SIZE
        && data_path.len() <= MAX_DATA_PATH_SIZE
        && chunk.len() <= (DATA_CHUNK_SIZE as usize)
}

fn chunk_hash_is_valid(chunk_hash: &H256, chunk: &Base64, block_height: u64) -> bool {
    if block_height < FORK_2_7_HEIGHT {
        return true;
    }

    let mut hasher = sha::Sha256::new();
    hasher.update(chunk.0.as_slice());
    let hash = H256::from(hasher.finish());
    hash == *chunk_hash
}

fn last_retarget_is_valid(
    block_header: &ArweaveBlockHeader,
    previous_block_header: &ArweaveBlockHeader,
) -> bool {
    if is_retarget_height(block_header) {
        block_header.last_retarget == block_header.timestamp
    } else {
        block_header.last_retarget == previous_block_header.last_retarget
    }
}

fn difficulty_is_valid(
    block_header: &ArweaveBlockHeader,
    previous_block_header: &ArweaveBlockHeader,
) -> bool {
    if is_retarget_height(block_header) {
        let result = calculate_difficulty(block_header, previous_block_header);
        match result {
            Ok(computed_diff) => {
                if computed_diff == block_header.diff {
                    true
                } else {
                    println!(
                        "\ncomputed: {}\n  actual: {}",
                        computed_diff, block_header.diff
                    );
                    false
                }
            }
            Err(_) => false,
        }
    } else {
        block_header.diff == previous_block_header.diff
            && block_header.last_retarget == previous_block_header.last_retarget
    }
}

fn calculate_difficulty(
    block_header: &ArweaveBlockHeader,
    previous_block_header: &ArweaveBlockHeader,
) -> Result<U256> {
    let height = block_header.height;
    let timestamp = block_header.timestamp;

    if height < FORK_2_5_HEIGHT {
        return Err(eyre!(
            "Can't calculate difficulty for block height prior to Fork 2.5"
        ));
    }
    let previous_diff = previous_block_header.diff;
    let previous_last_retarget = previous_block_header.last_retarget;

    // The largest possible value by which the previous block's timestamp may
    // exceed the next block's timestamp.
    let max_timestamp_deviation = JOIN_CLOCK_TOLERANCE * 2 + CLOCK_DRIFT_MAX;

    // Number of blocks between difficulty re-targets and the target block time
    let target_time = RETARGET_BLOCKS * TARGET_TIME;

    // The actual time since the last retarget
    let actual_time = std::cmp::max(timestamp - previous_last_retarget, max_timestamp_deviation);

    if actual_time < RETARGET_TOLERANCE_UPPER_BOUND && actual_time > RETARGET_TOLERANCE_LOWER_BOUND
    {
        // Maintain difficulty from previous block
        Ok(previous_diff)
    } else {
        // Calculate a new difficulty
        let min_diff = U256::from(MIN_SPORA_DIFFICULTY);
        let max_diff = U256::max_value();
        // We have to + 1 in these equations because MAX_DIFF in erlang is one larger
        // than what will fit in U256::max_value() and would cause integer overflow
        let diff_inverse = ((max_diff - previous_diff + 1) * actual_time) / target_time;
        let computed_diff = max_diff - diff_inverse + 1;
        Ok(computed_diff.clamp(min_diff, max_diff))
    }
}

fn cumulative_diff_is_valid(
    block_header: &ArweaveBlockHeader,
    previous_block_header: &ArweaveBlockHeader,
) -> bool {
    let cumulative_diff = compute_cumulative_diff(block_header, previous_block_header);
    cumulative_diff == block_header.cumulative_diff
}

fn compute_cumulative_diff(
    block_header: &ArweaveBlockHeader,
    previous_block_header: &ArweaveBlockHeader,
) -> U256 {
    // TODO: Make return val a result and check for block height > 2.5 fork
    let max_diff = U256::max_value();
    let delta = max_diff / (max_diff - block_header.diff);
    previous_block_header.cumulative_diff + delta
}

fn quick_pow_is_valid(
    block_header: &ArweaveBlockHeader,
    previous_block_header: &ArweaveBlockHeader,
    randomx_vm: Option<&RandomXVM>,
) -> Result<([u8; 32], [u8; 32])> {
    // Current block_header properties
    let nonce_limiter_info = &block_header.nonce_limiter_info;
    let vdf_output = nonce_limiter_info.output;
    let mining_address: H256 = block_header.reward_addr;
    let partition_number: u32 = block_header.partition_number as u32;

    // Properties from previous block header
    let previous_nonce_limiter_info = &previous_block_header.nonce_limiter_info;
    let previous_vdf_seed: H384 = previous_nonce_limiter_info.seed;

    let mining_hash = compute_mining_hash(
        vdf_output,
        partition_number,
        previous_vdf_seed,
        mining_address,
        randomx_vm,
    );

    // Now combine H0 with the preimage to create the solution_hash
    let hash_preimage = block_header.hash_preimage;
    let solution_hash = compute_solution_hash(&mining_hash, &hash_preimage);

    let solution_hash_value_big: U256 = U256::from_big_endian(&solution_hash);

    let diff: U256 = block_header.diff;
    if solution_hash_value_big > diff {
        Ok((mining_hash, solution_hash))
    } else {
        Err(eyre!(
            "Block solution_hash does not satisfy proof of work difficulty check"
        ))
    }
}

fn seed_data_is_valid(
    block_header: &ArweaveBlockHeader,
    previous_block_header: &ArweaveBlockHeader,
) -> bool {
    let nonce_info = &block_header.nonce_limiter_info;
    let expected_seed_data = get_seed_data(
        block_header.nonce_limiter_info.global_step_number,
        previous_block_header,
    );

    // Note: next_vdf_difficulty is not checked here as it is a heavier operation
    if expected_seed_data.seed == nonce_info.seed
        && expected_seed_data.next_seed == nonce_info.next_seed
        && expected_seed_data.next_partition_upper_bound == nonce_info.next_zone_upper_bound
        && expected_seed_data.partition_upper_bound == nonce_info.zone_upper_bound
        && expected_seed_data.vdf_difficulty == nonce_info.vdf_difficulty.unwrap_or(VDF_SHA_1S)
    {
        true
    } else {
        println!(
            "expected seed: {:?}\nfound seed: {:?}",
            expected_seed_data.seed, nonce_info.seed
        );
        false
    }
}

fn partition_number_is_valid(block_header: &ArweaveBlockHeader) -> bool {
    let max = std::cmp::max(
        0,
        block_header.nonce_limiter_info.zone_upper_bound / PARTITION_SIZE - 1,
    );
    block_header.partition_number <= max
}

fn nonce_is_valid(block_header: &ArweaveBlockHeader) -> bool {
    let max = RECALL_RANGE_SIZE / DATA_CHUNK_SIZE;
    let nonce_value = block_header.nonce.0 as u32;
    nonce_value < max
}

fn recall_bytes_is_valid(
    block_header: &ArweaveBlockHeader,
    mining_hash: &[u8; 32],
) -> Result<(U256, Option<U256>)> {
    let (recall_range1_start, recall_range2_start) = get_recall_range(
        mining_hash,
        block_header.partition_number,
        block_header.nonce_limiter_info.zone_upper_bound,
    );

    let recall_byte_1 = recall_range1_start + block_header.nonce.0 * DATA_CHUNK_SIZE as u64;
    let recall_byte_2 = recall_range2_start + block_header.nonce.0 * DATA_CHUNK_SIZE as u64;

    if let Some(b2) = block_header.recall_byte2 {
        if recall_byte_2 == b2 && recall_byte_1 == U256::from(block_header.recall_byte) {
            Ok((recall_byte_1, Some(recall_byte_2)))
        } else {
            Err(eyre!("invalid recall byte 2"))
        }
    } else if recall_byte_1 == U256::from(block_header.recall_byte) {
        Ok((recall_byte_1, None))
    } else {
        Err(eyre!("invalid recall byte 1"))
    }
}

fn poa_is_valid(
    poa_data: &PoaData,
    recall_byte: U256,
    block_index: &BlockIndex<Initialized>,
    reward_addr: &H256,
    randomx_vm: Option<&RandomXVM>,
) -> bool {
    // Use the block_index to look up the BlockStart, BlockEnd, and tx_root
    let block_bounds = block_index.get_block_bounds(recall_byte.as_u128());
    let start = block_bounds.block_start_offset;
    let end = block_bounds.block_end_offset;

    // Test to see if the recall byte chunk index is between the start and end
    // chunk offsets of the block
    if (start..=end).contains(&recall_byte.as_u128()) {
        // println!(
        //     "recall_byte falls within block_bounds {}..{} of block_height: {}",
        //     block_bounds.block_start_offset, block_bounds.block_end_offset, block_bounds.height
        // );
    } else {
        return false;
    }

    //let block_size = block_bounds.block_end_offset - block_bounds.block_start_offset;
    let byte_offset_in_block = get_byte_offset(recall_byte, block_bounds.block_start_offset, block_bounds.block_end_offset);
    // println!(
    //     "tx_root: {:?} target_offset_in_block: {byte_offset_in_block}",
    //     base64_url::encode(&block_bounds.tx_root)
    // );

    // TX_PATH Validation
    // --------------------------------------------------------------
    let tx_path_result = match validate_path(
        block_bounds.tx_root.0,
        &poa_data.tx_path,
        byte_offset_in_block,
    ) {
        Ok(result) => result,
        Err(_) => {
            println!("tx_path is invalid");
            return false;
        }
    };

    // Find the offset of the recall byte relative to a specific TX
    let byte_offset_in_tx = byte_offset_in_block - tx_path_result.left_bound;
    let tx_start = 0;
    let tx_end = tx_path_result.right_bound - tx_path_result.left_bound;
    // println!("tx_start: {tx_start} tx_end: {tx_end} byte offset: {byte_offset_in_tx}");

    // Test to see if the byte falls within the bounds of the tx
    if (tx_start..=tx_end).contains(&byte_offset_in_tx) || (tx_start == 0 && tx_end == 0) {
        // println!("recall_byte falls within tx_bounds {tx_start}..={tx_end}");
    } else {
        return false;
    }

    // DATA_PATH Validation
    // --------------------------------------------------------------
    // The leaf proof in the tx_path is the root of the data_path
    let data_path_result = match validate_path(
        tx_path_result.leaf_hash,
        &poa_data.data_path,
        byte_offset_in_tx,
    ) {
        Ok(result) => result,
        Err(_) => return false,
    };

    // Get the chunk (end) offset
    let chunk_size = (data_path_result.right_bound - data_path_result.left_bound) as usize;
    let chunk_offset =
        block_bounds.block_start_offset + tx_path_result.left_bound + data_path_result.right_bound;

    // println!("leaf_hash: {}, left_bound: {}, right_bound: {}", base64_url::encode(&data_path_result.leaf_hash), data_path_result.left_bound, data_path_result.right_bound);
    // println!("DATA_PATH is valid chunk_size: {chunk_size} target_byte: {byte_offset_in_tx}");

    // Create packed entropy scratchpad for the chunk + reward_address
    // randomx_long_with_entropy.cpp: 51
    let input = get_chunk_entropy_input(chunk_offset.into(), &block_bounds.tx_root, reward_addr);
    let randomx_program_count = RANDOMX_PACKING_ROUNDS_2_6;
    let entropy = compute_entropy(&input, randomx_program_count, randomx_vm);
 

    // Use a feistel cypher + entropy to decrypt the chunk
    // randomx_long_with_entropy.cpp: 113
    let ciphertext = poa_data.chunk.as_slice();
    let decrypted_chunk = feistel_decrypt(ciphertext, &entropy);

    // Because all chunks are packed as DATA_CHUNK_SIZE, if the proof chunk is
    // smaller we need to trim off the excess padding introduced by packing
    let (decrypted_chunk, _) = decrypted_chunk.split_at(chunk_size.min(decrypted_chunk.len()));

    // Hash the decoded chunk to see if it matches the data_path.leaf_hash
    // ar_poa.erl:84  ar_tx:generate_chunk_id(Unpacked)
    let chunk_hash = generate_chunk_id(decrypted_chunk);

    // Check if the decrypted chunk_hash matches the one in the data_path
    chunk_hash == data_path_result.leaf_hash
}

trait DoubleSigningProofBytes {
    fn bytes(&self) -> Vec<u8>;
}

impl DoubleSigningProofBytes for DoubleSigningProof {
    fn bytes(&self) -> Vec<u8> {
        // If no DoubleSigningProof is provided, return a 0 byte
        if self.pub_key.is_none() {
            return vec![0];
        }

        let mut buff: Vec<u8> = Vec::new();

        // If a DoubleSigningProof exists, the first byte should be 1
        buff.extend_raw_buf(1, &[1])
            .extend_optional_raw_buf(64, &self.pub_key)
            .extend_optional_raw_buf(64, &self.sig1)
            .extend_big(2, &self.cdiff1.unwrap_or_default())
            .extend_big(2, &self.prev_cdiff1.unwrap_or_default())
            .extend_raw_buf(8, self.preimage1.unwrap_or_default().as_bytes())
            .extend_optional_raw_buf(64, &self.sig2)
            .extend_big(2, &self.cdiff2.unwrap_or_default())
            .extend_big(2, &self.prev_cdiff2.unwrap_or_default())
            .extend_raw_buf(8, self.preimage2.unwrap_or_default().as_bytes());
        buff
    }
}

/// The extend_raw_* functions do not prepend any kind of size bytes to the
/// bytes they append. The other extend_<type> functions append bigEndian size
/// bytes before appending the bytes of <type>.
trait ExtendBytes {
    fn extend_raw_buf(&mut self, raw_size: usize, val: &[u8]) -> &mut Self;
    fn extend_optional_raw_buf(&mut self, raw_size: usize, val: &Option<Base64>) -> &mut Self;
    fn extend_raw_big(&mut self, raw_size: usize, val: &U256) -> &mut Self;
    fn extend_u64(&mut self, size_bytes: usize, val: &u64) -> &mut Self;
    fn extend_big(&mut self, size_bytes: usize, val: &U256) -> &mut Self;
    fn extend_optional_big(&mut self, size_bytes: usize, val: &Option<U256>) -> &mut Self;
    fn extend_optional_hash(&mut self, size_bytes: usize, val: &Option<H256>) -> &mut Self;
    fn extend_buf(&mut self, size_bytes: usize, val: &[u8]) -> &mut Self;
    fn extend_buf_list(&mut self, size_bytes: usize, val: &[Base64]) -> &mut Self;
    fn extend_hash_list(&mut self, val: &[H256]) -> &mut Self;
    fn trim_leading_zero_bytes(slice: &[u8]) -> &[u8] {
        let mut non_zero_index = slice.iter().position(|&x| x != 0).unwrap_or(slice.len());
        non_zero_index = std::cmp::min(non_zero_index, slice.len() - 1);
        &slice[non_zero_index..]
    }
}

impl ExtendBytes for Vec<u8> {
    /// Extends a Vec<u8> by [raw_size] amount of bytes by copying the last
    /// [raw_size] bytes from [val] and appending them to the Vec<u8>
    fn extend_raw_buf(&mut self, raw_size: usize, val: &[u8]) -> &mut Self {
        let mut bytes = vec![0u8; raw_size];

        // Calculate the start position in 'val' to copy from
        let start = if val.len() > raw_size {
            val.len() - raw_size
        } else {
            0
        };

        // Copy the last 'buf_size' bytes of 'val' into 'bytes'
        let insert = raw_size.saturating_sub(val.len());
        bytes[insert..].copy_from_slice(&val[start..]);

        // Extend 'self' with 'bytes'
        self.extend_from_slice(&bytes);
        self
    }

    fn extend_optional_raw_buf(&mut self, raw_size: usize, val: &Option<Base64>) -> &mut Self {
        let mut bytes: Vec<u8> = Vec::new();
        if let Some(val_bytes) = val {
            bytes.extend_from_slice(val_bytes.as_slice());
        }
        self.extend_raw_buf(raw_size, &bytes)
    }

    fn extend_raw_big(&mut self, raw_size: usize, val: &U256) -> &mut Self {
        let mut bytes = [0u8; 32];
        val.to_big_endian(&mut bytes);
        self.extend_raw_buf(raw_size, &bytes)
    }

    fn extend_u64(&mut self, num_size_bytes: usize, val: &u64) -> &mut Self {
        let bytes = &val.to_be_bytes();
        let bytes = Self::trim_leading_zero_bytes(bytes);
        let num_val_bytes = bytes.len();
        let size_bytes = num_val_bytes.to_be_bytes();
        let start = size_bytes.len().saturating_sub(num_size_bytes);
        self.extend_from_slice(&Vec::from(&size_bytes[start..]));
        self.extend_from_slice(bytes);
        self
    }

    fn extend_big(&mut self, num_size_bytes: usize, val: &U256) -> &mut Self {
        let mut be_bytes = [0u8; 32];
        val.to_big_endian(&mut be_bytes);
        let bytes = Self::trim_leading_zero_bytes(&be_bytes);
        let num_val_bytes = bytes.len();
        let size_bytes = num_val_bytes.to_be_bytes();
        let start = size_bytes.len().saturating_sub(num_size_bytes);
        self.extend_from_slice(&Vec::from(&size_bytes[start..]));
        self.extend_from_slice(bytes);
        self
    }

    fn extend_optional_big(&mut self, size_bytes: usize, val: &Option<U256>) -> &mut Self {
        if let Some(big_int) = val {
            self.extend_big(size_bytes, big_int)
        } else {
            // This will append the correct number of size_bytes to store a size of 0
            self.extend_buf(size_bytes, &[])
        }
    }

    fn extend_buf(&mut self, num_size_bytes: usize, val: &[u8]) -> &mut Self {
        let bytes = val;
        let num_val_bytes = bytes.len();
        let size_bytes = num_val_bytes.to_be_bytes();
        let start = size_bytes.len().saturating_sub(num_size_bytes);
        self.extend_from_slice(&Vec::from(&size_bytes[start..]));
        self.extend_from_slice(bytes);
        self
    }

    fn extend_optional_hash(&mut self, size_bytes: usize, val: &Option<H256>) -> &mut Self {
        let mut bytes: Vec<u8> = Vec::new();
        if let Some(val_bytes) = val {
            bytes.extend_from_slice(&val_bytes[..]);
        }
        self.extend_buf(size_bytes, &bytes)
    }

    fn extend_buf_list(&mut self, size_bytes: usize, data: &[Base64]) -> &mut Self {
        // Number of elements in the list, as 2 bytes
        let num_elements = data.len() as u16;
        self.extend_from_slice(&num_elements.to_be_bytes());
        // Iterate over each element in the data vector
        for elem in data.iter().rev() {
            self.extend_buf(size_bytes, elem.as_slice());
        }
        self
    }

    fn extend_hash_list(&mut self, data: &[H256]) -> &mut Self {
        // Number of hashes in the list, as 2 bytes
        let num_elements = data.len() as u16;
        self.extend_from_slice(&num_elements.to_be_bytes());
        // Iterate over each hash in the data vector and append it
        for elem in data.iter() {
            self.extend_from_slice(elem.as_bytes());
        }
        self
    }
}

fn block_hash_is_valid(block_header: &ArweaveBlockHeader) -> bool {
    let b = block_header;
    let nonce_info = &b.nonce_limiter_info;
    let mut diff_bytes: [u8; 32] = Default::default();
    b.diff.to_big_endian(&mut diff_bytes);

    let proof_bytes = b.double_signing_proof.bytes();

    //let expected: Vec<u8> = vec![];

    let mut buff: Vec<u8> = Vec::new();
    buff.extend_buf(1, b.previous_block.as_bytes())
        .extend_u64(1, &b.timestamp)
        .extend_u64(2, &b.nonce.0)
        .extend_u64(1, &b.height)
        .extend_buf(2, &diff_bytes)
        .extend_big(2, &b.cumulative_diff)
        .extend_u64(1, &b.last_retarget)
        .extend_buf(1, b.hash.as_bytes())
        .extend_u64(2, &b.block_size)
        .extend_u64(2, &b.weave_size)
        .extend_buf(1, b.reward_addr.as_bytes())
        .extend_optional_hash(1, &b.tx_root)
        .extend_buf(1, b.wallet_list.as_bytes())
        .extend_buf(1, b.hash_list_merkle.as_bytes())
        .extend_u64(1, &b.reward_pool)
        .extend_u64(1, &b.packing_2_5_threshold)
        .extend_u64(1, &b.strict_data_split_threshold)
        .extend_u64(1, &b.usd_to_ar_rate[0])
        .extend_u64(1, &b.usd_to_ar_rate[1])
        .extend_u64(1, &b.scheduled_usd_to_ar_rate[0])
        .extend_u64(1, &b.scheduled_usd_to_ar_rate[1])
        .extend_buf_list(2, &b.tags.0)
        .extend_buf_list(1, &b.txs.0)
        .extend_u64(1, &b.reward)
        .extend_u64(2, &b.recall_byte)
        .extend_buf(1, b.hash_preimage.as_bytes())
        .extend_optional_big(2, &b.recall_byte2)
        .extend_buf(2, b.reward_key.as_slice())
        .extend_u64(1, &b.partition_number)
        .extend_raw_buf(32, nonce_info.output.as_bytes())
        .extend_raw_buf(8, &nonce_info.global_step_number.to_be_bytes())
        .extend_raw_buf(48, nonce_info.seed.as_bytes())
        .extend_raw_buf(48, nonce_info.next_seed.as_bytes())
        .extend_raw_buf(32, &nonce_info.zone_upper_bound.to_be_bytes())
        .extend_raw_buf(32, &nonce_info.next_zone_upper_bound.to_be_bytes())
        .extend_buf(1, b.nonce_limiter_info.prev_output.as_bytes())
        .extend_hash_list(&b.nonce_limiter_info.checkpoints.0)
        .extend_hash_list(&b.nonce_limiter_info.last_step_checkpoints.0)
        .extend_buf(1, b.previous_solution_hash.as_bytes())
        .extend_big(1, &b.price_per_gib_minute)
        .extend_big(1, &b.scheduled_price_per_gib_minute)
        .extend_raw_buf(32, b.reward_history_hash.as_bytes())
        .extend_big(1, &b.debt_supply)
        .extend_raw_big(3, &b.kryder_plus_rate_multiplier)
        .extend_raw_big(1, &b.kryder_plus_rate_multiplier_latch)
        .extend_raw_big(3, &b.denomination)
        .extend_u64(1, &b.redenomination_height)
        .extend_raw_buf(proof_bytes.len(), &proof_bytes)
        .extend_big(2, &b.previous_cumulative_diff)
        // Added in 2.7
        .extend_big(2, &b.merkle_rebase_support_threshold)
        .extend_buf(3, b.poa.data_path.as_slice())
        .extend_buf(3, b.poa.tx_path.as_slice())
        .extend_buf(3, b.poa2.data_path.as_slice())
        .extend_buf(3, b.poa2.tx_path.as_slice())
        .extend_raw_buf(32, b.chunk_hash.as_bytes())
        .extend_optional_hash(1, &b.chunk2_hash)
        .extend_raw_buf(32, b.block_time_history_hash.as_bytes())
        .extend_u64(1, &nonce_info.vdf_difficulty.unwrap_or_default())
        .extend_u64(1, &nonce_info.next_vdf_difficulty.unwrap_or_default());

    // if let Some(i) = first_mismatch_index(&expected, &buff) {
    //     println!(
    //         "Found mismatched byte at index: {i} found:{} expected:{}",
    //         buff[i], expected[i]
    //     );
    // }

    let mut hasher = sha::Sha256::new();
    hasher.update(&buff);
    let signed_hash = hasher.finish();

    let mut hasher = sha::Sha384::new();
    hasher.update(&signed_hash);
    hasher.update(b.signature.as_slice());
    let hash = H384::from(hasher.finish());

    hash == b.indep_hash
}

fn is_retarget_height(block_header: &ArweaveBlockHeader) -> bool {
    let height = block_header.height;
    height % RETARGET_BLOCKS == 0 && height != 0
}

/// Utility function for debugging
fn first_mismatch_index(vec1: &[u8], vec2: &[u8]) -> Option<usize> {
    vec1.iter().zip(vec2.iter()).enumerate().find_map(
        |(index, (&val1, &val2))| {
            if val1 != val2 {
                Some(index)
            } else {
                None
            }
        },
    )
}
