use self::block::*;
use crate::{
    helpers::{consensus::*, U256},
    json_types::{ArweaveBlockHeader, PoaData, DoubleSigningProof},
};
use color_eyre::eyre::{eyre, Result};
use openssl::sha;

pub mod block;
pub mod hash_index;
pub mod hash_index_scraper;

// The original plan was to cap the proof at 262144 (also the maximum chunk size).
// The maximum tree depth is then (262144 - 64) / (32 + 32 + 32) = 2730.
// Later we added support for offset rebases by recognizing the extra 32 bytes,
// possibly at every branching point, as indicating a rebase. To preserve the depth maximum,
// we now cap the size at 2730 * (96 + 32) + 65 = 349504.
const MAX_DATA_PATH_SIZE: usize = 349504;

// We may have at most 1000 transactions + 1000 padding nodes => depth=11
// => at most 11 * 96 + 64 bytes worth of the proof. Due to its small size, we
// extend it somewhat for better future-compatibility.
const MAX_TX_PATH_SIZE: usize = 2176;

// Maximum size of a single data chunk, in bytes.
const DATA_CHUNK_SIZE: usize = 256 * 1024;

pub fn pre_validate_block(
    block_header: &ArweaveBlockHeader,
    previous_block_header: &ArweaveBlockHeader,
) -> Result<[u8; 32]> {
    let nonce_limiter_info = &block_header.nonce_limiter_info;
    let previous_nonce_limiter_info = &previous_block_header.nonce_limiter_info;
    let vdf_seed: [u8; 48] = previous_nonce_limiter_info.seed;
    let vdf_output: [u8; 32] = nonce_limiter_info.output;
    let mining_address: [u8; 32] = block_header.reward_addr;
    let partition_number: u32 = block_header.partition_number as u32;

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
    if !chunk_hash_is_valid(&block_header.chunk_hash, &chunk, block_height) {
        return Err(eyre!("chunk_hash does not match poa.chunk"));
    }

    // Validate chunk2_hash to see that it matches the poa2 chunk if present
    if block_header.chunk2_hash.is_some() {
        let chunk = &block_header.poa2.chunk;
        let chunk2_hash = block_header.chunk2_hash.unwrap_or_default();
        if !chunk_hash_is_valid(&chunk2_hash, &chunk, block_height) {
            return Err(eyre!("chunk2_hash does not match poa2.chunk"));
        }
    }

    // =========================================================================
    // Arweave General checks
    // =========================================================================

    // Compute the block_hash and validate it against the `indep_hash` header
    if !block_hash_is_valid(block_header) {
        return Err(eyre!("indep_hash does not match calculated block_has"));
    }

    // Validate timestamp - !only needed when validating new blocks!

    // Validate existing Solution hash - check to see if this solution has 
    // been validated and possibly report a double signing

    // Validate VDF step is within range of current - !only for new blocks!

    // Validate previous Solution - does the previous blocks hash match the
    // current blocks - previous_solution_hash

    // Validate last re-target

    // Validate difficulty

    // Validate cumulative difficulty

    // Validate nonce limiter info

    // Validate PoW with the mining_hash
    let mining_hash = compute_mining_hash(vdf_output, partition_number, vdf_seed, mining_address);

    // Now combine H0 with the preimage to create the solution_hash
    let hash_preimage = block_header.hash_preimage;
    let solution_hash = compute_solution_hash(&mining_hash, &hash_preimage);

    Ok(solution_hash)
}

pub fn compute_solution_hash(mining_hash: &[u8; 32], hash_preimage: &[u8]) -> [u8; 32] {
    let mut hasher = sha::Sha256::new();
    hasher.update(mining_hash);
    hasher.update(hash_preimage);
    hasher.finish().into()
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
        && chunk.len() <= DATA_CHUNK_SIZE
}

fn chunk_hash_is_valid(chunk_hash: &[u8; 32], chunk: &Vec<u8>, block_height: u64) -> bool {
    if block_height < FORK_2_7_HEIGHT {
        return true;
    }

    let mut hasher = sha::Sha256::new();
    hasher.update(chunk);
    let hash = hasher.finish();
    hash == *chunk_hash
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
            .extend_big(2,&self.cdiff1.unwrap_or_default())
            .extend_big(2, &self.prev_cdiff1.unwrap_or_default())
            .extend_raw_buf(8, &self.preimage1.unwrap_or_default())
            .extend_optional_raw_buf(64, &self.sig2)
            .extend_big(2,&self.cdiff2.unwrap_or_default())
            .extend_big(2, &self.prev_cdiff2.unwrap_or_default())
            .extend_raw_buf(8, &self.preimage2.unwrap_or_default())   
        ;
        buff
    }
}

trait ExtendBytes {
    fn extend_raw_buf(&mut self, raw_size: usize, val: &[u8]) -> &mut Self;
    fn extend_optional_raw_buf(&mut self, raw_size: usize, val: &Option<Vec<u8>>) -> &mut Self;
    fn extend_raw_big(&mut self, raw_size: usize, val: &U256) -> &mut Self;
    fn extend_u64(&mut self, size_bytes: usize, val: &u64) -> &mut Self;
    fn extend_big(&mut self, size_bytes: usize, val: &U256) -> &mut Self;
    fn extend_optional_big(&mut self, size_bytes: usize, val: &Option<U256>) -> &mut Self;
    fn extend_optional_hash(&mut self, size_bytes: usize, val: &Option<[u8;32]>) -> &mut Self;
    fn extend_buf(&mut self, size_bytes: usize, val: &[u8]) -> &mut Self;
    fn extend_buf_list(&mut self, size_bytes: usize, val: &Vec<Vec<u8>>) -> &mut Self;
    fn extend_hash_list(&mut self, val: &Vec<[u8; 32]>) -> &mut Self;
    fn trim_leading_zero_bytes(slice: &[u8]) -> &[u8] {
        let mut non_zero_index = slice
            .iter()
            .position(|&x| x != 0)
            .unwrap_or_else(|| slice.len());
        non_zero_index = std::cmp::min(non_zero_index, slice.len()-1);
        &slice[non_zero_index..]
    }
}

impl ExtendBytes for Vec<u8> {
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

    fn extend_optional_raw_buf(&mut self, raw_size: usize, val: &Option<Vec<u8>>) -> &mut Self {
        let mut bytes:Vec<u8> = Vec::new();
        if let Some(val_bytes) = val {
            bytes.extend_from_slice(&val_bytes[..]);
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
        self.extend_from_slice(&bytes[..]);
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
        self.extend_from_slice(&bytes[..]);
        self
    }

    fn extend_optional_big(&mut self, size_bytes: usize, val: &Option<U256>) -> &mut Self {
        if let Some(u256) = val {
            self.extend_big(size_bytes, &u256)
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
        self.extend_from_slice(&bytes[..]);
        self
    }

    fn extend_optional_hash(&mut self, size_bytes: usize, val: &Option<[u8;32]>) -> &mut Self {
        let mut bytes:Vec<u8> = Vec::new();
        if let Some(val_bytes) = val {
            bytes.extend_from_slice(&val_bytes[..]);
        }
        self.extend_buf(size_bytes, &bytes)
    }

    fn extend_buf_list(&mut self, size_bytes: usize, data: &Vec<Vec<u8>>) -> &mut Self {
        // Number of elements in the list, as 2 bytes
        let num_elements = data.len() as u16;
        self.extend_from_slice(&num_elements.to_be_bytes());
        // Iterate over each element in the data vector
        for elem in data.iter().rev() {
            self.extend_buf(size_bytes, elem);
        }
        self
    }

    fn extend_hash_list(&mut self, data: &Vec<[u8; 32]>) -> &mut Self {
        // Number of hashes in the list, as 2 bytes
        let num_elements = data.len() as u16;
        self.extend_from_slice(&num_elements.to_be_bytes());
        // Iterate over each hash in the data vector and append it
        for elem in data.iter() {
            self.extend_from_slice(elem);
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

    let mut buff: Vec<u8> = Vec::new();
    buff.extend_buf(1, &b.previous_block)
        .extend_u64(1, &b.timestamp)
        .extend_buf(2, &b.nonce)
        .extend_u64(1, &b.height)
        .extend_buf(2, &diff_bytes)
        .extend_big(2, &b.cumulative_diff)
        .extend_u64(1, &b.last_retarget)
        .extend_buf(1, &b.hash)
        .extend_u64(2, &b.block_size)
        .extend_u64(2, &b.weave_size)
        .extend_buf(1, &b.reward_addr)
        .extend_buf(1, &b.tx_root)
        .extend_buf(1, &b.wallet_list)
        .extend_buf(1, &b.hash_list_merkle)
        .extend_u64(1, &b.reward_pool)
        .extend_u64(1, &b.packing_2_5_threshold)
        .extend_u64(1, &b.strict_data_split_threshold)
        .extend_u64(1, &b.usd_to_ar_rate[0])
        .extend_u64(1, &b.usd_to_ar_rate[1])
        .extend_u64(1, &b.scheduled_usd_to_ar_rate[0])
        .extend_u64(1, &b.scheduled_usd_to_ar_rate[1])
        .extend_buf_list(2, &b.tags)
        .extend_buf_list(1, &b.txs)
        .extend_u64(1, &b.reward)
        .extend_u64(2, &b.recall_byte)
        .extend_buf(1, &b.hash_preimage)
        .extend_optional_big(2, &b.recall_byte2)
        .extend_buf(2, &b.reward_key)
        .extend_u64(1, &b.partition_number)
        .extend_raw_buf(32, &nonce_info.output)
        .extend_raw_buf(8, &nonce_info.global_step_number.to_be_bytes())
        .extend_raw_buf(48, &nonce_info.seed)
        .extend_raw_buf(48, &nonce_info.next_seed)
        .extend_raw_buf(32, &nonce_info.zone_upper_bound.to_be_bytes())
        .extend_raw_buf(32, &nonce_info.next_zone_upper_bound.to_be_bytes())
        .extend_buf(1, &b.nonce_limiter_info.prev_output)
        .extend_hash_list(&b.nonce_limiter_info.checkpoints)
        .extend_hash_list(&b.nonce_limiter_info.last_step_checkpoints)
        .extend_buf(1, &b.previous_solution_hash)
        .extend_big(1, &b.price_per_gib_minute)
        .extend_big(1, &b.scheduled_price_per_gib_minute)
        .extend_raw_buf(32, &b.reward_history_hash)
        .extend_big(1, &b.debt_supply)
        .extend_raw_big(3, &b.kryder_plus_rate_multiplier)
        .extend_raw_big(1, &b.kryder_plus_rate_multiplier_latch)
        .extend_raw_big(3, &b.denomination)
        .extend_u64(1,&b.redenomination_height)
        .extend_raw_buf(proof_bytes.len(), &proof_bytes)
        .extend_big(2, &b.previous_cumulative_diff)
        // Added in 2.7
        .extend_big(2, &b.merkle_rebase_support_threshold)
        .extend_buf(3, &b.poa.data_path)
        .extend_buf(3, &b.poa.tx_path)
        .extend_buf(3, &b.poa2.data_path)
        .extend_buf(3, &b.poa2.tx_path)
        .extend_raw_buf(32, &b.chunk_hash)
        .extend_optional_hash(1, &b.chunk2_hash)
        .extend_raw_buf(32, &b.block_time_history_hash)
        .extend_u64(1, &nonce_info.vdf_difficulty.unwrap_or_default())
        .extend_u64(1, &nonce_info.next_vdf_difficulty.unwrap_or_default());

    let mut hasher = sha::Sha256::new();
    hasher.update(&buff);
    let signed_hash = hasher.finish();

    let mut hasher = sha::Sha384::new();
    hasher.update(&signed_hash);
    hasher.update(&b.signature);
    let hash = hasher.finish();

    println!("\ntest_hash: {}\nindp_hash: {}", base64_url::encode(&hash), base64_url::encode(&b.indep_hash));

    hash == b.indep_hash
}
