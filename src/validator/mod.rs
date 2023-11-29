use self::block::*;
use crate::{
    helpers::consensus::*,
    json_types::{ArweaveBlockHeader, PoaData},
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
    let chunk = block_header
        .poa
        .chunk
        .as_ref()
        .expect("poa.chunk should exist");
    if !chunk_hash_is_valid(&block_header.chunk_hash, &chunk, block_height) {
        return Err(eyre!("chunk_hash does not match poa.chunk"));
    }

    // Validate chunk2_hash to see that it matches the poa2 chunk if present
    if block_header.chunk2_hash.is_some() {
        let chunk = block_header
            .poa2
            .chunk
            .as_ref()
            .expect("poa2.chunk should exist");
        let chunk2_hash = block_header.chunk2_hash.unwrap_or_default();
        if !chunk_hash_is_valid(&chunk2_hash, &chunk, block_height) {
            return Err(eyre!("chunk2_hash does not match poa2.chunk"));
        }
    }

    // =========================================================================
    // Arweave General checks
    // =========================================================================

    // Compute the block_hash and validate the signature

    // Validate timestamp

    // Validate Solution hash

    // Validate VDF step is within range of current

    // Validate previous Solution

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

    let tx_path = poa_data.tx_path.as_deref().unwrap_or_default();
    let data_path = poa_data.data_path.as_deref().unwrap_or_default();
    let chunk = poa_data.chunk.as_deref().unwrap_or_default();

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

trait LastBytes {
    fn last_2_bytes(&self) -> &[u8];
    fn last_byte(&self) -> u8;
}

impl LastBytes for [u8] {
    fn last_2_bytes(&self) -> &[u8] {
        let byte_count = 2;
        let start = if byte_count > self.len() {
            0
        } else {
            self.len() - byte_count
        };
        &self[start..]
    }

    fn last_byte(&self) -> u8 {
        let byte_count = 1;
        let start = if byte_count > self.len() {
            0
        } else {
            self.len() - byte_count
        };
        self[start..][0]
    }
}
// trait En

trait EncodeBytes {
    fn encode_u64_1(&mut self, val: u64) -> &mut Self;
    fn encode_u64_2(&mut self, val: u64) -> &mut Self;
    fn encode_buf_1(&mut self, val: &[u8]) -> &mut Self;
    fn encode_buf_2(&mut self, val: &[u8]) -> &mut Self;
    fn encode_buf_list_1(&mut self, val:&Vec<Vec<u8>>) -> &mut Self;
    fn encode_buf_list_2(&mut self, val:&Vec<Vec<u8>>) -> &mut Self;
    fn encode_raw_u64_8(&mut self, val: u64) -> &mut Self;
    fn encode_raw_u64_32(&mut self, val: u64) -> &mut Self;
    fn encode_raw_hash(&mut self, val: &[u8]) -> &mut Self;
}

impl EncodeBytes for Vec<u8> {
    /// Encode u64 with a 1 byte size prefix
    fn encode_u64_1(&mut self, val: u64) -> &mut Self {
        let bytes = val.to_be_bytes();
        let size = bytes.len();
        let mut size_bytes = Vec::from(&size.to_be_bytes()[size - 1..]);
        self.append(&mut size_bytes);
        self.extend_from_slice(&bytes[..]);
        self
    }

    /// Encode u64 with a 1 byte size prefix
    fn encode_u64_2(&mut self, val: u64) -> &mut Self {
        let bytes = val.to_be_bytes();
        let size = bytes.len();
        let mut size_bytes = Vec::from(&size.to_be_bytes()[size - 2..]);
        self.append(&mut size_bytes);
        self.extend_from_slice(&bytes[..]);
        self
    }

    /// Encode a byte array with a 1 byte size prefix
    fn encode_buf_1(&mut self, bytes: &[u8]) -> &mut Self {
        let size = bytes.len();
        let mut size_bytes = Vec::from(&size.to_be_bytes()[size - 1..]);
        self.append(&mut size_bytes);
        self.extend_from_slice(&bytes[..]);
        self
    }

    /// Encode a byte array with a 2 byte size prefix
    fn encode_buf_2(&mut self, bytes: &[u8]) -> &mut Self {
        let size = bytes.len();
        let mut size_bytes = Vec::from(&size.to_be_bytes()[size - 2..]);
        self.append(&mut size_bytes);
        self.extend_from_slice(&bytes[..]);
        self
    }

    /// Encode a list of byte arrays with a ONE byte size prefix on each element
    /// and a 2 byte count prefix for the encoded list of elements.
    fn encode_buf_list_1(&mut self, data: &Vec<Vec<u8>>)  -> &mut Self {
        // Number of elements in the list, as 2 bytes
        let num_elements = data.len() as u16;
        self.extend_from_slice(&num_elements.to_be_bytes());
        // Iterate over each element in the data vector
        for elem in data {
            self.encode_buf_1(elem);
        }
        self
    }

    /// Encode a list of byte arrays with a TWO byte size prefix on each element
    /// and a 2 byte count prefix for the encoded list of elements.
    fn encode_buf_list_2(&mut self, data: &Vec<Vec<u8>>)  -> &mut Self {
        // Number of elements in the list, as 2 bytes
        let num_elements = data.len() as u16;
        self.extend_from_slice(&num_elements.to_be_bytes());
        // Iterate over each element in the data vector
        for elem in data {
            self.encode_buf_2(elem);
        }
        self
    }

    fn encode_raw_u64_8(&mut self, val: u64) -> &mut Self {
        self.extend_from_slice(&val.to_be_bytes()[..]);
        self
    }
    fn encode_raw_u64_32(&mut self, val: u64) -> &mut Self {
        let mut bytes = [0u8; 32]; 
        // Copy the big-endian bytes of val into the last 8 bytes of the array
        bytes[24..32].copy_from_slice(&val.to_be_bytes()); 
        self.extend_from_slice(&bytes); 
        self
    }
    fn encode_raw_hash(&mut self, val: &[u8]) -> &mut Self {
        self.extend_from_slice(&val[..]);
        self
    }
}

fn compute_block_hash(block_header: &ArweaveBlockHeader) -> [u8; 32] {
    let b = block_header;
    let mut diff_bytes: [u8; 32] = Default::default();
    b.diff.to_big_endian(&mut diff_bytes);

    let mut buff: Vec<u8> = Vec::new();
    buff.encode_buf_1(&b.previous_block)
        .encode_u64_1(b.timestamp)
        .encode_buf_1(&b.nonce)
        .encode_u64_1(b.height)
        .encode_buf_2(&diff_bytes)
        .encode_u64_2(b.cumulative_diff)
        .encode_u64_1(b.last_retarget)
        .encode_buf_1(&b.hash)
        .encode_u64_2(b.block_size)
        .encode_u64_2(b.weave_size)
        .encode_buf_1(&b.reward_addr)
        .encode_buf_1(&b.tx_root)
        .encode_buf_1(&b.wallet_list)
        .encode_buf_1(&b.hash_list_merkle)
        .encode_u64_1(b.reward_pool)
        .encode_u64_1(b.packing_2_5_threshold)
        .encode_u64_1(b.usd_to_ar_rate[0])
        .encode_u64_1(b.usd_to_ar_rate[1])
        .encode_u64_1(b.scheduled_usd_to_ar_rate[0])
        .encode_u64_1(b.scheduled_usd_to_ar_rate[1])
        .encode_buf_list_2(&b.tags)
        .encode_buf_list_1(&b.txs)
        .encode_u64_1(b.reward)
        .encode_u64_2(b.recall_byte)
        .encode_buf_1(&b.hash_preimage)
        .encode_u64_2(b.recall_byte2.unwrap_or(0))
        .encode_buf_2(&b.reward_key)
        .encode_u64_1(b.partition_number)
        .encode_raw_hash(&b.nonce_limiter_info.output)
        .encode_raw_u64_8(b.nonce_limiter_info.global_step_number)
        .encode_raw_hash(&b.nonce_limiter_info.seed)
        .encode_raw_hash(&b.nonce_limiter_info.next_seed)
        .encode_raw_u64_32(b.nonce_limiter_info.zone_upper_bound)
        .encode_raw_u64_32(b.nonce_limiter_info.next_zone_upper_bound)
        .encode_buf_1(&b.nonce_limiter_info.prev_output);

    let mut hasher = sha::Sha256::new();
    hasher.update(&buff);
    hasher.finish()
}

fn encode_txs_list(data: &Vec<[u8; 32]>) -> Vec<u8> {
    let mut buffer = Vec::new();

    // Number of elements in the list, as 2 bytes
    let num_elements = data.len() as u16;
    buffer.extend_from_slice(&num_elements.to_be_bytes());

    // Iterate over each element in the data vector
    for elem in data {
        buffer.encode_buf_1(elem);
    }

    buffer
}

fn encode_tags_list(data: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut buffer = Vec::new();

    // Number of elements in the list, as 2 bytes
    let num_elements = data.len() as u16;
    buffer.extend_from_slice(&num_elements.to_be_bytes());

    // Iterate over each element in the data vector
    for elem in data {
        // Size of the element, in 2 bytes
        let element_size = elem.len() as u16; // Each element is less than 65,535 bytes in size
        buffer.extend_from_slice(&element_size.to_be_bytes());

        // Element's bytes
        buffer.extend_from_slice(elem);
    }

    buffer
}

fn encode_optional_u64(value: Option<u64>) -> [u8; 8] {
    match value {
        Some(v) => v.to_be_bytes(),
        None => 0u64.to_be_bytes(),
    }
}
