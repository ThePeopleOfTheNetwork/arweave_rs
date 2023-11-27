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
    let chunk = block_header.poa.chunk.as_ref().expect("poa.chunk should exist");
    if !chunk_hash_is_valid(&block_header.chunk_hash, &chunk, block_height) {
        return Err(eyre!("chunk_hash does not match poa.chunk"))
    }

    // Validate chunk2_hash to see that it matches the poa2 chunk if present
    if block_header.chunk2_hash.is_some() {
        let chunk = block_header.poa2.chunk.as_ref().expect("poa2.chunk should exist");
        let chunk2_hash = block_header.chunk2_hash.unwrap_or_default();
        if !chunk_hash_is_valid(&chunk2_hash, &chunk, block_height) {
            return Err(eyre!("chunk2_hash does not match poa2.chunk"))
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

fn chunk_hash_is_valid(chunk_hash: &[u8;32], chunk: &Vec<u8>, block_height: u64) -> bool {
    if block_height < FORK_2_7_HEIGHT {
        return true;
    }

    let mut hasher = sha::Sha256::new();
    hasher.update(chunk);
    let hash = hasher.finish();
    hash == *chunk_hash
}

// %% The elements must be either fixed-size or separated by the size separators (
// %% the ar_serialize:encode_* functions).
// Segment = << (encode_bin(PrevH, 8))/binary, (encode_int(TS, 8))/binary,
//         (encode_bin(Nonce2, 16))/binary, (encode_int(Height, 8))/binary,
//         (encode_int(Diff, 16))/binary, (encode_int(CDiff, 16))/binary,
//         (encode_int(LastRetarget, 8))/binary, (encode_bin(Hash, 8))/binary,
//         (encode_int(BlockSize, 16))/binary, (encode_int(WeaveSize, 16))/binary,
//         (encode_bin(Addr2, 8))/binary, (encode_bin(TXRoot, 8))/binary,
//         (encode_bin(WalletList, 8))/binary,
//         (encode_bin(HashListMerkle, 8))/binary, (encode_int(RewardPool, 8))/binary,
//         (encode_int(Packing_2_5_Threshold, 8))/binary,
//         (encode_int(StrictChunkThreshold, 8))/binary,
//                 (encode_int(RateDividend, 8))/binary,
//         (encode_int(RateDivisor, 8))/binary,
//                 (encode_int(ScheduledRateDividend, 8))/binary,
//         (encode_int(ScheduledRateDivisor, 8))/binary,
//         (encode_bin_list(Tags, 16, 16))/binary,
//         (encode_bin_list([GetTXID(TX) || TX <- TXs], 16, 8))/binary,
//         (encode_int(Reward, 8))/binary,
//         (encode_int(RecallByte, 16))/binary, (encode_bin(HashPreimage, 8))/binary,
//         (encode_int(RecallByte2, 16))/binary, (encode_bin(RewardKey2, 16))/binary,
//         (encode_int(PartitionNumber, 8))/binary, Output:32/binary, N:64,
//         Seed:48/binary, NextSeed:48/binary, PartitionUpperBound:256,
//         NextPartitionUpperBound:256, (encode_bin(PrevOutput, 8))/binary,
//         (length(Steps)):16, (iolist_to_binary(Steps))/binary,
//         (length(LastStepCheckpoints)):16, (iolist_to_binary(LastStepCheckpoints))/binary,
//         (encode_bin(PreviousSolutionHash, 8))/binary,
//         (encode_int(PricePerGiBMinute, 8))/binary,
//         (encode_int(ScheduledPricePerGiBMinute, 8))/binary,
//         RewardHistoryHash:32/binary, (encode_int(DebtSupply, 8))/binary,
//         KryderPlusRateMultiplier:24, KryderPlusRateMultiplierLatch:8, Denomination:24,
//         (encode_int(RedenominationHeight, 8))/binary,
//         (ar_serialize:encode_double_signing_proof(DoubleSigningProof))/binary,
//         (encode_int(PrevCDiff, 16))/binary, RebaseThresholdBin/binary,
//         DataPathBin/binary, TXPathBin/binary, DataPath2Bin/binary, TXPath2Bin/binary,
//         ChunkHashBin/binary, Chunk2HashBin/binary, BlockTimeHistoryHashBin/binary,
//         VDFDifficultyBin/binary, NextVDFDifficultyBin/binary >>,
// crypto:hash(sha256, Segment).


// let mut input = Vec::new();

//     input.append(&mut vdf_output.to_vec());

//     let pn:U256 = U256::from(partition_number);

//     let mut partition_bytes: [u8; 32] = [0u8; 32];
//     pn.to_big_endian(&mut partition_bytes);
//     input.append(&mut partition_bytes.try_into().unwrap());

//     input.append(&mut vdf_seed[..32].to_vec()); // Use first 32 bytes of vdf_seed

//     input.append(&mut mining_address.to_vec());


fn compute_block_hash(block_header: &ArweaveBlockHeader) -> [u8; 32] {

    let b = block_header;
    let mut diff_bytes:[u8;32] = Default::default();
    b.diff.to_big_endian(&mut diff_bytes);

    let mut buf:Vec<u8> = Vec::new();
    buf.push(b.previous_block[0]);
    buf.push(b.timestamp.to_be_bytes()[0]);
    buf.push(b.nonce[0]);
    buf.push(b.height.to_be_bytes()[0]);
    buf.extend_from_slice(&diff_bytes[0..=1]);
    buf.extend_from_slice(&b.cumulative_diff.to_be_bytes()[0..=1]);
    buf.push(b.last_retarget.to_be_bytes()[0]);
    buf.push(b.hash[0]);
    buf.extend_from_slice(&b.block_size.to_be_bytes()[0..=1]);
    buf.extend_from_slice(&b.weave_size.to_be_bytes()[0..=1]);

    let mut hasher = sha::Sha256::new();
    hasher.update(&buf);
    hasher.finish()
}