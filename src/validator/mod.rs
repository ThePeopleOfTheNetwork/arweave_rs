use self::block::*;
use crate::json_types::ArweaveBlockHeader;
use color_eyre::eyre::Result;
use eyre::Error;
use openssl::sha;

pub mod block;
pub mod hash_index;
pub mod hash_index_scraper;


// %% Test for block @ heght: 1287795

// NonceLimiterOutput = ar_util:decode(<<"58-7eFrG47SCvbmIsV58EHdYCUipNe341iOY5Y9Bes8">>),
// Seed = ar_util:decode(<<"xB4g11TSqOlKxsD5TwDyJw-uZg0bMiuN6OvFhR0DlxvnzLp47WybrpDiVvvBJZJn">>),
// MiningAddr = ar_util:decode(<<"g3Wxbuk6D2_h2nsLmE7G9rMeBxxl6SUdVGIzHem367Y">>),
// PartitionNumber = 11,
// HashPreimage = ar_util:decode(<<"UbRrrD539-opWa-FrwmkJ0x9GFzlUdKZ_M6b6rt-m5I">>),
// Diff = 115792089185377794820130381954655266142541246457170336309536530892857600224272,

// Test = << NonceLimiterOutput:32/binary,PartitionNumber:256, Seed:32/binary, MiningAddr/binary >>,

// H0 = ar_block:compute_h0(Output, PartitionNumber, Seed, MiningAddr),

// SolutionHash = ar_block:compute_solution_h(H0, HashPreimage),

// binary:decode_unsigned(SolutionHash, big) > Diff

// Schedulers = erlang:system_info(dirty_cpu_schedulers_online),
// PackingStateRef = ar_mine_randomx:init_fast(?RANDOMX_PACKING_KEY, Schedulers),
// {ok, H00} = hash_fast_nif(PackingStateRef, Test, 0,0,0),
// io:format("H00: ~p~n", [H00]),



pub fn pre_validate_block(block_header: &ArweaveBlockHeader) -> Result<[u8; 32]> {
    let nonce_limiter_info = &block_header.nonce_limiter_info;
    let vdf_seed: [u8; 48] = nonce_limiter_info.seed;
    let vdf_output: [u8; 32] = nonce_limiter_info.output;
    let mining_address: [u8; 32] = block_header.reward_addr;
    let partition_number: u32 = block_header.partition_number as u32;

    let mining_hash = compute_mining_hash(vdf_output, partition_number, vdf_seed, mining_address);

    let mining_hash2 = compute_mining_hash_test(vdf_output, partition_number, vdf_seed, mining_address);

    println!("");
    println!("H0:{mining_hash:?}");
    println!("H0:{mining_hash2:?}");

    // TODO: Possibly do this inside compute_mining_hash
    let hash_array = mining_hash
        .try_into()
        .map_err(|e| Error::msg("Couldn't map mining_hash to 32 byte array"))?;

    Ok(hash_array)
}

pub fn compute_block_hash(mining_hash: &[u8; 32], chunk_preimage: &[u8]) -> [u8; 32] {
    let mut hasher = sha::Sha256::new();
    hasher.update(mining_hash);
    hasher.update(chunk_preimage);
    hasher.finish().into()
}
