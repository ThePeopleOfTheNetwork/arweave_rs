#![allow(dead_code)]
#![allow(unused_imports)]
use arweave_randomx_rs::{create_randomx_vm, RandomXMode};
use arweave_rs::validator::block;
use arweave_rs::validator::hash_index::Initialized;
use eyre::Result;
use helpers::{DecodeHash, u256};
use json_types::{ArweaveBlockHeader, NonceLimiterInfo};
use lazy_static::lazy_static;
use openssl::hash;
use packing::pack::pack_chunk;
use paris::Logger;
use std::fs::File;
use std::io::Read;
use std::time::Instant;
use validator::block::{compute_randomx_hash, compute_randomx_hash_with_entropy};
use validator::hash_index::HashIndex;
use validator::hash_index_scraper::request_hash_index_jsons;
use validator::{compute_solution_hash, pre_validate_block};
use vdf::verify::*;

use crate::validator::hash_index_scraper::current_block_height;

mod helpers;
mod json_types;
mod packing;
mod validator;
mod vdf;

#[derive(Default, Clone)]
struct TestContext {
    pub base_case: Vec<NonceLimiterInfo>,
    pub reset_case: Vec<NonceLimiterInfo>,
    pub reset_first_case: Vec<NonceLimiterInfo>,
    pub reset_last_case: Vec<NonceLimiterInfo>,
    pub reset_2nd_to_last_case: Vec<NonceLimiterInfo>,
    pub reset_3rd_to_last_case: Vec<NonceLimiterInfo>,
    pub packing_case: (ArweaveBlockHeader, ArweaveBlockHeader),
    pub poa2_case: (ArweaveBlockHeader, ArweaveBlockHeader),
    pub no_tx_case: (ArweaveBlockHeader, ArweaveBlockHeader),
    pub diff_case: (ArweaveBlockHeader, ArweaveBlockHeader),
    pub block1_case: (ArweaveBlockHeader, ArweaveBlockHeader),
    pub block2_case: (ArweaveBlockHeader, ArweaveBlockHeader),
    pub block3_case: (ArweaveBlockHeader, ArweaveBlockHeader),
    pub reset_case2: (ArweaveBlockHeader, ArweaveBlockHeader),
    pub max_nonce_case: (ArweaveBlockHeader, ArweaveBlockHeader),
    pub poa_failed_case:  (ArweaveBlockHeader, ArweaveBlockHeader),
    pub bad_tx_path_case:  (ArweaveBlockHeader, ArweaveBlockHeader),
}

// Static test data for the tests, lazy loaded at runtime.
lazy_static! {
    static ref TEST_DATA: TestContext = {
        // Load the test NonceLimiterInfo
        let base1 = parse_nonce_limiter_info_from_file("data/1278893_no_reset.json");
        let base2 = parse_nonce_limiter_info_from_file("data/1278894_no_reset.json");

        let reset1 = parse_nonce_limiter_info_from_file("data/1278899_reset.json");
        let reset2 = parse_nonce_limiter_info_from_file("data/1278900_reset.json");

        let reset_first1 = parse_nonce_limiter_info_from_file("data/1132455_reset_first_step.json");

        let reset_last1 = parse_nonce_limiter_info_from_file("data/1276407_reset_last_step.json");
        let reset_last2 = parse_nonce_limiter_info_from_file("data/1276408_reset_last_step.json");

        let reset_2nd_to_last1 = parse_nonce_limiter_info_from_file("data/1277324_reset_2nd_to_last_step.json");

        let reset_3rd_to_last1 = parse_nonce_limiter_info_from_file("data/1276736_reset_3rd_to_last_step.json");

        let packing_case = parse_block_header_from_file("data/blocks/1287795.json");
        let packing_case_prev = parse_block_header_from_file("data/blocks/1287794.json");

        let poa2_case = parse_block_header_from_file("data/blocks/1315909.json");
        let poa2_case_prev = parse_block_header_from_file("data/blocks/1315908.json");

        let no_tx_case = parse_block_header_from_file("data/blocks/1315910.json");
        let no_tx_case_prev = parse_block_header_from_file("data/blocks/1315909.json");

        let diff_case = parse_block_header_from_file("data/blocks/1315850.json");
        let diff_case_prev = parse_block_header_from_file("data/blocks/1315849.json");

        let block1_case = parse_block_header_from_file("data/blocks/1309131.json");
        let block1_case_prev = parse_block_header_from_file("data/blocks/1309130.json");

        let block2_case = parse_block_header_from_file("data/blocks/1309645.json");
        let block2_case_prev = parse_block_header_from_file("data/blocks/1309644.json");

        let block3_case = parse_block_header_from_file("data/blocks/1309705.json");
        let block3_case_prev = parse_block_header_from_file("data/blocks/1309704.json");

        let reset_case2 = parse_block_header_from_file("data/blocks/1325673.json");
        let reset_case2_prev = parse_block_header_from_file("data/blocks/1325672.json");

        let max_nonce_case = parse_block_header_from_file("data/blocks/1337235.json");
        let max_nonce_case_prev = parse_block_header_from_file("data/blocks/1337234.json");

        let poa_failed_case = parse_block_header_from_file("data/blocks/1338015.json");
        let poa_failed_case_prev = parse_block_header_from_file("data/blocks/1338014.json");

        let bad_tx_path_case = parse_block_header_from_file("data/blocks/1338549.json");
        let bad_tx_path_case_prev = parse_block_header_from_file("data/blocks/1338548.json");

        let tc:TestContext = TestContext {
            base_case: vec![base1, base2],
            reset_case: vec![reset1, reset2],
            reset_first_case: vec![reset_first1],
            reset_last_case: vec![reset_last1, reset_last2],
            reset_2nd_to_last_case: vec![reset_2nd_to_last1],
            reset_3rd_to_last_case: vec![reset_3rd_to_last1],
            packing_case: (packing_case, packing_case_prev),
            poa2_case: (poa2_case, poa2_case_prev),
            no_tx_case: (no_tx_case, no_tx_case_prev),
            diff_case: (diff_case, diff_case_prev),
            block1_case: (block1_case, block1_case_prev),
            block2_case: (block2_case, block2_case_prev),
            block3_case: (block3_case, block3_case_prev),
            reset_case2: (reset_case2, reset_case2_prev),
            max_nonce_case: (max_nonce_case, max_nonce_case_prev),
            poa_failed_case: (poa_failed_case, poa_failed_case_prev),
            bad_tx_path_case: (bad_tx_path_case, bad_tx_path_case_prev)
        };
        tc
    };
}

/// Helper method for loading tests block info from disk
fn parse_nonce_limiter_info_from_file(file_path: &str) -> NonceLimiterInfo {
    let mut file = File::open(file_path).expect("the file to exist");
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .expect("the file to be readable");
    serde_json::from_str(&buf).expect("valid json for NonceLimiterInput")
}

fn parse_block_header_from_file(file_path: &str) -> ArweaveBlockHeader {
    let mut file = File::open(file_path).expect("the file to exist");
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .expect("the file to be readable");
    serde_json::from_str(&buf).expect("valid json for ArweaveBlockHeader")
}

fn parse_encoded_bytes_from_file(file_path: &str) -> Vec<u8> {
    let mut file = File::open(file_path).expect("the file to exist");
    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .expect("the file to be readable");
    base64_url::decode(&buf).unwrap()
}

/// Utility function fo executing a test, timing it, and logging results
fn run_test(func: fn() -> bool, test_name: &str, logger: &mut Logger) {
    logger.loading(format!("{test_name}..."));
    let start = Instant::now();
    let is_passed = func();
    let duration = start.elapsed();
    if is_passed {
        logger.success(format!("{test_name} - {duration:?}"));
    } else {
        logger.error(format!("{test_name} - {duration:?}"));
    };
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let mut logger = Logger::new();
    logger.info("Running Tests");

    // We don't rely on rusts #[test] or #[bench] features because...
    //
    //   #[test] - tries to run all the tests in parallel but the functions
    //             themselves are already highly parallelized and long running
    //             causing huge delays when running them simultaneously.
    //
    //  #[bench] - tries to run the benchmark tests multiple times to get a
    //             statistically valid measurement of each test. But some of
    //             these validation test take 30s or more making benchmark tests
    //             unbearably slow.
    //
    // In the end we just want to run our highly parallelized tests sequentially
    // one by one, which is what these lines of code accomplish.

    // run_test(
    //     test_last_step_checkpoints_base,
    //     "test_last_step_checkpoints_base",
    //     &mut logger,
    // );

    // run_test(test_checkpoints_base, "test_checkpoints_base", &mut logger);

    // run_test(
    //     test_checkpoints_reset,
    //     "test_checkpoints_reset",
    //     &mut logger,
    // );

    // run_test(
    //     test_checkpoints_reset_first_step,
    //     "test_checkpoints_reset_first_step",
    //     & mut logger
    // );

    // run_test(
    //     test_last_step_checkpoints_with_last_step_reset,
    //     "test_last_step_checkpoints_with_last_step_reset",
    //     &mut logger,
    // );

    // run_test(
    //     test_checkpoints_reset_last_step,
    //     "test_checkpoints_reset_last_step",
    //     &mut logger,
    // );

    // run_test(
    //     test_checkpoints_reset_last_step_next,
    //     "test_checkpoints_reset_last_step_next",
    //     &mut logger,
    // );

    // run_test(
    //     test_checkpoints_reset_2nd_to_last_step,
    //     "test_checkpoints_reset_2nd_to_last_step",
    //     &mut logger,
    // );

    // run_test(
    //     test_checkpoints_reset_3rd_to_last_step,
    //     "test_checkpoints_reset_3rd_to_last_step",
    //     &mut logger,
    // );

    // run_test(test_pack_chunk, "test_pack_chunk", &mut logger);
    // run_test(test_validator_init, "test_validator_init", &mut logger);
    // run_test(test_validator_index_jsons, "test_validator_index_jsons", &mut logger);
    run_test(test_pre_validation, "test_pre_validation", &mut logger);

    // run_test(test_randomx_hash, "test_randomx_hash", &mut logger);
    // run_test(
    //     test_randomx_hash_with_entropy,
    //     "test_randomx_hash_with_entropy",
    //     &mut logger,
    // );

    Ok(())
}

const ENCODED_KEY: &str = "UbkeSd5Det8s6uLyuNJwCDFOZMQFa2zvsdKJ0k694LM";
const ENCODED_HASH: &str = "QQYWA46qnFENL4OTQdGU8bWBj5OKZ2OOPyynY3izung";
const ENCODED_NONCE: &str = "f_z7RLug8etm3SrmRf-xPwXEL0ZQ_xHng2A5emRDQBw";
const ENCODED_SEGMENT: &str =
    "7XM3fgTCAY2GFpDjPZxlw4yw5cv8jNzZSZawywZGQ6_Ca-JDy2nX_MC2vjrIoDGp";

fn test_randomx_hash() -> bool {
    let key: [u8; 32] = DecodeHash::from(ENCODED_KEY).unwrap();
    let nonce: [u8; 32] = DecodeHash::from(ENCODED_NONCE).unwrap();
    let segment: [u8; 48] = DecodeHash::from(ENCODED_SEGMENT).unwrap();
    let expected_hash: [u8; 32] = DecodeHash::from(ENCODED_HASH).unwrap();

    let mut input = Vec::new();
    input.append(&mut nonce.to_vec());
    input.append(&mut segment.to_vec());

    let hash = compute_randomx_hash(&key, &input);

    //println!("\nt:{hash:?}\ne:{expected_hash:?}");

    for (a, b) in hash.iter().zip(expected_hash.iter()) {
        if a != b {
            return false;
        }
    }
    true
}

fn test_randomx_hash_with_entropy() -> bool {
    // Nonce = ar_util:decode(?ENCODED_NONCE),
    // Segment = ar_util:decode(?ENCODED_SEGMENT),
    // Input = << Nonce/binary, Segment/binary >>,
    // ExpectedHash = ar_util:decode(?ENCODED_HASH),
    // {ok, Hash, OutEntropy} = ar_mine_randomx:hash_fast_long_with_entropy_nif(State, Input,
    // 		8, 0, 0, 0),
    // %% Compute it again, the result must be the same.
    // {ok, Hash, OutEntropy} = ar_mine_randomx:hash_fast_long_with_entropy_nif(State, Input,
    // 		8, 0, 0, 0),
    // {ok, DifferentHash, DifferentEntropy} = ar_mine_randomx:hash_fast_long_with_entropy_nif(
    // 		State, crypto:strong_rand_bytes(48), 8, 0, 0, 0),
    // {ok, PlainHash} = ar_mine_randomx:hash_fast_nif(State, Input, 0, 0, 0),
    // ?assertEqual(PlainHash, Hash),
    // ?assertNotEqual(DifferentHash, Hash),
    // ?assertNotEqual(DifferentEntropy, OutEntropy),
    // ?assertEqual(ExpectedHash, Hash),
    // ExpectedEntropy = read_entropy_fixture(),
    // ?assertEqual(ExpectedEntropy, OutEntropy).

    let packing_key: [u8; 32] = DecodeHash::from(ENCODED_KEY).unwrap();
    let nonce: [u8; 32] = DecodeHash::from(ENCODED_NONCE).unwrap();
    let segment: [u8; 48] = DecodeHash::from(ENCODED_SEGMENT).unwrap();
    let _expected_hash: [u8; 32] = DecodeHash::from(ENCODED_HASH).unwrap();

    let mut input = Vec::new();
    input.append(&mut nonce.to_vec());
    input.append(&mut segment.to_vec());

    let randomx_vm = create_randomx_vm(RandomXMode::FastHashing, &packing_key);

    let randomx_program_count = 8;

    let (_hash, entropy) = compute_randomx_hash_with_entropy(&input, randomx_program_count, Some(&randomx_vm));

    // Slice the first 32 bytes (256 bits)
    let first_256_bits = &entropy[0..32];

    // Encode the first 256 bits to base64
    let _encoded = base64_url::encode(first_256_bits);
    //println!("{encoded:?}");

    let expected_entropy = parse_encoded_bytes_from_file("data/entropy/randomx_entropy.dat");

    for (a, b) in entropy.iter().zip(expected_entropy.iter()) {
        if a != b {
            return false;
        }
    }
    true
}

fn test_pre_validation() -> bool {
    let (block_header, previous_block_header) = &TEST_DATA.poa_failed_case;

    let hash_index: HashIndex = HashIndex::new();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let hash_index = runtime.block_on(hash_index.init()).unwrap();
    
    let solution_hash = pre_validate_block(block_header, previous_block_header, &hash_index, None).unwrap();

    let solution_hash_value_big: u256 = u256::from_big_endian(&solution_hash);

    let diff: u256 = block_header.diff;

    solution_hash_value_big > diff
}

fn test_validator_init() -> bool {
    // let block_height = get_current_block_height();
    // println!("{block_height:?}");
    let hash_index: HashIndex = HashIndex::new();

    //let client = reqwest::Client::new();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let hash_index = runtime.block_on(hash_index.init()).unwrap();

    println!("len: {}", hash_index.num_indexes());
    true
}

fn test_validator_index_jsons() -> bool {
    let client = reqwest::Client::new();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime
        .block_on(request_hash_index_jsons(
            "http://188.166.200.45:1984",
            1288400u64,
            1288509u64,
            &client,
        ))
        .unwrap();
    println!("{result:?}");
    true
}

fn test_pack_chunk() -> bool {
    // let block_header = &TEST_DATA.packing_case;
    // let reward_address: [u8; 32] = block_header.reward_addr;
    // let tx_root: [u8; 32] = block_header.tx_root;
    // let chunk = pack_chunk(U256::from(0), &reward_address, &tx_root);
    // chunk.len() > 0
    false
}

fn test_last_step_checkpoints_base() -> bool {
    let base_infos = &TEST_DATA.base_case;
    let base_info = &base_infos[1];
    last_step_checkpoints_is_valid(base_info)
}

fn test_last_step_checkpoints_with_last_step_reset() -> bool {
    let reset_last_infos: &Vec<NonceLimiterInfo> = &TEST_DATA.reset_last_case;
    let reset_last = &reset_last_infos[0];
    last_step_checkpoints_is_valid(reset_last)
}

fn test_checkpoints_reset_first_step() -> bool {
    let reset_first_infos: &Vec<NonceLimiterInfo> = &TEST_DATA.reset_first_case;
    let reset_first = &reset_first_infos[0];
    checkpoints_is_valid(reset_first)
}

fn test_checkpoints_reset_last_step() -> bool {
    let reset_last_infos: &Vec<NonceLimiterInfo> = &TEST_DATA.reset_last_case;
    let reset_last = &reset_last_infos[0];
    checkpoints_is_valid(reset_last)
}

fn test_checkpoints_reset_last_step_next() -> bool {
    let reset_last_infos2: &Vec<NonceLimiterInfo> = &TEST_DATA.reset_last_case;
    let reset_last2 = &reset_last_infos2[1];
    checkpoints_is_valid(reset_last2)
}

fn test_checkpoints_reset_2nd_to_last_step() -> bool {
    let reset_2nd_to_last_infos: &Vec<NonceLimiterInfo> = &TEST_DATA.reset_2nd_to_last_case;
    let reset_2nd_to_last = &reset_2nd_to_last_infos[0];
    checkpoints_is_valid(reset_2nd_to_last)
}

fn test_checkpoints_reset_3rd_to_last_step() -> bool {
    let reset_3rd_to_last_infos: &Vec<NonceLimiterInfo> = &TEST_DATA.reset_3rd_to_last_case;
    let reset_3rd_to_last = &reset_3rd_to_last_infos[0];
    checkpoints_is_valid(reset_3rd_to_last)
}

fn test_checkpoints_base() -> bool {
    let base_infos = &TEST_DATA.base_case;
    let base_info = &base_infos[1];
    checkpoints_is_valid(base_info)
}

fn test_checkpoints_reset() -> bool {
    let reset_infos = &TEST_DATA.reset_case;
    let reset_info = &reset_infos[1];
    checkpoints_is_valid(reset_info)
}
