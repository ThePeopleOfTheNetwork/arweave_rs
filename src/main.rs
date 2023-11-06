use helpers::U256;
use json_types::{ArweaveBlockHeader, NonceLimiterInfo};
use eyre::Result;
use lazy_static::lazy_static;
use packing::pack::pack_chunk;
use paris::Logger;
use validator::hash_index::HashIndex;
use validator::hash_index_scraper::request_hash_index_jsons;
use validator::{pre_validate_block, compute_block_hash};
use std::fs::File;
use std::io::Read;
use std::time::Instant;
use vdf::verify::*;

use crate::validator::hash_index_scraper::current_block_height;

mod json_types;
mod packing;
mod validator;
mod vdf;
mod helpers;

#[derive(Default, Clone)]
struct TestContext {
    pub base_case: Vec<NonceLimiterInfo>,
    pub reset_case: Vec<NonceLimiterInfo>,
    pub reset_first_case: Vec<NonceLimiterInfo>,
    pub reset_last_case: Vec<NonceLimiterInfo>,
    pub reset_2nd_to_last_case: Vec<NonceLimiterInfo>,
    pub reset_3rd_to_last_case: Vec<NonceLimiterInfo>,
    pub packing_case: ArweaveBlockHeader,
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

        let packing_case = parse_block_header_from_file("data/1287795_packing.json");

        let tc:TestContext = TestContext {
            base_case: vec![base1, base2],
            reset_case: vec![reset1, reset2],
            reset_first_case: vec![reset_first1],
            reset_last_case: vec![reset_last1, reset_last2],
            reset_2nd_to_last_case: vec![reset_2nd_to_last1],
            reset_3rd_to_last_case: vec![reset_3rd_to_last1],
            packing_case
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

    Ok(())
}

fn test_pre_validation() -> bool {
// H0: <<83,14,17,68,209,86,9,9,67,189,54,208,103,124,160,135,95,132,39,244,183,24,107,27,146,127,96,226,180,11,149,132>>
// SolutionHash: <<49,138,171,33,24,4,154,44,168,139,61,88,183,119,78,95,203,131,171,84,181,211,59,35,44,116,134,92,141,234,222,76>>
// Encoded SolutionHash: <<"MYqrIRgEmiyoiz1Yt3dOX8uDq1S10zsjLHSGXI3q3kw">>
// Decoded SolutionHash: 22408335566352399523540813921322114797570619716531381388632873791215228345932

    let block_header = &TEST_DATA.packing_case;
    let mining_hash = pre_validate_block(block_header).unwrap();
    let chunk_preimage = block_header.hash_preimage;
    let block_hash = compute_block_hash(&mining_hash, &chunk_preimage);


    let encoded = base64_url::encode(&mining_hash);
    println!("{encoded:?}");

    let block_hash_val: U256 = U256::from(block_hash);
    println!("");
    println!("DiffB: {block_hash_val}");

    let diff: U256 = U256::from_dec_str(&block_header.diff
    ).unwrap();
    println!("DiffH: {diff}");

    block_hash_val > diff
}


fn test_validator_init() -> bool {
    // let block_height = get_current_block_height();
    // println!("{block_height:?}");
    let hash_index:HashIndex = HashIndex::new();

    let client = reqwest::Client::new();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let hash_index =  runtime.block_on(hash_index.init()).unwrap();

    println!("len: {}", hash_index.num_indexes());
    true
}

fn test_validator_index_jsons() -> bool {
    let client = reqwest::Client::new();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let result = runtime.block_on(request_hash_index_jsons("http://188.166.200.45:1984".into(), 1288400u64, 1288509u64, &client)).unwrap();
    println!("{result:?}");
    true
}

fn test_pack_chunk() -> bool {
    let block_header = &TEST_DATA.packing_case;
    let reward_address: [u8; 32] = block_header.reward_addr;
    let tx_root: [u8; 32] = block_header.tx_root;
    let chunk = pack_chunk(U256::from(0), &reward_address, &tx_root);
    chunk.len() > 0
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
