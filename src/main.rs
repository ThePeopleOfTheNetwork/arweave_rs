use eyre::Result;
use lazy_static::lazy_static;
use paris::Logger;
use std::fs::File;
use std::io::Read;
use std::time::Instant;
use vdf::verify::*;

pub mod vdf;

#[derive(Default, Clone)]
struct TestContext {
    pub base_case: Vec<NonceLimiterInfo>,
    pub reset_case: Vec<NonceLimiterInfo>,
    pub reset_first_case: Vec<NonceLimiterInfo>,
    pub reset_last_case: Vec<NonceLimiterInfo>,
    pub reset_2nd_to_last_case: Vec<NonceLimiterInfo>,
    pub reset_3rd_to_last_case: Vec<NonceLimiterInfo>,
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

        let tc:TestContext = TestContext {
            base_case: vec![base1, base2],
            reset_case: vec![reset1, reset2],
            reset_first_case: vec![reset_first1],
            reset_last_case: vec![reset_last1, reset_last2],
            reset_2nd_to_last_case: vec![reset_2nd_to_last1],
            reset_3rd_to_last_case: vec![reset_3rd_to_last1]
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
    
    run_test(
        test_last_step_checkpoints_base,
        "test_last_step_checkpoints_base",
        &mut logger,
    );

    run_test(test_checkpoints_base, "test_checkpoints_base", &mut logger);

    run_test(
        test_checkpoints_reset,
        "test_checkpoints_reset",
        &mut logger,
    );

    run_test(
        test_checkpoints_reset_first_step,
        "test_checkpoints_reset_first_step",
        & mut logger
    );

    run_test(
        test_last_step_checkpoints_with_last_step_reset,
        "test_last_step_checkpoints_with_last_step_reset",
        &mut logger,
    );

    run_test(
        test_checkpoints_reset_last_step,
        "test_checkpoints_reset_last_step",
        &mut logger,
    );

    run_test(
        test_checkpoints_reset_last_step_next,
        "test_checkpoints_reset_last_step_next",
        &mut logger,
    );


    run_test(
        test_checkpoints_reset_2nd_to_last_step,
        "test_checkpoints_reset_2nd_to_last_step",
        &mut logger,
    );

    run_test(
        test_checkpoints_reset_3rd_to_last_step,
        "test_checkpoints_reset_3rd_to_last_step",
        &mut logger,
    );

    Ok(())
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
