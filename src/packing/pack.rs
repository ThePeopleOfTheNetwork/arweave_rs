#![allow(dead_code)]
use arweave_randomx_rs::{RandomXCache, RandomXFlag, RandomXVM};

use crate::helpers::{u256, consensus::*};

pub fn pack_chunk(chunk_offset:u256, reward_address:&[u8;32], tx_root:&[u8;32]) -> Vec<u8> {
    let key = RANDOMX_PACKING_KEY;
    let flags = RandomXFlag::get_recommended_flags();
    let cache = RandomXCache::new(flags, key).unwrap();
    let vm = RandomXVM::new(flags, Some(cache), None).unwrap();

    let input = get_chunk_entropy_input(chunk_offset, tx_root, reward_address);
    let entropy_size = arweave_randomx_rs::ARWEAVE_CHUNK_SIZE;
    let randomx_program_count = RANDOMX_PACKING_ROUNDS_2_6;
    let entropy = vm
        .calculate_entropy(&input, entropy_size, randomx_program_count)
        .unwrap();

    for i in 0..10.min(entropy.len()) {
        println!("{}", entropy[i]);
    }
	entropy
}

//pub fn unpack_chunk() {}
