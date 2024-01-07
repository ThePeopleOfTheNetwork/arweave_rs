use crate::helpers::{consensus::*, u256};
use arweave_randomx_rs::*;

pub fn compute_randomx_hash(key:&[u8], input:&[u8]) -> Vec<u8> {
    let flags = RandomXFlag::get_recommended_flags();
    let cache = RandomXCache::new(flags, key).unwrap();
    let vm = RandomXVM::new(flags, Some(cache), None).unwrap();
    vm.calculate_hash(input).unwrap()
}

pub fn compute_randomx_hash_with_entropy(key:&[u8], input:&[u8], randomx_program_count:usize) -> ([u8;RANDOMX_HASH_SIZE],[u8; RANDOMX_ENTROPY_SIZE]) {
    let flags = RandomXFlag::get_recommended_flags();
    let cache = RandomXCache::new(flags, key).unwrap();
    let vm = RandomXVM::new(flags, Some(cache), None).unwrap();

    vm.calculate_hash_with_entropy(input, randomx_program_count).unwrap()
}

/// The reference erlang implementation refers to this as ar_block:compute_h0
pub fn compute_mining_hash(
    vdf_output: [u8; 32],
    partition_number: u32,
    vdf_seed: [u8; 48],
    mining_address: [u8; 32],
) -> [u8;32] {
    // TODO: Access the RandomX Cache from some global location
    let key = RANDOMX_PACKING_KEY;

    // No dataset
    let flags = RandomXFlag::get_recommended_flags();
    let cache = RandomXCache::new(flags, key).unwrap();
    let vm = RandomXVM::new(flags, Some(cache), None).unwrap();

    // NOTE: FLAG_FULL_MEM is similar to HASH_FAST in the erlang code.
    // let flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM;
    // let cache = RandomXCache::new(flags, key).unwrap();
    // let dataset = RandomXDataset::new(flags, cache.clone(), 0).expect("Failed to allocate dataset");
    // let vm = RandomXVM::new(flags, Some(cache), Some(dataset)).unwrap();

    // Byte order for mining hash (remember erlang is BigEndian for ints)
    // vdf_output + partition_number + vdf_seed + mining_address

    let mut input = Vec::new();

    input.append(&mut vdf_output.to_vec());

    let pn:u256 = u256::from(partition_number);
    let mut partition_bytes: [u8; 32] = [0u8; 32];
    pn.to_big_endian(&mut partition_bytes);
    
    input.append(&mut partition_bytes.try_into().unwrap());

    input.append(&mut vdf_seed[..32].to_vec()); // Use first 32 bytes of vdf_seed

    input.append(&mut mining_address.to_vec());

    //println!("input: {input:?} len: {}", input.len());

    let mining_hash = vm.calculate_hash(&input).unwrap();

    let hash_array: [u8; 32] = mining_hash
    .try_into().unwrap();
    hash_array
}

pub fn compute_mining_hash_test(
    vdf_output: [u8; 32],
    partition_number: u32,
    vdf_seed: [u8; 48],
    mining_address: [u8; 32],
) -> Vec<u8> {
    // TODO: Access the RandomX Cache from some global location and figure out how to turn on FLAG_FULL_MEM
    let key = RANDOMX_PACKING_KEY;
    // NOTE: FLAG_FULL_MEM is similar to HASH_FAST in the erlang code.
    // let flags = RandomXFlag::get_recommended_flags() | RandomXFlag::FLAG_FULL_MEM;
    let flags = RandomXFlag::get_recommended_flags();
    let cache = RandomXCache::new(flags, key).unwrap();
    let vm = RandomXVM::new(flags, Some(cache), None).unwrap();

    // Byte order for mining hash (remember erlang is BigEndian for ints)
    // vdf_output + partition_number + vdf_seed + mining_address

    let mut input = vec![0u8; 32 + 4 + 32 + 32];

    let mut offset = 0;

    input[offset..offset + 32].copy_from_slice(&vdf_output);
    offset += 32;

    let partition_bytes = partition_number.to_be_bytes();
    input[offset..offset + 4].copy_from_slice(&partition_bytes);
    offset += 4;

    // Use first 32 bytes of vdf_seed
    input[offset..offset + 32].copy_from_slice(&vdf_seed[..32]);
    offset += 32;

    input[offset..].copy_from_slice(&mining_address);

    //println!("input: {input:?}");

    // Call hash function on input
    vm.calculate_hash(&input).unwrap()
}
