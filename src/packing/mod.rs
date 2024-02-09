//! RandomX entropy generation and feistel decryption cypher for unpacking Arweave data.
#![allow(dead_code)]
use crate::{arweave_types::*, consensus::*};
use arweave_randomx_rs::{create_randomx_vm, RandomXCache, RandomXFlag, RandomXMode, RandomXVM};

pub mod feistel;

/// Computes the RandomX entropy scratchpad from the `input` using the specified 
/// number of programs.
pub fn compute_entropy(
    input: &[u8],
    randomx_program_count: usize,
    randomx_vm: Option<&RandomXVM>,
) -> [u8; RANDOMX_ENTROPY_SIZE] {
    // These variables extend the life of the created RandomX instance outside
    // the scope of the [None] match arm below
    let vm: &RandomXVM;
    let vm_storage: Option<RandomXVM>;

    // If needed, lazy initialize a RandomXVM and borrow a reference to it
    match randomx_vm {
        Some(existing_vm) => {
            vm = existing_vm;
        }
        None => {
            // Creates a disposable RandomXVM instance for use in this function
            vm_storage = Some(create_randomx_vm(
                RandomXMode::FastHashing,
                RANDOMX_PACKING_KEY,
            ));
            vm = vm_storage.as_ref().unwrap();
        }
    };

    vm.calculate_entropy(input, randomx_program_count).unwrap()
}


/// Computes the RandomX Hash and associated entropy scratchpad from the `input`
/// using the specified number of `randomx_program_count`.
fn compute_randomx_hash_with_entropy(
    input: &[u8],
    randomx_program_count: usize,
    randomx_vm: Option<&RandomXVM>,
) -> ([u8; RANDOMX_HASH_SIZE], [u8; RANDOMX_ENTROPY_SIZE]) {
    // These variables extend the life of the created RandomX instance outside
    // the scope of the [None] match arm below
    let vm: &RandomXVM;
    let vm_storage: Option<RandomXVM>;

    // If needed, lazy initialize a RandomXVM and borrow a reference to it
    match randomx_vm {
        Some(existing_vm) => {
            vm = existing_vm;
        }
        None => {
            // Creates a disposable RandomXVM instance for use in this function
            vm_storage = Some(create_randomx_vm(
                RandomXMode::FastHashing,
                RANDOMX_PACKING_KEY,
            ));
            vm = vm_storage.as_ref().unwrap();
        }
    };

    vm.calculate_hash_with_entropy(input, randomx_program_count)
        .unwrap()
}

/// Only used to text / exercise pack chunk plumbing. Candidate for deletion.
fn pack_chunk(chunk_offset: U256, reward_address: &H256, tx_root: &H256) -> Vec<u8> {
    let key = RANDOMX_PACKING_KEY;
    let flags = RandomXFlag::get_recommended_flags();
    let cache = RandomXCache::new(flags, key).unwrap();
    let vm = RandomXVM::new(flags, Some(cache), None).unwrap();

    let input = get_chunk_entropy_input(chunk_offset, tx_root, reward_address);
    let randomx_program_count = RANDOMX_PACKING_ROUNDS_2_6;
    let entropy = vm.calculate_entropy(&input, randomx_program_count).unwrap();

    println!();
    for byte in entropy.iter().take(10.min(entropy.len())) {
        println!("{}", byte);
    }

    let (_hash, entropy) =
        compute_randomx_hash_with_entropy(&input, randomx_program_count, Some(&vm));

    println!();
    for byte in entropy.iter().take(10.min(entropy.len())) {
        println!("{}", byte);
    }

    entropy.to_vec()
}
