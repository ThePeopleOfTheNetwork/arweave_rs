use openssl::sha;

use crate::helpers::U256;

//The key to initialize the RandomX state from, for RandomX packing.
pub const RANDOMX_PACKING_KEY: &[u8] = b"default arweave 2.5 pack key";
// pub const RANDOMX_PACKING_ROUNDS_2_5: usize = 8*20;
pub const RANDOMX_PACKING_ROUNDS_2_6: usize = 8*45;

pub const RANDOMX_HASH_SIZE: usize = 32;
pub const RANDOMX_ENTROPY_SIZE: usize = 256 * 1024; //256KiB

pub const FORK_2_7_HEIGHT: u64 = 1275480;

// The presence of the absolute end offset in the key makes sure packing of 
// every chunk is unique, even when the same chunk is present in the same 
// transaction or across multiple transactions or blocks. The presence of the
// transaction root in the key ensures one cannot find data that has certain 
// patterns after packing. The presence of the reward address, combined with the
// 2.6 mining mechanics, puts a relatively low cap on the performance of a
// single dataset replica, essentially incentivizing miners to create more weave
// replicas per invested dollar.
pub fn get_chunk_entropy_input(chunk_offset:U256, tx_root:&[u8;32], reward_address:&[u8;32]) -> [u8; 32]
{
	let mut chunk_offset_bytes: [u8; 32] = [0; 32];
	chunk_offset.to_big_endian(&mut chunk_offset_bytes);

	let mut hasher = sha::Sha256::new();
	hasher.update(&chunk_offset_bytes);
	hasher.update(tx_root);
	hasher.update(reward_address);
	hasher.finish().into()
}