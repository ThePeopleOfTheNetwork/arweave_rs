Library package that contains functions related to packing/unpacking arweave chunks. Presently used in validating the `poa` and `poa2` chunks included in Arweave block headers.

## Packing
The main packing function is 

```rust
pub fn compute_entropy(
    input: &[u8],
    randomx_program_count: usize,
    randomx_vm: Option<&RandomXVM>,
) -> [u8; RANDOMX_ENTROPY_SIZE] {
  ...
}
```
Which takes a byte buffer and performs RandomX hashing on it to generate a scratchpad. Currently `RANDOMX_ENTROPY_SIZE` is 256Kib, the size of an Arweave chunk.

the `input` for each chunks entropy comes form the following consensus method.

```rust
pub fn get_chunk_entropy_input(
    chunk_offset: U256,
    tx_root: &H256,
    reward_addr: &H256
) -> [u8; 32] {
    let mut chunk_offset_bytes: [u8; 32] = [0; 32];
    chunk_offset.to_big_endian(&mut chunk_offset_bytes);

    let mut hasher = sha::Sha256::new();
    hasher.update(&chunk_offset_bytes);
    hasher.update(tx_root.as_bytes());
    hasher.update(reward_addr.as_bytes());
    hasher.finish()
}
```
The `chunk_offset` is the absolute offset of the chunk in the weave data set, and the `tx_root` comes from the block which contains the chunk. Currently `tx_root` is retrieved from the `BlockIndex` during validation.

## Decrypting

Arweave chunks are packed using a combination of the original 256KiB bytes of the chunk combined with 256KiB bytes of RandomX entropy. To pack the chunk the original bytes of the chunk and the entropy are combined using a feistel block cypher.To get the original bytes out of a packed chunk means generating the randomX entropy for the packed chunk and using that as in input to feistel decript the original chunk bytes.
