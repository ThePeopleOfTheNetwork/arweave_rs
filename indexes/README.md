This library package contains implementations of the various indexes (lookup tables) of information related to Arweave block validation.

The first index is the `BlockIndex` which stores a list of `BlockIndexItems` indexed by block height.

```rust
pub struct BlockIndexItem {
    pub block_hash: H384, // 48 bytes
    pub weave_size: u128, // 16 bytes
    pub tx_root: H256,    // 32 bytes
}
```

These `BlockIndexItems` enable the validator to look up the `tx_root` for any chunk provided for the `poa` or `poa2` proof in the block header. This is critical for proving weather the chunk belongs to a transaction in the block or not. 
