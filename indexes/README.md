This library package contains implementations of the various indexes (lookup tables) of information related to Arweave block validation.

## BlockIndex
The first index is the `BlockIndex` which stores a list of `BlockIndexItems` indexed by block height.

```rust
pub struct BlockIndexItem {
    pub block_hash: H384, // 48 bytes
    pub weave_size: u128, // 16 bytes
    pub tx_root: H256,    // 32 bytes
}
```

These `BlockIndexItems` enable the validator to look up the `tx_root` for any chunk provided for the `poa` or `poa2` proof in the block header. This is critical for proving weather the chunk belongs to a transaction in the block or not. 

## BlockIndexScraper

In order to initialize the `BlockIndex` this package includes a scraper module that connects to an Arweave peer and queries the block index. Arweave peers provide a specialized endpoint specifically for this task.

```
/block_index/{start_block_height}/{end_block_height}
```

At startup the `BlockIndex` will attempt to connect to the network and update its local cache with updated block index data. The local cache is persisted to disk at `./data/index.dat` and will be appended to over time. This removes the need to require the entire index every time the `BlockIndex` is used.
