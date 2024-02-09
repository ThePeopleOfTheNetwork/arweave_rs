//! In order to validate blocks `arweave_rs` caches state about the blockchain
//! in various indexes. This module contains the implementation of those
//! indexes and in some cases the modules that initialize them from the Arweave
//! peers.
use std::sync::Arc;
use self::block_index::BlockIndexItem;

pub mod block_index;
pub mod block_index_scraper;


/// This struct represents the `Uninitialized` type state.
pub struct Uninitialized;

/// This struct represents the `Initialized` type state.
pub struct Initialized;


/// Stores an index of `{block_hash, weave_size, tx_root}` entries for each of 
/// Arweaves' blocks. Implemented using the type state pattern which has 
/// [`Initialized`] and [`Uninitialized`] states that are checked at compile 
/// time.
pub struct BlockIndex<State = Uninitialized> {
    #[allow(dead_code)]
    state: State,
    indexes: Arc<[BlockIndexItem]>,
}
