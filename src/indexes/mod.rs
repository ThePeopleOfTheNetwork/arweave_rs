use std::sync::Arc;
use self::block_index::BlockIndexItem;

pub mod block_index;
pub mod block_index_scraper;


// Allowable states for the index
pub struct Uninitialized;
pub struct Initialized;


pub struct BlockIndex<State = Uninitialized> {
    #[allow(dead_code)]
    state: State,
    indexes: Arc<[BlockIndexItem]>,
}
