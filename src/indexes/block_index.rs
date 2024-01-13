use color_eyre::eyre::{eyre, Result};
use std::fs::{File, OpenOptions, self};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::Arc;

use crate::arweave_types::{decode::*, H384, H256};
use super::{BlockIndex, Uninitialized, Initialized};
use super::block_index_scraper::{current_block_height_async, request_indexes, BlockIndexJson};

const HASH_INDEX_ITEM_SIZE: u64 = 48 + 16 + 32;
const FILE_PATH: &str = "data/index.dat";


/// Use a Type State pattern for BlockIndex with two states, Uninitialized and Initialized
impl BlockIndex {
    pub fn new() -> Self {
        BlockIndex {
            indexes: Arc::new([]),
            state: Uninitialized,
        }
    }
}

//==============================================================================
// Uninitialized State
//------------------------------------------------------------------------------

impl Default for BlockIndex<Uninitialized> {
    fn default() -> Self {
        BlockIndex::new()
    }
}

impl BlockIndex<Uninitialized> {
    pub async fn init(mut self) -> Result<BlockIndex<Initialized>> {
        // Get the current block height from the network
        let current_block_height: u64 = current_block_height_async().await;

         // Ensure the path exists
         let path = Path::new(FILE_PATH);

         if let Some(dir) = path.parent() {
             fs::create_dir_all(dir)?;
         }

        // Try to load the hash index from disk
        match load_index_from_file() {
            Ok(indexes) => self.indexes = indexes.into(),
            Err(err) => println!("Error encountered\n {:?}", err),
        }

        // Get the most recent blockheight from the index
        let latest_height = self.indexes.len() as u64;

        // EARLY OUT: if the index is already current
        if latest_height >= current_block_height - 20 {
            // Return the "Initialized" state of the BlockIndex type
            return Ok(BlockIndex {
                indexes: self.indexes,
                state: Initialized,
            });
        }

        // Otherwise, request updates to the hash index in batches of 720,
        // starting from the last known blockheight to current_block_height - 20
        // (preferring confirmed blocks to account for forks & reorgs)
        let new_index_count = (current_block_height - 20) - latest_height;
        let num_batches = new_index_count / 720;
        let remainder = new_index_count % 720; // indexes remaining after full batches

        // Build a vec of tuples containing starting block heights and the
        // number of indexes to load
        let mut start_block_heights: Vec<(u64, u64)> = Vec::new();
        for i in 0..num_batches {
            let height = latest_height + 1 + i * 720;
            start_block_heights.push((height, 720 - 1)); // -1 to avoid duplicate hash entries
        }

        // Handle the final batch with less than 720 indexes if necessary
        if remainder > 0 {
            let final_height = latest_height + 1 + num_batches * 720;
            start_block_heights.push((final_height, remainder));
        }

        // Make concurrent requests to retrieve the batches of indexes. Utilize
        // exponential backoff when getting 429 (Too Many Requests) responses.
        let index_jsons =
            request_indexes("http://188.166.200.45:1984", &start_block_heights).await?;

        // Once the batches have completed, write them  to the block_index
        // transforming the JSONS to bytes so they take up less space on disk
        // and in memory.
        let index_items = index_jsons
            .iter()
            .flatten()
            .map(BlockIndexItem::from)
            .collect::<Result<Vec<BlockIndexItem>>>()
            .unwrap();

        // Write the updates to the index and to disk
        append_items_to_file(&index_items)?;

        // Append the updates to the existing in memory items
        let mut vec = self.indexes.to_vec();
        vec.extend(index_items);
        self.indexes = vec.into();

        // Return the "Initialized" state of the BlockIndex type
        Ok(BlockIndex {
            indexes: self.indexes,
            state: Initialized,
        })
    }
}

//==============================================================================
// Initialized State
//------------------------------------------------------------------------------

impl BlockIndex<Initialized> {
    pub fn num_indexes(&self) -> u64 {
        self.indexes.len() as u64
    }

    pub fn get_item(&self, index: usize) -> Option<&BlockIndexItem> {
        self.indexes.get(index)
    }

    pub fn get_block_bounds(&self, recall_byte: u128) -> BlockBounds {
        let mut block_bounds: BlockBounds = Default::default();

        let result = self.get_block_index_item(recall_byte);
        if let Ok((index, found_item)) = result {
            let previous_item = self.get_item(index - 1).unwrap();
            block_bounds.block_start_offset = previous_item.weave_size;
            block_bounds.block_end_offset = found_item.weave_size;
            block_bounds.tx_root = found_item.tx_root;
            block_bounds.height = (index + 1) as u128;
        }
        block_bounds
    }

    fn get_block_index_item(&self, recall_byte: u128) -> Result<(usize, &BlockIndexItem)> {
        let result = self.indexes.binary_search_by(|item| {
            if recall_byte < item.weave_size {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Less
            }
        });

        // It's the nature of binary_search_bh to return Err if it doesn't find
        // an exact match. We are looking for the position of the closest element
        // so we ignore the Result enum values and extract the pos return val.
        let index = match result {
            Ok(pos) => pos,
            Err(pos) => pos,
        };

        Ok((index, &self.indexes[index]))
    }
}

#[derive(Clone, Default)]
pub struct BlockIndexItem {
    pub block_hash: H384, // 48 bytes
    pub weave_size: u128, // 16 bytes
    pub tx_root: H256,    // 32 bytes
                              // TODO: add height
                              // height: u128 (ar_block_index.erl: 111)
                              // Oh yeah, height is implicit in the indexing of the items
}

#[derive(Default, Clone, Debug)]
pub struct BlockBounds {
    pub height: u128,
    pub block_start_offset: u128,
    pub block_end_offset: u128,
    pub tx_root: H256,
}

impl BlockIndexItem {
    pub fn from(json: &BlockIndexJson) -> Result<Self> {
        let block_hash: H384 = DecodeHash::from(&json.hash)
            .map_err(|e| eyre!("Failed to decode block_hash: {}", e))?;
        let weave_size = json
            .weave_size
            .parse()
            .map_err(|e| eyre!("Failed to parse weave_size: {}", e))?;

        let mut tx_root = H256::empty();
        if !json.tx_root.is_empty() {
            tx_root = DecodeHash::from(&json.tx_root)
                .map_err(|e| eyre!("Failed to decode tx_root: {}", e))?;
        }

        Ok(Self {
            tx_root,
            block_hash,
            weave_size,
        })
    }
}

impl BlockIndexItem {
    // Serialize the BlockIndexItem to bytes
    fn to_bytes(&self) -> [u8; 48 + 16 + 32] {
        let mut bytes = [0u8; 48 + 16 + 32];
        bytes[0..48].copy_from_slice(self.block_hash.as_bytes());
        bytes[48..64].copy_from_slice(&self.weave_size.to_le_bytes());
        bytes[64..96].copy_from_slice(self.tx_root.as_bytes());
        bytes
    }

    // Deserialize bytes to BlockIndexItem
    fn from_bytes(bytes: &[u8]) -> BlockIndexItem {
        let mut block_hash = H384::empty();
        let mut weave_size_bytes = [0u8; 16];
        let mut tx_root = H256::empty();

        block_hash.0.copy_from_slice(&bytes[0..48]);
        weave_size_bytes.copy_from_slice(&bytes[48..64]);
        tx_root.0.copy_from_slice(&bytes[64..96]);

        BlockIndexItem {
            block_hash,
            weave_size: u128::from_le_bytes(weave_size_bytes),
            tx_root,
        }
    }
}

#[allow(dead_code)]
fn save_index(block_index_items: &[BlockIndexItem]) -> io::Result<()> {
    let mut file = File::create(FILE_PATH)?;
    for item in block_index_items {
        let bytes = item.to_bytes();
        file.write_all(&bytes)?;
    }
    Ok(())
}

#[allow(dead_code)]
fn read_item_at(block_height: u64) -> io::Result<BlockIndexItem> {
    let mut file = File::open(FILE_PATH)?;
    let mut buffer = [0; HASH_INDEX_ITEM_SIZE as usize];
    file.seek(SeekFrom::Start(block_height * HASH_INDEX_ITEM_SIZE))?;
    file.read_exact(&mut buffer)?;
    Ok(BlockIndexItem::from_bytes(&buffer))
}

#[allow(dead_code)]
fn append_item(item: BlockIndexItem) -> io::Result<()> {
    let mut file = OpenOptions::new().append(true).open(FILE_PATH)?;
    file.write_all(&item.to_bytes())?;
    Ok(())
}

fn append_items_to_file(items: &Vec<BlockIndexItem>) -> io::Result<()> {
    let mut file = OpenOptions::new().append(true).open(FILE_PATH)?;

    for item in items {
        file.write_all(&item.to_bytes())?;
    }

    Ok(())
}

#[allow(dead_code)]
fn update_file_item_at(block_height: u64, item: BlockIndexItem) -> io::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(FILE_PATH)?;
    file.seek(SeekFrom::Start(block_height * HASH_INDEX_ITEM_SIZE))?;
    file.write_all(&item.to_bytes())?;
    Ok(())
}

fn load_index_from_file() -> io::Result<Vec<BlockIndexItem>> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(FILE_PATH)?;

    // Determine the file size
    let file_size = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(0))?;

    // Read the entire file into a buffer
    let mut buffer = vec![0u8; file_size as usize];
    file.read_exact(&mut buffer)?;

    // Initialize a vector to hold the BlockIndexItems
    let mut block_index_items = Vec::new();

    // Chunk the buffer and deserialize each chunk
    for chunk in buffer.chunks(HASH_INDEX_ITEM_SIZE as usize) {
        let item = BlockIndexItem::from_bytes(chunk);
        block_index_items.push(item);
    }

    Ok(block_index_items)
}
