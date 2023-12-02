use color_eyre::eyre::{eyre, Result};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};

use crate::helpers::DecodeHash;

use super::hash_index_scraper::{
    current_block_height, current_block_height_async, request_indexes, HashIndexJson,
};

pub struct HashIndexItem {
    pub block_hash: [u8; 48], // 48 bytes
    pub weave_size: u128,     // 16 bytes
    pub tx_root: [u8; 32],    // 32 bytes
}

impl HashIndexItem {
    pub fn from(json: &HashIndexJson) -> Result<Self> {
        let block_hash: [u8; 48] = DecodeHash::from(&json.hash)
            .map_err(|e| eyre!("Failed to decode block_hash: {}", e))?;
        let weave_size = json
            .weave_size
            .parse()
            .map_err(|e| eyre!("Failed to parse weave_size: {}", e))?;

        let mut tx_root = [0u8; 32];
        if json.tx_root.len() > 0 {
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

const HASH_INDEX_ITEM_SIZE: u64 = 48 + 16 + 32;
const FILE_PATH: &str = "data/index.dat";

pub struct Uninitialized;
pub struct Initialized;

pub struct HashIndex<State = Uninitialized> {
    #[allow(dead_code)]
    state: State,
    indexes: Vec<HashIndexItem>,
}

impl HashIndex {
    pub fn new() -> Self {
        HashIndex {
            indexes: Default::default(),
            state: Uninitialized,
        }
    }
}

impl HashIndex<Uninitialized> {
    pub async fn init(mut self) -> Result<HashIndex<Initialized>> {
        // Get the current block height from the network
        let current_block_height: u64 = current_block_height_async().await;

        // Try to load the hash index from disk
        match load_index_from_file() {
            Ok(indexes) => self.indexes = indexes,
            Err(err) => println!("{err:?}"),
        }

        // Get the most recent blockheight from the index
        let latest_height = self.indexes.len() as u64;

        // EARLY OUT: if the index is already current
        if latest_height >= current_block_height - 20 {
            // Return the "Initialized" state of the HashIndex type
            return Ok(HashIndex {
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
            request_indexes("http://188.166.200.45:1984".into(), &start_block_heights).await?;

        // Once the batches have completed, write them  to the hash_index
        // transforming the JSONS to bytes so they take up less space on disk
        // and in memory.
        let index_items = index_jsons
            .iter()
            .flatten()
            .map(|json_item| HashIndexItem::from(json_item))
            .collect::<Result<Vec<HashIndexItem>>>()
            .unwrap();

        // Write the updates to the index and to disk
        append_items(&index_items)?;

        // Append the updates to the existing in memory items
        self.indexes.extend(index_items);

        // Return the "Initialized" state of the HashIndex type
        Ok(HashIndex {
            indexes: self.indexes,
            state: Initialized,
        })
    }
}

impl HashIndex<Initialized> {
    pub fn num_indexes(self) -> u64 {
        self.indexes.len() as u64
    }
}

impl HashIndexItem {
    // Serialize the HashIndexItem to bytesß
    fn to_bytes(&self) -> [u8; 48 + 16 + 32] {
        let mut bytes = [0u8; 48 + 16 + 32];
        bytes[0..48].copy_from_slice(&self.block_hash);
        bytes[48..64].copy_from_slice(&self.weave_size.to_le_bytes());
        bytes[64..96].copy_from_slice(&self.tx_root);
        bytes
    }

    // Deserialize bytes to HashIndexItem
    fn from_bytes(bytes: &[u8]) -> HashIndexItem {
        let mut block_hash = [0u8; 48];
        let mut weave_size_bytes = [0u8; 16];
        let mut tx_root = [0u8; 32];

        block_hash.copy_from_slice(&bytes[0..48]);
        weave_size_bytes.copy_from_slice(&bytes[48..64]);
        tx_root.copy_from_slice(&bytes[64..96]);

        HashIndexItem {
            block_hash,
            weave_size: u128::from_le_bytes(weave_size_bytes),
            tx_root,
        }
    }
}

fn save_initial_index(hash_items: &[HashIndexItem]) -> io::Result<()> {
    let mut file = File::create(FILE_PATH)?;
    for item in hash_items {
        let bytes = item.to_bytes();
        file.write_all(&bytes)?;
    }
    Ok(())
}

fn read_item_at(block_height: u64) -> io::Result<HashIndexItem> {
    let mut file = File::open(FILE_PATH)?;
    let mut buffer = [0; HASH_INDEX_ITEM_SIZE as usize];
    file.seek(SeekFrom::Start(block_height * HASH_INDEX_ITEM_SIZE))?;
    file.read_exact(&mut buffer)?;
    Ok(HashIndexItem::from_bytes(&buffer))
}

fn append_item(item: HashIndexItem) -> io::Result<()> {
    let mut file = OpenOptions::new().append(true).open(FILE_PATH)?;
    file.write_all(&item.to_bytes())?;
    Ok(())
}

fn append_items(items: &Vec<HashIndexItem>) -> io::Result<()> {
    let mut file = OpenOptions::new().append(true).open(FILE_PATH)?;

    for item in items {
        file.write_all(&item.to_bytes())?;
    }

    Ok(())
}

fn update_item_at(block_height: u64, item: HashIndexItem) -> io::Result<()> {
    let mut file = OpenOptions::new().read(true).write(true).open(FILE_PATH)?;
    file.seek(SeekFrom::Start(block_height * HASH_INDEX_ITEM_SIZE))?;
    file.write_all(&item.to_bytes())?;
    Ok(())
}

fn load_index_from_file() -> io::Result<Vec<HashIndexItem>> {
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

    // Initialize a vector to hold the HashIndexItems
    let mut hash_index_items = Vec::new();

    // Chunk the buffer and deserialize each chunk
    for chunk in buffer.chunks(HASH_INDEX_ITEM_SIZE as usize) {
        let item = HashIndexItem::from_bytes(chunk);
        hash_index_items.push(item);
    }

    Ok(hash_index_items)
}