use serde::{Deserialize, Deserializer};
use serde_derive::Deserialize;
use serde_json::Value;

use crate::helpers::{DecodeHash, U256};

#[derive(Clone, Debug, Deserialize)]
pub struct ArweaveBlockHeader {
    pub partition_number: usize,
    pub nonce_limiter_info: NonceLimiterInfo,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub hash_preimage: [u8; 32],
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub previous_block: [u8; 48],
    pub timestamp: usize,
    pub last_retarget: u64,
    #[serde(deserialize_with = "parse_string_to_u64")]
    pub recall_byte: u64,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub chunk_hash: [u8; 32],
    #[serde(default, deserialize_with = "parse_optional_string_to_u64")]
    pub recall_byte2: Option<u64>,
    #[serde(default, deserialize_with = "decode_hash_to_bytes")]
    pub chunk2_hash: Option<[u8; 32]>,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub hash: [u8; 32],
    #[serde(default, deserialize_with = " parse_string_to_u256")]
    pub diff: U256,
    pub height: u64,
    #[serde(deserialize_with = "base64_string_to_bytes")]
    pub nonce: Vec<u8>,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub tx_root: [u8; 32],
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub reward_addr: [u8; 32],
    #[serde(deserialize_with = "parse_string_to_u64")]
    pub reward_pool: u64,
    #[serde(deserialize_with = "parse_string_to_u64")]
    pub weave_size: u64,
    #[serde(deserialize_with = "parse_string_to_u64")]
    pub block_size: u64,
    #[serde(deserialize_with = "parse_string_to_u64")]
    pub cumulative_diff: u64,
    pub poa: PoaData,
    pub poa2: PoaData,
}

impl Default for ArweaveBlockHeader {
    fn default() -> Self {
        Self {
            partition_number: Default::default(),
            nonce_limiter_info: Default::default(),
            hash_preimage: Default::default(),
            previous_block: [0u8; 48],
            timestamp: Default::default(),
            last_retarget: Default::default(),
            recall_byte: Default::default(),
            chunk_hash: Default::default(),
            recall_byte2: Default::default(),
            chunk2_hash: Default::default(),
            hash: Default::default(),
            diff: U256::zero(),
            height: Default::default(),
            tx_root: Default::default(),
            reward_addr: Default::default(),
            reward_pool: Default::default(),
            weave_size: Default::default(),
            block_size: Default::default(),
            poa: Default::default(),
            poa2: Default::default(),
            nonce: Default::default(),
            cumulative_diff: Default::default(),
        }
    }
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct PoaData {
    pub option: String,
    #[serde(deserialize_with = "optional_base64_string_to_bytes")]
    pub tx_path: Option<Vec<u8>>,
    #[serde(deserialize_with = "optional_base64_string_to_bytes")]
    pub data_path: Option<Vec<u8>>,
    #[serde(deserialize_with = "optional_base64_string_to_bytes")]
    pub chunk: Option<Vec<u8>>,
}

/// NonceLImiterInput holds the nonce_limiter_info from the Arweave block header
#[derive(Clone, Debug, Deserialize)]
pub struct NonceLimiterInfo {
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub output: [u8; 32],
    pub global_step_number: u64,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub seed: [u8; 48],
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub next_seed: [u8; 48],
    pub zone_upper_bound: u64,
    pub next_zone_upper_bound: u64,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub prev_output: [u8; 32],
    pub last_step_checkpoints: Vec<String>,
    pub checkpoints: Vec<String>,
    #[serde(default, deserialize_with = "parse_optional_string_to_u64")]
    pub vdf_difficulty: Option<u64>,
    #[serde(default, deserialize_with = "parse_optional_string_to_u64")]
    pub next_vdf_difficulty: Option<u64>,
}

impl Default for NonceLimiterInfo {
    fn default() -> Self {
        NonceLimiterInfo {
            output: [0; 32],
            global_step_number: 0,
            seed: [0; 48],
            next_seed: [0; 48],
            zone_upper_bound: 0,
            next_zone_upper_bound: 0,
            prev_output: [0; 32],
            last_step_checkpoints: Vec::new(),
            checkpoints: Vec::new(),
            vdf_difficulty: None,
            next_vdf_difficulty: None,
        }
    }
}

/// serde helper method to convert an optional JSON `string` value to a `usize`
fn parse_optional_string_to_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt_val: Option<Value> = Option::deserialize(deserializer)?;

    match opt_val {
        Some(Value::String(s)) => s.parse::<u64>().map(Some).map_err(serde::de::Error::custom),
        Some(_) => Err(serde::de::Error::custom("Invalid type")),
        None => Ok(None),
    }
}

/// serde helper method to convert a JSON `string` value to a `u64`
fn parse_string_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    s.parse::<u64>().map_err(serde::de::Error::custom)
}

fn parse_string_to_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    U256::from_dec_str(&s).map_err(serde::de::Error::custom)
}

pub fn decode_hash_to_bytes<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DecodeHash,
{
    let s = String::deserialize(deserializer)?;
    if s.is_empty() {
        // Return an instance of T that represents an array of 0's.
        Ok(T::empty())
    } else {
        T::from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

pub fn optional_base64_string_to_bytes<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt_val: Option<Value> =
        Option::deserialize(deserializer).map_err(serde::de::Error::custom)?;

    match opt_val {
        Some(Value::String(s)) => base64_url::decode(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(_) => Err(serde::de::Error::custom("Invalid type")),
        None => Ok(None),
    }
}

pub fn base64_string_to_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    base64_url::decode(&s).map_err(serde::de::Error::custom)
}
