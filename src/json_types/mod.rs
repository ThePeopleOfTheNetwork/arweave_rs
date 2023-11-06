use serde::{Deserialize, Deserializer};
use serde_derive::Deserialize;
use serde_json::Value;

use crate::helpers::DecodeHash;

#[derive(Default, Clone, Debug, Deserialize)]
pub struct ArweaveBlockHeader {
    pub partition_number: usize,
    pub nonce_limiter_info: NonceLimiterInfo,
    #[serde(deserialize_with = "deserialize_base64url_bytes")]
    pub hash_preimage: [u8; 32],
    pub previous_block: String,
    pub timestamp: usize,
    pub diff: String,
    pub height: u64,
    #[serde(deserialize_with = "deserialize_base64url_bytes")]
    pub tx_root: [u8; 32],
    #[serde(deserialize_with = "deserialize_base64url_bytes")]
    pub reward_addr: [u8; 32],
    #[serde(deserialize_with = "deserialize_str_to_u64")]
    pub recall_byte: u64,
    #[serde(deserialize_with = "deserialize_str_to_u64")]
    pub reward_pool: u64,
    #[serde(deserialize_with = "deserialize_str_to_u64")]
    pub weave_size: u64,
    #[serde(deserialize_with = "deserialize_str_to_u64")]
    pub block_size: u64,
}

/// NonceLImiterInput holds the nonce_limiter_info from the Arweave block header
#[derive(Clone, Debug, Deserialize)]
pub struct NonceLimiterInfo {
    #[serde(deserialize_with = "deserialize_base64url_bytes")]
    pub output: [u8; 32],
    pub global_step_number: u64,
    #[serde(deserialize_with = "deserialize_base64url_bytes")]
    pub seed: [u8; 48],
    #[serde(deserialize_with = "deserialize_base64url_bytes")]
    pub next_seed: [u8; 48],
    pub zone_upper_bound: u64,
    pub next_zone_upper_bound: u64,
    #[serde(deserialize_with = "deserialize_base64url_bytes")]
    pub prev_output: [u8; 32],
    pub last_step_checkpoints: Vec<String>,
    pub checkpoints: Vec<String>,
    #[serde(default, deserialize_with = "optional_string_to_u64")]
    pub vdf_difficulty: Option<u64>,
    #[serde(default, deserialize_with = "optional_string_to_u64")]
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
fn optional_string_to_u64<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
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
fn deserialize_str_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    s.parse::<u64>().map_err(serde::de::Error::custom)
}

pub fn deserialize_base64url_bytes<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DecodeHash,
{
    let s = String::deserialize(deserializer)?;
    T::from(s.as_str()).map_err(serde::de::Error::custom)
}
