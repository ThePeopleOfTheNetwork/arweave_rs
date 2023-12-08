use serde::{Deserialize, Deserializer};
use serde_derive::Deserialize;
use serde_json::Value;

use crate::helpers::{DecodeHash, U256};

#[derive(Clone, Debug, Deserialize)]
pub struct ArweaveBlockHeader {
    #[serde(deserialize_with = "parse_string_to_u256")]
    pub merkle_rebase_support_threshold:U256,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub chunk_hash: [u8; 32],
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub block_time_history_hash: [u8;32],
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub hash_preimage: [u8; 32],
    #[serde(deserialize_with = "parse_string_to_u64")]
    pub recall_byte: u64,
    #[serde(deserialize_with = "parse_string_to_u64")]
    pub reward: u64,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub previous_solution_hash: [u8; 32],
    pub partition_number: u64,
    pub nonce_limiter_info: NonceLimiterInfo,
    pub poa2: PoaData,
    #[serde(deserialize_with = "base64_string_to_bytes")]
    pub signature: Vec<u8>,
    #[serde(deserialize_with = "base64_string_to_bytes")]
    pub reward_key: Vec<u8>,
    #[serde(deserialize_with = "parse_string_to_u256")]
    pub price_per_gib_minute: U256,
    #[serde(deserialize_with = "parse_string_to_u256")]
    pub scheduled_price_per_gib_minute: U256,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub reward_history_hash: [u8; 32],
    #[serde(deserialize_with = "parse_string_to_u256")]
    pub debt_supply: U256,
    #[serde(deserialize_with = "parse_string_to_u256")]
    pub kryder_plus_rate_multiplier: U256,
    #[serde(deserialize_with = "parse_string_to_u256")]
    pub kryder_plus_rate_multiplier_latch: U256,
    #[serde(deserialize_with = "parse_string_to_u256")]
    pub denomination: U256,
    pub redenomination_height: u64,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub previous_block: [u8; 48],
    pub timestamp: u64,
    pub last_retarget: u64,
    #[serde(default, deserialize_with = "optional_parse_string_to_U256")]
    pub recall_byte2: Option<U256>,
    #[serde(default, deserialize_with = "decode_hash_to_bytes")]
    pub chunk2_hash: Option<[u8; 32]>,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub hash: [u8; 32],
    #[serde(deserialize_with = "parse_string_to_u256")]
    pub diff: U256,
    pub height: u64,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub indep_hash: [u8; 48],
    #[serde(deserialize_with = "parse_array_of_base64_to_bytes")]
    pub txs: Vec<Vec<u8>>,
    #[serde(deserialize_with = "base64_string_to_bytes")]
    pub nonce: Vec<u8>,
    #[serde(default, deserialize_with = "decode_hash_to_bytes")]
    pub tx_root: Option<[u8; 32]>,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub wallet_list: [u8; 48],
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub reward_addr: [u8; 32],
    #[serde(deserialize_with = "parse_array_of_base64_to_bytes")]
    pub tags: Vec<Vec<u8>>,
    #[serde(deserialize_with = "parse_string_to_u64")]
    pub reward_pool: u64,
    #[serde(deserialize_with = "parse_string_to_u64")]
    pub weave_size: u64,
    #[serde(deserialize_with = "parse_string_to_u64")]
    pub block_size: u64,
    #[serde(default, deserialize_with = "parse_string_to_u256")]
    pub cumulative_diff: U256,
    pub double_signing_proof: DoubleSigningProof,
    #[serde(deserialize_with = "parse_string_to_u256")]
    pub previous_cumulative_diff: U256,
    #[serde(deserialize_with = "parse_usd_to_ar_rate")]
    pub usd_to_ar_rate: [u64; 2],
    #[serde(deserialize_with = "parse_usd_to_ar_rate")]
    pub scheduled_usd_to_ar_rate: [u64; 2],
   
   
    #[serde(deserialize_with = "parse_string_to_u64")]
    pub packing_2_5_threshold: u64,
    #[serde(deserialize_with = "parse_string_to_u64")]
    pub strict_data_split_threshold: u64,
    #[serde(deserialize_with = "decode_hash_to_bytes")]
    pub hash_list_merkle: [u8; 48],
    pub poa: PoaData,
   
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
            diff: Default::default(),
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
            wallet_list: [0u8; 48],
            hash_list_merkle: [0u8; 48],
            packing_2_5_threshold: Default::default(),
            usd_to_ar_rate: Default::default(),
            scheduled_usd_to_ar_rate: Default::default(),
            reward_history_hash: Default::default(),
            debt_supply: U256::zero(),
            strict_data_split_threshold: Default::default(),
            txs: Default::default(),
            tags: Default::default(),
            reward: Default::default(),
            reward_key: Default::default(),
            previous_solution_hash: Default::default(),
            price_per_gib_minute: Default::default(),
            scheduled_price_per_gib_minute: Default::default(),
            kryder_plus_rate_multiplier: Default::default(),
            kryder_plus_rate_multiplier_latch: Default::default(),
            denomination: Default::default(),
            redenomination_height: Default::default(),
            merkle_rebase_support_threshold: Default::default(),
            block_time_history_hash:Default::default(),
            signature: Default::default(),
            previous_cumulative_diff:  Default::default(),
            double_signing_proof: Default::default(),
            indep_hash: [0u8; 48],
        }
    }
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct PoaData {
    pub option: String,
    #[serde(deserialize_with = "base64_string_to_bytes")]
    pub tx_path: Vec<u8>,
    #[serde(deserialize_with = "base64_string_to_bytes")]
    pub data_path: Vec<u8>,
    #[serde(deserialize_with = "base64_string_to_bytes")]
    pub chunk: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct DoubleSigningProof {
    #[serde(default, deserialize_with = "optional_base64_string_to_bytes")]
    pub pub_key: Option<Vec<u8>>,
     #[serde(default, deserialize_with = "optional_base64_string_to_bytes")]
    pub sig1: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_parse_string_to_U256")]
    pub cdiff1: Option<U256>,
    #[serde(default, deserialize_with = "optional_parse_string_to_U256")]
    pub prev_cdiff1:Option<U256>,
    #[serde(default, deserialize_with = "optional_decode_hash_to_bytes")]
    pub preimage1: Option<[u8;32]>,
     #[serde(default, deserialize_with = "optional_base64_string_to_bytes")]
    pub sig2: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_parse_string_to_U256")]
    pub cdiff2:Option<U256>,
    #[serde(default, deserialize_with = "optional_parse_string_to_U256")]
    pub prev_cdiff2:Option<U256>,
    #[serde(default, deserialize_with = "optional_decode_hash_to_bytes")]
    pub preimage2: Option<[u8;32]>
}

impl Default for DoubleSigningProof {
    fn default() -> Self {
        DoubleSigningProof {
            pub_key: Default::default(),
            sig1: Default::default(),
            cdiff1: Default::default(),
            prev_cdiff1: Default::default(),
            preimage1: Default::default(),
            sig2: Default::default(),
            cdiff2: Default::default(),
            prev_cdiff2: Default::default(),
            preimage2: Default::default(),
        }
    }
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
    #[serde(deserialize_with = "parse_array_of_hashes_to_bytes")]
    pub last_step_checkpoints: Vec<[u8; 32]>,
    #[serde(deserialize_with = "parse_array_of_hashes_to_bytes")]
    pub checkpoints: Vec<[u8; 32]>,
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

pub fn optional_decode_hash_to_bytes<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DecodeHash,
{
    let opt_val: Option<Value> =
    Option::deserialize(deserializer).map_err(serde::de::Error::custom)?;

    match opt_val {
        Some(Value::String(s)) => T::from(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(_) => Err(serde::de::Error::custom("Invalid optional hash")),
        None => Ok(None),
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

fn optional_parse_string_to_U256<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
where
    D: Deserializer<'de>,
{
    let opt_val: Option<Value> =
    Option::deserialize(deserializer).map_err(serde::de::Error::custom)?;

    match opt_val {
        Some(Value::String(s)) => U256::from_dec_str(&s)
            .map(Some)
            .map_err(serde::de::Error::custom),
        Some(_) => Err(serde::de::Error::custom("Invalid U256 type")),
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

fn parse_usd_to_ar_rate<'de, D>(deserializer: D) -> Result<[u64; 2], D::Error>
where
    D: Deserializer<'de>,
{
    // Deserialize `usd_to_ar_rate` as a vector of strings.
    let vec: Vec<String> = Deserialize::deserialize(deserializer)?;

    // Try to convert the vector of strings to a vector of `u64`.
    let mut numbers = vec.iter().map(|s| s.parse::<u64>());

    // Extract two numbers from the iterator to create an array.
    let n1 = numbers
        .next()
        .ok_or_else(|| serde::de::Error::custom("Invalid first number"))?
        .unwrap();

    let n2 = numbers
        .next()
        .ok_or_else(|| serde::de::Error::custom("Invalid second number"))?
        .unwrap();

    // Return the array of numbers, or an error if parsing failed.
    Ok([n1, n2])
}

fn parse_array_of_hashes_to_bytes<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Base64VecVisitor;

    impl<'de> serde::de::Visitor<'de> for Base64VecVisitor {
        type Value = Vec<[u8; 32]>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a base64 URL encoded string")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<[u8; 32]>, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut buffer = Vec::new();

            while let Some(elem) = seq.next_element::<String>()? {
                let bytes: [u8; 32] = DecodeHash::from(&elem).map_err(serde::de::Error::custom)?;
                buffer.push(bytes);
            }

            Ok(buffer)
        }
    }

    deserializer.deserialize_seq(Base64VecVisitor)
}

fn parse_array_of_base64_to_bytes<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Base64VecVisitor;

    impl<'de> serde::de::Visitor<'de> for Base64VecVisitor {
        type Value = Vec<Vec<u8>>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a base64 URL encoded string")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<Vec<u8>>, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut buffer: Vec<Vec<u8>> = Vec::new();
            while let Some(elem) = seq.next_element::<String>()? {
                let mut bytes = base64_url::decode(&elem)
                    .map(Some)
                    .map_err(serde::de::Error::custom)?;
                buffer.push(bytes.expect("base64url encoded bytes can be parsed"));
            }

            Ok(buffer)
        }
    }

    deserializer.deserialize_seq(Base64VecVisitor)
}
