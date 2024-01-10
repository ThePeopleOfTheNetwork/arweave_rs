use primitive_types::U256;
use serde::{Deserialize, Deserializer};
use serde_derive::Deserialize;
use serde_json::Value;

use crate::helpers::{DecodeHash, hashes::{H256, H384}, Base64};

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ArweaveBlockHeader {
    #[serde(deserialize_with = "string_to_u256")]
    pub merkle_rebase_support_threshold: U256,
    pub chunk_hash: H256,
    pub block_time_history_hash: H256,
    pub hash_preimage: H256,
    #[serde(with = "stringify")]
    pub recall_byte: u64,
    #[serde(with = "stringify")]
    pub reward: u64,
    pub previous_solution_hash: H256,
    pub partition_number: u64,
    pub nonce_limiter_info: NonceLimiterInfo,
    pub poa2: PoaData,
    pub signature: Base64,
    pub reward_key: Base64,
    #[serde(deserialize_with = "string_to_u256")]
    pub price_per_gib_minute: U256,
    #[serde(deserialize_with = "string_to_u256")]
    pub scheduled_price_per_gib_minute: U256,
    pub reward_history_hash: H256,
    #[serde(deserialize_with = "string_to_u256")]
    pub debt_supply: U256,
    #[serde(deserialize_with = "string_to_u256")]
    pub kryder_plus_rate_multiplier: U256,
    #[serde(deserialize_with = "string_to_u256")]
    pub kryder_plus_rate_multiplier_latch: U256,
    #[serde(deserialize_with = "string_to_u256")]
    pub denomination: U256,
    pub redenomination_height: u64,
    pub previous_block: H384,
    pub timestamp: u64,
    pub last_retarget: u64,
    #[serde(default, deserialize_with = "optional_string_to_u256")]
    pub recall_byte2: Option<U256>,
    #[serde(default, deserialize_with = "decode_to_bytes")]
    pub chunk2_hash: Option<H256>,
    pub hash: H256,
    #[serde(deserialize_with = "string_to_u256")]
    pub diff: U256,
    pub height: u64,
    pub indep_hash: H384,
    #[serde(deserialize_with = "array_of_base64_to_bytes")]
    pub txs: Vec<Vec<u8>>,
    #[serde(deserialize_with = "array_of_base64_to_bytes")]
    pub tags: Vec<Vec<u8>>,
    #[serde(deserialize_with = "decode_nonce_u64")]
    pub nonce: u64,
    #[serde(default, deserialize_with = "decode_to_bytes")]
    pub tx_root: Option<H256>,
    pub wallet_list: H384,
    pub reward_addr: H256,
    #[serde(with = "stringify")]
    pub reward_pool: u64,
    #[serde(with = "stringify")]
    pub weave_size: u64,
    #[serde(with = "stringify")]
    pub block_size: u64,
    #[serde(default, deserialize_with = "string_to_u256")]
    pub cumulative_diff: U256,
    pub double_signing_proof: DoubleSigningProof,
    #[serde(deserialize_with = "string_to_u256")]
    pub previous_cumulative_diff: U256,
    #[serde(deserialize_with = "parse_usd_to_ar_rate")]
    pub usd_to_ar_rate: [u64; 2],
    #[serde(deserialize_with = "parse_usd_to_ar_rate")]
    pub scheduled_usd_to_ar_rate: [u64; 2],
    #[serde(with = "stringify")]
    pub packing_2_5_threshold: u64,
    #[serde(with = "stringify")]
    pub strict_data_split_threshold: u64,
    pub hash_list_merkle: H384,
    pub poa: PoaData,
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct PoaData {
    pub option: String,
    pub tx_path: Base64,
    pub data_path: Base64,
    pub chunk: Base64,
}

#[derive(Default, Clone, Debug, Deserialize)]
pub struct DoubleSigningProof {
    #[serde(default, deserialize_with = "optional_base64_string_to_bytes")]
    pub pub_key: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_base64_string_to_bytes")]
    pub sig1: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_string_to_u256")]
    pub cdiff1: Option<U256>,
    #[serde(default, deserialize_with = "optional_string_to_u256")]
    pub prev_cdiff1: Option<U256>,
    #[serde(default, deserialize_with = "optional_decode_to_bytes")]
    pub preimage1: Option<[u8; 32]>,
    #[serde(default, deserialize_with = "optional_base64_string_to_bytes")]
    pub sig2: Option<Vec<u8>>,
    #[serde(default, deserialize_with = "optional_string_to_u256")]
    pub cdiff2: Option<U256>,
    #[serde(default, deserialize_with = "optional_string_to_u256")]
    pub prev_cdiff2: Option<U256>,
    #[serde(default, deserialize_with = "optional_decode_to_bytes")]
    pub preimage2: Option<[u8; 32]>,
}

/// NonceLImiterInput holds the nonce_limiter_info from the Arweave block header
#[derive(Clone, Debug, Default, Deserialize)]
pub struct NonceLimiterInfo {
    pub output: H256,
    pub global_step_number: u64,
    pub seed: H384,
    pub next_seed: H384,
    pub zone_upper_bound: u64,
    pub next_zone_upper_bound: u64,
    pub prev_output: H256,
    #[serde(deserialize_with = "parse_array_of_hashes_to_bytes")]
    pub last_step_checkpoints: Vec<H256>,
    #[serde(deserialize_with = "parse_array_of_hashes_to_bytes")]
    pub checkpoints: Vec<H256>,
    #[serde(default, deserialize_with = "parse_optional_string_to_u64")]
    pub vdf_difficulty: Option<u64>,
    #[serde(default, deserialize_with = "parse_optional_string_to_u64")]
    pub next_vdf_difficulty: Option<u64>,
}

/// Serializes and deserializes numbers represented as Strings.
pub mod stringify {
    use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: std::str::FromStr,
        <T as std::str::FromStr>::Err: std::fmt::Display,
    {
        String::deserialize(deserializer)?
            .parse::<T>()
            .map_err(|e| D::Error::custom(format!("{}", e)))
    }

    pub fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: std::fmt::Display,
    {
        format!("{}", value).serialize(serializer)
    }
}
// -------

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
fn string_to_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    s.parse::<u64>().map_err(serde::de::Error::custom)
}

fn string_to_u256<'de, D>(deserializer: D) -> Result<U256, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    U256::from_dec_str(&s).map_err(serde::de::Error::custom)
}

pub fn decode_to_bytes<'de, D, T>(deserializer: D) -> Result<T, D::Error>
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

pub fn optional_decode_to_bytes<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DecodeHash,
{
    let opt_val: Option<Value> =
        Option::deserialize(deserializer).map_err(serde::de::Error::custom)?;

    match opt_val {
        Some(Value::String(s)) => T::from(&s).map(Some).map_err(serde::de::Error::custom),
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

fn optional_string_to_u256<'de, D>(deserializer: D) -> Result<Option<U256>, D::Error>
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

fn parse_array_of_hashes_to_bytes<'de, D>(deserializer: D) -> Result<Vec<H256>, D::Error>
where
    D: Deserializer<'de>,
{
    struct Base64VecVisitor;

    impl<'de> serde::de::Visitor<'de> for Base64VecVisitor {
        type Value = Vec<H256>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
            formatter.write_str("a base64 URL encoded string")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Vec<H256>, A::Error>
        where
            A: serde::de::SeqAccess<'de>,
        {
            let mut buffer = Vec::new();

            while let Some(elem) = seq.next_element::<String>()? {
                let bytes: H256 = DecodeHash::from(&elem).map_err(serde::de::Error::custom)?;
                buffer.push(bytes);
            }

            Ok(buffer)
        }
    }

    deserializer.deserialize_seq(Base64VecVisitor)
}

fn array_of_base64_to_bytes<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
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
                let bytes = base64_url::decode(&elem)
                    .map(Some)
                    .map_err(serde::de::Error::custom)?;
                buffer.push(bytes.expect("base64url encoded bytes can be parsed"));
            }

            Ok(buffer)
        }
    }

    deserializer.deserialize_seq(Base64VecVisitor)
}

fn decode_nonce_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let bytes = base64_url::decode(&s).map_err(serde::de::Error::custom)?;
    vec_to_u64_be(&bytes).map_err(serde::de::Error::custom)
}

fn vec_to_u64_be(bytes: &Vec<u8>) -> Result<u64, &'static str> {
    match bytes.len() {
        1 => Ok(bytes[0] as u64),
        2 => Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as u64),
        3 => {
            let mut arr = [0u8; 4];
            arr[1..4].copy_from_slice(bytes);
            Ok(u32::from_be_bytes(arr) as u64)
        }
        4 => {
            let mut arr = [0u8; 4];
            arr[0..4].copy_from_slice(bytes);
            Ok(u32::from_be_bytes(arr) as u64)
        }
        _ => Err("Vec<u8> must have 1, 2, 3, or 4 bytes"),
    }
}
