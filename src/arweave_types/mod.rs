use eyre::Error;
use fixed_hash::construct_fixed_hash;
use serde::{de, de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use serde_derive::Deserialize;
use std::{ops::Index, slice::SliceIndex, str::FromStr};
use uint::construct_uint;

use self::decode::DecodeHash;
pub mod decode;

#[derive(Clone, Debug, Default, Deserialize)]
pub struct ArweaveBlockHeader {
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
    pub price_per_gib_minute: U256,
    pub scheduled_price_per_gib_minute: U256,
    pub reward_history_hash: H256,
    pub debt_supply: U256,
    pub kryder_plus_rate_multiplier: U256,
    pub kryder_plus_rate_multiplier_latch: U256,
    pub denomination: U256,
    pub redenomination_height: u64,
    pub previous_block: H384,
    pub timestamp: u64,
    pub last_retarget: u64,
    #[serde(default)]
    pub recall_byte2: Option<U256>,
    #[serde(default, with = "serde_option_encode_hash")]
    pub chunk2_hash: Option<H256>,
    pub hash: H256,
    pub diff: U256,
    pub height: u64,
    pub indep_hash: H384,
    pub txs: Base64List,
    pub tags: Base64List,
    pub nonce: Nonce,
    #[serde(default, with = "serde_option_encode_hash")]
    pub tx_root: Option<H256>,
    pub wallet_list: H384,
    pub reward_addr: H256,
    #[serde(with = "stringify")]
    pub reward_pool: u64,
    #[serde(with = "stringify")]
    pub weave_size: u64,
    #[serde(with = "stringify")]
    pub block_size: u64,
    pub cumulative_diff: U256,
    pub double_signing_proof: DoubleSigningProof,
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
    #[serde(default)]
    pub pub_key: Option<Base64>,
    #[serde(default)]
    pub sig1: Option<Base64>,
    #[serde(default)]
    pub cdiff1: Option<U256>,
    #[serde(default)]
    pub prev_cdiff1: Option<U256>,
    #[serde(default)]
    pub preimage1: Option<H256>,
    #[serde(default)]
    pub sig2: Option<Base64>,
    #[serde(default)]
    pub cdiff2: Option<U256>,
    #[serde(default)]
    pub prev_cdiff2: Option<U256>,
    #[serde(default)]
    pub preimage2: Option<H256>,
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
    pub last_step_checkpoints: H256List,
    pub checkpoints: H256List,
    #[serde(default, with = "option_u64_stringify")]
    pub vdf_difficulty: Option<u64>,
    #[serde(default, with = "option_u64_stringify")]
    pub next_vdf_difficulty: Option<u64>,
}

//==============================================================================
// String to integer type
//------------------------------------------------------------------------------
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

//==============================================================================
// Option<u64>
//------------------------------------------------------------------------------
/// where u64 is represented as a string in the json
mod option_u64_stringify {
    use serde::{self, Deserialize, Deserializer, Serializer};
    use serde_json::Value;

    #[allow(dead_code)]
    pub fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(number) => serializer.serialize_str(&number.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt_val: Option<Value> = Option::deserialize(deserializer)?;

        let ret = match opt_val {
            Some(Value::String(s)) => s.parse::<u64>().map(Some).map_err(serde::de::Error::custom),
            Some(_) => Err(serde::de::Error::custom("Invalid type")),
            None => Ok(None),
        };
        ret
    }
}

//==============================================================================
// Optional<*Hash*> Type, support H256 and H384
//------------------------------------------------------------------------------
mod serde_option_encode_hash {
    use serde::{self, Deserialize, Deserializer, Serializer};

    use super::{decode::DecodeHash, H256};

    #[allow(dead_code)]
    pub fn serialize<S>(value: &Option<H256>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(hash_bytes) => serializer.serialize_str(&base64_url::encode(&hash_bytes.0)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
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
}

//==============================================================================
// Nonce Type
//------------------------------------------------------------------------------

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Nonce(pub u64);

/// The nonce field in the ArweaveBlockHeader is unique. Arweave Nonces can
/// range from 0-(RECALL_RANGE_SIZE/DATA_CHUNK_SIZE). Today this is a value 
/// is between 0-400. Two bytes can store values between 0-511. This is enough 
/// to store the  nonce range, when encoded to base64_url this encodes to a
/// string of 1-3 bytes of base64_url_encoded data in the JSON.
impl Nonce {
    fn to_encoded_bytes(&self) -> String {
        let bytes = self.0.to_be_bytes();
        let bytes = trim_leading_zero_bytes(&bytes);
        base64_url::encode(&bytes)
    }
}

/// Implement Serialize for Nonce
impl Serialize for Nonce {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_encoded_bytes().as_str())
    }
}

/// Implement Deserialize for Nonce
impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Nonce, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = base64_url::decode(&s).map_err(serde::de::Error::custom)?;
        Ok(Nonce(
            vec_to_u64_be(&bytes).map_err(serde::de::Error::custom)?,
        ))
    }
}

fn trim_leading_zero_bytes(bytes: &[u8]) -> &[u8] {
    let mut non_zero_index = bytes.iter().position(|&x| x != 0).unwrap_or(bytes.len());
    non_zero_index = std::cmp::min(non_zero_index, bytes.len() - 1);
    &bytes[non_zero_index..]
}

/// While only < 4 bytes are expected, it doesn't hurt to support one more.
fn vec_to_u64_be(bytes: &Vec<u8>) -> Result<u64, &'static str> {
    match bytes.len() {
        1 => Ok(bytes[0] as u64),
        2 => Ok(u16::from_be_bytes([bytes[0], bytes[1]]) as u64),
        3 => {
            let mut arr = [0u8; 4];
            arr[1..4].copy_from_slice(bytes);
            Ok(u32::from_be_bytes(arr) as u64)
        }
        _ => Err("Vec<u8> must have 1, 2, or 3 bytes and no more"),
    }
}

//==============================================================================
// USD to AR rate
//------------------------------------------------------------------------------

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

//==============================================================================
// U256 Type
//------------------------------------------------------------------------------
construct_uint! {
    /// 256-bit unsigned integer.
    #[cfg_attr(feature = "scale-info", derive(TypeInfo))]
    pub struct U256(4);
}

/// Implement Serialize for U256
impl Serialize for U256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

/// Implement Deserialize for U256
impl<'de> Deserialize<'de> for U256 {
    fn deserialize<D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        U256::from_dec_str(&s).map_err(serde::de::Error::custom)
    }
}

//==============================================================================
// H256 Type
//------------------------------------------------------------------------------
construct_fixed_hash! {
    pub struct H256(32);
}

impl H256 {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// Implement Serialize for H256
impl Serialize for H256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(base64_url::encode(self.as_bytes()).as_str())
    }
}

// Implement Deserialize for H256
impl<'de> Deserialize<'de> for H256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        DecodeHash::from(&s).map_err(|e| D::Error::custom(format!("{}", e)))
    }
}

//==============================================================================
// H384 Type
//------------------------------------------------------------------------------
construct_fixed_hash! {
    pub struct H384(48);
}

impl H384 {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// Implement Serialize for H384
impl Serialize for H384 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(base64_url::encode(self.as_bytes()).as_str())
    }
}

// Implement Deserialize for H384
impl<'de> Deserialize<'de> for H384 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        DecodeHash::from(&s).map_err(|e| D::Error::custom(format!("{}", e)))
    }
}

//==============================================================================
// Base64 Type
//------------------------------------------------------------------------------
/// A struct of [`Vec<u8>`] used for all Base64Url encoded fields

#[derive(Debug, Clone, PartialEq)]
pub struct Base64(pub Vec<u8>);

impl Default for Base64 {
    fn default() -> Self {
        Base64(vec![])
    }
}

impl std::fmt::Display for Base64 {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let string = base64_url::encode(&self.0);
        write!(f, "{}", string)
    }
}

/// Converts a base64url encoded string to a Base64 struct.
impl FromStr for Base64 {
    type Err = base64_url::base64::DecodeError;
    fn from_str(str: &str) -> Result<Self, base64_url::base64::DecodeError> {
        let result = base64_url::decode(str)?;
        Ok(Self(result))
    }
}

impl Base64 {
    pub fn from_utf8_str(str: &str) -> Result<Self, Error> {
        Ok(Self(str.as_bytes().to_vec()))
    }
    pub fn to_utf8_string(&self) -> Result<String, Error> {
        Ok(String::from_utf8(self.0.clone())?)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    pub fn split_at(&self, mid: usize) -> (&[u8], &[u8]) {
        self.0.split_at(mid)
    }
}

impl Serialize for Base64 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format!("{}", &self))
    }
}

impl<'de> Deserialize<'de> for Base64 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Vis;
        impl serde::de::Visitor<'_> for Vis {
            type Value = Base64;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a base64 string")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                base64_url::decode(v)
                    .map(Base64)
                    .map_err(|_| de::Error::custom("failed to decode base64 string"))
            }
        }
        deserializer.deserialize_str(Vis)
    }
}

//==============================================================================
// Base64List Type
//------------------------------------------------------------------------------
/// A struct of [`Vec<Base64>`] used for arrays/lists of Base64 elements
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Base64List(pub Vec<Base64>);

// Implement Serialize for Base64Array
impl Serialize for Base64List {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize self.0 (Vec<Base64>) directly
        self.0.serialize(serializer)
    }
}

// Implement Deserialize for Base64Array
impl<'de> Deserialize<'de> for Base64List {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize a Vec<Base64> and then wrap it in Base64Array
        Vec::<Base64>::deserialize(deserializer).map(Base64List)
    }
}

//==============================================================================
// H256List Type
//------------------------------------------------------------------------------
/// A struct of [`Vec<H256>`] used for arrays/lists of Base64 encoded hashes
#[derive(Debug, Default, Clone, PartialEq)]
pub struct H256List(pub Vec<H256>);

impl H256List {
    pub fn push(&mut self, value: H256) {
        self.0.push(value)
    }

    pub fn reverse(&mut self) {
        self.0.reverse()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn iter(&self) -> std::slice::Iter<'_, H256> {
        self.0.iter()
    }

    pub fn get(&self, index: usize) -> Option<&<usize as SliceIndex<[H256]>>::Output> {
        self.0.get(index)
    }
}

impl Index<usize> for H256List {
    type Output = H256;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl PartialEq<Vec<H256>> for H256List {
    fn eq(&self, other: &Vec<H256>) -> bool {
        &self.0 == other
    }
}

impl PartialEq<H256List> for Vec<H256> {
    fn eq(&self, other: &H256List) -> bool {
        self == &other.0
    }
}

// Implement Serialize for H256 base64url encoded Array
impl Serialize for H256List {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize self.0 (Vec<Base64>) directly
        self.0.serialize(serializer)
    }
}

// Implement Deserialize for H256 base64url encoded Array
impl<'de> Deserialize<'de> for H256List {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize a Vec<Base64> and then wrap it in Base64Array
        Vec::<H256>::deserialize(deserializer).map(H256List)
    }
}
