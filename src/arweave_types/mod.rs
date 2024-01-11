use serde_derive::Deserialize;
use eyre::Error;
use uint::construct_uint;
use fixed_hash::construct_fixed_hash;
use serde::{de, de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

use self::decode_hash::DecodeHash;

pub mod decode_hash;

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
    #[serde(default)]
    pub chunk2_hash: Option<H256>,
    pub hash: H256,
    pub diff: U256,
    pub height: u64,
    pub indep_hash: H384,
    pub txs: Base64List,
    pub tags: Base64List,
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
    #[serde(deserialize_with = "parse_array_of_hashes_to_bytes")]
    pub last_step_checkpoints: Vec<H256>,
    #[serde(deserialize_with = "parse_array_of_hashes_to_bytes")]
    pub checkpoints: Vec<H256>,
    #[serde(default, with = "serde_option_u64_string")]
    pub vdf_difficulty: Option<u64>,
    #[serde(default, with = "serde_option_u64_string")]
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

/// serde helper method to convert an optional JSON `string` value to a `usize`
mod serde_option_u64_string {
    use serde::{self, Serializer, Deserializer, Deserialize};
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

//==============================================================================
// nonce serialization
//------------------------------------------------------------------------------
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