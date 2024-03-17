//! Contains a common set of types used across all of the `arweave_rs` modules.
//!
//! This module implements a single location where these types are managed,
//! making them easy to reference and maintain.

#![allow(clippy::assign_op_pattern)]
#![allow(clippy::non_canonical_clone_impl)]
use eyre::Error;
use fixed_hash::construct_fixed_hash;
use serde::{de, de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use serde_derive::Deserialize;
use std::{ops::Index, slice::SliceIndex, str::FromStr};
use uint::construct_uint;

/// Decodes hashes from `base64_url` encoded strings
pub mod decode;
pub mod consensus;
use self::decode::DecodeHash;

#[derive(Clone, Debug, Default, Deserialize)]
/// Stores deserialized fields from a JSON formatted Arweave block header.
pub struct ArweaveBlockHeader {
    /// The number of bytes added to the Arweave dataset by this block.
    #[serde(with = "stringify")]
    pub block_size: u64,

    /// `SHA-256` hash of the block_time_history log.
    pub block_time_history_hash: H256,

    /// If the block was produced with a `poa2` proof it will optionally include
    /// this field. Its value is the `SHA-256` hash of the `poa2` chunks bytes.
    #[serde(default, with = "optional_hash")]
    pub chunk2_hash: Option<H256>,

    /// `SHA-256` hash of the first PoA chunks (unencoded) bytes.
    pub chunk_hash: H256,

    /// The sum of the average number of hashes computed by the network to
    /// produce the past blocks including this one.
    pub cumulative_diff: U256,

    /// The total number of Winston emitted when the endowment was not
    /// sufficient to compensate mining.
    pub debt_supply: U256,
    pub denomination: U256,

    /// Difficulty threshold used to produce the current block.
    pub diff: U256,

    /// The proof of signing the same block several times or extending two equal forks.
    pub double_signing_proof: DoubleSigningProof,

    /// The solution hash for the block
    pub hash: H256,

    /// The Merkle root of the block index - the list of {`indep_hash`,
    /// `weave_size`, `tx_root`} triplets describing the past blocks excluding
    /// this one.
    pub hash_list_merkle: H384,

    /// A performance optimization for block validation.
    ///
    /// For a block to be valid its producer must have calculated a
    /// `solution_hash` that exceeds the difficulty setting of the network
    /// (indicated by the `diff` field in this struct). That `solution_hash` is
    /// a `SHA-256` hash of the combination of the `mining_hash` (named `H0` in
    /// the erlang reference implementation) and the `hash_preimage`.
    ///
    /// If the block includes both `poa` and `poa2` proof data the
    /// `hash_preimage` will be the hash of `poa2` chunk, otherwise it will be
    /// the hash of the `poa` chunk.
    /// This allows the initial Proof-of-Work validation to be done on a block
    /// header without having to load the `poa` (or possibly `poa2`) chunks
    /// bytes into memory and hash them.
    ///
    /// Used for initial solution validation without a poa data chunk.
    pub hash_preimage: H256,

    /// The block height.
    pub height: u64,

    /// The block identifier.
    pub indep_hash: H384,

    /// An additional multiplier for the transaction fees doubled every time the
    /// endowment pool becomes empty.
    pub kryder_plus_rate_multiplier: U256,

    /// A lock controlling the updates of kryder_plus_rate_multiplier. It is set
    /// to 1 after the update and back to 0 when the endowment pool is bigger
    /// than RESET_KRYDER_PLUS_LATCH_THRESHOLD (redenominated according to the
    /// denomination used at the time).
    pub kryder_plus_rate_multiplier_latch: U256,

    /// Unix timestamp of the last difficulty adjustment
    pub last_retarget: u64,

    /// Chunk index (weave offset) at which merkle_rebase_support is enabled.
    pub merkle_rebase_support_threshold: U256,

    /// The nonce used to produce the blocks solution_hash.
    pub nonce: Nonce,

    /// Nonce limiter / VDF info for this block.
    pub nonce_limiter_info: NonceLimiterInfo,

    /// Was used to allow a gradient transition to "packed chunks" in the v2.5
    /// upgrade. Today the threshold has reached 0 and all weave data is stored
    /// in chunks.
    #[serde(with = "stringify")]
    pub packing_2_5_threshold: u64,

    /// The partition number used with the `VDF` output to determine the recall
    /// ranges for `poa` and `poa2`.
    pub partition_number: u64,

    /// The first proof of access
    pub poa: PoaData,

    /// The second proof of access (empty when the solution was found with only
    /// one chunk).
    pub poa2: PoaData,

    pub previous_block: H384,
    pub previous_cumulative_diff: U256,
    /// The solution hash of the previous block in the chain.
    pub previous_solution_hash: H256,

    /// The estimated number of Winstons it costs the network to store one 
    /// gigabyte for one minute.
    pub price_per_gib_minute: U256,

    /// This field is awkwardly named, perhaps a holdover from older versions of
    /// consensus pre Arweave 2.5. It contains the index of the chunk used in
    /// the block solution (offset from the beginning of the weave). The
    /// `recall_byte` value must indicate a chunk index from either `poa2` or
    /// `poa`'s recall range.
    #[serde(with = "stringify")]
    pub recall_byte: u64,

    /// Absolute offset of the second recall offset
    #[serde(default)]
    pub recall_byte2: Option<U256>,

    /// The largest known redenomination height (0 means there were no 
    /// redenominations yet).
    pub redenomination_height: u64,

    /// The block reward in Winstons. The smallest unit of Arweave.
    #[serde(with = "stringify")]
    pub reward: u64,

    /// Address of the miner claiming the block reward, also used in validation
    /// of the poa and poa2 chunks as the packing key. 
    pub reward_addr: H256,

    /// The recursive hash of the network hash rates, block rewards, and mining 
    /// addresses of the latest ?REWARD_HISTORY_BLOCKS blocks.
    pub reward_history_hash: H256,
    
    /// {KeyType, PubKey} - the public key the block was signed with. The only 
    /// supported KeyType is currently {rsa, 65537}.
    pub reward_key: Base64,
    
    /// The number of Winston in the endowment pool.
    #[serde(with = "stringify")]
    pub reward_pool: u64,

    /// The updated estimation of the number of Winstons it costs the network to 
    /// store one gigabyte for one minute.
    pub scheduled_price_per_gib_minute: U256,

    /// The estimated USD to AR conversion rate scheduled to be used a bit 
    /// later, used to compute the necessary fee for the currently signed txs. 
    /// A tuple {Dividend, Divisor}. Used until the transition to dynamic 
    /// pricing is complete.
    pub scheduled_usd_to_ar_rate: USDToARRate,

    /// The block signature
    pub signature: Base64,

    /// The offset on the weave separating the data which has to be split 
    /// according to the stricter rules introduced in the fork 2.5 from the 
    /// historical data. The new rules require all chunk sizes to be 256 KiB 
    /// excluding the last or the only chunks of the corresponding transactions
    ///  and the second last chunks of their transactions where they exceed 256 
    /// KiB in size when combined with the following (last) chunk. Furthermore,
    /// the new chunks may not be smaller than their Merkle proofs unless they
    ///  are the last chunks. The motivation is to be able to put all chunks 
    /// into 256 KiB buckets. It makes all chunks equally attractive because 
    /// they have equal chances of being chosen as recall chunks. Moreover, 
    /// every chunk costs the same in terms of storage and computation 
    /// expenditure when packed (smaller chunks are simply padded before 
    /// packing).
    #[serde(with = "stringify")]
    pub strict_data_split_threshold: u64,

    /// A list of arbitrary key-value pairs. Keys and values are binaries.
    pub tags: Base64List,

    /// Unix timestamp of when the block was discovered/produced
    pub timestamp: u64,

    /// The Merkle root of the tree whose leaves are the data_roots of each of
    /// the transactions in the block.
    #[serde(default, with = "optional_hash")]
    pub tx_root: Option<H256>,

    /// List of transaction ids included in the block
    pub txs: Base64List,

    /// The estimated USD to AR conversion rate used in the pricing calculations.
	/// A tuple {Dividend, Divisor} (representing a fraction Dividend/Divisor)
	/// Used until the transition to dynamic pricing is complete.
    pub usd_to_ar_rate: USDToARRate,

    /// The root hash of the Merkle Patricia Tree containing all wallet (account)
    /// balances and the identifiers of the last transactions posted by them.
    pub wallet_list: H384,

    /// The total number of bytes in the weave dataset at this block height.
    #[serde(with = "stringify")]
    pub weave_size: u64,
}

#[derive(Default, Clone, Debug, Deserialize)]
/// Stores deserialized fields from a `poa` (Proof of Access) JSON
pub struct PoaData {
    pub option: String,
    pub tx_path: Base64,
    pub data_path: Base64,
    pub chunk: Base64,
}

#[derive(Default, Clone, Debug, Deserialize)]
/// Stores deserialized fields from a `Double Signing Proof` JSON
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
    pub preimage1: Option<H512>,
    #[serde(default)]
    pub sig2: Option<Base64>,
    #[serde(default)]
    pub cdiff2: Option<U256>,
    #[serde(default)]
    pub prev_cdiff2: Option<U256>,
    #[serde(default)]
    pub preimage2: Option<H512>,
}

/// Stores the `nonce_limiter_info` in the [`ArweaveBlockHeader`]
#[derive(Clone, Debug, Default, Deserialize)]
pub struct NonceLimiterInfo {
    /// The output of the latest step - the source of the entropy for the mining nonces.
    pub output: H256,
    /// The global sequence number of the nonce limiter step at which the block was found.
    pub global_step_number: u64,
    /// The hash of the latest block mined below the current reset line.
    pub seed: H384,
    /// The hash of the latest block mined below the future reset line.
    pub next_seed: H384,
    /// The weave size of the latest block mined below the current reset line.
    pub zone_upper_bound: u64,
    /// The weave size of the latest block mined below the future reset line.
    pub next_zone_upper_bound: u64,
    /// The output of the latest step of the previous block
    pub prev_output: H256,
    /// VDF_CHECKPOINT_COUNT_IN_STEP checkpoints from the most recent step in the nonce limiter process.
    pub last_step_checkpoints: H256List,
    /// A list of the output of each step of the nonce limiting process. Note: each step
    /// has VDF_CHECKPOINT_COUNT_IN_STEP checkpoints, the last of which is that step's output.
    /// This field would be more accurately named "steps" as checkpoints are between steps.
    pub checkpoints: H256List,
    /// The number of SHA2-256 iterations in a single VDF checkpoint. The protocol aims to keep the
	/// checkpoint calculation time to around 40ms by varying this parameter. Note: there are
	/// 25 checkpoints in a single VDF step - so the protocol aims to keep the step calculation at
	/// 1 second by varying this parameter.
    #[serde(default, with = "option_u64_stringify")]
    pub vdf_difficulty: Option<u64>,
    /// The VDF difficulty scheduled for to be applied after the next VDF reset line.
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

        match opt_val {
            Some(Value::String(s)) => s.parse::<u64>().map(Some).map_err(serde::de::Error::custom),
            Some(_) => Err(serde::de::Error::custom("Invalid type")),
            None => Ok(None),
        }
    }
}

//==============================================================================
// Optional<*Hash*> Type, support H256 and H384
//------------------------------------------------------------------------------
mod optional_hash {
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
/// A struct of [`u64`] which can be parsed from big-endian `base64_url` bytes
///
/// The nonce field in the [`ArweaveBlockHeader`] has distinct serialization
/// rules. Arweave nonces range from 0-(`RECALL_RANGE_SIZE`/`DATA_CHUNK_SIZE`).
/// Today, this is a value is between `0-400`.
///
/// Two bytes can store integer values between `0-511`. This is enough
/// to store the  nonce range, when `base64_url` encoded these bytes result in a
/// string of 1-3 characters of encoded data in the JSON.
pub struct Nonce(pub u64);

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

#[derive(Default, Debug, Clone, PartialEq)]
/// Stores deserialized values of the `usd_to_ar_rate` field in the [`ArweaveBlockHeader`]
pub struct USDToARRate(pub [u64; 2]);

impl Index<usize> for USDToARRate {
    type Output = u64;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

/// Implement Serialize for USDToARRate
impl Serialize for USDToARRate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Convert the u64 numbers in the array to strings
        let as_strings = vec![self.0[0].to_string(), self.0[1].to_string()];

        // Serialize the vector of strings
        as_strings.serialize(serializer)
    }
}

/// Implement Deserialize for USDToARRate
impl<'de> Deserialize<'de> for USDToARRate {
    fn deserialize<D>(deserializer: D) -> Result<USDToARRate, D::Error>
    where
        D: Deserializer<'de>,
    {
        // Deserialize `usd_to_ar_rate` json value as a vector of strings.
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
        Ok(USDToARRate([n1, n2]))
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
    /// A 256-bit hash type (32 bytes)
    pub struct H256(32);
}

impl H256 {
    pub fn to_vec(self) -> Vec<u8> {
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
        DecodeHash::from(&s).map_err(D::Error::custom)
    }
}

//==============================================================================
// H384 Type
//------------------------------------------------------------------------------
construct_fixed_hash! {
    /// A 384-bit hash type (48 bytes)
    pub struct H384(48);
}

impl H384 {
    pub fn to_vec(self) -> Vec<u8> {
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
        DecodeHash::from(&s).map_err(D::Error::custom)
    }
}

//==============================================================================
// H512 Type
//------------------------------------------------------------------------------
construct_fixed_hash! {
    /// A 512-bit hash type (48 bytes)
    pub struct H512(64);
}

impl H512 {
    pub fn to_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

// Implement Serialize for H512
impl Serialize for H512 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(base64_url::encode(self.as_bytes()).as_str())
    }
}

// Implement Deserialize for H512
impl<'de> Deserialize<'de> for H512 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        DecodeHash::from(&s).map_err(D::Error::custom)
    }
}

//==============================================================================
// Base64 Type
//------------------------------------------------------------------------------
/// A struct of [`Vec<u8>`] used for all `base64_url` encoded fields

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Base64(pub Vec<u8>);

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

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
/// A struct of [`Vec<Base64>`] used for lists of [`Base64`] encoded elements
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
/// A struct of [`Vec<H256>`] used for lists of [`Base64`] encoded hashes
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

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
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
