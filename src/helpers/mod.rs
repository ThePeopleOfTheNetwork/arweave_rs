use eyre::Error;
use fixed_hash::construct_fixed_hash;
use serde::{de, de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;
use uint::construct_uint;

pub mod consensus;

construct_uint! {
    /// 256-bit unsigned integer.
    #[cfg_attr(feature = "scale-info", derive(TypeInfo))]
    pub struct U256(4);
}

construct_fixed_hash! {
    pub struct H256(32);
}

construct_fixed_hash! {
    pub struct H384(48);
}

impl H256 {
    fn to_vec(&self) -> Vec<u8> {
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

// Implement Serialize for U256
impl Serialize for U256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl<'de> Deserialize<'de> for U256 {
    fn deserialize<D>(deserializer: D) -> Result<U256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        U256::from_dec_str(&s).map_err(serde::de::Error::custom)
    }
}

/// A struct of [`Vec<u8>`] used for all data and address fields.
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

/// Traits to decode base64_url encoded hashes into their corresponding bytes
pub trait DecodeHash: Sized {
    fn from(base64_url_string: &str) -> Result<Self, String>;
    fn empty() -> Self;
}

impl DecodeHash for H256 {
    fn from(base64_url_string: &str) -> Result<Self, String> {
        base64_url::decode(base64_url_string)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                H256::from_slice(bytes.as_slice())
                    .try_into()
                    .map_err(|_| format!("Length mismatch 32 - {base64_url_string}"))
            })
    }

    fn empty() -> Self {
        H256::zero()
    }
}

impl DecodeHash for H384 {
    fn from(base64_url_string: &str) -> Result<Self, String> {
        base64_url::decode(base64_url_string)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                H384::from_slice(bytes.as_slice())
                    .try_into()
                    .map_err(|_| format!("Length mismatch 32 - {base64_url_string}"))
            })
    }

    fn empty() -> Self {
        H384::zero()
    }
}

impl DecodeHash for Option<H256> {
    fn from(base64_url_string: &str) -> Result<Self, String> {
        if base64_url_string.is_empty() {
            Ok(None)
        } else {
            base64_url::decode(base64_url_string)
                .map_err(|e| e.to_string())
                .and_then(|bytes| {
                    H256::from_slice(bytes.as_slice())
                        .try_into()
                        .map_err(|_| format!("Length mismatch 32 - {base64_url_string}"))
                })
        }
    }

    fn empty() -> Self {
        None
    }
}

impl DecodeHash for [u8; 32] {
    fn from(base64_url_string: &str) -> Result<Self, String> {
        base64_url::decode(base64_url_string)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| format!("Length mismatch 32 - {base64_url_string}"))
            })
    }

    fn empty() -> Self {
        [0u8; 32]
    }
}

impl DecodeHash for Option<[u8; 32]> {
    fn from(base64_url_string: &str) -> Result<Self, String> {
        if base64_url_string.is_empty() {
            Ok(None)
        } else {
            base64_url::decode(base64_url_string)
                .map_err(|e| e.to_string())
                .and_then(|bytes| {
                    bytes
                        .try_into()
                        .map(Some)
                        .map_err(|_| format!("Length mismatch: expected 32 - {base64_url_string}"))
                })
        }
    }

    fn empty() -> Self {
        None
    }
}

impl DecodeHash for [u8; 48] {
    fn from(base64_url_string: &str) -> Result<Self, String> {
        base64_url::decode(base64_url_string)
            .map_err(|e| e.to_string())
            .and_then(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| format!("Length mismatch 48 - {base64_url_string}"))
            })
    }
    fn empty() -> Self {
        [0u8; 48]
    }
}
