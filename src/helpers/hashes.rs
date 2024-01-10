use primitive_types::{H256 as _H256, H384 as _H384};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Index, IndexMut, RangeTo, RangeFull};
use super::DecodeHash;

// =============================================================================
// Wrapper type for H256
// -----------------------------------------------------------------------------
#[derive(Default, Copy, Debug, Clone, PartialEq)]
pub struct H256(_H256);

impl H256 {
    pub fn from_slice(src: &[u8]) -> Self {
        H256(_H256::from_slice(src))
    }

    pub fn zero() -> Self {
        H256(_H256::zero())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn as_sized_array(&self) -> [u8;32] {
        self.0.as_bytes().try_into().expect("32 byte hash")
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl AsRef<[u8]> for H256 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for H256 {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl From<[u8; 32]> for H256 {
    fn from(bytes: [u8; 32]) -> Self {
        H256(_H256::from(bytes))
    }
}

impl Index<usize> for H256 {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl Index<std::ops::Range<usize>> for H256 {
    type Output = [u8];

    fn index(&self, index: std::ops::Range<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<std::ops::Range<usize>> for H256 {
    fn index_mut(&mut self, index: std::ops::Range<usize>) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl Index<RangeTo<usize>> for H256 {
    type Output = [u8];

    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl Index<RangeFull> for H256 {
    type Output = [u8];

    fn index(&self, _: RangeFull) -> &Self::Output {
        &self.0[..]
    }
}

impl IndexMut<RangeFull> for H256 {
    fn index_mut(&mut self, _: RangeFull) -> &mut Self::Output {
        &mut self.0[..]
    }
}

// Implement Serialize for H256Wrapper
impl Serialize for H256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(base64_url::encode(self.as_bytes()).as_str())
    }
}

// Implement Deserialize for H256Wrapper
impl<'de> Deserialize<'de> for H256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        DecodeHash::from(&s).map_err(|e| D::Error::custom(format!("{}", e)))
    }
}


// =============================================================================
// Wrapper type for H384
// -----------------------------------------------------------------------------
#[derive(Default, Copy, Debug, Clone, PartialEq)]
pub struct H384(_H384);

impl H384 {
    pub fn from_slice(src: &[u8]) -> Self {
        H384(_H384::from_slice(src))
    }

    pub fn zero() -> Self {
        H384(_H384::zero())
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn as_sized_array(&self) -> [u8;32] {
        self.0.as_bytes().try_into().expect("32 byte hash")
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.as_bytes().to_vec()
    }
}

impl AsRef<[u8]> for H384 {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl AsMut<[u8]> for H384 {
    fn as_mut(&mut self) -> &mut [u8] {
        self.0.as_mut()
    }
}

impl From<[u8; 48]> for H384 {
    fn from(bytes: [u8; 48]) -> Self {
        H384(_H384::from(bytes))
    }
}

impl Index<usize> for H384 {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl Index<std::ops::Range<usize>> for H384 {
    type Output = [u8];

    fn index(&self, index: std::ops::Range<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl IndexMut<std::ops::Range<usize>> for H384 {
    fn index_mut(&mut self, index: std::ops::Range<usize>) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl Index<RangeTo<usize>> for H384 {
    type Output = [u8];

    fn index(&self, index: RangeTo<usize>) -> &Self::Output {
        &self.0[index]
    }
}

impl Index<RangeFull> for H384 {
    type Output = [u8];

    fn index(&self, _: RangeFull) -> &Self::Output {
        &self.0[..]
    }
}

impl IndexMut<RangeFull> for H384 {
    fn index_mut(&mut self, _: RangeFull) -> &mut Self::Output {
        &mut self.0[..]
    }
}

// Implement Serialize for H384Wrapper
impl Serialize for H384 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(base64_url::encode(self.as_bytes()).as_str())
    }
}

// Implement Deserialize for H384Wrapper
impl<'de> Deserialize<'de> for H384 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        DecodeHash::from(&s).map_err(|e| D::Error::custom(format!("{}", e)))
    }
}
