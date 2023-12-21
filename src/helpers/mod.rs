use uint::construct_uint;

// Definition of the U256 type
construct_uint! {
    /// 256-bit unsigned integer.
    #[cfg_attr(feature = "scale-info", derive(TypeInfo))]
    pub struct u256(4);
}

pub mod consensus;

/// Traits to decode base64_url encoded hashes into their corresponding bytes
pub trait DecodeHash: Sized {
    fn from(base64_url_string: &str) -> Result<Self, String>;
    fn empty() -> Self; 
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
