use uint::construct_uint;

// Definition of the U256 type
construct_uint! {
    /// 256-bit unsigned integer.
    #[cfg_attr(feature = "scale-info", derive(TypeInfo))]
    pub struct U256(4);
}

/// Traits to decode base64_url encoded hashes into their corresponding bytes
pub trait DecodeHash: Sized {
    fn from(base64_url_string: &str) -> Result<Self, String>;
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
}
