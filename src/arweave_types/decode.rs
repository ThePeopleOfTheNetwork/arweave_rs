use super::{H256, H384};

/// Traits to decode base64_url encoded hashes into their corresponding types
pub trait DecodeHash: Sized {
    fn from(base64_url_string: &str) -> Result<Self, String>;
    fn empty() -> Self;
}

impl DecodeHash for H256 {
    fn from(base64_url_string: &str) -> Result<Self, String> {
        base64_url::decode(base64_url_string)
            .map_err(|e| e.to_string())
            .map(|bytes| H256::from_slice(bytes.as_slice()))
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
