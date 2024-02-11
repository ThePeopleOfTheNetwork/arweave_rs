//! Decryption methods for separating the original chunk data from the randomX
//! entropy using a feistel block cypher.
use openssl::sha;

const FEISTEL_BLOCK_LENGTH: usize = 32;

/// Takes `right` and `key` arrays of bytes, takes the first 32 bytes of each
/// and SHA-256 hashes the combined 64 bytes together, returning the hash.
fn feistel_hash(right: &[u8], key: &[u8]) -> [u8; 32] {
    // Use only the first FEISTEL_BLOCK_LENGTH bytes of right and key
    let right_slice: &[u8; FEISTEL_BLOCK_LENGTH] = &right[..FEISTEL_BLOCK_LENGTH.min(right.len())]
        .try_into()
        .unwrap_or_else(|_| panic!("the right_slice should be {FEISTEL_BLOCK_LENGTH} bytes"));
    let key_slice: &[u8; FEISTEL_BLOCK_LENGTH] = &key[..FEISTEL_BLOCK_LENGTH.min(key.len())]
        .try_into()
        .unwrap_or_else(|_| panic!("the key_slice should be {FEISTEL_BLOCK_LENGTH} bytes"));

    // SHA-256 hash the first 32 bytes of [right] and [key] together
    let mut hasher = sha::Sha256::new();
    hasher.update(right_slice);
    hasher.update(key_slice);

    hasher.finish()
}

/// Takes the `left` and `right` feistel blocks and uses the `key` to decrypt
///  them, returning the decrypted left and right blocks
fn feistel_decrypt_block(
    in_left: &[u8],
    in_right: &[u8],
    in_key: &[u8],
) -> ([u8; FEISTEL_BLOCK_LENGTH], [u8; FEISTEL_BLOCK_LENGTH]) {
    let mut left = [0u8; FEISTEL_BLOCK_LENGTH];
    let mut right = [0u8; FEISTEL_BLOCK_LENGTH];

    let key_offset = FEISTEL_BLOCK_LENGTH;
    let key = &in_key[key_offset..];

    // feistel_hashes the first FEISTEL_BLOCK of [in_left] and the
    // second FEISTEL_BLOCK of [in_key] to produce a [key_hash]
    let key_hash = feistel_hash(in_left, key);

    // XOR [in_right] with the [key_hash], storing it in [left] and copy
    // the first FEISTEL_BLOCK_LENGTH bytes of [in_left] to [right]
    for j in 0..FEISTEL_BLOCK_LENGTH {
        left[j] = in_right[j] ^ key_hash[j];
        right[j] = in_left[j];
    }

    // feistel_hash [left] & the first FEISTEL_BLOCK_LENGTH bytes of in_key
    let key_hash = feistel_hash(&left, in_key);

    // Allocate the return values
    let mut out_left = [0u8; FEISTEL_BLOCK_LENGTH];
    let mut out_right = [0u8; FEISTEL_BLOCK_LENGTH];

    // XOR [right] with the new [key_hash], storing it in [out_left] and copy
    // [left] to [out_right]
    for j in 0..FEISTEL_BLOCK_LENGTH {
        out_left[j] = right[j] ^ key_hash[j];
        out_right[j] = left[j];
    }

    (out_left, out_right)
}

/// Given a `ciphertext` array and an `in_key` array, both will be
/// `RANDOMX_ENTROPY_SIZE` when decrypting Arweave chunks. `ciphertext` will
/// be the encrypted chunk and `key` will be the RandomX entropy.
pub fn feistel_decrypt(ciphertext: &[u8], in_key: &[u8]) -> Vec<u8> {
    let num_steps = ciphertext.len() / (2 * FEISTEL_BLOCK_LENGTH);
    let mut plaintext = vec![0u8; ciphertext.len()];
    let mut feed_key = [0u8; 2 * FEISTEL_BLOCK_LENGTH];

    // Compute the offset of the last 2*FEISTEL_BLOCK_LENGTH bytes of ciphertext
    let mut offset = ciphertext.len() - 2 * FEISTEL_BLOCK_LENGTH;

    // For every decrypt step but the last...
    for _ in 0..num_steps - 1 {
        // Get a slice of the 2*FEISTEL_BLOCK_LENGTH bytes of [ciphertext] and
        // [in_key] following offset
        let block_bytes = ciphertext.split_at(offset).1;
        let key = in_key.split_at(offset).1;

        for j in 0..2 * FEISTEL_BLOCK_LENGTH {
            // Get the left feistel block of the previous step
            let prev_offset = offset - 2 * FEISTEL_BLOCK_LENGTH;
            let (_, prev_block) = ciphertext.split_at(prev_offset);

            // XOR the [key] with [prev_block], to compute [feed_key]
            feed_key[j] = key[j] ^ prev_block[j];
        }

        let (in_left, in_right) = block_bytes.split_at(FEISTEL_BLOCK_LENGTH);
        let (out_left, out_right) = feistel_decrypt_block(in_left, in_right, &feed_key);

        let mut out_offset = offset;

        // Prepend [out_right] and [out_left] to the plaintext response
        plaintext[out_offset..out_offset + FEISTEL_BLOCK_LENGTH].copy_from_slice(&out_left);
        out_offset += FEISTEL_BLOCK_LENGTH;
        plaintext[out_offset..out_offset + FEISTEL_BLOCK_LENGTH].copy_from_slice(&out_right);

        offset -= 2 * FEISTEL_BLOCK_LENGTH;
    }

    // Do the final decrypt step with the first bytes of the inputs
    let in_left = ciphertext.split_at(FEISTEL_BLOCK_LENGTH).0;
    let in_right = ciphertext.split_at(FEISTEL_BLOCK_LENGTH).1;
    let (out_left, out_right) = feistel_decrypt_block(in_left, in_right, in_key);

    // Prepend [out_right] and [out_left] to the plaintext response
    plaintext[..FEISTEL_BLOCK_LENGTH].copy_from_slice(&out_left);
    plaintext[FEISTEL_BLOCK_LENGTH..2 * FEISTEL_BLOCK_LENGTH].copy_from_slice(&out_right);

    plaintext
}
