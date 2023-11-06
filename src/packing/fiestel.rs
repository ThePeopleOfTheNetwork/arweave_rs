use openssl::sha;

// WIP

const FEISTEL_BLOCK_LENGTH: usize = 32;

// NOTE feistel_encrypt_block/feistel_decrypt_block with less than 2 blocks are malformed

pub fn feistel_hash(
    right: &[u8; FEISTEL_BLOCK_LENGTH],
    key: &[u8; FEISTEL_BLOCK_LENGTH],
) -> [u8; FEISTEL_BLOCK_LENGTH] {
    let mut hasher = sha::Sha256::new();
    hasher.update(right);
    hasher.update(key);
    hasher.finish().into()
}

pub fn feistel_encrypt_block(
    in_left: &[u8; FEISTEL_BLOCK_LENGTH],
    in_right: &[u8; FEISTEL_BLOCK_LENGTH],
    in_key: &[u8; FEISTEL_BLOCK_LENGTH],
) -> ([u8; FEISTEL_BLOCK_LENGTH], [u8; FEISTEL_BLOCK_LENGTH]) {
    let mut key_hash: [u8; FEISTEL_BLOCK_LENGTH] = [0; FEISTEL_BLOCK_LENGTH];
    let mut left: [u8; FEISTEL_BLOCK_LENGTH] = [0; FEISTEL_BLOCK_LENGTH];
    let mut right: [u8; FEISTEL_BLOCK_LENGTH] = [0; FEISTEL_BLOCK_LENGTH];
    let mut key = &in_key[..];

    let key_hash = feistel_hash(&in_right, key);
    key = &key[FEISTEL_BLOCK_LENGTH..];

    for j in 0..FEISTEL_BLOCK_LENGTH {
        right[j] = in_left[j] ^ key_hash[j];
        left[j] = in_right[j];
    }

    let mut out_left: [u8; FEISTEL_BLOCK_LENGTH] = [0; FEISTEL_BLOCK_LENGTH];
    let mut out_right: [u8; FEISTEL_BLOCK_LENGTH] = [0; FEISTEL_BLOCK_LENGTH];

    let key_hash = feistel_hash(right, key);
    for j in 0..FEISTEL_BLOCK_LENGTH {
        out_right[j] = left[j] ^ key_hash[j];
        out_left[j] = right[j];
    }

    (out_left, out_right)
}

pub fn feistel_decrypt_block(
    in_left: &[u8; FEISTEL_BLOCK_LENGTH],
    in_right: &[u8; FEISTEL_BLOCK_LENGTH],
    in_key: &[u8; FEISTEL_BLOCK_LENGTH],
) -> ([u8; FEISTEL_BLOCK_LENGTH], [u8; FEISTEL_BLOCK_LENGTH]) {
    let mut key_hash: [u8; FEISTEL_BLOCK_LENGTH] = [0; FEISTEL_BLOCK_LENGTH];
    let mut left: [u8; FEISTEL_BLOCK_LENGTH] = [0; FEISTEL_BLOCK_LENGTH];
    let mut right: [u8; FEISTEL_BLOCK_LENGTH] = [0; FEISTEL_BLOCK_LENGTH];

    let key_offset = FEISTEL_BLOCK_LENGTH;
    let mut key = &in_key[key_offset..];

    let key_hash = feistel_hash(&in_left, key);
    let new_key_start = key.len().saturating_sub(FEISTEL_BLOCK_LENGTH);
    key = &in_key[..new_key_start];

    for j in 0..FEISTEL_BLOCK_LENGTH {
        left[j] = in_right[j] ^ key_hash[j];
        right[j] = in_left[j];
    }

    let mut out_left: [u8; FEISTEL_BLOCK_LENGTH] = [0; FEISTEL_BLOCK_LENGTH];
    let mut out_right: [u8; FEISTEL_BLOCK_LENGTH] = [0; FEISTEL_BLOCK_LENGTH];

    let key_hash = feistel_hash(&left, key);
    for j in 0..FEISTEL_BLOCK_LENGTH {
        out_left[j] = right[j] ^ key_hash[j];
        out_right[j] = left[j];
    }

    (out_left, out_right)
}

// feistel_encrypt accepts padded message with 2*FEISTEL_BLOCK_LENGTH = 64 bytes
// in_key_length == plaintext_len
// CBC

fn feistel_encrypt(plaintext: &[u8], in_key: &[u8]) -> Vec<u8> {
    let block_count = plaintext_len / (2 * FEISTEL_BLOCK_LENGTH);
    let mut ciphertext: Vec<u8> = vec![0; plaintext.len()];
    let mut feed_key: [u8; 2 * FEISTEL_BLOCK_LENGTH] = [0; 2 * FEISTEL_BLOCK_LENGTH];

    let mut in_offset = 0;
    let mut out_offset = 0;
    let mut key_offset = 0;

    // Perform the initial encryption for the first block
    let (out_left, out_right) = feistel_encrypt_block(
        &plaintext[in_offset..in_offset + FEISTEL_BLOCK_LENGTH],
        &plaintext[in_offset + FEISTEL_BLOCK_LENGTH..in_offset + 2 * FEISTEL_BLOCK_LENGTH],
        &in_key[key_offset..key_offset + 2 * FEISTEL_BLOCK_LENGTH],
    );
    ciphertext[out_offset..out_offset + FEISTEL_BLOCK_LENGTH].copy_from_slice(&out_left);
    ciphertext[out_offset + FEISTEL_BLOCK_LENGTH..out_offset + 2 * FEISTEL_BLOCK_LENGTH]
        .copy_from_slice(&out_right);

    in_offset += 2 * FEISTEL_BLOCK_LENGTH;
    key_offset += 2 * FEISTEL_BLOCK_LENGTH;

    for _ in 1..block_count {
        for j in 0..2 * FEISTEL_BLOCK_LENGTH {
            feed_key[j] = in_key[key_offset + j] ^ ciphertext[out_offset + j];
        }
        out_offset += 2 * FEISTEL_BLOCK_LENGTH;

        // Perform encryption for the subsequent blocks using feed_key
        let (out_left, out_right) = feistel_encrypt_block(
            &plaintext[in_offset..in_offset + FEISTEL_BLOCK_LENGTH],
            &plaintext[in_offset + FEISTEL_BLOCK_LENGTH..in_offset + 2 * FEISTEL_BLOCK_LENGTH],
            &feed_key,
        );
        ciphertext[out_offset..out_offset + FEISTEL_BLOCK_LENGTH].copy_from_slice(&out_left);
        ciphertext[out_offset + FEISTEL_BLOCK_LENGTH..out_offset + 2 * FEISTEL_BLOCK_LENGTH]
            .copy_from_slice(&out_right);

        in_offset += 2 * FEISTEL_BLOCK_LENGTH;
        key_offset += 2 * FEISTEL_BLOCK_LENGTH;
    }

    ciphertext
}

fn feistel_encrypt2(plaintext: &[u8], in_key: &[u8]) -> Vec<u8> {
    const FEISTEL_BLOCK_LENGTH: usize = 64; // Set your actual block length here
    let block_count = plaintext.len() / (2 * FEISTEL_BLOCK_LENGTH);

    let mut ciphertext = vec![0; plaintext.len()];
    let mut feed_key = [0; 2 * FEISTEL_BLOCK_LENGTH];

    let mut blocks = plaintext.chunks_exact(2 * FEISTEL_BLOCK_LENGTH);
    let mut out_blocks = ciphertext.chunks_exact_mut(2 * FEISTEL_BLOCK_LENGTH);
    let mut keys = in_key.chunks_exact(2 * FEISTEL_BLOCK_LENGTH);

    if let (Some(block), Some(out_block), Some(key)) =
        (blocks.next(), out_blocks.next(), keys.next())
    {
        let (left, right) = block.split_at(FEISTEL_BLOCK_LENGTH);
        let (out_left, out_right) = feistel_encrypt_block(left, right, key);
        out_block[0..FEISTEL_BLOCK_LENGTH].copy_from_slice(&out_left);
        out_block[FEISTEL_BLOCK_LENGTH..].copy_from_slice(&out_right);
    }

    for (block, out_block, key) in Iterator::zip(Iterator::zip(blocks, out_blocks), keys) {
        for (feed, &out) in feed_key
            .iter_mut()
            .zip(&out_block[0..2 * FEISTEL_BLOCK_LENGTH])
        {
            *feed = key[0] ^ out;
        }

        let (left, right) = block.split_at(FEISTEL_BLOCK_LENGTH);
        let (out_left, out_right) = feistel_encrypt_block(left, right, &feed_key);

        out_block[0..FEISTEL_BLOCK_LENGTH].copy_from_slice(&out_left);
        out_block[FEISTEL_BLOCK_LENGTH..].copy_from_slice(&out_right);
    }

    ciphertext
}

// void feistel_decrypt(const unsigned char *ciphertext, const size_t ciphertext_len, const unsigned char *in_key, unsigned char *plaintext) {
// 	size_t block_count = ciphertext_len / (2*FEISTEL_BLOCK_LENGTH);
// 	unsigned char feed_key[2*FEISTEL_BLOCK_LENGTH] = {0};

// 	const unsigned char *in = ciphertext + ciphertext_len - 2*FEISTEL_BLOCK_LENGTH;
// 	unsigned char *out = plaintext + ciphertext_len - 2*FEISTEL_BLOCK_LENGTH;
// 	const unsigned char *key = in_key + ciphertext_len - 2*FEISTEL_BLOCK_LENGTH;

// 	for(size_t i = 0; i < block_count-1; i++) {
// 		for(int j = 0; j < 2*FEISTEL_BLOCK_LENGTH; j++) {
// 			feed_key[j] = key[j] ^ in[j - 2*FEISTEL_BLOCK_LENGTH];
// 		}

// 		feistel_decrypt_block(in, in + FEISTEL_BLOCK_LENGTH, feed_key, out, out + FEISTEL_BLOCK_LENGTH);
// 		in  -= 2*FEISTEL_BLOCK_LENGTH;
// 		key -= 2*FEISTEL_BLOCK_LENGTH;
// 		out -= 2*FEISTEL_BLOCK_LENGTH;
// 	}

// 	feistel_decrypt_block(in, in + FEISTEL_BLOCK_LENGTH, key, out, out + FEISTEL_BLOCK_LENGTH);
// }
