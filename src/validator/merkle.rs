use borsh::BorshDeserialize;
use borsh_derive::BorshDeserialize;
use color_eyre::eyre::eyre;
use eyre::Error;
use openssl::sha;

/// Single struct used for original data chunks (Leaves) and branch nodes (hashes of pairs of child nodes).
#[derive(Debug, PartialEq, Clone)]
pub struct Node {
    pub id: [u8; HASH_SIZE],
    pub data_hash: Option<[u8; HASH_SIZE]>,
    pub min_byte_range: usize,
    pub max_byte_range: usize,
    pub left_child: Option<Box<Node>>,
    pub right_child: Option<Box<Node>>,
}

/// Concatenated ids and offsets for full set of nodes for an original data chunk, starting with the root.
#[derive(Debug, PartialEq, Clone)]
pub struct Proof {
    pub offset: usize,
    pub proof: Vec<u8>,
}

/// Populated with data from deserialized [`Proof`] for original data chunk (Leaf [`Node`]).
#[repr(C)]
#[derive(BorshDeserialize, Debug, PartialEq, Clone)]
pub struct LeafProof {
    data_hash: [u8; HASH_SIZE],
    notepad: [u8; NOTE_SIZE - 8],
    offset: [u8; 8],
}

/// Populated with data from deserialized [`Proof`] for branch [`Node`] (hash of pair of child nodes).
#[derive(BorshDeserialize, Debug, PartialEq, Clone)]
pub struct BranchProof {
    left_id: [u8; HASH_SIZE],
    right_id: [u8; HASH_SIZE],
    notepad: [u8; NOTE_SIZE - 8],
    offset: [u8; 8],
}

/// Includes methods to deserialize [`Proof`]s.
pub trait ProofDeserialize<T> {
    fn try_from_proof_slice(slice: &[u8]) -> Result<T, Error>;
    fn offset(&self) -> usize;
}

impl ProofDeserialize<LeafProof> for LeafProof {
    fn try_from_proof_slice(slice: &[u8]) -> Result<Self, Error> {
        let proof = LeafProof::try_from_slice(slice)?;
        Ok(proof)
    }
    fn offset(&self) -> usize {
        usize::from_be_bytes(self.offset)
    }
}

impl ProofDeserialize<BranchProof> for BranchProof {
    fn try_from_proof_slice(slice: &[u8]) -> Result<Self, Error> {
        let proof = BranchProof::try_from_slice(slice)?;
        Ok(proof)
    }
    fn offset(&self) -> usize {
        usize::from_be_bytes(self.offset)
    }
}

pub const MAX_CHUNK_SIZE: usize = 256 * 1024;
pub const MIN_CHUNK_SIZE: usize = 32 * 1024;
pub const HASH_SIZE: usize = 32;
const NOTE_SIZE: usize = 32;

/// Includes a function to convert a number to a Vec of 32 bytes per the Arweave spec.
pub trait Helpers<T> {
    fn to_note_vec(&self) -> Vec<u8>;
}

impl Helpers<usize> for usize {
    fn to_note_vec(&self) -> Vec<u8> {
        let mut note = vec![0; NOTE_SIZE - 8];
        note.extend((*self as u64).to_be_bytes());
        note
    }
}

pub struct ValidatePathResult {
    pub leaf_hash: [u8; HASH_SIZE],
    pub left_bound: u128,
    pub right_bound: u128,
}

pub fn validate_path(
    root_hash: [u8; HASH_SIZE],
    path_buff: &Vec<u8>,
    target_offset: u128,
) -> Result<ValidatePathResult, Error> {
    // Split proof into branches and leaf. Leaf is the final proof and branches
    // are ordered from root to leaf.
    let (branches, leaf) = path_buff.split_at(path_buff.len() - HASH_SIZE - NOTE_SIZE);

    // Deserialize proof.
    let branch_proofs: Vec<BranchProof> = branches
        .chunks(HASH_SIZE * 2 + NOTE_SIZE)
        .map(|b| BranchProof::try_from_proof_slice(b).unwrap())
        .collect();
    let leaf_proof = LeafProof::try_from_proof_slice(leaf)?;

    let mut left_bound: u128 = 0;
    let mut expected_path_hash = root_hash;

    // Validate branches.
    for branch_proof in branch_proofs.iter() {
        // Calculate the path_hash from the proof elements.
        let path_hash = hash_all_sha256(vec![
            &branch_proof.left_id,
            &branch_proof.right_id,
            &branch_proof.offset().to_note_vec(),
        ])?;

        // Proof is invalid if the calculated path_hash doesn't match expected
        if path_hash != expected_path_hash {
            return Err(eyre!("Invalid Branch Proof"));
        }

        let offset = branch_proof.offset() as u128;
        let is_right_of_offset = target_offset > offset;

        // Choose the next expected_path_hash based on weather the target_offset
        // byte is to the left or right of the branch_proof's "offset" value
        expected_path_hash = match is_right_of_offset {
            true => branch_proof.right_id,
            false => branch_proof.left_id,
        };

        // Keep track of left bound as we traverse down the branches
        if is_right_of_offset {
            left_bound = offset;
        }

        println!(
            "BranchProof: left: {}{}, right: {}{},offset: {} => path_hash: {}",
            if is_right_of_offset { "" } else { "✅" },
            base64_url::encode(&branch_proof.left_id),
            if is_right_of_offset { "✅" } else { "" },
            base64_url::encode(&branch_proof.right_id),
            branch_proof.offset(),
            base64_url::encode(&path_hash)
        );
    }
    println!(
        "  LeafProof: data_hash: {}, offset: {}",
        base64_url::encode(&leaf_proof.data_hash),
        usize::from_be_bytes(leaf_proof.offset)
    );

    // Proof nodes (including leaf nodes) always contain their right bound
    let right_bound = leaf_proof.offset() as u128;

    Ok(ValidatePathResult {
        leaf_hash: leaf_proof.data_hash,
        left_bound,
        right_bound,
    })
}

pub fn print_debug(proof: &Vec<u8>, target_offset: u128) -> Result<([u8; 32], u128, u128), Error> {
    // Split proof into branches and leaf. Leaf is at the end and branches are
    // ordered from root to leaf.
    let (branches, leaf) = proof.split_at(proof.len() - HASH_SIZE - NOTE_SIZE);

    // Deserialize proof.
    let branch_proofs: Vec<BranchProof> = branches
        .chunks(HASH_SIZE * 2 + NOTE_SIZE)
        .map(|b| BranchProof::try_from_proof_slice(b).unwrap())
        .collect();
    let leaf_proof = LeafProof::try_from_proof_slice(leaf)?;

    let mut left_bound: u128 = 0;

    // Validate branches.
    for branch_proof in branch_proofs.iter() {
        // Calculate the id from the proof.
        let path_hash = hash_all_sha256(vec![
            &branch_proof.left_id,
            &branch_proof.right_id,
            &branch_proof.offset().to_note_vec(),
        ])?;

        let offset = branch_proof.offset() as u128;
        let is_right_of_offset = target_offset > offset;

        // Keep track of left and right bounds as we traverse down the proof
        if is_right_of_offset {
            left_bound = offset;
        }

        println!(
            "BranchProof: left: {}{}, right: {}{},offset: {} => path_hash: {}",
            if is_right_of_offset { "" } else { "✅" },
            base64_url::encode(&branch_proof.left_id),
            if is_right_of_offset { "✅" } else { "" },
            base64_url::encode(&branch_proof.right_id),
            branch_proof.offset(),
            base64_url::encode(&path_hash)
        );
    }
    println!(
        "  LeafProof: data_hash: {}, offset: {}",
        base64_url::encode(&leaf_proof.data_hash),
        usize::from_be_bytes(leaf_proof.offset)
    );

    let right_bound = leaf_proof.offset() as u128;
    Ok((leaf_proof.data_hash, left_bound, right_bound))
}

/// Validates chunk of data against provided [`Proof`].
pub fn validate_chunk(
    mut root_id: [u8; HASH_SIZE],
    chunk: Node,
    proof: Proof,
) -> Result<(), Error> {
    match chunk {
        Node {
            data_hash: Some(data_hash),
            max_byte_range,
            ..
        } => {
            // Split proof into branches and leaf. Leaf is at the end and branches are ordered
            // from root to leaf.
            let (branches, leaf) = proof
                .proof
                .split_at(proof.proof.len() - HASH_SIZE - NOTE_SIZE);

            // Deserialize proof.
            let branch_proofs: Vec<BranchProof> = branches
                .chunks(HASH_SIZE * 2 + NOTE_SIZE)
                .map(|b| BranchProof::try_from_proof_slice(b).unwrap())
                .collect();
            let leaf_proof = LeafProof::try_from_proof_slice(leaf)?;

            // Validate branches.
            for branch_proof in branch_proofs.iter() {
                // Calculate the id from the proof.
                let id = hash_all_sha256(vec![
                    &branch_proof.left_id,
                    &branch_proof.right_id,
                    &branch_proof.offset().to_note_vec(),
                ])?;

                // Ensure calculated id correct.
                if id != root_id {
                    return Err(eyre!("Invalid Branch Proof"));
                }

                // If the offset from the proof is greater than the offset in the data chunk,
                // then the next id to validate against is from the left.
                root_id = match max_byte_range > branch_proof.offset() {
                    true => branch_proof.right_id,
                    false => branch_proof.left_id,
                }
            }

            // Validate leaf: both id and data_hash are correct.
            let id = hash_all_sha256(vec![&data_hash, &max_byte_range.to_note_vec()])?;
            if (id != root_id) && (data_hash != leaf_proof.data_hash) {
                return Err(eyre!("Invalid Leaf Proof"));
            }
        }
        _ => {
            unreachable!()
        }
    }
    Ok(())
}

pub fn hash_sha256(message: &[u8]) -> Result<[u8; 32], Error> {
    let mut hasher = sha::Sha256::new();
    hasher.update(message);
    let result = hasher.finish();
    Ok(result)
}

/// Returns a SHA256 hash of the the concatenated SHA256 hashes of a vector of messages.
pub fn hash_all_sha256(messages: Vec<&[u8]>) -> Result<[u8; 32], Error> {
    let hash: Vec<u8> = messages
        .into_iter()
        .flat_map(|m| hash_sha256(m).unwrap())
        .collect();
    let hash = hash_sha256(&hash)?;
    Ok(hash)
}
