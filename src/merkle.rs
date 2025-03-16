use sha2::{Sha256, Digest};

fn tagged_hash(tag: &[u8], data: &[u8]) -> Vec<u8> {
    let mut inner_hasher = Sha256::new();
    inner_hasher.update(tag);
    let tag_hash = inner_hasher.finalize()[..].to_vec();
    let concatenated = [tag_hash.clone(), tag_hash.clone(), data.to_vec()].concat();
    let mut outer_hasher = Sha256::new();
    outer_hasher.update(concatenated);
    return outer_hasher.finalize()[..].to_vec();
}

enum MerkleNode {
    Value(Vec<u8>),
    Left(Option<Box<MerkleNode>>),
    Right(Option<Box<MerkleNode>>),
}