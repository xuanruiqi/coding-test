//! A simple Merkle tree implementation
//! 
//! Given an array of byte vectors, this module provides functions to build a Merkle tree,
//! compute the Merkle root, and compute the Merkle proof for a given leaf.
use sha2::{digest::FixedOutputReset, Digest, Sha256};
use serde::{ser::SerializeSeq, Serialize};
use data_encoding::HEXLOWER;
/*
 * It is more natural to make HASH_SIZE a const field of HashAlgorithm rather than a parameter.
 * However, since using associated constants in type expressions is not supported by stable Rust
 * (requires the experimental generic_const_exprs flag), we have to make HASH_SIZE a parameter.
 */
pub trait HashAlgorithm<const HASH_SIZE: usize> {
    fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; HASH_SIZE];
}

pub struct Sha256Algorithm {}
impl HashAlgorithm<32> for Sha256Algorithm {
    fn tagged_hash(tag: &[u8], data: &[u8]) -> [u8; 32]{
        let mut hasher = Sha256::new();
        hasher.update(tag);
        let tag_hash: [u8; 32] = hasher.finalize_fixed_reset().into();
        let concatenated = [tag_hash.to_vec(), tag_hash.to_vec(), data.to_vec()].concat();
        hasher.reset();
        hasher.update(concatenated);
        hasher.finalize().into()
    }
}

fn concat_hashes<const HASH_SIZE: usize>(hashes: &Vec<[u8; HASH_SIZE]>) -> Vec<Vec<u8>> {
    let mut concatenated_hashes = Vec::new();
    for i in (0..hashes.len()).step_by(2) {
        if i != hashes.len() - 1 {
            let concatenated = [hashes[i].to_vec(), hashes[i+1].to_vec()].concat();
            concatenated_hashes.push(concatenated);
        } else {
            let last = hashes.last().unwrap();
            concatenated_hashes.push([last.to_vec(), last.to_vec()].concat());
        }
    }
    concatenated_hashes
}

fn hash_values<const HASH_SIZE: usize, H: HashAlgorithm<HASH_SIZE>>(values: Vec<Vec<u8>>, tag: &Vec<u8>) -> Vec<[u8; HASH_SIZE]> {
    values.iter().map(|x| H::tagged_hash(&tag, x)).collect::<Vec<_>>()
}

/*
 * Use the binary-tree-as-array trick, because our tree is always complete
 * and the array approach is faster and easier to implement. Also, the number of
 * nodes required can be pre-computed, so we can pre-allocate.
 * 
 * Note that HASH_SIZE is actually determined by the provided H: HashAlgorithm.
 * It is possible to make HASH_SIZE an associated constant but currently using generic
 * parameters in const expressions is not supported by stable Rust, so we have to do
 * with a bit of redundancy. 
 */
#[derive(Debug)]
pub struct MerkleTree<const HASH_SIZE: usize, H: HashAlgorithm<HASH_SIZE>> {
    layers: Vec<Vec<[u8; HASH_SIZE]>>,
    leaf_tag: Vec<u8>,
    branch_tag: Vec<u8>,
    _hasher: std::marker::PhantomData<H> // a phantom field that serves as evidence for H
}

#[derive(Debug)]
pub enum MerkleProofItem<const HASH_SIZE: usize> {
    Left([u8; HASH_SIZE]),
    Right([u8; HASH_SIZE])
}

#[derive(Debug, Serialize)]
pub struct MerkleProof<const HASH_SIZE: usize>(pub Vec<MerkleProofItem<HASH_SIZE>>);

#[derive(Debug)]
pub struct MerkleRoot<const HASH_SIZE: usize>(pub [u8; HASH_SIZE]);

impl<const HASH_SIZE: usize, H: HashAlgorithm<HASH_SIZE>> MerkleTree<HASH_SIZE, H> {
    fn build_rec(&mut self, values: Vec<Vec<u8>>, is_leaf: bool) {
        let tag = if is_leaf { &self.leaf_tag } else { &self.branch_tag };
        let hashes = hash_values::<HASH_SIZE, H>(values, tag);
        if hashes.len() > 1 {
            let concatenated_hashes = concat_hashes::<HASH_SIZE>(&hashes);
            self.layers.push(hashes);
            self.build_rec(concatenated_hashes, false);
        } else {
            self.layers.push(hashes); // we've just got to the root, done
        }        
    }

    /// This function builds a Merkle tree from a vector of byte vectors, which represent the leaf values (unhashed!).
    /// BIP340 compatible tagged hashing is used.
    /// `leaf_tag` is the tag used for hashing the leaf nodes, and `branch_tag` is the tag used for hashing the branch nodes.
    pub fn build(values: Vec<Vec<u8>>, leaf_tag: Vec<u8>, branch_tag: Vec<u8>) -> MerkleTree<HASH_SIZE, H> {
        let mut tree = MerkleTree {
            layers: Vec::new(),
            leaf_tag,
            branch_tag,
            _hasher: std::marker::PhantomData
        };
        tree.build_rec(values, true);
        tree
    }

    /// Returns the Merkle root of a given Merkle tree as a byte array of length 32 (i.e., 256 bits).
    pub fn get_root(&self) -> MerkleRoot<HASH_SIZE> {
        MerkleRoot(self.layers.last().unwrap()[0])
    }

    // Get the proof item for a given node in the tree
    fn get_proof_item(&self, layer: usize, index: usize) -> Option<MerkleProofItem<HASH_SIZE>> {
        // this is a right node
        if index % 2 == 1 {
            Some(MerkleProofItem::Left(self.layers[layer][index - 1]))
        } else if index == self.layers[layer].len() - 1 {
            // the number of nodes in this level is odd, so this is a lone node without a sibling
            None
        } else {
            Some(MerkleProofItem::Right(self.layers[layer][index + 1]))

        }
    }

    // build the proof by moving up the tree
    fn build_proof(&self, index: usize) -> MerkleProof<HASH_SIZE> {
        let mut proof = Vec::new();
        let mut curr_index = index;
        // the -1 is important, because the root is not needed
        for i in 0..(self.layers.len() - 1) {
            let proof_item = self.get_proof_item(i, curr_index);
            curr_index /= 2;
            match proof_item {
                None => {
                    // this node has no sibling, don't need to include anything
                    continue;
                },
                Some(prf) => {
                    proof.push(prf);
                }
            }
        }
        MerkleProof(proof)
    }

    /// Given a value, return the Merkle proof for the leaf with that value if
    /// the value is in the tree, or None if the value is not in the tree.
    pub fn get_proof(&self, value: Vec<u8>) -> Option<MerkleProof<HASH_SIZE>> {
        let hash: [u8; HASH_SIZE] = H::tagged_hash(&self.leaf_tag, &value);
        match self.layers[0].iter().position(|&x| x == hash) {
            Some(index) => Some(self.build_proof(index)),
            None => None
        }
    }
}

impl<const HASH_SIZE: usize> Serialize for MerkleProofItem<HASH_SIZE> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        match self {
            MerkleProofItem::Left(hash) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(&0)?;
                seq.serialize_element(&format!("0x{}", HEXLOWER.encode(hash)))?;
                seq.end()
            },
            MerkleProofItem::Right(hash) => {
                let mut seq = serializer.serialize_seq(Some(2))?;
                seq.serialize_element(&1)?;
                seq.serialize_element(&format!("0x{}", HEXLOWER.encode(hash)))?;
                seq.end()
            }
        }
    }
}

impl<const HASH_SIZE: usize> Serialize for MerkleRoot<HASH_SIZE> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        serializer.serialize_str(&format!("0x{}", HEXLOWER.encode(&self.0)))
    }
}