//! A simple Merkle tree implementation
//! 
//! Given an array of byte vectors, this module provides functions to build a Merkle tree,
//! compute the Merkle root, and compute the Merkle proof for a given leaf.

use sha2::{digest::FixedOutputReset, Digest, Sha256};

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

fn count_nodes(num_leaves: usize) -> usize {
    let mut num_nodes = 1;
    let mut n = num_leaves;
    while n > 1 {
        if n % 2 != 0 {
            n += 1;
        }
        num_nodes += n;
        n = n / 2;
    }
    // print!{"Number of nodes: {}\n", num_nodes};
    num_nodes
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

// left child = 2i + 1, right child = 2i + 2, so we can minus 1 and (integer) divide by 2
fn parent_index(index: usize) -> usize {
    (index - 1) / 2
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
    nodes: Vec<[u8; HASH_SIZE]>,
    leaf_tag: Vec<u8>,
    branch_tag: Vec<u8>,
    num_leaves: usize, // number of leaves
    total_nodes: usize, // total number of nodes in the tree
    built_nodes: usize, // number of already built nodes
    _hasher: std::marker::PhantomData<H> // 
}

#[derive(Debug)]
pub enum Position { Left, Right }
pub struct MerkleProof<const HASH_SIZE: usize>(pub Vec<(Position, [u8; HASH_SIZE])>);

// I choose to build the tree imperatively, because it is more natural for our representation
impl<const HASH_SIZE: usize, H: HashAlgorithm<HASH_SIZE>> MerkleTree<HASH_SIZE, H> {
    // Initialize the tree, create the arrays, but don't build any nodes
    fn initialize(&mut self, num_leaves: usize) {
        let num_nodes = count_nodes(num_leaves);
        self.nodes = vec![[0; HASH_SIZE]; num_nodes];
        self.total_nodes = num_nodes;
        self.built_nodes = 0;
    }

    fn build_layer(&mut self, hashes: &Vec<[u8; HASH_SIZE]>) {
        // include a copy of the last hash if the layer has an odd number of nodes
        // print!("num hashes: {}\n", hashes.len());
        let layer_nodes = if hashes.len() % 2 == 0 || hashes.len() == 1 { hashes.len() } else { hashes.len() + 1 };
        // print!("Total nodes: {}, Built nodes: {}, Layer nodes: {}\n", self.total_nodes, self.built_nodes, layer_nodes);
        let start = self.total_nodes - self.built_nodes - layer_nodes;
        let nodes = &mut self.nodes[start..start+layer_nodes];
        for i in 0..hashes.len() {
            nodes[i] = hashes[i];
        }
        if hashes.len() % 2 != 0 && hashes.len() != 1 {
            nodes[hashes.len()] = nodes[hashes.len() - 1];
        }
        self.built_nodes += layer_nodes;
    }

    fn build_rec(&mut self, values: Vec<Vec<u8>>, is_leaf: bool) {
        let tag = if is_leaf { &self.leaf_tag } else { &self.branch_tag };
        let hashes = hash_values::<HASH_SIZE, H>(values, tag);
        self.build_layer(&hashes);
        if hashes.len() > 1 {
            let concatenated = concat_hashes(&hashes);
            self.build_rec(concatenated, false);
        }
    }

    /// This function builds a Merkle tree from a vector of byte vectors, which represent the leaf values (unhashed!).
    /// BIP340 compatible tagged hashing (SHA256) is used.
    /// `leaf_tag` is the tag used for hashing the leaf nodes, and `branch_tag` is the tag used for hashing the branch nodes.
    pub fn build(values: Vec<Vec<u8>>, leaf_tag: Vec<u8>, branch_tag: Vec<u8>) -> MerkleTree<HASH_SIZE, H> {
        let mut tree = MerkleTree {
            nodes: Vec::new(),
            leaf_tag,
            branch_tag,
            num_leaves: values.len(),
            total_nodes: 0,
            built_nodes: 0,
            _hasher: std::marker::PhantomData
        };
        tree.initialize(values.len());
        tree.build_rec(values, true);
        tree
    }

    /// Returns the Merkle root of a given Merkle tree as a byte array of length 32 (i.e., 256 bits).
    pub fn get_root(&self) -> [u8; HASH_SIZE] {
        self.nodes[0]
    }

    // Get the sibling and position of a leaf
    fn get_sibling(&self, index: usize) -> (Position, [u8; HASH_SIZE]) {
        // if the index is even then this is a right leaf
        if index % 2 == 0 {
            (Position::Left, self.nodes[index - 1])
        } else {
            (Position::Right, self.nodes[index + 1])
        }
    }

    // build the proof by moving up the tree
    fn build_proof(&self, index: usize) -> MerkleProof<HASH_SIZE> {
        let mut proof: Vec<(Position, [u8; HASH_SIZE])> = Vec::new();
        let mut i = index;
        while i > 0 {
            let sibling = self.get_sibling(i);
            proof.push(sibling);
            i = parent_index(i);
        }
        MerkleProof(proof)
    }

    fn find_leaf(&self, hash: [u8; HASH_SIZE]) -> Option<usize> {
        for i in (self.total_nodes - self.num_leaves + 1)..self.total_nodes {
            if self.nodes[i] == hash {
                return Some(i);
            }
        }
        None
    }

    /// Given a value, return the Merkle proof for the leaf with that value if
    /// the value is in the tree, or None if the value is not in the tree.
    pub fn get_proof(&self, value: Vec<u8>) -> Option<MerkleProof<HASH_SIZE>> {
        let hash: [u8; HASH_SIZE] = H::tagged_hash(&self.leaf_tag, &value);
        match self.find_leaf(hash) {
            Some(index) => Some(self.build_proof(index)),
            None => None
        }
    }

}