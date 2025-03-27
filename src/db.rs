use crate::merkle::{MerkleTree, HashAlgorithm, MerkleRoot, MerkleProof};
use std::collections::HashMap;

// This serves as the witness for a particular Merkle tree implementation
pub trait MerkleTreeImpl<const HASH_SIZE: usize, H: HashAlgorithm<HASH_SIZE>> {}
impl<const HASH_SIZE: usize, H: HashAlgorithm<HASH_SIZE>> MerkleTreeImpl<HASH_SIZE, H> for MerkleTree<HASH_SIZE, H> {}

/* 
 * The Merkle tree should logically be part of the database. It is generic over the Merkle tree implementation
 * as when the database grows large in production, the Merkle tree might be stored on disk or otherwise. Moreover,
 * one may want to consider an incremental Merkle tree implementation, such as the Merkle mountain range.
 * 
 * Currently there is no functionality to add users because the Merkle tree is not online, but that could be added
 * by simply inheriting the UserDatabase trait.
 */
pub trait UserDatabase<const HASH_SIZE: usize, H: HashAlgorithm<HASH_SIZE>, M: MerkleTreeImpl<HASH_SIZE, H>> {
    fn create(user_data: Vec<(u64, u64)>, leaf_tag: Vec<u8>, branch_tag: Vec<u8>) -> Self;
    fn get_balance(&self, user_id: u64) -> Option<u64>;
    fn get_root(&self) -> MerkleRoot<HASH_SIZE>;
    fn get_proof(&self, user_id: u64) -> Option<MerkleProof<HASH_SIZE>>;
}

pub struct InMemoryDatabase<const HASH_SIZE: usize, H: HashAlgorithm<HASH_SIZE>> {
    users: HashMap<u64, u64>,
    tree: MerkleTree<HASH_SIZE, H>,
}

fn serialize_user(user_id: u64, balance: u64) -> Vec<u8> {
    format!("({},{}", user_id, balance).into_bytes()
}

impl<const HASH_SIZE: usize, H: HashAlgorithm<HASH_SIZE>> UserDatabase<HASH_SIZE, H, MerkleTree<HASH_SIZE, H>> for InMemoryDatabase<HASH_SIZE, H> {
    fn create(user_data: Vec<(u64, u64)>, leaf_tag: Vec<u8>, branch_tag: Vec<u8>) -> Self {
        let serialized_user_data: Vec<Vec<u8>> = user_data.iter().map(|(id, balance)| serialize_user(*id, *balance)).collect();
        let tree = MerkleTree::<HASH_SIZE, H>::build(serialized_user_data, leaf_tag, branch_tag);
        let user_map: HashMap<_, _> = user_data.into_iter().collect();
        InMemoryDatabase { users: user_map, tree }
    }

    fn get_balance(&self, user_id: u64) -> Option<u64> {
        self.users.get(&user_id).copied()
    }

    fn get_root(&self) -> MerkleRoot<HASH_SIZE> {
        self.tree.get_root()
    }
    
    fn get_proof(&self, user_id: u64) -> Option<MerkleProof<HASH_SIZE>> {
        let balance = self.get_balance(user_id)?;
        let serialized = serialize_user(user_id, balance);
        self.tree.get_proof(serialized)
    }
}