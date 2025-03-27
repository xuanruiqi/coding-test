mod merkle;
use merkle::{MerkleTree, Sha256Algorithm};

fn test_merkle_root() {
    let test_values = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec(), b"ddd".to_vec(), b"eee".to_vec()];
    let tag = (b"Bitcoin_Transaction").to_vec();
    let tree = MerkleTree::<32, Sha256Algorithm>::build(test_values, tag.clone(), tag.clone());
    let root = tree.get_root();
    println!("{:02X?}", root);
}

fn test_merkle_proof() {
    let test_values = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec(), b"ddd".to_vec(), b"eee".to_vec()];
    let tag = (b"Bitcoin_Transaction").to_vec();
    let tree = MerkleTree::<32, Sha256Algorithm>::build(test_values, tag.clone(), tag.clone());
    let proof = tree.get_proof(b"eee".to_vec());
    match proof {
        Some(proof) => {
            println!("Proof found:");
            for pr_item in proof.0.iter() {
                println!("{:?}", pr_item);
            }
        },
        None => {
            println!("No proof found.");
        }
    }
}

fn main() {
    println!("Testing the Merkle root implementation...");
    test_merkle_root();
}
