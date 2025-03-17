mod merkle;
use merkle::MerkleTree;

fn main() {
    let test_values = vec![b"aaa".to_vec(), b"bbb".to_vec(), b"ccc".to_vec(), b"ddd".to_vec()];
    let tag = (b"Bitcoin_Transaction").to_vec();
    let tree = MerkleTree::build_sha256(test_values, tag);
    let root = tree.merkle_root();
    print!("{:02X?}", root);
}
