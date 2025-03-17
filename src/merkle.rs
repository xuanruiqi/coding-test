use sha2::{digest::FixedOutputReset, Digest, Sha256};

fn tagged_hash(tag: &[u8], data: &[u8], hasher: &mut Sha256) -> [u8; 32]{
    hasher.reset();
    hasher.update(tag);
    let tag_hash: [u8; 32] = hasher.finalize_fixed_reset().into();
    let concatenated = [tag_hash.to_vec(), tag_hash.to_vec(), data.to_vec()].concat();
    hasher.reset();
    hasher.update(concatenated);
    hasher.finalize_fixed_reset().into()
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

fn concat_hashes(hashes: &Vec<[u8; 32]>) -> Vec<Vec<u8>> {
    let mut cated_hashes = Vec::new();
    for i in (0..hashes.len()).step_by(2) {
        if i != hashes.len() - 1 {
            let concatenated = [hashes[i].to_vec(), hashes[i+1].to_vec()].concat();
            cated_hashes.push(concatenated);
        } else {
            let last = hashes.last().unwrap();
            cated_hashes.push([last.to_vec(), last.to_vec()].concat());
        }
    }
    cated_hashes
}

fn hash_values(values: Vec<Vec<u8>>, tag: &Vec<u8>, hasher: &mut Sha256) -> Vec<[u8; 32]> {
    values.iter().map(|x| tagged_hash(&tag, x, hasher)).collect::<Vec<_>>()
}

/* Use the binary-tree-as-array trick, because our tree is always complete
 * and the array approach is faster and easier to implement. Also, the number of
 * nodes required can be pre-computed, so we can pre-allocate.
 */
#[derive(Debug)]
pub struct MerkleTree {
    nodes: Vec<[u8; 32]>,
    hasher: Sha256,
    leaf_tag: Vec<u8>,
    branch_tag: Vec<u8>,
    total_nodes: usize, // total number of nodes in the tree
    built_nodes: usize // number of already built nodes
}

// I choose to build the tree imperatively, because it is more natural for our representation
impl MerkleTree {
    // Initialize the tree, create the arrays, but don't build any nodes
    fn init_tree(&mut self, num_leaves: usize) {
        let num_nodes = count_nodes(num_leaves);
        self.nodes = vec![[0; 32]; num_nodes];
        self.total_nodes = num_nodes;
        self.built_nodes = 0;
    }

    fn build_layer(&mut self, hashes: &Vec<[u8; 32]>) {
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
        let hashes = hash_values(values, tag, &mut self.hasher);
        self.build_layer(&hashes);
        if hashes.len() > 1 {
            let cated = concat_hashes(&hashes);
            self.build_rec(cated, false);
        }
    }

    pub fn build(values: Vec<Vec<u8>>, leaf_tag: Vec<u8>, branch_tag: Vec<u8>) -> MerkleTree {
        let mut tree = MerkleTree {
            nodes: Vec::new(),
            hasher: Sha256::new(),
            leaf_tag,
            branch_tag,
            total_nodes: 0,
            built_nodes: 0
        };
        tree.init_tree(values.len());
        tree.build_rec(values, true);
        tree
    }

    pub fn merkle_root(&self) -> [u8; 32] {
        self.nodes[0]
    }
}