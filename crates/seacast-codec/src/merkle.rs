use seacast_core::{Bytes32, InlineVec};

use crate::sha256::{Sha256, sha256_pair, sha256_prefixed_many};

/// Maximum Merkle proof depth (`List[Bytes32, 14]` in `seacast-lite.md` §1–§2).
pub const MAX_PROOF_DEPTH: usize = 14;

/// Maximum leaves supported by stack-allocated Merkle tree construction: a
/// group's indices.
pub const MAX_MERKLE_LEAVES: usize = seacast_core::MAX_BITMAP_BITS;

/// Stack-allocated, fixed-capacity Merkle proof (`Copy`, zero heap allocation).
pub type MerkleProof = InlineVec<Bytes32, MAX_PROOF_DEPTH>;

/// Computes the domain-separated leaf digest `sha256(0x00 || data)`
/// (`seacast-lite.md` §1).
#[inline]
pub fn leaf_hash(data: &[u8]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(&[0x00]);
    h.update(data);
    h.finalize()
}

/// Computes the domain-separated internal node digest `sha256(0x01 || left ||
/// right)` (`seacast-lite.md` §1).
#[inline]
pub fn node_hash(left: &Bytes32, right: &Bytes32) -> Bytes32 {
    sha256_pair(0x01, left, right)
}

/// Returns the padded power-of-two width for `count` leaves.
#[inline]
pub fn tree_width(count: usize) -> usize {
    if count <= 1 { 1 } else { count.next_power_of_two() }
}

/// Stack-allocated Merkle tree over up to [`MAX_MERKLE_LEAVES`] leaves.
/// Stores all layers contiguously in a fixed array (`2 * MAX_MERKLE_LEAVES =
/// 1024` digests).
#[derive(Clone)]
pub struct MerkleTree {
    nodes: [Bytes32; 2 * MAX_MERKLE_LEAVES],
    width: usize,
}

impl MerkleTree {
    /// Builds a Merkle tree from `leaves` on the stack with zero heap
    /// allocation.
    pub fn build<T: AsRef<[u8]>>(leaves: &[T]) -> Self {
        let width = tree_width(leaves.len());
        assert!(width <= MAX_MERKLE_LEAVES, "leaf count exceeds MAX_MERKLE_LEAVES");
        let mut nodes = [[0u8; 32]; 2 * MAX_MERKLE_LEAVES];
        sha256_prefixed_many(0x00, leaves, &mut nodes[width..width + leaves.len()]);
        Self::above(nodes, width, leaves.len())
    }

    /// The tree whose leaves have the digests `hashes` ([`leaf_hash`]): no leaf
    /// is hashed.
    pub fn from_leaf_hashes(hashes: &[Bytes32]) -> Self {
        let width = tree_width(hashes.len());
        assert!(width <= MAX_MERKLE_LEAVES, "leaf count exceeds MAX_MERKLE_LEAVES");
        let mut nodes = [[0u8; 32]; 2 * MAX_MERKLE_LEAVES];
        nodes[width..width + hashes.len()].copy_from_slice(hashes);
        Self::above(nodes, width, hashes.len())
    }

    /// Fills in the nodes above the `count` leaf digests at `nodes[width..]`.
    fn above(mut nodes: [Bytes32; 2 * MAX_MERKLE_LEAVES], width: usize, count: usize) -> Self {
        // `live` nodes of a level have a leaf below them. The rest are all one value,
        // the hash of an all-padding subtree, computed once per level.
        let (mut level, mut live) = (width, count);
        while level > 1 {
            let (parents, children) = nodes.split_at_mut(level);
            let (level_up, live_up) = (level / 2, live.div_ceil(2));
            let hashed = (live_up + 1).min(level_up);
            for i in 0..hashed {
                parents[level_up + i] = node_hash(&children[2 * i], &children[2 * i + 1]);
            }
            let padding = parents[level_up + hashed - 1];
            parents[level_up + hashed..level].fill(padding);
            (level, live) = (level_up, live_up);
        }
        Self { nodes, width }
    }

    /// Returns the Merkle root of the tree.
    #[inline]
    pub fn root(&self) -> Bytes32 {
        self.nodes[1]
    }

    /// The digest of leaf `index`.
    #[inline]
    pub fn leaf(&self, index: usize) -> Bytes32 {
        self.nodes[self.width + index]
    }

    /// Extracts the stack-allocated [`MerkleProof`] for leaf `index`.
    #[inline]
    pub fn proof(&self, index: usize) -> MerkleProof {
        let mut proof = MerkleProof::new();
        let mut pos = self.width + index;
        while pos > 1 {
            let sibling = pos ^ 1;
            let _ = proof.push(self.nodes[sibling]);
            pos >>= 1;
        }
        proof
    }
}

/// Computes the Merkle root and all tree layers over `leaves`
/// (`seacast-lite.md` §1 `[c1]`).
pub fn build_merkle_layers<T: AsRef<[u8]>>(leaves: &[T]) -> MerkleTree {
    MerkleTree::build(leaves)
}

/// Computes the Merkle root over `leaves` (`merkle_root(leaves)` in
/// `seacast-lite.md` §1).
pub fn merkle_root<T: AsRef<[u8]>>(leaves: &[T]) -> Bytes32 {
    MerkleTree::build(leaves).root()
}

/// Extracts the Merkle proof for leaf `index` from precomputed `tree`
/// (`merkle_proof(leaves, i)`).
pub fn merkle_proof_from_layers(tree: &MerkleTree, index: usize) -> MerkleProof {
    tree.proof(index)
}

/// Computes the Merkle proof for leaf `index` over `leaves`
/// (`merkle_proof(leaves, i)`).
pub fn merkle_proof<T: AsRef<[u8]>>(leaves: &[T], index: usize) -> MerkleProof {
    MerkleTree::build(leaves).proof(index)
}

/// Verifies a chunk's Merkle proof against `root` (`verify_merkle_proof` in
/// `seacast-lite.md` §3).
pub fn verify_merkle_proof(
    root: &Bytes32,
    data: &[u8],
    index: u32,
    count: u32,
    proof: &[Bytes32],
) -> bool {
    proven_leaf_hash(root, data, index, count, proof).is_some()
}

/// [`verify_merkle_proof`], giving the leaf digest it proved: the one committed
/// under `root` at `index`.
pub fn proven_leaf_hash(
    root: &Bytes32,
    data: &[u8],
    index: u32,
    count: u32,
    proof: &[Bytes32],
) -> Option<Bytes32> {
    if count == 0 || index >= count || proof.len() > MAX_PROOF_DEPTH {
        return None;
    }
    let leaf = leaf_hash(data);
    verify_leaf_path(root, &leaf, index, count, proof).then_some(leaf)
}

/// Whether `proof` leads from the leaf digest `leaf` at `index` to `root`: the
/// rest of [`verify_merkle_proof`] once the leaf is hashed.
pub fn verify_leaf_path(
    root: &Bytes32,
    leaf: &Bytes32,
    index: u32,
    count: u32,
    proof: &[Bytes32],
) -> bool {
    if count == 0 || index >= count || proof.len() > MAX_PROOF_DEPTH {
        return false;
    }
    let width = tree_width(count as usize);
    if proof.len() != width.trailing_zeros() as usize {
        return false;
    }
    let mut cur = *leaf;
    let mut idx = index as usize;
    for sibling in proof {
        if idx & 1 == 0 {
            cur = node_hash(&cur, sibling);
        } else {
            cur = node_hash(sibling, &cur);
        }
        idx >>= 1;
    }
    &cur == root
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The padding shortcut against hashing every node, at every leaf count of
    /// a few widths.
    #[test]
    fn test_merkle_padding_matches_full_hashing() {
        let leaves: Vec<[u8; 3]> = (0..70u8).map(|i| [i, 1, 2]).collect();
        for count in 0..=leaves.len() {
            let width = tree_width(count);
            let mut nodes = vec![[0u8; 32]; 2 * width];
            for (i, leaf) in leaves[..count].iter().enumerate() {
                nodes[width + i] = leaf_hash(leaf);
            }
            for i in (1..width).rev() {
                nodes[i] = node_hash(&nodes[2 * i], &nodes[2 * i + 1]);
            }
            let tree = MerkleTree::build(&leaves[..count]);
            assert_eq!(&tree.nodes[1..2 * width], &nodes[1..], "{count} leaves");
        }
    }

    #[test]
    fn test_merkle_root_and_proofs() {
        let leaves: [[u8; 32]; 10] = std::array::from_fn(|i| [i as u8; 32]);
        let tree = build_merkle_layers(&leaves);
        let root = tree.root();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = merkle_proof_from_layers(&tree, i);
            assert_eq!(proof.len(), 4); // next_power_of_two(10) = 16 -> depth 4
            assert!(verify_merkle_proof(&root, leaf, i as u32, 10, &proof));
            assert!(!verify_merkle_proof(&root, b"tampered", i as u32, 10, &proof));
        }
    }
}
