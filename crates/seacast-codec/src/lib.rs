//! # `seacast-codec`
//!
//! Cryptographic, erasure-coding and segmentation implementations for
//! **SEACAST**. A binding's bytes are its crate's (`seacast-gossipsub`).

pub mod buffer;
pub mod layout;
pub mod merkle;
pub mod reed_solomon;
pub mod segment;
pub mod segmented;
pub mod sha256;
pub mod snappy;
pub mod standalone;

pub use buffer::{ArcBufferPool, BufferPool, ChunkBytes, VecBufferPool};
pub use layout::ChunkLayout;
pub use merkle::{
    MAX_MERKLE_LEAVES, MAX_PROOF_DEPTH, MerkleProof, MerkleTree, build_merkle_layers, leaf_hash,
    merkle_proof, merkle_proof_from_layers, merkle_root, node_hash, proven_leaf_hash, tree_width,
    verify_leaf_path, verify_merkle_proof,
};
pub use reed_solomon::{
    GF256, Gf256Tables, build_systematic_matrix, rs_complete_data_in_place, rs_complete_in_place,
    rs_parity, rs_parity_rows, rs_reconstruct_data, rs_reconstruct_into,
};
pub use segment::{
    Compressor, DESCRIPTOR_BYTES, Frame, MAX_CHUNKS, MAX_CODED_BODY, MAX_PLAIN_BODY,
    MAX_PLAIN_CHUNKS, MAX_SEGMENT_SIZE, SegmentDescriptor, Shard, SnappyBlockCompressor, UNIT,
    body_into, body_len, build_chunks, build_frame, build_group, check_frame, check_frame_leaf,
    check_frame_proof, chunk_id, chunk_wire_size, complete_in_place, decode_and_reencode,
    decode_and_reencode_with, frame_content, frame_identity, frame_leaf_hash, group_id, group_key,
    proof_len, split_frame,
};
pub use segmented::SegmentedCodec;
pub use sha256::{Sha256, sha256};
pub use standalone::{StandaloneCodec, check_standalone, standalone_group};
