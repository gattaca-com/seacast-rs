use seacast_core::{
    Bytes32, ChunkBuffer, ChunkId, ChunkMsg, GroupId, MAX_BITMAP_BITS, PreallocVec, TypeId,
};

use crate::{
    buffer::{BufferPool, ChunkBytes},
    merkle::{
        MerkleProof, MerkleTree, build_merkle_layers, leaf_hash, merkle_proof_from_layers,
        proven_leaf_hash, tree_width, verify_leaf_path,
    },
    reed_solomon::{rs_complete_in_place, rs_parity_rows, rs_reconstruct_into},
    sha256::{Sha256, sha256_prefixed_many},
    snappy,
};

/// Target uncompressed segment size (`UNIT = 16 KiB` in `seacast-lite.md` §1
/// `[c1]`).
pub const UNIT: usize = 16 * 1024;

/// Maximum coded chunks (data + parity) (`MAX_CHUNKS = 256` in
/// `seacast-lite.md` §1 `[c6]`).
pub const MAX_CHUNKS: u32 = 256;

/// Maximum chunks of a coded group (`MAX_CHUNKS`, `seacast-lite.md` §1 `[c6]`).
/// A body past `MAX_CHUNKS / 2` segments goes plain.
pub const MAX_CODED_CHUNKS: u32 = MAX_CHUNKS;

/// Maximum plain (uncoded) chunks supported by a group (`MAX_BITMAP_BITS =
/// 512`).
pub const MAX_PLAIN_CHUNKS: usize = MAX_BITMAP_BITS;

/// Longest body [`build_group`] takes: `MAX_PLAIN_CHUNKS` segments of `UNIT`.
pub const MAX_PLAIN_BODY: usize = MAX_PLAIN_CHUNKS * UNIT;

/// Maximum segment byte size (`MAX_SEGMENT_SIZE = 2 * UNIT = 32 KiB` in
/// `seacast-lite.md` §1 `[c1]`).
pub const MAX_SEGMENT_SIZE: u32 = (2 * UNIT) as u32;

/// Longest body a coded group carries: `MAX_CODED_CHUNKS / 2` data segments of
/// `UNIT`. A coded group's segments decompress to at most this.
pub const MAX_CODED_BODY: usize = (MAX_CODED_CHUNKS as usize / 2) * UNIT;

/// Serialized size of a `SegmentDescriptor` in bytes (`1 + 1 + 1 + 4 + 4 + 8 +
/// 32 = 51`).
pub const DESCRIPTOR_BYTES: usize = 51;

/// Pluggable pre-coding body compressor (`encoding = 1` in
/// `SegmentDescriptor`).
pub trait Compressor {
    fn compress(&self, input: &[u8]) -> Vec<u8>;
    fn decompress(&self, compressed: &[u8]) -> Option<Vec<u8>>;
}

/// Standard Snappy block format compressor/decompressor ([`snappy`]). It
/// decompresses at most [`MAX_PLAIN_BODY`] bytes.
#[derive(Debug, Default, Clone, Copy)]
pub struct SnappyBlockCompressor;

impl Compressor for SnappyBlockCompressor {
    fn compress(&self, input: &[u8]) -> Vec<u8> {
        snappy::compress(input)
    }

    fn decompress(&self, compressed: &[u8]) -> Option<Vec<u8>> {
        snappy::decompress(compressed, MAX_PLAIN_BODY)
    }
}

/// `SegmentDescriptor`: the header of a segmented group, which the domain
/// commits (`seacast-lite.md` §1 `[c1]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SegmentDescriptor {
    /// `2` = coded (Reed–Solomon parity after the data); `1` = plain.
    pub version: u8,
    /// `0` = SHA-256.
    pub hash_id: u8,
    /// `1` = snappy block compression applied before segmenting (`[c6]`);
    /// `0` = none. Either goes with either version.
    pub encoding: u8,
    /// `N`: total chunks in the group (data + parity).
    pub count: u32,
    /// Bytes per chunk (the last data chunk may be shorter).
    pub segment_size: u32,
    /// Length of the segmented byte string.
    pub total_length: u64,
    /// Merkle root over the `N` chunks.
    pub root: Bytes32,
}

impl SegmentDescriptor {
    /// Serializes the descriptor into its SSZ layout (`serialize(d)` in
    /// `seacast-lite.md` §1).
    pub fn serialize(&self) -> [u8; DESCRIPTOR_BYTES] {
        let mut out = [0u8; DESCRIPTOR_BYTES];
        out[0] = self.version;
        out[1] = self.hash_id;
        out[2] = self.encoding;
        out[3..7].copy_from_slice(&self.count.to_le_bytes());
        out[7..11].copy_from_slice(&self.segment_size.to_le_bytes());
        out[11..19].copy_from_slice(&self.total_length.to_le_bytes());
        out[19..51].copy_from_slice(&self.root);
        out
    }

    /// Deserializes a `SegmentDescriptor` from [`DESCRIPTOR_BYTES`] bytes.
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < DESCRIPTOR_BYTES {
            return None;
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes[19..51]);
        Some(Self {
            version: bytes[0],
            hash_id: bytes[1],
            encoding: bytes[2],
            count: u32::from_le_bytes([bytes[3], bytes[4], bytes[5], bytes[6]]),
            segment_size: u32::from_le_bytes([bytes[7], bytes[8], bytes[9], bytes[10]]),
            total_length: u64::from_le_bytes(bytes[11..19].try_into().unwrap()),
            root,
        })
    }

    /// Number of data chunks `K(d) = ceil(d.total_length / d.segment_size)`
    /// (`seacast-lite.md` §1).
    #[inline]
    pub fn k(&self) -> u32 {
        if self.segment_size == 0 {
            return 0;
        }
        // Saturated: a descriptor is a peer's until its group id has been checked by
        // the domain, and no valid one has more than `MAX_PLAIN_CHUNKS` chunks.
        u32::try_from(self.total_length.div_ceil(self.segment_size as u64)).unwrap_or(u32::MAX)
    }

    /// Total number of chunks `N(d) = d.count` (`seacast-lite.md` §1).
    #[inline]
    pub fn n(&self) -> u32 {
        self.count
    }

    /// Expected byte length of chunk `index` (`segment_length(d, i)` in
    /// `seacast-lite.md` §1).
    #[inline]
    pub fn segment_length(&self, index: u32) -> usize {
        let k = self.k();
        if k > 0 && index == k - 1 {
            let prev = ((k - 1) as u64) * (self.segment_size as u64);
            (self.total_length.saturating_sub(prev)) as usize
        } else {
            self.segment_size as usize
        }
    }

    /// The tree chunk `index` is a leaf of: its root, the leaf's place in it
    /// and its leaf count.
    fn tree_of(&self, index: u32) -> (&Bytes32, u32, u32) {
        (&self.root, index, self.count)
    }

    /// The digests in the proof of any chunk of the group.
    pub fn proof_len(&self) -> usize {
        proof_len(self.tree_of(0).2)
    }

    /// Checks whether this descriptor is valid before allocating group state
    /// (`valid_descriptor(d)` in `seacast-lite.md` §1).
    pub fn is_valid(&self) -> bool {
        if self.hash_id != 0 || self.segment_size == 0 || self.segment_size > MAX_SEGMENT_SIZE {
            return false;
        }
        if self.total_length == 0 {
            return false;
        }
        let k = self.k();
        if k == 0 {
            return false;
        }
        let last_len = self.total_length.checked_sub(((k - 1) as u64) * (self.segment_size as u64));
        if !matches!(last_len, Some(l) if l > 0 && l <= (self.segment_size as u64)) {
            return false;
        }
        match self.version {
            _ if self.encoding > 1 => false,
            2 => self.count <= MAX_CHUNKS && self.count as u64 == 2 * k as u64,
            1 => self.count == k && (self.count as usize) <= MAX_PLAIN_CHUNKS,
            _ => false,
        }
    }
}

/// Computes `group_id(d) = sha256(0x02 || serialize(d))` (`seacast-lite.md`
/// §1).
pub fn group_id(d: &SegmentDescriptor) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(&[0x02]);
    h.update(&d.serialize());
    h.finalize()
}

/// The group of a segmented type: index 0 under the key `sha256(0x03 || type ||
/// header_id || context)`, where `header_id` is [`group_id`] of its descriptor
/// and `context` is what the domain reads.
pub fn group_key(type_id: TypeId, header_id: &Bytes32, context: &[u8]) -> GroupId {
    let mut h = Sha256::new();
    h.update(&[0x03, type_id.0]);
    h.update(header_id);
    h.update(context);
    GroupId::new(type_id, h.finalize(), 0)
}

/// The digests in the proof of any leaf of a tree of `count` leaves.
pub fn proof_len(count: u32) -> usize {
    tree_width(count as usize).trailing_zeros() as usize
}

/// A segmented chunk's frame: `descriptor | context | proof | data`. Every
/// length is given: the descriptor's is fixed, the context's is its type's, the
/// proof's follows from the descriptor, and the data is the rest.
pub struct Frame<'a> {
    pub descriptor: SegmentDescriptor,
    pub context: &'a [u8],
    pub proof: &'a [u8],
    pub data: &'a [u8],
}

impl Frame<'_> {
    pub fn proof(&self) -> MerkleProof {
        let mut proof = MerkleProof::new();
        for digest in self.proof.as_chunks::<32>().0 {
            let _ = proof.push(*digest);
        }
        proof
    }
}

/// Splits `frame` into its parts. `None` if it is too short for them, or its
/// descriptor's count is beyond what a proof covers.
pub fn split_frame(frame: &[u8], context_len: usize) -> Option<Frame<'_>> {
    let descriptor = SegmentDescriptor::deserialize(frame.get(..DESCRIPTOR_BYTES)?)?;
    if descriptor.count as usize > MAX_PLAIN_CHUNKS {
        return None;
    }
    let rest = &frame[DESCRIPTOR_BYTES..];
    let (context, rest) = rest.split_at_checked(context_len)?;
    let (proof, data) = rest.split_at_checked(32 * descriptor.proof_len())?;
    Some(Frame { descriptor, context, proof, data })
}

/// The frame of a chunk: `descriptor | context | proof | data`.
pub fn build_frame(
    descriptor: &SegmentDescriptor,
    context: &[u8],
    proof: &[Bytes32],
    data: &[u8],
) -> Vec<u8> {
    let mut frame =
        Vec::with_capacity(DESCRIPTOR_BYTES + context.len() + 32 * proof.len() + data.len());
    frame.extend_from_slice(&descriptor.serialize());
    frame.extend_from_slice(context);
    for digest in proof {
        frame.extend_from_slice(digest);
    }
    frame.extend_from_slice(data);
    frame
}

/// The 59-byte id of a chunk (`seacast-bindings.md` §1.2): its group (type,
/// key, index), its index, then the first 20 bytes of `content`, a digest that
/// binds every byte of its frame level 1 reads ([`frame_content`],
/// [`standalone_group`](crate::standalone_group)). Two copies that differ
/// anywhere have two ids, so a forged copy, rejected, does not mark an honest
/// one seen.
pub fn chunk_id(group: &GroupId, index: u32, content: &Bytes32) -> ChunkId {
    let mut out = [0u8; 59];
    out[0] = group.type_id.0;
    out[1..33].copy_from_slice(&group.key);
    out[33..35].copy_from_slice(&group.index.to_le_bytes());
    out[35..39].copy_from_slice(&index.to_le_bytes());
    out[39..].copy_from_slice(&content[..20]);
    out
}

/// The bytes a chunk counts for in the window: its compressed length where the
/// host has set it (`ChunkMsg::wire_len`), else its frame's.
pub fn chunk_wire_size<B: ChunkBuffer>(chunk: &ChunkMsg<B>) -> usize {
    if chunk.wire_len > 0 { chunk.wire_len as usize } else { chunk.frame.len() }
}

/// The content of a segmented chunk's id: `sha256(leaf || head)`, where `leaf`
/// is the leaf digest of its data and `head` the frame's bytes before the data
/// (descriptor, context, proof). The data is hashed once, for its leaf.
pub fn frame_content(leaf: &Bytes32, head: &[u8]) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(leaf);
    h.update(head);
    h.finalize()
}

/// A segmented chunk's id content and its data's leaf digest, the proof not
/// checked: what a reader computes before level 1, which then checks the proof
/// from the leaf ([`check_frame_leaf`]). A frame that does not split has the
/// digest of all its bytes, and no leaf.
pub fn frame_identity(frame: &[u8], context_len: usize) -> (Bytes32, Option<Bytes32>) {
    match split_frame(frame, context_len) {
        Some(f) => {
            let leaf = leaf_hash(f.data);
            (frame_content(&leaf, &frame[..frame.len() - f.data.len()]), Some(leaf))
        }
        None => (crate::sha256::sha256(frame), None),
    }
}

/// `Shard`: a chunk's content and stack-allocated [`MerkleProof`] built by the
/// publisher (`seacast-lite.md` §1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard<B> {
    pub index: u32,
    pub proof: MerkleProof,
    pub data: B,
}

/// Compresses and segments `body`, Reed–Solomon-encodes it where a coded
/// group holds it, and builds the Merkle tree (`build_group(body)` in
/// `seacast-lite.md` §1 `[c1, c6]`).
///
/// A body past the coded size is compressed too and cut at `UNIT`, as Prysm's
/// publisher cuts it. Only where its compression has more segments than a
/// group holds does it go as it is.
///
/// Panics if `body` is empty or longer than [`MAX_PLAIN_BODY`]: the caller
/// checks its length.
pub fn build_group<B, Pool, Comp>(
    body: &[u8],
    pool: &mut Pool,
    compressor: &Comp,
) -> (SegmentDescriptor, Vec<Shard<B>>)
where
    B: ChunkBuffer,
    Pool: BufferPool<B>,
    Comp: Compressor,
{
    assert!(!body.is_empty(), "body must not be empty");
    assert!(body.len() <= MAX_PLAIN_BODY, "body exceeds MAX_PLAIN_BODY");
    let k = body.len().div_ceil(UNIT);
    let coded = 2 * k <= MAX_CHUNKS as usize;
    // Coded, the compressed bytes are padded in place to `k` whole segments: the
    // Reed–Solomon input as it stands, with no copy per segment.
    let mut compressed = compressor.compress(body);
    assert!(!compressed.is_empty(), "the compressor returned nothing");
    let raw = !coded && compressed.len().div_ceil(UNIT) > MAX_PLAIN_CHUNKS;
    let total = if raw { body.len() } else { compressed.len() };
    let (k, size) = if coded { (k, total.div_ceil(k)) } else { (total.div_ceil(UNIT), UNIT) };
    let mut parity = Vec::new();
    if coded {
        compressed.resize(k * size, 0);
        parity.resize(k * size, 0);
        let srcs: Vec<&[u8]> = compressed.chunks_exact(size).collect();
        let rows: Vec<usize> = (k..2 * k).collect();
        let mut dsts: Vec<&mut [u8]> = parity.chunks_exact_mut(size).collect();
        rs_parity_rows(&srcs, 2 * k, &rows, &mut dsts);
    }
    let data = if raw { body } else { &compressed[..total] };

    let mut leaves: Vec<&[u8]> =
        (0..k).map(|i| &data[(i * size).min(total)..((i + 1) * size).min(total)]).collect();
    leaves.extend(parity.chunks_exact(size));

    // Plain, `leaves[k..]` is empty and its root is zero.
    let tree = build_merkle_layers(&leaves);
    let root = tree.root();

    let descriptor = SegmentDescriptor {
        version: if coded { 2 } else { 1 },
        hash_id: 0,
        encoding: u8::from(!raw),
        count: leaves.len() as u32,
        segment_size: size as u32,
        total_length: total as u64,
        root,
    };

    let mut shards = Vec::with_capacity(leaves.len());
    for (i, leaf) in leaves.into_iter().enumerate() {
        let proof = merkle_proof_from_layers(&tree, i);
        shards.push(Shard { index: i as u32, proof, data: pool.alloc_from_slice(leaf) });
    }
    (descriptor, shards)
}

/// The part of level 1 that reads no data (`validate_chunk` in
/// `seacast-lite.md` §3): the frame splits, its descriptor is valid, `group` is
/// the id of `type_id`, the descriptor and the context, `index` is one the
/// descriptor has, and the data has the length it gives.
pub fn check_frame(
    type_id: TypeId,
    group: &GroupId,
    index: u32,
    frame: &[u8],
    context_len: usize,
) -> bool {
    let Some(f) = split_frame(frame, context_len) else {
        return false;
    };
    f.descriptor.is_valid() &&
        group_key(type_id, &group_id(&f.descriptor), f.context) == *group &&
        index < f.descriptor.count &&
        f.data.len() == f.descriptor.segment_length(index)
}

/// The rest of level 1: the data is the leaf of chunk `index` in its tree
/// under the descriptor.
pub fn check_frame_proof(index: u32, frame: &[u8], context_len: usize) -> bool {
    frame_leaf_hash(index, frame, context_len).is_some()
}

/// [`check_frame_proof`] with the data's leaf digest already in hand
/// ([`frame_identity`]): the data is not hashed again.
pub fn check_frame_leaf(index: u32, frame: &[u8], context_len: usize, leaf: &Bytes32) -> bool {
    let Some(f) = split_frame(frame, context_len) else {
        return false;
    };
    let (root, at, count) = f.descriptor.tree_of(index);
    verify_leaf_path(root, leaf, at, count, &f.proof())
}

/// [`check_frame_proof`], giving the leaf digest it proved: what
/// [`complete_in_place`] takes for a chunk that is there.
pub fn frame_leaf_hash(index: u32, frame: &[u8], context_len: usize) -> Option<Bytes32> {
    let f = split_frame(frame, context_len)?;
    let (root, leaf, count) = f.descriptor.tree_of(index);
    proven_leaf_hash(root, f.data, leaf, count, &f.proof())
}

/// The chunks of a group built by [`build_group`], as a publisher hands them to
/// the node.
pub fn build_chunks<B, Pool>(
    type_id: TypeId,
    context: &[u8],
    descriptor: &SegmentDescriptor,
    shards: &[Shard<B>],
    pool: &mut Pool,
) -> Vec<ChunkMsg<B>>
where
    B: ChunkBytes,
    Pool: BufferPool<B>,
{
    let group = group_key(type_id, &group_id(descriptor), context);
    shards
        .iter()
        .map(|shard| {
            let data = shard.data.as_bytes();
            let frame = build_frame(descriptor, context, &shard.proof, data);
            let leaf = leaf_hash(data);
            let content = frame_content(&leaf, &frame[..frame.len() - data.len()]);
            ChunkMsg {
                group,
                index: shard.index,
                cached_id: chunk_id(&group, shard.index, &content),
                frame: pool.alloc_from_slice(&frame),
                memo: leaf,
                wire_len: 0,
            }
        })
        .collect()
}

/// Level 2 on a group whose chunks are kept where they were written
/// (`seacast-lite.md` §3, §4.6): `data` is the `K` data segments end to end,
/// every one `segment_size` bytes, the last padded with zeros; `parity` is the
/// other `N - K` chunks, laid out the same way; `have(i)` says chunk `i` is
/// there. Every missing chunk is computed into its place, nothing present is
/// moved, and the tree over all `N` must have the committed root.
///
/// `hashes[i]` is the leaf digest of chunk `i` as level 1 proved it
/// ([`frame_leaf_hash`]), for every chunk that is there; the other entries are
/// not read. Only the chunks computed here are hashed: a proved digest is the
/// committed one, so the root is the same as from hashing every chunk. A slot
/// that changed after its level 1 is therefore not detected.
///
/// The tree gives the proofs of the chunks filled in. `None` if `K` chunks are
/// not there, or if the root differs: the group is inconsistent, and what was
/// filled in is not to be used.
pub fn complete_in_place(
    descriptor: &SegmentDescriptor,
    data: &mut [u8],
    parity: &mut [u8],
    have: impl Fn(usize) -> bool,
    hashes: &[Bytes32],
) -> Option<MerkleTree> {
    if !descriptor.is_valid() {
        return None;
    }
    let (k, n) = (descriptor.k() as usize, descriptor.n() as usize);
    let size = descriptor.segment_size as usize;
    if data.len() != k * size || parity.len() != (n - k) * size || hashes.len() != n {
        return None;
    }
    rs_complete_in_place(k, n, data, parity, &have)?;
    let computed: Vec<usize> = (0..n).filter(|&i| !have(i)).collect();
    let leaves: Vec<&[u8]> = (computed.iter())
        .map(|&i| match i < k {
            true => &data[i * size..][..descriptor.segment_length(i as u32)],
            false => &parity[(i - k) * size..][..size],
        })
        .collect();
    let mut digests = vec![[0u8; 32]; leaves.len()];
    sha256_prefixed_many(0x00, &leaves, &mut digests);
    let mut all = hashes.to_vec();
    for (&i, digest) in computed.iter().zip(digests) {
        all[i] = digest;
    }
    let tree = MerkleTree::from_leaf_hashes(&all);
    (tree.root() == descriptor.root).then_some(tree)
}

/// The length of the body a complete group's data segments hold: what
/// [`body_into`] writes. A caller reserves that much; it is at most
/// [`MAX_PLAIN_BODY`].
pub fn body_len(descriptor: &SegmentDescriptor, data: &[u8]) -> Option<usize> {
    let segmented = data.get(..usize::try_from(descriptor.total_length).ok()?)?;
    match descriptor.encoding {
        1 => snappy::decompressed_len(segmented).filter(|&len| len <= MAX_PLAIN_BODY),
        _ => Some(segmented.len()),
    }
}

/// Writes the body of a complete group at the start of `out`, from its data
/// segments where they lie, and returns its length: the one move of the body's
/// bytes after their arrival. The data segments end to end are the segmented
/// byte string itself, so nothing is gathered.
pub fn body_into(descriptor: &SegmentDescriptor, data: &[u8], out: &mut [u8]) -> Option<usize> {
    let segmented = data.get(..usize::try_from(descriptor.total_length).ok()?)?;
    match descriptor.encoding {
        1 => {
            snappy::decompressed_len(segmented).filter(|&len| len <= MAX_PLAIN_BODY)?;
            snappy::decompress_into(segmented, out)
        }
        _ => {
            out.get_mut(..segmented.len())?.copy_from_slice(segmented);
            Some(segmented.len())
        }
    }
}

/// The data of a chunk whose frame has `skip` bytes before it.
fn data_at<B: ChunkBytes>(chunk: &ChunkMsg<B>, skip: usize) -> &[u8] {
    match chunk.frame.tail() {
        [] => chunk.frame.as_bytes().get(skip..).unwrap_or(&[]),
        tail => tail,
    }
}

/// Level 2 decoding: reconstructs all `N` chunks from any `K` verified chunks
/// in `available`, re-encodes parity, verifies the Merkle root, populates
/// `out_rebuilt` with all `N` chunks, and returns the decompressed body
/// allocated via `pool` (`decode_and_reencode` in `seacast-lite.md` §1, §4.6).
pub fn decode_and_reencode<B, Pool, Comp>(
    available_chunks: &[ChunkMsg<B>],
    context_len: usize,
    pool: &mut Pool,
    compressor: &Comp,
    out_rebuilt: &mut PreallocVec<ChunkMsg<B>>,
) -> Option<B>
where
    B: ChunkBytes,
    Pool: BufferPool<B>,
    Comp: Compressor,
{
    let first_chunk = available_chunks.first()?;
    let head = split_frame(first_chunk.frame.as_bytes(), context_len)?;
    let (descriptor, context) = (&head.descriptor, head.context);
    let group = first_chunk.group;
    // Every chunk of the group has the same header, context and proof length before
    // its data.
    let skip = DESCRIPTOR_BYTES + context_len + 32 * descriptor.proof_len();
    decode_and_reencode_with(
        available_chunks,
        descriptor,
        skip,
        pool,
        compressor,
        out_rebuilt,
        |index, proof, data, leaf, pool| {
            let frame = build_frame(descriptor, context, proof, data);
            let content = frame_content(leaf, &frame[..frame.len() - data.len()]);
            ChunkMsg {
                group,
                index,
                cached_id: chunk_id(&group, index, &content),
                frame: pool.alloc_from_slice(&frame),
                memo: *leaf,
                wire_len: 0,
            }
        },
    )
}

/// [`decode_and_reencode`] for any frame layout whose data is the frame's
/// tail: `descriptor` is the group's, `skip` the bytes of every frame before
/// its data, and `rebuild` makes the chunk of an index that was not given,
/// from its proof, data and leaf digest.
pub fn decode_and_reencode_with<B, Pool, Comp>(
    available_chunks: &[ChunkMsg<B>],
    descriptor: &SegmentDescriptor,
    skip: usize,
    pool: &mut Pool,
    compressor: &Comp,
    out_rebuilt: &mut PreallocVec<ChunkMsg<B>>,
    mut rebuild: impl FnMut(u32, &MerkleProof, &[u8], &Bytes32, &mut Pool) -> ChunkMsg<B>,
) -> Option<B>
where
    B: ChunkBytes,
    Pool: BufferPool<B>,
    Comp: Compressor,
{
    if !descriptor.is_valid() || descriptor.count as usize > MAX_PLAIN_CHUNKS {
        return None;
    }
    let k = descriptor.k() as usize;
    let n = descriptor.n() as usize;
    let seg_size = descriptor.segment_size as usize;
    if available_chunks.len() < k {
        return None;
    }

    // The first chunk given of each index.
    let mut given: [Option<&ChunkMsg<B>>; MAX_PLAIN_CHUNKS] = [None; MAX_PLAIN_CHUNKS];
    for ch in available_chunks {
        if let Some(entry @ None) = given.get_mut(ch.index as usize) {
            *entry = Some(ch);
        }
    }

    // The data segments end to end, every one `seg_size` bytes; coded, the parity
    // chunks that were not among the `k` decoded from.
    let mut data = Vec::new();
    let mut parity = Vec::new();
    let mut leaves: Vec<&[u8]> = Vec::with_capacity(n);
    // The chunks whose bytes the leaves are: the others are computed.
    let decoded_from: Vec<&ChunkMsg<B>>;
    if descriptor.version == 2 {
        let used = &available_chunks[..k];
        decoded_from = used.iter().collect();
        if used.iter().any(|ch| {
            ch.index as usize >= n || data_at(ch, skip).len() != descriptor.segment_length(ch.index)
        }) {
            return None;
        }
        // The last data chunk alone may be shorter than a segment: padded, as it was
        // coded.
        let last = (k - 1) as u32;
        let short = descriptor.segment_length(last) < seg_size;
        let mut padded_last = Vec::new();
        if let Some(ch) = used.iter().find(|ch| short && ch.index == last) {
            padded_last.extend_from_slice(data_at(ch, skip));
            padded_last.resize(seg_size, 0);
        }
        let indices: Vec<u32> = used.iter().map(|ch| ch.index).collect();
        let chunks: Vec<&[u8]> = used
            .iter()
            .map(|ch| if short && ch.index == last { &padded_last[..] } else { data_at(ch, skip) })
            .collect();
        data.resize(k * seg_size, 0);
        rs_reconstruct_into(k, n, &indices, &chunks, &mut data)?;
        // The pad of a short last chunk is zero, whichever chunks were decoded
        // from: one recovered is checked, so the verdict is the same at every
        // node (`seacast-lite.md` §3, level 2).
        let total = usize::try_from(descriptor.total_length).ok()?;
        if data.get(total..)?.iter().any(|&b| b != 0) {
            return None;
        }

        leaves.extend((0..k).map(|i| &data[i * seg_size..][..descriptor.segment_length(i as u32)]));

        // Decoding from `k` chunks and coding again gives those `k` back whatever they
        // hold, so only the other parity chunks are computed; the root check
        // below covers them all.
        let other_parity: Vec<usize> = (k..n).filter(|r| !indices.contains(&(*r as u32))).collect();
        parity.resize(other_parity.len() * seg_size, 0);
        let srcs: Vec<&[u8]> = data.chunks_exact(seg_size).collect();
        let mut dsts: Vec<&mut [u8]> = parity.chunks_exact_mut(seg_size).collect();
        rs_parity_rows(&srcs, n, &other_parity, &mut dsts);

        let mut computed = parity.chunks_exact(seg_size);
        for r in k..n {
            leaves.push(match used.iter().find(|ch| ch.index as usize == r) {
                Some(ch) => data_at(ch, skip),
                None => computed.next()?,
            });
        }
    } else {
        decoded_from = given[..k].iter().flatten().copied().collect();
        for chunk in &given[..k] {
            let bytes = data_at((*chunk)?, skip);
            leaves.push(bytes);
            data.extend_from_slice(bytes);
        }
    }

    // The digest of a chunk decoded from is the one its level 1 proved, if that
    // left it in `memo`: the committed one, so only the other leaves are hashed.
    let mut digests = vec![[0u8; 32]; leaves.len()];
    for ch in decoded_from {
        if let Some(digest) = digests.get_mut(ch.index as usize) {
            *digest = ch.memo;
        }
    }
    let unknown: Vec<usize> = (0..leaves.len()).filter(|&i| digests[i] == [0; 32]).collect();
    let to_hash: Vec<&[u8]> = unknown.iter().map(|&i| leaves[i]).collect();
    let mut hashed = vec![[0u8; 32]; to_hash.len()];
    sha256_prefixed_many(0x00, &to_hash, &mut hashed);
    for (&i, digest) in unknown.iter().zip(hashed) {
        digests[i] = digest;
    }
    let tree = MerkleTree::from_leaf_hashes(&digests);
    if tree.root() != descriptor.root {
        return None;
    }

    let segmented_bytes = data.get(..descriptor.total_length as usize)?;
    let body_buf = if descriptor.encoding == 1 {
        pool.alloc_from_slice(&compressor.decompress(segmented_bytes)?)
    } else {
        pool.alloc_from_slice(segmented_bytes)
    };

    out_rebuilt.clear();
    for (i, leaf) in leaves.into_iter().enumerate() {
        let idx = i as u32;
        if let Some(existing) = given[i] {
            let _ = out_rebuilt.push(existing.clone());
        } else {
            let proof = merkle_proof_from_layers(&tree, i);
            let _ = out_rebuilt.push(rebuild(idx, &proof, leaf, &tree.leaf(i), pool));
        }
    }
    Some(body_buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::VecBufferPool;

    /// What a domain would put there: these tests only carry it.
    const CONTEXT: [u8; 40] = [3; 40];

    fn valid(chunk: &ChunkMsg<Vec<u8>>) -> bool {
        let (index, frame) = (chunk.index, &chunk.frame[..]);
        check_frame(chunk.group.type_id, &chunk.group, index, frame, CONTEXT.len()) &&
            check_frame_proof(index, frame, CONTEXT.len())
    }

    #[test]
    fn test_build_and_decode_group() {
        let mut pool = VecBufferPool;
        let comp = SnappyBlockCompressor;
        let body: Vec<u8> = (0..(UNIT * 4 + 1234)).map(|i| (i % 251) as u8).collect();
        let (desc, shards) = build_group(&body, &mut pool, &comp);
        assert!(desc.is_valid());
        assert_eq!(desc.version, 2);
        assert_eq!(desc.k(), 5);
        assert_eq!(desc.n(), 10);
        assert_eq!(shards.len(), 10);

        // Indices 1, 3, 5, 7, 9: data and parity, without index 4, the short last data
        // chunk.
        let subset = chunks_of(&desc, &shards, [1, 3, 5, 7, 9].into_iter());
        assert!(subset.iter().all(valid));

        let mut rebuilt = PreallocVec::with_capacity(16);
        let recovered = decode_and_reencode(&subset, CONTEXT.len(), &mut pool, &comp, &mut rebuilt)
            .expect("level 2 decode");
        assert_eq!(rebuilt.len(), 10);
        assert_eq!(recovered, body);
        for ch in rebuilt.iter() {
            assert!(valid(ch));
        }
    }

    /// Level 2 takes the digest level 1 left in a chunk it decodes from, and
    /// leaves one in every chunk it makes: the same verdict and chunks as from
    /// hashing, and a digest that is not the committed one fails the root.
    #[test]
    fn test_decode_takes_the_digests_of_level_1() {
        let mut pool = VecBufferPool;
        let comp = SnappyBlockCompressor;
        let body: Vec<u8> = (0..(UNIT * 4 + 1234)).map(|i| (i % 251) as u8).collect();
        let (desc, shards) = build_group(&body, &mut pool, &comp);
        let mut subset = chunks_of(&desc, &shards, [1, 3, 5, 7, 9].into_iter());
        for ch in &mut subset {
            ch.memo = frame_leaf_hash(ch.index, &ch.frame, CONTEXT.len()).expect("valid");
        }
        let mut rebuilt = PreallocVec::with_capacity(16);
        let recovered = decode_and_reencode(&subset, CONTEXT.len(), &mut pool, &comp, &mut rebuilt);
        assert_eq!(recovered.as_deref(), Some(&body[..]));
        for ch in rebuilt.iter() {
            assert!(valid(ch));
            assert_eq!(Some(ch.memo), frame_leaf_hash(ch.index, &ch.frame, CONTEXT.len()));
        }
        subset[0].memo[0] ^= 1;
        assert!(
            decode_and_reencode(&subset, CONTEXT.len(), &mut pool, &comp, &mut rebuilt).is_none()
        );
    }

    /// A builder that pads the short last data chunk with other than zeros
    /// before coding fails level 2 whichever chunks a node decodes from.
    #[test]
    fn test_nonzero_pad_fails_at_every_basis() {
        let mut pool = VecBufferPool;
        let comp = SnappyBlockCompressor;
        let body: Vec<u8> = (0..(UNIT * 4 + 1234)).map(|i| (i % 251) as u8).collect();
        let k = body.len().div_ceil(UNIT);
        let mut data = comp.compress(&body);
        let total = data.len();
        let size = total.div_ceil(k);
        assert!(total < k * size, "the last data chunk is short");
        data.resize(k * size, 0xAB);
        let mut parity = vec![0u8; k * size];
        let srcs: Vec<&[u8]> = data.chunks_exact(size).collect();
        let rows: Vec<usize> = (k..2 * k).collect();
        let mut dsts: Vec<&mut [u8]> = parity.chunks_exact_mut(size).collect();
        rs_parity_rows(&srcs, 2 * k, &rows, &mut dsts);
        let mut leaves: Vec<&[u8]> =
            (0..k).map(|i| &data[i * size..((i + 1) * size).min(total)]).collect();
        leaves.extend(parity.chunks_exact(size));
        let tree = build_merkle_layers(&leaves);
        let desc = SegmentDescriptor {
            version: 2,
            hash_id: 0,
            encoding: 1,
            count: leaves.len() as u32,
            segment_size: size as u32,
            total_length: total as u64,
            root: tree.root(),
        };
        let shards: Vec<Shard<Vec<u8>>> = leaves
            .iter()
            .enumerate()
            .map(|(i, leaf)| Shard {
                index: i as u32,
                proof: merkle_proof_from_layers(&tree, i),
                data: leaf.to_vec(),
            })
            .collect();
        let bases: [Vec<usize>; 4] = [
            (0..k).collect(),
            (k - 1..2 * k - 1).collect(),
            (0..k - 1).chain([k]).collect(),
            (k..2 * k).collect(),
        ];
        for basis in bases {
            let mut subset = chunks_of(&desc, &shards, basis.iter().copied());
            for ch in &mut subset {
                assert!(valid(ch));
                ch.memo = frame_leaf_hash(ch.index, &ch.frame, CONTEXT.len()).expect("valid");
            }
            let mut rebuilt = PreallocVec::with_capacity(16);
            assert!(
                decode_and_reencode(&subset, CONTEXT.len(), &mut pool, &comp, &mut rebuilt)
                    .is_none(),
                "decoded from {basis:?}"
            );
        }
    }

    fn chunks_of(
        desc: &SegmentDescriptor,
        shards: &[Shard<Vec<u8>>],
        indices: impl Iterator<Item = usize>,
    ) -> Vec<ChunkMsg<Vec<u8>>> {
        let all = build_chunks(TypeId(0), &CONTEXT, desc, shards, &mut VecBufferPool);
        indices.map(|i| all[i].clone()).collect()
    }

    /// Bodies that compress and bodies that do not, decoded from the data
    /// alone, the parity alone and a mix, with the rebuilt chunks the ones
    /// the publisher made.
    #[test]
    fn test_decode_from_any_half() {
        let mut pool = VecBufferPool;
        let comp = SnappyBlockCompressor;
        let mut state = 5u64;
        let mut noise = move || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 56) as u8
        };
        for len in [1, 1000, UNIT, UNIT + 1, 7 * UNIT + 99, 128 * UNIT] {
            for compressible in [false, true] {
                let body: Vec<u8> = (0..len)
                    .map(|i| if compressible { (i / 7 % 13) as u8 } else { noise() })
                    .collect();
                let (desc, shards) = build_group::<Vec<u8>, _, _>(&body, &mut pool, &comp);
                assert!(desc.is_valid() && desc.version == 2, "{len} bytes");
                let (k, n) = (desc.k() as usize, desc.n() as usize);
                assert_eq!((shards.len(), n), (n, 2 * k));
                let subsets: [Vec<usize>; 4] = [
                    (0..k).collect(),
                    (k..n).collect(),
                    (0..n).filter(|i| i % 2 == 1).collect(),
                    (0..n).rev().filter(|i| i % 3 != 0).take(k).collect(),
                ];
                for subset in subsets {
                    let available = chunks_of(&desc, &shards, subset.iter().copied());
                    let mut rebuilt = PreallocVec::with_capacity(n);
                    let decoded = decode_and_reencode(
                        &available,
                        CONTEXT.len(),
                        &mut pool,
                        &comp,
                        &mut rebuilt,
                    );
                    assert_eq!(decoded.as_ref(), Some(&body), "{len} bytes from {subset:?}");
                    // The indices of the chunks decoding gives, lowest first.
                    let expected: Vec<usize> = (0..n).collect();
                    assert_eq!(rebuilt.len(), expected.len());
                    for (ch, i) in rebuilt.iter().zip(expected) {
                        let frame = split_frame(&ch.frame, CONTEXT.len()).expect("a frame");
                        assert_eq!(
                            (ch.index as usize, frame.data, frame.proof()),
                            (i, &shards[i].data[..], shards[i].proof)
                        );
                        assert!(valid(ch));
                    }
                }
            }
        }
    }

    #[test]
    fn test_decode_refuses_bad_chunks() {
        let mut pool = VecBufferPool;
        let comp = SnappyBlockCompressor;
        let body: Vec<u8> = (0..5 * UNIT).map(|i| (i * i % 251) as u8).collect();
        let (desc, shards) = build_group::<Vec<u8>, _, _>(&body, &mut pool, &comp);
        let k = desc.k() as usize;
        let mut rebuilt = PreallocVec::with_capacity(2 * k);
        let mut decode = |available: &[ChunkMsg<Vec<u8>>]| {
            decode_and_reencode(available, CONTEXT.len(), &mut VecBufferPool, &comp, &mut rebuilt)
        };
        let good = chunks_of(&desc, &shards, 1..k + 1);
        assert_eq!(decode(&good), Some(body.clone()));
        // A byte changed in a data chunk and in a parity chunk, a chunk given twice,
        // one of the wrong length, an index outside the group, and too few
        // chunks.
        for at in [0, k - 1] {
            let mut bad = good.clone();
            // Past the descriptor, the context and the proof: in the data.
            let last = bad[at].frame.len() - 5;
            bad[at].frame[last] ^= 1;
            assert_eq!(decode(&bad), None);
        }
        let mut bad = good.clone();
        bad[1] = bad[0].clone();
        assert_eq!(decode(&bad), None);
        let mut bad = good.clone();
        bad[2].frame.pop();
        assert_eq!(decode(&bad), None);
        let mut bad = good.clone();
        bad[3].index = 2 * k as u32;
        assert_eq!(decode(&bad), None);
        assert_eq!(decode(&good[1..]), None);
    }

    /// A descriptor is checked before its group id is: no field of it may
    /// overflow the checks.
    #[test]
    fn test_descriptor_limits_do_not_overflow() {
        let base = SegmentDescriptor {
            version: 1,
            hash_id: 0,
            encoding: 0,
            count: 1,
            segment_size: 1,
            total_length: u64::MAX,
            root: [0; 32],
        };
        assert!(!base.is_valid());
        for (segment_size, total_length, count, version, encoding) in [
            (1, (1u64 << 32) + 1, 1, 1, 0),
            (MAX_SEGMENT_SIZE, u64::MAX, u32::MAX, 1, 0),
            (3, 3 * (1u64 << 31), 0, 2, 1),
            (MAX_SEGMENT_SIZE, u64::MAX - 1, 2, 2, 1),
        ] {
            let d =
                SegmentDescriptor { version, encoding, count, segment_size, total_length, ..base };
            assert!(!d.is_valid(), "{d:?}");
            let _ = (d.k(), d.segment_length(0), d.segment_length(d.k().saturating_sub(1)));
        }
    }

    /// A group kept in place: chunks written once into their slots, whatever is
    /// missing computed there, and the body decompressed straight out of
    /// the data slots.
    #[test]
    fn test_decode_in_place() {
        let mut pool = VecBufferPool;
        let comp = SnappyBlockCompressor;
        for len in [1, UNIT + 1, 7 * UNIT + 99, 128 * UNIT] {
            let body: Vec<u8> = (0..len).map(|i| (i / 5 % 17) as u8 ^ (i >> 9) as u8).collect();
            let (desc, shards) = build_group::<Vec<u8>, _, _>(&body, &mut pool, &comp);
            let (k, n, size) = (desc.k() as usize, desc.n() as usize, desc.segment_size as usize);
            // What level 1 gives for each chunk.
            let mut hashes = vec![[0u8; 32]; n];
            for shard in &shards {
                hashes[shard.index as usize] = crate::merkle::leaf_hash(&shard.data);
            }
            for kept in [0, 1, 2] {
                // Every chunk, the parity alone, and every other one.
                let have = |i: usize| match kept {
                    0 => true,
                    1 => i >= k,
                    _ => i % 2 == 1,
                };
                let (mut data, mut parity) = (vec![0u8; k * size], vec![0u8; (n - k) * size]);
                for shard in shards.iter().filter(|shard| have(shard.index as usize)) {
                    let i = shard.index as usize;
                    let slot =
                        if i < k { &mut data[i * size..] } else { &mut parity[(i - k) * size..] };
                    slot[..shard.data.len()].copy_from_slice(&shard.data);
                }
                let tree = complete_in_place(&desc, &mut data, &mut parity, have, &hashes)
                    .expect("consistent");
                for shard in &shards {
                    let i = shard.index as usize;
                    let slot = if i < k { &data[i * size..] } else { &parity[(i - k) * size..] };
                    assert_eq!(
                        &slot[..shard.data.len()],
                        &shard.data[..],
                        "{len} bytes, chunk {i}"
                    );
                    assert_eq!(merkle_proof_from_layers(&tree, i), shard.proof);
                }
                let mut out = vec![0u8; body_len(&desc, &data).expect("well formed")];
                assert_eq!(body_into(&desc, &data, &mut out), Some(body.len()));
                assert!(out == body, "{len} bytes");
            }
            // A chunk that is not the committed one fails the root, and too few chunks
            // decode nothing.
            let (mut data, mut parity) = (vec![0u8; k * size], vec![0u8; (n - k) * size]);
            for shard in &shards {
                let i = shard.index as usize;
                let slot =
                    if i < k { &mut data[i * size..] } else { &mut parity[(i - k) * size..] };
                slot[..shard.data.len()].copy_from_slice(&shard.data);
            }
            parity[0] ^= 1;
            assert!(
                complete_in_place(&desc, &mut data, &mut parity, |i| i >= k, &hashes).is_none()
            );
            assert!(complete_in_place(&desc, &mut data, &mut parity, |i| i > k, &hashes).is_none());
            // A digest that is not the committed one fails the root too.
            parity[0] ^= 1;
            let mut wrong = hashes.clone();
            wrong[n - 1][0] ^= 1;
            assert!(complete_in_place(&desc, &mut data, &mut parity, |_| true, &wrong).is_none());
            assert!(complete_in_place(&desc, &mut data, &mut parity, |_| true, &hashes).is_some());
        }
    }

    /// A chunk's id is its object header and a digest over its data's leaf and
    /// the rest of its frame; its memo is its leaf's digest.
    #[test]
    fn test_chunk_id() {
        let (desc, shards) = build_group::<Vec<u8>, _, _>(
            &[7u8; 40_000],
            &mut VecBufferPool,
            &SnappyBlockCompressor,
        );
        let chunks = build_chunks(TypeId(1), &CONTEXT, &desc, &shards, &mut VecBufferPool);
        let chunk = &chunks[1];
        let frame = split_frame(&chunk.frame, CONTEXT.len()).unwrap();
        let leaf = leaf_hash(frame.data);
        assert_eq!(frame_leaf_hash(1, &chunk.frame, CONTEXT.len()), Some(leaf));
        assert_eq!(chunk.memo, leaf);
        let rest = &chunk.frame[..chunk.frame.len() - frame.data.len()];
        let mut h = Sha256::new();
        h.update(&leaf);
        h.update(rest);
        assert_eq!(chunk.cached_id[0], 1);
        assert_eq!(chunk.cached_id[1..33], chunk.group.key);
        assert_eq!(chunk.cached_id[33..39], [0, 0, 1, 0, 0, 0]);
        assert_eq!(chunk.cached_id[39..], h.finalize()[..20]);
        assert_eq!(
            frame_identity(&chunk.frame, CONTEXT.len()),
            (frame_content(&leaf, rest), Some(leaf))
        );
        assert!(check_frame_leaf(1, &chunk.frame, CONTEXT.len(), &leaf));
        assert!(!check_frame_leaf(1, &chunk.frame, CONTEXT.len(), &[1; 32]));
        assert_eq!(GroupId::of_chunk_id(&chunk.cached_id), chunk.group);
    }

    /// Bytes that do not compress.
    fn noise(len: usize) -> Vec<u8> {
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    /// A body of 10 MiB that does not compress is a plain group of a little
    /// over 640 chunks: more than half the indices a bitmap names, and within
    /// them.
    #[test]
    fn test_largest_gossip_body_fits_a_group() {
        let mut pool = VecBufferPool;
        let comp = SnappyBlockCompressor;
        let body = noise(10 << 20);
        let (desc, shards) = build_group::<Vec<u8>, _, _>(&body, &mut pool, &comp);
        assert!(desc.is_valid() && (desc.version, desc.encoding) == (1, 1));
        assert!((640..MAX_PLAIN_CHUNKS as u32).contains(&desc.count));
        assert_eq!(desc.segment_size as usize, UNIT);
        let available = chunks_of(&desc, &shards, 0..desc.count as usize);
        assert!(available.iter().all(valid));
        let mut rebuilt = PreallocVec::with_capacity(desc.count as usize);
        let decoded =
            decode_and_reencode(&available, CONTEXT.len(), &mut pool, &comp, &mut rebuilt);
        assert!(decoded.as_ref() == Some(&body));
    }

    /// A body past the coded limit goes uncoded: its compression cut at
    /// `UNIT`.
    #[test]
    fn test_plain_group_round_trip() {
        let mut pool = VecBufferPool;
        let comp = SnappyBlockCompressor;
        let body: Vec<u8> =
            (0..(MAX_CODED_CHUNKS as usize / 2 + 1) * UNIT + 5).map(|i| (i % 253) as u8).collect();
        let (desc, shards) = build_group::<Vec<u8>, _, _>(&body, &mut pool, &comp);
        assert!(desc.is_valid() && (desc.version, desc.encoding) == (1, 1));
        let count = desc.count as usize;
        assert_eq!(count, comp.compress(&body).len().div_ceil(UNIT));
        assert!(count > 1 && desc.segment_size as usize == UNIT);
        let available = chunks_of(&desc, &shards, (0..count).rev());
        let mut rebuilt = PreallocVec::with_capacity(count);
        assert_eq!(
            decode_and_reencode(&available, CONTEXT.len(), &mut pool, &comp, &mut rebuilt),
            Some(body)
        );
        assert_eq!(rebuilt.len(), count);
        assert_eq!(
            decode_and_reencode(&available[1..], CONTEXT.len(), &mut pool, &comp, &mut rebuilt,),
            None
        );
        // A coded descriptor past `MAX_CHUNKS` is rejected (`seacast-lite.md` §1).
        let wide_coded = SegmentDescriptor {
            version: 2,
            hash_id: 0,
            encoding: 1,
            count: MAX_CHUNKS + 2,
            segment_size: UNIT as u32,
            total_length: ((MAX_CHUNKS / 2 + 1) as u64) * (UNIT as u64),
            root: [0; 32],
        };
        assert!(!wide_coded.is_valid());
    }

    /// A body whose compression has more segments than a group holds goes as
    /// it is.
    #[test]
    fn test_plain_group_of_a_body_that_grows() {
        let mut pool = VecBufferPool;
        let comp = SnappyBlockCompressor;
        let body = noise(MAX_PLAIN_BODY);
        assert!(comp.compress(&body).len() > MAX_PLAIN_BODY);
        let (desc, shards) = build_group::<Vec<u8>, _, _>(&body, &mut pool, &comp);
        assert!(desc.is_valid() && (desc.version, desc.encoding) == (1, 0));
        assert_eq!(desc.count as usize, MAX_PLAIN_CHUNKS);
        let available = chunks_of(&desc, &shards, 0..MAX_PLAIN_CHUNKS);
        let mut rebuilt = PreallocVec::with_capacity(MAX_PLAIN_CHUNKS);
        let decoded =
            decode_and_reencode(&available, CONTEXT.len(), &mut pool, &comp, &mut rebuilt);
        assert!(decoded.as_ref() == Some(&body));
    }
}
