//! The payload on the gossipsub binding (`seacast-lite.md` §1, §2). A chunk's
//! frame is the SSZ of `Chunk`, the decompressed data of its gossipsub
//! message, so a received message is a frame as it stands:
//!
//! ```text
//!   0  slot                 uint64
//!   8  beacon_block_root    Bytes32
//!  40  group                Bytes32, the group key
//!  72  descriptor           SegmentDescriptor (design A)
//! 123  index                uint32
//! 127  offset of proof      uint32, = 135
//! 131  offset of data       uint32
//! 135  proof                List[Bytes32, 14]
//!      data                 ByteList[MAX_SEGMENT_SIZE]
//! ```
//!
//! The context the domain reads is `slot | beacon_block_root`.

use std::marker::PhantomData;

use seacast_codec::{
    BufferPool, ChunkBytes, DESCRIPTOR_BYTES, MAX_PLAIN_CHUNKS, MAX_PROOF_DEPTH, MAX_SEGMENT_SIZE,
    SegmentDescriptor, Sha256, Shard, SnappyBlockCompressor, chunk_wire_size,
    decode_and_reencode_with, group_id, leaf_hash, snappy, verify_leaf_path,
};
use seacast_core::{
    Bytes32, ChunkId, ChunkMsg, GroupId, PreallocVec, Shape, TypeCodec, TypeId, ValidationResult,
};

/// The payload's object type (`seacast-bindings.md` §1.2).
pub const PAYLOAD: TypeId = TypeId(0);

/// A chunk's context: `slot | beacon_block_root`.
pub const CONTEXT_BYTES: usize = 8 + 32;
const GROUP_AT: usize = CONTEXT_BYTES;
const DESCRIPTOR_AT: usize = GROUP_AT + 32;
const INDEX_AT: usize = DESCRIPTOR_AT + DESCRIPTOR_BYTES;
/// The fixed part of `Chunk`: its fields up to the two offsets.
pub const CHUNK_FIXED: usize = INDEX_AT + 4 + 4 + 4;
/// The bound on a chunk's SSZ (`seacast-bindings.md` §1.4, design A).
pub const MAX_CHUNK_BYTES: usize = CHUNK_FIXED + 32 * MAX_PROOF_DEPTH + MAX_SEGMENT_SIZE as usize;

pub const MESSAGE_ID_BYTES: usize = 32 + 4 + 20;
/// A chunk's gossipsub message id (`seacast-lite.md` §2 `message_id`): group
/// key, index, content id.
pub type MessageId = [u8; MESSAGE_ID_BYTES];

/// `MESSAGE_DOMAIN_VALID_SNAPPY` of the Altair networking rules.
const MESSAGE_DOMAIN_VALID_SNAPPY: [u8; 4] = [1, 0, 0, 0];

/// `group_key(gid, slot) = sha256(0x03 || gid || uint64_le(slot))`
/// (`seacast-lite.md` §1): a descriptor's group id, committed at a slot.
pub fn group_key(gid: &Bytes32, slot: u64) -> Bytes32 {
    let mut h = Sha256::new();
    h.update(&[0x03]);
    h.update(gid);
    h.update(&slot.to_le_bytes());
    h.finalize()
}

/// The node's id of the payload group with `key` (`seacast-bindings.md` §1.2).
pub const fn payload_group(key: Bytes32) -> GroupId {
    GroupId::new(PAYLOAD, key, 0)
}

/// The message id of a payload chunk with the node's id `id`.
pub fn message_id_of(id: &ChunkId) -> MessageId {
    let mut out = [0u8; MESSAGE_ID_BYTES];
    out[..32].copy_from_slice(&id[1..33]);
    out[32..].copy_from_slice(&id[35..]);
    out
}

/// The node's id of the payload chunk whose message id is `mid`. `None`: not
/// of a chunk's length.
pub fn chunk_id_of(mid: &[u8]) -> Option<ChunkId> {
    let mid: &MessageId = mid.try_into().ok()?;
    let mut out = [0u8; 59];
    out[0] = PAYLOAD.0;
    out[1..33].copy_from_slice(&mid[..32]);
    out[35..].copy_from_slice(&mid[32..]);
    Some(out)
}

/// A chunk's frame, split.
pub struct Chunk<'a> {
    pub slot: u64,
    pub beacon_block_root: &'a [u8],
    pub group: Bytes32,
    pub descriptor: SegmentDescriptor,
    pub index: u32,
    pub proof: &'a [Bytes32],
    pub data: &'a [u8],
}

/// Splits `frame`, the SSZ of a `Chunk`. `None` where it is not one: too
/// short, an offset out of place, a proof that is not whole digests or over
/// its limit, data over its limit.
pub fn split_chunk(frame: &[u8]) -> Option<Chunk<'_>> {
    split_parts(frame, &[])
}

/// [`split_chunk`] of the frame `head || tail`, which a host may keep cut at
/// its data ([`ChunkBytes::tail`]). `None` also where it is cut elsewhere.
pub fn split_parts<'a>(head: &'a [u8], tail: &'a [u8]) -> Option<Chunk<'a>> {
    let (fixed, rest) = head.split_at_checked(CHUNK_FIXED)?;
    let u32_at = |at: usize| u32::from_le_bytes(fixed[at..at + 4].try_into().unwrap());
    let (proof_at, data_at) = (u32_at(INDEX_AT + 4) as usize, u32_at(INDEX_AT + 8) as usize);
    if proof_at != CHUNK_FIXED {
        return None;
    }
    let (proof, data) = rest.split_at_checked(data_at.checked_sub(CHUNK_FIXED)?)?;
    let data = match (data, tail) {
        (data, []) => data,
        ([], tail) => tail,
        _ => return None,
    };
    let (proof, []) = proof.as_chunks::<32>() else {
        return None;
    };
    if proof.len() > MAX_PROOF_DEPTH || data.len() > MAX_SEGMENT_SIZE as usize {
        return None;
    }
    Some(Chunk {
        slot: u64::from_le_bytes(fixed[..8].try_into().unwrap()),
        beacon_block_root: &fixed[8..CONTEXT_BYTES],
        group: fixed[GROUP_AT..DESCRIPTOR_AT].try_into().unwrap(),
        descriptor: SegmentDescriptor::deserialize(&fixed[DESCRIPTOR_AT..INDEX_AT])?,
        index: u32_at(INDEX_AT),
        proof,
        data,
    })
}

/// The SSZ of a `Chunk`. `context` is `slot | beacon_block_root`.
pub fn build_chunk(
    context: &[u8; CONTEXT_BYTES],
    group: &Bytes32,
    descriptor: &SegmentDescriptor,
    index: u32,
    proof: &[Bytes32],
    data: &[u8],
) -> Vec<u8> {
    let data_at = CHUNK_FIXED + 32 * proof.len();
    let mut frame = Vec::with_capacity(data_at + data.len());
    frame.extend_from_slice(context);
    frame.extend_from_slice(group);
    frame.extend_from_slice(&descriptor.serialize());
    frame.extend_from_slice(&index.to_le_bytes());
    frame.extend_from_slice(&(CHUNK_FIXED as u32).to_le_bytes());
    frame.extend_from_slice(&(data_at as u32).to_le_bytes());
    for digest in proof {
        frame.extend_from_slice(digest);
    }
    frame.extend_from_slice(data);
    frame
}

/// The payload's [`TypeCodec`] on one topic. It reads a frame kept in two
/// parts ([`ChunkBytes::tail`]); the frames it makes are whole.
///
/// The group key binds the descriptor and the slot, not the block root
/// (`seacast-lite.md` §1): two blocks of a slot whose bids commit one
/// descriptor share a group. The node asks the domain once a group, with the
/// first chunk's context, so a later chunk's root is not the domain's to see.
/// A host that must hold every chunk to an installed block checks the root in
/// its catalog's `check`.
pub struct PayloadCodec<Pool, B> {
    pub pool: Pool,
    /// The content id's hash over what precedes the chunk: the domain, the
    /// topic's length, the topic.
    id_prefix: Sha256,
    _buffer: PhantomData<B>,
}

impl<Pool, B> PayloadCodec<Pool, B>
where
    Pool: BufferPool<B>,
    B: ChunkBytes,
{
    /// `topic`: the gossipsub topic's name, which a chunk's content id binds.
    pub fn new(pool: Pool, topic: &[u8]) -> Self {
        let mut id_prefix = Sha256::new();
        id_prefix.update(&MESSAGE_DOMAIN_VALID_SNAPPY);
        id_prefix.update(&(topic.len() as u64).to_le_bytes());
        id_prefix.update(topic);
        Self { pool, id_prefix, _buffer: PhantomData }
    }

    /// The Altair message id of `frame` on the topic: the first 20 bytes of
    /// `sha256(domain || uint64_le(len(topic)) || topic || frame)`.
    pub fn content_id(&self, frame: &[u8]) -> [u8; 20] {
        content_id(&self.id_prefix, frame, &[])
    }

    /// A received message as a chunk. `data` is the message's data, snappy
    /// compressed; `decompress` writes the frame, of the length given, into a
    /// buffer of the host's ([`snappy::decompress_into`]). The chunk's id is
    /// set, and its `memo` to its data's leaf digest, the proof not checked.
    ///
    /// `None`: the frame is over its bound, does not decompress or is not a
    /// `Chunk`. The message then has the inherited id
    /// ([`content_id`](Self::content_id) of what decompressed), and is
    /// rejected with no state made (`seacast-lite.md` §2).
    pub fn read_message(
        &self,
        data: &[u8],
        decompress: impl FnOnce(&[u8], usize) -> Option<B>,
    ) -> Option<ChunkMsg<B>> {
        let len = snappy::decompressed_len(data).filter(|&len| len <= MAX_CHUNK_BYTES)?;
        let frame = decompress(data, len).filter(|frame| frame.len() == len)?;
        let f = split(&frame)?;
        let (group, index, memo) = (payload_group(f.group), f.index, leaf_hash(f.data));
        let cached_id = self.chunk_id(&group, index, frame.as_bytes(), frame.tail());
        Some(ChunkMsg { group, index, cached_id, frame, memo, wire_len: data.len() as u32 })
    }

    /// The chunks of a group built by `seacast_codec::build_group`, as a
    /// publisher hands them to the node. `context` is `slot |
    /// beacon_block_root`.
    pub fn build_chunks(
        &mut self,
        context: &[u8; CONTEXT_BYTES],
        descriptor: &SegmentDescriptor,
        shards: &[Shard<B>],
    ) -> Vec<ChunkMsg<B>> {
        let slot = u64::from_le_bytes(context[..8].try_into().unwrap());
        let key = group_key(&group_id(descriptor), slot);
        let group = payload_group(key);
        shards
            .iter()
            .map(|shard| {
                let data = shard.data.as_bytes();
                let frame = build_chunk(context, &key, descriptor, shard.index, &shard.proof, data);
                ChunkMsg {
                    group,
                    index: shard.index,
                    cached_id: self.chunk_id(&group, shard.index, &frame, &[]),
                    frame: self.pool.alloc_from_slice(&frame),
                    memo: leaf_hash(data),
                    wire_len: 0,
                }
            })
            .collect()
    }

    /// The rest of level 1 for a chunk [`TypeCodec::check_proof`] answered
    /// `Pending` for: its Merkle proof, from the leaf digest in `memo`. The
    /// host runs it wherever it sees fit before it calls `on_validated`.
    pub fn check_proof(&self, chunk: &ChunkMsg<B>) -> ValidationResult {
        let ok = split(&chunk.frame).is_some_and(|f| {
            let d = &f.descriptor;
            verify_leaf_path(&d.root, &chunk.memo, f.index, d.count, f.proof)
        });
        if ok { ValidationResult::Accept } else { ValidationResult::Reject }
    }

    /// The node's id of the chunk of `group` at `index` whose frame is `head
    /// || tail`: [`chunk_id_of`] its message id.
    pub fn chunk_id(&self, group: &GroupId, index: u32, head: &[u8], tail: &[u8]) -> ChunkId {
        chunk_id(&self.id_prefix, group, index, head, tail)
    }
}

/// A frame split, whole or kept in two parts.
fn split<B: ChunkBytes>(frame: &B) -> Option<Chunk<'_>> {
    split_parts(frame.as_bytes(), frame.tail())
}

fn content_id(id_prefix: &Sha256, head: &[u8], tail: &[u8]) -> [u8; 20] {
    let mut h = id_prefix.clone();
    h.update(head);
    h.update(tail);
    h.finalize()[..20].try_into().unwrap()
}

fn chunk_id(id_prefix: &Sha256, group: &GroupId, index: u32, head: &[u8], tail: &[u8]) -> ChunkId {
    let mut out = [0u8; 59];
    out[0] = group.type_id.0;
    out[1..33].copy_from_slice(&group.key);
    out[35..39].copy_from_slice(&index.to_le_bytes());
    out[39..].copy_from_slice(&content_id(id_prefix, head, tail));
    out
}

impl<Pool, B> TypeCodec<B> for PayloadCodec<Pool, B>
where
    Pool: BufferPool<B>,
    B: ChunkBytes,
{
    fn shape(&self, chunk: &ChunkMsg<B>) -> Option<Shape> {
        let d = split(&chunk.frame)?.descriptor;
        Some(Shape { n: d.count, k: d.k() })
    }

    /// `validate_chunk` of `seacast-lite.md` §3 up to the proof: the chunk's
    /// group and index are the frame's, the descriptor is valid, the group key
    /// is the descriptor's at the slot, and the proof and the data have the
    /// lengths the descriptor gives.
    fn check(&self, chunk: &ChunkMsg<B>) -> bool {
        let Some(f) = split(&chunk.frame) else {
            return false;
        };
        let d = &f.descriptor;
        chunk.group == payload_group(f.group) &&
            chunk.index == f.index &&
            d.is_valid() &&
            d.count as usize <= MAX_PLAIN_CHUNKS &&
            f.index < d.count &&
            f.proof.len() == d.proof_len() &&
            f.data.len() == d.segment_length(f.index) &&
            group_key(&group_id(d), f.slot) == f.group
    }

    fn check_proof(&mut self, _chunk: &ChunkMsg<B>) -> ValidationResult {
        ValidationResult::Pending
    }

    fn header_id(&self, chunk: &ChunkMsg<B>) -> Bytes32 {
        split(&chunk.frame).map(|f| group_id(&f.descriptor)).unwrap_or_default()
    }

    fn context<'a>(&self, chunk: &'a ChunkMsg<B>) -> &'a [u8] {
        chunk.frame.as_bytes().get(..CONTEXT_BYTES).unwrap_or(&[])
    }

    fn decode(
        &mut self,
        group: &GroupId,
        available: &[ChunkMsg<B>],
        _shape: &Shape,
        out_rebuilt: &mut PreallocVec<ChunkMsg<B>>,
    ) -> Option<B> {
        let first = &available.first()?.frame;
        let f = split(first)?;
        let (descriptor, key) = (f.descriptor, f.group);
        let context: &[u8; CONTEXT_BYTES] = first.as_bytes()[..CONTEXT_BYTES].try_into().unwrap();
        // Every chunk of the group has the same descriptor, so the same proof
        // length before its data.
        let skip = CHUNK_FIXED + 32 * descriptor.proof_len();
        let (id_prefix, group) = (&self.id_prefix, *group);
        decode_and_reencode_with(
            available,
            &descriptor,
            skip,
            &mut self.pool,
            &SnappyBlockCompressor,
            out_rebuilt,
            |index, proof, data, leaf, pool| {
                let frame = build_chunk(context, &key, &descriptor, index, proof, data);
                ChunkMsg {
                    group,
                    index,
                    cached_id: chunk_id(id_prefix, &group, index, &frame, &[]),
                    frame: pool.alloc_from_slice(&frame),
                    memo: *leaf,
                    wire_len: 0,
                }
            },
        )
    }

    fn wire_size(&self, chunk: &ChunkMsg<B>, _first_of_group: bool) -> usize {
        chunk_wire_size(chunk)
    }
}

#[cfg(test)]
mod tests {
    use seacast_codec::{VecBufferPool, build_group, sha256};

    use super::*;

    const TOPIC: &[u8] = b"/eth2/00000000/seacast_payload/ssz_snappy";

    fn context(slot: u64) -> [u8; CONTEXT_BYTES] {
        let mut context = [9u8; CONTEXT_BYTES];
        context[..8].copy_from_slice(&slot.to_le_bytes());
        context
    }

    type Codec = PayloadCodec<VecBufferPool, Vec<u8>>;

    fn group(len: usize) -> (Codec, Vec<ChunkMsg<Vec<u8>>>) {
        let body: Vec<u8> = (0..len as u32).map(|i| (i * 31 % 251) as u8).collect();
        let (descriptor, shards) =
            build_group::<Vec<u8>, _, _>(&body, &mut VecBufferPool, &SnappyBlockCompressor);
        let mut codec = PayloadCodec::new(VecBufferPool, TOPIC);
        let chunks = codec.build_chunks(&context(77), &descriptor, &shards);
        (codec, chunks)
    }

    #[test]
    fn test_chunk_bytes() {
        assert_eq!((CHUNK_FIXED, MAX_CHUNK_BYTES), (135, 33_351));
        let (codec, chunks) = group(100_000);
        let chunk = &chunks[3];
        let f = split_chunk(&chunk.frame).unwrap();
        let d = f.descriptor;

        // The SSZ of `Chunk`, field by field.
        let frame = &chunk.frame;
        assert_eq!(frame[..8], 77u64.to_le_bytes());
        assert_eq!(frame[8..40], [9; 32]);
        assert_eq!(frame[40..72], chunk.group.key);
        assert_eq!(frame[72..123], d.serialize());
        assert_eq!(frame[123..127], 3u32.to_le_bytes());
        assert_eq!(frame[127..131], 135u32.to_le_bytes());
        assert_eq!(frame[131..135], (135 + 32 * d.proof_len() as u32).to_le_bytes());
        assert_eq!(frame.len(), 135 + 32 * d.proof_len() + d.segment_length(3));

        // The group key and the id (`seacast-lite.md` §1, §2).
        let mut keyed = vec![0x03];
        keyed.extend_from_slice(&group_id(&d));
        keyed.extend_from_slice(&77u64.to_le_bytes());
        assert_eq!(chunk.group, payload_group(sha256(&keyed)));
        let mut hashed = vec![1, 0, 0, 0];
        hashed.extend_from_slice(&(TOPIC.len() as u64).to_le_bytes());
        hashed.extend_from_slice(TOPIC);
        hashed.extend_from_slice(frame);
        let mid = message_id_of(&chunk.cached_id);
        assert_eq!(mid[..32], chunk.group.key);
        assert_eq!(mid[32..36], 3u32.to_le_bytes());
        assert_eq!(mid[36..], sha256(&hashed)[..20]);
        assert_eq!(chunk_id_of(&mid), Some(chunk.cached_id));
        assert_eq!(GroupId::of_chunk_id(&chunk.cached_id), chunk.group);
        assert_eq!(chunk_id_of(&mid[..55]), None);

        // Level 1.
        assert!(codec.check(chunk));
        assert_eq!(codec.check_proof(chunk), ValidationResult::Accept);
        assert_eq!(codec.shape(chunk), Some(Shape { n: d.count, k: d.k() }));
        assert_eq!(codec.header_id(chunk), group_id(&d));
        assert_eq!(codec.context(chunk), context(77));
    }

    #[test]
    fn test_level1_refuses() {
        let (codec, chunks) = group(100_000);
        let chunk = &chunks[1];
        let with = |edit: &dyn Fn(&mut ChunkMsg<Vec<u8>>)| {
            let mut c = chunk.clone();
            edit(&mut c);
            c
        };
        // Another slot is another key; another root is not (`seacast-lite.md` §1).
        assert!(!codec.check(&with(&|c| c.frame[0] ^= 1)));
        assert!(codec.check(&with(&|c| c.frame[8] ^= 1)));
        assert!(!codec.check(&with(&|c| c.frame[40] ^= 1)));
        assert!(!codec.check(&with(&|c| c.frame[72 + 19] ^= 1)));
        assert!(!codec.check(&with(&|c| c.index = 2)));
        assert!(!codec.check(&with(&|c| c.frame[127] += 1)));
        assert!(!codec.check(&with(&|c| c.frame[131] += 32)));
        assert!(!codec.check(&with(&|c| c.frame.push(0))));
        assert!(!codec.check(&with(&|c| c.frame.truncate(100))));
        assert!(!codec.check(&with(&|c| c.group.index = 1)));
        // A proof step or a data byte changed passes the head, not the proof.
        for at in [135, chunk.frame.len() - 1] {
            let mut bad = with(&|c| c.frame[at] ^= 1);
            bad.memo = leaf_hash(split_chunk(&bad.frame).unwrap().data);
            assert!(codec.check(&bad));
            assert_eq!(codec.check_proof(&bad), ValidationResult::Reject);
        }
    }

    #[test]
    fn test_message_round_trip() {
        let (codec, chunks) = group(100_000);
        let decompress = |data: &[u8], len: usize| {
            let mut out = vec![0u8; len];
            snappy::decompress_into(data, &mut out).map(|n| {
                out.truncate(n);
                out
            })
        };
        for chunk in &chunks {
            let data = snappy::compress(&chunk.frame);
            let read = codec.read_message(&data, decompress).unwrap();
            assert_eq!(read, ChunkMsg { wire_len: data.len() as u32, ..chunk.clone() });
            assert_eq!(codec.wire_size(&read, false), data.len());
        }
        // Over the bound, not snappy, not a chunk.
        assert!(
            codec
                .read_message(&snappy::compress(&[0u8; MAX_CHUNK_BYTES + 1]), decompress)
                .is_none()
        );
        assert!(codec.read_message(&[0xff; 8], decompress).is_none());
        assert!(codec.read_message(&snappy::compress(&[0u8; 134]), decompress).is_none());
    }

    /// A frame cut at its data.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Cut(Vec<u8>, Vec<u8>);

    impl seacast_core::ChunkBuffer for Cut {
        fn len(&self) -> usize {
            self.0.len() + self.1.len()
        }
    }

    impl ChunkBytes for Cut {
        fn as_bytes(&self) -> &[u8] {
            &self.0
        }

        fn tail(&self) -> &[u8] {
            &self.1
        }
    }

    struct CutPool;

    impl BufferPool<Cut> for CutPool {
        fn alloc_from_slice(&mut self, data: &[u8]) -> Cut {
            Cut(data.to_vec(), Vec::new())
        }
    }

    #[test]
    fn test_a_frame_in_two_parts() {
        let (whole, chunks) = group(100_000);
        let mut codec = PayloadCodec::<CutPool, Cut>::new(CutPool, TOPIC);
        let cut = |chunk: &ChunkMsg<Vec<u8>>, at: usize| ChunkMsg {
            group: chunk.group,
            index: chunk.index,
            cached_id: chunk.cached_id,
            frame: Cut(chunk.frame[..at].to_vec(), chunk.frame[at..].to_vec()),
            memo: chunk.memo,
            wire_len: 0,
        };
        let data_at = |chunk: &ChunkMsg<Vec<u8>>| {
            chunk.frame.len() - split_chunk(&chunk.frame).unwrap().data.len()
        };
        let parts: Vec<_> = chunks.iter().map(|c| cut(c, data_at(c))).collect();

        // The same chunk, the same id and the same level 1, whole or in parts.
        for (chunk, part) in chunks.iter().zip(&parts) {
            let Cut(head, tail) = &part.frame;
            assert_eq!(codec.chunk_id(&part.group, part.index, head, tail), chunk.cached_id);
            assert!(codec.check(part));
            assert_eq!(codec.check_proof(part), ValidationResult::Accept);
            assert_eq!(codec.shape(part), whole.shape(chunk));
            assert_eq!(codec.header_id(part), whole.header_id(chunk));
            assert_eq!(codec.context(part), whole.context(chunk));
        }
        // Cut elsewhere than at its data, it is no chunk.
        assert!(!codec.check(&cut(&chunks[0], data_at(&chunks[0]) + 1)));
        assert!(!codec.check(&cut(&chunks[0], CHUNK_FIXED)));

        // Level 2 from parts rebuilds the chunks the publisher built.
        let shape = codec.shape(&parts[0]).unwrap();
        let available: Vec<_> = parts.iter().rev().take(shape.k as usize).cloned().collect();
        let mut rebuilt = PreallocVec::with_capacity(shape.n as usize);
        let body = codec.decode(&parts[0].group, &available, &shape, &mut rebuilt).unwrap();
        assert_eq!(body.0.len(), 100_000);
        for (chunk, made) in chunks.iter().zip(rebuilt.as_slice()) {
            assert_eq!(made.cached_id, chunk.cached_id);
            assert_eq!([&made.frame.0[..], &made.frame.1[..]].concat(), chunk.frame);
        }
    }

    #[test]
    fn test_level2_rebuilds_the_group() {
        let (mut codec, chunks) = group(100_000);
        let shape = codec.shape(&chunks[0]).unwrap();
        let available: Vec<_> = chunks.iter().rev().take(shape.k as usize).cloned().collect();
        let mut rebuilt = PreallocVec::with_capacity(shape.n as usize);
        let body = codec.decode(&chunks[0].group, &available, &shape, &mut rebuilt).unwrap();
        assert_eq!(body.len(), 100_000);
        assert_eq!(rebuilt.as_slice(), chunks.as_slice());
    }
}
