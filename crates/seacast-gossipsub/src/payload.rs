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
//!
//! [`Layout::Attached`] is a frame for a body that is no payload: the same
//! without the context, and the group key the descriptor's alone. What its
//! domain reads travels beside the frame, not in it ([`attach`]).

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
/// The fixed part of a frame after its context: the group key, the
/// descriptor, the index and the two offsets.
const FIXED_AFTER_CONTEXT: usize = 32 + DESCRIPTOR_BYTES + 4 + 4 + 4;
/// The fixed part of `Chunk`: its fields up to the two offsets.
pub const CHUNK_FIXED: usize = CONTEXT_BYTES + FIXED_AFTER_CONTEXT;

/// A frame's layout, one a topic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// `seacast-lite.md` §2's `Chunk`. The group key binds the slot.
    Payload,
    /// `Chunk` without `slot` and `beacon_block_root`. The group key is
    /// `sha256(0x03 || group_id)`, so a body is one group whenever it is sent.
    /// On the wire an attachment precedes the frame ([`attach`]): bytes that
    /// travel with a chunk on a link and are not the chunk's, so its id and
    /// the frame a node keeps and rebuilds are the same with or without them.
    Attached,
}

impl Layout {
    pub const fn context_len(self) -> usize {
        match self {
            Self::Payload => CONTEXT_BYTES,
            Self::Attached => 0,
        }
    }

    /// The fixed part of a frame: its fields up to the two offsets.
    pub const fn fixed(self) -> usize {
        self.context_len() + FIXED_AFTER_CONTEXT
    }

    /// The bound on a frame.
    pub const fn max_frame(self) -> usize {
        self.fixed() + 32 * MAX_PROOF_DEPTH + MAX_SEGMENT_SIZE as usize
    }

    /// The key of the group of a descriptor with id `gid`, `context` the
    /// frame's.
    pub fn group_key(self, gid: &Bytes32, context: &[u8]) -> Bytes32 {
        let mut h = Sha256::new();
        h.update(&[0x03]);
        h.update(gid);
        if let Self::Payload = self {
            h.update(&context[..8]);
        }
        h.finalize()
    }

    /// Splits the frame `head || tail`, which a host may keep cut at its data
    /// ([`ChunkBytes::tail`]). `None` where it is not one: too short, an
    /// offset out of place, a proof that is not whole digests or over its
    /// limit, data over its limit, or a cut elsewhere than at its data.
    pub fn split<'a>(self, head: &'a [u8], tail: &'a [u8]) -> Option<Chunk<'a>> {
        let (context, fixed_at) = (self.context_len(), self.fixed());
        let (fixed, rest) = head.split_at_checked(fixed_at)?;
        let (group_at, descriptor_at) = (context, context + 32);
        let index_at = descriptor_at + DESCRIPTOR_BYTES;
        let u32_at = |at: usize| u32::from_le_bytes(fixed[at..at + 4].try_into().unwrap());
        let (proof_at, data_at) = (u32_at(index_at + 4) as usize, u32_at(index_at + 8) as usize);
        if proof_at != fixed_at {
            return None;
        }
        let (proof, data) = rest.split_at_checked(data_at.checked_sub(fixed_at)?)?;
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
        let slot = fixed.first_chunk::<8>().filter(|_| context != 0);
        Some(Chunk {
            slot: slot.map_or(0, |slot| u64::from_le_bytes(*slot)),
            beacon_block_root: &fixed[context.min(8)..context],
            group: fixed[group_at..descriptor_at].try_into().unwrap(),
            descriptor: SegmentDescriptor::deserialize(&fixed[descriptor_at..index_at])?,
            index: u32_at(index_at),
            proof,
            data,
        })
    }

    /// A frame. `context` is the layout's: `slot | beacon_block_root`, or
    /// nothing.
    pub fn build(
        self,
        context: &[u8],
        group: &Bytes32,
        descriptor: &SegmentDescriptor,
        index: u32,
        proof: &[Bytes32],
        data: &[u8],
    ) -> Vec<u8> {
        debug_assert_eq!(context.len(), self.context_len());
        let data_at = self.fixed() + 32 * proof.len();
        let mut frame = Vec::with_capacity(data_at + data.len());
        frame.extend_from_slice(context);
        frame.extend_from_slice(group);
        frame.extend_from_slice(&descriptor.serialize());
        frame.extend_from_slice(&index.to_le_bytes());
        frame.extend_from_slice(&(self.fixed() as u32).to_le_bytes());
        frame.extend_from_slice(&(data_at as u32).to_le_bytes());
        for digest in proof {
            frame.extend_from_slice(digest);
        }
        frame.extend_from_slice(data);
        frame
    }
}

/// The bound on an attachment.
pub const MAX_ATTACHMENT: usize = u16::MAX as usize;

/// The start of a [`Layout::Attached`] message: `uint16 length | attachment`,
/// the frame after it. `attachment` may be empty, and is at most
/// [`MAX_ATTACHMENT`] bytes.
pub fn attach(attachment: &[u8], out: &mut Vec<u8>) {
    debug_assert!(attachment.len() <= MAX_ATTACHMENT);
    out.extend_from_slice(&(attachment.len() as u16).to_le_bytes());
    out.extend_from_slice(attachment);
}

/// A [`Layout::Attached`] message as its attachment and its frame.
pub fn split_attached(message: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = message.split_first_chunk::<2>()?;
    rest.split_at_checked(u16::from_le_bytes(*len) as usize)
}
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
    topic_group(PAYLOAD, key)
}

/// The node's id of the group with `key` on the topic of `object_type`. The
/// wire names a group by its key alone: a host with a type a topic gives the
/// type from the topic, and for an entry that names no topic from the group
/// it has on record.
pub const fn topic_group(object_type: TypeId, key: Bytes32) -> GroupId {
    GroupId::new(object_type, key, 0)
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
    chunk_id_on(PAYLOAD, mid)
}

/// [`chunk_id_of`] for a chunk of `object_type`.
pub fn chunk_id_on(object_type: TypeId, mid: &[u8]) -> Option<ChunkId> {
    let mid: &MessageId = mid.try_into().ok()?;
    let mut out = [0u8; 59];
    out[0] = object_type.0;
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
    Layout::Payload.split(head, tail)
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
    Layout::Payload.build(context, group, descriptor, index, proof, data)
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
    /// The type of the topic's groups.
    object_type: TypeId,
    layout: Layout,
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
        Self::of(PAYLOAD, pool, topic)
    }

    /// The codec of `topic` where its groups are of `object_type`: a host
    /// with several chunk topics gives each a type of its own.
    pub fn of(object_type: TypeId, pool: Pool, topic: &[u8]) -> Self {
        Self::with_layout(object_type, Layout::Payload, pool, topic)
    }

    /// [`of`](Self::of) for a topic whose frames are `layout`'s.
    pub fn with_layout(object_type: TypeId, layout: Layout, pool: Pool, topic: &[u8]) -> Self {
        let mut id_prefix = Sha256::new();
        id_prefix.update(&MESSAGE_DOMAIN_VALID_SNAPPY);
        id_prefix.update(&(topic.len() as u64).to_le_bytes());
        id_prefix.update(topic);
        Self { pool, object_type, layout, id_prefix, _buffer: PhantomData }
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
        let bound = self.layout.max_frame();
        let len = snappy::decompressed_len(data).filter(|&len| len <= bound)?;
        let frame = decompress(data, len).filter(|frame| frame.len() == len)?;
        self.read_frame(frame, data.len() as u32)
    }

    /// A frame as a chunk, as [`read_message`](Self::read_message) makes it.
    /// A host of [`Layout::Attached`] takes the attachment off the message
    /// first ([`split_attached`]). `wire_len`: the message's length.
    pub fn read_frame(&self, frame: B, wire_len: u32) -> Option<ChunkMsg<B>> {
        let f = self.split(&frame)?;
        let group = topic_group(self.object_type, f.group);
        let (index, memo) = (f.index, leaf_hash(f.data));
        let cached_id = self.chunk_id(&group, index, frame.as_bytes(), frame.tail());
        Some(ChunkMsg { group, index, cached_id, frame, memo, wire_len })
    }

    fn split<'a>(&self, frame: &'a B) -> Option<Chunk<'a>> {
        self.layout.split(frame.as_bytes(), frame.tail())
    }

    /// The chunks of a group built by `seacast_codec::build_group`, as a
    /// publisher hands them to the node. `context` is the layout's: `slot |
    /// beacon_block_root`, or nothing.
    pub fn build_chunks(
        &mut self,
        context: &[u8],
        descriptor: &SegmentDescriptor,
        shards: &[Shard<B>],
    ) -> Vec<ChunkMsg<B>> {
        let layout = self.layout;
        let key = layout.group_key(&group_id(descriptor), context);
        let group = topic_group(self.object_type, key);
        shards
            .iter()
            .map(|shard| {
                let data = shard.data.as_bytes();
                let frame =
                    layout.build(context, &key, descriptor, shard.index, &shard.proof, data);
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
        let ok = self.split(&chunk.frame).is_some_and(|f| {
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
        let d = self.split(&chunk.frame)?.descriptor;
        Some(Shape { n: d.count, k: d.k() })
    }

    /// `validate_chunk` of `seacast-lite.md` §3 up to the proof: the chunk's
    /// group and index are the frame's, the descriptor is valid, the group key
    /// is the descriptor's at the slot, and the proof and the data have the
    /// lengths the descriptor gives.
    fn check(&self, chunk: &ChunkMsg<B>) -> bool {
        let Some(f) = self.split(&chunk.frame) else {
            return false;
        };
        let d = &f.descriptor;
        let context = &chunk.frame.as_bytes()[..self.layout.context_len()];
        chunk.group == topic_group(self.object_type, f.group) &&
            chunk.index == f.index &&
            d.is_valid() &&
            d.count as usize <= MAX_PLAIN_CHUNKS &&
            f.index < d.count &&
            f.proof.len() == d.proof_len() &&
            f.data.len() == d.segment_length(f.index) &&
            self.layout.group_key(&group_id(d), context) == f.group
    }

    fn check_proof(&mut self, _chunk: &ChunkMsg<B>) -> ValidationResult {
        ValidationResult::Pending
    }

    fn header_id(&self, chunk: &ChunkMsg<B>) -> Bytes32 {
        self.split(&chunk.frame).map(|f| group_id(&f.descriptor)).unwrap_or_default()
    }

    fn context<'a>(&self, chunk: &'a ChunkMsg<B>) -> &'a [u8] {
        chunk.frame.as_bytes().get(..self.layout.context_len()).unwrap_or(&[])
    }

    fn decode(
        &mut self,
        group: &GroupId,
        available: &[ChunkMsg<B>],
        _shape: &Shape,
        out_rebuilt: &mut PreallocVec<ChunkMsg<B>>,
    ) -> Option<B> {
        let first = &available.first()?.frame;
        let f = self.split(first)?;
        let (descriptor, key, layout) = (f.descriptor, f.group, self.layout);
        let context = &first.as_bytes()[..layout.context_len()];
        // Every chunk of the group has the same descriptor, so the same proof
        // length before its data.
        let skip = layout.fixed() + 32 * descriptor.proof_len();
        let (id_prefix, group) = (&self.id_prefix, *group);
        decode_and_reencode_with(
            available,
            &descriptor,
            skip,
            &mut self.pool,
            &SnappyBlockCompressor,
            out_rebuilt,
            |index, proof, data, leaf, pool| {
                let frame = layout.build(context, &key, &descriptor, index, proof, data);
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

    /// A frame with no context: the group key is the descriptor's alone, an
    /// attachment rides before the frame and changes neither the chunk nor
    /// its id, and the group decodes and rebuilds as the payload's does.
    #[test]
    fn an_attached_layout_has_no_context() {
        const OTHER: TypeId = TypeId(1);
        let body: Vec<u8> = (0..120_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let (descriptor, shards) =
            build_group::<Vec<u8>, _, _>(&body, &mut VecBufferPool, &SnappyBlockCompressor);
        let mut codec: Codec =
            PayloadCodec::with_layout(OTHER, Layout::Attached, VecBufferPool, b"/eth2/0/other");
        let chunks = codec.build_chunks(&[], &descriptor, &shards);
        let chunk = &chunks[2];
        assert_eq!(Layout::Attached.fixed(), CHUNK_FIXED - CONTEXT_BYTES);
        let mut keyed = vec![0x03];
        keyed.extend_from_slice(&group_id(&descriptor));
        assert_eq!(chunk.group, topic_group(OTHER, sha256(&keyed)));
        assert_eq!(chunk.frame[..32], chunk.group.key);
        assert!(TypeCodec::check(&codec, chunk));
        assert!(TypeCodec::context(&codec, chunk).is_empty());
        assert_eq!(codec.check_proof(chunk), ValidationResult::Accept);

        // With and without an attachment the frame, and so the chunk, is one.
        for attachment in [&b""[..], &[7u8; 300][..]] {
            let mut message = Vec::new();
            attach(attachment, &mut message);
            message.extend_from_slice(&chunk.frame);
            let (got, frame) = split_attached(&message).unwrap();
            assert_eq!(got, attachment);
            let read = codec.read_frame(frame.to_vec(), 0).unwrap();
            assert_eq!(
                (read.group, read.index, read.cached_id),
                (chunk.group, chunk.index, chunk.cached_id)
            );
        }
        assert_eq!(split_attached(&[9, 0, 1]), None);

        // From the data chunks alone: the body, and every chunk as it was sent.
        let k = descriptor.k() as usize;
        let shape = Shape { n: descriptor.n(), k: descriptor.k() };
        let mut rebuilt = PreallocVec::with_capacity(chunks.len());
        let decoded = codec.decode(&chunks[0].group, &chunks[..k], &shape, &mut rebuilt).unwrap();
        assert_eq!(decoded, body);
        assert_eq!(rebuilt.as_slice(), chunks.as_slice());
    }

    /// A second topic's groups are of its own type: the wire's bytes say
    /// nothing of it, the node's ids do.
    #[test]
    fn a_topic_gives_its_type() {
        const OTHER: TypeId = TypeId(1);
        let body: Vec<u8> = (0..50_000u32).map(|i| (i * 31 % 251) as u8).collect();
        let (descriptor, shards) =
            build_group::<Vec<u8>, _, _>(&body, &mut VecBufferPool, &SnappyBlockCompressor);
        let mut other: Codec = PayloadCodec::of(OTHER, VecBufferPool, b"/eth2/00000000/other");
        let chunks = other.build_chunks(&context(77), &descriptor, &shards);
        let chunk = &chunks[0];
        let key = group_key(&group_id(&descriptor), 77);
        assert_eq!(chunk.group, topic_group(OTHER, key));
        assert_ne!(chunk.group, payload_group(key));
        let mid = message_id_of(&chunk.cached_id);
        assert_eq!(mid[..32], key);
        assert_eq!(chunk_id_on(OTHER, &mid), Some(chunk.cached_id));
        assert_ne!(chunk_id_of(&mid), Some(chunk.cached_id));
        // Read back on its topic it is the same chunk; the payload's codec refuses it.
        let data = snappy::compress(&chunk.frame);
        let read = other.read_message(&data, snappy::decompress).unwrap();
        assert_eq!((read.group, read.cached_id), (chunk.group, chunk.cached_id));
        assert!(TypeCodec::check(&other, chunk));
        let payload: Codec = PayloadCodec::new(VecBufferPool, TOPIC);
        assert!(!TypeCodec::check(&payload, chunk));
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
