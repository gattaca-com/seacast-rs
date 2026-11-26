//! The payload as the catalog a `SeacastNode` is driven with on the gossipsub
//! binding: the codec is [`PayloadCodec`], the [`Domain`] is the host's
//! ([`PayloadHost`]: whether a block's bid commits a descriptor), and the
//! [`Policy`] is one type, joined on every link, whose relations the host
//! keeps.

use seacast_codec::Sha256;
use seacast_core::{
    Bytes32, ChunkBuffer, ChunkId, ChunkMsg, Domain, Duty, ForkDigest, GroupId, InlineVec,
    InterestKind, Join, MAX_JOINED_TYPES, NodeId, PeerId, Policy, PreallocVec, Shape, Timestamp,
    TypeCodec, TypeId, TypeParams, ValidationResult,
};

use crate::payload::PAYLOAD;

/// What the payload asks of the domain. A `context` is `slot |
/// beacon_block_root` ([`CONTEXT_BYTES`](crate::CONTEXT_BYTES)).
pub trait PayloadHost {
    /// Whether the block `context` names commits the descriptor whose group id
    /// is `header_id` (`Domain::authenticate`): `Defer` until that block is
    /// validated and applied locally, then whether its slot is the context's
    /// and its bid's group id is `header_id`.
    fn authenticate(
        &mut self,
        group: &GroupId,
        header_id: &Bytes32,
        context: &[u8],
    ) -> ValidationResult;

    /// Whether an installed block commits `group` (`Domain::authenticable`).
    fn authenticable(&self, group: &GroupId) -> bool;

    /// When `context`'s slot leaves the live window (`Domain::deadline`).
    fn deadline(&self, _group: &GroupId, _context: &[u8]) -> Option<Timestamp> {
        None
    }

    /// Whether a chunk of `group` may name the block of `context`. Asked of
    /// every chunk, where `authenticate` is asked once a group and a group's
    /// chunks may name two blocks of its slot (`seacast-lite.md` §1). `false`
    /// rejects the chunk and penalises its sender: only for a block that is
    /// installed and whose bid does not commit the group. A block not
    /// installed is no ground to refuse.
    fn names_block(&self, _group: &GroupId, _context: &[u8]) -> bool {
        true
    }

    fn node_id(&self, peer: PeerId) -> NodeId;
}

/// The payload's parameters on this binding: one colour, one relation both
/// ways, kept by the host as its topic's mesh. The rest are the defaults.
pub fn payload_params() -> TypeParams {
    TypeParams { m: 1, symmetric: true, host_relations: true, ..TypeParams::default() }
}

/// The JOIN a subscription to the payload's topic stands for, ours and a
/// peer's (`seacast-bindings.md` §0): every chunk, with duty.
pub const fn payload_join(fork_digest: ForkDigest) -> Join {
    topic_join(PAYLOAD, fork_digest)
}

/// [`payload_join`] for the topic of `object_type`.
pub const fn topic_join(object_type: TypeId, fork_digest: ForkDigest) -> Join {
    Join {
        object_type,
        fork_digest,
        interest: InterestKind::All,
        custody_count: 0,
        duty: Duty::Forward,
        colours: 1,
    }
}

/// `C` is the payload's codec: [`PayloadCodec`], or a host's own over it where
/// the host keeps a group's chunks in place and runs level 2 there.
pub struct PayloadCatalog<Host, C> {
    pub host: Host,
    pub codec: C,
    pub params: TypeParams,
    pub join: Join,
}

impl<Host: PayloadHost, C> PayloadCatalog<Host, C> {
    /// The catalog with [`payload_params`] and [`payload_join`].
    pub fn new(host: Host, codec: C, fork_digest: ForkDigest) -> Self {
        Self::of(PAYLOAD, host, codec, fork_digest)
    }

    /// The catalog of the topic of `object_type`, `codec` its codec.
    pub fn of(object_type: TypeId, host: Host, codec: C, fork_digest: ForkDigest) -> Self {
        Self { host, codec, params: payload_params(), join: topic_join(object_type, fork_digest) }
    }
}

/// Several chunk topics in one node: the type with id `i` is the topic of
/// `types[i]`, with its own host, codec and parameters. A chunk, an IHAVE and
/// a subscription name their topic, which gives the type. An IWANT and an
/// IDONTWANT entry name none: their type is that of the group on record with
/// the key, and an entry of no such group is not the node's.
///
/// A key under two types is two groups. The node ids are the first topic's
/// host's.
pub struct TopicCatalogs<Host, C> {
    pub types: Vec<PayloadCatalog<Host, C>>,
}

impl<Host: PayloadHost, C> TopicCatalogs<Host, C> {
    /// `types[i]` made with [`PayloadCatalog::of`] for `TypeId(i)`.
    pub fn new(types: Vec<PayloadCatalog<Host, C>>) -> Self {
        assert!(!types.is_empty() && types.len() <= MAX_JOINED_TYPES);
        assert!(types.iter().enumerate().all(|(i, of)| of.join.object_type.0 as usize == i));
        Self { types }
    }

    fn of(&self, t: TypeId) -> Option<&PayloadCatalog<Host, C>> {
        self.types.get(t.0 as usize)
    }

    fn of_mut(&mut self, t: TypeId) -> Option<&mut PayloadCatalog<Host, C>> {
        self.types.get_mut(t.0 as usize)
    }
}

/// A chunk of a type the node does not run fails level 1.
impl<Host, C, B> TypeCodec<B> for TopicCatalogs<Host, C>
where
    Host: PayloadHost,
    C: TypeCodec<B>,
    B: ChunkBuffer,
{
    fn shape(&self, chunk: &ChunkMsg<B>) -> Option<Shape> {
        self.of(chunk.group.type_id)?.shape(chunk)
    }

    fn check(&self, chunk: &ChunkMsg<B>) -> bool {
        self.of(chunk.group.type_id).is_some_and(|of| of.check(chunk))
    }

    fn check_proof(&mut self, chunk: &ChunkMsg<B>) -> ValidationResult {
        match self.of_mut(chunk.group.type_id) {
            Some(of) => of.check_proof(chunk),
            None => ValidationResult::Reject,
        }
    }

    fn header_id(&self, chunk: &ChunkMsg<B>) -> Bytes32 {
        self.of(chunk.group.type_id).map_or([0; 32], |of| of.header_id(chunk))
    }

    fn context<'a>(&self, chunk: &'a ChunkMsg<B>) -> &'a [u8] {
        self.of(chunk.group.type_id).map_or(&[], |of| of.context(chunk))
    }

    fn decode(
        &mut self,
        group: &GroupId,
        available: &[ChunkMsg<B>],
        shape: &Shape,
        out_rebuilt: &mut PreallocVec<ChunkMsg<B>>,
    ) -> Option<B> {
        self.of_mut(group.type_id)?.decode(group, available, shape, out_rebuilt)
    }

    fn wire_size(&self, chunk: &ChunkMsg<B>, first_of_group: bool) -> usize {
        self.of(chunk.group.type_id).map_or(0, |of| of.wire_size(chunk, first_of_group))
    }
}

impl<Host: PayloadHost, C> Domain for TopicCatalogs<Host, C> {
    fn authenticate(
        &mut self,
        group: &GroupId,
        header_id: &Bytes32,
        context: &[u8],
    ) -> ValidationResult {
        match self.of_mut(group.type_id) {
            Some(of) => of.authenticate(group, header_id, context),
            None => ValidationResult::Reject,
        }
    }

    fn authenticable(&self, group: &GroupId) -> bool {
        self.of(group.type_id).is_some_and(|of| of.authenticable(group))
    }

    fn deadline(&self, group: &GroupId, context: &[u8]) -> Option<Timestamp> {
        self.of(group.type_id)?.deadline(group, context)
    }
}

impl<Host: PayloadHost, C> Policy for TopicCatalogs<Host, C> {
    /// Asked for a type the node runs only.
    fn params(&self, t: TypeId) -> &TypeParams {
        &self.types[t.0 as usize].params
    }

    fn our_join(&self, t: TypeId) -> Join {
        self.types[t.0 as usize].join
    }

    fn joined_types(&self) -> InlineVec<TypeId, MAX_JOINED_TYPES> {
        let mut types = InlineVec::new();
        for of in &self.types {
            let _ = types.push(of.join.object_type);
        }
        types
    }

    fn tiebreak(&self, chunk_id: &ChunkId, peer: PeerId) -> u64 {
        self.types[0].tiebreak(chunk_id, peer)
    }

    fn node_id(&self, peer: PeerId) -> NodeId {
        self.types[0].host.node_id(peer)
    }
}

impl<Host, C, B> TypeCodec<B> for PayloadCatalog<Host, C>
where
    Host: PayloadHost,
    C: TypeCodec<B>,
    B: ChunkBuffer,
{
    fn shape(&self, chunk: &ChunkMsg<B>) -> Option<Shape> {
        self.codec.shape(chunk)
    }

    fn check(&self, chunk: &ChunkMsg<B>) -> bool {
        self.codec.check(chunk) && self.host.names_block(&chunk.group, self.codec.context(chunk))
    }

    fn check_proof(&mut self, chunk: &ChunkMsg<B>) -> ValidationResult {
        self.codec.check_proof(chunk)
    }

    fn header_id(&self, chunk: &ChunkMsg<B>) -> Bytes32 {
        self.codec.header_id(chunk)
    }

    fn context<'a>(&self, chunk: &'a ChunkMsg<B>) -> &'a [u8] {
        self.codec.context(chunk)
    }

    fn decode(
        &mut self,
        group: &GroupId,
        available: &[ChunkMsg<B>],
        shape: &Shape,
        out_rebuilt: &mut PreallocVec<ChunkMsg<B>>,
    ) -> Option<B> {
        self.codec.decode(group, available, shape, out_rebuilt)
    }

    fn wire_size(&self, chunk: &ChunkMsg<B>, first_of_group: bool) -> usize {
        self.codec.wire_size(chunk, first_of_group)
    }
}

impl<Host: PayloadHost, C> Domain for PayloadCatalog<Host, C> {
    fn authenticate(
        &mut self,
        group: &GroupId,
        header_id: &Bytes32,
        context: &[u8],
    ) -> ValidationResult {
        self.host.authenticate(group, header_id, context)
    }

    fn authenticable(&self, group: &GroupId) -> bool {
        self.host.authenticable(group)
    }

    fn deadline(&self, group: &GroupId, context: &[u8]) -> Option<Timestamp> {
        self.host.deadline(group, context)
    }
}

impl<Host: PayloadHost, C> Policy for PayloadCatalog<Host, C> {
    fn params(&self, _t: TypeId) -> &TypeParams {
        &self.params
    }

    fn our_join(&self, _t: TypeId) -> Join {
        self.join
    }

    fn joined_types(&self) -> InlineVec<TypeId, MAX_JOINED_TYPES> {
        InlineVec::singleton(PAYLOAD)
    }

    /// A hash of the chunk and the peer, the same at every node (`tiebreak(f,
    /// p)`, `seacast-lite.md` §5.3).
    fn tiebreak(&self, chunk_id: &ChunkId, peer: PeerId) -> u64 {
        let mut h = Sha256::new();
        h.update(chunk_id);
        h.update(&self.host.node_id(peer));
        u64::from_be_bytes(h.finalize()[..8].try_into().unwrap())
    }

    fn node_id(&self, peer: PeerId) -> NodeId {
        self.host.node_id(peer)
    }
}
