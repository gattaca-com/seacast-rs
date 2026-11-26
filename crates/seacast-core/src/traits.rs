use crate::{
    bitmap::{Bitmap, MAX_CHUNKS},
    collections::{
        InlineVec, MAX_INLINE_PEERS, MAX_JOINED_TYPES, MAX_PROJECTED, PreallocMap, PreallocVec,
    },
    message::{ChunkMsg, Join},
    types::{
        Ask, Bytes32, ChunkId, Duty, FamilyId, GenerationPeerId, GroupId, InterestKind, LinkFloor,
        NodeId, PeerId, Shape, Timestamp, TypeId, TypeParams, ValidationResult,
    },
};

/// A handle to the bytes of a chunk or an evidence body.
///
/// The state machine stores, clones and compares handles and asks only their
/// length: it never reads the bytes. Getting at them is the host's, where it
/// writes to the wire or decodes, since for a handle into a ring cache that
/// takes a reader and can fail.
pub trait ChunkBuffer: Clone + PartialEq + Eq + std::fmt::Debug {
    /// Length of the buffer in bytes.
    fn len(&self) -> usize;

    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl ChunkBuffer for Vec<u8> {
    #[inline]
    fn len(&self) -> usize {
        Vec::len(self)
    }
}

impl ChunkBuffer for std::sync::Arc<[u8]> {
    #[inline]
    fn len(&self) -> usize {
        <[u8]>::len(self)
    }
}

/// Pluggable source of randomness for protocol shuffling, sampling, and jitter.
pub trait RngSource {
    /// Generates a random `u64`.
    fn next_u64(&mut self) -> u64;

    /// Generates a uniform float in `[0.0, 1.0)`.
    #[inline]
    fn next_f64(&mut self) -> f64 {
        const SCALE: f64 = 1.0 / ((1u64 << 53) as f64);
        ((self.next_u64() >> 11) as f64) * SCALE
    }

    /// Generates a uniform float in `[low, high)`.
    #[inline]
    fn uniform(&mut self, low: f64, high: f64) -> f64 {
        low + (high - low) * self.next_f64()
    }

    /// In-place Fisher–Yates shuffle (`shuffled(xs)` in the spec).
    fn shuffle<T>(&mut self, slice: &mut [T])
    where
        Self: Sized,
    {
        let len = slice.len();
        if len <= 1 {
            return;
        }
        for i in (1..len).rev() {
            let j = (self.next_u64() as usize) % (i + 1);
            slice.swap(i, j);
        }
    }

    /// Samples up to `k` elements without replacement on the stack
    /// (`sample_without_replacement(xs, k)`).
    fn sample_without_replacement<T: Copy + Default, const CAP: usize>(
        &mut self,
        items: &[T],
        k: usize,
    ) -> InlineVec<T, CAP>
    where
        Self: Sized,
    {
        let mut pool = InlineVec::<T, CAP>::from_slice(items);
        let k = k.min(pool.len());
        let len = pool.len();
        for i in 0..k {
            let j = i + ((self.next_u64() as usize) % (len - i));
            pool.as_mut_slice().swap(i, j);
        }
        pool.truncate(k);
        pool
    }

    /// [`Self::sample_without_replacement`] in place: the sample is the first
    /// `k` of `items`. The same draws.
    fn sample_in_place<T>(&mut self, items: &mut [T], k: usize)
    where
        Self: Sized,
    {
        let len = items.len();
        for i in 0..k.min(len) {
            let j = i + ((self.next_u64() as usize) % (len - i));
            items.swap(i, j);
        }
    }

    /// Picks one element uniformly at random (`choice(xs)` in the spec).
    fn choice<'a, T>(&mut self, items: &'a [T]) -> Option<&'a T>
    where
        Self: Sized,
    {
        if items.is_empty() {
            None
        } else {
            let idx = (self.next_u64() as usize) % items.len();
            Some(&items[idx])
        }
    }
}

/// Deterministic SplitMix64 RNG implementation for reproducible tests and
/// simulations.
#[derive(Debug, Clone, Copy)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }
}

impl RngSource for SplitMix64 {
    #[inline]
    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
}

/// Timer events scheduled by the state machine and driven back into
/// `SeacastNode::on_timer`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TimerEvent {
    /// Retry an offer after `IWANT_WINDOW + RETRY_SLACK` or `START_DELAY`
    /// (`retry_offer(a)`).
    RetryOffer(Ask),
    /// Check if an ask's promise expired (`promise_due(a, p, at_bits)`).
    PromiseDue { ask: Ask, peer: PeerId, at_bits: u64 },
    /// Ask a parked announcer as a last resort (`ask_parked(a)`).
    AskParked(Ask),
    /// Release a congestion window allocation on timeout (`window_timeout(p, g,
    /// i, at_bits)`).
    WindowTimeout { peer: PeerId, group: GroupId, index: u32, at_bits: u64 },
    /// Reconsider a delayed decode duty (`reconsider(g, at_bits)`).
    Reconsider { group: GroupId, at_bits: u64 },
    /// A sampler's wait on `peer` ran out (`resample(g, i, q, first)`). No
    /// peer: nobody could be asked in the first phase.
    Resample { group: GroupId, index: u32, peer: Option<GenerationPeerId>, first: bool },
    /// Paced gossip tick (`on_pace_tick()`, every `HEARTBEAT / 16`).
    PaceTick,
    /// Heartbeat tick (`on_heartbeat()`, every `HEARTBEAT`).
    Heartbeat,
}

/// Reason a peer was penalised by the protocol (`penalise(p)` in the spec).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PenaltyReason {
    /// Chunk failed Level 1 authenticity check (`seacast-lite.md` §3, §4.2).
    InvalidChunkLevel1,
    /// `Have` bitmap exceeded `MAX_HAVE_BYTES` or had bits `>= N`
    /// (`seacast-lite.md` §4.3, §8.2).
    InvalidHaveBitmap,
    /// Peer sent an ask for a chunk it already claimed in `peer_has`
    /// (`seacast-lite.md` §4.5).
    AskedForClaimedChunk,
    /// Peer claimed `claim_all` on a group and failed to answer the
    /// verification probe (`seacast.md` §4.6 `R5`).
    UnansweredClaimProbe,
}

/// Pluggable bounded store for deferred chunks waiting for the domain's word on
/// their group (`seacast-lite.md` §4.2, §8.2).
pub trait DeferredStore<B> {
    /// Attempts to reserve space for a deferred chunk from `peer`.
    fn reserve(&mut self, peer: PeerId, chunk: &ChunkMsg<B>) -> bool;

    /// Releases a previously granted reservation.
    fn release(&mut self, peer: PeerId, chunk: &ChunkMsg<B>);
}

/// Preallocated bounded in-memory reservation counter implementing
/// `DeferredStore` with zero hot-path allocation.
#[derive(Debug, Clone)]
pub struct BoundedDeferredStore {
    pub max_per_peer: usize,
    pub max_total: usize,
    pub per_peer: PreallocMap<PeerId, usize>,
    pub total: usize,
}

impl Default for BoundedDeferredStore {
    fn default() -> Self {
        Self::with_capacity(MAX_INLINE_PEERS, 256, 4096)
    }
}

impl BoundedDeferredStore {
    pub fn with_capacity(max_peers: usize, max_per_peer: usize, max_total: usize) -> Self {
        Self { max_per_peer, max_total, per_peer: PreallocMap::with_capacity(max_peers), total: 0 }
    }
}

impl<B> DeferredStore<B> for BoundedDeferredStore {
    fn reserve(&mut self, peer: PeerId, _chunk: &ChunkMsg<B>) -> bool {
        if self.total >= self.max_total {
            return false;
        }
        // A peer whose count cannot be kept reserves nothing: its cap could not
        // be held, nor its reservations released.
        if self.per_peer.is_full() && !self.per_peer.contains_key(&peer) {
            return false;
        }
        let count = self.per_peer.entry_or_default(peer);
        if *count >= self.max_per_peer {
            return false;
        }
        *count += 1;
        self.total += 1;
        true
    }

    fn release(&mut self, peer: PeerId, _chunk: &ChunkMsg<B>) {
        let Some(count) = self.per_peer.get_mut(&peer) else {
            return;
        };
        if *count > 0 {
            *count -= 1;
            self.total = self.total.saturating_sub(1);
        }
        // A count of zero gives its place back.
        if *count == 0 {
            self.per_peer.remove(&peer);
        }
    }
}

/// The input of a group's level 2 (`RuntimeEnv::start_decode`).
#[derive(Debug, Clone, Copy)]
pub struct DecodeJob<'a, B> {
    pub shape: &'a Shape,
    /// The chunks held, in index order.
    pub chunks: &'a [ChunkMsg<B>],
}

/// Pluggable runtime environment for timers, background decode tasks, I/O
/// wakeups, and callbacks.
pub trait RuntimeEnv<B: ChunkBuffer> {
    /// Current monotonic clock time in seconds (`now`).
    fn now(&self) -> Timestamp;

    /// Schedules a `TimerEvent` to fire after `delay` seconds (`after(delay,
    /// fn, ...)`).
    fn schedule_after(&mut self, delay: f64, event: TimerEvent);

    /// `peer`'s writer has something to take: the host calls
    /// `SeacastNode::next_to_send` for it until that gives nothing.
    fn wake_writer(&mut self, _peer: PeerId) {}

    /// Whether `peer`'s writer has an unfinished write on its transport
    /// (`seacast-lite.md` §7.1 `writing(p)`, `seacast.md` §4.11). While true,
    /// the window's waiter line passes `peer` over without taking its place.
    fn is_writing(&self, _peer: PeerId) -> bool {
        false
    }

    /// Level 2 of `group` is due (`start(decode_group, g)`). The host runs
    /// `TypeCodec::decode` on `job`, on any thread, and passes the result to
    /// `SeacastNode::on_decoded`. `job` borrows the node's scratch: the host
    /// copies what it needs out of it before returning. A host that decodes
    /// on the node's thread may call `SeacastNode::decode_group` instead.
    fn start_decode(&mut self, group: GroupId, job: DecodeJob<'_, B>);

    /// Delivers a reconstructed and Level-2-verified object to the application
    /// for Level 3 checks (`deliver(g, object)`).
    fn deliver(&mut self, group: GroupId, object: B);

    /// Publishes fraud-proof evidence when a group fails Level 2 consistency
    /// (`publish_evidence(g, body)`).
    fn publish_evidence(&mut self, _group: GroupId, _body: B) {}

    /// Notifies the application when no connected peer can serve declared
    /// sample indices (`unreachable(g, bits)`).
    fn unreachable(&mut self, _group: GroupId, _bits: Bitmap) {}

    /// Applies a peer-scoring penalty to `peer` (`penalise(p)`).
    fn penalise(&mut self, peer: PeerId, reason: PenaltyReason);
}

/// The networking mechanics of the object types: how a chunk's frame is laid
/// out, what makes it well formed, and how a group is rebuilt. Nothing here
/// knows where a header's authority comes from.
pub trait TypeCodec<B: ChunkBuffer> {
    /// The index count and threshold of `chunk`'s group, from its header.
    fn shape(&self, chunk: &ChunkMsg<B>) -> Option<Shape>;

    /// The part of level 1 that reads no data: the group id is that of the
    /// chunk's type, header and context, the index is one the header has,
    /// the length is what the header says.
    fn check(&self, chunk: &ChunkMsg<B>) -> bool;

    /// The rest of level 1: the proof. `Pending` to have it checked off the
    /// chunk path, its verdict then coming back through
    /// `SeacastNode::on_validated`.
    fn check_proof(&mut self, chunk: &ChunkMsg<B>) -> ValidationResult;

    /// What the domain commits to of `chunk`'s group: the id of its header.
    fn header_id(&self, chunk: &ChunkMsg<B>) -> Bytes32;

    /// The chunk's context: the bytes that say to the domain what the group
    /// belongs to.
    fn context<'a>(&self, chunk: &'a ChunkMsg<B>) -> &'a [u8];

    /// Level 2 (`T.decode`): decodes `available`, checks consistency, and
    /// writes to `out_rebuilt` the chunk at every index of the group, lowest
    /// first. `None` if the group is inconsistent.
    fn decode(
        &mut self,
        group: &GroupId,
        available: &[ChunkMsg<B>],
        shape: &Shape,
        out_rebuilt: &mut PreallocVec<ChunkMsg<B>>,
    ) -> Option<B>;

    /// Every `(group, index)` pair a single chunk fills (`T.project(f)`, `R4`).
    fn project(&self, chunk: &ChunkMsg<B>) -> InlineVec<(GroupId, u32), MAX_PROJECTED> {
        InlineVec::singleton((chunk.group, chunk.index))
    }

    /// The other `(group, index)` pairs corresponding to index `i` of `group`,
    /// from IDs alone (`T.cross(g, i)`, `R4`).
    fn cross(&self, _group: &GroupId, _index: u32) -> InlineVec<(GroupId, u32), MAX_PROJECTED> {
        InlineVec::new()
    }

    /// Returns the wire size in bytes of `chunk` for the byte congestion window
    /// (`wire_size(p, entry)`, §4.11). `first_of_group`: the write is the first
    /// unsolicited one of the group to its peer, which may carry more
    /// ([`QueueEntry::first_of_group`](crate::QueueEntry)).
    fn wire_size(&self, chunk: &ChunkMsg<B>, _first_of_group: bool) -> usize {
        chunk.frame.len()
    }
}

/// The domain: what a group belongs to, and whether that is authentic. Asked
/// once a group.
pub trait Domain {
    /// Whether `header_id` is what `context` commits to for a group of type
    /// `t`: `Accept`, `Reject`, `Defer` while that cannot be told yet (the
    /// host then calls `SeacastNode::on_groups_authenticated`), or `Ignore`
    /// for a group that is too old or too early. Never `Pending`.
    fn authenticate(
        &mut self,
        group: &GroupId,
        header_id: &Bytes32,
        context: &[u8],
    ) -> ValidationResult;

    /// Whether the domain commits `group` already: nothing is asked for of a
    /// group before.
    fn authenticable(&self, group: &GroupId) -> bool;

    /// When a group of type `t` with this `context` leaves the domain's
    /// window, on the host's clock: its state and its deferred chunks go then
    /// at the latest, and its tombstone is kept until then. The domain
    /// answers `Ignore` for the group from then on. `None`: the node's
    /// lifetimes alone apply (`GROUP_TTL`, `tombstone_ttl`).
    fn deadline(&self, _group: &GroupId, _context: &[u8]) -> Option<Timestamp> {
        None
    }

    /// The id under which a peer is asked for at most one sample: that of the
    /// object the group is part of, where a node samples several groups of
    /// one object (`seacast.md` §4.10 `sampled_from`, I6).
    fn sample_scope(&self, group: &GroupId) -> GroupId {
        *group
    }

    /// The shape of a group the domain knows ahead of its chunks.
    fn shape_by_group(&self, _group: &GroupId) -> Option<Shape> {
        None
    }
}

/// What this node takes part in and how: its types, interest, duty and
/// parameters.
pub trait Policy {
    /// Returns the protocol parameters `TypeParams` for `t` (`T.params`).
    fn params(&self, t: TypeId) -> &TypeParams;

    /// The relation family key for `group` (`T.family(g)`).
    fn family(&self, _group: &GroupId) -> FamilyId {
        0
    }

    /// Computes a peer's `DERIVED` interest in `group` (`T.derived_interest(g,
    /// hdr, node_id(p), j)`).
    fn derived_interest(
        &self,
        _group: &GroupId,
        _shape: Option<&Shape>,
        _peer: PeerId,
        _node_id: &NodeId,
        _join: &Join,
    ) -> Bitmap {
        Bitmap::EVERY_INDEX
    }

    /// Computes this node's own initial interest in `group`
    /// (`own_interest_bits(g)`).
    fn own_interest(&self, _group: &GroupId) -> Bitmap {
        Bitmap::EVERY_INDEX
    }

    /// Returns the `Join` declaration this node sends for object type `t`
    /// (`our_join(T)`).
    fn our_join(&self, t: TypeId) -> Join;

    /// Returns the list of object types this node participates in
    /// (`joined_types()`).
    fn joined_types(&self) -> InlineVec<TypeId, MAX_JOINED_TYPES>;

    /// Returns the families of object type `t` in which this node has
    /// forwarding duty (`families_with_duty(T)`).
    fn families_with_duty(&self, _t: TypeId) -> InlineVec<FamilyId, MAX_CHUNKS> {
        InlineVec::singleton(0)
    }

    /// Returns `true` if this node wants to receive pushes for `family` of type
    /// `t` (`wants_family(T, fam)`).
    fn wants_family(&self, _t: TypeId, _family: FamilyId) -> bool {
        true
    }

    /// Whether a peer's `DERIVED` interest holds every index of the groups of
    /// `family` (`seacast.md` §1.3 `link_cover`).
    fn holds_family(
        &self,
        _t: TypeId,
        _family: FamilyId,
        _peer: PeerId,
        _node_id: &NodeId,
        _join: &Join,
    ) -> bool {
        true
    }

    /// Whether a peer counts as one of high custody in a floor that asks for
    /// diversity (`seacast.md` §1.3). The base custody count is the
    /// domain's, so the default knows only interest `ALL`.
    fn high_custody(&self, _t: TypeId, join: &Join) -> bool {
        join.interest == InterestKind::All
    }

    /// The link floors of `t` beyond the relation floor: the repair, source
    /// and coverage floors this node keeps (`seacast.md` §1.3, §4.6,
    /// §4.7). Read by `SeacastNode::link_deficits`.
    fn link_floors(&self, _t: TypeId) -> InlineVec<LinkFloor, MAX_CHUNKS> {
        InlineVec::new()
    }

    /// Returns this node's duty for `group` (`duty_for(g)`).
    fn duty_for(&self, group: &GroupId) -> Duty {
        self.our_join(group.type_id).duty
    }

    /// Repair rule: whether this node decodes `group` immediately at `K`
    /// (`T.params.DECODE_AT_K(g)`).
    fn decode_at_k(&self, _group: &GroupId) -> bool {
        true
    }

    /// Repair rule: whether this node decodes `group` after a delay if still
    /// short, and the delay in seconds from `known_at[g]`
    /// (`T.params.DECODE_LATER(g)`).
    fn decode_later(&mut self, _group: &GroupId, _rng: &mut dyn RngSource) -> Option<f64> {
        None
    }

    /// Repair rule: candidate peers to whom rebuilt chunks of `group` may be
    /// pushed/offered (`T.params.REPAIR_TO(g)`). If `None` is returned,
    /// defaults to the peers in the push relation, and the peers outside it
    /// whose interest in `group` is not `ALL`.
    fn repair_to(&self, _group: &GroupId) -> Option<InlineVec<PeerId, MAX_INLINE_PEERS>> {
        None
    }

    /// Computes a deterministic tiebreak hash for target selection
    /// (`hash(message_id(f), p)`).
    fn tiebreak(&self, chunk_id: &ChunkId, peer: PeerId) -> u64;

    /// Returns the 32-byte `NodeId` of `peer` (`node_id(p)`).
    fn node_id(&self, peer: PeerId) -> NodeId;
}

/// Everything the node asks of its host about object types: the three traits
/// together.
pub trait ObjectCatalog<B: ChunkBuffer>: TypeCodec<B> + Domain + Policy {}

impl<B: ChunkBuffer, T: TypeCodec<B> + Domain + Policy> ObjectCatalog<B> for T {}
