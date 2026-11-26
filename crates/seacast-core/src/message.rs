use crate::{
    bitmap::Bitmap,
    collections::{InlineVec, MAX_ENTRY_CONTROL},
    types::{
        Ask, Bytes32, ChunkId, Colour, Direction, Duty, FamilyId, ForkDigest, GroupId,
        InterestKind, TypeId,
    },
};

/// `Join`: per link and object type, sent by both ends (`seacast.md` §2
/// `[D11]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Join {
    pub object_type: TypeId,
    /// A link carries the type only where both ends name the same fork
    /// (`seacast-bindings.md` §1.3).
    pub fork_digest: ForkDigest,
    pub interest: InterestKind,
    pub custody_count: u64,
    pub duty: Duty,
    pub colours: u16,
}

/// `Graft`: relation maintenance per family and colour (`seacast.md` §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Graft {
    pub object_type: TypeId,
    pub family: FamilyId,
    pub colour: Colour,
    pub direction: Direction,
    /// The yes to the receiver's GRAFT: not answered where the relation is
    /// held (`seacast.md` §4.1).
    pub answer: bool,
}

/// `Prune`: relation teardown per family and colour (`seacast.md` §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Prune {
    pub object_type: TypeId,
    pub family: FamilyId,
    pub colour: Colour,
    pub direction: Direction,
}

/// `Have`: holding (`offer = false`) or offer (`offer = true`) bitmap
/// (`seacast.md` §2 `[c7, D3]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Have {
    pub group: GroupId,
    pub bits: Bitmap,
    /// `true`: `"you may ask me for these"` (an offer);
    /// `false`: `"I hold these, verified"` (a holding).
    pub offer: bool,
    /// `[c10, D3]` The decode claim (`claim_all`): sender holds or can produce
    /// every index.
    pub claim_all: bool,
    /// `[D3]` Sender's interest in this group is satisfied (`complete`).
    pub complete: bool,
}

impl Have {
    #[inline]
    pub const fn holding(group: GroupId, bits: Bitmap, claim_all: bool, complete: bool) -> Self {
        Self { group, bits, offer: false, claim_all, complete }
    }

    #[inline]
    pub const fn offer(group: GroupId, bits: Bitmap) -> Self {
        Self { group, bits, offer: true, claim_all: false, complete: false }
    }
}

/// `Want`: `"send me these"`, per recipient (`seacast.md` §2 `[D2]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Want {
    pub group: GroupId,
    pub bits: Bitmap,
    /// Also when the chunks arrive, not only if held now (§4.10, `[D12]`).
    pub standing: bool,
    /// Forwarding steps the request may still take (§4.10, `[D12]`).
    pub hops: u8,
    /// The probe of a claim: answered whatever the sender holds (§4.6, R5).
    pub probe: bool,
    /// Ours only, not sent: an offer-driven pull ask, whose `PROMISE` starts
    /// when it is written (`seacast-lite.md` §7.2). A standing, probe or
    /// custodian ask starts none there (`seacast.md` §4.5, §4.6, §4.10).
    pub track_promise: bool,
}

impl Want {
    /// Creates an offer-driven pull ask for a single index (starts a promise
    /// when written).
    #[inline]
    pub fn pull_ask(ask: Ask) -> Self {
        Self {
            group: ask.group,
            bits: Bitmap::singleton(ask.index),
            standing: false,
            hops: 0,
            probe: false,
            track_promise: true,
        }
    }

    /// An ask answered only if held now: a repair's ask of a custodian (§4.6).
    #[inline]
    pub const fn direct(group: GroupId, bits: Bitmap) -> Self {
        Self { group, bits, standing: false, hops: 0, probe: false, track_promise: false }
    }

    /// A standing request: a sampler's (§4.10).
    #[inline]
    pub const fn standing(group: GroupId, bits: Bitmap) -> Self {
        Self { standing: true, ..Self::direct(group, bits) }
    }

    /// The probe of a claim (§4.6 `defer_on_claim`).
    #[inline]
    pub const fn probe(group: GroupId, bits: Bitmap) -> Self {
        Self { probe: true, ..Self::direct(group, bits) }
    }
}

/// `ChunkMsg`: a chunk as the node holds it (`seacast.md` §2). The node
/// reads its group, index and id; its header, context, proof and data are
/// the type's codec's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkMsg<B> {
    pub group: GroupId,
    pub index: u32,
    /// The chunk's header, context, proof and data, laid out by its type's
    /// codec.
    pub frame: B,
    /// Cached 59-byte structured chunk ID ([`ChunkId`], `chunk_id(f)`).
    pub cached_id: ChunkId,
    /// What the type's codec keeps of the chunk from its level 1 for its level
    /// 2; zero until the codec sets it. The node does not read it.
    pub memo: Bytes32,
    /// Compressed wire length of `frame` in bytes when known; zero falls back
    /// to `frame.len()` in `wire_size`.
    pub wire_len: u32,
}

/// `Evidence`: fraud-proof object published when a group fails Level 2
/// consistency (`seacast.md` §2 `[D6]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence<B> {
    pub group: GroupId,
    pub body: B,
}

/// Standalone RPC message bundle exchanged on a link (`seacast.md` §4, §7).
///
/// Uses stack-allocated [`InlineVec`] for control messages and carries at most
/// one [`ChunkMsg`] per wire frame, performing **zero heap allocation**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rpc<B> {
    pub joins: InlineVec<Join, MAX_ENTRY_CONTROL>,
    pub chunk: Option<ChunkMsg<B>>,
    pub haves: InlineVec<Have, MAX_ENTRY_CONTROL>,
    pub wants: InlineVec<Want, MAX_ENTRY_CONTROL>,
    pub grafts: InlineVec<Graft, MAX_ENTRY_CONTROL>,
    pub prunes: InlineVec<Prune, MAX_ENTRY_CONTROL>,
    pub evidence: Option<Evidence<B>>,
}

impl<B> Default for Rpc<B> {
    #[inline]
    fn default() -> Self {
        Self {
            joins: InlineVec::new(),
            chunk: None,
            haves: InlineVec::new(),
            wants: InlineVec::new(),
            grafts: InlineVec::new(),
            prunes: InlineVec::new(),
            evidence: None,
        }
    }
}

impl<B> Rpc<B> {
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.joins.is_empty() &&
            self.chunk.is_none() &&
            self.haves.is_empty() &&
            self.wants.is_empty() &&
            self.grafts.is_empty() &&
            self.prunes.is_empty() &&
            self.evidence.is_none()
    }
}

/// One control message waiting in a peer's queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    Join(Join),
    Have(Have),
    Want(Want),
    Graft(Graft),
    Prune(Prune),
}

/// What waits in a peer's queue (`seacast-lite.md` §7): a chunk, named by the
/// key it is stored under, or one control message. The entry that leaves is
/// built from it when it is sent (`SeacastNode::next_to_send`), so a queue
/// holds no chunk, proof or header, and an item is the same small size whatever
/// it stands for.
#[derive(Debug, Clone, Copy)]
pub enum Queued {
    Chunk { group: GroupId, index: u32, solicited: bool },
    Control(Control),
}

impl Queued {
    /// `chunk` as it is stored: under its own group and index.
    #[inline]
    pub fn from_chunk<B>(chunk: &ChunkMsg<B>, solicited: bool) -> Self {
        Self::Chunk { group: chunk.group, index: chunk.index, solicited }
    }

    #[inline]
    pub fn from_have(have: Have) -> Self {
        Self::Control(Control::Have(have))
    }

    #[inline]
    pub fn from_want(want: Want) -> Self {
        Self::Control(Control::Want(want))
    }

    #[inline]
    pub fn from_join(join: Join) -> Self {
        Self::Control(Control::Join(join))
    }

    #[inline]
    pub fn from_graft(graft: Graft) -> Self {
        Self::Control(Control::Graft(graft))
    }

    #[inline]
    pub fn from_prune(prune: Prune) -> Self {
        Self::Control(Control::Prune(prune))
    }

    #[inline]
    pub fn is_chunk(&self) -> bool {
        matches!(self, Self::Chunk { .. })
    }
}

/// An entry in a peer's two-lane send queue (`seacast-lite.md` §7.2 `Entry`).
/// Carries at most one chunk, plus optional control messages stored inline with
/// zero heap allocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueEntry<B> {
    pub chunk: Option<ChunkMsg<B>>,
    pub solicited: bool,
    /// The chunk is unsolicited and the first of its group written to the
    /// peer (`seacast.md` §2, P2): its type may send more with it, as a
    /// cell its header ([`TypeCodec::wire_size`](crate::TypeCodec)).
    pub first_of_group: bool,
    pub joins: InlineVec<Join, MAX_ENTRY_CONTROL>,
    pub haves: InlineVec<Have, MAX_ENTRY_CONTROL>,
    pub wants: InlineVec<Want, MAX_ENTRY_CONTROL>,
    pub grafts: InlineVec<Graft, MAX_ENTRY_CONTROL>,
    pub prunes: InlineVec<Prune, MAX_ENTRY_CONTROL>,
    pub evidence: Option<Evidence<B>>,
}

impl<B> Default for QueueEntry<B> {
    #[inline]
    fn default() -> Self {
        Self {
            chunk: None,
            solicited: false,
            first_of_group: false,
            joins: InlineVec::new(),
            haves: InlineVec::new(),
            wants: InlineVec::new(),
            grafts: InlineVec::new(),
            prunes: InlineVec::new(),
            evidence: None,
        }
    }
}

impl<B> QueueEntry<B> {
    #[inline]
    pub fn empty() -> Self {
        Self::default()
    }

    #[inline]
    pub fn from_chunk(chunk: ChunkMsg<B>, solicited: bool) -> Self {
        Self { chunk: Some(chunk), solicited, ..Self::default() }
    }

    #[inline]
    pub fn from_have(have: Have) -> Self {
        Self { haves: InlineVec::singleton(have), ..Self::default() }
    }

    #[inline]
    pub fn from_want(want: Want) -> Self {
        Self { wants: InlineVec::singleton(want), ..Self::default() }
    }

    #[inline]
    pub fn from_join(join: Join) -> Self {
        Self { joins: InlineVec::singleton(join), ..Self::default() }
    }

    #[inline]
    pub fn from_graft(graft: Graft) -> Self {
        Self { grafts: InlineVec::singleton(graft), ..Self::default() }
    }

    #[inline]
    pub fn from_prune(prune: Prune) -> Self {
        Self { prunes: InlineVec::singleton(prune), ..Self::default() }
    }

    /// Adds `control` if its kind has room in the entry.
    #[inline]
    pub fn push_control(&mut self, control: Control) -> bool {
        match control {
            Control::Join(join) => self.joins.push(join),
            Control::Have(have) => self.haves.push(have),
            Control::Want(want) => self.wants.push(want),
            Control::Graft(graft) => self.grafts.push(graft),
            Control::Prune(prune) => self.prunes.push(prune),
        }
    }

    #[inline]
    pub fn add_offer(&mut self, offer: Have) {
        let _ = self.haves.push(offer);
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.chunk.is_none() &&
            self.joins.is_empty() &&
            self.haves.is_empty() &&
            self.wants.is_empty() &&
            self.grafts.is_empty() &&
            self.prunes.is_empty() &&
            self.evidence.is_none()
    }

    #[inline]
    pub fn into_rpc(self) -> Rpc<B> {
        Rpc {
            joins: self.joins,
            chunk: self.chunk,
            haves: self.haves,
            wants: self.wants,
            grafts: self.grafts,
            prunes: self.prunes,
            evidence: self.evidence,
        }
    }
}
