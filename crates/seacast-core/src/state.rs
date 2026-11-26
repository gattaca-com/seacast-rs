use crate::{
    bitmap::{BITMAP_WORDS, Bitmap},
    collections::{InlineVec, PeerSets, PreallocDeque, PreallocMap, PreallocVec, word_bits},
    message::{ChunkMsg, Control, Join, QueueEntry, Queued},
    types::{
        Ask, Colour, FamilyId, GroupId, GroupState, HaveEntry, NodeId, PeerId, PushEntry, Shape,
        Timestamp, TypeId,
    },
};

/// Maximum groups in a single heartbeat gossip emission batch.
pub const MAX_GOSSIP_GROUPS: usize = 64;

/// Maximum sliding heartbeat windows in [`GossipHistory`].
pub const MAX_GOSSIP_WINDOWS: usize = 8;

/// Outcome of `SeacastNode::next_to_send` for a peer's writer (`seacast.md`
/// §4.11).
// Not boxed: the writer path does not allocate.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchOutcome<B> {
    /// Entry ready to be written to the peer's transport stream.
    Send(QueueEntry<B>),
    /// Writer is waiting in the FIFO line for congestion window bytes (`WAIT`).
    Wait,
    /// Queue has nothing to send (`None`).
    Empty,
}

/// The two-lane bounded per-peer send queue (`seacast-lite.md` §7, §8.2),
/// preallocated at initialization.
#[derive(Debug, Clone)]
pub struct PeerQueue {
    pub urgent: PreallocDeque<Queued>,
    pub normal: PreallocVec<Queued>,
    pub max_entries: usize,
    /// The offers and the answers a full queue refused, of the groups of one
    /// chunk, oldest first (`owed`, `owed_answers`). Full, the oldest goes. A
    /// group that has ended stays until it is taken.
    pub owed_single: PreallocDeque<GroupId>,
    pub owed_single_answers: PreallocDeque<GroupId>,
    /// JOINs, GRAFTs and PRUNEs a full queue refused, and those handed over
    /// since, in order (`owed_relations`).
    pub owed_relations: PreallocDeque<Control>,
}

/// Indices of groups of more than one chunk owed to peers, by peer and group:
/// one table for all peers, an equal share of it a peer. What is owed of a
/// pair beyond its peer's share is dropped.
#[derive(Debug, Clone)]
pub struct Owed {
    bits: PreallocMap<(PeerId, GroupId), Bitmap>,
    /// The pairs of each peer: a peer with none is not searched for.
    per_peer: Vec<u32>,
}

impl Owed {
    pub fn with_capacity(pairs: usize, max_peers: usize) -> Self {
        Self { bits: PreallocMap::with_capacity(pairs), per_peer: vec![0; max_peers] }
    }

    #[inline]
    pub fn any(&self, peer: PeerId) -> bool {
        self.per_peer[peer as usize] > 0
    }

    pub fn add(&mut self, peer: PeerId, group: GroupId, bits: &Bitmap) {
        if bits.is_empty() {
            return;
        }
        let key = (peer, group);
        // A peer has its share of the table and no more: what is owed to one
        // peer cannot take the room of what is owed to another.
        let share = self.bits.capacity() / self.per_peer.len().max(1);
        if let Some(owed) = self.bits.get_mut(&key) {
            *owed |= bits;
        } else if (self.per_peer[peer as usize] as usize) < share {
            self.bits.insert(key, *bits);
            self.per_peer[peer as usize] += 1;
        }
    }

    /// The lowest group id owed to `peer` and the lowest index owed of it. A
    /// pass over the table.
    pub fn lowest(&self, peer: PeerId) -> Option<(GroupId, u32)> {
        if !self.any(peer) {
            return None;
        }
        self.bits
            .iter()
            .filter(|((of, _), _)| *of == peer)
            .filter_map(|(&(_, group), bits)| Some((group, bits.first_index()?)))
            .min()
    }

    pub fn take(&mut self, peer: PeerId, group: &GroupId) -> Option<Bitmap> {
        let bits = self.bits.remove(&(peer, *group))?;
        self.per_peer[peer as usize] -= 1;
        Some(bits)
    }

    /// Takes `index` of `group` from what `peer` is owed.
    pub fn take_index(&mut self, peer: PeerId, group: &GroupId, index: u32) {
        let Some(bits) = self.bits.get_mut(&(peer, *group)) else {
            return;
        };
        bits.clear(index);
        if bits.is_empty() {
            self.take(peer, group);
        }
    }

    pub fn drop_peer(&mut self, peer: PeerId) {
        if self.any(peer) {
            self.bits.retain(|(of, _), _| *of != peer);
            self.per_peer[peer as usize] = 0;
        }
    }

    pub fn drop_group(&mut self, group: &GroupId) {
        let per_peer = &mut self.per_peer;
        self.bits.retain(|(peer, of), _| {
            if of == group {
                per_peer[*peer as usize] -= 1;
            }
            of != group
        });
    }
}

impl PeerQueue {
    /// Preallocates both lanes with fixed capacity `max_entries`, what is
    /// owed for `max_single` groups of one chunk, and `max_entries` owed
    /// GRAFTs and PRUNEs with a JOIN for each of `max_types`.
    pub fn with_capacity(max_entries: usize, max_single: usize, max_types: usize) -> Self {
        Self {
            urgent: PreallocDeque::with_capacity(max_entries),
            normal: PreallocVec::with_capacity(max_entries),
            max_entries,
            owed_single: PreallocDeque::with_capacity(max_single),
            owed_single_answers: PreallocDeque::with_capacity(max_single),
            // A JOIN a type besides: a link's JOINs are never dropped.
            owed_relations: PreallocDeque::with_capacity(max_entries + max_types),
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.urgent.clear();
        self.normal.clear();
        self.owed_single.clear();
        self.owed_single_answers.clear();
        self.owed_relations.clear();
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.urgent.len() + self.normal.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.urgent.is_empty() && self.normal.is_empty()
    }

    #[inline]
    pub fn has_room(&self) -> bool {
        self.len() < self.max_entries
    }

    #[inline]
    pub fn has_chunks(&self) -> bool {
        self.normal.iter().any(Queued::is_chunk)
    }
}

/// Everything kept of one connection by the peer alone, or by peer and type
/// (`seacast.md` §3). Reset when the connection closes.
#[derive(Debug, Clone)]
pub struct Peer {
    /// The connection's node, taken at `connect_peer`.
    pub node_id: NodeId,
    pub join_recv: PreallocMap<TypeId, Join>,
    pub join_sent: PreallocMap<TypeId, Join>,
    /// Chunks the peer is listed for across `offers`.
    pub listed_count: usize,
    // This heartbeat: offers taken, asks made of them, chunks served.
    pub ihave_frames: usize,
    pub ihave_asked: usize,
    pub(crate) unwanted_ids: usize,
    pub(crate) served_now: usize,
    /// Groups the peer has ties on, groups it has named in HAVEs/offers, and
    /// unknown groups it has named in WANTs (`admitted_group`).
    pub(crate) tie_count: usize,
    pub(crate) named_count: usize,
    pub(crate) wanted_count: usize,
    /// The last pass over peers that took this one (`SeacastNode::mark`): a
    /// set of peers for one pass, without a list.
    pub(crate) mark: u64,
}

impl Peer {
    pub fn with_capacity(max_types: usize) -> Self {
        Self {
            node_id: [0; 32],
            join_recv: PreallocMap::with_capacity(max_types),
            join_sent: PreallocMap::with_capacity(max_types),
            listed_count: 0,
            ihave_frames: 0,
            ihave_asked: 0,
            unwanted_ids: 0,
            served_now: 0,
            tie_count: 0,
            named_count: 0,
            wanted_count: 0,
            mark: 0,
        }
    }

    pub fn reset(&mut self) {
        self.node_id = [0; 32];
        self.join_recv.clear();
        self.join_sent.clear();
        self.listed_count = 0;
        self.ihave_frames = 0;
        self.ihave_asked = 0;
        self.unwanted_ids = 0;
        self.served_now = 0;
        self.tie_count = 0;
        self.named_count = 0;
        self.wanted_count = 0;
        self.mark = 0;
    }
}

/// A set of peers, named by how it is read from the node's bitmasks. It is
/// read a word at a time where it is used (`SeacastNode::walk`): nothing is
/// copied out of the node, and the set has no length to be cut at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerSet {
    /// The links of a type (`links(T)`).
    Links(TypeId),
    /// The peers that push us a type, family and colour (`in_pushers`).
    In(TypeId, FamilyId, Colour),
    /// The peers we push a type, family and colour (`out_pushees`).
    Out(TypeId, FamilyId, Colour),
    /// The peers in one direction only of a type, family and colour.
    OneWay(TypeId, FamilyId, Colour),
    /// The links that push us a family in any of the type's colours
    /// (`suppression_scope`); the last field is the number of colours.
    Scope(TypeId, FamilyId, Colour),
    /// The links in no relation of a family, in any of the type's colours.
    Unrelated(TypeId, FamilyId, Colour),
    /// The peers with a standing request for a chunk.
    Standing(GroupId, u32),
    /// The peers that claim a whole group.
    Claims(GroupId),
    /// The askers whose probe of our claim waits for a chunk we have not
    /// stored.
    ProbeWaiting(GroupId, u32),
}

/// A candidate of a push, with what `choose_push` orders it by.
#[derive(Debug, Clone, Copy)]
pub struct PushCand {
    pub unproven: bool,
    pub known: u32,
    pub tie: (u64, NodeId),
    pub peer: PeerId,
}

/// A push relation: peer, type, family, colour.
pub type RelationKey = (PeerId, TypeId, FamilyId, Colour);

/// One direction of the push relations (`push_in` or `push_out`,
/// `seacast.md` §3): the peers of each type, family and colour as a
/// bitmask, so that a chunk's targets are read without a walk over the peers.
#[derive(Debug, Clone)]
pub struct Relations {
    sets: PeerSets<(TypeId, FamilyId, Colour)>,
    len: usize,
}

impl Relations {
    pub fn with_capacity(keys: usize, max_peers: usize) -> Self {
        Self { sets: PeerSets::with_capacity(keys, max_peers), len: 0 }
    }

    /// The relations held.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn contains(&self, &(peer, t, fam, c): &RelationKey) -> bool {
        self.sets.contains(&(t, fam, c), peer)
    }

    /// Whether `insert` would keep the relation: admission, before a yes.
    #[inline]
    pub fn has_room(&self, &(_, t, fam, c): &RelationKey) -> bool {
        self.sets.has_room(&(t, fam, c))
    }

    /// Returns whether the relation was added.
    pub fn insert(&mut self, (peer, t, fam, c): RelationKey) -> bool {
        let added = !self.sets.contains(&(t, fam, c), peer) && self.sets.insert((t, fam, c), peer);
        self.len += added as usize;
        added
    }

    /// Returns whether the relation was held.
    pub fn remove(&mut self, &(peer, t, fam, c): &RelationKey) -> bool {
        let held = self.sets.remove(&(t, fam, c), peer);
        self.len -= held as usize;
        held
    }

    pub fn remove_peer(&mut self, peer: PeerId) {
        self.len -= self.sets.keys().filter(|key| self.sets.contains(key, peer)).count();
        self.sets.remove_peer(peer);
    }

    /// Drops `peer`'s relations of type `t`.
    pub fn remove_peer_type(&mut self, peer: PeerId, t: TypeId) {
        self.len -= self.pairs_of(peer, t).count();
        self.sets.remove_peer_if(peer, |&(ty, _, _)| ty == t);
    }

    /// Word `w` of the peers of a type, family and colour.
    #[inline]
    pub fn word(&self, t: TypeId, fam: FamilyId, c: Colour, w: usize) -> u64 {
        self.sets.word(&(t, fam, c), w)
    }

    /// Word `w` of the peers of a type and family in any of its `m` colours.
    pub fn family_word(&self, t: TypeId, fam: FamilyId, m: Colour, w: usize) -> u64 {
        (0..m).fold(0, |word, c| word | self.sets.word(&(t, fam, c), w))
    }

    pub fn count(&self, t: TypeId, fam: FamilyId, c: Colour) -> usize {
        self.sets.count(&(t, fam, c))
    }

    /// Whether `peer` is in the relation of a type and family in any of its
    /// `m` colours.
    pub fn any_colour(&self, peer: PeerId, t: TypeId, fam: FamilyId, m: Colour) -> bool {
        (0..m).any(|c| self.sets.contains(&(t, fam, c), peer))
    }

    /// Whether `peer` is in any relation.
    pub fn related(&self, peer: PeerId) -> bool {
        self.sets.keys().any(|key| self.sets.contains(key, peer))
    }

    /// The families and colours of type `t` that `peer` is in, by a walk over
    /// the keys, not the peers.
    pub fn pairs_of(
        &self,
        peer: PeerId,
        t: TypeId,
    ) -> impl Iterator<Item = (FamilyId, Colour)> + '_ {
        self.sets
            .keys()
            .filter(move |&&(ty, fam, c)| ty == t && self.sets.contains(&(ty, fam, c), peer))
            .map(|&(_, fam, c)| (fam, c))
    }

    pub fn iter(&self) -> impl Iterator<Item = RelationKey> + '_ {
        self.sets.keys().flat_map(|&(t, fam, c)| {
            self.sets.iter(&(t, fam, c)).map(move |peer| (peer, t, fam, c))
        })
    }
}

/// The bitmaps of a group's record. Each is unset until it is first written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupBits {
    Received,
    Rebuilt,
    Mine,
    Interest,
    /// As a source: the indices acknowledged.
    Origin,
}

impl GroupBits {
    const COUNT: usize = 5;
}

/// Where one of a record's bitmaps is: in the record while it names no index
/// past 63, else in the record's row of `Groups::wide`. A group of few chunks
/// then takes no row.
#[derive(Debug, Clone, Copy, Default)]
enum KeptBits {
    #[default]
    Unset,
    Narrow {
        inverted: bool,
        word: u64,
    },
    Wide,
}

/// Everything kept of one group. A field is `None` until it is first written,
/// as its entry was absent when each field was a map of its own.
#[derive(Debug, Clone, Default)]
pub struct Group {
    /// The group's object type: set when the group is opened.
    pub t_of: Option<TypeId>,
    /// The group's index count and threshold, from its header.
    pub hdr: Option<Shape>,
    /// Whether the domain has authenticated the group: asked once, not once a
    /// chunk.
    pub authentic: bool,
    /// When the group leaves the domain's window (`Domain::deadline`).
    pub deadline: Option<Timestamp>,
    pub state: Option<GroupState>,
    /// The record's bitmaps, read and written through [`Groups`].
    bits: [KeptBits; GroupBits::COUNT],
    /// The row of `Groups::wide` that holds the bitmaps kept there.
    wide: Option<u32>,
    pub stop_pull: Option<bool>,
    /// The indices asked for whose ask is on record (`asked_at`).
    pub asks_open: u16,
    /// Whether a holding of this group has gone out with `claim_all`: any index
    /// may then be asked for.
    pub claimed_all: bool,
    pub known_at: Option<Timestamp>,
    pub last_activity: Option<Timestamp>,
    // Claims, deferral, probe and repair sampling (`seacast.md` §3, §4.6)
    pub reconsider_at: Option<u64>,
    pub deferred: Option<bool>,
    pub waited: Option<bool>,
    pub probe: Option<u32>,
    pub probed: Option<PeerId>,
    /// The probe settled, once (`settle_probe`): `Some(Some(ok))` its verdict,
    /// whether the claimant's own copy came; `Some(None)` no verdict, the
    /// probe not written in time or the claimant gone.
    pub probe_ok: Option<Option<bool>>,
    /// Whether the probe's WANT was written: its promise and the verdict's
    /// wait start there (`probe_sent`).
    pub probe_sent: bool,
    /// The duty's own time when the claim deferred it: a probe with no
    /// verdict returns the duty to it (`duty_at`).
    pub duty_at: Option<Timestamp>,
    pub rsample_step: Option<usize>,
    pub rsample_final: Option<bool>,
}

/// The groups a node keeps anything of, a record each (`seacast.md` §3,
/// `seacast-lite.md` §8.1).
///
/// Two limits, each `max_groups`: on the groups that are open, and on those
/// that are not, which peers name before any chunk of them has been accepted.
/// Neither kind can take the other's room.
#[derive(Debug, Clone)]
pub struct Groups {
    recs: PreallocMap<GroupId, Group>,
    /// Where a group past its limit is written, so that `rec` still returns a
    /// place.
    spill: Group,
    open: usize,
    max_groups: usize,
    /// The bitmaps that name an index past 63, a row a group that has one.
    wide: Vec<[Bitmap; GroupBits::COUNT]>,
    free_rows: Vec<u32>,
}

impl Groups {
    pub fn with_capacity(max_groups: usize, max_wide_groups: usize) -> Self {
        Self {
            recs: PreallocMap::with_capacity(2 * max_groups),
            spill: Group::default(),
            open: 0,
            max_groups,
            wide: vec![[Bitmap::EMPTY; GroupBits::COUNT]; max_wide_groups],
            free_rows: (0..max_wide_groups as u32).rev().collect(),
        }
    }

    pub fn bits(&self, group: &GroupId, field: GroupBits) -> Option<Bitmap> {
        let rec = self.recs.get(group)?;
        match rec.bits[field as usize] {
            KeptBits::Unset => None,
            KeptBits::Narrow { inverted, word } => {
                let mut words = [0; BITMAP_WORDS];
                words[0] = word;
                Some(Bitmap::from_raw(inverted, words))
            }
            KeptBits::Wide => Some(self.wide[rec.wide? as usize][field as usize]),
        }
    }

    #[inline]
    pub fn has_bits(&self, group: &GroupId, field: GroupBits) -> bool {
        self.recs.get(group).is_some_and(|rec| !matches!(rec.bits[field as usize], KeptBits::Unset))
    }

    /// Writes one of `group`'s bitmaps, its record made if it has none. Not
    /// kept, as with [`Self::rec`], past the limit on groups that are not
    /// open; nor is a bitmap that names an index past 63 once every row of
    /// `max_wide_groups` is taken: the bitmap then stays as it was.
    pub fn put_bits(&mut self, group: GroupId, field: GroupBits, bits: Bitmap) {
        if !self.recs.contains_key(&group) && self.recs.len() - self.open >= self.max_groups {
            return;
        }
        let rec = self.recs.get_or_insert_with(group, Group::default);
        let (inverted, words) = bits.raw();
        if words[1..].iter().all(|word| *word == 0) {
            rec.bits[field as usize] = KeptBits::Narrow { inverted, word: words[0] };
            return;
        }
        if rec.wide.is_none() {
            rec.wide = self.free_rows.pop();
        }
        if let Some(row) = rec.wide {
            self.wide[row as usize][field as usize] = bits;
            rec.bits[field as usize] = KeptBits::Wide;
        }
    }

    /// Changes one of `group`'s bitmaps, from empty if it is unset.
    pub fn edit_bits(&mut self, group: GroupId, field: GroupBits, edit: impl FnOnce(&mut Bitmap)) {
        let mut bits = self.bits(&group, field).unwrap_or_default();
        edit(&mut bits);
        self.put_bits(group, field, bits);
    }

    #[inline]
    pub fn get(&self, group: &GroupId) -> Option<&Group> {
        self.recs.get(group)
    }

    #[inline]
    pub fn get_mut(&mut self, group: &GroupId) -> Option<&mut Group> {
        self.recs.get_mut(group)
    }

    /// `group`'s record, made if it has none. Past the limit on groups that are
    /// not open the record is not kept: what is written to it is lost.
    pub fn rec(&mut self, group: GroupId) -> &mut Group {
        if !self.recs.contains_key(&group) && self.recs.len() - self.open >= self.max_groups {
            self.spill = Group::default();
            return &mut self.spill;
        }
        self.recs.get_or_insert_with(group, Group::default)
    }

    /// Opens `group` as an object of type `t`. `false`, with nothing changed,
    /// at the limit on open groups.
    pub fn open(&mut self, group: GroupId, t: TypeId) -> bool {
        let is_open = self.recs.get(&group).is_some_and(|rec| rec.t_of.is_some());
        if !is_open {
            if self.open >= self.max_groups {
                return false;
            }
            self.open += 1;
        }
        self.recs.get_or_insert_with(group, Group::default).t_of = Some(t);
        true
    }

    /// Whether one more group may be opened.
    #[inline]
    pub fn can_open(&self) -> bool {
        self.open < self.max_groups
    }

    pub fn remove(&mut self, group: &GroupId) -> Option<Group> {
        let rec = self.recs.remove(group)?;
        if rec.t_of.is_some() {
            self.open -= 1;
        }
        if let Some(row) = rec.wide {
            self.free_rows.push(row);
        }
        Some(rec)
    }

    /// The number of open groups.
    #[inline]
    pub fn open_count(&self) -> usize {
        self.open
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.recs.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.recs.is_empty()
    }

    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (&GroupId, &Group)> {
        self.recs.iter()
    }

    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&GroupId, &mut Group)> {
        self.recs.iter_mut()
    }
}

/// A value per ask and peer. `peers` holds who has a value for an ask, so an
/// arriving chunk closes its records without a scan. Bounded twice: the
/// records of the node, and those of one peer. A record over either bound is
/// refused.
#[derive(Debug, Clone)]
pub struct AskPeers<V: Copy> {
    values: PreallocMap<(Ask, PeerId), V>,
    peers: PeerSets<Ask>,
    per_peer: Box<[u32]>,
    max_per_peer: u32,
}

impl<V: Copy> AskPeers<V> {
    pub fn with_capacity(records: usize, max_per_peer: usize, max_peers: usize) -> Self {
        Self {
            values: PreallocMap::with_capacity(records),
            peers: PeerSets::with_capacity(records, max_peers),
            per_peer: vec![0; max_peers].into_boxed_slice(),
            max_per_peer: max_per_peer as u32,
        }
    }

    pub fn get(&self, ask: Ask, peer: PeerId) -> Option<V> {
        self.values.get(&(ask, peer)).copied()
    }

    pub fn contains(&self, ask: Ask, peer: PeerId) -> bool {
        self.values.contains_key(&(ask, peer))
    }

    /// Whether `insert` would take a value for `ask` and `peer`.
    pub fn has_room(&self, ask: Ask, peer: PeerId) -> bool {
        self.contains(ask, peer) ||
            (!self.values.is_full() && self.per_peer[peer as usize] < self.max_per_peer)
    }

    /// Returns `false` if the record is new and over a bound.
    pub fn insert(&mut self, ask: Ask, peer: PeerId, value: V) -> bool {
        if let Some(held) = self.values.get_mut(&(ask, peer)) {
            *held = value;
            return true;
        }
        if !self.has_room(ask, peer) {
            return false;
        }
        self.values.insert((ask, peer), value);
        self.peers.insert(ask, peer);
        self.per_peer[peer as usize] += 1;
        true
    }

    pub fn remove(&mut self, ask: Ask, peer: PeerId) -> Option<V> {
        let value = self.values.remove(&(ask, peer))?;
        self.peers.remove(&ask, peer);
        self.per_peer[peer as usize] -= 1;
        Some(value)
    }

    /// Drops every peer's value for `ask`.
    pub fn remove_ask(&mut self, ask: Ask) {
        for peer in self.peers.iter(&ask) {
            self.values.remove(&(ask, peer));
            self.per_peer[peer as usize] -= 1;
        }
        self.peers.remove_key(&ask);
    }

    /// Drops every value of `peer`.
    pub fn remove_peer(&mut self, peer: PeerId) {
        if self.per_peer[peer as usize] != 0 {
            self.retain(|_, q, _| q != peer);
        }
    }

    pub fn retain(&mut self, mut keep: impl FnMut(Ask, PeerId, V) -> bool) {
        let (peers, per_peer) = (&mut self.peers, &mut self.per_peer);
        self.values.retain(|&(ask, peer), value| {
            if keep(ask, peer, *value) {
                return true;
            }
            peers.remove(&ask, peer);
            per_peer[peer as usize] -= 1;
            false
        });
    }

    /// The number of (ask, peer) pairs.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// The number of asks `peer` has a value for.
    pub fn count_of(&self, peer: PeerId) -> usize {
        self.per_peer[peer as usize] as usize
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Sliding heartbeat message cache for heartbeat gossip (`seacast-lite.md`
/// §6.4, `seacast.md` §4.8).
///
/// Preallocated once at initialization; performs **zero heap allocation**
/// during `put`, `shift`, `gossip_group_bits`, and `remove_group`.
#[derive(Debug, Clone)]
pub struct GossipHistory {
    windows: PreallocVec<PreallocVec<(GroupId, Bitmap)>>,
    head: usize,
    length: usize,
    gossip_windows: usize,
}

impl GossipHistory {
    /// Preallocates `length` sliding windows, each with capacity `max_groups`.
    pub fn with_capacity(length: usize, gossip_windows: usize, max_groups: usize) -> Self {
        let length = length.clamp(1, MAX_GOSSIP_WINDOWS);
        let gossip_windows = gossip_windows.min(length);
        let mut windows = PreallocVec::with_capacity(length);
        for _ in 0..length {
            let _ = windows.push(PreallocVec::with_capacity(max_groups));
        }
        Self { windows, head: 0, length, gossip_windows }
    }

    /// Adds a published or forwarded chunk to the current heartbeat window
    /// (`gossip_history.put(f)`).
    pub fn put<B>(&mut self, chunk: &ChunkMsg<B>) {
        let front = &mut self.windows[self.head];
        for (g, bits) in front.iter_mut() {
            if *g == chunk.group {
                bits.set(chunk.index);
                return;
            }
        }
        let _ = front.push((chunk.group, Bitmap::singleton(chunk.index)));
    }

    /// Shifts the sliding window at each heartbeat without heap allocation.
    pub fn shift(&mut self) {
        self.head = (self.head + self.length - 1) % self.length;
        self.windows[self.head].clear();
    }

    /// Returns chunk `(group, bits)` pairs from the newest `gossip_windows`
    /// heartbeats on the stack (`group_bits(gossip_history.gossip_ids())`).
    pub fn gossip_group_bits(&self) -> InlineVec<(GroupId, Bitmap), MAX_GOSSIP_GROUPS> {
        let mut out: InlineVec<(GroupId, Bitmap), MAX_GOSSIP_GROUPS> = InlineVec::new();
        for offset in 0..self.gossip_windows {
            let idx = (self.head + offset) % self.length;
            for &(group, ref bits) in self.windows[idx].iter() {
                if let Some((_, existing)) = out.iter_mut().find(|(g, _)| *g == group) {
                    *existing |= bits;
                } else {
                    let _ = out.push((group, *bits));
                }
            }
        }
        out
    }

    /// Removes all entries of `group` (`gossip_history.remove_group(g)`).
    pub fn remove_group(&mut self, group: &GroupId) {
        for w in self.windows.iter_mut() {
            w.retain(|(g, _)| g != group);
        }
    }
}

/// The bitmaps a (peer, group) pair keeps, by their place in its record.
#[derive(Clone, Copy)]
enum PairBits {
    Has = 0,
    Pushed = 1,
    SentTo = 2,
    Want = 3,
    Offered = 4,
    OfferedTo = 5,
}

const PAIR_BITMAPS: usize = 6;
/// Words of a bitmap kept in the record itself. A group with more indices than
/// these hold takes a block of full bitmaps from the pool.
const NARROW_WORDS: usize = 2;
const NO_WIDE: u32 = u32::MAX;

const CLAIM_ALL: u8 = 1;
const COMPLETE: u8 = 1 << 1;
const FIRST_PUSH: u8 = 1 << 2;
const OFFER_AT: u8 = 1 << 3;
const PARK: u8 = 1 << 4;
/// As a claimant: the peer's probe of the group has been answered.
const PROBE_SERVED: u8 = 1 << 5;
/// An unsolicited chunk of the group has been written to the peer. Not kept
/// alone: a pair that holds nothing else goes, and the next push is a first
/// one again.
const FIRST_WRITTEN: u8 = 1 << 6;

#[derive(Debug, Clone, Copy)]
struct Pair {
    narrow: [[u64; NARROW_WORDS]; PAIR_BITMAPS],
    /// Which bitmaps exist, and which of them are complemented, a bit each.
    present: u8,
    inverted: u8,
    flags: u8,
    /// The pair's block in the pool, if it has one.
    wide: u32,
    have_ttl: u32,
    push_ttl: u32,
    served: u32,
    first_push: Timestamp,
    offer_at: Timestamp,
    park: Timestamp,
}

impl Pair {
    const EMPTY: Self = Self {
        narrow: [[0; NARROW_WORDS]; PAIR_BITMAPS],
        present: 0,
        inverted: 0,
        flags: 0,
        wide: NO_WIDE,
        have_ttl: 0,
        push_ttl: 0,
        served: 0,
        first_push: 0.0,
        offer_at: 0.0,
        park: 0.0,
    };

    fn has(&self, field: PairBits) -> bool {
        self.present & (1 << field as u8) != 0
    }

    fn drop_bits(&mut self, field: PairBits) {
        self.present &= !(1 << field as u8);
    }

    fn is_empty(&self) -> bool {
        self.present == 0 && self.served == 0 && self.flags & (OFFER_AT | PARK | PROBE_SERVED) == 0
    }
}

type PairKey = (PeerId, GroupId);

/// Everything kept per peer and group (`peer_has`, `pushed`, `sent_to`,
/// `served`, `want_p`, `offered`, its time and `park` in `seacast.md` §3),
/// one record a pair.
///
/// A record holds its bitmaps narrow. The first index past them moves the
/// pair's bitmaps to a block of the pool; with the pool empty the indices past
/// them are not kept.
#[derive(Debug, Clone)]
pub struct Pairs {
    recs: PreallocMap<PairKey, Pair>,
    wide: Vec<[[u64; BITMAP_WORDS]; PAIR_BITMAPS]>,
    free: Vec<u32>,
    /// The peers with offers of a group, and those with a holding of it: a
    /// pair is found by its group without a walk over the peers.
    offering: PeerSets<GroupId>,
    having: PeerSets<GroupId>,
}

impl Pairs {
    /// `groups`: the groups that may have pairs at one time.
    pub fn with_capacity(pairs: usize, wide_pairs: usize, groups: usize, max_peers: usize) -> Self {
        Self {
            recs: PreallocMap::with_capacity(pairs),
            wide: vec![[[0; BITMAP_WORDS]; PAIR_BITMAPS]; wide_pairs],
            free: (0..wide_pairs as u32).rev().collect(),
            offering: PeerSets::with_capacity(groups, max_peers),
            having: PeerSets::with_capacity(groups, max_peers),
        }
    }

    /// The peers with offers of `group`, in peer id order.
    pub fn offering<'a>(&'a self, group: &GroupId) -> impl Iterator<Item = PeerId> + use<'a> {
        self.offering.iter(group)
    }

    /// The peers with a holding of `group`, in peer id order.
    pub fn having<'a>(&'a self, group: &GroupId) -> impl Iterator<Item = PeerId> + use<'a> {
        self.having.iter(group)
    }

    /// Takes `index` out of every peer's offers of `group`.
    pub fn clear_offered(&mut self, group: &GroupId, index: u32) {
        for w in 0..self.offering.width() {
            let Some(word) = self.offering.row(group).map(|row| row[w]) else {
                return;
            };
            for peer in word_bits(w, word) {
                let key = (peer, *group);
                if let Some(mut bits) = self.offered(&key) {
                    bits.clear(index);
                    self.set_offered(key, bits);
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.recs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.recs.is_empty()
    }

    pub fn keys(&self) -> impl Iterator<Item = &PairKey> {
        self.recs.iter().map(|(key, _)| key)
    }

    fn load(&self, pair: &Pair, field: PairBits) -> Bitmap {
        let at = field as usize;
        let mut words = [0; BITMAP_WORDS];
        if pair.wide == NO_WIDE {
            words[..NARROW_WORDS].copy_from_slice(&pair.narrow[at]);
        } else {
            words = self.wide[pair.wide as usize][at];
        }
        Bitmap::from_raw(pair.inverted & (1 << at) != 0, words)
    }

    fn bits(&self, key: &PairKey, field: PairBits) -> Option<Bitmap> {
        let pair = self.recs.get(key).filter(|pair| pair.has(field))?;
        Some(self.load(pair, field))
    }

    /// The pair's record, made if there is room for one.
    fn rec(&mut self, key: PairKey) -> Option<&mut Pair> {
        if !self.recs.contains_key(&key) {
            if self.recs.is_full() {
                return None;
            }
            self.recs.insert(key, Pair::EMPTY);
        }
        self.recs.get_mut(&key)
    }

    fn put(&mut self, key: PairKey, field: PairBits, bits: &Bitmap) -> Option<&mut Pair> {
        let at = field as usize;
        let (inverted, words) = bits.raw();
        let is_wide = words[NARROW_WORDS..].iter().any(|&word| word != 0);
        if !self.recs.contains_key(&key) && self.recs.is_full() {
            return None;
        }
        // Not kept where the index has no room: a pair the index lacks is not found.
        let indexed = match field {
            PairBits::Offered => self.offering.insert(key.1, key.0),
            PairBits::Has => self.having.insert(key.1, key.0),
            _ => true,
        };
        if !indexed {
            return None;
        }
        let (wide, free) = (&mut self.wide, &mut self.free);
        let pair = if self.recs.contains_key(&key) || !self.recs.is_full() {
            self.recs.get_or_insert_with(key, || Pair::EMPTY)
        } else {
            return None;
        };
        if is_wide && pair.wide == NO_WIDE {
            if let Some(block) = free.pop() {
                let moved = &mut wide[block as usize];
                *moved = [[0; BITMAP_WORDS]; PAIR_BITMAPS];
                for (to, from) in moved.iter_mut().zip(&pair.narrow) {
                    to[..NARROW_WORDS].copy_from_slice(from);
                }
                pair.wide = block;
            }
        }
        if pair.wide == NO_WIDE {
            pair.narrow[at].copy_from_slice(&words[..NARROW_WORDS]);
        } else {
            wide[pair.wide as usize][at] = *words;
        }
        pair.present |= 1 << at;
        pair.inverted = (pair.inverted & !(1 << at)) | ((inverted as u8) << at);
        Some(pair)
    }

    pub fn peer_has(&self, key: &PairKey) -> Option<HaveEntry> {
        let pair = self.recs.get(key).filter(|pair| pair.has(PairBits::Has))?;
        Some(HaveEntry {
            bits: self.load(pair, PairBits::Has),
            ttl: pair.have_ttl,
            claim_all: pair.flags & CLAIM_ALL != 0,
            complete: pair.flags & COMPLETE != 0,
        })
    }

    /// What the peer holds of the group, empty if it has claimed nothing.
    pub fn has_bits(&self, key: &PairKey) -> Bitmap {
        self.bits(key, PairBits::Has).unwrap_or(Bitmap::EMPTY)
    }

    pub fn set_peer_has(&mut self, key: PairKey, entry: HaveEntry) {
        if let Some(pair) = self.put(key, PairBits::Has, &entry.bits) {
            pair.have_ttl = entry.ttl;
            pair.flags &= !(CLAIM_ALL | COMPLETE);
            if entry.claim_all {
                pair.flags |= CLAIM_ALL;
            }
            if entry.complete {
                pair.flags |= COMPLETE;
            }
        }
    }

    pub fn pushed(&self, key: &PairKey) -> Option<PushEntry> {
        let pair = self.recs.get(key).filter(|pair| pair.has(PairBits::Pushed))?;
        Some(PushEntry {
            bits: self.load(pair, PairBits::Pushed),
            first_push: (pair.flags & FIRST_PUSH != 0).then_some(pair.first_push),
            ttl: pair.push_ttl,
        })
    }

    /// What was pushed to the peer of the group, empty if nothing.
    pub fn pushed_bits(&self, key: &PairKey) -> Bitmap {
        self.bits(key, PairBits::Pushed).unwrap_or(Bitmap::EMPTY)
    }

    pub fn set_pushed(&mut self, key: PairKey, entry: PushEntry) {
        if let Some(pair) = self.put(key, PairBits::Pushed, &entry.bits) {
            pair.push_ttl = entry.ttl;
            pair.flags &= !FIRST_PUSH;
            if let Some(at) = entry.first_push {
                pair.flags |= FIRST_PUSH;
                pair.first_push = at;
            }
        }
    }

    pub fn sent_to(&self, key: &PairKey) -> Option<Bitmap> {
        self.bits(key, PairBits::SentTo)
    }

    pub fn set_sent_to(&mut self, key: PairKey, bits: Bitmap) {
        self.put(key, PairBits::SentTo, &bits);
    }

    pub fn want_p(&self, key: &PairKey) -> Option<Bitmap> {
        self.bits(key, PairBits::Want)
    }

    pub fn set_want_p(&mut self, key: PairKey, bits: Bitmap) {
        self.put(key, PairBits::Want, &bits);
    }

    pub fn offered(&self, key: &PairKey) -> Option<Bitmap> {
        self.bits(key, PairBits::Offered)
    }

    pub fn offered_to(&self, key: &PairKey) -> Option<Bitmap> {
        self.bits(key, PairBits::OfferedTo)
    }

    pub fn add_offered_to(&mut self, key: PairKey, bits: &Bitmap) {
        if bits.is_empty() {
            return;
        }
        let existing = self.bits(&key, PairBits::OfferedTo).unwrap_or(Bitmap::EMPTY);
        self.put(key, PairBits::OfferedTo, &(existing | bits));
    }

    /// Clears `want_p` for `(peer, group)`.
    pub fn clear_want_p(&mut self, key: &PairKey) {
        self.clear_field(key, PairBits::Want);
    }

    fn clear_field(&mut self, key: &PairKey, field: PairBits) {
        let Some(pair) = self.recs.get_mut(key) else {
            return;
        };
        pair.drop_bits(field);
        if pair.is_empty() {
            let wide = pair.wide;
            self.recs.remove(key);
            if wide != NO_WIDE {
                self.free.push(wide);
            }
        }
    }

    /// Masks `want_p` of `group` for each of `peers`, keeping only indices for
    /// which `keep(index)` holds.
    pub fn retain_want_p(
        &mut self,
        group: &GroupId,
        peers: &[PeerId],
        mut keep: impl FnMut(u32) -> bool,
    ) {
        for &peer in peers {
            let key = (peer, *group);
            let Some(bits) = self.bits(&key, PairBits::Want) else {
                continue;
            };
            let mut next = Bitmap::new();
            for i in bits.iter() {
                if keep(i) {
                    next.set(i);
                }
            }
            if next.is_empty() {
                self.clear_field(&key, PairBits::Want);
            } else if next != bits {
                self.put(key, PairBits::Want, &next);
            }
        }
    }

    pub fn set_offered(&mut self, key: PairKey, bits: Bitmap) {
        self.put(key, PairBits::Offered, &bits);
    }

    /// Removes the peer's offers of the group with their time, and returns
    /// them.
    pub fn take_offered(&mut self, key: &PairKey) -> Option<Bitmap> {
        let bits = self.bits(key, PairBits::Offered);
        if let Some(pair) = self.recs.get_mut(key) {
            pair.drop_bits(PairBits::Offered);
            pair.flags &= !OFFER_AT;
            self.offering.remove(&key.1, key.0);
        }
        bits
    }

    pub fn served(&self, key: &PairKey) -> usize {
        self.recs.get(key).map_or(0, |pair| pair.served as usize)
    }

    /// Whether the pair has a record or the table has room for one: what a
    /// count of the pair needs.
    #[inline]
    pub fn has_room(&self, key: &PairKey) -> bool {
        self.recs.contains_key(key) || !self.recs.is_full()
    }

    pub fn add_served(&mut self, key: PairKey) {
        if let Some(pair) = self.rec(key) {
            pair.served = pair.served.saturating_add(1);
        }
    }

    pub fn set_offer_at(&mut self, key: PairKey, at: Timestamp) {
        if let Some(pair) = self.rec(key) {
            pair.flags |= OFFER_AT;
            pair.offer_at = at;
        }
    }

    /// A pair whose last offer is older than `cutoff`.
    pub fn expired_offer(&self, cutoff: Timestamp) -> Option<PairKey> {
        self.recs
            .iter()
            .find(|(_, pair)| pair.flags & OFFER_AT != 0 && pair.offer_at < cutoff)
            .map(|(&key, _)| key)
    }

    /// Whether an unsolicited chunk of the group has been written to the peer
    /// ([`QueueEntry::first_of_group`](crate::QueueEntry)).
    pub fn first_written(&self, key: &PairKey) -> bool {
        self.recs.get(key).is_some_and(|pair| pair.flags & FIRST_WRITTEN != 0)
    }

    /// Records that an unsolicited chunk of the group was written to the peer,
    /// where the table has room for the pair.
    pub fn set_first_written(&mut self, key: PairKey) {
        if let Some(pair) = self.rec(key) {
            pair.flags |= FIRST_WRITTEN;
        }
    }

    pub fn park(&self, key: &PairKey) -> Option<Timestamp> {
        let pair = self.recs.get(key).filter(|pair| pair.flags & PARK != 0)?;
        Some(pair.park)
    }

    pub fn set_park(&mut self, key: PairKey, until: Timestamp) {
        if let Some(pair) = self.rec(key) {
            pair.flags |= PARK;
            pair.park = until;
        }
    }

    /// The pairs with a park, and its end.
    pub fn parks(&self) -> impl Iterator<Item = (&PairKey, Timestamp)> {
        self.recs
            .iter()
            .filter(|(_, pair)| pair.flags & PARK != 0)
            .map(|(key, pair)| (key, pair.park))
    }

    pub fn clear_park(&mut self, key: &PairKey) {
        if let Some(pair) = self.recs.get_mut(key) {
            pair.flags &= !PARK;
        }
    }

    /// As a claimant: whether the peer's probe of the group was answered
    /// (`seacast.md` §4.6 `probe_served`).
    pub fn probe_served(&self, key: &PairKey) -> bool {
        self.recs.get(key).is_some_and(|pair| pair.flags & PROBE_SERVED != 0)
    }

    pub fn set_probe_served(&mut self, key: PairKey) {
        if let Some(pair) = self.rec(key) {
            pair.flags |= PROBE_SERVED;
        }
    }

    /// Keeps the pairs `keep` accepts.
    pub fn retain(&mut self, mut keep: impl FnMut(&PairKey) -> bool) {
        let (free, offering, having) = (&mut self.free, &mut self.offering, &mut self.having);
        self.recs.retain(|key, pair| {
            let kept = keep(key);
            if !kept {
                offering.remove(&key.1, key.0);
                having.remove(&key.1, key.0);
                if pair.wide != NO_WIDE {
                    free.push(pair.wide);
                }
            }
            kept
        });
    }

    /// One heartbeat: `HAVE_TTL` and `PUSH_TTL` count down and a park past its
    /// time ends. A holding that expires goes with what was sent to the
    /// peer, and is given to `expired`. A pair left with nothing is
    /// removed.
    pub fn heartbeat(&mut self, now: Timestamp, mut expired: impl FnMut(PeerId, GroupId, Bitmap)) {
        let (wide, free, having) = (&self.wide, &mut self.free, &mut self.having);
        self.recs.retain(|&(peer, group), pair| {
            if pair.has(PairBits::Has) {
                if pair.have_ttl > 1 {
                    pair.have_ttl -= 1;
                } else {
                    let mut words = [0; BITMAP_WORDS];
                    if pair.wide == NO_WIDE {
                        words[..NARROW_WORDS].copy_from_slice(&pair.narrow[PairBits::Has as usize]);
                    } else {
                        words = wide[pair.wide as usize][PairBits::Has as usize];
                    }
                    let inverted = pair.inverted & (1 << PairBits::Has as u8) != 0;
                    expired(peer, group, Bitmap::from_raw(inverted, words));
                    pair.drop_bits(PairBits::Has);
                    having.remove(&group, peer);
                    pair.drop_bits(PairBits::SentTo);
                    pair.flags &= !(CLAIM_ALL | COMPLETE);
                }
            }
            if pair.has(PairBits::Pushed) {
                if pair.push_ttl > 1 {
                    pair.push_ttl -= 1;
                } else {
                    pair.drop_bits(PairBits::Pushed);
                    pair.flags &= !FIRST_PUSH;
                }
            }
            if pair.flags & PARK != 0 && now >= pair.park {
                pair.flags &= !PARK;
            }
            let kept = !pair.is_empty();
            if !kept && pair.wide != NO_WIDE {
                free.push(pair.wide);
            }
            kept
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bitmap that names an index past 63 takes a row, which its group's
    /// end frees; with no row left such a bitmap stays as it was.
    #[test]
    fn wide_bitmaps_take_a_row() {
        let mut groups = Groups::with_capacity(4, 1);
        let (a, b) = (GroupId::new(TypeId(0), [1; 32], 0), GroupId::new(TypeId(0), [2; 32], 0));
        let narrow = Bitmap::from_indices([0, 63]);
        let wide = Bitmap::from_indices([0, 64, 1023]);

        groups.put_bits(a, GroupBits::Mine, narrow);
        groups.put_bits(a, GroupBits::Interest, Bitmap::EVERY_INDEX);
        assert_eq!(groups.bits(&a, GroupBits::Mine), Some(narrow));
        assert_eq!(groups.bits(&a, GroupBits::Interest), Some(Bitmap::EVERY_INDEX));
        assert_eq!(groups.bits(&a, GroupBits::Received), None);
        assert_eq!(groups.free_rows.len(), 1);

        groups.put_bits(a, GroupBits::Mine, wide);
        groups.edit_bits(a, GroupBits::Received, |bits| bits.set(700));
        assert_eq!(groups.bits(&a, GroupBits::Mine), Some(wide));
        assert_eq!(groups.bits(&a, GroupBits::Received), Some(Bitmap::singleton(700)));
        assert!(groups.free_rows.is_empty());

        groups.put_bits(b, GroupBits::Mine, narrow);
        groups.put_bits(b, GroupBits::Mine, wide);
        assert_eq!(groups.bits(&b, GroupBits::Mine), Some(narrow));

        groups.remove(&a);
        groups.put_bits(b, GroupBits::Mine, wide);
        assert_eq!(groups.bits(&b, GroupBits::Mine), Some(wide));
    }
}
