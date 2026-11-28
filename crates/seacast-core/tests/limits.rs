//! What a peer sends cannot crash a node or grow its state past its limits, and
//! nothing it is owed or has asked for is left behind (`seacast-lite.md` §8.1,
//! §8.2; `seacast.md` §2, §3, §6.3).

use seacast_core::{
    Ask, Bitmap, BoundedDeferredStore, ChunkId, ChunkMsg, Control, Direction, DispatchOutcome,
    Domain, Duty, FamilyId, Graft, GroupBits, GroupId, GroupState, Have, InlineVec, InterestKind,
    Join, LinkFloor, MAX_CHUNKS, MAX_JOINED_TYPES, NodeConfig, NodeId, PeerId, PenaltyReason,
    Policy, PreallocVec, Prune, Queued, Rpc, RuntimeEnv, SeacastNode, Shape, SplitMix64,
    TimerEvent, Timestamp, TypeCodec, TypeId, TypeParams, ValidationResult, Want,
};

type Chunk = ChunkMsg<Vec<u8>>;
const TYPE: TypeId = TypeId(0);
const NODES: u64 = 32;
type BlockRoot = [u8; 32];
type Node = SeacastNode<Vec<u8>>;

struct Env {
    now: Timestamp,
    delivered: usize,
    /// `RetryOffer` timers armed, and penalties reported.
    retries: usize,
    penalties: usize,
    /// Peers whose writer is currently mid-write (`RuntimeEnv::is_writing`).
    writing: Vec<PeerId>,
    /// Peers woken by `RuntimeEnv::wake_writer`.
    woken: Vec<PeerId>,
}

impl RuntimeEnv<Vec<u8>> for Env {
    fn now(&self) -> Timestamp {
        self.now
    }
    fn schedule_after(&mut self, _delay: f64, event: TimerEvent) {
        if matches!(event, TimerEvent::RetryOffer(_)) {
            self.retries += 1;
        }
    }
    fn wake_writer(&mut self, peer: PeerId) {
        self.woken.push(peer);
    }
    fn is_writing(&self, peer: PeerId) -> bool {
        self.writing.contains(&peer)
    }
    fn start_decode(&mut self, _group: GroupId, _job: seacast_core::DecodeJob<'_, Vec<u8>>) {}
    fn deliver(&mut self, _group: GroupId, _object: Vec<u8>) {
        self.delivered += 1;
    }
    fn penalise(&mut self, _peer: PeerId, _reason: PenaltyReason) {
        self.penalties += 1;
    }
}

/// One type of `n` indices, complete at `k`. A header is the chunk's own;
/// `interest` is what the node itself wants, `declared` whether it joins as a
/// sampler does.
struct Catalog {
    params: TypeParams,
    n: u32,
    k: u32,
    interest: Bitmap,
    declared: bool,
    /// The one block root taken as installed, if set: a chunk naming another is
    /// deferred.
    installed: Option<BlockRoot>,
    /// Whether the proof is checked off the chunk path: the inline check then
    /// answers `Pending`.
    deferred_proof: bool,
    /// Groups whose gate is a header, and whether that header is validated:
    /// their chunks need no installed block once it is.
    cells: Vec<GroupId>,
    header_validated: bool,
    /// The domain does not take groups yet: their chunks are ignored.
    too_early: bool,
    /// When the domain's window closes on every group, if it has one.
    deadline: Option<Timestamp>,
    /// A second index every chunk is said to fill, as a faulty `project` would.
    stray_index: Option<u32>,
    /// The node joins with a derived interest, and keeps its duty.
    derived: bool,
    /// The peers whose derived interest holds every family, if not all do.
    covering: Option<Vec<PeerId>>,
    /// The link floors beyond the relation floor.
    floors: Vec<LinkFloor>,
    /// The delay to a decode the node keeps for later, if it does not decode
    /// at `k`.
    later: Option<f64>,
    /// A group every index also fills, as a cell fills its row and column.
    cross_group: Option<GroupId>,
}

impl Catalog {
    fn new(n: u32, k: u32) -> Self {
        Self {
            params: TypeParams::default(),
            n,
            k,
            interest: Bitmap::EVERY_INDEX,
            declared: false,
            installed: None,
            deferred_proof: false,
            cells: Vec::new(),
            header_validated: false,
            too_early: false,
            deadline: None,
            stray_index: None,
            derived: false,
            covering: None,
            floors: Vec::new(),
            later: None,
            cross_group: None,
        }
    }
}

impl TypeCodec<Vec<u8>> for Catalog {
    fn shape(&self, _chunk: &Chunk) -> Option<Shape> {
        Some(Shape { n: self.n, k: self.k })
    }
    fn check(&self, chunk: &Chunk) -> bool {
        chunk.index < self.n
    }
    fn check_proof(&mut self, _chunk: &Chunk) -> ValidationResult {
        if self.deferred_proof { ValidationResult::Pending } else { ValidationResult::Accept }
    }
    fn header_id(&self, _chunk: &Chunk) -> [u8; 32] {
        [0; 32]
    }
    /// The block root a chunk names.
    fn context<'a>(&self, chunk: &'a Chunk) -> &'a [u8] {
        &chunk.frame[..32]
    }
    fn decode(
        &mut self,
        group: &GroupId,
        available: &[Chunk],
        _shape: &Shape,
        out_rebuilt: &mut PreallocVec<Chunk>,
    ) -> Option<Vec<u8>> {
        if available.len() < self.k as usize {
            return None;
        }
        let root: BlockRoot = available[0].frame[..32].try_into().unwrap();
        for i in 0..self.n {
            let _ = out_rebuilt.push(chunk(*group, i, root));
        }
        Some(vec![0xAA; 16])
    }
    fn project(&self, chunk: &Chunk) -> InlineVec<(GroupId, u32), { seacast_core::MAX_PROJECTED }> {
        let mut filled = InlineVec::singleton((chunk.group, chunk.index));
        if let Some(index) = self.stray_index {
            let _ = filled.push((chunk.group, index));
        }
        filled
    }
    fn cross(
        &self,
        _group: &GroupId,
        index: u32,
    ) -> InlineVec<(GroupId, u32), { seacast_core::MAX_PROJECTED }> {
        self.cross_group.map(|g| InlineVec::singleton((g, index))).unwrap_or_default()
    }
}

impl Domain for Catalog {
    fn authenticate(
        &mut self,
        group: &GroupId,
        _header_id: &[u8; 32],
        context: &[u8],
    ) -> ValidationResult {
        let by_header = self.header_validated && self.cells.contains(group);
        if self.too_early {
            ValidationResult::Ignore
        } else if by_header || self.installed.is_none_or(|root| root[..] == *context) {
            ValidationResult::Accept
        } else {
            ValidationResult::Defer
        }
    }
    fn deadline(&self, _group: &GroupId, _context: &[u8]) -> Option<Timestamp> {
        self.deadline
    }

    fn authenticable(&self, _group: &GroupId) -> bool {
        true
    }
}

impl Policy for Catalog {
    fn params(&self, t: TypeId) -> &TypeParams {
        assert_eq!(t, TYPE, "asked for a type this node does not run");
        &self.params
    }
    fn own_interest(&self, _group: &GroupId) -> Bitmap {
        self.interest
    }
    fn decode_at_k(&self, _group: &GroupId) -> bool {
        // A sampler rebuilds nothing.
        !self.declared && self.later.is_none()
    }
    fn decode_later(
        &mut self,
        _group: &GroupId,
        _rng: &mut dyn seacast_core::RngSource,
    ) -> Option<f64> {
        self.later
    }
    fn our_join(&self, t: TypeId) -> Join {
        assert_eq!(t, TYPE, "asked for a type this node does not run");
        Join {
            object_type: t,
            interest: match (self.declared, self.derived) {
                (true, _) => InterestKind::Declared,
                (_, true) => InterestKind::Derived,
                _ => InterestKind::All,
            },
            fork_digest: [0; 4],
            custody_count: 0,
            duty: if self.declared { Duty::None } else { Duty::Forward },
            colours: 1,
        }
    }
    fn joined_types(&self) -> InlineVec<TypeId, MAX_JOINED_TYPES> {
        InlineVec::singleton(TYPE)
    }
    fn holds_family(
        &self,
        _t: TypeId,
        _family: FamilyId,
        peer: PeerId,
        _node_id: &NodeId,
        _join: &Join,
    ) -> bool {
        self.covering.as_ref().is_none_or(|peers| peers.contains(&peer))
    }
    fn link_floors(&self, _t: TypeId) -> InlineVec<LinkFloor, MAX_CHUNKS> {
        InlineVec::from_slice(&self.floors)
    }
    fn tiebreak(&self, chunk_id: &ChunkId, peer: PeerId) -> u64 {
        (chunk_id[1] as u64).wrapping_add(peer)
    }
    fn node_id(&self, peer: PeerId) -> NodeId {
        let mut id = [0u8; 32];
        // Peer ids `NODES` apart are connections of one node.
        id[..8].copy_from_slice(&(peer % NODES).to_le_bytes());
        id
    }
}

fn group(tag: u32) -> GroupId {
    let mut g = [0u8; 32];
    g[..4].copy_from_slice(&tag.to_le_bytes());
    g[31] = 1;
    GroupId::new(TYPE, g, 0)
}

fn chunk(group: GroupId, index: u32, root: BlockRoot) -> Chunk {
    let mut cached_id = [0u8; 59];
    cached_id[0] = TYPE.0;
    cached_id[1..33].copy_from_slice(&group.key);
    cached_id[33..35].copy_from_slice(&group.index.to_le_bytes());
    cached_id[35..39].copy_from_slice(&index.to_le_bytes());
    cached_id[39] = root[0];
    let mut frame = root.to_vec();
    frame.extend_from_slice(&[index as u8; 8]);
    ChunkMsg { group, index, frame, cached_id, memo: [0; 32], wire_len: 0 }
}

fn peer_join(interest: InterestKind) -> Join {
    Join {
        object_type: TYPE,
        fork_digest: [0; 4],
        interest,
        custody_count: 0,
        duty: Duty::Forward,
        colours: 1,
    }
}

struct World {
    node: Node,
    env: Env,
    catalog: Catalog,
    rng: SplitMix64,
    store: BoundedDeferredStore,
}

impl World {
    /// A node with `peers` connected, each joined to the type with `interest`.
    fn new(catalog: Catalog, peers: u64, interest: InterestKind) -> Self {
        Self::with_config(NodeConfig::default(), catalog, peers, interest)
    }

    fn with_config(
        config: NodeConfig,
        catalog: Catalog,
        peers: u64,
        interest: InterestKind,
    ) -> Self {
        let mut world = Self {
            node: SeacastNode::new(config),
            env: Env {
                now: 1.0,
                delivered: 0,
                retries: 0,
                penalties: 0,
                writing: Vec::new(),
                woken: Vec::new(),
            },
            catalog,
            rng: SplitMix64::new(7),
            store: BoundedDeferredStore::default(),
        };
        for peer in 1..=peers {
            world.node.connect_peer(peer, true, &mut world.env, &world.catalog);
            let mut rpc = Rpc::default();
            let _ = rpc.joins.push(peer_join(interest));
            world.rpc(peer, rpc);
            world.drain(peer);
        }
        world
    }

    fn rpc(&mut self, peer: PeerId, rpc: Rpc<Vec<u8>>) {
        self.node.on_frame(
            peer,
            rpc,
            &mut self.env,
            &mut self.catalog,
            &mut self.rng,
            &mut self.store,
        );
    }

    fn heartbeat(&mut self) {
        self.node.on_timer(
            TimerEvent::Heartbeat,
            &mut self.env,
            &mut self.catalog,
            &mut self.rng,
            &mut self.store,
        );
    }

    /// Everything the writer to `peer` sends until its queue is empty.
    fn drain(&mut self, peer: PeerId) -> Vec<seacast_core::QueueEntry<Vec<u8>>> {
        let mut sent = Vec::new();
        while let DispatchOutcome::Send(entry) =
            self.node.next_to_send(peer, &mut self.env, &self.catalog)
        {
            sent.push(entry);
        }
        sent
    }
}

fn chunk_rpc(chunk: Chunk) -> Rpc<Vec<u8>> {
    Rpc { chunk: Some(chunk), ..Rpc::default() }
}

/// More grafts, offers, holdings, asks and chunks than any table has room for,
/// from one linked peer: nothing panics, and what the peer made the node keep
/// stays within the per-peer limits.
#[test]
fn a_peer_cannot_overflow_the_tables() {
    let mut world = World::new(Catalog::new(400, 400), 1, InterestKind::Declared);
    let limit = world.node.config.max_pending_groups;
    let per_link = world.catalog.params.max_relations;

    // Grafts in both directions for every family, and for colours the type does not
    // have.
    for family in 0..6000u16 {
        let mut rpc = Rpc::default();
        for colour in [0u16, 1, 7] {
            let _ = rpc.grafts.push(Graft {
                object_type: TYPE,
                family,
                colour,
                direction: Direction::Both,
                answer: false,
            });
        }
        world.rpc(1, rpc);
    }
    assert!(world.node.push_in.len() <= per_link && world.node.push_out.len() <= per_link);
    assert!(world.node.push_in.iter().all(|(_, _, _, colour)| colour == 0));

    // Offers, holdings and asks of every index for thousands of groups nobody has a
    // header for.
    let every = Bitmap::all_bits(400);
    for tag in 0..3000 {
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::offer(group(tag), every));
        let _ = rpc.haves.push(Have::holding(group(tag + 10_000), every, true, true));
        let _ = rpc.wants.push(Want::standing(group(tag + 20_000), every));
        // An offer of nothing, and one of indices this node does not want, keep
        // nothing.
        let _ = rpc.haves.push(Have::offer(group(tag + 30_000), Bitmap::new()));
        world.rpc(1, rpc);
        world.drain(1);
    }
    let named = |groups: Vec<GroupId>| {
        let mut distinct = groups;
        distinct.sort_unstable();
        distinct.dedup();
        distinct.len()
    };
    // Up to `limit` unknown groups from HAVEs/offers and `limit` from WANTs
    // (`seacast.md` §4.5 `admitted_group`).
    assert!(named(world.node.pairs.keys().map(|&(_, g)| g).collect()) <= 2 * limit);
    assert!(world.node.groups.len() <= 2 * limit);
    // Holders are counted for groups the node has open, and it has opened none.
    assert_eq!(world.node.holders.len(), 0);

    // Junk chunks: every one rejected at level 1, each with an id of its own.
    for tag in 0..10_000u32 {
        world.rpc(1, chunk_rpc(chunk(group(40_000 + tag), 400, [0; 32])));
    }
    // Chunks of more groups than the node tracks.
    for tag in 0..600u32 {
        world.rpc(1, chunk_rpc(chunk(group(60_000 + tag), 0, [0; 32])));
        world.drain(1);
    }
    assert!(world.node.groups.open_count() <= world.node.config.capacities.max_groups);
    assert_eq!(world.node.chunks.len(), world.node.groups.open_count());
}

/// A group's state goes `GROUP_TTL` after its last chunk, leaving a tombstone
/// that keeps the group from being taken up again, and the tombstone goes in
/// its turn.
#[test]
fn a_group_expires_and_leaves_a_tombstone() {
    let mut world = World::new(Catalog::new(8, 8), 2, InterestKind::All);
    let g = group(1);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(g, Bitmap::all_bits(8)));
    let _ = rpc.haves.push(Have::holding(g, Bitmap::singleton(3), false, false));
    world.rpc(2, rpc);
    assert_eq!(world.node.group_state(&g), Some(GroupState::Collecting));
    assert!(!world.node.offers.is_empty() && !world.node.seen_ids.is_empty());

    // Short of the lifetime: still there.
    world.env.now += world.node.config.group_ttl - 1.0;
    world.heartbeat();
    assert_eq!(world.node.group_state(&g), Some(GroupState::Collecting));

    world.env.now += 2.0;
    world.heartbeat();
    assert!(world.node.expired(&g));
    assert_eq!(world.node.group_state(&g), None);
    let node = &world.node;
    assert!(node.chunks.is_empty() && node.known_id.is_empty() && node.groups.is_empty());
    assert!(node.offers.is_empty() && node.pairs.is_empty() && node.tried.is_empty());
    assert!(node.asked_at.is_empty() && node.promises.is_empty() && node.seen_ids.is_empty());
    assert!(node.holders.is_empty());
    assert!(node.slots.iter().all(|slot| slot.listed_count == 0));

    // Expired for good: a chunk, an offer and a holding of it are ignored.
    world.rpc(1, chunk_rpc(chunk(g, 1, [0; 32])));
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(g, Bitmap::all_bits(8)));
    world.rpc(2, rpc);
    assert!(
        world.node.chunks.is_empty() &&
            world.node.offers.is_empty() &&
            world.node.groups.is_empty()
    );

    world.env.now += world.node.config.tombstone_ttl + 1.0;
    world.heartbeat();
    assert!(!world.node.expired(&g) && world.node.tombstones.is_empty());
}

/// A domain whose window a group has left ends it: the group and the chunks
/// still waiting for it go, and it leaves a tombstone. A chunk waiting for a
/// group nothing ends goes `GROUP_TTL` after it arrived.
#[test]
fn the_domain_ends_a_group_and_its_deferred_chunks() {
    let mut catalog = Catalog::new(8, 8);
    catalog.installed = Some([9; 32]);
    let mut world = World::new(catalog, 1, InterestKind::All);
    let (held, waiting, other) = (group(1), group(2), group(3));
    world.rpc(1, chunk_rpc(chunk(held, 0, [9; 32])));
    world.rpc(1, chunk_rpc(chunk(waiting, 0, [5; 32])));
    world.rpc(1, chunk_rpc(chunk(other, 0, [5; 32])));
    assert_eq!((world.node.pending.len(), world.node.pending_ids.len()), (2, 2));

    for g in [held, waiting] {
        world.node.end_group(g, &mut world.env, &mut world.store);
    }
    assert_eq!(world.node.group_state(&held), None);
    assert_eq!((world.node.pending.len(), world.node.pending_ids.len()), (1, 1));
    assert!(world.node.expired(&held) && world.node.expired(&waiting));

    world.env.now += world.node.config.group_ttl + 1.0;
    world.heartbeat();
    assert!(world.node.pending.is_empty() && world.node.pending_ids.is_empty());
}

/// A group the domain gave a deadline goes at it, sooner than `GROUP_TTL`, with
/// its deferred chunks; one ended before the deadline is kept out until it,
/// longer than `tombstone_ttl`.
#[test]
fn a_deadline_ends_a_group_and_bounds_its_tombstone() {
    let mut catalog = Catalog::new(8, 8);
    catalog.installed = Some([9; 32]);
    let mut world = World::new(catalog, 1, InterestKind::All);
    let ttl = world.node.config.group_ttl;
    assert!(world.node.config.tombstone_ttl <= ttl);
    world.catalog.deadline = Some(world.env.now + 4.0 * ttl);
    let (ended, waiting) = (group(1), group(2));
    world.rpc(1, chunk_rpc(chunk(ended, 0, [9; 32])));
    world.node.end_group(ended, &mut world.env, &mut world.store);
    world.env.now += 2.0 * ttl;
    world.heartbeat();
    assert!(world.node.expired(&ended));

    world.catalog.deadline = Some(world.env.now + 2.0);
    let held = group(3);
    world.rpc(1, chunk_rpc(chunk(held, 0, [9; 32])));
    world.rpc(1, chunk_rpc(chunk(waiting, 0, [5; 32])));
    assert_eq!(world.node.group_state(&held), Some(GroupState::Collecting));
    assert_eq!(world.node.pending.len(), 1);

    world.env.now += 3.0;
    world.heartbeat();
    assert_eq!(world.node.group_state(&held), None);
    assert!(world.node.chunks.is_empty() && world.node.pending.is_empty());
    assert!(world.node.pending_ids.is_empty());
    // Past its deadline a group needs no tombstone: the domain ignores it.
    assert!(!world.node.expired(&held) && world.node.expired(&ended));

    world.env.now += 2.0 * ttl;
    world.heartbeat();
    assert!(world.node.tombstones.is_empty());
}

/// A configuration whose bounds on the asks of one peer refuse none.
fn unbounded_asks() -> NodeConfig {
    let mut config = NodeConfig::default();
    config.max_asks_per_peer = config.capacities.max_asks;
    config.capacities.max_ask_peers = config.capacities.max_asks;
    config
}

/// Every index an offer makes the node ask for leaves in a WANT, however many
/// there are.
#[test]
fn every_ask_of_an_offer_is_sent() {
    let mut world =
        World::with_config(unbounded_asks(), Catalog::new(300, 300), 1, InterestKind::All);
    let mut rpc = Rpc::default();
    for tag in 0..3 {
        let _ = rpc.haves.push(Have::offer(group(tag), Bitmap::all_bits(300)));
    }
    world.rpc(1, rpc);
    let asked: usize = world.node.asked_at.len();
    assert_eq!(asked, 900);
    let mut sent = 0;
    for entry in world.drain(1) {
        for want in entry.wants.iter() {
            assert!(want.track_promise);
            sent += want.bits.popcount() as usize;
        }
    }
    assert_eq!(sent, asked);
    // A promise runs for each of them from the write.
    assert_eq!(world.node.promises.len(), asked);
}

/// Offers owed in more groups than one entry carries all leave, over as many
/// entries as it takes.
#[test]
fn owed_offers_are_never_dropped() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    for tag in 0..50 {
        world.node.owe(1, group(tag), Bitmap::singleton(tag % 8), &mut world.env);
    }
    let mut offered = Vec::new();
    for entry in world.drain(1) {
        offered.extend(entry.haves.iter().filter(|h| h.offer).map(|h| h.group));
    }
    offered.sort_unstable();
    assert_eq!(offered, (0..50).map(group).collect::<Vec<_>>());
    assert!(!world.node.sends.owed.any(1));
}

/// What is owed of groups of one chunk is kept in a ring a peer: past its
/// length the oldest offer goes.
#[test]
fn offers_owed_of_single_chunks_are_bounded() {
    let mut config = NodeConfig::default();
    config.capacities.max_owed_single_per_peer = 4;
    let mut world = World::with_config(config, Catalog::new(1, 1), 2, InterestKind::All);
    for tag in 0..6 {
        world.rpc(1, chunk_rpc(chunk(group(tag), 0, [5; 32])));
    }
    world.drain(2);
    for tag in 0..6 {
        world.node.owe(2, group(tag), Bitmap::singleton(0), &mut world.env);
        world.node.owe(2, group(tag), Bitmap::singleton(0), &mut world.env);
    }
    assert!(!world.node.sends.owed.any(2));
    let queue = world.node.sends.queue.get(2).unwrap();
    assert_eq!(queue.owed_single.len(), 4);
    assert_eq!(queue.owed_single.front(), Some(&group(2)));
    assert!(world.node.sends.has_owed_offers(2));

    world.drain(2);
    assert!(!world.node.sends.has_owed_offers(2));
}

/// A chunk that waited for its block from a peer that then left can still
/// arrive from another.
#[test]
fn a_departed_peer_does_not_block_its_deferred_chunks() {
    let mut catalog = Catalog::new(8, 8);
    catalog.installed = Some([9; 32]);
    let mut world = World::new(catalog, 2, InterestKind::All);
    let g = group(1);
    let waiting = chunk(g, 0, [5; 32]);
    world.rpc(1, chunk_rpc(waiting.clone()));
    assert_eq!(world.node.pending_ids.len(), 1);
    world.node.disconnect_peer(1, &mut world.env, &mut world.store);
    assert!(world.node.pending.is_empty() && world.node.pending_ids.is_empty());

    // The block installs, and the same chunk comes from the other peer.
    world.catalog.installed = None;
    world.rpc(2, chunk_rpc(waiting));
    assert!(world.node.chunks.contains_key(&(g, 0)));
}

/// What a sampler declared before a group opened is still its interest once a
/// chunk opens it, so it completes when its indices have arrived.
#[test]
fn a_sampler_completes_on_its_declared_indices() {
    let mut catalog = Catalog::new(8, 8);
    catalog.interest = Bitmap::new();
    catalog.declared = true;
    let mut world = World::new(catalog, 1, InterestKind::All);
    let g = group(1);
    let mut wanted = Bitmap::new();
    wanted.set(2);
    wanted.set(5);
    world.node.sample(g, wanted, &mut world.env, &world.catalog, &mut world.rng);
    world.rpc(1, chunk_rpc(chunk(g, 2, [0; 32])));
    assert_eq!(world.node.group_state(&g), Some(GroupState::Collecting));
    assert_eq!(world.node.groups.bits(&g, GroupBits::Interest), Some(wanted));
    world.rpc(1, chunk_rpc(chunk(g, 5, [0; 32])));
    assert_eq!(world.node.group_state(&g), Some(GroupState::Complete));
}

/// On a link that has not joined a type this node runs, chunks and holdings
/// are taken (with `claim_all` not making the peer a claimant), while offers
/// and WANTs are ignored without state or answer (`seacast.md` §2, §4.3).
#[test]
fn messages_of_an_unjoined_type_are_ignored() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    world.node.connect_peer(2, false, &mut world.env, &world.catalog);
    let g = group(1);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    world.drain(1);

    let mut rpc = chunk_rpc(chunk(g, 1, [0; 32]));
    let _ = rpc.haves.push(Have::offer(g, Bitmap::all_bits(8)));
    let _ = rpc.haves.push(Have::holding(g, Bitmap::singleton(4), true, false));
    let _ = rpc.wants.push(Want::pull_ask(Ask { group: g, index: 0 }));
    world.rpc(2, rpc);
    // Chunk and holding accepted; claim_all recorded in peer_has but peer 2 is
    // not a claimant; offer and WANT ignored (no chunk 0 answer sent).
    assert!(world.node.chunks.contains_key(&(g, 1)));
    assert!(world.node.pairs.peer_has(&(2, g)).is_some_and(|e| e.has(4) && e.claim_all));
    assert!(!world.node.claims.contains(&g, 2));
    assert!(world.node.pairs.offered(&(2, g)).is_none());
    let sent = world.drain(2);
    assert!(sent.iter().all(|e| e.chunk.is_none()));
}

/// A chunk whose proof is checked off the chunk path is held by the host until
/// its verdict: nothing is stored, claimed or forwarded before, a second copy
/// is not verified again, and the static checks still reject at once.
#[test]
fn a_chunk_waits_for_its_verdict() {
    let mut catalog = Catalog::new(8, 8);
    catalog.deferred_proof = true;
    let mut world = World::new(catalog, 2, InterestKind::All);
    let g = group(1);
    let (good, forged) = (chunk(g, 0, [0; 32]), chunk(g, 1, [0; 32]));

    world.rpc(1, chunk_rpc(good.clone()));
    world.rpc(2, chunk_rpc(good.clone()));
    world.rpc(1, chunk_rpc(forged.clone()));
    // An index outside the group fails the inline check: never handed out.
    world.rpc(1, chunk_rpc(chunk(g, 8, [0; 32])));
    // The group is known to be authentic and nothing more: it is not open.
    assert!(world.node.chunks.is_empty() && world.node.group_state(&g).is_none());
    assert!(world.drain(1).is_empty() && world.drain(2).is_empty());

    let (from, first) = world.node.pop_unverified().expect("the first copy");
    let (_, second) = world.node.pop_unverified().expect("the other chunk");
    assert_eq!((from.peer_id(), first.index, second.index), (1, 0, 1));
    assert!(world.node.pop_unverified().is_none());

    let (env, catalog, rng, store) =
        (&mut world.env, &mut world.catalog, &mut world.rng, &mut world.store);
    world.node.on_validated(from, first, ValidationResult::Accept, env, catalog, rng, store);
    world.node.on_validated(from, second, ValidationResult::Reject, env, catalog, rng, store);
    assert!(world.node.chunks.contains_key(&(g, 0)) && !world.node.chunks.contains_key(&(g, 1)));
    assert!(world.node.verifying.is_empty());
    // The accepted chunk is claimed to its sender; the rejected one is seen, so
    // another copy of it is not verified again.
    assert!(
        world.drain(1).iter().any(|entry| entry.haves.iter().any(|h| !h.offer && h.bits.has(0)))
    );
    world.rpc(2, chunk_rpc(forged));
    assert!(world.node.pop_unverified().is_none());
}

/// Groups that peers only name have their own room: however many there are, a
/// group whose chunk arrives can still be opened.
#[test]
fn named_groups_do_not_crowd_out_open_ones() {
    let mut world = World::new(Catalog::new(8, 8), 6, InterestKind::All);
    let max_groups = world.node.config.capacities.max_groups;
    for peer in 1..=6u64 {
        for tag in 0..64 {
            let mut rpc = Rpc::default();
            let _ =
                rpc.haves.push(Have::offer(group(peer as u32 * 1000 + tag), Bitmap::all_bits(8)));
            world.rpc(peer, rpc);
        }
    }
    assert_eq!((world.node.groups.len(), world.node.groups.open_count()), (max_groups, 0));
    for tag in 0..10 {
        world.rpc(1, chunk_rpc(chunk(group(900_000 + tag), 0, [0; 32])));
    }
    assert_eq!(world.node.groups.open_count(), 10);
    assert_eq!(world.node.chunks.len(), 10);
}

/// A chunk of a group the domain does not take yet is ignored, and taken once
/// it does.
#[test]
fn a_chunk_the_domain_ignores_leaves_nothing() {
    let mut catalog = Catalog::new(8, 8);
    catalog.too_early = true;
    let mut world = World::new(catalog, 1, InterestKind::All);
    world.rpc(1, chunk_rpc(chunk(group(1), 0, [0; 32])));
    assert!(world.node.chunks.is_empty() && world.node.seen_ids.is_empty());
    assert_eq!(world.env.penalties, 0);
    world.catalog.too_early = false;
    world.rpc(1, chunk_rpc(chunk(group(1), 0, [0; 32])));
    assert_eq!(world.node.chunks.len(), 1);
}

/// Cells that arrive before their header wait for it, not for the block: when
/// the header is validated they are taken up, and those of another group of the
/// root keep waiting.
#[test]
fn a_validated_header_resumes_its_deferred_chunks() {
    let (cell, other) = (group(1), group(2));
    let mut catalog = Catalog::new(8, 8);
    catalog.installed = Some([9; 32]);
    catalog.cells = vec![cell];
    let mut world = World::new(catalog, 1, InterestKind::All);
    world.rpc(1, chunk_rpc(chunk(cell, 0, [5; 32])));
    world.rpc(1, chunk_rpc(chunk(other, 0, [5; 32])));
    assert_eq!((world.node.pending.len(), world.node.chunks.len()), (2, 0));

    world.catalog.header_validated = true;
    let (env, catalog, rng, store) =
        (&mut world.env, &mut world.catalog, &mut world.rng, &mut world.store);
    world.node.on_groups_authenticated(&[cell], env, catalog, rng, store);
    assert!(world.node.chunks.contains_key(&(cell, 0)));
    assert_eq!((world.node.pending.len(), world.node.pending_ids.len()), (1, 1));
    assert!(!world.node.tied_to_root(1, Ask { group: cell, index: 0 }));
    assert!(world.node.tied_to_root(1, Ask { group: other, index: 0 }));
}

/// A chunk's head settles a duplicate before its body is read: a copy of a
/// chunk held is answered with a holding, one of a chunk that waits ties its
/// sender, and a chunk not yet seen is read.
#[test]
fn a_duplicate_is_settled_by_its_head() {
    let (held, waiting) = (group(1), group(2));
    let mut world = World::new(Catalog::new(8, 8), 2, InterestKind::All);
    world.rpc(1, chunk_rpc(chunk(held, 0, [5; 32])));
    world.drain(2);

    let head = |world: &mut World, peer, g: &GroupId, index, id: Option<&ChunkId>| {
        world.node.on_chunk_head(peer, g, index, id, &mut world.env, &world.catalog)
    };
    assert!(!head(&mut world, 2, &held, 0, None));
    let sent = world.drain(2);
    assert!(sent.iter().any(|e| e.haves.iter().any(|h| !h.offer && h.group == held)));
    assert!(head(&mut world, 2, &held, 1, None));
    let other = GroupId { type_id: TypeId(TYPE.0 + 1), ..held };
    assert!(!head(&mut world, 2, &other, 1, None));

    world.catalog.installed = Some([9; 32]);
    let deferred = chunk(waiting, 0, [5; 32]);
    world.rpc(1, chunk_rpc(deferred.clone()));
    assert_eq!(world.node.pending_ids.len(), 1);
    assert!(!head(&mut world, 1, &waiting, 0, None));
    assert!(head(&mut world, 2, &waiting, 0, None));
    assert!(!head(&mut world, 2, &waiting, 0, Some(&deferred.cached_id)));
    assert!(world.node.tied_to_root(2, Ask { group: waiting, index: 0 }));
}

/// A JOIN for a type this node does not run asks nothing of the catalog and
/// leaves no state.
#[test]
fn a_join_of_an_unknown_type_is_ignored() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    let joined = world.node.slots.get(1).expect("connected").join_recv.len();
    for t in 1..=u8::MAX {
        let mut rpc = Rpc::default();
        let _ = rpc.joins.push(Join { object_type: TypeId(t), ..peer_join(InterestKind::All) });
        world.rpc(1, rpc);
    }
    assert_eq!(world.node.slots.get(1).expect("connected").join_recv.len(), joined);
    assert!(world.drain(1).is_empty());
}

/// Past the IHAVE limits an offer arms no timer and makes no ask; the next
/// heartbeat takes it up.
#[test]
fn offers_over_the_limits_arm_no_timer() {
    let mut world =
        World::with_config(unbounded_asks(), Catalog::new(1024, 1024), 1, InterestKind::All);
    let offer = |world: &mut World, tag: u32| {
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::offer(group(tag), Bitmap::all_bits(1024)));
        world.rpc(1, rpc);
    };
    let mut tag = 0;
    while !world.node.over_ihave_limits(1) {
        offer(&mut world, tag);
        tag += 1;
    }
    let (retries, asked) = (world.env.retries, world.node.asked_at.len());
    assert_eq!(retries, asked);
    for _ in 0..4 {
        offer(&mut world, tag);
        tag += 1;
    }
    // The same offers again cost nothing either.
    for again in 0..tag {
        offer(&mut world, again);
    }
    assert_eq!((world.env.retries, world.node.asked_at.len()), (retries, asked));

    world.drain(1);
    world.env.now += 0.7;
    world.heartbeat();
    let asks = world.drain(1).iter().flat_map(|entry| entry.wants.iter()).count();
    assert!(asks > 0);
}

/// An ask the table has no room for is not made, so its timer is not armed
/// either.
#[test]
fn an_unrecorded_ask_is_not_made() {
    let mut config = NodeConfig::default();
    config.capacities.max_asks = 16;
    let mut world = World::with_config(config, Catalog::new(300, 300), 1, InterestKind::All);
    for round in 0..8 {
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::offer(group(1), Bitmap::all_bits(300)));
        world.rpc(1, rpc);
        assert_eq!(world.node.asked_at.len(), 16);
        assert!(world.env.retries <= 16 * (round + 1));
        world.env.now += 1.0;
    }
}

/// One peer is asked for no more chunks at once than its bound. What is left
/// goes to another announcer, or waits for the heartbeat.
#[test]
fn the_asks_of_one_peer_are_bounded() {
    let per_peer = 128;
    let config = NodeConfig { max_asks_per_peer: per_peer, ..NodeConfig::default() };
    let mut world = World::with_config(config, Catalog::new(300, 300), 2, InterestKind::All);
    let offer = |world: &mut World, peer: PeerId| {
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::offer(group(1), Bitmap::all_bits(300)));
        world.rpc(peer, rpc);
    };
    offer(&mut world, 1);
    assert_eq!(world.node.tried.count_of(1), per_peer);
    assert_eq!(world.node.asked_at.len(), per_peer);
    let sent: usize = world
        .drain(1)
        .iter()
        .flat_map(|e| e.wants.iter())
        .map(|w| w.bits.popcount() as usize)
        .sum();
    assert_eq!(sent, per_peer);
    assert_eq!(world.node.promises.count_of(1), per_peer);

    // The heartbeat takes the group up again and finds the peer still full.
    world.env.now += 0.7;
    world.heartbeat();
    assert_eq!(world.node.tried.count_of(1), per_peer);

    world.env.now += 0.7;
    offer(&mut world, 2);
    assert_eq!(world.node.tried.count_of(2), per_peer);
    assert_eq!(world.node.tried.len(), 2 * per_peer);

    world.node.disconnect_peer(1, &mut world.env, &mut world.store);
    assert_eq!(world.node.tried.count_of(1), 0);
    assert_eq!(world.node.promises.count_of(1), 0);
    assert_eq!(world.node.tried.len(), per_peer);
}

/// The records of every peer together stay within the table.
#[test]
fn the_ask_records_of_the_node_are_bounded() {
    let mut config = NodeConfig::default();
    config.capacities.max_ask_peers = 16;
    let mut world = World::with_config(config, Catalog::new(300, 300), 2, InterestKind::All);
    for peer in 1..=2 {
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::offer(group(peer as u32), Bitmap::all_bits(300)));
        world.rpc(peer, rpc);
    }
    assert_eq!(world.node.tried.len(), 16);
    assert_eq!(world.node.asked_at.len(), 16);
    assert_eq!(world.env.retries, 16);
}

/// An offer naming an index past the group's count is refused whole and counts
/// against its sender.
#[test]
fn an_offer_past_the_index_count_is_refused() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    let g = group(1);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    let penalties = world.env.penalties;
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(g, Bitmap::all_bits(300)));
    world.rpc(1, rpc);
    assert_eq!(world.env.penalties, penalties + 1);
    assert!(world.node.asked_at.is_empty() && world.node.pairs.is_empty());
    assert_eq!(world.env.retries, 0);
}

/// An index `project` returns that no bitmap can name is dropped, not indexed
/// with.
#[test]
fn a_projected_index_past_the_bitmap_is_dropped() {
    let mut catalog = Catalog::new(8, 8);
    catalog.stray_index = Some(5000);
    let mut world = World::new(catalog, 2, InterestKind::All);
    let g = group(1);
    for index in 0..8 {
        world.rpc(1, chunk_rpc(chunk(g, index, [0; 32])));
    }
    assert_eq!(world.node.group_state(&g), Some(GroupState::Decoding));
    assert!(!world.node.chunks.contains_key(&(g, 5000)));
}

/// Once a group's gate is open, an ask outside what this node serves is
/// ignored without penalty and leaves no standing request (`seacast.md` §4.5).
#[test]
fn an_ask_outside_offer_and_interest_is_refused() {
    let mut catalog = Catalog::new(8, 8);
    catalog.derived = true;
    catalog.interest = Bitmap::all_bits(4);
    let mut world = World::new(catalog, 1, InterestKind::Declared);
    let g = group(1);
    let ask = |world: &mut World, index: u32| {
        let mut rpc = Rpc::default();
        let _ = rpc.wants.push(Want::pull_ask(Ask { group: g, index }));
        world.rpc(1, rpc);
    };
    ask(&mut world, 2);
    assert_eq!(world.env.penalties, 0);
    assert!(world.node.standing.contains_key(&(g, 2)));
    ask(&mut world, 6);
    assert_eq!(world.env.penalties, 0);
    assert!(!world.node.standing.contains_key(&(g, 6)));
}

/// A holding that repeats a bit frees the room of a copy written to its sender
/// since (`seacast.md` §4.3, card 14).
#[test]
fn a_repeated_holding_bit_frees_the_room() {
    let mut world = World::new(Catalog::new(8, 4), 1, InterestKind::All);
    let g = group(1);
    let holding = |world: &mut World| {
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::holding(g, Bitmap::singleton(0), false, false));
        world.rpc(1, rpc);
    };
    holding(&mut world);
    // A copy written since, as a probe's answer is, exempt from cancel.
    let before = world.node.sends.in_flight;
    world.node.sends.sent.insert((1, g, 0), (world.env.now.to_bits(), 100));
    world.node.sends.in_flight += 100;
    holding(&mut world);
    assert!(!world.node.sends.sent.contains_key(&(1, g, 0)));
    assert_eq!(world.node.sends.in_flight, before);
}

/// A place for an unknown group named in WANTs lasts `GROUP_TTL` from its
/// first naming, however often it is named again, and takes the asker's
/// standing requests with it when it ends; every place ends, however many end
/// at one heartbeat (`seacast.md` §4.5).
#[test]
fn a_want_place_ends_at_its_lifetime() {
    let peers = 5u64;
    let mut world = World::new(Catalog::new(8, 4), peers, InterestKind::All);
    let places = world.node.config.max_pending_groups as u32;
    let ask = |world: &mut World, from: u32| {
        for peer in 1..=peers {
            for tag in from..from + places {
                let mut rpc = Rpc::default();
                let _ = rpc.wants.push(Want::standing(group(tag), Bitmap::singleton(2)));
                world.rpc(peer, rpc);
            }
        }
    };
    ask(&mut world, 0);
    assert_eq!(world.node.standing.len(), places as usize);
    assert_eq!(world.node.standing.count(&(group(0), 2)), peers as usize);
    // Named again before the lifetime ends: the places are not renewed.
    world.env.now += world.node.config.group_ttl / 2.0;
    ask(&mut world, 0);
    world.env.now = 1.0 + world.node.config.group_ttl + 0.5;
    world.heartbeat();
    assert!(world.node.standing.is_empty());
    // The places are free again.
    ask(&mut world, 1000);
    assert_eq!(world.node.standing.len(), places as usize);
}

/// A backoff that has run out holds no place under `MAX_RELATIONS`, before
/// the heartbeat drops it (`seacast.md` §4.1 `relation_room`).
#[test]
fn a_backoff_run_out_holds_no_relation_place() {
    let mut catalog = Catalog::new(8, 4);
    catalog.params.max_relations = 1;
    let mut world = World::new(catalog, 1, InterestKind::All);
    let graft = |world: &mut World, family: u16| {
        let mut rpc = Rpc::default();
        let _ = rpc.grafts.push(Graft {
            object_type: TYPE,
            family,
            colour: 0,
            direction: Direction::Both,
            answer: false,
        });
        world.rpc(1, rpc);
        world.drain(1);
    };
    graft(&mut world, 0);
    assert!(world.node.push_in.contains(&(1, TYPE, 0, 0)));
    let mut rpc = Rpc::default();
    let _ = rpc.prunes.push(Prune {
        object_type: TYPE,
        family: 0,
        colour: 0,
        direction: Direction::Both,
    });
    world.rpc(1, rpc);
    // The backoff holds the link's one place.
    graft(&mut world, 1);
    assert!(!world.node.push_in.contains(&(1, TYPE, 1, 0)));
    world.env.now += world.catalog.params.prune_backoff + 1.0;
    graft(&mut world, 1);
    assert!(world.node.push_in.contains(&(1, TYPE, 1, 0)));
}

/// A GRAFT counts for nothing until it is answered: the relation is entered at
/// the peer's yes, a peer's own GRAFT is answered yes, a PRUNE ends the
/// relation and holds the next GRAFT back for the backoff, and none of these is
/// lost to a full queue (`seacast.md` §4.1).
#[test]
fn a_graft_is_answered_and_a_prune_backs_off() {
    let grafts = |world: &mut World| -> Vec<Graft> {
        world.drain(1).iter().flat_map(|e| e.grafts.iter().copied()).collect()
    };
    let relation = (1, TYPE, 0, 0);
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    world.heartbeat();
    let ours = grafts(&mut world);
    assert!(ours.iter().any(|g| g.direction == Direction::In && !g.answer));
    assert!(ours.iter().any(|g| g.direction == Direction::Out && !g.answer));
    assert!(!world.node.push_in.contains(&relation) && !world.node.push_out.contains(&relation));
    // Unanswered, the peer is not grafted again.
    world.heartbeat();
    assert!(grafts(&mut world).is_empty());

    // The yes to our "push me" is the peer's "I will push you": entered, not
    // answered.
    let graft = |direction, answer| {
        let mut rpc = Rpc::default();
        let _ =
            rpc.grafts.push(Graft { object_type: TYPE, family: 0, colour: 0, direction, answer });
        rpc
    };
    world.rpc(1, graft(Direction::Out, true));
    assert!(world.node.push_in.contains(&relation));
    assert!(grafts(&mut world).is_empty());
    // A GRAFT of the peer's own for a relation held is answered yes again, a yes is
    // not.
    world.rpc(1, graft(Direction::Out, false));
    let again = grafts(&mut world);
    assert!(again.len() == 1 && again[0].direction == Direction::In && again[0].answer);
    world.rpc(1, graft(Direction::Out, true));
    assert!(grafts(&mut world).is_empty());
    // The peer's "push me" crosses our unanswered "I will push you": that is the
    // yes.
    world.rpc(1, graft(Direction::In, false));
    assert!(world.node.push_out.contains(&relation));
    assert!(grafts(&mut world).is_empty());

    // The peer's PRUNE ends the relation, and it is not grafted again at once.
    let mut rpc = Rpc::default();
    let _ = rpc.prunes.push(seacast_core::Prune {
        object_type: TYPE,
        family: 0,
        colour: 0,
        direction: Direction::Out,
    });
    world.rpc(1, rpc);
    assert!(!world.node.push_in.contains(&relation));
    world.heartbeat();
    assert!(grafts(&mut world).iter().all(|g| g.direction != Direction::In));
    world.env.now += 13.0;
    world.heartbeat();
    assert!(grafts(&mut world).iter().any(|g| g.direction == Direction::In));

    // A full queue owes the answers, in the order they were made.
    let mut config = NodeConfig::default();
    config.capacities.max_queue_entries_per_peer = 2;
    let mut world = World::with_config(config, Catalog::new(8, 8), 1, InterestKind::All);
    for tag in 1..=3 {
        world.rpc(1, chunk_rpc(chunk(group(tag), 0, [0; 32])));
    }
    assert!(!world.node.sends.queue.get(1).expect("connected").has_room());
    world.rpc(1, graft(Direction::Out, false));
    world.rpc(1, graft(Direction::In, false));
    let sent = grafts(&mut world);
    let directions: Vec<Direction> = sent.iter().map(|g| g.direction).collect();
    assert_eq!(directions, [Direction::In, Direction::Out]);
    assert!(sent.iter().all(|g| g.answer));
}

/// A source with no relation peer pushes to its links, and offers a chunk to
/// the links it did not push it to when a copy is known to have arrived: at a
/// holding that names it, or at its window's timeout, and once
/// (`seacast.md` §4.7 `source_pool`, `origin_acked`).
#[test]
fn a_source_offers_at_the_acknowledgement() {
    let offers = |world: &mut World, peer: PeerId| -> usize {
        world.drain(peer).iter().flat_map(|e| e.haves.iter()).filter(|h| h.offer).count()
    };
    for by_timeout in [false, true] {
        let mut world = World::new(Catalog::new(2, 2), 4, InterestKind::All);
        let g = group(1);
        let shards = [chunk(g, 0, [0; 32]), chunk(g, 1, [0; 32])];
        let (env, catalog, rng) = (&mut world.env, &world.catalog, &mut world.rng);
        world.node.publish(g, Shape { n: 2, k: 2 }, &shards, env, catalog, rng);
        // Each chunk goes to its budget of links, and nobody is offered anything.
        let mut pushed = [0usize; 2];
        let mut unpushed = Vec::new();
        for peer in 1..=4 {
            let sent = world.drain(peer);
            assert!(sent.iter().all(|e| e.haves.iter().all(|h| !h.offer)));
            let got: Vec<u32> =
                sent.iter().filter_map(|e| e.chunk.as_ref()).map(|f| f.index).collect();
            for &i in &got {
                pushed[i as usize] += 1;
            }
            if !got.contains(&0) {
                unpushed.push(peer);
            }
        }
        assert_eq!(pushed, [2, 2]);
        assert_eq!(unpushed.len(), 2);
        // Chunk 0 is acknowledged: the links not pushed it are offered it, once.
        // A timeout acknowledges only while the copy's room is held.
        let holder = (1..=4).find(|peer| !unpushed.contains(peer)).expect("a target");
        let ack = |world: &mut World| {
            if by_timeout {
                let at_bits = world.env.now().to_bits();
                let event = TimerEvent::WindowTimeout { peer: holder, group: g, index: 0, at_bits };
                let (env, catalog, rng, store) =
                    (&mut world.env, &mut world.catalog, &mut world.rng, &mut world.store);
                world.node.on_timer(event, env, catalog, rng, store);
            } else {
                let mut rpc = Rpc::default();
                let _ = rpc.haves.push(Have::holding(g, Bitmap::singleton(0), false, false));
                world.rpc(holder, rpc);
            }
        };
        // A timeout of a copy whose room is not held acknowledges nothing.
        let at_bits = world.env.now().to_bits();
        let stale = TimerEvent::WindowTimeout { peer: unpushed[0], group: g, index: 0, at_bits };
        let (env, catalog, rng, store) =
            (&mut world.env, &mut world.catalog, &mut world.rng, &mut world.store);
        world.node.on_timer(stale, env, catalog, rng, store);
        for peer in 1..=4 {
            assert_eq!(offers(&mut world, peer), 0);
        }
        ack(&mut world);
        for &peer in &unpushed {
            assert_eq!(offers(&mut world, peer), 1, "by timeout: {by_timeout}");
        }
        ack(&mut world);
        for peer in 1..=4 {
            assert_eq!(offers(&mut world, peer), 0);
        }
    }
}

/// A claimant answers the probe of its claim whatever the asker holds, once for
/// the group: the answer is written though the asker holds the chunk, and a
/// second marked ask is an ask for a claimed chunk (`seacast.md` §4.6, R5).
#[test]
fn a_probe_of_a_claim_is_answered_once() {
    let mut world = World::new(Catalog::new(8, 8), 2, InterestKind::All);
    let g = group(1);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    world.drain(2);
    // The asker holds the chunk, and probes it.
    let mut held = Rpc::default();
    let _ = held.haves.push(Have::holding(g, Bitmap::singleton(0), false, false));
    world.rpc(2, held);
    let probe = |world: &mut World| {
        let mut rpc = Rpc::default();
        let _ = rpc.wants.push(Want::probe(g, Bitmap::singleton(0)));
        world.rpc(2, rpc);
        world.drain(2).iter().filter(|entry| entry.chunk.is_some()).count()
    };
    assert_eq!((probe(&mut world), world.env.penalties), (1, 0));
    assert!(world.node.probe_answers.is_empty());
    assert_eq!((probe(&mut world), world.env.penalties), (0, 1));
    // An unmarked ask of a chunk the asker holds was never answered.
    let mut world = World::new(Catalog::new(8, 8), 2, InterestKind::All);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    world.drain(2);
    let mut held = Rpc::default();
    let _ = held.haves.push(Have::holding(g, Bitmap::singleton(0), false, false));
    world.rpc(2, held);
    let mut rpc = Rpc::default();
    let _ = rpc.wants.push(Want::direct(g, Bitmap::singleton(0)));
    world.rpc(2, rpc);
    assert_eq!(world.env.penalties, 1);
    assert!(world.drain(2).iter().all(|entry| entry.chunk.is_none()));
}

/// However many chunks a peer asks for, it is served a bounded number of them a
/// heartbeat.
#[test]
fn asks_are_served_within_the_heartbeat_budget() {
    let config = NodeConfig { max_served_per_heartbeat: 4, ..Default::default() };
    let mut world = World::with_config(config, Catalog::new(16, 16), 2, InterestKind::All);
    let g = group(1);
    for index in 0..8 {
        world.rpc(1, chunk_rpc(chunk(g, index, [0; 32])));
    }
    world.drain(2);
    let served = |world: &mut World| {
        let mut rpc = Rpc::default();
        let _ = rpc.wants.push(Want::standing(g, Bitmap::all_bits(8)));
        world.rpc(2, rpc);
        let sent = world.drain(2);
        sent.iter().filter(|entry| entry.chunk.is_some()).count()
    };
    assert_eq!(served(&mut world), 4);
    assert_eq!(served(&mut world), 0);
    world.heartbeat();
    world.drain(2);
    assert_eq!(served(&mut world), 4);
}

/// A pair keeps indices past its narrow bitmaps in a pool block; with the pool
/// empty they are not kept, and a pair that goes gives its block back.
#[test]
fn a_pair_keeps_wide_bitmaps_while_the_pool_has_room() {
    let mut pairs = seacast_core::Pairs::with_capacity(4, 1, 4, 64);
    let (first, second) = ((1, group(1)), (2, group(1)));
    let wide = Bitmap::from_indices([3, 127, 128, 1000]);
    pairs.set_offered(first, Bitmap::singleton(5));
    pairs.set_want_p(first, wide);
    assert_eq!(pairs.offered(&first), Some(Bitmap::singleton(5)));
    assert_eq!(pairs.want_p(&first), Some(wide));
    assert_eq!(pairs.sent_to(&first), None);

    pairs.set_offered(second, wide);
    assert_eq!(pairs.offered(&second), Some(Bitmap::from_indices([3, 127])));
    pairs.retain(|key| *key != first);
    pairs.set_offered(second, wide);
    assert_eq!(pairs.offered(&second), Some(wide));

    // A complemented bitmap keeps its meaning.
    let mut all_but = Bitmap::EVERY_INDEX;
    all_but.clear(7);
    pairs.set_sent_to(second, all_but);
    assert_eq!(pairs.sent_to(&second), Some(all_but));
}

/// A chunk that waits in a peer's queue is not written once the peer says it
/// holds it (`seacast-lite.md` §7.2 `filter_entry`).
#[test]
fn a_queued_chunk_is_not_written_to_a_peer_that_holds_it() {
    let mut world = World::new(Catalog::new(8, 8), 2, InterestKind::All);
    let g = group(1);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    let mut rpc = Rpc::default();
    let _ = rpc.wants.push(Want::pull_ask(Ask { group: g, index: 0 }));
    world.rpc(2, rpc);
    let queued = |world: &World| {
        world.node.sends.queue.get(2).is_some_and(|q| q.normal.iter().any(|item| item.is_chunk()))
    };
    assert!(queued(&world));

    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::holding(g, Bitmap::singleton(0), false, false));
    world.rpc(2, rpc);
    assert!(world.drain(2).iter().all(|entry| entry.chunk.is_none()));
    assert!(!queued(&world));
}

/// A group names its type: a holding, offer or ask of a group of a type not
/// joined on the link is ignored.
#[test]
fn a_group_of_a_type_not_joined_is_ignored() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    let other = GroupId { type_id: TypeId(9), ..group(1) };

    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(other, Bitmap::all_bits(8)));
    world.rpc(1, rpc);
    assert!(world.node.groups.get(&other).is_none() && world.node.asked_at.is_empty());

    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(group(1), Bitmap::all_bits(8)));
    world.rpc(1, rpc);
    assert_eq!(world.node.asked_at.len(), 8);
}

/// A symmetric type keeps one relation both ways: grafted and answered as one,
/// ended both ways by a PRUNE, made whole where it is held one way, and pruned
/// at the cap (`seacast.md` §4.1).
#[test]
fn a_symmetric_relation_is_one_both_ways() {
    let grafts = |world: &mut World, peer| -> Vec<Graft> {
        world.drain(peer).iter().flat_map(|e| e.grafts.iter().copied()).collect()
    };
    let graft = |answer| {
        let mut rpc = Rpc::default();
        let direction = Direction::Both;
        let _ =
            rpc.grafts.push(Graft { object_type: TYPE, family: 0, colour: 0, direction, answer });
        rpc
    };
    let relation = (1, TYPE, 0, 0);
    let mut catalog = Catalog::new(8, 8);
    catalog.params.symmetric = true;
    let mut world = World::new(catalog, 2, InterestKind::All);
    world.heartbeat();
    let ours = grafts(&mut world, 1);
    assert!(ours.len() == 1 && ours[0].direction == Direction::Both && !ours[0].answer);
    assert!(!world.node.push_in.contains(&relation) && !world.node.push_out.contains(&relation));

    // The yes enters both directions and is not answered.
    world.rpc(1, graft(true));
    assert!(world.node.push_in.contains(&relation) && world.node.push_out.contains(&relation));
    assert!(grafts(&mut world, 1).is_empty());

    // A PRUNE naming one direction ends both.
    let mut rpc = Rpc::default();
    let direction = Direction::Out;
    let _ =
        rpc.prunes.push(seacast_core::Prune { object_type: TYPE, family: 0, colour: 0, direction });
    world.rpc(1, rpc);
    assert!(!world.node.push_in.contains(&relation) && !world.node.push_out.contains(&relation));

    // The peer's own GRAFT is decided as one and answered with one.
    world.rpc(1, graft(false));
    assert!(world.node.push_in.contains(&relation) && world.node.push_out.contains(&relation));
    let yes = grafts(&mut world, 1);
    assert!(yes.len() == 1 && yes[0].direction == Direction::Both && yes[0].answer);

    // Held one way only, it is grafted again whatever the count.
    world.rpc(2, graft(true));
    world.drain(2);
    world.node.push_out.remove(&relation);
    world.heartbeat();
    let again = grafts(&mut world, 1);
    assert!(again.len() == 1 && again[0].direction == Direction::Both && !again[0].answer);
    world.rpc(1, graft(true));
    assert!(world.node.push_out.contains(&relation));

    // At the cap the relation is pruned down to the target.
    world.catalog.params.f_lo = 1;
    world.catalog.params.f_hi = 2;
    world.catalog.params.d_out = 1;
    world.heartbeat();
    assert_eq!((world.node.push_in.len(), world.node.push_out.len()), (1, 1));
    let pruned: usize =
        (1..=2).map(|p| world.drain(p).iter().map(|e| e.prunes.len()).sum::<usize>()).sum();
    assert_eq!(pruned, 1);
}

/// A relation is grafted only on a link whose peer's interest holds the family,
/// and the links a floor is short of are reported, a peer of high custody
/// counting for `COVER_HIGH` families of a floor that asks for diversity
/// (`seacast.md` §1.3, §4.1 `candidates`, `keep_floor`, `keep_coverage`).
#[test]
fn links_count_where_interest_holds_the_family() {
    let mut catalog = Catalog::new(8, 8);
    catalog.covering = Some(vec![1, 2]);
    let mut world = World::new(catalog, 3, InterestKind::Derived);
    world.heartbeat();
    assert!(world.drain(1).iter().any(|e| !e.grafts.is_empty()));
    assert!(world.drain(2).iter().any(|e| !e.grafts.is_empty()));
    assert!(world.drain(3).iter().all(|e| e.grafts.is_empty()));

    let deficits = |world: &World| {
        let mut short = Vec::new();
        world.node.link_deficits(TYPE, &world.catalog, |family, links| short.push((family, links)));
        short
    };
    // The relation floor: `F_LO` links, two held.
    let f_lo = world.catalog.params.f_lo;
    assert_eq!(deficits(&world), vec![(0, f_lo - 2)]);
    world.catalog.params.f_lo = 2;
    assert!(deficits(&world).is_empty());

    // A floor of the policy's: every covering link counts.
    world.catalog.floors = vec![LinkFloor { family: 4, links: 3, diverse: false }];
    assert_eq!(deficits(&world), vec![(4, 1)]);

    // A peer with interest `ALL` is of high custody: it counts for one family of a
    // floor that asks for diversity, and for every family of one that does not.
    let mut rpc = Rpc::default();
    let _ = rpc.joins.push(peer_join(InterestKind::All));
    world.rpc(3, rpc);
    let floor = |family, diverse| LinkFloor { family, links: 3, diverse };
    world.catalog.floors = vec![floor(4, true), floor(5, true)];
    assert_eq!(deficits(&world), vec![(5, 1)]);
    world.catalog.floors = vec![floor(4, false), floor(5, false)];
    assert!(deficits(&world).is_empty());
}

/// A sampler asks one peer for each sample and no peer for two: a link of
/// ordinary custody first, a routed request where none is left, a peer of high
/// custody only after the first wait. Its later asks are bounded in flight, and
/// nothing of them is left behind (`seacast.md` §4.10).
#[test]
fn a_sampler_asks_one_peer_for_each_sample() {
    let wants = |world: &mut World, peer| -> Vec<Want> {
        world.drain(peer).iter().flat_map(|e| e.wants.iter().copied()).collect()
    };
    let mut catalog = Catalog::new(8, 8);
    catalog.interest = Bitmap::new();
    catalog.declared = true;
    let config = NodeConfig { sample_outstanding: 1, ..Default::default() };
    let mut world = World::with_config(config, catalog, 4, InterestKind::Derived);
    // Peer 3 has no interest of its own and forwards; peer 4 is of high custody.
    for (peer, interest) in [(3, InterestKind::Declared), (4, InterestKind::All)] {
        let mut rpc = Rpc::default();
        let _ = rpc.joins.push(peer_join(interest));
        world.rpc(peer, rpc);
    }
    let g = group(1);
    let mut bits = Bitmap::new();
    for i in [2, 5, 6, 7] {
        bits.set(i);
    }
    world.node.sample(g, bits, &mut world.env, &world.catalog, &mut world.rng);
    let hops = world.catalog.params.route_hops;
    let (direct_1, direct_2) = (wants(&mut world, 1), wants(&mut world, 2));
    let (via, high) = (wants(&mut world, 3), wants(&mut world, 4));
    for w in [&direct_1, &direct_2] {
        assert!(w.len() == 1 && w[0].standing && w[0].hops == 0 && w[0].bits.iter().count() == 1);
    }
    assert!(via.len() == 1 && via[0].standing && via[0].hops == hops);
    // The fourth sample has nobody but the peer of high custody: it waits.
    assert!(high.is_empty());
    assert_eq!(world.node.sampled_from.len(), 3);
    assert!(world.node.samples_in_flight.is_empty());

    // The first wait runs out on two samples: one goes to the peer of high custody,
    // the other is held back by the limit in flight.
    let asked: Vec<u32> =
        bits.iter().filter(|&i| direct_1[0].bits.has(i) || direct_2[0].bits.has(i)).collect();
    let fire = |world: &mut World, index, peer: Option<PeerId>, first| {
        let peer = peer.map(|p| world.node.slots.stamp(p));
        let event = TimerEvent::Resample { group: g, index, peer, first };
        world.node.on_timer(
            event,
            &mut world.env,
            &mut world.catalog,
            &mut world.rng,
            &mut world.store,
        );
    };
    let first_peer = |i| if direct_1[0].bits.has(i) { 1 } else { 2 };
    fire(&mut world, asked[0], Some(first_peer(asked[0])), true);
    let second = wants(&mut world, 4);
    assert!(second.len() == 1 && second[0].bits.has(asked[0]) && second[0].hops == 0);
    fire(&mut world, asked[1], Some(first_peer(asked[1])), true);
    assert_eq!((world.node.samples_in_flight.len(), world.node.held_samples.len()), (1, 1));

    // Its wait over, the held one is taken: nobody is left to ask, and nothing
    // stays.
    fire(&mut world, asked[0], Some(4), false);
    assert!(world.node.samples_in_flight.is_empty() && world.node.held_samples.is_empty());
    for peer in 1..=4 {
        assert!(wants(&mut world, peer).is_empty());
    }
    world.env.now += world.node.config.group_ttl + 1.0;
    world.heartbeat();
    assert!(world.node.sampled_from.is_empty());
}

/// A node with duty passes a routed sample request it cannot answer one step
/// on, to a link that serves the index, a bounded number of times per asking
/// peer until the host starts a new period, and answers the asker when the
/// chunk arrives. The same ask without `hops` is a violation
/// (`seacast.md` §4.5 `route_want`, X6).
#[test]
fn a_routed_request_is_passed_on_within_the_limit() {
    let mut catalog = Catalog::new(8, 8);
    catalog.interest = Bitmap::new();
    catalog.derived = true;
    let mut world = World::new(catalog, 2, InterestKind::Derived);
    let mut rpc = Rpc::default();
    let _ = rpc.joins.push(peer_join(InterestKind::Declared));
    world.rpc(1, rpc);
    let g = group(1);
    let ask = |world: &mut World, index, hops| {
        let mut rpc = Rpc::default();
        let want = Want { hops, ..Want::standing(g, Bitmap::singleton(index)) };
        let _ = rpc.wants.push(want);
        world.rpc(1, rpc);
        world.drain(2).iter().flat_map(|e| e.wants.iter().copied()).collect::<Vec<Want>>()
    };
    let passed = ask(&mut world, 3, 1);
    assert!(passed.len() == 1 && passed[0].standing && passed[0].hops == 0);
    assert!(passed[0].bits == Bitmap::singleton(3));
    assert_eq!(world.node.forwarded.get(&(world.catalog.node_id(1), TYPE)), Some(&1));
    // A routed ask outside our interest adds no bit to the DECLARED peer's want_p.
    assert!(world.node.pairs.want_p(&(1, g)).is_none());
    // At the limit: not passed on, not kept standing outside our interest, no
    // penalty.
    assert!(ask(&mut world, 4, 1).is_empty());
    assert!(!world.node.standing.contains_key(&(g, 4)));
    assert_eq!(world.env.penalties, 0);
    world.node.reset_period();
    assert_eq!(ask(&mut world, 5, 1).len(), 1);

    // The chunk comes back the way the request went.
    world.rpc(2, chunk_rpc(chunk(g, 3, [0; 32])));
    let answers: Vec<u32> =
        world.drain(1).iter().filter_map(|e| e.chunk.as_ref()).map(|c| c.index).collect();
    assert_eq!(answers, vec![3]);

    // Without `hops`, an index outside our interest is ignored without penalty.
    assert!(ask(&mut world, 6, 0).is_empty());
    assert_eq!(world.env.penalties, 0);
    // The count outlives the connection: connecting again does not reset it.
    world.node.disconnect_peer(1, &mut world.env, &mut world.store);
    assert_eq!(world.node.forwarded.get(&(world.catalog.node_id(1), TYPE)), Some(&1));
    // The node's next connection, under another peer id, is still at the limit.
    let again = 1 + NODES;
    world.node.connect_peer(again, true, &mut world.env, &world.catalog);
    let mut rpc = Rpc::default();
    let _ = rpc.joins.push(peer_join(InterestKind::Declared));
    world.rpc(again, rpc);
    world.drain(2);
    let ask = |world: &mut World, index| {
        let mut rpc = Rpc::default();
        let want = Want { hops: 1, ..Want::standing(g, Bitmap::singleton(index)) };
        let _ = rpc.wants.push(want);
        world.rpc(again, rpc);
        world.drain(2).iter().map(|e| e.wants.len()).sum::<usize>()
    };
    assert_eq!(ask(&mut world, 6), 0);
    world.node.reset_period();
    assert_eq!(ask(&mut world, 7), 1);
}

/// A tie on a group the domain never tells of goes once its sender has stopped
/// naming the group (`seacast-lite.md` §4.2 `drop_stale_waits`).
#[test]
fn a_tie_on_a_group_never_told_of_expires() {
    let mut catalog = Catalog::new(8, 8);
    catalog.installed = Some([9; 32]);
    let mut world = World::new(catalog, 1, InterestKind::All);
    let g = group(1);
    world.rpc(1, chunk_rpc(chunk(g, 0, [5; 32])));
    assert!(world.node.tied_to_root(1, Ask { group: g, index: 0 }));
    assert!(world.node.groups.get(&g).is_none());
    let heartbeats = (world.node.config.group_ttl / world.node.config.heartbeat) as usize + 2;
    for _ in 0..heartbeats {
        world.env.now += world.node.config.heartbeat;
        world.heartbeat();
    }
    assert!(world.node.tied.is_empty());
    assert!(!world.node.tied_to_root(1, Ask { group: g, index: 0 }));
}

/// A park is the node's, not the connection's: it returns on the node's next
/// connection until its end, and the table that keeps it is bounded
/// (`seacast-lite.md` §8.1).
#[test]
fn a_park_outlives_its_connection() {
    let mut config = NodeConfig::default();
    config.capacities.max_kept_parks = 2;
    let mut world = World::with_config(config, Catalog::new(8, 8), 2, InterestKind::All);
    let until = world.env.now + world.node.config.park_ttl;
    for tag in 1..=3 {
        world.node.pairs.set_park((1, group(tag)), until);
    }
    world.node.disconnect_peer(1, &mut world.env, &mut world.store);
    assert_eq!(world.node.kept_parks.len(), 2);

    // The node's next connection has another peer id.
    let again = 1 + NODES;
    world.node.connect_peer(again, true, &mut world.env, &world.catalog);
    let now = world.env.now;
    let parked = (1..=3).filter(|&tag| world.node.parked(again, &group(tag), now)).count();
    assert_eq!(parked, 2);
    assert!(world.node.kept_parks.is_empty());
    // Another node's connection takes none of them.
    assert!((1..=3).all(|tag| !world.node.parked(2, &group(tag), now)));

    // Past its end a kept park does not return.
    world.node.disconnect_peer(again, &mut world.env, &mut world.store);
    assert_eq!(world.node.kept_parks.len(), 2);
    world.env.now = until;
    world.node.connect_peer(1, true, &mut world.env, &world.catalog);
    assert!((1..=3).all(|tag| !world.node.parked(1, &group(tag), until)));
    assert!(world.node.kept_parks.is_empty());
}

/// A connection's record is reset when it closes: the next connection with its
/// peer id starts with nothing of the last one's.
#[test]
fn a_closed_connection_leaves_nothing_to_the_next_with_its_id() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(group(1), Bitmap::singleton(0)));
    world.rpc(1, rpc);
    let slot = world.node.slots.get(1).expect("connected");
    assert!(slot.listed_count == 1 && slot.ihave_frames == 1 && slot.join_recv.len() == 1);

    world.node.disconnect_peer(1, &mut world.env, &mut world.store);
    assert!(world.node.slots.get(1).is_none() && world.node.sends.queue.get(1).is_none());
    world.node.connect_peer(1, false, &mut world.env, &world.catalog);
    let slot = world.node.slots.get(1).expect("connected");
    assert!(slot.listed_count == 0 && slot.ihave_frames == 0);
    assert!(slot.join_recv.is_empty() && slot.join_sent.is_empty());
    assert!(world.node.sends.queue.get(1).is_some_and(|q| q.is_empty()));
}

/// The host keeps peer ids below `max_peers`.
#[test]
#[should_panic]
fn a_peer_id_out_of_range_panics() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    let peer = world.node.config.capacities.max_peers as PeerId;
    world.node.connect_peer(peer, false, &mut world.env, &world.catalog);
}

/// What the node gave out for a connection is not taken back for the next
/// connection with its peer id: a verdict on a chunk of the closed one is
/// dropped, and a sampler's wait on it parks nobody.
#[test]
fn a_result_for_a_closed_connection_is_not_the_next_ones() {
    let mut catalog = Catalog::new(8, 8);
    catalog.deferred_proof = true;
    let mut world = World::new(catalog, 1, InterestKind::All);
    let g = group(1);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    let (from, first) = world.node.pop_unverified().expect("the chunk");
    let stale = world.node.slots.stamp(1);
    assert_eq!(from, stale);

    world.node.disconnect_peer(1, &mut world.env, &mut world.store);
    world.node.connect_peer(1, false, &mut world.env, &world.catalog);
    assert_ne!(world.node.slots.stamp(1), stale);
    assert_eq!(world.node.slots.resolve(stale), None);

    let (env, catalog, rng, store) =
        (&mut world.env, &mut world.catalog, &mut world.rng, &mut world.store);
    world.node.on_validated(from, first, ValidationResult::Reject, env, catalog, rng, store);
    assert_eq!(world.env.penalties, 0);
    assert!(world.node.verifying.is_empty() && world.node.seen_ids.is_empty());

    let event = TimerEvent::Resample { group: g, index: 3, peer: Some(stale), first: false };
    let (env, catalog, rng, store) =
        (&mut world.env, &mut world.catalog, &mut world.rng, &mut world.store);
    world.node.on_timer(event, env, catalog, rng, store);
    assert!(!world.node.parked(1, &g, world.env.now));
}

/// The pair table finds the peers that offer or hold a group without a walk
/// over the peers, for peer ids past one word of the bitmask; with no row
/// left for a new group, an offer is not kept.
#[test]
fn a_pair_is_found_by_its_group() {
    let mut pairs = seacast_core::Pairs::with_capacity(16, 0, 2, 200);
    let (g, other) = (group(1), group(2));
    for peer in [3, 70, 199] {
        pairs.set_offered((peer, g), Bitmap::from_indices([1, 2]));
    }
    let holding = seacast_core::HaveEntry {
        bits: Bitmap::singleton(4),
        ttl: 1,
        claim_all: false,
        complete: false,
    };
    pairs.set_peer_has((70, g), holding);
    pairs.set_offered((5, other), Bitmap::singleton(1));
    assert_eq!(pairs.offering(&g).collect::<Vec<_>>(), vec![3, 70, 199]);
    assert_eq!(pairs.having(&g).collect::<Vec<_>>(), vec![70]);

    pairs.clear_offered(&g, 1);
    for peer in [3, 70, 199] {
        assert_eq!(pairs.offered(&(peer, g)), Some(Bitmap::singleton(2)));
    }
    assert_eq!(pairs.offered(&(5, other)), Some(Bitmap::singleton(1)));

    pairs.take_offered(&(3, g));
    pairs.retain(|&(peer, _)| peer != 199);
    assert_eq!(pairs.offering(&g).collect::<Vec<_>>(), vec![70]);
    // The holding expires at the heartbeat.
    pairs.heartbeat(0.0, |_, _, _| {});
    assert_eq!(pairs.having(&g).count(), 0);

    // Both rows are taken: a third group has none.
    pairs.set_offered((9, group(3)), Bitmap::singleton(0));
    assert_eq!(pairs.offered(&(9, group(3))), None);
}

/// A direction of the push relations answers by type, family and colour, and
/// loses a peer's relations in one pass.
#[test]
fn relations_are_read_by_family_and_colour() {
    let mut set = seacast_core::Relations::with_capacity(8, 200);
    assert!(set.insert((3, TYPE, 7, 0)) && set.insert((130, TYPE, 7, 0)));
    assert!(set.insert((130, TYPE, 7, 1)) && !set.insert((130, TYPE, 7, 1)));
    assert_eq!(set.len(), 3);
    assert_eq!((set.word(TYPE, 7, 0, 0), set.word(TYPE, 7, 0, 2)), (1 << 3, 1 << 2));
    assert!(set.any_colour(130, TYPE, 7, 2) && !set.any_colour(3, TYPE, 8, 2));
    assert_eq!(set.family_word(TYPE, 7, 2, 2), 1 << 2);
    assert!(set.related(3) && !set.related(4));

    set.remove_peer(130);
    assert_eq!((set.len(), set.count(TYPE, 7, 1)), (1, 0));
    assert!(set.remove(&(3, TYPE, 7, 0)) && set.is_empty());
}

/// A peer counts as a link of a type once both JOINs have crossed, and no
/// longer once its connection closes.
#[test]
fn links_follow_the_joins() {
    let mut world = World::new(Catalog::new(8, 8), 2, InterestKind::All);
    assert_eq!(world.node.peers_of(world.node.links(TYPE)).collect::<Vec<_>>(), vec![1, 2]);
    world.node.connect_peer(3, true, &mut world.env, &world.catalog);
    assert_eq!(world.node.peers_of(world.node.links(TYPE)).collect::<Vec<_>>(), vec![1, 2]);
    world.node.disconnect_peer(1, &mut world.env, &mut world.store);
    assert_eq!(world.node.peers_of(world.node.links(TYPE)).collect::<Vec<_>>(), vec![2]);
}

/// A link counts once our JOIN is queued, not while a full queue owes it
/// (`seacast.md` §4.1 `links`).
#[test]
fn a_link_waits_for_our_owed_join() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    world.node.connect_peer(2, false, &mut world.env, &world.catalog);
    let prune = Prune { object_type: TYPE, family: 0, colour: 0, direction: Direction::Out };
    while world.node.sends.send::<Vec<u8>, _>(
        2,
        Queued::Control(Control::Prune(prune)),
        false,
        &mut world.env,
    ) {}
    let mut rpc = Rpc::default();
    let _ = rpc.joins.push(peer_join(InterestKind::All));
    world.rpc(2, rpc);
    assert!(world.node.join_sent(2, TYPE).is_some());
    assert!(!world.node.is_linked(2, TYPE));
    let sent = world.drain(2);
    assert!(sent.iter().any(|e| !e.joins.is_empty()));
    assert!(world.node.is_linked(2, TYPE));
}

/// A chunk the chunk table refuses is neither counted nor claimed.
#[test]
fn a_chunk_not_stored_is_not_counted() {
    let mut config = NodeConfig::default();
    config.capacities.max_stored_chunks = 2;
    let mut world = World::with_config(config, Catalog::new(8, 8), 1, InterestKind::All);
    let g = group(1);
    for index in 0..3 {
        world.rpc(1, chunk_rpc(chunk(g, index, [0; 32])));
    }
    let two = Bitmap::all_bits(2);
    assert_eq!(world.node.chunks.len(), 2);
    assert_eq!(world.node.groups.bits(&g, GroupBits::Received), Some(two));
    assert_eq!(world.node.groups.bits(&g, GroupBits::Mine), Some(two));
}

/// A GRAFT for a relation the tables cannot keep is answered no.
#[test]
fn a_graft_the_tables_cannot_keep_is_refused() {
    let mut config = NodeConfig::default();
    config.capacities.max_relation_keys = 1;
    let mut world = World::with_config(config, Catalog::new(8, 8), 1, InterestKind::All);
    let graft = |world: &mut World, family: u16| {
        let mut rpc = Rpc::default();
        let _ = rpc.grafts.push(Graft {
            object_type: TYPE,
            family,
            colour: 0,
            direction: Direction::Both,
            answer: false,
        });
        world.rpc(1, rpc);
        world.drain(1)
    };
    let sent = graft(&mut world, 0);
    assert!(world.node.push_in.contains(&(1, TYPE, 0, 0)));
    assert!(sent.iter().any(|e| !e.grafts.is_empty()));
    let sent = graft(&mut world, 1);
    assert!(!world.node.push_in.contains(&(1, TYPE, 1, 0)));
    assert!(!world.node.push_out.contains(&(1, TYPE, 1, 0)));
    assert!(sent.iter().all(|e| e.grafts.is_empty()) && sent.iter().any(|e| !e.prunes.is_empty()));
}

/// The default deferred store keeps a count for a peer or reserves nothing for
/// it, and a count of zero gives its place back.
#[test]
fn the_deferred_store_reserves_only_what_it_counts() {
    use seacast_core::DeferredStore;
    let mut store = BoundedDeferredStore::with_capacity(1, 4, 100);
    let f = chunk(group(1), 0, [0; 32]);
    assert!(store.reserve(1, &f));
    assert!(!store.reserve(2, &f));
    assert_eq!(store.total, 1);
    store.release(1, &f);
    assert_eq!(store.total, 0);
    assert!(store.reserve(2, &f));
}

/// A link's JOIN is owed whatever else is: the GRAFTs and PRUNEs owed leave
/// its room. One that repeats the last owed for its family and colour is not
/// owed twice, and one refused is reported (`seacast.md` §4.1
/// `send_relation`).
#[test]
fn a_join_is_owed_past_the_owed_relations() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    world.node.connect_peer(2, false, &mut world.env, &world.catalog);
    let prune = |family| {
        Control::Prune(Prune { object_type: TYPE, family, colour: 0, direction: Direction::Out })
    };
    while world.node.sends.send::<Vec<u8>, _>(2, Queued::Control(prune(0)), false, &mut world.env) {
    }
    let room = world.node.config.capacities.max_queue_entries_per_peer;
    for family in 0..room as u16 {
        assert!(world.node.sends.send_relation::<Vec<u8>, _>(2, prune(family), &mut world.env));
        // A repeat of the last one owed takes no room.
        assert!(world.node.sends.send_relation::<Vec<u8>, _>(2, prune(family), &mut world.env));
    }
    let owed = |world: &World| world.node.sends.queue.get(2).expect("open").owed_relations.len();
    assert_eq!(owed(&world), room);
    assert!(!world.node.sends.send_relation::<Vec<u8>, _>(2, prune(u16::MAX), &mut world.env));
    // The peer's JOIN is answered: ours is owed, and the link waits for it.
    let mut rpc = Rpc::default();
    let _ = rpc.joins.push(peer_join(InterestKind::All));
    world.rpc(2, rpc);
    assert_eq!(owed(&world), room + 1);
    assert!(!world.node.is_linked(2, TYPE));
    let sent = world.drain(2);
    assert!(sent.iter().any(|e| !e.joins.is_empty()));
    assert!(world.node.is_linked(2, TYPE));
}

/// A holding saved before the group's count was known keeps no index past it
/// once the group opens.
#[test]
fn a_saved_holding_is_cut_at_the_count() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    let g = group(1);
    let mut bits = Bitmap::singleton(2);
    bits.set(100);
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::holding(g, bits, false, false));
    world.rpc(1, rpc);
    assert_eq!(world.node.pairs.peer_has(&(1, g)).map(|e| e.bits), Some(bits));
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    let kept = world.node.pairs.peer_has(&(1, g)).map(|e| e.bits).expect("kept");
    assert!(kept.has(2) && !kept.has(100));
    assert!(!world.node.holders.contains_key(&(g, 100)));
}

/// The id of a rejected chunk of a group with no record is not kept: nothing
/// would ever drop it.
#[test]
fn a_rejected_chunk_of_no_group_leaves_no_id() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    for tag in 0..100 {
        world.rpc(1, chunk_rpc(chunk(group(tag), 8, [0; 32])));
    }
    assert_eq!(world.env.penalties, 100);
    assert!(world.node.seen_ids.is_empty());
}

/// What is owed to one peer does not take the room of what is owed to
/// another.
#[test]
fn owed_answers_of_one_peer_leave_room_for_another() {
    let mut world = World::new(Catalog::new(8, 8), 2, InterestKind::All);
    let pairs = world.node.config.capacities.max_owed_pairs as u32;
    for tag in 0..pairs + 10 {
        world.node.sends.owed_answers.add(1, group(tag), &Bitmap::singleton(1));
    }
    world.node.sends.owed_answers.add(2, group(0), &Bitmap::singleton(1));
    assert!(world.node.sends.owed_answers.any(2));
}

/// A list of peers is not cut at a fixed length: with more links than one
/// word of the bitmask holds, every peer that pushes a family is told of a
/// chunk held.
#[test]
fn every_peer_of_a_relation_is_told() {
    let mut config = NodeConfig::default();
    config.capacities.max_peers = 200;
    let peers = 150;
    let mut world = World::with_config(config, Catalog::new(8, 8), peers, InterestKind::All);
    assert_eq!(world.node.count(world.node.links(TYPE)), peers as usize);
    let g = group(1);
    for peer in 2..=peers {
        world.node.push_in.insert((peer, TYPE, world.catalog.family(&g), 0));
    }
    let scope = world.node.suppression_scope(&g, &world.catalog);
    assert_eq!(world.node.count(scope), peers as usize - 1);

    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    let told = (1..=peers)
        .filter(|&peer| {
            world.drain(peer).iter().any(|e| e.haves.iter().any(|h| !h.offer && h.bits.has(0)))
        })
        .count();
    assert_eq!(told, peers as usize);
}

/// No set of peers is cut at a length. With more peers than one word of a
/// bitmask holds: a chunk goes, as a push or an offer, to every peer of its
/// relation; every standing request for it is served; and the heartbeat's
/// gossip is drawn from all the peers outside the relations.
#[test]
fn sets_of_peers_are_not_cut_at_a_length() {
    let mut config = NodeConfig::default();
    config.capacities.max_peers = 200;
    config.paced_gossip = false;
    let peers: u64 = 150;
    let got = |world: &mut World, index: u32| {
        let (mut chunks, mut offers) = (0, 0);
        for peer in 2..=peers {
            let sent = world.drain(peer);
            chunks +=
                sent.iter().any(|e| e.chunk.as_ref().is_some_and(|c| c.index == index)) as usize;
            offers +=
                sent.iter().any(|e| e.haves.iter().any(|h| h.offer && h.bits.has(index))) as usize;
        }
        (chunks, offers)
    };

    // A relation of every peer: the chunk is pushed to some and offered to the
    // rest.
    let mut world =
        World::with_config(config.clone(), Catalog::new(8, 8), peers, InterestKind::All);
    let g = group(1);
    let fam = world.catalog.family(&g);
    for peer in 1..=peers {
        world.node.push_out.insert((peer, TYPE, fam, 0));
    }
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    let (chunks, offers) = got(&mut world, 0);
    assert!(chunks <= world.node.config.r_node());
    assert_eq!(chunks + offers, peers as usize - 1);

    // A standing request of every peer for a chunk not held yet.
    for peer in 2..=peers {
        let mut rpc = Rpc::default();
        let _ = rpc.wants.push(Want::standing(g, Bitmap::singleton(1)));
        world.rpc(peer, rpc);
    }
    assert_eq!(world.node.count(seacast_core::PeerSet::Standing(g, 1)), peers as usize - 1);
    world.rpc(1, chunk_rpc(chunk(g, 1, [0; 32])));
    assert_eq!(got(&mut world, 1).0, peers as usize - 1);
    assert!(world.node.standing.is_empty());

    // No relation: the gossip of a heartbeat goes to its share of all the peers.
    let mut world = World::with_config(config, Catalog::new(8, 8), peers, InterestKind::All);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    got(&mut world, 0);
    world.heartbeat();
    let share = (world.node.config.gossip_factor * peers as f64) as usize;
    let (_, offers) = got(&mut world, 0);
    assert!(offers + 1 >= share && offers <= share, "{offers} of {share}");
}

/// A node that follows its links' speeds.
fn adaptive(catalog: Catalog, peers: u64) -> World {
    let config = NodeConfig { link_adaptive: true, ..NodeConfig::default() };
    World::with_config(config, catalog, peers, InterestKind::All)
}

/// Of a peer on a slow link a node that decodes at `K` asks for no more of a
/// coded group than it lacks to `K`, whatever it is offered. Of any other
/// peer, and where it does not decode, it asks for all.
#[test]
fn asks_of_a_slow_link_stop_at_what_a_decode_takes() {
    let asked = |catalog: Catalog, slow: bool| {
        let mut world = adaptive(catalog, 2);
        world.node.set_link_slow(1, slow);
        let g = group(1);
        // The chunk gives the group's count and threshold.
        world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
        world.drain(1);
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::offer(g, Bitmap::all_bits(8)));
        world.rpc(1, rpc);
        let asks = world.drain(1);
        let bits = asks.iter().flat_map(|entry| entry.wants.iter()).map(|w| w.bits.popcount());
        bits.sum::<u32>()
    };
    // One of four held: three more of a slow link, all seven of another.
    assert_eq!(asked(Catalog::new(8, 4), true), 3);
    assert_eq!(asked(Catalog::new(8, 4), false), 7);
    // Not coded: every index is needed.
    assert_eq!(asked(Catalog::new(8, 8), true), 7);
    let mut sampler = Catalog::new(8, 4);
    sampler.later = Some(1.0);
    assert_eq!(asked(sampler, true), 7);

    // An offer ahead of the group's first chunk: the threshold is in no
    // offer, and half of what is offered is asked for, coded or not. A chunk
    // then tells, and the rest of a group that is not coded is asked for.
    for (k, rest) in [(4, 0), (8, 4)] {
        let mut world = adaptive(Catalog::new(8, k), 2);
        world.node.set_link_slow(1, true);
        let g = group(1);
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::offer(g, Bitmap::all_bits(8)));
        world.rpc(1, rpc);
        let asks = |world: &mut World| -> Bitmap {
            let mut asked = Bitmap::new();
            for want in world.drain(1).iter().flat_map(|entry| entry.wants.iter()) {
                want.bits.iter().for_each(|index| asked.set(index));
            }
            asked
        };
        let first = asks(&mut world);
        assert_eq!(first.popcount(), 4);
        world.rpc(1, chunk_rpc(chunk(g, first.first_index().unwrap(), [0; 32])));
        world.env.now += 1.0;
        world.heartbeat();
        assert_eq!(asks(&mut world).and_not(&first).popcount(), rest, "k = {k}");
    }
}

/// A chunk goes to the peers on links not slow before any on a slow one, to
/// more of them than the push degree, and a peer on a slow link is offered no
/// more of a coded group than it lacks to decode.
#[test]
fn pushes_go_to_fast_links_and_offers_to_slow_ones_are_bounded() {
    let peers: u64 = 9;
    let mut world = adaptive(Catalog::new(8, 4), peers);
    let g = group(1);
    let fam = world.catalog.family(&g);
    for peer in 1..=peers {
        world.node.push_out.insert((peer, TYPE, fam, 0));
    }
    // Peer 1 is the sender; 2 to 5 keep up, 6 to 9 do not.
    let slow = |peer: u64| peer >= 6;
    for peer in 1..=peers {
        world.node.set_link_slow(peer, slow(peer));
    }
    let (mut pushed, mut offered) = ([0u32; 10], [0u32; 10]);
    for index in 0..8 {
        world.rpc(1, chunk_rpc(chunk(g, index, [0; 32])));
        for peer in 2..=peers {
            for entry in world.drain(peer) {
                pushed[peer as usize] += entry.chunk.is_some() as u32;
                for h in entry.haves.iter().filter(|h| h.offer) {
                    offered[peer as usize] += h.bits.popcount();
                }
            }
        }
    }
    for peer in 2..=peers {
        let (pushed, offered) = (pushed[peer as usize], offered[peer as usize]);
        match slow(peer) {
            // All four are pushed to, where the push degree alone takes two of
            // the nine: until each is projected to have enough.
            false => assert!(pushed >= 2, "peer {peer}: {pushed} {offered}"),
            // Pushed to only once the fast links have enough, and pushed and
            // offered no more than the threshold together.
            true => assert!(pushed + offered <= 4, "peer {peer}: {pushed} {offered}"),
        }
    }
    assert_eq!(world.node.config.r, 2);
}

/// The bounds on a slow link are shares of `N` the host sets: asks stop at
/// `slow_ask_pct`, offers at `slow_offer_pct`.
#[test]
fn slow_link_bounds_are_shares_of_the_coded_set() {
    let config = NodeConfig {
        link_adaptive: true,
        slow_ask_pct: 75,
        slow_offer_pct: 25,
        ..NodeConfig::default()
    };
    let mut world = World::with_config(config.clone(), Catalog::new(8, 4), 2, InterestKind::All);
    world.node.set_link_slow(1, true);
    let g = group(1);
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    world.drain(1);
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(g, Bitmap::all_bits(8)));
    world.rpc(1, rpc);
    let asked: u32 =
        world.drain(1).iter().flat_map(|e| e.wants.iter()).map(|w| w.bits.popcount()).sum();
    // One held, to six of eight.
    assert_eq!(asked, 5);

    // Pushes and offers to the slow peers 2 to 4 as chunks come from peer 1.
    let sent = |slow_offer_pct: u8| {
        let peers: u64 = 4;
        let config = NodeConfig { slow_offer_pct, ..config.clone() };
        let mut world = World::with_config(config, Catalog::new(8, 4), peers, InterestKind::All);
        let fam = world.catalog.family(&g);
        for peer in 1..=peers {
            world.node.push_out.insert((peer, TYPE, fam, 0));
            world.node.set_link_slow(peer, peer >= 2);
        }
        let (mut pushed, mut offered) = (0u32, 0u32);
        for index in 0..8 {
            world.rpc(1, chunk_rpc(chunk(g, index, [0; 32])));
            for peer in 2..=peers {
                for entry in world.drain(peer) {
                    pushed += entry.chunk.is_some() as u32;
                    let offers = entry.haves.iter().filter(|h| h.offer);
                    offered += offers.map(|h| h.bits.popcount()).sum::<u32>();
                }
            }
        }
        (pushed, offered)
    };
    // Each slow peer is offered up to its share less what it is known to
    // hold. The pushes are not bounded by it.
    let (pushed, offered) = sent(25);
    assert!(offered <= 3 * 2, "{pushed} {offered}");
    let (wide_pushed, wide_offered) = sent(100);
    assert_eq!(wide_pushed, pushed);
    assert!(wide_offered > offered, "{wide_offered} {offered}");
}

/// With enough links not slow, a forwarded chunk is pushed to none on a slow
/// link, whatever the random draw among the proven.
#[test]
fn a_slow_link_is_not_pushed_to_while_fast_ones_fill_the_budget() {
    let peers: u64 = 9;
    let mut world = adaptive(Catalog::new(8, 4), peers);
    let slow = |peer: u64| peer >= 6;
    for peer in 1..=peers {
        world.node.set_link_slow(peer, slow(peer));
    }
    for n in 1..=32 {
        let g = group(n);
        let fam = world.catalog.family(&g);
        for peer in 1..=peers {
            world.node.push_out.insert((peer, TYPE, fam, 0));
        }
        world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
        for peer in 2..=peers {
            let pushed = world.drain(peer).iter().any(|e| e.chunk.is_some());
            assert!(!(slow(peer) && pushed), "group {n}: slow peer {peer} pushed");
        }
    }
}

/// A peer that said it is pull only is pushed nothing and offered instead,
/// and pushed to again once it says it is not. A node that is pull only
/// pushes to nobody.
#[cfg(feature = "pull-only")]
#[test]
fn pull_only_peers_and_nodes_get_and_make_no_pushes() {
    let sent = |config: NodeConfig, pull_only_peer: Option<u64>| {
        let peers: u64 = 4;
        let mut world = World::with_config(config, Catalog::new(8, 4), peers, InterestKind::All);
        let g = group(1);
        let fam = world.catalog.family(&g);
        for peer in 1..=peers {
            world.node.push_out.insert((peer, TYPE, fam, 0));
        }
        if let Some(peer) = pull_only_peer {
            world.node.set_peer_pull_only(peer, true);
        }
        world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
        let mut out = [(false, false); 5];
        for peer in 2..=peers {
            let entries = world.drain(peer);
            out[peer as usize] = (
                entries.iter().any(|e| e.chunk.is_some()),
                entries.iter().any(|e| e.haves.iter().any(|h| h.offer)),
            );
        }
        (world, out)
    };
    let config = NodeConfig { r: 3, ..NodeConfig::default() };
    // Pushed to peers 2 to 4; with peer 3 pull only, peer 3 is offered.
    let (_, all) = sent(config.clone(), None);
    assert!((2..=4).all(|p| all[p].0));
    let (mut world, out) = sent(config.clone(), Some(3));
    assert_eq!(out[3], (false, true));
    assert!(out[2].0 && out[4].0);
    // It says it takes pushes again: the next chunk goes to it.
    world.node.set_peer_pull_only(3, false);
    world.rpc(1, chunk_rpc(chunk(group(1), 1, [0; 32])));
    assert!(world.drain(3).iter().any(|e| e.chunk.is_some()));
    // A node that is pull only pushes to nobody, and offers to all.
    let (_, none) = sent(NodeConfig { pull_only: true, ..config }, None);
    assert!((2..=4).all(|p| none[p] == (false, true)), "{none:?}");
}

/// A forwarded chunk is offered to `offer_peers` of the relation at most, a
/// sample of those not pushed it.
#[test]
fn offers_go_to_offer_peers_at_most() {
    let offered = |offer_peers: usize| {
        let peers: u64 = 8;
        let config = NodeConfig { offer_peers, ..NodeConfig::default() };
        let mut world = World::with_config(config, Catalog::new(8, 4), peers, InterestKind::All);
        let g = group(1);
        let fam = world.catalog.family(&g);
        for peer in 1..=peers {
            world.node.push_out.insert((peer, TYPE, fam, 0));
        }
        world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
        let (mut pushed, mut offered) = (0, 0);
        for peer in 2..=peers {
            let entries = world.drain(peer);
            pushed += entries.iter().any(|e| e.chunk.is_some()) as usize;
            offered += entries.iter().any(|e| e.haves.iter().any(|h| h.offer)) as usize;
        }
        (pushed, offered)
    };
    let (pushed, all) = offered(usize::MAX);
    assert_eq!(pushed + all, 7);
    let (pushed_capped, capped) = offered(2);
    assert_eq!(pushed_capped, pushed);
    assert_eq!(capped, 2);
}

/// Heartbeat gossip goes to `joined_peers()` (`seacast.md` §3), the links of a
/// type the node runs. A peer whose JOIN is in is not one while ours is owed.
#[test]
fn heartbeat_gossip_goes_to_links_only() {
    let config = NodeConfig { paced_gossip: false, ..NodeConfig::default() };
    let mut world = World::with_config(config, Catalog::new(8, 8), 2, InterestKind::All);
    // Peer 3: its queue full, so our answer to its JOIN is owed.
    world.node.connect_peer(3, false, &mut world.env, &world.catalog);
    let prune = Control::Prune(Prune {
        object_type: TYPE,
        family: 0,
        colour: 0,
        direction: Direction::Out,
    });
    while world.node.sends.send::<Vec<u8>, _>(3, Queued::Control(prune), false, &mut world.env) {}
    assert!(world.node.sends.send_relation::<Vec<u8>, _>(3, prune, &mut world.env));
    let mut rpc = Rpc::default();
    let _ = rpc.joins.push(peer_join(InterestKind::All));
    world.rpc(3, rpc);
    assert!(!world.node.is_linked(3, TYPE));

    world.rpc(1, chunk_rpc(chunk(group(1), 0, [0; 32])));
    world.drain(2);
    let offered = |world: &mut World, peer| {
        world.drain(peer).iter().any(|e| e.haves.iter().any(|h| h.offer && h.bits.has(0)))
    };
    world.heartbeat();
    assert!(offered(&mut world, 2));
    // The drain writes our JOIN, and the next heartbeat takes the link.
    assert!(!offered(&mut world, 3));
    assert!(world.node.is_linked(3, TYPE));
    world.heartbeat();
    assert!(offered(&mut world, 3));
}

/// A dropped group's later chunks are not acted on: not forwarded, and not kept
/// for heartbeat gossip (`seacast.md` §4.6).
#[test]
fn a_dropped_group_is_not_acted_on() {
    let mut world = World::new(Catalog::new(8, 8), 2, InterestKind::All);
    let g = group(1);
    let gossiped = |world: &World| {
        world.node.gossip_history.gossip_group_bits().iter().any(|&(of, _)| of == g)
    };
    world.rpc(1, chunk_rpc(chunk(g, 0, [0; 32])));
    assert!(gossiped(&world));
    world.node.drop_group(g);
    assert!(!gossiped(&world));
    world.rpc(1, chunk_rpc(chunk(g, 1, [0; 32])));
    assert!(!gossiped(&world));
    assert!(world.drain(2).iter().all(|e| e.chunk.is_none() && e.haves.iter().all(|h| !h.offer)));
}

/// A decode answers the standing WANTs of its own group, as an arrival does
/// (`seacast.md` §4.5).
#[test]
fn a_decode_answers_the_standing_wants_of_its_group() {
    let mut world = World::new(Catalog::new(8, 4), 2, InterestKind::All);
    let g = group(1);
    let mut rpc = Rpc::default();
    let _ = rpc.wants.push(Want::standing(g, Bitmap::singleton(7)));
    world.rpc(2, rpc);
    for i in 0..4 {
        world.rpc(1, chunk_rpc(chunk(g, i, [0; 32])));
    }
    world.drain(2);
    let (env, catalog, rng) = (&mut world.env, &mut world.catalog, &mut world.rng);
    world.node.decode_group(g, env, catalog, rng);
    let answers = world
        .drain(2)
        .into_iter()
        .filter(|e| e.solicited && e.chunk.as_ref().is_some_and(|f| f.index == 7))
        .count();
    assert_eq!(answers, 1);
}

/// A claimant still decoding keeps the first probe an asker sends, and
/// answers it once when the chunk is stored; a standing WANT of the same
/// index from the asker is not kept beside it (`seacast.md` §4.6).
#[test]
fn a_probe_that_finds_its_claimant_decoding_is_answered_once_stored() {
    let mut world = World::new(Catalog::new(8, 4), 2, InterestKind::All);
    let g = group(1);
    for i in 0..4 {
        world.rpc(1, chunk_rpc(chunk(g, i, [0; 32])));
    }
    assert_eq!(world.node.group_state(&g), Some(GroupState::Decoding));
    world.drain(2);
    let mut rpc = Rpc::default();
    let _ = rpc.wants.push(Want::probe(g, Bitmap::singleton(6)));
    let _ = rpc.wants.push(Want::standing(g, Bitmap::singleton(6)));
    world.rpc(2, rpc);
    assert!(world.drain(2).iter().all(|e| e.chunk.is_none()));
    assert_eq!(world.node.probe_waiting_of.len(), 1);

    let (env, catalog, rng) = (&mut world.env, &mut world.catalog, &mut world.rng);
    world.node.decode_group(g, env, catalog, rng);
    let answers = world
        .drain(2)
        .into_iter()
        .filter(|e| e.solicited && e.chunk.as_ref().is_some_and(|f| f.index == 6))
        .count();
    assert_eq!((answers, world.env.penalties), (1, 0));
    assert!(world.node.probe_waiting_of.is_empty() && world.node.probe_waiting.is_empty());
}

/// The probes kept for a decoding claimant stay within their table, whatever
/// the askers.
#[test]
fn the_probes_kept_while_decoding_are_bounded() {
    let mut config = NodeConfig::default();
    config.capacities.max_groups = 4;
    let mut world = World::with_config(config, Catalog::new(8, 4), 63, InterestKind::All);
    let g = group(1);
    for i in 0..4 {
        world.rpc(1, chunk_rpc(chunk(g, i, [0; 32])));
    }
    for peer in 2..=63 {
        let mut rpc = Rpc::default();
        let _ = rpc.wants.push(Want::probe(g, Bitmap::singleton(4 + peer as u32 % 4)));
        world.rpc(peer, rpc);
    }
    let kept = world.node.probe_waiting_of.len();
    assert!(kept > 0 && kept <= world.node.probe_waiting_of.capacity());
    // They go with their connections.
    for peer in 2..=63 {
        world.node.disconnect_peer(peer, &mut world.env, &mut world.store);
    }
    assert!(world.node.probe_waiting_of.is_empty() && world.node.probe_waiting.is_empty());
}

/// A node that keeps its decode for later and is told of a whole claim
/// probes the claimant. The probe's promise starts at its write; a probe not
/// written by the verdict gets none, and one whose claimant leaves gets none
/// and returns the duty to its own time (`seacast.md` §4.6).
#[test]
fn a_probe_is_judged_only_once_written_and_while_its_claimant_stays() {
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Case {
        Written,
        Unwritten,
        Closed,
    }
    for case in [Case::Written, Case::Unwritten, Case::Closed] {
        let mut catalog = Catalog::new(8, 4);
        catalog.later = Some(5.0);
        let mut world = World::new(catalog, 2, InterestKind::All);
        let g = group(1);
        for i in 0..4 {
            world.rpc(1, chunk_rpc(chunk(g, i, [0; 32])));
        }
        assert_eq!(world.node.group_state(&g), Some(GroupState::Complete));
        world.drain(2);
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::holding(g, Bitmap::all_bits(8), true, true));
        world.rpc(2, rpc);
        let rec = world.node.groups.get(&g).expect("open");
        assert_eq!(rec.deferred, Some(true));
        let (ask, duty_at) = (Ask::new(g, rec.probe.expect("probed")), rec.duty_at);
        assert!(world.node.promises.get(ask, 2).is_none());
        if case != Case::Unwritten {
            assert!(world.drain(2).iter().any(|e| e.wants.iter().any(|w| w.probe)));
            assert!(world.node.promises.get(ask, 2).is_some());
        }
        if case == Case::Closed {
            world.node.disconnect_peer(2, &mut world.env, &mut world.store);
            let rec = world.node.groups.get(&g).expect("open");
            assert_eq!(rec.probe_ok, Some(None));
            assert_eq!(rec.reconsider_at, duty_at.map(f64::to_bits));
            assert!(!world.node.probe_asks.contains(&ask));
            continue;
        }
        let at_bits = world.node.groups.get(&g).and_then(|r| r.reconsider_at).expect("armed");
        world.env.now = f64::from_bits(at_bits);
        let event = TimerEvent::Reconsider { group: g, at_bits };
        let (env, catalog, rng, store) =
            (&mut world.env, &mut world.catalog, &mut world.rng, &mut world.store);
        world.node.on_timer(event, env, catalog, rng, store);
        let rec = world.node.groups.get(&g).expect("open");
        let verdict = if case == Case::Written { Some(Some(false)) } else { Some(None) };
        assert_eq!(rec.probe_ok, verdict, "{case:?}");
        assert_eq!(world.env.penalties, usize::from(case == Case::Written), "{case:?}");
        assert!(!world.node.probe_asks.contains(&ask));
        // Settled while queued, it is not written.
        assert!(world.drain(2).iter().all(|e| e.wants.iter().all(|w| !w.probe)));
    }
}

/// A pull-only type's source pushes nothing and offers every chunk at publish,
/// one offer a peer over the colours (`seacast.md` §4.7
/// `offer_at_publish`).
#[test]
fn a_pull_only_source_offers_at_publish() {
    let mut catalog = Catalog::new(2, 2);
    catalog.params.eager = false;
    let mut world = World::new(catalog, 4, InterestKind::All);
    // Two colours, each pool the links: chunk 0 is colour 0, chunk 1 colour 1.
    world.catalog.params.m = 2;
    let g = group(1);
    let shards = [chunk(g, 0, [0; 32]), chunk(g, 1, [0; 32])];
    let (env, catalog, rng) = (&mut world.env, &world.catalog, &mut world.rng);
    world.node.publish(g, Shape { n: 2, k: 2 }, &shards, env, catalog, rng);
    for peer in 1..=4 {
        let sent = world.drain(peer);
        assert!(sent.iter().all(|e| e.chunk.is_none()));
        let offers: Vec<Bitmap> =
            sent.iter().flat_map(|e| e.haves.iter()).filter(|h| h.offer).map(|h| h.bits).collect();
        assert_eq!(offers, vec![Bitmap::all_bits(2)]);
    }
}

/// At `SOURCE_OFFERS = PUBLISH` the peers not pushed a chunk are offered it at
/// publish, and an acknowledgement offers nothing more (`seacast.md` §4.7).
#[test]
fn a_source_may_offer_at_publish() {
    let config =
        NodeConfig { source_offers: seacast_core::SourceOffers::Publish, ..NodeConfig::default() };
    let mut world = World::with_config(config, Catalog::new(2, 2), 4, InterestKind::All);
    let g = group(1);
    let shards = [chunk(g, 0, [0; 32]), chunk(g, 1, [0; 32])];
    let (env, catalog, rng) = (&mut world.env, &world.catalog, &mut world.rng);
    world.node.publish(g, Shape { n: 2, k: 2 }, &shards, env, catalog, rng);
    for peer in 1..=4 {
        let sent = world.drain(peer);
        let pushed =
            sent.iter().filter_map(|e| e.chunk.as_ref()).fold(Bitmap::new(), |mut acc, f| {
                acc.set(f.index);
                acc
            });
        let offered = sent
            .iter()
            .flat_map(|e| e.haves.iter())
            .filter(|h| h.offer)
            .fold(Bitmap::new(), |acc, h| acc | h.bits);
        assert_eq!(pushed | offered, Bitmap::all_bits(2));
        assert!((pushed & offered).is_empty());
    }
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::holding(g, Bitmap::all_bits(2), false, false));
    world.rpc(1, rpc);
    for peer in 1..=4 {
        assert!(world.drain(peer).iter().flat_map(|e| e.haves.iter()).all(|h| !h.offer));
    }
}

/// A push is noted under every group the chunk fills, so that it is not
/// offered or repaired to that peer through another axis (`seacast.md`
/// §4.4 `note_push`).
#[test]
fn a_push_is_noted_under_every_group_it_fills() {
    let mut catalog = Catalog::new(2, 2);
    let (g, across) = (group(1), group(2));
    catalog.cross_group = Some(across);
    let mut world = World::new(catalog, 4, InterestKind::All);
    let shards = [chunk(g, 0, [0; 32]), chunk(g, 1, [0; 32])];
    let (env, catalog, rng) = (&mut world.env, &world.catalog, &mut world.rng);
    world.node.publish(g, Shape { n: 2, k: 2 }, &shards, env, catalog, rng);
    let mut noted = 0;
    for peer in 1..=4 {
        for f in world.drain(peer).iter().filter_map(|e| e.chunk.as_ref()) {
            assert!(world.node.pairs.pushed(&(peer, across)).is_some_and(|e| e.has(f.index)));
            noted += 1;
        }
    }
    assert!(noted > 0);
}

/// The first unsolicited chunk of a group written to a peer is marked, for its
/// type to send more with it (`seacast-bindings.md` §1.3, P2): no later one
/// of the group to that peer, and no answer.
#[test]
fn the_first_push_of_a_group_to_a_peer_is_marked() {
    let mut world = World::new(Catalog::new(4, 4), 4, InterestKind::All);
    let g = group(1);
    let shards: Vec<_> = (0..4).map(|i| chunk(g, i, [0; 32])).collect();
    let (env, catalog, rng) = (&mut world.env, &world.catalog, &mut world.rng);
    world.node.publish(g, Shape { n: 4, k: 4 }, &shards, env, catalog, rng);
    let (mut pushed, mut marked, mut reached) = (0, 0, 0);
    for peer in 1..=4 {
        let firsts: Vec<bool> = world
            .drain(peer)
            .iter()
            .filter(|e| e.chunk.is_some())
            .map(|e| e.first_of_group)
            .collect();
        if let Some((&first, rest)) = firsts.split_first() {
            assert!(first && rest.iter().all(|&f| !f), "peer {peer}: {firsts:?}");
            reached += 1;
        }
        pushed += firsts.len();
        marked += firsts.iter().filter(|&&f| f).count();
    }
    assert_eq!(marked, reached);
    assert!(pushed > reached, "no peer was pushed two chunks of the group");

    let mut rpc = Rpc::default();
    let _ = rpc.wants.push(Want::direct(g, Bitmap::all_bits(4)));
    world.rpc(1, rpc);
    let sent = world.drain(1);
    assert!(sent.iter().any(|e| e.solicited && e.chunk.is_some()));
    assert!(sent.iter().all(|e| !e.first_of_group));
}

/// A second copy under an unseen id for an index already received on an axis
/// is acknowledged there and not forwarded; one held only as rebuilt is still
/// forwarded (`seacast.md` §4.2, §4.4).
#[test]
fn a_second_id_for_a_received_index_is_not_forwarded() {
    let mut world = World::new(Catalog::new(4, 2), 3, InterestKind::All);
    for peer in 1..=3 {
        world.node.push_out.insert((peer, TYPE, 0, 0));
    }
    let g = group(1);
    let first = chunk(g, 0, [1; 32]);
    world.rpc(1, chunk_rpc(first.clone()));
    assert!(world.drain(2).iter().any(|e| e.chunk.is_some()));
    assert!(world.drain(3).iter().any(|e| e.chunk.is_some()));
    world.drain(1);
    // Clear gossip history by shifting it out.
    for _ in 0..4 {
        world.node.gossip_history.shift();
    }

    // Second copy with a different unseen id: acknowledged to sender, not
    // forwarded to peer 3, and not added to gossip history.
    let mut second = first.clone();
    second.cached_id[58] ^= 0xff;
    world.rpc(2, chunk_rpc(second));
    let acks = world.drain(2);
    assert!(acks.iter().any(|e| e.haves.iter().any(|h| !h.offer && h.group == g && h.bits.has(0))));
    assert!(world.drain(3).is_empty());
    assert!(world.node.gossip_history.gossip_group_bits().is_empty());

    // Now test an index held only as rebuilt: open g2 with chunk 1, decode to
    // rebuild chunk 0, drain, then receive chunk 0 under an unseen id.
    let g2 = group(2);
    let c1 = chunk(g2, 1, [2; 32]);
    world.rpc(1, chunk_rpc(c1.clone()));
    let c0_rebuilt = chunk(g2, 0, [2; 32]);
    let rebuilt = [c0_rebuilt.clone(), c1];
    let (env, catalog, rng) = (&mut world.env, &mut world.catalog, &mut world.rng);
    world.node.on_decoded(g2, Some(vec![0]), &rebuilt, env, catalog, rng);
    for peer in 1..=3 {
        world.drain(peer);
    }
    for _ in 0..4 {
        world.node.gossip_history.shift();
    }
    assert!(world.node.groups.bits(&g2, GroupBits::Rebuilt).is_some_and(|b| b.has(0)));
    assert!(!world.node.groups.bits(&g2, GroupBits::Received).is_some_and(|b| b.has(0)));

    let mut c0_net = c0_rebuilt;
    c0_net.cached_id[58] ^= 0xaa;
    world.rpc(1, chunk_rpc(c0_net));
    // Forwarded to peer 2 or 3 (not skipped because it was rebuilt only).
    let forwarded = world.drain(2).iter().any(|e| e.chunk.is_some() || !e.haves.is_empty()) ||
        world.drain(3).iter().any(|e| e.chunk.is_some() || !e.haves.is_empty());
    assert!(forwarded);
    assert!(!world.node.gossip_history.gossip_group_bits().is_empty());
}

/// A writer mid-write keeps its place in the window's waiter line without
/// stalling writers behind it, and `write_waits` wakes the next writer that can
/// write only while room is free (`seacast.md` §4.11, `seacast-lite.md` §7.1).
#[test]
fn the_window_line_skips_a_writer_mid_write() {
    let config = NodeConfig { chunk_bytes: 32, ..NodeConfig::default() };
    let window = config.window_bytes();
    let mut world = World::with_config(config, Catalog::new(4, 4), 3, InterestKind::All);
    let g = group(1);
    let mut c = chunk(g, 0, [0; 32]);
    c.frame = vec![0u8; window];
    world.node.chunks.insert((g, 0), c);
    for peer in 1..=3 {
        assert!(world.node.enqueue(
            peer,
            Queued::Chunk { group: g, index: 0, solicited: false },
            false,
            &mut world.env,
        ));
    }

    // Peer 1 fills the window; peers 2 and 3 join the waiter line in order.
    assert!(matches!(
        world.node.next_to_send(1, &mut world.env, &world.catalog),
        DispatchOutcome::Send(_)
    ));
    assert!(matches!(
        world.node.next_to_send(2, &mut world.env, &world.catalog),
        DispatchOutcome::Wait
    ));
    assert!(matches!(
        world.node.next_to_send(3, &mut world.env, &world.catalog),
        DispatchOutcome::Wait
    ));

    // Peer 2 is mid-write when window is full: write_waits wakes nobody.
    world.env.writing.push(2);
    world.env.woken.clear();
    world.node.write_waits(2, &mut world.env);
    assert!(world.env.woken.is_empty());

    // Freeing peer 1's room skips peer 2 and wakes peer 3.
    world.node.sends.window_release(1, g, 0, &mut world.env);
    assert_eq!(world.env.woken, vec![3]);

    // Peer 3 acquires room while peer 2 keeps its place in line.
    assert!(matches!(
        world.node.next_to_send(3, &mut world.env, &world.catalog),
        DispatchOutcome::Send(_)
    ));

    // Peer 2 finishes its write and peer 3's room frees: peer 2 is woken.
    world.env.writing.clear();
    world.env.woken.clear();
    world.node.sends.window_release(3, g, 0, &mut world.env);
    assert_eq!(world.env.woken, vec![2]);

    // Peer 2 becomes mid-write again while room is free: write_waits wakes
    // peer 3 if peer 3 is waiting behind it.
    assert!(world.node.enqueue(
        3,
        Queued::Chunk { group: g, index: 0, solicited: false },
        false,
        &mut world.env,
    ));
    // Re-queue peer 3 into the waiter line behind peer 2 (window has room,
    // front is peer 2 since writing is cleared, so peer 3 waits).
    assert!(matches!(
        world.node.next_to_send(3, &mut world.env, &world.catalog),
        DispatchOutcome::Wait
    ));
    world.env.writing.push(2);
    world.env.woken.clear();
    world.node.write_waits(2, &mut world.env);
    assert_eq!(world.env.woken, vec![3]);
}

/// Source `publish` answers standing requests waiting for its chunks
/// (`seacast.md` §4.7).
#[test]
fn publish_answers_standing_requests() {
    let mut world = World::new(Catalog::new(2, 2), 2, InterestKind::Declared);
    let g = group(1);
    let mut rpc = Rpc::default();
    let _ = rpc.wants.push(Want::standing(g, Bitmap::singleton(1)));
    world.rpc(1, rpc);
    assert!(world.node.standing.contains_key(&(g, 1)));

    let shards = [chunk(g, 0, [0; 32]), chunk(g, 1, [0; 32])];
    let (env, catalog, rng) = (&mut world.env, &world.catalog, &mut world.rng);
    world.node.publish(g, Shape { n: 2, k: 2 }, &shards, env, catalog, rng);
    let answered: Vec<u32> = world
        .drain(1)
        .iter()
        .filter(|e| e.solicited)
        .filter_map(|e| e.chunk.as_ref())
        .map(|c| c.index)
        .collect();
    assert_eq!(answered, vec![1]);
}

/// Answers to asks on our own written offers do not count against
/// `SERVE_BUDGET`, and an index asked twice in one frame is counted once
/// (`seacast.md` §4.5).
#[test]
fn offers_exempt_from_serve_budget_and_duplicate_asks_counted_once() {
    let config = NodeConfig { max_served_per_heartbeat: 1, ..Default::default() };
    let mut world = World::with_config(config, Catalog::new(8, 8), 2, InterestKind::All);
    let g = group(1);
    for i in 0..3 {
        world.rpc(1, chunk_rpc(chunk(g, i, [0; 32])));
    }
    world.drain(2);
    // Offer chunk 0 to peer 2 and write it out so `offered_to` records it.
    let (env, catalog) = (&mut world.env, &world.catalog);
    world.node.announce(2, g, Bitmap::singleton(0), env, catalog);
    let written = world.drain(2);
    assert!(written.iter().any(|e| e.haves.iter().any(|h| h.offer && h.bits.has(0))));

    // Ask for offered chunk 0 (exempt) and unoffered chunk 1 twice in one frame:
    // both 0 and 1 are answered, and chunk 1 uses 1 budget unit (not 2).
    let mut rpc = Rpc::default();
    let _ = rpc.wants.push(Want::direct(g, Bitmap::from_indices([0, 1])));
    let _ = rpc.wants.push(Want::direct(g, Bitmap::singleton(1)));
    world.rpc(2, rpc);
    let sent: Vec<u32> =
        world.drain(2).iter().filter_map(|e| e.chunk.as_ref()).map(|c| c.index).collect();
    assert_eq!(sent, vec![0, 1]);
    assert_eq!(world.node.pairs.served(&(2, g)), 2);

    // Budget (1) is now spent: unoffered chunk 2 is refused.
    let mut rpc = Rpc::default();
    let _ = rpc.wants.push(Want::direct(g, Bitmap::singleton(2)));
    world.rpc(2, rpc);
    assert!(world.drain(2).iter().all(|e| e.chunk.is_none()));
}

/// Where the host keeps the relations, the node grafts and prunes nothing,
/// ignores a GRAFT, and pushes to the peers the host names
/// (`SeacastNode::relation_added`, `seacast.md` §7).
#[test]
fn the_host_keeps_the_relations() {
    let relation = (1, TYPE, 0, 0);
    let mut catalog = Catalog::new(8, 8);
    catalog.params.host_relations = true;
    let mut world = World::new(catalog, 2, InterestKind::All);
    world.heartbeat();
    let mut rpc = Rpc::default();
    let direction = Direction::Both;
    let _ = rpc.grafts.push(Graft {
        object_type: TYPE,
        family: 0,
        colour: 0,
        direction,
        answer: false,
    });
    world.rpc(1, rpc);
    assert!(world.drain(1).iter().all(|e| e.grafts.is_empty() && e.prunes.is_empty()));
    assert!(world.node.push_in.is_empty() && world.node.push_out.is_empty());

    // A peer that has not joined the type is refused.
    let (env, catalog) = (&mut world.env, &world.catalog);
    assert!(!world.node.relation_added(9, TYPE, 0, 0, env, catalog));
    assert!(world.node.relation_added(1, TYPE, 0, 0, env, catalog));
    assert!(world.node.push_in.contains(&relation) && world.node.push_out.contains(&relation));

    // A chunk from peer 2 is pushed to peer 1, in the relation.
    world.rpc(2, chunk_rpc(chunk(group(1), 0, [0; 32])));
    assert!(world.drain(1).iter().any(|e| e.chunk.is_some()));

    world.node.relation_removed(1, TYPE, 0, 0);
    assert!(!world.node.push_in.contains(&relation) && !world.node.push_out.contains(&relation));
    world.rpc(2, chunk_rpc(chunk(group(1), 1, [0; 32])));
    assert!(world.drain(1).iter().all(|e| e.chunk.is_none()));
}

/// A JOIN taken back ends the link for the type and its relations, and a later
/// JOIN links it again without ours being sent twice (`SeacastNode::on_leave`).
#[test]
fn a_join_taken_back_ends_the_link() {
    let relation = (1, TYPE, 0, 0);
    let mut world = World::new(Catalog::new(8, 8), 2, InterestKind::All);
    world.node.push_in.insert(relation);
    world.node.push_out.insert(relation);
    world.node.push_out.insert((2, TYPE, 0, 0));
    world.node.on_leave(1, TYPE);
    assert!(!world.node.is_linked(1, TYPE) && world.node.is_linked(2, TYPE));
    assert!(!world.node.push_in.contains(&relation) && !world.node.push_out.contains(&relation));
    assert_eq!((world.node.push_in.len(), world.node.push_out.len()), (0, 1));

    // Nothing is pushed to it, and its offer is ignored.
    let g = group(1);
    world.rpc(2, chunk_rpc(chunk(g, 0, [0; 32])));
    let mut rpc = Rpc::default();
    let _ = rpc.haves.push(Have::offer(g, Bitmap::all_bits(8)));
    world.rpc(1, rpc);
    assert!(world.drain(1).iter().all(|e| e.chunk.is_none() && e.wants.is_empty()));

    let mut rpc = Rpc::default();
    let _ = rpc.joins.push(peer_join(InterestKind::All));
    world.rpc(1, rpc);
    assert!(world.node.is_linked(1, TYPE));
    assert!(world.drain(1).iter().all(|e| e.joins.is_empty()));
}

/// An id a peer does not want is kept for a group on record only, up to the
/// limit per peer and heartbeat, and an ask of it is then not answered
/// (`seacast.md` §4.5 `unwanted`).
#[test]
fn unwanted_ids_are_bounded_per_peer() {
    let config = NodeConfig { max_unwanted_ids: 1, ..Default::default() };
    let mut world = World::with_config(config, Catalog::new(8, 8), 2, InterestKind::All);
    let g = group(1);
    let (first, second) = (chunk(g, 0, [0; 32]), chunk(g, 1, [0; 32]));
    world.rpc(1, chunk_rpc(first.clone()));
    world.rpc(1, chunk_rpc(second.clone()));
    world.drain(2);

    // No record of the group: nothing is kept.
    assert!(!world.node.note_unwanted(2, chunk(group(2), 0, [0; 32]).cached_id));
    assert!(world.node.note_unwanted(2, first.cached_id));
    assert!(!world.node.note_unwanted(2, second.cached_id));
    assert_eq!(world.node.unwanted.len(), 1);

    let mut rpc = Rpc::default();
    let _ = rpc.wants.push(Want::direct(g, Bitmap::from_indices([0, 1])));
    world.rpc(2, rpc);
    let sent: Vec<u32> =
        world.drain(2).iter().filter_map(|e| e.chunk.as_ref()).map(|c| c.index).collect();
    assert_eq!(sent, vec![1]);

    // The count is the heartbeat's.
    world.heartbeat();
    assert!(world.node.note_unwanted(2, second.cached_id));
}

/// A frame handed over in parts is one offer-bearing frame (§4.3).
#[test]
fn a_frame_in_parts_counts_once() {
    let mut world = World::new(Catalog::new(8, 8), 1, InterestKind::All);
    let mut offered = false;
    for tag in 1..=3 {
        let mut rpc = Rpc::default();
        let _ = rpc.haves.push(Have::offer(group(tag), Bitmap::all_bits(8)));
        offered = world.node.on_frame_part(
            1,
            rpc,
            offered,
            &mut world.env,
            &mut world.catalog,
            &mut world.rng,
            &mut world.store,
        );
    }
    assert!(offered);
    assert_eq!(world.node.slots.get(1).unwrap().ihave_frames, 1);
}
