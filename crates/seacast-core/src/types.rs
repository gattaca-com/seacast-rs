use crate::bitmap::Bitmap;

/// 32-byte digest / root / group key (`Bytes32`, `Root`, `GroupId` in the
/// spec).
pub type Bytes32 = [u8; 32];

/// 59-byte structured chunk ID (`seacast-bindings.md` §1.3): `group (35B:
/// type, key, index LE) || index (4B LE) || content (20B)`.
pub type ChunkId = [u8; 59];

/// Group identifier in diffusion (`seacast-bindings.md` §1.3): its object
/// type, a key, and an index under the key, such as a block root and a column.
/// The type's codec derives it from a chunk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct GroupId {
    pub type_id: TypeId,
    pub key: Bytes32,
    pub index: u16,
}

impl GroupId {
    #[inline]
    pub const fn new(type_id: TypeId, key: Bytes32, index: u16) -> Self {
        Self { type_id, key, index }
    }

    /// The group a chunk id opens with ([`ChunkId`]).
    #[inline]
    pub fn of_chunk_id(id: &ChunkId) -> Self {
        let mut key = [0u8; 32];
        key.copy_from_slice(&id[1..33]);
        Self { type_id: TypeId(id[0]), key, index: u16::from_le_bytes([id[33], id[34]]) }
    }
}

/// Peer identifier in the state machine.
pub type PeerId = u64;

/// A `PeerId` with the generation of its connection in the high 32 bits. The
/// node gives it out with what comes back to it later (a timer, a chunk to
/// verify), and takes nothing back for a connection that has closed since,
/// though another has its peer id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GenerationPeerId(u64);

impl GenerationPeerId {
    #[inline]
    pub const fn new(peer: PeerId, generation: u32) -> Self {
        Self((generation as u64) << 32 | peer & 0xffff_ffff)
    }

    #[inline]
    pub const fn peer_id(self) -> PeerId {
        self.0 & 0xffff_ffff
    }

    #[inline]
    pub const fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }
}

/// 32-byte cryptographic node identifier (`node_id(p)` in `seacast.md`).
pub type NodeId = Bytes32;

/// Object type identifier. The domain assigns the values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct TypeId(pub u8);

/// The fork at which a node runs a type (`seacast-bindings.md` §1.3).
pub type ForkDigest = [u8; 4];

/// Relation family key within a type (`Policy::family`).
pub type FamilyId = u16;

/// Colour index (`0..M[T]`, `seacast.md` §1.4).
pub type Colour = u16;

/// Monotonic timestamp in seconds (`now` in `seacast-lite.md` / `seacast.md`).
pub type Timestamp = f64;

/// Interest kind declared per link and object type at `JOIN` (`seacast.md`
/// §1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum InterestKind {
    /// Whole object (`ALL`): complete at `K` distinct chunks (or `N` when
    /// uncoded).
    #[default]
    All,
    /// Computed by both ends from node ID and `custody_count` (`DERIVED`).
    Derived,
    /// Told per group and per peer in a standing `Want` (`DECLARED`, e.g. a
    /// sampler).
    Declared,
}

/// Duty declared per link and object type at `JOIN` (`seacast.md` §1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Duty {
    /// Holds push and announce relations and forwards received chunks into
    /// others' interest.
    #[default]
    Forward,
    /// Receives only (still answers direct asks within `SERVE_LIMIT`).
    None,
}

/// Direction of a `Graft` or `Prune` message (`seacast.md` §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Direction {
    /// `"I will push you this colour"` (`OUT`).
    #[default]
    Out,
    /// `"Push me this colour"` (`IN`).
    In,
    /// Symmetric push relation (`BOTH`).
    Both,
}

impl Direction {
    #[inline]
    pub fn includes_out(self) -> bool {
        matches!(self, Self::Out | Self::Both)
    }

    #[inline]
    pub fn includes_in(self) -> bool {
        matches!(self, Self::In | Self::Both)
    }
}

/// Announce width beyond the push/in relation (`seacast.md` §1.1
/// `ANNOUNCE_EXTRA`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AnnounceWidth {
    /// Announce immediately at forward time to all joined peers wanting the
    /// index (`ALL_JOINED`).
    AllJoined,
    /// Announce via paced heartbeat gossip to a random sample of non-related
    /// peers (`SAMPLE`).
    Sample,
    /// Do not announce outside the push relation (`NONE`).
    None,
}

/// When a source offers each chunk to the pool's peers it did not push it to
/// (`SOURCE_OFFERS`, `seacast.md` §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceOffers {
    /// At the chunk's acknowledgement; the holding names the chunks
    /// acknowledged so far (`ACK`).
    Ack,
    /// At publish; the holding grows at each chunk's first write, and an
    /// acknowledgement does nothing (`PUBLISH`).
    Publish,
}

/// Node uplink bandwidth class (`seacast.md` §4.1, `[c17]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UplinkClass {
    Home,
    Fast,
}

/// Level 1 per-chunk validation outcome (`seacast-lite.md` §3, `seacast.md`
/// §1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ValidationResult {
    Accept,
    Reject,
    Defer,
    /// What can be checked without reading the chunk's data holds; the rest is
    /// checked off the chunk path, and its verdict comes back through
    /// `SeacastNode::on_validated`.
    Pending,
    /// Not taken, and not held against its sender: the domain no longer wants
    /// the group, or does not want it yet.
    Ignore,
}

/// A group's index count `N` and its threshold `K`, from its header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Shape {
    pub n: u32,
    pub k: u32,
}

/// Lifecycle state of a tracked group (`seacast-lite.md` §4.2, `seacast.md`
/// §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GroupState {
    Collecting,
    Decoding,
    Complete,
    Invalid,
}

/// Verdict of IncrementalDAS repair sampling (`seacast.md` §4.6
/// `repair_verdict`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RepairVerdict {
    Repaired,
    Asked,
    NotRepaired,
}

/// Key identifying an ask for a specific `(group, index)` (`Ask(g, i)` /
/// `WantIndex`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ask {
    pub group: GroupId,
    pub index: u32,
}

impl Ask {
    #[inline]
    pub const fn new(group: GroupId, index: u32) -> Self {
        Self { group, index }
    }
}

/// Links a node is to keep to peers whose interest holds `family`, beyond the
/// relation floor: a repair, source or coverage floor (`seacast.md` §1.3,
/// §4.6, §4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LinkFloor {
    pub family: FamilyId,
    pub links: usize,
    /// A peer of high custody counts for at most `COVER_HIGH` of the type's
    /// floors that set this (the coverage floor).
    pub diverse: bool,
}

/// Per-object-type protocol parameters (`seacast.md` §1.1 `TypeParams`,
/// §6.3).
#[derive(Debug, Clone)]
pub struct TypeParams {
    /// Number of colours of the push relation (`M`, `[D10]`).
    pub m: u16,
    /// Floor of in-pushers per family and colour (`F_LO`, `[D10]`).
    pub f_lo: usize,
    /// Cap of in-pushers per family and colour (`F_HI`, `[D10]`).
    pub f_hi: usize,
    /// Target out-pushees per family and colour for normal uplinks (`D_OUT`,
    /// `[D10]`).
    pub d_out: usize,
    /// Target out-pushees per family and colour for fast uplinks (`D_OUT_FAST`,
    /// `[c17]`).
    pub d_out_fast: usize,
    /// Maximum out-pushees accepted per family and colour (`D_OUT_MAX`).
    pub d_out_max: usize,
    /// One relation both ways per family and colour, grafted and pruned with
    /// `BOTH` (`SYMMETRIC`, §4.1).
    pub symmetric: bool,
    /// The host keeps the type's relations, as a gossipsub client its topic's
    /// mesh (`seacast.md` §7), and tells the node of each change
    /// (`SeacastNode::relation_added`, `relation_removed`). The node then
    /// sends no GRAFT or PRUNE and ignores one received.
    pub host_relations: bool,
    /// Families a peer of high custody counts for in a floor that asks for
    /// diversity (`COVER_HIGH`, §1.3, `[D12]`).
    pub cover_high: usize,
    /// Announce width beyond the relation (`ANNOUNCE_EXTRA`, `[D5]`).
    pub announce_extra: AnnounceWidth,
    /// Whether chunks of this type are pushed eagerly (`EAGER`; `false` for
    /// rows).
    pub eager: bool,
    /// Whether rebuilt chunks are pushed using source per-chunk budget `R_NODE`
    /// (`REPAIR_BUDGET`, `[D4]`).
    pub repair_budget: bool,
    /// How long a peer's `claim_all` defers our own later decode duty
    /// (`DEFER_WINDOW`, `R5`, `[D4]`).
    pub defer_window: f64,
    /// Seconds from `known_at[g]` before asking against offers (`START_DELAY`,
    /// `[D8]`, `R7`).
    pub start_delay: f64,
    /// Maximum chunks served per peer and group (`SERVE_LIMIT`, `R6`).
    pub serve_limit: usize,
    /// Seconds after a PRUNE this node receives during which it does not graft
    /// that peer again for the relation the PRUNE named (`PRUNE_BACKOFF`).
    pub prune_backoff: f64,
    /// Seconds a sampler waits for a standing `Want` before retrying another
    /// peer (`SAMPLE_RETRY`, §4.10).
    pub sample_retry: f64,
    /// Seconds a sampler waits on each later peer (`SAMPLE_RETRY2`, §4.10,
    /// `[D12]`).
    pub sample_retry2: f64,
    /// Forwarding steps a sampler's routed request may take (`ROUTE_HOPS`,
    /// §4.10, `[D12]`).
    pub route_hops: u8,
    /// Routed requests passed on per asking peer and type between two calls of
    /// `SeacastNode::reset_period` (`FORWARD_LIMIT`, §4.5, X6).
    pub forward_limit: usize,
    /// Maximum `(family, colour)` relation pairs per link for this type, in
    /// any state (`MAX_RELATIONS`, `seacast.md` §4.1, §6.3).
    pub max_relations: usize,
    /// Seconds an offer's promise runs before a broken one parks the peer for
    /// the group (`PROMISE = 0.400s`, `[c5]`; per object type,
    /// `seacast.md` §6.3).
    pub promise: f64,
    /// Optional IncrementalDAS repair sampling steps `[(S_1, L_1), (S_2, L_2),
    /// ...]` (`REPAIR_SAMPLE`, `R5`).
    pub repair_sample: Option<Vec<(usize, usize)>>,
    /// Wait time in seconds before judging each repair sample step
    /// (`SAMPLE_WAIT`, `R5`).
    pub sample_wait: f64,
    /// Whether lost repair sample cells are re-asked from another custodian
    /// (`REPAIR_REASK`, `R5`).
    pub repair_reask: bool,
    /// Optional fraud-proof evidence object type (`EVIDENCE`, `[D6]`).
    pub evidence: Option<TypeId>,
    /// Most indices a group of this type has, before its count is known: a
    /// WANT's index bound (`MAX_INDICES`, `seacast.md` §4.5) and
    /// [`CapacityConfig::size_for`]'s.
    pub max_indices: u32,
    /// Most groups of this type the domain takes in one of its slots. Not in
    /// the specification: read by [`CapacityConfig::size_for`] only.
    pub max_groups_per_slot: u32,
}

impl Default for TypeParams {
    /// Tier 4 parameters (`seacast.md` §6.1).
    fn default() -> Self {
        Self {
            m: 1,
            f_lo: 6,
            f_hi: 12,
            d_out: 8,
            d_out_fast: 8,
            d_out_max: 12,
            symmetric: false,
            host_relations: false,
            cover_high: 1,
            announce_extra: AnnounceWidth::Sample,
            eager: true,
            repair_budget: false,
            defer_window: 1.0,
            start_delay: 0.0,
            serve_limit: usize::MAX,
            prune_backoff: 12.0,
            sample_retry: 2.0,
            sample_retry2: 0.5,
            route_hops: 1,
            forward_limit: 1,
            max_relations: 256,
            promise: 0.400,
            repair_sample: None,
            sample_wait: 0.0,
            repair_reask: false,
            evidence: None,
            max_indices: crate::bitmap::MAX_BITMAP_BITS as u32,
            max_groups_per_slot: 4,
        }
    }
}

/// Node-wide protocol configuration and card switches (`seacast-lite.md` §8.3,
/// `seacast.md` §6.3).
#[derive(Debug, Clone)]
pub struct NodeConfig {
    /// Base push degree (`R = 2` with erasure coding, `3` uncoded).
    pub r: usize,
    /// Fast uplink push degree (`R_FAST = 6`, `[c17]`).
    pub r_fast: usize,
    /// Threshold uplink in bits/sec for `R_FAST` (`FAST_UPLINK = 500 Mbps`,
    /// `[c17]`).
    pub fast_uplink_bps: f64,
    /// Configured node uplink in bits/sec (`UPLINK`).
    pub uplink_bps: f64,
    /// Threshold uplink in bits/sec for striped source publishing
    /// (`STRIPE_UPLINK = 1 Gbps`, `[c13]`).
    pub stripe_uplink_bps: f64,
    /// Scaling factor applied when computing byte window from uplink.
    pub window_scale: f64,
    /// Base ask window in seconds (`IWANT_WINDOW = 0.200s`, `[c5]`).
    pub iwant_window: f64,
    /// Retry slack added to `IWANT_WINDOW` (`RETRY_SLACK = 0.005s`, `[c5]`).
    pub retry_slack: f64,
    /// Uplink threshold below which `IWANT_WINDOW` stretches (`ASK_UPLINK = 50
    /// Mbps`, §4.13).
    pub ask_uplink_bps: f64,
    /// Park duration in seconds (`PARK_TTL = 30.0s`, `[c5]`).
    pub park_ttl: f64,
    /// Offer lifetime in seconds (`OFFER_TTL = 30.0s`, §8.1).
    pub offer_ttl: f64,
    /// Proof guard grace period in seconds (`GUARD_GRACE = 0.200s`, `[c16]`).
    pub guard_grace: f64,
    /// Projection fan-in factor (`FAN_IN = 2`, `[c12]`).
    pub fan_in: u32,
    /// Reference RTT in seconds for window sizing (`RTT_REF = 0.112s`,
    /// `[c14]`).
    pub rtt_ref: f64,
    /// Target queue delay in seconds for window sizing (`TARGET = 0.020s`,
    /// `[c14]`).
    pub target_delay: f64,
    /// Reference chunk size in bytes (`CHUNK_BYTES = 12_000`, `[c14]`).
    pub chunk_bytes: usize,
    /// Window slot/byte timeout in seconds (`WINDOW_TIMEOUT = 0.500s`,
    /// `[c14]`).
    pub window_timeout: f64,
    /// Heartbeat period in seconds (`HEARTBEAT = 0.700s`).
    pub heartbeat: f64,
    /// Secret of this node's HMAC-SHA-256 order of the announcers beyond an
    /// ask's list, drawn by the host at start and never sent (`seacast-lite.md`
    /// §6.1).
    pub order_key: Bytes32,
    /// Minimum non-related gossip peers (`D_LAZY = 6`).
    pub d_lazy: usize,
    /// Fraction of non-related eligible peers sampled for gossip
    /// (`GOSSIP_FACTOR = 0.25`).
    pub gossip_factor: f64,
    /// Maximum answers served per chunk ID per peer (`GOSSIP_RETRANSMISSION =
    /// 3`).
    pub gossip_retransmission: usize,
    /// Maximum offer-bearing RPCs handled immediately per peer per heartbeat
    /// (`MAX_IHAVE_MESSAGES`).
    pub max_ihave_messages: usize,
    /// Maximum asks sent in immediate reply to a peer's offers per heartbeat
    /// (`MAX_IHAVE_LENGTH`).
    pub max_ihave_length: usize,
    /// Maximum chunk ids taken per peer per heartbeat as not wanted
    /// ([`SeacastNode::note_unwanted`](crate::SeacastNode::note_unwanted)).
    pub max_unwanted_ids: usize,
    /// Chunks served to one peer's asks per heartbeat, over all groups,
    /// excluding answers on our own written offers and claim probes
    /// (`SERVE_BUDGET`, `seacast.md` §4.5, §6.3).
    pub max_served_per_heartbeat: usize,
    /// A sampler's second-phase asks in flight per scope across all sampled
    /// types (`SAMPLE_OUTSTANDING`, `seacast.md` §4.10, §6.3). At least 1.
    pub sample_outstanding: usize,
    /// Holding entry lifetime in heartbeats (`HAVE_TTL = 3`).
    pub have_ttl: u32,
    /// Push entry lifetime in heartbeats (`PUSH_TTL = 6`).
    pub push_ttl: u32,
    /// Group active lifetime in seconds after last chunk or completion
    /// (`GROUP_TTL`).
    pub group_ttl: f64,
    /// Seconds an expired group's tombstone is kept: what the group's id is
    /// refused for.
    pub tombstone_ttl: f64,
    /// Maximum pending (unauthenticated) groups tracked per peer
    /// (`MAX_PENDING_GROUPS`, §8.2).
    pub max_pending_groups: usize,
    /// Maximum asks with a tried record, and with an open promise, per peer
    /// (one group's indices). Not in the specification.
    pub max_asks_per_peer: usize,
    /// Maximum announcers in the ordered offer list per ask (`16`, §6.1, §8.2).
    pub max_offers_per_ask: usize,
    /// Maximum ordered offer lists a single peer may appear in (`256`, §6.1,
    /// §8.2).
    pub max_listed_per_peer: usize,
    /// Card 8: Cancel queued chunk if peer now holds it (`CANCEL`).
    pub cancel_enabled: bool,
    /// Card 9: Rarest-first pop from normal queue (`RAREST`).
    pub rarest_enabled: bool,
    /// Card 12: Skip unsolicited push when peer is projected to reach K
    /// (`PROJECT`).
    pub project_enabled: bool,
    /// Card 14: Congestion window enabled (`W_BYTES`).
    pub window_enabled: bool,
    /// Card 15: Paced heartbeat gossip (`PACED`).
    pub paced_gossip: bool,
    /// When a source offers its chunks (`SOURCE_OFFERS`).
    pub source_offers: SourceOffers,
    /// Card 16: Furthest-behind-first target selection with proof guard.
    pub card16_enabled: bool,
    /// Card 17: Fast uplink class uses `R_FAST`.
    pub card17_enabled: bool,
    /// Card 13: Striped publishing at source when `uplink_bps >=
    /// stripe_uplink_bps`.
    pub card13_enabled: bool,
    /// `[P4]`: Merge source holdings still waiting in the urgent queue
    /// (`MERGE_HOLDINGS`, §4.2).
    pub merge_holdings: bool,
    /// Option (`ANSWERS_FIRST`, §4.12): Send solicited answers before pushes
    /// (after own chunks).
    pub answers_first: bool,
    /// Fixed preallocation capacities for node state tables.
    pub capacities: CapacityConfig,
}

/// Fixed preallocation capacities for [`SeacastNode`](crate::SeacastNode) state
/// tables.
///
/// All collections are allocated once at initialization with these capacities;
/// protocol execution performs no heap allocation.
#[derive(Debug, Clone, Copy)]
pub struct CapacityConfig {
    /// Maximum connected peers (`64`). Every `PeerId` is below it: the
    /// per-connection records are indexed by peer id.
    pub max_peers: usize,
    /// Maximum object types (`8`).
    pub max_types: usize,
    /// Maximum active groups tracked concurrently (`256`).
    pub max_groups: usize,
    /// Of those, the groups with a chunk index past 63 (`256`): their
    /// bitmaps are kept apart from their records.
    pub max_wide_groups: usize,
    /// Maximum (peer, group) pairs with state. `max_peers * max_groups` refuses
    /// none.
    pub max_pairs: usize,
    /// Of those, the pairs of groups with more than 128 indices.
    pub max_wide_pairs: usize,
    /// Maximum stored chunks across all active groups (`4096`).
    pub max_stored_chunks: usize,
    /// Keys of the relation tables (`(type, family, colour)` with a relation,
    /// GRAFTs unanswered, backoffs) = `4096`.
    pub max_relation_keys: usize,
    /// Maximum `(group, index)` asks / offers tracked concurrently (`4096`).
    pub max_asks: usize,
    /// Maximum seen/deferred chunk IDs (`8192`).
    pub max_seen_ids: usize,
    /// Maximum deferred chunks waiting for the domain's word on their group
    /// (`1024`).
    pub max_deferred_chunks: usize,
    /// Maximum queue entries per peer lane (`512`).
    pub max_queue_entries_per_peer: usize,
    /// Maximum (peer, group) pairs with offers owed, and as many with answers
    /// owed, of the groups of more than one chunk (`4096`).
    pub max_owed_pairs: usize,
    /// Maximum groups of one chunk with an offer, and as many with an answer,
    /// owed to one peer (`256`). Past it the oldest is dropped.
    pub max_owed_single_per_peer: usize,
    /// Maximum groups with a repair sample (`256`). Past it a group asks for
    /// none.
    pub max_repair_samples: usize,
    /// Maximum parks kept of nodes not connected (`1024`).
    pub max_kept_parks: usize,
    /// Maximum (ask, peer) records in each of the tried and promise tables
    /// (`4096`).
    pub max_ask_peers: usize,
}

impl Default for CapacityConfig {
    fn default() -> Self {
        Self {
            max_peers: 64,
            max_types: 8,
            max_groups: 256,
            max_wide_groups: 256,
            max_pairs: 64 * 256,
            max_wide_pairs: 64 * 16,
            max_stored_chunks: 4096,
            max_relation_keys: 4096,
            max_asks: 4096,
            max_seen_ids: 8192,
            max_deferred_chunks: 1024,
            max_queue_entries_per_peer: 512,
            max_owed_pairs: 4096,
            max_owed_single_per_peer: 256,
            max_repair_samples: 256,
            max_kept_parks: 1024,
            max_ask_peers: 4096,
        }
    }
}

impl CapacityConfig {
    /// Sizes the tables that grow with the groups for the types a node
    /// joins: `types` gives each type's parameters with the number of types
    /// joined that have them (the subnets of a topic), and `slots` how many
    /// of the domain's slots a group lives.
    pub fn size_for<'a>(
        &mut self,
        types: impl IntoIterator<Item = (&'a TypeParams, usize)>,
        slots: usize,
    ) {
        let (mut joined, mut groups, mut wide, mut chunks) = (0, 0, 0, 0);
        for (params, count) in types {
            let of_type = count * params.max_groups_per_slot as usize * slots;
            joined += count;
            groups += of_type;
            chunks += of_type * params.max_indices as usize;
            if params.max_indices > 64 {
                wide += of_type;
            }
        }
        self.max_types = joined;
        self.max_groups = groups;
        self.max_wide_groups = wide;
        self.max_stored_chunks = chunks;
    }
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            r: 2,
            r_fast: 6,
            fast_uplink_bps: 500e6,
            uplink_bps: 50e6,
            stripe_uplink_bps: 1000e6,
            window_scale: 1.0,
            iwant_window: 0.200,
            retry_slack: 0.005,
            ask_uplink_bps: 50e6,
            park_ttl: 30.0,
            offer_ttl: 30.0,
            guard_grace: 0.200,
            fan_in: 2,
            rtt_ref: 0.112,
            target_delay: 0.020,
            chunk_bytes: 12_000,
            window_timeout: 0.500,
            heartbeat: 0.700,
            order_key: [0; 32],
            d_lazy: 6,
            gossip_factor: 0.25,
            gossip_retransmission: 3,
            max_ihave_messages: 128,
            max_ihave_length: 2 * crate::bitmap::MAX_BITMAP_BITS,
            max_unwanted_ids: 2 * crate::bitmap::MAX_BITMAP_BITS,
            max_served_per_heartbeat: 2 * crate::bitmap::MAX_BITMAP_BITS,
            sample_outstanding: 4,
            have_ttl: 3,
            push_ttl: 6,
            group_ttl: 30.0,
            tombstone_ttl: 30.0,
            max_pending_groups: 64,
            max_asks_per_peer: crate::bitmap::MAX_BITMAP_BITS,
            max_offers_per_ask: 16,
            max_listed_per_peer: 256,
            cancel_enabled: true,
            rarest_enabled: true,
            project_enabled: true,
            window_enabled: true,
            paced_gossip: true,
            source_offers: SourceOffers::Ack,
            card16_enabled: true,
            card17_enabled: true,
            card13_enabled: true,
            merge_holdings: false,
            answers_first: false,
            capacities: CapacityConfig::default(),
        }
    }
}

impl NodeConfig {
    /// Effective per-chunk push budget for this node (`R_NODE` in
    /// `seacast-lite.md` §5.2 `[c17]`).
    #[inline]
    pub fn r_node(&self) -> usize {
        if self.card17_enabled && self.uplink_bps >= self.fast_uplink_bps {
            self.r_fast
        } else {
            self.r
        }
    }

    /// Node's uplink class (`FAST` or `HOME`).
    #[inline]
    pub fn uplink_class(&self) -> UplinkClass {
        if self.card17_enabled && self.uplink_bps >= self.fast_uplink_bps {
            UplinkClass::Fast
        } else {
            UplinkClass::Home
        }
    }

    /// Ask window scaling factor (`ask_scale()` in `seacast.md` §4.13).
    #[inline]
    pub fn ask_scale(&self) -> f64 {
        (self.ask_uplink_bps / self.uplink_bps).max(1.0)
    }

    /// Effective ask window in seconds (`IWANT_WINDOW * ask_scale()`,
    /// `seacast.md` §4.13).
    #[inline]
    pub fn scaled_iwant_window(&self) -> f64 {
        self.iwant_window * self.ask_scale()
    }

    /// Node-wide congestion window in slots (`W` in `seacast-lite.md` §7.1
    /// `[c14]`).
    #[inline]
    pub fn window_slots(&self) -> usize {
        if !self.window_enabled {
            return usize::MAX;
        }
        let uplink_bytes_per_s = (self.uplink_bps * self.window_scale) / 8.0;
        let w = (uplink_bytes_per_s * (self.rtt_ref + self.target_delay) /
            (self.chunk_bytes as f64))
            .ceil() as usize;
        w.max(1)
    }

    /// Node-wide congestion window in bytes (`W_BYTES = W * CHUNK_BYTES` in
    /// `seacast.md` §4.11 `[c14, X3]`).
    #[inline]
    pub fn window_bytes(&self) -> usize {
        if !self.window_enabled {
            return usize::MAX;
        }
        self.window_slots().saturating_mul(self.chunk_bytes)
    }
}

/// Entry in `peer_has[p][g]` tracking a peer's holdings and claims
/// (`seacast.md` §3, §4.3).
#[derive(Debug, Clone, Copy, Default)]
pub struct HaveEntry {
    pub bits: Bitmap,
    pub ttl: u32,
    pub claim_all: bool,
    pub complete: bool,
}

impl HaveEntry {
    #[inline]
    pub fn has(&self, index: u32) -> bool {
        self.bits.has(index)
    }
}

/// Entry in `pushed[p][g]` tracking chunks chosen for push to a peer
/// (`seacast-lite.md` §5.2, §5.3).
#[derive(Debug, Clone, Copy, Default)]
pub struct PushEntry {
    pub bits: Bitmap,
    pub first_push: Option<Timestamp>,
    pub ttl: u32,
}

impl PushEntry {
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bits.is_empty()
    }

    #[inline]
    pub fn has(&self, index: u32) -> bool {
        self.bits.has(index)
    }

    #[inline]
    pub fn set(&mut self, index: u32) {
        self.bits.set(index);
    }

    #[inline]
    pub fn clear(&mut self, index: u32) {
        self.bits.clear(index);
    }

    #[inline]
    pub fn popcount(&self) -> u32 {
        self.bits.popcount()
    }
}
