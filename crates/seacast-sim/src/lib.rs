pub mod payload;

use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, BinaryHeap},
};

use seacast_codec::sha256;
use seacast_core::{
    AnnounceWidth, Bitmap, BoundedDeferredStore, Bytes32, ChunkBuffer, ChunkId, ChunkMsg,
    DispatchOutcome, Domain, Duty, FamilyId, ForkDigest, GroupBits, GroupId, InlineVec,
    InterestKind, Join, MAX_CHUNKS, MAX_JOINED_TYPES, MAX_PROJECTED, NodeConfig, NodeId, PeerId,
    PenaltyReason, Policy, PreallocVec, QueueEntry, RngSource, RuntimeEnv, SeacastNode, Shape,
    SplitMix64, TimerEvent, Timestamp, TypeCodec, TypeId, TypeParams, ValidationResult,
};

/// The object types of this domain.
pub const PAYLOAD: TypeId = TypeId(0);
pub const COLUMN: TypeId = TypeId(1);
pub const ROW: TypeId = TypeId(2);
/// The fork every node of a run is at.
pub const FORK_DIGEST: ForkDigest = [0; 4];

type BlockRoot = [u8; 32];

/// Virtual zero-allocation byte blob for fast discrete-event simulations
/// (`Blob` in `toy/wire.py`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimBlob {
    pub byte_len: usize,
    pub tag: u64,
}

impl ChunkBuffer for SimBlob {
    #[inline]
    fn len(&self) -> usize {
        self.byte_len
    }
}

/// Group header in the simulator (`SegmentDescriptor` or DAS Column/Row
/// header).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimHeader {
    pub block: BlockRoot,
    pub k: u32,
    pub n: u32,
    pub segment_size: usize,
    pub column: Option<u32>,
    pub row: Option<u32>,
}

/// The five `seacast.md` §6.2 settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimSetting {
    /// Setting 1: Tier 4 payload broadcast (`M = 1`, `ALL`, `FORWARD`).
    Tier4,
    /// Setting 2: Variant C independent pusher sets per colour (`M = N`, `ALL`,
    /// `FORWARD`).
    VariantC,
    /// Setting 3: PeerDAS column custody with optional supernode phase-2
    /// reconstruction.
    Custody,
    /// Setting 4: RowDAS columns + rows with cross-fill (`R4`), phased
    /// reconstruction, and claim probe (`R5`).
    Rows,
    /// Setting 5: FullDAS / PeerDAS declared-interest sampling on top of
    /// custody (`§4.10`).
    Sampling,
}

/// Configuration for a simulation scenario.
#[derive(Debug, Clone)]
pub struct SimConfig {
    pub setting: SimSetting,
    pub num_nodes: usize,
    pub seed: u64,
    pub k_chunks: u32,
    pub n_chunks: u32,
    pub chunk_size: usize,
    pub degree: usize,
    pub mesh_d: usize,
    pub custody_columns_per_node: usize,
    pub num_columns: u32,
    pub num_rows: u32,
    pub row_subnets: u32,
    pub supernodes: usize,
    pub samplers: usize,
    pub withhold_half_columns: bool,
    pub liar_nodes: usize,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            setting: SimSetting::Tier4,
            num_nodes: 24,
            seed: 7,
            k_chunks: 16,
            n_chunks: 32,
            chunk_size: 12_000,
            degree: 10,
            mesh_d: 4,
            custody_columns_per_node: 4,
            num_columns: 16,
            num_rows: 8,
            row_subnets: 4,
            supernodes: 2,
            samplers: 0,
            withhold_half_columns: false,
            liar_nodes: 0,
        }
    }
}

/// Pluggable `ObjectCatalog` implementation supporting all five
/// `seacast.md` §6.2 settings.
pub struct SimCatalog {
    pub node_id: PeerId,
    pub setting: SimSetting,
    pub payload_params: TypeParams,
    pub column_params: TypeParams,
    pub row_params: TypeParams,
    pub custody_map: BTreeMap<PeerId, BTreeSet<u32>>,
    pub row_subnet_map: BTreeMap<PeerId, u32>,
    pub supernodes: BTreeSet<PeerId>,
    pub reconstructors: BTreeSet<PeerId>,
    pub samplers: BTreeSet<PeerId>,
    pub liars: BTreeSet<PeerId>,
    pub group_headers: BTreeMap<GroupId, SimHeader>,
    pub group_col: BTreeMap<GroupId, u32>,
    pub group_row_subnet: BTreeMap<GroupId, u32>,
    pub row_groups_by_block: BTreeMap<(BlockRoot, u32), GroupId>,
    pub col_groups_by_block: BTreeMap<(BlockRoot, u32), GroupId>,
    pub canonical_chunks: BTreeMap<GroupId, BTreeMap<u32, ChunkMsg<SimBlob>>>,
    pub installed_blocks: BTreeMap<BlockRoot, Option<GroupId>>,
    pub keeps_rows: bool,
}

impl TypeCodec<SimBlob> for SimCatalog {
    fn shape(&self, chunk: &ChunkMsg<SimBlob>) -> Option<Shape> {
        self.shape_by_group(&chunk.group)
    }

    fn check(&self, chunk: &ChunkMsg<SimBlob>) -> bool {
        self.group_headers.get(&chunk.group).is_some_and(|h| chunk.index < h.n)
    }

    fn check_proof(&mut self, _chunk: &ChunkMsg<SimBlob>) -> ValidationResult {
        ValidationResult::Accept
    }

    fn header_id(&self, _chunk: &ChunkMsg<SimBlob>) -> [u8; 32] {
        [0; 32]
    }

    // A blob has no bytes: the domain looks a group's block up by its id.
    fn context<'a>(&self, _chunk: &'a ChunkMsg<SimBlob>) -> &'a [u8] {
        &[]
    }

    fn decode(
        &mut self,
        group: &GroupId,
        available: &[ChunkMsg<SimBlob>],
        shape: &Shape,
        out_rebuilt: &mut PreallocVec<ChunkMsg<SimBlob>>,
    ) -> Option<SimBlob> {
        if (available.len() as u32) < shape.k {
            return None;
        }
        let segment_size = self.group_headers.get(group)?.segment_size;
        let canonical = self.canonical_chunks.get(group)?;
        out_rebuilt.clear();
        for ch in canonical.values() {
            let _ = out_rebuilt.push(ch.clone());
        }
        Some(SimBlob { byte_len: (shape.k as usize) * segment_size, tag: 1 })
    }

    fn project(&self, chunk: &ChunkMsg<SimBlob>) -> InlineVec<(GroupId, u32), MAX_PROJECTED> {
        if (chunk.group.type_id == COLUMN || chunk.group.type_id == ROW) && self.keeps_rows {
            if let Some(&col) = self.group_col.get(&chunk.group) {
                if let Some(h) = self.group_headers.get(&chunk.group) {
                    if let Some(&g_row) = self.row_groups_by_block.get(&(h.block, chunk.index)) {
                        return InlineVec::from_slice(&[(chunk.group, chunk.index), (g_row, col)]);
                    }
                }
            }
            if let Some(h) = self.group_headers.get(&chunk.group) {
                if let Some(row_idx) = h.row {
                    if let Some(&g_col) = self.col_groups_by_block.get(&(h.block, chunk.index)) {
                        return InlineVec::from_slice(&[
                            (chunk.group, chunk.index),
                            (g_col, row_idx),
                        ]);
                    }
                }
            }
        }
        InlineVec::singleton((chunk.group, chunk.index))
    }

    fn cross(&self, group: &GroupId, index: u32) -> InlineVec<(GroupId, u32), MAX_PROJECTED> {
        if !self.keeps_rows {
            return InlineVec::new();
        }
        let Some(h) = self.group_headers.get(group) else {
            return InlineVec::new();
        };
        if group.type_id == COLUMN {
            if let Some(&col) = self.group_col.get(group) {
                if let Some(&g_row) = self.row_groups_by_block.get(&(h.block, index)) {
                    return InlineVec::singleton((g_row, col));
                }
            }
        } else if group.type_id == ROW {
            if let Some(row_idx) = h.row {
                if let Some(&g_col) = self.col_groups_by_block.get(&(h.block, index)) {
                    return InlineVec::singleton((g_col, row_idx));
                }
            }
        }
        InlineVec::new()
    }

    fn wire_size(&self, chunk: &ChunkMsg<SimBlob>, _first_of_group: bool) -> usize {
        chunk.frame.len() + 180
    }
}

impl Domain for SimCatalog {
    fn sample_scope(&self, group: &GroupId) -> GroupId {
        self.group_headers.get(group).map_or(*group, |h| GroupId::new(PAYLOAD, h.block, 0))
    }

    fn authenticate(
        &mut self,
        group: &GroupId,
        _header_id: &[u8; 32],
        _context: &[u8],
    ) -> ValidationResult {
        let installed = self
            .group_headers
            .get(group)
            .is_some_and(|h| self.installed_blocks.contains_key(&h.block));
        if group.type_id == PAYLOAD && !installed {
            ValidationResult::Defer
        } else {
            ValidationResult::Accept
        }
    }

    fn authenticable(&self, group: &GroupId) -> bool {
        if group.type_id == PAYLOAD {
            self.installed_blocks.values().any(|&bg| bg == Some(*group))
        } else {
            true
        }
    }

    fn shape_by_group(&self, group: &GroupId) -> Option<Shape> {
        self.group_headers.get(group).map(|h| Shape { n: h.n, k: h.k })
    }
}

impl Policy for SimCatalog {
    fn params(&self, t: TypeId) -> &TypeParams {
        match t {
            PAYLOAD => &self.payload_params,
            COLUMN => &self.column_params,
            ROW => &self.row_params,
            _ => &self.payload_params,
        }
    }

    fn family(&self, group: &GroupId) -> FamilyId {
        match group.type_id {
            PAYLOAD => 0,
            COLUMN => self.group_col.get(group).copied().unwrap_or(0) as FamilyId,
            ROW => self.group_row_subnet.get(group).copied().unwrap_or(0) as FamilyId,
            _ => 0,
        }
    }

    fn derived_interest(
        &self,
        group: &GroupId,
        _shape: Option<&Shape>,
        peer: PeerId,
        _node_id: &NodeId,
        _join: &Join,
    ) -> Bitmap {
        match group.type_id {
            PAYLOAD => Bitmap::EVERY_INDEX,
            COLUMN => {
                let col = self.group_col.get(group).copied().unwrap_or(u32::MAX);
                if self.custody_map.get(&peer).map(|s| s.contains(&col)).unwrap_or(false) {
                    Bitmap::EVERY_INDEX
                } else {
                    Bitmap::EMPTY
                }
            }
            ROW => {
                let sub = self.group_row_subnet.get(group).copied();
                let peer_sub = self.row_subnet_map.get(&peer).copied();
                if sub.is_some() && sub == peer_sub && !self.samplers.contains(&peer) {
                    Bitmap::EVERY_INDEX
                } else {
                    Bitmap::EMPTY
                }
            }
            _ => Bitmap::EMPTY,
        }
    }

    fn own_interest(&self, group: &GroupId) -> Bitmap {
        match group.type_id {
            PAYLOAD => Bitmap::EVERY_INDEX,
            COLUMN => {
                if self.samplers.contains(&self.node_id) {
                    return Bitmap::EMPTY;
                }
                let col = self.group_col.get(group).copied().unwrap_or(u32::MAX);
                if self.custody_map.get(&self.node_id).map(|s| s.contains(&col)).unwrap_or(false) {
                    Bitmap::EVERY_INDEX
                } else {
                    Bitmap::EMPTY
                }
            }
            ROW => {
                if self.supernodes.contains(&self.node_id) {
                    return Bitmap::EVERY_INDEX;
                }
                if self.samplers.contains(&self.node_id) {
                    return Bitmap::EMPTY;
                }
                let sub = self.group_row_subnet.get(group).copied();
                let my_sub = self.row_subnet_map.get(&self.node_id).copied();
                if sub.is_some() && sub == my_sub { Bitmap::EVERY_INDEX } else { Bitmap::EMPTY }
            }
            _ => Bitmap::EMPTY,
        }
    }

    fn our_join(&self, t: TypeId) -> Join {
        match t {
            PAYLOAD => Join {
                object_type: PAYLOAD,
                fork_digest: FORK_DIGEST,
                interest: InterestKind::All,
                custody_count: 0,
                duty: Duty::Forward,
                colours: self.payload_params.m,
            },
            COLUMN => {
                if self.samplers.contains(&self.node_id) {
                    Join {
                        object_type: COLUMN,
                        fork_digest: FORK_DIGEST,
                        interest: InterestKind::Declared,
                        custody_count: 0,
                        duty: Duty::None,
                        colours: 1,
                    }
                } else {
                    let cgc =
                        self.custody_map.get(&self.node_id).map(|s| s.len() as u64).unwrap_or(0);
                    Join {
                        object_type: COLUMN,
                        fork_digest: FORK_DIGEST,
                        interest: InterestKind::Derived,
                        custody_count: cgc,
                        duty: Duty::Forward,
                        colours: 1,
                    }
                }
            }
            ROW => {
                let no_row = self.samplers.contains(&self.node_id) ||
                    self.node_id == 1 ||
                    self.setting != SimSetting::Rows;
                Join {
                    object_type: ROW,
                    fork_digest: FORK_DIGEST,
                    interest: if no_row { InterestKind::Declared } else { InterestKind::Derived },
                    custody_count: 0,
                    duty: if no_row { Duty::None } else { Duty::Forward },
                    colours: 1,
                }
            }
            _ => unreachable!(),
        }
    }

    fn joined_types(&self) -> InlineVec<TypeId, MAX_JOINED_TYPES> {
        match self.setting {
            SimSetting::Tier4 | SimSetting::VariantC => InlineVec::singleton(PAYLOAD),
            SimSetting::Custody | SimSetting::Sampling => {
                if self.keeps_rows {
                    InlineVec::from_slice(&[COLUMN, ROW])
                } else {
                    InlineVec::singleton(COLUMN)
                }
            }
            SimSetting::Rows => InlineVec::from_slice(&[COLUMN, ROW]),
        }
    }

    fn holds_family(
        &self,
        t: TypeId,
        family: FamilyId,
        peer: PeerId,
        _node_id: &NodeId,
        _join: &Join,
    ) -> bool {
        match t {
            COLUMN => self.custody_map.get(&peer).is_some_and(|s| s.contains(&u32::from(family))),
            ROW => {
                self.row_subnet_map.get(&peer).copied() == Some(u32::from(family)) &&
                    !self.samplers.contains(&peer)
            }
            _ => true,
        }
    }

    fn families_with_duty(&self, t: TypeId) -> InlineVec<FamilyId, MAX_CHUNKS> {
        match t {
            PAYLOAD => InlineVec::singleton(0),
            COLUMN => {
                let mut fams = InlineVec::new();
                if let Some(s) = self.custody_map.get(&self.node_id) {
                    for &c in s {
                        let _ = fams.push(c as FamilyId);
                    }
                }
                fams
            }
            ROW => {
                let mut fams = InlineVec::new();
                if let Some(&sub) = self.row_subnet_map.get(&self.node_id) {
                    let _ = fams.push(sub as FamilyId);
                }
                fams
            }
            _ => InlineVec::new(),
        }
    }

    fn wants_family(&self, t: TypeId, family: FamilyId) -> bool {
        match t {
            PAYLOAD => true,
            COLUMN => {
                let family = u32::from(family);
                self.custody_map.get(&self.node_id).map(|s| s.contains(&family)).unwrap_or(false)
            }
            ROW => self.row_subnet_map.get(&self.node_id).copied() == Some(u32::from(family)),
            _ => false,
        }
    }

    fn decode_at_k(&self, group: &GroupId) -> bool {
        match group.type_id {
            PAYLOAD => true,
            COLUMN => false,
            ROW => {
                let own_row = self.row_subnet_map.get(&self.node_id).copied() ==
                    self.group_row_subnet.get(group).copied();
                self.reconstructors.contains(&self.node_id) && own_row
            }
            _ => false,
        }
    }

    fn decode_later(&mut self, group: &GroupId, rng: &mut dyn RngSource) -> Option<f64> {
        if group.type_id != ROW {
            return None;
        }
        let own_row = self.row_subnet_map.get(&self.node_id).copied() ==
            self.group_row_subnet.get(group).copied() &&
            self.row_subnet_map.contains_key(&self.node_id);
        if own_row {
            if self.liars.contains(&self.node_id) {
                None
            } else {
                Some(2.0 + rng.uniform(0.0, 0.2))
            }
        } else if self.supernodes.contains(&self.node_id) {
            Some(1.0 + rng.uniform(0.0, 0.2))
        } else {
            None
        }
    }

    fn tiebreak(&self, chunk_id: &ChunkId, peer: PeerId) -> u64 {
        // The group's key, the index and the content: the type and the group's
        // index add nothing to the order.
        let mut buf = [0u8; 64];
        buf[0..32].copy_from_slice(&chunk_id[1..33]);
        buf[32..56].copy_from_slice(&chunk_id[35..59]);
        buf[56..64].copy_from_slice(&peer.to_le_bytes());
        let h = sha256(&buf);
        u64::from_le_bytes(h[0..8].try_into().unwrap())
    }

    fn node_id(&self, peer: PeerId) -> NodeId {
        sha256(&peer.to_le_bytes())
    }
}

/// A chunk id of the binding's layout ([`ChunkId`]) with `content` in place of
/// the digest of a frame: a blob has no bytes.
fn sim_chunk_id(group: &GroupId, index: u32, content: &Bytes32) -> ChunkId {
    let mut id = [0u8; 59];
    id[0] = group.type_id.0;
    id[1..33].copy_from_slice(&group.key);
    id[33..35].copy_from_slice(&group.index.to_le_bytes());
    id[35..39].copy_from_slice(&index.to_le_bytes());
    id[39..59].copy_from_slice(&content[..20]);
    id
}

/// Scheduled discrete event in the simulator.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
enum SimAction {
    Timer(TimerEvent),
    DecodeComplete(GroupId),
    WriterRun(PeerId),
    DeliverEntry { from: PeerId, entry: QueueEntry<SimBlob> },
}

#[derive(Clone)]
struct ScheduledEvent {
    time: Timestamp,
    seq: u64,
    node: PeerId,
    action: SimAction,
}

impl PartialEq for ScheduledEvent {
    fn eq(&self, other: &Self) -> bool {
        self.time.to_bits() == other.time.to_bits() && self.seq == other.seq
    }
}

impl Eq for ScheduledEvent {}

impl PartialOrd for ScheduledEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScheduledEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .time
            .partial_cmp(&self.time)
            .unwrap_or(Ordering::Equal)
            .then_with(|| other.seq.cmp(&self.seq))
    }
}

/// Per-invocation `RuntimeEnv` adapter collecting scheduled timers and
/// callbacks.
struct SimNodeEnv {
    now: Timestamp,
    scheduled: Vec<(f64, TimerEvent)>,
    woken_writers: BTreeSet<PeerId>,
    started_decodes: Vec<GroupId>,
    delivered: Vec<(GroupId, SimBlob)>,
    unreachable_samples: Vec<(GroupId, Bitmap)>,
    penalties: Vec<(PeerId, PenaltyReason)>,
}

impl SimNodeEnv {
    fn new(now: Timestamp) -> Self {
        Self {
            now,
            scheduled: Vec::new(),
            woken_writers: BTreeSet::new(),
            started_decodes: Vec::new(),
            delivered: Vec::new(),
            unreachable_samples: Vec::new(),
            penalties: Vec::new(),
        }
    }
}

impl RuntimeEnv<SimBlob> for SimNodeEnv {
    fn now(&self) -> Timestamp {
        self.now
    }

    fn schedule_after(&mut self, delay: f64, event: TimerEvent) {
        self.scheduled.push((delay, event));
    }

    fn wake_writer(&mut self, peer: PeerId) {
        self.woken_writers.insert(peer);
    }

    fn start_decode(&mut self, group: GroupId, _job: seacast_core::DecodeJob<'_, SimBlob>) {
        self.started_decodes.push(group);
    }

    fn deliver(&mut self, group: GroupId, payload: SimBlob) {
        self.delivered.push((group, payload));
    }

    fn unreachable(&mut self, group: GroupId, bits: Bitmap) {
        self.unreachable_samples.push((group, bits));
    }

    fn penalise(&mut self, peer: PeerId, reason: PenaltyReason) {
        self.penalties.push((peer, reason));
    }
}

/// Summary and invariant check results of a simulation run
/// (`toy/invariants.py`).
#[derive(Debug, Clone)]
pub struct SimReport {
    pub chunks_published: usize,
    pub eager_pushes: usize,
    pub source_pushes: usize,
    pub repair_pushes: usize,
    pub answers_sent: usize,
    pub violations_i3: usize,
    pub violations_duty_budget: usize,
    pub violations_cross_fill: usize,
    pub incomplete_pairs: usize,
    pub penalties_recorded: usize,
    pub p50_completion_ms: f64,
    pub p99_completion_ms: f64,
}

impl SimReport {
    /// Returns `true` if all SEACAST invariants (`I3`, duty budget,
    /// cross-fill `R4`, and completion) hold.
    pub fn invariants_hold(&self) -> bool {
        self.violations_i3 == 0 &&
            self.violations_duty_budget == 0 &&
            self.violations_cross_fill == 0 &&
            self.incomplete_pairs == 0
    }
}

/// Runs a complete discrete-event simulation for the given `SimConfig` and
/// checks all protocol invariants.
pub fn run_simulation(cfg: SimConfig) -> SimReport {
    let mut master_rng = SplitMix64::new(cfg.seed);
    let n_nodes = cfg.num_nodes;

    // 1. Assign roles, custody columns, and row subnets
    let mut supernodes = BTreeSet::new();
    let mut samplers = BTreeSet::new();
    let mut reconstructors = BTreeSet::new();
    let mut liars = BTreeSet::new();
    let mut custody_map: BTreeMap<PeerId, BTreeSet<u32>> = BTreeMap::new();
    let mut row_subnet_map: BTreeMap<PeerId, u32> = BTreeMap::new();

    // Node 1 is the publisher / proposer
    let all_cols: BTreeSet<u32> = (0..cfg.num_columns).collect();
    custody_map.insert(1, all_cols.clone());

    let mut cur_id = 2u64;
    for _ in 0..cfg.supernodes {
        if cur_id <= n_nodes as u64 {
            supernodes.insert(cur_id);
            reconstructors.insert(cur_id);
            custody_map.insert(cur_id, all_cols.clone());
            cur_id += 1;
        }
    }
    for _ in 0..cfg.samplers {
        if cur_id <= n_nodes as u64 {
            samplers.insert(cur_id);
            custody_map.insert(cur_id, BTreeSet::new());
            cur_id += 1;
        }
    }
    for _ in 0..cfg.liar_nodes {
        if cur_id <= n_nodes as u64 {
            liars.insert(cur_id);
            cur_id += 1;
        }
    }

    let col_list: Vec<u32> = (0..cfg.num_columns).collect();
    for nid in 2..=(n_nodes as u64) {
        if !supernodes.contains(&nid) && !samplers.contains(&nid) {
            let mut cols: BTreeSet<u32> = BTreeSet::new();
            // Ensure every column has custodians and each node gets
            // `custody_columns_per_node`
            let base =
                ((nid as usize - 2) * cfg.custody_columns_per_node) % (cfg.num_columns as usize);
            for offset in 0..cfg.custody_columns_per_node {
                cols.insert(((base + offset) % (cfg.num_columns as usize)) as u32);
            }
            let sampled: InlineVec<u32, MAX_CHUNKS> =
                master_rng.sample_without_replacement(&col_list, cfg.custody_columns_per_node);
            for c in sampled {
                if cols.len() < cfg.custody_columns_per_node {
                    cols.insert(c);
                }
            }
            if cols.len() >= (cfg.num_columns as usize) / 2 {
                reconstructors.insert(nid);
            }
            custody_map.insert(nid, cols);
        }
        if !samplers.contains(&nid) && nid != 1 {
            let sub = ((nid - 2) as u32) % cfg.row_subnets.max(1);
            row_subnet_map.insert(nid, sub);
        }
    }

    // 2. Build canonical groups & chunks
    let block_root: BlockRoot = sha256(b"sim-block-root-1");
    let mut group_headers = BTreeMap::new();
    let mut group_col = BTreeMap::new();
    let mut group_row_subnet = BTreeMap::new();
    let mut row_groups_by_block = BTreeMap::new();
    let mut col_groups_by_block = BTreeMap::new();
    let mut canonical_chunks: BTreeMap<GroupId, BTreeMap<u32, ChunkMsg<SimBlob>>> = BTreeMap::new();
    let mut published_groups: Vec<GroupId> = Vec::new();
    let mut installed_blocks: BTreeMap<BlockRoot, Option<GroupId>> = BTreeMap::new();

    match cfg.setting {
        SimSetting::Tier4 | SimSetting::VariantC => {
            let g = GroupId::new(PAYLOAD, sha256(b"payload-group-1"), 0);
            let hdr = SimHeader {
                block: block_root,
                k: cfg.k_chunks,
                n: cfg.n_chunks,
                segment_size: cfg.chunk_size,
                column: None,
                row: None,
            };
            group_headers.insert(g, hdr.clone());
            installed_blocks.insert(block_root, Some(g));
            let mut g_chunks = BTreeMap::new();
            for i in 0..cfg.n_chunks {
                let mut id_seed = Vec::new();
                id_seed.extend_from_slice(&g.key);
                id_seed.extend_from_slice(&i.to_le_bytes());
                let digest = sha256(&id_seed);
                g_chunks.insert(i, ChunkMsg {
                    group: g,
                    index: i,
                    frame: SimBlob { byte_len: cfg.chunk_size, tag: (i as u64) + 1 },
                    cached_id: sim_chunk_id(&g, i, &digest),
                    memo: [0; 32],
                    wire_len: 0,
                });
            }
            canonical_chunks.insert(g, g_chunks);
            published_groups.push(g);
        }
        SimSetting::Custody | SimSetting::Rows | SimSetting::Sampling => {
            installed_blocks.insert(block_root, None);
            for col in 0..cfg.num_columns {
                let mut seed_bytes = b"col-group-".to_vec();
                seed_bytes.extend_from_slice(&col.to_le_bytes());
                let g = GroupId::new(COLUMN, sha256(&seed_bytes), 0);
                let hdr = SimHeader {
                    block: block_root,
                    k: cfg.num_rows,
                    n: cfg.num_rows,
                    segment_size: 2096,
                    column: Some(col),
                    row: None,
                };
                group_headers.insert(g, hdr.clone());
                group_col.insert(g, col);
                col_groups_by_block.insert((block_root, col), g);
                let mut g_chunks = BTreeMap::new();
                for row in 0..cfg.num_rows {
                    g_chunks.insert(row, ChunkMsg {
                        group: g,
                        index: row,
                        frame: SimBlob { byte_len: 2096, tag: ((col as u64) << 16) | (row as u64) },
                        cached_id: sim_chunk_id(&g, row, &[0; 32]),
                        memo: [0; 32],
                        wire_len: 0,
                    });
                }
                canonical_chunks.insert(g, g_chunks);
                let withhold = cfg.withhold_half_columns && col >= cfg.num_columns / 2;
                if !withhold {
                    published_groups.push(g);
                }
            }

            // Build row groups for cross-fill and row reconstruction
            for row in 0..cfg.num_rows {
                let mut seed_bytes = b"row-group-".to_vec();
                seed_bytes.extend_from_slice(&row.to_le_bytes());
                let g_row = GroupId::new(ROW, sha256(&seed_bytes), 0);
                let hdr = SimHeader {
                    block: block_root,
                    k: cfg.num_columns / 2,
                    n: cfg.num_columns,
                    segment_size: 2096,
                    column: None,
                    row: Some(row),
                };
                group_headers.insert(g_row, hdr);
                group_row_subnet.insert(g_row, row % cfg.row_subnets.max(1));
                row_groups_by_block.insert((block_root, row), g_row);

                let mut r_chunks = BTreeMap::new();
                for col in 0..cfg.num_columns {
                    let g_col = col_groups_by_block[&(block_root, col)];
                    let cell_chunk = canonical_chunks[&g_col][&row].clone();
                    r_chunks.insert(col, cell_chunk);
                }
                canonical_chunks.insert(g_row, r_chunks);
            }
        }
    }

    // 3. Instantiate nodes, catalogs, RNGs, and topologies
    let mut nodes: BTreeMap<PeerId, SeacastNode<SimBlob>> = BTreeMap::new();
    let mut catalogs: BTreeMap<PeerId, SimCatalog> = BTreeMap::new();
    let mut rngs: BTreeMap<PeerId, SplitMix64> = BTreeMap::new();
    let mut deferred_stores: BTreeMap<PeerId, BoundedDeferredStore> = BTreeMap::new();

    let m_colours = if cfg.setting == SimSetting::VariantC { cfg.n_chunks as u16 } else { 1 };

    for nid in 1..=(n_nodes as u64) {
        let mut node_cfg = NodeConfig::default();
        if supernodes.contains(&nid) {
            node_cfg.uplink_bps = 1000e6;
        }
        let payload_params = TypeParams { m: m_colours, ..Default::default() };

        let column_params = TypeParams {
            announce_extra: AnnounceWidth::AllJoined,
            eager: true,
            ..Default::default()
        };

        let row_params = TypeParams {
            announce_extra: AnnounceWidth::AllJoined,
            eager: false,
            // `seacast.md` §6.3: the rows' first ask and a claim's deferral, both
            // decided at one second.
            start_delay: 1.0,
            serve_limit: (cfg.num_columns / 2) as usize,
            defer_window: 1.0,
            ..Default::default()
        };

        let keeps_rows = cfg.setting == SimSetting::Rows || supernodes.contains(&nid);

        let cat = SimCatalog {
            node_id: nid,
            setting: cfg.setting,
            payload_params,
            column_params,
            row_params,
            custody_map: custody_map.clone(),
            row_subnet_map: row_subnet_map.clone(),
            supernodes: supernodes.clone(),
            reconstructors: reconstructors.clone(),
            samplers: samplers.clone(),
            liars: liars.clone(),
            group_headers: group_headers.clone(),
            group_col: group_col.clone(),
            group_row_subnet: group_row_subnet.clone(),
            row_groups_by_block: row_groups_by_block.clone(),
            col_groups_by_block: col_groups_by_block.clone(),
            canonical_chunks: canonical_chunks.clone(),
            installed_blocks: installed_blocks.clone(),
            keeps_rows,
        };
        nodes.insert(nid, SeacastNode::new(node_cfg));
        catalogs.insert(nid, cat);
        rngs.insert(nid, SplitMix64::new((cfg.seed << 20) ^ nid));
        deferred_stores.insert(nid, BoundedDeferredStore::default());
    }

    // Connect all nodes in a connected graph and set up push relations
    for i in 1..=(n_nodes as u64) {
        for j in 1..=(n_nodes as u64) {
            if i == j {
                continue;
            }
            let cat_i = &catalogs[&i];
            let cat_j = &catalogs[&j];
            let node_i = nodes.get_mut(&i).unwrap();
            let mut dummy_env = SimNodeEnv::new(0.0);
            node_i.connect_peer(j, false, &mut dummy_env, cat_i);
            for t in [PAYLOAD, COLUMN, ROW] {
                let slot = node_i.slots.get_mut(j).expect("connected");
                let _ = slot.join_sent.insert(t, cat_i.our_join(t));
                let _ = slot.join_recv.insert(t, cat_j.our_join(t));
                node_i.relink(j, t);
            }
        }
    }

    // Configure push relations per setting
    match cfg.setting {
        SimSetting::Tier4 | SimSetting::VariantC => {
            for i in 1..=(n_nodes as u64) {
                for c in 0..m_colours {
                    for offset in 1..=cfg.mesh_d {
                        let peer =
                            ((i as usize - 1 + offset + (c as usize) * 3) % n_nodes + 1) as u64;
                        if peer != i {
                            nodes.get_mut(&i).unwrap().push_out.insert((peer, PAYLOAD, 0, c));
                            nodes.get_mut(&i).unwrap().push_in.insert((peer, PAYLOAD, 0, c));
                            nodes.get_mut(&peer).unwrap().push_out.insert((i, PAYLOAD, 0, c));
                            nodes.get_mut(&peer).unwrap().push_in.insert((i, PAYLOAD, 0, c));
                        }
                    }
                }
            }
        }
        SimSetting::Custody | SimSetting::Rows | SimSetting::Sampling => {
            // Mesh per column among its custodians (plus proposer node 1)
            for col in 0..cfg.num_columns {
                let custodians: Vec<PeerId> = (1..=(n_nodes as u64))
                    .filter(|&nid| custody_map.get(&nid).map(|s| s.contains(&col)).unwrap_or(false))
                    .collect();
                for &u in &custodians {
                    for &v in &custodians {
                        if u != v {
                            nodes.get_mut(&u).unwrap().push_out.insert((
                                v,
                                COLUMN,
                                col as FamilyId,
                                0,
                            ));
                            nodes.get_mut(&u).unwrap().push_in.insert((
                                v,
                                COLUMN,
                                col as FamilyId,
                                0,
                            ));
                        }
                    }
                }
            }
            if cfg.setting == SimSetting::Rows {
                for sub in 0..cfg.row_subnets {
                    let members: Vec<PeerId> = (2..=(n_nodes as u64))
                        .filter(|&nid| row_subnet_map.get(&nid).copied() == Some(sub))
                        .collect();
                    for &u in &members {
                        for &v in &members {
                            if u != v {
                                nodes.get_mut(&u).unwrap().push_out.insert((
                                    v,
                                    ROW,
                                    sub as FamilyId,
                                    0,
                                ));
                                nodes.get_mut(&u).unwrap().push_in.insert((
                                    v,
                                    ROW,
                                    sub as FamilyId,
                                    0,
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    // 4. Event loop state & invariant counters
    let mut heap: BinaryHeap<ScheduledEvent> = BinaryHeap::new();
    let mut seq_counter: u64 = 0;
    let mut schedule = |heap: &mut BinaryHeap<ScheduledEvent>,
                        time: Timestamp,
                        node: PeerId,
                        action: SimAction| {
        seq_counter += 1;
        heap.push(ScheduledEvent { time, seq: seq_counter, node, action });
    };

    // Schedule initial heartbeats
    for nid in 1..=(n_nodes as u64) {
        schedule(&mut heap, 0.700, nid, SimAction::Timer(TimerEvent::Heartbeat));
    }

    // Publish all published_groups at t = 0.0 on node 1
    let mut chunks_published = 0usize;
    {
        let mut env = SimNodeEnv::new(0.0);
        let node1 = nodes.get_mut(&1).unwrap();
        let cat1 = catalogs.get(&1).unwrap();
        let rng1 = rngs.get_mut(&1).unwrap();
        for &g in &published_groups {
            let hdr = group_headers[&g].clone();
            let shards: Vec<ChunkMsg<SimBlob>> = canonical_chunks[&g].values().cloned().collect();
            chunks_published += shards.len();
            node1.publish(g, Shape { n: hdr.n, k: hdr.k }, &shards, &mut env, cat1, rng1);
        }
        for (delay, ev) in env.scheduled {
            schedule(&mut heap, delay, 1, SimAction::Timer(ev));
        }
        for p in env.woken_writers {
            schedule(&mut heap, 0.0, 1, SimAction::WriterRun(p));
        }
    }

    // If RowDAS or supernodes exist, open row groups on interested nodes at t = 0.0
    // so known_at is 0.0
    if cfg.setting == SimSetting::Rows || !supernodes.is_empty() {
        for (&(_, _), &g_row) in &row_groups_by_block {
            let hdr = group_headers[&g_row].clone();
            for nid in 2..=(n_nodes as u64) {
                let cat = &catalogs[&nid];
                if !cat.keeps_rows {
                    continue;
                }
                let want = cat.own_interest(&g_row);
                if !want.is_empty() {
                    let node = nodes.get_mut(&nid).unwrap();
                    if node.groups.open(g_row, ROW) {
                        let rec = node.groups.rec(g_row);
                        rec.hdr = Some(Shape { n: hdr.n, k: hdr.k });
                        rec.state = Some(seacast_core::GroupState::Collecting);
                        rec.known_at = Some(0.0);
                        node.groups.put_bits(g_row, GroupBits::Interest, want);
                    }
                }
            }
        }
    }

    // If Sampling setting, samplers declare standing Wants at t = 0.0
    let mut declared_samples: BTreeMap<(PeerId, GroupId), Bitmap> = BTreeMap::new();
    if cfg.setting == SimSetting::Sampling {
        for &sid in &samplers {
            let mut env = SimNodeEnv::new(0.0);
            let node = nodes.get_mut(&sid).unwrap();
            let cat = catalogs.get(&sid).unwrap();
            let rng = rngs.get_mut(&sid).unwrap();
            for col in 0..4u32.min(cfg.num_columns) {
                let g_col = col_groups_by_block[&(block_root, col)];
                let bits = Bitmap::singleton(0) | Bitmap::singleton(1);
                declared_samples.insert((sid, g_col), bits);
                node.sample(g_col, bits, &mut env, cat, rng);
            }
            for (delay, ev) in env.scheduled {
                schedule(&mut heap, delay, sid, SimAction::Timer(ev));
            }
            for p in env.woken_writers {
                schedule(&mut heap, 0.0, sid, SimAction::WriterRun(p));
            }
        }
    }

    let mut eager_pushes: BTreeMap<(PeerId, GroupId, u32), usize> = BTreeMap::new();
    let mut source_pushes: BTreeMap<(PeerId, GroupId, u32), usize> = BTreeMap::new();
    let mut repair_pushes = 0usize;
    let mut answers_sent = 0usize;
    let mut violations_i3 = 0usize;
    let mut penalties_recorded = 0usize;
    let mut completion_times: BTreeMap<(PeerId, GroupId), Timestamp> = BTreeMap::new();

    // 5. Run discrete event loop up to 8.0 simulated seconds
    while let Some(ev) = heap.pop() {
        if ev.time > 8.0 {
            break;
        }
        let now = ev.time;
        let nid = ev.node;
        let mut env = SimNodeEnv::new(now);

        match ev.action {
            SimAction::Timer(timer_ev) => {
                let is_hb = timer_ev == TimerEvent::Heartbeat;
                {
                    let node = nodes.get_mut(&nid).unwrap();
                    let cat = catalogs.get_mut(&nid).unwrap();
                    let rng = rngs.get_mut(&nid).unwrap();
                    let def_store = deferred_stores.get_mut(&nid).unwrap();
                    node.on_timer(timer_ev, &mut env, cat, rng, def_store);
                }
                if is_hb && now + 0.700 <= 8.0 {
                    schedule(&mut heap, now + 0.700, nid, SimAction::Timer(TimerEvent::Heartbeat));
                }
            }
            SimAction::DecodeComplete(g) => {
                let node = nodes.get_mut(&nid).unwrap();
                let cat = catalogs.get_mut(&nid).unwrap();
                let rng = rngs.get_mut(&nid).unwrap();
                node.decode_group(g, &mut env, cat, rng);
            }
            SimAction::WriterRun(peer) => {
                loop {
                    let outcome = {
                        let node = nodes.get_mut(&nid).unwrap();
                        let cat = catalogs.get(&nid).unwrap();
                        node.next_to_send(peer, &mut env, cat)
                    };
                    match outcome {
                        DispatchOutcome::Send(mut entry) => {
                            // Liar fault simulation: a liar node claims all cells of its row on its
                            // first holding and never answers asks
                            // (`toy/node.py` `--fault claim`).
                            if liars.contains(&nid) {
                                for h in entry.haves.as_mut_slice() {
                                    if !h.offer && h.group.type_id == ROW {
                                        h.bits = Bitmap::all_bits(cfg.num_columns);
                                        h.claim_all = true;
                                        h.complete = true;
                                    }
                                }
                                if entry.solicited {
                                    entry.chunk = None;
                                }
                            }
                            if entry.is_empty() {
                                continue;
                            }

                            // Check I3 and duty budget on transmitted chunks
                            if let Some(ref ch) = entry.chunk {
                                let g = ch.group;
                                let idx = ch.index;
                                let rcv_cat = &catalogs[&peer];
                                let rcv_node = &nodes[&peer];
                                let wants_primary = if samplers.contains(&peer) {
                                    declared_samples
                                        .get(&(peer, g))
                                        .map(|b| b.has(idx))
                                        .unwrap_or(false)
                                } else {
                                    rcv_node
                                        .groups
                                        .bits(&g, GroupBits::Interest)
                                        .unwrap_or_else(|| rcv_cat.own_interest(&g))
                                        .has(idx)
                                };
                                let wants_cross = rcv_cat.project(ch).iter().any(|&(g2, i2)| {
                                    rcv_node
                                        .groups
                                        .bits(&g2, GroupBits::Interest)
                                        .unwrap_or_else(|| rcv_cat.own_interest(&g2))
                                        .has(i2)
                                });
                                // I3 binds pushes. An answer was asked for: a forwarder's, to
                                // its WANT for a routed request, is outside its interest (§4.5).
                                if !entry.solicited && !wants_primary && !wants_cross {
                                    violations_i3 += 1;
                                }

                                let sender_node = &nodes[&nid];
                                if entry.solicited {
                                    answers_sent += 1;
                                } else if sender_node
                                    .groups
                                    .bits(&g, GroupBits::Rebuilt)
                                    .map(|b| b.has(idx))
                                    .unwrap_or(false)
                                {
                                    repair_pushes += 1;
                                } else if !sender_node
                                    .groups
                                    .bits(&g, GroupBits::Received)
                                    .map(|b| b.has(idx))
                                    .unwrap_or(false)
                                {
                                    *source_pushes.entry((nid, g, idx)).or_insert(0) += 1;
                                } else {
                                    *eager_pushes.entry((nid, g, idx)).or_insert(0) += 1;
                                }
                            }

                            let link_delay = 0.025 +
                                ((nid.wrapping_mul(17) ^ peer.wrapping_mul(31)) % 20) as f64 *
                                    0.001;
                            schedule(&mut heap, now + link_delay, peer, SimAction::DeliverEntry {
                                from: nid,
                                entry,
                            });
                        }
                        DispatchOutcome::Wait | DispatchOutcome::Empty => break,
                    }
                }
            }
            SimAction::DeliverEntry { from, entry } => {
                let rpc = entry.into_rpc();
                let node = nodes.get_mut(&nid).unwrap();
                let cat = catalogs.get_mut(&nid).unwrap();
                let rng = rngs.get_mut(&nid).unwrap();
                let def_store = deferred_stores.get_mut(&nid).unwrap();
                node.on_frame(from, rpc, &mut env, cat, rng, def_store);

                // Record completion timestamps when `stop_pull[g]` becomes true
                for (g, rec) in node.groups.iter() {
                    if rec.stop_pull == Some(true) && !completion_times.contains_key(&(nid, *g)) {
                        completion_times.insert((nid, *g), now);
                    }
                }
            }
        }

        penalties_recorded += env.penalties.len();
        for (delay, tev) in env.scheduled {
            schedule(&mut heap, now + delay, nid, SimAction::Timer(tev));
        }
        for p in env.woken_writers {
            schedule(&mut heap, now, nid, SimAction::WriterRun(p));
        }
        for g in env.started_decodes {
            schedule(&mut heap, now + 0.005, nid, SimAction::DecodeComplete(g));
        }
    }

    // 6. Verify invariants: Duty budget, Cross-fill (R4), and Completion
    let mut violations_duty_budget = 0usize;
    for (&(nid, _, _), &count) in &eager_pushes {
        if count > nodes[&nid].config.r_node() {
            violations_duty_budget += 1;
        }
    }
    for (&(nid, _, _), &count) in &source_pushes {
        if count > nodes[&nid].config.r {
            violations_duty_budget += 1;
        }
    }

    let mut violations_cross_fill = 0usize;
    if cfg.setting == SimSetting::Rows {
        for nid in 2..=(n_nodes as u64) {
            let node = &nodes[&nid];
            for (&(_, _), &g_row) in &row_groups_by_block {
                for (&(ref g_r, col_idx), ch) in node.chunks.iter() {
                    if g_r == &g_row {
                        let g_col = col_groups_by_block[&(block_root, col_idx)];
                        let mirrored = node.chunks.contains_key(&(g_col, ch.index));
                        if !mirrored {
                            violations_cross_fill += 1;
                        }
                    }
                }
            }
        }
    }

    let mut incomplete_pairs = 0usize;
    let mut times_ms: Vec<f64> = Vec::new();
    for nid in 2..=(n_nodes as u64) {
        let node = &nodes[&nid];
        let cat = &catalogs[&nid];
        for &g in group_headers.keys() {
            let t = g.type_id;
            if t == ROW && cfg.setting != SimSetting::Rows {
                continue;
            }
            let want = if samplers.contains(&nid) {
                declared_samples.get(&(nid, g)).cloned().unwrap_or(Bitmap::EMPTY)
            } else if supernodes.contains(&nid) && t == ROW {
                // Supernodes keep rows internally for phase-2 repair; their external custody is
                // columns
                continue;
            } else {
                cat.own_interest(&g)
            };
            if want.is_empty() {
                continue;
            }
            if !node.interest_satisfied(&g, cat) {
                incomplete_pairs += 1;
            } else if let Some(&t_done) = completion_times.get(&(nid, g)) {
                times_ms.push(t_done * 1000.0);
            }
        }
    }
    times_ms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let p50 = if times_ms.is_empty() { 0.0 } else { times_ms[times_ms.len() / 2] };
    let p99 = if times_ms.is_empty() {
        0.0
    } else {
        times_ms[((times_ms.len() * 99) / 100).min(times_ms.len() - 1)]
    };

    SimReport {
        chunks_published,
        eager_pushes: eager_pushes.values().sum(),
        source_pushes: source_pushes.values().sum(),
        repair_pushes,
        answers_sent,
        violations_i3,
        violations_duty_budget,
        violations_cross_fill,
        incomplete_pairs,
        penalties_recorded,
        p50_completion_ms: p50,
        p99_completion_ms: p99,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setting_tier4_payload() {
        let cfg = SimConfig { setting: SimSetting::Tier4, ..SimConfig::default() };
        let report = run_simulation(cfg);
        assert!(report.invariants_hold(), "Tier4 report: {:?}", report);
        assert!(report.p50_completion_ms > 0.0);
    }

    #[test]
    fn test_setting_variant_c_coloured_relations() {
        let cfg = SimConfig { setting: SimSetting::VariantC, ..SimConfig::default() };
        let report = run_simulation(cfg);
        assert!(report.invariants_hold(), "VariantC report: {:?}", report);
    }

    #[test]
    fn test_setting_peerdas_custody_with_withheld_columns_and_supernodes() {
        let cfg = SimConfig {
            setting: SimSetting::Custody,
            withhold_half_columns: true,
            supernodes: 2,
            ..SimConfig::default()
        };
        let report = run_simulation(cfg);
        assert!(report.invariants_hold(), "Custody withheld report: {:?}", report);
        assert!(report.repair_pushes > 0);
    }

    #[test]
    fn test_setting_rowdas_with_liar_claim_probe_and_cross_fill() {
        let cfg = SimConfig {
            setting: SimSetting::Rows,
            withhold_half_columns: true,
            supernodes: 1,
            liar_nodes: 2,
            ..SimConfig::default()
        };
        let report = run_simulation(cfg);
        assert!(report.invariants_hold(), "RowDAS report: {:?}", report);
        assert!(
            report.penalties_recorded > 0,
            "Liar false claims must be detected by probe and penalised"
        );
    }

    #[test]
    fn test_setting_fulldas_sampling() {
        let cfg = SimConfig { setting: SimSetting::Sampling, samplers: 4, ..SimConfig::default() };
        let report = run_simulation(cfg);
        assert!(report.invariants_hold(), "Sampling report: {:?}", report);
        assert!(report.answers_sent >= 4 * 4 * 2);
    }
}
