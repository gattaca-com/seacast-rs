use crate::{
    bitmap::{Bitmap, MAX_BITMAP_BITS},
    collections::{
        InlineVec, MAX_ENTRY_CONTROL, MAX_INLINE_OFFERS, PeerSets, PeerSlab, PreallocDeque,
        PreallocMap, PreallocSet, PreallocVec,
    },
    message::{ChunkMsg, Control, Join, Queued, Rpc, Want},
    queue::SendQueues,
    state::{
        AskPeers, GossipHistory, GroupBits, Groups, MAX_GOSSIP_GROUPS, Pairs, Peer, PushCand,
        Relations,
    },
    traits::{ChunkBuffer, DeferredStore, ObjectCatalog, RngSource, RuntimeEnv, TimerEvent},
    types::{
        Ask, ChunkId, Colour, FamilyId, GenerationPeerId, GroupId, GroupState, NodeConfig, NodeId,
        PeerId, Timestamp, TypeId,
    },
};

/// A paced gossip send: the peer, the groups and indices, and when it is due.
pub type PacedGossip =
    (GenerationPeerId, InlineVec<(GroupId, Bitmap), MAX_GOSSIP_GROUPS>, Timestamp);

/// Standalone `sans-io` state machine for a SEACAST node (`seacast.md` +
/// `seacast-lite.md` v0.8).
///
/// All state tables are preallocated with fixed capacities in
/// [`SeacastNode::new`]. Protocol execution performs **no heap allocation**;
/// all external resources (I/O, timers, randomness, buffer allocation, deferred
/// chunk storage, and object verification) are injected via traits.
pub struct SeacastNode<B> {
    pub config: NodeConfig,

    /// The per-peer send queues and the byte window (`seacast.md` §4.11,
    /// §4.12).
    pub sends: SendQueues,

    // Connected peers in deterministic registration order
    pub peers: PreallocVec<PeerId>,
    /// A record a connection, indexed by `PeerId`: the host keeps peer ids
    /// below `max_peers`.
    pub slots: PeerSlab<Peer>,
    /// The parks of a node whose connection closed, until their end: a
    /// `PeerId` is a connection's, and a park outlives it (`seacast-lite.md`
    /// §8.1).
    pub kept_parks: PreallocMap<(NodeId, GroupId), Timestamp>,

    // Per link and object type (`seacast.md` §3)
    pub push_out: Relations,
    pub push_in: Relations,
    /// The peers linked for each type: both JOINs have crossed (`links(T)`).
    pub(crate) linked: PeerSets<TypeId>,
    /// Our GRAFTs not yet answered: "push me" and "I will push you". They count
    /// for nothing until the peer's yes (`seacast.md` §4.1).
    pub grafted_in: PreallocSet<(PeerId, TypeId, FamilyId, Colour)>,
    pub grafted_out: PreallocSet<(PeerId, TypeId, FamilyId, Colour)>,
    /// Until when a relation a peer's PRUNE ended is not grafted again; `true`
    /// for our "push me" (`backoff`).
    pub backoff: PreallocMap<(PeerId, TypeId, FamilyId, Colour, bool), Timestamp>,

    // Per group state (`seacast.md` §3, `seacast-lite.md` §8.1)
    /// Per group state (`seacast.md` §3, `seacast-lite.md` §8.1), a record a
    /// group.
    pub groups: Groups,
    pub chunks: PreallocMap<(GroupId, u32), ChunkMsg<B>>,
    pub known_id: PreallocMap<(GroupId, u32), ChunkId>,
    /// Until when each expired group is kept out.
    pub tombstones: PreallocMap<GroupId, Timestamp>,

    // Per peer and group diffusion state (`seacast.md` §3)
    /// `peer_has`, `pushed`, `sent_to`, `served`, `want_p`, `offered` and
    /// `park`, a record a pair.
    pub pairs: Pairs,
    /// The peers known to hold each chunk.
    pub holders: PeerSets<(GroupId, u32)>,
    pub serve_count: PreallocMap<(PeerId, ChunkId), usize>,
    pub unwanted: PreallocSet<(PeerId, ChunkId)>,
    pub standing: PeerSets<(GroupId, u32)>,
    /// The ids answered in the frame `on_want` handles, with each answer's
    /// position: an id is answered once a frame (§4.5).
    pub(crate) frame_ids: PreallocMap<ChunkId, usize>,
    /// Peers whose standing request for a chunk was routed (`seacast.md` §4.5
    /// `routed_standing`).
    pub routed_standing: PeerSets<(GroupId, u32)>,
    /// The peers that claim each group whole (`claims`).
    pub claims: PeerSets<GroupId>,

    // Pull discipline, offer ledger, promises, and parking (`seacast-lite.md` §6.1, §8.1)
    pub offers: PreallocMap<Ask, InlineVec<PeerId, MAX_INLINE_OFFERS>>,
    pub tried: AskPeers<Timestamp>,
    pub asked_at: PreallocMap<Ask, Timestamp>,
    pub promises: AskPeers<u64>,
    pub asked_parked: PeerSets<(GroupId, u32)>,
    pub last_resort_armed: PreallocSet<(GroupId, u32)>,
    pub retry_armed: PreallocSet<Ask>,
    pub held_back: PreallocMap<(GroupId, u32), Ask>,
    /// Groups with offers taken in over the IHAVE limits: their asks are the
    /// next heartbeat's.
    pub(crate) held_groups: PreallocSet<GroupId>,
    /// The groups one heartbeat ends, while their state is removed in one pass
    /// a table.
    pub(crate) expiring: PreallocSet<GroupId>,

    // Claims, deferral, probe, and IncrementalDAS repair sampling (`seacast.md` §3, §4.6)
    pub probe_asks: PreallocSet<Ask>,
    /// As a claimant still decoding: the first marked ask per asker and group
    /// of an index we claim and have not stored, answered when it is
    /// (`probe_waiting`, `seacast.md` §4.6). By chunk, and by asker and
    /// group; an entry is in both or neither.
    pub probe_waiting: PeerSets<(GroupId, u32)>,
    pub probe_waiting_of: PreallocMap<(PeerId, GroupId), u32>,
    /// As a claimant: answers to probes, by the chunk's own group and index,
    /// until they are written (`seacast.md` §4.6 `probe_answers`).
    pub probe_answers: PreallocSet<(PeerId, GroupId, u32)>,
    /// The peers asked for a sample, by the sample's scope, one each, until
    /// the time kept (`seacast.md` §4.10 `sampled_from`, I6).
    pub sampled_from: PreallocMap<(GroupId, PeerId), Timestamp>,
    /// Second-phase sample asks waiting, by scope (`samples_in_flight`).
    pub samples_in_flight: PreallocMap<GroupId, usize>,
    /// Samples held back by `SAMPLE_OUTSTANDING`: scope, group, index
    /// (`held_samples`).
    pub held_samples: PreallocDeque<(GroupId, GroupId, u32)>,
    /// Routed requests of a node passed on per type since `reset_period`
    /// (`seacast.md` §4.5 `forwarded`, X6). By node, so that connecting again
    /// does not reset the count.
    pub forwarded: PreallocMap<(NodeId, TypeId), usize>,
    /// As a source: the pushes planned at `publish` that were not made, and so
    /// are owed. With the pushes made, the plan (`seacast.md` §4.7
    /// `planned`): whom a chunk is not offered at its acknowledgement.
    pub plan_refused: PreallocSet<(PeerId, GroupId, u32)>,
    pub rsample_asked: PreallocSet<(GroupId, u32, PeerId)>,
    /// The indices asked for as a group's repair sample (`rsample`), of the
    /// groups that have one.
    pub rsamples: PreallocMap<GroupId, InlineVec<u32, MAX_BITMAP_BITS>>,

    // Gate deferral & equivocation ties (`seacast-lite.md` §4.2)
    pub seen_ids: PreallocSet<ChunkId>,
    /// Chunks waiting for the domain's word on their group, with when each
    /// is dropped.
    pub pending: PreallocVec<(Timestamp, PeerId, ChunkMsg<B>)>,
    pub pending_ids: PreallocSet<ChunkId>,
    /// Chunks that passed the inline checks, for the host to verify, and their
    /// ids until the verdict is in: a second copy meanwhile is not verified
    /// again.
    pub(crate) unverified: PreallocDeque<(GenerationPeerId, ChunkMsg<B>)>,
    pub verifying: PreallocSet<ChunkId>,
    /// A probed claimant whose copy came while another's was being verified:
    /// it answers the probe at the verdict.
    pub(crate) verifying_claimant: PreallocMap<ChunkId, GenerationPeerId>,
    pub tied: PreallocMap<(PeerId, GroupId), Bitmap>,
    /// `tied` by peer and group, over every root, and the number of ties of
    /// each peer: what the per-index and per-chunk checks read.
    pub(crate) tied_bits: PreallocMap<(PeerId, GroupId), Bitmap>,
    /// Groups without a header that a peer has named in HAVEs/offers, with the
    /// heartbeats each has left (`MAX_PENDING_GROUPS`, `seacast-lite.md` §8.2).
    pub(crate) named: PreallocMap<(PeerId, GroupId), u32>,
    /// Unknown groups a peer has named in WANTs, counted apart from `named`,
    /// with the time each place ends (`seacast.md` §4.5 `admitted_group`).
    pub(crate) wanted_groups: PreallocMap<(PeerId, GroupId), u64>,

    pub gossip_history: GossipHistory,
    pub pace_queue: PreallocDeque<PacedGossip>,
    pub pace_timer_active: bool,

    /// Scratch for a set of peers that is ordered or sampled: room for every
    /// peer. Taken out of the node while in use.
    pub(crate) peer_scratch: PreallocVec<PeerId>,
    /// A second such scratch, for an order made anew from the first.
    pub(crate) shuffle_scratch: PreallocVec<PeerId>,
    /// The mark of the pass in progress over peers (`Peer::mark`).
    pub(crate) mark: u64,
    /// Scratch for the candidates of a push while they are ordered.
    pub(crate) push_scratch: PreallocVec<PushCand>,

    // Preallocated scratch buffers for Level 2 decode (`decode_group`)
    pub(crate) decode_in_scratch: PreallocVec<ChunkMsg<B>>,
    pub(crate) decode_out_scratch: PreallocVec<ChunkMsg<B>>,
}

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Creates a new SEACAST node state machine and preallocates all
    /// fixed-capacity state tables.
    pub fn new(config: NodeConfig) -> Self {
        let cap = &config.capacities;
        let peer_asks = cap.max_peers * 64;

        Self {
            peers: PreallocVec::with_capacity(cap.max_peers),
            slots: PeerSlab::with_capacity(cap.max_peers, || Peer::with_capacity(cap.max_types)),
            kept_parks: PreallocMap::with_capacity(cap.max_kept_parks),
            push_out: Relations::with_capacity(cap.max_relation_keys, cap.max_peers),
            push_in: Relations::with_capacity(cap.max_relation_keys, cap.max_peers),
            linked: PeerSets::with_capacity(cap.max_types, cap.max_peers),
            grafted_in: PreallocSet::with_capacity(cap.max_relation_keys),
            grafted_out: PreallocSet::with_capacity(cap.max_relation_keys),
            backoff: PreallocMap::with_capacity(cap.max_relation_keys),
            groups: Groups::with_capacity(cap.max_groups, cap.max_wide_groups),
            chunks: PreallocMap::with_capacity(cap.max_stored_chunks),
            known_id: PreallocMap::with_capacity(cap.max_stored_chunks),
            tombstones: PreallocMap::with_capacity(cap.max_groups),
            pairs: Pairs::with_capacity(
                cap.max_pairs,
                cap.max_wide_pairs,
                cap.max_pairs.min(cap.max_groups + cap.max_peers * config.max_pending_groups),
                cap.max_peers,
            ),
            holders: PeerSets::with_capacity(cap.max_stored_chunks, cap.max_peers),
            serve_count: PreallocMap::with_capacity(cap.max_seen_ids),
            unwanted: PreallocSet::with_capacity(cap.max_seen_ids),
            standing: PeerSets::with_capacity(cap.max_asks, cap.max_peers),
            frame_ids: PreallocMap::with_capacity(MAX_BITMAP_BITS),
            routed_standing: PeerSets::with_capacity(cap.max_asks, cap.max_peers),
            claims: PeerSets::with_capacity(cap.max_groups, cap.max_peers),
            offers: PreallocMap::with_capacity(cap.max_asks),
            tried: AskPeers::with_capacity(
                cap.max_ask_peers,
                config.max_asks_per_peer,
                cap.max_peers,
            ),
            asked_at: PreallocMap::with_capacity(cap.max_asks),
            promises: AskPeers::with_capacity(
                cap.max_ask_peers,
                config.max_asks_per_peer,
                cap.max_peers,
            ),
            asked_parked: PeerSets::with_capacity(cap.max_asks, cap.max_peers),
            last_resort_armed: PreallocSet::with_capacity(cap.max_asks),
            retry_armed: PreallocSet::with_capacity(cap.max_asks),
            held_back: PreallocMap::with_capacity(cap.max_asks),
            held_groups: PreallocSet::with_capacity(2 * cap.max_groups),
            expiring: PreallocSet::with_capacity(2 * cap.max_groups),
            probe_asks: PreallocSet::with_capacity(cap.max_groups),
            probe_waiting: PeerSets::with_capacity(cap.max_groups, cap.max_peers),
            probe_waiting_of: PreallocMap::with_capacity(cap.max_groups),
            probe_answers: PreallocSet::with_capacity(cap.max_groups),
            sampled_from: PreallocMap::with_capacity(cap.max_asks),
            samples_in_flight: PreallocMap::with_capacity(cap.max_groups),
            held_samples: PreallocDeque::with_capacity(cap.max_asks),
            forwarded: PreallocMap::with_capacity(cap.max_peers * cap.max_types),
            plan_refused: PreallocSet::with_capacity(cap.max_stored_chunks),
            rsample_asked: PreallocSet::with_capacity(peer_asks),
            rsamples: PreallocMap::with_capacity(cap.max_repair_samples),
            seen_ids: PreallocSet::with_capacity(cap.max_seen_ids),
            pending: PreallocVec::with_capacity(cap.max_deferred_chunks),
            pending_ids: PreallocSet::with_capacity(cap.max_deferred_chunks),
            unverified: PreallocDeque::with_capacity(cap.max_deferred_chunks),
            verifying: PreallocSet::with_capacity(cap.max_deferred_chunks),
            verifying_claimant: PreallocMap::with_capacity(cap.max_deferred_chunks),
            tied: PreallocMap::with_capacity(cap.max_deferred_chunks),
            tied_bits: PreallocMap::with_capacity(cap.max_deferred_chunks),
            named: PreallocMap::with_capacity(cap.max_peers * config.max_pending_groups),
            wanted_groups: PreallocMap::with_capacity(cap.max_peers * config.max_pending_groups),
            gossip_history: GossipHistory::with_capacity(6, 3, cap.max_groups),
            pace_queue: PreallocDeque::with_capacity(cap.max_peers * 4),
            pace_timer_active: false,
            peer_scratch: PreallocVec::with_capacity(cap.max_peers),
            shuffle_scratch: PreallocVec::with_capacity(cap.max_peers),
            mark: 0,
            push_scratch: PreallocVec::with_capacity(cap.max_peers),
            decode_in_scratch: PreallocVec::with_capacity(MAX_BITMAP_BITS),
            decode_out_scratch: PreallocVec::with_capacity(MAX_BITMAP_BITS),
            sends: SendQueues::new(config.clone()),
            config,
        }
    }

    // =========================================================================
    // Connection & Link Management (§1.3, §4.1, §8.1)
    // =========================================================================

    /// Registers a newly connected peer and optionally sends our initial `Join`
    /// declarations.
    pub fn connect_peer<E, C>(&mut self, peer: PeerId, send_joins: bool, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if self.slots.open(peer) {
            let _ = self.peers.push(peer);
        }
        self.sends.connect(peer);
        // The node's parks return to its new connection; those past their end go.
        let (id, now) = (catalog.node_id(peer), env.now());
        if let Some(slot) = self.slots.get_mut(peer) {
            slot.node_id = id;
        }
        let pairs = &mut self.pairs;
        self.kept_parks.retain(|&(of, group), &mut until| {
            if of == id && now < until {
                pairs.set_park((peer, group), until);
            }
            of != id && now < until
        });
        if send_joins {
            for t in catalog.joined_types() {
                // Once a link and type; owed if the queue is full (§4.1 `send_join`).
                let j = catalog.our_join(t);
                if let Some(slot) = self.slots.get_mut(peer) {
                    slot.join_sent.insert(t, j);
                }
                self.sends.send_relation(peer, Control::Join(j), env);
                self.relink(peer, t);
            }
        }
    }

    /// Cleans up all per-connection state when a peer disconnects
    /// (`seacast-lite.md` §8.1). Its parks are kept by node, for its next
    /// connection.
    pub fn disconnect_peer<E, D>(&mut self, peer: PeerId, env: &mut E, deferred_store: &mut D)
    where
        E: RuntimeEnv<B>,
        D: DeferredStore<B>,
    {
        self.peers.retain(|&q| q != peer);
        self.push_out.remove_peer(peer);
        self.push_in.remove_peer(peer);
        self.linked.remove_peer(peer);
        self.grafted_in.retain(|&(q, _, _, _)| q != peer);
        self.grafted_out.retain(|&(q, _, _, _)| q != peer);
        self.backoff.retain(|&(q, _, _, _, _), _| q != peer);

        let id = self.slots.close(peer).map(|slot| {
            let id = slot.node_id;
            slot.reset();
            id
        });
        if let Some(id) = id {
            let now = env.now();
            self.kept_parks.retain(|_, &mut until| now < until);
            for (&(q, group), until) in self.pairs.parks() {
                if q == peer && now < until {
                    self.kept_parks.insert((id, group), until);
                }
            }
        }

        // Remove peer from live holders when its `peer_has` goes
        self.pairs.retain(|&(q, _)| q != peer);
        self.holders.remove_peer(peer);

        self.serve_count.retain(|&(q, _), _| q != peer);
        self.unwanted.retain(|&(q, _)| q != peer);

        self.standing.remove_peer(peer);
        self.routed_standing.remove_peer(peer);

        // Remove peer from ordered offer lists
        self.offers.retain(|_, list| {
            list.remove_item(&peer);
            !list.is_empty()
        });

        // Close promises and tried records for this peer
        self.tried.remove_peer(peer);
        self.promises.remove_peer(peer);
        self.asked_parked.remove_peer(peer);

        // Release deferred chunks and ties from this peer
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].1 == peer {
                let (_, _, chunk) = self.pending.remove(i);
                self.pending_ids.remove(&chunk.cached_id);
                deferred_store.release(peer, &chunk);
            } else {
                i += 1;
            }
        }
        self.tied.retain(|&(q, _), _| q != peer);
        self.reindex_ties();
        self.named.retain(|&(q, _), _| q != peer);
        self.wanted_groups.retain(|&(q, _), _| q != peer);

        // A claim is a connection's: a gone claimant is neither probed nor counted.
        // Our probe of it, not yet judged, gets no verdict, and our own repair is
        // reconsidered at the duty's own time, at once if that has passed
        // (`claims_close`, `seacast.md` §4.6).
        self.claims.remove_peer(peer);
        let now = env.now();
        for (&g, rec) in self.groups.iter_mut() {
            if rec.probed != Some(peer) {
                continue;
            }
            rec.probed = None;
            if rec.deferred == Some(true) && rec.probe_ok.is_none() {
                rec.probe_ok = Some(None);
                if let Some(i) = rec.probe {
                    self.probe_asks.remove(&Ask::new(g, i));
                }
                let at = now.max(rec.duty_at.unwrap_or(now));
                rec.reconsider_at = Some(at.to_bits());
                env.schedule_after(at - now, TimerEvent::Reconsider {
                    group: g,
                    at_bits: at.to_bits(),
                });
            }
        }
        self.rsample_asked.retain(|&(_, _, q)| q != peer);
        self.probe_answers.retain(|&(q, _, _)| q != peer);
        self.probe_waiting.remove_peer(peer);
        self.probe_waiting_of.retain(|&(q, _), _| q != peer);
        self.plan_refused.retain(|&(q, _, _)| q != peer);
        self.sampled_from.retain(|&(_, q), _| q != peer);
        self.sends.disconnect(peer, env);
    }

    /// Starts a new period of the limits the specification counts per slot:
    /// the routed requests passed on per peer (`FORWARD_LIMIT`,
    /// `seacast.md` §4.5). The host calls it at its slot boundary, or on
    /// a period of its own where it has no slots.
    pub fn reset_period(&mut self) {
        self.forwarded.clear();
    }

    // =========================================================================
    // §4. Events: Top-Level RPC & Timer Dispatch
    // =========================================================================

    /// Handles an incoming standalone `Rpc` from `peer` (`seacast.md` §4
    /// `on_frame`).
    pub fn on_frame<E, C, R, D>(
        &mut self,
        peer: PeerId,
        rpc: Rpc<B>,
        env: &mut E,
        catalog: &mut C,
        rng: &mut R,
        deferred_store: &mut D,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
        D: DeferredStore<B>,
    {
        self.on_frame_part(peer, rpc, false, env, catalog, rng, deferred_store);
    }

    /// [`on_frame`](Self::on_frame) for a binding whose frame holds more than
    /// an `Rpc` does, as a gossipsub RPC: the host hands the frame over in
    /// parts, its holdings in the last ones. `offered`: an earlier part of
    /// the frame bore an offer, so the frame is counted already (§4.3).
    /// Returns `offered` for the next part.
    #[allow(clippy::too_many_arguments)]
    pub fn on_frame_part<E, C, R, D>(
        &mut self,
        peer: PeerId,
        rpc: Rpc<B>,
        mut offered: bool,
        env: &mut E,
        catalog: &mut C,
        rng: &mut R,
        deferred_store: &mut D,
    ) -> bool
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
        D: DeferredStore<B>,
    {
        for j in rpc.joins {
            self.on_join(peer, j, env, catalog);
        }
        // Chunks and holdings are taken on any link for types this node runs;
        // GRAFT, PRUNE, offers and WANTs require the link to have joined the
        // type (`seacast.md` §2, §4.1).
        if let Some(f) = rpc.chunk {
            if catalog.joined_types().contains(&f.group.type_id) {
                self.on_chunk(peer, f, env, catalog, rng, deferred_store);
            }
        }
        // One WANT per group: an offer's asks are bits of one bitmap, so none is left
        // behind.
        let mut asks: InlineVec<Want, MAX_ENTRY_CONTROL> = InlineVec::new();
        for h in &rpc.haves {
            if h.offer && self.is_linked(peer, h.group.type_id) {
                // An offer-bearing frame, for §4.3's limits.
                if !offered {
                    offered = true;
                    if let Some(slot) = self.slots.get_mut(peer) {
                        slot.ihave_frames += 1;
                    }
                }
                for a in self.on_offer(peer, h, env, catalog, rng) {
                    match asks.iter_mut().find(|w| w.group == a.group) {
                        Some(w) => w.bits.set(a.index),
                        None => {
                            let _ = asks.push(Want::pull_ask(a));
                        }
                    }
                }
            }
        }
        let mut wants: InlineVec<Want, MAX_ENTRY_CONTROL> = InlineVec::new();
        for w in &rpc.wants {
            if self.is_linked(peer, w.group.type_id) {
                let _ = wants.push(*w);
            }
        }
        let answers = self.on_want(peer, &wants, env, catalog, rng);
        // A GRAFT's answer goes on its own, in the order of the link's relation
        // messages (§4.1).
        for gr in rpc.grafts {
            self.on_graft(peer, gr, env, catalog);
        }
        for pr in rpc.prunes {
            self.on_prune(peer, pr, env, catalog);
        }
        for h in rpc.haves {
            if !h.offer && catalog.joined_types().contains(&h.group.type_id) {
                self.on_holding(peer, h, env, catalog, rng);
            }
        }
        self.respond(peer, &asks, &answers, env);
        offered
    }

    /// Records that `peer` does not want the chunk `id`: an ask of it by id
    /// is then not answered (§4.5 `unwanted`). For a binding that carries
    /// such ids, as gossipsub's IDONTWANT. Taken only for a group this node
    /// has a record of, and goes with it; at most
    /// `NodeConfig::max_unwanted_ids` per peer and heartbeat. Returns whether
    /// it was kept.
    pub fn note_unwanted(&mut self, peer: PeerId, id: ChunkId) -> bool {
        let limit = self.config.max_unwanted_ids;
        if self.groups.get(&GroupId::of_chunk_id(&id)).is_none() {
            return false;
        }
        let Some(slot) = self.slots.get_mut(peer) else {
            return false;
        };
        if slot.unwanted_ids >= limit {
            return false;
        }
        slot.unwanted_ids += 1;
        self.unwanted.insert((peer, id))
    }

    /// Sends one combined response per RPC handled (`seacast-lite.md` §4.1
    /// `respond`).
    pub fn respond<E>(
        &mut self,
        peer: PeerId,
        asks: &[Want],
        answers: &[(GroupId, u32)],
        env: &mut E,
    ) where
        E: RuntimeEnv<B>,
    {
        // The control goes ahead of the answers; the writer sends what is control at
        // the head of a lane as one RPC.
        for &want in asks {
            self.enqueue(peer, Queued::from_want(want), false, env);
        }
        for &(group, index) in answers {
            if self.resolve_chunk(&group, index).is_none() {
                continue;
            }
            let entry = Queued::Chunk { group, index, solicited: true };
            if !self.enqueue(peer, entry, false, env) {
                let single = self.single_chunk(&group);
                self.sends.owe_answer(peer, group, index, single);
            }
        }
    }

    /// Dispatches a scheduled `TimerEvent` (`seacast.md` §4).
    pub fn on_timer<E, C, R, D>(
        &mut self,
        event: TimerEvent,
        env: &mut E,
        catalog: &mut C,
        rng: &mut R,
        deferred_store: &mut D,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
        D: DeferredStore<B>,
    {
        match event {
            TimerEvent::RetryOffer(ask) => {
                self.retry_armed.remove(&ask);
                self.retry_offer(ask, env, catalog);
            }
            TimerEvent::PromiseDue { ask, peer, at_bits } => {
                self.promise_due(ask, peer, at_bits, env);
            }
            TimerEvent::AskParked(ask) => {
                self.ask_parked(ask, env, catalog);
            }
            TimerEvent::WindowTimeout { peer, group, index, at_bits } => {
                // No holding came in time for a chunk this node published, which
                // is acknowledged anyway (`seacast.md` §4.11
                // `window_timeout`).
                if self.sends.window_timeout((peer, group, index), at_bits, env) &&
                    self.groups.has_bits(&group, GroupBits::Origin)
                {
                    self.origin_acked(group, index, env, catalog);
                }
            }
            TimerEvent::Reconsider { group, at_bits } => {
                self.reconsider(group, at_bits, env, catalog, rng);
            }
            TimerEvent::Resample { group, index, peer, first } => {
                self.resample(group, index, peer, first, env, catalog, rng);
            }
            TimerEvent::PaceTick => {
                self.on_pace_tick(env, catalog);
            }
            TimerEvent::Heartbeat => {
                self.on_heartbeat(env, catalog, rng, deferred_store);
            }
        }
    }

    // =========================================================================
    // Shared State Queries
    // =========================================================================

    #[inline]
    pub fn accepted(&self, group: &GroupId, index: u32) -> bool {
        self.groups.get(group).and_then(|r| r.state.as_ref()) != Some(&GroupState::Invalid) &&
            self.chunks.contains_key(&(*group, index))
    }

    /// The next chunk whose level 1 check the host is to finish, with the
    /// connection it came from. The verdict goes to [`Self::on_validated`].
    pub fn pop_unverified(&mut self) -> Option<(GenerationPeerId, ChunkMsg<B>)> {
        self.unverified.pop_front()
    }

    /// Whether the chunk stored at `(group, index)` is the one with id `mid`
    /// (`accepted(mid)`).
    #[inline]
    pub fn accepted_id(&self, mid: &ChunkId, group: &GroupId, index: u32) -> bool {
        self.groups.get(group).and_then(|r| r.state.as_ref()) != Some(&GroupState::Invalid) &&
            self.known_id.get(&(*group, index)) == Some(mid)
    }

    #[inline]
    pub fn resolve_chunk(&self, group: &GroupId, index: u32) -> Option<ChunkMsg<B>> {
        if self.groups.get(group).and_then(|r| r.state.as_ref()) == Some(&GroupState::Invalid) {
            return None;
        }
        self.chunks.get(&(*group, index)).cloned()
    }

    /// Whether `group` is open with one chunk: what is owed of it is kept in a
    /// peer's ring.
    #[inline]
    pub(crate) fn single_chunk(&self, group: &GroupId) -> bool {
        self.groups.get(group).and_then(|r| r.hdr.as_ref()).is_some_and(|shape| shape.n == 1)
    }

    #[inline]
    pub fn held(&self, ask: Ask) -> bool {
        self.groups.bits(&ask.group, GroupBits::Mine).map(|b| b.has(ask.index)).unwrap_or(false)
    }

    #[inline]
    pub fn gated(&self, ask: Ask) -> bool {
        self.groups.get(&ask.group).and_then(|r| r.stop_pull.as_ref()).copied().unwrap_or(false) &&
            !self.probe_asks.contains(&ask)
    }

    #[inline]
    pub fn expired(&self, group: &GroupId) -> bool {
        self.tombstones.contains_key(group)
    }

    /// Whether `group` failed level 2 or 3 (`drop_group`): its chunks are not
    /// acted on (`seacast.md` §4.6).
    #[inline]
    pub fn dropped(&self, group: &GroupId) -> bool {
        self.groups.get(group).and_then(|r| r.state.as_ref()) == Some(&GroupState::Invalid)
    }

    #[inline]
    pub fn holder_count(&self, group: &GroupId, index: u32) -> usize {
        self.holders.count(&(*group, index))
    }

    /// Every `(group, index)` a chunk fills (`T.project(f)`), but for an index
    /// no bitmap can name: what follows indexes bitmaps with them.
    pub(crate) fn projections<C>(
        catalog: &C,
        chunk: &ChunkMsg<B>,
    ) -> InlineVec<(GroupId, u32), { crate::collections::MAX_PROJECTED }>
    where
        C: ObjectCatalog<B>,
    {
        let mut projected = catalog.project(chunk);
        projected.retain(|&(_, index)| (index as usize) < MAX_BITMAP_BITS);
        projected
    }

    /// Counts `peer` as linked for `t` once both JOINs are recorded and ours is
    /// queued, not owed (§4.1 `links`). A host that writes a link's JOINs into
    /// its record calls it after.
    pub fn relink(&mut self, peer: PeerId, t: TypeId) {
        if self.join_recv(peer, t).is_some() &&
            self.join_sent(peer, t).is_some() &&
            !self.sends.join_owed(peer, t)
        {
            self.linked.insert(t, peer);
        }
    }

    /// Takes back `peer`'s JOIN for `t`: on gossipsub's wires, its
    /// unsubscription from the type's last topic (`seacast-bindings.md` §0).
    /// The link no longer counts for the type and its relations of the type
    /// end, so nothing more is pushed or offered to the peer, and its offers,
    /// WANTs, GRAFTs and PRUNEs of the type are ignored. Our JOIN stands: a
    /// later JOIN of the peer's links the type again.
    ///
    /// What the peer has told of the type's groups stays until they end, as
    /// holdings and chunks are taken on any link: its standing WANTs are
    /// still answered, and its offers may still be asked against.
    pub fn on_leave(&mut self, peer: PeerId, t: TypeId) {
        let Some(slot) = self.slots.get_mut(peer) else {
            return;
        };
        slot.join_recv.remove(&t);
        self.linked.remove(&t, peer);
        self.push_in.remove_peer_type(peer, t);
        self.push_out.remove_peer_type(peer, t);
        self.grafted_in.retain(|&(q, ty, _, _)| (q, ty) != (peer, t));
        self.grafted_out.retain(|&(q, ty, _, _)| (q, ty) != (peer, t));
        self.backoff.retain(|&(q, ty, _, _, _), _| (q, ty) != (peer, t));
    }

    /// The JOIN `peer` sent for `t`, and ours to it.
    #[inline]
    pub fn join_recv(&self, peer: PeerId, t: TypeId) -> Option<&Join> {
        self.slots.get(peer)?.join_recv.get(&t)
    }

    #[inline]
    pub fn join_sent(&self, peer: PeerId, t: TypeId) -> Option<&Join> {
        self.slots.get(peer)?.join_sent.get(&t)
    }

    #[inline]
    pub fn over_ihave_limits(&self, peer: PeerId) -> bool {
        self.slots.get(peer).is_some_and(|s| {
            s.ihave_frames > self.config.max_ihave_messages ||
                s.ihave_asked >= self.config.max_ihave_length
        })
    }

    pub fn valid_have<C>(&self, h: &crate::message::Have, _catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        if h.bits.wire_byte_len() > crate::bitmap::MAX_HAVE_BYTES {
            return false;
        }
        if let Some(hdr) = self.groups.get(&h.group).and_then(|r| r.hdr.as_ref()) {
            let n = hdr.n;
            if !h.bits.all_below(n) {
                return false;
            }
        }
        true
    }

    /// Whether `peer` may have state kept for `group`: always for a group with
    /// a header, else as one of the `MAX_PENDING_GROUPS` it has named
    /// lately (`admitted_group(p, g)`). Naming a group again keeps its
    /// place.
    pub fn admit_group(&mut self, peer: PeerId, group: &GroupId) -> bool {
        if self.groups.get(group).is_some_and(|r| r.hdr.is_some()) {
            return true;
        }
        // As long as the group's own state would live without a chunk of it.
        let heartbeats = (self.config.group_ttl / self.config.heartbeat).ceil().max(1.0) as u32;
        if let Some(left) = self.named.get_mut(&(peer, *group)) {
            *left = heartbeats;
            return true;
        }
        let Some(slot) = self.slots.get_mut(peer) else {
            return false;
        };
        if slot.named_count >= self.config.max_pending_groups || self.named.is_full() {
            return false;
        }
        self.named.insert((peer, *group), heartbeats);
        slot.named_count += 1;
        true
    }

    /// Whether `peer` may have WANT state kept for `group`: always for an open
    /// group, else as one of the `MAX_PENDING_GROUPS` unknown groups it has
    /// named in WANTs, counted apart from `named`. A place lasts `GROUP_TTL`
    /// from the group's first naming (`seacast.md` §4.5 `admitted_group`).
    pub fn admit_want_group(&mut self, peer: PeerId, group: &GroupId, now: Timestamp) -> bool {
        if self.groups.get(group).is_some_and(|r| r.hdr.is_some()) ||
            self.wanted_groups.contains_key(&(peer, *group))
        {
            return true;
        }
        let Some(slot) = self.slots.get_mut(peer) else {
            return false;
        };
        if slot.wanted_count >= self.config.max_pending_groups || self.wanted_groups.is_full() {
            return false;
        }
        self.wanted_groups.insert((peer, *group), (now + self.config.group_ttl).to_bits());
        slot.wanted_count += 1;
        true
    }

    /// Frees every peer's WANT place for `group`, which has opened.
    pub(crate) fn release_wanted_group(&mut self, group: &GroupId) {
        let slots = &mut self.slots;
        self.wanted_groups.retain(|&(peer, ref of), _| {
            if of == group {
                if let Some(slot) = slots.get_mut(peer) {
                    slot.wanted_count = slot.wanted_count.saturating_sub(1);
                }
                return false;
            }
            true
        });
    }

    /// Frees the WANT places whose lifetime has passed, with the asker's
    /// standing requests, route marks and interest bits for the group
    /// (`seacast.md` §4.5 `release_wanted_groups`).
    pub(crate) fn release_wanted_groups(&mut self, now: Timestamp) {
        let (slots, pairs) = (&mut self.slots, &mut self.pairs);
        let (standing, routed) = (&mut self.standing, &mut self.routed_standing);
        self.wanted_groups.retain(|&(peer, group), &mut until| {
            if f64::from_bits(until) > now {
                return true;
            }
            if let Some(slot) = slots.get_mut(peer) {
                slot.wanted_count = slot.wanted_count.saturating_sub(1);
            }
            pairs.clear_want_p(&(peer, group));
            standing.remove_peer_if(peer, |&(of, _)| of == group);
            routed.remove_peer_if(peer, |&(of, _)| of == group);
            false
        });
    }

    #[inline]
    pub fn tie_room(&self, peer: PeerId, group: &GroupId, index: u32) -> bool {
        if (index as usize) >= crate::bitmap::MAX_BITMAP_BITS {
            return false;
        }
        let shape = self.groups.get(group).and_then(|r| r.hdr.as_ref());
        if shape.is_some_and(|shape| index >= shape.n) {
            return false;
        }
        self.tied.contains_key(&(peer, *group)) ||
            self.slots.get(peer).is_some_and(|s| s.tie_count < self.config.max_pending_groups)
    }

    /// Rebuilds the per-peer views of `tied` after ties were removed.
    pub(crate) fn reindex_ties(&mut self) {
        self.tied_bits.clear();
        for slot in self.slots.iter_mut() {
            slot.tie_count = 0;
        }
        for (&(peer, group), bits) in self.tied.iter() {
            *self.tied_bits.entry_or_default((peer, group)) |= bits;
            if let Some(slot) = self.slots.get_mut(peer) {
                slot.tie_count += 1;
            }
        }
    }

    /// Returns the current lifecycle state of `group` (`Pending` or
    /// `Complete`), if open.
    #[inline]
    pub fn group_state(&self, group: &GroupId) -> Option<GroupState> {
        self.groups.get(group).and_then(|r| r.state.as_ref()).copied()
    }
}
