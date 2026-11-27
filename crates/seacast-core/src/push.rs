use crate::{
    bitmap::{Bitmap, MAX_BITMAP_BITS},
    collections::{InlineVec, PreallocVec},
    message::{ChunkMsg, Have, Queued},
    node::SeacastNode,
    state::{GroupBits, PeerSet, PushCand},
    traits::{ChunkBuffer, ObjectCatalog, RngSource, RuntimeEnv},
    types::{
        AnnounceWidth, Colour, Duty, FamilyId, GroupId, GroupState, PeerId, Shape, SourceOffers,
        Timestamp, TypeId,
    },
};

/// Peers one chunk of a published group is planned for: its budget `R`, with
/// room above it.
const MAX_PLAN_TARGETS: usize = 8;

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Returns the suppression scope of `group`: peers that may push this
    /// family to us (`seacast.md` §4.2 `suppression_scope`).
    pub fn suppression_scope<C>(&self, group: &GroupId, catalog: &C) -> PeerSet
    where
        C: ObjectCatalog<B>,
    {
        let t = group.type_id;
        PeerSet::Scope(t, catalog.family(group), catalog.params(t).m.max(1))
    }

    /// Sends a holding (`Have` with `offer = false`) on the urgent lane
    /// (`send_have(p, g)`).
    pub fn send_have<E, C>(&mut self, peer: PeerId, group: GroupId, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let bits = self.have_bits(&group);
        let h = self.holding_of(group, bits, catalog);
        if h.claim_all {
            self.groups.rec(group).claimed_all = true;
        }
        if self.groups.has_bits(&group, GroupBits::Origin) &&
            self.config.merge_holdings &&
            self.sends.merge_waiting(peer, &h)
        {
            return;
        }
        self.enqueue(peer, Queued::from_have(h), true, env);
    }

    /// Builds a holding `Have` message with `claim_all` and `complete` flags
    /// (`holding_of(g, bits)`).
    pub fn holding_of<C>(&self, group: GroupId, bits: Bitmap, catalog: &C) -> Have
    where
        C: ObjectCatalog<B>,
    {
        let n = self
            .groups
            .get(&group)
            .and_then(|r| r.hdr.as_ref())
            .map(|h| h.n)
            .or_else(|| catalog.shape_by_group(&group).map(|h| h.n))
            .unwrap_or(0);
        let (whole, done) = if self.groups.has_bits(&group, GroupBits::Origin) {
            let all_sent = n > 0 && bits.popcount() >= n;
            (all_sent, all_sent)
        } else {
            let mine_count =
                self.groups.bits(&group, GroupBits::Mine).map(|b| b.popcount()).unwrap_or(0);
            // A decoding node claims what it can produce, which may be less than all.
            let whole = n > 0 && mine_count >= n;
            let done = self
                .groups
                .get(&group)
                .and_then(|r| r.stop_pull.as_ref())
                .copied()
                .unwrap_or(false);
            (whole, done)
        };
        Have::holding(group, bits, whole, done)
    }

    /// Returns what our holding says of `group` (`have_bits(g)` in
    /// `seacast-lite.md` §4.2 `[P4]`).
    #[inline]
    pub fn have_bits(&self, group: &GroupId) -> Bitmap {
        self.groups
            .bits(group, GroupBits::Origin)
            .or_else(|| self.groups.bits(group, GroupBits::Mine))
            .unwrap_or(Bitmap::EMPTY)
    }

    /// Forwards a verified chunk along each `(group, index)` axis in `axes`
    /// where we have `FORWARD` duty (`seacast.md` §4.4 `forward`).
    pub fn forward<E, C, R>(
        &mut self,
        chunk: &ChunkMsg<B>,
        from_peer: PeerId,
        axes: &[(GroupId, u32)],
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        for &(g, i) in axes {
            if self.expired(&g) || self.dropped(&g) {
                continue;
            }
            let t = g.type_id;
            if catalog.duty_for(&g) != Duty::Forward {
                continue;
            }
            let fam = catalog.family(&g);
            let m = catalog.params(t).m.max(1) as u32;
            let c = (i % m) as u16;
            let pushees = self.out_pushees(t, fam, c);
            let held = |node: &Self, q: PeerId| {
                node.pairs.peer_has(&(q, g)).map(|e| e.has(i)).unwrap_or(false)
            };
            let cand = |node: &Self, q: PeerId| {
                !held(node, q) &&
                    q != from_peer &&
                    node.interest_of_peer(q, &g, catalog).has(i) &&
                    !node.pairs.peer_has(&(q, g)).map(|e| e.complete).unwrap_or(false)
            };
            let holding = self.peers_of(pushees).filter(|&q| held(self, q)).count();
            let budget = if catalog.params(t).eager {
                self.config.r_node().saturating_sub(holding)
            } else {
                0
            };
            let targets =
                self.choose_push(chunk, &g, pushees, &cand, budget, false, env.now(), catalog, rng);
            for &q in targets.iter() {
                let entry = Queued::Chunk { group: g, index: i, solicited: false };
                if self.enqueue(q, entry, false, env) {
                    self.note_push(q, g, i, env.now(), catalog);
                } else {
                    self.owe(q, g, Bitmap::singleton(i), env);
                }
            }
            let mut offered =
                std::mem::replace(&mut self.shuffle_scratch, PreallocVec::with_capacity(0));
            offered.clear();
            for q in self.peers_of(pushees) {
                if cand(self, q) && !targets.contains(&q) {
                    let _ = offered.push(q);
                }
            }
            let cap = self.config.offer_peers;
            if offered.len() > cap {
                rng.shuffle(offered.as_mut_slice());
            }
            for &q in offered.iter().take(cap) {
                self.announce(q, g, Bitmap::singleton(i), env, catalog);
            }
            self.shuffle_scratch = offered;
            self.peer_scratch = targets;
            self.announce_extra(g, i, env, catalog);
        }
        self.put_gossip(chunk, catalog);
    }

    /// Chooses up to `budget` push targets among the peers of `set` that `cand`
    /// accepts (`seacast-lite.md` §5.3 `choose_push`, `[c16]`). The targets
    /// come in the node's peer scratch, which the caller gives back
    /// (`self.peer_scratch`).
    #[allow(clippy::too_many_arguments)]
    pub fn choose_push<C, R>(
        &mut self,
        chunk: &ChunkMsg<B>,
        group: &GroupId,
        set: PeerSet,
        cand: &impl Fn(&Self, PeerId) -> bool,
        budget: usize,
        at_source: bool,
        now: Timestamp,
        catalog: &C,
        rng: &mut R,
    ) -> PreallocVec<PeerId>
    where
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let mut targets = std::mem::replace(&mut self.peer_scratch, PreallocVec::with_capacity(0));
        targets.clear();
        if budget == 0 {
            return targets;
        }
        for q in self.peers_of(set).filter(|&q| cand(self, q)) {
            let _ = targets.push(q);
        }
        // The peers on links not slow are pushed to before any other, up to
        // `r_fast` of them: an offer saves nothing on a link that keeps up.
        let adaptive = self.config.link_adaptive;
        let budget = match adaptive {
            true => {
                let fast = targets.iter().filter(|&&q| !self.link_slow(q)).count();
                budget.max(fast.min(self.config.r_fast))
            }
            false => budget,
        };
        if budget >= targets.len() {
            return targets;
        }
        // Ordered by the tiebreak, larger first; under `[c16]` the proven come before
        // the unproven and, of each, those that know less first. A total order, so
        // that the sort needs no buffer.
        let card16 = self.config.card16_enabled;
        let mut order = std::mem::replace(&mut self.push_scratch, PreallocVec::with_capacity(0));
        order.clear();
        for &p in targets.iter() {
            let (unproven, known) = if card16 {
                let has_bits = &self.pairs.has_bits(&(p, *group));
                let pushed_bits = &self.pairs.pushed_bits(&(p, *group));
                (self.guard_fails(p, group, now), (has_bits | pushed_bits).popcount())
            } else {
                (false, 0)
            };
            let tie = (catalog.tiebreak(&chunk.cached_id, p), catalog.node_id(p));
            let slow = self.link_slow(p);
            let _ = order.push(PushCand { slow, unproven, known, tie, peer: p });
        }
        order.as_mut_slice().sort_unstable_by(|a, b| {
            (a.slow, a.unproven, a.known)
                .cmp(&(b.slow, b.unproven, b.known))
                .then(b.tie.cmp(&a.tie))
                .then(a.peer.cmp(&b.peer))
        });
        if card16 && !at_source {
            // Of the proven, those at or under the median of what they know: drawn at
            // random, ahead of the rest.
            let proven = order.iter().take_while(|c| !c.unproven).count();
            if proven > 0 {
                let median = order[(proven - 1) / 2].known;
                let pool = order[..proven].iter().take_while(|c| c.known <= median).count();
                rng.sample_in_place(&mut order.as_mut_slice()[..pool], budget.min(pool));
            }
        }
        targets.clear();
        for c in order.iter().take(budget) {
            let _ = targets.push(c.peer);
        }
        self.push_scratch = order;
        targets
    }

    /// Proof guard (`seacast-lite.md` §5.3 `guard_fails(p, g)` `[c16]`):
    /// Demotes a peer that has been pushed at least `R_NODE` chunks of `group`,
    /// the first more than `GUARD_GRACE` ago, without sending any `Have`
    /// holding for `group`.
    pub fn guard_fails(&self, peer: PeerId, group: &GroupId, now: Timestamp) -> bool {
        let Some(e) = self.pairs.pushed(&(peer, *group)) else {
            return false;
        };
        let Some(first_push) = e.first_push else {
            return false;
        };
        let has_any_have = self.pairs.peer_has(&(peer, *group)).is_some();
        (e.popcount() as usize) >= self.config.r_node() &&
            (now - first_push) > self.config.guard_grace &&
            !has_any_have
    }

    /// Records a chosen push to `peer` under every group the chunk fills, from
    /// the ids alone (`seacast.md` §4.4 `note_push`, R4): a chunk sent
    /// through one axis is not offered or repaired to that peer through
    /// another.
    pub fn note_push<C>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        index: u32,
        now: Timestamp,
        catalog: &C,
    ) where
        C: ObjectCatalog<B>,
    {
        self.mark_pushed(peer, group, index, now);
        for (g2, i2) in catalog.cross(&group, index) {
            self.mark_pushed(peer, g2, i2, now);
        }
    }

    fn mark_pushed(&mut self, peer: PeerId, group: GroupId, index: u32, now: Timestamp) {
        let push_ttl = self.config.push_ttl;
        let mut e = self.pairs.pushed(&(peer, group)).unwrap_or_default();
        if e.is_empty() {
            e.first_push = Some(now);
        }
        e.set(index);
        e.ttl = push_ttl;
        self.pairs.set_pushed((peer, group), e);
    }

    /// Sends an offer `Have(offer = true)` to `peer` for indices in `bits`
    /// (`seacast.md` §4.4 `announce`).
    pub fn announce<E, C>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        bits: Bitmap,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let pushed_bits = &self.pairs.pushed_bits(&(peer, group));
        let peer_has_bits = &self.pairs.has_bits(&(peer, group));
        let interest = self.interest_of_peer(peer, &group, catalog);
        let b = (bits.and_not(pushed_bits).and_not(peer_has_bits)) & interest;
        if b.is_empty() {
            return;
        }
        let offer = Have::offer(group, b);
        if !self.enqueue(peer, Queued::from_have(offer), false, env) {
            self.owe(peer, group, b, env);
        }
    }

    /// Announces `(group, index)` to the links outside the relation, where the
    /// type asks for it (`announce_extra(g, i)`, `[D5]`).
    pub fn announce_extra<E, C>(&mut self, group: GroupId, index: u32, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let t = group.type_id;
        let prm = catalog.params(t);
        if prm.announce_extra != AnnounceWidth::AllJoined {
            return;
        }
        let fam = catalog.family(&group);
        self.for_each(PeerSet::Unrelated(t, fam, prm.m.max(1)), |node, q| {
            if node.wants_from_me(q, &group, catalog).has(index) {
                node.announce(q, group, Bitmap::singleton(index), env, catalog);
            }
        });
    }

    /// Converts a skipped or refused push into an owed offer if `peer` is in
    /// the push relation (`unpush`).
    pub fn unpush<E, C>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        index: u32,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let t = group.type_id;
        // Not counted under any group `note_push` marked.
        for (g2, i2) in core::iter::once((group, index)).chain(catalog.cross(&group, index)) {
            if let Some(mut e) = self.pairs.pushed(&(peer, g2)) {
                e.clear(i2);
                self.pairs.set_pushed((peer, g2), e);
            }
        }
        let fam = catalog.family(&group);
        let m = catalog.params(t).m.max(1) as u32;
        let c = (index % m) as u16;
        // Owed to a relation peer, or at a source to a peer of the pool the push was
        // planned from, where it stays in the plan (§4.7).
        let source = self.groups.has_bits(&group, GroupBits::Origin);
        if source {
            self.plan_refused.insert((peer, group, index));
        }
        let pooled = source && self.in_set(self.source_pool(t, fam, c), peer);
        if self.push_out.contains(&(peer, t, fam, c)) || pooled {
            self.owe(peer, group, Bitmap::singleton(index), env);
        }
    }

    /// Whom a source pushes below `STRIPE_UPLINK`, and offers to: the relation,
    /// or with none in the family for the colour, the links. The caller filters
    /// by interest (`seacast.md` §4.7 `source_pool`).
    pub fn source_pool(&self, t: TypeId, fam: FamilyId, colour: Colour) -> PeerSet {
        let relation = self.out_pushees(t, fam, colour);
        if self.count(relation) == 0 { self.links(t) } else { relation }
    }

    /// Marks `bits` of `group` as owed to `peer` for the next write (`owe(p, g,
    /// bits)`).
    pub fn owe<E>(&mut self, peer: PeerId, group: GroupId, bits: Bitmap, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        let single = self.single_chunk(&group);
        self.sends.owe(peer, group, bits, single, env);
    }

    /// Publishes a group as its source (`seacast.md` §4.7 `publish`, `[c2,
    /// c13, P4]`) with zero heap allocation.
    pub fn publish<E, C, R>(
        &mut self,
        group: GroupId,
        shape: Shape,
        shards: &[ChunkMsg<B>],
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if self.expired(&group) {
            return;
        }
        let now = env.now();
        let t = group.type_id;
        let n = shape.n;
        if !self.groups.open(group, t) {
            return;
        }
        let deadline = shards.first().and_then(|f| catalog.deadline(&group, catalog.context(f)));
        let rec = self.groups.rec(group);
        rec.hdr = Some(shape);
        rec.authentic = true;
        rec.deadline = deadline;
        rec.known_at.get_or_insert(now);
        // A place that ran out goes before its group opens (§4.5).
        self.release_wanted_groups(now);
        self.release_wanted_group(&group);
        self.drop_beyond(group, n);
        self.drop_wants_beyond(group, n);
        self.groups.put_bits(group, GroupBits::Interest, catalog.own_interest(&group));

        // A chunk a full table refuses is not claimed.
        let mut stored = Bitmap::new();
        for f in shards {
            if !self.store_chunk(group, f.index, f.clone(), now) {
                continue;
            }
            stored.set(f.index);
            self.seen_ids.insert(f.cached_id);
            self.put_gossip(f, catalog);
        }
        self.groups.put_bits(group, GroupBits::Mine, stored);
        self.groups.rec(group).state.replace(GroupState::Complete);
        self.groups.rec(group).stop_pull.replace(true);
        // Standing WANTs that arrived ahead of publish are answered now (`seacast.md`
        // §4.7).
        for f in shards {
            self.serve_standing(group, f.index, env, catalog);
        }
        // A pull-only type's source pushes nothing, so no acknowledgement can come:
        // its holding names every chunk, and every chunk is offered now
        // (`offer_at_publish`).
        if !catalog.params(t).eager {
            self.groups.put_bits(group, GroupBits::Origin, Bitmap::all_bits(n));
            self.for_each(self.suppression_scope(&group, catalog), |node, q| {
                node.send_have(q, group, env, catalog);
            });
            self.offer_from_source(group, n, env, catalog, rng);
            return;
        }
        self.groups.put_bits(group, GroupBits::Origin, Bitmap::new());

        let r = self.config.r;
        // A chunk's targets are at most its budget. A chunk the plan has no room for is
        // pushed to nobody, and so stays in what the relation peers are offered
        // below.
        let mut plan: InlineVec<(u32, InlineVec<PeerId, MAX_PLAN_TARGETS>), MAX_BITMAP_BITS> =
            InlineVec::new();
        for i in 0..n {
            let Some(f) = self.chunks.get(&(group, i)).cloned() else {
                continue;
            };
            let wants =
                |node: &Self, q: PeerId| node.wants_from_me(q, &group, catalog).has(f.index);
            let pool = self.source_set(&f, catalog);
            let chosen = self.choose_push(&f, &group, pool, &wants, r, true, now, catalog, rng);
            let targets = InlineVec::<PeerId, MAX_PLAN_TARGETS>::from_slice(&chosen);
            self.peer_scratch = chosen;
            if !plan.push((i, targets)) {
                break;
            }
            for &p in &targets {
                self.note_push(p, group, i, now, catalog);
            }
        }

        // The peers given their leading holding in this pass carry its mark.
        self.mark += 1;
        let mark = self.mark;
        for copy in 0..r {
            for &(i, ref targets) in plan.iter() {
                if copy < targets.len() {
                    let p = targets[copy];
                    let Some(f) = self.chunks.get(&(group, i)).cloned() else {
                        continue;
                    };
                    let first = self.slots.get_mut(p).is_some_and(|slot| {
                        let first = slot.mark != mark;
                        slot.mark = mark;
                        first
                    });
                    if first {
                        let bits =
                            self.groups.bits(&group, GroupBits::Origin).unwrap_or(Bitmap::EMPTY) |
                                Bitmap::singleton(i);
                        let holding = self.holding_of(group, bits, catalog);
                        if holding.claim_all {
                            self.groups.rec(group).claimed_all = true;
                        }
                        self.enqueue(p, Queued::from_have(holding), true, env);
                    }
                    if !self.enqueue(p, Queued::from_chunk(&f, false), false, env) {
                        self.unpush(p, group, i, env, catalog);
                    }
                }
            }
        }
        // The pool's peers not chosen for a chunk are offered it at its
        // acknowledgement (`origin_acked`), or now (`SOURCE_OFFERS = PUBLISH`).
        if self.config.source_offers == SourceOffers::Publish {
            self.offer_from_source(group, n, env, catalog, rng);
        }
    }

    /// Offers each chunk of a group we publish to its colour's source pool, but
    /// to the peers it was pushed to: one offer a peer (`offer_at_publish`).
    fn offer_from_source<E, C, R>(
        &mut self,
        group: GroupId,
        n: u32,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let t = group.type_id;
        let fam = catalog.family(&group);
        let m = catalog.params(t).m.max(1) as u32;
        let pools = |node: &Self, p: PeerId| {
            let mut bits = Bitmap::new();
            for c in 0..m.min(n) {
                if node.in_set(node.source_pool(t, fam, c as u16), p) {
                    for i in (c..n).step_by(m as usize) {
                        bits.set(i);
                    }
                }
            }
            bits
        };
        // Every pool is within the links.
        let mut offered =
            std::mem::replace(&mut self.shuffle_scratch, PreallocVec::with_capacity(0));
        offered.clear();
        for p in self.peers_of(self.links(t)) {
            if !pools(self, p).is_empty() {
                let _ = offered.push(p);
            }
        }
        let cap = self.config.offer_peers;
        if offered.len() > cap {
            rng.shuffle(offered.as_mut_slice());
        }
        // `announce` leaves out a push that was made.
        for &p in offered.iter().take(cap) {
            let bits = pools(self, p);
            self.announce(p, group, bits, env, catalog);
        }
        self.shuffle_scratch = offered;
    }

    /// `SOURCE_OFFERS = PUBLISH`: a chunk of a group we publish is written for
    /// the first time. It joins our holding (`origin_written`).
    pub(crate) fn origin_written<E, C>(
        &mut self,
        group: GroupId,
        index: u32,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let Some(mut orig) = self.groups.bits(&group, GroupBits::Origin) else {
            return;
        };
        if orig.has(index) {
            return;
        }
        orig.set(index);
        self.groups.put_bits(group, GroupBits::Origin, orig);
        self.for_each(self.suppression_scope(&group, catalog), |node, q| {
            node.send_have(q, group, env, catalog);
        });
    }

    /// Keeps `chunk` for the heartbeat's gossip, if its type is gossiped at
    /// all: the history is bounded, and a type announced to every joined
    /// peer would crowd the others out of it.
    fn put_gossip<C>(&mut self, chunk: &ChunkMsg<B>, catalog: &C)
    where
        C: ObjectCatalog<B>,
    {
        let t = chunk.group.type_id;
        if catalog.params(t).announce_extra == AnnounceWidth::Sample && !self.dropped(&chunk.group)
        {
            self.gossip_history.put(chunk);
        }
    }

    /// A chunk of a group we publish is known to have arrived somewhere: a
    /// peer's holding names it, or its first copy's room timed out. It joins
    /// our holding, and the pool's peers not planned for it are offered it;
    /// a refused push is owed, and not offered again (`seacast.md` §4.7
    /// `origin_acked`, `[c3, P4]`).
    pub fn origin_acked<E, C>(&mut self, group: GroupId, index: u32, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        // At `PUBLISH` the offers left at publish and the holding grew at the write.
        if self.config.source_offers == SourceOffers::Publish {
            return;
        }
        let Some(mut orig) = self.groups.bits(&group, GroupBits::Origin) else {
            return;
        };
        if orig.has(index) {
            return;
        }
        orig.set(index);
        self.groups.put_bits(group, GroupBits::Origin, orig);
        self.for_each(self.suppression_scope(&group, catalog), |node, q| {
            node.send_have(q, group, env, catalog);
        });
        let t = group.type_id;
        let fam = catalog.family(&group);
        let c = (index % catalog.params(t).m.max(1) as u32) as u16;
        // `announce` leaves out a push that was made.
        self.for_each(self.source_pool(t, fam, c), |node, p| {
            if !node.plan_refused.contains(&(p, group, index)) {
                node.announce(p, group, Bitmap::singleton(index), env, catalog);
            }
        });
    }

    /// The peers a source's pushes of `chunk` are chosen from, before their
    /// interest is looked at (`seacast.md` §4.7 `candidates_for_source`).
    pub fn source_set<C>(&self, chunk: &ChunkMsg<B>, catalog: &C) -> PeerSet
    where
        C: ObjectCatalog<B>,
    {
        let g = chunk.group;
        let t = g.type_id;
        if self.config.card13_enabled && self.config.uplink_bps >= self.config.stripe_uplink_bps {
            return self.links(t);
        }
        let fam = catalog.family(&g);
        let m = catalog.params(t).m.max(1) as u32;
        self.source_pool(t, fam, (chunk.index % m) as u16)
    }

    /// Returns `true` if `peer` is projected to reach `K` for `group` without
    /// further unsolicited pushes (`seacast.md` §4.9 `projected(p, g)`,
    /// `[c12]`).
    pub fn projected<C>(&self, peer: PeerId, group: &GroupId, _catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        let Some(h) = self.groups.get(group).and_then(|r| r.hdr.as_ref()) else {
            return false;
        };
        let k = h.k;
        let n = h.n;
        if k == n {
            return false;
        }
        let has = &self.pairs.has_bits(&(peer, *group));
        let sent = self.pairs.sent_to(&(peer, *group)).unwrap_or_default();
        let unconfirmed = sent.and_not(has).popcount();
        has.popcount() + self.config.fan_in * unconfirmed >= k
    }
}
