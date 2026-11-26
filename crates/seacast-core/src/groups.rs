use crate::{
    bitmap::{Bitmap, MAX_BITMAP_BITS, MAX_CHUNKS},
    collections::{InlineVec, MAX_PROJECTED, PreallocVec},
    message::ChunkMsg,
    node::SeacastNode,
    state::GroupBits,
    traits::{
        ChunkBuffer, DecodeJob, DeferredStore, ObjectCatalog, PenaltyReason, RngSource, RuntimeEnv,
        TimerEvent,
    },
    types::{
        Ask, ChunkId, Duty, GenerationPeerId, GroupId, GroupState, PeerId, Shape, Timestamp,
        ValidationResult,
    },
};

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Handles an arriving chunk from `peer` (`seacast.md` §4.2 `on_chunk`,
    /// `seacast-lite.md` §4.2).
    pub fn on_chunk<E, C, R, D>(
        &mut self,
        peer: PeerId,
        chunk: ChunkMsg<B>,
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
        // An index no bitmap can name belongs to no group this node can hold.
        if chunk.index as usize >= MAX_BITMAP_BITS {
            return;
        }
        let mid = chunk.cached_id;
        let known = self.seen_ids.contains(&mid) || self.pending_ids.contains(&mid);
        if known || self.verifying.contains(&mid) {
            if self.accepted_id(&mid, &chunk.group, chunk.index) {
                // The claimant's copy passes its probe, a duplicate too (§4.6, R5).
                for (g, i) in catalog.project(&chunk) {
                    self.probe_answer(g, i, peer);
                }
                self.send_have(peer, chunk.group, env, catalog);
            } else if self.pending_ids.contains(&mid) {
                self.tie(peer, &chunk, catalog);
            } else if self.verifying.contains(&mid) {
                // The copy of a claimant we probed, while another's is being
                // verified: it answers the probe at the verdict (§4.6, R5).
                let probed = catalog.project(&chunk).iter().any(|&(g, i)| {
                    let a = Ask::new(g, i);
                    self.probe_asks.contains(&a) && self.promises.contains(a, peer)
                });
                if probed {
                    self.verifying_claimant.insert(mid, self.slots.stamp(peer));
                }
            }
            return;
        }
        if self.expired(&chunk.group) {
            return;
        }
        let res = self.level1(&chunk, catalog);
        self.route(peer, chunk, res, env, catalog, rng, deferred_store);
    }

    /// What a chunk's head settles before its body is read: `false` if the
    /// body is not wanted, with what a duplicate does already done. `true`:
    /// the host reads the body and passes the chunk to [`Self::on_chunk`].
    ///
    /// For a host that runs the proof check itself before `on_chunk`: a chunk
    /// kept at `(group, index)` then passed it, and the group's id binds its
    /// content, so another copy at that place is the same chunk. `id` is the
    /// chunk's id where the head alone gives it; without it a copy of a
    /// chunk another peer's waits for the domain's word is read.
    ///
    /// The copy that answers this node's probe is read: a claimant must not
    /// pass with a head.
    #[allow(clippy::too_many_arguments)]
    pub fn on_chunk_head<E, C>(
        &mut self,
        peer: PeerId,
        group: &GroupId,
        index: u32,
        id: Option<&ChunkId>,
        env: &mut E,
        catalog: &C,
    ) -> bool
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if index as usize >= MAX_BITMAP_BITS ||
            !catalog.joined_types().contains(&group.type_id) ||
            self.expired(group)
        {
            return false;
        }
        let ask = Ask::new(*group, index);
        if self.accepted(group, index) {
            // Our probe's answer may be named by the chunk's other group (R4).
            if self.probe_asks.contains(&ask) ||
                catalog
                    .cross(group, index)
                    .iter()
                    .any(|&(g, i)| self.probe_asks.contains(&Ask::new(g, i)))
            {
                return true;
            }
            self.send_have(peer, *group, env, catalog);
            return false;
        }
        if self.tied_to_root(peer, ask) {
            return false;
        }
        if id.is_some_and(|id| self.pending_ids.contains(id)) {
            self.tie_index(peer, *group, index);
            return false;
        }
        true
    }

    /// Level 1 of a chunk, in the order of its cost: the codec's checks that
    /// read no data, the domain's word on the group, which is asked once a
    /// group, then the proof.
    fn level1<C>(&mut self, chunk: &ChunkMsg<B>, catalog: &mut C) -> ValidationResult
    where
        C: ObjectCatalog<B>,
    {
        let rec = self.groups.get(&chunk.group);
        if !catalog.check(chunk) {
            return ValidationResult::Reject;
        }
        if !rec.is_some_and(|r| r.authentic) {
            let header_id = catalog.header_id(chunk);
            let context = catalog.context(chunk);
            let verdict = catalog.authenticate(&chunk.group, &header_id, context);
            if verdict != ValidationResult::Accept {
                // A domain's `Pending` is no verdict: the chunk is not taken.
                return if verdict == ValidationResult::Pending {
                    ValidationResult::Ignore
                } else {
                    verdict
                };
            }
            let deadline = catalog.deadline(&chunk.group, context);
            let rec = self.groups.rec(chunk.group);
            rec.authentic = true;
            rec.deadline = deadline;
        }
        catalog.check_proof(chunk)
    }

    /// Takes a chunk on from its inline check: to the host if the rest of level
    /// 1 is still to do, else on as validated.
    #[allow(clippy::too_many_arguments)]
    fn route<E, C, R, D>(
        &mut self,
        peer: PeerId,
        chunk: ChunkMsg<B>,
        result: ValidationResult,
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
        let peer = self.slots.stamp(peer);
        if result != ValidationResult::Pending {
            return self.on_validated(peer, chunk, result, env, catalog, rng, deferred_store);
        }
        // With no room the chunk is dropped unseen: a later copy is taken up again.
        if !self.unverified.is_full() && self.verifying.insert(chunk.cached_id) {
            let _ = self.unverified.push_back((peer, chunk));
        }
    }

    /// Continues chunk processing once Level 1 validation returns
    /// (`on_validated(p, f, result)`): from the inline check, or from the
    /// host with the verdict on a chunk it took from `pop_unverified`.
    #[allow(clippy::too_many_arguments)]
    pub fn on_validated<E, C, R, D>(
        &mut self,
        peer: GenerationPeerId,
        chunk: ChunkMsg<B>,
        result: ValidationResult,
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
        self.verifying.remove(&chunk.cached_id);
        let claimant = self.verifying_claimant.remove(&chunk.cached_id);
        // Its connection closed meanwhile: the chunk is dropped unseen, as one that
        // never came. Another connection may have the peer id.
        let Some(peer) = self.slots.resolve(peer) else {
            return;
        };
        if self.expired(&chunk.group) {
            return;
        }
        if result == ValidationResult::Defer {
            self.defer(peer, chunk, env, catalog, deferred_store);
            return;
        }
        // A verdict is `Accept`, `Reject`, `Defer` or `Ignore`.
        if result == ValidationResult::Pending || result == ValidationResult::Ignore {
            return;
        }
        if result == ValidationResult::Reject {
            // An id leaves `seen_ids` with its group's record. Of a group with
            // none it would stay for good, so it is not kept: a repeat is
            // checked, and counted against its sender, again.
            if self.groups.get(&chunk.group).is_some() {
                self.seen_ids.insert(chunk.cached_id);
            }
            env.penalise(peer, PenaltyReason::InvalidChunkLevel1);
            return;
        }
        self.seen_ids.insert(chunk.cached_id);
        let projected = Self::projections(catalog, &chunk);
        // A second id for an index already received on an axis is only
        // acknowledged there (`fill`), not forwarded; one held only as rebuilt
        // is still forwarded (`seacast.md` §4.2).
        let mut new_axes: InlineVec<(GroupId, u32), MAX_PROJECTED> = InlineVec::new();
        for &(g, i) in &projected {
            if !self.groups.bits(&g, GroupBits::Received).is_some_and(|b| b.has(i)) {
                let _ = new_axes.push((g, i));
            }
        }
        for &(g, i) in &projected {
            self.fill(g, i, &chunk, Some(peer), env, catalog);
        }
        if let Some(q) = claimant.and_then(|q| self.slots.resolve(q)) {
            for &(g, i) in &projected {
                self.probe_answer(g, i, q);
            }
        }
        // A dropped or expired axis is not acted on (`seacast.md` §4.6).
        let mut acting: InlineVec<(GroupId, u32), MAX_PROJECTED> = InlineVec::new();
        for &(g, i) in &new_axes {
            if !self.expired(&g) && !self.dropped(&g) {
                let _ = acting.push((g, i));
            }
        }
        if acting.iter().any(|&(g, _)| catalog.duty_for(&g) == Duty::Forward) {
            self.forward(&chunk, peer, &acting, env, catalog, rng);
        }
        for (g, _) in projected {
            self.check_completion(g, env, catalog, rng);
        }
    }

    /// Fills `(group, index)` with a verified or rebuilt chunk
    /// (`seacast.md` §4.2 `fill`).
    pub fn fill<E, C>(
        &mut self,
        group: GroupId,
        index: u32,
        chunk: &ChunkMsg<B>,
        sender: Option<PeerId>,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if self.expired(&group) {
            return;
        }
        if index as usize >= MAX_BITMAP_BITS {
            return;
        }
        if self.groups.get(&group).is_none_or(|r| r.t_of.is_none()) {
            self.open_group(group, chunk, env.now(), catalog);
        }
        // Not opened: the group tables are full, or its header names more indices than
        // a bitmap has.
        if self.groups.get(&group).is_none_or(|r| r.t_of.is_none()) ||
            self.groups.get(&group).and_then(|r| r.state.as_ref()) == Some(&GroupState::Invalid)
        {
            return;
        }
        let already_held = self
            .groups
            .bits(&group, GroupBits::Received)
            .map(|b| b.has(index))
            .unwrap_or(false) ||
            self.groups.bits(&group, GroupBits::Rebuilt).map(|b| b.has(index)).unwrap_or(false);
        if already_held {
            if let Some(p) = sender {
                self.probe_answer(group, index, p);
                self.send_have(p, group, env, catalog);
            }
            return;
        }
        if !self.store_chunk(group, index, chunk.clone(), env.now()) {
            return;
        }
        if sender.is_some() {
            self.groups.edit_bits(group, GroupBits::Received, |bits| bits.set(index));
        } else {
            self.groups.edit_bits(group, GroupBits::Rebuilt, |bits| bits.set(index));
        }
        // Only the claimant's own copy passes its probe; another peer's leaves
        // the probe's promise open (§4.6, R5).
        if let Some(p) = sender {
            self.probe_answer(group, index, p);
        }
        let kept = self.probe_promise(group, index);
        self.close_promises(group, index, None);
        if let Some((claimant, at_bits)) = kept {
            self.promises.insert(Ask::new(group, index), claimant, at_bits);
        }
        self.serve_standing(group, index, env, catalog);
        self.serve_waiting_probe(group, index, env, catalog);

        let claim = !self.groups.bits(&group, GroupBits::Mine).is_some_and(|mine| mine.has(index));
        self.groups.edit_bits(group, GroupBits::Mine, |mine| mine.set(index));
        let scope = self.suppression_scope(&group, catalog);
        if claim {
            self.for_each(scope, |node, q| node.send_have(q, group, env, catalog));
        }
        if let Some(p) = sender.filter(|&p| !claim || !self.in_set(scope, p)) {
            self.send_have(p, group, env, catalog);
        }
    }

    pub(crate) fn open_group<C>(
        &mut self,
        group: GroupId,
        chunk: &ChunkMsg<B>,
        now: Timestamp,
        catalog: &C,
    ) where
        C: ObjectCatalog<B>,
    {
        // A chunk opens its own group as its type; one it only projects onto, as that
        // group's.
        let t = group.type_id;
        let header = catalog
            .shape_by_group(&group)
            .or_else(|| (chunk.group == group).then(|| catalog.shape(chunk)).flatten());
        if let Some(h) = &header {
            if h.n as usize > MAX_BITMAP_BITS {
                return;
            }
        }
        if !self.groups.open(group, t) {
            return;
        }
        let rec = self.groups.rec(group);
        if header.is_some() {
            rec.hdr = header;
        }
        if let Some(h) = &header {
            // A place that ran out goes before its group opens (§4.5).
            self.release_wanted_groups(now);
            self.release_wanted_group(&group);
            self.drop_beyond(group, h.n);
            self.drop_wants_beyond(group, h.n);
        }
        let rec = self.groups.rec(group);
        rec.state = Some(GroupState::Collecting);
        rec.known_at.get_or_insert(now);
        rec.last_activity = Some(now);
        // What a sampler declared, or an offer recorded, before the group opened is
        // kept.
        let own = catalog.own_interest(&group);
        self.groups.edit_bits(group, GroupBits::Interest, |interest| *interest |= &own);
        // Holdings that arrived before the group opened count from now on.
        for p in self.pairs.having(&group) {
            let Some(entry) = self.pairs.peer_has(&(p, group)) else {
                continue;
            };
            for i in entry.bits.iter() {
                self.holders.insert((group, i), p);
            }
            if entry.claim_all && self.is_linked(p, group.type_id) {
                self.claims.insert(group, p);
            }
        }
    }

    pub(crate) fn store_chunk(
        &mut self,
        group: GroupId,
        index: u32,
        chunk: ChunkMsg<B>,
        now: Timestamp,
    ) -> bool {
        // Admitted before any state changes: a chunk a full table refuses is
        // neither counted nor claimed.
        let key = (group, index);
        if self.chunks.is_full() && !self.chunks.contains_key(&key) ||
            self.known_id.is_full() && !self.known_id.contains_key(&key)
        {
            return false;
        }
        self.known_id.insert(key, chunk.cached_id);
        self.chunks.insert(key, chunk);
        self.groups.rec(group).last_activity.replace(now);
        true
    }

    /// Defers a chunk whose group the domain cannot tell of yet
    /// (`seacast-lite.md` §4.2 `defer`).
    pub fn defer<E, C, D>(
        &mut self,
        peer: PeerId,
        chunk: ChunkMsg<B>,
        env: &mut E,
        catalog: &mut C,
        deferred_store: &mut D,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        D: DeferredStore<B>,
    {
        // A group beyond the peer's unknown groups: neither kept nor tied
        // (`seacast-lite.md` §8.2).
        if !self.admit_group(peer, &chunk.group) {
            return;
        }
        self.tie(peer, &chunk, catalog);
        if self.pending.is_full() || self.pending_ids.len() >= self.pending_ids.capacity() {
            return;
        }
        if deferred_store.reserve(peer, &chunk) {
            self.pending_ids.insert(chunk.cached_id);
            let until = catalog
                .deadline(&chunk.group, catalog.context(&chunk))
                .unwrap_or(env.now() + self.config.group_ttl);
            let _ = self.pending.push((until, peer, chunk));
        }
    }

    /// Ties a sender to the group its deferred chunk is of (`seacast-lite.md`
    /// §4.2 `tie`).
    pub fn tie<C>(&mut self, peer: PeerId, chunk: &ChunkMsg<B>, _catalog: &C)
    where
        C: ObjectCatalog<B>,
    {
        self.tie_index(peer, chunk.group, chunk.index);
    }

    fn tie_index(&mut self, peer: PeerId, group: GroupId, index: u32) {
        if self.expired(&group) {
            return;
        }
        if !self.admit_group(peer, &group) || !self.tie_room(peer, &group, index) {
            return;
        }
        let key = (peer, group);
        if !self.tied.contains_key(&key) && self.tied.is_full() {
            return;
        }
        if !self.tied.contains_key(&key) {
            if let Some(slot) = self.slots.get_mut(peer) {
                slot.tie_count += 1;
            }
        }
        self.tied.entry_or_default(key).set(index);
        self.tied_bits.entry_or_default((peer, group)).set(index);
        self.close_promises(group, index, Some(peer));
    }

    /// Returns `true` if `peer` has a copy of `ask` waiting for the domain's
    /// word on its group (`tied_to_root(p, a)`).
    pub fn tied_to_root(&self, peer: PeerId, ask: Ask) -> bool {
        self.tied_bits.get(&(peer, ask.group)).is_some_and(|bits| bits.has(ask.index))
    }

    /// The domain can now tell of `groups` (`seacast-lite.md` §4.2
    /// `on_block_installed`, `seacast.md` §4.2 `on_header_validated`):
    /// the chunks of them that waited are taken up again, each once; the
    /// senders tied to one it commits become announcers of what they
    /// sent, a tie on one it does not commit is dropped; and what was offered
    /// is asked for.
    pub fn on_groups_authenticated<E, C, R, D>(
        &mut self,
        groups: &[GroupId],
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
        let (mut idx, mut left) = (0, self.pending.len());
        while left > 0 {
            left -= 1;
            if !groups.contains(&self.pending[idx].2.group) {
                idx += 1;
                continue;
            }
            let (_, p, f) = self.pending.remove(idx);
            self.pending_ids.remove(&f.cached_id);
            deferred_store.release(p, &f);
            let res = self.level1(&f, catalog);
            self.route(p, f, res, env, catalog, rng, deferred_store);
        }
        self.release_ties(groups, env, catalog);
        for g in groups {
            self.drop_outside(*g, catalog);
            let asks = self.ledger(g);
            for a in asks {
                self.retry_offer(a, env, catalog);
            }
        }
    }

    /// Releases the ties on `groups`: the senders of a group the domain commits
    /// are unparked and become announcers of what they sent; a tie on any
    /// other is dropped.
    fn release_ties<E, C>(&mut self, groups: &[GroupId], env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let now = env.now();
        // The ties, in peer and group order.
        let mut released: InlineVec<(PeerId, GroupId), MAX_BITMAP_BITS> = InlineVec::new();
        loop {
            released.clear();
            for &(p, g) in self.tied.keys() {
                if groups.contains(&g) && !released.push((p, g)) {
                    break;
                }
            }
            if released.is_empty() {
                break;
            }
            released.as_mut_slice().sort_unstable();
            for &(p, g) in released.iter() {
                let Some(bits) = self.tied.remove(&(p, g)) else {
                    continue;
                };
                if self.expired(&g) {
                    continue;
                }
                if !catalog.authenticable(&g) {
                    self.drop_tie(p, g, &bits, env, catalog);
                    continue;
                }
                self.pairs.clear_park(&(p, g));
                // An index the group does not have is dropped (`seacast-lite.md` §4.2).
                let count = self.groups.get(&g).and_then(|r| r.hdr.as_ref()).map(|h| h.n);
                for i in bits.iter().filter(|&i| count.is_none_or(|n| i < n)) {
                    self.asked_parked.remove(&(g, i), p);
                    let held =
                        self.groups.bits(&g, GroupBits::Mine).map(|b| b.has(i)).unwrap_or(false);
                    if !held && self.is_linked(p, g.type_id) {
                        self.add_offer(Ask::new(g, i), p, now);
                    }
                }
            }
        }
        self.reindex_ties();
    }

    /// Drops a tie on a group the domain does not commit (`drop_tie`).
    pub fn drop_tie<E, C>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        bits: &Bitmap,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let auth = catalog.authenticable(&group);
        for i in bits.iter() {
            self.drop_offer(group, i, peer);
            if auth {
                self.retry_offer(Ask::new(group, i), env, catalog);
            }
        }
    }

    /// Checks whether our interest in `group` is satisfied and triggers
    /// completion/decode (`seacast.md` §4.6 `check_completion`).
    pub fn check_completion<E, C, R>(
        &mut self,
        group: GroupId,
        env: &mut E,
        catalog: &mut C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if self.groups.get(&group).and_then(|r| r.state.as_ref()) != Some(&GroupState::Collecting) {
            return;
        }
        let Some(interest) = self.groups.bits(&group, GroupBits::Interest) else {
            return;
        };
        if interest.is_empty() || !self.interest_satisfied(&group, catalog) {
            return;
        }
        self.groups.rec(group).stop_pull.replace(true);
        if catalog.decode_at_k(&group) {
            self.groups.rec(group).state.replace(GroupState::Decoding);
            if let Some(h) = self.groups.get(&group).and_then(|r| r.hdr.as_ref()).copied() {
                // Claimed before the decode (`claim_group`, §4.6).
                self.groups.put_bits(group, GroupBits::Mine, Bitmap::all_bits(h.n));
            }
        } else {
            self.groups.rec(group).state.replace(GroupState::Complete);
            if let Some(later) = catalog.decode_later(&group, rng) {
                let known_at = self
                    .groups
                    .get(&group)
                    .and_then(|r| r.known_at.as_ref())
                    .copied()
                    .unwrap_or_else(|| env.now());
                self.arm(group, known_at + later, env);
            }
        }
        self.for_each(self.suppression_scope(&group, catalog), |node, q| {
            node.send_have(q, group, env, catalog);
        });
        self.close_promises_of_group(&group);
        if self.groups.get(&group).and_then(|r| r.state.as_ref()) == Some(&GroupState::Decoding) {
            self.start_decode(group, env);
        }
    }

    /// Returns `true` if our interest in `group` is satisfied
    /// (`interest_satisfied(g)`).
    pub fn interest_satisfied<C>(&self, group: &GroupId, _catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        let Some(h) = self.groups.get(group).and_then(|r| r.hdr.as_ref()) else {
            return false;
        };
        let recv = self.groups.bits(group, GroupBits::Received).unwrap_or(Bitmap::EMPTY);
        let reb = self.groups.bits(group, GroupBits::Rebuilt).unwrap_or(Bitmap::EMPTY);
        let have = recv | reb;
        let want = self.groups.bits(group, GroupBits::Interest).unwrap_or(Bitmap::EMPTY);
        if want.is_unbounded() { have.popcount() >= h.k } else { want.and_not(&have).is_empty() }
    }

    /// Arms a delayed decode duty for `group` at timestamp `at` (`arm(g, at)`).
    pub fn arm<E>(&mut self, group: GroupId, at: Timestamp, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        let at_bits = at.to_bits();
        self.groups.rec(group).reconsider_at.replace(at_bits);
        let delay = (at - env.now()).max(0.0);
        env.schedule_after(delay, TimerEvent::Reconsider { group, at_bits });
    }

    /// Collects the chunks held of `group` into `decode_in_scratch`, in index
    /// order, and gives its shape. `None` if there is nothing to decode.
    fn decode_inputs(&mut self, group: &GroupId) -> Option<Shape> {
        if self.expired(group) {
            return None;
        }
        let rec = self.groups.get(group)?;
        let h = rec.hdr.as_ref().cloned()?;
        let held = self.groups.bits(group, GroupBits::Mine).unwrap_or(Bitmap::EMPTY);
        self.decode_in_scratch.clear();
        // One lookup an index, not a pass over every group's chunks.
        for i in held.iter() {
            if let Some(ch) = self.chunks.get(&(*group, i)) {
                let _ = self.decode_in_scratch.push(ch.clone());
            }
        }
        (!self.decode_in_scratch.is_empty()).then_some(h)
    }

    /// Hands the host the level 2 of `group` (`RuntimeEnv::start_decode`).
    pub(crate) fn start_decode<E>(&mut self, group: GroupId, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        let Some(h) = self.decode_inputs(&group) else {
            return;
        };
        let chunks = self.decode_in_scratch.as_slice();
        env.start_decode(group, DecodeJob { shape: &h, chunks });
    }

    /// Level 2 and what follows it, on this thread (`seacast.md` §4.6
    /// `decode_group`): for a host that does not decode elsewhere. Uses the
    /// node's scratch buffers.
    pub fn decode_group<E, C, R>(
        &mut self,
        group: GroupId,
        env: &mut E,
        catalog: &mut C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let Some(h) = self.decode_inputs(&group) else {
            return;
        };
        // Taken for the call: `on_decoded` borrows the node.
        let mut out =
            std::mem::replace(&mut self.decode_out_scratch, PreallocVec::with_capacity(0));
        out.clear();
        let decoded = catalog.decode(&group, &self.decode_in_scratch, &h, &mut out);
        self.on_decoded(group, decoded, out.as_slice(), env, catalog, rng);
        self.decode_out_scratch = out;
    }

    /// The result of a group's level 2 (`seacast.md` §4.6 `decode_group`,
    /// from the decode on): `decoded` and `rebuilt` are what
    /// `TypeCodec::decode` gave for the job of `RuntimeEnv::start_decode`.
    /// Stores what was rebuilt, fills the groups it
    /// crosses, pushes repair and delivers; `None` drops the group.
    #[allow(clippy::too_many_arguments)]
    pub fn on_decoded<E, C, R>(
        &mut self,
        group: GroupId,
        decoded: Option<B>,
        rebuilt: &[ChunkMsg<B>],
        env: &mut E,
        catalog: &mut C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if self.expired(&group) {
            return;
        }
        let Some(h) = self.groups.get(&group).and_then(|r| r.hdr.as_ref()).cloned() else {
            return;
        };
        let Some(object) = decoded else {
            self.drop_group(group);
            return;
        };
        let recv = self.groups.bits(&group, GroupBits::Received).unwrap_or(Bitmap::EMPTY);
        let mut new_indices: InlineVec<u32, MAX_BITMAP_BITS> = InlineVec::new();
        let mut filled_groups: InlineVec<GroupId, MAX_CHUNKS> = InlineVec::new();
        let now = env.now();

        // A chunk's place in the group is its place in `rebuilt`, not its own index: a
        // chunk of two groups keeps the index of its first (`R4`).
        for (ch, i) in rebuilt.iter().zip(0..h.n) {
            if !recv.has(i) {
                if !self.store_chunk(group, i, ch.clone(), now) {
                    continue;
                }
                let _ = new_indices.push(i);
                self.groups.edit_bits(group, GroupBits::Rebuilt, |bits| bits.set(i));
                // Standing WANTs and a kept probe that waited for it, as `fill` answers
                // them (§4.5, §4.6).
                self.serve_standing(group, i, env, catalog);
                self.serve_waiting_probe(group, i, env, catalog);
                for (g2, i2) in Self::projections(catalog, ch) {
                    if g2 == group {
                        continue;
                    }
                    self.fill(g2, i2, ch, None, env, catalog);
                    filled_groups.insert_unique(g2);
                }
            }
        }
        self.groups.rec(group).state.replace(GroupState::Complete);
        self.groups.rec(group).last_activity.replace(now);
        self.push_rebuilt(group, &new_indices, env, catalog, rng);
        for g2 in filled_groups {
            self.check_completion(g2, env, catalog, rng);
        }
        env.deliver(group, object);
    }

    /// Drops a group when Level 2 or Level 3 validation fails
    /// (`seacast-lite.md` §4.6 `drop_group`).
    pub fn drop_group(&mut self, group: GroupId) {
        self.groups.rec(group).state.replace(GroupState::Invalid);
        self.groups.rec(group).stop_pull.replace(true);
        self.sends.cancel_group(&group);
        self.gossip_history.remove_group(&group);
        self.discard_paced(&group);
        self.close_promises_of_group(&group);
    }

    /// Ends `group` now, as the end of its lifetime would, for a domain whose
    /// window the group has left: its chunks still waiting go with it, and
    /// it leaves a tombstone.
    pub fn end_group<E, D>(&mut self, group: GroupId, env: &mut E, deferred_store: &mut D)
    where
        E: RuntimeEnv<B>,
        D: DeferredStore<B>,
    {
        let mut at = 0;
        while at < self.pending.len() {
            if self.pending[at].2.group == group {
                let (_, peer, chunk) = self.pending.remove(at);
                self.pending_ids.remove(&chunk.cached_id);
                deferred_store.release(peer, &chunk);
            } else {
                at += 1;
            }
        }
        self.expiring.insert(group);
        self.expire_due(env.now());
    }

    /// Ends the active lifetime of every group past it (`seacast-lite.md`
    /// §8.1): a group `GROUP_TTL` after its last chunk or its completion
    /// leaves a tombstone and nothing else; a deferred chunk goes
    /// `GROUP_TTL` after it arrived; a tombstone goes after its own time. A
    /// group the domain gave a deadline goes at it if that is sooner, as do
    /// its deferred chunks, and its tombstone is kept until it.
    pub(crate) fn expire_groups<E, D>(&mut self, env: &mut E, deferred_store: &mut D)
    where
        E: RuntimeEnv<B>,
        D: DeferredStore<B>,
    {
        let now = env.now();
        let ttl = self.config.group_ttl;
        let mut at = 0;
        while at < self.pending.len() {
            if now > self.pending[at].0 {
                let (_, peer, chunk) = self.pending.remove(at);
                self.pending_ids.remove(&chunk.cached_id);
                deferred_store.release(peer, &chunk);
            } else {
                at += 1;
            }
        }

        // A record nothing has stamped yet counts from now.
        for (_, rec) in self.groups.iter_mut() {
            if rec.known_at.is_none() && rec.last_activity.is_none() {
                rec.known_at = Some(now);
            }
        }
        // Every group due is ended together: each table is walked once a heartbeat, not
        // once a group.
        loop {
            for (&group, rec) in self.groups.iter() {
                let active = rec.last_activity.or(rec.known_at).unwrap_or(now);
                if now - active > ttl || rec.deadline.is_some_and(|at| now > at) {
                    self.expiring.insert(group);
                }
            }
            if self.expiring.is_empty() {
                break;
            }
            self.expire_due(now);
        }

        self.tombstones.retain(|_, &mut until| now <= until);
    }

    /// Removes everything kept of the groups in `expiring` but their
    /// tombstones.
    fn expire_due(&mut self, now: Timestamp) {
        let dead = core::mem::replace(&mut self.expiring, crate::PreallocSet::with_capacity(0));
        for &group in dead.iter() {
            let deadline = self.groups.remove(&group).and_then(|rec| rec.deadline);
            self.tombstones.insert(group, deadline.unwrap_or(now + self.config.tombstone_ttl));
        }
        let gone = |of: &GroupId| dead.contains(of);
        let gone_id = |id: &crate::ChunkId| dead.contains(&GroupId::of_chunk_id(id));

        self.chunks.retain(|(of, _), _| !gone(of));
        self.known_id.retain(|(of, _), _| !gone(of));
        // A chunk id carries its group after its type.
        self.seen_ids.retain(|id| !gone_id(id));
        self.verifying.retain(|id| !gone_id(id));
        self.verifying_claimant.retain(|id, _| !gone_id(id));
        self.serve_count.retain(|(_, id), _| !gone_id(id));
        self.unwanted.retain(|(_, id)| !gone_id(id));

        self.pairs.retain(|(_, of)| !gone(of));
        self.kept_parks.retain(|(_, of), _| !gone(of));
        self.holders.retain_keys(|(of, _)| !gone(of));
        self.standing.retain_keys(|(of, _)| !gone(of));
        self.routed_standing.retain_keys(|(of, _)| !gone(of));
        self.claims.retain_keys(|of| !gone(of));

        // The pull state: offers with their announcers' counts, then what hangs off an
        // ask.
        let slots = &mut self.slots;
        self.offers.retain(|ask, announcers| {
            if !gone(&ask.group) {
                return true;
            }
            for &p in announcers.iter() {
                if let Some(slot) = slots.get_mut(p) {
                    slot.listed_count = slot.listed_count.saturating_sub(1);
                }
            }
            false
        });
        self.tried.retain(|ask, _, _| !gone(&ask.group));
        self.asked_at.retain(|ask, _| !gone(&ask.group));
        self.promises.retain(|ask, _, _| !gone(&ask.group));
        self.asked_parked.retain_keys(|(of, _)| !gone(of));
        self.last_resort_armed.retain(|(of, _)| !gone(of));
        self.retry_armed.retain(|ask| !gone(&ask.group));
        self.held_back.retain(|(of, _), _| !gone(of));
        self.tied.retain(|(_, of), _| !gone(of));
        self.reindex_ties();
        let slots = &mut self.slots;
        self.named.retain(|&(peer, ref of), _| {
            if gone(of) {
                if let Some(slot) = slots.get_mut(peer) {
                    slot.named_count = slot.named_count.saturating_sub(1);
                }
            }
            !gone(of)
        });
        let slots = &mut self.slots;
        self.wanted_groups.retain(|&(peer, ref of), _| {
            if gone(of) {
                if let Some(slot) = slots.get_mut(peer) {
                    slot.wanted_count = slot.wanted_count.saturating_sub(1);
                }
            }
            !gone(of)
        });

        self.probe_asks.retain(|ask| !gone(&ask.group));
        self.probe_answers.retain(|(_, of, _)| !gone(of));
        self.probe_waiting.retain_keys(|(of, _)| !gone(of));
        self.probe_waiting_of.retain(|(_, of), _| !gone(of));
        self.plan_refused.retain(|(_, of, _)| !gone(of));
        self.rsample_asked.retain(|(of, _, _)| !gone(of));
        self.rsamples.retain(|of, _| !gone(of));

        // Queued chunks, offers and asks of them, and what is owed; their holdings
        // still leave.
        for g in dead.iter() {
            self.sends.cancel_group(g);
            self.gossip_history.remove_group(g);
            self.discard_paced(g);
        }
        let mut dead = dead;
        dead.clear();
        self.expiring = dead;
    }

    pub(crate) fn discard_paced(&mut self, group: &GroupId) {
        for idx in 0..self.pace_queue.len() {
            if let Some((_, items, _)) = self.pace_queue.get_mut(idx) {
                items.retain(|(g, _)| g != group);
            }
        }
    }
}
