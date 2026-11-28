use crate::{
    bitmap::{Bitmap, MAX_BITMAP_BITS},
    collections::{InlineVec, PreallocVec},
    message::{Have, Queued, Want},
    node::SeacastNode,
    state::{GroupBits, PeerSet},
    traits::{ChunkBuffer, ObjectCatalog, PenaltyReason, RngSource, RuntimeEnv, TimerEvent},
    types::{
        Ask, Duty, GenerationPeerId, GroupId, GroupState, InterestKind, PeerId, RepairVerdict,
        TypeId,
    },
};

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Handles an arriving holding (`Have` with `offer = false`,
    /// `seacast.md` §4.3 `on_holding`).
    pub fn on_holding<E, C, R>(
        &mut self,
        peer: PeerId,
        h: Have,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if self.expired(&h.group) {
            return;
        }
        if !self.valid_have(&h, catalog) {
            env.penalise(peer, PenaltyReason::InvalidHaveBitmap);
            return;
        }
        if !self.admit_group(peer, &h.group) {
            return;
        }
        let have_ttl = self.config.have_ttl;
        let mut e = self.pairs.peer_has(&(peer, h.group)).unwrap_or_default();
        let newly = h.bits.and_not(&e.bits);
        e.bits |= &h.bits;
        e.ttl = have_ttl;
        e.claim_all = e.claim_all || h.claim_all;
        e.complete = e.complete || h.complete;
        self.pairs.set_peer_has((peer, h.group), e);
        // The holders follow the holding as it is kept: an index the pair's
        // record has no room for names no holder, since none would be removed
        // for it.
        let kept = self.pairs.peer_has(&(peer, h.group)).map(|e| e.bits).unwrap_or(Bitmap::EMPTY);

        // A group this node has not opened has no claim to act on and no holders to
        // count: both are taken from `peer_has` when it opens (`open_group`).
        // A peer becomes a claimant only on a link that joined the type
        // (`seacast.md` §4.3).
        let open = self.groups.get(&h.group).is_some_and(|r| r.t_of.is_some());
        if h.claim_all && open && self.is_linked(peer, h.group.type_id) {
            self.note_claim(peer, h.group, env, catalog, rng);
        }
        for i in newly.iter() {
            if open && kept.has(i) {
                self.holders.insert((h.group, i), peer);
            }
            self.sends.window_release(peer, h.group, i, env);
            // A copy of a chunk we publish exists elsewhere (§4.7).
            if self.groups.has_bits(&h.group, GroupBits::Origin) {
                self.origin_acked(h.group, i, env, catalog);
            }
        }
        // A bit held already: a copy written since (a probe's answer, or any
        // without cancel) frees its room (§4.3, card 14).
        for i in h.bits.and_not(&newly).iter() {
            self.sends.window_release(peer, h.group, i, env);
        }
    }

    /// The claimant's own copy of the probed index, first or a duplicate,
    /// passes the probe and keeps its promise (`seacast.md` §4.6
    /// `probe_answer`).
    pub(crate) fn probe_answer(&mut self, group: GroupId, index: u32, sender: PeerId) {
        let Some(rec) = self.groups.get_mut(&group) else {
            return;
        };
        let ours = rec.deferred == Some(true) && rec.probe == Some(index);
        if ours && rec.probed == Some(sender) && rec.probe_ok.is_none() {
            self.settle_probe(group, Some(true));
            self.promises.remove(Ask::new(group, index), sender);
        }
    }

    /// The probe's verdict, once, or none. Settled, the probe's ask is gated
    /// again: the probed cell is pulled past stop-pull no more
    /// (`seacast.md` §4.6 `settle_probe`).
    pub(crate) fn settle_probe(&mut self, group: GroupId, verdict: Option<bool>) {
        let Some(rec) = self.groups.get_mut(&group) else {
            return;
        };
        rec.probe_ok = Some(verdict);
        if let Some(i) = rec.probe {
            self.probe_asks.remove(&Ask::new(group, i));
        }
    }

    /// The probe's promise, still open: the claimant and when it started
    /// (`probe_promise`).
    pub(crate) fn probe_promise(&self, group: GroupId, index: u32) -> Option<(PeerId, u64)> {
        let rec = self.groups.get(&group)?;
        // Settled, a promise under its key is a plain ask's, which any copy closes.
        if rec.deferred != Some(true) || rec.probe != Some(index) || rec.probe_ok.is_some() {
            return None;
        }
        let claimant = rec.probed?;
        Some((claimant, self.promises.get(Ask::new(group, index), claimant)?))
    }

    /// Whether `want`'s ask of `index` to `peer` is our probe of it, not yet
    /// answered or judged: written even if another peer's copy came first
    /// (`probe_waits`).
    pub(crate) fn probe_waits(&self, peer: PeerId, want: &Want, index: u32) -> bool {
        want.probe &&
            self.groups.get(&want.group).is_some_and(|rec| {
                rec.deferred == Some(true) &&
                    rec.probed == Some(peer) &&
                    rec.probe == Some(index) &&
                    rec.probe_ok.is_none()
            })
    }

    /// Returns the union of our holdings and our un-claimed relation peers'
    /// holdings (`known_in_scope(g)`).
    pub fn known_in_scope<C>(&self, group: &GroupId, catalog: &C) -> Bitmap
    where
        C: ObjectCatalog<B>,
    {
        let mut known = self.groups.bits(group, GroupBits::Mine).unwrap_or(Bitmap::EMPTY);
        for q in self.peers_of(self.suppression_scope(group, catalog)) {
            if self.claims.contains(group, q) {
                continue;
            }
            if let Some(e) = self.pairs.peer_has(&(q, *group)) {
                known |= &e.bits;
            }
        }
        known
    }

    /// Returns what our relation peers on the cross axis hold of `group`
    /// (`known_across(g)`, `R4`).
    pub fn known_across<C>(&self, group: &GroupId, catalog: &C) -> Bitmap
    where
        C: ObjectCatalog<B>,
    {
        let mut known = self.groups.bits(group, GroupBits::Mine).unwrap_or(Bitmap::EMPTY);
        let Some(h) = self.groups.get(group).and_then(|r| r.hdr.as_ref()) else {
            return known;
        };
        let n = h.n;
        for i in 0..n {
            if known.has(i) {
                continue;
            }
            for (g2, i2) in catalog.cross(group, i) {
                let scope2 = self.suppression_scope(&g2, catalog);
                if self
                    .peers_of(scope2)
                    .any(|q| self.pairs.peer_has(&(q, g2)).map(|e| e.has(i2)).unwrap_or(false))
                {
                    known.set(i);
                    break;
                }
            }
        }
        known
    }

    /// Member check (`seacast.md` §4.6 `owed_missing(g)`, `R5`):
    /// Returns `true` if a chunk of `group` that belongs to our own interest on
    /// the cross axis is still missing from our holdings.
    pub fn owed_missing<C>(&self, group: &GroupId, catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        let Some(h) = self.groups.get(group).and_then(|r| r.hdr.as_ref()) else {
            return false;
        };
        let n = h.n;
        let recv = self.groups.bits(group, GroupBits::Received).unwrap_or(Bitmap::EMPTY);
        let reb = self.groups.bits(group, GroupBits::Rebuilt).unwrap_or(Bitmap::EMPTY);
        for i in 0..n {
            if recv.has(i) || reb.has(i) {
                continue;
            }
            for (g2, i2) in catalog.cross(group, i) {
                let interest2 = self
                    .groups
                    .bits(&g2, GroupBits::Interest)
                    .unwrap_or_else(|| catalog.own_interest(&g2));
                if interest2.has(i2) {
                    return true;
                }
            }
        }
        false
    }

    /// IncrementalDAS sampling verdict on a claimant's repair
    /// (`repair_verdict(g)`, `R5`).
    pub fn repair_verdict<E, C, R>(
        &mut self,
        group: GroupId,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) -> RepairVerdict
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let t = group.type_id;
        let Some(ref steps_ref) = catalog.params(t).repair_sample else {
            return RepairVerdict::Repaired;
        };
        let steps = InlineVec::<(usize, usize), 8>::from_slice(steps_ref);
        let repair_reask = catalog.params(t).repair_reask;
        let k = self.groups.get(&group).and_then(|r| r.rsample_step.as_ref()).copied().unwrap_or(0);
        if k > 0 {
            let recv = self.groups.bits(&group, GroupBits::Received).unwrap_or(Bitmap::EMPTY);
            let reb = self.groups.bits(&group, GroupBits::Rebuilt).unwrap_or(Bitmap::EMPTY);
            let sampled = self.rsamples.get(&group).copied().unwrap_or_default();
            let mut lost: InlineVec<u32, MAX_BITMAP_BITS> = InlineVec::new();
            for i in sampled {
                if !recv.has(i) && !reb.has(i) {
                    let _ = lost.push(i);
                }
            }
            if lost.len() <= steps[k - 1].1 {
                return RepairVerdict::Repaired;
            }
            if k == steps.len() &&
                self.groups
                    .get(&group)
                    .and_then(|r| r.rsample_final.as_ref())
                    .copied()
                    .unwrap_or(false)
            {
                return RepairVerdict::NotRepaired;
            }
            let mut reasked_any = false;
            if repair_reask {
                for &i in &lost {
                    if self.ask_custodian(group, i, env, catalog, rng) {
                        reasked_any = true;
                    }
                }
            }
            if k == steps.len() {
                if !reasked_any {
                    return RepairVerdict::NotRepaired;
                }
                self.groups.rec(group).rsample_final.replace(true);
                return RepairVerdict::Asked;
            }
        }

        let current_len = self.rsamples.get(&group).map(|v| v.len()).unwrap_or(0);
        let mut want = steps[k].0.saturating_sub(current_len);
        let n = self.groups.get(&group).and_then(|r| r.hdr.as_ref()).map(|h| h.n).unwrap_or(0);
        let recv = self.groups.bits(&group, GroupBits::Received).unwrap_or(Bitmap::EMPTY);
        let reb = self.groups.bits(&group, GroupBits::Rebuilt).unwrap_or(Bitmap::EMPTY);
        let existing = self.rsamples.get(&group).copied().unwrap_or_default();
        // No room to keep a sample of this group: none is asked for.
        if !self.rsamples.contains_key(&group) && self.rsamples.is_full() {
            want = 0;
        }
        let mut pool: InlineVec<u32, MAX_BITMAP_BITS> = InlineVec::new();
        for i in 0..n {
            if !recv.has(i) && !reb.has(i) && !existing.contains(&i) {
                let _ = pool.push(i);
            }
        }
        rng.shuffle(pool.as_mut_slice());
        for i in pool {
            if want == 0 {
                break;
            }
            if self.ask_custodian(group, i, env, catalog, rng) {
                let _ = self.rsamples.entry_or_default(group).push(i);
                want -= 1;
            }
        }
        self.groups.rec(group).rsample_step.replace(k + 1);
        if self.rsamples.get(&group).is_some_and(|v| !v.is_empty()) {
            RepairVerdict::Asked
        } else {
            RepairVerdict::Repaired
        }
    }

    /// Asks a custodian of family `i` for cell `i` of `group`
    /// (`ask_custodian(g, i)`).
    pub fn ask_custodian<E, C, R>(
        &mut self,
        group: GroupId,
        index: u32,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) -> bool
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let cross = catalog.cross(&group, index);
        let Some(&(g2, i2)) = cross.first() else {
            return false;
        };
        if self.expired(&g2) {
            return false;
        }
        let t2 = g2.type_id;
        let Some(q) = self.choose_one(self.links(t2), rng, |q| {
            let claimed = self.claims.contains(&group, q);
            let already = self.rsample_asked.contains(&(group, index, q));
            self.interest_of_peer(q, &g2, catalog).has(i2) && !claimed && !already
        }) else {
            return false;
        };
        self.rsample_asked.insert((group, index, q));
        let want = Want::direct(g2, Bitmap::singleton(i2));
        self.enqueue(q, Queued::from_want(want), false, env);
        true
    }

    /// Evaluates a delayed decode duty when its timer fires (`seacast.md`
    /// §4.6 `reconsider`).
    pub fn reconsider<E, C, R>(
        &mut self,
        group: GroupId,
        at_bits: u64,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if self.groups.get(&group).and_then(|r| r.reconsider_at.as_ref()).copied() != Some(at_bits) ||
            self.groups.get(&group).and_then(|r| r.state.as_ref()) != Some(&GroupState::Complete)
        {
            return;
        }
        self.groups.get_mut(&group).and_then(|r| r.reconsider_at.take());
        // The probe's verdict, once: only the claimant's own copy passes it,
        // whichever peer brought the cell. A probe not written by now gets none, and
        // our own repair goes on below (§4.6, R5).
        if let Some(rec) = self.groups.get(&group) {
            if rec.deferred == Some(true) && rec.probe_ok.is_none() {
                let (sent, claimant) = (rec.probe_sent, rec.probed);
                self.settle_probe(group, sent.then_some(false));
                if let Some(claimant) = claimant.filter(|_| sent) {
                    env.penalise(claimant, PenaltyReason::UnansweredClaimProbe);
                }
            }
        }
        let Some(h) = self.groups.get(&group).and_then(|r| r.hdr.as_ref()).cloned() else {
            return;
        };
        let t = group.type_id;
        let n = h.n;
        if self.known_in_scope(&group, catalog).popcount() >= n {
            return;
        }
        let is_deferred =
            self.groups.get(&group).and_then(|r| r.deferred.as_ref()).copied().unwrap_or(false);
        let probe_received = self
            .groups
            .get(&group)
            .and_then(|r| r.probe.as_ref())
            .map(|&p_idx| {
                self.groups.bits(&group, GroupBits::Received).map(|b| b.has(p_idx)).unwrap_or(false)
            })
            .unwrap_or(false);
        let fam = catalog.family(&group);

        if is_deferred &&
            probe_received &&
            catalog.wants_family(t, fam) &&
            !self.owed_missing(&group, catalog)
        {
            if catalog.params(t).repair_sample.is_none() {
                return;
            }
            let sample_wait = catalog.params(t).sample_wait;
            match self.repair_verdict(group, env, catalog, rng) {
                RepairVerdict::Repaired => return,
                RepairVerdict::Asked => {
                    self.arm(group, env.now() + sample_wait, env);
                    return;
                }
                RepairVerdict::NotRepaired => {}
            }
        }

        let is_waited =
            self.groups.get(&group).and_then(|r| r.waited.as_ref()).copied().unwrap_or(false);
        if !is_waited && !is_deferred {
            let combined =
                self.known_in_scope(&group, catalog) | self.known_across(&group, catalog);
            if combined.popcount() >= n {
                self.groups.rec(group).waited.replace(true);
                let defer_win = catalog.params(t).defer_window;
                self.arm(group, env.now() + defer_win, env);
                return;
            }
        }

        let has_claims = self.claims.contains_key(&group);
        if has_claims && !is_deferred {
            self.defer_on_claim(group, env, catalog, rng);
            return;
        }

        self.groups.rec(group).state.replace(GroupState::Decoding);
        self.groups.put_bits(group, GroupBits::Mine, Bitmap::all_bits(h.n));
        self.for_each(self.suppression_scope(&group, catalog), |node, q| {
            node.send_have(q, group, env, catalog);
        });
        self.start_decode(group, env);
    }

    /// Records a peer's `claim_all` and defers our own pending decode if armed
    /// (`note_claim(p, g)`).
    pub fn note_claim<E, C, R>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        self.claims.insert(group, peer);
        let is_deferred =
            self.groups.get(&group).and_then(|r| r.deferred.as_ref()).copied().unwrap_or(false);
        if self.groups.get(&group).is_some_and(|r| r.reconsider_at.is_some()) &&
            self.groups.get(&group).and_then(|r| r.state.as_ref()) == Some(&GroupState::Complete) &&
            !is_deferred
        {
            if let Some(h) = self.groups.get(&group).and_then(|r| r.hdr.as_ref()) {
                let n = h.n;
                let mine_count =
                    self.groups.bits(&group, GroupBits::Mine).map(|b| b.popcount()).unwrap_or(0);
                if mine_count < n {
                    self.defer_on_claim(group, env, catalog, rng);
                }
            }
        }
    }

    /// Defers a decode once on a peer's `claim_all` and sends a verification
    /// probe ask (`defer_on_claim(g)`).
    pub fn defer_on_claim<E, C, R>(&mut self, group: GroupId, env: &mut E, catalog: &C, rng: &mut R)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let Some(h) = self.groups.get(&group).and_then(|r| r.hdr.as_ref()) else {
            return;
        };
        let t = group.type_id;
        let n = h.n;
        let mine = self.groups.bits(&group, GroupBits::Mine).unwrap_or(Bitmap::EMPTY);
        // An index we lack, at random: the claimant cannot tell which
        // (`seacast.md` §4.6 `defer_on_claim`).
        let lacked = (0..n).filter(|&i| !mine.has(i)).count();
        if lacked == 0 {
            return;
        }
        let pick = rng.next_u64() as usize % lacked;
        let Some(probe_idx) = (0..n).filter(|&i| !mine.has(i)).nth(pick) else {
            return;
        };
        let Some(q) = self.choose_one(PeerSet::Claims(group), rng, |_| true) else {
            return;
        };
        let a = Ask::new(group, probe_idx);
        let now = env.now();
        let defer_win = catalog.params(t).defer_window;
        let duty_at = self
            .groups
            .get(&group)
            .and_then(|r| r.reconsider_at)
            .map(f64::from_bits)
            .unwrap_or(now);
        // No probe without its promise. A probe that cannot be sent has no
        // verdict, and our own repair is reconsidered at the duty's own time
        // (§4.6).
        if !self.promises.has_room(a, q) {
            let rec = self.groups.rec(group);
            rec.deferred.replace(true);
            rec.duty_at = Some(duty_at);
            self.settle_probe(group, None);
            self.arm(group, now.max(duty_at), env);
            return;
        }
        let rec = self.groups.rec(group);
        rec.deferred.replace(true);
        rec.probe.replace(probe_idx);
        rec.probed.replace(q);
        rec.duty_at = Some(duty_at);

        self.add_offer(a, q, now);
        self.tried.insert(a, q, now);
        self.probe_asks.insert(a);

        // Its promise starts at its write (`filter_entry`). Refused by a full queue,
        // never written: no verdict, and our own repair is reconsidered at the duty's
        // own time (§4.6).
        let want = Want::probe(group, Bitmap::singleton(probe_idx));
        if !self.enqueue(q, Queued::from_want(want), false, env) {
            self.settle_probe(group, None);
            self.arm(group, now.max(duty_at), env);
            return;
        }

        let current_reconsider = self
            .groups
            .get(&group)
            .and_then(|r| r.reconsider_at.as_ref())
            .map(|&bits| f64::from_bits(bits))
            .unwrap_or(now);
        let arm_at = current_reconsider.max(now + defer_win);
        self.arm(group, arm_at, env);
    }

    /// Pushes or offers rebuilt chunks across each group they fill
    /// (`seacast.md` §4.6 `push_rebuilt`) with zero heap allocation.
    pub fn push_rebuilt<E, C, R>(
        &mut self,
        group: GroupId,
        new_indices: &[u32],
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        // Collect unique target groups g2 and their (i2, source_index) pairs on the
        // stack
        let mut group_order: InlineVec<GroupId, MAX_BITMAP_BITS> = InlineVec::new();
        let mut projected_items: InlineVec<(GroupId, u32, u32), { 2 * MAX_BITMAP_BITS }> =
            InlineVec::new();

        for &i in new_indices {
            if let Some(ch) = self.chunks.get(&(group, i)) {
                for (g2, i2) in Self::projections(catalog, ch) {
                    group_order.insert_unique(g2);
                    let _ = projected_items.push((g2, i2, i));
                }
            }
        }

        for g2 in group_order {
            if self.expired(&g2) || self.dropped(&g2) {
                continue;
            }
            let mut items: InlineVec<(u32, u32), MAX_BITMAP_BITS> = InlineVec::new();
            for &(ref pg, i2, src_i) in projected_items.iter() {
                if *pg == g2 {
                    let _ = items.push((i2, src_i));
                }
            }
            if items.is_empty() {
                continue;
            }

            let t2 = g2.type_id;
            let Some(h2) = self
                .groups
                .get(&g2)
                .and_then(|r| r.hdr.as_ref())
                .cloned()
                .or_else(|| catalog.shape_by_group(&g2))
            else {
                continue;
            };
            let k = h2.k;
            let prm2 = catalog.params(t2);
            let repair_budget = prm2.repair_budget;
            let eager = self.eager(t2, catalog);

            if repair_budget && eager {
                self.push_rebuilt_as_source(group, g2, t2, &items, env, catalog, rng);
                continue;
            }

            let mut repair_peers =
                std::mem::replace(&mut self.peer_scratch, PreallocVec::with_capacity(0));
            self.repair_candidates(t2, &g2, catalog, &mut repair_peers);
            rng.shuffle(repair_peers.as_mut_slice());

            for &q in repair_peers.iter() {
                let complete = self.pairs.peer_has(&(q, g2)).map(|e| e.complete).unwrap_or(false);
                if complete {
                    continue;
                }
                let has_bits = &self.pairs.has_bits(&(q, g2));
                let pushed_bits = &self.pairs.pushed_bits(&(q, g2));
                let known = has_bits | pushed_bits;
                let known_count = known.popcount();
                if known_count >= k {
                    continue;
                }
                let short = (k - known_count) as usize;
                let want = self.interest_of_peer(q, &g2, catalog);
                let mut lacks: InlineVec<(u32, u32), MAX_BITMAP_BITS> = InlineVec::new();
                for &(i2, src_i) in items.iter() {
                    if !known.has(i2) && want.has(i2) {
                        let _ = lacks.push((i2, src_i));
                    }
                }
                rng.shuffle(lacks.as_mut_slice());

                for &(i2, src_i) in lacks.iter().take(short) {
                    if !eager || self.peer_pull_only(q) {
                        self.announce(q, g2, Bitmap::singleton(i2), env, catalog);
                        continue;
                    }
                    if !self.chunks.contains_key(&(group, src_i)) {
                        continue;
                    }
                    let entry = Queued::Chunk { group, index: src_i, solicited: false };
                    if self.enqueue(q, entry, false, env) {
                        self.note_push(q, g2, i2, env.now(), catalog);
                    } else {
                        self.owe(q, g2, Bitmap::singleton(i2), env);
                    }
                }
            }
            self.peer_scratch = repair_peers;
        }
    }

    /// Pushes each rebuilt chunk to `R_NODE` peers lacking it and offers it to
    /// the rest (`seacast.md` §4.6 `push_rebuilt_as_source`,
    /// `REPAIR_BUDGET`).
    #[allow(clippy::too_many_arguments)]
    fn push_rebuilt_as_source<E, C, R>(
        &mut self,
        src_group: GroupId,
        g2: GroupId,
        t2: TypeId,
        items: &[(u32, u32)],
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let r_node = self.config.r_node();
        let mut base = std::mem::replace(&mut self.peer_scratch, PreallocVec::with_capacity(0));
        let mut shuffled =
            std::mem::replace(&mut self.shuffle_scratch, PreallocVec::with_capacity(0));
        self.repair_candidates(t2, &g2, catalog, &mut base);
        for &(i2, src_i) in items {
            if !self.chunks.contains_key(&(src_group, src_i)) {
                continue;
            }
            let entry = Queued::Chunk { group: src_group, index: src_i, solicited: false };
            // Each chunk in an order of its own, from the same start.
            shuffled.clear();
            for &q in base.iter() {
                let _ = shuffled.push(q);
            }
            rng.shuffle(shuffled.as_mut_slice());
            // The first `R_NODE` that lack it are pushed it, the rest offered it. A
            // push to one peer does not change whether another lacks it.
            let mut pushed = 0;
            for &q in shuffled.iter() {
                let complete = self.pairs.peer_has(&(q, g2)).map(|e| e.complete).unwrap_or(false);
                let has_bits = &self.pairs.has_bits(&(q, g2));
                let pushed_bits = &self.pairs.pushed_bits(&(q, g2));
                if complete ||
                    (has_bits | pushed_bits).has(i2) ||
                    !self.interest_of_peer(q, &g2, catalog).has(i2)
                {
                    continue;
                }
                if pushed >= r_node || self.peer_pull_only(q) {
                    self.announce(q, g2, Bitmap::singleton(i2), env, catalog);
                    continue;
                }
                pushed += 1;
                if self.enqueue(q, entry, false, env) {
                    self.note_push(q, g2, i2, env.now(), catalog);
                } else {
                    self.owe(q, g2, Bitmap::singleton(i2), env);
                }
            }
        }
        self.peer_scratch = base;
        self.shuffle_scratch = shuffled;
    }

    pub(crate) fn repair_candidates<C>(
        &self,
        t: TypeId,
        group: &GroupId,
        catalog: &C,
        out: &mut PreallocVec<PeerId>,
    ) where
        C: ObjectCatalog<B>,
    {
        out.clear();
        if let Some(custom) = catalog.repair_to(group) {
            for q in custom {
                let _ = out.push(q);
            }
            return;
        }
        let fam = catalog.family(group);
        let m = catalog.params(t).m.max(1);
        for &q in self.peers.iter() {
            // A peer that takes every index is repaired through the relation
            // only (§6.2, tier 4); one with an interest of its own, a
            // custodian, wherever it is (§6.3 `REPAIR_TO`).
            let in_rel = self.push_out.any_colour(q, t, fam, m);
            let takes_all = self.join_recv(q, t).is_some_and(|j| j.interest == InterestKind::All);
            if in_rel || !takes_all && !self.interest_of_peer(q, group, catalog).is_empty() {
                let _ = out.push(q);
            }
        }
    }

    /// Declares a sample of `group`: every index of `bits` at once, one peer
    /// each (`seacast.md` §4.10 `sample(g, bits)`, the first phase).
    pub fn sample<E, C, R>(
        &mut self,
        group: GroupId,
        bits: Bitmap,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        if self.expired(&group) || bits.is_empty() {
            return;
        }
        let now = env.now();
        self.groups.edit_bits(group, GroupBits::Interest, |interest| *interest |= bits);
        self.groups.rec(group).known_at.get_or_insert(now);
        for i in bits.iter() {
            self.ask_sample(group, i, true, env, catalog, rng);
        }
    }

    /// One sample to one peer, never one asked for another sample of the
    /// scope (I6): a link of ordinary custody that serves it, else a routed
    /// request through a forwarding link, else, after the first phase, a link
    /// of high custody (`ask_sample`). The routed request's first hop is drawn
    /// at random: no routing neighbours are kept.
    fn ask_sample<E, C, R>(
        &mut self,
        group: GroupId,
        index: u32,
        first: bool,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let held = self.groups.bits(&group, GroupBits::Mine).is_some_and(|m| m.has(index));
        if held || self.expired(&group) {
            return;
        }
        let t = group.type_id;
        let prm = catalog.params(t);
        let scope = catalog.sample_scope(&group);
        let missing = Bitmap::singleton(index);
        let in_flight = self.samples_in_flight.get(&scope).copied().unwrap_or(0);
        if !first && in_flight >= self.config.sample_outstanding.max(1) {
            // Asked when a second-phase ask ends.
            if !self.held_samples.push_back((scope, group, index)) {
                env.unreachable(group, missing);
            }
            return;
        }
        let now = env.now();
        // Whom the sample may be asked of: 0, a peer that serves the index; 1, one
        // that passes the request on; 2, one of high custody that serves it.
        let class = |q: PeerId| -> Option<usize> {
            if self.sampled_from.contains_key(&(scope, q)) || self.parked(q, &group, now) {
                return None;
            }
            let j = self.join_recv(q, t)?;
            let serves = j.interest != InterestKind::Declared &&
                self.interest_of_peer(q, &group, catalog).has(index);
            match (serves, catalog.high_custody(t, j)) {
                (false, _) if j.duty != Duty::Forward => None,
                (false, _) => Some(1),
                (true, false) => Some(0),
                (true, true) => Some(2),
            }
        };
        let mut counts = [0usize; 3];
        for at in self.peers_of(self.links(t)).filter_map(class) {
            counts[at] += 1;
        }
        let (of, hops) = if counts[0] > 0 {
            (0, 0)
        } else if counts[1] > 0 {
            (1, prm.route_hops)
        } else if !first && counts[2] > 0 {
            (2, 0)
        } else if first {
            // Only high custody serves it, or nobody yet: the second phase.
            let retry = TimerEvent::Resample { group, index, peer: None, first };
            env.schedule_after(prm.sample_retry, retry);
            return;
        } else {
            // Nobody left to ask: missing, for the application's verdict.
            env.unreachable(group, missing);
            return;
        };
        let Some(q) = self.choose_one(self.links(t), rng, |q| class(q) == Some(of)) else {
            return;
        };
        if self.sampled_from.is_full() ||
            (!first && self.samples_in_flight.is_full() && in_flight == 0)
        {
            env.unreachable(group, missing);
            return;
        }
        self.sampled_from.insert((scope, q), now + self.config.group_ttl);
        if !first {
            *self.samples_in_flight.entry_or_default(scope) += 1;
        }
        // No promise timer: the waits are the WANT's own (§4.5).
        let want = Want { hops, ..Want::standing(group, missing) };
        self.enqueue(q, Queued::from_want(want), false, env);
        let wait = if first { prm.sample_retry } else { prm.sample_retry2 };
        let peer = Some(self.slots.stamp(q));
        env.schedule_after(wait, TimerEvent::Resample { group, index, peer, first });
    }

    /// The wait on `peer` ran out: a sample still missing goes to another
    /// peer, with the short wait, and the asks held back take the place freed
    /// (`seacast.md` §4.10 `resample`, the second phase).
    ///
    /// The asks held back are taken also when this group has expired: they may
    /// be of another group of the scope.
    #[allow(clippy::too_many_arguments)]
    pub fn resample<E, C, R>(
        &mut self,
        group: GroupId,
        index: u32,
        peer: Option<GenerationPeerId>,
        first: bool,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let scope = catalog.sample_scope(&group);
        if !first {
            if let Some(n) = self.samples_in_flight.get_mut(&scope) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    self.samples_in_flight.remove(&scope);
                }
            }
        }
        let held = self.groups.bits(&group, GroupBits::Mine).is_some_and(|m| m.has(index));
        if !held && !self.expired(&group) {
            // Not a connection closed since: another may have its peer id.
            if let Some(q) = peer.and_then(|p| self.slots.resolve(p)) {
                // It held or should have held it; a first hop may have had no route.
                let now = env.now();
                self.pairs.set_park((q, group), now + self.config.park_ttl);
            }
            self.ask_sample(group, index, false, env, catalog, rng);
        }
        // Room left in flight goes to held samples of this scope, even when the
        // timed-out group has expired (`seacast.md` §4.10).
        let cap = self.config.sample_outstanding.max(1);
        while self.samples_in_flight.get(&scope).copied().unwrap_or(0) < cap {
            let Some(at) = self.held_samples.position(|h| h.0 == scope) else {
                break;
            };
            if let Some((_, g, i)) = self.held_samples.remove(at) {
                self.ask_sample(g, i, false, env, catalog, rng);
            }
        }
    }
}
