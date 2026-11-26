use crate::{
    bitmap::{Bitmap, MAX_BITMAP_BITS},
    collections::{InlineVec, MAX_ENTRY_CONTROL, PreallocVec},
    message::{Have, Queued, Want},
    node::SeacastNode,
    state::{GroupBits, PeerSet},
    traits::{ChunkBuffer, ObjectCatalog, PenaltyReason, RngSource, RuntimeEnv, TimerEvent},
    types::{Ask, Duty, GroupId, InterestKind, PeerId, Timestamp, TypeId},
};

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Handles an arriving offer (`Have` with `offer = true`, `seacast.md`
    /// §4.3 `on_offer` + `seacast-lite.md` §4.4).
    pub fn on_offer<E, C, R>(
        &mut self,
        peer: PeerId,
        h: &Have,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) -> InlineVec<Ask, MAX_BITMAP_BITS>
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let g = h.group;
        if self.expired(&g) {
            return InlineVec::new();
        }
        // An offer is a HAVE bitmap: one naming an index the group does not have is
        // ignored and counts against its sender (`seacast-lite.md` §8.2).
        if !self.valid_have(h, catalog) {
            env.penalise(peer, PenaltyReason::InvalidHaveBitmap);
            return InlineVec::new();
        }
        if !self.admit_group(peer, &g) {
            return InlineVec::new();
        }

        let t = g.type_id;
        let now = env.now();
        let interest = match self.groups.bits(&g, GroupBits::Interest) {
            Some(interest) => interest,
            None => catalog.own_interest(&g),
        };
        // Nothing is kept of an offer that names nothing this node wants: state for a
        // group starts with an offer the admission above counts (`offered`, by
        // `add_offer`).
        if (h.bits & interest)
            .and_not(&self.groups.bits(&g, GroupBits::Mine).unwrap_or(Bitmap::EMPTY))
            .is_empty()
        {
            return InlineVec::new();
        }
        let known_at = *self.groups.rec(g).known_at.get_or_insert(now);

        // Over the IHAVE limits the offer is recorded and nothing is done per index:
        // what it lets the node ask for is the next heartbeat's (`seacast-lite.md`
        // §4.4).
        if self.over_ihave_limits(peer) {
            let mine = self.groups.bits(&g, GroupBits::Mine);
            let wanted = (h.bits & interest).and_not(&mine.unwrap_or(Bitmap::EMPTY));
            let held = self.pairs.offered(&(peer, g)).unwrap_or_default();
            self.pairs.set_offered((peer, g), held | wanted);
            self.pairs.set_offer_at((peer, g), now);
            self.held_groups.insert(g);
            return InlineVec::new();
        }

        let start_delay = catalog.params(t).start_delay;
        if now - known_at < start_delay {
            return self.deferred_offers(peer, h, &interest, known_at, start_delay, env);
        }

        let mine = self.groups.bits(&g, GroupBits::Mine).unwrap_or(Bitmap::EMPTY);
        let wanted = (h.bits & interest).and_not(&mine);
        let auth = catalog.authenticable(&g);

        let mut candidates: InlineVec<Ask, MAX_BITMAP_BITS> = InlineVec::new();
        for i in wanted.iter() {
            let a = Ask::new(g, i);
            self.add_offer(a, peer, now);
            if self.gated(a) || !auth {
                continue;
            }
            if self.tied_to_root(peer, a) {
                continue;
            }
            if self.parked(peer, &g, now) {
                self.last_resort(a, env, catalog);
                continue;
            }
            if self.outstanding(peer, a) {
                continue;
            }
            let _ = candidates.push(a);
        }

        rng.shuffle(candidates.as_mut_slice());
        let mut asks = InlineVec::new();
        for a in candidates {
            if self.over_ihave_limits(peer) {
                self.held_back.insert((a.group, a.index), a);
            } else if self.may_ask(a, peer, env) {
                let _ = asks.push(a);
                if let Some(slot) = self.slots.get_mut(peer) {
                    slot.ihave_asked += 1;
                }
            }
        }
        asks
    }

    /// Records offers arriving before `START_DELAY` and schedules their first
    /// retry after the delay (`seacast.md` §4.3 `deferred_offers`,
    /// `[D8]`).
    fn deferred_offers<E>(
        &mut self,
        peer: PeerId,
        h: &Have,
        interest: &Bitmap,
        known_at: Timestamp,
        start_delay: f64,
        env: &mut E,
    ) -> InlineVec<Ask, MAX_BITMAP_BITS>
    where
        E: RuntimeEnv<B>,
    {
        let g = h.group;
        let now = env.now();
        let due = (known_at + start_delay - now).max(0.0) + 1e-6;
        let mine = self.groups.bits(&g, GroupBits::Mine).unwrap_or(Bitmap::EMPTY);
        let wanted = (h.bits & interest).and_not(&mine);
        for i in wanted.iter() {
            let a = Ask::new(g, i);
            self.add_offer(a, peer, now);
            if self.retry_armed.insert(a) {
                env.schedule_after(due, TimerEvent::RetryOffer(a));
            }
        }
        InlineVec::new()
    }

    /// Handles incoming `Want` asks from `peer` (`seacast.md` §4.5 `on_want`),
    /// returning deduplicated `(group, index)` answers with zero heap
    /// allocation.
    pub fn on_want<E, C, R>(
        &mut self,
        peer: PeerId,
        wants: &[Want],
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) -> InlineVec<(GroupId, u32), MAX_BITMAP_BITS>
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        let mut answers: InlineVec<(GroupId, u32), MAX_BITMAP_BITS> = InlineVec::new();
        // The indices answered in this frame, by group; past the table's room,
        // read from the answers.
        let mut taken: InlineVec<(GroupId, Bitmap), MAX_ENTRY_CONTROL> = InlineVec::new();
        let any_probe = wants.iter().any(|w| w.probe);

        for w in wants {
            let g = w.group;
            let at = match taken.iter().position(|(of, _)| *of == g) {
                Some(at) => Some(at),
                None => taken.push((g, Bitmap::new())).then(|| taken.len() - 1),
            };
            if self.expired(&g) {
                continue;
            }
            let t = g.type_id;
            let declared =
                self.join_recv(peer, t).is_some_and(|j| j.interest == InterestKind::Declared);
            let serve_limit = catalog.params(t).serve_limit;
            let count = self.groups.get(&g).and_then(|r| r.hdr.as_ref()).map(|h| h.n);
            let max_idx = count.unwrap_or(catalog.params(t).max_indices);
            let budget = self.config.max_served_per_heartbeat;
            // Routed only through a node whose duty towards `peer` is FORWARD (§4.5).
            let hops = if self.join_sent(peer, t).is_some_and(|j| j.duty == Duty::Forward) {
                w.hops
            } else {
                0
            };
            let our_interest = self.our_interest_for(peer, &g, catalog);

            for idx in w.bits.iter() {
                let answered = match at {
                    Some(at) => taken[at].1.has(idx),
                    None => answers.contains(&(g, idx)),
                };
                if answered {
                    continue;
                }
                if idx >= max_idx {
                    continue;
                }
                let peer_claimed =
                    self.pairs.peer_has(&(peer, g)).map(|e| e.has(idx)).unwrap_or(false);
                // Outside what we serve: ignored without penalty and leaves no state,
                // except where `peer` itself claimed the chunk (penalised below).
                if self.outside(peer, &g, idx, hops > 0, catalog) && !peer_claimed {
                    continue;
                }
                if !self.admit_want_group(peer, &g, env.now()) {
                    continue;
                }
                let in_our_interest = our_interest.has(idx);
                if declared && !(hops > 0 && !in_our_interest) {
                    let now = env.now();
                    self.groups.rec(g).known_at.get_or_insert(now);
                    let mut wanted = self.pairs.want_p(&(peer, g)).unwrap_or_default();
                    wanted.set(idx);
                    self.pairs.set_want_p((peer, g), wanted);
                }
                // The peer's probe of our claim: answered whatever it holds, once
                // for the group (`seacast.md` §4.6 `probe_of_claim`). A plain ask
                // of an index the same frame also probes takes that probe if valid.
                let claimed = self.groups.bits(&g, GroupBits::Mine);
                let waiting = self.probe_waiting_of.get(&(peer, g)).copied();
                let probed_in_frame = w.probe ||
                    any_probe &&
                        wants.iter().any(|o| o.probe && o.group == g && o.bits.has(idx));
                let flagged = probed_in_frame &&
                    claimed.is_some_and(|mine| mine.has(idx)) &&
                    !self.pairs.probe_served(&(peer, g)) &&
                    waiting.is_none_or(|j| j == idx);
                if peer_claimed && !flagged {
                    env.penalise(peer, PenaltyReason::AskedForClaimedChunk);
                    continue;
                }
                if self.pairs.served(&(peer, g)) >= serve_limit {
                    continue;
                }
                let Some(&mid) = self.known_id.get(&(g, idx)) else {
                    let passed =
                        hops > 0 && self.route_want(peer, t, g, idx, hops, env, catalog, rng);
                    // Claimed, not stored: we are decoding. The first probe per asker and
                    // group is kept and answered once, when the chunk is stored, in place
                    // of a standing WANT of that index from the asker (§4.6).
                    if flagged && waiting.is_none() {
                        if !self.probe_waiting_of.is_full() &&
                            self.probe_waiting.insert((g, idx), peer)
                        {
                            self.probe_waiting_of.insert((peer, g), idx);
                            self.standing.remove(&(g, idx), peer);
                            self.routed_standing.remove(&(g, idx), peer);
                        }
                    } else if (declared || w.standing) &&
                        waiting != Some(idx) &&
                        (hops == 0 || passed || in_our_interest)
                    {
                        self.standing.insert((g, idx), peer);
                        if hops > 0 {
                            self.routed_standing.insert((g, idx), peer);
                        }
                    }
                    continue;
                };
                if self.groups.get(&g).and_then(|r| r.state.as_ref()) ==
                    Some(&crate::types::GroupState::Invalid)
                {
                    continue;
                }
                // An id asked twice in one frame is answered and counted once; a
                // probe of the cell through its other type takes its exemption on
                // the answer already chosen (§4.5).
                if let Some(&ans_idx) = self.frame_ids.get(&mid) {
                    if flagged {
                        self.pairs.set_probe_served((peer, g));
                        let (ag, aidx) = answers[ans_idx];
                        if let Some(of) =
                            self.resolve_chunk(&ag, aidx).map(|f| (peer, f.group, f.index))
                        {
                            self.probe_answers.insert(of);
                        }
                    }
                    continue;
                }
                if self.unwanted.contains(&(peer, mid)) && !flagged {
                    continue;
                }
                if self.serve_count.get(&(peer, mid)).copied().unwrap_or(0) >=
                    self.config.gossip_retransmission
                {
                    continue;
                }
                // An answer whose counts cannot be kept is not given: the limits
                // would not hold.
                if self.serve_count.is_full() && !self.serve_count.contains_key(&(peer, mid)) ||
                    !self.pairs.has_room(&(peer, g))
                {
                    continue;
                }
                let counted =
                    !flagged && !self.pairs.offered_to(&(peer, g)).is_some_and(|b| b.has(idx));
                if counted && self.slots.get(peer).is_none_or(|s| s.served_now >= budget) {
                    continue;
                }
                if counted {
                    if let Some(slot) = self.slots.get_mut(peer) {
                        slot.served_now += 1;
                    }
                }
                *self.serve_count.entry_or_default((peer, mid)) += 1;
                self.pairs.add_served((peer, g));
                if flagged {
                    // The cap is taken, and the answer passes the write's filter once,
                    // under the chunk's own group and index (`serve_probe`).
                    self.pairs.set_probe_served((peer, g));
                    if let Some(of) = self.resolve_chunk(&g, idx).map(|f| (peer, f.group, f.index))
                    {
                        self.probe_answers.insert(of);
                    }
                }
                if let Some(at) = at {
                    taken[at].1.set(idx);
                }
                self.frame_ids.insert(mid, answers.len());
                let _ = answers.push((g, idx));
            }
        }
        self.frame_ids.clear();
        answers
    }

    /// Our interest in `group` as we declared it to `peer` (`seacast.md` §4.5
    /// `our_interest_for`).
    pub(crate) fn our_interest_for<C>(&self, peer: PeerId, group: &GroupId, catalog: &C) -> Bitmap
    where
        C: ObjectCatalog<B>,
    {
        let Some(j) = self.join_sent(peer, group.type_id) else {
            return Bitmap::EMPTY;
        };
        match j.interest {
            InterestKind::All => Bitmap::EVERY_INDEX,
            InterestKind::Derived => catalog.own_interest(group),
            InterestKind::Declared => Bitmap::EMPTY,
        }
    }

    /// Whether `(group, index)` is outside what this node serves `peer` once
    /// the group's gate is open (`seacast.md` §4.5 `outside`).
    pub(crate) fn outside<C>(
        &self,
        peer: PeerId,
        group: &GroupId,
        index: u32,
        routed: bool,
        catalog: &C,
    ) -> bool
    where
        C: ObjectCatalog<B>,
    {
        if !catalog.authenticable(group) ||
            self.groups.has_bits(group, GroupBits::Origin) ||
            self.groups.bits(group, GroupBits::Mine).is_some_and(|m| m.has(index))
        {
            return false;
        }
        if routed && self.join_sent(peer, group.type_id).is_some_and(|j| j.duty == Duty::Forward) {
            return false;
        }
        !self.our_interest_for(peer, group, catalog).has(index)
    }

    /// Sweeps standing requests and `want_p` bits that arrived before `group`'s
    /// gate opened and fall outside what this node serves (`seacast.md` §4.5
    /// `drop_outside`).
    pub(crate) fn drop_outside<C>(&mut self, group: GroupId, catalog: &C)
    where
        C: ObjectCatalog<B>,
    {
        // One index at a time, so that no list of every (index, peer) is needed.
        let mut indices = Bitmap::new();
        for &(g, i) in self.standing.keys() {
            if g == group {
                indices.set(i);
            }
        }
        let mut out = std::mem::replace(&mut self.peer_scratch, PreallocVec::with_capacity(0));
        for i in indices.iter() {
            out.clear();
            for q in self.standing.iter(&(group, i)) {
                let routed = self.routed_standing.contains(&(group, i), q);
                if self.outside(q, &group, i, routed, catalog) {
                    let _ = out.push(q);
                }
            }
            for &q in out.iter() {
                self.standing.remove(&(group, i), q);
                self.routed_standing.remove(&(group, i), q);
            }
        }
        self.peer_scratch = out;
        // Pairs exist only for connected peers.
        for k in 0..self.peers.len() {
            let q = self.peers[k];
            let Some(bits) = self.pairs.want_p(&(q, group)) else {
                continue;
            };
            let mut kept = bits;
            for i in bits.iter() {
                let routed = self.routed_standing.contains(&(group, i), q);
                if self.outside(q, &group, i, routed, catalog) {
                    kept.clear(i);
                }
            }
            if kept.is_empty() {
                self.pairs.clear_want_p(&(q, group));
            } else if kept != bits {
                self.pairs.set_want_p((q, group), kept);
            }
        }
    }

    /// Strips standing requests, route marks and `want_p` bits at or past
    /// `group`'s index count `n` once it is known (`seacast.md` §4.5
    /// `drop_wants_beyond`).
    pub(crate) fn drop_wants_beyond(&mut self, group: GroupId, n: u32) {
        self.standing.retain_keys(|&(g, i)| g != group || i < n);
        self.routed_standing.retain_keys(|&(g, i)| g != group || i < n);
        self.pairs.retain_want_p(&group, &self.peers, |i| i < n);
    }

    /// Passes a routed sample request this node cannot answer one step on: to
    /// a link that serves the index, or, where none does and steps are left,
    /// to a forwarding link (`seacast.md` §4.5 `route_want`). Returns `true`
    /// if the next peer's queue admitted the request.
    #[allow(clippy::too_many_arguments)]
    fn route_want<E, C, R>(
        &mut self,
        peer: PeerId,
        t: TypeId,
        group: GroupId,
        index: u32,
        hops: u8,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
    ) -> bool
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        // By node and type: a connection's end does not reset the count.
        let Some(id) = self.slots.get(peer).map(|s| s.node_id) else {
            return false;
        };
        let key = (id, t);
        let passed = match self.forwarded.get(&key) {
            Some(&n) => n,
            // No room for a count: the limit could not be held.
            None if self.forwarded.is_full() => return false,
            None => 0,
        };
        if passed >= catalog.params(t).forward_limit {
            return false;
        }
        let now = env.now();
        let mut left = 0;
        let mut pick = self.choose_one(self.links(t), rng, |q| {
            q != peer &&
                self.join_recv(q, t).is_some_and(|j| j.interest != InterestKind::Declared) &&
                self.interest_of_peer(q, &group, catalog).has(index) &&
                !self.parked(q, &group, now)
        });
        if pick.is_none() && hops > 1 {
            pick = self.choose_one(self.links(t), rng, |q| {
                q != peer && self.join_recv(q, t).is_some_and(|j| j.duty == Duty::Forward)
            });
            left = hops - 1;
        }
        let Some(q) = pick else {
            return false;
        };
        let want = Want { hops: left, ..Want::standing(group, Bitmap::singleton(index)) };
        if !self.enqueue(q, Queued::from_want(want), false, env) {
            return false;
        }
        *self.forwarded.entry_or_default(key) += 1;
        true
    }

    /// Serves standing `Want` requests that preceded the arrival of `(group,
    /// index)` (`serve_standing`).
    pub fn serve_standing<E, C>(&mut self, group: GroupId, index: u32, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if !self.standing.contains_key(&(group, index)) {
            return;
        }
        if self.resolve_chunk(&group, index).is_none() {
            self.standing.remove_key(&(group, index));
            self.routed_standing.remove_key(&(group, index));
            return;
        }
        let t = group.type_id;
        let serve_limit = catalog.params(t).serve_limit;
        let now = env.now();

        self.for_each(PeerSet::Standing(group, index), |node, q| {
            let peer_already_has =
                node.pairs.peer_has(&(q, group)).map(|e| e.has(index)).unwrap_or(false);
            let served_so_far = node.pairs.served(&(q, group));
            let counted = !node.pairs.offered_to(&(q, group)).is_some_and(|b| b.has(index));
            let over = counted &&
                node.slots
                    .get(q)
                    .is_none_or(|s| s.served_now >= node.config.max_served_per_heartbeat);
            if peer_already_has ||
                served_so_far >= serve_limit ||
                over ||
                !node.pairs.has_room(&(q, group))
            {
                return;
            }
            if counted {
                if let Some(slot) = node.slots.get_mut(q) {
                    slot.served_now += 1;
                }
            }
            node.pairs.add_served((q, group));
            let entry = Queued::Chunk { group, index, solicited: true };
            if !node.enqueue(q, entry, false, env) {
                let single = node.single_chunk(&group);
                node.sends.owe_answer(q, group, index, single);
            }
            node.note_push(q, group, index, now, catalog);
        });
        self.standing.remove_key(&(group, index));
        self.routed_standing.remove_key(&(group, index));
    }

    /// Answers the probes kept for `(group, index)`, now stored, received or
    /// rebuilt, as `on_want` answers a probe, with its one exemption
    /// (`seacast.md` §4.6 `serve_waiting_probe`).
    pub fn serve_waiting_probe<E, C>(
        &mut self,
        group: GroupId,
        index: u32,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if !self.probe_waiting.contains_key(&(group, index)) {
            return;
        }
        let Some(of) = self.resolve_chunk(&group, index).map(|f| (f.group, f.index)) else {
            return;
        };
        let t = group.type_id;
        let serve_limit = catalog.params(t).serve_limit;
        let now = env.now();
        self.for_each(PeerSet::ProbeWaiting(group, index), |node, q| {
            node.probe_waiting_of.remove(&(q, group));
            if node.pairs.probe_served(&(q, group)) || node.pairs.served(&(q, group)) >= serve_limit
            {
                return;
            }
            node.pairs.add_served((q, group));
            node.pairs.set_probe_served((q, group));
            node.probe_answers.insert((q, of.0, of.1));
            let entry = Queued::Chunk { group, index, solicited: true };
            if !node.enqueue(q, entry, false, env) {
                let single = node.single_chunk(&group);
                node.sends.owe_answer(q, group, index, single);
            }
            node.note_push(q, group, index, now, catalog);
        });
        self.probe_waiting.remove_key(&(group, index));
    }

    /// Returns `true` if `peer` may legitimately be asked for `(group, index)`
    /// (`may_be_asked(p, g, i)`).
    pub fn may_be_asked<C>(&self, peer: PeerId, group: &GroupId, index: u32, catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        let offered_us = self.pairs.offered(&(peer, *group)).map(|b| b.has(index)).unwrap_or(false);
        let in_interest = self.interest_of_peer(peer, group, catalog).has(index);
        let claimed_all =
            self.pairs.peer_has(&(peer, *group)).map(|e| e.claim_all).unwrap_or(false);
        offered_us || in_interest || claimed_all
    }

    /// Checks if an ask for `a` may be sent now (`seacast-lite.md` §6.1
    /// `may_ask(a, p)` `[c5]`).
    pub fn may_ask<E>(&mut self, ask: Ask, peer: PeerId, env: &mut E) -> bool
    where
        E: RuntimeEnv<B>,
    {
        let now = env.now();
        let iwant_win = self.config.scaled_iwant_window();
        match self.asked_at.get(&ask) {
            Some(&at) if now - at < iwant_win => return false,
            Some(_) => {}
            // An ask that cannot be recorded is not made: nothing would stop its repeat. The
            // next heartbeat takes its group up again.
            None if self.asked_at.is_full() => {
                self.held_groups.insert(ask.group);
                return false;
            }
            None => {}
        }
        // The same for an ask over the peer's bound or the table's.
        if !self.tried.has_room(ask, peer) {
            self.held_groups.insert(ask.group);
            return false;
        }
        self.asked_at.insert(ask, now);
        self.tried.insert(ask, peer, now);
        env.schedule_after(iwant_win + self.config.retry_slack, TimerEvent::RetryOffer(ask));
        true
    }

    /// Retries an ask after `IWANT_WINDOW` closes (`seacast-lite.md` §6.1
    /// `retry_offer(a)`).
    pub fn retry_offer<E, C>(&mut self, ask: Ask, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if self.held(ask) ||
            self.groups
                .get(&ask.group)
                .and_then(|r| r.stop_pull.as_ref())
                .copied()
                .unwrap_or(false) ||
            self.expired(&ask.group)
        {
            return;
        }
        // Nothing is asked for before it can be authenticated (`seacast.md` §4.2):
        // the offers wait in the ledger, and the gate's opening retries them.
        if !catalog.authenticable(&ask.group) {
            return;
        }
        let now = env.now();
        let iwant_win = self.config.scaled_iwant_window();
        if let Some(&at) = self.asked_at.get(&ask) {
            if now - at < iwant_win {
                return;
            }
        }
        let cand = |q: PeerId| !self.parked(q, &ask.group, now) && !self.tied_to_root(q, ask);
        if !self.announcers(ask).any(cand) {
            self.last_resort(ask, env, catalog);
            return;
        }
        let Some(pick) = self.pick_announcer(ask, |q| cand(q) && !self.outstanding(q, ask)) else {
            env.schedule_after(iwant_win + self.config.retry_slack, TimerEvent::RetryOffer(ask));
            return;
        };
        if self.may_ask(ask, pick, env) {
            let want = Want::pull_ask(ask);
            self.enqueue(pick, Queued::from_want(want), false, env);
        }
    }

    /// Returns `true` if an ask for `ask` to `peer` is currently promised or
    /// queued (`outstanding(q, a)`).
    pub fn outstanding(&self, peer: PeerId, ask: Ask) -> bool {
        self.promises.contains(ask, peer) || self.sends.ask_waiting(peer, ask)
    }

    /// Records `peer`'s offer of `ask` (`seacast-lite.md` §6.1 `add_offer(a,
    /// p)`).
    pub fn add_offer(&mut self, ask: Ask, peer: PeerId, now: Timestamp) {
        let key = (peer, ask.group);
        let mut offered = self.pairs.offered(&key).unwrap_or_default();
        offered.set(ask.index);
        self.pairs.set_offered(key, offered);
        self.pairs.set_offer_at(key, now);

        let max_offers = self.config.max_offers_per_ask;
        let max_listed = self.config.max_listed_per_peer;
        let Some(slot) = self.slots.get_mut(peer) else {
            return;
        };
        // With no room for the ask's list the peer is not listed: a count taken
        // for a list that is not kept would never be given back.
        if self.offers.is_full() && !self.offers.contains_key(&ask) {
            return;
        }
        let list = self.offers.entry_or_default(ask);
        if !list.contains(&peer) && list.len() < max_offers && slot.listed_count < max_listed {
            if list.push(peer) {
                slot.listed_count += 1;
            }
        }
    }

    /// Drops `peer`'s offers and queued/promised asks of `(group, index)`
    /// (`drop_offer` in `seacast-lite.md` §6.1).
    pub fn drop_offer(&mut self, group: GroupId, index: u32, peer: PeerId) {
        self.drop_offers(group, &Bitmap::singleton(index), peer);
    }

    /// [`Self::drop_offer`] for every index of `bits`, with one pass over the
    /// peer's queue.
    pub fn drop_offers(&mut self, group: GroupId, bits: &Bitmap, peer: PeerId) {
        if let Some(offered) = self.pairs.offered(&(peer, group)) {
            self.pairs.set_offered((peer, group), offered.and_not(bits));
        }
        for index in bits.iter() {
            let ask = Ask::new(group, index);
            let mut remove_ask = false;
            if let Some(list) = self.offers.get_mut(&ask) {
                if list.remove_item(&peer) {
                    if let Some(slot) = self.slots.get_mut(peer) {
                        slot.listed_count = slot.listed_count.saturating_sub(1);
                    }
                }
                remove_ask = list.is_empty();
            }
            if remove_ask {
                self.offers.remove(&ask);
            }
            self.promises.remove(ask, peer);
        }
        self.sends.cancel_asks(peer, group, bits);
    }

    /// The peers that offered `ask`: its offer list, then every other peer
    /// whose offers of the group name the index (`announcers(a)`). Their order
    /// is [`Self::announcer_rank`].
    pub fn announcers(&self, ask: Ask) -> impl Iterator<Item = PeerId> + '_ {
        let listed = self.offers.get(&ask).map(|list| list.as_slice()).unwrap_or(&[]);
        let others = self.pairs.offering(&ask.group).filter(move |q| {
            !listed.contains(q) &&
                self.pairs.offered(&(*q, ask.group)).is_some_and(|b| b.has(ask.index))
        });
        listed.iter().copied().chain(others)
    }

    /// Where `q` stands among the announcers of `ask`, smaller first: the offer
    /// list in its order, then the others by HMAC-SHA-256 of the ask and peer
    /// under `NodeConfig::order_key`, larger first (`seacast-lite.md` §6.1).
    fn announcer_rank(&self, ask: Ask, q: PeerId) -> (u64, u64, u64) {
        let listed = self.offers.get(&ask).and_then(|list| list.iter().position(|&p| p == q));
        match listed {
            Some(at) => (0, at as u64, 0),
            None => {
                let mut msg = [0u8; 47];
                msg[0] = ask.group.type_id.0;
                msg[1..33].copy_from_slice(&ask.group.key);
                msg[33..35].copy_from_slice(&ask.group.index.to_le_bytes());
                msg[35..39].copy_from_slice(&ask.index.to_le_bytes());
                msg[39..47].copy_from_slice(&q.to_le_bytes());
                let score = crate::hmac::hmac_sha256_u64(&self.config.order_key, &msg);
                (1, !score, !q)
            }
        }
    }

    /// The announcer of `ask` to ask among those `free` takes: one not tried
    /// yet, else the one tried longest ago; of several, the first in the
    /// announcers' order.
    fn pick_announcer(&self, ask: Ask, free: impl Fn(PeerId) -> bool) -> Option<PeerId> {
        let free = || self.announcers(ask).filter(|&q| free(q));
        let untried = free()
            .filter(|&q| !self.tried.contains(ask, q))
            .min_by_key(|&q| self.announcer_rank(ask, q));
        untried.or_else(|| {
            free().min_by(|&a, &b| {
                let ta = self.tried.get(ask, a).unwrap_or(f64::NEG_INFINITY);
                let tb = self.tried.get(ask, b).unwrap_or(f64::NEG_INFINITY);
                ta.partial_cmp(&tb)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| self.announcer_rank(ask, a).cmp(&self.announcer_rank(ask, b)))
            })
        })
    }

    /// Returns all offered and not-yet-held asks of `group` (`seacast-lite.md`
    /// §6.1 `ledger(g)`).
    pub fn ledger(&self, group: &GroupId) -> InlineVec<Ask, MAX_BITMAP_BITS> {
        let mut bits = Bitmap::new();
        for q in self.pairs.offering(group) {
            if let Some(b) = self.pairs.offered(&(q, *group)) {
                bits |= b;
            }
        }
        let mine = self.groups.bits(group, GroupBits::Mine).unwrap_or(Bitmap::EMPTY);
        let mut out = InlineVec::new();
        for i in bits.and_not(&mine).iter() {
            let _ = out.push(Ask::new(*group, i));
        }
        out
    }

    /// Parks `peer` for `ask.group` when its promise expires unanswered
    /// (`promise_due(a, p, at)`).
    pub fn promise_due<E>(&mut self, ask: Ask, peer: PeerId, at_bits: u64, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        if self.promises.get(ask, peer) != Some(at_bits) {
            return;
        }
        self.promises.remove(ask, peer);
        let now = env.now();
        self.pairs.set_park((peer, ask.group), now + self.config.park_ttl);
    }

    /// Returns `true` if `peer` is currently parked for `group` (`parked(p,
    /// a)`).
    #[inline]
    pub fn parked(&self, peer: PeerId, group: &GroupId, now: Timestamp) -> bool {
        self.pairs.park(&(peer, *group)).map(|until| now < until).unwrap_or(false)
    }

    /// Arms a doubling backoff retry when every announcer of `ask` is parked
    /// (`last_resort(a)`).
    pub fn last_resort<E, C>(&mut self, ask: Ask, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let k = (ask.group, ask.index);
        let now = env.now();
        let untied = |q: &PeerId| !self.tied_to_root(*q, ask);
        if self.last_resort_armed.contains(&k) ||
            self.announcers(ask).filter(untied).any(|q| !self.parked(q, &ask.group, now))
        {
            return;
        }
        let done_len = self.asked_parked.count(&k);
        let all_done =
            self.announcers(ask).filter(untied).all(|q| self.asked_parked.contains(&k, q));
        if all_done {
            return;
        }
        self.last_resort_armed.insert(k);
        let factor = 1u64.checked_shl(done_len as u32).unwrap_or(u64::MAX);
        let t = ask.group.type_id;
        let delay = catalog.params(t).promise * (factor as f64);
        env.schedule_after(delay, TimerEvent::AskParked(ask));
    }

    /// Asks a parked announcer once more when `last_resort`'s timer fires
    /// (`ask_parked(a)`).
    pub fn ask_parked<E, C>(&mut self, ask: Ask, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let _ = catalog;
        let k = (ask.group, ask.index);
        self.last_resort_armed.remove(&k);
        if self.held(ask) ||
            self.groups
                .get(&ask.group)
                .and_then(|r| r.stop_pull.as_ref())
                .copied()
                .unwrap_or(false) ||
            self.expired(&ask.group)
        {
            return;
        }
        let now = env.now();
        let iwant_win = self.config.scaled_iwant_window();
        if let Some(&at) = self.asked_at.get(&ask) {
            if now - at < iwant_win {
                return;
            }
        }
        // An announcer unparked meanwhile first, else one not asked while parked.
        let untied = |q: PeerId| !self.tied_to_root(q, ask);
        let unparked = |q: PeerId| untied(q) && !self.parked(q, &ask.group, now);
        let unasked = |q: PeerId| untied(q) && !self.asked_parked.contains(&k, q);
        let any_unparked = self.announcers(ask).any(unparked);
        if !any_unparked && !self.announcers(ask).any(unasked) {
            return;
        }
        let cand = |q: PeerId| if any_unparked { unparked(q) } else { unasked(q) };
        let Some(pick) = self.pick_announcer(ask, |q| cand(q) && !self.outstanding(q, ask)) else {
            self.last_resort_armed.insert(k);
            env.schedule_after(iwant_win + self.config.retry_slack, TimerEvent::AskParked(ask));
            return;
        };
        let want = Want::pull_ask(ask);
        if self.may_ask(ask, pick, env) && self.enqueue(pick, Queued::from_want(want), false, env) {
            if self.parked(pick, &ask.group, now) {
                self.asked_parked.insert(k, pick);
            }
        }
    }

    pub(crate) fn close_promises(&mut self, group: GroupId, index: u32, of_peer: Option<PeerId>) {
        let ask = Ask::new(group, index);
        if let Some(peer) = of_peer {
            self.promises.remove(ask, peer);
            return;
        }
        self.tried.remove_ask(ask);
        self.promises.remove_ask(ask);
        if let Some(list) = self.offers.remove(&ask) {
            for p in list {
                if let Some(slot) = self.slots.get_mut(p) {
                    slot.listed_count = slot.listed_count.saturating_sub(1);
                }
            }
        }
        self.asked_at.remove(&ask);
        self.asked_parked.remove_key(&(group, index));
        self.pairs.clear_offered(&group, index);
    }

    /// `group`'s count is known now: the holdings, offers, asks, tries and
    /// promises of an index it has not go (`drop_beyond`, `seacast-lite.md`
    /// §4.2, §8.2). Every
    /// ask is of an offered index, so the offers name them all. A tie past the
    /// count went at its release, before the group could open.
    pub(crate) fn drop_beyond(&mut self, group: GroupId, n: u32) {
        // A holding saved before the count was known keeps no index past it:
        // it would count toward the group being whole elsewhere.
        let within = Bitmap::all_bits(n);
        for k in 0..self.peers.len() {
            let key = (self.peers[k], group);
            if let Some(mut e) = self.pairs.peer_has(&key) {
                if !e.bits.and_not(&within).is_empty() {
                    e.bits = e.bits & within;
                    self.pairs.set_peer_has(key, e);
                }
            }
        }
        let mut beyond = Bitmap::new();
        for q in self.pairs.offering(&group) {
            if let Some(bits) = self.pairs.offered(&(q, group)) {
                beyond |= &bits;
            }
        }
        let beyond = beyond.and_not(&Bitmap::all_bits(n));
        if beyond.is_empty() {
            return;
        }
        let mut offering = std::mem::replace(&mut self.peer_scratch, PreallocVec::with_capacity(0));
        offering.clear();
        for q in self.pairs.offering(&group) {
            let _ = offering.push(q);
        }
        for &q in offering.iter() {
            self.drop_offers(group, &beyond, q);
        }
        self.peer_scratch = offering;
        for i in beyond.iter() {
            self.close_promises(group, i, None);
        }
    }

    pub(crate) fn close_promises_of_group(&mut self, group: &GroupId) {
        self.promises.retain(|a, _, _| &a.group != group);
    }
}
