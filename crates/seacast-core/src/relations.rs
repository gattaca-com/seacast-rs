use crate::{
    bitmap::Bitmap,
    collections::{InlineVec, PreallocVec, word_bits},
    message::{Control, Graft, Join, Prune},
    node::SeacastNode,
    state::{GroupBits, PeerSet},
    traits::{ChunkBuffer, ObjectCatalog, RngSource, RuntimeEnv},
    types::{
        Colour, Direction, Duty, FamilyId, GroupId, GroupState, InterestKind, PeerId, Timestamp,
        TypeId, UplinkClass,
    },
};

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Handles a `Join` from `peer` (`seacast.md` §4.1 `on_join`).
    pub fn on_join<E, C>(&mut self, peer: PeerId, join: Join, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let t = join.object_type;
        // The type id is the peer's: nothing is asked of the catalog, or kept, for a
        // type this node does not run.
        if !catalog.joined_types().contains(&t) ||
            join.colours != catalog.params(t).m ||
            join.fork_digest != catalog.our_join(t).fork_digest
        {
            return;
        }
        let Some(slot) = self.slots.get_mut(peer) else {
            return;
        };
        slot.join_recv.insert(t, join);
        if !slot.join_sent.contains_key(&t) {
            let our = catalog.our_join(t);
            // The answer, unless ours went first (§4.1 `send_join`).
            slot.join_sent.insert(t, our);
            self.sends.send_relation(peer, Control::Join(our), env);
        }
        self.relink(peer, t);
    }

    /// Computes what `peer` is to receive of `group`, as far as we know
    /// (`interest_of_peer(p, g)`).
    pub fn interest_of_peer<C>(&self, peer: PeerId, group: &GroupId, catalog: &C) -> Bitmap
    where
        C: ObjectCatalog<B>,
    {
        let t = group.type_id;
        let Some(j) = self.join_recv(peer, t) else {
            return Bitmap::EMPTY;
        };
        match j.interest {
            InterestKind::All => Bitmap::EVERY_INDEX,
            InterestKind::Derived => catalog.derived_interest(
                group,
                self.groups.get(group).and_then(|r| r.hdr.as_ref()),
                peer,
                &catalog.node_id(peer),
                j,
            ),
            InterestKind::Declared => self.pairs.want_p(&(peer, *group)).unwrap_or(Bitmap::EMPTY),
        }
    }

    /// Computes indices of `group` that `peer` still wants from us
    /// (`wants_from_me(p, g)`).
    pub fn wants_from_me<C>(&self, peer: PeerId, group: &GroupId, catalog: &C) -> Bitmap
    where
        C: ObjectCatalog<B>,
    {
        let pushed_bits = &self.pairs.pushed_bits(&(peer, *group));
        if let Some(e) = self.pairs.peer_has(&(peer, *group)) {
            if e.complete {
                return Bitmap::EMPTY;
            }
            let interest = self.interest_of_peer(peer, group, catalog);
            interest.and_not(&e.bits).and_not(pushed_bits)
        } else {
            let interest = self.interest_of_peer(peer, group, catalog);
            interest.and_not(pushed_bits)
        }
    }

    /// Maintains push/in relations for object type `t` at the heartbeat
    /// (`maintain_relations(T)`).
    pub fn maintain_relations<E, C, R>(&mut self, t: TypeId, env: &mut E, catalog: &C, rng: &mut R)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
    {
        // A node without duty for the type holds no relations (`seacast.md` §1.2).
        if catalog.our_join(t).duty != Duty::Forward || catalog.params(t).host_relations {
            return;
        }
        let now = env.now();
        let prm = catalog.params(t);
        let (m, f_lo, f_hi) = (prm.m, prm.f_lo, prm.f_hi);
        let target = match self.config.uplink_class() {
            UplinkClass::Fast => prm.d_out_fast,
            _ => prm.d_out,
        };

        for fam in catalog.families_with_duty(t) {
            for c in 0..m {
                let ins = self.count(self.in_pushers(t, fam, c));
                if prm.symmetric {
                    // Kept as gossipsub keeps its mesh: below the floor grafted up to `D_OUT`,
                    // at the cap, where `on_graft` refuses, pruned down to it at random.
                    if ins < f_lo {
                        let n = prm.d_out.saturating_sub(ins);
                        self.graft_candidates(t, fam, c, Direction::Both, n, now, env, catalog);
                    } else if ins >= f_hi {
                        let n = ins.saturating_sub(prm.d_out);
                        let mut held = std::mem::replace(
                            &mut self.peer_scratch,
                            PreallocVec::with_capacity(0),
                        );
                        held.clear();
                        for q in self.peers_of(self.in_pushers(t, fam, c)) {
                            let _ = held.push(q);
                        }
                        let n = n.min(held.len());
                        rng.sample_in_place(held.as_mut_slice(), n);
                        for &q in &held[..n] {
                            self.prune(q, t, fam, c, Direction::Both, env);
                        }
                        self.peer_scratch = held;
                    }
                    // Held one way only, by lost state: grafted again at any count, and the
                    // other end makes it whole or refuses it.
                    self.for_each(PeerSet::OneWay(t, fam, c), |node, q| {
                        let key = (q, t, fam, c);
                        if !node.grafted_in.contains(&key) && !node.grafted_out.contains(&key) {
                            node.graft(q, t, fam, c, Direction::Both, env);
                        }
                    });
                    continue;
                }
                // The floor per colour: "push me", counted once the peer says yes.
                if ins < f_lo {
                    self.graft_candidates(t, fam, c, Direction::In, f_lo - ins, now, env, catalog);
                }
                if ins > f_hi {
                    let mut kept = 0;
                    self.for_each(self.in_pushers(t, fam, c), |node, q| {
                        kept += 1;
                        if kept > f_hi {
                            node.prune(q, t, fam, c, Direction::In, env);
                        }
                    });
                }
                // "I will push you": pushed once the peer says yes.
                let n = target.saturating_sub(self.count(self.out_pushees(t, fam, c)));
                self.graft_candidates(t, fam, c, Direction::Out, n, now, env, catalog);
            }
        }
    }

    /// Our GRAFT: nothing is counted until the peer answers it (`graft`).
    fn graft<E>(
        &mut self,
        q: PeerId,
        t: TypeId,
        fam: FamilyId,
        c: Colour,
        d: Direction,
        env: &mut E,
    ) where
        E: RuntimeEnv<B>,
    {
        if d.includes_in() {
            self.grafted_in.insert((q, t, fam, c));
        }
        if d.includes_out() {
            self.grafted_out.insert((q, t, fam, c));
        }
        let graft = Graft { object_type: t, family: fam, colour: c, direction: d, answer: false };
        // A GRAFT that could not be owed was not sent: nothing waits for its
        // answer, and upkeep makes it again.
        if !self.sends.send_relation(q, Control::Graft(graft), env) {
            self.grafted_in.remove(&(q, t, fam, c));
            self.grafted_out.remove(&(q, t, fam, c));
        }
    }

    /// Our PRUNE: the relation ends at our end at once (`prune`).
    fn prune<E>(
        &mut self,
        q: PeerId,
        t: TypeId,
        fam: FamilyId,
        c: Colour,
        d: Direction,
        env: &mut E,
    ) where
        E: RuntimeEnv<B>,
    {
        if d.includes_in() {
            self.push_in.remove(&(q, t, fam, c));
            self.grafted_in.remove(&(q, t, fam, c));
        }
        if d.includes_out() {
            self.push_out.remove(&(q, t, fam, c));
            self.grafted_out.remove(&(q, t, fam, c));
        }
        let prune = Prune { object_type: t, family: fam, colour: c, direction: d };
        self.sends.send_relation(q, Control::Prune(prune), env);
    }

    /// The answer to a GRAFT, from our side: a GRAFT is yes, a PRUNE no (`yes`,
    /// `no`).
    fn answer<E>(&mut self, p: PeerId, gr: &Graft, d: Direction, yes: bool, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        let (object_type, family, colour) = (gr.object_type, gr.family, gr.colour);
        let message = match yes {
            true => {
                Control::Graft(Graft { object_type, family, colour, direction: d, answer: true })
            }
            false => Control::Prune(Prune { object_type, family, colour, direction: d }),
        };
        self.sends.send_relation(p, message, env);
    }

    /// Handles an incoming `Graft`: each direction is answered, and one that is
    /// the yes to ours, or crossed it, is not (`seacast.md` §4.1
    /// `on_graft`, `[D10]`).
    pub fn on_graft<E, C>(&mut self, peer: PeerId, gr: Graft, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let t = gr.object_type;
        let prm = catalog.params(t);
        if !self.is_linked(peer, t) || prm.host_relations {
            return;
        }
        let (fam, c) = (gr.family, gr.colour);
        // No such colour: not a relation of this type.
        if c >= prm.m {
            return;
        }
        // Families x colours one link may carry, in any state (`seacast.md`
        // §4.1 `relation_room`, `MAX_RELATIONS`). At the limit, a GRAFT for a
        // new pair is ignored with no answer.
        if !self.relation_room(peer, t, fam, c, env.now(), catalog) {
            return;
        }
        let key = (peer, t, fam, c);

        if prm.symmetric {
            // One relation both ways: decided as one, one answer.
            let asked_in = self.grafted_in.remove(&key);
            let asked = self.grafted_out.remove(&key) || asked_in;
            let (held_in, held_out) = (self.push_in.contains(&key), self.push_out.contains(&key));
            let held = held_in || held_out;
            let duty = self.join_sent(peer, t).is_some_and(|j| j.duty == Duty::Forward);
            let room = self.count(self.in_pushers(t, fam, c)) < prm.f_hi &&
                catalog.wants_family(t, fam) &&
                duty;
            // A relation the tables cannot keep is refused, and one held one way
            // that cannot be made whole ends.
            let fits = self.push_in.has_room(&key) && self.push_out.has_room(&key);
            if !held && !room || !fits {
                self.push_in.remove(&key);
                self.push_out.remove(&key);
                self.answer(peer, &gr, Direction::Both, false, env);
                return;
            }
            // Held either way: made whole again.
            if !held_in {
                self.push_in.insert(key);
            }
            if !asked && !(held && gr.answer) {
                self.answer(peer, &gr, Direction::Both, true, env);
            }
            if !held_out {
                self.push_out.insert(key);
                self.on_relation_join(peer, t, fam, c, env, catalog);
            }
            return;
        }

        // The peer will push us colour `c`.
        if gr.direction.includes_out() {
            // The yes to our "push me", or a GRAFT that crossed it.
            let asked = self.grafted_in.remove(&key);
            if self.push_in.contains(&key) {
                // Held: yes again, unless it answers ours or is a yes.
                if !asked && !gr.answer {
                    self.answer(peer, &gr, Direction::In, true, env);
                }
            } else if self.count(self.in_pushers(t, fam, c)) < prm.f_hi &&
                catalog.wants_family(t, fam) &&
                self.push_in.has_room(&key)
            {
                self.push_in.insert(key);
                if !asked {
                    self.answer(peer, &gr, Direction::In, true, env);
                }
            } else {
                // "Stop pushing me": the no names its direction from our side.
                self.answer(peer, &gr, Direction::In, false, env);
            }
        }

        // The peer asks us to push it colour `c`.
        if gr.direction.includes_in() {
            let asked = self.grafted_out.remove(&key);
            let our_duty =
                self.join_sent(peer, t).map(|j| j.duty).unwrap_or_else(|| catalog.our_join(t).duty);
            let has_duty =
                our_duty == Duty::Forward && catalog.families_with_duty(t).contains(&fam);
            if self.push_out.contains(&key) {
                if !asked && !gr.answer {
                    self.answer(peer, &gr, Direction::Out, true, env);
                }
            } else if has_duty &&
                self.count(self.out_pushees(t, fam, c)) < prm.d_out_max &&
                self.push_out.has_room(&key)
            {
                if !asked {
                    self.answer(peer, &gr, Direction::Out, true, env);
                }
                // In the relation at our end: what we hold is announced (`join_push`).
                self.push_out.insert(key);
                self.on_relation_join(peer, t, fam, c, env, catalog);
            } else {
                // "I will not push you".
                self.answer(peer, &gr, Direction::Out, false, env);
            }
        }
    }

    /// Handles an incoming `Prune`: the peer's no, or its end of the relation.
    /// Ours ends too, with our GRAFT for it still unanswered, and is not
    /// grafted again before the backoff has run (`seacast.md` §4.1
    /// `on_prune`).
    ///
    /// The backoff is kept only for a relation this node held or had asked
    /// for: a peer's PRUNEs of others make it keep nothing.
    pub fn on_prune<E, C>(&mut self, peer: PeerId, pr: Prune, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let t = pr.object_type;
        if !self.is_linked(peer, t) {
            return;
        }
        let key = (peer, t, pr.family, pr.colour);
        let prm = catalog.params(t);
        if prm.host_relations {
            return;
        }
        let until = env.now() + prm.prune_backoff;
        // A symmetric relation ends both ways.
        let d = if prm.symmetric { Direction::Both } else { pr.direction };
        // "I stop pushing you", "I will not push you": our "push me" waits.
        if d.includes_out() {
            let held = self.push_in.remove(&key);
            if self.grafted_in.remove(&key) || held {
                self.backoff.insert((peer, t, pr.family, pr.colour, true), until);
            }
        }
        // "Stop pushing me": our "I will push you" waits.
        if d.includes_in() {
            let held = self.push_out.remove(&key);
            if self.grafted_out.remove(&key) || held {
                self.backoff.insert((peer, t, pr.family, pr.colour, false), until);
            }
        }
    }

    /// The host's word that `peer` is in the relation of `(t, fam, c)`, both
    /// ways: on gossipsub's wires, that it is in the topic's mesh, by a GRAFT
    /// sent or one accepted (`seacast.md` §4.1, §7). What we hold is announced
    /// to it (`join_push`). `false`: the peer has not joined the type on the
    /// link, or the tables cannot keep the relation; the host then leaves it
    /// out of its mesh.
    pub fn relation_added<E, C>(
        &mut self,
        peer: PeerId,
        t: TypeId,
        fam: FamilyId,
        c: Colour,
        env: &mut E,
        catalog: &C,
    ) -> bool
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let key = (peer, t, fam, c);
        if !self.is_linked(peer, t) ||
            !(self.push_in.has_room(&key) && self.push_out.has_room(&key))
        {
            return false;
        }
        self.push_in.insert(key);
        if !self.push_out.contains(&key) {
            self.push_out.insert(key);
            self.on_relation_join(peer, t, fam, c, env, catalog);
        }
        true
    }

    /// The host's word that the relation of `(t, fam, c)` with `peer` has
    /// ended: a PRUNE sent or received. A closed connection needs none
    /// (`disconnect_peer`).
    pub fn relation_removed(&mut self, peer: PeerId, t: TypeId, fam: FamilyId, c: Colour) {
        let key = (peer, t, fam, c);
        self.push_in.remove(&key);
        self.push_out.remove(&key);
    }

    /// Announces stored chunks when a peer joins our out-relation
    /// (`seacast-lite.md` §5.4 `on_mesh_join`).
    pub fn on_relation_join<E, C>(
        &mut self,
        peer: PeerId,
        t: TypeId,
        fam: FamilyId,
        colour: Colour,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        // Every open group of the type and family, in the order of their ids.
        let mut groups: InlineVec<GroupId, 512> = InlineVec::new();
        for (g, rec) in self.groups.iter() {
            if rec.t_of.is_some() && g.type_id == t && catalog.family(g) == fam {
                let _ = groups.push(*g);
            }
        }
        groups.as_mut_slice().sort_unstable();
        let m = catalog.params(t).m.max(1) as u32;
        for g in groups {
            if self.expired(&g) ||
                self.groups.get(&g).and_then(|r| r.state.as_ref()) == Some(&GroupState::Invalid)
            {
                continue;
            }
            let tg = g.type_id;
            if tg != t || catalog.family(&g) != fam {
                continue;
            }
            let mut bits = Bitmap::new();
            for idx in self.groups.bits(&g, GroupBits::Mine).unwrap_or(Bitmap::EMPTY).iter() {
                if (idx % m) as u16 == colour && self.chunks.contains_key(&(g, idx)) {
                    bits.set(idx);
                }
            }
            if !bits.is_empty() {
                self.announce(peer, g, bits, env, catalog);
            }
        }
    }

    /// Returns all peers that have completed a bidirectional `Join` for `t`
    /// (`links(T)`).
    pub fn links(&self, t: TypeId) -> PeerSet {
        PeerSet::Links(t)
    }

    /// Word `w` of `set`.
    fn set_word(&self, set: PeerSet, w: usize) -> u64 {
        match set {
            PeerSet::Links(t) => self.linked.word(&t, w),
            PeerSet::In(t, fam, c) => self.push_in.word(t, fam, c, w),
            PeerSet::Out(t, fam, c) => self.push_out.word(t, fam, c, w),
            PeerSet::OneWay(t, fam, c) => {
                self.push_in.word(t, fam, c, w) ^ self.push_out.word(t, fam, c, w)
            }
            PeerSet::Scope(t, fam, m) => {
                self.linked.word(&t, w) & self.push_in.family_word(t, fam, m, w)
            }
            PeerSet::Standing(group, index) => self.standing.word(&(group, index), w),
            PeerSet::Claims(group) => self.claims.word(&group, w),
            PeerSet::ProbeWaiting(group, index) => self.probe_waiting.word(&(group, index), w),
            PeerSet::Unrelated(t, fam, m) => {
                self.linked.word(&t, w) &
                    !(self.push_in.family_word(t, fam, m, w) |
                        self.push_out.family_word(t, fam, m, w))
            }
        }
    }

    /// The peers of `set`, in peer id order.
    pub fn peers_of(&self, set: PeerSet) -> impl Iterator<Item = PeerId> + '_ {
        (0..self.linked.width()).flat_map(move |w| word_bits(w, self.set_word(set, w)))
    }

    pub fn count(&self, set: PeerSet) -> usize {
        (0..self.linked.width()).map(|w| self.set_word(set, w).count_ones() as usize).sum()
    }

    #[inline]
    pub fn in_set(&self, set: PeerSet, peer: PeerId) -> bool {
        self.set_word(set, peer as usize / 64) & (1 << (peer % 64)) != 0
    }

    /// One peer of `set` that `accept` takes, each as likely: the draw of
    /// `RngSource::choice` over the list of them in peer id order, which is
    /// not made.
    pub(crate) fn choose_one<R: RngSource>(
        &self,
        set: PeerSet,
        rng: &mut R,
        accept: impl Fn(PeerId) -> bool,
    ) -> Option<PeerId> {
        let n = self.peers_of(set).filter(|&q| accept(q)).count();
        if n == 0 {
            return None;
        }
        let k = (rng.next_u64() as usize) % n;
        self.peers_of(set).filter(|&q| accept(q)).nth(k)
    }

    /// Calls `f` with the node for each peer of `set`, in peer id order, until
    /// it returns `false`. The set is read a word at a time: a change `f`
    /// makes to it counts for the words not yet read.
    pub fn walk(&mut self, set: PeerSet, mut f: impl FnMut(&mut Self, PeerId) -> bool) {
        for w in 0..self.linked.width() {
            for q in word_bits(w, self.set_word(set, w)) {
                if !f(self, q) {
                    return;
                }
            }
        }
    }

    /// [`Self::walk`] over every peer of `set`.
    pub fn for_each(&mut self, set: PeerSet, mut f: impl FnMut(&mut Self, PeerId)) {
        self.walk(set, |node, q| {
            f(node, q);
            true
        });
    }

    #[inline]
    pub fn is_linked(&self, peer: PeerId, t: TypeId) -> bool {
        self.in_set(PeerSet::Links(t), peer)
    }

    /// Returns peers in `push_in[*][t][fam]` holding `colour` (`in_pushers(T,
    /// fam, c)`).
    pub fn in_pushers(&self, t: TypeId, fam: FamilyId, colour: Colour) -> PeerSet {
        PeerSet::In(t, fam, colour)
    }

    /// Returns peers in `push_out[*][t][fam]` holding `colour` (`out_pushees(T,
    /// fam, c)`).
    pub fn out_pushees(&self, t: TypeId, fam: FamilyId, colour: Colour) -> PeerSet {
        PeerSet::Out(t, fam, colour)
    }

    /// Whether `peer`'s interest holds every index of the groups of `fam`
    /// (`seacast.md` §1.3 `link_cover`).
    pub(crate) fn link_covers<C>(&self, peer: PeerId, t: TypeId, fam: FamilyId, catalog: &C) -> bool
    where
        C: ObjectCatalog<B>,
    {
        let Some(j) = self.join_recv(peer, t) else {
            return false;
        };
        match j.interest {
            InterestKind::All => true,
            InterestKind::Derived => catalog.holds_family(t, fam, peer, &catalog.node_id(peer), j),
            InterestKind::Declared => false,
        }
    }

    /// The links a relation may be grafted on: a peer with duty whose interest
    /// holds the family, not in the relation, with no GRAFT of ours for it
    /// unanswered and none refused within the backoff, with `BOTH` in neither
    /// direction (`candidates`).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn relation_candidate<C>(
        &self,
        q: PeerId,
        t: TypeId,
        fam: FamilyId,
        colour: Colour,
        d: Direction,
        now: Timestamp,
        catalog: &C,
    ) -> bool
    where
        C: ObjectCatalog<B>,
    {
        let peer_duty = self.join_recv(q, t).map(|j| j.duty).unwrap_or(Duty::None);
        if peer_duty != Duty::Forward || !self.link_covers(q, t, fam, catalog) {
            return false;
        }
        let key = (q, t, fam, colour);
        if !self.relation_room(q, t, fam, colour, now, catalog) {
            return false;
        }
        let waits =
            |inbound| self.backoff.get(&(q, t, fam, colour, inbound)).is_some_and(|&t| t > now);
        let taken_in = d.includes_in() &&
            (self.push_in.contains(&key) || self.grafted_in.contains(&key) || waits(true));
        let taken_out = d.includes_out() &&
            (self.push_out.contains(&key) || self.grafted_out.contains(&key) || waits(false));
        !taken_in && !taken_out
    }

    /// Whether `(fam, c)` already has relation state on `(peer, t)`, or the
    /// link has fewer `(family, colour)` pairs of `t` than `MAX_RELATIONS`:
    /// relations, our GRAFTs not yet answered, backoffs not run out, and our
    /// GRAFTs and PRUNEs still owed (`seacast.md` §4.1 `relation_room`, §6.3).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn relation_room<C>(
        &self,
        peer: PeerId,
        t: TypeId,
        fam: FamilyId,
        c: Colour,
        now: Timestamp,
        catalog: &C,
    ) -> bool
    where
        C: ObjectCatalog<B>,
    {
        let live = |f, k, inbound| {
            self.backoff.get(&(peer, t, f, k, inbound)).is_some_and(|&until| until > now)
        };
        let related = |f, k| {
            self.push_in.contains(&(peer, t, f, k)) || self.push_out.contains(&(peer, t, f, k))
        };
        let grafted = |f, k| {
            self.grafted_in.contains(&(peer, t, f, k)) ||
                self.grafted_out.contains(&(peer, t, f, k))
        };
        let backed_off = |f, k| live(f, k, true) || live(f, k, false);
        if related(fam, c) ||
            grafted(fam, c) ||
            backed_off(fam, c) ||
            self.sends.owed_pairs(peer, t).any(|fc| fc == (fam, c))
        {
            return true;
        }
        let limit = catalog.params(t).max_relations;
        // Every source counted whole bounds the distinct pairs from above.
        let bound = self.push_in.pairs_of(peer, t).count() +
            self.push_out.pairs_of(peer, t).count() +
            self.grafted_in.len() +
            self.grafted_out.len() +
            self.backoff.len() +
            self.sends.owed_pairs(peer, t).count();
        if bound < limit {
            return true;
        }
        // Each pair counted at its first source.
        let mut n = self.push_in.pairs_of(peer, t).count();
        n += self
            .push_out
            .pairs_of(peer, t)
            .filter(|&(f, k)| !self.push_in.contains(&(peer, t, f, k)))
            .count();
        n += self
            .grafted_in
            .iter()
            .filter(|&&(q, ty, f, k)| q == peer && ty == t && !related(f, k))
            .count();
        n += self
            .grafted_out
            .iter()
            .filter(|&&(q, ty, f, k)| {
                q == peer && ty == t && !related(f, k) && !self.grafted_in.contains(&(q, ty, f, k))
            })
            .count();
        n += self
            .backoff
            .iter()
            .filter(|&(&(q, ty, f, k, inbound), &until)| {
                q == peer &&
                    ty == t &&
                    until > now &&
                    !related(f, k) &&
                    !grafted(f, k) &&
                    (inbound || !live(f, k, true))
            })
            .count();
        n += self
            .sends
            .owed_pairs(peer, t)
            .filter(|&(f, k)| !related(f, k) && !grafted(f, k) && !backed_off(f, k))
            .count();
        n < limit
    }

    /// GRAFTs the first `n` candidates of a relation, in peer id order.
    #[allow(clippy::too_many_arguments)]
    fn graft_candidates<E, C>(
        &mut self,
        t: TypeId,
        fam: FamilyId,
        colour: Colour,
        d: Direction,
        n: usize,
        now: Timestamp,
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let mut left = n;
        self.walk(self.links(t), |node, q| {
            if left == 0 {
                return false;
            }
            if node.relation_candidate(q, t, fam, colour, d, now, catalog) {
                node.graft(q, t, fam, colour, d, env);
                left -= 1;
            }
            true
        });
    }

    /// Reports each family of `t` in which this node has fewer links than a
    /// floor asks for, with the number missing: the relation floor's `F_LO`
    /// links per family it has duty in (`seacast.md` §4.1 `keep_floor`),
    /// and the policy's floors (`Policy::link_floors`, as `keep_coverage`
    /// counts them). A link counts where its peer's interest holds the family.
    ///
    /// The node opens no link: the host does, and subtracts those it has
    /// opened whose JOINs have not crossed yet. A family short of two floors
    /// is reported for each.
    pub fn link_deficits<C, F>(&self, t: TypeId, catalog: &C, mut report: F)
    where
        C: ObjectCatalog<B>,
        F: FnMut(FamilyId, usize),
    {
        let prm = catalog.params(t);
        let links = self.links(t);
        if catalog.our_join(t).duty == Duty::Forward {
            for fam in catalog.families_with_duty(t) {
                let have =
                    self.peers_of(links).filter(|&q| self.link_covers(q, t, fam, catalog)).count();
                if have < prm.f_lo {
                    report(fam, prm.f_lo - have);
                }
            }
        }
        let mut floors = catalog.link_floors(t);
        for q in self.peers_of(links) {
            let high = self.join_recv(q, t).is_some_and(|j| catalog.high_custody(t, j));
            let mut counted = 0;
            for floor in floors.as_mut_slice() {
                if floor.links == 0 || !self.link_covers(q, t, floor.family, catalog) {
                    continue;
                }
                if floor.diverse && high {
                    if counted == prm.cover_high {
                        continue;
                    }
                    counted += 1;
                }
                floor.links -= 1;
            }
        }
        for floor in floors.iter().filter(|f| f.links > 0) {
            report(floor.family, floor.links);
        }
    }

    pub(crate) fn is_related(&self, peer: PeerId) -> bool {
        self.push_out.related(peer) || self.push_in.related(peer)
    }
}
