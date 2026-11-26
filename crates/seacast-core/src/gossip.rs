use crate::{
    bitmap::{Bitmap, MAX_CHUNKS},
    collections::{InlineVec, PreallocVec},
    node::SeacastNode,
    traits::{ChunkBuffer, DeferredStore, ObjectCatalog, RngSource, RuntimeEnv, TimerEvent},
    types::{AnnounceWidth, Ask, GroupId, PeerId, Timestamp},
};

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Runs heartbeat maintenance (`seacast.md` §4.8 `on_heartbeat`,
    /// `seacast-lite.md` §6.4) with zero heap allocation.
    pub fn on_heartbeat<E, C, R, D>(
        &mut self,
        env: &mut E,
        catalog: &C,
        rng: &mut R,
        deferred_store: &mut D,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
        R: RngSource,
        D: DeferredStore<B>,
    {
        for slot in self.slots.iter_mut() {
            slot.ihave_frames = 0;
            slot.ihave_asked = 0;
            slot.unwanted_ids = 0;
            slot.served_now = 0;
        }
        // Every ask held back is retried, a batch at a time. A retry that is held back
        // again waits for the next heartbeat: at most as many are taken as were
        // waiting.
        let mut waiting = self.held_back.len();
        while waiting > 0 {
            let mut batch: InlineVec<Ask, MAX_CHUNKS> = InlineVec::new();
            for (_, &a) in self.held_back.iter().take(waiting.min(MAX_CHUNKS)) {
                let _ = batch.push(a);
            }
            waiting -= batch.len();
            for a in &batch {
                self.held_back.remove(&(a.group, a.index));
            }
            for a in batch {
                self.retry_offer(a, env, catalog);
            }
        }

        // Offers taken in over the limits: what they name is asked for now, a group at
        // a time. A group held again by a retry waits for the next heartbeat.
        for _ in 0..self.held_groups.len() {
            let next = self.held_groups.iter().next().copied();
            let Some(g) = next else { break };
            self.held_groups.remove(&g);
            for a in self.ledger(&g) {
                self.retry_offer(a, env, catalog);
            }
        }

        let now = env.now();
        self.expire_groups(env, deferred_store);
        self.expire_heartbeat_ttls(now);
        self.drop_stale_ties(env, catalog);
        let group_bits = self.gossip_history.gossip_group_bits();
        self.gossip_history.shift();

        // A backoff lives until it runs out, whatever the type's duty (§3).
        self.backoff.retain(|_, until| *until > now);
        for t in catalog.joined_types() {
            self.maintain_relations(t, env, catalog, rng);
        }

        if group_bits.is_empty() {
            return;
        }

        let mut eligible = std::mem::replace(&mut self.peer_scratch, PreallocVec::with_capacity(0));
        eligible.clear();
        // `joined_peers()` that hold no relation with this node (`seacast.md` §3):
        // a link of a type the node runs, not a JOIN received alone.
        let types = catalog.joined_types();
        for &q in self.peers.iter() {
            let joined = types.iter().any(|&t| self.in_set(self.links(t), q));
            if joined && !self.is_related(q) {
                let _ = eligible.push(q);
            }
        }
        let factor_n = ((self.config.gossip_factor * (eligible.len() as f64)).floor()) as usize;
        let n = eligible.len().min(self.config.d_lazy.max(factor_n));
        rng.sample_in_place(eligible.as_mut_slice(), n);

        for &q in &eligible[..n] {
            if self.config.paced_gossip {
                let was_empty = self.pace_queue.is_empty();
                let _ = self.pace_queue.push_back((self.slots.stamp(q), group_bits, now));
                if was_empty && !self.pace_timer_active {
                    self.pace_timer_active = true;
                    env.schedule_after(self.config.heartbeat / 16.0, TimerEvent::PaceTick);
                }
            } else {
                self.send_gossip(q, &group_bits, env, catalog);
            }
        }
        self.peer_scratch = eligible;
    }

    /// Drops the ties on a group that has no state and that its sender no
    /// longer names: one the domain never told of (`seacast-lite.md` §4.2
    /// `drop_stale_waits`). A tie on a group with state goes at its expiry.
    fn drop_stale_ties<E, C>(&mut self, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let mut stale: InlineVec<(PeerId, GroupId), MAX_CHUNKS> = InlineVec::new();
        loop {
            stale.clear();
            for key in self.tied.keys() {
                let dead = !self.named.contains_key(key) && self.groups.get(&key.1).is_none();
                if dead && !stale.push(*key) {
                    break;
                }
            }
            if stale.is_empty() {
                return;
            }
            for &(p, g) in stale.iter() {
                if let Some(bits) = self.tied.remove(&(p, g)) {
                    self.drop_tie(p, g, &bits, env, catalog);
                }
            }
            self.reindex_ties();
        }
    }

    /// Sends one peer's paced gossip per tick (`seacast-lite.md` §6.4
    /// `on_pace_tick`).
    pub fn on_pace_tick<E, C>(&mut self, env: &mut E, catalog: &C)
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        self.pace_timer_active = false;
        let now = env.now();
        while let Some((q, group_bits, at)) = self.pace_queue.pop_front() {
            let Some(q) = self.slots.resolve(q).filter(|_| now - at < self.config.heartbeat) else {
                continue;
            };
            self.send_gossip(q, &group_bits, env, catalog);
            break;
        }
        if !self.pace_queue.is_empty() && !self.pace_timer_active {
            self.pace_timer_active = true;
            env.schedule_after(self.config.heartbeat / 16.0, TimerEvent::PaceTick);
        }
    }

    /// Announces gossip bitmaps to `peer` for `SAMPLE` object types
    /// (`send_gossip(q, ids)`).
    pub fn send_gossip<E, C>(
        &mut self,
        peer: PeerId,
        group_bits: &[(GroupId, Bitmap)],
        env: &mut E,
        catalog: &C,
    ) where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        for (g, bits) in group_bits {
            if self.expired(g) {
                continue;
            }
            let t = g.type_id;
            if catalog.params(t).announce_extra == AnnounceWidth::Sample {
                self.announce(peer, *g, *bits, env, catalog);
            }
        }
    }

    pub(crate) fn expire_heartbeat_ttls(&mut self, now: Timestamp) {
        // Expire HAVE_TTL (counted in heartbeats); what was sent to the peer goes with
        // its claims, and the peer leaves the holders of what it claimed.
        let holders = &mut self.holders;
        self.pairs.heartbeat(now, |peer, group, bits| {
            for i in bits.iter() {
                holders.remove(&(group, i), peer);
            }
        });

        self.sampled_from.retain(|_, until| *until > now);

        // Groups a peer named and has not named since.
        let slots = &mut self.slots;
        self.named.retain(|&(peer, _), left| {
            if *left > 1 {
                *left -= 1;
                return true;
            }
            if let Some(slot) = slots.get_mut(peer) {
                slot.named_count = slot.named_count.saturating_sub(1);
            }
            false
        });

        self.release_wanted_groups(now);

        // `tried`, and `asked_parked` with it, live as long as an offer does; an ask's
        // time, its window; a park, `PARK_TTL` (`seacast-lite.md` §8.1).
        let cutoff = now - self.config.offer_ttl;
        let asked_parked = &mut self.asked_parked;
        self.tried.retain(|ask, peer, at| {
            if at >= cutoff {
                return true;
            }
            asked_parked.remove(&(ask.group, ask.index), peer);
            false
        });
        let window = self.config.scaled_iwant_window();
        self.asked_at.retain(|_, &mut at| now - at < window);

        // Expire OFFER_TTL (30s after announcer's last offer of the group,
        // `seacast-lite.md` §8.1)
        while let Some((p, g)) = self.pairs.expired_offer(cutoff) {
            let bits = self.pairs.take_offered(&(p, g)).unwrap_or(Bitmap::EMPTY);
            self.drop_offers(g, &bits, p);
        }
    }
}
