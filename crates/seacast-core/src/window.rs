use crate::{
    bitmap::Bitmap,
    message::{QueueEntry, Queued, Want},
    node::SeacastNode,
    state::GroupBits,
    traits::{ChunkBuffer, ObjectCatalog, RuntimeEnv, TimerEvent},
    types::{Ask, PeerId},
};

impl<B: ChunkBuffer> SeacastNode<B> {
    /// Queues `entry` for `peer` (`enqueue`). `false` if the queue is full.
    pub fn enqueue<E>(&mut self, peer: PeerId, entry: Queued, urgent: bool, env: &mut E) -> bool
    where
        E: RuntimeEnv<B>,
    {
        self.sends.send(peer, entry, urgent, env)
    }

    /// Returns `true` if `entry` is an unsolicited push of a chunk this node
    /// held from the start as source (`seacast.md` §4.12
    /// `own_chunk(e)`).
    pub fn own_chunk(&self, entry: &Queued) -> bool {
        let &Queued::Chunk { group, index, solicited: false } = entry else {
            return false;
        };
        let in_received =
            self.groups.bits(&group, GroupBits::Received).map(|b| b.has(index)).unwrap_or(false);
        let in_rebuilt =
            self.groups.bits(&group, GroupBits::Rebuilt).map(|b| b.has(index)).unwrap_or(false);
        !in_received && !in_rebuilt
    }

    /// Filters a popped queue entry right before sending (`seacast-lite.md`
    /// §7.2 `filter_entry` `[c8, c12]`). An ask starts its promise here and
    /// a chunk is recorded as sent.
    pub(crate) fn filter_entry<E, C>(
        &mut self,
        peer: PeerId,
        mut entry: QueueEntry<B>,
        env: &mut E,
        catalog: &C,
    ) -> Option<QueueEntry<B>>
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        if let Some(ref f) = entry.chunk {
            let g = f.group;
            let idx = f.index;
            let peer_holds = self.pairs.peer_has(&(peer, g)).map(|e| e.has(idx)).unwrap_or(false);
            // Our answer to the peer's probe: written whatever it holds, once (§4.6, R5).
            let exempt = entry.solicited && self.probe_answers.remove(&(peer, g, idx));
            if self.config.cancel_enabled && peer_holds && !exempt {
                entry.chunk = None;
            } else if self.config.project_enabled &&
                !entry.solicited &&
                self.projected(peer, &g, catalog)
            {
                entry.chunk = None;
                self.unpush(peer, g, idx, env, catalog);
            } else {
                let mut sent = self.pairs.sent_to(&(peer, g)).unwrap_or_default();
                sent.set(idx);
                self.pairs.set_sent_to((peer, g), sent);
            }
        }

        for w_idx in 0..entry.wants.len() {
            let want = entry.wants[w_idx];
            entry.wants[w_idx].bits = self.promise_asks(peer, &want, env, catalog);
        }
        entry.wants.retain(|w| !w.bits.is_empty());

        if entry.is_empty() { None } else { Some(entry) }
    }

    /// The bits of `want` still to be asked of `peer`: not held, gated or tied,
    /// in a group that has not expired. Each starts its promise if the ask
    /// tracks one.
    fn promise_asks<E, C>(&mut self, peer: PeerId, want: &Want, env: &mut E, catalog: &C) -> Bitmap
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        let g = want.group;
        if self.expired(&g) {
            return Bitmap::EMPTY;
        }
        let t = g.type_id;
        let promise = catalog.params(t).promise;
        let at_bits = env.now().to_bits();
        let mut asked = Bitmap::new();
        // Our probe of the group, settled while queued, is not written (§4.6).
        if want.probe && self.groups.get(&g).is_some_and(|r| r.probe_ok.is_some()) {
            return Bitmap::EMPTY;
        }
        for idx in want.bits.iter() {
            let a = Ask::new(g, idx);
            let waits = self.probe_waits(peer, want, idx);
            let held = self.held(a) && !waits;
            if held || self.gated(a) || self.tied_to_root(peer, a) {
                continue;
            }
            if waits && !self.groups.get(&g).is_some_and(|r| r.probe_sent) {
                // Our probe, written now: its promise and the verdict's wait start here.
                if !self.promises.insert(a, peer, at_bits) {
                    continue;
                }
                let window = catalog.params(t).defer_window;
                env.schedule_after(window, TimerEvent::PromiseDue { ask: a, peer, at_bits });
                let rec = self.groups.rec(g);
                rec.probe_sent = true;
                let now = env.now();
                let at = rec.reconsider_at.map(f64::from_bits).unwrap_or(now).max(now + window);
                self.arm(g, at, env);
            } else if want.track_promise && !self.promises.contains(a, peer) {
                // An ask whose promise cannot be recorded is not written: its retry
                // takes it up.
                if !self.promises.insert(a, peer, at_bits) {
                    continue;
                }
                env.schedule_after(promise, TimerEvent::PromiseDue { ask: a, peer, at_bits });
            }
            asked.set(idx);
        }
        asked
    }
}
