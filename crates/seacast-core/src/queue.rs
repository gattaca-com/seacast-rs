//! The send path: a bounded two-lane queue a peer and the node-wide byte
//! window (`seacast.md` §4.11, §4.12; `seacast-lite.md` §7). The node owns it
//! (`SeacastNode::sends`); each peer's writer calls
//! [`SeacastNode::next_to_send`].

use crate::{
    bitmap::Bitmap,
    collections::{InlineVec, MAX_ENTRY_CONTROL, PeerSlab, PreallocDeque, PreallocMap},
    message::{Control, Have, QueueEntry, Queued},
    node::SeacastNode,
    state::{DispatchOutcome, GroupBits, Owed, PeerQueue},
    traits::{ChunkBuffer, ObjectCatalog, RuntimeEnv, TimerEvent},
    types::{Ask, Colour, FamilyId, GroupId, NodeConfig, PeerId, SourceOffers, TypeId},
};

#[derive(Debug, Clone)]
pub struct SendQueues {
    config: NodeConfig,
    /// A queue a connection, indexed by `PeerId`.
    pub queue: PeerSlab<PeerQueue>,
    /// Bytes of chunks written and not yet acknowledged or timed out.
    pub in_flight: usize,
    waiters: PreallocDeque<PeerId>,
    pub sent: PreallocMap<(PeerId, GroupId, u32), (u64, usize)>,
    /// Offers a full queue refused, of groups of more than one chunk: they
    /// leave with the peer's next RPC (`owed`).
    pub owed: Owed,
    /// Answers a full queue refused, of groups of more than one chunk: queued
    /// again as the queue empties (`owed_answers`).
    pub owed_answers: Owed,
}

impl SendQueues {
    /// Preallocates a queue for each of `config`'s peers.
    pub fn new(config: NodeConfig) -> Self {
        let cap = config.capacities;
        Self {
            queue: PeerSlab::with_capacity(cap.max_peers, || {
                PeerQueue::with_capacity(
                    cap.max_queue_entries_per_peer,
                    cap.max_owed_single_per_peer,
                    cap.max_types,
                )
            }),
            in_flight: 0,
            waiters: PreallocDeque::with_capacity(cap.max_peers),
            sent: PreallocMap::with_capacity(cap.max_peers * 64),
            owed: Owed::with_capacity(cap.max_owed_pairs, cap.max_peers),
            owed_answers: Owed::with_capacity(cap.max_owed_pairs, cap.max_peers),
            config,
        }
    }

    /// Opens `peer`'s queue.
    pub fn connect(&mut self, peer: PeerId) {
        self.queue.open(peer);
    }

    /// Closes `peer`'s queue and frees what was in flight to it.
    pub fn disconnect<B: ChunkBuffer, E: RuntimeEnv<B>>(&mut self, peer: PeerId, env: &mut E) {
        if let Some(q) = self.queue.close(peer) {
            q.clear();
        }
        self.owed.drop_peer(peer);
        self.owed_answers.drop_peer(peer);
        self.leave_line(peer, env);
        let mut freed = 0;
        self.sent.retain(|key, &mut (_, bytes)| {
            if key.0 == peer {
                freed += bytes;
            }
            key.0 != peer
        });
        if freed > 0 {
            self.free_room(freed, env);
        }
    }

    /// Enqueues an entry into `peer`'s bounded two-lane queue and wakes
    /// `peer`'s writer (`enqueue`).
    pub fn send<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        entry: Queued,
        urgent: bool,
        env: &mut E,
    ) -> bool {
        // Nothing is queued to a peer that is gone, which a timer armed before it left
        // may name.
        let Some(q) = self.queue.get_mut(peer) else {
            return false;
        };
        if !q.has_room() {
            return false;
        }
        if urgent {
            let _ = q.urgent.push_back(entry);
        } else {
            let _ = q.normal.push(entry);
        }
        env.wake_writer(peer);
        true
    }

    /// Queues a JOIN, GRAFT or PRUNE, or owes it: one a full queue refuses, and
    /// every later one, waits in order (`seacast.md` §4.1 `send_relation`).
    /// A JOIN is always owed: the room for a link's JOINs is kept apart. A
    /// GRAFT or PRUNE that repeats the last one owed for its family and colour
    /// is not owed twice. With no room left to owe, a GRAFT or PRUNE is
    /// dropped, and `false` returned.
    pub fn send_relation<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        message: Control,
        env: &mut E,
    ) -> bool {
        let urgent = matches!(message, Control::Join(_));
        let waiting = self.queue.get(peer).is_some_and(|q| !q.owed_relations.is_empty());
        if !waiting && self.send(peer, Queued::Control(message), urgent, env) {
            return true;
        }
        let Some(q) = self.queue.get_mut(peer) else {
            return false;
        };
        let pair = |m: &Control| match m {
            Control::Graft(g) => Some((g.object_type, g.family, g.colour)),
            Control::Prune(p) => Some((p.object_type, p.family, p.colour)),
            _ => None,
        };
        let owed = if urgent {
            q.owed_relations.push_back(message)
        } else {
            let of = pair(&message);
            let last = q.owed_relations.iter().filter(|m| pair(m) == of).last();
            last == Some(&message) ||
                q.owed_relations.len() < q.max_entries && q.owed_relations.push_back(message)
        };
        env.wake_writer(peer);
        owed
    }

    /// What is owed of the relation's messages, queued in order while there is
    /// room: the writer's first step (`queue_owed_relations`). True if a JOIN
    /// was queued.
    fn queue_owed_relations<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        env: &mut E,
    ) -> bool {
        let mut joined = false;
        while self.has_queue_room(peer) {
            let Some(message) = self.queue.get_mut(peer).and_then(|q| q.owed_relations.pop_front())
            else {
                break;
            };
            let urgent = matches!(message, Control::Join(_));
            joined |= urgent;
            self.send(peer, Queued::Control(message), urgent, env);
        }
        joined
    }

    /// The family and colour of each GRAFT and PRUNE of type `t` owed to
    /// `peer`, the first of each pair only.
    pub fn owed_pairs(
        &self,
        peer: PeerId,
        t: TypeId,
    ) -> impl Iterator<Item = (FamilyId, Colour)> + '_ {
        let owed = self.queue.get(peer).map(|q| &q.owed_relations);
        let pair = move |m: &Control| match m {
            Control::Graft(g) if g.object_type == t => Some((g.family, g.colour)),
            Control::Prune(p) if p.object_type == t => Some((p.family, p.colour)),
            _ => None,
        };
        owed.into_iter().flat_map(move |q| {
            q.iter().enumerate().filter_map(move |(i, m)| {
                let fc = pair(m)?;
                (!q.iter().take(i).any(|e| pair(e) == Some(fc))).then_some(fc)
            })
        })
    }

    /// Our JOIN for `t` to `peer` is owed, not queued.
    pub fn join_owed(&self, peer: PeerId, t: TypeId) -> bool {
        self.queue.get(peer).is_some_and(|q| {
            q.owed_relations.iter().any(|m| matches!(m, Control::Join(j) if j.object_type == t))
        })
    }

    /// Marks `bits` of `group` as owed to `peer` for the next write (`owe(p, g,
    /// bits)`). `single`: the group has one chunk.
    pub fn owe<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        bits: Bitmap,
        single: bool,
        env: &mut E,
    ) {
        if let Some(q) = self.queue.get_mut(peer) {
            if single {
                owe_single(&mut q.owed_single, group);
            } else {
                self.owed.add(peer, group, &bits);
            }
        }
        env.wake_writer(peer);
    }

    /// Records an answer a full queue refused, to be queued again as the queue
    /// empties. `single`: the group has one chunk.
    pub fn owe_answer(&mut self, peer: PeerId, group: GroupId, index: u32, single: bool) {
        if let Some(q) = self.queue.get_mut(peer) {
            if single {
                owe_single(&mut q.owed_single_answers, group);
            } else {
                self.owed_answers.add(peer, group, &Bitmap::singleton(index));
            }
        }
    }

    /// Merges a holding of `h.group` into an existing urgent holding still
    /// waiting in `peer`'s queue (`seacast.md` §4.2 `merge_waiting`).
    pub fn merge_waiting(&mut self, peer: PeerId, h: &Have) -> bool {
        let Some(q) = self.queue.get_mut(peer) else {
            return false;
        };
        for idx in 0..q.urgent.len() {
            if let Some(Queued::Control(Control::Have(existing))) = q.urgent.get_mut(idx) {
                if !existing.offer && existing.group == h.group {
                    existing.bits |= &h.bits;
                    existing.claim_all = h.claim_all;
                    existing.complete = h.complete;
                    return true;
                }
            }
        }
        false
    }

    /// Whether an ask for `ask` waits in `peer`'s queue.
    pub fn ask_waiting(&self, peer: PeerId, ask: Ask) -> bool {
        let Some(q) = self.queue.get(peer) else {
            return false;
        };
        q.normal.iter().any(|item| {
            matches!(item, Queued::Control(Control::Want(w)) if w.group == ask.group && w.bits.has(ask.index))
        })
    }

    /// Takes `bits` of `group` out of the asks waiting in `peer`'s queue; a
    /// standing request is not one.
    pub fn cancel_asks(&mut self, peer: PeerId, group: GroupId, bits: &Bitmap) {
        if let Some(q) = self.queue.get_mut(peer) {
            q.normal.retain_mut(|item| match item {
                Queued::Control(Control::Want(w)) if w.group == group && w.track_promise => {
                    w.bits = w.bits.and_not(bits);
                    !w.bits.is_empty()
                }
                _ => true,
            });
        }
    }

    /// Drops the chunks, offers and asks of `group` that wait, and what is owed
    /// of it.
    pub fn cancel_group(&mut self, group: &GroupId) {
        for q in self.queue.iter_mut() {
            q.normal.retain(|item| match item {
                Queued::Chunk { group: of, .. } => of != group,
                Queued::Control(Control::Have(h)) => !h.offer || &h.group != group,
                Queued::Control(Control::Want(w)) => &w.group != group,
                Queued::Control(_) => true,
            });
        }
        self.owed.drop_group(group);
        self.owed_answers.drop_group(group);
    }

    /// The first peer in the waiter line whose writer can write
    /// (`seacast-lite.md` §7.1 `front`).
    fn front<B: ChunkBuffer, E: RuntimeEnv<B>>(&self, env: &E) -> Option<PeerId> {
        self.waiters.iter().copied().find(|&q| !env.is_writing(q))
    }

    /// Wakes the first writer in line that can write, if the window has room
    /// (`seacast.md` §4.11 `wake_front`).
    pub fn wake_front<B: ChunkBuffer, E: RuntimeEnv<B>>(&self, env: &mut E) {
        if self.in_flight >= self.config.window_bytes() {
            return;
        }
        if let Some(q) = self.front(env) {
            env.wake_writer(q);
        }
    }

    /// `peer`'s write has not completed (`seacast.md` §4.11 `write_waits`):
    /// if `peer` is in the waiter line, wakes the first writer in line that can
    /// write, if the window has room.
    pub fn write_waits<B: ChunkBuffer, E: RuntimeEnv<B>>(&self, peer: PeerId, env: &mut E) {
        if self.waiters.contains(&peer) {
            self.wake_front(env);
        }
    }

    /// Attempts to acquire `need` bytes in the node-wide congestion window for
    /// `peer`'s writer (`seacast.md` §4.11 `acquire_room(p, need)`).
    pub fn acquire_room<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        need: usize,
        env: &mut E,
    ) -> bool {
        let w_bytes = self.config.window_bytes();
        let fits = self.in_flight.saturating_add(need) <= w_bytes || self.in_flight == 0;
        let first = self.front(env);
        if fits && (first.is_none() || first == Some(peer)) {
            if let Some(pos) = self.waiters.position(|&q| q == peer) {
                self.waiters.remove(pos);
            }
            self.in_flight = self.in_flight.saturating_add(need);
            self.wake_front(env);
            return true;
        }
        if !self.waiters.contains(&peer) {
            let _ = self.waiters.push_back(peer);
        }
        false
    }

    /// Removes `peer` from the congestion window waiter line (`leave_line(p)`).
    pub fn leave_line<B: ChunkBuffer, E: RuntimeEnv<B>>(&mut self, peer: PeerId, env: &mut E) {
        if let Some(pos) = self.waiters.position(|&q| q == peer) {
            self.waiters.remove(pos);
            self.wake_front(env);
        }
    }

    /// Associates `need` window bytes with an in-flight chunk
    /// (`track_in_flight(p, f, need)`).
    pub fn track_in_flight<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        index: u32,
        need: usize,
        env: &mut E,
    ) {
        let key = (peer, group, index);
        // Tracked already, or not trackable, so nothing would free these bytes later:
        // they leave the window now.
        if self.sent.contains_key(&key) || self.sent.is_full() {
            self.free_room(need, env);
            return;
        }
        let now_bits = env.now().to_bits();
        self.sent.insert(key, (now_bits, need));
        env.schedule_after(self.config.window_timeout, TimerEvent::WindowTimeout {
            peer,
            group,
            index,
            at_bits: now_bits,
        });
    }

    /// Frees in-flight window bytes when `peer` reports holding `(group,
    /// index)` (`window_release`).
    pub fn window_release<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        peer: PeerId,
        group: GroupId,
        index: u32,
        env: &mut E,
    ) {
        if let Some((_, need)) = self.sent.remove(&(peer, group, index)) {
            self.free_room(need, env);
        }
    }

    /// Frees in-flight window bytes on `WINDOW_TIMEOUT` (`window_timeout`).
    /// True if the room was still held: no holding freed it first.
    pub fn window_timeout<B: ChunkBuffer, E: RuntimeEnv<B>>(
        &mut self,
        key: (PeerId, GroupId, u32),
        at_bits: u64,
        env: &mut E,
    ) -> bool {
        match self.sent.get(&key) {
            Some(&(sent_at, need)) if sent_at == at_bits => {
                self.sent.remove(&key);
                self.free_room(need, env);
                true
            }
            _ => false,
        }
    }

    /// Returns `need` bytes to the congestion window and wakes the first
    /// waiting writer that can write (`free_room`).
    pub fn free_room<B: ChunkBuffer, E: RuntimeEnv<B>>(&mut self, need: usize, env: &mut E) {
        self.in_flight = self.in_flight.saturating_sub(need);
        self.wake_front(env);
    }

    pub fn has_owed_offers(&self, peer: PeerId) -> bool {
        self.owed.any(peer) || self.queue.get(peer).is_some_and(|q| !q.owed_single.is_empty())
    }

    fn has_owed_answers(&self, peer: PeerId) -> bool {
        self.owed_answers.any(peer) ||
            self.queue.get(peer).is_some_and(|q| !q.owed_single_answers.is_empty())
    }

    fn has_queue_room(&self, peer: PeerId) -> bool {
        self.queue.get(peer).map(|q| q.has_room()).unwrap_or(true)
    }
}

fn owe_single(owed: &mut PreallocDeque<GroupId>, group: GroupId) {
    if (0..owed.len()).any(|at| owed.get(at) == Some(&group)) {
        return;
    }
    if owed.is_full() {
        owed.pop_front();
    }
    let _ = owed.push_back(group);
}

impl<B: ChunkBuffer> SeacastNode<B> {
    /// `peer`'s writer has started to wait on its transport (`seacast.md`
    /// §4.11 `write_waits`): if `peer` is in the window's waiter line, wakes
    /// the first writer in line that can write, if room is free.
    pub fn write_waits<E>(&self, peer: PeerId, env: &mut E)
    where
        E: RuntimeEnv<B>,
    {
        self.sends.write_waits(peer, env);
    }

    /// Selects and filters the next queue entry to write to `peer`
    /// (`seacast.md` §4.11 `next_to_send`).
    pub fn next_to_send<E, C>(
        &mut self,
        peer: PeerId,
        env: &mut E,
        catalog: &C,
    ) -> DispatchOutcome<B>
    where
        E: RuntimeEnv<B>,
        C: ObjectCatalog<B>,
    {
        loop {
            if self.sends.queue_owed_relations(peer, env) {
                // A link counts once our JOIN is queued (§4.1 `links`).
                for t in catalog.joined_types() {
                    self.relink(peer, t);
                }
            }
            if self.sends.has_owed_answers(peer) && self.sends.has_queue_room(peer) {
                if let Some((group, index)) = self.pop_owed_answer(peer) {
                    let entry = Queued::Chunk { group, index, solicited: true };
                    self.sends.send(peer, entry, false, env);
                }
            }
            if let Some(urgent_entry) = self.take_head(peer, true) {
                if let Some(out) = self.with_owed(peer, urgent_entry) {
                    self.note_offers_written(peer, &out);
                    return DispatchOutcome::Send(out);
                }
                continue;
            }
            let normal_empty =
                self.sends.queue.get(peer).map(|q| q.normal.is_empty()).unwrap_or(true);
            if normal_empty {
                if self.sends.has_owed_offers(peer) {
                    if let Some(out) = self.with_owed(peer, QueueEntry::empty()) {
                        self.note_offers_written(peer, &out);
                        return DispatchOutcome::Send(out);
                    }
                }
                self.sends.leave_line(peer, env);
                return DispatchOutcome::Empty;
            }

            let k = self.choose_normal_index(peer);
            let item = self.sends.queue.get(peer).and_then(|q| q.normal.get(k)).copied();
            let (entry, need) = match item {
                Some(Queued::Chunk { group, index, solicited }) => {
                    // Gone since it was queued (its group dropped or expired): nothing to send.
                    let Some(chunk) = self.resolve_chunk(&group, index) else {
                        self.sends.queue.get_mut(peer).expect("queue exists").normal.remove(k);
                        continue;
                    };
                    let first = !solicited && !self.pairs.first_written(&(peer, group));
                    let need = catalog.wire_size(&chunk, first);
                    if need > 0 && !self.sends.acquire_room(peer, need, env) {
                        return DispatchOutcome::Wait;
                    }
                    self.sends.queue.get_mut(peer).expect("queue exists").normal.remove(k);
                    let entry = QueueEntry::from_chunk(chunk, solicited);
                    (QueueEntry { first_of_group: first, ..entry }, need)
                }
                // `choose` names a control item only at the head.
                _ => match self.take_head(peer, false) {
                    Some(entry) => (entry, 0),
                    None => continue,
                },
            };
            let out = self.filter_entry(peer, entry, env, catalog);
            let has_chunk = out.as_ref().and_then(|e| e.chunk.as_ref()).is_some();
            if need > 0 && !has_chunk {
                self.sends.free_room(need, env);
            }
            if let Some(out_entry) = out {
                if let Some(ref ch) = out_entry.chunk {
                    self.sends.track_in_flight(peer, ch.group, ch.index, need, env);
                    if out_entry.first_of_group {
                        self.pairs.set_first_written((peer, ch.group));
                    }
                    if self.config.source_offers == SourceOffers::Publish {
                        let (g, i) = (ch.group, ch.index);
                        self.origin_written(g, i, env, catalog);
                    }
                }
                if let Some(final_entry) = self.with_owed(peer, out_entry) {
                    self.note_offers_written(peer, &final_entry);
                    return DispatchOutcome::Send(final_entry);
                }
            }
        }
    }

    /// Records offers written to `peer` so answers to asks on them are exempt
    /// from `SERVE_BUDGET` (`seacast.md` §4.5 `offers_in`).
    fn note_offers_written(&mut self, peer: PeerId, entry: &QueueEntry<B>) {
        for h in entry.haves.iter() {
            if h.offer {
                self.pairs.add_offered_to((peer, h.group), &h.bits);
            }
        }
    }

    /// Chooses the index in `queue[peer].normal` to pop next (`seacast.md`
    /// §4.12 `choose(q)`) with zero heap allocation.
    pub fn choose_normal_index(&self, peer: PeerId) -> usize {
        let Some(q) = self.sends.queue.get(peer) else {
            return 0;
        };
        if q.normal.is_empty() || !q.normal[0].is_chunk() {
            return 0;
        }
        if let Some(best_own) = self.pick_rarest_matching(q, |e| self.own_chunk(e)) {
            return best_own;
        }
        if self.config.answers_first {
            if let Some(best_asked) =
                self.pick_rarest_matching(q, |e| matches!(e, Queued::Chunk { solicited: true, .. }))
            {
                return best_asked;
            }
        }
        if self.config.rarest_enabled { self.rarest(q) } else { 0 }
    }

    /// Picks the rarest entry satisfying `pred` without heap allocation
    /// (`seacast.md` §4.12 `pick(q, ks)`).
    fn pick_rarest_matching<F>(&self, q: &PeerQueue, mut pred: F) -> Option<usize>
    where
        F: FnMut(&Queued) -> bool,
    {
        let mut best_k: Option<usize> = None;
        let mut best_h = usize::MAX;
        for (k, entry) in q.normal.iter().enumerate() {
            if !pred(entry) {
                continue;
            }
            if !self.config.rarest_enabled {
                return Some(k);
            }
            let &Queued::Chunk { group, index, .. } = entry else {
                continue;
            };
            let h = self.holder_count(&group, index);
            if best_k.is_none() || h < best_h {
                best_h = h;
                best_k = Some(k);
            }
        }
        best_k
    }

    /// Picks the rarest chunk ahead of the first control-only entry
    /// (`seacast-lite.md` §7.2 `rarest(q)` `[c9]`).
    pub fn rarest(&self, q: &PeerQueue) -> usize {
        let mut best_h = usize::MAX;
        let mut best_i = 0;
        for (i, entry) in q.normal.iter().enumerate() {
            let &Queued::Chunk { group, index, .. } = entry else {
                break;
            };
            let h = self.holder_count(&group, index);
            if h < best_h {
                best_h = h;
                best_i = i;
            }
        }
        best_i
    }

    /// Attaches owed offers for `peer` to `entry` (`seacast-lite.md` §7.2
    /// `with_owed`).
    pub fn with_owed(&mut self, peer: PeerId, mut entry: QueueEntry<B>) -> Option<QueueEntry<B>> {
        // Only as many groups as the entry has room for leave `owed`: the rest stay
        // owed, and the writer, which runs until the queue and `owed` are both
        // empty, takes them next.
        let room = MAX_ENTRY_CONTROL - entry.haves.len();
        let mut owed_groups: InlineVec<(GroupId, Bitmap), MAX_ENTRY_CONTROL> = InlineVec::new();
        // The lowest group id first: the order does not depend on the table's.
        while owed_groups.len() < room {
            let Some((g, _)) = self.sends.owed.lowest(peer) else {
                break;
            };
            let bits = self.sends.owed.take(peer, &g).unwrap_or(Bitmap::EMPTY);
            let _ = owed_groups.push((g, bits));
        }
        if let Some(q) = self.sends.queue.get_mut(peer) {
            while owed_groups.len() < room {
                let Some(g) = q.owed_single.pop_front() else {
                    break;
                };
                // Ended since it was owed: nothing of it is offered.
                if self.groups.has_bits(&g, GroupBits::Mine) {
                    let _ = owed_groups.push((g, Bitmap::singleton(0)));
                }
            }
        }
        if owed_groups.is_empty() {
            return if entry.is_empty() { None } else { Some(entry) };
        }
        for (g, bits) in owed_groups {
            let pushed_bits = &self.pairs.pushed_bits(&(peer, g));
            let peer_has_bits = &self.pairs.has_bits(&(peer, g));
            let mut b = bits.and_not(pushed_bits).and_not(peer_has_bits);
            if let Some(ref ch) = entry.chunk {
                if ch.group == g {
                    b.clear(ch.index);
                }
            }
            if !b.is_empty() {
                entry.add_offer(Have::offer(g, b));
            }
        }
        if entry.is_empty() { None } else { Some(entry) }
    }

    /// The entry for the head of a lane of `peer`'s queue, taken off it: a
    /// chunk, or the run of control items there.
    fn take_head(&mut self, peer: PeerId, urgent: bool) -> Option<QueueEntry<B>> {
        loop {
            let q = self.sends.queue.get_mut(peer)?;
            let item = if urgent {
                q.urgent.pop_front()?
            } else if q.normal.is_empty() {
                return None;
            } else {
                q.normal.remove(0)
            };
            match item {
                Queued::Control(control) => {
                    let mut entry = QueueEntry::empty();
                    entry.push_control(control);
                    // The control items behind it leave in the same RPC, as far as it has room.
                    let q = self.sends.queue.get_mut(peer)?;
                    loop {
                        let next = if urgent { q.urgent.front() } else { q.normal.first() };
                        let Some(&Queued::Control(control)) = next else {
                            break;
                        };
                        if !entry.push_control(control) {
                            break;
                        }
                        if urgent {
                            q.urgent.pop_front();
                        } else {
                            q.normal.remove(0);
                        }
                    }
                    return Some(entry);
                }
                Queued::Chunk { group, index, solicited } => {
                    if let Some(chunk) = self.resolve_chunk(&group, index) {
                        return Some(QueueEntry::from_chunk(chunk, solicited));
                    }
                }
            }
        }
    }

    fn pop_owed_answer(&mut self, peer: PeerId) -> Option<(GroupId, u32)> {
        // The lowest group id, then its lowest index; then the groups of one chunk.
        // An answer whose chunk has gone is passed over: those behind it are
        // live.
        loop {
            let (g, idx) = match self.sends.owed_answers.lowest(peer) {
                Some((g, idx)) => {
                    self.sends.owed_answers.take_index(peer, &g, idx);
                    (g, idx)
                }
                None => (self.sends.queue.get_mut(peer)?.owed_single_answers.pop_front()?, 0),
            };
            if self.chunks.contains_key(&(g, idx)) {
                return Some((g, idx));
            }
        }
    }
}
