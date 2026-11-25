//! Nodes on the gossipsub binding, end to end: a subscription as the JOIN,
//! the host's mesh as the relation, chunks as messages, holdings, offers and
//! asks as strings, the host's side of level 1 and level 2, and the body
//! delivered. The `RPC` between them is a plain struct in place of gossipsub's
//! protobuf, and carries entries that are not SEACAST's beside those that are.

use std::collections::HashMap;

use seacast_codec::{
    SegmentDescriptor, SnappyBlockCompressor, UNIT, VecBufferPool, build_group, group_id, snappy,
};
use seacast_core::{
    BoundedDeferredStore, Bytes32, ChunkMsg, DecodeJob, DispatchOutcome, GroupId, GroupState,
    NodeConfig, NodeId, PeerId, PenaltyReason, PreallocVec, Rpc, RuntimeEnv, SeacastNode, Shape,
    SplitMix64, TimerEvent, Timestamp, TypeCodec, ValidationResult,
};
use seacast_gossipsub::{
    CONTEXT_BYTES, Inbound, MESSAGE_ID_BYTES, PAYLOAD, PayloadCatalog, PayloadCodec, PayloadHost,
    RpcOut, chunk_id_of, group_key, is_seacast, message_id_of, payload_group, payload_join,
    read_holding, read_offer, read_want, write_entry,
};

const TOPIC: &[u8] = b"/eth2/00000000/seacast_payload/ssz_snappy";
const FORK: [u8; 4] = [0; 4];
const SLOT: u64 = 7;
const ROOT: Bytes32 = [0xb1; 32];
/// A node's first peer, and the second of a node between two.
const PEER: PeerId = 1;
const NEXT: PeerId = 2;

type Chunk = ChunkMsg<Vec<u8>>;
type Catalog = PayloadCatalog<Blocks, PayloadCodec<VecBufferPool, Vec<u8>>>;

fn context() -> [u8; CONTEXT_BYTES] {
    let mut context = [0; CONTEXT_BYTES];
    context[..8].copy_from_slice(&SLOT.to_le_bytes());
    context[8..].copy_from_slice(&ROOT);
    context
}

/// The domain: the blocks installed, each with its slot and the group id its
/// bid commits, and the groups whose chunks wait for a block.
#[derive(Default)]
struct Blocks {
    installed: HashMap<Bytes32, (u64, Bytes32)>,
    waiting: Vec<(Bytes32, GroupId)>,
}

impl PayloadHost for Blocks {
    fn authenticate(
        &mut self,
        group: &GroupId,
        header_id: &Bytes32,
        context: &[u8],
    ) -> ValidationResult {
        let slot = u64::from_le_bytes(context[..8].try_into().unwrap());
        let root: Bytes32 = context[8..].try_into().unwrap();
        match self.installed.get(&root) {
            None => {
                self.waiting.push((root, *group));
                ValidationResult::Defer
            }
            Some(&(of, bid)) if of == slot && bid == *header_id => ValidationResult::Accept,
            Some(_) => ValidationResult::Reject,
        }
    }

    fn authenticable(&self, group: &GroupId) -> bool {
        self.installed.values().any(|&(slot, bid)| payload_group(group_key(&bid, slot)) == *group)
    }

    fn node_id(&self, peer: PeerId) -> NodeId {
        let mut id = [0u8; 32];
        id[..8].copy_from_slice(&peer.to_le_bytes());
        id
    }
}

#[derive(Default)]
struct Env {
    to_decode: Vec<(GroupId, Shape, Vec<Chunk>)>,
    delivered: Vec<(GroupId, Vec<u8>)>,
    penalties: Vec<(PeerId, PenaltyReason)>,
}

impl RuntimeEnv<Vec<u8>> for Env {
    fn now(&self) -> Timestamp {
        1.0
    }
    fn schedule_after(&mut self, _delay: f64, _event: TimerEvent) {}
    fn start_decode(&mut self, group: GroupId, job: DecodeJob<'_, Vec<u8>>) {
        self.to_decode.push((group, *job.shape, job.chunks.to_vec()));
    }
    fn deliver(&mut self, group: GroupId, payload: Vec<u8>) {
        self.delivered.push((group, payload));
    }
    fn penalise(&mut self, peer: PeerId, reason: PenaltyReason) {
        self.penalties.push((peer, reason));
    }
}

/// A gossipsub `RPC`, as a client has parsed it.
#[derive(Default)]
struct Wire {
    /// A change of subscription to the topic.
    subscribe: Option<bool>,
    /// The data of each message on the topic, and its message id.
    messages: Vec<(Vec<u8>, Vec<u8>)>,
    ihave: Vec<Vec<u8>>,
    iwant: Vec<Vec<u8>>,
    idontwant: Vec<Vec<u8>>,
}

impl Wire {
    fn is_empty(&self) -> bool {
        self.messages.is_empty() &&
            self.ihave.is_empty() &&
            self.iwant.is_empty() &&
            self.idontwant.is_empty()
    }
}

impl RpcOut<Vec<u8>> for Wire {
    fn message(&mut self, chunk: &Chunk) {
        self.messages
            .push((snappy::compress(&chunk.frame), message_id_of(&chunk.cached_id).into()));
    }
    fn ihave(&mut self, entry: &[u8]) {
        self.ihave.push(entry.to_vec());
    }
    fn iwant(&mut self, entry: &[u8]) {
        self.iwant.push(entry.to_vec());
    }
    fn idontwant(&mut self, entry: &[u8]) {
        self.idontwant.push(entry.to_vec());
    }
}

/// What crossed the wire, summed.
#[derive(Default, Debug, PartialEq)]
struct Seen {
    messages: usize,
    offers: usize,
    wants: usize,
    holdings: usize,
    /// Entries left to the client's own gossipsub.
    foreign: usize,
}

struct Host {
    node: SeacastNode<Vec<u8>>,
    env: Env,
    catalog: Catalog,
    rng: SplitMix64,
    store: BoundedDeferredStore,
    seen: Seen,
    /// Chunks written that no WANT asked for.
    pushed: usize,
}

impl Host {
    /// A node with its peer connected. The JOIN the node queues is the
    /// subscription the host sends.
    fn new(seed: u64) -> Self {
        Self::with_peers(seed, &[PEER])
    }

    fn with_peers(seed: u64, peers: &[PeerId]) -> Self {
        let catalog =
            PayloadCatalog::new(Blocks::default(), PayloadCodec::new(VecBufferPool, TOPIC), FORK);
        let mut host = Self {
            node: SeacastNode::new(NodeConfig::default()),
            env: Env::default(),
            catalog,
            rng: SplitMix64::new(seed),
            store: BoundedDeferredStore::default(),
            seen: Seen::default(),
            pushed: 0,
        };
        for &peer in peers {
            host.node.connect_peer(peer, true, &mut host.env, &host.catalog);
        }
        host
    }

    /// The `RPC` to the peer: everything the node has to send, with an entry
    /// of the client's own in each control field it writes.
    fn drain(&mut self) -> Wire {
        self.drain_to(PEER)
    }

    fn drain_to(&mut self, peer: PeerId) -> Wire {
        let mut wire = Wire::default();
        while let DispatchOutcome::Send(entry) =
            self.node.next_to_send(peer, &mut self.env, &self.catalog)
        {
            if entry.chunk.is_some() && !entry.solicited {
                self.pushed += 1;
            }
            write_entry(&entry, &mut wire);
        }
        if !wire.iwant.is_empty() {
            wire.iwant.insert(0, vec![0xee; 20]);
        }
        if !wire.idontwant.is_empty() {
            wire.idontwant.insert(0, vec![0xee; 20]);
        }
        wire
    }

    fn receive(&mut self, wire: Wire) {
        self.receive_from(PEER, wire);
    }

    fn receive_from(&mut self, from: PeerId, wire: Wire) {
        let decompress = |data: &[u8], len: usize| {
            let mut out = vec![0u8; len];
            snappy::decompress_into(data, &mut out).map(|n| {
                out.truncate(n);
                out
            })
        };
        let mut chunks = Vec::new();
        for (data, mid) in &wire.messages {
            let chunk = self.catalog.codec.read_message(data, decompress).expect("a chunk");
            // The id a receiver computes is the id the sender's client used.
            assert_eq!(&message_id_of(&chunk.cached_id)[..], &mid[..]);
            chunks.push(chunk);
        }
        if wire.subscribe == Some(false) {
            self.node.on_leave(from, PAYLOAD);
        }

        let route_hops = self.catalog.params.route_hops;
        let seen = &mut self.seen;
        let (node, env, catalog) = (&mut self.node, &mut self.env, &mut self.catalog);
        let (rng, store) = (&mut self.rng, &mut self.store);
        let mut sink = |rpc: Rpc<Vec<u8>>, offered: bool| {
            node.on_frame_part(from, rpc, offered, env, catalog, rng, store)
        };
        let mut frame = Inbound::new();
        if wire.subscribe == Some(true) {
            frame.join(payload_join(FORK), &mut sink);
        }
        for chunk in chunks {
            seen.messages += 1;
            frame.chunk(chunk, &mut sink);
        }
        for entry in &wire.ihave {
            if let Some(offer) = read_offer(entry) {
                seen.offers += 1;
                frame.offer(offer, &mut sink);
            }
        }
        for entry in &wire.iwant {
            if !is_seacast(entry) {
                seen.foreign += 1;
            } else if let Some(want) = read_want(entry, route_hops) {
                seen.wants += 1;
                frame.want(want, &mut sink);
            }
        }
        // The holdings last: handled after the frame's asks.
        let mut unwanted = Vec::new();
        for entry in &wire.idontwant {
            if !is_seacast(entry) {
                seen.foreign += 1;
            } else if let Some(holding) = read_holding(entry) {
                seen.holdings += 1;
                frame.holding(holding, &mut sink);
            } else if let Some(id) = chunk_id_of(entry) {
                unwanted.push(id);
            }
        }
        frame.finish(&mut sink);
        for id in unwanted {
            self.node.note_unwanted(from, id);
        }
        self.run();
    }

    /// The host's side of level 1 and level 2.
    fn run(&mut self) {
        while let Some((peer, chunk)) = self.node.pop_unverified() {
            let verdict = self.catalog.codec.check_proof(&chunk);
            self.node.on_validated(
                peer,
                chunk,
                verdict,
                &mut self.env,
                &mut self.catalog,
                &mut self.rng,
                &mut self.store,
            );
        }
        for (group, shape, chunks) in std::mem::take(&mut self.env.to_decode) {
            let mut rebuilt = PreallocVec::with_capacity(shape.n as usize);
            let object = self.catalog.decode(&group, &chunks, &shape, &mut rebuilt);
            self.node.on_decoded(
                group,
                object,
                rebuilt.as_slice(),
                &mut self.env,
                &mut self.catalog,
                &mut self.rng,
            );
        }
    }

    /// The block is installed: the domain can tell of the groups that waited.
    fn install(&mut self, descriptor: &SegmentDescriptor) {
        let blocks = &mut self.catalog.host;
        blocks.installed.insert(ROOT, (SLOT, group_id(descriptor)));
        let mut groups: Vec<GroupId> = Vec::new();
        blocks.waiting.retain(|&(root, group)| {
            if root == ROOT && !groups.contains(&group) {
                groups.push(group);
            }
            root != ROOT
        });
        self.node.on_groups_authenticated(
            &groups,
            &mut self.env,
            &mut self.catalog,
            &mut self.rng,
            &mut self.store,
        );
        self.run();
    }

    /// Publishes `body` as the block's payload. Returns its descriptor and
    /// chunks.
    fn publish(&mut self, body: &[u8]) -> (SegmentDescriptor, Vec<Chunk>) {
        let (descriptor, shards) =
            build_group::<Vec<u8>, _, _>(body, &mut VecBufferPool, &SnappyBlockCompressor);
        self.install(&descriptor);
        let chunks = self.catalog.codec.build_chunks(&context(), &descriptor, &shards);
        let shape = Shape { n: descriptor.n(), k: descriptor.k() };
        self.node.publish(
            chunks[0].group,
            shape,
            &chunks,
            &mut self.env,
            &self.catalog,
            &mut self.rng,
        );
        (descriptor, chunks)
    }
}

/// Carries `RPC`s both ways until neither node has anything to send.
fn pump(a: &mut Host, b: &mut Host) {
    for _ in 0..1000 {
        let (to_b, to_a) = (a.drain(), b.drain());
        if to_b.is_empty() && to_a.is_empty() {
            return;
        }
        b.receive(to_b);
        a.receive(to_a);
    }
    panic!("the nodes never came to rest");
}

/// Two nodes subscribed to the topic and linked.
fn linked() -> (Host, Host) {
    let (mut a, mut b) = (Host::new(3), Host::new(4));
    // The JOINs the nodes queued write nothing: the subscriptions say them.
    let (mut to_b, mut to_a) = (a.drain(), b.drain());
    assert!(to_b.is_empty() && to_a.is_empty());
    to_b.subscribe = Some(true);
    to_a.subscribe = Some(true);
    b.receive(to_b);
    a.receive(to_a);
    assert!(a.node.is_linked(PEER, PAYLOAD) && b.node.is_linked(PEER, PAYLOAD));
    (a, b)
}

fn body(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i / 3 % 29) as u8 ^ (i >> 10) as u8).collect()
}

/// The source pushes part of the group as messages and offers the rest in an
/// IHAVE, which the receiver asks for in IWANTs. The chunks wait at the
/// receiver for its block, then give the body.
#[test]
fn a_payload_crosses_a_link() {
    let (mut a, mut b) = linked();
    // A GRAFT before the subscription is refused; after it, the mesh is the
    // relation.
    assert!(!a.node.relation_added(2, PAYLOAD, 0, 0, &mut a.env, &a.catalog));
    assert!(a.node.relation_added(PEER, PAYLOAD, 0, 0, &mut a.env, &a.catalog));
    assert!(b.node.relation_added(PEER, PAYLOAD, 0, 0, &mut b.env, &b.catalog));

    let body = body(4 * UNIT + 321);
    let (descriptor, chunks) = a.publish(&body);
    let (group, n) = (chunks[0].group, descriptor.n() as usize);
    pump(&mut a, &mut b);
    assert!(b.seen.messages > 0 && b.seen.holdings > 0);
    assert!(!b.node.pending.is_empty() && b.env.delivered.is_empty());

    b.install(&descriptor);
    pump(&mut a, &mut b);
    assert_eq!(b.node.group_state(&group), Some(GroupState::Complete));
    assert_eq!(b.env.delivered, vec![(group, body)]);
    assert_eq!(b.node.chunks.len(), n);
    for chunk in &chunks {
        let held = b.node.chunks.get(&(group, chunk.index)).expect("held");
        assert_eq!((&held.frame, held.cached_id), (&chunk.frame, chunk.cached_id));
        assert_eq!(message_id_of(&held.cached_id).len(), MESSAGE_ID_BYTES);
    }
    // The source knows the receiver holds the group, and the client's own
    // entries crossed beside the node's with no penalty.
    assert!(a.node.pairs.peer_has(&(PEER, group)).is_some_and(|has| has.complete));
    assert!(a.seen.holdings > 0 && a.seen.foreign > 0);
    assert!(a.env.penalties.is_empty() && b.env.penalties.is_empty());
    assert!(a.pushed > 0 && b.seen.offers > 0 && a.seen.wants > 0);
    assert_eq!(b.seen.messages, n);

    // An unsubscription ends the link and the relation.
    b.receive(Wire { subscribe: Some(false), ..Wire::default() });
    assert!(!b.node.is_linked(PEER, PAYLOAD) && b.node.push_out.is_empty());
}

/// A node between two forwards what it receives to the peer in its mesh, and
/// pushes nothing to one outside it (`SeacastNode::relation_added`).
#[test]
fn a_node_forwards_into_its_mesh_only() {
    for meshed in [true, false] {
        // A - B - C: B's peers are A (`PEER`) and C (`NEXT`).
        let (mut a, mut c) = (Host::new(3), Host::new(5));
        let mut b = Host::with_peers(4, &[PEER, NEXT]);
        let subscribe = || Wire { subscribe: Some(true), ..Wire::default() };
        a.receive(subscribe());
        c.receive(subscribe());
        b.receive_from(PEER, subscribe());
        b.receive_from(NEXT, subscribe());
        for host in [&mut a, &mut b, &mut c] {
            assert!(host.drain().is_empty());
        }
        if meshed {
            assert!(b.node.relation_added(NEXT, PAYLOAD, 0, 0, &mut b.env, &b.catalog));
            assert!(c.node.relation_added(PEER, PAYLOAD, 0, 0, &mut c.env, &c.catalog));
        }

        let body = body(4 * UNIT + 321);
        let (descriptor, chunks) = a.publish(&body);
        b.install(&descriptor);
        c.install(&descriptor);
        for _ in 0..1000 {
            let (ab, ba) = (a.drain(), b.drain_to(PEER));
            let (bc, cb) = (b.drain_to(NEXT), c.drain());
            if [&ab, &ba, &bc, &cb].iter().all(|wire| wire.is_empty()) {
                break;
            }
            b.receive_from(PEER, ab);
            a.receive(ba);
            c.receive(bc);
            b.receive_from(NEXT, cb);
        }
        assert_eq!(b.env.delivered, vec![(chunks[0].group, body.clone())]);
        // `b.pushed` counts its unsolicited chunks: all of them are to C.
        assert_eq!(b.pushed > 0, meshed);
        if meshed {
            assert_eq!(c.env.delivered, vec![(chunks[0].group, body)]);
        }
        for host in [&a, &b, &c] {
            assert!(host.env.penalties.is_empty());
        }
    }
}
