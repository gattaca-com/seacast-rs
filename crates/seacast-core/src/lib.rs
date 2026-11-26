//! # `seacast-core`
//!
//! Standalone `sans-io` state machine for **SEACAST** (`seacast.md` and
//! `seacast-lite.md` v0.8).
//!
//! ## Design Principles
//! - **Separation of concerns**: Each protocol subsystem lives in its own
//!   focused module ([`node`], [`relations`], [`groups`], [`push`], [`pull`],
//!   [`repair`], [`gossip`], [`window`]).
//! - **No side effects / Pluggable external resources**: I/O, timers,
//!   randomness, buffer allocation, deferred chunk reservations, and object
//!   verification/decoding are strictly decoupled behind traits in [`traits`].
//! - **Zero heap allocation on the hot path**: All internal collections are
//!   preallocated to fixed capacities at node initialization (`PreallocMap`,
//!   `PreallocSet`, `PreallocDeque`, `PreallocVec` in [`collections`]) or
//!   stack-allocated (`Bitmap` in [`bitmap`], `InlineVec` in [`collections`]).

pub mod bitmap;
pub mod collections;
pub mod gossip;
pub mod groups;
mod hmac;
pub mod message;
pub mod node;
pub mod pull;
pub mod push;
pub mod queue;
pub mod relations;
pub mod repair;
pub mod state;
pub mod traits;
pub mod types;
pub mod window;

pub use bitmap::{BITMAP_WORDS, Bitmap, MAX_BITMAP_BITS, MAX_HAVE_BYTES};
pub use collections::{
    InlineVec, MAX_CHUNKS, MAX_ENTRY_CONTROL, MAX_INLINE_OFFERS, MAX_INLINE_PEERS,
    MAX_JOINED_TYPES, MAX_PROJECTED, PeerSets, PeerSlab, PreallocDeque, PreallocMap, PreallocSet,
    PreallocVec,
};
pub use message::{
    ChunkMsg, Control, Evidence, Graft, Have, Join, Prune, QueueEntry, Queued, Rpc, Want,
};
pub use node::SeacastNode;
pub use queue::SendQueues;
pub use state::{
    AskPeers, DispatchOutcome, GossipHistory, Group, GroupBits, Groups, Owed, Pairs, Peer,
    PeerQueue, PeerSet, Relations,
};
pub use traits::{
    BoundedDeferredStore, ChunkBuffer, DecodeJob, DeferredStore, Domain, ObjectCatalog,
    PenaltyReason, Policy, RngSource, RuntimeEnv, SplitMix64, TimerEvent, TypeCodec,
};
pub use types::{
    AnnounceWidth, Ask, Bytes32, CapacityConfig, ChunkId, Colour, Direction, Duty, FamilyId,
    ForkDigest, GenerationPeerId, GroupId, GroupState, HaveEntry, InterestKind, LinkFloor,
    NodeConfig, NodeId, PeerId, PushEntry, RepairVerdict, Shape, SourceOffers, Timestamp, TypeId,
    TypeParams, UplinkClass, ValidationResult,
};

#[cfg(test)]
mod tests {
    use std::{
        alloc::{GlobalAlloc, Layout, System},
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use super::*;

    const TYPE: TypeId = TypeId(0);

    struct CountingAllocator;

    static TRACK_ALLOCS: AtomicBool = AtomicBool::new(false);
    static ALLOC_COUNT: AtomicUsize = AtomicUsize::new(0);

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            if TRACK_ALLOCS.load(Ordering::Relaxed) {
                ALLOC_COUNT.fetch_add(1, Ordering::Relaxed);
            }
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }

    #[global_allocator]
    static GLOBAL: CountingAllocator = CountingAllocator;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct FixedChunkBuf {
        bytes: [u8; 64],
        len: usize,
    }

    impl Default for FixedChunkBuf {
        fn default() -> Self {
            Self { bytes: [0u8; 64], len: 0 }
        }
    }

    impl ChunkBuffer for FixedChunkBuf {
        fn len(&self) -> usize {
            self.len
        }
    }

    struct FixedBufferPool;

    impl FixedBufferPool {
        fn alloc_from_slice(&mut self, data: &[u8]) -> FixedChunkBuf {
            let n = data.len().min(64);
            let mut bytes = [0u8; 64];
            bytes[..n].copy_from_slice(&data[..n]);
            FixedChunkBuf { bytes, len: n }
        }
    }

    struct MockEnv {
        now: Timestamp,
        delivered_count: usize,
        last_delivered_group: Option<GroupId>,
        penalties: usize,
    }

    impl MockEnv {
        fn new() -> Self {
            Self { now: 1.0, delivered_count: 0, last_delivered_group: None, penalties: 0 }
        }
    }

    impl RuntimeEnv<FixedChunkBuf> for MockEnv {
        fn now(&self) -> Timestamp {
            self.now
        }
        fn schedule_after(&mut self, _delay: f64, _event: TimerEvent) {}
        fn start_decode(&mut self, _group: GroupId, _job: crate::DecodeJob<'_, FixedChunkBuf>) {}
        fn deliver(&mut self, group: GroupId, _object: FixedChunkBuf) {
            self.delivered_count += 1;
            self.last_delivered_group = Some(group);
        }
        fn penalise(&mut self, _peer: PeerId, _reason: PenaltyReason) {
            self.penalties += 1;
        }
    }

    struct MockCatalog {
        params: TypeParams,
        n: u32,
        k: u32,
    }

    impl TypeCodec<FixedChunkBuf> for MockCatalog {
        fn shape(&self, _chunk: &ChunkMsg<FixedChunkBuf>) -> Option<Shape> {
            Some(Shape { n: self.n, k: self.k })
        }
        fn check(&self, _chunk: &ChunkMsg<FixedChunkBuf>) -> bool {
            true
        }
        fn check_proof(&mut self, _chunk: &ChunkMsg<FixedChunkBuf>) -> ValidationResult {
            ValidationResult::Accept
        }
        fn header_id(&self, _chunk: &ChunkMsg<FixedChunkBuf>) -> Bytes32 {
            [0; 32]
        }
        fn context<'a>(&self, _chunk: &'a ChunkMsg<FixedChunkBuf>) -> &'a [u8] {
            &[]
        }
        fn decode(
            &mut self,
            group: &GroupId,
            available: &[ChunkMsg<FixedChunkBuf>],
            _shape: &Shape,
            out_rebuilt: &mut PreallocVec<ChunkMsg<FixedChunkBuf>>,
        ) -> Option<FixedChunkBuf> {
            if available.len() < self.k as usize {
                return None;
            }
            let mut pool = FixedBufferPool;
            for i in 0..self.n {
                let frame = pool.alloc_from_slice(&[i as u8; 8]);
                let mut cached_id = [0u8; 59];
                cached_id[1..33].copy_from_slice(&group.key);
                cached_id[35..39].copy_from_slice(&i.to_le_bytes());
                let _ = out_rebuilt.push(ChunkMsg {
                    group: *group,
                    index: i,
                    frame,
                    cached_id,
                    memo: [0; 32],
                    wire_len: 0,
                });
            }
            Some(pool.alloc_from_slice(&[0xAA; 16]))
        }
    }

    impl Domain for MockCatalog {
        fn authenticate(
            &mut self,
            _group: &GroupId,
            _header_id: &Bytes32,
            _context: &[u8],
        ) -> ValidationResult {
            ValidationResult::Accept
        }
        fn authenticable(&self, _group: &GroupId) -> bool {
            true
        }
    }

    impl Policy for MockCatalog {
        fn params(&self, _t: TypeId) -> &TypeParams {
            &self.params
        }
        fn our_join(&self, t: TypeId) -> Join {
            Join {
                object_type: t,
                fork_digest: [0; 4],
                interest: InterestKind::All,
                custody_count: 1,
                duty: Duty::Forward,
                colours: 0,
            }
        }
        fn joined_types(&self) -> InlineVec<TypeId, MAX_JOINED_TYPES> {
            InlineVec::singleton(TYPE)
        }
        fn tiebreak(&self, chunk_id: &ChunkId, peer: PeerId) -> u64 {
            (chunk_id[0] as u64).wrapping_add(peer)
        }
        fn node_id(&self, peer: PeerId) -> NodeId {
            let mut id = [0u8; 32];
            id[0] = peer as u8;
            id
        }
    }

    #[test]
    fn test_zero_heap_allocation_on_hot_path() {
        let cfg = NodeConfig::default();
        let mut node: SeacastNode<FixedChunkBuf> = SeacastNode::new(cfg.clone());
        let mut env = MockEnv::new();
        let mut catalog = MockCatalog { params: TypeParams::default(), n: 4, k: 2 };
        let mut rng = SplitMix64::new(42);
        let mut defer_store = BoundedDeferredStore::default();
        let group = GroupId::new(TYPE, [7u8; 32], 0);

        // Start tracking heap allocations after initialization
        ALLOC_COUNT.store(0, Ordering::SeqCst);
        TRACK_ALLOCS.store(true, Ordering::SeqCst);

        // 1. Connect peers and exchange Joins / Grafts
        node.connect_peer(1, true, &mut env, &catalog);
        node.connect_peer(2, true, &mut env, &catalog);
        node.maintain_relations(TYPE, &mut env, &catalog, &mut rng);

        // 2. Drain initial Join/Graft control messages
        while let DispatchOutcome::Send(_) = node.next_to_send(1, &mut env, &catalog) {}
        while let DispatchOutcome::Send(_) = node.next_to_send(2, &mut env, &catalog) {}

        // 3. Receive chunks, trigger threshold K completion, decode & rebuild N chunks,
        //    forward/announce
        let mut pool_tmp = FixedBufferPool;
        let mut id0 = [0u8; 59];
        id0[1..33].copy_from_slice(&group.key);
        id0[35..39].copy_from_slice(&0u32.to_le_bytes());
        let c0 = ChunkMsg {
            group,
            index: 0,
            frame: pool_tmp.alloc_from_slice(&[10, 20, 30, 40]),
            cached_id: id0,
            memo: [0; 32],
            wire_len: 0,
        };
        let mut id1 = [0u8; 59];
        id1[1..33].copy_from_slice(&group.key);
        id1[35..39].copy_from_slice(&1u32.to_le_bytes());
        let c1 = ChunkMsg {
            group,
            index: 1,
            frame: pool_tmp.alloc_from_slice(&[50, 60, 70, 80]),
            cached_id: id1,
            memo: [0; 32],
            wire_len: 0,
        };

        // A peer's messages count once it has joined the type on the link
        // (`seacast.md` §2).
        let peer_join = Join {
            object_type: TYPE,
            fork_digest: [0; 4],
            interest: InterestKind::All,
            custody_count: 1,
            duty: Duty::Forward,
            colours: 1,
        };
        let mut rpc0 = Rpc::default();
        let _ = rpc0.joins.push(peer_join);
        rpc0.chunk = Some(c0);
        node.on_frame(1, rpc0, &mut env, &mut catalog, &mut rng, &mut defer_store);

        let rpc1 = Rpc { chunk: Some(c1), ..Default::default() };
        node.on_frame(1, rpc1, &mut env, &mut catalog, &mut rng, &mut defer_store);

        node.decode_group(group, &mut env, &mut catalog, &mut rng);

        // 4. Receive Have and Want messages and drain writer queue
        let mut rpc_have = Rpc::default();
        let _ = rpc_have.joins.push(peer_join);
        let _ = rpc_have.haves.push(Have::holding(group, Bitmap::singleton(0), false, false));
        let _ = rpc_have.wants.push(Want::pull_ask(Ask { group, index: 2 }));
        node.on_frame(2, rpc_have, &mut env, &mut catalog, &mut rng, &mut defer_store);

        while let DispatchOutcome::Send(_) = node.next_to_send(2, &mut env, &catalog) {}

        // 5. Heartbeat and pace tick
        node.on_timer(TimerEvent::Heartbeat, &mut env, &mut catalog, &mut rng, &mut defer_store);
        node.on_timer(TimerEvent::PaceTick, &mut env, &mut catalog, &mut rng, &mut defer_store);

        TRACK_ALLOCS.store(false, Ordering::SeqCst);
        let allocs = ALLOC_COUNT.load(Ordering::SeqCst);

        assert_eq!(allocs, 0, "Expected zero heap allocations on protocol hot path, got {allocs}");
        assert_eq!(env.delivered_count, 1);
        assert_eq!(env.last_delivered_group, Some(group));
        assert_eq!(node.group_state(&group), Some(GroupState::Complete));
    }
}
