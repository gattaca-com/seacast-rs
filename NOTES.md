# Open items

Working notes for whoever picks this up next. Nothing here is decided unless it says so. Remove an item when it is done; put design that has landed in `README.md`, not here.

## Integration into Silver (network and control tiles)

The node runs in the network tile, with its send queues. Decided; not checked against Silver's code.

- **Network tile:** `SeacastNode` (with `SendQueues`), the catalog, and the writer that calls `next_to_send`. Received chunks are written to tcache there, so the tile links `seacast-codec`.
- **Other threads:** level 2 (`start_decode` hands the job, `on_decoded` takes the result) and the domain's verdict (`Domain::authenticate` answers `Defer` on a cache miss, the host calls `on_groups_authenticated` when the verdict is cached).

What the host must hold to:

- **`B` must be `Send`, and a chunk's bytes must stay valid until `on_decoded`.** The decode job carries buffer handles to another thread. The core checks neither.
- **`Domain` is a cache in the network tile.** `authenticate`, `authenticable`, `deadline` and `sample_scope` are called on the node's thread. `on_groups_authenticated` calls `authenticate` again, so the verdict must be cached before that call.
- **Chunks of a group wait while its verdict is pending**, bounded by the `DeferredStore` and by `max_pending_groups` a peer. A slow verdict therefore drops chunks. Not measured.
- **A decode works on the chunks held when it was started.** Chunks that arrive during the decode are stored and not decoded from. `on_decoded` after the group has expired is ignored. A second `on_decoded` for one group is not guarded against.
- **`start_decode` clones the handles of the chunks held into the node's scratch**, and a host that decodes on the node's thread through `decode_group` collects them a second time.
- **The byte window is node-wide.** It works as is only if one network tile owns all peers. With peers spread over several tiles it must be split or shared.

Questions that need Silver's code read (tcache):

- **Chunk lifetime in tcache.** The node keeps a handle for the group's whole life, to serve late asks and to decode from any K chunks. If tcache can overwrite an entry before the group ends, the handle dangles. Either tcache is sized for the worst case over a group's lifetime, or accepted chunks are copied into a per-group slot store, which the codec's in-place functions (`complete_in_place`, `body_into`) already support.

## Open design questions in the core

- **One catalog object implements all three traits.** `PayloadCatalog` therefore forwards every `TypeCodec` method to its `SegmentedCodec`. Passing codec, domain and policy to the node as separate arguments would remove the forwarding and change every entry point's signature.
- **No catalog composes several types.** `SegmentedCodec` and `StandaloneCodec` are each one type's `TypeCodec`; a host with several types dispatches on the group's `type_id` itself. A node joins at most `MAX_JOINED_TYPES`.
- **Cost with many types is not measured.** A host with a type per subnet joins up to about 200. `maintain_relations` and the heartbeat's gossip walk every joined type, `joined_types()` returns `MAX_JOINED_TYPES` ids by value, and each connection's record holds three maps sized `max_types`.
- **A chunk's context is in every chunk.** A type whose context is long (a column's commitments) pays it N times. `protocol-v2.md` sends a header once a group and link; not done here.
- **A cancelled push leaves an offer owed** through `SendQueues::owe`. Whether the node should send that offer itself was left open.
- **`on_chunk_head` trusts the host's proof check.** It drops a copy of a chunk held, or of one that waits, on its head alone. A host that leaves the proof to `TypeCodec::check_proof` must not call it. A copy of a chunk that waits is told only by its id, which no chunk's head gives, since the id hashes the frame: such a copy from another peer is read. The entry has one test, with scripted peers.
- **Capacities follow the types joined** (`CapacityConfig::size_for`, from `TypeParams::max_indices` and `max_groups_per_slot`). Open points:
  - **Only `max_types`, `max_groups` and `max_stored_chunks` are derived.** `max_owed_pairs`, `max_pairs`, `max_asks`, `max_seen_ids`, `max_deferred_chunks` and `max_ask_peers` also grow with the groups and are still the host's to set.
  - **A group's bitmaps are kept in its record only while they name no index past 63** (`GroupBits`, read and written through `Groups::bits`, `put_bits`, `edit_bits`). One that names a higher index is kept in a row of `max_wide_groups` rows, a row a group. With no row left the write is dropped and the bitmap stays as it was: the node then holds a chunk it does not count as held. Nothing counts or logs it. `CapacityConfig::size_for` takes a type as wide if its `max_indices` is above 64.
  - **A read of a bitmap copies it**, 136 bytes, where it was a reference into the record. Not measured.
  - **The table of records has room for twice `max_groups` rounded up to a power of two.**
  - **A group's repair sample is kept beside its record** (`rsamples`, `max_repair_samples` groups). Full, a group asks for no sample and its verdict is `Repaired`, as when no custodian could be asked. `CapacityConfig::size_for` does not set it.
  - **`cancel_group` walks every peer's queue** at each group's end, so its cost is peers times the queue length a group. With thousands of groups a slot this is not measured.
  - **What is owed of a group of one chunk is dropped at a full ring** (`max_owed_single_per_peer`), offers and answers each in a ring of their own. A dropped offer reaches the peer by the heartbeat's gossip; a dropped answer breaks the promise the peer runs on its ask. A group that ended stays in the ring until it is taken, and takes a place meanwhile.
  - **What is owed of the other groups is one table for all peers**, by peer and group (`Owed`, `max_owed_pairs`), offers and answers each in one. A peer has an equal share of it (`max_owed_pairs / max_peers` pairs): what is owed of a pair beyond its peer's share is dropped, with the same effect as at a full ring; nothing counts or logs it. The lowest group owed to a peer is found by a pass over the whole table, a pass for each group an entry takes: only for a peer that is owed something. Not measured.
  - **A group counts as of one chunk by its header** (`Shape::n == 1`), not by its type's `max_indices`: what is owed of a group not open goes to the map.
- **A popped chunk must get a verdict.** A host that takes a chunk from `pop_unverified` and never calls `on_validated` leaves its id in `verifying` until the group ends, and other copies are refused meanwhile. There is no timeout.
- **A deadline is fixed when first asked**, and a group known only from offers has none until its first chunk.
- **Memory.** The per (peer, group) table is the largest. Ideas not tried: peer lists held inline, a dense index for pairs. `cargo run --release -p seacast-core --example node_size` prints the heap a node holds after `new`. Most of it is the send queues: three lanes of `max_queue_entries_per_peer` entries and two maps of `max_groups` bitmaps for every peer id, allocated whether the peer is connected or not. An entry is as wide as a control message with its bitmap, also when it stands for a chunk.

## Reed-Solomon

- **The FFT parity path covers K a power of two only.** For another K the points `0..2K` are not closed under XOR and the matrix is used. Whether such a K can use a transform without changing the code is open; padding K up changes the parity, so it is a specification change.
- **The NEON and ARMv8 SHA2 arms are compiled and linted for `aarch64-apple-darwin` where they are written, and run on one Apple core**: its tests and benchmark, which asserts every root.
- **`STREAMS` is four on aarch64 by analogy with x86.** On one Apple core two, three and four streams hash at the same rate: its SHA2 rounds overlap less than SHA-NI's do on the x86 core tried, and two streams already reach the limit. Four is kept for a core that overlaps more; none has been tried.
- **The NEON three-input XOR needs the `sha3` target feature**; without it two XORs are used. This one is still chosen at compile time: a build for a baseline aarch64 target uses two XORs on every CPU.
- **The kernels are chosen at run time** (`Arm` in `sha256.rs`, `Code` and `Kernel` in `reed_solomon.rs`). Open points:
  - **A kernel's entry point is called, not inlined**, since its caller is compiled for the baseline. Against a build with `-C target-cpu=native` the benchmark is level, but for the parity of a group over GF(2^16), which is slower: a butterfly there is a call per plane of a strip.
  - **Code outside the kernels is compiled for the baseline.** The XOR of two strips was such a loop and is now the kernel's (`Kernel::xor`). The copies between a chunk and its planes (`gf16::load`, `store`) are not: compiling them with the kernel's instructions was tried and gained nothing.
  - **The four-stream SHA-NI arm needs AVX**, for the three-operand encoding. A CPU with SHA-NI and no AVX hashes one message at a time; none was tried.
  - **The single-stream SHA-NI arm moves its message words by position**, so that they stay in registers without the round loop being unrolled, which the baseline build does not do. The same change made the four-stream arm slower and is not made there. The ARMv8 arm indexes its words as before and was not measured in a baseline build.
  - **One body compiled for two sets of instructions through `#[inline(always)]` was tried** for the four-stream arm, with and without AVX, and was slower than either compiled directly.
  - **The run-time choice on aarch64 is linted for `aarch64-apple-darwin` and not run.**
- **The row count from which `rs_parity_rows` takes the transform** is one constant for the GFNI kernel, measured, and one for the others, placed from the benchmark's sweep on AVX2 and on one NEON machine: two shapes each, not a sweep of both paths.
- **`combine` copies each strip of the sources side by side on the kernels that make a pass per row**, since segments of one buffer evict each other from the cache. Measured on AVX2; on NEON it is inferred from one machine's benchmark, where the in-place lines were several times slower than the same work on separately allocated chunks, and not yet rerun there. The destinations are still written where they lie.
- **The GFNI and NEON arms compute several rows a pass; AVX2 does not.** It has sixteen registers and needs two for a coefficient's tables, so at most four rows of one vector; not tried.
- **Running the transform in the parity chunks themselves, with no work buffer, was tried and was slower.** Chunks a multiple of the page size apart land in the same cache sets.
- **`fft::parity` allocates its work buffer on every call**, K strips.
- **Recovery over GF(2^8) is still by matrix.** Its cost grows with the chunks lost; a transform-based erasure decode would bound it. Not tried there.
- **The `GF(2^16)` Leopard-RS implementation (`reed_solomon/gf16.rs`) is kept in `seacast-codec` (`#[allow(dead_code)]`)**, but `segment.rs` enforces the specification's `MAX_CHUNKS = 256` limit for coded groups (`version == 2`), sending larger bodies plain (`version == 1`). Open points on `gf16.rs` if it is ever enabled:
  - **A 10 MiB body is not coded.** K = 640 gives 1280 chunks and a bitmap names 1024 (`BITMAP_WORDS`). Twenty words would take it, and widen every bitmap, queue entry and pair record. The code's tables follow `MAX_BITMAP_BITS`.
  - **The format is not in the specification.** It is that of `leo_encode` of Leopard-RS with as many recovery shards as original ones, and the descriptor does not name it: the count alone says which field. A change needs a descriptor version.
  - **Compatibility is checked against parity from one build of the reference** (`github.com/catid/leopard` at `910ad0a`, the legacy `leo_encode`): six cases, by a hash and the first bytes, in `test_parity_is_leopards`. The reference's decoder has not been run on chunks made here, and no port of Leopard (`reed-solomon-simd`, `klauspost/reedsolomon`) has been checked.
  - **Only the wide code is Leopard's.** A group of 256 chunks or fewer is the specification's GF(2^8) code, which is not Leopard's 8-bit code.
  - **Leopard picks its transform length from the recovery count.** The code here is always that of `K` recovery shards, which is what a group has. `rs_parity_rows` with fewer rows gives rows of that code, not what `leo_encode` gives for the smaller count.
  - **A chunk is split into two planes in the work buffer and joined on the way out**, a copy each way. A kernel over the blocks as they lie would save both; not written.
  - **Recovery costs the same whatever is lost**: two transforms over twice the points and the derivative. With few chunks lost a matrix over GF(2^16) would do less; not written.
  - **The transform of the data does not skip the zero slots** past `K`, and the transform to the parity is not cut to the `K` rows, as Leopard's is, so K just past a power of two pays for twice the points.
  - **The locator is a sum of logarithms per point and point not known**, quadratic in the points. A Walsh transform would make it `n log n`; not measured as a share of recovery.
  - **`parity` and `restore` allocate their work buffers on every call**, and the tables are built at the first wide call (`LazyLock`): the first group pays for them. `restore` builds a constant for every chunk known and wanted on every call.
  - **The bytes past a kernel's last whole vector go through the logarithm tables**, a symbol at a time, as does every byte of the portable arm. Only a segment whose half is not whole vectors has such bytes.
  - **The strip length was placed from the benchmark on the GFNI kernel only.**
  - **The NEON butterfly is type-checked for `aarch64-apple-darwin` and has not run.** The AVX2 and portable arms were tested by building for `haswell` and `x86-64`.
  - **No group of more than 256 chunks has gone through the core or the simulator.** The codec's tests cover it; the core already took plain groups of that length.
  - **`MAX_CODED_BODY` is four times what it was**, so a host that reserves it per group reserves that much more, and a coded group may decompress to that.
- **`gfni::row` is `#[inline]`** because adding the FFT module stopped it being inlined into `combine`, which slowed recovery. The other kernels' `row` were already out of line and are unchanged.

## Findings of the 2026-11-23 study

A study of commit `1e486ee` against the specification listed defects by number (F1 to F20, R2 to R4). Addressed 2026-11-23:

- **F13: the pad of a short last data chunk is checked to be zero after the decode** (`decode_and_reencode`), so level 2 gives the same verdict whichever chunks a node decodes from.
- **F12: `build_group` refuses a body past `MAX_PLAIN_BODY`** with a panic of its own, documented, where `MerkleTree::build` panicked.
- **F11: `PROTOCOL_ID` was `/seacast-rs/2.0.0`.** Gone with the local wire format (below).
- **F2, F6, F7, F9: admission before any change of state.** A chunk the chunk table refuses is neither counted nor claimed (`store_chunk`); a GRAFT the relation tables cannot keep is answered no; an answer whose counts cannot be kept (`serve_count`, the pair's record) is not given; the default deferred store reserves nothing for a peer it cannot count, and a count of zero gives its place back. At `publish` a chunk not stored is not claimed, and the group is still marked complete.
- **F4: a peer has a share of the owed table** (above).
- **F16: an owed answer whose chunk has gone is passed over** (`pop_owed_answer`).
- **F3: a probe's answer named by the chunk's other group is read** (`on_chunk_head`, through `cross`).
- **F18: a probed claimant's copy that comes while another's is being verified answers the probe at the verdict** (`verifying_claimant`, one claimant an id).
- **F17: a probe with no room for its promise has no verdict, and the repair duty is armed again at its own time.**
- **F14: the default repair candidates** (README). The simulator's tier 4 row moved with it: fewer repair pushes, more answers, a later p99.
- **F8: the id of a rejected chunk of a group with no record is not kept in `seen_ids`.** A repeat is checked and counted against its sender again.
- **F19: a holding saved before the count was known is cut at it** (`drop_beyond`, also called from `publish`).
- **R2, R3: a JOIN is never dropped, and a repeated GRAFT or PRUNE is owed once** (README). A GRAFT or PRUNE refused by a full ring is still dropped; for a PRUNE or an answer the two ends then disagree until upkeep or a later message sets it right.
- **R4: `on_relation_join` lists the groups of the type and family only**, still 512 at most.
- **F10, F20 in part:** a peer is not counted as listed for an ask whose list the offers table has no room for; the holders follow a holding as the pair's record keeps it.

Left as they are:

- **F1: `complete_in_place` does not compute again the chunks that are there** (see "Level 2 hashing").
- **F10: the window tracks at most `max_peers * 64` chunks**, a full tombstone table lets an expired group back, and `pending` has one cap for all peers.
- **F20: with the pool of wide bitmaps empty, a pair's indices past 127 are not kept**, and with no wide row left a group's bitmap is not written.
- **`probe_answers` full:** a probe's answer then loses its exemption at the write.

## The specification's v0.10.11 to v0.12.0 changes

Applied 2026-11-23:

- **Asks outside what the node serves (`seacast.md` §4.5 `outside`, `drop_outside`):** ignored without penalty once `authenticable(g)` is true; asks arriving before the gate are swept in `on_groups_authenticated`. `PenaltyReason::AskOutsideOfferOrInterest` was removed.
- **Routed requests and `FORWARD_LIMIT` (`seacast.md` §4.5):** routed asks outside our interest add no `want_p` bit and are kept in `standing` only when `route_want` passes them on; `forwarded` is keyed by `(NodeId, TypeId)` and increments only when `enqueue` succeeds.
- **WANT bounds and deduplication (`seacast.md` §4.5):** indices bounded by `TypeParams::max_indices` (`MAX_INDICES`) before open and swept by `drop_wants_beyond`; unknown groups in WANTs tracked in `wanted_groups` separately from `named`, a place lasting `GROUP_TTL` from the group's first naming and freed with the asker's standing requests, route marks and interest bits (`release_wanted_groups`, at each heartbeat and before a group opens); duplicate asks/chunk IDs in one frame charged once; answers on our own written offers (`offered_to`, recorded in `next_to_send`) and claim probes are exempt from `max_served_per_heartbeat`.
- **Chunks and holdings on unjoined links (`seacast.md` §2, §4.2, §4.3):** accepted for any type the node runs; `claim_all` on an unjoined link does not enter `claims` and ties on an unjoined link do not become offers.
- **Per-type `MAX_RELATIONS` (`TypeParams::max_relations`, `relation_room`):** counts `(family, colour)` pairs across `push_in`, `push_out`, `grafted_in`, `grafted_out`, backoffs not run out and our GRAFTs and PRUNEs still owed; GRAFTs for new pairs at the limit are ignored without answer. `NodeConfig::max_relations_per_link` is removed. `relation_room` walks the relation keys of the type, not their peers; past a bound taken from the tables' lengths it also walks `grafted_in`, `grafted_out` and `backoff`, which hold every link's entries. It runs at each GRAFT received and for each candidate of our own GRAFTs, not on the chunk path.
- **A holding that repeats a bit frees the room of a copy written since** (`seacast.md` §4.3, v0.10.12).
- **Source `publish` answers standing requests (`seacast.md` §4.7).**
- **`SAMPLE_OUTSTANDING` moved from `TypeParams` to `NodeConfig` (`seacast.md` §4.10, v0.11.1).**
- **Spec filenames updated to `seacast.md`, `seacast-lite.md` and `seacast-bindings.md` (v0.12.0).**

## The specification's v0.10.4 to v0.10.11 changes

Applied 2026-11-22:

- **`on_validated` and `forward` skip axes where the index is already `Received`** (`protocol-v2.md` §4.2, §4.4, v0.10.6), while still forwarding an index held only as `Rebuilt`. Covered by `a_second_id_for_a_received_index_is_not_forwarded` in `crates/seacast-core/tests/limits.rs`.
- **The window's waiter line skips writers mid-write** (`RuntimeEnv::is_writing`, `SeacastNode::write_waits`, `protocol-v2.md` §4.11, v0.10.7 and v0.10.9). `RuntimeEnv::is_writing` defaults to `false`, and the simulator does not model mid-write backpressure. Covered by `the_window_line_skips_a_writer_mid_write` in `crates/seacast-core/tests/limits.rs`.
- **The Waggle, libp2p stream, partial-messages and draft native QUIC bindings are not implemented**, and cell header form (c) has no wire kind defined in the specification.

## The specification's v0.10.2 to v0.10.4 changes

Applied 2026-11-18, the README's first departure lists them. Open:

- **The standalone binding's encoding (`seacast-codec::wire`) was removed 2026-11-23** for the gossipsub binding (below). The node still marks the first unsolicited push of a group on a link (`QueueEntry::first_of_group`) and tells `wire_size`; no type sends anything with it.
- **The chunk id's content is built on the data's leaf** (decided, after the binding's hash of the body cost each chunk a second pass over its data). `sha256(leaf || the frame before the data)` binds every byte level 1 reads, so ids stay unforgeable; a hash of the data alone would let a copy with the right data and a wrong proof, rejected and marked seen, shut out the honest one. The codec benchmark's `decode_and_reencode` is back near its former time.
- **`SegmentedCodec::check_proof` trusts a nonzero `memo` as the data's leaf.** `identify` computes it from the bytes; a host that sets `memo` otherwise must set the leaf.
- **The group carries its type** (`GroupId::type_id`), as the binding's does. `Policy::type_of_group`, the separate types of `Have`, `Want` and `ChunkMsg`, and the type a peer named a group with went; the trait methods that take a group, and `DecodeJob`, no longer take a type beside it.
- **Hashing the wider `GroupId` moved the simulator's Sampling p99.** With the group hashed by its key alone the summary is byte-identical to before, so the binding's other changes left it as it was; the shift is `fxhash`'s order over the wider key.
- **The simulator's groups keep their former keys at index 0**, a column's not its block root and column. A cell is carried with its column's group and id on either axis, as the binding's id is.
- **`Evidence` stays in the node's message types** and `RuntimeEnv::publish_evidence` remains; the wire sends none, as the binding reserves its kind.
- **The IHAVE limits keep their defaults, 128 frames and 2048 asks a heartbeat**, under the specification's reference values (4096 and 5000). Decided; the values are each node's own.
- **The simulator's Rows setting moved with `note_push` across axes**: one eager copy and seven repair copies fewer, the same latencies. No other change moved the summary; at the default `SOURCE_OFFERS` the source is as before.
- **The new rules are tested with scripted peers only** (`crates/seacast-core/tests/limits.rs`): the simulator reaches no dropped group, pull-only source, refused or unwritten probe, departed claimant or probe kept while decoding.
- **`drop_beyond` takes the indices from the offers.** Every ask, try and promise is of an offered index, so they are covered; a tie past the count goes at its release instead, which comes before the group can open.
- **`serve_waiting_probe` does not hold to the heartbeat's serving budget**, as the draft's does not; `serve_standing` here does.

## The specification's v0.10 changes

`informed-diffusion-spec` moved from v0.8 to v0.10.1 (2026-11-15). The README's first departure lists what is applied and what is not. Open on what is applied:

- **`probe_answers` shares `max_groups` as its capacity** and has no limit test of its own: an asker can add one entry per group it probes, which the per-peer limit on groups bounds.
- **The simulator's row setting now starts its asks after one second** (`START_DELAY`, decided in §6.3), so its latencies are a second longer than in earlier summaries.

- **The relation upkeep is not run by the simulator**, which writes its relations into the sets at setup. The answered GRAFT, the backoff and the owed messages are covered by one test in `crates/seacast-core/tests/limits.rs`, with one peer; two nodes grafting each other have not been run against each other.
- **`SendQueues` owes at most `max_queue_entries_per_peer` relation messages a peer**, and drops the newest beyond that.
- **`PRUNE_BACKOFF` defaults to 12 seconds and `FORWARD_LIMIT` to 1.** The draft states both by their bounds; each node's value is its own, so neither is a departure. The 12 seconds have not been checked against the backoff's upper bound (how long a node may stay below its floor once its candidates have refused).
- **`plan_refused` holds a source's refused pushes** until their group expires, sized by `max_stored_chunks`. Full, a refused push is offered a second time at its acknowledgement.

Open on the floors, the sampler and the rest of §4.1:

- **`link_deficits` is called by nothing here.** The simulator opens no links. It is covered by one test in `crates/seacast-core/tests/limits.rs`. Silver's host is to poll it and to subtract the links it has opened that are not joined yet.
- **`reset_period` is called by nothing here.** The simulator runs one block. Silver's host is to call it at the slot boundary.
- **`NodeConfig::order_key` defaults to zero.** The host must draw it. Ordering beyond an ask's offer list uses HMAC-SHA-256 (`crates/seacast-core/src/hmac.rs`). Nothing on the wire carries it.
- **The keyed order of the announcers has no test.**
- **The symmetric relation is covered by one test with scripted peers.** No simulator setting uses a symmetric type.
- **The sampler's second phase, its peer of high custody and its limit in flight are covered by one test.** The simulator's sampling setting reaches the first phase and routed requests of one step; `ROUTE_HOPS` above one has not been run.
- **The simulator's sampling setting scopes "one sample per peer" by block** (`Domain::sample_scope`), and its interest check now counts pushes only: an answer to a forwarder's own WANT is outside its interest by design (§4.5).
- **`sampled_from` and `held_samples` share `max_asks` as their capacity, `samples_in_flight` shares `max_groups`, `forwarded` `max_peers`.** They hold the node's own asks, except `forwarded`, which a peer fills with one entry. Full, a sample is reported unreachable.
- **A set of peers is named, not copied.** `PeerSet` says how a set is read from the node's bitmasks (`links`, `in_pushers`, `out_pushees`, `suppression_scope`, `source_pool`, a chunk's standing requests, a group's claimants). `SeacastNode::walk` and `for_each` read it a word at a time and hand the node to a closure for each peer; `peers_of`, `count` and `in_set` read it without one. A change the closure makes to the set it walks counts for the words not yet read: no loop body does that today.
- **Where a set is ordered or sampled it is written to a scratch list in the node**, with room for every peer (`peer_scratch`, `shuffle_scratch`, `push_scratch`): `choose_push`, the heartbeat's gossip sample, the repair shuffles, and the pruning of a symmetric relation. The list is taken out of the node while in use and must be put back: a path that returns without it leaves the scratch empty, and the next use then keeps no peer.
- **One peer is picked by two passes**, a count and a walk to the peer drawn (`choose_one`): the same draw as `RngSource::choice` over the list, which is not made. The announcer to ask is picked in one pass by its rank (`pick_announcer`).
- **Lists of a fixed length that remain:**
  - `Policy::repair_to` returns a list of 64: a host's own choice of repair targets is cut there.
  - A source's plan keeps `MAX_PLAN_TARGETS` (8) targets a chunk, and an ask's offer list `max_offers_per_ask`: both bound by design, not by the peers.
- **`choose_push` orders its candidates with an unstable sort over a total key**, where it sorted twice with a stable sort. The stable sort allocates past a short length, which the allocation test did not reach.
- **A claimant to probe is drawn in peer id order**, not in the order the claims came. The simulator's summary did not move.
- **Peer lists are now in peer id order**, not the order of connection. The simulator connects in id order, so its summary did not move; a host that connects in another order draws its targets from lists in another order.
- **Walks over the peers that remain**, none on the chunk path: `maintain_relations` (the relations held one way), `repair_candidates`, the heartbeat's choice of gossip targets, `disconnect_peer` (a pass over each table) and group expiry.
- **`CapacityConfig::max_relation_keys` bounds the keys (type, family, colour) with a relation, a direction, not the relations.** Each key holds a bitmask of `max_peers` bits. The relations of one link are bounded by `MAX_RELATIONS` (`TypeParams::max_relations`).
- **A group's offers and holdings need a row in the pair table's index**, sized `max_groups + max_peers * max_pending_groups` rows and at most `max_pairs`. Past that an offer or a holding of a new group is not kept, as with a full pair table.
- **The writer still scans its own queue**: `choose_normal_index` reads the normal lane up to three times a write, with a `holders` lookup a chunk.
- **`family_word` reads a row a colour**: a type of many colours costs that many lookups a word of the bitmask, a chunk. Not measured.
- **The slab holds the state keyed by the peer alone or by peer and type** (`Peer`), and the send queue has a slab of its own in `SendQueues`. The tables keyed by peer and something unbounded per peer are still global maps: the relations (`push_*`, `grafted_*`, `backoff`), `pairs`, `tied`, `named`, `serve_count`, `unwanted`, `probe_answers`, `plan_refused`, `sampled_from`, `rsample_asked`, `sends.sent`. Moving them into the slot changes their capacity from one shared budget to the worst case of every peer, and makes the reads across peers (`forward` over a family's relations) a walk over the slots. Not measured either way.
- **A connection past `max_peers` is no longer refused by the node.** A peer id out of range panics; the host admits connections.
- **`forwarded` is keyed by `NodeId` with capacity `max_peers`.** Nodes that connect, route one request and leave fill it within a period; routed requests of a node without a count are then refused until `reset_period`.
- **`tried` and `promises` (`AskPeers`) are one flat map each, by ask and peer,** with a bitmask of peers an ask so that an arriving chunk closes its records without a scan. Each is bounded twice: `max_ask_peers` records in the node and `max_asks_per_peer` for one peer. Open points:
  - **The bound per peer delays a pull from one announcer.** An offer of more chunks than the bound makes that many asks; the rest wait for the heartbeat, which retries them while the peer's records are still open. The default bound is one group's indices (`MAX_BITMAP_BITS`), so a pull of one whole group from one announcer is not cut; asks of several groups open at one peer can be. The specification's own limit, `MAX_IHAVE_LENGTH`, counts asks per heartbeat and is above the default bound. The simulator's settings do not reach either bound, so this delay is not measured.
  - **A retry does not pass over a full peer.** `pick_announcer` can pick an announcer whose records are full; the ask is then held to the next heartbeat although another announcer may have room.
  - **A probe that cannot record its promise is not sent** and the decode is not deferred.
  - **Closing a connection scans the two maps** if the peer has a record. A group's end scans them always.
  - **A refused record is not logged or counted.** The core has no log.
- **`kept_parks` is bounded by `max_kept_parks`.** Full, a park is not kept and the node's next connection starts without it. Entries past their end go at the next connect or disconnect, and with their group.
- **A chunk whose verdict comes after its connection closed is dropped unseen**, also when the verdict is `Accept`: the proof check is spent and the chunk must come again. Chunks of a closed connection still in `unverified` are handed to the host all the same. Both could be avoided by taking the chunk with no sender.
- **`PromiseDue` and `WindowTimeout` carry a plain `PeerId`.** Their `at_bits` is the guard: a closed connection's entry is gone, and the next connection's has another time. Two connections of one peer id that make the same ask at the same clock reading are not told apart.
- **A forwarder's WANT for a routed request starts no timer.** If the next hop never answers, the standing request it kept for the asker goes with the group.
- **`TimerEvent::Resample` changed shape**: one index, an optional peer and the phase. A host only passes it back.

## Level 2 hashing

- **Four leaves at a time on SHA-NI matched the 16-lane AVX-512 kernel on full batches** on the one machine tried (Zen 5), so `sha256/x16.rs` could go there. Not measured on an Intel core, where the SHA-NI rounds may not overlap as well; the 16-lane kernel stays until it is.
- **`ChunkMsg::memo` is 32 bytes a chunk the node holds**, in every table of chunks. Memory has not been measured with it.
- **A chunk whose `memo` is zero is hashed at level 2**: one a host passed through neither `identify` nor `SegmentedCodec::check_proof`. A publisher's own carry their leaf's digest from `build_chunks`, which hashes each leaf a second time after `build_group` built the tree.
- **`decode_and_reencode` takes the digest of the K chunks it decodes from only.** A parity chunk given beyond those is computed again and hashed, as the specification's re-encode does, so that every node gives the same verdict. `complete_in_place` does not: it leaves a chunk that is there as it is, so a group whose committed parity is not the code's passes at a node that holds all the data. That was so before the digests were reused.
- **A slot that changes after its level 1 is not detected by level 2**, since its digest is not recomputed. Before, the full rehash caught it.

## Small cleanups

- `projected`, `valid_have`, `tie` and `interest_satisfied` keep an unused `_catalog` parameter.
- `tied` and `tied_bits` appear to hold the same thing since ties became keyed by group; check and merge.
- `tied_to_root` keeps the specification's name though the core has no root.
- `SendQueues`' methods are still `pub`, as when a host kept the queues. Only `connect`, `disconnect` and the queue's state need to be seen outside `seacast-core`, the last by the tests.
- `build_chunks` copies each data segment into a frame with its header and proof: one extra copy of the body at the publisher. The benchmark does not cover it.

## Tests and simulator

- The simulator's domain returns no deadline (it has no slots), so deadlines are covered only by `a_deadline_ends_a_group_and_bounds_its_tombstone` in `crates/seacast-core/tests/limits.rs`.
- The host in `crates/seacast-sim/tests/payload.rs` has a slot in its context and could return a slot-boundary deadline; it returns none.

## Specification

- Every departure is listed in the README, "Where this differs from the specification", in the change that makes it. A host's own departures (its object types, what its contexts hold) are the host's to list.
- The departures listed in the README have not been written into `informed-diffusion-spec`. The spec repository is unchanged.
- That list was built from the changes made here, each checked by searching the spec for the rule in question. A full audit of the core against both protocol files has not been done, so older departures may be missing.
- "Serving" in that list: the ask-legitimacy check was compared with the `on_want` pseudocode only. The spec's prose may already state the condition, in which case it is an enforcement and not a departure.

## The gossipsub binding

Added 2026-11-23: `crates/seacast-gossipsub` (`seacast-bindings.md` §4), for integration into Silver and rust-libp2p. Open:

- **One client adapter, in Silver, not merged** (2026-11-24): `crates/gossip/src/handler/seacast` on the branch `seacast-gossip` of `pq-silver`, behind its `seacast` feature. Its tests run two handlers over real gossipsub frames with timers and loss. It takes the first two groups it sees in a slot as authentic, as Prysm's interim authority does, since a chunk names no block. Here, `crates/seacast-gossipsub/tests/nodes.rs` still runs `PayloadCatalog` over a plain struct in place of gossipsub's `RPC` and fires no timer.
- **A frame kept in two parts** (`ChunkBytes::tail`, 2026-11-24) is read by `PayloadCodec` and by level 2 only. `SegmentedCodec` and the frame-level functions of `seacast-codec` take a whole frame. `PayloadCatalog` is generic over its codec, so a host that keeps a group's chunks in place gives its own `decode` (over `complete_in_place`).
- **A sender's chunks of a group not yet authenticated are kept up to a limit.** Seen from the adapter when its domain still deferred a group until its block (it no longer defers): a receiver whose block arrived after an uncoded group's chunks (more of them than the limit) kept the first of them, and did not get the rest from the source that had pushed them all, within the seconds the test ran. Not investigated: whether repair gets them later, or from another peer.
- **One test vector from another implementation, for the payload's chunk only** (2026-11-24, made again 2026-11-25): `crates/seacast-gossipsub/tests/prysm_segments.txt`, a coded group of six segments from Prysm's `seacast-devnet` at `958496b95c`, whose chunk is the specification's `Chunk`, made with `segments.Build`, `segments.WithContext` and `p2p.MsgID`. Every chunk names slot 9 and the block root `0xb1` x 32. It covers the frame, the group id, the group key, the message id, the proofs and the Reed-Solomon parity. `prysm_plain_segments.txt` is the same body as a plain group with snappy, cut at 1000 bytes. No vector covers the control strings. The two implementations' snappy encoders may write different bytes for one body, so a publisher's descriptor is not compared, only read. The specification notes that its research harness writes a WANT's index big-endian; here it is little-endian, as the text and Prysm have it.
- **The payload's frame is `seacast-lite.md`'s again** (local branch `spec-chunk`, 2026-11-25): the frame, `group_key` and the context `slot | beacon_block_root` are as at `dac6b00`, for a Prysm that moved to the specification's `Chunk`. The rest of the parity commit stays: a plain group cut from the compressed body (`encoding = 1` with `version = 1`) and a frame read in two parts (`split_parts`). `tests/prysm.rs` reads vectors of this frame from Prysm at `958496b95c`.
- **The content id costs a second pass over a chunk's bytes**, beside the data's leaf digest, on receive and at publish. Not measured: the codec benchmark has no case for it.
- **The mesh is the host's** (`TypeParams::host_relations`, `relation_added`, `relation_removed`), decided 2026-11-23. The host must tell the node of every change, a PRUNE it sends or receives included; nothing checks the two agree. `link_deficits` still reports floors for such a type.
- **Unsubscribing** is `SeacastNode::on_leave` (2026-11-23). It ends the link and the relations of the type; what the peer told of the type's groups (holdings, offers, standing WANTs) stays until the groups end.
- **The sampler's rules** (`seacast-bindings.md` §6) and **cell groups** are not implemented on this binding.
- **`ChunkLayout`** (the two-step level 1 of a stream reader) has no user left but its tests.
