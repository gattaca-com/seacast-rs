# AGENTS.md

## What this is

A Rust implementation of SEACAST: chunked, erasure-coded diffusion of large objects between peers. The specification is the `informed-diffusion-spec` repository (`seacast.md` is primary; `seacast-lite.md` holds the rules it carries over). `README.md` describes the design, the host's contract, and every place the code departs from the specification. `NOTES.md` lists the open items: read it before starting, and keep it current.

## Priorities

The emphasis is on, in this order:

1. **Performance.** This is latency-critical code. Nothing on the chunk path allocates, blocks or copies a chunk's bytes without need.
2. **Simplicity.** Simple, predictable designs are easier to optimise, debug and scale.

Assume a very high bar for engineering quality.

- **Simplicity over complexity.** Be concise. Complexity spreads fast and kills performance.
- **Simplicity is not laziness.** Simple does not mean the easiest path. Heavy abstractions (async everywhere, large frameworks) are quick to write and hard to reason about and optimise later. Real simplicity is clarity: code that is easy to understand a month from now and hides no cost behind layers. Convenience is not simplicity.
- **Contain complexity.** Keep modules tight, scope narrow and interfaces explicit (no `pub use ::*`). Complexity that leaks across boundaries becomes spaghetti.

## Design principles

- **The core is domain-agnostic.** `seacast-core` knows a chunk's type, group, index and an opaque frame. It knows nothing of blocks, slots, bids, payloads or any concrete object type, and it has no clock but the host's. Do not add domain names, constants or rules to it.
- **The codec is networking mechanics only.** `seacast-codec` holds segmentation, the segment descriptor, Reed-Solomon, Merkle, SHA-256, Snappy. `SegmentedCodec` is the `TypeCodec` of a segmented type. No domain logic.
- **Everything domain-specific lives in `seacast-sim`:** the type ids, the payload catalog and its host, the simulator.
- **Three traits, three concerns.** `TypeCodec` (frame layout and the checks that need only the chunk), `Domain` (whether a group is authentic, and its deadline), `Policy` (types, interest, duty, parameters). Keep a new rule in the trait whose concern it is.
- **Sans-io and single-threaded.** `SeacastNode` never blocks, spawns nothing and holds no lock. All I/O, timers, randomness and buffers come through `RuntimeEnv` and the other host traits.
- **No allocation after `SeacastNode::new`.** Every table is sized once from `CapacityConfig`. A test in `crates/seacast-core/src/lib.rs` counts allocations.
- **The node never reads a chunk's bytes.** It is generic over the buffer handle only, so a handle may point into a host's cache.
- **The node owns its send queues** (`SendQueues`): the host's writer takes what to write with `next_to_send`, and there is one send path.
- **Slow steps leave the node's thread as a request and return as a result:** the proof check (`pop_unverified`, `on_validated`), level 2 (`start_decode`, `on_decoded`) and the domain's word (`Defer`, `on_groups_authenticated`). Do not add a call that blocks the node on any of them.
- **A `PeerId` is a connection's and indexes a slab.** The host keeps peer ids below `max_peers` and may use one again after `disconnect_peer`. State kept by the peer alone, or by peer and type, is a field of `Peer` and is reset when the connection closes. State that must outlive a connection is keyed by `NodeId`. A peer id the node gives out to take back later (a timer, a chunk to verify) is stamped (`PeerSlab::stamp`, `GenerationPeerId`) and resolved on return.
- **No walk over the peers on the chunk path, and no list of peers of a fixed length.** Who is in a relation, who is linked for a type, who offers or holds a group and who waits for a chunk are bitmasks by key (`PeerSets`), kept as the state changes. A set of peers is named by a `PeerSet` and read in place: `walk` and `for_each` hand the node to a closure for each peer, `peers_of`, `count` and `in_set` read it. Do not copy a set out to loop over it. Where a set must be ordered or sampled, use the node's scratch lists, which have room for every peer.
- **Peer-created state is bounded.** A full table refuses a new key instead of failing, and state a peer can make the node keep is admitted against a limit first. A new table needs a capacity, a limit and a test in `crates/seacast-core/tests/limits.rs`.
- **Lifetimes are deadlines or TTLs, never slots.** The domain may give a group a deadline; otherwise the node's TTLs apply.

## Layout

| crate | role |
| --- | --- |
| `crates/seacast-core` | the state machine with its send queues, the host's traits. Only dependency: `fxhash`. |
| `crates/seacast-codec` | the codec of segmented and standalone types |
| `crates/seacast-gossipsub` | the gossipsub binding: control strings, the payload's codec, a received `RPC` in parts |
| `crates/seacast-sim` | the domain: type ids, the payload catalog, the discrete-event simulator |

The README's last section lists the modules of `seacast-core`.

## Building and checking

```bash
just fmt                                 # rustfmt on the pinned nightly
just clippy                              # clippy, warnings denied
cargo test --release --workspace         # unit, limit, end-to-end and simulation tests
cargo run --release -p seacast-sim       # the five settings of seacast.md §6.2
cargo run --release -p seacast-codec --example bench
```

- Run `just fmt` and `just clippy` after every change; both must pass. `just clippy` does not cover test and example targets, so also run it with `--all-targets` when you touch them.
- **The simulator's summary is the regression check for the core.** A change that is meant to preserve behaviour must leave the last lines of the simulator's output byte-identical: hash them before and after.
- The codec benchmark is the check for the codec's hot paths: compare before and after a change there.

## Working rules

- **Minimal diffs.** No refactors unless asked.
- **No new dependencies without asking.**
- **Scope discipline.** Read only what the task needs. The spec files are large: search them for the rule in question instead of reading them through.
- **Commit only when asked.** While work is uncommitted, copy `crates/` and `README.md` to a directory under `target/` (git-ignored) before a large change.
- **Keep the README current** with every change to behaviour, names or the host's contract. Its section "Where this differs from the specification" must list every departure: add a bullet when a change introduces one. Its diagrams are Mermaid: check they still parse after editing them.
- **Report faithfully.** Say what was verified and what was not, and flag uncertainty.

## Style

- Explicit, systems-style Rust, in the tone of the Linux kernel or Firedancer.
- Comments are terse and factual, written for senior systems engineers, and only where the logic is not obvious. No tutorial comments. Cite the specification's rule (`seacast.md` §4.6) where code implements one.
- **Never put a measurement in a comment, a doc comment or this file.** It goes stale. A comment may say which way a result went and why, never by how much.
- Simple technical English: concise, stable terminology, one term for one thing.
- No em-dashes or en-dashes in prose. Never hard-wrap prose in Markdown: one paragraph is one line.
