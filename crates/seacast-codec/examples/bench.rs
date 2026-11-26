//! Timings of the codec's hot paths: `cargo run --release -p seacast-codec
//! --example bench`.
//!
//! Each line is the fastest of several runs. No dependency: `Instant` and
//! `black_box`.

use std::{hint::black_box, time::Instant};

use seacast_codec::{
    Compressor, MerkleTree, SnappyBlockCompressor, UNIT, VecBufferPool, body_into, build_chunks,
    build_group, build_merkle_layers, check_frame, check_frame_proof, complete_in_place,
    decode_and_reencode, frame_leaf_hash, merkle_proof_from_layers, node_hash,
    rs_complete_data_in_place, rs_complete_in_place, rs_parity, rs_parity_rows,
    rs_reconstruct_data, sha256, verify_merkle_proof,
};
use seacast_core::{ChunkMsg, PreallocVec, TypeId};

/// Fastest of `runs` calls, in seconds.
fn best<R>(runs: usize, mut f: impl FnMut() -> R) -> f64 {
    let mut fastest = f64::INFINITY;
    for _ in 0..runs {
        let started = Instant::now();
        black_box(f());
        fastest = fastest.min(started.elapsed().as_secs_f64());
    }
    fastest
}

fn line(name: &str, seconds: f64, bytes: usize) {
    let rate = bytes as f64 / seconds / (1 << 20) as f64;
    println!("{name:<44} {:>10.3} ms {rate:>10.1} MiB/s", seconds * 1e3);
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 11
    }
}

fn random(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    (0..len).map(|_| rng.next() as u8).collect()
}

/// Records of a few fields drawn from a small dictionary, between runs of fresh
/// bytes: about half redundant.
fn structured(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng(seed);
    let words: Vec<[u8; 32]> =
        (0..256).map(|_| std::array::from_fn(|_| rng.next() as u8)).collect();
    let mut out = Vec::with_capacity(len + 64);
    while out.len() < len {
        out.extend_from_slice(&words[rng.next() as usize % words.len()][..20]);
        out.extend_from_slice(&[0; 12]);
        out.extend_from_slice(&words[rng.next() as usize % words.len()]);
        for _ in 0..rng.next() % 96 {
            out.push(rng.next() as u8);
        }
    }
    out.truncate(len);
    out
}

/// Level 2 of a `(K, 2K)` group of which a node holds `x` data chunks and `y =
/// K - x` parity chunks, under two commitments, step by step and whole.
///
/// One root over all `N` leaves (`seacast-lite.md` §3): recover the `y` missing
/// data chunks, recompute the `K - y` missing parity chunks, check the root
/// over `N` leaves. A root over the data leaves alone: recover the `y` missing
/// data chunks, check the root over `K` leaves. The parity check that
/// commitment leaves off the delivery path is not timed.
///
/// Only the chunks computed are hashed: the digests of the chunks held are
/// those level 1 proved.
fn reencode_sweep() {
    const K: usize = 32;
    let n = 2 * K;
    let source: Vec<Vec<u8>> = (0..K).map(|i| random(UNIT, 500 + i as u64)).collect();
    let coded = rs_parity(&source, K);
    let leaves: Vec<&[u8]> = source.iter().chain(&coded).map(Vec::as_slice).collect();
    let (tree_all, tree_data) = (build_merkle_layers(&leaves), build_merkle_layers(&leaves[..K]));
    let proved: Vec<[u8; 32]> = (0..n).map(|i| tree_all.leaf(i)).collect();
    // The root over the first `count` chunks, hashing those that are not held.
    let root_of = |data: &[u8], parity: &[u8], count: usize, have: &dyn Fn(usize) -> bool| {
        let (data, parity) = (data.as_chunks::<UNIT>().0, parity.as_chunks::<UNIT>().0);
        let computed: Vec<usize> = (0..count).filter(|&i| !have(i)).collect();
        let hashed = build_merkle_layers(
            &computed
                .iter()
                .map(|&i| if i < K { &data[i] } else { &parity[i - K] })
                .collect::<Vec<_>>(),
        );
        let mut digests = proved[..count].to_vec();
        for (at, &i) in computed.iter().enumerate() {
            digests[i] = hashed.leaf(at);
        }
        MerkleTree::from_leaf_hashes(&digests).root()
    };

    println!("level 2, K = {K}, N = {n}, 16 KiB chunks, X data and Y parity held, ms");
    println!("{:>26} | {:>29} | {:>19}", "", "root over N", "root over K");
    println!(
        "{:>4} {:>4} {:>8} {:>7} | {:>9} {:>9} {:>9} | {:>9} {:>9}",
        "X", "Y", "recover", "", "re-encode", "merkle", "whole", "merkle", "whole"
    );
    for y in [0, 1, 4, 8, 16, 24, 32] {
        // Held: data `y..K` and parity `K..K + y`.
        let have = |i: usize| (y..K + y).contains(&i);
        let (mut data, mut parity) = (vec![0u8; K * UNIT], vec![0u8; K * UNIT]);
        for i in (0..n).filter(|&i| have(i)) {
            let slot = if i < K { &mut data[i * UNIT..] } else { &mut parity[(i - K) * UNIT..] };
            slot[..UNIT].copy_from_slice(leaves[i]);
        }
        // What is filled in is the same every run; it is not reset.
        let recover = best(20, || {
            rs_complete_data_in_place(K, n, &mut data, &parity, have).expect("decodes");
        });
        let rows: Vec<usize> = (K..n).filter(|&r| !have(r)).collect();
        let reencode = best(20, || {
            let srcs: Vec<&[u8]> =
                data.as_chunks::<UNIT>().0.iter().map(|segment| &segment[..]).collect();
            let mut dsts: Vec<&mut [u8]> =
                (parity.as_chunks_mut::<UNIT>().0.iter_mut().enumerate())
                    .filter(|(r, _)| !have(K + r))
                    .map(|(_, segment)| &mut segment[..])
                    .collect();
            if !rows.is_empty() {
                rs_parity_rows(&srcs, n, &rows, &mut dsts);
            }
        });
        let merkle_all = best(20, || assert!(root_of(&data, &parity, n, &have) == tree_all.root()));
        let merkle_data =
            best(20, || assert!(root_of(&data, &parity, K, &have) == tree_data.root()));
        let whole_all = best(20, || {
            rs_complete_in_place(K, n, &mut data, &mut parity, have).expect("decodes");
            assert!(root_of(&data, &parity, n, &have) == tree_all.root());
        });
        let whole_data = best(20, || {
            rs_complete_data_in_place(K, n, &mut data, &parity, have).expect("decodes");
            assert!(root_of(&data, &parity, K, &have) == tree_data.root());
        });
        let ms = |seconds: f64| seconds * 1e3;
        println!(
            "{:>4} {y:>4} {:>8.3} {:>7} | {:>9.3} {:>9.3} {:>9.3} | {:>9.3} {:>9.3}",
            K - y,
            ms(recover),
            "",
            ms(reencode),
            ms(merkle_all),
            ms(whole_all),
            ms(merkle_data),
            ms(whole_data)
        );
    }
}

fn main() {
    let megabyte = random(1 << 20, 1);
    line("sha256, 1 MiB", best(20, || sha256(&megabyte)), megabyte.len());
    let (left, right) = (sha256(b"left"), sha256(b"right"));
    let nodes = 100_000;
    let per_node = best(5, || {
        let mut acc = left;
        for _ in 0..nodes {
            acc = node_hash(&acc, &right);
        }
        acc
    }) / nodes as f64;
    println!("{:<44} {:>10.1} ns", "node_hash", per_node * 1e9);

    let k = 128;
    let data: Vec<Vec<u8>> = (0..k).map(|i| random(UNIT, 100 + i as u64)).collect();
    let bytes = k * UNIT;
    // Twice, so the first line also shows what a cold generator matrix costs.
    let started = Instant::now();
    let parity = black_box(rs_parity(&data, k));
    line("rs_parity, K = 128, 16 KiB, first call", started.elapsed().as_secs_f64(), bytes);
    line("rs_parity, K = 128, 16 KiB", best(5, || rs_parity(&data, k)), bytes);
    let small: Vec<Vec<u8>> = data[..16].to_vec();
    line("rs_parity, K = 16, 16 KiB", best(20, || rs_parity(&small, 16)), 16 * UNIT);

    let all_parity: Vec<(u32, Vec<u8>)> =
        parity.iter().enumerate().map(|(i, p)| ((k + i) as u32, p.clone())).collect();
    let rebuilt = rs_reconstruct_data(k, 2 * k, UNIT, &all_parity).expect("decodes");
    assert_eq!(rebuilt, data);
    line(
        "rs_reconstruct_data, K = 128, all parity",
        best(5, || rs_reconstruct_data(k, 2 * k, UNIT, &all_parity)),
        bytes,
    );
    // One data chunk in eight is lost and replaced by a parity chunk.
    let mostly_data: Vec<(u32, Vec<u8>)> = (0..k)
        .map(|i| {
            if i % 8 == 0 {
                ((k + i) as u32, parity[i].clone())
            } else {
                (i as u32, data[i].clone())
            }
        })
        .collect();
    assert_eq!(rs_reconstruct_data(k, 2 * k, UNIT, &mostly_data).expect("decodes"), data);
    line(
        "rs_reconstruct_data, K = 128, 1 in 8 lost",
        best(5, || rs_reconstruct_data(k, 2 * k, UNIT, &mostly_data)),
        bytes,
    );

    // Past 256 chunks the code is over `GF(2^16)`.
    for k in [129usize, 256, 512] {
        let data: Vec<Vec<u8>> = (0..k).map(|i| random(UNIT, 900 + i as u64)).collect();
        let bytes = k * UNIT;
        let parity = rs_parity(&data, k);
        line(&format!("rs_parity, K = {k}, 16 KiB"), best(5, || rs_parity(&data, k)), bytes);
        let all_parity: Vec<(u32, Vec<u8>)> =
            parity.iter().enumerate().map(|(i, p)| ((k + i) as u32, p.clone())).collect();
        assert_eq!(rs_reconstruct_data(k, 2 * k, UNIT, &all_parity).expect("decodes"), data);
        line(
            &format!("rs_reconstruct_data, K = {k}, all parity"),
            best(5, || rs_reconstruct_data(k, 2 * k, UNIT, &all_parity)),
            bytes,
        );
        let mostly_data: Vec<(u32, Vec<u8>)> = (0..k)
            .map(|i| {
                if i % 8 == 0 {
                    ((k + i) as u32, parity[i].clone())
                } else {
                    (i as u32, data[i].clone())
                }
            })
            .collect();
        assert_eq!(rs_reconstruct_data(k, 2 * k, UNIT, &mostly_data).expect("decodes"), data);
        line(
            &format!("rs_reconstruct_data, K = {k}, 1 in 8 lost"),
            best(5, || rs_reconstruct_data(k, 2 * k, UNIT, &mostly_data)),
            bytes,
        );
    }

    let leaves: Vec<Vec<u8>> = data.iter().chain(&parity).cloned().collect();
    line(
        "merkle build, 256 leaves of 16 KiB",
        best(10, || build_merkle_layers(&leaves)),
        2 * bytes,
    );
    let few: Vec<Vec<u8>> = leaves[..65].to_vec();
    line("merkle build, 65 leaves of 16 KiB", best(10, || build_merkle_layers(&few)), 65 * UNIT);
    let tree = build_merkle_layers(&leaves);
    let (root, proof) = (tree.root(), merkle_proof_from_layers(&tree, 77));
    assert!(verify_merkle_proof(&root, &leaves[77], 77, 256, &proof));
    line(
        "verify_merkle_proof, 16 KiB chunk",
        best(200, || verify_merkle_proof(&root, &leaves[77], 77, 256, &proof)),
        UNIT,
    );

    let comp = SnappyBlockCompressor;
    for (name, body) in [("structured", structured(2 << 20, 7)), ("random", random(2 << 20, 9))] {
        let mib = body.len() >> 20;
        let compressed = comp.compress(&body);
        assert_eq!(comp.decompress(&compressed).as_deref(), Some(&body[..]));
        println!("snappy, {name}: {} -> {} bytes", body.len(), compressed.len());
        line(
            &format!("snappy compress, {mib} MiB {name}"),
            best(10, || comp.compress(&body)),
            body.len(),
        );
        line(
            &format!("snappy decompress, {mib} MiB {name}"),
            best(10, || comp.decompress(&compressed)),
            body.len(),
        );

        let mut pool = VecBufferPool;
        line(
            &format!("build_group, {mib} MiB {name}"),
            best(5, || build_group::<Vec<u8>, _, _>(&body, &mut pool, &comp)),
            body.len(),
        );
        let (descriptor, shards) = build_group::<Vec<u8>, _, _>(&body, &mut pool, &comp);
        // What a domain would put there: the codec only carries it.
        let context = [7u8; 40];
        let mut all = build_chunks(TypeId(0), &context, &descriptor, &shards, &mut pool);
        // As a node holds them: with the leaf digest level 1 leaves behind.
        for chunk in &mut all {
            chunk.memo = frame_leaf_hash(chunk.index, &chunk.frame, context.len()).expect("valid");
        }
        let chunk = |index: usize| all[index].clone();
        let valid = |chunk: &ChunkMsg<Vec<u8>>| {
            let (index, frame) = (chunk.index, &chunk.frame[..]);
            check_frame(chunk.group.type_id, &chunk.group, index, frame, context.len()) &&
                check_frame_proof(index, frame, context.len())
        };
        let k = descriptor.k() as usize;
        let first = chunk(3);
        assert!(valid(&first));
        line(
            &format!("level 1 of a chunk, {name}"),
            best(200, || valid(&first)),
            first.frame.len(),
        );
        // Every other chunk: half the data, half the parity.
        let half: Vec<_> = (0..2 * k).filter(|i| i % 2 == 1).map(chunk).collect();
        // One data chunk in eight replaced by parity.
        let most: Vec<_> = (0..k).map(|i| chunk(if i % 8 == 0 { k + i } else { i })).collect();
        for (case, available) in [("half lost", &half), ("1 in 8 lost", &most)] {
            let mut rebuilt = PreallocVec::with_capacity(2 * k);
            let decoded =
                decode_and_reencode(available, context.len(), &mut pool, &comp, &mut rebuilt);
            assert_eq!(decoded.as_deref(), Some(&body[..]));
            assert_eq!(rebuilt.len(), 2 * k);
            line(
                &format!("decode_and_reencode, {name}, {case}"),
                best(5, || {
                    decode_and_reencode(available, context.len(), &mut pool, &comp, &mut rebuilt)
                }),
                body.len(),
            );
        }

        // The same group kept in place: chunks in their slots, the missing ones
        // computed there, the payload decompressed straight out of the data
        // slots.
        let (n, size) = (2 * k, descriptor.segment_size as usize);
        let hashes: Vec<[u8; 32]> = all.iter().map(|chunk| chunk.memo).collect();
        for (case, have) in [
            ("nothing lost", (|_| true) as fn(usize) -> bool),
            ("half lost", |i| i % 2 == 1),
            ("1 in 8 lost", |i| i % 8 != 0),
        ] {
            let (mut data, mut parity) = (vec![0u8; k * size], vec![0u8; (n - k) * size]);
            for shard in shards.iter().filter(|shard| have(shard.index as usize)) {
                let i = shard.index as usize;
                let slot =
                    if i < k { &mut data[i * size..] } else { &mut parity[(i - k) * size..] };
                slot[..shard.data.len()].copy_from_slice(&shard.data);
            }
            let mut out = vec![0u8; body.len()];
            let seconds = best(5, || {
                // What `complete_in_place` fills in is the same every run; it is not reset.
                complete_in_place(&descriptor, &mut data, &mut parity, have, &hashes)
                    .expect("consistent");
                body_into(&descriptor, &data, &mut out).expect("well formed")
            });
            assert!(out == body);
            line(&format!("in place, {name}, {case}"), seconds, body.len());
        }
    }

    reencode_sweep();
}
