//! Decode-then-single-hash cost: flat (Naive) vs tree backend.
//!
//! Models the decode-once-hash-once path (gossiped blocks/attestations, the
//! conformance writer). Quantifies what `decode -> Tree` would cost vs the
//! current `decode -> flat`.

use criterion::{Criterion, criterion_group, criterion_main};
use pharos_ssz::{SszList, TreeHash};
use pharos_utils::Hash256;

const N: u64 = 1 << 20; // 1,048,576

fn bench(c: &mut Criterion) {
    // Packed basic: List[u64].
    let u64s: Vec<u64> = (0..N).collect();
    c.bench_function("decode_hash/u64/flat", |b| {
        b.iter(|| {
            let l = SszList::<u64, N>::from_vec(u64s.clone()).unwrap();
            l.tree_hash_root()
        })
    });
    c.bench_function("decode_hash/u64/tree", |b| {
        b.iter(|| {
            let l = SszList::<u64, N>::from_vec_tree(u64s.clone()).unwrap();
            l.tree_hash_root()
        })
    });

    // Composite full-chunk: List[Hash256] (256k to keep it bounded).
    let roots: Vec<Hash256> = (0..(1u32 << 18))
        .map(|i| Hash256::from_array([i as u8; 32]))
        .collect();
    c.bench_function("decode_hash/root/flat", |b| {
        b.iter(|| {
            let l = SszList::<Hash256, { 1 << 20 }>::from_vec(roots.clone()).unwrap();
            l.tree_hash_root()
        })
    });
    c.bench_function("decode_hash/root/tree", |b| {
        b.iter(|| {
            let l = SszList::<Hash256, { 1 << 20 }>::from_vec_tree(roots.clone()).unwrap();
            l.tree_hash_root()
        })
    });
}

criterion_group!(benches, bench);
criterion_main!(benches);
