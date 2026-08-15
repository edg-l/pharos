//! Integration test for `#[derive(TreeHash)]` with ≥4 fields (rayon::join path).
//!
//! Defines a 25-field struct mirroring BeaconState's field count, derives
//! `TreeHash`, and asserts the result is byte-identical to the serial
//! `merkleize(&[f1.tree_hash_root(), ..., f25.tree_hash_root()])` reference.
//!
//! This test does NOT assert parallelism (rayon's scheduler is transparent);
//! it asserts semantic identity between the rayon-join emission (Phase 4) and
//! the serial emission that preceded it.

use pharos_ssz::{TreeHash, merkleize};
use pharos_utils::Hash256;

/// 25-field struct; each field is `u64` for deterministic tree-hash roots.
#[derive(TreeHash)]
struct TwentyFive {
    f00: u64,
    f01: u64,
    f02: u64,
    f03: u64,
    f04: u64,
    f05: u64,
    f06: u64,
    f07: u64,
    f08: u64,
    f09: u64,
    f10: u64,
    f11: u64,
    f12: u64,
    f13: u64,
    f14: u64,
    f15: u64,
    f16: u64,
    f17: u64,
    f18: u64,
    f19: u64,
    f20: u64,
    f21: u64,
    f22: u64,
    f23: u64,
    f24: u64,
}

/// Build the serial reference root: compute each field root independently and
/// feed them into `merkleize` exactly as the pre-Phase-4 serial emission did.
fn serial_reference_root(s: &TwentyFive) -> Hash256 {
    let roots: &[Hash256] = &[
        s.f00.tree_hash_root(),
        s.f01.tree_hash_root(),
        s.f02.tree_hash_root(),
        s.f03.tree_hash_root(),
        s.f04.tree_hash_root(),
        s.f05.tree_hash_root(),
        s.f06.tree_hash_root(),
        s.f07.tree_hash_root(),
        s.f08.tree_hash_root(),
        s.f09.tree_hash_root(),
        s.f10.tree_hash_root(),
        s.f11.tree_hash_root(),
        s.f12.tree_hash_root(),
        s.f13.tree_hash_root(),
        s.f14.tree_hash_root(),
        s.f15.tree_hash_root(),
        s.f16.tree_hash_root(),
        s.f17.tree_hash_root(),
        s.f18.tree_hash_root(),
        s.f19.tree_hash_root(),
        s.f20.tree_hash_root(),
        s.f21.tree_hash_root(),
        s.f22.tree_hash_root(),
        s.f23.tree_hash_root(),
        s.f24.tree_hash_root(),
    ];
    merkleize(roots)
}

#[test]
fn derive_tree_hash_25_fields_matches_serial_reference() {
    let s = TwentyFive {
        f00: 0,
        f01: 1,
        f02: 2,
        f03: 3,
        f04: 4,
        f05: 5,
        f06: 6,
        f07: 7,
        f08: 8,
        f09: 9,
        f10: 10,
        f11: 11,
        f12: 12,
        f13: 13,
        f14: 14,
        f15: 15,
        f16: 16,
        f17: 17,
        f18: 18,
        f19: 19,
        f20: 20,
        f21: 21,
        f22: 22,
        f23: 23,
        f24: 24,
    };

    let derived = s.tree_hash_root();
    let reference = serial_reference_root(&s);

    assert_eq!(
        derived, reference,
        "derive(TreeHash) rayon-join emission must be byte-identical to serial merkleize reference"
    );
}

/// Confirm the threshold fires: a 4-field struct also takes the parallel path,
/// and its root still matches the serial reference.
#[derive(TreeHash)]
struct FourFields {
    a: u64,
    b: u64,
    c: u64,
    d: u64,
}

#[test]
fn derive_tree_hash_4_fields_matches_serial_reference() {
    let s = FourFields {
        a: 0xdead,
        b: 0xbeef,
        c: 0xcafe,
        d: 0xbabe,
    };

    let derived = s.tree_hash_root();
    let reference = {
        let roots: &[Hash256] = &[
            s.a.tree_hash_root(),
            s.b.tree_hash_root(),
            s.c.tree_hash_root(),
            s.d.tree_hash_root(),
        ];
        merkleize(roots)
    };

    assert_eq!(
        derived, reference,
        "4-field struct must match serial reference (threshold boundary)"
    );
}

/// Confirm the serial path is still used for structs below the threshold.
#[derive(TreeHash)]
struct ThreeFields {
    x: u64,
    y: u64,
    z: u64,
}

#[test]
fn derive_tree_hash_3_fields_matches_serial_reference() {
    let s = ThreeFields {
        x: 111,
        y: 222,
        z: 333,
    };

    let derived = s.tree_hash_root();
    let reference = {
        let roots: &[Hash256] = &[
            s.x.tree_hash_root(),
            s.y.tree_hash_root(),
            s.z.tree_hash_root(),
        ];
        merkleize(roots)
    };

    assert_eq!(
        derived, reference,
        "3-field struct (below threshold) must match serial reference"
    );
}
