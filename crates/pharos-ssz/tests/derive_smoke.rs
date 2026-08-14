//! Smoke test for the SSZ derive macros using a fixed-only struct.
//!
//! Per S3 (Phase 2 constraint): this smoke test uses only fixed-size field types.
//! A variable-size smoke test (`VarTestStruct`) lands in Phase 3 Task 3.9
//! once `SszList` is available.
//!
//! # `FixedTestStruct`
//!
//! Matches the `FixedTestStruct` from the SSZ generic spec test containers:
//! ```python
//! class FixedTestStruct(Container):
//!     A: uint8
//!     B: uint64
//!     C: uint32
//! ```
//!
//! SSZ layout (all fixed):
//! - byte 0: A (u8)
//! - bytes 1..9: B (u64 LE)
//! - bytes 9..13: C (u32 LE)
//!
//! Total: 13 bytes.

use pharos_ssz::{Decode, Encode, TreeHash, TreeHashType, merkleize};
use pharos_utils::Hash256;

/// Fixed-only test container matching the SSZ generic spec `FixedTestStruct`.
#[derive(Encode, Decode, TreeHash, Debug, PartialEq, Eq, Clone)]
struct FixedTestStruct {
    a: u8,
    b: u64,
    c: u32,
}

#[test]
fn fixed_test_struct_is_fixed_size() {
    const { assert!(<FixedTestStruct as Encode>::IS_FIXED_SIZE) };
    assert_eq!(<FixedTestStruct as Encode>::ssz_fixed_len(), 13);
    const { assert!(<FixedTestStruct as Decode>::IS_FIXED_SIZE) };
    assert_eq!(<FixedTestStruct as Decode>::ssz_fixed_len(), 13);
}

#[test]
fn fixed_test_struct_encode_layout() {
    let s = FixedTestStruct {
        a: 0x01,
        b: 0x0203040506070809u64,
        c: 0x0a0b0c0du32,
    };
    let encoded = s.as_ssz_bytes();
    assert_eq!(encoded.len(), 13);
    // A at byte 0
    assert_eq!(encoded[0], 0x01);
    // B at bytes 1..9 in little-endian
    assert_eq!(&encoded[1..9], &0x0203040506070809u64.to_le_bytes());
    // C at bytes 9..13 in little-endian
    assert_eq!(&encoded[9..13], &0x0a0b0c0du32.to_le_bytes());
}

#[test]
fn fixed_test_struct_roundtrip() {
    let original = FixedTestStruct {
        a: 255,
        b: u64::MAX,
        c: 0,
    };
    let encoded = original.as_ssz_bytes();
    let decoded = FixedTestStruct::from_ssz_bytes(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn fixed_test_struct_tree_hash_type_is_container() {
    assert_eq!(
        <FixedTestStruct as TreeHash>::TREE_HASH_TYPE,
        TreeHashType::Container
    );
}

#[test]
fn fixed_test_struct_tree_hash_matches_manual_merkleize() {
    let s = FixedTestStruct {
        a: 0xab,
        b: 0xdeadbeef_12345678u64,
        c: 0xcafe_babe,
    };

    // Manually compute: merkleize([a.tree_hash_root(), b.tree_hash_root(), c.tree_hash_root()])
    let a_root = s.a.tree_hash_root();
    let b_root = s.b.tree_hash_root();
    let c_root = s.c.tree_hash_root();
    let manual_root = merkleize(&[a_root, b_root, c_root]);

    let derived_root = s.tree_hash_root();
    assert_eq!(derived_root, manual_root);
}

#[test]
fn fixed_test_struct_default_tree_hash() {
    let s = FixedTestStruct { a: 0, b: 0, c: 0 };
    let root = s.tree_hash_root();

    // a=0, b=0, c=0 all produce zero chunks.
    let zero_root: Hash256 = Hash256::default();
    let manual_root = merkleize(&[zero_root, zero_root, zero_root]);
    assert_eq!(root, manual_root);
}

#[test]
fn fixed_test_struct_decode_wrong_length_errors() {
    assert!(FixedTestStruct::from_ssz_bytes(&[0u8; 12]).is_err());
    assert!(FixedTestStruct::from_ssz_bytes(&[0u8; 14]).is_err());
}

#[test]
fn fixed_test_struct_tree_hash_differs_for_different_values() {
    let s1 = FixedTestStruct { a: 1, b: 0, c: 0 };
    let s2 = FixedTestStruct { a: 0, b: 0, c: 0 };
    assert_ne!(s1.tree_hash_root(), s2.tree_hash_root());
}
