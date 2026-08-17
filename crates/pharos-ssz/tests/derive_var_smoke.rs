//! Smoke test for the SSZ derive macros using a variable-size struct.
//!
//! Per S3: the variable-size case requires `SszList`.
//!
//! # `VarTestStruct`
//!
//! Matches the `VarTestStruct` from the SSZ generic spec test containers:
//! ```python
//! class VarTestStruct(Container):
//!     A: uint16
//!     B: List[uint16, 1024]
//!     C: uint8
//! ```
//!
//! SSZ layout (A and C are fixed, B is variable):
//! - Fixed region:
//!   - bytes 0..2: A (u16 LE)
//!   - bytes 2..6: offset for B (u32 LE) = 7 (= 2 + 4 + 1)
//!   - bytes 6..7: C (u8)
//! - Variable region (starting at byte 7):
//!   - bytes 7..: B serialized (u16 LE elements packed)
//!
//! # Hash-tree-root
//!
//! `VarTestStruct` is a container so:
//! `hash_tree_root = merkleize([A.tree_hash_root(), B.tree_hash_root(), C.tree_hash_root()])`

use pharos_ssz::{
    Decode, Encode, SszList, TreeHash, TreeHashType, merkleize, merkleize_padded, mix_in_length,
    pack_bytes_to_chunks,
};
use pharos_utils::Hash256;

/// Variable-size test container matching the SSZ generic spec `VarTestStruct`.
#[derive(Encode, Decode, TreeHash, Debug, PartialEq, Eq, Clone)]
struct VarTestStruct {
    a: u16,
    b: SszList<u16, 1024>,
    c: u8,
}

// ── Layout / encoding tests ────────────────────────────────────────────────────

#[test]
fn var_test_struct_is_variable_size() {
    const { assert!(!<VarTestStruct as Encode>::IS_FIXED_SIZE) };
    assert_eq!(
        <VarTestStruct as Encode>::ssz_fixed_len(),
        pharos_ssz::BYTES_PER_LENGTH_OFFSET
    );
}

#[test]
fn var_test_struct_encode_empty_list() {
    let s = VarTestStruct {
        a: 0x0102u16,
        b: SszList::new(),
        c: 0x03,
    };
    let encoded = s.as_ssz_bytes();
    // A (2 bytes) + offset (4 bytes) + C (1 byte) + B body (0 bytes) = 7 bytes
    assert_eq!(encoded.len(), 7);
    // A at bytes 0..2
    assert_eq!(&encoded[0..2], &0x0102u16.to_le_bytes());
    // Offset for B = 7 (end of fixed region)
    assert_eq!(&encoded[2..6], &7u32.to_le_bytes());
    // C at byte 6
    assert_eq!(encoded[6], 0x03);
}

#[test]
fn var_test_struct_encode_nonempty_list() {
    let s = VarTestStruct {
        a: 0x0102u16,
        b: SszList::from_vec(vec![0x0304u16, 0x0506]).unwrap(),
        c: 0x07,
    };
    let encoded = s.as_ssz_bytes();
    // 2 (A) + 4 (offset) + 1 (C) + 4 (B body: 2*u16) = 11 bytes
    assert_eq!(encoded.len(), 11);
    // Offset points to byte 7
    assert_eq!(&encoded[2..6], &7u32.to_le_bytes());
    // C
    assert_eq!(encoded[6], 0x07);
    // B body at bytes 7..11
    assert_eq!(&encoded[7..9], &0x0304u16.to_le_bytes());
    assert_eq!(&encoded[9..11], &0x0506u16.to_le_bytes());
}

// ── Round-trip tests ───────────────────────────────────────────────────────────

#[test]
fn var_test_struct_roundtrip_empty_list() {
    let original = VarTestStruct {
        a: 42,
        b: SszList::new(),
        c: 7,
    };
    let encoded = original.as_ssz_bytes();
    let decoded = VarTestStruct::from_ssz_bytes(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn var_test_struct_roundtrip_nonempty_list() {
    let original = VarTestStruct {
        a: 0xDEAD,
        b: SszList::from_vec(vec![1u16, 2, 3, 4, 5]).unwrap(),
        c: 0xFF,
    };
    let encoded = original.as_ssz_bytes();
    let decoded = VarTestStruct::from_ssz_bytes(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn var_test_struct_roundtrip_max_list() {
    let items: Vec<u16> = (0u16..100).collect();
    let original = VarTestStruct {
        a: 0xBEEF,
        b: SszList::from_vec(items).unwrap(),
        c: 0x42,
    };
    let encoded = original.as_ssz_bytes();
    let decoded = VarTestStruct::from_ssz_bytes(&encoded).unwrap();
    assert_eq!(original, decoded);
}

// ── Tree-hash tests ────────────────────────────────────────────────────────────

#[test]
fn var_test_struct_tree_hash_type_is_container() {
    assert_eq!(
        <VarTestStruct as TreeHash>::TREE_HASH_TYPE,
        TreeHashType::Container
    );
}

/// Assert that the derived `tree_hash_root` for `VarTestStruct` equals an
/// independently-computed `merkleize([A.root, B.root, C.root])`.
///
/// This is the same pattern used in `derive_smoke.rs` for `FixedTestStruct`.
#[test]
fn var_test_struct_tree_hash_matches_manual_merkleize() {
    let s = VarTestStruct {
        a: 0x1234u16,
        b: SszList::from_vec(vec![1u16, 2, 3]).unwrap(),
        c: 0xAB,
    };

    let a_root = s.a.tree_hash_root();
    let b_root = s.b.tree_hash_root();
    let c_root = s.c.tree_hash_root();
    let manual_root = merkleize(&[a_root, b_root, c_root]);

    assert_eq!(s.tree_hash_root(), manual_root);
}

#[test]
fn var_test_struct_tree_hash_empty_list_matches_manual() {
    let s = VarTestStruct {
        a: 0,
        b: SszList::new(),
        c: 0,
    };
    let a_root = s.a.tree_hash_root();
    let b_root = s.b.tree_hash_root();
    let c_root = s.c.tree_hash_root();
    let manual_root = merkleize(&[a_root, b_root, c_root]);
    assert_eq!(s.tree_hash_root(), manual_root);
}

/// Verify `B.tree_hash_root()` manually for a small list to ensure the derived
/// `merkleize_padded` + `mix_in_length` is correct.
#[test]
fn var_test_struct_b_list_tree_hash_manual() {
    let b = SszList::<u16, 1024>::from_vec(vec![1u16, 2, 3]).unwrap();
    let root = b.tree_hash_root();

    // Manual: pack u16 packed encodings, compute chunks, merkleize_padded(limit), mix_in_length.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&2u16.to_le_bytes());
    bytes.extend_from_slice(&3u16.to_le_bytes());
    let chunks = pack_bytes_to_chunks(&bytes);
    // limit = ceil(1024 * 2 / 32) = 64
    let limit = (1024u64 * 2).div_ceil(32) as usize;
    let manual_root = merkleize_padded(&chunks, limit);
    let expected = mix_in_length(manual_root, 3);
    assert_eq!(root, expected);
}

#[test]
fn var_test_struct_decode_wrong_offset_errors() {
    // Construct a byte slice with an invalid offset (points into fixed region).
    let mut bytes = vec![0u8; 7];
    // A = 0 (bytes 0..2)
    // offset = 5 (points into fixed region, not >= 7)
    bytes[2..6].copy_from_slice(&5u32.to_le_bytes());
    // C = 0 (byte 6)
    assert!(VarTestStruct::from_ssz_bytes(&bytes).is_err());
}

// ── Composite list: VarTestStruct as element type ─────────────────────────────

/// A container that holds a list of `VarTestStruct` elements to exercise the
/// composite-element path of `SszList` encoding/decoding and tree-hash.
#[derive(Encode, Decode, TreeHash, Debug, PartialEq, Eq, Clone)]
struct NestedContainer {
    items: SszList<VarTestStruct, 16>,
    count: u32,
}

#[test]
fn nested_container_roundtrip() {
    let items = vec![
        VarTestStruct {
            a: 1,
            b: SszList::from_vec(vec![10u16, 20]).unwrap(),
            c: 100,
        },
        VarTestStruct {
            a: 2,
            b: SszList::new(),
            c: 200,
        },
    ];
    let original = NestedContainer {
        items: SszList::from_vec(items).unwrap(),
        count: 2,
    };
    let encoded = original.as_ssz_bytes();
    let decoded = NestedContainer::from_ssz_bytes(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn nested_container_tree_hash_composite_list() {
    let items = vec![
        VarTestStruct {
            a: 1,
            b: SszList::from_vec(vec![10u16]).unwrap(),
            c: 10,
        },
        VarTestStruct {
            a: 2,
            b: SszList::new(),
            c: 20,
        },
    ];
    let container = NestedContainer {
        items: SszList::from_vec(items.clone()).unwrap(),
        count: 2,
    };

    let derived_root = container.tree_hash_root();

    // Manual: compute per-element roots, merkleize_padded(limit=16), mix_in_length, then
    // container root = merkleize([items_root, count_root]).
    let elem_roots: Vec<Hash256> = items.iter().map(|e| e.tree_hash_root()).collect();
    let padded_root = merkleize_padded(&elem_roots, 16);
    let items_root = mix_in_length(padded_root, 2);
    let count_root = 2u32.tree_hash_root();
    let manual_root = merkleize(&[items_root, count_root]);

    assert_eq!(derived_root, manual_root);
}
