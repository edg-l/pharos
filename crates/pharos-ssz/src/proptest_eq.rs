//! Property tests for `SszList` and `SszVector` equivalence.
//!
//! Validates that the `SszList<u64, 1024>` persistent API produces results
//! consistent with a reference `Vec<u64>` across random sequences of push and
//! set operations. Also verifies that `tree_hash_root` is consistent with a
//! fresh computation from the underlying data.
//!
//! Run via `cargo test -p pharos-ssz proptest_eq`. The whole module is gated
//! on `#[cfg(test)]` since `proptest` is a dev-only dependency. When the
//! tree-backed `SszSequence` impl lands, this harness can be lifted to a
//! shared crate; for now it lives next to the naive impl it covers.

#![cfg(test)]

use crate::{
    encode::Encode,
    sequence::{SszList, SszSequence, SszVector},
    tree_hash::{TreeHash, merkleize_padded, mix_in_length, pack_bytes_to_chunks},
};
use proptest::prelude::*;

/// Maximum capacity for the list under test.
const N: u64 = 1024;
/// Proptest case count.
const CASES: u32 = 256;

/// Operations that can be applied to an `SszList<u64, N>` and a shadow `Vec<u64>`.
#[derive(Debug, Clone)]
enum Op {
    Push(u64),
    Set(usize, u64),
    Get(usize),
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    /// Apply a sequence of push/set/get operations to both `SszList<u64, 1024>`
    /// and a shadow `Vec<u64>`, asserting they agree at every step.
    #[test]
    fn ssz_list_ops_agree_with_vec_reference(
        ops in prop::collection::vec(
            prop_oneof![
                (0u64..10000u64).prop_map(Op::Push),
                (0usize..N as usize, 0u64..10000u64).prop_map(|(i, v)| Op::Set(i, v)),
                (0usize..N as usize).prop_map(Op::Get),
            ],
            1..50,
        )
    ) {
        let mut list = SszList::<u64, N>::new();
        let mut shadow: Vec<u64> = Vec::new();

        for op in &ops {
            match op {
                Op::Push(v) => {
                    if shadow.len() < N as usize {
                        let new_list = list.with_push(*v).unwrap();
                        shadow.push(*v);
                        list = new_list;
                    }
                    // If at limit: skip rather than error (limit behaviour
                    // tested separately)
                }
                Op::Set(i, v) => {
                    if *i < shadow.len() {
                        let new_list = list.with_set(*i, *v).unwrap();
                        shadow[*i] = *v;
                        list = new_list;
                    }
                }
                Op::Get(i) => {
                    let list_val = list.get(*i);
                    let shadow_val = shadow.get(*i);
                    prop_assert_eq!(list_val, shadow_val);
                }
            }
        }

        // After all ops: verify full equality.
        prop_assert_eq!(list.len(), shadow.len());
        for (i, v) in shadow.iter().enumerate() {
            prop_assert_eq!(list.get(i), Some(v));
        }

        // Verify tree_hash_root agrees with a fresh computation from the shadow vec.
        let list_root = list.tree_hash_root();
        let shadow_root = {
            let mut bytes: Vec<u8> = Vec::new();
            for &v in &shadow {
                bytes.extend_from_slice(&v.tree_hash_packed_encoding());
            }
            let chunks = pack_bytes_to_chunks(&bytes);
            let elem_size = <u64 as Encode>::ssz_fixed_len() as u64;
            let limit = (N * elem_size).div_ceil(32) as usize;
            let root = merkleize_padded(&chunks, limit);
            mix_in_length(root, shadow.len() as u64)
        };
        prop_assert_eq!(list_root, shadow_root);
    }

    /// Verify that `SszVector<u64, 4>` round-trips correctly under proptest.
    #[test]
    fn ssz_vector_roundtrip(
        a in 0u64..u64::MAX,
        b in 0u64..u64::MAX,
        c in 0u64..u64::MAX,
        d in 0u64..u64::MAX,
    ) {
        use crate::decode::Decode;

        let v = SszVector::<u64, 4>::from_vec(vec![a, b, c, d]).unwrap();
        let encoded = v.as_ssz_bytes();
        let decoded = SszVector::<u64, 4>::from_ssz_bytes(&encoded).unwrap();
        prop_assert_eq!(v, decoded);
    }
}
