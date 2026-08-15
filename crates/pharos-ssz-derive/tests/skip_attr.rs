//! Integration test for `#[ssz(skip)]` field attribute.
//!
//! Verifies that a skipped field is:
//!  - absent from the SSZ wire encoding (bytes equal to encoding the non-skipped fields only),
//!  - reset to `Default::default()` on decode.

use pharos_ssz::{Decode, Encode};
use pharos_utils::Hash256;
use std::sync::OnceLock;

#[derive(Encode, Decode, Debug)]
struct S {
    a: u64,
    #[ssz(skip)]
    b: OnceLock<Hash256>,
}

#[test]
fn skip_field_excluded_from_wire() {
    let s = S {
        a: 42u64,
        b: {
            let lock = OnceLock::new();
            // Populate the skipped field to confirm it does not appear in encoding.
            lock.get_or_init(Hash256::default);
            lock
        },
    };

    let encoded = s.as_ssz_bytes();

    // Wire bytes must equal encoding `a` alone.
    assert_eq!(
        encoded,
        42u64.as_ssz_bytes(),
        "skipped field must not appear in encoding"
    );
}

#[test]
fn skip_field_default_on_decode() {
    let a_val: u64 = 99;
    let bytes = a_val.as_ssz_bytes();

    let decoded = S::from_ssz_bytes(&bytes).expect("decode must succeed");

    assert_eq!(decoded.a, a_val);
    // The skipped field must be the default (empty OnceLock).
    assert!(
        decoded.b.get().is_none(),
        "skipped field must be Default::default() after decode"
    );
}

#[test]
fn skip_field_round_trip() {
    let s = S {
        a: 1234u64,
        b: OnceLock::new(),
    };
    let bytes = s.as_ssz_bytes();
    let decoded = S::from_ssz_bytes(&bytes).expect("round-trip decode must succeed");
    assert_eq!(decoded.a, s.a);
}
