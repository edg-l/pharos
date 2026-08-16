//! Fuzz target: SSZ decode of key beacon-chain containers.
//!
//! Oracle: `from_ssz_bytes` on arbitrary input must never panic — only `Err`.
//!
//! Containers fuzzed (Minimal preset for smaller fixed sizes):
//! - `MinimalSignedBeaconBlock` (fork-enum, covers phase0 through electra)
//! - `MinimalBeaconState`       (fork-enum)
//! - `Attestation<2048>`        (phase0, fixed MAX_VALIDATORS_PER_COMMITTEE)
//! - `BlobSidecar`              (deneb; no generic const)
#![no_main]

use libfuzzer_sys::fuzz_target;
use pharos_ssz::Decode;
use pharos_types::{
    deneb::BlobSidecar,
    phase0::Attestation,
    state::{MinimalBeaconState, MinimalSignedBeaconBlock},
};

fuzz_target!(|data: &[u8]| {
    // Use the first byte to select which type to decode, rest as SSZ input.
    if data.is_empty() {
        return;
    }
    let (selector, payload) = data.split_first().unwrap();
    match selector % 4 {
        0 => {
            // Fork-enum SignedBeaconBlock (minimal preset: phase0 .. electra).
            let _ = MinimalSignedBeaconBlock::from_ssz_bytes(payload);
        }
        1 => {
            // Fork-enum BeaconState (minimal preset: phase0 .. electra).
            let _ = MinimalBeaconState::from_ssz_bytes(payload);
        }
        2 => {
            // Phase0 Attestation with max-committee-size used in the STF.
            let _ = Attestation::<2048>::from_ssz_bytes(payload);
        }
        _ => {
            // BlobSidecar (deneb, no generic).
            let _ = BlobSidecar::from_ssz_bytes(payload);
        }
    }
});
