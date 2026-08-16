//! Fuzz target: `process_block` on a fixed valid base state.
//!
//! Oracle: feeding arbitrary bytes as a phase0 block (with `verify_signatures =
//! false`) to `process_block` must never panic — only return
//! `StateTransitionError`.
//!
//! Strategy:
//! 1. Use a fixed genesis `MinimalBeaconState` (phase0) constructed once.
//! 2. Attempt to decode the fuzz input as a `MinimalBeaconBlock` (phase0
//!    inner block). If decode fails, we still pass a default block to exercise
//!    the STF with partially-valid inputs.
//! 3. Call `process_block::<MinimalEthSpec>` on a clone of the base state with
//!    the decoded (or default) block and `verify_signatures = false`.
//! 4. Discard the `Result`; assert no panic occurred.
#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use pharos_ssz::Decode;
use pharos_stf::phase0::process_block;
use pharos_types::{MinimalEthSpec, phase0::MinimalBeaconBlock, state::MinimalBeaconState};
use pharos_utils::Hash256;

// Fixed base state — constructed once, cloned per fuzz iteration.
static BASE_STATE: OnceLock<MinimalBeaconState> = OnceLock::new();

fn base_state() -> &'static MinimalBeaconState {
    BASE_STATE.get_or_init(|| {
        pharos_stf::initialize_beacon_state_from_eth1::<MinimalEthSpec>(Hash256::default(), 0, &[])
    })
}

fuzz_target!(|data: &[u8]| {
    // Attempt to decode the fuzz input as a phase0 MinimalBeaconBlock.
    // If decode fails, use a default block (all-zero fields) so that the STF
    // still runs on a structurally-plausible (though invalid) input.
    let block = MinimalBeaconBlock::from_ssz_bytes(data).unwrap_or_default();

    let mut state = base_state().clone();

    // Call process_block with signatures disabled — we are probing for panics
    // in the STF logic, not BLS verification.
    let _ = process_block::<MinimalEthSpec>(&mut state, &block, false);
});
