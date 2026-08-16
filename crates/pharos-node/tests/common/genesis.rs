//! Cached minimal-preset genesis state for integration tests.
//!
//! Uses `OnceLock` so the (somewhat expensive) genesis construction runs only
//! once per test binary invocation regardless of how many tests call
//! `minimal_genesis()`.
//!
//! The genesis state is deterministic: `eth1_block_hash = Hash256::zero()`,
//! `eth1_timestamp = 0`, `deposits = []`. This matches the M1 conformance
//! harness pattern and avoids both fixture maintenance debt and the
//! production binary's `--genesis-state-path` flow (which is exercised
//! separately in a future `tests/binary_smoke.rs`).

use std::sync::OnceLock;

use pharos_types::state::MinimalBeaconState;
use pharos_utils::Hash256;

static GENESIS: OnceLock<MinimalBeaconState> = OnceLock::new();

/// Returns a reference to the cached minimal-preset genesis `BeaconState`.
///
/// On first call this constructs the state via
/// `initialize_beacon_state_from_eth1` with a zero Eth1 block hash, zero
/// timestamp, and an empty deposit list. Subsequent calls return the cached
/// reference without re-computing.
///
/// Spec cite: `specs/phase0/beacon-chain.md:1300-1337`.
pub fn minimal_genesis() -> &'static MinimalBeaconState {
    GENESIS.get_or_init(|| {
        pharos_stf::initialize_beacon_state_from_eth1::<pharos_types::MinimalBeaconSpec>(
            Hash256::default(),
            0,
            &[],
        )
    })
}
