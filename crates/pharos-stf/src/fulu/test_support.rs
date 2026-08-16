//! Shared test fixtures for the fulu STF unit tests.

use pharos_ssz::{SszList, SszVector};
use pharos_types::{
    BeaconSpec, eth_spec::MinimalBeaconSpec, fulu::MinimalBeaconState, phase0::Epoch,
    phase0::Validator,
};
use pharos_utils::{BLSPubkey, Bytes32, Gwei, Hash256};

/// Build a minimal-preset fulu `BeaconState` with 64 active, equal-balance
/// compounding validators and non-zero randao mixes so proposer election
/// terminates quickly and is deterministic from the seed. The default
/// `proposer_lookahead` (all-zero) is retained for window-shift tests.
pub(crate) fn build_test_fulu_minimal_state() -> MinimalBeaconState {
    // `default()` already gives slot 0; the all-zero `proposer_lookahead` is
    // retained for the window-shift tests.
    let mut state = MinimalBeaconState::default();

    let mut validators = Vec::new();
    for i in 0..64u64 {
        let mut pk = [0u8; 48];
        pk[..8].copy_from_slice(&i.to_le_bytes());
        let mut wc = [0u8; 32];
        wc[0] = 0x02; // compounding prefix.
        validators.push(Validator {
            pubkey: BLSPubkey::from_array(pk),
            withdrawal_credentials: Bytes32::from_array(wc),
            effective_balance: Gwei(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE_ELECTRA),
            activation_epoch: Epoch(0),
            exit_epoch: Epoch(u64::MAX),
            withdrawable_epoch: Epoch(u64::MAX),
            ..Validator::default()
        });
    }
    state.validators = SszList::from_vec(validators).expect("validators");
    state.balances = SszList::from_vec(vec![
        Gwei(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE_ELECTRA);
        64
    ])
    .expect("balances");

    let mixes: Vec<Hash256> = (0..MinimalBeaconSpec::EPOCHS_PER_HISTORICAL_VECTOR)
        .map(|j| {
            let mut b = [0u8; 32];
            b[0] = (j as u8).wrapping_add(1);
            Hash256::from_array(b)
        })
        .collect();
    state.randao_mixes = SszVector::from_vec(mixes).expect("randao_mixes");

    state
}
