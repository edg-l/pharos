//! `process_block` and `process_operations` per
//! `specs/phase0/beacon-chain.md:1876-1884` and `1938-1960`.

use pharos_ssz::TreeHash;
use pharos_types::{
    BeaconSpec, BeaconStateView,
    phase0::{Attestation, AttesterSlashing, Deposit},
    views::{BeaconBlockBodyView, BeaconBlockView},
};

use crate::error::StateTransitionError;
use crate::phase0::{
    operations::{
        process_attestation, process_attester_slashing, process_block_header, process_deposit,
        process_eth1_data, process_proposer_slashing, process_randao, process_voluntary_exit,
    },
    state_write::BeaconStateWrite,
};

/// `process_block` per `specs/phase0/beacon-chain.md:1876-1884`.
///
/// Accepts the concrete phase0 block (not the fork-enum). The caller
/// (`state_transition`) unwraps the fork-enum before calling this.
pub fn process_block<E: BeaconSpec>(
    state: &mut E::BeaconState,
    block: &E::Phase0BeaconBlock,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody>,
    E::Phase0BeaconBlockBody: TreeHash
        + BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
{
    let body: &E::Phase0BeaconBlockBody = block.body();
    process_block_header::<E>(state, block)?;
    process_randao::<E>(state, body, verify_signatures)?;
    process_eth1_data::<E>(state, body)?;
    process_operations::<E>(state, body, verify_signatures)?;
    Ok(())
}

/// `process_operations` per `specs/phase0/beacon-chain.md:1938-1960`.
///
/// Validates the deposit count pre-condition then applies all five operation
/// types in the spec-mandated order, threading `verify_signatures` into each
/// processor that performs BLS verification.
fn process_operations<E: BeaconSpec>(
    state: &mut E::BeaconState,
    body: &E::Phase0BeaconBlockBody,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = AttesterSlashing<2048>,
            Deposit = Deposit<33>,
        >,
{
    // Verify outstanding deposits are processed up to the maximum.
    // Spec: `assert len(body.deposits) == min(MAX_DEPOSITS, state.eth1_data.deposit_count -
    //        state.eth1_deposit_index)`
    let eth1_data = state.eth1_data();
    let expected_deposits = E::MAX_DEPOSITS.min(
        eth1_data
            .deposit_count
            .saturating_sub(state.eth1_deposit_index()),
    );
    if body.deposits().len() as u64 != expected_deposits {
        return Err(StateTransitionError::InvalidDepositCount);
    }

    for slashing in body.proposer_slashings() {
        process_proposer_slashing::<E>(state, slashing, verify_signatures)?;
    }
    for slashing in body.attester_slashings() {
        process_attester_slashing::<E>(state, slashing, verify_signatures)?;
    }
    for attestation in body.attestations() {
        process_attestation::<E>(state, attestation, verify_signatures)?;
    }
    for deposit in body.deposits() {
        process_deposit::<E>(state, deposit, verify_signatures)?;
    }
    for exit in body.voluntary_exits() {
        process_voluntary_exit::<E>(state, exit, verify_signatures)?;
    }

    Ok(())
}
