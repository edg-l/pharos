//! Mutable state access trait for the state transition function.
//!
//! `BeaconStateWrite` extends the read-only `BeaconStateView` with the
//! mutation methods required by operations and mutators.  A blanket impl
//! is provided for `pharos_types::phase0::BeaconState<…>`.
//!
//! This is separate from `genesis::BeaconStateMut` (which has
//! genesis-construction helpers that are not relevant to block processing).

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconStateView,
    phase0::{BeaconBlockHeader, Eth1Data, PendingAttestation, Validator},
};
use pharos_utils::{Gwei, Hash256};

use crate::error::StateTransitionError;

/// Mutation interface for beacon state fields accessed by operations.
///
/// `PendingAttestation<2048>` appears as a concrete parameter on
/// `push_{current,previous}_epoch_attestation` because trait method
/// signatures cannot return / accept types parameterised by
/// `E::MAX_VALIDATORS_PER_COMMITTEE` on stable Rust 1.85 (needs unstable
/// `generic_const_exprs`). Both `MainnetEthSpec` and `MinimalEthSpec`
/// bind `MAX_VALIDATORS_PER_COMMITTEE = 2048`, so the literal is correct
/// for every current preset. Revisit if a future preset diverges.
pub trait BeaconStateWrite: BeaconStateView {
    fn set_slot(&mut self, slot: pharos_types::phase0::Slot);
    fn set_latest_block_header(&mut self, header: BeaconBlockHeader);
    fn set_eth1_data(&mut self, data: Eth1Data);
    fn push_eth1_data_vote(&mut self, data: Eth1Data) -> Result<(), StateTransitionError>;
    fn increment_eth1_deposit_index(&mut self);
    fn set_validator(&mut self, idx: usize, v: Validator) -> Result<(), StateTransitionError>;
    fn push_validator(&mut self, v: Validator) -> Result<(), StateTransitionError>;
    fn set_balance(&mut self, idx: usize, val: Gwei);
    fn push_balance(&mut self, val: Gwei) -> Result<(), StateTransitionError>;
    fn set_slashing(&mut self, idx: usize, val: Gwei) -> Result<(), StateTransitionError>;
    fn set_randao_mix(&mut self, idx: usize, mix: Hash256) -> Result<(), StateTransitionError>;
    fn push_current_epoch_attestation(
        &mut self,
        att: PendingAttestation<2048>,
    ) -> Result<(), StateTransitionError>;
    fn push_previous_epoch_attestation(
        &mut self,
        att: PendingAttestation<2048>,
    ) -> Result<(), StateTransitionError>;
    fn eth1_deposit_index(&self) -> u64;
    fn eth1_data_votes_count(&self) -> usize;
    fn eth1_data_votes_count_matching(&self, data: &Eth1Data) -> usize;
}

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
> BeaconStateWrite
    for pharos_types::phase0::BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_PENDING_ATTESTATIONS,
        JUSTIFICATION_BITS_LENGTH,
        2048,
    >
where
    pharos_utils::Hash256: Default + Clone,
    pharos_types::phase0::Root: Default + Clone,
    Gwei: Default + Clone,
{
    fn set_slot(&mut self, slot: pharos_types::phase0::Slot) {
        self.slot = slot;
    }

    fn set_latest_block_header(&mut self, header: BeaconBlockHeader) {
        self.latest_block_header = header;
    }

    fn set_eth1_data(&mut self, data: Eth1Data) {
        self.eth1_data = data;
    }

    fn push_eth1_data_vote(&mut self, data: Eth1Data) -> Result<(), StateTransitionError> {
        self.eth1_data_votes = self
            .eth1_data_votes
            .with_push(data)
            .map_err(StateTransitionError::Ssz)?;
        Ok(())
    }

    fn increment_eth1_deposit_index(&mut self) {
        self.eth1_deposit_index += 1;
    }

    fn set_validator(&mut self, idx: usize, v: Validator) -> Result<(), StateTransitionError> {
        self.validators = self
            .validators
            .with_set(idx, v)
            .map_err(StateTransitionError::Ssz)?;
        Ok(())
    }

    fn push_validator(&mut self, v: Validator) -> Result<(), StateTransitionError> {
        self.validators = self
            .validators
            .with_push(v)
            .map_err(StateTransitionError::Ssz)?;
        Ok(())
    }

    fn set_balance(&mut self, idx: usize, val: Gwei) {
        self.balances = self
            .balances
            .with_set(idx, val)
            .expect("balance index in range");
    }

    fn push_balance(&mut self, val: Gwei) -> Result<(), StateTransitionError> {
        self.balances = self
            .balances
            .with_push(val)
            .map_err(StateTransitionError::Ssz)?;
        Ok(())
    }

    fn set_slashing(&mut self, idx: usize, val: Gwei) -> Result<(), StateTransitionError> {
        self.slashings = self
            .slashings
            .with_set(idx, val)
            .map_err(StateTransitionError::Ssz)?;
        Ok(())
    }

    fn set_randao_mix(&mut self, idx: usize, mix: Hash256) -> Result<(), StateTransitionError> {
        self.randao_mixes = self
            .randao_mixes
            .with_set(idx, mix)
            .map_err(StateTransitionError::Ssz)?;
        Ok(())
    }

    fn push_current_epoch_attestation(
        &mut self,
        att: PendingAttestation<2048>,
    ) -> Result<(), StateTransitionError> {
        self.current_epoch_attestations = self
            .current_epoch_attestations
            .with_push(att)
            .map_err(StateTransitionError::Ssz)?;
        Ok(())
    }

    fn push_previous_epoch_attestation(
        &mut self,
        att: PendingAttestation<2048>,
    ) -> Result<(), StateTransitionError> {
        self.previous_epoch_attestations = self
            .previous_epoch_attestations
            .with_push(att)
            .map_err(StateTransitionError::Ssz)?;
        Ok(())
    }

    fn eth1_deposit_index(&self) -> u64 {
        self.eth1_deposit_index
    }

    fn eth1_data_votes_count(&self) -> usize {
        self.eth1_data_votes.len()
    }

    fn eth1_data_votes_count_matching(&self, data: &Eth1Data) -> usize {
        self.eth1_data_votes.iter().filter(|v| *v == data).count()
    }
}
