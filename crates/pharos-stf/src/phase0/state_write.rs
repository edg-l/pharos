//! Mutable state access trait for the state transition function.
//!
//! `BeaconStateWrite` extends the read-only `BeaconStateView` with the
//! mutation methods required by operations and mutators.  A blanket impl
//! is provided for `pharos_types::phase0::BeaconState<…>`.
//!
//! This is separate from `genesis::BeaconStateMut` (which has
//! genesis-construction helpers that are not relevant to block processing).

use pharos_ssz::{Bitvector, SszSequence};
use pharos_types::{
    BeaconStateView,
    phase0::{BeaconBlockHeader, Checkpoint, Eth1Data, PendingAttestation, Validator},
    state::BeaconState as ForkBeaconState,
};
use pharos_utils::{Gwei, Hash256};

use crate::error::StateTransitionError;

/// Mutation interface for beacon state fields accessed by operations.
///
/// `PendingAttestation<2048>` appears as a concrete parameter on
/// `push_{current,previous}_epoch_attestation` because trait method
/// signatures cannot return / accept types parameterised by
/// `E::MAX_VALIDATORS_PER_COMMITTEE` on stable Rust 1.85 (needs unstable
/// `generic_const_exprs`). Both `MainnetBeaconSpec` and `MinimalBeaconSpec`
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
    fn set_balance(&mut self, idx: usize, val: Gwei) -> Result<(), StateTransitionError>;
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

    // ── Epoch processing mutations ────────────────────────────────────────────

    /// Replace the justification bits with `bits`.
    fn set_justification_bits(&mut self, bits: Bitvector<4>);
    fn set_previous_justified_checkpoint(&mut self, cp: Checkpoint);
    fn set_current_justified_checkpoint(&mut self, cp: Checkpoint);
    fn set_finalized_checkpoint(&mut self, cp: Checkpoint);
    fn push_historical_root(
        &mut self,
        root: pharos_types::phase0::Root,
    ) -> Result<(), StateTransitionError>;
    /// Replace `previous_epoch_attestations` with the given list.
    fn set_previous_epoch_attestations(
        &mut self,
        atts: Vec<PendingAttestation<2048>>,
    ) -> Result<(), StateTransitionError>;
    /// Clear `current_epoch_attestations`.
    fn clear_current_epoch_attestations(&mut self);
    /// Clear `eth1_data_votes`.
    fn clear_eth1_data_votes(&mut self);
    /// Read `previous_epoch_attestations` as an owned vec.
    fn previous_epoch_attestations(&self) -> Vec<PendingAttestation<2048>>;
    /// Read `current_epoch_attestations` as an owned vec.
    fn current_epoch_attestations(&self) -> Vec<PendingAttestation<2048>>;
    /// Read `justification_bits` as a concrete `Bitvector<4>` (both presets use 4 bits).
    fn justification_bits(&self) -> Bitvector<4>;
    /// Read `historical_roots` length.
    fn historical_roots_len(&self) -> usize;

    // ── Slot processing mutations ─────────────────────────────────────────────

    /// Write `state_roots[idx] = root`.
    ///
    /// `idx` is always `state.slot % SLOTS_PER_HISTORICAL_ROOT`; the caller
    /// computes the index before calling so this method stays index-typed.
    fn set_state_root(
        &mut self,
        idx: usize,
        root: pharos_types::phase0::Root,
    ) -> Result<(), StateTransitionError>;

    /// Write `block_roots[idx] = root`.
    ///
    /// `idx` is always `state.slot % SLOTS_PER_HISTORICAL_ROOT`.
    fn set_block_root(
        &mut self,
        idx: usize,
        root: pharos_types::phase0::Root,
    ) -> Result<(), StateTransitionError>;
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

    fn set_validator(&mut self, idx: usize, mut v: Validator) -> Result<(), StateTransitionError> {
        // Any direct field mutations on a cloned validator leave `cached_root`
        // stale.  Reset it so the leaf node recomputes on the next hash walk.
        v.invalidate_cache();
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

    fn set_balance(&mut self, idx: usize, val: Gwei) -> Result<(), StateTransitionError> {
        self.balances = self
            .balances
            .with_set(idx, val)
            .map_err(|_| StateTransitionError::IndexOutOfRange(idx))?;
        Ok(())
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

    fn set_justification_bits(&mut self, bits: Bitvector<4>) {
        // JUSTIFICATION_BITS_LENGTH = 4 for both mainnet and minimal.
        // The const-generic on the field is JUSTIFICATION_BITS_LENGTH, which
        // equals 4 in every current preset, so the transmute below is safe.
        // We use a raw copy instead to avoid any potential alignment issues.
        // Since both types are the same concrete layout (4 bits, 1 byte),
        // just re-decode by rebuilding the bitvector bit-by-bit.
        for i in 0..4usize {
            let val = bits.get(i).unwrap_or(false);
            self.justification_bits.set(i, val);
        }
    }

    fn set_previous_justified_checkpoint(&mut self, cp: Checkpoint) {
        self.previous_justified_checkpoint = cp;
    }

    fn set_current_justified_checkpoint(&mut self, cp: Checkpoint) {
        self.current_justified_checkpoint = cp;
    }

    fn set_finalized_checkpoint(&mut self, cp: Checkpoint) {
        self.finalized_checkpoint = cp;
    }

    fn push_historical_root(
        &mut self,
        root: pharos_types::phase0::Root,
    ) -> Result<(), StateTransitionError> {
        self.historical_roots = self
            .historical_roots
            .with_push(root)
            .map_err(StateTransitionError::Ssz)?;
        Ok(())
    }

    fn set_previous_epoch_attestations(
        &mut self,
        atts: Vec<PendingAttestation<2048>>,
    ) -> Result<(), StateTransitionError> {
        self.previous_epoch_attestations = pharos_ssz::SszList::from_vec(atts)
            .map_err(StateTransitionError::Ssz)?
            .into_tree()
            .map_err(StateTransitionError::Ssz)?;
        Ok(())
    }

    fn clear_current_epoch_attestations(&mut self) {
        self.current_epoch_attestations = pharos_ssz::SszList::empty_tree();
    }

    fn clear_eth1_data_votes(&mut self) {
        self.eth1_data_votes = pharos_ssz::SszList::default();
    }

    fn previous_epoch_attestations(&self) -> Vec<PendingAttestation<2048>> {
        self.previous_epoch_attestations.iter().cloned().collect()
    }

    fn current_epoch_attestations(&self) -> Vec<PendingAttestation<2048>> {
        self.current_epoch_attestations.iter().cloned().collect()
    }

    // JUSTIFICATION_BITS_LENGTH = 4 in both mainnet and minimal presets.
    // The impl returns a clone re-built as Bitvector<4> to avoid the
    // type-level mismatch between the trait's concrete `4` and the
    // generic const param `JUSTIFICATION_BITS_LENGTH`.
    fn justification_bits(&self) -> Bitvector<4> {
        let mut out = Bitvector::<4>::new();
        for i in 0..4usize {
            out.set(i, self.justification_bits.get(i).unwrap_or(false));
        }
        out
    }

    fn historical_roots_len(&self) -> usize {
        self.historical_roots.len()
    }

    fn set_state_root(
        &mut self,
        idx: usize,
        root: pharos_types::phase0::Root,
    ) -> Result<(), StateTransitionError> {
        self.state_roots = self
            .state_roots
            .with_set(idx, root)
            .map_err(StateTransitionError::Ssz)?;
        Ok(())
    }

    fn set_block_root(
        &mut self,
        idx: usize,
        root: pharos_types::phase0::Root,
    ) -> Result<(), StateTransitionError> {
        self.block_roots = self
            .block_roots
            .with_set(idx, root)
            .map_err(StateTransitionError::Ssz)?;
        Ok(())
    }
}

// ── BeaconStateWrite for fork-enum BeaconState ────────────────────────────────
//
// The fork-enum `pharos_types::BeaconState` must satisfy
// `BeaconStateWrite` so that phase0 STF code (which is generic over
// `E::BeaconState: BeaconStateWrite`) compiles without changes.
//
// Delegation: all methods delegate to the `Phase0` inner state.
// The `Altair` variant is not reached by phase0 STF code; `unreachable!()`
// guards these arms per the project conventions (CLAUDE.md).

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const MAX_PENDING_ATTESTATIONS: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    const LOOKAHEAD_WINDOW: u64,
> BeaconStateWrite
    for ForkBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        MAX_PENDING_ATTESTATIONS,
        JUSTIFICATION_BITS_LENGTH,
        2048, // MAX_VALIDATORS_PER_COMMITTEE
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
        LOOKAHEAD_WINDOW,
    >
where
    pharos_utils::Hash256: Default + Clone,
    pharos_types::phase0::Root: Default + Clone,
    Gwei: Default + Clone,
{
    fn set_slot(&mut self, slot: pharos_types::phase0::Slot) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_slot(slot),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_latest_block_header(&mut self, header: BeaconBlockHeader) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_latest_block_header(header),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_eth1_data(&mut self, data: Eth1Data) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_eth1_data(data),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn push_eth1_data_vote(&mut self, data: Eth1Data) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.push_eth1_data_vote(data),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn increment_eth1_deposit_index(&mut self) {
        match self {
            ForkBeaconState::Phase0(s) => s.increment_eth1_deposit_index(),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_validator(&mut self, idx: usize, v: Validator) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.set_validator(idx, v),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn push_validator(&mut self, v: Validator) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.push_validator(v),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_balance(&mut self, idx: usize, val: Gwei) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.set_balance(idx, val),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn push_balance(&mut self, val: Gwei) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.push_balance(val),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_slashing(&mut self, idx: usize, val: Gwei) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.set_slashing(idx, val),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_randao_mix(&mut self, idx: usize, mix: Hash256) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.set_randao_mix(idx, mix),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn push_current_epoch_attestation(
        &mut self,
        att: PendingAttestation<2048>,
    ) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.push_current_epoch_attestation(att),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn push_previous_epoch_attestation(
        &mut self,
        att: PendingAttestation<2048>,
    ) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.push_previous_epoch_attestation(att),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn eth1_deposit_index(&self) -> u64 {
        match self {
            ForkBeaconState::Phase0(s) => s.eth1_deposit_index(),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn eth1_data_votes_count(&self) -> usize {
        match self {
            ForkBeaconState::Phase0(s) => s.eth1_data_votes_count(),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn eth1_data_votes_count_matching(&self, data: &Eth1Data) -> usize {
        match self {
            ForkBeaconState::Phase0(s) => s.eth1_data_votes_count_matching(data),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_justification_bits(&mut self, bits: Bitvector<4>) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_justification_bits(bits),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_previous_justified_checkpoint(&mut self, cp: Checkpoint) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_previous_justified_checkpoint(cp),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_current_justified_checkpoint(&mut self, cp: Checkpoint) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_current_justified_checkpoint(cp),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_finalized_checkpoint(&mut self, cp: Checkpoint) {
        match self {
            ForkBeaconState::Phase0(s) => s.set_finalized_checkpoint(cp),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn push_historical_root(
        &mut self,
        root: pharos_types::phase0::Root,
    ) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.push_historical_root(root),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_previous_epoch_attestations(
        &mut self,
        atts: Vec<PendingAttestation<2048>>,
    ) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.set_previous_epoch_attestations(atts),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn clear_current_epoch_attestations(&mut self) {
        match self {
            ForkBeaconState::Phase0(s) => s.clear_current_epoch_attestations(),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn clear_eth1_data_votes(&mut self) {
        match self {
            ForkBeaconState::Phase0(s) => s.clear_eth1_data_votes(),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn previous_epoch_attestations(&self) -> Vec<PendingAttestation<2048>> {
        match self {
            ForkBeaconState::Phase0(s) => s.previous_epoch_attestations(),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn current_epoch_attestations(&self) -> Vec<PendingAttestation<2048>> {
        match self {
            ForkBeaconState::Phase0(s) => s.current_epoch_attestations(),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn justification_bits(&self) -> Bitvector<4> {
        match self {
            ForkBeaconState::Phase0(s) => s.justification_bits(),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn historical_roots_len(&self) -> usize {
        match self {
            ForkBeaconState::Phase0(s) => s.historical_roots_len(),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_state_root(
        &mut self,
        idx: usize,
        root: pharos_types::phase0::Root,
    ) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.set_state_root(idx, root),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }

    fn set_block_root(
        &mut self,
        idx: usize,
        root: pharos_types::phase0::Root,
    ) -> Result<(), StateTransitionError> {
        match self {
            ForkBeaconState::Phase0(s) => s.set_block_root(idx, root),
            ForkBeaconState::Altair(_) => {
                unreachable!("phase0 STF called on Altair BeaconState")
            }
            ForkBeaconState::Bellatrix(_) => {
                unreachable!("phase0 STF called on Bellatrix BeaconState")
            }
            ForkBeaconState::Capella(_) => {
                unreachable!("phase0 STF called on Capella BeaconState")
            }
            ForkBeaconState::Deneb(_) => {
                unreachable!("phase0 STF called on Deneb BeaconState")
            }
            ForkBeaconState::Electra(_) => {
                unreachable!("phase0 STF called on Electra BeaconState")
            }
            ForkBeaconState::Fulu(_) => {
                unreachable!("phase0 STF called on Fulu BeaconState")
            }
        }
    }
}
