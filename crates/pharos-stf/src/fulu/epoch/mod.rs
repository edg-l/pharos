//! Fulu epoch processing.
//!
//! Per `specs/fulu/beacon-chain.md` Epoch processing.
//!
//! Fulu epoch processing is electra epoch processing plus `process_proposer_lookahead`
//! (EIP-7917) as the final step. All other steps are identical to electra and
//! delegate through the `fulu_state_to_electra` / `update_fulu_from_electra`
//! projection helpers.

pub mod pending_deposits;
pub mod process_proposer_lookahead;

pub use pending_deposits::process_pending_deposits;
pub use process_proposer_lookahead::process_proposer_lookahead;

use pharos_types::{
    BeaconSpec, altair::BeaconState as AltairBeaconState,
    capella::BeaconState as CapellaBeaconState, config::RuntimeConfig,
    deneb::BeaconState as DenebBeaconState, electra::BeaconState as ElectraBeaconState,
    fulu::BeaconState as FuluBeaconState,
};

use crate::electra::epoch::process_epoch as electra_process_epoch;
use crate::error::EpochProcessingError;
use crate::fulu::{fulu_state_to_electra, update_fulu_from_electra};

/// `process_epoch` for Fulu per `specs/fulu/beacon-chain.md`.
///
/// Fulu epoch processing is identical to Electra (steps 1–14) plus a final
/// step: `process_proposer_lookahead` (EIP-7917). All steps 1–14 run on an
/// ephemeral electra-projection via `fulu_state_to_electra`, and the result
/// is written back through `update_fulu_from_electra`. The fulu-only
/// `proposer_lookahead` field is preserved through the electra delegation and
/// updated by `process_proposer_lookahead`.
#[allow(clippy::type_complexity)]
pub fn process_epoch<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    const LOOKAHEAD_WINDOW: u64,
    E,
>(
    state: &mut FuluBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
        LOOKAHEAD_WINDOW,
    >,
    runtime_cfg: &RuntimeConfig,
) -> Result<(), EpochProcessingError>
where
    E: BeaconSpec<
            AltairBeaconState = AltairBeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
            CapellaBeaconState = CapellaBeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
            DenebBeaconState = DenebBeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
            >,
            FuluBeaconState = FuluBeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
                PENDING_DEPOSITS_LIMIT,
                PENDING_PARTIAL_WITHDRAWALS_LIMIT,
                PENDING_CONSOLIDATIONS_LIMIT,
                LOOKAHEAD_WINDOW,
            >,
        >,
    pharos_utils::BLSPubkey: Default + Clone,
{
    // ── Steps 1–14: delegate to electra `process_epoch` via state projection ───
    let mut electra = fulu_state_to_electra::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
        LOOKAHEAD_WINDOW,
    >(state);
    electra_process_epoch::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
        E,
    >(&mut electra, runtime_cfg)?;
    update_fulu_from_electra::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
        LOOKAHEAD_WINDOW,
    >(state, electra);

    // ── Step 15: process_proposer_lookahead (new in EIP-7917) ─────────────────
    process_proposer_lookahead::<
        E,
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
        LOOKAHEAD_WINDOW,
    >(state)?;

    Ok(())
}

/// Dispatch trait for fulu epoch-processing JaF step via the electra projection.
pub trait FuluJaFDispatch<E: BeaconSpec>: Sized {
    fn process_jaf_fulu(&mut self) -> Result<(), EpochProcessingError>;
}

impl<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
    const LOOKAHEAD_WINDOW: u64,
    E,
> FuluJaFDispatch<E>
    for FuluBeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
        LOOKAHEAD_WINDOW,
    >
where
    E: BeaconSpec<
            AltairBeaconState = AltairBeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
            >,
            ElectraBeaconState = ElectraBeaconState<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
                BYTES_PER_LOGS_BLOOM,
                MAX_EXTRA_DATA_BYTES,
                PENDING_DEPOSITS_LIMIT,
                PENDING_PARTIAL_WITHDRAWALS_LIMIT,
                PENDING_CONSOLIDATIONS_LIMIT,
            >,
        >,
    pharos_utils::BLSPubkey: Default + Clone,
{
    fn process_jaf_fulu(&mut self) -> Result<(), EpochProcessingError> {
        use crate::altair::epoch::process_justification_and_finalization;
        use crate::capella::helpers::{capella_state_to_altair, update_capella_from_altair_ref};
        use crate::deneb::helpers::{deneb_state_to_capella, update_deneb_from_capella};
        use crate::electra::helpers::{electra_state_to_deneb, update_electra_from_deneb};

        // Project fulu → electra → deneb → capella → altair for JaF.
        let electra = fulu_state_to_electra::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            PENDING_DEPOSITS_LIMIT,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT,
            PENDING_CONSOLIDATIONS_LIMIT,
            LOOKAHEAD_WINDOW,
        >(self);
        let deneb = electra_state_to_deneb::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            PENDING_DEPOSITS_LIMIT,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT,
            PENDING_CONSOLIDATIONS_LIMIT,
        >(&electra);
        let capella = deneb_state_to_capella::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >(&deneb);
        let mut altair = capella_state_to_altair(&capella);

        process_justification_and_finalization::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(&mut altair)?;

        // Propagate JaF result back: altair → capella → deneb → electra → fulu.
        let mut capella_out = deneb_state_to_capella::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >(&deneb);
        update_capella_from_altair_ref(&mut capella_out, &altair);
        let mut deneb_out = electra_state_to_deneb::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            PENDING_DEPOSITS_LIMIT,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT,
            PENDING_CONSOLIDATIONS_LIMIT,
        >(&electra);
        update_deneb_from_capella::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        >(&mut deneb_out, capella_out);
        let mut electra_out = electra;
        update_electra_from_deneb::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            PENDING_DEPOSITS_LIMIT,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT,
            PENDING_CONSOLIDATIONS_LIMIT,
        >(&mut electra_out, deneb_out);
        update_fulu_from_electra::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
            PENDING_DEPOSITS_LIMIT,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT,
            PENDING_CONSOLIDATIONS_LIMIT,
            LOOKAHEAD_WINDOW,
        >(self, electra_out);
        Ok(())
    }
}
