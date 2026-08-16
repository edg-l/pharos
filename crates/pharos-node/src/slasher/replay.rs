//! Slasher Phase B — chain-history replay scanner (opt-in via `--slasher`).
//!
//! `ChainReplaySlasher` walks the stored block history via the
//! `slot_to_block_root` index (the same navigational index
//! [`crate::state_regen::StateRegenService`] uses) and, for every canonical
//! block:
//!
//! - **Proposer double-block** — builds the block's `SignedBeaconBlockHeader`
//!   and feeds it to the persistent [`super::proposer::ProposerSlasher`], which
//!   catches two distinct blocks signed by the same proposer at the same slot.
//! - **Attester slashing** — extracts the block's attestations (phase0-family
//!   `Attestation<2048>`, covering phase0 through deneb), converts each to an
//!   `IndexedAttestation` against the post-state at the block's slot
//!   (`get_indexed_attestation`), and feeds it through the Phase A
//!   [`super::AttestationSlasher`] double/surround detector — catching attester
//!   slashings the live node never observed on gossip.
//!
//! Both detectors push detected slashings into the shared `op_pools` and
//! increment `pharos_slasher_detections_total`, exactly like the live gossip
//! path. The replay reuses [`StateRegenService::state_at_slot`] (which itself
//! reuses `replay_to`) to obtain the per-slot state for committee resolution,
//! so no STF logic is duplicated.
//!
//! # Fork coverage
//!
//! Proposer double-block detection is fork-agnostic (it operates on block
//! headers) and covers every fork including electra. Attestation replay covers
//! the phase0-family `Attestation<2048>` blocks (phase0..deneb); electra block
//! attestations use the EIP-7549 aggregated shape with preset-dependent const
//! generics that cannot be instantiated in fully-generic `E` code, and are
//! observed by the live Phase A gossip path (`validate_attestation` feeds the
//! same `AttestationSlasher`). This is recorded in `D-slasher-replay-att-scope`.
//!
//! The scanner is sync (it drives RocksDB + STF replay); the `--slasher`
//! startup wires it through [`run_replay`] inside a `spawn_blocking`.

use std::sync::Arc;

use pharos_stf::NullExecutionEngine;
use pharos_stf::phase0::accessors::{compute_epoch_at_slot, get_indexed_attestation};
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::EthSpec;
use pharos_types::phase0::Attestation;
use pharos_types::phase0::primitives::{Root, Slot};
use pharos_types::views::{BeaconBlockView, SignedBeaconBlockView};
use tracing::{info, warn};

use super::AttestationSlasher;
use super::proposer::{ProposerSlasher, ProposerSlasherError, header_from_parts};
use crate::state_regen::{RegenError, StateRegenService};

/// Chain-history replay slasher (Phase B).
///
/// Holds the persistent proposer detector, the (shared) Phase A attestation
/// detector, the block store, and a [`StateRegenService`] for per-slot state
/// resolution. Constructed once at `--slasher` startup.
pub struct ChainReplaySlasher<E: EthSpec> {
    /// Block + index store (`slot_to_block_root`, `blocks`, cold CFs).
    store: Arc<RocksStore>,
    /// Persistent proposer double-block detector.
    proposer: ProposerSlasher<E>,
    /// Phase A attestation double/surround detector (shared `op_pools`).
    attestation: Arc<AttestationSlasher<E>>,
    /// State-regeneration service for per-slot committee resolution.
    regen: Arc<StateRegenService<E>>,
}

impl<E: EthSpec> ChainReplaySlasher<E> {
    /// Construct a new `ChainReplaySlasher`.
    pub fn new(
        store: Arc<RocksStore>,
        proposer: ProposerSlasher<E>,
        attestation: Arc<AttestationSlasher<E>>,
        regen: Arc<StateRegenService<E>>,
    ) -> Self {
        Self {
            store,
            proposer,
            attestation,
            regen,
        }
    }

    /// Replay every canonical block in `[from_slot, to_slot]`, feeding each
    /// block's proposer header and attestations through the detectors.
    ///
    /// Returns the number of blocks scanned. Per-block errors (a missing block,
    /// a state-regen failure) are logged and skipped so one bad slot never
    /// aborts the whole scan.
    pub fn replay(&self, from_slot: Slot, to_slot: Slot) -> Result<u64, ReplayError>
    where
        E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
                Attestation = Attestation<2048>,
                AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
                Deposit = pharos_types::phase0::Deposit<33>,
            >,
        E::BeaconState:
            pharos_stf::phase0::state_write::BeaconStateWrite + pharos_ssz::TreeHash + Clone,
        E::BeaconBlock: BeaconBlockView + pharos_ssz::TreeHash + Clone,
        E::SignedBeaconBlock:
            pharos_ssz::Decode + SignedBeaconBlockView<Message = E::BeaconBlock> + Clone,
        E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody> + Clone,
        E::Phase0SignedBeaconBlock:
            pharos_ssz::Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
        E::AltairBeaconState: pharos_stf::AltairDispatch<E>
            + pharos_stf::AltairJaFDispatch<E>
            + pharos_stf::AltairProcessSlotsDispatch<E>
            + pharos_stf::AltairUpgradeDispatch<E>,
        E::AltairBeaconBlock: BeaconBlockView + Clone,
        E::AltairSignedBeaconBlock:
            pharos_ssz::Decode + SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
        E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, NullExecutionEngine>
            + pharos_stf::BellatrixJaFDispatch<E>
            + pharos_stf::BellatrixProcessSlotsDispatch<E>
            + pharos_stf::BellatrixUpgradeDispatch<E>
            + pharos_ssz::TreeHash,
        E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, NullExecutionEngine>
            + pharos_stf::CapellaJaFDispatch<E>
            + pharos_stf::CapellaProcessSlotsDispatch<E>
            + pharos_stf::CapellaUpgradeDispatch<E>,
        E::DenebBeaconState: pharos_stf::DenebDispatch<E, NullExecutionEngine>
            + pharos_stf::DenebProcessSlotsDispatch<E>
            + pharos_stf::DenebUpgradeDispatch<E>
            + pharos_ssz::TreeHash,
        E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, NullExecutionEngine>
            + pharos_stf::ElectraProcessSlotsDispatch<E>
            + pharos_ssz::TreeHash,
        E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
        E::BellatrixSignedBeaconBlock:
            pharos_ssz::Decode + SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
        <E::AltairBeaconBlock as BeaconBlockView>::Body:
            pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
        <E::BellatrixBeaconBlock as BeaconBlockView>::Body:
            pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
        <E::CapellaBeaconBlock as BeaconBlockView>::Body:
            pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
        <E::DenebBeaconBlock as BeaconBlockView>::Body:
            pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
        E::CapellaSignedBeaconBlock: SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
        E::DenebSignedBeaconBlock: SignedBeaconBlockView<Message = E::DenebBeaconBlock>,
    {
        let mut scanned: u64 = 0;
        let mut slot = from_slot;
        while slot <= to_slot {
            let block_root = match self.store.block_root_at_slot(slot) {
                Ok(Some(r)) => r,
                Ok(None) => {
                    slot = Slot(slot.0 + 1);
                    continue;
                }
                Err(e) => {
                    warn!(slot = slot.0, error = ?e, "slasher replay: slot-index read failed");
                    slot = Slot(slot.0 + 1);
                    continue;
                }
            };

            if let Err(e) = self.scan_block(block_root) {
                warn!(slot = slot.0, ?block_root, error = ?e, "slasher replay: block scan failed");
            } else {
                scanned += 1;
            }

            slot = Slot(slot.0 + 1);
        }
        Ok(scanned)
    }

    /// Scan one canonical block: proposer header + attestations.
    fn scan_block(&self, block_root: Root) -> Result<(), ReplayError>
    where
        E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
                Attestation = Attestation<2048>,
                AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
                Deposit = pharos_types::phase0::Deposit<33>,
            >,
        E::BeaconState:
            pharos_stf::phase0::state_write::BeaconStateWrite + pharos_ssz::TreeHash + Clone,
        E::BeaconBlock: BeaconBlockView + pharos_ssz::TreeHash + Clone,
        E::SignedBeaconBlock:
            pharos_ssz::Decode + SignedBeaconBlockView<Message = E::BeaconBlock> + Clone,
        E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody> + Clone,
        E::Phase0SignedBeaconBlock:
            pharos_ssz::Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
        E::AltairBeaconState: pharos_stf::AltairDispatch<E>
            + pharos_stf::AltairJaFDispatch<E>
            + pharos_stf::AltairProcessSlotsDispatch<E>
            + pharos_stf::AltairUpgradeDispatch<E>,
        E::AltairBeaconBlock: BeaconBlockView + Clone,
        E::AltairSignedBeaconBlock:
            pharos_ssz::Decode + SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
        E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, NullExecutionEngine>
            + pharos_stf::BellatrixJaFDispatch<E>
            + pharos_stf::BellatrixProcessSlotsDispatch<E>
            + pharos_stf::BellatrixUpgradeDispatch<E>
            + pharos_ssz::TreeHash,
        E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, NullExecutionEngine>
            + pharos_stf::CapellaJaFDispatch<E>
            + pharos_stf::CapellaProcessSlotsDispatch<E>
            + pharos_stf::CapellaUpgradeDispatch<E>,
        E::DenebBeaconState: pharos_stf::DenebDispatch<E, NullExecutionEngine>
            + pharos_stf::DenebProcessSlotsDispatch<E>
            + pharos_stf::DenebUpgradeDispatch<E>
            + pharos_ssz::TreeHash,
        E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, NullExecutionEngine>
            + pharos_stf::ElectraProcessSlotsDispatch<E>
            + pharos_ssz::TreeHash,
        E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
        E::BellatrixSignedBeaconBlock:
            pharos_ssz::Decode + SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
        <E::AltairBeaconBlock as BeaconBlockView>::Body:
            pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
        <E::BellatrixBeaconBlock as BeaconBlockView>::Body:
            pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
        <E::CapellaBeaconBlock as BeaconBlockView>::Body:
            pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
        <E::DenebBeaconBlock as BeaconBlockView>::Body:
            pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
        E::CapellaSignedBeaconBlock: SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
        E::DenebSignedBeaconBlock: SignedBeaconBlockView<Message = E::DenebBeaconBlock>,
    {
        // Load the signed block (hot CF, then cold CF for migrated history).
        let hot = <RocksStore as DbStore<E>>::get_block(&self.store, &block_root)?;
        let signed_block = match hot {
            Some(b) => b,
            None => <RocksStore as DbStore<E>>::get_cold_block(&self.store, &block_root)?
                .ok_or(ReplayError::MissingBlock { root: block_root })?,
        };

        // ── 1. Proposer double-block ──────────────────────────────────────────
        let header = signed_block_header::<E>(&signed_block);
        self.proposer.observe(&header)?;

        // ── 2. Attester slashings via the block's attestations ────────────────
        let atts = block_phase0_attestations::<E>(&signed_block);
        if !atts.is_empty() {
            let block_slot = header.message.slot;
            // Resolve the post-state at the block slot for committee lookup.
            let state = self.regen.state_at_slot(block_slot)?;
            // Drive the Phase A eviction window off the block's own epoch so
            // that historical records stay live for the duration of the scan
            // (each block is observed in slot order, so the window only grows).
            let block_epoch = compute_epoch_at_slot(block_slot, E::SLOTS_PER_EPOCH).0;
            for att in &atts {
                let indexed = get_indexed_attestation::<E>(&state, att);
                self.attestation.observe(&indexed, block_epoch);
            }
        }

        Ok(())
    }
}

/// Build the `SignedBeaconBlockHeader` of a fork-enum signed block.
///
/// Mirrors [`crate::import::signed_block_slot`] / `signed_block_state_root`:
/// no single trait-dispatch accessor covers every variant, so each fork is
/// unwrapped here in ONE place. Adding a fork requires extending this function
/// — a missing arm is a compile error.
pub fn signed_block_header<E: EthSpec>(
    b: &E::SignedBeaconBlock,
) -> pharos_types::phase0::operations::SignedBeaconBlockHeader {
    use pharos_ssz::TreeHash;

    macro_rules! header_of {
        ($inner:expr) => {{
            let msg = $inner.message();
            header_from_parts(
                msg.slot(),
                msg.proposer_index().0,
                msg.parent_root(),
                msg.state_root(),
                msg.body().tree_hash_root(),
                *$inner.signature(),
            )
        }};
    }

    if let Some(inner) = E::unwrap_phase0_signed_block(b) {
        header_of!(inner)
    } else if let Some(inner) = E::unwrap_altair_signed_block(b) {
        header_of!(inner)
    } else if let Some(inner) = E::unwrap_bellatrix_signed_block(b) {
        header_of!(inner)
    } else if let Some(inner) = E::unwrap_capella_signed_block(b) {
        header_of!(inner)
    } else if let Some(inner) = E::unwrap_deneb_signed_block(b) {
        header_of!(inner)
    } else if let Some(inner) = E::unwrap_electra_signed_block(b) {
        header_of!(inner)
    } else {
        unreachable!("unknown fork variant in SignedBeaconBlock")
    }
}

/// Extract the phase0-family `Attestation<2048>`s from a fork-enum signed block.
///
/// Covers phase0 through deneb (all share the `Attestation<2048>` shape).
/// Electra blocks use the EIP-7549 aggregated attestation with preset-dependent
/// const generics that cannot be instantiated in generic `E` code; an electra
/// block returns an empty vec here (its attestations are observed by the live
/// Phase A gossip path). Per `D-slasher-replay-att-scope`.
pub fn block_phase0_attestations<E: EthSpec>(b: &E::SignedBeaconBlock) -> Vec<Attestation<2048>>
where
    E::Phase0SignedBeaconBlock: SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairSignedBeaconBlock: SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixSignedBeaconBlock: SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    E::CapellaSignedBeaconBlock: SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::DenebSignedBeaconBlock: SignedBeaconBlockView<Message = E::DenebBeaconBlock>,
    <E::Phase0BeaconBlock as BeaconBlockView>::Body:
        pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
    <E::AltairBeaconBlock as BeaconBlockView>::Body:
        pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
    <E::BellatrixBeaconBlock as BeaconBlockView>::Body:
        pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
    <E::CapellaBeaconBlock as BeaconBlockView>::Body:
        pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
    <E::DenebBeaconBlock as BeaconBlockView>::Body:
        pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    use pharos_types::views::BeaconBlockBodyView as _;

    macro_rules! atts_of {
        ($inner:expr) => {
            $inner.message().body().attestations().to_vec()
        };
    }

    if let Some(inner) = E::unwrap_phase0_signed_block(b) {
        atts_of!(inner)
    } else if let Some(inner) = E::unwrap_altair_signed_block(b) {
        atts_of!(inner)
    } else if let Some(inner) = E::unwrap_bellatrix_signed_block(b) {
        atts_of!(inner)
    } else if let Some(inner) = E::unwrap_capella_signed_block(b) {
        atts_of!(inner)
    } else if let Some(inner) = E::unwrap_deneb_signed_block(b) {
        atts_of!(inner)
    } else {
        // Electra (EIP-7549 aggregated attestations) or unknown: observed on
        // the gossip path, not block-replay. Per D-slasher-replay-att-scope.
        Vec::new()
    }
}

/// Run the chain-history replay once over `[from_slot, to_slot]`.
///
/// Drives the sync [`ChainReplaySlasher::replay`] inside a `spawn_blocking`
/// (the scan is CPU + RocksDB bound) so it never blocks the tokio executor.
/// This is the `--slasher` startup entry point; it is a no-op-safe one-shot
/// pass over the stored history present at startup. Errors are logged, not
/// propagated, so a slasher failure never takes the node down.
pub async fn run_replay<E>(slasher: Arc<ChainReplaySlasher<E>>, from_slot: Slot, to_slot: Slot)
where
    E: EthSpec,
    E::Phase0BeaconBlockBody: pharos_types::views::BeaconBlockBodyView<
            Attestation = Attestation<2048>,
            AttesterSlashing = pharos_types::phase0::AttesterSlashing<2048>,
            Deposit = pharos_types::phase0::Deposit<33>,
        >,
    E::BeaconState:
        pharos_stf::phase0::state_write::BeaconStateWrite + pharos_ssz::TreeHash + Clone,
    E::BeaconBlock: BeaconBlockView + pharos_ssz::TreeHash + Clone,
    E::SignedBeaconBlock:
        pharos_ssz::Decode + SignedBeaconBlockView<Message = E::BeaconBlock> + Clone,
    E::Phase0BeaconBlock: BeaconBlockView<Body = E::Phase0BeaconBlockBody> + Clone,
    E::Phase0SignedBeaconBlock:
        pharos_ssz::Decode + SignedBeaconBlockView<Message = E::Phase0BeaconBlock>,
    E::AltairBeaconState: pharos_stf::AltairDispatch<E>
        + pharos_stf::AltairJaFDispatch<E>
        + pharos_stf::AltairProcessSlotsDispatch<E>
        + pharos_stf::AltairUpgradeDispatch<E>,
    E::AltairBeaconBlock: BeaconBlockView + Clone,
    E::AltairSignedBeaconBlock:
        pharos_ssz::Decode + SignedBeaconBlockView<Message = E::AltairBeaconBlock>,
    E::BellatrixBeaconState: pharos_stf::BellatrixDispatch<E, NullExecutionEngine>
        + pharos_stf::BellatrixJaFDispatch<E>
        + pharos_stf::BellatrixProcessSlotsDispatch<E>
        + pharos_stf::BellatrixUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::CapellaBeaconState: pharos_stf::CapellaDispatch<E, NullExecutionEngine>
        + pharos_stf::CapellaJaFDispatch<E>
        + pharos_stf::CapellaProcessSlotsDispatch<E>
        + pharos_stf::CapellaUpgradeDispatch<E>,
    E::DenebBeaconState: pharos_stf::DenebDispatch<E, NullExecutionEngine>
        + pharos_stf::DenebProcessSlotsDispatch<E>
        + pharos_stf::DenebUpgradeDispatch<E>
        + pharos_ssz::TreeHash,
    E::ElectraBeaconState: pharos_stf::ElectraDispatch<E, NullExecutionEngine>
        + pharos_stf::ElectraProcessSlotsDispatch<E>
        + pharos_ssz::TreeHash,
    E::Phase0BeaconState: pharos_stf::Phase0UpgradeDispatch<E>,
    E::BellatrixSignedBeaconBlock:
        pharos_ssz::Decode + SignedBeaconBlockView<Message = E::BellatrixBeaconBlock>,
    <E::AltairBeaconBlock as BeaconBlockView>::Body:
        pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
    <E::BellatrixBeaconBlock as BeaconBlockView>::Body:
        pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
    <E::CapellaBeaconBlock as BeaconBlockView>::Body:
        pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
    <E::DenebBeaconBlock as BeaconBlockView>::Body:
        pharos_types::views::BeaconBlockBodyView<Attestation = Attestation<2048>>,
    E::CapellaSignedBeaconBlock: SignedBeaconBlockView<Message = E::CapellaBeaconBlock>,
    E::DenebSignedBeaconBlock: SignedBeaconBlockView<Message = E::DenebBeaconBlock>,
{
    info!(
        from_slot = from_slot.0,
        to_slot = to_slot.0,
        "slasher: starting chain-history replay scan"
    );
    let result = tokio::task::spawn_blocking(move || slasher.replay(from_slot, to_slot)).await;
    match result {
        Ok(Ok(scanned)) => {
            info!(
                blocks_scanned = scanned,
                "slasher: chain-history replay complete"
            )
        }
        Ok(Err(e)) => warn!(error = ?e, "slasher: chain-history replay failed"),
        Err(e) => warn!(error = ?e, "slasher: chain-history replay task panicked"),
    }
}

/// Errors from the chain-replay slasher.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    /// A block referenced by the slot index is absent from both hot and cold CFs.
    #[error("missing block {root:?} during slasher replay")]
    MissingBlock { root: Root },

    /// A storage read/write failed.
    #[error("slasher replay storage error: {0}")]
    Storage(#[from] pharos_storage::StorageError),

    /// State regeneration for committee resolution failed.
    #[error("slasher replay state-regen error: {0}")]
    Regen(#[from] RegenError),

    /// The proposer detector's index storage failed.
    #[error("slasher replay proposer error: {0}")]
    Proposer(#[from] ProposerSlasherError),
}
