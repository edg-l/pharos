//! Altair light-client sync protocol functions.
//!
//! Per `specs/altair/light-client/sync-protocol.md`.
//!
//! Also covers the `full-node.md` create-* functions referenced in Phase 6
//! (Task 6.9).  The store functions are in this module because they are needed
//! by the Phase 4 conformance runner.

use pharos_ssz::TreeHash;
use pharos_types::{
    EthSpec,
    altair::light_client::{
        CURRENT_SYNC_COMMITTEE_GINDEX, FINALIZED_ROOT_GINDEX, LightClientBootstrap,
        LightClientHeader, LightClientStore, LightClientUpdate, NEXT_SYNC_COMMITTEE_GINDEX,
    },
    phase0::primitives::{Root, Slot},
};
use pharos_utils::{BLSPubkey, Bytes32};

use crate::altair::helpers::DOMAIN_SYNC_COMMITTEE;
use crate::phase0::accessors::{compute_domain, compute_epoch_at_slot, compute_signing_root};
use crate::phase0::operations::deposit::is_valid_merkle_branch;

// ── Constants ─────────────────────────────────────────────────────────────────

/// `MIN_SYNC_COMMITTEE_PARTICIPANTS = 1`.
///
/// Per `specs/altair/light-client/sync-protocol.md` (Preset / Misc).
pub const MIN_SYNC_COMMITTEE_PARTICIPANTS: u64 = 1;

// ── floorlog2 ─────────────────────────────────────────────────────────────────

/// Integer floor-log2: the bit position of the highest set bit.
///
/// `floorlog2(1) = 0`, `floorlog2(2) = 1`, `floorlog2(4) = 2`, etc.
fn floorlog2(n: u64) -> u64 {
    debug_assert!(n >= 1, "floorlog2 undefined for 0");
    63 - n.leading_zeros() as u64
}

// ── Generalized-index helpers ─────────────────────────────────────────────────

/// `get_subtree_index(gindex)` = `gindex % 2^floorlog2(gindex)`.
///
/// Per `specs/altair/light-client/sync-protocol.md`.
fn get_subtree_index(gindex: u64) -> u64 {
    let depth = floorlog2(gindex);
    gindex % (1u64 << depth)
}

// ── Merkle helpers ─────────────────────────────────────────────────────────────

/// `is_valid_normalized_merkle_branch` per
/// `specs/altair/light-client/sync-protocol.md`.
///
/// Handles a branch that may have leading zero hashes (normalised form).
fn is_valid_normalized_merkle_branch(
    leaf: &Bytes32,
    branch: &[Bytes32],
    gindex: u64,
    root: &Root,
) -> bool {
    let depth = floorlog2(gindex) as usize;
    let index = get_subtree_index(gindex);
    let num_extra = branch.len().saturating_sub(depth);
    for extra in branch.iter().take(num_extra) {
        if extra != &Bytes32::default() {
            return false;
        }
    }
    // Bytes32 = Hash256 = FixedBytes<32>, same type.
    let branch_slice = &branch[num_extra..];
    is_valid_merkle_branch(leaf, branch_slice, depth as u64, index, root)
}

// ── Sync committee count helpers ──────────────────────────────────────────────

/// Count the number of set bits in a `Bitvector` (number of participants).
fn count_participants<const SYNC_COMMITTEE_SIZE: u64>(
    bits: &pharos_ssz::Bitvector<SYNC_COMMITTEE_SIZE>,
) -> u64 {
    bits.iter().filter(|b| *b).count() as u64
}

// ── Altair sync committee period helpers ──────────────────────────────────────

/// `compute_sync_committee_period(epoch)` = `epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD`.
///
/// Per `specs/altair/beacon-chain.md`.
pub fn compute_sync_committee_period<E: EthSpec>(epoch: pharos_utils::Epoch) -> u64 {
    epoch.0 / E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD
}

/// `compute_sync_committee_period_at_slot(slot)`.
///
/// Per `specs/altair/light-client/sync-protocol.md`.
pub fn compute_sync_committee_period_at_slot<E: EthSpec>(slot: Slot) -> u64 {
    let epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);
    compute_sync_committee_period::<E>(epoch)
}

// ── LightClientStore helpers ──────────────────────────────────────────────────

/// `is_sync_committee_update(update)` — branch is non-zero.
///
/// Per `specs/altair/light-client/sync-protocol.md`.
pub fn is_sync_committee_update<const SYNC_COMMITTEE_SIZE: u64>(
    update: &LightClientUpdate<SYNC_COMMITTEE_SIZE>,
) -> bool
where
    Bytes32: Default + PartialEq + Clone,
{
    update.next_sync_committee_branch.as_slice() != vec![Bytes32::default(); 5]
}

/// `is_finality_update(update)` — finality branch is non-zero.
///
/// Per `specs/altair/light-client/sync-protocol.md`.
pub fn is_finality_update<const SYNC_COMMITTEE_SIZE: u64>(
    update: &LightClientUpdate<SYNC_COMMITTEE_SIZE>,
) -> bool
where
    Bytes32: Default + PartialEq + Clone,
{
    update.finality_branch.as_slice() != vec![Bytes32::default(); 6]
}

/// `is_next_sync_committee_known(store)`.
///
/// Per `specs/altair/light-client/sync-protocol.md`.
pub fn is_next_sync_committee_known<const SYNC_COMMITTEE_SIZE: u64>(
    store: &LightClientStore<SYNC_COMMITTEE_SIZE>,
) -> bool
where
    Bytes32: Default + Clone,
    BLSPubkey: Default + PartialEq + Clone,
{
    use pharos_types::altair::operations::SyncCommittee;
    store.next_sync_committee != SyncCommittee::default()
}

/// `get_safety_threshold(store)`.
///
/// Per `specs/altair/light-client/sync-protocol.md`.
pub fn get_safety_threshold<const SYNC_COMMITTEE_SIZE: u64>(
    store: &LightClientStore<SYNC_COMMITTEE_SIZE>,
) -> u64 {
    store
        .previous_max_active_participants
        .max(store.current_max_active_participants)
        / 2
}

/// `is_better_update(new_update, old_update)`.
///
/// Per `specs/altair/light-client/sync-protocol.md`.
pub fn is_better_update<E: EthSpec, const SYNC_COMMITTEE_SIZE: u64>(
    new_update: &LightClientUpdate<SYNC_COMMITTEE_SIZE>,
    old_update: &LightClientUpdate<SYNC_COMMITTEE_SIZE>,
) -> bool
where
    Bytes32: Default + PartialEq + Clone,
{
    let max_active = SYNC_COMMITTEE_SIZE;
    let new_n = count_participants(&new_update.sync_aggregate.sync_committee_bits);
    let old_n = count_participants(&old_update.sync_aggregate.sync_committee_bits);
    let new_super = new_n * 3 >= max_active * 2;
    let old_super = old_n * 3 >= max_active * 2;
    if new_super != old_super {
        return new_super;
    }
    if !new_super && new_n != old_n {
        return new_n > old_n;
    }

    let new_relevant = is_sync_committee_update(new_update)
        && compute_sync_committee_period_at_slot::<E>(new_update.attested_header.beacon.slot)
            == compute_sync_committee_period_at_slot::<E>(new_update.signature_slot);
    let old_relevant = is_sync_committee_update(old_update)
        && compute_sync_committee_period_at_slot::<E>(old_update.attested_header.beacon.slot)
            == compute_sync_committee_period_at_slot::<E>(old_update.signature_slot);
    if new_relevant != old_relevant {
        return new_relevant;
    }

    let new_fin = is_finality_update(new_update);
    let old_fin = is_finality_update(old_update);
    if new_fin != old_fin {
        return new_fin;
    }

    if new_fin {
        let new_sc_fin =
            compute_sync_committee_period_at_slot::<E>(new_update.finalized_header.beacon.slot)
                == compute_sync_committee_period_at_slot::<E>(
                    new_update.attested_header.beacon.slot,
                );
        let old_sc_fin =
            compute_sync_committee_period_at_slot::<E>(old_update.finalized_header.beacon.slot)
                == compute_sync_committee_period_at_slot::<E>(
                    old_update.attested_header.beacon.slot,
                );
        if new_sc_fin != old_sc_fin {
            return new_sc_fin;
        }
    }

    if new_n != old_n {
        return new_n > old_n;
    }

    if new_update.attested_header.beacon.slot != old_update.attested_header.beacon.slot {
        return new_update.attested_header.beacon.slot < old_update.attested_header.beacon.slot;
    }

    new_update.signature_slot < old_update.signature_slot
}

// ── compute_fork_version ──────────────────────────────────────────────────────

/// `compute_fork_version(epoch)` — returns the fork version active at `epoch`.
///
/// For altair conformance: only phase0 and altair fork versions exist.
/// Per `specs/phase0/beacon-chain.md` fork versioning scheme.
pub fn compute_fork_version<E: EthSpec>(epoch: pharos_utils::Epoch) -> [u8; 4] {
    if epoch.0 >= E::ALTAIR_FORK_EPOCH {
        E::ALTAIR_FORK_VERSION
    } else {
        E::GENESIS_FORK_VERSION
    }
}

// ── initialize_light_client_store ─────────────────────────────────────────────

/// `initialize_light_client_store(trusted_block_root, bootstrap)`.
///
/// Per `specs/altair/light-client/sync-protocol.md:332-353`.
pub fn initialize_light_client_store<E: EthSpec, const SYNC_COMMITTEE_SIZE: u64>(
    trusted_block_root: &Root,
    bootstrap: &LightClientBootstrap<SYNC_COMMITTEE_SIZE>,
) -> Result<LightClientStore<SYNC_COMMITTEE_SIZE>, LightClientError>
where
    Bytes32: Default + PartialEq + Clone,
    BLSPubkey: Default + PartialEq + Clone,
{
    let header_root = bootstrap.header.beacon.tree_hash_root();
    if &header_root != trusted_block_root {
        return Err(LightClientError::TrustedBlockRootMismatch);
    }

    // Root = Bytes32 = Hash256 = FixedBytes<32>, same type.
    let committee_root = bootstrap.current_sync_committee.tree_hash_root();
    let branch_hashes: Vec<Bytes32> = bootstrap.current_sync_committee_branch.as_slice().to_vec();

    if !is_valid_normalized_merkle_branch(
        &committee_root,
        &branch_hashes,
        CURRENT_SYNC_COMMITTEE_GINDEX,
        &bootstrap.header.beacon.state_root,
    ) {
        return Err(LightClientError::InvalidCurrentSyncCommitteeBranch);
    }

    Ok(LightClientStore {
        finalized_header: bootstrap.header.clone(),
        current_sync_committee: bootstrap.current_sync_committee.clone(),
        next_sync_committee: Default::default(),
        best_valid_update: None,
        optimistic_header: bootstrap.header.clone(),
        previous_max_active_participants: 0,
        current_max_active_participants: 0,
    })
}

// ── validate_light_client_update ──────────────────────────────────────────────

/// `validate_light_client_update(store, update, current_slot, genesis_validators_root)`.
///
/// Per `specs/altair/light-client/sync-protocol.md:375-455`.
pub fn validate_light_client_update<E: EthSpec, const SYNC_COMMITTEE_SIZE: u64>(
    store: &LightClientStore<SYNC_COMMITTEE_SIZE>,
    update: &LightClientUpdate<SYNC_COMMITTEE_SIZE>,
    current_slot: Slot,
    genesis_validators_root: &Root,
) -> Result<(), LightClientError>
where
    Bytes32: Default + PartialEq + Clone,
    BLSPubkey: Default + PartialEq + Clone,
{
    let n_participants = count_participants(&update.sync_aggregate.sync_committee_bits);
    if n_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS {
        return Err(LightClientError::InsufficientParticipants);
    }

    let update_attested_slot = update.attested_header.beacon.slot;
    let update_finalized_slot = update.finalized_header.beacon.slot;

    if !(current_slot >= update.signature_slot
        && update.signature_slot > update_attested_slot
        && update_attested_slot >= update_finalized_slot)
    {
        return Err(LightClientError::InvalidSlotOrder);
    }

    let store_period =
        compute_sync_committee_period_at_slot::<E>(store.finalized_header.beacon.slot);
    let update_sig_period = compute_sync_committee_period_at_slot::<E>(update.signature_slot);

    if is_next_sync_committee_known(store) {
        if update_sig_period != store_period && update_sig_period != store_period + 1 {
            return Err(LightClientError::SignaturePeriodOutOfRange);
        }
    } else if update_sig_period != store_period {
        return Err(LightClientError::SignaturePeriodOutOfRange);
    }

    let update_attested_period = compute_sync_committee_period_at_slot::<E>(update_attested_slot);
    let update_has_next_sync_committee = !is_next_sync_committee_known(store)
        && is_sync_committee_update(update)
        && update_attested_period == store_period;
    if !(update_attested_slot > store.finalized_header.beacon.slot
        || update_has_next_sync_committee)
    {
        return Err(LightClientError::NotRelevant);
    }

    // Verify finality branch if present.
    if !is_finality_update(update) {
        if update.finalized_header != LightClientHeader::default() {
            return Err(LightClientError::InvalidFinalityBranch);
        }
    } else {
        let finalized_root = if update_finalized_slot.0 == 0 {
            // Genesis slot
            if update.finalized_header != LightClientHeader::default() {
                return Err(LightClientError::InvalidFinalityBranch);
            }
            Bytes32::default()
        } else {
            // Root = Hash256 = FixedBytes<32> = Bytes32, same type.
            update.finalized_header.beacon.tree_hash_root()
        };
        let finality_branch: Vec<Bytes32> = update.finality_branch.as_slice().to_vec();
        if !is_valid_normalized_merkle_branch(
            &finalized_root,
            &finality_branch,
            FINALIZED_ROOT_GINDEX,
            &update.attested_header.beacon.state_root,
        ) {
            return Err(LightClientError::InvalidFinalityBranch);
        }
    }

    // Verify next sync committee branch if present.
    if !is_sync_committee_update(update) {
        use pharos_types::altair::operations::SyncCommittee;
        if update.next_sync_committee != SyncCommittee::default() {
            return Err(LightClientError::InvalidNextSyncCommitteeBranch);
        }
    } else {
        if update_attested_period == store_period
            && is_next_sync_committee_known(store)
            && update.next_sync_committee != store.next_sync_committee
        {
            return Err(LightClientError::NextSyncCommitteeMismatch);
        }
        // Root = Bytes32, same type.
        let nsc_root = update.next_sync_committee.tree_hash_root();
        let nsc_branch: Vec<Bytes32> = update.next_sync_committee_branch.as_slice().to_vec();
        if !is_valid_normalized_merkle_branch(
            &nsc_root,
            &nsc_branch,
            NEXT_SYNC_COMMITTEE_GINDEX,
            &update.attested_header.beacon.state_root,
        ) {
            return Err(LightClientError::InvalidNextSyncCommitteeBranch);
        }
    }

    // Verify BLS signature.
    let sync_committee = if update_sig_period == store_period {
        &store.current_sync_committee
    } else {
        &store.next_sync_committee
    };

    let participant_pubkeys: Vec<BLSPubkey> = update
        .sync_aggregate
        .sync_committee_bits
        .iter()
        .zip(sync_committee.pubkeys.as_slice().iter())
        .filter_map(|(bit, pk)| if bit { Some(*pk) } else { None })
        .collect();

    let fork_version_slot = if update.signature_slot.0 > 0 {
        Slot(update.signature_slot.0 - 1)
    } else {
        Slot(0)
    };
    let epoch = compute_epoch_at_slot(fork_version_slot, E::SLOTS_PER_EPOCH);
    let fork_version = compute_fork_version::<E>(epoch);
    let domain = compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root);
    let signing_root = compute_signing_root(&update.attested_header.beacon, domain);

    let sig_valid = pharos_utils::bls::fast_aggregate_verify(
        &participant_pubkeys,
        signing_root.as_slice(),
        &update.sync_aggregate.sync_committee_signature,
    )
    .map_err(|e| LightClientError::Bls(format!("{e:?}")))?;

    if !sig_valid {
        return Err(LightClientError::InvalidSignature);
    }

    Ok(())
}

// ── apply_light_client_update ─────────────────────────────────────────────────

/// `apply_light_client_update(store, update)`.
///
/// Per `specs/altair/light-client/sync-protocol.md:461-477`.
pub fn apply_light_client_update<E: EthSpec, const SYNC_COMMITTEE_SIZE: u64>(
    store: &mut LightClientStore<SYNC_COMMITTEE_SIZE>,
    update: &LightClientUpdate<SYNC_COMMITTEE_SIZE>,
) where
    Bytes32: Default + PartialEq + Clone,
    BLSPubkey: Default + PartialEq + Clone,
{
    let store_period =
        compute_sync_committee_period_at_slot::<E>(store.finalized_header.beacon.slot);
    let update_finalized_period =
        compute_sync_committee_period_at_slot::<E>(update.finalized_header.beacon.slot);

    if !is_next_sync_committee_known(store) {
        store.next_sync_committee = update.next_sync_committee.clone();
    } else if update_finalized_period == store_period + 1 {
        store.current_sync_committee = store.next_sync_committee.clone();
        store.next_sync_committee = update.next_sync_committee.clone();
        store.previous_max_active_participants = store.current_max_active_participants;
        store.current_max_active_participants = 0;
    }

    if update.finalized_header.beacon.slot > store.finalized_header.beacon.slot {
        store.finalized_header = update.finalized_header.clone();
        if store.finalized_header.beacon.slot > store.optimistic_header.beacon.slot {
            store.optimistic_header = store.finalized_header.clone();
        }
    }
}

// ── process_light_client_store_force_update ───────────────────────────────────

/// `process_light_client_store_force_update(store, current_slot)`.
///
/// Per `specs/altair/light-client/sync-protocol.md:483-498`.
pub fn process_light_client_store_force_update<E: EthSpec, const SYNC_COMMITTEE_SIZE: u64>(
    store: &mut LightClientStore<SYNC_COMMITTEE_SIZE>,
    current_slot: Slot,
) where
    Bytes32: Default + PartialEq + Clone,
    BLSPubkey: Default + PartialEq + Clone,
{
    let update_timeout = E::SLOTS_PER_EPOCH * E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD;
    if current_slot.0 > store.finalized_header.beacon.slot.0 + update_timeout
        && store.best_valid_update.is_some()
    {
        let mut best = store.best_valid_update.take().unwrap();
        if best.finalized_header.beacon.slot <= store.finalized_header.beacon.slot {
            best.finalized_header = best.attested_header.clone();
        }
        apply_light_client_update::<E, SYNC_COMMITTEE_SIZE>(store, &best);
    }
}

// ── process_light_client_update ───────────────────────────────────────────────

/// `process_light_client_update(store, update, current_slot, genesis_validators_root)`.
///
/// Per `specs/altair/light-client/sync-protocol.md:504-547`.
pub fn process_light_client_update<E: EthSpec, const SYNC_COMMITTEE_SIZE: u64>(
    store: &mut LightClientStore<SYNC_COMMITTEE_SIZE>,
    update: &LightClientUpdate<SYNC_COMMITTEE_SIZE>,
    current_slot: Slot,
    genesis_validators_root: &Root,
) -> Result<(), LightClientError>
where
    Bytes32: Default + PartialEq + Clone,
    BLSPubkey: Default + PartialEq + Clone,
{
    validate_light_client_update::<E, SYNC_COMMITTEE_SIZE>(
        store,
        update,
        current_slot,
        genesis_validators_root,
    )?;

    let n_participants = count_participants(&update.sync_aggregate.sync_committee_bits);

    // Update best valid update.
    let update_is_better = match &store.best_valid_update {
        None => true,
        Some(best) => is_better_update::<E, SYNC_COMMITTEE_SIZE>(update, best),
    };
    if update_is_better {
        store.best_valid_update = Some(update.clone());
    }

    // Track max active participants.
    store.current_max_active_participants =
        store.current_max_active_participants.max(n_participants);

    // Update optimistic header.
    if n_participants > get_safety_threshold(store)
        && update.attested_header.beacon.slot > store.optimistic_header.beacon.slot
    {
        store.optimistic_header = update.attested_header.clone();
    }

    // Update finalized header.
    let update_has_finalized_next_sync_committee = !is_next_sync_committee_known(store)
        && is_sync_committee_update(update)
        && is_finality_update(update)
        && compute_sync_committee_period_at_slot::<E>(update.finalized_header.beacon.slot)
            == compute_sync_committee_period_at_slot::<E>(update.attested_header.beacon.slot);

    if n_participants * 3 >= SYNC_COMMITTEE_SIZE * 2
        && (update.finalized_header.beacon.slot > store.finalized_header.beacon.slot
            || update_has_finalized_next_sync_committee)
    {
        apply_light_client_update::<E, SYNC_COMMITTEE_SIZE>(store, update);
        store.best_valid_update = None;
    }

    Ok(())
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Error variants for light client operations.
#[derive(Debug, PartialEq, Eq)]
pub enum LightClientError {
    TrustedBlockRootMismatch,
    InvalidCurrentSyncCommitteeBranch,
    InsufficientParticipants,
    InvalidSlotOrder,
    SignaturePeriodOutOfRange,
    NotRelevant,
    InvalidFinalityBranch,
    InvalidNextSyncCommitteeBranch,
    NextSyncCommitteeMismatch,
    InvalidSignature,
    Bls(String),
}

impl std::fmt::Display for LightClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrustedBlockRootMismatch => write!(f, "trusted block root mismatch"),
            Self::InvalidCurrentSyncCommitteeBranch => {
                write!(f, "invalid current sync committee branch")
            }
            Self::InsufficientParticipants => write!(f, "insufficient sync committee participants"),
            Self::InvalidSlotOrder => write!(f, "invalid slot order in update"),
            Self::SignaturePeriodOutOfRange => write!(f, "signature period out of range"),
            Self::NotRelevant => write!(f, "update not relevant"),
            Self::InvalidFinalityBranch => write!(f, "invalid finality branch"),
            Self::InvalidNextSyncCommitteeBranch => {
                write!(f, "invalid next sync committee branch")
            }
            Self::NextSyncCommitteeMismatch => write!(f, "next sync committee mismatch"),
            Self::InvalidSignature => write!(f, "invalid BLS signature"),
            Self::Bls(msg) => write!(f, "BLS error: {msg}"),
        }
    }
}
