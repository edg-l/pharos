//! Altair light-client sync protocol functions.
//!
//! Per `specs/altair/light-client/sync-protocol.md`.
//!
//! Also covers the `full-node.md` create-* functions referenced in Phase 6
//! (Task 6.9).  The store functions are in this module because they are needed
//! by the Phase 4 conformance runner.

use pharos_ssz::{SszVector, TreeHash, build_single_proof_from_leaves};
use pharos_types::{
    BeaconSpec,
    altair::{
        BeaconBlock, BeaconState,
        light_client::{
            CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH, CURRENT_SYNC_COMMITTEE_GINDEX,
            FINALITY_BRANCH_DEPTH, FINALIZED_ROOT_GINDEX, LightClientBootstrap,
            LightClientFinalityUpdate, LightClientHeader, LightClientOptimisticUpdate,
            LightClientStore, LightClientUpdate, NEXT_SYNC_COMMITTEE_BRANCH_DEPTH,
            NEXT_SYNC_COMMITTEE_GINDEX,
        },
    },
    phase0::primitives::{Root, Slot},
};
use pharos_utils::{BLSPubkey, Bytes32, Hash256};

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
pub(crate) fn count_participants<const SYNC_COMMITTEE_SIZE: u64>(
    bits: &pharos_ssz::Bitvector<SYNC_COMMITTEE_SIZE>,
) -> u64 {
    bits.iter().filter(|b| *b).count() as u64
}

// ── Altair sync committee period helpers ──────────────────────────────────────

/// `compute_sync_committee_period(epoch)` = `epoch / EPOCHS_PER_SYNC_COMMITTEE_PERIOD`.
///
/// Per `specs/altair/beacon-chain.md`.
pub fn compute_sync_committee_period<E: BeaconSpec>(epoch: pharos_utils::Epoch) -> u64 {
    epoch.0 / E::EPOCHS_PER_SYNC_COMMITTEE_PERIOD
}

/// `compute_sync_committee_period_at_slot(slot)`.
///
/// Per `specs/altair/light-client/sync-protocol.md`.
pub fn compute_sync_committee_period_at_slot<E: BeaconSpec>(slot: Slot) -> u64 {
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
pub fn is_better_update<E: BeaconSpec, const SYNC_COMMITTEE_SIZE: u64>(
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
pub fn compute_fork_version<E: BeaconSpec>(epoch: pharos_utils::Epoch) -> [u8; 4] {
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
pub fn initialize_light_client_store<E: BeaconSpec, const SYNC_COMMITTEE_SIZE: u64>(
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
pub fn validate_light_client_update<E: BeaconSpec, const SYNC_COMMITTEE_SIZE: u64>(
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
pub fn apply_light_client_update<E: BeaconSpec, const SYNC_COMMITTEE_SIZE: u64>(
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
pub fn process_light_client_store_force_update<E: BeaconSpec, const SYNC_COMMITTEE_SIZE: u64>(
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
pub fn process_light_client_update<E: BeaconSpec, const SYNC_COMMITTEE_SIZE: u64>(
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

// ── block_to_light_client_header ─────────────────────────────────────────────

/// `block_to_light_client_header(block)` per
/// `specs/altair/light-client/full-node.md`.
///
/// Constructs a `LightClientHeader` from the block's fields.
pub fn block_to_light_client_header<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
>(
    block: &BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
) -> LightClientHeader
where
    pharos_types::altair::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: TreeHash,
{
    use pharos_types::phase0::operations::BeaconBlockHeader;
    LightClientHeader {
        beacon: BeaconBlockHeader {
            slot: block.slot,
            proposer_index: block.proposer_index,
            parent_root: block.parent_root,
            state_root: block.state_root,
            body_root: block.body.tree_hash_root(),
        },
    }
}

// ── BeaconState Merkle proof helpers ─────────────────────────────────────────

/// Compute the 24 per-field `tree_hash_root()` values for an altair `BeaconState`.
///
/// The altair `BeaconState` has 24 fields (field indices 0..23). The SSZ
/// Merkle tree pads these to 32 leaves (next power-of-two ≥ 24). Leaf at
/// position `k` (0-based in the padded array) is at generalized index 32+k.
///
/// Per `specs/altair/beacon-chain.md:159-188` field ordering.
fn beacon_state_field_hashes<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
>(
    state: &BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
) -> [Hash256; 24] {
    [
        state.genesis_time.tree_hash_root(),                  // 0
        state.genesis_validators_root.tree_hash_root(),       // 1
        state.slot.tree_hash_root(),                          // 2
        state.fork.tree_hash_root(),                          // 3
        state.latest_block_header.tree_hash_root(),           // 4
        state.block_roots.tree_hash_root(),                   // 5
        state.state_roots.tree_hash_root(),                   // 6
        state.historical_roots.tree_hash_root(),              // 7
        state.eth1_data.tree_hash_root(),                     // 8
        state.eth1_data_votes.tree_hash_root(),               // 9
        state.eth1_deposit_index.tree_hash_root(),            // 10
        state.validators.tree_hash_root(),                    // 11
        state.balances.tree_hash_root(),                      // 12
        state.randao_mixes.tree_hash_root(),                  // 13
        state.slashings.tree_hash_root(),                     // 14
        state.previous_epoch_participation.tree_hash_root(),  // 15
        state.current_epoch_participation.tree_hash_root(),   // 16
        state.justification_bits.tree_hash_root(),            // 17
        state.previous_justified_checkpoint.tree_hash_root(), // 18
        state.current_justified_checkpoint.tree_hash_root(),  // 19
        state.finalized_checkpoint.tree_hash_root(),          // 20
        state.inactivity_scores.tree_hash_root(),             // 21
        state.current_sync_committee.tree_hash_root(),        // 22
        state.next_sync_committee.tree_hash_root(),           // 23
    ]
}

/// Build a Merkle proof for `field_gindex` within an altair `BeaconState`.
///
/// The state has 24 fields padded to 32 in the SSZ tree. Only accepts
/// gindices in the range `[32, 55]` (direct state fields) and gindex 105
/// (`finalized_checkpoint.root`, a one-level-deep nested field).
///
/// Returns the branch as a `Vec<Bytes32>` whose length equals
/// `floor(log2(field_gindex))`.
pub(crate) fn compute_state_proof<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
>(
    state: &BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    field_gindex: u64,
) -> Vec<Bytes32> {
    let field_hashes = beacon_state_field_hashes(state);

    if (32..=55).contains(&field_gindex) {
        // Direct top-level field proof: gindex = 32 + field_index.
        let proof = build_single_proof_from_leaves(&field_hashes, field_gindex);
        proof.branch.into_iter().collect()
    } else if field_gindex == FINALIZED_ROOT_GINDEX {
        // gindex 105 = finalized_checkpoint.root.
        // Two-level proof:
        //   Level 1: prove finalized_checkpoint (field 20, gindex 52) within state.
        //   Level 2: prove root (field 1, gindex 3) within finalized_checkpoint.
        //
        // Per `floorlog2(105) = 6`:
        //   Branch has 6 elements: 1 from the checkpoint subtree + 5 from the state tree.

        // Level 2: proof of `root` (gindex 3) within Checkpoint.
        // Checkpoint has 2 fields: epoch (idx 0, gindex 2) and root (idx 1, gindex 3).
        let checkpoint_leaves = [
            state.finalized_checkpoint.epoch.tree_hash_root(),
            state.finalized_checkpoint.root.tree_hash_root(),
        ];
        let checkpoint_proof = build_single_proof_from_leaves(&checkpoint_leaves, 3);
        // checkpoint_proof.branch has length 1 (depth of gindex 3 = 1).

        // Level 1: proof of finalized_checkpoint (field 20, gindex 52) within state.
        let state_proof = build_single_proof_from_leaves(&field_hashes, 52);
        // state_proof.branch has length 5 (depth of gindex 52 = 5).

        // Combined branch: checkpoint branch first, then state branch.
        let mut branch: Vec<Bytes32> = Vec::with_capacity(6);
        for h in checkpoint_proof.branch {
            branch.push(h);
        }
        for h in state_proof.branch {
            branch.push(h);
        }
        branch
    } else {
        // Unsupported gindex; return empty branch.
        Vec::new()
    }
}

// ── update_light_client_snapshots ────────────────────────────────────────────

/// STF hook: build and persist light-client snapshots after each altair block.
///
/// Per `D-light-client-server-only` (Task 6.9) and Q-light-client-create-frequency:
/// - `LightClientBootstrap` is stored for each block.
/// - `LightClientOptimisticUpdate` is stored on each head update (every block).
/// - `LightClientFinalityUpdate` is stored on finality advance (every ~32 slots).
/// - `LightClientUpdate` (per period) is stored when the update is non-trivial.
///
/// This function is called by the node immediately after `state_transition`
/// completes. It propagates the store via its parameter (no global state).
///
/// `attested_state` and `attested_block` are the post-state and block of
/// `block.message.parent_root`. Pass `None` for `attested_state`/`attested_block`
/// when the parent state is unavailable (e.g. first block after checkpoint sync);
/// in that case, only the bootstrap and optimistic update are stored.
///
/// `finalized_block` is the block at `attested_state.finalized_checkpoint.root`,
/// pass `None` when unavailable.
pub fn update_light_client_snapshots<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E,
    S,
>(
    post_state: &BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    block: &BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    attested_state: Option<
        &BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
    attested_block: Option<
        &BeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
    finalized_block: Option<
        &BeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
    store: &S,
) where
    E: BeaconSpec<
            AltairLightClientBootstrap = LightClientBootstrap<SYNC_COMMITTEE_SIZE>,
            AltairLightClientUpdate = LightClientUpdate<SYNC_COMMITTEE_SIZE>,
            AltairLightClientFinalityUpdate = LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE>,
            AltairLightClientOptimisticUpdate = LightClientOptimisticUpdate<SYNC_COMMITTEE_SIZE>,
        >,
    pharos_types::altair::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: TreeHash,
    Bytes32: Default + Clone,
    S: pharos_storage::Store<E>,
{
    use pharos_ssz::TreeHash as _;
    use pharos_storage::Store as StoreT;

    // Compute block root for bootstrap keying.
    let block_root = block.tree_hash_root();

    // 1. Store LightClientBootstrap for this block.
    if let Some(bootstrap) = create_light_client_bootstrap(post_state, block) {
        let _ = StoreT::put_light_client_bootstrap(store, block_root, &bootstrap);
    }

    // 2. Build update from (block, attested_state, attested_block).
    let maybe_update = attested_state
        .zip(attested_block)
        .and_then(|(att_s, att_b)| {
            create_light_client_update::<
                MAX_PROPOSER_SLASHINGS,
                MAX_ATTESTER_SLASHINGS,
                MAX_ATTESTATIONS,
                MAX_DEPOSITS,
                MAX_VOLUNTARY_EXITS,
                MAX_VALIDATORS_PER_COMMITTEE,
                DEPOSIT_PROOF_LENGTH,
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
                E,
            >(post_state, block, att_s, att_b, finalized_block)
        });

    if let Some(update) = maybe_update {
        // 3. Store LightClientUpdate per sync-committee period (keeps best update).
        let period = compute_sync_committee_period_at_slot::<E>(update.attested_header.beacon.slot);
        let should_store = match StoreT::get_light_client_update(store, period) {
            Ok(Some(existing)) => is_better_update::<E, SYNC_COMMITTEE_SIZE>(&update, &existing),
            _ => true,
        };
        if should_store {
            let _ = StoreT::put_light_client_update(store, period, &update);
        }

        // 4. Store LightClientFinalityUpdate when finality_branch is non-zero.
        if is_finality_update(&update) {
            let finality_update = create_light_client_finality_update(&update);
            let _ = StoreT::put_light_client_finality_update(store, &finality_update);
        }

        // 5. Store LightClientOptimisticUpdate (every block = every head update).
        let optimistic_update = create_light_client_optimistic_update(&update);
        let _ = StoreT::put_light_client_optimistic_update(store, &optimistic_update);
    }
}

// ── create_light_client_bootstrap ────────────────────────────────────────────

/// `create_light_client_bootstrap(state, block)` per
/// `specs/altair/light-client/full-node.md`.
///
/// Constructs a `LightClientBootstrap` from the post-state and corresponding
/// signed beacon block. The state must be a post-Altair block's immediate
/// post-state.
///
/// Returns `None` if the block root / state root preconditions fail.
pub fn create_light_client_bootstrap<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
>(
    state: &BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    block: &BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
) -> Option<LightClientBootstrap<SYNC_COMMITTEE_SIZE>>
where
    pharos_types::altair::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: TreeHash,
    Bytes32: Default + Clone,
{
    // Precondition: state.slot == state.latest_block_header.slot.
    if state.slot != state.latest_block_header.slot {
        return None;
    }

    // Reconstruct the block root: patch latest_block_header with current state_root.
    let mut header = state.latest_block_header.clone();
    header.state_root = state.tree_hash_root();
    let block_root = header.tree_hash_root();

    // Verify this matches block's hash.
    if block_root != block.tree_hash_root() {
        return None;
    }

    // Build the current_sync_committee_branch (gindex 54, depth 5).
    let branch_hashes = compute_state_proof(state, CURRENT_SYNC_COMMITTEE_GINDEX);
    debug_assert_eq!(
        branch_hashes.len(),
        CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH as usize
    );
    let mut branch_vec: Vec<Bytes32> = branch_hashes;
    while branch_vec.len() < CURRENT_SYNC_COMMITTEE_BRANCH_DEPTH as usize {
        branch_vec.push(Bytes32::default());
    }
    let current_sync_committee_branch = SszVector::from_vec(branch_vec).unwrap_or_default();

    Some(LightClientBootstrap {
        header: block_to_light_client_header(block),
        current_sync_committee: state.current_sync_committee.clone(),
        current_sync_committee_branch,
    })
}

// ── create_light_client_update ────────────────────────────────────────────────

/// `create_light_client_update(state, block, attested_state, attested_block,
///  finalized_block)` per `specs/altair/light-client/full-node.md`.
///
/// Constructs a `LightClientUpdate` for a given block and its parent
/// (attested) block. `finalized_block` is `None` when unavailable (e.g.
/// after checkpoint sync).
pub fn create_light_client_update<
    const MAX_PROPOSER_SLASHINGS: u64,
    const MAX_ATTESTER_SLASHINGS: u64,
    const MAX_ATTESTATIONS: u64,
    const MAX_DEPOSITS: u64,
    const MAX_VOLUNTARY_EXITS: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    const DEPOSIT_PROOF_LENGTH: u64,
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E: BeaconSpec,
>(
    _state: &BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    block: &BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    attested_state: &BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    attested_block: &BeaconBlock<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    finalized_block: Option<
        &BeaconBlock<
            MAX_PROPOSER_SLASHINGS,
            MAX_ATTESTER_SLASHINGS,
            MAX_ATTESTATIONS,
            MAX_DEPOSITS,
            MAX_VOLUNTARY_EXITS,
            MAX_VALIDATORS_PER_COMMITTEE,
            DEPOSIT_PROOF_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
) -> Option<LightClientUpdate<SYNC_COMMITTEE_SIZE>>
where
    pharos_types::altair::BeaconBlockBody<
        MAX_PROPOSER_SLASHINGS,
        MAX_ATTESTER_SLASHINGS,
        MAX_ATTESTATIONS,
        MAX_DEPOSITS,
        MAX_VOLUNTARY_EXITS,
        MAX_VALIDATORS_PER_COMMITTEE,
        DEPOSIT_PROOF_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >: TreeHash,
    Bytes32: Default + Clone,
{
    // Verify sync_aggregate has enough participants.
    let n_participants = count_participants(&block.body.sync_aggregate.sync_committee_bits);
    if n_participants < MIN_SYNC_COMMITTEE_PARTICIPANTS {
        return None;
    }

    // Derive update_signature_period from block.slot.
    let update_signature_period = compute_sync_committee_period_at_slot::<E>(block.slot);

    // Precondition: attested_state.slot == attested_state.latest_block_header.slot.
    if attested_state.slot != attested_state.latest_block_header.slot {
        return None;
    }
    let mut attested_header = attested_state.latest_block_header.clone();
    attested_header.state_root = attested_state.tree_hash_root();
    let attested_block_root = attested_header.tree_hash_root();
    if attested_block_root != attested_block.tree_hash_root() {
        return None;
    }
    if attested_block_root != block.parent_root {
        return None;
    }

    let update_attested_period = compute_sync_committee_period_at_slot::<E>(attested_block.slot);

    // Compute next_sync_committee branch when attested and signature periods match.
    let (next_sync_committee, next_sync_committee_branch) =
        if update_attested_period == update_signature_period {
            let nsc_branch_hashes = compute_state_proof(attested_state, NEXT_SYNC_COMMITTEE_GINDEX);
            let mut nsc_vec: Vec<Bytes32> = nsc_branch_hashes;
            while nsc_vec.len() < NEXT_SYNC_COMMITTEE_BRANCH_DEPTH as usize {
                nsc_vec.push(Bytes32::default());
            }
            (
                attested_state.next_sync_committee.clone(),
                SszVector::from_vec(nsc_vec).unwrap_or_default(),
            )
        } else {
            Default::default()
        };

    // Compute finality header and branch when finalized_block is available.
    let (finalized_header, finality_branch) = if let Some(fin_block) = finalized_block {
        let header = if fin_block.slot.0 != 0 {
            block_to_light_client_header(fin_block)
        } else {
            LightClientHeader::default()
        };
        let fin_branch_hashes = compute_state_proof(attested_state, FINALIZED_ROOT_GINDEX);
        let mut fin_vec: Vec<Bytes32> = fin_branch_hashes;
        while fin_vec.len() < FINALITY_BRANCH_DEPTH as usize {
            fin_vec.push(Bytes32::default());
        }
        (header, SszVector::from_vec(fin_vec).unwrap_or_default())
    } else {
        Default::default()
    };

    Some(LightClientUpdate {
        attested_header: block_to_light_client_header(attested_block),
        next_sync_committee,
        next_sync_committee_branch,
        finalized_header,
        finality_branch,
        sync_aggregate: block.body.sync_aggregate.clone(),
        signature_slot: block.slot,
    })
}

// ── create_light_client_finality_update ───────────────────────────────────────

/// `create_light_client_finality_update(update)` per
/// `specs/altair/light-client/full-node.md`.
///
/// Derives a `LightClientFinalityUpdate` from a `LightClientUpdate`.
pub fn create_light_client_finality_update<const SYNC_COMMITTEE_SIZE: u64>(
    update: &LightClientUpdate<SYNC_COMMITTEE_SIZE>,
) -> LightClientFinalityUpdate<SYNC_COMMITTEE_SIZE>
where
    Bytes32: Default + Clone,
{
    LightClientFinalityUpdate {
        attested_header: update.attested_header.clone(),
        finalized_header: update.finalized_header.clone(),
        finality_branch: update.finality_branch.clone(),
        sync_aggregate: update.sync_aggregate.clone(),
        signature_slot: update.signature_slot,
    }
}

// ── create_light_client_optimistic_update ─────────────────────────────────────

/// `create_light_client_optimistic_update(update)` per
/// `specs/altair/light-client/full-node.md`.
///
/// Derives a `LightClientOptimisticUpdate` from a `LightClientUpdate`.
pub fn create_light_client_optimistic_update<const SYNC_COMMITTEE_SIZE: u64>(
    update: &LightClientUpdate<SYNC_COMMITTEE_SIZE>,
) -> LightClientOptimisticUpdate<SYNC_COMMITTEE_SIZE> {
    LightClientOptimisticUpdate {
        attested_header: update.attested_header.clone(),
        sync_aggregate: update.sync_aggregate.clone(),
        signature_slot: update.signature_slot,
    }
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
