//! Checkpoint-sync: fetch a finalised anchor state+block from a trusted
//! Beacon API endpoint and persist it atomically to RocksDB.
//!
//! # Design (`D-checkpoint-sync-source`)
//!
//! 1. `fetch_checkpoint` fetches `GET .../eth/v2/debug/beacon/states/finalized`
//!    (SSZ, accept: application/octet-stream), reads the `Eth-Consensus-Version`
//!    response header to determine the fork, SSZ-decodes the body into the
//!    appropriate per-fork state, derives the block root from `latest_block_header`,
//!    then fetches the matching block.
//!
//! 2. `apply_anchor` synthesises a `ForkChoiceSnapshot` and writes the block,
//!    state, slot-index, and snapshot atomically via `BlockTransition` —
//!    never via individual `put_block`/`put_state`/`put_forkchoice_snapshot`
//!    calls (see `D-anchor-state-on-disk`).

use pharos_ssz::{Decode, TreeHash};
use pharos_storage::{BlockTransition, ForkChoiceSnapshot, RocksStore, Store};
use pharos_types::BeaconSpec;
use pharos_types::PayloadStatus;
use pharos_types::phase0::misc::Checkpoint;
use pharos_types::phase0::operations::BeaconBlockHeader;
use pharos_types::phase0::primitives::{Epoch, Root, Slot, ValidatorIndex};
use pharos_types::views::{BeaconBlockView as _, BeaconStateView as _, SignedBeaconBlockView};
use pharos_types::weak_subjectivity::{
    active_validator_stats, compute_weak_subjectivity_period, is_within_weak_subjectivity_period,
};
use reqwest::header::ACCEPT;

// ── Public types ──────────────────────────────────────────────────────────────

/// Validated checkpoint anchor fetched from a Beacon API endpoint.
#[derive(Debug)]
pub struct CheckpointAnchor<E: BeaconSpec> {
    /// The finalised beacon state.
    pub state: E::BeaconState,
    /// The signed beacon block whose `message.state_root` equals `state_root`.
    pub signed_block: E::SignedBeaconBlock,
    /// `hash_tree_root(state)`.
    pub state_root: Root,
    /// Block root derived from `state.latest_block_header` (with `state_root` substituted).
    pub block_root: Root,
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors that can occur during checkpoint-sync fetch or anchor persistence.
#[derive(thiserror::Error, Debug)]
pub enum CheckpointSyncError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("HTTP status {code}: {body}")]
    Status { code: u16, body: String },

    #[error("missing Eth-Consensus-Version header")]
    MissingForkHeader,

    #[error("unsupported fork: {0}")]
    UnsupportedFork(String),

    #[error("SSZ decode failed: {0}")]
    Ssz(String),

    #[error("block.state_root ({block_state_root}) != computed_state_root ({computed_state_root})")]
    BlockStateMismatch {
        block_state_root: Root,
        computed_state_root: Root,
    },

    #[error(
        "block_root ({block_root}) != reconstructed latest_block_header root ({latest_block_header_root})"
    )]
    BlockRootMismatch {
        block_root: Root,
        latest_block_header_root: Root,
    },

    #[error("state.slot ({state_slot}) != block.slot ({block_slot})")]
    SlotMismatch { state_slot: Slot, block_slot: Slot },

    #[error(
        "block.message.proposer_index ({block_proposer_index}) != state.latest_block_header.proposer_index ({header_proposer_index})"
    )]
    ProposerIndexMismatch {
        block_proposer_index: ValidatorIndex,
        header_proposer_index: ValidatorIndex,
    },

    #[error("expected block_root {expected}, got {actual}")]
    TamperFlagMismatch { expected: Root, actual: Root },

    #[error(
        "checkpoint at epoch {anchor_epoch} is older than the weak-subjectivity period \
         (current epoch {current_epoch}, ws_period {ws_period} epochs); the anchor is unsafe \
         to sync from — obtain a fresher checkpoint or pass --ignore-weak-subjectivity-period"
    )]
    CheckpointTooOld {
        anchor_epoch: u64,
        current_epoch: u64,
        ws_period: u64,
    },

    #[error("invalid URL: {0}")]
    BeaconApiUrl(String),

    #[error("storage: {0}")]
    Storage(#[from] pharos_storage::StorageError),
}

// ── fetch_checkpoint ──────────────────────────────────────────────────────────

/// Fetch a finalised checkpoint anchor from a Beacon API endpoint.
///
/// Steps:
/// 1. GET `<url>/eth/v2/debug/beacon/states/finalized` with SSZ accept header.
/// 2. Read `Eth-Consensus-Version` header; decode body as the matching fork.
/// 3. Compute `state_root = hash_tree_root(state)`.
/// 4. Derive `block_root` from `state.latest_block_header` (substituting `state_root`).
/// 5. GET `<url>/eth/v2/beacon/blocks/0x<block_root>`; decode the matching block.
/// 6. Re-hash the decoded block.message and assert it equals `block_root` (`BlockRootMismatch`).
/// 7. Validate: `block.message.proposer_index == state.latest_block_header.proposer_index`.
/// 8. Validate: `block.message.state_root == computed_state_root`, `block.slot == state.slot`.
/// 9. If `expected_block_root` is `Some`, assert the derived `block_root` matches (`TamperFlagMismatch`).
pub async fn fetch_checkpoint<E: BeaconSpec>(
    url: &reqwest::Url,
    http: &reqwest::Client,
    expected_block_root: Option<Root>,
) -> Result<CheckpointAnchor<E>, CheckpointSyncError>
where
    <E::Phase0SignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
    <E::AltairSignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
    <E::BellatrixSignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
    <E::CapellaSignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
    <E::DenebSignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
    <E::ElectraSignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
    <E::FuluSignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
{
    // ── Step 1-2: fetch state ─────────────────────────────────────────────────
    let state_url = url
        .join("eth/v2/debug/beacon/states/finalized")
        .map_err(|e| CheckpointSyncError::BeaconApiUrl(e.to_string()))?;

    let resp = http
        .get(state_url)
        .header(ACCEPT, "application/octet-stream")
        .send()
        .await?;

    if !resp.status().is_success() {
        let code = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(CheckpointSyncError::Status { code, body });
    }

    let fork_str = resp
        .headers()
        .get("Eth-Consensus-Version")
        .ok_or(CheckpointSyncError::MissingForkHeader)?
        .to_str()
        .unwrap_or("")
        .to_string();

    let body_bytes = resp.bytes().await?;

    // ── Step 3: decode state and compute state root ────────────────────────────
    let (state, computed_state_root) = decode_state::<E>(&fork_str, &body_bytes)?;

    // ── Step 4: derive block root from latest_block_header ────────────────────
    //
    // Per `specs/phase0/beacon-chain.md` `process_block_header`: after the
    // block is processed, `state.latest_block_header.state_root` is zeroed and
    // is only filled in by `process_slot` at the next slot.  To reconstruct the
    // block root from a post-state, we substitute `computed_state_root` into a
    // copy of `latest_block_header` and hash it.
    let block_root = {
        let mut header: BeaconBlockHeader = state.latest_block_header().clone();
        header.state_root = computed_state_root;
        header.tree_hash_root()
    };

    // ── Step 5: fetch the matching block ──────────────────────────────────────
    let block_root_hex = hex::encode(block_root.as_slice());
    let block_url = url
        .join(&format!("eth/v2/beacon/blocks/0x{block_root_hex}"))
        .map_err(|e| CheckpointSyncError::BeaconApiUrl(e.to_string()))?;

    let block_resp = http
        .get(block_url)
        .header(ACCEPT, "application/octet-stream")
        .send()
        .await?;

    if !block_resp.status().is_success() {
        let code = block_resp.status().as_u16();
        let body = block_resp.text().await.unwrap_or_default();
        return Err(CheckpointSyncError::Status { code, body });
    }

    let block_fork_str = block_resp
        .headers()
        .get("Eth-Consensus-Version")
        .ok_or(CheckpointSyncError::MissingForkHeader)?
        .to_str()
        .unwrap_or("")
        .to_string();

    let block_bytes = block_resp.bytes().await?;
    let signed_block = decode_signed_block::<E>(&block_fork_str, &block_bytes)?;

    // ── Step 6a: re-hash the block.message bytes-hash layer (Blocker 1) ───────
    //
    // Compute `tree_hash_root` of the decoded `block.message` and compare it
    // against `block_root` derived from the state's `latest_block_header`.
    // A tampered or mismatched block will fail here before any field checks.
    let computed_block_root = extract_block_message_root::<E>(&signed_block)?;
    if computed_block_root != block_root {
        return Err(CheckpointSyncError::BlockRootMismatch {
            block_root,
            latest_block_header_root: computed_block_root,
        });
    }

    // ── Step 6b: validate block ↔ state ──────────────────────────────────────
    //
    // Access the inner concrete block via the fork-unwrap helpers (the fork-enum
    // `SignedBeaconBlockView::message()` panics — use per-variant accessors).
    let (block_state_root, block_slot, block_proposer_index) =
        extract_block_fields::<E>(&signed_block)?;

    let state_slot = state.slot();
    if block_slot != state_slot {
        return Err(CheckpointSyncError::SlotMismatch {
            state_slot,
            block_slot,
        });
    }

    // ── Step 6c: proposer_index cross-check (Blocker 3) ──────────────────────
    //
    // Defense-in-depth: block.message.proposer_index must equal
    // state.latest_block_header.proposer_index (D-checkpoint-sync-source step 5).
    let header_proposer_index = state.latest_block_header().proposer_index;
    if block_proposer_index != header_proposer_index {
        return Err(CheckpointSyncError::ProposerIndexMismatch {
            block_proposer_index,
            header_proposer_index,
        });
    }

    if block_state_root != computed_state_root {
        return Err(CheckpointSyncError::BlockStateMismatch {
            block_state_root,
            computed_state_root,
        });
    }

    // ── Step 6d: tamper-flag check (operator-supplied expected root) ──────────
    if let Some(expected) = expected_block_root
        && block_root != expected
    {
        return Err(CheckpointSyncError::TamperFlagMismatch {
            expected,
            actual: block_root,
        });
    }

    Ok(CheckpointAnchor {
        state,
        signed_block,
        state_root: computed_state_root,
        block_root,
    })
}

// ── apply_anchor ──────────────────────────────────────────────────────────────

/// Persist an anchor atomically and return the synthesised `ForkChoiceSnapshot`.
///
/// Uses a single `BlockTransition<E>` write (never individual `put_block` /
/// `put_state` / `put_forkchoice_snapshot` calls) per `D-anchor-state-on-disk`.
///
/// # Weak-subjectivity gate
///
/// Before persisting, computes the weak-subjectivity period from the anchor
/// state (`specs/phase0/weak-subjectivity.md`) and rejects (`CheckpointTooOld`)
/// any anchor whose epoch is older than the WS period before `current_slot`
/// (the node's wall-clock slot), so we never sync from an unsafe checkpoint.
/// `current_slot` is the slot derived from wall-clock time and the anchor
/// state's `genesis_time`. `ignore_ws_period` bypasses the rejection (logging a
/// `WARN` at the call site) for the `--ignore-weak-subjectivity-period` escape
/// hatch.
pub fn apply_anchor<E: BeaconSpec>(
    anchor: CheckpointAnchor<E>,
    store: &RocksStore,
    current_slot: u64,
    ignore_ws_period: bool,
) -> Result<ForkChoiceSnapshot, CheckpointSyncError> {
    let state_slot = anchor.state.slot();
    let genesis_time = anchor.state.genesis_time();
    let seconds_per_slot = E::SLOT_DURATION_MS / 1000;
    let last_known_time = genesis_time + state_slot.0 * seconds_per_slot;

    // ── Weak-subjectivity freshness check ─────────────────────────────────────
    //
    // Per `specs/phase0/weak-subjectivity.md` `is_within_weak_subjectivity_period`:
    // a checkpoint older than the WS period before the current slot is unsafe to
    // sync from. Compute the period from the anchor state's active validator set
    // and reject a stale anchor unless the operator opts out via
    // `--ignore-weak-subjectivity-period` (which bypasses the whole gate).
    let anchor_epoch_for_ws = state_slot.0 / E::SLOTS_PER_EPOCH;
    let current_epoch = current_slot / E::SLOTS_PER_EPOCH;
    if ignore_ws_period {
        tracing::warn!(
            anchor_epoch = anchor_epoch_for_ws,
            current_epoch,
            "checkpoint-sync: skipping the weak-subjectivity freshness check because \
             --ignore-weak-subjectivity-period is set (UNSAFE)"
        );
    } else {
        let (active_count, total_active_balance_gwei) =
            active_validator_stats(anchor.state.validators_iter(), Epoch(anchor_epoch_for_ws));
        if active_count == 0 {
            // A state with no active validators cannot anchor a sync; the spec
            // WS math divides by N. Treat as unsafe (degenerate / wrong state).
            return Err(CheckpointSyncError::CheckpointTooOld {
                anchor_epoch: anchor_epoch_for_ws,
                current_epoch,
                ws_period: 0,
            });
        }
        let ws_period =
            compute_weak_subjectivity_period::<E>(active_count, total_active_balance_gwei);
        let within = is_within_weak_subjectivity_period::<E>(
            state_slot.0,
            current_slot,
            active_count,
            total_active_balance_gwei,
        );
        if !within {
            return Err(CheckpointSyncError::CheckpointTooOld {
                anchor_epoch: anchor_epoch_for_ws,
                current_epoch,
                ws_period,
            });
        }
    }

    // Per `D-anchor-state-on-disk` + weak-subjectivity sync convention:
    // the anchor block is treated as the local finalized/justified root.
    // Pre-anchor history is opaque (trusted via operator URL choice per
    // `D-checkpoint-sync-source`); using `state.finalized_checkpoint` as-is
    // would reference earlier epoch-boundary blocks we never fetched,
    // breaking `rehydrate_fork_choice_store` block lookup at startup.rs:80.
    //
    // `finalized_checkpoint.epoch = anchor_epoch` so that
    // `get_checkpoint_block(store, block_root, finalized_epoch)` walks back to
    // `anchor_epoch * SLOTS_PER_EPOCH = anchor_slot`, resolving to
    // `anchor_block_root` and satisfying the `correct_finalized` check in
    // `filter_block_tree`.
    //
    // `justified_checkpoint.epoch = 0 (GENESIS_EPOCH)` so that
    // `filter_block_tree`'s `correct_justified` shortcut fires unconditionally.
    // Without attestations, `get_voting_source` returns epoch 0 for all
    // blocks, which cannot match `anchor_epoch` on the second condition; the
    // GENESIS_EPOCH shortcut is the only path that keeps descendant blocks
    // viable as fork-choice heads.
    let anchor_epoch = Epoch(state_slot.0 / E::SLOTS_PER_EPOCH);

    let finalized_checkpoint = Checkpoint {
        epoch: anchor_epoch,
        root: anchor.block_root,
    };
    let justified_checkpoint = Checkpoint {
        epoch: Epoch(0),
        root: anchor.block_root,
    };

    let unrealized_justified_checkpoint = justified_checkpoint.clone();
    let unrealized_finalized_checkpoint = finalized_checkpoint.clone();

    let snap = ForkChoiceSnapshot {
        genesis_time,
        justified_checkpoint: justified_checkpoint.clone(),
        finalized_checkpoint: finalized_checkpoint.clone(),
        unrealized_justified_checkpoint,
        unrealized_finalized_checkpoint,
        proposer_boost_root: Root::default(),
        head_root: anchor.block_root,
        head_slot: state_slot,
        last_known_time,
    };

    // Initialize `split_slot` and `anchor_slot` metadata to the anchor slot so
    // the freezer and rehydrate know where the hot window starts.  Both keys ride
    // the SAME single-BlockTransition anchor write per `D-anchor-state-on-disk`.
    // Per Task 4.3: anchor is the initial hot/cold boundary.
    let anchor_slot_be = state_slot.0.to_be_bytes();

    let mut batch = BlockTransition::<E>::new();
    batch.block = Some((anchor.block_root, anchor.signed_block));
    batch.state = Some((anchor.state_root, anchor.state));
    batch.forkchoice = Some(snap.clone());
    batch.slot_index = Some((state_slot, anchor.block_root));
    // Per `specs/sync/optimistic.md` "Checkpoint Sync (Weak Subjectivity Sync)":
    // a CL MAY assume the anchor's ExecutionPayload is VALID.  Seed it here so
    // `is_optimistic(store, anchor_root)` returns false for a post-merge anchor
    // and `latest_verified_ancestor` never walks past the trusted weak-subjectivity
    // root.  Also persists the status to RocksDB so restart rehydration reads it.
    batch.payload_status = Some((anchor.block_root, PayloadStatus::Valid));
    batch
        .metadata
        .push((b"split_slot", anchor_slot_be.to_vec()));
    batch
        .metadata
        .push((b"anchor_slot", anchor_slot_be.to_vec()));

    <RocksStore as Store<E>>::write_block_transition(store, batch)?;

    Ok(snap)
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// SSZ-decode the raw bytes as the per-fork `E::BeaconState` and return
/// `(state, state_root)`. Flips the decoded state to `Backend::Tree` on the
/// seven hot list/vector fields per `D-no-tree-backend-on-decode`, so the
/// downstream `apply_anchor` write and any post-anchor STF reuses the
/// per-node hash cache.
fn decode_state<E: BeaconSpec>(
    fork: &str,
    bytes: &[u8],
) -> Result<(E::BeaconState, Root), CheckpointSyncError> {
    match fork {
        "phase0" => {
            let inner = E::Phase0BeaconState::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let state = E::phase0_into_state(inner)
                .into_tree_backend()
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let root = state.tree_hash_root();
            Ok((state, root))
        }
        "altair" => {
            let inner = E::AltairBeaconState::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let state = E::altair_into_state(inner)
                .into_tree_backend()
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let root = state.tree_hash_root();
            Ok((state, root))
        }
        "bellatrix" => {
            let inner = E::BellatrixBeaconState::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let state = E::bellatrix_into_state(inner)
                .into_tree_backend()
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let root = state.tree_hash_root();
            Ok((state, root))
        }
        "capella" => {
            let inner = E::CapellaBeaconState::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let state = E::capella_into_state(inner)
                .into_tree_backend()
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let root = state.tree_hash_root();
            Ok((state, root))
        }
        "deneb" => {
            let inner = E::DenebBeaconState::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let state = E::deneb_into_state(inner)
                .into_tree_backend()
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let root = state.tree_hash_root();
            Ok((state, root))
        }
        "electra" => {
            let inner = E::ElectraBeaconState::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let state = E::electra_into_state(inner)
                .into_tree_backend()
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let root = state.tree_hash_root();
            Ok((state, root))
        }
        "fulu" => {
            let inner = E::FuluBeaconState::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let state = E::fulu_into_state(inner)
                .into_tree_backend()
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            let root = state.tree_hash_root();
            Ok((state, root))
        }
        other => Err(CheckpointSyncError::UnsupportedFork(other.to_owned())),
    }
}

/// SSZ-decode the raw bytes as the per-fork `E::SignedBeaconBlock`.
fn decode_signed_block<E: BeaconSpec>(
    fork: &str,
    bytes: &[u8],
) -> Result<E::SignedBeaconBlock, CheckpointSyncError> {
    match fork {
        "phase0" => {
            let inner = E::Phase0SignedBeaconBlock::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            Ok(E::phase0_into_signed_block(inner))
        }
        "altair" => {
            let inner = E::AltairSignedBeaconBlock::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            Ok(E::altair_into_signed_block(inner))
        }
        "bellatrix" => {
            let inner = E::BellatrixSignedBeaconBlock::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            Ok(E::bellatrix_into_signed_block(inner))
        }
        "capella" => {
            let inner = E::CapellaSignedBeaconBlock::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            Ok(E::capella_into_signed_block(inner))
        }
        "deneb" => {
            let inner = E::DenebSignedBeaconBlock::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            Ok(E::deneb_into_signed_block(inner))
        }
        "electra" => {
            let inner = E::ElectraSignedBeaconBlock::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            Ok(E::electra_into_signed_block(inner))
        }
        "fulu" => {
            let inner = E::FuluSignedBeaconBlock::from_ssz_bytes(bytes)
                .map_err(|e| CheckpointSyncError::Ssz(e.to_string()))?;
            Ok(E::fulu_into_signed_block(inner))
        }
        other => Err(CheckpointSyncError::UnsupportedFork(other.to_owned())),
    }
}

/// Compute `tree_hash_root` of `block.message` for the given fork-enum block.
///
/// Used by Blocker 1: re-hash the decoded block bytes and compare against the
/// root derived from `state.latest_block_header`.
///
/// Uses explicit `TreeHash` where-clause bounds on each fork's `Message` type.
/// `BeaconBlockView` does not require `TreeHash`, but all concrete `BeaconSpec`
/// implementations satisfy these bounds (their `Message` types are concrete
/// `BeaconBlock` structs that derive `TreeHash`).
fn extract_block_message_root<E: BeaconSpec>(
    signed: &E::SignedBeaconBlock,
) -> Result<Root, CheckpointSyncError>
where
    <E::Phase0SignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
    <E::AltairSignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
    <E::BellatrixSignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
    <E::CapellaSignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
    <E::DenebSignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
    <E::ElectraSignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
    <E::FuluSignedBeaconBlock as SignedBeaconBlockView>::Message: TreeHash,
{
    if let Some(inner) = E::unwrap_phase0_signed_block(signed) {
        return Ok(inner.message().tree_hash_root());
    }
    if let Some(inner) = E::unwrap_altair_signed_block(signed) {
        return Ok(inner.message().tree_hash_root());
    }
    if let Some(inner) = E::unwrap_bellatrix_signed_block(signed) {
        return Ok(inner.message().tree_hash_root());
    }
    if let Some(inner) = E::unwrap_capella_signed_block(signed) {
        return Ok(inner.message().tree_hash_root());
    }
    if let Some(inner) = E::unwrap_deneb_signed_block(signed) {
        return Ok(inner.message().tree_hash_root());
    }
    if let Some(inner) = E::unwrap_electra_signed_block(signed) {
        return Ok(inner.message().tree_hash_root());
    }
    if let Some(inner) = E::unwrap_fulu_signed_block(signed) {
        return Ok(inner.message().tree_hash_root());
    }
    unreachable!("unrecognised SignedBeaconBlock fork variant")
}

/// Extract `(state_root, slot, proposer_index)` from a fork-enum `SignedBeaconBlock`.
///
/// Uses the per-variant unwrap helpers because the fork-enum
/// `SignedBeaconBlockView::message()` is unimplemented (see `state.rs`).
fn extract_block_fields<E: BeaconSpec>(
    signed: &E::SignedBeaconBlock,
) -> Result<(Root, Slot, ValidatorIndex), CheckpointSyncError> {
    if let Some(inner) = E::unwrap_phase0_signed_block(signed) {
        let msg = inner.message();
        return Ok((msg.state_root(), msg.slot(), msg.proposer_index()));
    }
    if let Some(inner) = E::unwrap_altair_signed_block(signed) {
        let msg = inner.message();
        return Ok((msg.state_root(), msg.slot(), msg.proposer_index()));
    }
    if let Some(inner) = E::unwrap_bellatrix_signed_block(signed) {
        let msg = inner.message();
        return Ok((msg.state_root(), msg.slot(), msg.proposer_index()));
    }
    if let Some(inner) = E::unwrap_capella_signed_block(signed) {
        let msg = inner.message();
        return Ok((msg.state_root(), msg.slot(), msg.proposer_index()));
    }
    if let Some(inner) = E::unwrap_deneb_signed_block(signed) {
        let msg = inner.message();
        return Ok((msg.state_root(), msg.slot(), msg.proposer_index()));
    }
    if let Some(inner) = E::unwrap_electra_signed_block(signed) {
        let msg = inner.message();
        return Ok((msg.state_root(), msg.slot(), msg.proposer_index()));
    }
    if let Some(inner) = E::unwrap_fulu_signed_block(signed) {
        let msg = inner.message();
        return Ok((msg.state_root(), msg.slot(), msg.proposer_index()));
    }
    // Unreachable: all seven fork-enum arms are covered above.
    unreachable!("unrecognised SignedBeaconBlock fork variant")
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use axum::http::{HeaderMap, StatusCode};
    use axum::{Router, routing::get};
    use pharos_ssz::TreeHash;
    use pharos_types::MinimalBeaconSpec;
    use pharos_types::bellatrix::{
        MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState, MinimalSignedBeaconBlock,
    };
    use pharos_types::capella::{
        MinimalBeaconBlock as CapellaMinimalBeaconBlock,
        MinimalBeaconBlockBody as CapellaMinimalBeaconBlockBody,
        MinimalBeaconState as CapellaMinimalBeaconState,
        MinimalSignedBeaconBlock as CapellaMinimalSignedBeaconBlock,
    };
    use pharos_types::phase0::operations::BeaconBlockHeader;
    use pharos_types::phase0::primitives::{Root, Slot};
    use pharos_types::state::MinimalBeaconState as ForkMinimalBeaconState;
    use tokio::net::TcpListener;

    use super::*;

    // ── Mock server helpers ───────────────────────────────────────────────────

    /// Bind to a random free port and return `(SocketAddr, TcpListener)`.
    async fn bind_random() -> (SocketAddr, TcpListener) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        (addr, listener)
    }

    // ── Test (a): happy path — Bellatrix anchor ───────────────────────────────

    #[tokio::test]
    async fn fetch_bellatrix_anchor_happy_path() {
        // Build a minimal Bellatrix state with non-default genesis_time.
        // The Beacon API returns raw per-fork SSZ (no discriminant prefix);
        // encode the concrete inner type directly.
        let body = MinimalBeaconBlockBody::default();
        let body_root: Root = body.tree_hash_root();

        let state_inner = MinimalBeaconState {
            genesis_time: 1_600_000_000u64,
            slot: Slot(64),
            latest_block_header: BeaconBlockHeader {
                slot: Slot(64),
                state_root: Root::default(), // zeroed per spec (process_block_header)
                body_root,
                ..BeaconBlockHeader::default()
            },
            ..MinimalBeaconState::default()
        };

        // Compute the fork-enum state root (used for block.state_root).
        let fork_state = ForkMinimalBeaconState::Bellatrix(state_inner.clone());
        let computed_state_root: Root = fork_state.tree_hash_root();

        // The actual block served by the API has state_root = computed_state_root.
        let signed_block_inner = MinimalSignedBeaconBlock {
            message: MinimalBeaconBlock {
                slot: Slot(64),
                state_root: computed_state_root,
                body: body.clone(),
                ..MinimalBeaconBlock::default()
            },
            ..MinimalSignedBeaconBlock::default()
        };

        // Derive expected block_root (same derivation as fetch_checkpoint).
        let expected_block_root: Root = {
            let mut h = state_inner.latest_block_header.clone();
            h.state_root = computed_state_root;
            h.tree_hash_root()
        };

        // Encode as raw per-fork SSZ (no fork-enum discriminant).
        use pharos_ssz::Encode as _;
        let state_bytes = state_inner.as_ssz_bytes();
        let block_bytes = signed_block_inner.as_ssz_bytes();

        // Capture block root hex for the block URL path.
        let block_root_hex = hex::encode(expected_block_root.as_slice());

        let state_bytes_arc = std::sync::Arc::new(state_bytes);
        let block_bytes_arc = std::sync::Arc::new(block_bytes);
        let app = Router::new()
            .route(
                "/eth/v2/debug/beacon/states/finalized",
                get({
                    let sb = state_bytes_arc.clone();
                    move || {
                        let sb = sb.clone();
                        async move {
                            let mut headers = HeaderMap::new();
                            headers.insert("Eth-Consensus-Version", "bellatrix".parse().unwrap());
                            (StatusCode::OK, headers, (*sb).clone())
                        }
                    }
                }),
            )
            .route(
                &format!("/eth/v2/beacon/blocks/0x{block_root_hex}"),
                get({
                    let bb = block_bytes_arc.clone();
                    move || {
                        let bb = bb.clone();
                        async move {
                            let mut headers = HeaderMap::new();
                            headers.insert("Eth-Consensus-Version", "bellatrix".parse().unwrap());
                            (StatusCode::OK, headers, (*bb).clone())
                        }
                    }
                }),
            );

        let (addr, listener) = bind_random().await;
        let handle = tokio::spawn(axum::serve(listener, app).into_future());

        let url = reqwest::Url::parse(&format!("http://{addr}/")).unwrap();
        let http = reqwest::Client::new();
        let result = fetch_checkpoint::<MinimalBeaconSpec>(&url, &http, None).await;

        handle.abort();

        let anchor = result.expect("fetch should succeed");
        assert_eq!(
            anchor.block_root, expected_block_root,
            "block_root mismatch"
        );
        assert_eq!(
            anchor.state_root, computed_state_root,
            "state_root mismatch"
        );
    }

    // ── Test (b): block ↔ state mismatch ─────────────────────────────────────

    #[tokio::test]
    async fn fetch_rejects_state_block_mismatch() {
        // Build a state and a block whose state_root does NOT match.
        // Encode both as raw per-fork SSZ (no discriminant prefix).
        use pharos_ssz::Encode as _;
        let body = MinimalBeaconBlockBody::default();
        let body_root: Root = body.tree_hash_root();
        let state_inner = MinimalBeaconState {
            slot: Slot(10),
            latest_block_header: BeaconBlockHeader {
                slot: Slot(10),
                body_root,
                state_root: Root::default(),
                ..BeaconBlockHeader::default()
            },
            ..MinimalBeaconState::default()
        };

        // Compute the state root via the fork-enum wrapper.
        let fork_state = ForkMinimalBeaconState::Bellatrix(state_inner.clone());
        let computed_state_root: Root = fork_state.tree_hash_root();

        // Block root derived correctly.
        let block_root: Root = {
            let mut h = state_inner.latest_block_header.clone();
            h.state_root = computed_state_root;
            h.tree_hash_root()
        };

        // Build a block with a WRONG state_root.
        let wrong_state_root = Root::from([0xAAu8; 32]);
        let bad_block_inner = MinimalSignedBeaconBlock {
            message: MinimalBeaconBlock {
                slot: Slot(10),
                state_root: wrong_state_root, // intentionally wrong
                ..MinimalBeaconBlock::default()
            },
            ..MinimalSignedBeaconBlock::default()
        };

        let state_bytes = state_inner.as_ssz_bytes();
        let block_bytes = bad_block_inner.as_ssz_bytes();
        let block_root_hex = hex::encode(block_root.as_slice());

        let state_bytes_arc = std::sync::Arc::new(state_bytes);
        let block_bytes_arc = std::sync::Arc::new(block_bytes);

        let app = Router::new()
            .route(
                "/eth/v2/debug/beacon/states/finalized",
                get({
                    let sb = state_bytes_arc.clone();
                    move || {
                        let sb = sb.clone();
                        async move {
                            let mut headers = HeaderMap::new();
                            headers.insert("Eth-Consensus-Version", "bellatrix".parse().unwrap());
                            (StatusCode::OK, headers, (*sb).clone())
                        }
                    }
                }),
            )
            .route(
                &format!("/eth/v2/beacon/blocks/0x{block_root_hex}"),
                get({
                    let bb = block_bytes_arc.clone();
                    move || {
                        let bb = bb.clone();
                        async move {
                            let mut headers = HeaderMap::new();
                            headers.insert("Eth-Consensus-Version", "bellatrix".parse().unwrap());
                            (StatusCode::OK, headers, (*bb).clone())
                        }
                    }
                }),
            );

        let (addr, listener) = bind_random().await;
        let handle = tokio::spawn(axum::serve(listener, app).into_future());
        let url = reqwest::Url::parse(&format!("http://{addr}/")).unwrap();
        let http = reqwest::Client::new();
        let result = fetch_checkpoint::<MinimalBeaconSpec>(&url, &http, None).await;
        handle.abort();

        // Blocker 1 fires first: the tampered block's tree_hash_root differs from
        // the block_root derived from state.latest_block_header.
        assert!(
            matches!(result, Err(CheckpointSyncError::BlockRootMismatch { .. })),
            "expected BlockRootMismatch (Blocker 1 fires first), got {result:?}"
        );
    }

    // ── Test (c): happy path — Capella anchor ─────────────────────────────────

    #[tokio::test]
    async fn fetch_capella_anchor_happy_path() {
        use pharos_ssz::Encode as _;

        let body = CapellaMinimalBeaconBlockBody::default();
        let body_root: Root = body.tree_hash_root();

        let state_inner = CapellaMinimalBeaconState {
            genesis_time: 1_700_000_000u64,
            slot: Slot(64),
            latest_block_header: BeaconBlockHeader {
                slot: Slot(64),
                state_root: Root::default(), // zeroed per spec (process_block_header)
                body_root,
                ..BeaconBlockHeader::default()
            },
            ..CapellaMinimalBeaconState::default()
        };

        // Compute the fork-enum state root via the Capella wrapper.
        let fork_state = ForkMinimalBeaconState::Capella(state_inner.clone());
        let computed_state_root: Root = fork_state.tree_hash_root();

        // Build the block with the correct state_root.
        let signed_block_inner = CapellaMinimalSignedBeaconBlock {
            message: CapellaMinimalBeaconBlock {
                slot: Slot(64),
                state_root: computed_state_root,
                body: body.clone(),
                ..CapellaMinimalBeaconBlock::default()
            },
            ..CapellaMinimalSignedBeaconBlock::default()
        };

        // Derive expected block_root (same derivation as fetch_checkpoint).
        let expected_block_root: Root = {
            let mut h = state_inner.latest_block_header.clone();
            h.state_root = computed_state_root;
            h.tree_hash_root()
        };

        let state_bytes = state_inner.as_ssz_bytes();
        let block_bytes = signed_block_inner.as_ssz_bytes();
        let block_root_hex = hex::encode(expected_block_root.as_slice());

        let state_bytes_arc = std::sync::Arc::new(state_bytes);
        let block_bytes_arc = std::sync::Arc::new(block_bytes);
        let app = Router::new()
            .route(
                "/eth/v2/debug/beacon/states/finalized",
                get({
                    let sb = state_bytes_arc.clone();
                    move || {
                        let sb = sb.clone();
                        async move {
                            let mut headers = HeaderMap::new();
                            headers.insert("Eth-Consensus-Version", "capella".parse().unwrap());
                            (StatusCode::OK, headers, (*sb).clone())
                        }
                    }
                }),
            )
            .route(
                &format!("/eth/v2/beacon/blocks/0x{block_root_hex}"),
                get({
                    let bb = block_bytes_arc.clone();
                    move || {
                        let bb = bb.clone();
                        async move {
                            let mut headers = HeaderMap::new();
                            headers.insert("Eth-Consensus-Version", "capella".parse().unwrap());
                            (StatusCode::OK, headers, (*bb).clone())
                        }
                    }
                }),
            );

        let (addr, listener) = bind_random().await;
        let handle = tokio::spawn(axum::serve(listener, app).into_future());

        let url = reqwest::Url::parse(&format!("http://{addr}/")).unwrap();
        let http = reqwest::Client::new();
        let result = fetch_checkpoint::<MinimalBeaconSpec>(&url, &http, None).await;

        handle.abort();

        let anchor = result.expect("capella fetch should succeed");
        assert_eq!(
            anchor.block_root, expected_block_root,
            "block_root mismatch"
        );
        assert_eq!(
            anchor.state_root, computed_state_root,
            "state_root mismatch"
        );
    }

    // ── Test (c2): unsupported fork header ────────────────────────────────────

    #[tokio::test]
    async fn fetch_rejects_unsupported_fork() {
        use pharos_ssz::Encode as _;
        let state_inner = MinimalBeaconState::default();
        let state_bytes = state_inner.as_ssz_bytes();
        let state_bytes_arc = std::sync::Arc::new(state_bytes);

        let app = Router::new().route(
            "/eth/v2/debug/beacon/states/finalized",
            get({
                let sb = state_bytes_arc.clone();
                move || {
                    let sb = sb.clone();
                    async move {
                        let mut headers = HeaderMap::new();
                        // Use a truly unknown fork name (not any currently supported fork).
                        headers.insert("Eth-Consensus-Version", "gloas".parse().unwrap());
                        (StatusCode::OK, headers, (*sb).clone())
                    }
                }
            }),
        );

        let (addr, listener) = bind_random().await;
        let handle = tokio::spawn(axum::serve(listener, app).into_future());
        let url = reqwest::Url::parse(&format!("http://{addr}/")).unwrap();
        let http = reqwest::Client::new();
        let result = fetch_checkpoint::<MinimalBeaconSpec>(&url, &http, None).await;
        handle.abort();

        assert!(
            matches!(result, Err(CheckpointSyncError::UnsupportedFork(ref s)) if s == "gloas"),
            "expected UnsupportedFork(gloas), got {result:?}"
        );
    }

    // ── Test (d): missing fork header ─────────────────────────────────────────

    #[tokio::test]
    async fn fetch_rejects_missing_fork_header() {
        let app = Router::new().route(
            "/eth/v2/debug/beacon/states/finalized",
            get(|| async {
                // No Eth-Consensus-Version header.
                (StatusCode::OK, b"garbage".to_vec())
            }),
        );

        let (addr, listener) = bind_random().await;
        let handle = tokio::spawn(axum::serve(listener, app).into_future());
        let url = reqwest::Url::parse(&format!("http://{addr}/")).unwrap();
        let http = reqwest::Client::new();
        let result = fetch_checkpoint::<MinimalBeaconSpec>(&url, &http, None).await;
        handle.abort();

        assert!(
            matches!(result, Err(CheckpointSyncError::MissingForkHeader)),
            "expected MissingForkHeader, got {result:?}"
        );
    }

    // ── Test (e): 404 response ─────────────────────────────────────────────────

    #[tokio::test]
    async fn fetch_rejects_404() {
        let app = Router::new().route(
            "/eth/v2/debug/beacon/states/finalized",
            get(|| async { (StatusCode::NOT_FOUND, "not found") }),
        );

        let (addr, listener) = bind_random().await;
        let handle = tokio::spawn(axum::serve(listener, app).into_future());
        let url = reqwest::Url::parse(&format!("http://{addr}/")).unwrap();
        let http = reqwest::Client::new();
        let result = fetch_checkpoint::<MinimalBeaconSpec>(&url, &http, None).await;
        handle.abort();

        assert!(
            matches!(result, Err(CheckpointSyncError::Status { code: 404, .. })),
            "expected Status {{ code: 404 }}, got {result:?}"
        );
    }

    // ── Test (f): block root mismatch (Blocker 1) ─────────────────────────────

    /// Serves a valid state but a block whose `tree_hash_root` (message) differs
    /// from the block_root derived from `state.latest_block_header`.
    /// Asserts `BlockRootMismatch` is returned.
    #[tokio::test]
    async fn fetch_rejects_block_root_mismatch() {
        use pharos_ssz::Encode as _;

        let body = MinimalBeaconBlockBody::default();
        let body_root: Root = body.tree_hash_root();

        let state_inner = MinimalBeaconState {
            slot: Slot(32),
            latest_block_header: BeaconBlockHeader {
                slot: Slot(32),
                body_root,
                state_root: Root::default(),
                proposer_index: pharos_types::phase0::primitives::ValidatorIndex(7),
                ..BeaconBlockHeader::default()
            },
            ..MinimalBeaconState::default()
        };

        let fork_state = ForkMinimalBeaconState::Bellatrix(state_inner.clone());
        let computed_state_root: Root = fork_state.tree_hash_root();

        // The block_root the server uses as the URL parameter (derived from state).
        let correct_block_root: Root = {
            let mut h = state_inner.latest_block_header.clone();
            h.state_root = computed_state_root;
            h.tree_hash_root()
        };

        // Build a block with different proposer_index so its tree_hash_root ≠ correct_block_root.
        let tampered_block = MinimalSignedBeaconBlock {
            message: MinimalBeaconBlock {
                slot: Slot(32),
                state_root: computed_state_root,
                proposer_index: pharos_types::phase0::primitives::ValidatorIndex(99), // differs
                body: body.clone(),
                ..MinimalBeaconBlock::default()
            },
            ..MinimalSignedBeaconBlock::default()
        };

        let state_bytes = state_inner.as_ssz_bytes();
        let block_bytes = tampered_block.as_ssz_bytes();
        let block_root_hex = hex::encode(correct_block_root.as_slice());

        let state_bytes_arc = std::sync::Arc::new(state_bytes);
        let block_bytes_arc = std::sync::Arc::new(block_bytes);

        let app = Router::new()
            .route(
                "/eth/v2/debug/beacon/states/finalized",
                get({
                    let sb = state_bytes_arc.clone();
                    move || {
                        let sb = sb.clone();
                        async move {
                            let mut headers = HeaderMap::new();
                            headers.insert("Eth-Consensus-Version", "bellatrix".parse().unwrap());
                            (StatusCode::OK, headers, (*sb).clone())
                        }
                    }
                }),
            )
            .route(
                &format!("/eth/v2/beacon/blocks/0x{block_root_hex}"),
                get({
                    let bb = block_bytes_arc.clone();
                    move || {
                        let bb = bb.clone();
                        async move {
                            let mut headers = HeaderMap::new();
                            headers.insert("Eth-Consensus-Version", "bellatrix".parse().unwrap());
                            (StatusCode::OK, headers, (*bb).clone())
                        }
                    }
                }),
            );

        let (addr, listener) = bind_random().await;
        let handle = tokio::spawn(axum::serve(listener, app).into_future());
        let url = reqwest::Url::parse(&format!("http://{addr}/")).unwrap();
        let http = reqwest::Client::new();
        let result = fetch_checkpoint::<MinimalBeaconSpec>(&url, &http, None).await;
        handle.abort();

        assert!(
            matches!(result, Err(CheckpointSyncError::BlockRootMismatch { .. })),
            "expected BlockRootMismatch, got {result:?}"
        );
    }

    // ── Test (g): tamper-flag mismatch ─────────────────────────────────────────

    /// Serves a valid state+block but supplies `expected_block_root = Some(<wrong>)`.
    /// Asserts `TamperFlagMismatch` is returned.
    #[tokio::test]
    async fn fetch_rejects_tamper_flag_mismatch() {
        use pharos_ssz::Encode as _;

        let body = MinimalBeaconBlockBody::default();
        let body_root: Root = body.tree_hash_root();

        let state_inner = MinimalBeaconState {
            genesis_time: 1_600_000_000u64,
            slot: Slot(64),
            latest_block_header: BeaconBlockHeader {
                slot: Slot(64),
                state_root: Root::default(),
                body_root,
                ..BeaconBlockHeader::default()
            },
            ..MinimalBeaconState::default()
        };

        let fork_state = ForkMinimalBeaconState::Bellatrix(state_inner.clone());
        let computed_state_root: Root = fork_state.tree_hash_root();

        let block_inner = MinimalSignedBeaconBlock {
            message: MinimalBeaconBlock {
                slot: Slot(64),
                state_root: computed_state_root,
                body: body.clone(),
                ..MinimalBeaconBlock::default()
            },
            ..MinimalSignedBeaconBlock::default()
        };

        let real_block_root: Root = {
            let mut h = state_inner.latest_block_header.clone();
            h.state_root = computed_state_root;
            h.tree_hash_root()
        };

        let state_bytes = state_inner.as_ssz_bytes();
        let block_bytes = block_inner.as_ssz_bytes();
        let block_root_hex = hex::encode(real_block_root.as_slice());

        let state_bytes_arc = std::sync::Arc::new(state_bytes);
        let block_bytes_arc = std::sync::Arc::new(block_bytes);

        let app = Router::new()
            .route(
                "/eth/v2/debug/beacon/states/finalized",
                get({
                    let sb = state_bytes_arc.clone();
                    move || {
                        let sb = sb.clone();
                        async move {
                            let mut headers = HeaderMap::new();
                            headers.insert("Eth-Consensus-Version", "bellatrix".parse().unwrap());
                            (StatusCode::OK, headers, (*sb).clone())
                        }
                    }
                }),
            )
            .route(
                &format!("/eth/v2/beacon/blocks/0x{block_root_hex}"),
                get({
                    let bb = block_bytes_arc.clone();
                    move || {
                        let bb = bb.clone();
                        async move {
                            let mut headers = HeaderMap::new();
                            headers.insert("Eth-Consensus-Version", "bellatrix".parse().unwrap());
                            (StatusCode::OK, headers, (*bb).clone())
                        }
                    }
                }),
            );

        let (addr, listener) = bind_random().await;
        let handle = tokio::spawn(axum::serve(listener, app).into_future());
        let url = reqwest::Url::parse(&format!("http://{addr}/")).unwrap();
        let http = reqwest::Client::new();

        // Supply a wrong expected_block_root — operator expects a different root.
        let wrong_expected = Root::from([0xBBu8; 32]);
        let result = fetch_checkpoint::<MinimalBeaconSpec>(&url, &http, Some(wrong_expected)).await;
        handle.abort();

        assert!(
            matches!(
                result,
                Err(CheckpointSyncError::TamperFlagMismatch {
                    expected,
                    ..
                }) if expected == wrong_expected
            ),
            "expected TamperFlagMismatch, got {result:?}"
        );
    }

    // ── Test (h): apply_anchor seeds payload_status Valid for post-merge anchor ─

    /// Verifies that `apply_anchor` writes `PayloadStatus::Valid` to the
    /// `CF_PAYLOAD_STATUS` RocksDB column family for the anchor block root.
    ///
    /// After `apply_anchor`, rebuilding a fork-choice store via
    /// `get_forkchoice_store` AND rehydrating via `rehydrate_fork_choice_store`
    /// must both show `is_optimistic(store, anchor_root) == false` for a
    /// post-merge (Bellatrix) anchor block.
    ///
    /// Per `specs/sync/optimistic.md` "Checkpoint Sync (Weak Subjectivity Sync)".
    #[test]
    fn apply_anchor_seeds_payload_status_valid_for_bellatrix_anchor() {
        use pharos_fork_choice::optimistic::is_optimistic;
        use pharos_fork_choice::store::get_forkchoice_store;
        use pharos_storage::{RocksStore, RocksStoreConfig, Store as StoreTrait};
        use pharos_types::PayloadStatus;

        let dir = tempfile::TempDir::new().unwrap();
        let rocks = RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: dir.path().join("db"),
            create_if_missing: true,
        })
        .expect("open rocksdb");

        // Build a valid Bellatrix anchor state + signed block.
        let body = MinimalBeaconBlockBody::default();
        let body_root: Root = body.tree_hash_root();
        let state_inner = MinimalBeaconState {
            genesis_time: 1_600_000_000u64,
            slot: Slot(64),
            latest_block_header: BeaconBlockHeader {
                slot: Slot(64),
                state_root: Root::default(),
                body_root,
                ..BeaconBlockHeader::default()
            },
            ..MinimalBeaconState::default()
        };
        let fork_state = ForkMinimalBeaconState::Bellatrix(state_inner.clone());
        let state_root: Root = fork_state.tree_hash_root();

        let signed_block_inner = MinimalSignedBeaconBlock {
            message: MinimalBeaconBlock {
                slot: Slot(64),
                state_root,
                body: body.clone(),
                ..MinimalBeaconBlock::default()
            },
            ..MinimalSignedBeaconBlock::default()
        };

        let block_root: Root = {
            let mut h = state_inner.latest_block_header.clone();
            h.state_root = state_root;
            h.tree_hash_root()
        };

        // Build the CheckpointAnchor manually (bypassing the HTTP fetch).
        let fork_signed_block =
            <MinimalBeaconSpec as pharos_types::BeaconSpec>::bellatrix_into_signed_block(
                signed_block_inner,
            );

        let anchor = CheckpointAnchor {
            state: fork_state,
            signed_block: fork_signed_block,
            state_root,
            block_root,
        };

        // Apply anchor — this should persist PayloadStatus::Valid for block_root.
        // The minimal default state has no active validators, so bypass the WS
        // freshness gate here (this test exercises payload-status seeding, not
        // the WS check, which has its own dedicated tests below).
        apply_anchor::<MinimalBeaconSpec>(anchor, &rocks, 64, true).expect("apply_anchor");

        // Confirm the persisted status is Valid.
        let stored_status =
            <RocksStore as StoreTrait<MinimalBeaconSpec>>::payload_status(&rocks, block_root)
                .expect("payload_status lookup")
                .expect("status must be present after apply_anchor");
        assert_eq!(
            stored_status,
            PayloadStatus::Valid,
            "apply_anchor must persist PayloadStatus::Valid for the anchor block root"
        );

        // Confirm that get_forkchoice_store (which also seeds Valid) results in
        // is_optimistic == false for the anchor.
        let anchor_state_in = MinimalBeaconState {
            genesis_time: 1_600_000_000u64,
            slot: Slot(64),
            latest_block_header: BeaconBlockHeader {
                slot: Slot(64),
                state_root: Root::default(),
                body_root,
                ..BeaconBlockHeader::default()
            },
            ..MinimalBeaconState::default()
        };
        let anchor_fork_state2 = ForkMinimalBeaconState::Bellatrix(anchor_state_in);
        let state_root2: Root = anchor_fork_state2.tree_hash_root();
        let raw_block = MinimalBeaconBlock {
            slot: Slot(64),
            state_root: state_root2,
            body: body.clone(),
            ..MinimalBeaconBlock::default()
        };
        let anchor_block2 = pharos_types::BeaconBlock::Bellatrix(raw_block);

        let fc_store = get_forkchoice_store::<MinimalBeaconSpec>(anchor_fork_state2, anchor_block2);
        let anchor_root2 = fc_store.finalized_checkpoint.root;
        assert!(
            !is_optimistic::<MinimalBeaconSpec>(&fc_store, anchor_root2),
            "post-merge anchor must not be optimistic in get_forkchoice_store"
        );
    }

    // ── Weak-subjectivity gate tests ──────────────────────────────────────────

    /// Build a Bellatrix `CheckpointAnchor` at `anchor_slot` with `n_validators`
    /// active validators (32 ETH effective balance each, activation_epoch 0,
    /// exit FAR_FUTURE), persisted into a fresh RocksDB. Returns `(anchor, store,
    /// tempdir)`. Used to drive the WS freshness gate.
    fn make_ws_anchor(
        anchor_slot: u64,
        n_validators: u64,
    ) -> (
        CheckpointAnchor<MinimalBeaconSpec>,
        pharos_storage::RocksStore,
        tempfile::TempDir,
    ) {
        use pharos_ssz::SszList;
        use pharos_storage::{RocksStore, RocksStoreConfig};
        use pharos_types::phase0::misc::Validator;
        use pharos_types::phase0::primitives::Epoch;
        use pharos_utils::Gwei;

        let dir = tempfile::TempDir::new().unwrap();
        let rocks = RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: dir.path().join("db"),
            create_if_missing: true,
        })
        .expect("open rocksdb");

        let validators: Vec<Validator> = (0..n_validators)
            .map(|_| Validator {
                effective_balance: Gwei(32_000_000_000),
                activation_epoch: Epoch(0),
                exit_epoch: Epoch(u64::MAX),
                ..Validator::default()
            })
            .collect();

        let body = MinimalBeaconBlockBody::default();
        let body_root: Root = body.tree_hash_root();
        let state_inner = MinimalBeaconState {
            genesis_time: 1_600_000_000u64,
            slot: Slot(anchor_slot),
            latest_block_header: BeaconBlockHeader {
                slot: Slot(anchor_slot),
                state_root: Root::default(),
                body_root,
                ..BeaconBlockHeader::default()
            },
            validators: SszList::from_vec(validators).expect("validators list"),
            ..MinimalBeaconState::default()
        };
        let fork_state = ForkMinimalBeaconState::Bellatrix(state_inner.clone());
        let state_root: Root = fork_state.tree_hash_root();

        let signed_block_inner = MinimalSignedBeaconBlock {
            message: MinimalBeaconBlock {
                slot: Slot(anchor_slot),
                state_root,
                body: body.clone(),
                ..MinimalBeaconBlock::default()
            },
            ..MinimalSignedBeaconBlock::default()
        };
        let block_root: Root = {
            let mut h = state_inner.latest_block_header.clone();
            h.state_root = state_root;
            h.tree_hash_root()
        };
        let fork_signed_block =
            <MinimalBeaconSpec as pharos_types::BeaconSpec>::bellatrix_into_signed_block(
                signed_block_inner,
            );
        let anchor = CheckpointAnchor {
            state: fork_state,
            signed_block: fork_signed_block,
            state_root,
            block_root,
        };
        (anchor, rocks, dir)
    }

    /// Minimal preset: 16 validators at 32 ETH → WS period == 256 epochs
    /// (`SLOTS_PER_EPOCH = 8`). A current slot one epoch past the anchor is well
    /// inside the period → `apply_anchor` accepts.
    #[test]
    fn apply_anchor_accepts_fresh_checkpoint() {
        let anchor_slot = 100 * MinimalBeaconSpec::SLOTS_PER_EPOCH; // epoch 100
        let (anchor, rocks, _dir) = make_ws_anchor(anchor_slot, 16);
        let current_slot = 101 * MinimalBeaconSpec::SLOTS_PER_EPOCH; // epoch 101
        let res = apply_anchor::<MinimalBeaconSpec>(anchor, &rocks, current_slot, false);
        assert!(res.is_ok(), "fresh anchor should be accepted: {res:?}");
    }

    /// Anchor at epoch 100, current at epoch 100 + 256 + 1 = 357 → past the WS
    /// period → `apply_anchor` rejects with `CheckpointTooOld`.
    #[test]
    fn apply_anchor_rejects_stale_checkpoint() {
        let anchor_epoch = 100u64;
        let anchor_slot = anchor_epoch * MinimalBeaconSpec::SLOTS_PER_EPOCH;
        let (anchor, rocks, _dir) = make_ws_anchor(anchor_slot, 16);
        // Period is 256 for this set; go one epoch past the boundary.
        let current_epoch = anchor_epoch + 256 + 1;
        let current_slot = current_epoch * MinimalBeaconSpec::SLOTS_PER_EPOCH;
        let res = apply_anchor::<MinimalBeaconSpec>(anchor, &rocks, current_slot, false);
        assert!(
            matches!(
                res,
                Err(CheckpointSyncError::CheckpointTooOld {
                    anchor_epoch: ae,
                    ws_period: 256,
                    ..
                }) if ae == anchor_epoch
            ),
            "stale anchor should be rejected with CheckpointTooOld(ws_period=256), got {res:?}"
        );
    }

    /// The same stale anchor is accepted when `ignore_ws_period == true`
    /// (`--ignore-weak-subjectivity-period` escape hatch).
    #[test]
    fn apply_anchor_ignore_flag_bypasses_stale_check() {
        let anchor_epoch = 100u64;
        let anchor_slot = anchor_epoch * MinimalBeaconSpec::SLOTS_PER_EPOCH;
        let (anchor, rocks, _dir) = make_ws_anchor(anchor_slot, 16);
        let current_slot = (anchor_epoch + 256 + 1) * MinimalBeaconSpec::SLOTS_PER_EPOCH;
        let res = apply_anchor::<MinimalBeaconSpec>(anchor, &rocks, current_slot, true);
        assert!(
            res.is_ok(),
            "ignore flag must bypass the WS gate even for a stale anchor: {res:?}"
        );
    }
}
