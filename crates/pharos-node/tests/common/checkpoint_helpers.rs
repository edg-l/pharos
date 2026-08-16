//! Shared fixture-chain builders for checkpoint-sync + backfill integration tests.
//!
//! Extracted from `engine_pipeline.rs` so that both `engine_pipeline.rs` and
//! `checkpoint_backfill_pipeline.rs` can share the same fixture construction
//! logic without duplication.

// Each test binary that includes this module uses a different subset of the
// exported items.  Suppress dead_code warnings so test binaries that don't
// use all items don't fail with `-D warnings`.
#![allow(dead_code)]

use blst::min_pk::SecretKey;
use pharos_ssz::{SszList, SszSequence as _, SszVector, TreeHash};
use pharos_stf::phase0::accessors::{compute_signing_root, get_current_epoch, get_domain};
use pharos_stf::phase0::helpers::{DOMAIN_BEACON_PROPOSER, DOMAIN_RANDAO};
use pharos_stf::{NullExecutionEngine, process_slots_fork, state_transition};
use pharos_types::altair::{MinimalSyncAggregate, MinimalSyncCommittee};
use pharos_types::bellatrix::{
    MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState, MinimalSignedBeaconBlock,
    execution_payload::MinimalExecutionPayload,
};
use pharos_types::config::RuntimeConfig;
use pharos_types::phase0::misc::{Fork, Validator};
use pharos_types::phase0::operations::BeaconBlockHeader;
use pharos_types::phase0::primitives::{Epoch, Gwei, Root, Slot, ValidatorIndex, Version};
use pharos_types::state::{
    MinimalBeaconState as ForkMinimalBeaconState, SignedBeaconBlock as ForkSignedBeaconBlock,
};
use pharos_types::{EthSpec, MinimalEthSpec};
use pharos_utils::bls::BLS_DST;
use pharos_utils::{BLSPubkey, BLSSignature, Hash256};

/// Type alias for the fork-enum `SignedBeaconBlock` over minimal-preset params.
pub type MinForkSignedBlock = ForkSignedBeaconBlock<
    16,
    2,
    128,
    16,
    16,
    2048,
    33,
    32,
    1_073_741_824,
    1_048_576,
    256,
    32,
    4,
    16,
    4096,
>;

/// `TERMINAL_BLOCK_HASH` bytes used in the checkpoint-sync fixture chain.
///
/// Block 1's `payload.parent_hash` is set to this value so the fork-choice
/// merge-transition guard passes without consulting an EL.
pub const TERMINAL_BLOCK_HASH_BYTES: [u8; 32] = [0x01u8; 32];

/// A far-past genesis time (unix seconds) used in backfill integration tests so
/// that the computed `wall_slot` is much larger than any test chain length.
///
/// `1_000_000` seconds from the Unix epoch is 1970-01-12, which is far enough in
/// the past that `wall_slot >> N_BACKFILL_BLOCKS` for any sane test fixture.
pub const BACKFILL_GENESIS_TIME_SECS: u64 = 1_000_000;

/// Seconds to add to the current wall-clock when advancing `fc_store.time` ahead
/// of the current slot in integration tests that need the fork-choice time cursor
/// to already be ahead of the test chain tip.
///
/// ~11.5 days in seconds, large enough that `current_slot` comfortably exceeds
/// `ANCHOR_SLOT + N_BACKFILL_BLOCKS` for any realistic test fixture.
pub const FC_STORE_TIME_ADVANCE_SECS: u64 = 1_000_000;

// ── BLS test keypair helpers ──────────────────────────────────────────────────

/// Deterministic secret key derived from a fixed 32-byte seed.
fn test_sk() -> SecretKey {
    SecretKey::key_gen(&[1u8; 32], &[]).expect("valid IKM")
}

/// Compressed pubkey bytes for `test_sk()`.
fn test_pubkey() -> BLSPubkey {
    BLSPubkey::from_array(test_sk().sk_to_pk().compress())
}

/// Sign `msg` with `test_sk()` using the Ethereum BLS DST.
fn test_sign(msg: &[u8]) -> BLSSignature {
    BLSSignature::from_array(test_sk().sign(msg, BLS_DST, &[]).compress())
}

/// Build a Bellatrix anchor state at the given slot with the given genesis_time,
/// plus a matching signed beacon block.
///
/// The anchor state has one active validator (index 0) so that
/// `get_beacon_proposer_index` can select a proposer. The validator's pubkey is
/// set to `test_pubkey()` so that `process_randao` can resolve it.
///
/// The `latest_block_header.state_root` is zeroed per the spec (it is filled
/// in by `process_slot` at the next slot). The returned `MinimalSignedBeaconBlock`
/// has `state_root` set to `hash_tree_root(fork_state)` so `fetch_checkpoint`
/// cross-checks pass.
pub fn build_anchor_bellatrix(
    slot: Slot,
    genesis_time: u64,
) -> (MinimalBeaconState, MinimalSignedBeaconBlock) {
    let anchor_body = MinimalBeaconBlockBody::default();
    let anchor_body_root: Root = anchor_body.tree_hash_root();

    let validator = Validator {
        pubkey: test_pubkey(),
        effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch(u64::MAX),
        withdrawable_epoch: Epoch(u64::MAX),
        slashed: false,
        ..Validator::default()
    };

    // Build sync committees with test_pubkey() so process_sync_aggregate resolves.
    let sync_committee = MinimalSyncCommittee {
        pubkeys: SszVector::from_vec(vec![
            test_pubkey();
            MinimalEthSpec::SYNC_COMMITTEE_SIZE as usize
        ])
        .unwrap(),
        aggregate_pubkey: test_pubkey(),
    };

    let state_inner = MinimalBeaconState {
        genesis_time,
        slot,
        fork: Fork {
            previous_version: Version::from_array([0x01, 0x00, 0x00, 0x01]),
            current_version: Version::from_array(MinimalEthSpec::BELLATRIX_FORK_VERSION),
            epoch: Epoch(0),
        },
        latest_block_header: BeaconBlockHeader {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: Root::default(), // zeroed per spec (process_block_header)
            body_root: anchor_body_root,
        },
        validators: SszList::empty_tree().with_push(validator).unwrap(),
        balances: SszList::with_push(
            &SszList::default(),
            Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
        )
        .unwrap(),
        previous_epoch_participation: SszList::with_push(&SszList::default(), 0u8).unwrap(),
        current_epoch_participation: SszList::with_push(&SszList::default(), 0u8).unwrap(),
        inactivity_scores: SszList::with_push(&SszList::default(), 0u64).unwrap(),
        current_sync_committee: sync_committee.clone(),
        next_sync_committee: sync_committee,
        ..MinimalBeaconState::default()
    };

    // Compute the state root via the fork-enum wrapper.
    let fork_state = ForkMinimalBeaconState::Bellatrix(state_inner.clone());
    let computed_state_root: Root = fork_state.tree_hash_root();

    // Build the anchor block with state_root = computed_state_root.
    let anchor_block = MinimalSignedBeaconBlock {
        message: MinimalBeaconBlock {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: computed_state_root,
            body: anchor_body,
        },
        signature: BLSSignature::from_array([0u8; 96]),
    };

    (state_inner, anchor_block)
}

/// Build a chain of `count` sequential Bellatrix blocks starting from slot
/// `anchor_state.slot + 1`.
///
/// Uses `NullExecutionEngine` + `validate_result: false` for the construction
/// pass. Blocks are signed with `test_sk()` so that `run_backfill_loop`'s
/// STF call (which uses `validate_result: true`) accepts them.
///
/// The first block's `payload.parent_hash` is set to `TERMINAL_BLOCK_HASH_BYTES`
/// so the fork-choice merge-transition guard passes without an EL.
///
/// Returns a `Vec` of signed blocks in ascending slot order.
pub fn build_backfill_chain(
    anchor_state: &MinimalBeaconState,
    count: u64,
) -> Vec<MinForkSignedBlock> {
    let runtime_cfg = RuntimeConfig {
        seconds_per_slot: MinimalEthSpec::SLOT_DURATION_MS / 1000,
        bellatrix_fork_version: MinimalEthSpec::BELLATRIX_FORK_VERSION,
        ..Default::default()
    };
    let null_engine = NullExecutionEngine;

    // Fork-wrap the anchor state so the STF accepts it.
    let mut state = ForkMinimalBeaconState::Bellatrix(anchor_state.clone());

    // The anchor block root becomes the parent_root of the first chain block.
    // Recompute from latest_block_header (substituting computed_state_root).
    let anchor_state_root = state.tree_hash_root();
    let anchor_block_root: Root = {
        let mut h = anchor_state.latest_block_header.clone();
        h.state_root = anchor_state_root;
        h.tree_hash_root()
    };

    let anchor_slot = anchor_state.slot.0;
    let mut prev_block_root = anchor_block_root;
    let mut signed_blocks = Vec::with_capacity(count as usize);

    // G2_POINT_AT_INFINITY: the valid empty sync_committee_signature per
    // eth_fast_aggregate_verify semantics.
    const G2_INFINITY: [u8; 96] = {
        let mut b = [0u8; 96];
        b[0] = 0xc0;
        b
    };

    for i in 1..=count {
        let slot = Slot(anchor_slot + i);

        // Advance a clone to `slot` to read randao_mix and expected timestamp.
        let mut pre_state_advanced = state.clone();
        process_slots_fork::<MinimalEthSpec>(
            &mut pre_state_advanced,
            slot,
            pharos_stf::ForkEpochs::never(),
            &runtime_cfg,
        )
        .unwrap_or_else(|e| {
            panic!(
                "build_backfill_chain: process_slots_fork failed at slot {}: {e}",
                slot.0
            )
        });

        let (prev_randao, expected_timestamp) = {
            let s = match &pre_state_advanced {
                ForkMinimalBeaconState::Bellatrix(s) => s,
                _ => panic!("expected Bellatrix state"),
            };
            let epoch = slot.0 / MinimalEthSpec::SLOTS_PER_EPOCH;
            let idx = (epoch % MinimalEthSpec::EPOCHS_PER_HISTORICAL_VECTOR) as usize;
            let randao = s.randao_mixes.get(idx).copied().unwrap_or_default();
            let ts = s.genesis_time + slot.0 * runtime_cfg.seconds_per_slot;
            (randao, ts)
        };

        // Payload parent hash: first block uses terminal hash; subsequent blocks
        // use [prev_block_index, 0...; 32].
        let payload_parent_hash = if i == 1 {
            Hash256::from_array(TERMINAL_BLOCK_HASH_BYTES)
        } else {
            let mut h = [0u8; 32];
            h[0] = (i - 1) as u8;
            Hash256::from_array(h)
        };
        let mut bh = [0u8; 32];
        bh[0] = i as u8;
        let block_hash = Hash256::from_array(bh);

        let payload = MinimalExecutionPayload {
            parent_hash: payload_parent_hash,
            prev_randao,
            block_number: i,
            gas_limit: 0x1c9c380,
            timestamp: expected_timestamp,
            block_hash,
            ..Default::default()
        };

        // Produce a valid RANDAO reveal so process_randao with verify_signatures=true
        // passes in run_backfill_loop.
        let randao_epoch = get_current_epoch::<MinimalEthSpec>(&pre_state_advanced);
        let randao_domain =
            get_domain::<MinimalEthSpec>(&pre_state_advanced, DOMAIN_RANDAO, Some(randao_epoch));
        let randao_signing_root = compute_signing_root(&randao_epoch, randao_domain);
        let randao_reveal = test_sign(randao_signing_root.as_slice());

        // Empty sync aggregate must use G2_POINT_AT_INFINITY.
        let sync_aggregate = MinimalSyncAggregate {
            sync_committee_signature: BLSSignature::from_array(G2_INFINITY),
            ..Default::default()
        };

        let body = MinimalBeaconBlockBody {
            execution_payload: payload,
            randao_reveal,
            sync_aggregate,
            ..Default::default()
        };

        // Step 1: draft pass with state_root = default to obtain post-state.
        let draft = MinimalBeaconBlock {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root: prev_block_root,
            state_root: Root::default(),
            body: body.clone(),
        };
        let draft_signed = MinForkSignedBlock::Bellatrix(MinimalSignedBeaconBlock {
            message: draft,
            signature: BLSSignature::from_array([0u8; 96]),
        });

        let (post_state_draft, _) = state_transition::<MinimalEthSpec, NullExecutionEngine>(
            state.clone(),
            &draft_signed,
            &null_engine,
            false,
            &runtime_cfg,
        )
        .unwrap_or_else(|e| {
            panic!(
                "build_backfill_chain: draft STF failed at slot {}: {e}",
                slot.0
            )
        });

        // Step 2: build final block with correct state_root.
        let state_root: Root = post_state_draft.tree_hash_root();
        let final_block = MinimalBeaconBlock {
            slot,
            proposer_index: ValidatorIndex(0),
            parent_root: prev_block_root,
            state_root,
            body,
        };
        let block_root: Root = final_block.tree_hash_root();

        // Produce a valid BLS block signature so state_transition with
        // validate_result=true (used by run_backfill_loop) accepts the block.
        let domain =
            get_domain::<MinimalEthSpec>(&pre_state_advanced, DOMAIN_BEACON_PROPOSER, None);
        let signing_root = compute_signing_root(&final_block, domain);
        let real_sig = test_sign(signing_root.as_slice());

        let fork_signed = MinForkSignedBlock::Bellatrix(MinimalSignedBeaconBlock {
            message: final_block,
            signature: real_sig,
        });

        // Step 3: final STF pass with correct state_root.
        let (post_state, _) = state_transition::<MinimalEthSpec, NullExecutionEngine>(
            state.clone(),
            &fork_signed,
            &null_engine,
            false,
            &runtime_cfg,
        )
        .unwrap_or_else(|e| {
            panic!(
                "build_backfill_chain: final STF failed at slot {}: {e}",
                slot.0
            )
        });

        state = post_state;
        prev_block_root = block_root;
        signed_blocks.push(fork_signed);
    }

    signed_blocks
}
