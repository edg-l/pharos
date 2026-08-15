//! LMD-GHOST smoke test.
//!
//! ## Design
//!
//! This is a hand-built internal sanity test, NOT a fixture-based conformance
//! test (those come in Phase 9).
//!
//! ## Approach and hacks
//!
//! Calling `on_block` requires full BLS-signed blocks and a real state
//! transition, which in turn requires genuine BLS deposit credentials.
//! Rather than vendor a BLS key-generation dependency for a smoke test, this
//! test fabricates blocks and states **directly into the store maps**,
//! bypassing `on_block` and BLS verification entirely.
//!
//! Specifically:
//! - `MinimalBeaconBlock` structs are constructed with `Default` fields and
//!   only `slot`, `parent_root`, and `proposer_index` set.
//! - `MinimalBeaconState` structs are constructed by cloning the genesis
//!   anchor state and setting `slot` appropriately.  Validators are added via
//!   direct struct construction with `BLSPubkey::default()` (zeroed keys).
//!   This is only safe in a test context where BLS is never verified.
//! - Checkpoints, block roots, and state roots reference fabricated hashes.
//! - `latest_messages` are inserted directly without going through
//!   `on_attestation` (which would require BLS-valid indexed attestations).
//!
//! These hacks are acceptable because:
//! 1. `get_head` only reads `store.blocks`, `store.block_states`,
//!    `store.latest_messages`, `store.checkpoint_states`, and
//!    `store.equivocating_indices` — none of which require authentic
//!    signatures.
//! 2. Real fixture-based testing (including BLS verification) is Phase 9.
//!
//! ## Topology
//!
//! ```
//!   genesis (slot 0)
//!      ├── A (slot 1) ── B (slot 2)   [chain 1]
//!      └── C (slot 1)                  [chain 2]
//! ```
//!
//! Round 1: attestations vote for B → `get_head` returns B.
//! Round 2: attestations swing to C → `get_head` returns C.

use pharos_fork_choice::{
    Store,
    get_head::get_head,
    store::{LatestMessage, get_forkchoice_store},
};
use pharos_ssz::TreeHash;
use pharos_stf::phase0::state_write::BeaconStateWrite;
use pharos_types::PayloadStatus;
use pharos_types::{
    MinimalEthSpec,
    phase0::{Epoch, Gwei, Root, Slot, Validator, ValidatorIndex},
};
use pharos_utils::{BLSPubkey, Bytes32, Hash256};

// ── Preset shorthands ─────────────────────────────────────────────────────────

// The concrete phase0 structs, used for state/block construction and mutation.
type MinState = pharos_types::phase0::MinimalBeaconState;
type MinBlock = pharos_types::phase0::MinimalBeaconBlock;

// The fork-enum wrappers that Store<MinimalEthSpec> actually stores.
type ForkMinState = pharos_types::state::MinimalBeaconState;
type ForkMinBlock = pharos_types::state::MinimalBeaconBlock;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a `Validator` active at genesis with `effective_balance`.
fn make_validator(effective_balance: u64) -> Validator {
    Validator {
        pubkey: BLSPubkey::from_array([0u8; 48]),
        withdrawal_credentials: Bytes32::default(),
        effective_balance: Gwei(effective_balance),
        slashed: false,
        activation_eligibility_epoch: Epoch(0),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch(u64::MAX),
        withdrawable_epoch: Epoch(u64::MAX),
    }
}

/// Build a genesis `MinState` with `n` validators, each with `effective_balance`.
///
/// # Hacks
/// - Validators have zeroed pubkeys; BLS is never verified in this test.
/// - `genesis_time` is set to 1_000_000 (arbitrary past timestamp).
/// - All list/vector fields other than `validators` and `balances` are
///   default-initialised (zeroed or empty).
fn make_genesis_state(n: usize, effective_balance: u64) -> MinState {
    use pharos_stf::phase0::genesis::BeaconStateMut;
    use pharos_utils::Bytes4;

    let genesis_time = 1_000_000u64;
    let eth1_data = pharos_types::phase0::Eth1Data::default();
    let body_root = pharos_types::phase0::MinimalBeaconBlockBody::default().tree_hash_root();
    let fork = pharos_types::phase0::Fork {
        previous_version: Bytes4::from_array([0; 4]),
        current_version: Bytes4::from_array([0; 4]),
        epoch: Epoch(0),
    };
    let mut state =
        MinState::genesis_state(genesis_time, fork, eth1_data, body_root, Hash256::default());

    for _ in 0..n {
        let v = make_validator(effective_balance);
        state.push_validator(v).unwrap();
        state.push_balance(Gwei(effective_balance)).unwrap();
    }

    state
}

/// Return a `MinBlock` at `slot` with `parent_root`.
fn make_block(slot: u64, parent_root: Root) -> MinBlock {
    MinBlock {
        slot: Slot(slot),
        parent_root,
        ..Default::default()
    }
}

/// Insert a block and a cloned-genesis state at `slot` directly into `store`.
fn insert_block(
    store: &mut Store<MinimalEthSpec>,
    block: MinBlock,
    anchor_state: &MinState,
) -> Root {
    let root: Root = block.tree_hash_root();
    let mut state = anchor_state.clone();
    // Advance the state slot field directly.  Do NOT call process_slots
    // (which would require proper block roots filled in).
    state.set_slot(block.slot);
    // Wrap in the fork-enum before inserting; Store<E> holds E::BeaconBlock
    // and E::BeaconState which are now fork-enum types.
    store.blocks.insert(root, ForkMinBlock::Phase0(block));
    store.block_states.insert(root, ForkMinState::Phase0(state));
    root
}

/// Cast `n` votes (from validator indices `0..n`) for `voted_root` at `epoch`.
fn cast_votes(store: &mut Store<MinimalEthSpec>, voted_root: Root, epoch: Epoch, n: usize) {
    for i in 0..n {
        store.latest_messages.insert(
            ValidatorIndex(i as u64),
            LatestMessage {
                epoch,
                root: voted_root,
            },
        );
    }
}

// ── Test ───────────────────────────────────────────────────────────────────────

#[test]
fn lmd_ghost_basic_weight_switch() {
    // Build genesis state and block.
    // 10 validators, each with MAX_EFFECTIVE_BALANCE (32 ETH).
    let n_validators = 10usize;
    let eff_balance = 32_000_000_000u64;
    let anchor_state = make_genesis_state(n_validators, eff_balance);

    // Genesis block: state_root must equal hash_tree_root(anchor_state) to
    // satisfy the assertion in get_forkchoice_store (spec line 192).
    let anchor_block = MinBlock {
        state_root: anchor_state.tree_hash_root(),
        ..MinBlock::default()
    };

    // Seed checkpoint state so get_weight can read it.
    // get_forkchoice_store expects E::BeaconState and E::BeaconBlock (fork-enum).
    let mut store = get_forkchoice_store::<MinimalEthSpec>(
        ForkMinState::Phase0(anchor_state.clone()),
        ForkMinBlock::Phase0(anchor_block.clone()),
    );

    // Insert the justified checkpoint state so get_weight works.
    store.checkpoint_states.insert(
        store.justified_checkpoint.clone(),
        ForkMinState::Phase0(anchor_state.clone()),
    );

    // ── Build chain: genesis -> A -> B ────────────────────────────────────────
    let genesis_root: Root = anchor_block.tree_hash_root();

    let block_a = make_block(1, genesis_root);
    let root_a = insert_block(&mut store, block_a, &anchor_state);

    let block_b = make_block(2, root_a);
    let root_b = insert_block(&mut store, block_b, &anchor_state);

    // ── Build competing chain: genesis -> C ──────────────────────────────────
    // Use a distinct parent root so B and C are siblings of genesis.
    let mut block_c = make_block(1, genesis_root);
    // Distinguish C from A by giving it a different proposer_index.
    block_c.proposer_index = ValidatorIndex(99);
    let root_c = insert_block(&mut store, block_c, &anchor_state);

    // Also insert root_a and root_b unrealized justifications.
    store
        .unrealized_justifications
        .insert(root_a, store.justified_checkpoint.clone());
    store
        .unrealized_justifications
        .insert(root_b, store.justified_checkpoint.clone());
    store
        .unrealized_justifications
        .insert(root_c, store.justified_checkpoint.clone());

    // ── Round 1: vote for B ───────────────────────────────────────────────────
    // 7 out of 10 validators vote for B.
    cast_votes(&mut store, root_b, Epoch(0), 7);
    // 3 validators vote for C.
    for i in 7..10usize {
        store.latest_messages.insert(
            ValidatorIndex(i as u64),
            LatestMessage {
                epoch: Epoch(0),
                root: root_c,
            },
        );
    }

    // B has more weight than C: get_head must be B.
    let head = get_head::<MinimalEthSpec>(&store);
    assert_eq!(
        head, root_b,
        "expected head=B when 7/10 validators voted for B chain"
    );

    // ── Round 2: swing all votes to C ─────────────────────────────────────────
    cast_votes(&mut store, root_c, Epoch(1), n_validators);

    let head = get_head::<MinimalEthSpec>(&store);
    assert_eq!(
        head, root_c,
        "expected head=C after all validators switched to C"
    );
}

/// Three-block chain `genesis → A → B`. Marking A as `Invalid` must prune
/// both A and B from the viable head set; `get_head` falls back to the
/// pre-invalid parent (genesis), since B is unreachable through an invalid A.
#[test]
fn filter_block_tree_skips_invalid_payload() {
    let n_validators = 4usize;
    let eff_balance = 32_000_000_000u64;
    let anchor_state = make_genesis_state(n_validators, eff_balance);
    let anchor_block = MinBlock {
        state_root: anchor_state.tree_hash_root(),
        ..MinBlock::default()
    };
    let mut store = get_forkchoice_store::<MinimalEthSpec>(
        ForkMinState::Phase0(anchor_state.clone()),
        ForkMinBlock::Phase0(anchor_block.clone()),
    );
    store.checkpoint_states.insert(
        store.justified_checkpoint.clone(),
        ForkMinState::Phase0(anchor_state.clone()),
    );

    let genesis_root: Root = anchor_block.tree_hash_root();
    let block_a = make_block(1, genesis_root);
    let root_a = insert_block(&mut store, block_a, &anchor_state);
    let block_b = make_block(2, root_a);
    let root_b = insert_block(&mut store, block_b, &anchor_state);

    store
        .unrealized_justifications
        .insert(root_a, store.justified_checkpoint.clone());
    store
        .unrealized_justifications
        .insert(root_b, store.justified_checkpoint.clone());

    cast_votes(&mut store, root_b, Epoch(0), n_validators);

    // Sanity: without any payload-status marks, head = B (heaviest leaf).
    let head_before = get_head::<MinimalEthSpec>(&store);
    assert_eq!(
        head_before, root_b,
        "expected head=B before marking A invalid"
    );

    // Mark A invalid; this also makes B unreachable through A.
    store.mark_payload_status(root_a, PayloadStatus::Invalid);
    let head_after = get_head::<MinimalEthSpec>(&store);
    assert_eq!(
        head_after, genesis_root,
        "expected head=genesis after A marked Invalid"
    );
}
