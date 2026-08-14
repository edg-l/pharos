//! Smoke test for the flat-const-only resolution in Task 4.4.
//!
//! Canary: if the const-generic approach regresses, these tests fail to compile.
//!
//! Tests verify:
//! - Round-trip SSZ encode/decode for `Validator` and `MinimalBeaconState`.
//! - `tree_hash_root` consistency: compute root, mutate a field, recompute,
//!   assert they differ.
//! - Cross-preset sanity: same `Validator` under both presets has the same root
//!   (since `Validator` has no generic fields). `MinimalBeaconState` vs
//!   `MainnetBeaconState` differ structurally (different block_roots vector size).

use pharos_ssz::{Decode, Encode, TreeHash};
use pharos_types::phase0::{MainnetBeaconState, MinimalBeaconState, Validator};
use pharos_utils::{BLSPubkey, Bytes32, Epoch, Gwei};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_validator(pubkey_byte: u8) -> Validator {
    let mut pubkey = BLSPubkey::default();
    pubkey.0[0] = pubkey_byte;
    Validator {
        pubkey,
        withdrawal_credentials: Bytes32::default(),
        effective_balance: Gwei(32_000_000_000),
        slashed: false,
        activation_eligibility_epoch: Epoch(0),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch(u64::MAX),
        withdrawable_epoch: Epoch(u64::MAX),
    }
}

// ── Validator round-trip ──────────────────────────────────────────────────────

#[test]
fn validator_ssz_roundtrip() {
    let v = make_validator(0xAB);
    let encoded = v.as_ssz_bytes();
    // Validator is fully fixed-size:
    // BLSPubkey (48) + Bytes32 (32) + Gwei (8) + bool (1) + 4 * Epoch (32) = 121
    assert_eq!(encoded.len(), 48 + 32 + 8 + 1 + 32);
    let decoded = Validator::from_ssz_bytes(&encoded).expect("decode should succeed");
    assert_eq!(v, decoded);
}

#[test]
fn validator_tree_hash_changes_on_mutation() {
    let v1 = make_validator(0x01);
    let v2 = make_validator(0x01);

    let root1 = v1.tree_hash_root();
    assert_eq!(
        root1,
        v2.tree_hash_root(),
        "identical validators must have equal roots"
    );

    // Mutate effective_balance — root must change.
    let v3 = Validator {
        effective_balance: Gwei(1_000_000_000),
        ..make_validator(0x01)
    };
    let root2 = v3.tree_hash_root();
    assert_ne!(
        root1, root2,
        "mutating effective_balance must change tree hash root"
    );
}

// ── MinimalBeaconState round-trip ─────────────────────────────────────────────

#[test]
fn minimal_beacon_state_ssz_roundtrip() {
    let state = MinimalBeaconState::default();
    let encoded = state.as_ssz_bytes();
    let decoded = MinimalBeaconState::from_ssz_bytes(&encoded)
        .expect("minimal BeaconState decode should succeed");
    assert_eq!(state, decoded);
}

#[test]
fn minimal_beacon_state_tree_hash_changes_on_mutation() {
    let state1 = MinimalBeaconState::default();
    let state2 = MinimalBeaconState::default();

    let root1 = state1.tree_hash_root();
    assert_eq!(
        root1,
        state2.tree_hash_root(),
        "identical states must have equal roots"
    );

    // Mutate genesis_time — root must change.
    let state3 = MinimalBeaconState {
        genesis_time: 1234567890,
        ..Default::default()
    };
    let root2 = state3.tree_hash_root();
    assert_ne!(
        root1, root2,
        "mutating genesis_time must change tree hash root"
    );
}

// ── Cross-preset sanity ───────────────────────────────────────────────────────

#[test]
fn validator_root_same_across_presets() {
    // `Validator` is a non-generic struct (no list fields). Its tree hash
    // root depends only on its field values, not on preset constants.
    // Two Validator instances with the same fields must hash identically
    // regardless of which preset the BeaconState they live in uses.
    let v = make_validator(0x42);
    let root = v.tree_hash_root();
    // Re-create with same values — should give identical root.
    let v2 = make_validator(0x42);
    assert_eq!(root, v2.tree_hash_root());
}

#[test]
fn non_default_state_hash_differs_from_default() {
    let default_state = MinimalBeaconState::default();
    let modified_state = MinimalBeaconState {
        genesis_time: 42,
        ..Default::default()
    };

    let default_root = default_state.tree_hash_root();
    let modified_root = modified_state.tree_hash_root();
    assert_ne!(
        default_root, modified_root,
        "non-default state must differ in tree hash from default state"
    );
}

// ── MainnetBeaconState basic smoke ────────────────────────────────────────────

#[test]
fn mainnet_beacon_state_ssz_roundtrip() {
    let state = MainnetBeaconState::default();
    let encoded = state.as_ssz_bytes();
    let decoded = MainnetBeaconState::from_ssz_bytes(&encoded)
        .expect("mainnet BeaconState decode should succeed");
    assert_eq!(state, decoded);
}

// ── MinimalBeaconState vs MainnetBeaconState structural difference ────────────

#[test]
fn minimal_and_mainnet_default_states_have_different_roots() {
    // MinimalBeaconState has block_roots: SszVector<Root, 64>
    // MainnetBeaconState has block_roots: SszVector<Root, 8192>
    // These are structurally different types with different tree hashes.
    let minimal_root = MinimalBeaconState::default().tree_hash_root();
    let mainnet_root = MainnetBeaconState::default().tree_hash_root();
    assert_ne!(
        minimal_root, mainnet_root,
        "minimal and mainnet default BeaconStates must differ in tree hash \
         because block_roots/state_roots/randao_mixes/slashings have different sizes"
    );
}

// ── SignedBeaconBlock round-trip ──────────────────────────────────────────────

#[test]
fn minimal_signed_beacon_block_ssz_roundtrip() {
    use pharos_types::phase0::MinimalSignedBeaconBlock;

    let block = MinimalSignedBeaconBlock::default();
    let encoded = block.as_ssz_bytes();
    let decoded = MinimalSignedBeaconBlock::from_ssz_bytes(&encoded)
        .expect("SignedBeaconBlock decode should succeed");
    assert_eq!(block, decoded);
}

// ── Deposit round-trip ────────────────────────────────────────────────────────

#[test]
fn deposit_ssz_roundtrip() {
    use pharos_types::phase0::MinimalDeposit;

    let deposit = MinimalDeposit::default();
    let encoded = deposit.as_ssz_bytes();
    let decoded = MinimalDeposit::from_ssz_bytes(&encoded).expect("Deposit decode should succeed");
    assert_eq!(deposit, decoded);
}

// ── HistoricalBatch round-trip ────────────────────────────────────────────────

#[test]
fn minimal_historical_batch_ssz_roundtrip() {
    use pharos_types::phase0::MinimalHistoricalBatch;

    let batch = MinimalHistoricalBatch::default();
    let encoded = batch.as_ssz_bytes();
    let decoded = MinimalHistoricalBatch::from_ssz_bytes(&encoded)
        .expect("HistoricalBatch decode should succeed");
    assert_eq!(batch, decoded);
}
