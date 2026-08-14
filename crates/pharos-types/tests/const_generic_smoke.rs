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
use pharos_utils::{
    BLSPubkey, BLSSignature, Bytes32, CommitteeIndex, Epoch, Gwei, Slot, ValidatorIndex,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn make_validator(pubkey_byte: u8) -> Validator {
    let mut arr = [0u8; 48];
    arr[0] = pubkey_byte;
    let pubkey = BLSPubkey::from_array(arr);
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
    //
    // Verify the SSZ encode → decode → tree_hash_root path produces the same
    // root as the in-memory value. A trivial `hash_tree_root(x) == hash_tree_root(x)`
    // would pass by determinism alone; reconstructing the value from raw bytes
    // exercises the `Decode` path and confirms re-export consistency.
    let v = make_validator(0x42);
    let in_memory_root = v.tree_hash_root();

    let encoded = v.as_ssz_bytes();
    let decoded = Validator::from_ssz_bytes(&encoded).expect("decode should succeed");
    let decoded_root = decoded.tree_hash_root();

    assert_eq!(
        in_memory_root, decoded_root,
        "Validator tree_hash_root must be invariant across SSZ encode/decode"
    );

    // A second value differing only in pubkey must produce a different root,
    // confirming the comparison above is not vacuously equal.
    let other = make_validator(0x43);
    assert_ne!(
        in_memory_root,
        other.tree_hash_root(),
        "validators with different pubkeys must have different roots"
    );
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

// ── Round-trip + tree_hash_root tests for the 19 under-covered containers ─────
//
// Each test: construct a non-default value, encode → decode → eq, then verify
// that `tree_hash_root` differs between the non-default and default.

#[test]
fn fork_roundtrip() {
    use pharos_types::phase0::Fork;
    use pharos_utils::Bytes4;
    let v = Fork {
        previous_version: Bytes4::from_array([1, 0, 0, 0]),
        current_version: Bytes4::from_array([2, 0, 0, 0]),
        epoch: Epoch(7),
    };
    let encoded = v.as_ssz_bytes();
    let decoded = Fork::from_ssz_bytes(&encoded).expect("Fork decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        Fork::default().tree_hash_root(),
        "non-default Fork root must differ"
    );
}

#[test]
fn fork_data_roundtrip() {
    use pharos_types::phase0::ForkData;
    use pharos_utils::{Bytes4, Bytes32};
    let v = ForkData {
        current_version: Bytes4::from_array([3, 0, 0, 0]),
        genesis_validators_root: Bytes32::from_array([0xAB; 32]),
    };
    let encoded = v.as_ssz_bytes();
    let decoded = ForkData::from_ssz_bytes(&encoded).expect("ForkData decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        ForkData::default().tree_hash_root(),
        "non-default ForkData root must differ"
    );
}

#[test]
fn checkpoint_roundtrip() {
    use pharos_types::phase0::Checkpoint;
    use pharos_utils::Hash256;
    let v = Checkpoint {
        epoch: Epoch(42),
        root: Hash256::from_array([0xFF; 32]),
    };
    let encoded = v.as_ssz_bytes();
    let decoded = Checkpoint::from_ssz_bytes(&encoded).expect("Checkpoint decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        Checkpoint::default().tree_hash_root(),
        "non-default Checkpoint root must differ"
    );
}

#[test]
fn attestation_data_roundtrip() {
    use pharos_types::phase0::{AttestationData, Checkpoint};
    use pharos_utils::Hash256;
    let chk = Checkpoint {
        epoch: Epoch(1),
        root: Hash256::from_array([0x11; 32]),
    };
    let v = AttestationData {
        slot: Slot(100),
        index: CommitteeIndex(2),
        beacon_block_root: Hash256::from_array([0x22; 32]),
        source: chk.clone(),
        target: chk,
    };
    let encoded = v.as_ssz_bytes();
    let decoded = AttestationData::from_ssz_bytes(&encoded).expect("AttestationData decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        AttestationData::default().tree_hash_root(),
        "non-default AttestationData root must differ"
    );
}

#[test]
fn indexed_attestation_roundtrip() {
    use pharos_ssz::SszList;
    use pharos_types::phase0::MinimalIndexedAttestation;
    let v = MinimalIndexedAttestation {
        attesting_indices: SszList::from_vec(vec![ValidatorIndex(1), ValidatorIndex(2)])
            .expect("list from vec"),
        ..Default::default()
    };
    let encoded = v.as_ssz_bytes();
    let decoded =
        MinimalIndexedAttestation::from_ssz_bytes(&encoded).expect("IndexedAttestation decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        MinimalIndexedAttestation::default().tree_hash_root(),
        "non-default IndexedAttestation root must differ"
    );
}

#[test]
fn pending_attestation_roundtrip() {
    use pharos_types::phase0::MinimalPendingAttestation;
    let v = MinimalPendingAttestation {
        inclusion_delay: Slot(3),
        proposer_index: ValidatorIndex(5),
        ..Default::default()
    };
    let encoded = v.as_ssz_bytes();
    let decoded =
        MinimalPendingAttestation::from_ssz_bytes(&encoded).expect("PendingAttestation decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        MinimalPendingAttestation::default().tree_hash_root(),
        "non-default PendingAttestation root must differ"
    );
}

#[test]
fn attestation_roundtrip() {
    use pharos_types::phase0::MinimalAttestation;
    let v = MinimalAttestation {
        signature: BLSSignature::from_array([0xAA; 96]),
        ..Default::default()
    };
    let encoded = v.as_ssz_bytes();
    let decoded = MinimalAttestation::from_ssz_bytes(&encoded).expect("Attestation decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        MinimalAttestation::default().tree_hash_root(),
        "non-default Attestation root must differ"
    );
}

#[test]
fn attester_slashing_roundtrip() {
    use pharos_types::phase0::MinimalAttesterSlashing;
    let v = MinimalAttesterSlashing {
        attestation_1: {
            use pharos_types::phase0::MinimalIndexedAttestation;
            MinimalIndexedAttestation {
                signature: BLSSignature::from_array([0x01; 96]),
                ..Default::default()
            }
        },
        ..Default::default()
    };
    let encoded = v.as_ssz_bytes();
    let decoded =
        MinimalAttesterSlashing::from_ssz_bytes(&encoded).expect("AttesterSlashing decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        MinimalAttesterSlashing::default().tree_hash_root(),
        "non-default AttesterSlashing root must differ"
    );
}

#[test]
fn eth1_data_roundtrip() {
    use pharos_types::phase0::Eth1Data;
    use pharos_utils::Hash256;
    let v = Eth1Data {
        deposit_root: Hash256::from_array([0x55; 32]),
        deposit_count: 42,
        block_hash: Hash256::from_array([0x66; 32]),
    };
    let encoded = v.as_ssz_bytes();
    let decoded = Eth1Data::from_ssz_bytes(&encoded).expect("Eth1Data decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        Eth1Data::default().tree_hash_root(),
        "non-default Eth1Data root must differ"
    );
}

#[test]
fn deposit_message_roundtrip() {
    use pharos_types::phase0::DepositMessage;
    let v = DepositMessage {
        pubkey: BLSPubkey::from_array([0x77; 48]),
        withdrawal_credentials: Bytes32::from_array([0x88; 32]),
        amount: Gwei(32_000_000_000),
    };
    let encoded = v.as_ssz_bytes();
    let decoded = DepositMessage::from_ssz_bytes(&encoded).expect("DepositMessage decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        DepositMessage::default().tree_hash_root(),
        "non-default DepositMessage root must differ"
    );
}

#[test]
fn deposit_data_roundtrip() {
    use pharos_types::phase0::DepositData;
    let v = DepositData {
        pubkey: BLSPubkey::from_array([0x11; 48]),
        withdrawal_credentials: Bytes32::from_array([0x22; 32]),
        amount: Gwei(1_000_000_000),
        signature: BLSSignature::from_array([0x33; 96]),
    };
    let encoded = v.as_ssz_bytes();
    let decoded = DepositData::from_ssz_bytes(&encoded).expect("DepositData decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        DepositData::default().tree_hash_root(),
        "non-default DepositData root must differ"
    );
}

#[test]
fn beacon_block_header_roundtrip() {
    use pharos_types::phase0::BeaconBlockHeader;
    use pharos_utils::Hash256;
    let v = BeaconBlockHeader {
        slot: Slot(99),
        proposer_index: ValidatorIndex(3),
        parent_root: Hash256::from_array([0xAA; 32]),
        state_root: Hash256::from_array([0xBB; 32]),
        body_root: Hash256::from_array([0xCC; 32]),
    };
    let encoded = v.as_ssz_bytes();
    let decoded = BeaconBlockHeader::from_ssz_bytes(&encoded).expect("BeaconBlockHeader decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        BeaconBlockHeader::default().tree_hash_root(),
        "non-default BeaconBlockHeader root must differ"
    );
}

#[test]
fn signing_data_roundtrip() {
    use pharos_types::phase0::SigningData;
    use pharos_utils::{Bytes32, Hash256};
    let v = SigningData {
        object_root: Hash256::from_array([0xDD; 32]),
        domain: Bytes32::from_array([0xEE; 32]),
    };
    let encoded = v.as_ssz_bytes();
    let decoded = SigningData::from_ssz_bytes(&encoded).expect("SigningData decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        SigningData::default().tree_hash_root(),
        "non-default SigningData root must differ"
    );
}

#[test]
fn proposer_slashing_roundtrip() {
    use pharos_types::phase0::{BeaconBlockHeader, ProposerSlashing, SignedBeaconBlockHeader};
    use pharos_utils::Hash256;
    let header = BeaconBlockHeader {
        slot: Slot(5),
        proposer_index: ValidatorIndex(10),
        parent_root: Hash256::from_array([0x01; 32]),
        state_root: Hash256::from_array([0x02; 32]),
        body_root: Hash256::from_array([0x03; 32]),
    };
    let signed = SignedBeaconBlockHeader {
        message: header,
        signature: BLSSignature::from_array([0x04; 96]),
    };
    let v = ProposerSlashing {
        signed_header_1: signed.clone(),
        signed_header_2: signed,
    };
    let encoded = v.as_ssz_bytes();
    let decoded = ProposerSlashing::from_ssz_bytes(&encoded).expect("ProposerSlashing decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        ProposerSlashing::default().tree_hash_root(),
        "non-default ProposerSlashing root must differ"
    );
}

#[test]
fn voluntary_exit_roundtrip() {
    use pharos_types::phase0::VoluntaryExit;
    let v = VoluntaryExit {
        epoch: Epoch(100),
        validator_index: ValidatorIndex(7),
    };
    let encoded = v.as_ssz_bytes();
    let decoded = VoluntaryExit::from_ssz_bytes(&encoded).expect("VoluntaryExit decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        VoluntaryExit::default().tree_hash_root(),
        "non-default VoluntaryExit root must differ"
    );
}

#[test]
fn signed_voluntary_exit_roundtrip() {
    use pharos_types::phase0::{SignedVoluntaryExit, VoluntaryExit};
    let v = SignedVoluntaryExit {
        message: VoluntaryExit {
            epoch: Epoch(200),
            validator_index: ValidatorIndex(8),
        },
        signature: BLSSignature::from_array([0x55; 96]),
    };
    let encoded = v.as_ssz_bytes();
    let decoded =
        SignedVoluntaryExit::from_ssz_bytes(&encoded).expect("SignedVoluntaryExit decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        SignedVoluntaryExit::default().tree_hash_root(),
        "non-default SignedVoluntaryExit root must differ"
    );
}

#[test]
fn signed_beacon_block_header_roundtrip() {
    use pharos_types::phase0::{BeaconBlockHeader, SignedBeaconBlockHeader};
    let v = SignedBeaconBlockHeader {
        message: BeaconBlockHeader {
            slot: Slot(50),
            ..Default::default()
        },
        signature: BLSSignature::from_array([0xCC; 96]),
    };
    let encoded = v.as_ssz_bytes();
    let decoded =
        SignedBeaconBlockHeader::from_ssz_bytes(&encoded).expect("SignedBeaconBlockHeader decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        SignedBeaconBlockHeader::default().tree_hash_root(),
        "non-default SignedBeaconBlockHeader root must differ"
    );
}

#[test]
fn beacon_block_body_roundtrip() {
    use pharos_types::phase0::MinimalBeaconBlockBody;
    use pharos_utils::Bytes32;
    let v = MinimalBeaconBlockBody {
        graffiti: Bytes32::from_array([0x01; 32]),
        ..Default::default()
    };
    let encoded = v.as_ssz_bytes();
    let decoded = MinimalBeaconBlockBody::from_ssz_bytes(&encoded).expect("BeaconBlockBody decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        MinimalBeaconBlockBody::default().tree_hash_root(),
        "non-default BeaconBlockBody root must differ"
    );
}

#[test]
fn beacon_block_roundtrip() {
    use pharos_types::phase0::MinimalBeaconBlock;
    let v = MinimalBeaconBlock {
        slot: Slot(77),
        ..Default::default()
    };
    let encoded = v.as_ssz_bytes();
    let decoded = MinimalBeaconBlock::from_ssz_bytes(&encoded).expect("BeaconBlock decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        MinimalBeaconBlock::default().tree_hash_root(),
        "non-default BeaconBlock root must differ"
    );
}

// ── validator.md container round-trips ───────────────────────────────────────

#[test]
fn eth1_block_roundtrip() {
    use pharos_types::phase0::Eth1Block;
    use pharos_utils::Hash256;
    let v = Eth1Block {
        timestamp: 1_700_000_000,
        deposit_root: Hash256::from_array([0xAB; 32]),
        deposit_count: 1024,
    };
    let encoded = v.as_ssz_bytes();
    let decoded = Eth1Block::from_ssz_bytes(&encoded).expect("Eth1Block decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        Eth1Block::default().tree_hash_root(),
        "non-default Eth1Block root must differ"
    );
}

#[test]
fn aggregate_and_proof_roundtrip() {
    use pharos_types::phase0::MinimalAggregateAndProof;
    let v = MinimalAggregateAndProof {
        aggregator_index: ValidatorIndex(42),
        selection_proof: BLSSignature::from_array([0x55; 96]),
        ..Default::default()
    };
    let encoded = v.as_ssz_bytes();
    let decoded =
        MinimalAggregateAndProof::from_ssz_bytes(&encoded).expect("AggregateAndProof decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        MinimalAggregateAndProof::default().tree_hash_root(),
        "non-default AggregateAndProof root must differ"
    );
}

#[test]
fn signed_aggregate_and_proof_roundtrip() {
    use pharos_types::phase0::MinimalSignedAggregateAndProof;
    let v = MinimalSignedAggregateAndProof {
        signature: BLSSignature::from_array([0x66; 96]),
        ..Default::default()
    };
    let encoded = v.as_ssz_bytes();
    let decoded = MinimalSignedAggregateAndProof::from_ssz_bytes(&encoded)
        .expect("SignedAggregateAndProof decode");
    assert_eq!(v, decoded);
    assert_ne!(
        v.tree_hash_root(),
        MinimalSignedAggregateAndProof::default().tree_hash_root(),
        "non-default SignedAggregateAndProof root must differ"
    );
}
