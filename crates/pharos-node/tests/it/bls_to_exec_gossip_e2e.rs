//! Integration test for `validate_bls_to_execution_change`.
//!
//! Happy path (Accept) + a reject path for the
//! BLS-to-execution-change gossip validator.
//!
//! Uses `MinimalBeaconSpec` with capella_fork_epoch=0 so the validator runs.

use std::sync::Arc;

use blst::min_pk::SecretKey as BlstSecretKey;
use parking_lot::RwLock;
use pharos_fork_choice::get_forkchoice_store;
use pharos_network::host::{GossipValidator as _, GossipVerdict};
use pharos_ssz::{SszList, SszSequence as _, TreeHash};
use pharos_stf::phase0::accessors::{compute_domain, compute_signing_root};
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::capella::operations::{BLSToExecutionChange, SignedBLSToExecutionChange};
use pharos_types::fork::{DOMAIN_BLS_TO_EXECUTION_CHANGE, ForkSchedule};
use pharos_types::phase0::misc::{Fork, Validator};
use pharos_types::phase0::operations::BeaconBlockHeader;
use pharos_types::phase0::primitives::{Epoch, Root, Slot, ValidatorIndex, Version};
use pharos_types::phase0::{MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState};
use pharos_types::state::MinimalBeaconState as ForkMinimalBeaconState;
use pharos_types::{BeaconSpec, MinimalBeaconSpec, RuntimeConfig};
use pharos_utils::bls::BLS_DST;
use pharos_utils::{BLSPubkey, BLSSignature, Gwei};

use pharos_node::host_impl::HostImpl;

// ── BLS key helpers ───────────────────────────────────────────────────────────

/// Validator signing key (not the BLS withdrawal key).
fn val_sk() -> BlstSecretKey {
    BlstSecretKey::key_gen(&[77u8; 32], &[]).expect("valid IKM")
}
fn val_pubkey() -> BLSPubkey {
    BLSPubkey::from_array(val_sk().sk_to_pk().compress())
}

/// BLS withdrawal key used for `from_bls_pubkey`.
fn bls_withdrawal_sk() -> BlstSecretKey {
    BlstSecretKey::key_gen(&[88u8; 32], &[]).expect("valid IKM")
}
fn bls_withdrawal_pubkey() -> BLSPubkey {
    BLSPubkey::from_array(bls_withdrawal_sk().sk_to_pk().compress())
}

// ── Host construction ─────────────────────────────────────────────────────────

/// Build a `HostImpl<MinimalBeaconSpec>` with one validator whose withdrawal
/// credentials are `0x00 || hash(bls_withdrawal_pubkey)[1..]`.
///
/// `capella_fork_epoch` = 0 so the current-epoch-is-capella IGNORE check passes.
fn make_bls_host(dir: &tempfile::TempDir) -> HostImpl<MinimalBeaconSpec> {
    let store = Arc::new(
        RocksStore::open::<MinimalBeaconSpec>(RocksStoreConfig {
            path: dir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("open store"),
    );

    // Build 0x00 BLS withdrawal credential.
    let pubkey_hash = pharos_utils::hash::hash(bls_withdrawal_pubkey().as_slice());
    let mut creds = [0u8; 32];
    creds[0] = 0x00;
    creds[1..].copy_from_slice(&pubkey_hash.as_slice()[1..]);

    let genesis_slot = Slot(0);
    let validator = Validator {
        pubkey: val_pubkey(),
        effective_balance: Gwei(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch(u64::MAX),
        withdrawable_epoch: Epoch(u64::MAX),
        slashed: false,
        withdrawal_credentials: pharos_utils::Hash256::from_array(creds),
        ..Default::default()
    };

    let genesis_body_root = MinimalBeaconBlockBody::default().tree_hash_root();
    let genesis_state_inner = MinimalBeaconState {
        genesis_time: 0,
        slot: genesis_slot,
        fork: Fork {
            previous_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            current_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
            epoch: Epoch(0),
        },
        latest_block_header: BeaconBlockHeader {
            slot: genesis_slot,
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: Root::default(),
            body_root: genesis_body_root,
        },
        validators: SszList::with_push(&SszList::default(), validator).unwrap(),
        balances: SszList::with_push(
            &SszList::default(),
            Gwei(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE),
        )
        .unwrap(),
        ..Default::default()
    };

    let fork_genesis_state = ForkMinimalBeaconState::Phase0(genesis_state_inner);
    let genesis_inner_block = MinimalBeaconBlock {
        slot: genesis_slot,
        proposer_index: ValidatorIndex(0),
        parent_root: Root::default(),
        state_root: fork_genesis_state.tree_hash_root(),
        body: MinimalBeaconBlockBody::default(),
    };
    let genesis_root: Root = genesis_inner_block.tree_hash_root();
    let genesis_block = pharos_types::state::BeaconBlock::Phase0(genesis_inner_block);

    let fc_store = get_forkchoice_store::<MinimalBeaconSpec>(
        fork_genesis_state.clone(),
        genesis_block.clone(),
    );
    let fork_choice = Arc::new(RwLock::new(fc_store));
    {
        let mut fc = fork_choice.write();
        fc.block_states
            .insert(genesis_root, fork_genesis_state.clone());
        fc.blocks.insert(genesis_root, genesis_block);
    }

    let gvr = Root::default();
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
        altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
        altair_fork_epoch: Epoch(u64::MAX),
        bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
        bellatrix_fork_epoch: Epoch(u64::MAX),
        capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
        capella_fork_epoch: Epoch(0), // active at genesis
        deneb_fork_version: Version::from_array([0x04, 0x00, 0x00, 0x00]),
        deneb_fork_epoch: Epoch(u64::MAX),
        electra_fork_version: Version::from_array([0x05, 0x00, 0x00, 0x00]),
        electra_fork_epoch: Epoch(u64::MAX),
        fulu_fork_version: Version::from_array([0x06, 0x00, 0x00, 0x00]),
        fulu_fork_epoch: Epoch(u64::MAX),
        blob_schedule: Vec::new(),
        genesis_validators_root: gvr,
    };
    let runtime_cfg = Arc::new(RuntimeConfig {
        seconds_per_slot: MinimalBeaconSpec::SLOT_DURATION_MS / 1000,
        ..Default::default()
    });
    HostImpl::<MinimalBeaconSpec>::new(store, fork_choice, gvr, fork_schedule, 0, runtime_cfg)
}

fn make_valid_msg() -> SignedBLSToExecutionChange {
    let gvr = Root::default();
    let msg = BLSToExecutionChange {
        validator_index: ValidatorIndex(0),
        from_bls_pubkey: bls_withdrawal_pubkey(),
        to_execution_address: pharos_utils::FixedBytes::default(),
    };
    let domain = compute_domain(
        DOMAIN_BLS_TO_EXECUTION_CHANGE,
        MinimalBeaconSpec::GENESIS_FORK_VERSION,
        &gvr,
    );
    let sr = compute_signing_root(&msg, domain);
    let sig = BLSSignature::from_array(
        bls_withdrawal_sk()
            .sign(sr.as_ref(), BLS_DST, &[])
            .compress(),
    );
    SignedBLSToExecutionChange {
        message: msg,
        signature: sig,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Happy path: a well-formed, correctly-signed BLS-to-execution-change is accepted.
#[test]
fn bls_to_exec_happy_path_accept() {
    let dir = tempfile::TempDir::new().unwrap();
    let host = make_bls_host(&dir);
    let signed = make_valid_msg();
    assert_eq!(
        host.validate_bls_to_execution_change(&signed),
        GossipVerdict::Accept,
        "well-formed BLS-to-exec-change must be Accepted",
    );
}

/// A message with an incorrect (zero) BLS signature is rejected.
#[test]
fn bls_to_exec_reject_invalid_signature() {
    let dir = tempfile::TempDir::new().unwrap();
    let host = make_bls_host(&dir);
    let msg = BLSToExecutionChange {
        validator_index: ValidatorIndex(0),
        from_bls_pubkey: bls_withdrawal_pubkey(),
        to_execution_address: pharos_utils::FixedBytes::default(),
    };
    let signed = SignedBLSToExecutionChange {
        message: msg,
        signature: BLSSignature::from_array([0u8; 96]),
    };
    assert_eq!(
        host.validate_bls_to_execution_change(&signed),
        GossipVerdict::Reject("bls_to_exec: invalid signature".into()),
        "zero signature must be Rejected",
    );
}
