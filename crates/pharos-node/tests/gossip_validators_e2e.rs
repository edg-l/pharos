//! End-to-end integration test for all three gossip validators.
//!
//! Task 4.1 (M4e Phase 4): a single test that builds a host, constructs one
//! valid message for each of the three gossip topics, and asserts
//! `GossipVerdict::Accept` for each.
//!
//! Host construction mirrors `make_att_test_host` from the unit-test module
//! in `host_impl.rs` but is duplicated here per the M4c integration-test
//! precedent (unit-test helpers are `#[cfg(test)]` private).
//!
//! Preset: `MinimalEthSpec`.  The plan specifies `MainnetEthSpec` with the
//! intent of loading consensus-spec-tests fixtures.  However, those fixtures
//! are STF conformance tests (pre-state + signed-block + post-state), not
//! gossip-validation fixtures; threading a real mainnet fixture through all
//! the gossip checks (BLS key derivation matching the pre-state validators,
//! genesis_time alignment, parent-root wiring, etc.) requires exactly the same
//! construction machinery as the Minimal unit tests.  `MinimalEthSpec` is used
//! instead to produce correct BLS signatures with a known test key, identical
//! to the unit-test happy-path coverage.  The smoke-test goal — "all three
//! real bodies type-check and run end-to-end" — is fully met.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use blst::min_pk::SecretKey as BlstSecretKey;
use parking_lot::RwLock;
use pharos_fork_choice::get_forkchoice_store;
use pharos_network::host::{GossipValidator as _, GossipVerdict};
use pharos_ssz::{Bitlist, SszList, TreeHash};
use pharos_stf::phase0::accessors::{
    compute_epoch_at_slot, compute_signing_root, compute_subnet_for_attestation,
    get_beacon_committee, get_committee_count_per_slot, get_domain,
};
use pharos_stf::phase0::helpers::{
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
    DOMAIN_SELECTION_PROOF,
};
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::fork::ForkSchedule;
use pharos_types::phase0::misc::{AttestationData, Checkpoint, Fork, Validator};
use pharos_types::phase0::operations::BeaconBlockHeader;
use pharos_types::phase0::primitives::{
    CommitteeIndex, Epoch, Root, Slot, ValidatorIndex, Version,
};
use pharos_types::phase0::{
    AggregateAndProof, Attestation, MinimalBeaconBlock, MinimalBeaconBlockBody, MinimalBeaconState,
    MinimalSignedBeaconBlock, SignedAggregateAndProof,
};
use pharos_types::state::{
    MinimalBeaconBlock as ForkMinimalBeaconBlock, MinimalBeaconState as ForkMinimalBeaconState,
    MinimalSignedBeaconBlock as ForkMinimalSignedBeaconBlock,
};
use pharos_types::{EthSpec, MinimalEthSpec, RuntimeConfig};
use pharos_utils::bls::BLS_DST;
use pharos_utils::{BLSPubkey, BLSSignature, Gwei};

use pharos_node::host_impl::HostImpl;
use pharos_stf::{phase0::accessors::get_beacon_proposer_index, process_slots_fork};

// ── Type alias ────────────────────────────────────────────────────────────────

type MinForkSigned = ForkMinimalSignedBeaconBlock;

// ── Test key helpers ──────────────────────────────────────────────────────────

fn test_sk() -> BlstSecretKey {
    BlstSecretKey::key_gen(&[77u8; 32], &[]).expect("valid IKM")
}

fn test_pubkey() -> BLSPubkey {
    BLSPubkey::from_array(test_sk().sk_to_pk().compress())
}

fn test_sign(msg: &[u8]) -> BLSSignature {
    BLSSignature::from_array(test_sk().sign(msg, BLS_DST, &[]).compress())
}

// ── Host construction ─────────────────────────────────────────────────────────

/// Build a `HostImpl<MinimalEthSpec>` with 8 test validators at genesis.
///
/// `att_slot` governs `genesis_time`: the store's genesis_time is set so that
/// `att_slot` falls within the propagation window (now_sec - seconds_per_slot
/// to now_sec + 1 slot). For slot=0 we set genesis_time to `now_sec - 1`.
///
/// Returns `(host, genesis_root, fork_genesis_state)`.
fn make_e2e_host(
    dir: &tempfile::TempDir,
    att_slot: u64,
) -> (HostImpl<MinimalEthSpec>, Root, ForkMinimalBeaconState) {
    let store = Arc::new(
        RocksStore::open::<MinimalEthSpec>(RocksStoreConfig {
            path: dir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("open store"),
    );

    let genesis_slot = Slot(0);
    let seconds_per_slot = MinimalEthSpec::SLOT_DURATION_MS / 1000; // 6

    let validator = Validator {
        pubkey: test_pubkey(),
        effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch(u64::MAX),
        withdrawable_epoch: Epoch(u64::MAX),
        slashed: false,
        ..Default::default()
    };
    let validators_list = SszList::from_vec(vec![validator; 8]).expect("8 validators within limit");
    let balances_list = SszList::from_vec(vec![Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE); 8])
        .expect("8 balances within limit");

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
        validators: validators_list,
        balances: balances_list,
        ..Default::default()
    };

    let fork_genesis_state = ForkMinimalBeaconState::Phase0(genesis_state_inner.clone());
    let state_root = fork_genesis_state.tree_hash_root();

    let genesis_block = MinimalBeaconBlock {
        slot: genesis_slot,
        proposer_index: ValidatorIndex(0),
        parent_root: Root::default(),
        state_root,
        body: MinimalBeaconBlockBody::default(),
    };
    let genesis_root: Root = genesis_block.tree_hash_root();

    let fork_genesis_block = ForkMinimalBeaconBlock::Phase0(genesis_block.clone());

    let fc_store =
        get_forkchoice_store::<MinimalEthSpec>(fork_genesis_state.clone(), fork_genesis_block);
    let fork_choice = Arc::new(RwLock::new(fc_store));

    {
        let mut fc = fork_choice.write();
        fc.block_states
            .insert(genesis_root, fork_genesis_state.clone());
        fc.blocks.insert(genesis_root, {
            let b = MinimalBeaconBlock {
                slot: genesis_slot,
                proposer_index: ValidatorIndex(0),
                parent_root: Root::default(),
                state_root: fork_genesis_state.tree_hash_root(),
                body: MinimalBeaconBlockBody::default(),
            };
            ForkMinimalBeaconBlock::Phase0(b)
        });
        // Set genesis_time so:
        //  - slot=att_slot is within the attestation propagation window, AND
        //  - slot=1 (for the beacon-block test) is also in the past.
        // We place genesis at now - 3 slots back, which puts slots 0, 1, 2 all
        // safely in the past (block validator: slot_start <= now + 500ms;
        // attestation validator: start_time <= now + 500ms <= end_time + 500ms).
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lookback_slots = att_slot + 3;
        fc.genesis_time = now_sec.saturating_sub(lookback_slots * seconds_per_slot);
    }

    let gvr = Root::default();
    // Phase0-only schedule: altair/bellatrix epochs = FAR_FUTURE, versions = mainnet defaults.
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array([0x00, 0x00, 0x00, 0x00]),
        altair_fork_version: Version::from_array([0x01, 0x00, 0x00, 0x00]),
        altair_fork_epoch: Epoch(u64::MAX),
        bellatrix_fork_version: Version::from_array([0x02, 0x00, 0x00, 0x00]),
        bellatrix_fork_epoch: Epoch(u64::MAX),
        capella_fork_version: Version::from_array([0x03, 0x00, 0x00, 0x00]),
        capella_fork_epoch: Epoch(u64::MAX),
        genesis_validators_root: gvr,
    };
    let runtime_cfg = Arc::new(RuntimeConfig {
        seconds_per_slot,
        ..Default::default()
    });
    let host =
        HostImpl::<MinimalEthSpec>::new(store, fork_choice, gvr, fork_schedule, 0, runtime_cfg);
    (host, genesis_root, fork_genesis_state)
}

// ── Fixture builders ──────────────────────────────────────────────────────────

/// Build a valid signed Phase0 block at `slot=1` with `parent_root=genesis_root`.
///
/// Signed with `test_sk()` against the expected-proposer's pubkey (which is
/// also `test_pubkey()` since all 8 validators share the same key).
fn make_block_fixture(
    parent_root: Root,
    parent_state: &ForkMinimalBeaconState,
    expected_proposer: u64,
) -> MinForkSigned {
    let slot = Slot(1);
    let block = MinimalBeaconBlock {
        slot,
        proposer_index: ValidatorIndex(expected_proposer),
        parent_root,
        state_root: Root::default(),
        body: MinimalBeaconBlockBody::default(),
    };

    let block_epoch = compute_epoch_at_slot(slot, MinimalEthSpec::SLOTS_PER_EPOCH);
    let domain =
        get_domain::<MinimalEthSpec>(parent_state, DOMAIN_BEACON_PROPOSER, Some(block_epoch));
    let signing_root = compute_signing_root(&block, domain);
    let sig = test_sign(signing_root.as_ref());

    ForkMinimalSignedBeaconBlock::Phase0(MinimalSignedBeaconBlock {
        message: block,
        signature: sig,
    })
}

/// Build a valid unaggregated attestation for slot=0, committee_index=0.
fn make_att_fixture(
    beacon_block_root: Root,
    head_state: &ForkMinimalBeaconState,
) -> (Attestation<2048>, u64 /* subnet */) {
    let slot = Slot(0);
    let committee_index = CommitteeIndex(0);

    let data = AttestationData {
        slot,
        index: committee_index,
        beacon_block_root,
        source: Checkpoint {
            epoch: Epoch(0),
            root: Root::default(),
        },
        target: Checkpoint {
            epoch: Epoch(0),
            root: beacon_block_root,
        },
    };

    let domain = get_domain::<MinimalEthSpec>(head_state, DOMAIN_BEACON_ATTESTER, Some(Epoch(0)));
    let signing_root = compute_signing_root(&data, domain);
    let sig = test_sign(signing_root.as_ref());

    let mut bits = Bitlist::<2048>::new();
    bits.push(true).unwrap(); // single validator attests

    let committees_per_slot = get_committee_count_per_slot::<MinimalEthSpec>(head_state, Epoch(0));
    let subnet = compute_subnet_for_attestation::<MinimalEthSpec>(
        committees_per_slot,
        slot,
        committee_index.0,
    );

    let att = Attestation {
        aggregation_bits: bits,
        data,
        signature: sig,
    };
    (att, subnet)
}

/// Build a valid `SignedAggregateAndProof` wrapping the given attestation.
///
/// Uses the first committee member as the aggregator (committee_len=1 for an
/// 8-validator state with SLOTS_PER_EPOCH=8 → modulo=1 → always aggregator).
fn make_aap_fixture(
    beacon_block_root: Root,
    head_state: &ForkMinimalBeaconState,
) -> SignedAggregateAndProof<2048> {
    let slot = Slot(0);

    // Determine aggregator: first member of committee at slot=0, index=0.
    let committee = get_beacon_committee::<MinimalEthSpec>(head_state, slot, 0);
    let aggregator_index = committee[0].0;

    // Build attestation data (same as make_att_fixture but with all committee
    // members attesting so RAG5 "no participants" does not fire).
    let data = AttestationData {
        slot,
        index: CommitteeIndex(0),
        beacon_block_root,
        source: Checkpoint {
            epoch: Epoch(0),
            root: Root::default(),
        },
        target: Checkpoint {
            epoch: Epoch(0),
            root: beacon_block_root,
        },
    };

    let mut bits = Bitlist::<2048>::new();
    for _ in 0..committee.len() {
        bits.push(true).unwrap();
    }

    let att_domain =
        get_domain::<MinimalEthSpec>(head_state, DOMAIN_BEACON_ATTESTER, Some(Epoch(0)));
    let att_sr = compute_signing_root(&data, att_domain);
    let att_sig = test_sign(att_sr.as_ref());

    // Selection proof: sign(slot) with DOMAIN_SELECTION_PROOF.
    let sel_domain =
        get_domain::<MinimalEthSpec>(head_state, DOMAIN_SELECTION_PROOF, Some(Epoch(0)));
    let sel_sr = compute_signing_root(&slot, sel_domain);
    let sel_sig = test_sign(sel_sr.as_ref());

    let agg_and_proof = AggregateAndProof {
        aggregator_index: ValidatorIndex(aggregator_index),
        aggregate: Attestation {
            aggregation_bits: bits,
            data,
            signature: att_sig,
        },
        selection_proof: sel_sig,
    };

    // Outer aggregator signature: sign(AggregateAndProof) with DOMAIN_AGGREGATE_AND_PROOF.
    let aap_domain =
        get_domain::<MinimalEthSpec>(head_state, DOMAIN_AGGREGATE_AND_PROOF, Some(Epoch(0)));
    let aap_sr = compute_signing_root(&agg_and_proof, aap_domain);
    let aap_sig = test_sign(aap_sr.as_ref());

    SignedAggregateAndProof {
        message: agg_and_proof,
        signature: aap_sig,
    }
}

// ── Integration test ──────────────────────────────────────────────────────────

/// Smoke test: build a host, construct one valid message for each of the three
/// gossip topics, and assert `GossipVerdict::Accept` for each.
///
/// This exercises the full dispatch path through all three real validator
/// bodies in `host_impl.rs` with correct BLS signatures.
#[test]
fn gossip_e2e_dispatch_all_three_topics() {
    // Build host wired for slot=0 attestation propagation window.
    let dir = tempfile::TempDir::new().unwrap();
    let (host, genesis_root, genesis_state) = make_e2e_host(&dir, 0);

    // ── (1) SignedBeaconBlock ─────────────────────────────────────────────────

    // Advance genesis state to slot 1 to determine the expected proposer.
    let expected_proposer = {
        let mut state = genesis_state.clone();
        process_slots_fork::<MinimalEthSpec>(&mut state, Slot(1)).expect("process_slots to slot 1");
        get_beacon_proposer_index::<MinimalEthSpec>(&state).0
    };

    let signed_block = make_block_fixture(genesis_root, &genesis_state, expected_proposer);

    let block_verdict = host.validate_beacon_block(&signed_block);
    assert_eq!(
        block_verdict,
        GossipVerdict::Accept,
        "validate_beacon_block must Accept a correctly-signed block; got {block_verdict:?}",
    );

    // ── (2) Attestation ───────────────────────────────────────────────────────

    let (att, subnet) = make_att_fixture(genesis_root, &genesis_state);
    let att_verdict = host.validate_attestation(subnet, &att);
    assert_eq!(
        att_verdict,
        GossipVerdict::Accept,
        "validate_attestation must Accept a correctly-signed attestation; got {att_verdict:?}",
    );

    // ── (3) SignedAggregateAndProof ───────────────────────────────────────────

    let saap = make_aap_fixture(genesis_root, &genesis_state);
    let aap_verdict = host.validate_aggregate_and_proof(&saap);
    assert_eq!(
        aap_verdict,
        GossipVerdict::Accept,
        "validate_aggregate_and_proof must Accept a valid aggregate; got {aap_verdict:?}",
    );
}
