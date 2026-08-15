//! Gossip-validation benchmarks.
//!
//! Covers:
//!   - `lc_finality_update`  (M4c baseline; O(1) tree-hash compare)
//!   - `beacon_block`        (M4e; proposer lookup + 1× BLS verify)
//!   - `attestation_unaggregated` (M4e; committee compute + 1× BLS verify)
//!   - `aggregate_and_proof` (M4e; committee compute + 3× BLS verify)
//!   - `attestation_cache_warm` (M4e; measures IGNORE-path with both
//!     committee_cache and seen_attestation_validators pre-populated,
//!     isolating the pure dedup-overhead cost from committee-compute cost)
//!
//! All benches use `MinimalEthSpec` (6-second slots, 8 slots/epoch) so that
//! fixture construction is deterministic and fast.
//!
//! **Note on cache behaviour across criterion samples**
//!
//! `beacon_block` and `attestation_unaggregated` use a monotonically
//! increasing slot/index counter so that each criterion sample exercises
//! the full Accept path (proposer lookup or committee compute + BLS verify).
//! Each sample's slot is unique, so the internal caches (`proposer_cache`,
//! `committee_cache`) are cold on every sample.  The doc-comment on each
//! bench function notes the per-iteration cache state.
//!
//! Per M4c precedent (`D-bench-location-per-crate`, `D-bench-iter-batched`),
//! benches live here rather than in the integration-test folder, and use
//! `iter_batched` to keep fixture construction in the unmeasured setup phase.
//!
//! The fixture helpers are duplicated from
//! `crates/pharos-node/tests/gossip_validators_e2e.rs` because criterion
//! bench files cannot import from `tests/`.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use blst::min_pk::SecretKey as BlstSecretKey;
use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use parking_lot::RwLock;
use pharos_fork_choice::get_forkchoice_store;
use pharos_network::host::{GossipValidator as _, GossipVerdict};
use pharos_ssz::{Bitlist, SszList, TreeHash};
use pharos_stf::phase0::accessors::{
    compute_epoch_at_slot, compute_signing_root, compute_subnet_for_attestation,
    get_beacon_committee, get_beacon_proposer_index, get_committee_count_per_slot, get_domain,
};
use pharos_stf::phase0::helpers::{
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
    DOMAIN_SELECTION_PROOF,
};
use pharos_stf::process_slots_fork;
use pharos_storage::{RocksStore, RocksStoreConfig, Store as StoreTrait};
use pharos_types::EthSpec;
use pharos_types::MinimalEthSpec as E;
use pharos_types::RuntimeConfig;
use pharos_types::altair::light_client::LightClientFinalityUpdate;
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
use pharos_utils::bls::BLS_DST;
use pharos_utils::{BLSPubkey, BLSSignature, Gwei};

use pharos_node::host_impl::HostImpl;

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

/// Build a `HostImpl<E>` (MinimalEthSpec) with 8 test validators at genesis.
///
/// `att_slot` governs `genesis_time`: the store's genesis_time is set so that
/// `att_slot` falls within the propagation window.
///
/// Returns `(host, genesis_root, fork_genesis_state)`.
fn make_bench_host(
    dir: &tempfile::TempDir,
    att_slot: u64,
) -> (HostImpl<E>, Root, ForkMinimalBeaconState) {
    let store = Arc::new(
        RocksStore::open::<E>(RocksStoreConfig {
            path: dir.path().join("chain_db"),
            create_if_missing: true,
        })
        .expect("open store"),
    );

    let genesis_slot = Slot(0);
    let seconds_per_slot = E::SLOT_DURATION_MS / 1000; // 6

    let validator = Validator {
        pubkey: test_pubkey(),
        effective_balance: Gwei(E::MAX_EFFECTIVE_BALANCE),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch(u64::MAX),
        withdrawable_epoch: Epoch(u64::MAX),
        slashed: false,
        ..Default::default()
    };
    let validators_list = SszList::from_vec(vec![validator; 8]).expect("8 validators within limit");
    let balances_list = SszList::from_vec(vec![Gwei(E::MAX_EFFECTIVE_BALANCE); 8])
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

    let fc_store = get_forkchoice_store::<E>(fork_genesis_state.clone(), fork_genesis_block);
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
        // Place genesis 3 slots before att_slot so all relevant slots are in
        // the past (block and attestation propagation windows both pass).
        let now_sec = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let lookback_slots = att_slot + 3;
        fc.genesis_time = now_sec.saturating_sub(lookback_slots * seconds_per_slot);
    }

    let gvr = Root::default();
    let fv = Version::from_array([0x00, 0x00, 0x00, 0x00]);
    let runtime_cfg = Arc::new(RuntimeConfig {
        seconds_per_slot,
        ..Default::default()
    });
    let host = HostImpl::<E>::new(store, fork_choice, gvr, fv, runtime_cfg);
    (host, genesis_root, fork_genesis_state)
}

// ── Fixture builders ──────────────────────────────────────────────────────────

/// Build a valid signed Phase0 block at the given `slot` with
/// `parent_root = genesis_root` and the expected proposer for that slot.
fn make_block_fixture(
    parent_root: Root,
    parent_state: &ForkMinimalBeaconState,
    slot: Slot,
    expected_proposer: u64,
) -> ForkMinimalSignedBeaconBlock {
    let block = MinimalBeaconBlock {
        slot,
        proposer_index: ValidatorIndex(expected_proposer),
        parent_root,
        state_root: Root::default(),
        body: MinimalBeaconBlockBody::default(),
    };

    let block_epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);
    let domain = get_domain::<E>(parent_state, DOMAIN_BEACON_PROPOSER, Some(block_epoch));
    let signing_root = compute_signing_root(&block, domain);
    let sig = test_sign(signing_root.as_ref());

    ForkMinimalSignedBeaconBlock::Phase0(MinimalSignedBeaconBlock {
        message: block,
        signature: sig,
    })
}

/// Build a valid unaggregated attestation for the given slot, committee_index=0.
fn make_att_fixture(
    beacon_block_root: Root,
    head_state: &ForkMinimalBeaconState,
    slot: Slot,
) -> (Attestation<2048>, u64 /* subnet */) {
    let committee_index = CommitteeIndex(0);
    let epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);

    let data = AttestationData {
        slot,
        index: committee_index,
        beacon_block_root,
        source: Checkpoint {
            epoch: Epoch(0),
            root: Root::default(),
        },
        target: Checkpoint {
            epoch,
            root: beacon_block_root,
        },
    };

    let domain = get_domain::<E>(head_state, DOMAIN_BEACON_ATTESTER, Some(epoch));
    let signing_root = compute_signing_root(&data, domain);
    let sig = test_sign(signing_root.as_ref());

    let mut bits = Bitlist::<2048>::new();
    bits.push(true).unwrap(); // single validator attests

    let committees_per_slot = get_committee_count_per_slot::<E>(head_state, epoch);
    let subnet = compute_subnet_for_attestation::<E>(committees_per_slot, slot, committee_index.0);

    let att = Attestation {
        aggregation_bits: bits,
        data,
        signature: sig,
    };
    (att, subnet)
}

/// Build a valid `SignedAggregateAndProof` for the given slot.
fn make_aap_fixture(
    beacon_block_root: Root,
    head_state: &ForkMinimalBeaconState,
    slot: Slot,
) -> SignedAggregateAndProof<2048> {
    let epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);

    // Determine aggregator: first member of committee at the given slot, index=0.
    let committee = get_beacon_committee::<E>(head_state, slot, 0);
    let aggregator_index = committee[0].0;

    let data = AttestationData {
        slot,
        index: CommitteeIndex(0),
        beacon_block_root,
        source: Checkpoint {
            epoch: Epoch(0),
            root: Root::default(),
        },
        target: Checkpoint {
            epoch,
            root: beacon_block_root,
        },
    };

    let mut bits = Bitlist::<2048>::new();
    for _ in 0..committee.len() {
        bits.push(true).unwrap();
    }

    let att_domain = get_domain::<E>(head_state, DOMAIN_BEACON_ATTESTER, Some(epoch));
    let att_sr = compute_signing_root(&data, att_domain);
    let att_sig = test_sign(att_sr.as_ref());

    let sel_domain = get_domain::<E>(head_state, DOMAIN_SELECTION_PROOF, Some(epoch));
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

    let aap_domain = get_domain::<E>(head_state, DOMAIN_AGGREGATE_AND_PROOF, Some(epoch));
    let aap_sr = compute_signing_root(&agg_and_proof, aap_domain);
    let aap_sig = test_sign(aap_sr.as_ref());

    SignedAggregateAndProof {
        message: agg_and_proof,
        signature: aap_sig,
    }
}

// ── Criterion benchmarks ──────────────────────────────────────────────────────

/// `gossip_validation/lc_finality_update` — M4c baseline.
///
/// Measures only the LC-finality-update validator body; the per-iter
/// RocksDB `put_light_client_finality_update` is in the `iter_batched` setup
/// phase (unmeasured).  First sample pays any cold path; subsequent samples
/// hit the warm RocksDB page cache.
fn bench_lc_finality_update(c: &mut Criterion) {
    use pharos_types::altair::light_client::LightClientHeader;
    use pharos_types::phase0::operations::BeaconBlockHeader;
    use pharos_types::phase0::primitives::Slot;

    let dir = tempfile::TempDir::new().unwrap();
    let host = {
        let store = Arc::new(
            RocksStore::open::<E>(RocksStoreConfig {
                path: dir.path().join("chain_db"),
                create_if_missing: true,
            })
            .expect("open store"),
        );
        let genesis_state = <E as EthSpec>::BeaconState::default();
        let state_root = genesis_state.tree_hash_root();
        let anchor_block = pharos_types::state::MinimalBeaconBlock::Phase0(
            pharos_types::phase0::MinimalBeaconBlock {
                state_root,
                ..pharos_types::phase0::MinimalBeaconBlock::default()
            },
        );
        let fc_store = pharos_fork_choice::get_forkchoice_store::<E>(genesis_state, anchor_block);
        let fork_choice = Arc::new(RwLock::new(fc_store));
        let gvr = Root::default();
        let fv = Version::from_array([0x00, 0x00, 0x00, 0x00]);
        let runtime_cfg = Arc::new(RuntimeConfig::default());
        HostImpl::new(store, fork_choice, gvr, fv, runtime_cfg)
    };

    let make_lc_update = |slot: u64| LightClientFinalityUpdate {
        finalized_header: LightClientHeader {
            beacon: BeaconBlockHeader {
                slot: Slot(slot),
                ..BeaconBlockHeader::default()
            },
        },
        attested_header: LightClientHeader {
            beacon: BeaconBlockHeader {
                slot: Slot(slot),
                ..BeaconBlockHeader::default()
            },
        },
        signature_slot: Slot(slot),
        ..Default::default()
    };

    let initial = make_lc_update(1);
    <RocksStore as StoreTrait<E>>::put_light_client_finality_update(&*host.store_arc(), &initial)
        .expect("put_light_client_finality_update failed in bench setup");

    let mut slot_counter: u64 = 1;

    c.bench_function("gossip_validation/lc_finality_update", |b| {
        b.iter_batched(
            || {
                slot_counter += 1;
                let msg = make_lc_update(slot_counter);
                <RocksStore as StoreTrait<E>>::put_light_client_finality_update(
                    &*host.store_arc(),
                    &msg,
                )
                .expect("put_light_client_finality_update failed in bench setup");
                msg
            },
            |msg| host.validate_light_client_finality_update(&msg),
            BatchSize::SmallInput,
        )
    });
}

/// `gossip_validation/beacon_block` — M4e baseline.
///
/// Measures the full Accept path for `validate_beacon_block`:
///   - proposer lookup (cold: `process_slots` + `get_beacon_proposer_index`)
///   - proposer-signature BLS verify (1×)
///
/// A monotonically increasing slot counter is used so that each criterion
/// sample exercises a fresh (slot, proposer) pair.  This keeps
/// `seen_block_proposers` from triggering the IGNORE early-exit, ensuring
/// every sample reaches the BLS-verify step.  As a result, `proposer_cache`
/// is cold on every sample (each slot is a unique cache key).
///
/// The expected proposers for slots 1..=200 are pre-computed outside the
/// bench loop so that setup overhead (process_slots) stays in the unmeasured
/// `iter_batched` setup phase.
fn bench_beacon_block(c: &mut Criterion) {
    let dir = tempfile::TempDir::new().unwrap();
    // Use att_slot=200 so genesis_time covers all slots 1..=200.
    let (host, genesis_root, genesis_state) = make_bench_host(&dir, 200);

    // Pre-compute expected proposers for slots 1..=200 outside the bench loop.
    let proposer_table: Vec<(Slot, u64)> = (1u64..=200)
        .map(|s| {
            let slot = Slot(s);
            let mut state = genesis_state.clone();
            process_slots_fork::<E>(&mut state, slot).expect("process_slots");
            let idx = get_beacon_proposer_index::<E>(&state).0;
            (slot, idx)
        })
        .collect();

    // Preflight: confirm slot 1 is on the Accept path before measuring.
    // Slot 1 is consumed by this assertion (seen_block_proposers now contains
    // (Slot(1), proposer_table[0].1)), so the bench loop iterates over
    // slots 2..=200 to avoid measuring an IGNORE on the first sample.
    let (preflight_slot, preflight_proposer) = proposer_table[0];
    let preflight_block = make_block_fixture(
        genesis_root,
        &genesis_state,
        preflight_slot,
        preflight_proposer,
    );
    assert_eq!(
        host.validate_beacon_block(&preflight_block),
        GossipVerdict::Accept,
        "bench preflight expects Accept on slot 1"
    );

    let usable = &proposer_table[1..]; // slots 2..=200
    let mut iter_idx: usize = 0;

    c.bench_function("gossip_validation/beacon_block", |b| {
        b.iter_batched(
            || {
                let (slot, proposer) = usable[iter_idx % usable.len()];
                iter_idx += 1;
                // Beyond `usable.len()` samples the bench wraps and measures the
                // RB3 dedup IGNORE path; unlikely within a 100-sample criterion run.
                make_block_fixture(genesis_root, &genesis_state, slot, proposer)
            },
            |block| {
                let _ = host.validate_beacon_block(&block);
            },
            BatchSize::SmallInput,
        )
    });
}

/// `gossip_validation/attestation_unaggregated` — M4e baseline.
///
/// Measures the full Accept path for `validate_attestation`:
///   - committee compute (cold: `process_slots` + `get_beacon_committee`)
///   - attestation-signature BLS verify (1×)
///
/// A monotonically increasing slot counter is used so that each sample
/// uses a fresh slot, keeping `committee_cache` cold on every sample
/// (slot is part of the cache key).  Every sample returns Accept.
fn bench_attestation_unaggregated(c: &mut Criterion) {
    let dir = tempfile::TempDir::new().unwrap();
    // att_slot=200 so all slots 1..=200 are in the propagation window.
    let (host, genesis_root, genesis_state) = make_bench_host(&dir, 200);

    // Pre-compute subnet for each slot.  MinimalEthSpec has 64 attestation
    // subnets and 8 validators; the subnet is deterministic per slot.
    let subnet_table: Vec<(Slot, u64)> = (0u64..=200)
        .map(|s| {
            let slot = Slot(s);
            let epoch = compute_epoch_at_slot(slot, E::SLOTS_PER_EPOCH);
            let cc = get_committee_count_per_slot::<E>(&genesis_state, epoch);
            let subnet = compute_subnet_for_attestation::<E>(cc, slot, 0);
            (slot, subnet)
        })
        .collect();

    // Preflight: confirm slot 0 is on the Accept path before measuring.
    // Slot 0 is consumed by this assertion; the bench loop iterates
    // over slots 1..=200 to avoid an RAT7 dedup IGNORE on the first sample.
    let (pf_slot, pf_subnet) = subnet_table[0];
    let (pf_att, _) = make_att_fixture(genesis_root, &genesis_state, pf_slot);
    assert_eq!(
        host.validate_attestation(pf_subnet, &pf_att),
        GossipVerdict::Accept,
        "bench preflight expects Accept on slot 0"
    );

    let usable = &subnet_table[1..]; // slots 1..=200
    let mut iter_idx: usize = 0;

    c.bench_function("gossip_validation/attestation_unaggregated", |b| {
        b.iter_batched(
            || {
                let (slot, subnet) = usable[iter_idx % usable.len()];
                iter_idx += 1;
                let (att, _computed_subnet) = make_att_fixture(genesis_root, &genesis_state, slot);
                (att, subnet)
            },
            |(att, subnet)| {
                let _ = host.validate_attestation(subnet, &att);
            },
            BatchSize::SmallInput,
        )
    });
}

/// `gossip_validation/aggregate_and_proof` — M4e baseline.
///
/// Measures the full Accept path for `validate_aggregate_and_proof`:
///   - committee compute (cold: `process_slots` + `get_beacon_committee`)
///   - selection-proof BLS verify (1×)
///   - outer-aggregator-signature BLS verify (1×)
///   - aggregate-attestation BLS verify (1×, via indexed attestation)
///
/// A monotonically increasing slot counter is used so that each sample
/// uses a fresh slot, keeping `committee_cache` cold and `seen_aggregators`
/// from triggering the IGNORE path.  Every sample returns Accept.
fn bench_aggregate_and_proof(c: &mut Criterion) {
    let dir = tempfile::TempDir::new().unwrap();
    // att_slot=200 so all slots 0..=200 are in the propagation window.
    let (host, genesis_root, genesis_state) = make_bench_host(&dir, 200);

    let slots: Vec<Slot> = (0u64..=200).map(Slot).collect();

    // Preflight: confirm slot 0 is on the Accept path before measuring.
    // Slot 0 is consumed by this assertion (seen_aggregators now contains
    // (aggregator_index, epoch_of_slot_0)); the bench loop uses slots 1..=200.
    let pf_saap = make_aap_fixture(genesis_root, &genesis_state, slots[0]);
    assert_eq!(
        host.validate_aggregate_and_proof(&pf_saap),
        GossipVerdict::Accept,
        "bench preflight expects Accept on slot 0"
    );

    let usable = &slots[1..]; // slots 1..=200
    let mut iter_idx: usize = 0;

    c.bench_function("gossip_validation/aggregate_and_proof", |b| {
        b.iter_batched(
            || {
                let slot = usable[iter_idx % usable.len()];
                iter_idx += 1;
                make_aap_fixture(genesis_root, &genesis_state, slot)
            },
            |saap| {
                let _ = host.validate_aggregate_and_proof(&saap);
            },
            BatchSize::SmallInput,
        )
    });
}

/// `gossip_validation/attestation_cache_warm` — M4e cache-contention micro-bench.
///
/// Measures the steady-state dedup-overhead path for `validate_attestation`:
/// committee_cache and seen_attestation_validators are both pre-populated
/// before the criterion sample loop.  Every sample short-circuits at the
/// RAT7 duplicate-validator IGNORE check, after a committee_cache hit.
///
/// Comparing this against `attestation_unaggregated` isolates the cost of:
///   `committee compute + BLS verify ≈ attestation_unaggregated − attestation_cache_warm`
///
/// Uses `iter_batched` per `D-bench-iter-batched` so that the fixture clone
/// stays in the unmeasured setup phase.  Pre-population happens once before
/// the bench via a single `validate_attestation` call on the warm fixture.
fn bench_attestation_cache_warm(c: &mut Criterion) {
    let dir = tempfile::TempDir::new().unwrap();
    // att_slot=0 is within the propagation window.
    let (host, genesis_root, genesis_state) = make_bench_host(&dir, 0);

    // Build the attestation fixture for slot=0 (the fixed slot used by all samples).
    let (warm_att, warm_subnet) = make_att_fixture(genesis_root, &genesis_state, Slot(0));

    // Pre-warm: call validate_attestation once outside the bench loop.
    // This populates:
    //   - committee_cache: key=(Slot(0), 0, genesis_root) → committee vec
    //   - seen_attestation_validators: key=(participant, epoch=0) → ()
    // After this call, ALL subsequent samples hit both caches and return IGNORE.
    let verdict = host.validate_attestation(warm_subnet, &warm_att);
    assert_eq!(
        verdict,
        GossipVerdict::Accept,
        "pre-warm call must Accept the fixture; got {verdict:?}"
    );

    c.bench_function("gossip_validation/attestation_cache_warm", |b| {
        b.iter_batched(
            || warm_att.clone(),
            |att| {
                // committee_cache hit + seen_attestation_validators hit → IGNORE.
                let _ = host.validate_attestation(warm_subnet, &att);
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(
    benches,
    bench_lc_finality_update,
    bench_beacon_block,
    bench_attestation_unaggregated,
    bench_aggregate_and_proof,
    bench_attestation_cache_warm,
);
criterion_main!(benches);
