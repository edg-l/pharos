//! Light-client gossip publish integration tests.
//!
//! Task 2.7 (M4c Phase 2): verify that the block-ingestion loop correctly
//! writes LC snapshots and publishes LC gossip updates after each head change.
//!
//! Tests:
//!   (a) `snapshots_written_after_altair_block` — run one Altair block through
//!       the ingestion loop and assert the RocksDB LC finality update CF is
//!       populated.
//!   (b) `publish_called_after_head_change` — spy on the `NetworkCommandSender`
//!       channel and confirm two `Publish` commands (finality + optimistic) are
//!       observed after one Altair block.
//!   (c) `no_publish_for_phase0_block` — feed a Phase 0 block; assert zero
//!       `Publish` commands are emitted.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use pharos_engine::spawn_engine_actor;
use pharos_fork_choice::get_forkchoice_store;
use pharos_network::host::ForkContext as _;
use pharos_network::host::LightClientProvider as _;
use pharos_network::network::NetworkCommand;
use pharos_network::network::NetworkEvent;
use pharos_network::topics::{GossipTopic, GossipTopicKind};
use pharos_network::types::Fork as NetworkFork;
use pharos_ssz::{Bitvector, SszList, SszSequence as _, SszVector, TreeHash};
use pharos_stf::NullExecutionEngine;
use pharos_types::altair::{
    MinimalBeaconBlock as AltairMinimalBeaconBlock,
    MinimalBeaconBlockBody as AltairMinimalBeaconBlockBody,
    MinimalBeaconState as AltairMinimalBeaconState,
    MinimalSignedBeaconBlock as AltairMinimalSignedBeaconBlock, MinimalSyncAggregate,
    MinimalSyncCommittee,
};
use pharos_types::fork::ForkSchedule;
use pharos_types::phase0::misc::{Fork, Validator};
use pharos_types::phase0::operations::BeaconBlockHeader;
use pharos_types::phase0::primitives::{Epoch, Gwei, Root, Slot, ValidatorIndex, Version};
use pharos_types::phase0::{
    BeaconBlock as Phase0MinimalBeaconBlock, BeaconBlockBody as Phase0MinimalBeaconBlockBody,
    SignedBeaconBlock as Phase0MinimalSignedBeaconBlock,
};
use pharos_types::state::{
    MinimalBeaconBlock as ForkMinimalBeaconBlock, MinimalBeaconState as ForkMinimalBeaconState,
    MinimalSignedBeaconBlock as ForkMinimalSignedBeaconBlock,
};
use pharos_types::{EthSpec, MinimalEthSpec, RuntimeConfig};
use pharos_utils::{BLSPubkey, BLSSignature};
use tokio::sync::{mpsc, watch};

use pharos_node::block_ingestion::{IngestionEgress, run_block_ingestion_loop};
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest};
use pharos_node::host_impl::HostImpl;
use pharos_node::pow_block::EnginePowBlockProvider;

mod common;

// ── Shared Altair fixture builder ─────────────────────────────────────────────

/// A root that is used as the anchor state's `finalized_checkpoint.root`.
///
/// Set to a recognisable non-zero value. After calling
/// `get_forkchoice_store`, a dummy Altair block with this key is inserted into
/// `fc_store.blocks` so that `dispatch_update_light_client_snapshots` finds a
/// non-None `finalized_block` and writes a `LightClientFinalityUpdate`.
const DUMMY_FINALIZED_ROOT: [u8; 32] = [0x42u8; 32];

/// Build a minimal Altair anchor state + anchor block for light-client tests.
///
/// The state has one active validator, proper sync committees, and its
/// `finalized_checkpoint.root` set to `DUMMY_FINALIZED_ROOT` so that the LC
/// snapshot writer can find a `finalized_block` in the fork-choice store
/// (inserted separately after this call).
///
/// Returns `(anchor_state_inner, anchor_block_inner, anchor_block_root)`.
fn build_altair_anchor() -> (AltairMinimalBeaconState, AltairMinimalBeaconBlock, Root) {
    use blst::min_pk::SecretKey;

    let sk = SecretKey::key_gen(&[1u8; 32], &[]).expect("valid IKM");
    let pubkey = BLSPubkey::from_array(sk.sk_to_pk().compress());

    let sync_committee = MinimalSyncCommittee {
        pubkeys: SszVector::from_vec(vec![pubkey; MinimalEthSpec::SYNC_COMMITTEE_SIZE as usize])
            .unwrap(),
        aggregate_pubkey: pubkey,
    };

    let validator = Validator {
        pubkey,
        effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch(u64::MAX),
        withdrawable_epoch: Epoch(u64::MAX),
        slashed: false,
        ..Validator::default()
    };

    // Build the anchor body first so we can hash it for latest_block_header.body_root.
    // Having at least 1 sync-committee participant satisfies MIN_SYNC_COMMITTEE_PARTICIPANTS.
    let anchor_body = AltairMinimalBeaconBlockBody {
        sync_aggregate: MinimalSyncAggregate {
            sync_committee_bits: {
                let mut bits = Bitvector::<32>::default();
                bits.set(0, true);
                bits
            },
            sync_committee_signature: BLSSignature::from_array([0u8; 96]),
        },
        ..AltairMinimalBeaconBlockBody::default()
    };
    let anchor_body_root: Root = anchor_body.tree_hash_root();

    // Build the anchor state with:
    //   - latest_block_header.body_root = anchor_body_root  (matches the anchor block)
    //   - latest_block_header.state_root = Root::default()  (zeroed per spec; process_slot
    //     will patch it to state.tree_hash_root() so that process_block_header_altair's
    //     parent_root check passes for block 1)
    //   - finalized_checkpoint.root = DUMMY_FINALIZED_ROOT  (so the LC snapshot writer
    //     finds a finalized_block in the store and writes a LightClientFinalityUpdate)
    let anchor_state = AltairMinimalBeaconState {
        genesis_time: 0,
        slot: Slot(0),
        fork: Fork {
            previous_version: Version::from_array([0x00, 0x00, 0x00, 0x01]),
            current_version: Version::from_array(MinimalEthSpec::ALTAIR_FORK_VERSION),
            epoch: Epoch(0),
        },
        latest_block_header: BeaconBlockHeader {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: Root::default(), // zeroed; process_slot will patch this
            body_root: anchor_body_root, // must match anchor_block.body
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
        finalized_checkpoint: pharos_types::phase0::Checkpoint {
            epoch: Epoch(0),
            root: Root::from_array(DUMMY_FINALIZED_ROOT),
        },
        ..AltairMinimalBeaconState::default()
    };

    // Build the anchor block with state_root = anchor_state.tree_hash_root().
    // This satisfies get_forkchoice_store's invariant:
    //   anchor_block.state_root() == anchor_state.tree_hash_root().
    let anchor_state_root = {
        let fork_state = ForkMinimalBeaconState::Altair(anchor_state.clone());
        fork_state.tree_hash_root()
    };

    let anchor_block = AltairMinimalBeaconBlock {
        slot: Slot(0),
        proposer_index: ValidatorIndex(0),
        parent_root: Root::default(),
        state_root: anchor_state_root,
        body: anchor_body,
    };

    let anchor_block_root = {
        let fork_block = ForkMinimalBeaconBlock::Altair(anchor_block.clone());
        fork_block.tree_hash_root()
    };

    (anchor_state, anchor_block, anchor_block_root)
}

/// Build an Altair signed block at `slot` with `parent_root` and at least 1
/// sync-committee participant.
fn build_altair_signed_block(slot: u64, parent_root: Root) -> ForkMinimalSignedBeaconBlock {
    let body = AltairMinimalBeaconBlockBody {
        sync_aggregate: MinimalSyncAggregate {
            sync_committee_bits: {
                let mut bits = Bitvector::<32>::default();
                bits.set(0, true);
                bits
            },
            sync_committee_signature: BLSSignature::from_array([0u8; 96]),
        },
        ..AltairMinimalBeaconBlockBody::default()
    };

    let block = AltairMinimalBeaconBlock {
        slot: Slot(slot),
        proposer_index: ValidatorIndex(0),
        parent_root,
        state_root: Root::default(), // validate_result: false — not checked
        body,
    };

    ForkMinimalSignedBeaconBlock::Altair(AltairMinimalSignedBeaconBlock {
        message: block,
        signature: BLSSignature::from_array([0u8; 96]),
    })
}

/// Shared setup: build the Altair fork-choice store + open a RocksStore.
///
/// Returns `(fc_store, host, pow_provider, tmpdir)` where `tmpdir` must be kept
/// alive for the duration of the test.
#[allow(clippy::type_complexity)]
fn build_altair_test_infra() -> (
    Arc<RwLock<pharos_fork_choice::Store<MinimalEthSpec>>>,
    Arc<HostImpl<MinimalEthSpec>>,
    Arc<EnginePowBlockProvider>,
    tempfile::TempDir,
) {
    let (anchor_state_inner, anchor_block_inner, _anchor_block_root) = build_altair_anchor();

    let fork_anchor_state = ForkMinimalBeaconState::Altair(anchor_state_inner);
    let fork_anchor_block = ForkMinimalBeaconBlock::Altair(anchor_block_inner);

    let mut fc = get_forkchoice_store::<MinimalEthSpec>(fork_anchor_state, fork_anchor_block);

    // Insert a dummy Altair block keyed by DUMMY_FINALIZED_ROOT so the LC
    // snapshot writer finds a non-None finalized_block and writes a
    // LightClientFinalityUpdate.
    let dummy_fin_block = ForkMinimalBeaconBlock::Altair(AltairMinimalBeaconBlock::default());
    fc.blocks
        .insert(Root::from_array(DUMMY_FINALIZED_ROOT), dummy_fin_block);

    // Advance time so on_block's future-slot guard doesn't reject blocks.
    fc.time = 10_000_000;

    let fc = Arc::new(RwLock::new(fc));

    let tmpdir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        pharos_storage::RocksStore::open::<MinimalEthSpec>(pharos_storage::RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .unwrap(),
    );

    let genesis_validators_root = Root::default();
    // Altair-at-genesis schedule: altair_fork_epoch = 0, bellatrix = FAR_FUTURE.
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array(MinimalEthSpec::GENESIS_FORK_VERSION),
        altair_fork_version: Version::from_array(MinimalEthSpec::ALTAIR_FORK_VERSION),
        altair_fork_epoch: Epoch(0),
        bellatrix_fork_version: Version::from_array(MinimalEthSpec::BELLATRIX_FORK_VERSION),
        bellatrix_fork_epoch: Epoch(u64::MAX),
        genesis_validators_root,
    };
    let host = Arc::new(HostImpl::<MinimalEthSpec>::new(
        store,
        Arc::clone(&fc),
        genesis_validators_root,
        fork_schedule,
        0,
        Arc::new(RuntimeConfig::default()),
    ));

    // EnginePowBlockProvider: for Altair blocks, pow-block lookup is never called.
    // We still need a real engine handle to construct it.
    let jwt_secret = pharos_engine::JwtSecret::from_bytes([0u8; 32]);
    let dummy_url: reqwest::Url = "http://127.0.0.1:9999/".parse().unwrap();
    let client = pharos_engine::EngineClient::new(dummy_url, jwt_secret).unwrap();
    let engine_handle = spawn_engine_actor(client, None);
    let pow_provider = Arc::new(EnginePowBlockProvider::new(engine_handle));

    (fc, host, pow_provider, tmpdir)
}

// ── Test (a): snapshots_written_after_altair_block ────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn snapshots_written_after_altair_block() {
    let _ = tracing_subscriber::fmt::try_init();

    let (fc, host, pow_provider, _tmpdir) = build_altair_test_infra();

    // Retrieve the anchor block root so we can set parent_root on block 1.
    let anchor_block_root = {
        let store = fc.read();
        store.justified_checkpoint.root
    };

    // Build a signed Altair block at slot 1.
    let signed_block = build_altair_signed_block(1, anchor_block_root);

    // Wire up the ingestion loop.
    let (head_tx, _head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalEthSpec>>(4);
    let (net_tx, _net_rx) = mpsc::channel(4);
    let net_sender = pharos_network::NetworkCommandSender::new(net_tx);

    let egress = IngestionEgress {
        head_tx,
        payload_tx,
        network: net_sender,
        notify_backfill: std::sync::Arc::new(tokio::sync::Notify::new()),
    };

    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(4);
    let fc_clone = Arc::clone(&fc);
    let host_clone = Arc::clone(&host);
    let exec_engine = Arc::new(NullExecutionEngine);
    tokio::spawn(async move {
        let _ = run_block_ingestion_loop::<MinimalEthSpec, NullExecutionEngine>(
            event_rx,
            host_clone,
            fc_clone,
            exec_engine,
            pow_provider,
            egress,
            false,
        )
        .await;
    });

    // SSZ-encode the fork-enum signed block and send as a GossipMessage.
    // Use the host's real Altair fork-digest so the by-fork-digest decode in
    // run_block_ingestion_loop (commit 211fd00) resolves to Altair, not Phase0.
    use pharos_ssz::Encode as _;
    // Real gossip carries the raw per-fork SSZ (no fork-enum discriminant), so
    // encode the inner per-fork block directly, matching the network wire format.
    let ssz_bytes = match &signed_block {
        ForkMinimalSignedBeaconBlock::Altair(inner) => inner.as_ssz_bytes(),
        _ => unreachable!("build_altair_signed_block always yields an Altair block"),
    };
    let fork_digest = host.fork_digest_for(NetworkFork::Altair);
    let topic = GossipTopic {
        fork_digest,
        kind: GossipTopicKind::BeaconBlock,
    };
    let dummy_peer = libp2p::PeerId::random();

    event_tx
        .send(NetworkEvent::GossipMessage {
            topic,
            peer: dummy_peer,
            data: ssz_bytes,
        })
        .await
        .unwrap();

    // Give the ingestion loop time to process the block and write snapshots.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Assert the LC finality update was written to RocksDB.
    let update = host.light_client_finality_update();
    assert!(
        update.is_some(),
        "expected LightClientFinalityUpdate in store after processing an Altair block"
    );
}

// ── Test (b): publish_called_after_head_change ────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn publish_called_after_head_change() {
    let _ = tracing_subscriber::fmt::try_init();

    let (fc, host, pow_provider, _tmpdir) = build_altair_test_infra();

    let anchor_block_root = {
        let store = fc.read();
        store.justified_checkpoint.root
    };

    let signed_block = build_altair_signed_block(1, anchor_block_root);

    let (head_tx, _head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalEthSpec>>(4);

    // Spy channel: capture NetworkCommand messages sent by the ingestion loop.
    let (net_tx, mut net_rx) = mpsc::channel::<NetworkCommand<MinimalEthSpec>>(16);
    let net_sender = pharos_network::NetworkCommandSender::new(net_tx);

    let egress = IngestionEgress {
        head_tx,
        payload_tx,
        network: net_sender,
        notify_backfill: std::sync::Arc::new(tokio::sync::Notify::new()),
    };

    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(4);
    let fc_clone = Arc::clone(&fc);
    let host_clone = Arc::clone(&host);
    let exec_engine = Arc::new(NullExecutionEngine);
    tokio::spawn(async move {
        let _ = run_block_ingestion_loop::<MinimalEthSpec, NullExecutionEngine>(
            event_rx,
            host_clone,
            fc_clone,
            exec_engine,
            pow_provider,
            egress,
            false,
        )
        .await;
    });

    use pharos_ssz::Encode as _;
    // Real gossip carries the raw per-fork SSZ (no fork-enum discriminant), so
    // encode the inner per-fork block directly, matching the network wire format.
    let ssz_bytes = match &signed_block {
        ForkMinimalSignedBeaconBlock::Altair(inner) => inner.as_ssz_bytes(),
        _ => unreachable!("build_altair_signed_block always yields an Altair block"),
    };
    // Real Altair fork-digest so the by-fork-digest decode resolves to Altair.
    let fork_digest = host.fork_digest_for(NetworkFork::Altair);
    let topic = GossipTopic {
        fork_digest,
        kind: GossipTopicKind::BeaconBlock,
    };
    let dummy_peer = libp2p::PeerId::random();

    event_tx
        .send(NetworkEvent::GossipMessage {
            topic,
            peer: dummy_peer,
            data: ssz_bytes,
        })
        .await
        .unwrap();

    // Collect NetworkCommand::Publish messages from the spy channel.
    // Expect at most 2 (finality + optimistic update) within a 2-second window.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    let mut publish_count = 0u32;
    let mut finality_seen = false;
    let mut optimistic_seen = false;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, net_rx.recv()).await {
            Ok(Some(NetworkCommand::Publish { topic, .. })) => {
                publish_count += 1;
                if topic.kind == GossipTopicKind::LightClientFinalityUpdate {
                    finality_seen = true;
                }
                if topic.kind == GossipTopicKind::LightClientOptimisticUpdate {
                    optimistic_seen = true;
                }
                if publish_count >= 2 {
                    break;
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => break,
        }
    }

    // Wait a bit longer to ensure no extra publishes happen.
    tokio::time::sleep(Duration::from_millis(200)).await;
    // Drain any remaining messages.
    while let Ok(cmd) = net_rx.try_recv() {
        if let NetworkCommand::Publish { topic, .. } = cmd {
            publish_count += 1;
            if topic.kind == GossipTopicKind::LightClientFinalityUpdate {
                finality_seen = true;
            }
            if topic.kind == GossipTopicKind::LightClientOptimisticUpdate {
                optimistic_seen = true;
            }
        }
    }

    assert_eq!(
        publish_count, 2,
        "expected exactly 2 publish calls (finality + optimistic), got {publish_count}"
    );
    assert!(
        finality_seen,
        "expected a LightClientFinalityUpdate publish"
    );
    assert!(
        optimistic_seen,
        "expected a LightClientOptimisticUpdate publish"
    );
}

// ── Test (c): no_publish_for_phase0_block ─────────────────────────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_publish_for_phase0_block() {
    let _ = tracing_subscriber::fmt::try_init();

    // Build a Phase0 fork-choice store from a minimal genesis state.
    let (_p0_state_inner, _p0_signed_block_inner) =
        common::checkpoint_helpers::build_anchor_bellatrix(Slot(0), 0);

    // Downgrade: use the Phase0 inner state from the Bellatrix state fields.
    // Actually, we need a genuine Phase0 state. Build one directly.
    let p0_anchor_body =
        pharos_types::phase0::BeaconBlockBody::<16, 2, 128, 16, 16, 2048, 33>::default();
    let p0_anchor_body_root: Root = p0_anchor_body.tree_hash_root();

    use blst::min_pk::SecretKey;
    let sk = SecretKey::key_gen(&[1u8; 32], &[]).expect("valid IKM");
    let pubkey = BLSPubkey::from_array(sk.sk_to_pk().compress());

    let validator = Validator {
        pubkey,
        effective_balance: Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
        activation_epoch: Epoch(0),
        exit_epoch: Epoch(u64::MAX),
        withdrawable_epoch: Epoch(u64::MAX),
        slashed: false,
        ..Validator::default()
    };

    let p0_anchor_state_inner = pharos_types::phase0::BeaconState::<
        64,
        16_777_216,
        32,
        1_099_511_627_776,
        64,
        64,
        1024,
        4,
        2048,
    > {
        genesis_time: 0,
        slot: Slot(0),
        fork: Fork {
            previous_version: Version::from_array([0u8; 4]),
            current_version: Version::from_array(MinimalEthSpec::GENESIS_FORK_VERSION),
            epoch: Epoch(0),
        },
        latest_block_header: BeaconBlockHeader {
            slot: Slot(0),
            proposer_index: ValidatorIndex(0),
            parent_root: Root::default(),
            state_root: Root::default(),
            body_root: p0_anchor_body_root,
        },
        validators: SszList::empty_tree().with_push(validator).unwrap(),
        balances: SszList::with_push(
            &SszList::default(),
            Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE),
        )
        .unwrap(),
        ..pharos_types::phase0::BeaconState::default()
    };

    let fork_state = ForkMinimalBeaconState::Phase0(p0_anchor_state_inner.clone());
    let p0_state_root: Root = fork_state.tree_hash_root();

    let p0_anchor_block_inner = Phase0MinimalBeaconBlock::<16, 2, 128, 16, 16, 2048, 33> {
        slot: Slot(0),
        proposer_index: ValidatorIndex(0),
        parent_root: Root::default(),
        state_root: p0_state_root,
        body: p0_anchor_body,
    };
    let fork_anchor_block = ForkMinimalBeaconBlock::Phase0(p0_anchor_block_inner.clone());
    let p0_anchor_block_root = fork_anchor_block.tree_hash_root();

    let mut fc = get_forkchoice_store::<MinimalEthSpec>(fork_state, fork_anchor_block);
    fc.time = 10_000_000;
    let fc = Arc::new(RwLock::new(fc));

    let tmpdir = tempfile::tempdir().unwrap();
    let store = Arc::new(
        pharos_storage::RocksStore::open::<MinimalEthSpec>(pharos_storage::RocksStoreConfig {
            path: tmpdir.path().join("chain_db"),
            create_if_missing: true,
        })
        .unwrap(),
    );
    let genesis_validators_root = Root::default();
    // Phase0-only schedule: altair/bellatrix epochs = FAR_FUTURE.
    let fork_schedule = ForkSchedule {
        genesis_fork_version: Version::from_array(MinimalEthSpec::GENESIS_FORK_VERSION),
        altair_fork_version: Version::from_array(MinimalEthSpec::ALTAIR_FORK_VERSION),
        altair_fork_epoch: Epoch(u64::MAX),
        bellatrix_fork_version: Version::from_array(MinimalEthSpec::BELLATRIX_FORK_VERSION),
        bellatrix_fork_epoch: Epoch(u64::MAX),
        genesis_validators_root,
    };
    let host = Arc::new(HostImpl::<MinimalEthSpec>::new(
        store,
        Arc::clone(&fc),
        genesis_validators_root,
        fork_schedule,
        0,
        Arc::new(RuntimeConfig::default()),
    ));

    let jwt_secret = pharos_engine::JwtSecret::from_bytes([0u8; 32]);
    let dummy_url: reqwest::Url = "http://127.0.0.1:9999/".parse().unwrap();
    let client = pharos_engine::EngineClient::new(dummy_url, jwt_secret).unwrap();
    let engine_handle = spawn_engine_actor(client, None);
    let pow_provider = Arc::new(EnginePowBlockProvider::new(engine_handle));

    // Build a Phase0 signed block at slot 1.
    let p0_block_body = Phase0MinimalBeaconBlockBody::<16, 2, 128, 16, 16, 2048, 33>::default();
    let p0_block = Phase0MinimalBeaconBlock::<16, 2, 128, 16, 16, 2048, 33> {
        slot: Slot(1),
        proposer_index: ValidatorIndex(0),
        parent_root: p0_anchor_block_root,
        state_root: Root::default(),
        body: p0_block_body,
    };
    let p0_signed = ForkMinimalSignedBeaconBlock::Phase0(Phase0MinimalSignedBeaconBlock::<
        16,
        2,
        128,
        16,
        16,
        2048,
        33,
    > {
        message: p0_block,
        signature: BLSSignature::from_array([0u8; 96]),
    });

    let (head_tx, _head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, _payload_rx) = mpsc::channel::<NewPayloadRequest<MinimalEthSpec>>(4);

    // Spy on publish calls.
    let (net_tx, mut net_rx) = mpsc::channel::<NetworkCommand<MinimalEthSpec>>(16);
    let net_sender = pharos_network::NetworkCommandSender::new(net_tx);

    let egress = IngestionEgress {
        head_tx,
        payload_tx,
        network: net_sender,
        notify_backfill: std::sync::Arc::new(tokio::sync::Notify::new()),
    };

    let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(4);
    let fc_clone = Arc::clone(&fc);
    let host_clone = Arc::clone(&host);
    let exec_engine = Arc::new(NullExecutionEngine);
    tokio::spawn(async move {
        let _ = run_block_ingestion_loop::<MinimalEthSpec, NullExecutionEngine>(
            event_rx,
            host_clone,
            fc_clone,
            exec_engine,
            pow_provider,
            egress,
            false,
        )
        .await;
    });

    use pharos_ssz::Encode as _;
    // Encode the inner Phase0 block directly (raw gossip carries no discriminant).
    let ssz_bytes = match &p0_signed {
        ForkMinimalSignedBeaconBlock::Phase0(inner) => inner.as_ssz_bytes(),
        _ => unreachable!("this test constructs a Phase0 block"),
    };
    // Real Phase0 fork-digest (round-trips to Phase0 via fork_from_context).
    let fork_digest = host.fork_digest_for(NetworkFork::Phase0);
    let topic = GossipTopic {
        fork_digest,
        kind: GossipTopicKind::BeaconBlock,
    };
    let dummy_peer = libp2p::PeerId::random();

    event_tx
        .send(NetworkEvent::GossipMessage {
            topic,
            peer: dummy_peer,
            data: ssz_bytes,
        })
        .await
        .unwrap();

    // Wait long enough for the ingestion loop to process the block.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Drain the spy channel and count any Publish commands.
    let mut publish_count = 0u32;
    while let Ok(cmd) = net_rx.try_recv() {
        if matches!(cmd, NetworkCommand::Publish { .. }) {
            publish_count += 1;
        }
    }

    assert_eq!(
        publish_count, 0,
        "expected zero publish calls for a Phase0 block, got {publish_count}"
    );
}
