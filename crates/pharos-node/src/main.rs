//! Pharos beacon-node entry point.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use clap::Parser;
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use parking_lot::RwLock;
use pharos_engine::{EngineClient, spawn_engine_actor};
use pharos_fork_choice::{get_forkchoice_store, on_tick};
use pharos_network::discovery::subnets::compute_subscribed_subnets;
use pharos_network::{NetworkBuilder, NoopScorer};
use pharos_ssz::{Bitvector, Decode, TreeHash};
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::phase0::MainnetBeaconState as Phase0MainnetBeaconState;
use pharos_types::phase0::primitives::ATTESTATION_SUBNET_COUNT;
use pharos_types::state::{BeaconBlock as ForkBeaconBlock, MainnetBeaconState};
use pharos_types::{EthSpec, MainnetEthSpec, load_config_dir};
use tokio::sync::{mpsc, watch};
use tracing::info;

use pharos_node::ExecutionEngineHandle;
use pharos_node::block_ingestion::{IngestionEgress, run_block_ingestion_loop};
use pharos_node::checkpoint_sync::{apply_anchor, fetch_checkpoint};
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest, run_engine_driver_loop};
use pharos_node::engine_keepalive::{hex_to_u256, run_transition_config_keepalive, u256_to_hex};
use pharos_node::fork_migration::run_fork_migration_loop;
use pharos_node::host_impl::HostImpl;
use pharos_node::jwt_autogen::ensure_jwt_secret;
use pharos_node::pow_block::EnginePowBlockProvider;
use pharos_node::startup::rehydrate_fork_choice_store;
use pharos_node::subnet_rotation::run_subnet_rotation_loop;

// ── CLI ───────────────────────────────────────────────────────────────────────

/// Pharos Ethereum consensus-layer beacon node.
#[derive(Parser, Debug)]
#[command(name = "pharos", version, long_version = pharos_utils::version::LONG_VERSION)]
struct Args {
    /// TCP listen multiaddr for libp2p (e.g. /ip4/127.0.0.1/tcp/9000).
    #[arg(long, default_value = "/ip4/127.0.0.1/tcp/9000")]
    listen_addr: Multiaddr,

    /// UDP port for discv5 peer discovery.
    #[arg(long, default_value_t = 9000)]
    discv5_port: u16,

    /// Bootstrap ENR(s) for discv5 routing table initialisation (repeatable).
    #[arg(long, value_name = "ENR")]
    bootnode: Vec<String>,

    /// Data directory for persistent state (chain DB, slashing DB, etc.).
    #[arg(long, default_value = "./data")]
    data_dir: PathBuf,

    /// Path to a Phase-0 `BeaconState` SSZ file used as the genesis anchor.
    ///
    /// Required on cold start unless `--checkpoint-sync-url` is provided.
    /// On warm restart the stored fork-choice snapshot is loaded instead.
    #[arg(
        long,
        value_name = "PATH",
        required_unless_present = "checkpoint_sync_url"
    )]
    genesis_state_path: Option<PathBuf>,

    /// URL of a trusted Beacon API endpoint serving a finalised state to
    /// bootstrap fork choice from.
    ///
    /// When present AND no warm-restart snapshot exists in `--data-dir`, pharos
    /// fetches `GET <url>/eth/v2/debug/beacon/states/finalized` plus the matching
    /// block and uses it as the fork-choice anchor (skipping genesis replay).
    /// On warm restart, this flag is ignored; the persisted snapshot wins.
    ///
    /// Weak-subjectivity validation is deferred to M11; the operator's choice of
    /// URL is the trust root. For tamper detection, pair with
    /// `--checkpoint-sync-block-root`.
    #[arg(long, value_name = "URL")]
    checkpoint_sync_url: Option<String>,

    /// Optional 0x-prefixed 32-byte hex block root that the checkpoint-sync
    /// anchor MUST match. Aborts startup on mismatch.
    #[arg(long, value_name = "ROOT", requires = "checkpoint_sync_url")]
    checkpoint_sync_block_root: Option<String>,

    /// Path to the network config directory (without `.yaml` extension).
    ///
    /// Accepts a path of the form `<repo>/configs/<network>`, e.g.:
    ///   `~/dev/consensus-specs/configs/mainnet`
    ///
    /// The loader appends `.yaml` to read the network config file, then
    /// discovers the preset files at `<repo>/presets/<PRESET_BASE>/`.
    ///
    /// When absent, defaults to the `MainnetEthSpec` compile-time preset.
    #[arg(long, value_name = "PATH")]
    config_dir: Option<PathBuf>,

    /// Path to the JWT secret file for Engine API authentication.
    ///
    /// The file must contain a 32-byte hex-encoded secret (64 hex chars),
    /// optionally with a `0x` prefix. Typically at `<el-datadir>/jwt.hex`.
    #[arg(long, value_name = "PATH")]
    jwt_secret: Option<PathBuf>,

    /// Engine API (auth-RPC) endpoint URL for the primary execution client.
    ///
    /// Defaults to `http://127.0.0.1:8551`.
    #[arg(long, default_value = "http://127.0.0.1:8551")]
    execution_endpoint: String,

    /// Engine API (auth-RPC) endpoint URL for the secondary (failover) EL.
    ///
    /// Optional. When present, the engine actor fails over to this endpoint
    /// after `MAX_HEALTH_FAILURES` consecutive primary health-check failures.
    #[arg(long, value_name = "URL")]
    execution_endpoint_secondary: Option<String>,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Extract `(IpAddr, tcp_port)` from a `/ip4/<addr>/tcp/<port>` multiaddr.
fn parse_listen_addr(addr: &Multiaddr) -> anyhow::Result<(IpAddr, u16)> {
    let mut iter = addr.iter();
    let ip = match iter.next() {
        Some(Protocol::Ip4(a)) => IpAddr::V4(a),
        Some(Protocol::Ip6(a)) => IpAddr::V6(a),
        other => bail!("--listen-addr: expected /ip4 or /ip6 prefix, got {other:?}"),
    };
    let port = match iter.next() {
        Some(Protocol::Tcp(p)) => p,
        other => bail!("--listen-addr: expected /tcp/<port>, got {other:?}"),
    };
    Ok((ip, port))
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    // Shutdown broadcast: set to `true` on Ctrl-C to signal long-lived tasks.
    let (pharos_node_shutdown_tx, pharos_node_shutdown_rx) = watch::channel(false);

    // ── Step 0: Load RuntimeConfig ─────────────────────────────────────────
    //
    // `--config-dir` absent: use compile-time mainnet defaults.
    // `--config-dir <path>`: load from YAML and assert the preset matches
    // the binary's compile-time `MainnetEthSpec` constants.
    let runtime_cfg = if let Some(ref config_dir) = args.config_dir {
        info!(path = %config_dir.display(), "loading runtime config from YAML");
        let cfg = load_config_dir(config_dir)
            .with_context(|| format!("loading config from {:?}", config_dir))?;
        cfg.assert_matches_preset::<MainnetEthSpec>()
            .with_context(|| "runtime config does not match MainnetEthSpec preset")?;
        info!(
            altair_fork_epoch = cfg.altair_fork_epoch,
            "runtime config loaded"
        );
        cfg
    } else {
        MainnetEthSpec::default_runtime_config()
    };

    info!(version = env!("CARGO_PKG_VERSION"), "pharos starting");
    info!(listen_addr = %args.listen_addr, discv5_port = args.discv5_port, "configuration");
    info!(data_dir = %args.data_dir.display(), "data directory");

    // Parse --listen-addr into IP + TCP port.
    let (listen_ip, tcp_port) = parse_listen_addr(&args.listen_addr)
        .context("--listen-addr is not a valid /ip4/<addr>/tcp/<port> multiaddr")?;

    // Parse --bootnode ENR strings.
    let bootnodes: Vec<pharos_network::discovery::enr::Enr> = args
        .bootnode
        .iter()
        .map(|s| {
            s.parse::<pharos_network::discovery::enr::Enr>()
                .map_err(|e| anyhow::anyhow!("invalid bootnode ENR {s:?}: {e}"))
        })
        .collect::<anyhow::Result<_>>()?;

    // ── Step 1+2: Open RocksDB ─────────────────────────────────────────────

    let chain_db_path = args.data_dir.join("chain_db");
    info!(path = %chain_db_path.display(), "opening chain database");

    let store = Arc::new(
        RocksStore::open::<MainnetEthSpec>(RocksStoreConfig {
            path: chain_db_path,
            create_if_missing: true,
        })
        .context("failed to open chain database")?,
    );

    // ── Step 3: Build fork-choice store ──────────────────────────────────────
    //
    // Three-way branch (`D-anchor-state-on-disk`):
    //   1. Warm restart   — RocksDB snapshot exists → rehydrate.
    //   2. Checkpoint sync — `--checkpoint-sync-url` set → fetch + persist anchor.
    //   3. Genesis cold start — `--genesis-state-path` provided → genesis replay.
    //   4. Neither         — bail with a helpful error.

    use pharos_types::views::BeaconStateView;

    let snapshot =
        <RocksStore as pharos_storage::Store<MainnetEthSpec>>::get_forkchoice_snapshot(&store)
            .context("reading fork-choice snapshot")?;

    // `genesis_validators_root` is extracted from whichever anchor we land on.
    let (fc_store, genesis_validators_root) = if let Some(ref snap) = snapshot {
        info!("warm restart: rehydrating fork-choice store from snapshot");
        let fc = rehydrate_fork_choice_store::<MainnetEthSpec>(&store, snap)
            .context("rehydrating fork-choice store")?;
        // Derive genesis_validators_root from the anchor block's post-state.
        // The finalized_checkpoint.root is the block root; get the block to
        // find state_root, then load the state.
        let anchor_block = <RocksStore as pharos_storage::Store<MainnetEthSpec>>::get_block(
            &store,
            &snap.finalized_checkpoint.root,
        )
        .context("loading anchor block for genesis_validators_root")?;
        let gvr = if let Some(signed) = anchor_block {
            // Access the inner block via fork-unwrap to get state_root.
            use pharos_types::views::BeaconBlockView as _;
            use pharos_types::views::SignedBeaconBlockView as _;
            let state_root =
                if let Some(inner) = MainnetEthSpec::unwrap_phase0_signed_block(&signed) {
                    inner.message().state_root()
                } else if let Some(inner) = MainnetEthSpec::unwrap_altair_signed_block(&signed) {
                    inner.message().state_root()
                } else if let Some(inner) = MainnetEthSpec::unwrap_bellatrix_signed_block(&signed) {
                    inner.message().state_root()
                } else {
                    unreachable!("unrecognised SignedBeaconBlock fork variant in warm restart")
                };
            let state = <RocksStore as pharos_storage::Store<MainnetEthSpec>>::get_state(
                &store,
                &state_root,
            )
            .context("loading anchor state for genesis_validators_root")?
            .ok_or_else(|| anyhow::anyhow!("anchor state not found for state_root {state_root}"))?;
            state.genesis_validators_root()
        } else if let Some(ref path) = args.genesis_state_path {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading genesis state from {path:?}"))?;
            let inner = Phase0MainnetBeaconState::from_ssz_bytes(&bytes)
                .context("decoding genesis BeaconState SSZ")?;
            let s = MainnetBeaconState::Phase0(inner);
            s.genesis_validators_root()
        } else {
            bail!(
                "warm restart: anchor block not found in store and --genesis-state-path not provided"
            );
        };
        (fc, gvr)
    } else if let Some(ref ckpt_url) = args.checkpoint_sync_url {
        info!(url = %ckpt_url, "checkpoint-sync: fetching anchor");
        let url =
            reqwest::Url::parse(ckpt_url).context("--checkpoint-sync-url is not a valid URL")?;
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .context("building checkpoint-sync HTTP client")?;
        // Parse the optional operator-supplied expected block root and pass it
        // into fetch_checkpoint for tamper detection (TamperFlagMismatch).
        let expected_block_root = if let Some(ref expected_hex) = args.checkpoint_sync_block_root {
            Some(parse_root_hex(expected_hex)?)
        } else {
            None
        };

        let anchor = fetch_checkpoint::<MainnetEthSpec>(&url, &http, expected_block_root)
            .await
            .context("fetching checkpoint anchor")?;

        // TODO(M11): weak-subjectivity check goes here.
        info!(
            slot = %anchor.state.slot(), block_root = %anchor.block_root,
            "checkpoint-sync: anchor accepted"
        );

        let gvr = anchor.state.genesis_validators_root();
        let synth_snap = apply_anchor::<MainnetEthSpec>(anchor, &store)
            .context("persisting checkpoint anchor")?;
        let fc = rehydrate_fork_choice_store::<MainnetEthSpec>(&store, &synth_snap)
            .context("rehydrating fork-choice store from checkpoint anchor")?;
        (fc, gvr)
    } else if let Some(ref genesis_path) = args.genesis_state_path {
        info!("cold start: seeding fork-choice from genesis state");
        let genesis_bytes = std::fs::read(genesis_path)
            .with_context(|| format!("reading genesis state from {genesis_path:?}"))?;
        // The genesis state is a raw phase0 SSZ blob. Decode lands `Backend::Naive`
        // per `D-no-tree-backend-on-decode`; flip the seven hot fields to
        // `Backend::Tree` so the fork-choice store and subsequent STF benefit
        // from per-node hash caching from the very first block.
        let genesis_state_inner = Phase0MainnetBeaconState::from_ssz_bytes(&genesis_bytes)
            .context("decoding genesis BeaconState SSZ")?;
        let genesis_state = MainnetBeaconState::Phase0(genesis_state_inner)
            .into_tree_backend()
            .context("flipping genesis state to tree backend")?;

        let gvr = genesis_state.genesis_validators_root();
        // Anchor block: state_root = hash_tree_root(genesis_state), empty sig.
        let state_root = genesis_state.tree_hash_root();
        let anchor_block = ForkBeaconBlock::Phase0(pharos_types::phase0::MainnetBeaconBlock {
            state_root,
            ..pharos_types::phase0::MainnetBeaconBlock::default()
        });
        let fc = get_forkchoice_store::<MainnetEthSpec>(genesis_state, anchor_block);
        (fc, gvr)
    } else {
        bail!(
            "no startup path available: provide --genesis-state-path for genesis cold start, \
             --checkpoint-sync-url for checkpoint sync, or ensure --data-dir contains a prior \
             snapshot for warm restart"
        );
    };

    let mut fc_store_mut = fc_store;

    // Advance the fork-choice time cursor to wall-clock after warm restart.
    let wall_clock_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system time before UNIX_EPOCH")?
        .as_secs();
    on_tick::<MainnetEthSpec>(&mut fc_store_mut, wall_clock_secs);

    // Set the Bellatrix terminal-block constants from the loaded RuntimeConfig.
    // These are read by `on_block`'s merge-transition guard (`validate_merge_block`)
    // without threading `RuntimeConfig` through the fork-choice boundary.
    fc_store_mut.set_terminal_config(
        runtime_cfg.terminal_total_difficulty,
        runtime_cfg.terminal_block_hash,
        runtime_cfg.terminal_block_hash_activation_epoch,
    );

    let fork_choice = Arc::new(RwLock::new(fc_store_mut));

    // ── Step 4: Construct Engine API client + actor ───────────────────────

    // Build `watch` and `mpsc` channels for the engine driver loop.
    // The block-ingestion loop owns these senders and drives the engine driver
    // via `head_tx.send()` / `payload_tx.try_send()` directly.
    let (head_tx, head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, payload_rx) = mpsc::channel::<NewPayloadRequest<MainnetEthSpec>>(64);

    // Spawn the engine actor when an explicit JWT secret is given, when the
    // user has configured a non-default execution endpoint, or when checkpoint
    // sync is requested (which implies an EL will be needed immediately after
    // anchor is written).
    let el_configured =
        args.execution_endpoint != "http://127.0.0.1:8551" || args.checkpoint_sync_url.is_some();
    let engine_handle_opt = if args.jwt_secret.is_some() || el_configured {
        let jwt_secret = ensure_jwt_secret(&args.data_dir, args.jwt_secret.as_deref())
            .context("ensuring JWT secret")?;

        let primary_url: reqwest::Url = args
            .execution_endpoint
            .parse()
            .context("--execution-endpoint is not a valid URL")?;

        let primary = EngineClient::new(primary_url, jwt_secret.clone())
            .context("constructing primary EngineClient")?;

        let secondary_opt = if let Some(ref sec_url_str) = args.execution_endpoint_secondary {
            let sec_url: reqwest::Url = sec_url_str
                .parse()
                .context("--execution-endpoint-secondary is not a valid URL")?;
            let sec = EngineClient::new(sec_url, jwt_secret)
                .context("constructing secondary EngineClient")?;
            Some(sec)
        } else {
            None
        };

        // `spawn_engine_actor` builds and OWNS the engine runtime on a dedicated
        // OS thread, so the runtime drops in a sync context at shutdown (a
        // `Runtime` dropped from inside an async context panics). The returned
        // `EngineHandle` holds only a non-owning `Handle`.
        let handle = spawn_engine_actor(primary, secondary_opt);
        info!(endpoint = %args.execution_endpoint, "engine actor started");
        Some(handle)
    } else {
        info!(
            "no EL configured (default endpoint + no --jwt-secret + no --checkpoint-sync-url); engine API integration disabled"
        );
        None
    };

    // ── Step 4b: Cold-start TTD check + keepalive ─────────────────────────

    if let Some(ref engine_handle) = engine_handle_opt {
        let cl_cfg = pharos_engine::TransitionConfigurationV1 {
            terminal_total_difficulty: u256_to_hex(runtime_cfg.terminal_total_difficulty),
            terminal_block_hash: format!(
                "0x{}",
                hex::encode(runtime_cfg.terminal_block_hash.as_slice())
            ),
            terminal_block_number: "0x0".into(),
        };
        match engine_handle
            .exchange_transition_configuration_async(cl_cfg)
            .await
        {
            Ok(el_cfg) => {
                info!(
                    el_ttd = %el_cfg.terminal_total_difficulty,
                    "exchange_transition_configuration succeeded"
                );
                match hex_to_u256(&el_cfg.terminal_total_difficulty) {
                    Ok(el_ttd) => {
                        if el_ttd != runtime_cfg.terminal_total_difficulty {
                            tracing::warn!(
                                cl_ttd = %runtime_cfg.terminal_total_difficulty,
                                el_ttd = %el_ttd,
                                "TTD mismatch with execution layer (cold-start check)",
                            );
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "failed to parse EL TTD from cold-start response");
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = %e, "cold-start exchange_transition_configuration failed");
            }
        }

        // Spawn keepalive task.
        let eng = engine_handle.clone();
        let ttd = runtime_cfg.terminal_total_difficulty;
        let shutdown_rx = pharos_node_shutdown_rx.clone();
        tokio::spawn(async move {
            run_transition_config_keepalive(eng, ttd, shutdown_rx).await;
        });
        info!("transition_config keepalive task started");
    }

    // ── Step 5: Construct host + network ──────────────────────────────────

    // Build the fork schedule from runtime_cfg so --config-dir overrides take
    // effect. Constructed here (single source of truth) so the same Arc is
    // shared with both HostImpl and the migration/rotation loops.
    let fork_schedule = Arc::new(pharos_types::fork::ForkSchedule {
        genesis_fork_version: pharos_types::phase0::primitives::Version::from_array(
            runtime_cfg.genesis_fork_version,
        ),
        altair_fork_version: pharos_types::phase0::primitives::Version::from_array(
            runtime_cfg.altair_fork_version,
        ),
        altair_fork_epoch: pharos_utils::Epoch(runtime_cfg.altair_fork_epoch),
        bellatrix_fork_version: pharos_types::phase0::primitives::Version::from_array(
            runtime_cfg.bellatrix_fork_version,
        ),
        bellatrix_fork_epoch: pharos_utils::Epoch(runtime_cfg.bellatrix_fork_epoch),
        genesis_validators_root,
    });

    // genesis_time is populated by every startup branch (cold, checkpoint, warm).
    let (genesis_time_secs, anchored_slot) = {
        let s = fork_choice.read();
        (s.genesis_time, pharos_fork_choice::get_current_slot(&s))
    };
    info!(genesis_time = genesis_time_secs, current_slot = %anchored_slot, "slot clock anchored");

    // Wrap in Arc so we can retain a handle for record_attnets_change after
    // passing a clone into the network builder. Arc<HostImpl<E>> satisfies
    // Host<E> via the blanket impls in pharos_network::host.
    //
    // Wire the engine-driver channels before Arc::new so that HostImpl's
    // on_head_change / on_new_block are live for the M4b/M4c gossip-validator
    // path. Clones of head_tx / payload_tx are used here; the block-ingestion
    // loop owns the originals (passed separately in Step 5b below).
    let mut host_inner = HostImpl::<MainnetEthSpec>::new(
        store,
        fork_choice.clone(),
        genesis_validators_root,
        (*fork_schedule).clone(),
        genesis_time_secs,
        Arc::new(runtime_cfg.clone()),
    );
    host_inner.wire_engine(head_tx.clone(), payload_tx.clone());
    let host = Arc::new(host_inner);

    let discv5_addr = SocketAddr::new(listen_ip, args.discv5_port);

    let (mut handle, discovery_handle) =
        NetworkBuilder::<MainnetEthSpec, Arc<HostImpl<MainnetEthSpec>>, NoopScorer>::new(
            host.clone(),
        )
        .listen_ip(listen_ip)
        .tcp_listen_port(tcp_port)
        .discv5_addr(discv5_addr)
        .bootnodes(bootnodes)
        .spawn()
        .await
        .context("failed to start network")?;

    info!(peer_id = %handle.local_peer_id(), "network started");

    // Compute initial attestation subnets from the node-id and record them.
    // This bumps MetaData.seq_number from 0 to 1 exactly once at startup,
    // fulfilling the p2p-interface.md:391-393 requirement.
    let node_id = handle.local_node_id();
    let subnets = compute_subscribed_subnets::<MainnetEthSpec>(node_id, 0u64);
    let mut initial_attnets = Bitvector::<ATTESTATION_SUBNET_COUNT>::default();
    for subnet in subnets {
        initial_attnets.set(subnet as usize, true);
    }
    host.record_attnets_change(initial_attnets);
    tracing::info!(
        seq_number = 1,
        "initial attnets recorded; metadata seq_number = 1"
    );

    // Spawn subnet rotation loop (attestation subnet re-assignment every
    // EPOCHS_PER_SUBNET_SUBSCRIPTION = 256 epochs).
    // Takes a clonable `NetworkCommandSender` so we retain `handle` ownership.
    {
        let cmd = handle.command_sender();
        let sched = Arc::clone(&fork_schedule);
        let nid = node_id;
        tokio::spawn(async move {
            run_subnet_rotation_loop::<MainnetEthSpec>(cmd, sched, nid, genesis_time_secs).await;
        });
    }

    // Spawn fork migration loop: handles ALL fork crossings (phase0→altair,
    // altair→bellatrix, and future forks) within a single run, updating the
    // ENR `eth2` field and rotating gossip topics at each boundary.
    {
        let cmd = handle.command_sender();
        let disc = discovery_handle.clone();
        let sched = Arc::clone(&fork_schedule);
        tokio::spawn(async move {
            run_fork_migration_loop::<MainnetEthSpec>(cmd, disc, sched, genesis_time_secs).await;
        });
    }

    // Spawn engine driver loop + block ingestion loop when the engine is active.
    if let Some(engine_handle) = engine_handle_opt {
        // Spawn engine driver: listens for HeadChange watch and NewPayloadRequest mpsc.
        {
            let fc = Arc::clone(&fork_choice);
            let eng = engine_handle.clone();
            tokio::spawn(async move {
                run_engine_driver_loop::<MainnetEthSpec>(eng, fc, head_rx, payload_rx).await;
            });
            info!("engine driver loop started");
        }

        // Build production execution-engine bridge (EngineHandle → ExecutionEngine).
        let exec_engine = Arc::new(ExecutionEngineHandle::new(engine_handle.clone()));

        // Build production PoW-block provider for the merge-transition guard.
        let pow_provider = Arc::new(EnginePowBlockProvider::new(engine_handle.clone()));

        // Shared Notify: fired by ingestion when an orphan is deferred, wakes
        // the backfill loop for tip re-convergence.
        let notify_backfill = std::sync::Arc::new(tokio::sync::Notify::new());

        // Take the network event receiver and spawn the block-ingestion loop.
        let event_rx = handle.take_event_receiver();
        {
            let fc = Arc::clone(&fork_choice);
            let h = Arc::clone(&host);
            let exec_engine_clone = Arc::clone(&exec_engine);
            let pow_clone = Arc::clone(&pow_provider);
            let head_tx_clone = head_tx.clone();
            let payload_tx_clone = payload_tx.clone();
            let ingestion_egress = IngestionEgress {
                head_tx: head_tx_clone,
                payload_tx: payload_tx_clone,
                network: handle.command_sender(),
                notify_backfill: notify_backfill.clone(),
            };
            tokio::spawn(async move {
                if let Err(e) = run_block_ingestion_loop::<MainnetEthSpec, ExecutionEngineHandle>(
                    event_rx,
                    h,
                    fc,
                    exec_engine_clone,
                    pow_clone,
                    ingestion_egress,
                    true, // validate_result: enforce BLS signatures and state roots
                )
                .await
                {
                    tracing::error!(error = %e, "block ingestion loop exited with error");
                }
            });
        }
        info!("block ingestion loop started");

        // Spawn forward backfill loop.
        {
            use pharos_node::backfill::run_backfill_loop;
            use pharos_node::network_backfill_provider::{
                NetworkBackfillProvider, NetworkHandlePeerPicker,
            };

            let peer_picker = Arc::new(NetworkHandlePeerPicker::new(handle.command_sender()));
            let provider = NetworkBackfillProvider::new(handle.command_sender(), peer_picker);
            let shutdown_rx = pharos_node_shutdown_rx.clone();
            let fc = Arc::clone(&fork_choice);
            let h = Arc::clone(&host);
            tokio::spawn(async move {
                if let Err(e) = run_backfill_loop::<
                    MainnetEthSpec,
                    _,
                    ExecutionEngineHandle,
                    EnginePowBlockProvider,
                >(
                    provider,
                    h,
                    fc,
                    exec_engine,
                    pow_provider,
                    head_tx,
                    payload_tx,
                    genesis_time_secs,
                    shutdown_rx,
                    notify_backfill,
                )
                .await
                {
                    tracing::error!(error = %e, "backfill loop exited with error");
                }
            });
        }
        info!("backfill loop started");
    }

    // Block until Ctrl-C.
    tokio::signal::ctrl_c()
        .await
        .context("ctrl_c signal handler failed")?;

    info!("received shutdown signal");
    // Signal long-lived tasks (keepalive, etc.) to shut down.
    let _ = pharos_node_shutdown_tx.send(true);
    handle.shutdown().await;
    info!("network shutdown complete");

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Parse a `0x`-prefixed 32-byte hex string into a `Root`.
fn parse_root_hex(s: &str) -> anyhow::Result<pharos_types::phase0::primitives::Root> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(stripped)
        .with_context(|| format!("--checkpoint-sync-block-root is not valid hex: {s:?}"))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!("--checkpoint-sync-block-root must be 32 bytes (got != 32)")
    })?;
    Ok(pharos_types::phase0::primitives::Root::from(arr))
}
