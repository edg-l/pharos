//! Pharos beacon-node entry point.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

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
use pharos_node::block_ingestion::run_block_ingestion_loop;
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest, run_engine_driver_loop};
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
    /// Required on cold start. On warm restart the stored fork-choice snapshot
    /// is loaded instead, but the genesis state is still needed to extract the
    /// genesis validators root and fork version. Use `--checkpoint-sync-url`
    /// (M4) for production mainnet.
    #[arg(long, value_name = "PATH")]
    genesis_state_path: PathBuf,

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

    // ── Step 3: Load genesis state + build fork-choice ────────────────────

    let genesis_bytes = std::fs::read(&args.genesis_state_path)
        .with_context(|| format!("reading genesis state from {:?}", args.genesis_state_path))?;
    // The genesis state is stored as a raw phase0 SSZ blob. Decode as the
    // concrete phase0 type and wrap in the fork-enum (Phase0 variant).
    let genesis_state_inner = Phase0MainnetBeaconState::from_ssz_bytes(&genesis_bytes)
        .context("decoding genesis BeaconState SSZ")?;
    let genesis_state = MainnetBeaconState::Phase0(genesis_state_inner);

    // Compute genesis validators root and fork version from the state.
    use pharos_types::views::BeaconStateView;
    let genesis_validators_root = genesis_state.genesis_validators_root();
    let genesis_fork_version = MainnetEthSpec::GENESIS_FORK_VERSION;
    let fork_version = pharos_types::phase0::primitives::Version::from_array(genesis_fork_version);

    // Build fork-choice store: warm restart or cold start.
    let snapshot =
        <RocksStore as pharos_storage::Store<MainnetEthSpec>>::get_forkchoice_snapshot(&store)
            .context("reading fork-choice snapshot")?;

    let fc_store = if let Some(ref snap) = snapshot {
        info!("warm restart: rehydrating fork-choice store from snapshot");
        rehydrate_fork_choice_store::<MainnetEthSpec>(&store, snap)
            .context("rehydrating fork-choice store")?
    } else {
        info!("cold start: seeding fork-choice from genesis state");
        // Anchor block: state_root = hash_tree_root(genesis_state), empty sig.
        let state_root = genesis_state.tree_hash_root();
        let anchor_block = ForkBeaconBlock::Phase0(pharos_types::phase0::MainnetBeaconBlock {
            state_root,
            ..pharos_types::phase0::MainnetBeaconBlock::default()
        });
        get_forkchoice_store::<MainnetEthSpec>(genesis_state, anchor_block)
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

    // Spawn the engine actor when an explicit JWT secret is given or when the
    // user has configured a non-default execution endpoint.  Without either
    // signal (e.g. dev/test runs with the defaults) the engine driver is not
    // started.
    let el_configured = args.execution_endpoint != "http://127.0.0.1:8551";
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

        let engine_runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_name("pharos-engine")
                .enable_all()
                .build()
                .context("building engine tokio runtime")?,
        );

        let handle = spawn_engine_actor(engine_runtime, primary, secondary_opt);
        info!(endpoint = %args.execution_endpoint, "engine actor started");
        Some(handle)
    } else {
        // TODO(m4b-phase-2): extend message with "+ no --checkpoint-sync-url" when the flag lands
        info!(
            "no EL configured (default endpoint + no --jwt-secret); engine API integration disabled"
        );
        None
    };

    // ── Step 5: Construct host + network ──────────────────────────────────

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
        fork_version,
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

    // Build fork schedule for the subnet rotation and fork migration loops.
    // Use runtime_cfg so --config-dir overrides take effect.
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

    // Genesis time: for a production node this would be read from the chain
    // database or the genesis state's `genesis_time` field. For now, use
    // wall clock as a conservative approximation (cold-start scenario).
    let genesis_time_secs = wall_clock_secs;

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

    // Spawn fork migration loop (fires once at ALTAIR_FORK_EPOCH to update the
    // ENR `eth2` field and rotate gossip topics).
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
        let pow_provider = Arc::new(EnginePowBlockProvider::new(engine_handle));

        // Take the network event receiver and spawn the block-ingestion loop.
        let event_rx = handle.take_event_receiver();
        {
            let fc = Arc::clone(&fork_choice);
            let h = Arc::clone(&host);
            tokio::spawn(async move {
                if let Err(e) = run_block_ingestion_loop::<MainnetEthSpec, ExecutionEngineHandle>(
                    event_rx,
                    h,
                    fc,
                    exec_engine,
                    pow_provider,
                    head_tx,
                    payload_tx,
                    true, // validate_result: enforce BLS signatures and state roots
                )
                .await
                {
                    tracing::error!(error = %e, "block ingestion loop exited with error");
                }
            });
        }
        info!("block ingestion loop started");
    }

    // Block until Ctrl-C.
    tokio::signal::ctrl_c()
        .await
        .context("ctrl_c signal handler failed")?;

    info!("received shutdown signal");
    handle.shutdown().await;
    info!("network shutdown complete");

    Ok(())
}
