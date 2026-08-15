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
use pharos_fork_choice::{get_forkchoice_store, on_tick};
use pharos_network::discovery::subnets::compute_subscribed_subnets;
use pharos_network::{NetworkBuilder, NoopScorer};
use pharos_ssz::{Bitvector, Decode, TreeHash};
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::phase0::MainnetBeaconState as Phase0MainnetBeaconState;
use pharos_types::phase0::primitives::ATTESTATION_SUBNET_COUNT;
use pharos_types::state::{BeaconBlock as ForkBeaconBlock, MainnetBeaconState};
use pharos_types::{EthSpec, MainnetEthSpec};
use tracing::info;

use pharos_node::host_impl::HostImpl;
use pharos_node::startup::rehydrate_fork_choice_store;

// ── CLI ───────────────────────────────────────────────────────────────────────

/// Pharos Ethereum consensus-layer beacon node.
#[derive(Parser, Debug)]
#[command(name = "pharos", version)]
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

    let fork_choice = Arc::new(RwLock::new(fc_store_mut));

    // ── Step 4: Construct host + network ──────────────────────────────────

    // Wrap in Arc so we can retain a handle for record_attnets_change after
    // passing a clone into the network builder. Arc<HostImpl<E>> satisfies
    // Host<E> via the blanket impls in pharos_network::host.
    let host = Arc::new(HostImpl::<MainnetEthSpec>::new(
        store,
        fork_choice,
        genesis_validators_root,
        fork_version,
    ));

    let discv5_addr = SocketAddr::new(listen_ip, args.discv5_port);

    let handle = NetworkBuilder::<MainnetEthSpec, Arc<HostImpl<MainnetEthSpec>>, NoopScorer>::new(
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
    // TODO(M3b): wire to subnet-rotation epoch driver once M3b lands.
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

    // Block until Ctrl-C.
    tokio::signal::ctrl_c()
        .await
        .context("ctrl_c signal handler failed")?;

    info!("received shutdown signal");
    handle.shutdown().await;
    info!("network shutdown complete");

    Ok(())
}
