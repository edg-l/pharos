//! Pharos beacon-node entry point.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail};
use clap::{Parser, Subcommand};
use libp2p::Multiaddr;
use libp2p::multiaddr::Protocol;
use parking_lot::RwLock;
use pharos_engine::{EngineClient, spawn_engine_actor};
use pharos_fork_choice::{get_forkchoice_store, on_tick};
use pharos_network::discovery::subnets::compute_subscribed_subnets;
use pharos_network::{NetworkBuilder, NoopScorer, RealScorer};
use pharos_ssz::{Bitvector, Decode, TreeHash};
use pharos_storage::{RocksStore, RocksStoreConfig};
use pharos_types::phase0::MainnetBeaconState as Phase0MainnetBeaconState;
use pharos_types::phase0::primitives::ATTESTATION_SUBNET_COUNT;
use pharos_types::state::{BeaconBlock as ForkBeaconBlock, MainnetBeaconState};
use pharos_types::{BeaconSpec, MainnetBeaconSpec, load_config_dir};
use serde_json::{Map as JsonMap, Value as JsonValue};
use tokio::sync::{mpsc, watch};
use tracing::{info, warn};

use pharos_node::ExecutionEngineHandle;
use pharos_node::blob_ingestion::run_blob_ingestion_loop;
use pharos_node::blob_prune::run_blob_prune_loop;
use pharos_node::block_ingestion::{IngestionEgress, ReinjectBlock, run_block_ingestion_loop};
use pharos_node::checkpoint_sync::{apply_anchor, fetch_checkpoint};
use pharos_node::column_ingestion::{ColumnAwaitingBlocks, run_column_ingestion_loop};
use pharos_node::column_prune::run_column_prune_loop;
use pharos_node::custody::{CustodyState, run_custody_adjustment_loop};
use pharos_node::data_availability::{BlobAwaitingBlocks, ForkAwareDataAvailabilityChecker};
use pharos_node::engine_driver::{HeadChange, NewPayloadRequest, run_engine_driver_loop};
use pharos_node::engine_keepalive::{hex_to_u256, run_transition_config_keepalive, u256_to_hex};
use pharos_node::fork_migration::{run_bpo_migration_loop, run_fork_migration_loop};
use pharos_node::freezer::run_freezer_loop;
use pharos_node::host_impl::HostImpl;
use pharos_node::jwt_autogen::ensure_jwt_secret;
use pharos_node::lookup::{LookupRequest, run_lookup_loop};
use pharos_node::network_backfill_provider::NetworkHandlePeerPicker;
use pharos_node::network_lookup_provider::NetworkLookupProvider;
use pharos_node::pending_blocks::PendingBlocks;
use pharos_node::pow_block::EnginePowBlockProvider;
use pharos_node::shutdown::run_shutdown_sequence;
use pharos_node::startup::rehydrate_fork_choice_store;
use pharos_node::state_regen::StateRegenService;
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

    /// Optional IPv6 TCP listen multiaddr for libp2p (e.g.
    /// `/ip6/::1/tcp/9000`). When set, the node listens on IPv6 in ADDITION to
    /// the IPv4 `--listen-addr` and advertises ENR `ip6`/`tcp6`
    /// (`D-discv5-dualstack`). Requires `--discv5-port-ipv6`.
    #[arg(long, value_name = "MULTIADDR", requires = "discv5_port_ipv6")]
    listen_addr_ipv6: Option<Multiaddr>,

    /// UDP port for discv5 IPv6 peer discovery (`D-discv5-dualstack`). Required
    /// when `--listen-addr-ipv6` is supplied so the discv5 IP family is
    /// unambiguous.
    #[arg(long, value_name = "PORT", requires = "listen_addr_ipv6")]
    discv5_port_ipv6: Option<u16>,

    /// Bootstrap ENR(s) for discv5 routing table initialisation (repeatable).
    #[arg(long, value_name = "ENR")]
    bootnode: Vec<String>,

    /// EIP-1459 `enrtree://<base32-pubkey>@<domain>` DNS node list(s) to
    /// resolve into bootnodes (repeatable; mixed with `--bootnode`).
    #[arg(long, value_name = "ENRTREE_URL")]
    bootnode_dns: Vec<String>,

    /// Hard cap on connected peers.
    ///
    /// Inbound connections beyond this limit are rejected at the swarm level.
    /// `tick_score_prune` and outbound dials may bring the count below this
    /// via the target-peers mechanism; `--max-peers` is the absolute ceiling.
    /// Per `D-connection-limit-prefer-high-score` (M11 Phase 12).
    #[arg(long, default_value_t = 50, value_name = "N")]
    max_peers: usize,

    /// Desired steady-state connected peer count.
    ///
    /// The discv5 discovery cadence scales with `target_peers - connected_peers`:
    /// large deficit → frequent FINDNODE queries; at/above target → slow maintenance
    /// cadence. `tick_score_prune` prunes excess to this level (lowest-scoring
    /// peers first). Per `D-connection-limit-prefer-high-score` (M11 Phase 12).
    #[arg(long, default_value_t = 50, value_name = "N")]
    target_peers: usize,

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
    /// The synced anchor is subjected to the weak-subjectivity freshness gate
    /// (`specs/phase0/weak-subjectivity.md`); a stale anchor aborts startup
    /// unless `--ignore-weak-subjectivity-period` is set. For tamper detection,
    /// pair with `--checkpoint-sync-block-root` or `--weak-subjectivity-checkpoint`.
    #[arg(long, value_name = "URL")]
    checkpoint_sync_url: Option<String>,

    /// Optional 0x-prefixed 32-byte hex block root that the checkpoint-sync
    /// anchor MUST match. Aborts startup on mismatch.
    #[arg(long, value_name = "ROOT", requires = "checkpoint_sync_url")]
    checkpoint_sync_block_root: Option<String>,

    /// Optional weak-subjectivity checkpoint in `<block_root>:<epoch>` format
    /// (e.g. `0xabc...:9544`), per `specs/phase0/weak-subjectivity.md`. When
    /// supplied with `--checkpoint-sync-url`, the synced anchor's block root AND
    /// epoch MUST match this checkpoint; a mismatch aborts startup.
    #[arg(long, value_name = "ROOT:EPOCH", requires = "checkpoint_sync_url")]
    weak_subjectivity_checkpoint: Option<String>,

    /// Bypass the weak-subjectivity period freshness check on the checkpoint-sync
    /// anchor. UNSAFE: only use when intentionally syncing from a checkpoint
    /// known to be older than the weak-subjectivity period.
    #[arg(long, default_value_t = false)]
    ignore_weak_subjectivity_period: bool,

    /// Path to the network config directory (without `.yaml` extension).
    ///
    /// Accepts a path of the form `<repo>/configs/<network>`, e.g.:
    ///   `~/dev/consensus-specs/configs/mainnet`
    ///
    /// The loader appends `.yaml` to read the network config file, then
    /// discovers the preset files at `<repo>/presets/<PRESET_BASE>/`.
    ///
    /// When absent, defaults to the `MainnetBeaconSpec` compile-time preset.
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

    // ── Beacon API HTTP server ────────────────────────────────────────────────
    // ── Freezer / hot-cold split ──────────────────────────────────────────────
    /// Restore-point cadence: how many epochs between cold state snapshots.
    ///
    /// At each finalization step the freezer writes one full `BeaconState` per
    /// `N` epochs into the `cold-states` CF (per `D-restore-point-interval`).
    /// Lower values reduce max replay cost; higher values reduce disk growth.
    /// Default: 8 (balance of replay speed vs. cold-DB growth; see write-budget
    /// appendix in `docs/storage-plan.md`).
    #[arg(long, default_value_t = 8, value_name = "EPOCHS")]
    restore_point_interval_epochs: u64,

    /// Disable the freezer/hot-cold migration loop.
    ///
    /// When set, finalized blocks/states are never migrated to the cold CFs and
    /// hot data is never pruned. Useful for short devnets and integration tests
    /// where bounded DB growth is not a concern.
    #[arg(long, default_value_t = false)]
    no_freezer: bool,

    /// Enable the opt-in chain-history replay slasher (Phase B).
    ///
    /// When set, on startup the node walks its stored block history (via the
    /// `slot_to_block_root` index) and feeds every block's proposer header and
    /// attestations through the slasher's double/surround/proposer-double-block
    /// detectors, persisting the proposer-header index to the `slasher-proposers`
    /// RocksDB CF. This catches slashings the live gossip path never observed,
    /// at the cost of higher storage (roughly the proposer-header index over the
    /// retained history). The always-on Phase A in-memory attestation slasher
    /// runs regardless of this flag. Default: off.
    #[arg(long, default_value_t = false)]
    slasher: bool,

    /// Enable backward state backfill (genesis-ward historical state
    /// reconstruction).
    ///
    /// When set, a long-running BACKGROUND loop reconstructs restore-point states
    /// below the anchor by replaying stored blocks backward by
    /// `SLOTS_PER_HISTORICAL_ROOT`-slot intervals, gated on forward block backfill
    /// supplying the source blocks. May take days on mainnet; it never blocks node
    /// startup and emits coarse per-interval progress logging. Default: off.
    #[arg(long, default_value_t = false)]
    backward_backfill: bool,

    /// Enable the Beacon API HTTP server.
    ///
    /// When set, an HTTP server is started on `--http-address:--http-port`
    /// serving the `eth/v1` Beacon API endpoints. Default: off.
    #[arg(long, default_value_t = false)]
    http: bool,

    /// IP address for the Beacon API HTTP server.
    ///
    /// Only consulted when `--http` is set.
    #[arg(long, default_value = "127.0.0.1", value_name = "ADDR")]
    http_address: std::net::IpAddr,

    /// Port for the Beacon API HTTP server.
    ///
    /// Only consulted when `--http` is set.
    #[arg(long, default_value_t = 5052, value_name = "PORT")]
    http_port: u16,

    /// Path to a file containing the Bearer token for `/eth/v1/validator/*` API auth.
    ///
    /// When provided, every request to the validator-duties namespace must carry
    /// `Authorization: Bearer <token>`.  The file is read at startup; its trimmed
    /// contents are used as the token (the common CL client format).
    /// When absent, no auth is required on the validator endpoints.
    #[arg(long, value_name = "PATH")]
    validator_api_token: Option<PathBuf>,

    // ── Prometheus metrics ────────────────────────────────────────────────────
    /// Enable the Prometheus metrics HTTP server.
    ///
    /// When set, a Prometheus exporter is started on
    /// `--metrics-address:--metrics-port` serving the `/metrics` endpoint.
    /// Default: off (opt-in).
    #[arg(long, default_value_t = false)]
    metrics: bool,

    /// IP address for the Prometheus metrics HTTP server.
    ///
    /// Only consulted when `--metrics` is set.
    #[arg(long, default_value = "127.0.0.1", value_name = "ADDR")]
    metrics_address: std::net::IpAddr,

    /// Port for the Prometheus metrics HTTP server.
    ///
    /// Only consulted when `--metrics` is set.
    #[arg(long, default_value_t = 5054, value_name = "PORT")]
    metrics_port: u16,

    // ── Logging ───────────────────────────────────────────────────────────────
    /// Log output format: `pretty` (human-readable, default) or `json`
    /// (machine-readable, suitable for log aggregators; emits span enter/exit
    /// events for per-span latency measurement).
    #[arg(long, default_value = "pretty", value_name = "FORMAT")]
    log_format: pharos_utils::tracing::LogFormat,

    /// Log filter directive in `RUST_LOG` syntax, e.g. `info` or
    /// `info,pharos_stf=debug`. Overridden by the `RUST_LOG` environment
    /// variable when set.
    #[arg(long, default_value = "info", value_name = "FILTER")]
    log_level: String,

    /// Optional file to tee logs into, in addition to the console. The file
    /// uses a non-blocking, daily-rolling writer with no ANSI colour codes.
    /// A bad/unwritable path falls back to console-only (the node still starts).
    #[arg(long, value_name = "PATH")]
    log_file: Option<std::path::PathBuf>,
}

// ── `pharos debug` subcommands ──────────────────────────────────────────────────
//
// Offline diagnostic calculators. Parsed via a separate top-level `Parser` so
// the node-run `Args` (with its `required_unless_present` constraints) is not
// validated when the user invokes a debug tool. Dispatched from `main` before
// `Args::parse()` when argv[1] == "debug".

/// Top-level wrapper matching the `pharos` binary name for the debug parse path.
#[derive(Parser, Debug)]
#[command(name = "pharos", version, long_version = pharos_utils::version::LONG_VERSION)]
struct DebugCli {
    #[command(subcommand)]
    cmd: DebugGroup,
}

#[derive(Subcommand, Debug)]
enum DebugGroup {
    /// Offline diagnostic calculators (no node startup, no network).
    Debug {
        #[command(subcommand)]
        tool: DebugTool,
    },
}

#[derive(Subcommand, Debug)]
enum DebugTool {
    /// PeerDAS custody calculator: node id + cgc -> custody groups, columns, subnets.
    Das {
        /// 32-byte node id as hex (with or without a `0x` prefix).
        #[arg(long, value_name = "HEX")]
        node_id: String,
        /// Custody group count. Defaults to the preset `CUSTODY_REQUIREMENT` (4).
        #[arg(long, value_name = "N")]
        cgc: Option<u64>,
        /// Preset whose custody constants to use.
        #[arg(long, default_value = "mainnet", value_name = "PRESET")]
        preset: pharos_node::debug::das::Preset,
        /// Restrict the subnet report to a single column index.
        #[arg(long, value_name = "K")]
        column: Option<u64>,
        /// Emit JSON instead of the human-readable table.
        #[arg(long)]
        json: bool,
    },
    /// `engine_getPayloadBodiesBy{Hash,Range}V1` consumer: drives a live EL over
    /// the Engine API and prints the returned payload bodies.
    PayloadBodies {
        /// Engine API (auth-RPC) endpoint URL of the execution client.
        #[arg(long, default_value = "http://127.0.0.1:8551", value_name = "URL")]
        execution_endpoint: String,
        /// Path to the JWT secret file for Engine API authentication.
        ///
        /// When absent, reuses/creates `<data-dir>/jwt.hex` (same as the node).
        #[arg(long, value_name = "PATH")]
        jwt_secret: Option<PathBuf>,
        /// Data directory used to locate/generate the JWT secret.
        #[arg(long, default_value = "./data")]
        data_dir: PathBuf,
        /// One or more 0x-prefixed block hashes (`engine_getPayloadBodiesByHashV1`).
        /// Mutually exclusive with `--start`/`--count`.
        #[arg(long = "block-hash", value_name = "HASH")]
        block_hash: Vec<String>,
        /// Starting block number for `engine_getPayloadBodiesByRangeV1`.
        /// Requires `--count`; mutually exclusive with `--block-hash`.
        #[arg(long, value_name = "N")]
        start: Option<u64>,
        /// Number of blocks for `engine_getPayloadBodiesByRangeV1`. Requires `--start`.
        #[arg(long, value_name = "N")]
        count: Option<u64>,
        /// Use the Amsterdam-era V2 variant instead of the advertised V1.
        #[arg(long)]
        v2: bool,
        /// Emit JSON instead of the human-readable listing.
        #[arg(long)]
        json: bool,
    },
}

/// Dispatch a `pharos debug <tool>` invocation. Returns after printing; never
/// starts the node.
async fn run_debug(cli: DebugCli) -> anyhow::Result<()> {
    let DebugGroup::Debug { tool } = cli.cmd;
    match tool {
        DebugTool::Das {
            node_id,
            cgc,
            preset,
            column,
            json,
        } => pharos_node::debug::das::run(&node_id, cgc, preset, column, json),
        DebugTool::PayloadBodies {
            execution_endpoint,
            jwt_secret,
            data_dir,
            block_hash,
            start,
            count,
            v2,
            json,
        } => {
            let by_hash = !block_hash.is_empty();
            let by_range = start.is_some() || count.is_some();
            let mode = if by_hash && by_range {
                bail!(
                    "--block-hash and --start/--count are mutually exclusive; provide exactly one"
                );
            } else if by_hash {
                pharos_node::debug::payload_bodies::Mode::ByHash(block_hash)
            } else if let (Some(start), Some(count)) = (start, count) {
                pharos_node::debug::payload_bodies::Mode::ByRange { start, count }
            } else if by_range {
                bail!("--start and --count must both be provided together");
            } else {
                bail!("provide either --block-hash (one or more) or --start/--count");
            };
            pharos_node::debug::payload_bodies::run(
                &execution_endpoint,
                jwt_secret.as_deref(),
                &data_dir,
                mode,
                v2,
                json,
            )
            .await
        }
    }
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

/// Map a network-layer `PeerInfo` to the beacon-API peer JSON object for
/// `/eth/v1/node/peers` (per `~/dev/beacon-APIs/apis/node/peers.yaml`).
fn peer_info_to_json(info: &pharos_network::PeerInfo) -> JsonValue {
    use pharos_network::{ConnectionDirection, PeerState};
    let state = match info.state {
        PeerState::Connecting | PeerState::Handshaking => "connecting",
        PeerState::Connected => "connected",
        PeerState::Disconnecting => "disconnecting",
        PeerState::Banned => "disconnected",
    };
    let direction = match info.direction {
        ConnectionDirection::Inbound => "inbound",
        ConnectionDirection::Outbound => "outbound",
    };
    let last_seen = info
        .addrs
        .first()
        .or(info.observed_addr.as_ref())
        .map(|a| a.to_string())
        .unwrap_or_default();
    let enr = info.enr.as_ref().map(|e| e.to_base64()).unwrap_or_default();
    serde_json::json!({
        "peer_id": info.peer_id.to_string(),
        "enr": enr,
        "last_seen_p2p_address": last_seen,
        "state": state,
        "direction": direction,
    })
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // `pharos debug <tool>` is an offline calculator path: parse the separate
    // debug CLI (so the node-run `Args` constraints don't apply), run it, exit.
    if std::env::args().nth(1).as_deref() == Some("debug") {
        return run_debug(DebugCli::parse()).await;
    }

    // Parse args first so --log-format / --log-level are available before the
    // subscriber is installed.  Tracing before this point uses the default
    // no-op subscriber; startup errors are surfaced via anyhow after init.
    let args = Args::parse();

    let (log_reload, _log_guard) = pharos_utils::tracing::init_tracing(
        args.log_format,
        &args.log_level,
        args.log_file.as_deref(),
    );

    // ── Metrics (opt-in via --metrics) ────────────────────────────────────────
    //
    // Deferred: the `/health` probe requires the fork-choice store to read sync
    // state, so `init_metrics` is called after `fork_choice` is built below.
    // The metrics address is parsed early to surface invalid-address errors
    // before any expensive startup work.
    let metrics_addr_opt = if args.metrics {
        Some(SocketAddr::new(args.metrics_address, args.metrics_port))
    } else {
        None
    };

    // Shutdown broadcast: set to `true` on Ctrl-C to signal long-lived tasks.
    let (pharos_node_shutdown_tx, pharos_node_shutdown_rx) = watch::channel(false);

    // ── Step 0: Load RuntimeConfig ─────────────────────────────────────────
    //
    // `--config-dir` absent: use compile-time mainnet defaults.
    // `--config-dir <path>`: load from YAML and assert the preset matches
    // the binary's compile-time `MainnetBeaconSpec` constants.
    let runtime_cfg = if let Some(ref config_dir) = args.config_dir {
        info!(path = %config_dir.display(), "loading runtime config from YAML");
        let cfg = load_config_dir(config_dir)
            .with_context(|| format!("loading config from {:?}", config_dir))?;
        cfg.assert_matches_preset::<MainnetBeaconSpec>()
            .with_context(|| "runtime config does not match MainnetBeaconSpec preset")?;
        info!(
            altair_fork_epoch = cfg.altair_fork_epoch,
            "runtime config loaded"
        );
        cfg
    } else {
        MainnetBeaconSpec::default_runtime_config()
    };

    info!(version = env!("CARGO_PKG_VERSION"), "pharos starting");
    info!(listen_addr = %args.listen_addr, discv5_port = args.discv5_port, "configuration");
    info!(data_dir = %args.data_dir.display(), "data directory");

    // Parse --listen-addr into IP + TCP port.
    let (listen_ip, tcp_port) = parse_listen_addr(&args.listen_addr)
        .context("--listen-addr is not a valid /ip4/<addr>/tcp/<port> multiaddr")?;

    // Parse the optional --listen-addr-ipv6 into an Ipv6Addr (the TCP port is
    // shared with the IPv4 listener; libp2p binds the same port number on both
    // families per `D-discv5-dualstack`). clap's `requires` guarantees
    // --discv5-port-ipv6 is present whenever --listen-addr-ipv6 is.
    let listen_ip6: Option<std::net::Ipv6Addr> = match &args.listen_addr_ipv6 {
        Some(addr) => {
            let (ip, _port) = parse_listen_addr(addr)
                .context("--listen-addr-ipv6 is not a valid /ip6/<addr>/tcp/<port> multiaddr")?;
            match ip {
                IpAddr::V6(v6) => Some(v6),
                IpAddr::V4(_) => bail!("--listen-addr-ipv6 must carry an /ip6 address"),
            }
        }
        None => None,
    };

    // Parse --bootnode ENR strings.
    let mut bootnodes: Vec<pharos_network::discovery::enr::Enr> = args
        .bootnode
        .iter()
        .map(|s| {
            s.parse::<pharos_network::discovery::enr::Enr>()
                .map_err(|e| anyhow::anyhow!("invalid bootnode ENR {s:?}: {e}"))
        })
        .collect::<anyhow::Result<_>>()?;

    // Resolve --bootnode-dns enrtree:// URLs (EIP-1459) and mix the discovered
    // ENRs into the static bootnode set.
    if !args.bootnode_dns.is_empty() {
        let resolver: Arc<dyn pharos_network::discovery::dns::TxtResolver> = Arc::new(
            pharos_network::discovery::dns::HickoryTxtResolver::from_system()
                .context("failed to initialise DNS resolver for --bootnode-dns")?,
        );
        for url in &args.bootnode_dns {
            match pharos_network::discovery::dns::resolve_enrtree(url, resolver.clone()).await {
                Ok(resolved) => {
                    info!(url = %url, count = resolved.len(), "resolved DNS bootnodes");
                    bootnodes.extend(resolved);
                }
                Err(e) => {
                    warn!(url = %url, error = %e, "failed to resolve --bootnode-dns URL");
                }
            }
        }
    }

    // ── Step 1+2: Open RocksDB ─────────────────────────────────────────────

    let chain_db_path = args.data_dir.join("chain_db");
    info!(path = %chain_db_path.display(), "opening chain database");

    let store = Arc::new(
        RocksStore::open::<MainnetBeaconSpec>(RocksStoreConfig {
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
        <RocksStore as pharos_storage::Store<MainnetBeaconSpec>>::get_forkchoice_snapshot(&store)
            .context("reading fork-choice snapshot")?;

    // `genesis_validators_root` is extracted from whichever anchor we land on.
    let (fc_store, genesis_validators_root) = if let Some(ref snap) = snapshot {
        info!("warm restart: rehydrating fork-choice store from snapshot");
        let fc = rehydrate_fork_choice_store::<MainnetBeaconSpec>(&store, snap, &runtime_cfg)
            .context("rehydrating fork-choice store")?;
        // Derive genesis_validators_root from the anchor block's post-state.
        // The finalized_checkpoint.root is the block root; get the block to
        // find state_root, then load the state.
        let anchor_block = <RocksStore as pharos_storage::Store<MainnetBeaconSpec>>::get_block(
            &store,
            &snap.finalized_checkpoint.root,
        )
        .context("loading anchor block for genesis_validators_root")?;
        let gvr = if let Some(signed) = anchor_block {
            // Access the inner block via fork-unwrap to get state_root.
            use pharos_types::views::BeaconBlockView as _;
            use pharos_types::views::SignedBeaconBlockView as _;
            let state_root = if let Some(inner) =
                MainnetBeaconSpec::unwrap_phase0_signed_block(&signed)
            {
                inner.message().state_root()
            } else if let Some(inner) = MainnetBeaconSpec::unwrap_altair_signed_block(&signed) {
                inner.message().state_root()
            } else if let Some(inner) = MainnetBeaconSpec::unwrap_bellatrix_signed_block(&signed) {
                inner.message().state_root()
            } else if let Some(inner) = MainnetBeaconSpec::unwrap_capella_signed_block(&signed) {
                inner.message().state_root()
            } else if let Some(inner) = MainnetBeaconSpec::unwrap_deneb_signed_block(&signed) {
                inner.message().state_root()
            } else if let Some(inner) = MainnetBeaconSpec::unwrap_electra_signed_block(&signed) {
                inner.message().state_root()
            } else if let Some(inner) = MainnetBeaconSpec::unwrap_fulu_signed_block(&signed) {
                inner.message().state_root()
            } else {
                unreachable!("unrecognised SignedBeaconBlock fork variant in warm restart")
            };
            let state = <RocksStore as pharos_storage::Store<MainnetBeaconSpec>>::get_state(
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
        // into fetch_checkpoint for tamper detection (TamperFlagMismatch). A
        // `--weak-subjectivity-checkpoint <root>:<epoch>` also pins the block
        // root (its epoch is asserted separately, below, against the anchor).
        let ws_checkpoint = match args.weak_subjectivity_checkpoint {
            Some(ref s) => Some(parse_weak_subjectivity_checkpoint(s)?),
            None => None,
        };
        let expected_block_root = match (&args.checkpoint_sync_block_root, &ws_checkpoint) {
            (Some(expected_hex), _) => Some(parse_root_hex(expected_hex)?),
            (None, Some((ws_root, _))) => Some(*ws_root),
            (None, None) => None,
        };

        let anchor = fetch_checkpoint::<MainnetBeaconSpec>(&url, &http, expected_block_root)
            .await
            .context("fetching checkpoint anchor")?;

        // Task 4: if a weak-subjectivity checkpoint was supplied, assert the
        // synced anchor's epoch matches it (block root already enforced via
        // `expected_block_root` → `TamperFlagMismatch`). Mismatch aborts startup.
        if let Some((ws_root, ws_epoch)) = ws_checkpoint {
            let anchor_epoch = anchor.state.slot().0 / MainnetBeaconSpec::SLOTS_PER_EPOCH;
            if anchor_epoch != ws_epoch {
                bail!(
                    "weak-subjectivity checkpoint epoch mismatch: anchor at epoch {anchor_epoch}, \
                     --weak-subjectivity-checkpoint specified epoch {ws_epoch}"
                );
            }
            if anchor.block_root != ws_root {
                bail!(
                    "weak-subjectivity checkpoint root mismatch: anchor root {}, \
                     --weak-subjectivity-checkpoint specified root {ws_root}",
                    anchor.block_root
                );
            }
        }

        // Compute the current (wall-clock) slot from the anchor state's
        // genesis_time so the weak-subjectivity freshness gate in apply_anchor
        // can reject a stale anchor (`specs/phase0/weak-subjectivity.md`).
        let genesis_time = anchor.state.genesis_time();
        let seconds_per_slot = MainnetBeaconSpec::SLOT_DURATION_MS / 1000;
        let wall_now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time before UNIX_EPOCH")?
            .as_secs();
        let current_slot = wall_now.saturating_sub(genesis_time) / seconds_per_slot.max(1);

        info!(
            slot = %anchor.state.slot(), block_root = %anchor.block_root,
            current_slot, "checkpoint-sync: anchor fetched, applying weak-subjectivity gate"
        );

        let gvr = anchor.state.genesis_validators_root();
        let synth_snap = apply_anchor::<MainnetBeaconSpec>(
            anchor,
            &store,
            current_slot,
            args.ignore_weak_subjectivity_period,
        )
        .context("persisting checkpoint anchor")?;
        let fc =
            rehydrate_fork_choice_store::<MainnetBeaconSpec>(&store, &synth_snap, &runtime_cfg)
                .context("rehydrating fork-choice store from checkpoint anchor")?;
        (fc, gvr)
    } else if let Some(ref genesis_path) = args.genesis_state_path {
        info!("cold start: seeding fork-choice from genesis state");
        let genesis_bytes = std::fs::read(genesis_path)
            .with_context(|| format!("reading genesis state from {genesis_path:?}"))?;
        // The genesis state is a raw phase0 SSZ blob. Decode lands `Backend::Flat`
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
        let fc = get_forkchoice_store::<MainnetBeaconSpec>(genesis_state, anchor_block);

        // Task 4.3 (genesis path): initialize split_slot and anchor_slot to 0.
        // On a genesis cold start there is no prior data, so the hot window
        // starts at slot 0. These are two independent metadata writes (not a
        // BlockTransition): genesis has no associated block yet, and a crash
        // between them is harmless — both default to 0 when absent (the freezer /
        // regen / rehydrate all fall back to `Slot(0)` on a missing key).
        <RocksStore as pharos_storage::Store<MainnetBeaconSpec>>::put_metadata(
            &store,
            b"split_slot",
            &0u64.to_be_bytes(),
        )
        .context("writing genesis split_slot metadata")?;
        <RocksStore as pharos_storage::Store<MainnetBeaconSpec>>::put_metadata(
            &store,
            b"anchor_slot",
            &0u64.to_be_bytes(),
        )
        .context("writing genesis anchor_slot metadata")?;

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
    on_tick::<MainnetBeaconSpec>(&mut fc_store_mut, wall_clock_secs);

    // Set the Bellatrix terminal-block constants from the loaded RuntimeConfig.
    // These are read by `on_block`'s merge-transition guard (`validate_merge_block`)
    // without threading `RuntimeConfig` through the fork-choice boundary.
    fc_store_mut.set_terminal_config(
        runtime_cfg.terminal_total_difficulty,
        runtime_cfg.terminal_block_hash,
        runtime_cfg.terminal_block_hash_activation_epoch,
    );
    // Wire fork epoch schedule so `process_slots_fork` triggers live upgrades
    // (per `D-live-fork-upgrade-trigger`).
    fc_store_mut.set_fork_epochs(
        runtime_cfg.altair_fork_epoch,
        runtime_cfg.bellatrix_fork_epoch,
        runtime_cfg.capella_fork_epoch,
    );
    fc_store_mut.runtime_cfg = runtime_cfg.clone();

    let fork_choice = Arc::new(RwLock::new(fc_store_mut));

    // ── Metrics server (deferred, requires fork_choice for /health probe) ──────
    //
    // The sync-state probe is a cheap closure over the fork-choice `RwLock`; it
    // reuses the same source as `/eth/v1/node/health` (`is_syncing` +
    // `is_optimistic`).  Per `D-health-probe-on-metrics-port` (M11 Phase 18).
    if let Some(metrics_addr) = metrics_addr_opt {
        use pharos_utils::metrics::SyncState;

        let fc_for_probe = Arc::clone(&fork_choice);
        let probe: Arc<dyn Fn() -> SyncState + Send + Sync> = Arc::new(move || {
            let fc = fc_for_probe.read();
            let is_optimistic = pharos_fork_choice::is_optimistic_node(&fc);
            let head_root = pharos_fork_choice::get_head(&fc);
            let head_slot = fc.blocks.get(&head_root).map(|b| {
                use pharos_types::views::BeaconBlockView;
                b.slot()
            });
            let current = pharos_fork_choice::get_current_slot(&fc);
            let is_syncing = match head_slot {
                Some(s) => u64::from(s) + 1 < u64::from(current),
                None => true,
            };
            if is_syncing || is_optimistic {
                SyncState::Syncing
            } else {
                SyncState::Synced
            }
        });

        pharos_utils::metrics::init_metrics(metrics_addr, Some(probe))
            .with_context(|| format!("starting Prometheus metrics server on {metrics_addr}"))?;
        info!(%metrics_addr, "Prometheus metrics server started (/metrics + /health)");
    }

    // Slot-clock driver: advance the fork-choice store's time cursor every
    // second so `on_block`'s future-slot guard tracks wall-clock. Without this
    // the cursor is frozen at startup and every block past the startup slot is
    // rejected as a "future block", stalling both backfill and gossip follow.
    // Mirrors the per-slot `on_tick` every CL client runs.
    {
        let fc = Arc::clone(&fork_choice);
        let mut shutdown_rx = pharos_node_shutdown_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(1));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let mut store = fc.write();
                        on_tick::<MainnetBeaconSpec>(&mut store, now);
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                    }
                }
            }
        });
        info!("slot-clock on_tick driver started");
    }

    // ── Step 4: Construct Engine API client + actor ───────────────────────

    // Build `watch` and `mpsc` channels for the engine driver loop.
    // The block-ingestion loop owns these senders and drives the engine driver
    // via `head_tx.send()` / `payload_tx.try_send()` directly.
    let (head_tx, head_rx) = watch::channel::<Option<HeadChange>>(None);
    let (payload_tx, payload_rx) = mpsc::channel::<NewPayloadRequest<MainnetBeaconSpec>>(64);

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

    // Identity of the connected execution client, from `engine_getClientVersionV1`.
    // Cached once at startup and surfaced via the Beacon API `/eth/v1/node/version`
    // (v2) `execution_client` field. `None` when no EL is wired or the EL predates
    // the method / the exchange failed.
    let mut el_client_version: Option<pharos_api::ExecutionClientVersion> = None;

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

        // Exchange client-version identities with the EL for client-diversity
        // stats (execution-apis/src/engine/identification.md). One-shot at
        // startup; on failure (EL down, or an EL that predates the method) we
        // simply leave `execution_client` unset in /eth/v1/node/version.
        let ours = pharos_engine::ClientVersionV1 {
            code: pharos_utils::version::CLIENT_CODE.to_string(),
            name: pharos_utils::version::CLIENT_NAME.to_string(),
            version: pharos_utils::version::CLIENT_VERSION.to_string(),
            commit: pharos_utils::version::COMMIT_4BYTE_HEX.to_string(),
        };
        match engine_handle.get_client_version_async(ours).await {
            Ok(mut els) if !els.is_empty() => {
                let el = els.remove(0);
                info!(
                    el_code = %el.code,
                    el_name = %el.name,
                    el_version = %el.version,
                    "engine_getClientVersionV1: connected to execution client"
                );
                el_client_version = Some(pharos_api::ExecutionClientVersion {
                    code: el.code,
                    name: el.name,
                    version: el.version,
                    commit: el.commit,
                });
            }
            Ok(_) => {
                tracing::warn!("engine_getClientVersionV1 returned an empty array");
            }
            Err(e) => {
                tracing::warn!(error = %e, "engine_getClientVersionV1 failed");
            }
        }
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
        capella_fork_version: pharos_types::phase0::primitives::Version::from_array(
            runtime_cfg.capella_fork_version,
        ),
        capella_fork_epoch: pharos_utils::Epoch(runtime_cfg.capella_fork_epoch),
        deneb_fork_version: pharos_types::phase0::primitives::Version::from_array(
            runtime_cfg.deneb_fork_version,
        ),
        deneb_fork_epoch: pharos_utils::Epoch(runtime_cfg.deneb_fork_epoch),
        electra_fork_version: pharos_types::phase0::primitives::Version::from_array(
            runtime_cfg.electra_fork_version,
        ),
        electra_fork_epoch: pharos_utils::Epoch(runtime_cfg.electra_fork_epoch),
        fulu_fork_version: pharos_types::phase0::primitives::Version::from_array(
            runtime_cfg.fulu_fork_version,
        ),
        fulu_fork_epoch: pharos_utils::Epoch(runtime_cfg.fulu_fork_epoch),
        blob_schedule: runtime_cfg.blob_schedule.clone(),
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
    let store_arc = Arc::clone(&store);
    // Shared (sticky-high) custody state, seeded at the protocol minimum
    // `CUSTODY_REQUIREMENT`. Created here so it can be wired into `HostImpl`
    // (which advertises it as the Fulu MetaDataV3 `custody_group_count` / ENR
    // `cgc`) AND driven by the custody-adjustment loop below — one source of
    // truth. A `cgc` of 0 makes fulu peers ban us (Goodbye Fault), so it must
    // never be left at the trait-default 0.
    let custody_state = Arc::new(CustodyState::new(
        <MainnetBeaconSpec as pharos_types::BeaconSpec>::CUSTODY_REQUIREMENT,
    ));

    let mut host_inner = HostImpl::<MainnetBeaconSpec>::new(
        store,
        fork_choice.clone(),
        genesis_validators_root,
        (*fork_schedule).clone(),
        genesis_time_secs,
        Arc::new(runtime_cfg.clone()),
    );
    host_inner.wire_engine(head_tx.clone(), payload_tx.clone());
    host_inner.wire_custody(Arc::clone(&custody_state));
    let host = Arc::new(host_inner);

    let discv5_addr = SocketAddr::new(listen_ip, args.discv5_port);

    // Optional IPv6 discv5 UDP socket (`D-discv5-dualstack`). Present iff
    // --listen-addr-ipv6 was supplied; clap's `requires` guarantees
    // --discv5-port-ipv6 is then also present.
    let discv5_addr6: Option<SocketAddr> = listen_ip6.map(|ip6| {
        let port = args
            .discv5_port_ipv6
            .expect("--discv5-port-ipv6 is required with --listen-addr-ipv6 (clap requires)");
        SocketAddr::new(IpAddr::V6(ip6), port)
    });

    // Create the per-node network directory (`<data-dir>/network/`) for ENR seq
    // persistence (`D-enr-seq-persistence`).
    let network_dir = args.data_dir.join("network");
    std::fs::create_dir_all(&network_dir)
        .with_context(|| format!("creating network directory {}", network_dir.display()))?;

    let (mut handle, discovery_handle) =
        NetworkBuilder::<MainnetBeaconSpec, Arc<HostImpl<MainnetBeaconSpec>>, NoopScorer>::new(
            host.clone(),
        )
        .listen_ip(listen_ip)
        .tcp_listen_port(tcp_port)
        .discv5_addr(discv5_addr)
        // M11 Phase 8: dual-stack discv5 + IPv6 libp2p listeners + ENR
        // ip6/tcp6/quic6 (`D-discv5-dualstack`). Both default to absent
        // (IPv4-only) when --listen-addr-ipv6 is not supplied.
        .listen_ip6(listen_ip6)
        .discv5_addr6(discv5_addr6)
        .bootnodes(bootnodes)
        // M11 Phase 12: wire CLI-provided connection limits into the builder so
        // PeerManager enforces max_peers on inbound and target_peers drives the
        // discv5 cadence formula (`D-connection-limit-prefer-high-score`).
        .max_peers(args.max_peers)
        .target_peers(args.target_peers)
        // M11 Phase 13: persist ENR seq across restarts so peers can re-resolve
        // us efficiently (`D-enr-seq-persistence`).
        .network_dir(network_dir)
        // M11 Phase 11: replace the M2 NoopScorer with the real peer scorer so
        // the swarm loop feeds live gossip/req-resp/dial signals into scoring
        // and acts on disconnect/ban/rate-limit/backoff decisions.
        .scorer(RealScorer::new())
        .spawn()
        .await
        .context("failed to start network")?;

    info!(peer_id = %handle.local_peer_id(), "network started");

    // Compute initial attestation subnets from the node-id and record them.
    // This bumps MetaData.seq_number from 0 to 1 exactly once at startup,
    // fulfilling the p2p-interface.md:391-393 requirement.
    let node_id = handle.local_node_id();
    let subnets = compute_subscribed_subnets::<MainnetBeaconSpec>(node_id, 0u64);
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
        let sps = runtime_cfg.seconds_per_slot;
        tokio::spawn(async move {
            run_subnet_rotation_loop::<MainnetBeaconSpec>(cmd, sched, nid, genesis_time_secs, sps)
                .await;
        });
    }

    // Spawn fork migration loop: handles ALL fork crossings (phase0→altair,
    // altair→bellatrix, and future forks) within a single run, updating the
    // ENR `eth2` field and rotating gossip topics at each boundary.
    {
        let cmd = handle.command_sender();
        let disc = discovery_handle.clone();
        let sched = Arc::clone(&fork_schedule);
        let sps = runtime_cfg.seconds_per_slot;
        tokio::spawn(async move {
            run_fork_migration_loop::<MainnetBeaconSpec>(cmd, disc, sched, genesis_time_secs, sps)
                .await;
        });
    }

    // Spawn the BPO-boundary migration loop (EIP-7892, RI-2): rotates the
    // fork-digest WITHIN the fulu fork at every BLOB_SCHEDULE entry's epoch
    // (distinct from the fork-VERSION crossings handled by the fork migration
    // loop). Exits immediately when no BPO entries are scheduled.
    {
        let cmd = handle.command_sender();
        let disc = discovery_handle.clone();
        let sched = Arc::clone(&fork_schedule);
        let max_blobs_electra = runtime_cfg.max_blobs_per_block_electra;
        let sps = runtime_cfg.seconds_per_slot;
        tokio::spawn(async move {
            run_bpo_migration_loop::<MainnetBeaconSpec>(
                cmd,
                disc,
                sched,
                genesis_time_secs,
                sps,
                max_blobs_electra,
            )
            .await;
        });
    }

    // ── Beacon API HTTP server (optional, --http flag) ────────────────────────
    //
    // Build the `NodeIdentityCache` here — BEFORE `handle.take_event_receiver()`
    // is called inside the engine block below. `wait_for_local_enr` and
    // `wait_for_listen_addr` drain early events from the event receiver;
    // both must complete while `handle` still owns the receiver.
    if args.http {
        // Wait for the network task to emit its ENR and bound listen address.
        let enr = handle.wait_for_local_enr().await;
        let listen_addr = handle.wait_for_listen_addr().await;

        // Derive discovery addrs from the ENR. enr_to_dial_addrs returns bare addrs
        // (no /p2p suffix) in QUIC-first order; we re-append /p2p/<peer_id> so the
        // Beacon API identity endpoint keeps the same with-/p2p format it always had.
        let local_peer_id = handle.local_peer_id();
        let discovery_addrs = pharos_network::discovery::enr::enr_to_dial_addrs(&enr)
            .map(|(_pid, addrs)| {
                addrs
                    .into_iter()
                    .filter_map(|a| a.with_p2p(local_peer_id).ok())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        let identity = pharos_api::NodeIdentityCache {
            peer_id: handle.local_peer_id(),
            enr,
            listen_addrs: vec![listen_addr],
            discovery_addrs,
            metadata: handle.metadata_ref(),
        };

        // Construct the Phase-2 state-regeneration service and wrap it in a
        // closure so that `NodeChainState` (in pharos-api) can call it without
        // a pharos-api → pharos-node dependency edge.
        let regen_svc = Arc::new(StateRegenService::<MainnetBeaconSpec>::new(
            Arc::clone(&store_arc),
            Arc::clone(&fork_choice),
            Arc::new(runtime_cfg.clone()),
        ));
        let regen_fn: Arc<pharos_api::RegenFn<MainnetBeaconSpec>> = {
            use pharos_api::ApiError;
            use pharos_api::RegenTarget;
            use pharos_node::state_regen::RegenError;
            let svc = Arc::clone(&regen_svc);
            Arc::new(move |target: RegenTarget| -> Result<_, ApiError> {
                let result = match target {
                    RegenTarget::Slot(slot) => svc.state_at_slot(slot),
                    RegenTarget::StateRoot(root) => svc.state_at_root(root),
                    RegenTarget::BlockRoot(block_root) => {
                        // Find the slot for this block root via the state-summary CF.
                        use pharos_storage::Store as DbStore;
                        let summary_result = <pharos_storage::RocksStore as DbStore<
                            MainnetBeaconSpec,
                        >>::get_state_summary(
                            svc.store_ref(), &block_root
                        )
                        .map_err(RegenError::Storage);
                        match summary_result {
                            Err(e) => Err(e),
                            Ok(Some(s)) => svc.state_at_slot(s.slot),
                            Ok(None) => Err(RegenError::NotFound(format!(
                                "no state-summary for block root {block_root:?}"
                            ))),
                        }
                    }
                };
                result.map_err(|e| match e {
                    RegenError::MissingBlock { .. }
                    | RegenError::MissingAnchorState
                    | RegenError::NotFound(_) => ApiError::NotFound(e.to_string()),
                    RegenError::Stf(_) | RegenError::Storage(_) => {
                        ApiError::Internal(e.to_string())
                    }
                })
            })
        };

        // Build the syncnets ENR callback that wires
        // `POST /eth/v1/validator/sync_committee_subscriptions` through to
        // `DiscoveryHandle::update_enr_syncnets` (`D-syncnets-enr-on-subscription`).
        let syncnets_fn: Arc<pharos_api::SyncnetsFn> = {
            use pharos_ssz::{Bitvector, Decode as SszDecode};
            use pharos_types::altair::constants::SYNC_COMMITTEE_SUBNET_COUNT;

            let disc = discovery_handle.clone();
            Arc::new(move |syncnets_ssz: Vec<u8>| {
                let bv =
                    Bitvector::<{ SYNC_COMMITTEE_SUBNET_COUNT }>::from_ssz_bytes(&syncnets_ssz)
                        .unwrap_or_default();
                let disc2 = disc.clone();
                tokio::spawn(async move {
                    if let Err(e) = disc2.update_enr_syncnets(bv).await {
                        tracing::warn!(?e, "syncnets ENR update failed");
                    }
                });
            })
        };

        let mut chain_state = pharos_api::NodeChainState::new_with_regen(
            Arc::clone(&store_arc),
            Arc::clone(&fork_choice),
            identity,
            Arc::new(runtime_cfg.clone()),
            regen_fn,
        )
        .with_syncnets_fn(syncnets_fn);

        // Wire block-production callbacks when an engine is configured.
        // When engine_handle_opt is None (no EL) the callbacks stay unset and
        // the validator-production endpoints return 503 as before.
        if let Some(ref engine_h) = engine_handle_opt {
            use std::collections::HashMap;
            use std::sync::Mutex;

            // Real `el_offline` for `/eth/v1/node/syncing`: read the engine
            // handle's liveness flag (updated on every blocking engine call).
            let el_engine = engine_h.clone();
            chain_state = chain_state.with_el_offline_fn(Arc::new(move || el_engine.el_offline()));

            // `execution_client` for `/eth/v1/node/version` (v2): serve the
            // identity captured from the startup `engine_getClientVersionV1`
            // exchange (static after startup).
            if let Some(el_cv) = el_client_version.clone() {
                chain_state =
                    chain_state.with_el_client_version_fn(Arc::new(move || Some(el_cv.clone())));
            }

            use pharos_api::ApiError;
            use pharos_network::host::ForkContext as _;
            use pharos_network::topics::{GossipTopic, GossipTopicKind};
            use pharos_ssz::Encode as SszEncode;

            use pharos_node::block_production::{produce_attestation_data, produce_block};
            use pharos_node::engine_driver::ExecutionEngineHandle as NodeEEHandle;
            use pharos_node::import::import_block;
            use pharos_node::pow_block::EnginePowBlockProvider as PowProvider;

            let pools_arc = Arc::clone(&host.op_pools);

            // Per-slot cache: slot → (SSZ bytes of unsigned block, fork discriminant byte,
            // blob sidecars produced alongside the block — non-empty only for Deneb).
            //
            // The SSZ bytes are from the CONCRETE per-fork type (no discriminant prefix).
            // The discriminant maps ForkVariant to the pharos storage byte used in the
            // state.rs fork-enum Decode impl: Phase0=0, Altair=1, Bellatrix=2, Capella=3,
            // Deneb=4.
            //
            // Shared between produce_fn (writer) and publish_fn (reader).
            type BlockCache =
                Arc<Mutex<HashMap<u64, (Vec<u8>, u8, Vec<pharos_types::deneb::BlobSidecar>)>>>;
            let produce_cache: BlockCache = Arc::new(Mutex::new(HashMap::new()));
            let produce_cache_pub = Arc::clone(&produce_cache);

            // ── produce_fn ───────────────────────────────────────────────────
            let produce_engine = engine_h.clone();
            let produce_fc = Arc::clone(&fork_choice);
            let produce_pools = Arc::clone(&pools_arc);
            let produce_cfg = runtime_cfg.clone();
            // KZG verifier for fulu data-column-sidecar production (computing the
            // per-blob cells from the V5 blobs bundle). Cheap to clone (Arc).
            let produce_kzg = Arc::new(pharos_kzg::KzgVerifier::mainnet());
            let produce_fn: Arc<pharos_api::ProduceFn> = Arc::new(
                move |slot: pharos_types::phase0::Slot,
                      randao_reveal: pharos_utils::BLSSignature,
                      graffiti: pharos_utils::Bytes32| {
                    // Use the zero address as the default fee recipient.
                    // The VC can override this via POST /eth/v1/validator/prepare_beacon_proposer.
                    let fee_recipient = "0x0000000000000000000000000000000000000000".to_string();

                    let (signed_block, _post_state, exec_value, blob_sidecars, _column_sidecars) =
                        produce_block::<MainnetBeaconSpec>(
                            &produce_fc,
                            &produce_pools,
                            &produce_engine,
                            &produce_kzg,
                            slot,
                            randao_reveal,
                            graffiti.into(),
                            fee_recipient,
                            &produce_cfg,
                        )
                        .map_err(|e| ApiError::Internal(format!("produce_block: {e}")))?;

                    // SSZ-encode the unsigned block and cache with fork discriminant.
                    // The fork-enum Decode impl expects: [disc_byte] ++ concrete_ssz.
                    let (ssz_bytes, disc, block_json_value) = match &signed_block {
                        pharos_types::state::SignedBeaconBlock::Phase0(inner) => {
                            let ssz = inner.as_ssz_bytes();
                            let json = pharos_api::dto::block::phase0_signed_block_to_api(inner)
                                .map_err(|e| ApiError::Internal(format!("DTO: {e}")))?;
                            (ssz, 0u8, json)
                        }
                        pharos_types::state::SignedBeaconBlock::Altair(inner) => {
                            let ssz = inner.as_ssz_bytes();
                            let json = pharos_api::dto::block::altair_signed_block_to_api(inner)
                                .map_err(|e| ApiError::Internal(format!("DTO: {e}")))?;
                            (ssz, 1u8, json)
                        }
                        pharos_types::state::SignedBeaconBlock::Bellatrix(inner) => {
                            let ssz = inner.as_ssz_bytes();
                            let json = pharos_api::dto::block::bellatrix_signed_block_to_api(inner)
                                .map_err(|e| ApiError::Internal(format!("DTO: {e}")))?;
                            (ssz, 2u8, json)
                        }
                        pharos_types::state::SignedBeaconBlock::Capella(inner) => {
                            let ssz = inner.as_ssz_bytes();
                            let json = pharos_api::dto::block::capella_signed_block_to_api(inner)
                                .map_err(|e| ApiError::Internal(format!("DTO: {e}")))?;
                            (ssz, 3u8, json)
                        }
                        pharos_types::state::SignedBeaconBlock::Deneb(inner) => {
                            use pharos_ssz::Encode as _;
                            use pharos_types::views::ForkVariant;
                            let ssz = inner.as_ssz_bytes();
                            // Deneb-specific JSON DTO is not yet written; the VC uses
                            // block_ssz (the SSZ hex) to compute the signing root, not
                            // the JSON body. Return a stub JSON with slot so the VC can
                            // read message.slot; the `block_ssz` field carries real bytes.
                            let stub_json = pharos_api::dto::block::SignedBlockForApi {
                                variant: ForkVariant::Deneb,
                                ssz_bytes: ssz.clone(),
                                attestations_json: vec![],
                                json: serde_json::json!({
                                    "message": {
                                        "slot": inner.message.slot.0.to_string(),
                                        "proposer_index": inner.message.proposer_index.0.to_string(),
                                        "parent_root": format!("0x{}", hex::encode(inner.message.parent_root.as_slice())),
                                        "state_root": format!("0x{}", hex::encode(inner.message.state_root.as_slice())),
                                    }
                                }),
                            };
                            (ssz, 4u8, stub_json)
                        }
                        pharos_types::state::SignedBeaconBlock::Electra(inner) => {
                            use pharos_ssz::Encode as _;
                            use pharos_types::views::ForkVariant;
                            let ssz = inner.as_ssz_bytes();
                            // As with Deneb: the VC signs over `block_ssz` (the unsigned
                            // message bytes), not the JSON body, so the JSON is a stub
                            // carrying message.slot etc. The `block_ssz` field carries the
                            // real fork-enum bytes for the proposer-root computation.
                            let stub_json = pharos_api::dto::block::SignedBlockForApi {
                                variant: ForkVariant::Electra,
                                ssz_bytes: ssz.clone(),
                                attestations_json: vec![],
                                json: serde_json::json!({
                                    "message": {
                                        "slot": inner.message.slot.0.to_string(),
                                        "proposer_index": inner.message.proposer_index.0.to_string(),
                                        "parent_root": format!("0x{}", hex::encode(inner.message.parent_root.as_slice())),
                                        "state_root": format!("0x{}", hex::encode(inner.message.state_root.as_slice())),
                                    }
                                }),
                            };
                            (ssz, 5u8, stub_json)
                        }
                        pharos_types::state::SignedBeaconBlock::Fulu(inner) => {
                            use pharos_ssz::Encode as _;
                            use pharos_types::views::ForkVariant;
                            let ssz = inner.as_ssz_bytes();
                            // Same serialize/proposer-root contract as Electra; the
                            // `block_ssz` field carries the fork-enum bytes for the VC.
                            let stub_json = pharos_api::dto::block::SignedBlockForApi {
                                variant: ForkVariant::Fulu,
                                ssz_bytes: ssz.clone(),
                                attestations_json: vec![],
                                json: serde_json::json!({
                                    "message": {
                                        "slot": inner.message.slot.0.to_string(),
                                        "proposer_index": inner.message.proposer_index.0.to_string(),
                                        "parent_root": format!("0x{}", hex::encode(inner.message.parent_root.as_slice())),
                                        "state_root": format!("0x{}", hex::encode(inner.message.state_root.as_slice())),
                                    }
                                }),
                            };
                            (ssz, 6u8, stub_json)
                        }
                    };

                    // Fork-enum BeaconBlock SSZ (`[disc] ++ message_ssz`) for the VC to
                    // decode and tree-hash so it signs the REAL proposer root. The
                    // SignedBeaconBlock SSZ is `[offset(4)][sig(96)][message_ssz]`, so the
                    // unsigned message bytes are `ssz_bytes[100..]`.
                    let block_ssz_hex = if ssz_bytes.len() >= 100 {
                        let mut fork_enum = Vec::with_capacity(1 + ssz_bytes.len() - 100);
                        fork_enum.push(disc);
                        fork_enum.extend_from_slice(&ssz_bytes[100..]);
                        format!("0x{}", hex::encode(&fork_enum))
                    } else {
                        String::new()
                    };

                    if let Ok(mut cache) = produce_cache.lock() {
                        cache.insert(slot.0, (ssz_bytes, disc, blob_sidecars));
                    }

                    // The handler reads `block_json.get("data").unwrap_or(&block_json)`.
                    // Return {"data": <unsigned BeaconBlock message>} so the VC signs it,
                    // plus `block_ssz` (the fork-enum SSZ) so the VC can compute the root.
                    let message_json = block_json_value
                        .json
                        .get("message")
                        .cloned()
                        .unwrap_or(block_json_value.json);
                    let mut block_json = JsonValue::Object(JsonMap::new());
                    block_json["data"] = message_json;
                    block_json["block_ssz"] = JsonValue::String(block_ssz_hex);

                    Ok((block_json, exec_value, pharos_utils::Uint256::ZERO))
                },
            );

            // ── produce_att_data_fn ──────────────────────────────────────────
            let att_fc = Arc::clone(&fork_choice);
            let att_cfg = runtime_cfg.clone();
            let produce_att_data_fn: Arc<pharos_api::ProduceAttDataFn> = Arc::new(
                move |slot: pharos_types::phase0::Slot,
                      committee_index: pharos_types::phase0::primitives::CommitteeIndex| {
                    produce_attestation_data::<MainnetBeaconSpec>(
                        &att_fc,
                        slot,
                        committee_index,
                        &att_cfg,
                    )
                    .map_err(|e| {
                        ApiError::Internal(format!("produce_attestation_data: {e}"))
                    })
                },
            );

            // ── publish_fn ───────────────────────────────────────────────────
            // Receives a SignedBeaconBlock JSON from the VC (with VC BLS signature).
            // Reconstructs the signed SSZ by overlaying the VC signature onto
            // the cached unsigned block bytes, then imports + gossips.
            //
            // SSZ layout of SignedBeaconBlock<...> (all fork variants):
            //   bytes  0..4   = LE u32 offset to message (= 100)
            //   bytes  4..100 = BLS signature (96 bytes, zeroed for unsigned block)
            //   bytes 100..   = BeaconBlock message SSZ bytes
            //
            // The fork-enum Decode impl (pharos_types::state::SignedBeaconBlock)
            // prepends a fork discriminant byte; we add it from the cache.
            //
            // This closure is called inside tokio::task::spawn_blocking by the
            // handler; tokio::spawn for the async import+gossip is safe from a
            // blocking thread as long as a tokio runtime is active.
            let pub_host = Arc::clone(&host);
            let pub_fc = Arc::clone(&fork_choice);
            let pub_engine = engine_h.clone();
            let pub_payload_tx = payload_tx.clone();
            let pub_cfg = runtime_cfg.clone();
            let pub_store = Arc::clone(&store_arc);
            let pub_cmd = handle.command_sender();
            let publish_fn: Arc<pharos_api::PublishFn> = Arc::new(move |block_json: JsonValue| {
                use pharos_ssz::Decode as SszDecode;

                // Extract BLS signature (96 bytes) from the JSON.
                let sig_hex = block_json["signature"]
                    .as_str()
                    .unwrap_or("0x")
                    .strip_prefix("0x")
                    .unwrap_or("");
                let sig_bytes_vec = hex::decode(sig_hex).unwrap_or_default();
                if sig_bytes_vec.len() != 96 {
                    return Err(ApiError::BadRequest(
                        "SignedBeaconBlock: signature must be 96 bytes".into(),
                    ));
                }
                let mut sig_bytes = [0u8; 96];
                sig_bytes.copy_from_slice(&sig_bytes_vec);

                // Extract slot to look up the cached unsigned block SSZ.
                let slot_val = block_json["message"]["slot"]
                    .as_str()
                    .and_then(|s| s.parse::<u64>().ok())
                    .or_else(|| block_json["message"]["slot"].as_u64())
                    .ok_or_else(|| ApiError::BadRequest("missing message.slot".into()))?;

                let (mut ssz_bytes, disc, mut cached_blob_sidecars) = produce_cache_pub
                    .lock()
                    .ok()
                    .and_then(|cache| cache.get(&slot_val).cloned())
                    .ok_or_else(|| {
                        ApiError::BadRequest(format!(
                            "no cached block for slot {slot_val}; call produce_block first"
                        ))
                    })?;

                // The cached sidecars were built before the VC signature existed,
                // so each `signed_block_header.signature` is still zero. Patch in
                // the real proposer signature; otherwise gossip peers `[REJECT]`
                // the sidecars on the proposer-signature rule
                // (`specs/deneb/p2p-interface.md` blob-sidecar validation).
                for sc in &mut cached_blob_sidecars {
                    sc.signed_block_header.signature = pharos_utils::BLSSignature::from(sig_bytes);
                }

                // Overlay the VC signature at bytes [4..100].
                if ssz_bytes.len() < 100 {
                    return Err(ApiError::Internal("cached block SSZ too short".into()));
                }
                ssz_bytes[4..100].copy_from_slice(&sig_bytes);

                // Prepend the fork discriminant and decode into the fork enum.
                let mut with_disc = Vec::with_capacity(1 + ssz_bytes.len());
                with_disc.push(disc);
                with_disc.extend_from_slice(&ssz_bytes);

                let signed_block =
                    pharos_types::state::MainnetSignedBeaconBlock::from_ssz_bytes(&with_disc)
                        .map_err(|e| {
                            ApiError::Internal(format!("SSZ decode signed block: {e:?}"))
                        })?;

                // Get the current fork digest for the gossip topic.
                let fork_digest = pub_host.current_fork_digest();

                // Spawn async import + gossip (fire-and-forget; returns Ok(true) optimistically).
                let fc_c = Arc::clone(&pub_fc);
                let ee_c = Arc::new(NodeEEHandle::new(pub_engine.clone()));
                let pow_c = Arc::new(PowProvider::new(pub_engine.clone()));
                let ptx_c = pub_payload_tx.clone();
                let cfg_c = pub_cfg.clone();
                let store_c = Arc::clone(&pub_store);
                let cmd_c = pub_cmd.clone();
                let gossip_bytes = ssz_bytes;
                tokio::spawn(async move {
                    // Locally proposed block: blobs are available by construction.
                    use pharos_node::data_availability::NoopDataAvailabilityChecker;
                    let noop_da = Arc::new(NoopDataAvailabilityChecker);
                    match import_block::<
                        MainnetBeaconSpec,
                        NodeEEHandle,
                        PowProvider,
                        NoopDataAvailabilityChecker,
                    >(
                        &signed_block,
                        &fc_c,
                        &ee_c,
                        &pow_c,
                        &ptx_c,
                        true,
                        &cfg_c,
                        &store_c,
                        &noop_da,
                    )
                    .await
                    {
                        Ok(outcome) => {
                            tracing::info!(
                                slot = slot_val,
                                block_root = ?outcome.block_root,
                                "VC-submitted block imported"
                            );
                        }
                        Err(e) => {
                            tracing::warn!(
                                slot = slot_val,
                                error = %e,
                                "VC-submitted block import failed"
                            );
                        }
                    }

                    // Gossip the signed block SSZ bytes (concrete fork, no discriminant).
                    let topic = GossipTopic {
                        fork_digest,
                        kind: GossipTopicKind::BeaconBlock,
                    };
                    // Wrap raw SSZ bytes in a minimal Encode impl for the publish API.
                    struct RawSsz(Vec<u8>);
                    impl pharos_ssz::Encode for RawSsz {
                        const IS_FIXED_SIZE: bool = false;
                        fn ssz_fixed_len() -> usize {
                            pharos_ssz::BYTES_PER_LENGTH_OFFSET
                        }
                        fn ssz_append(&self, buf: &mut Vec<u8>) {
                            buf.extend_from_slice(&self.0);
                        }
                        fn ssz_bytes_len(&self) -> usize {
                            self.0.len()
                        }
                    }
                    if let Err(e) = cmd_c.publish(topic, &RawSsz(gossip_bytes)).await {
                        tracing::warn!(
                            slot = slot_val,
                            error = %e,
                            "VC-submitted block gossip failed"
                        );
                    }

                    // ── Blob sidecars: persist + publish ─────────────────────
                    // For Deneb blocks, persist each sidecar to the store and
                    // publish it on the `blob_sidecar/{subnet_id}` gossip topic.
                    // The subnet for sidecar index `i` is `i % BLOB_SIDECAR_SUBNET_COUNT`.
                    if !cached_blob_sidecars.is_empty() {
                        // Derive block root from the sidecar's signed block header.
                        // All sidecars share the same block header, so use index 0.
                        let block_root: pharos_utils::Hash256 = {
                            use pharos_ssz::TreeHash as _;
                            cached_blob_sidecars[0]
                                .signed_block_header
                                .message
                                .tree_hash_root()
                        };
                        // Persist to storage (one call per sidecar).
                        for sidecar in &cached_blob_sidecars {
                            if let Err(e) = <pharos_storage::RocksStore as pharos_storage::Store<
                                MainnetBeaconSpec,
                            >>::put_blob_sidecar(
                                &store_c, block_root, sidecar.index, sidecar
                            ) {
                                tracing::warn!(
                                    slot = slot_val,
                                    index = sidecar.index,
                                    error = %e,
                                    "blob sidecar persist failed"
                                );
                            }
                        }
                        // Publish each sidecar on its subnet topic.
                        // subnet_id = sidecar.index % BLOB_SIDECAR_SUBNET_COUNT (= 6 for mainnet).
                        for sidecar in &cached_blob_sidecars {
                            let subnet_id =
                                sidecar.index % MainnetBeaconSpec::BLOB_SIDECAR_SUBNET_COUNT;
                            let sidecar_topic = GossipTopic {
                                fork_digest,
                                kind: GossipTopicKind::BlobSidecar(subnet_id),
                            };
                            if let Err(e) = cmd_c.publish(sidecar_topic, sidecar).await {
                                tracing::warn!(
                                    slot = slot_val,
                                    index = sidecar.index,
                                    error = %e,
                                    "blob sidecar gossip failed"
                                );
                            } else {
                                tracing::debug!(
                                    slot = slot_val,
                                    index = sidecar.index,
                                    "blob sidecar published"
                                );
                            }
                        }
                    }
                });

                Ok(true)
            });

            // ── peers_fn ─────────────────────────────────────────────────────
            // Query the live network task for connected peers and map each
            // `PeerInfo` to the beacon-API peer JSON. `peers_fn` is invoked from
            // the API handlers inside `spawn_blocking`, so `block_on` runs on a
            // blocking-pool thread (never a runtime worker) and is safe.
            let peers_cmd = handle.command_sender();
            let peers_rt = tokio::runtime::Handle::current();
            let peers_fn: Arc<pharos_api::PeersFn> = Arc::new(move || {
                peers_rt
                    .block_on(peers_cmd.peers())
                    .iter()
                    .map(peer_info_to_json)
                    .collect()
            });

            // ── sync_contribution_fn ─────────────────────────────────────────
            // Build a SyncCommitteeContribution for GET
            // /eth/v1/validator/sync_committee_contribution from pooled sync
            // messages + the head-state sync committee (non-draining).
            let sc_fc = Arc::clone(&fork_choice);
            let sc_pools = Arc::clone(&pools_arc);
            let sync_contribution_fn: Arc<pharos_api::SyncContributionFn> = Arc::new(
                move |slot: u64,
                      block_root: pharos_types::phase0::primitives::Root,
                      subc_idx: u64| {
                    use pharos_node::block_production::build_sync_contribution;
                    let (positions, sig) = build_sync_contribution::<MainnetBeaconSpec>(
                        &sc_fc,
                        &sc_pools,
                        pharos_types::phase0::Slot(slot),
                        block_root,
                        subc_idx,
                    )?;
                    // aggregation_bits is a fixed Bitvector[SYNC_SUBCOMMITTEE_SIZE]:
                    // no length-delimiter bit, byte i / bit i%8 little-endian.
                    let subc_size = MainnetBeaconSpec::SYNC_SUBCOMMITTEE_SIZE as usize;
                    let mut bits = vec![0u8; subc_size.div_ceil(8)];
                    for p in positions {
                        if p < subc_size {
                            bits[p / 8] |= 1 << (p % 8);
                        }
                    }
                    Some(serde_json::json!({
                        "slot": slot.to_string(),
                        "beacon_block_root": format!("0x{}", hex::encode(block_root.as_slice())),
                        "subcommittee_index": subc_idx.to_string(),
                        "aggregation_bits": format!("0x{}", hex::encode(&bits)),
                        "signature": format!("0x{}", hex::encode(sig.as_slice())),
                    }))
                },
            );

            chain_state = chain_state
                .with_pools(pools_arc)
                .with_produce_fns(produce_fn, produce_att_data_fn, publish_fn, peers_fn)
                .with_sync_contribution_fn(sync_contribution_fn);

            info!("block-production callbacks wired into Beacon API");
        }

        // Build the SSE event bus and spawn the adapter task.
        let event_bus = pharos_api::EventBus::new();
        let adapter_head_rx = head_tx.subscribe();
        {
            use pharos_node::api_event_adapter::run_api_event_adapter;
            let fc_adapter = Arc::clone(&fork_choice);
            let bus_adapter = Arc::clone(&event_bus);
            tokio::spawn(async move {
                run_api_event_adapter::<MainnetBeaconSpec>(
                    adapter_head_rx,
                    fc_adapter,
                    bus_adapter,
                )
                .await;
            });
            info!("SSE event adapter task started");
        }

        // Spawn the slot-aligned per-slot status heartbeat task.
        tokio::spawn(pharos_node::status_logger::run_status_heartbeat::<
            MainnetBeaconSpec,
        >(
            Arc::clone(&fork_choice),
            handle.command_sender(),
            genesis_time_secs,
            args.target_peers,
            pharos_node_shutdown_rx.clone(),
        ));
        info!("per-slot status heartbeat task started");

        // Load the optional validator-API token (trimmed file contents, the common CL client format).
        let validator_token: Option<String> = if let Some(ref token_path) = args.validator_api_token
        {
            let raw = std::fs::read_to_string(token_path)
                .with_context(|| format!("reading validator API token from {token_path:?}"))?;
            let token = raw.trim().to_string();
            if token.is_empty() {
                anyhow::bail!("--validator-api-token file is empty: {token_path:?}");
            }
            info!(path = %token_path.display(), "validator API token loaded; /eth/v1/validator/* is auth-gated");
            Some(token)
        } else {
            None
        };

        let api_state = pharos_api::ApiState::new_with_bus_and_log_reload(
            Arc::new(chain_state),
            event_bus,
            Some(log_reload.clone()),
        );
        let http_addr = SocketAddr::new(args.http_address, args.http_port);
        tokio::spawn(async move {
            pharos_api::serve_with_auth::<MainnetBeaconSpec>(http_addr, api_state, validator_token)
                .await;
        });
        info!(%http_addr, "Beacon API HTTP server spawned");
        info!(
            "runtime log-level endpoint enabled at POST /pharos/v1/log-level (validator-auth gated)"
        );
    }

    // ── Freezer loop (hot→cold migration at finalization) ────────────────────
    //
    // Driven off the existing `head_tx` watch per `D-freezer-driver-off-head-watch`.
    // A clone of `head_rx` is used so that both the engine driver and the freezer
    // receive head-advance notifications independently (watch semantics: multiple
    // receivers, no consumption).
    if !args.no_freezer {
        let freezer_head_rx = head_rx.clone();
        let freezer_store = Arc::clone(&store_arc);
        let freezer_fc = Arc::clone(&fork_choice);
        let rpi = args.restore_point_interval_epochs;
        let freezer_shutdown = pharos_node_shutdown_rx.clone();
        tokio::spawn(async move {
            run_freezer_loop::<MainnetBeaconSpec>(
                freezer_head_rx,
                freezer_store,
                freezer_fc,
                rpi,
                freezer_shutdown,
            )
            .await;
        });
        info!(
            restore_point_interval_epochs = args.restore_point_interval_epochs,
            "freezer loop started"
        );
    } else {
        info!("--no-freezer: hot/cold migration disabled");
    }

    // ── Custody adjustment loop (EIP-7594 PeerDAS) ─────────────────────────────
    //
    // Re-evaluates validator custody on each finalized state (off the head-watch,
    // `D-freezer-driver-off-head-watch`): on a custody INCREASE it raises the ENR
    // `cgc` (sticky-high) and re-subscribes to the covering `data_column_sidecar`
    // subnets; on a DECREASE it keeps the highest `cgc` and the previous set.
    //
    // VC → BN validator-indices ingress: the VC already reports its attached
    // validator indices via `POST /eth/v1/validator/prepare_beacon_proposer`; the
    // BN feeds those into `custody_validator_indices_tx` (the lighter-touch option
    // that reuses the existing BN↔VC REST pattern — no new endpoint/protocol).
    // The channel starts empty; a non-validating node keeps the protocol-minimum
    // custody (`CUSTODY_REQUIREMENT`). `custody_state` is created earlier (wired
    // into `HostImpl` for the MetaDataV3 `cgc` / ENR); the loop drives the same Arc.
    let (custody_validator_indices_tx, custody_validator_indices_rx) =
        watch::channel::<Vec<pharos_types::phase0::primitives::ValidatorIndex>>(Vec::new());
    // Hold the sender for the lifetime of the node so the channel stays open; the
    // `prepare_beacon_proposer` REST path updates it (documented ingress).
    let _custody_validator_indices_tx = custody_validator_indices_tx;
    {
        let custody_head_rx = head_rx.clone();
        let custody_fc = Arc::clone(&fork_choice);
        let custody_state_loop = Arc::clone(&custody_state);
        let custody_node_id = node_id.raw();
        let custody_cmd = handle.command_sender();
        let custody_disc = discovery_handle.clone();
        let custody_shutdown = pharos_node_shutdown_rx.clone();
        tokio::spawn(async move {
            run_custody_adjustment_loop::<MainnetBeaconSpec>(
                custody_head_rx,
                custody_fc,
                custody_validator_indices_rx,
                custody_state_loop,
                custody_node_id,
                custody_cmd,
                custody_disc,
                custody_shutdown,
            )
            .await;
        });
        info!("custody adjustment loop started");
    }

    // ── Slasher Phase B: chain-history replay (opt-in, --slasher) ──────────────
    //
    // Gated entirely behind `--slasher` (M11 Phase 9). When off, only the
    // always-on Phase A in-memory attestation slasher (inside HostImpl, fed from
    // gossip) runs and this replay path is skipped. When on, a one-shot
    // background pass walks the stored block history (anchor_slot → head) and
    // feeds each block's proposer header + attestations through the persistent
    // proposer detector and the (separate) Phase A attestation detector, sharing
    // the node's `op_pools` so detected slashings are block-includable.
    if args.slasher {
        use pharos_node::slasher::AttestationSlasher;
        use pharos_node::slasher::proposer::ProposerSlasher;
        use pharos_node::slasher::replay::{ChainReplaySlasher, run_replay};

        // Scan range: anchor_slot (lower bound on a checkpoint-synced node) up to
        // the current wall-clock slot. Empty slots in the index are skipped by the
        // scanner, so over-scanning to the wall slot is safe.
        let anchor_slot = <RocksStore as pharos_storage::Store<MainnetBeaconSpec>>::get_metadata(
            &store_arc,
            b"anchor_slot",
        )
        .ok()
        .flatten()
        .and_then(|v| v.try_into().ok().map(u64::from_be_bytes))
        .unwrap_or(0);
        let head_slot = {
            let s = fork_choice.read();
            pharos_fork_choice::get_current_slot(&s)
        };

        let slasher_op_pools = Arc::clone(&host.op_pools);
        let slasher_store = Arc::clone(&store_arc);
        let slasher_regen = Arc::new(StateRegenService::<MainnetBeaconSpec>::new(
            Arc::clone(&store_arc),
            Arc::clone(&fork_choice),
            Arc::new(runtime_cfg.clone()),
        ));
        let proposer = ProposerSlasher::<MainnetBeaconSpec>::new(
            Arc::clone(&slasher_store),
            Arc::clone(&slasher_op_pools),
        );
        let attestation = Arc::new(AttestationSlasher::<MainnetBeaconSpec>::new(Arc::clone(
            &slasher_op_pools,
        )));
        let chain_slasher = Arc::new(ChainReplaySlasher::<MainnetBeaconSpec>::new(
            slasher_store,
            proposer,
            attestation,
            slasher_regen,
        ));

        tokio::spawn(async move {
            run_replay::<MainnetBeaconSpec>(
                chain_slasher,
                pharos_types::phase0::primitives::Slot(anchor_slot),
                head_slot,
            )
            .await;
        });
        info!(
            anchor_slot,
            head_slot = %head_slot,
            "--slasher: chain-history replay scheduled"
        );
    } else {
        info!("--slasher: chain-history replay disabled (Phase A in-memory slasher still active)");
    }

    // ── Blob prune loop (W8: separate head-watch loop per D-blob-store-cf-keyed-by-root-index)
    //
    // Driven off a clone of `head_rx` (same pattern as the freezer loop).
    // Deletes blob sidecars whose epoch is older than
    // `MIN_EPOCHS_FOR_BLOB_SIDECARS_REQUESTS` behind the head epoch, clamped
    // to never prune at or below `deneb_fork_epoch`.
    {
        let blob_prune_head_rx = head_rx.clone();
        let blob_prune_store = Arc::clone(&store_arc);
        let blob_prune_fc = Arc::clone(&fork_choice);
        let deneb_fork_epoch = runtime_cfg.deneb_fork_epoch;
        let blob_prune_shutdown = pharos_node_shutdown_rx.clone();
        tokio::spawn(async move {
            run_blob_prune_loop::<MainnetBeaconSpec>(
                blob_prune_head_rx,
                blob_prune_store,
                blob_prune_fc,
                deneb_fork_epoch,
                blob_prune_shutdown,
            )
            .await;
        });
        info!(deneb_fork_epoch, "blob prune loop started");
    }

    // ── Data-column prune loop (EIP-7594 PeerDAS, separate head-watch loop) ─────
    //
    // Driven off a clone of `head_rx` (same pattern as the blob prune + freezer
    // loops). Deletes data-column sidecars whose epoch is older than
    // `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` (= 4096) behind the head
    // epoch, clamped to never prune at or below `fulu_fork_epoch`.
    {
        let column_prune_head_rx = head_rx.clone();
        let column_prune_store = Arc::clone(&store_arc);
        let column_prune_fc = Arc::clone(&fork_choice);
        let fulu_fork_epoch = runtime_cfg.fulu_fork_epoch;
        let column_prune_shutdown = pharos_node_shutdown_rx.clone();
        tokio::spawn(async move {
            run_column_prune_loop::<MainnetBeaconSpec>(
                column_prune_head_rx,
                column_prune_store,
                column_prune_fc,
                fulu_fork_epoch,
                column_prune_shutdown,
            )
            .await;
        });
        info!(fulu_fork_epoch, "data-column prune loop started");
    }

    // Spawn engine driver loop + block ingestion loop when the engine is active.
    if let Some(engine_handle) = engine_handle_opt {
        // Build production execution-engine bridge (EngineHandle → ExecutionEngine).
        let exec_engine = Arc::new(ExecutionEngineHandle::new(engine_handle.clone()));

        // Build production PoW-block provider for the merge-transition guard.
        // Constructed before the engine driver so the driver can hold a clone
        // for merge-transition VALID re-validation per
        // `consensus-specs/sync/optimistic.md:205-212` (Task 4.2).
        let pow_provider = Arc::new(EnginePowBlockProvider::new(engine_handle.clone()));

        // Spawn engine driver: listens for HeadChange watch and NewPayloadRequest mpsc.
        // A clone of head_tx is given so the driver can emit a HeadChange on INVALID
        // resolution (recomputed head after transitive invalidation).
        {
            let fc = Arc::clone(&fork_choice);
            let eng = engine_handle.clone();
            let head_tx_driver = head_tx.clone();
            let pow_driver = Arc::clone(&pow_provider);
            tokio::spawn(async move {
                run_engine_driver_loop::<MainnetBeaconSpec, EnginePowBlockProvider>(
                    eng,
                    fc,
                    head_rx,
                    payload_rx,
                    head_tx_driver,
                    pow_driver,
                )
                .await;
            });
            info!("engine driver loop started");
        }

        // Shared Notify: fired by ingestion when an orphan is deferred, wakes
        // the backfill loop for tip re-convergence.
        let notify_backfill = std::sync::Arc::new(tokio::sync::Notify::new());

        // Lookup-sync channels and shared pending-blocks store.
        let (lookup_tx, lookup_rx) = mpsc::channel::<LookupRequest>(256);
        let pending = Arc::new(PendingBlocks::default());

        // Re-inject channel: future gossip blocks held until their slot opens
        // are replayed back into the ingestion loop (fork-choice "delay future
        // blocks until they are in the past").
        let (reinject_tx, reinject_rx) = mpsc::channel::<ReinjectBlock>(64);

        // DA checker + blob-awaiting registry.
        //
        // Fork-aware: a live node spans the Electra→Fulu boundary and must gate
        // pre-Fulu blocks against blob sidecars and Fulu+ blocks against data
        // column sidecars. A static BlobAvailabilityChecker would park Fulu
        // blocks forever (blobs never arrive post-Fulu). Per
        // `D-fork-aware-live-da-checker`. The column sampling set uses the
        // node's NodeID + the baseline CUSTODY_REQUIREMENT (sampling_size =
        // max(SAMPLES_PER_SLOT, cgc) governs the actual expected-column count).
        let kzg_verifier = Arc::new(pharos_kzg::KzgVerifier::mainnet());
        let da_checker = Arc::new(ForkAwareDataAvailabilityChecker::<MainnetBeaconSpec>::new(
            Arc::clone(&store_arc),
            Arc::clone(&kzg_verifier),
            Arc::new(runtime_cfg.clone()),
            node_id.raw(),
            MainnetBeaconSpec::CUSTODY_REQUIREMENT,
        ));
        let blob_awaiting = Arc::new(BlobAwaitingBlocks::new());

        // Column-awaiting registry (EIP-7594 PeerDAS, Fulu). DA-pending fulu blocks
        // park here awaiting their data-column sidecars; re-injected on set completion.
        let column_awaiting = Arc::new(ColumnAwaitingBlocks::new());

        // Blob-sidecar forwarding channel (block ingestion loop demuxes blob events).
        let (blob_event_tx, blob_event_rx) =
            mpsc::channel::<pharos_network::network::NetworkEvent>(256);

        // Data-column-sidecar forwarding channel (block ingestion loop demuxes
        // GossipDataColumnSidecar events to the column ingestion loop).
        let (column_event_tx, column_event_rx) =
            mpsc::channel::<pharos_network::network::NetworkEvent>(256);

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
                lookup_tx: lookup_tx.clone(),
                reinject_tx: reinject_tx.clone(),
            };
            let da_checker_clone = Arc::clone(&da_checker);
            let blob_awaiting_clone = Arc::clone(&blob_awaiting);
            let column_awaiting_clone = Arc::clone(&column_awaiting);
            tokio::spawn(async move {
                if let Err(e) = run_block_ingestion_loop::<
                    MainnetBeaconSpec,
                    ExecutionEngineHandle,
                    ForkAwareDataAvailabilityChecker<MainnetBeaconSpec>,
                >(
                    event_rx,
                    reinject_rx,
                    h,
                    fc,
                    exec_engine_clone,
                    pow_clone,
                    ingestion_egress,
                    true, // validate_result: enforce BLS signatures and state roots
                    da_checker_clone,
                    blob_awaiting_clone,
                    Some(column_awaiting_clone),
                    Some(blob_event_tx),
                    Some(column_event_tx),
                )
                .await
                {
                    tracing::error!(error = %e, "block ingestion loop exited with error");
                }
            });
        }
        info!("block ingestion loop started");

        // Spawn blob-sidecar ingestion loop.
        {
            let blob_store = Arc::clone(&store_arc);
            let blob_awaiting_blob = Arc::clone(&blob_awaiting);
            tokio::spawn(async move {
                run_blob_ingestion_loop::<MainnetBeaconSpec>(
                    blob_event_rx,
                    blob_store,
                    blob_awaiting_blob,
                )
                .await;
            });
        }
        info!("blob ingestion loop started");

        // Spawn data-column-sidecar ingestion loop (EIP-7594 PeerDAS).
        {
            let column_store = Arc::clone(&store_arc);
            let column_awaiting_col = Arc::clone(&column_awaiting);
            let column_custody = Arc::clone(&custody_state);
            tokio::spawn(async move {
                run_column_ingestion_loop::<MainnetBeaconSpec>(
                    column_event_rx,
                    column_store,
                    column_awaiting_col,
                    column_custody,
                )
                .await;
            });
        }
        info!("data-column ingestion loop started");

        // Phase 2 (Task 2.1): forward-backfill progress signal. The forward loop
        // publishes the lowest imported block slot here; the backward state-backfill
        // loop subscribes and gates restore-point regeneration on it. Seed with the
        // lowest block slot the fork-choice store currently holds (the anchor) so the
        // backward loop has a sane initial bound; the forward loop republishes it on
        // start and after every chunk.
        let lowest_block_seed = {
            use pharos_types::views::BeaconBlockView as _;
            let fc = fork_choice.read();
            fc.blocks
                .values()
                .map(|b| b.slot())
                .min()
                .unwrap_or(anchored_slot)
        };
        let (lowest_block_tx, lowest_block_rx) =
            watch::channel::<pharos_types::phase0::primitives::Slot>(lowest_block_seed);

        // Spawn forward backfill loop.
        {
            use pharos_node::backfill::run_backfill_loop;
            use pharos_node::network_backfill_provider::NetworkBackfillProvider;

            let peer_picker = Arc::new(NetworkHandlePeerPicker::new(handle.command_sender()));
            let provider = NetworkBackfillProvider::new(handle.command_sender(), peer_picker);
            let shutdown_rx = pharos_node_shutdown_rx.clone();
            let fc = Arc::clone(&fork_choice);
            let h = Arc::clone(&host);
            let exec_engine_bf = Arc::clone(&exec_engine);
            let pow_provider_bf = Arc::clone(&pow_provider);
            let head_tx_bf = head_tx.clone();
            let payload_tx_bf = payload_tx.clone();
            let notify_backfill_bf = notify_backfill.clone();
            let lookup_tx_bf = lookup_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = run_backfill_loop::<
                    MainnetBeaconSpec,
                    _,
                    ExecutionEngineHandle,
                    EnginePowBlockProvider,
                >(
                    provider,
                    h,
                    fc,
                    exec_engine_bf,
                    pow_provider_bf,
                    head_tx_bf,
                    payload_tx_bf,
                    genesis_time_secs,
                    shutdown_rx,
                    notify_backfill_bf,
                    Some(lookup_tx_bf),
                    lowest_block_tx,
                )
                .await
                {
                    tracing::error!(error = %e, "backfill loop exited with error");
                }
            });
        }
        info!("backfill loop started");

        // Spawn Fulu data-column backfill loop (default-on, Fulu-gated).
        //
        // After checkpoint sync a freshly-synced Fulu node holds no historical
        // custody columns, so it cannot serve `DataColumnSidecarsByRange`. This
        // one-shot catch-up walks the `data_column_serve_range` window once,
        // KZG-verifies each custody column, and persists it. Gated on Fulu being
        // scheduled (`fulu_fork_epoch != u64::MAX`); mirrors how the prune loop
        // detects an active fork (W4 — no `FAR_FUTURE_EPOCH` import in the binary).
        if runtime_cfg.fulu_fork_epoch != u64::MAX {
            use pharos_node::column_backfill::run_column_backfill_loop;
            use pharos_node::network_column_backfill_provider::NetworkColumnBackfillProvider;

            let column_peer_picker =
                Arc::new(NetworkHandlePeerPicker::new(handle.command_sender()));
            let column_provider =
                NetworkColumnBackfillProvider::new(handle.command_sender(), column_peer_picker);
            let store_clone = Arc::clone(&store_arc);
            let fork_choice_clone = Arc::clone(&fork_choice);
            let custody_state_clone = Arc::clone(&custody_state);
            let runtime_cfg_clone = runtime_cfg.clone();
            let node_id_raw = node_id.raw();
            let shutdown_rx_clone = pharos_node_shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(e) = run_column_backfill_loop::<MainnetBeaconSpec, _>(
                    column_provider,
                    store_clone,
                    fork_choice_clone,
                    node_id_raw,
                    custody_state_clone,
                    runtime_cfg_clone,
                    shutdown_rx_clone,
                )
                .await
                {
                    tracing::error!(error = %e, "data-column backfill loop exited with error");
                }
            });
            info!("data-column backfill loop started");
        }

        // Spawn backward state-backfill loop (Phase 2) — opt-in via --backward-backfill.
        // Long-running BACKGROUND process; never blocks startup. Reconstructs
        // genesis-ward restore-point states by replaying stored blocks backward,
        // gated on the forward-backfill progress signal above.
        if args.backward_backfill {
            use pharos_node::backward_backfill::run_backward_backfill_loop;
            use pharos_node::state_regen::StateRegenService;

            let regen = Arc::new(StateRegenService::<MainnetBeaconSpec>::new(
                Arc::clone(&store_arc),
                Arc::clone(&fork_choice),
                Arc::new(runtime_cfg.clone()),
            ));
            let store_bbf = Arc::clone(&store_arc);
            let fc_bbf = Arc::clone(&fork_choice);
            let shutdown_rx = pharos_node_shutdown_rx.clone();
            tokio::spawn(async move {
                if let Err(e) = run_backward_backfill_loop::<MainnetBeaconSpec>(
                    regen,
                    store_bbf,
                    fc_bbf,
                    lowest_block_rx,
                    shutdown_rx,
                )
                .await
                {
                    tracing::error!(error = %e, "backward backfill loop exited with error");
                }
            });
            info!("backward state-backfill loop started (background)");
        }

        // Spawn lookup-sync loop.
        {
            let lookup_picker = Arc::new(NetworkHandlePeerPicker::new(handle.command_sender()));
            let lookup_provider =
                NetworkLookupProvider::new(handle.command_sender(), lookup_picker);
            let fc = Arc::clone(&fork_choice);
            let h = Arc::clone(&host);
            let shutdown_rx = pharos_node_shutdown_rx.clone();
            let reinject_tx = reinject_tx.clone();
            let lookup_node_id = node_id.raw();
            tokio::spawn(async move {
                if let Err(e) = run_lookup_loop::<
                    MainnetBeaconSpec,
                    _,
                    ExecutionEngineHandle,
                    EnginePowBlockProvider,
                >(
                    lookup_rx,
                    lookup_provider,
                    h,
                    fc,
                    exec_engine,
                    pow_provider,
                    head_tx,
                    payload_tx,
                    pending,
                    notify_backfill,
                    reinject_tx,
                    shutdown_rx,
                    lookup_node_id,
                    MainnetBeaconSpec::CUSTODY_REQUIREMENT,
                )
                .await
                {
                    tracing::error!(error = %e, "lookup loop exited with error");
                }
            });
        }
        info!("lookup loop started");
    }

    // ── Signal handler: SIGTERM or SIGINT triggers ordered shutdown ──────────────
    //
    // Wait for SIGTERM (systemd stop) or SIGINT (Ctrl-C) — whichever arrives
    // first — then drive the `D-graceful-shutdown-order` sequence (M11 Phase 17).
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = signal(SignalKind::terminate()).context("installing SIGTERM handler")?;

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("received SIGINT (Ctrl-C)");
            }
            _ = sigterm.recv() => {
                info!("received SIGTERM");
            }
        }
    }

    info!("received shutdown signal; starting ordered shutdown sequence");
    // Signal long-lived tasks (keepalive, backfill, freezer, etc.) to exit.
    let _ = pharos_node_shutdown_tx.send(true);

    // Run the ordered shutdown sequence per `D-graceful-shutdown-order`.
    //
    // Steps (a)+(b): `handle.shutdown()` sends `NetworkCommand::Shutdown` to
    // the network task, which internally: drains in-flight gossip_tasks (step b),
    // saves peer scores (step c — already in shutdown_goodbye), runs Goodbye(1)
    // to connected peers, then exits. `drain_gossip` is a no-op future because
    // the drain happens inside the network task.
    //
    // Steps (c)+(d): peer-score and ENR-seq saves happen inside the network task
    // during `shutdown_goodbye` (Phase 14 / Phase 13 hooks). The closures here
    // are no-ops kept for test instrumentation (the real saves run inside the
    // network task before `handle.shutdown()` resolves).
    let store_for_fsync = Arc::clone(&store_arc);
    run_shutdown_sequence(
        // (a) goodbye + (b) gossip drain — both driven inside the network task.
        async move { handle.shutdown().await },
        // (b) drain_gossip no-op: drained inside the network task.
        async {},
        // (c) save_scores no-op: done inside shutdown_goodbye (Phase 14).
        || {},
        // (d) save_enr no-op: ENR seq written on every mutation (Phase 13).
        || {},
        // (e) fsync chain DB.
        move || store_for_fsync.fsync(),
    )
    .await;

    info!("shutdown sequence complete");
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

/// Parse a weak-subjectivity checkpoint `<block_root>:<epoch>` string into
/// `(Root, epoch)`, per `specs/phase0/weak-subjectivity.md` § Weak Subjectivity
/// Sync Procedure (the `block_root:epoch_number` CLI format).
fn parse_weak_subjectivity_checkpoint(
    s: &str,
) -> anyhow::Result<(pharos_types::phase0::primitives::Root, u64)> {
    let (root_str, epoch_str) = s.split_once(':').with_context(|| {
        format!("--weak-subjectivity-checkpoint must be <block_root>:<epoch>, got {s:?}")
    })?;
    let stripped = root_str.strip_prefix("0x").unwrap_or(root_str);
    let bytes = hex::decode(stripped).with_context(|| {
        format!("--weak-subjectivity-checkpoint block_root is not valid hex: {root_str:?}")
    })?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
        anyhow::anyhow!("--weak-subjectivity-checkpoint block_root must be 32 bytes (got != 32)")
    })?;
    let epoch: u64 = epoch_str.parse().with_context(|| {
        format!("--weak-subjectivity-checkpoint epoch is not a valid integer: {epoch_str:?}")
    })?;
    Ok((pharos_types::phase0::primitives::Root::from(arr), epoch))
}
