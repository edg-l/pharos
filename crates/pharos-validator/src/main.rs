//! `pharos-vc` — Pharos validator client.
//!
//! Drives BLS key management, slashing protection, and duty scheduling for
//! validators operating against a Pharos (or compatible) beacon node.
//!
//! # Optimistic-sync contract
//!
//! Per `consensus-specs/sync/optimistic.md` "Validator assignments":
//! "An optimistic node MUST NOT: propose blocks, attest, or participate in sync
//!  committees until the node is no longer optimistic."
//!
//! This VC treats any HTTP 503 from production endpoints as "do not sign / skip
//! this slot". The BN returns 503 whenever `is_optimistic_node()` is true.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, bail};
use clap::Parser;
use tokio::sync::watch;
use tracing::{error, info, warn};

use pharos_validator::bn_client::BnClient;
use pharos_validator::doppelganger::run_doppelganger_loop;
use pharos_validator::duties::DutyScheduler;
use pharos_validator::interchange::{export_slashing_protection, import_slashing_protection};
use pharos_validator::keystore::load_all_keystores;
use pharos_validator::run::{ValidatorEntry, VcConfig, run_vc_loop};
use pharos_validator::slashing::SqliteSlashingProtection;

// ── CLI args ──────────────────────────────────────────────────────────────────

/// Pharos validator client.
#[derive(Parser, Debug)]
#[command(name = "pharos-vc", version = env!("CARGO_PKG_VERSION"), about)]
struct Args {
    /// Beacon node URLs (repeatable; failover in order).
    ///
    /// Example: `--beacon-node http://127.0.0.1:5052`
    #[arg(long, value_name = "URL", required = true, num_args = 1..)]
    beacon_node: Vec<reqwest::Url>,

    /// Directory containing EIP-2335 keystore JSON files.
    #[arg(long, value_name = "DIR")]
    keystore_dir: PathBuf,

    /// Directory containing password files (one per keystore, named by UUID or pubkey).
    #[arg(long, value_name = "DIR")]
    secrets_dir: PathBuf,

    /// VC data directory (slashing protection DB, interchange exports).
    #[arg(long, value_name = "DIR", default_value = ".pharos-vc")]
    vc_data_dir: PathBuf,

    /// Suggested fee recipient (0x-prefixed Ethereum address).
    ///
    /// Used in `prepare_beacon_proposer` and `register_validator` calls.
    #[arg(
        long,
        value_name = "ADDR",
        default_value = "0x0000000000000000000000000000000000000000"
    )]
    suggested_fee_recipient: String,

    /// Optional graffiti string (max 32 bytes, truncated if longer).
    #[arg(long, value_name = "STR")]
    graffiti: Option<String>,

    /// Enable doppelganger protection (default: on).
    ///
    /// When enabled, the VC holds off signing for the first 2 complete epochs
    /// and aborts FATALLY if any local validator appears live elsewhere.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    doppelganger_protection: bool,

    /// Import a slashing protection interchange file (EIP-3076 JSON) at startup.
    ///
    /// The genesis_validators_root in the file must match the BN's genesis.
    #[arg(long, value_name = "FILE")]
    import_slashing_protection: Option<PathBuf>,

    /// Export slashing protection interchange file on clean shutdown.
    ///
    /// Defaults to `<vc-data-dir>/slashing_protection_export.json`.
    #[arg(long, value_name = "FILE")]
    export_slashing_protection: Option<PathBuf>,
}

// ── entry point ───────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialise tracing.
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    info!("pharos-vc {} starting", env!("CARGO_PKG_VERSION"));

    // Ensure vc_data_dir exists.
    std::fs::create_dir_all(&args.vc_data_dir)
        .with_context(|| format!("creating vc-data-dir {:?}", args.vc_data_dir))?;

    // ── Beacon-node client ────────────────────────────────────────────────────

    if args.beacon_node.is_empty() {
        bail!("at least one --beacon-node URL is required");
    }
    let bn = BnClient::new(args.beacon_node.clone());

    // ── Slashing protection DB ────────────────────────────────────────────────

    let slashing_db_path = args.vc_data_dir.join("slashing_protection.sqlite");
    let slashing_db = Arc::new(
        SqliteSlashingProtection::open(&slashing_db_path)
            .context("opening slashing protection DB")?,
    );
    info!(path = %slashing_db_path.display(), "slashing protection DB opened");

    // ── Load keystores ────────────────────────────────────────────────────────

    let loaded_keys = load_all_keystores(&args.keystore_dir, &args.secrets_dir);
    if loaded_keys.is_empty() {
        bail!(
            "no keystores loaded from {:?} with secrets from {:?}",
            args.keystore_dir,
            args.secrets_dir
        );
    }
    info!(count = loaded_keys.len(), "keystores loaded");

    // ── Beacon genesis ────────────────────────────────────────────────────────

    // Fetch genesis_validators_root: needed for signing-domain computation AND to
    // verify the interchange file's genesis root (EIP-3076 precondition).
    let genesis_validators_root = fetch_genesis_validators_root(&bn).await;

    // ── Import slashing protection (if requested) ─────────────────────────────

    if let Some(ref import_path) = args.import_slashing_protection {
        let gvr_hex = format!("0x{}", hex::encode(genesis_validators_root));
        let json = std::fs::read_to_string(import_path)
            .with_context(|| format!("reading import file {:?}", import_path))?;
        let file: pharos_validator::interchange::InterchangeFile =
            serde_json::from_str(&json).context("parsing interchange file")?;
        import_slashing_protection(&slashing_db, &file, &gvr_hex)
            .context("importing slashing protection data")?;
        info!(path = %import_path.display(), "slashing protection imported");
    }

    // ── Resolve on-chain validator indices ────────────────────────────────────

    // GET /eth/v1/beacon/states/head/validators?id=<pubkey0>,<pubkey1>,...
    let pubkeys: Vec<String> = loaded_keys.iter().map(|(pk, _)| pk.clone()).collect();
    let state_validators = bn
        .get_state_validators(&pubkeys)
        .await
        .context("resolving validator indices (GET /eth/v1/beacon/states/head/validators)")?;
    let index_by_pubkey: std::collections::HashMap<String, u64> = state_validators
        .iter()
        .filter_map(|v| {
            v.index
                .parse::<u64>()
                .ok()
                .map(|idx| (v.validator.pubkey.to_lowercase(), idx))
        })
        .collect();

    let mut validator_entries: Vec<ValidatorEntry> = Vec::new();
    for (pubkey_hex, secret_key) in loaded_keys {
        match index_by_pubkey.get(&pubkey_hex.to_lowercase()) {
            Some(&index) => validator_entries.push(ValidatorEntry {
                index,
                pubkey_hex,
                secret_key,
            }),
            None => warn!(
                pubkey = %pubkey_hex,
                "validator has no on-chain index (not yet deposited/activated?); excluding from duties"
            ),
        }
    }
    if validator_entries.is_empty() {
        bail!("none of the loaded validators have an on-chain index on the beacon node");
    }
    let validators = Arc::new(validator_entries);

    // ── Prepare beacon proposer / register validators ────────────────────────

    let proposer_items: Vec<pharos_validator::bn_client::PrepareBeaconProposerItem> = validators
        .iter()
        .map(|e| pharos_validator::bn_client::PrepareBeaconProposerItem {
            validator_index: e.index.to_string(),
            fee_recipient: args.suggested_fee_recipient.clone(),
        })
        .collect();
    if let Err(e) = bn.prepare_beacon_proposer(&proposer_items).await {
        warn!(%e, "prepare_beacon_proposer failed (BN may not be ready yet)");
    }

    // ── Duty scheduler ────────────────────────────────────────────────────────

    let val_indices: Vec<u64> = validators.iter().map(|e| e.index).collect();
    let pubkeys_hex: Vec<String> = validators.iter().map(|e| e.pubkey_hex.clone()).collect();

    let scheduler = Arc::new(DutyScheduler::new(
        bn.clone(),
        val_indices.clone(),
        pubkeys_hex.clone(),
    ));
    let duties = scheduler.duties_ref();

    // Epoch watch channel: duty refresh loop sends current epoch; run loop receives.
    let startup_epoch = pharos_validator::duties::current_epoch_from_wall_clock(12_000, 32);
    let (epoch_tx, epoch_rx) = watch::channel(startup_epoch);

    // ── Doppelganger protection ───────────────────────────────────────────────

    if args.doppelganger_protection {
        info!(
            startup_epoch,
            "doppelganger protection enabled; no signing for first {} epochs",
            pharos_validator::doppelganger::HOLDOFF_EPOCHS,
        );
        let bn_ddg = bn.clone();
        let idx_ddg = val_indices.clone();
        let ddg_epoch = startup_epoch;
        tokio::spawn(async move {
            run_doppelganger_loop(true, bn_ddg, idx_ddg, ddg_epoch, 32, 12_000).await;
        });
    }

    // ── Duty refresh loop ─────────────────────────────────────────────────────

    {
        let sched = Arc::clone(&scheduler);
        tokio::spawn(async move {
            pharos_validator::duties::run_duty_refresh_loop(sched, epoch_tx, 32, 12_000).await;
        });
    }

    // ── SIGTERM handler ───────────────────────────────────────────────────────

    let export_path = args
        .export_slashing_protection
        .clone()
        .unwrap_or_else(|| args.vc_data_dir.join("slashing_protection_export.json"));
    let slashing_db_export = Arc::clone(&slashing_db);
    let pubkeys_export = pubkeys_hex.clone();

    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler registration failed");
        sigterm.recv().await;
        info!("SIGTERM received; exporting slashing protection and exiting");
        // Export slashing protection interchange.
        let gvr_hex = format!("0x{}", hex::encode(genesis_validators_root));
        match export_slashing_protection(&slashing_db_export, &pubkeys_export, &gvr_hex) {
            Ok(file) => {
                let json = serde_json::to_string_pretty(&file).unwrap_or_else(|_| "{}".to_string());
                if let Err(e) = std::fs::write(&export_path, json) {
                    error!(%e, path = %export_path.display(), "slashing export write failed");
                } else {
                    info!(path = %export_path.display(), "slashing protection exported");
                }
            }
            Err(e) => error!(%e, "slashing export failed"),
        }
        std::process::exit(0);
    });

    // ── Main run loop ─────────────────────────────────────────────────────────

    let vc_config = Arc::new(VcConfig {
        suggested_fee_recipient: args.suggested_fee_recipient.clone(),
        graffiti: args.graffiti.clone(),
        slots_per_epoch: 32,
        slot_duration_ms: 12_000,
        doppelganger_protection: args.doppelganger_protection,
    });

    info!("validator client run loop starting");
    run_vc_loop(
        bn,
        Arc::clone(&validators),
        Arc::clone(&slashing_db) as Arc<dyn pharos_validator::slashing::SlashingProtection>,
        duties,
        epoch_rx,
        vc_config,
        genesis_validators_root,
    )
    .await;

    Ok(())
}

// ── Genesis helpers ───────────────────────────────────────────────────────────

/// Fetch `genesis_validators_root` from `GET /eth/v1/beacon/genesis`.
///
/// Returns the zero root on failure (non-fatal; signing domains will be zero).
async fn fetch_genesis_validators_root(bn: &BnClient) -> [u8; 32] {
    match bn.get_genesis().await {
        Ok(val) => {
            let root_hex = val["data"]["genesis_validators_root"]
                .as_str()
                .unwrap_or("")
                .to_string();
            let hex_str = root_hex.strip_prefix("0x").unwrap_or(&root_hex);
            if let Ok(b) = hex::decode(hex_str) {
                if b.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    return arr;
                }
            }
            warn!("genesis_validators_root has unexpected format; using zero root");
            [0u8; 32]
        }
        Err(e) => {
            warn!(%e, "could not fetch genesis_validators_root; using zero root (signing domains may be wrong)");
            [0u8; 32]
        }
    }
}
