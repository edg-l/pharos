//! Fulu data-column backfill driver (requester side).
//!
//! After checkpoint sync, a Fulu node fetches its custody data-column sidecars
//! over the spec `data_column_serve_range` via `DataColumnSidecarsByRange`.
//! This module defines the provider trait that the backfill loop drives.
//!
//! Design note: `BackfillColumnProvider` uses native `async fn` in trait (Rust
//! 1.85 stable, no `async-trait` needed) because it is always used as a
//! monomorphised generic `P: BackfillColumnProvider<E>`, never as `dyn` —
//! mirroring `BackfillBlockProvider` in `backfill.rs`.

use std::collections::BTreeSet;
use std::sync::Arc;

use parking_lot::RwLock;
use pharos_ssz::TreeHash as _;
use tokio::sync::watch;
use tracing::{info, warn};

use pharos_fork_choice::{Store as FcStore, get_current_slot};
use pharos_kzg::KzgVerifier;
use pharos_stf::fulu::data_columns::{
    verify_data_column_sidecar, verify_data_column_sidecar_inclusion_proof,
    verify_data_column_sidecar_kzg_proofs,
};
use pharos_stf::phase0::accessors::compute_epoch_at_slot;
use pharos_storage::{RocksStore, Store as DbStore};
use pharos_types::RuntimeConfig;
use pharos_types::fulu::{DataColumnSidecar, get_blob_parameters};
use pharos_types::phase0::primitives::Root;
use pharos_types::{BeaconSpec, phase0::primitives::Slot};
use pharos_utils::Epoch;

// ── Constants ─────────────────────────────────────────────────────────────────

/// Number of slots to request in a single `DataColumnSidecarsByRange` call.
pub const COLUMN_BACKFILL_CHUNK_SLOTS: u64 = 32;

/// Per-request timeout for `DataColumnSidecarsByRange`.
pub const COLUMN_BACKFILL_REQ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Wait between retries when a peer served an empty chunk or the provider failed.
pub const COLUMN_BACKFILL_RETRY_DELAY: std::time::Duration = std::time::Duration::from_secs(5);

/// Wait between retries while no peers are connected yet (e.g. at startup,
/// before discovery yields peers). Longer than [`COLUMN_BACKFILL_RETRY_DELAY`]
/// because there is nothing to poll — we are simply parked waiting for peers —
/// so a short delay would only spam the log. This path does NOT count toward
/// the per-chunk retry budget (see `run_column_backfill_loop`).
pub const COLUMN_BACKFILL_NO_PEERS_PARK_DELAY: std::time::Duration =
    std::time::Duration::from_secs(12);

// ── ColumnBackfillError ─────────────────────────────────────────────────────────

/// Errors returned by the data-column backfill driver.
#[derive(thiserror::Error, Debug)]
pub enum ColumnBackfillError {
    #[error("no usable peers")]
    NoUsablePeers,
    #[error("provider: {0}")]
    Provider(String),
    #[error("storage: {0}")]
    Storage(#[from] pharos_storage::StorageError),
}

// ── BackfillColumnProvider ──────────────────────────────────────────────────────

/// Provides data-column sidecars for the backfill loop via a range request.
///
/// Native `async fn` in trait (Rust 1.85 stable). This trait is only used as a
/// monomorphised generic `P: BackfillColumnProvider<E>`; it is never invoked
/// through `dyn`. No `async-trait` dependency is needed.
///
/// The `columns` argument is a plain `Vec<u64>` (SSZ-free) so callers need not
/// depend on the SSZ wire types; the network impl converts it to the wire
/// `SszList` internally.
pub trait BackfillColumnProvider<E: BeaconSpec>: Send + Sync + 'static {
    fn data_columns_by_range(
        &self,
        start_slot: Slot,
        count: u64,
        columns: Vec<u64>,
    ) -> impl std::future::Future<
        Output = Result<Vec<DataColumnSidecar<4096, 4>>, ColumnBackfillError>,
    > + Send;
}

// ── Helpers ─────────────────────────────────────────────────────────────────────

/// Maximum number of consecutive retries for a single chunk before parking the
/// loop. A one-shot catch-up must not spin forever when peers cannot serve the
/// window; after this many failed attempts the chunk is abandoned and the loop
/// advances (the next process start, or live gossip/lookup, will cover it).
const COLUMN_BACKFILL_MAX_CHUNK_RETRIES: u32 = 5;

/// Compute the `data_column_serve_range` floor slot.
///
/// Mirrors the serving-side floor in `host_impl.rs`: the window starts
/// `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS` epochs behind `current_slot`,
/// clamped at the Fulu fork-epoch slot (never request pre-Fulu slots).
pub(crate) fn column_serve_floor_slot<E: BeaconSpec>(
    current_slot: u64,
    fulu_fork_epoch: u64,
) -> u64 {
    current_slot
        .saturating_sub(
            E::MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS.saturating_mul(E::SLOTS_PER_EPOCH),
        )
        .max(fulu_fork_epoch.saturating_mul(E::SLOTS_PER_EPOCH))
}

/// Returns `true` iff every column index in `want` is already persisted for
/// `block_root`. Returns `false` on a storage error so the slot is re-fetched.
fn slot_columns_present<E: BeaconSpec>(
    store: &RocksStore,
    block_root: &Root,
    want: &[u64],
) -> bool {
    match <RocksStore as DbStore<E>>::get_all_data_column_sidecars_by_root(store, block_root) {
        Ok(sidecars) => {
            let present: BTreeSet<u64> = sidecars.iter().map(|s| s.index).collect();
            want.iter().all(|c| present.contains(c))
        }
        Err(_) => false,
    }
}

/// Keep only sidecars whose index is in `want` AND that pass all three
/// verification steps (structural, inclusion proof, KZG proofs). Anything else
/// is dropped silently (req-resp has no gossip pre-validation, so a malicious or
/// faulty peer can return garbage; we never error, we just discard).
fn verify_and_filter<E: BeaconSpec>(
    sidecars: Vec<DataColumnSidecar<4096, 4>>,
    want: &BTreeSet<u64>,
    kzg: &KzgVerifier,
    runtime_cfg: &RuntimeConfig,
) -> Vec<DataColumnSidecar<4096, 4>> {
    sidecars
        .into_iter()
        .filter(|s| {
            if !want.contains(&s.index) {
                return false;
            }
            // Resolve the EIP-7892 epoch-driven blob-param limit from the
            // sidecar's own slot (mirrors `host_impl.rs`).
            let epoch =
                compute_epoch_at_slot(s.signed_block_header.message.slot, E::SLOTS_PER_EPOCH);
            let max_blobs = get_blob_parameters(
                epoch,
                &runtime_cfg.blob_schedule,
                Epoch(runtime_cfg.electra_fork_epoch),
                runtime_cfg.max_blobs_per_block_electra,
            )
            .max_blobs_per_block;
            verify_data_column_sidecar::<E, 4096, 4>(s, max_blobs).is_ok()
                && verify_data_column_sidecar_inclusion_proof::<4096, 4>(s).is_ok()
                && verify_data_column_sidecar_kzg_proofs::<4096, 4>(s, kzg).is_ok()
        })
        .collect()
}

// ── Backfill loop ─────────────────────────────────────────────────────────────

/// One-shot catch-up: fetch this node's custody data-column sidecars over the
/// `data_column_serve_range` window, KZG-verify each, and persist them.
///
/// Walks the window `[floor, current_slot]` (wall-clock current slot, per the
/// serving-side range) in `COLUMN_BACKFILL_CHUNK_SLOTS` chunks. Slots whose
/// custody columns are already complete are skipped (idempotent re-run). On
/// completion the loop returns `Ok(())`; live gossip + lookup cover ongoing
/// columns.
#[allow(clippy::too_many_arguments)]
pub async fn run_column_backfill_loop<E, P>(
    provider: P,
    store: Arc<RocksStore>,
    fc_store: Arc<RwLock<FcStore<E>>>,
    node_id: [u8; 32],
    custody_state: Arc<crate::custody::CustodyState>,
    runtime_cfg: RuntimeConfig,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), ColumnBackfillError>
where
    E: BeaconSpec,
    P: BackfillColumnProvider<E>,
{
    let fulu_fork_epoch = runtime_cfg.fulu_fork_epoch;

    // Wall-clock current slot (W5): walk floor→current, not head→current, so we
    // never request slots peers consider out of the serve range.
    let current_slot = get_current_slot::<E>(&fc_store.read()).0;

    // Before the Fulu fork there is no data-column serve range — nothing to do.
    if current_slot < fulu_fork_epoch.saturating_mul(E::SLOTS_PER_EPOCH) {
        return Ok(());
    }

    let floor = column_serve_floor_slot::<E>(current_slot, fulu_fork_epoch);

    let columns: Vec<u64> =
        crate::custody::custody_columns_for_cgc::<E>(node_id, custody_state.custody_group_count());
    let want: BTreeSet<u64> = columns.iter().copied().collect();

    let kzg = KzgVerifier::mainnet();

    let mut start = floor;
    while start <= current_slot {
        if *shutdown_rx.borrow() {
            info!("data-column backfill: shutdown; exiting");
            return Ok(());
        }

        let chunk_count = COLUMN_BACKFILL_CHUNK_SLOTS.min(current_slot - start + 1);
        let chunk_end = start + chunk_count; // exclusive

        // Idempotency: if every slot in the chunk is already complete (or has no
        // canonical block root), skip the network request entirely.
        let mut needs_fetch = false;
        for s in start..chunk_end {
            match store.block_root_at_slot(Slot(s)) {
                Ok(Some(root)) => {
                    if !slot_columns_present::<E>(&store, &root, &columns) {
                        needs_fetch = true;
                        break;
                    }
                }
                Ok(None) => {} // missed slot or before anchor; nothing to fetch
                Err(_) => {
                    // Storage error reading the mapping — re-fetch to be safe.
                    needs_fetch = true;
                    break;
                }
            }
        }
        if !needs_fetch {
            start = chunk_end;
            continue;
        }

        // Fetch the chunk with bounded retry (do NOT infinite-loop).
        let mut attempt = 0u32;
        let sidecars = loop {
            if *shutdown_rx.borrow() {
                info!("data-column backfill: shutdown; exiting");
                return Ok(());
            }
            // Delay before the next iteration. The no-peers path parks longer
            // and does NOT consume the retry budget (see below).
            let delay = match provider
                .data_columns_by_range(Slot(start), chunk_count, columns.clone())
                .await
            {
                Ok(v) if !v.is_empty() => break v,
                Ok(_) => {
                    // A peer answered but served no columns for this chunk;
                    // count it as a real attempt and back off briefly.
                    warn!(
                        start,
                        chunk_count, "data-column backfill: empty response; retrying after delay"
                    );
                    attempt += 1;
                    COLUMN_BACKFILL_RETRY_DELAY
                }
                Err(ColumnBackfillError::NoUsablePeers) => {
                    // No peers connected yet (common at startup, before discovery
                    // yields peers). Park and wait — do NOT count this toward the
                    // per-chunk retry budget, or we would abandon the entire serve
                    // window in ~25s before any peer connects. Mirrors the block
                    // backfill loop, which retries NoUsablePeers unbounded.
                    warn!("data-column backfill: no usable peers; parking until peers connect");
                    COLUMN_BACKFILL_NO_PEERS_PARK_DELAY
                }
                Err(e) => {
                    warn!(error = %e, "data-column backfill: provider failed; retrying after delay");
                    attempt += 1;
                    COLUMN_BACKFILL_RETRY_DELAY
                }
            };
            if attempt >= COLUMN_BACKFILL_MAX_CHUNK_RETRIES {
                warn!(
                    start,
                    chunk_count,
                    attempts = attempt,
                    "data-column backfill: chunk exhausted retries; advancing"
                );
                break Vec::new();
            }
            tokio::select! {
                _ = tokio::time::sleep(delay) => {}
                _ = shutdown_rx.changed() => {}
            }
        };

        let kept = verify_and_filter::<E>(sidecars, &want, &kzg, &runtime_cfg);

        for sidecar in kept {
            let block_root = sidecar.signed_block_header.message.tree_hash_root();
            let slot = sidecar.signed_block_header.message.slot.0;
            let store_clone = Arc::clone(&store);
            let sidecar_clone = sidecar.clone();
            let persist = tokio::task::spawn_blocking(move || {
                <RocksStore as DbStore<E>>::put_data_column_sidecar(
                    &store_clone,
                    block_root,
                    &sidecar_clone,
                )
            })
            .await;
            match persist {
                Ok(Ok(())) => {
                    // I8: the earliest_available_slot watermark hook lives here,
                    // NOT inside put_data_column_sidecar. Lower it so backfilled
                    // columns extend StatusV2.earliest_available_slot.
                    custody_state.observe_column_slot(slot);
                }
                Ok(Err(e)) => return Err(ColumnBackfillError::from(e)),
                Err(e) => {
                    return Err(ColumnBackfillError::Provider(format!(
                        "persist task panicked: {e}"
                    )));
                }
            }
        }

        start = chunk_end;
    }

    info!(floor, current_slot, "data-column backfill complete");
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_storage::db::RocksStoreConfig;
    use pharos_types::MainnetBeaconSpec as E;

    #[test]
    fn column_serve_floor_clamps_to_fulu() {
        let spe = <E as BeaconSpec>::SLOTS_PER_EPOCH;
        let min_epochs = <E as BeaconSpec>::MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS;
        let fulu_fork_epoch = 100u64;
        let fulu_slot = fulu_fork_epoch * spe;

        // Head-window underflows below the Fulu floor → clamps to fulu*SPE.
        // current just past the fork: current - min_epochs*SPE < fulu_slot.
        let current_low = fulu_slot + spe; // one epoch into Fulu
        assert_eq!(
            column_serve_floor_slot::<E>(current_low, fulu_fork_epoch),
            fulu_slot,
            "should clamp to fulu*SPE when the head window underflows"
        );

        // current well above the window → floor is the head-relative window.
        let current_high = (fulu_fork_epoch + min_epochs + 50) * spe;
        let expected_window = current_high - min_epochs * spe;
        assert!(expected_window > fulu_slot);
        assert_eq!(
            column_serve_floor_slot::<E>(current_high, fulu_fork_epoch),
            expected_window,
            "should use the head-relative window when above the Fulu floor"
        );
    }

    #[test]
    fn slot_columns_present_detects_partial() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = RocksStore::open::<E>(RocksStoreConfig {
            path: dir.path().to_path_buf(),
            create_if_missing: true,
        })
        .expect("open store");

        let block_root = Root::from([7u8; 32]);
        let want = [0u64, 1, 2];

        let put = |index: u64| {
            let sidecar = DataColumnSidecar::<4096, 4> {
                index,
                ..Default::default()
            };
            <RocksStore as DbStore<E>>::put_data_column_sidecar(&store, block_root, &sidecar)
                .expect("put sidecar");
        };

        // Put 2 of 3 → not present.
        put(0);
        put(1);
        assert!(
            !slot_columns_present::<E>(&store, &block_root, &want),
            "partial custody set must report not-present"
        );

        // Put the 3rd → present.
        put(2);
        assert!(
            slot_columns_present::<E>(&store, &block_root, &want),
            "complete custody set must report present"
        );
    }

    #[test]
    fn verify_and_filter_drops_non_custody() {
        let kzg = KzgVerifier::mainnet();
        let runtime_cfg = RuntimeConfig::default();

        // A sidecar whose index is NOT in `want` must be dropped before any KZG
        // work — this exercises the want-filter branch.
        // index 42 ∉ want: dropped by the want-filter before any KZG work.
        let non_custody = DataColumnSidecar::<4096, 4> {
            index: 42,
            ..Default::default()
        };
        // index 0 ∈ want but empty kzg_commitments: passes the want-filter, then
        // dropped by `verify_data_column_sidecar` (NoCommitments). Proves an
        // in-custody but unverifiable column is never kept.
        let in_want_invalid = DataColumnSidecar::<4096, 4> {
            index: 0,
            ..Default::default()
        };
        let want: BTreeSet<u64> = [0u64, 1, 2].into_iter().collect();

        let kept = verify_and_filter::<E>(
            vec![non_custody, in_want_invalid],
            &want,
            &kzg,
            &runtime_cfg,
        );
        assert!(
            kept.is_empty(),
            "non-custody and in-custody-but-unverifiable sidecars must both be dropped"
        );
    }
}
