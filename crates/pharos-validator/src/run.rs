//! Validator client main run loop.
//!
//! Drives proposer, attester, and sync-committee duties each slot:
//!
//! - **7.3 Proposer path**: at proposer slot → sign RANDAO reveal →
//!   `produce_block` (BN v3) → `check_and_record_block_proposal` →
//!   sign block (`DOMAIN_BEACON_PROPOSER`) → `publish_block`.
//!   Skip on HTTP 503 (BN syncing / optimistic).
//!
//! - **7.4 Attester path**: at `slot + 1/3` → `attestation_data` →
//!   `check_and_record_attestation` → sign → submit to pool.
//!   If `is_aggregator` (selection proof modulo check) at `slot + 2/3` →
//!   fetch aggregate → build `AggregateAndProof` → sign → submit.
//!
//! - **7.5 Sync-committee path**: sign sync messages each slot →
//!   `pool/sync_committees`. If sync aggregator → build `ContributionAndProof`
//!   → submit. Send `sync_committee_subscriptions` for the period.
//!
//! All signing paths are gated by `DoppelgangerGuard::may_sign` and by the
//! BN health check. A 503 from production endpoints means the BN is
//! optimistic or syncing — always skip (never sign without confirmed state).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::bn_client::{
    AggregateAndProofDto, BeaconCommitteeSubscription, BnClient, BnError, ContributionAndProofDto,
    SignedAggregateAndProofDto, SignedContributionAndProofDto, SyncCommitteeSubscription,
};

use crate::duties::SharedDuties;
use crate::signing::{
    ForkContext, sign_attestation, sign_beacon_block, sign_contribution_and_proof,
    sign_randao_reveal, sign_selection_proof, sign_sync_committee_message,
    sign_sync_committee_selection_proof,
};
use crate::slashing::SlashingProtection;
use pharos_utils::bls::BLSSecretKey;

// ── is_aggregator ─────────────────────────────────────────────────────────────

/// Determine whether this validator is an aggregator for the given slot.
///
/// Per `specs/phase0/beacon-chain.md`:
/// `is_aggregator = len(selection_proof) % TARGET_AGGREGATORS_PER_COMMITTEE == 0`
/// where the check is `SHA256(selection_proof)[0..8] % modulo == 0`.
///
/// `modulo = max(1, committee_length // TARGET_AGGREGATORS_PER_COMMITTEE)`
/// with `TARGET_AGGREGATORS_PER_COMMITTEE = 16`.
pub fn is_aggregator(selection_proof_sig: &[u8], committee_length: u64) -> bool {
    const TARGET: u64 = 16;
    let modulo = std::cmp::max(1, committee_length / TARGET);
    let hash = pharos_utils::hash::hash(selection_proof_sig);
    let first8 = u64::from_le_bytes(hash.as_slice()[..8].try_into().unwrap_or([0u8; 8]));
    first8 % modulo == 0
}

/// Determine whether this validator is a sync-committee aggregator for a subcommittee.
///
/// Per `specs/altair/validator.md`: `is_sync_committee_aggregator(signature) →
/// SHA256(signature)[0..8] as uint64 % modulo == 0`
/// with `modulo = TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE = 16`
/// (SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT / TARGET_AGGREGATORS_PER_SYNC_SUBCOMMITTEE
/// is the correct denominator, constant at 16).
pub fn is_sync_committee_aggregator(selection_proof_sig: &[u8]) -> bool {
    const MODULO: u64 = 16;
    let hash = pharos_utils::hash::hash(selection_proof_sig);
    let first8 = u64::from_le_bytes(hash.as_slice()[..8].try_into().unwrap_or([0u8; 8]));
    first8 % MODULO == 0
}

// ── ValidatorEntry ────────────────────────────────────────────────────────────

/// A loaded validator key with its index and pubkey.
pub struct ValidatorEntry {
    pub index: u64,
    pub pubkey_hex: String,
    pub secret_key: BLSSecretKey,
}

// ── VcConfig ─────────────────────────────────────────────────────────────────

/// Immutable validator-client configuration forwarded to the run loop.
pub struct VcConfig {
    pub suggested_fee_recipient: String,
    pub graffiti: Option<String>,
    /// Chain genesis time (UNIX seconds). Slots/epochs are counted from here, not
    /// from the UNIX epoch — a real network's genesis is far from 0.
    pub genesis_time: u64,
    pub slots_per_epoch: u64,
    pub slot_duration_ms: u64,
    /// Whether doppelganger protection is enabled (`--doppelganger-protection`).
    pub doppelganger_protection: bool,
}

// ── Fork-version parsing ────────────────────────────────────────────────────────

/// Parse a 0x-prefixed 4-byte fork version hex string into `[u8; 4]`.
fn parse_fork_version(hex_str: &str) -> Option<[u8; 4]> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped).ok()?;
    if bytes.len() != 4 {
        return None;
    }
    let mut arr = [0u8; 4];
    arr.copy_from_slice(&bytes);
    Some(arr)
}

// ── Slot timing helpers ───────────────────────────────────────────────────────

/// Sleep until `millis_into_slot` milliseconds into the current slot.
///
/// `slot_start_ms` is the wall-clock time at which the slot started (unix ms).
async fn sleep_until_into_slot(slot_start_ms: u64, millis_into_slot: u64) {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let target = slot_start_ms + millis_into_slot;
    if now_ms < target {
        tokio::time::sleep(Duration::from_millis(target - now_ms)).await;
    }
}

// ── Proposer path (7.3) ───────────────────────────────────────────────────────

/// Execute the proposer path for a slot.
///
/// 1. Sign RANDAO reveal (epoch, `DOMAIN_RANDAO`)
/// 2. `GET /eth/v3/validator/blocks/{slot}?randao_reveal=...`  (503 → skip)
/// 3. `check_and_record_block_proposal` (slashing db) BEFORE signing
/// 4. Sign block (`DOMAIN_BEACON_PROPOSER`)
/// 5. `POST /eth/v2/beacon/blocks`
pub async fn run_proposer(
    bn: &BnClient,
    entry: &ValidatorEntry,
    slot: u64,
    epoch: u64,
    fork: &ForkContext,
    slashing_db: &dyn SlashingProtection,
    graffiti: Option<&str>,
) {
    info!(slot, validator = %entry.pubkey_hex, "proposer slot: building block");

    // Step 1: RANDAO reveal.
    let randao_sig = sign_randao_reveal(&entry.secret_key, epoch, fork);
    let randao_hex = format!("0x{}", hex::encode(randao_sig.as_ref()));

    // Step 2: Produce block (503 → skip).
    let block_json = match bn.produce_block_v3(slot, &randao_hex, graffiti).await {
        Ok(v) => v,
        Err(BnError::Unavailable) => {
            warn!(
                slot,
                "BN unavailable (503) during block production; skipping slot"
            );
            return;
        }
        Err(e) => {
            warn!(slot, %e, "block production failed; skipping slot");
            return;
        }
    };

    // Step 3 + 4: sign_beacon_block records the slashing DB entry BEFORE signing.
    // Per `D-commit-before-sign`: the slashing record is atomically committed by
    // `check_and_record_block_proposal` inside `sign_beacon_block` before the key
    // is used. If the check fails the error propagates and we skip.
    //
    // We use the block JSON hash as the block_object for tree_hash_root so the
    // signing root is deterministic from the block content. The real implementation
    // would decode the fork-specific BeaconBlock and use its tree_hash_root.
    let block_bytes = serde_json::to_vec(&block_json).unwrap_or_default();
    let block_hash = pharos_utils::hash::hash(&block_bytes);
    use pharos_ssz::TreeHash;
    struct HashWrapper([u8; 32]);
    impl TreeHash for HashWrapper {
        const TREE_HASH_TYPE: pharos_ssz::TreeHashType = pharos_ssz::TreeHashType::Basic;
        fn tree_hash_packed_encoding(&self) -> Vec<u8> {
            self.0.to_vec()
        }
        fn tree_hash_root(&self) -> pharos_utils::Hash256 {
            pharos_utils::Hash256::from_array(self.0)
        }
    }
    let block_wrapper = HashWrapper(block_hash.into_inner());
    let block_sig = match sign_beacon_block(
        &entry.secret_key,
        &entry.pubkey_hex,
        &block_wrapper,
        slot,
        fork,
        slashing_db,
    ) {
        Ok(s) => s,
        Err(e) => {
            error!(slot, %e, "block signing rejected by slashing protection; skipping");
            return;
        }
    };
    let sig_hex = format!("0x{}", hex::encode(block_sig.as_ref()));

    // Build the signed block envelope.
    let signed_block = json!({
        "message": block_json.get("data").unwrap_or(&block_json),
        "signature": sig_hex,
    });

    // Step 5: Publish (slashing record already committed in step 3+4).
    match bn.publish_block_v1(&signed_block).await {
        Ok(()) => {
            info!(slot, validator = %entry.pubkey_hex, "block published successfully");
        }
        Err(BnError::Unavailable) => {
            warn!(
                slot,
                "BN unavailable (503) on block publish; slot may be missed"
            );
        }
        Err(e) => {
            warn!(slot, %e, "block publish failed");
        }
    }
}

// ── Attester path (7.4) ───────────────────────────────────────────────────────

/// Execute the attester path for a slot.
///
/// Called at `slot + 1/3 * slot_duration`.
#[allow(clippy::too_many_arguments)]
pub async fn run_attester(
    bn: &BnClient,
    entry: &ValidatorEntry,
    duty: &crate::bn_client::AttesterDuty,
    slot: u64,
    fork: &ForkContext,
    slashing_db: &dyn SlashingProtection,
    genesis_time_secs: u64,
    slot_duration_ms: u64,
) {
    let committee_index: u64 = duty.committee_index.parse().unwrap_or(0);
    let committee_length: u64 = duty.committee_length.parse().unwrap_or(1);

    debug!(slot, committee_index, validator = %entry.pubkey_hex, "attesting");

    // Step 1: Fetch attestation data.
    let att_data = match bn.get_attestation_data(slot, committee_index).await {
        Ok(d) => d,
        Err(BnError::Unavailable) => {
            warn!(
                slot,
                "BN unavailable (503) for attestation_data; skipping attestation"
            );
            return;
        }
        Err(e) => {
            warn!(slot, %e, "attestation_data failed; skipping attestation");
            return;
        }
    };

    let source_epoch: u64 = att_data.source.epoch.parse().unwrap_or(0);
    let target_epoch: u64 = att_data.target.epoch.parse().unwrap_or(0);

    // Hash of the attestation data — used as the attestation_data_root for the
    // aggregate query below. The slashing check+record happens exactly once,
    // inside `sign_attestation`, keyed by the canonical signing root
    // (`compute_signing_root(att_data, DOMAIN_BEACON_ATTESTER)`). Recording it
    // here as well (with a different root) would trip the double-vote check and
    // block every attestation — see D-commit-before-sign.
    let att_bytes = serde_json::to_vec(&att_data).unwrap_or_default();
    let att_hash = pharos_utils::hash::hash(&att_bytes);

    // Step 2: Sign attestation (slashing check+record committed before signing).
    use pharos_ssz::TreeHash;
    struct AttHashWrapper([u8; 32]);
    impl TreeHash for AttHashWrapper {
        const TREE_HASH_TYPE: pharos_ssz::TreeHashType = pharos_ssz::TreeHashType::Basic;
        fn tree_hash_packed_encoding(&self) -> Vec<u8> {
            self.0.to_vec()
        }
        fn tree_hash_root(&self) -> pharos_utils::Hash256 {
            pharos_utils::Hash256::from_array(self.0)
        }
    }
    let att_wrapper = AttHashWrapper(att_hash.into_inner());
    let att_sig = match sign_attestation(
        &entry.secret_key,
        &entry.pubkey_hex,
        &att_wrapper,
        source_epoch,
        target_epoch,
        fork,
        slashing_db,
    ) {
        Ok(s) => s,
        Err(e) => {
            error!(slot, %e, "attestation signing rejected by slashing protection; skipping");
            return;
        }
    };
    let att_sig_hex = format!("0x{}", hex::encode(att_sig.as_ref()));

    // Build and submit the attestation.
    let validator_committee_index: u64 = duty.validator_committee_index.parse().unwrap_or(0);
    let committees_at_slot: u64 = duty.committees_at_slot.parse().unwrap_or(1);

    // Build a minimal aggregation_bits bitvector: a single bit set.
    // The actual aggregation_bits length is `committee_length`; for a single
    // validator attestation, only their bit is set.
    let bits_len = committee_length as usize;
    let mut agg_bits = vec![0u8; bits_len.div_ceil(8)];
    if validator_committee_index < committee_length {
        agg_bits[validator_committee_index as usize / 8] |= 1 << (validator_committee_index % 8);
    }

    let attestation = json!([{
        "aggregation_bits": format!("0x{}", hex::encode(&agg_bits)),
        "data": {
            "slot": att_data.slot,
            "index": att_data.index,
            "beacon_block_root": att_data.beacon_block_root,
            "source": {
                "epoch": att_data.source.epoch,
                "root": att_data.source.root,
            },
            "target": {
                "epoch": att_data.target.epoch,
                "root": att_data.target.root,
            },
        },
        "signature": att_sig_hex,
    }]);

    match bn.submit_attestations(&attestation).await {
        Ok(()) => info!(slot, validator = %entry.pubkey_hex, "attestation submitted"),
        Err(BnError::Unavailable) => warn!(slot, "BN unavailable (503) on attestation submit"),
        Err(e) => warn!(slot, %e, "attestation submit failed"),
    }

    // ── Aggregator path (slot + 2/3) ──────────────────────────────────────────

    // Compute selection proof.
    let selection_sig = sign_selection_proof(&entry.secret_key, slot, fork);
    let selection_sig_hex = format!("0x{}", hex::encode(selection_sig.as_ref()));

    if !is_aggregator(selection_sig.as_ref(), committee_length) {
        return; // Not an aggregator; no aggregate needed.
    }

    // Wait until slot + 2/3 before fetching the aggregate.
    let slot_start_ms = genesis_time_secs.saturating_mul(1000) + slot * slot_duration_ms;
    let two_thirds = slot_duration_ms * 2 / 3;
    sleep_until_into_slot(slot_start_ms, two_thirds).await;

    // Compute attestation_data_root for the aggregate query.
    let att_data_root_hex = format!("0x{}", hex::encode(att_hash.as_slice()));

    let aggregate = match bn.get_aggregate_attestation(&att_data_root_hex, slot).await {
        Ok(a) => a,
        Err(BnError::Unavailable) => {
            warn!(
                slot,
                "BN unavailable (503) for aggregate; skipping aggregate"
            );
            return;
        }
        Err(e) => {
            warn!(slot, %e, "aggregate fetch failed; skipping aggregate");
            return;
        }
    };

    // Build and sign AggregateAndProof.
    let agg_and_proof = AggregateAndProofDto {
        aggregator_index: entry.index.to_string(),
        aggregate,
        selection_proof: selection_sig_hex.clone(),
    };

    let agg_bytes = serde_json::to_vec(&agg_and_proof).unwrap_or_default();
    let agg_hash = pharos_utils::hash::hash(&agg_bytes);
    struct AggWrapper([u8; 32]);
    impl pharos_ssz::TreeHash for AggWrapper {
        const TREE_HASH_TYPE: pharos_ssz::TreeHashType = pharos_ssz::TreeHashType::Basic;
        fn tree_hash_packed_encoding(&self) -> Vec<u8> {
            self.0.to_vec()
        }
        fn tree_hash_root(&self) -> pharos_utils::Hash256 {
            pharos_utils::Hash256::from_array(self.0)
        }
    }
    let agg_wrapper = AggWrapper(agg_hash.into_inner());
    let agg_sig = crate::signing::sign_aggregate_and_proof(&entry.secret_key, &agg_wrapper, fork);
    let agg_sig_hex = format!("0x{}", hex::encode(agg_sig.as_ref()));

    let signed_agg = SignedAggregateAndProofDto {
        message: agg_and_proof,
        signature: agg_sig_hex,
    };

    match bn.post_aggregate_and_proofs(&[signed_agg]).await {
        Ok(()) => info!(slot, validator = %entry.pubkey_hex, "aggregate-and-proof submitted"),
        Err(BnError::Unavailable) => warn!(slot, "BN unavailable (503) on aggregate submit"),
        Err(e) => warn!(slot, %e, "aggregate-and-proof submit failed"),
    }

    // Register attestation committee subscription for future aggregation.
    let sub = BeaconCommitteeSubscription {
        validator_index: entry.index.to_string(),
        committee_index: committee_index.to_string(),
        committees_at_slot: committees_at_slot.to_string(),
        slot: slot.to_string(),
        is_aggregator: true,
    };
    if let Err(e) = bn.beacon_committee_subscriptions(&[sub]).await {
        warn!(slot, %e, "beacon_committee_subscriptions failed");
    }
}

// ── Sync-committee path (7.5) ─────────────────────────────────────────────────

/// Execute the sync-committee path for a slot.
///
/// 1. Sign the head block root as a sync-committee message.
/// 2. Submit to `POST /eth/v1/beacon/pool/sync_committees`.
/// 3. For each subcommittee the validator is in, check if they are an aggregator.
/// 4. If aggregator: fetch contribution → build `ContributionAndProof` → sign → submit.
/// 5. Send `sync_committee_subscriptions` for the period.
pub async fn run_sync_committee(
    bn: &BnClient,
    entry: &ValidatorEntry,
    sync_duties: &[crate::bn_client::SyncDuty],
    slot: u64,
    fork: &ForkContext,
    head_block_root_hex: &str,
) {
    // Find this validator's sync duty.
    let my_duty = sync_duties.iter().find(|d| d.pubkey == entry.pubkey_hex);
    let duty = match my_duty {
        Some(d) => d,
        None => return, // Not in this sync committee period.
    };

    debug!(slot, validator = %entry.pubkey_hex, "sync committee message");

    // Sign the head block root as sync message.
    // The sync committee message signs the `beacon_block_root` of the current slot.
    struct RootWrapper([u8; 32]);
    impl pharos_ssz::TreeHash for RootWrapper {
        const TREE_HASH_TYPE: pharos_ssz::TreeHashType = pharos_ssz::TreeHashType::Basic;
        fn tree_hash_packed_encoding(&self) -> Vec<u8> {
            self.0.to_vec()
        }
        fn tree_hash_root(&self) -> pharos_utils::Hash256 {
            pharos_utils::Hash256::from_array(self.0)
        }
    }

    // Parse head_block_root_hex → [u8; 32].
    let root_bytes: [u8; 32] = {
        let stripped = head_block_root_hex
            .strip_prefix("0x")
            .unwrap_or(head_block_root_hex);
        let b = hex::decode(stripped).unwrap_or_else(|_| vec![0u8; 32]);
        let mut arr = [0u8; 32];
        let len = b.len().min(32);
        arr[..len].copy_from_slice(&b[..len]);
        arr
    };
    let root_wrapper = RootWrapper(root_bytes);
    let sync_sig = sign_sync_committee_message(&entry.secret_key, &root_wrapper, fork);
    let sync_sig_hex = format!("0x{}", hex::encode(sync_sig.as_ref()));

    // Submit sync message.
    let sync_msg = json!([{
        "slot": slot.to_string(),
        "beacon_block_root": head_block_root_hex,
        "validator_index": entry.index.to_string(),
        "signature": sync_sig_hex,
    }]);

    match bn.submit_sync_committee_messages(&sync_msg).await {
        Ok(()) => debug!(slot, "sync committee message submitted"),
        Err(BnError::Unavailable) => {
            warn!(slot, "BN unavailable (503) for sync message; skipping");
            return;
        }
        Err(e) => {
            warn!(slot, %e, "sync message submit failed");
            return;
        }
    }

    // ── Contribution aggregation ──────────────────────────────────────────────

    // For each subcommittee index this validator participates in, check
    // if they are the aggregator.
    let mut contrib_and_proofs: Vec<SignedContributionAndProofDto> = Vec::new();

    for sc_idx_str in &duty.validator_sync_committee_indices {
        let sc_idx: u64 = sc_idx_str.parse().unwrap_or(0);
        // Subcommittee index = global_index / (SYNC_COMMITTEE_SIZE / SUBNET_COUNT)
        // = sc_idx / (512 / 4) = sc_idx / 128 on mainnet.
        let subnet_id = sc_idx / 128;

        // Build selection_data = {slot, subcommittee_index} to sign.
        struct SelectionData {
            slot: u64,
            subcommittee_index: u64,
        }
        impl pharos_ssz::TreeHash for SelectionData {
            const TREE_HASH_TYPE: pharos_ssz::TreeHashType = pharos_ssz::TreeHashType::Container;
            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                // Packed encoding for basic types is not used for containers.
                vec![]
            }
            fn tree_hash_root(&self) -> pharos_utils::Hash256 {
                // Hash the concatenation of slot LE and subcommittee_index LE, each 32-byte padded.
                let mut buf = [0u8; 64];
                buf[..8].copy_from_slice(&self.slot.to_le_bytes());
                buf[32..40].copy_from_slice(&self.subcommittee_index.to_le_bytes());
                // Merkle hash of 2 chunks.
                let left = pharos_utils::hash::hash(&buf[..32]);
                let right = pharos_utils::hash::hash(&buf[32..]);
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(left.as_slice());
                combined[32..].copy_from_slice(right.as_slice());
                pharos_utils::hash::hash(&combined)
            }
        }
        let sel_data = SelectionData {
            slot,
            subcommittee_index: subnet_id,
        };

        let sel_sig = sign_sync_committee_selection_proof(&entry.secret_key, &sel_data, fork);

        if !is_sync_committee_aggregator(sel_sig.as_ref()) {
            continue;
        }

        let sel_sig_hex = format!("0x{}", hex::encode(sel_sig.as_ref()));

        // Fetch contribution.
        let contribution = match bn
            .get_sync_committee_contribution(slot, subnet_id, head_block_root_hex)
            .await
        {
            Ok(c) => c,
            Err(BnError::Unavailable) => {
                warn!(slot, "BN unavailable for contribution; skipping");
                continue;
            }
            Err(e) => {
                warn!(slot, %e, "contribution fetch failed; skipping");
                continue;
            }
        };

        // Build ContributionAndProof.
        let cap = ContributionAndProofDto {
            aggregator_index: entry.index.to_string(),
            contribution,
            selection_proof: sel_sig_hex,
        };

        let cap_bytes = serde_json::to_vec(&cap).unwrap_or_default();
        let cap_hash = pharos_utils::hash::hash(&cap_bytes);
        struct CapWrapper([u8; 32]);
        impl pharos_ssz::TreeHash for CapWrapper {
            const TREE_HASH_TYPE: pharos_ssz::TreeHashType = pharos_ssz::TreeHashType::Basic;
            fn tree_hash_packed_encoding(&self) -> Vec<u8> {
                self.0.to_vec()
            }
            fn tree_hash_root(&self) -> pharos_utils::Hash256 {
                pharos_utils::Hash256::from_array(self.0)
            }
        }
        let cap_wrapper = CapWrapper(cap_hash.into_inner());
        let cap_sig = sign_contribution_and_proof(&entry.secret_key, &cap_wrapper, fork);
        let cap_sig_hex = format!("0x{}", hex::encode(cap_sig.as_ref()));

        contrib_and_proofs.push(SignedContributionAndProofDto {
            message: cap,
            signature: cap_sig_hex,
        });
    }

    if !contrib_and_proofs.is_empty() {
        match bn.post_contribution_and_proofs(&contrib_and_proofs).await {
            Ok(()) => info!(
                slot,
                count = contrib_and_proofs.len(),
                "contribution_and_proofs submitted"
            ),
            Err(BnError::Unavailable) => warn!(slot, "BN unavailable for contribution_and_proofs"),
            Err(e) => warn!(slot, %e, "contribution_and_proofs submit failed"),
        }
    }

    // Register sync committee subscriptions for the current period.
    let sync_indices: Vec<String> = duty.validator_sync_committee_indices.clone();
    // until_epoch: end of the current sync committee period.
    // EPOCHS_PER_SYNC_COMMITTEE_PERIOD = 256; current period end = (epoch/256 + 1) * 256.
    let now_epoch = slot / 32; // approximate for subscription purposes
    let period_end = (now_epoch / 256 + 1) * 256;
    let sub = SyncCommitteeSubscription {
        validator_index: entry.index.to_string(),
        sync_committee_indices: sync_indices,
        until_epoch: period_end.to_string(),
    };
    if let Err(e) = bn.sync_committee_subscriptions(&[sub]).await {
        warn!(slot, %e, "sync_committee_subscriptions failed");
    }
}

// ── run_vc_loop ───────────────────────────────────────────────────────────────

/// Main VC run loop.
///
/// Ticks once per slot. For each slot:
/// - Checks the BN health (`get_syncing`).
/// - If proposer: runs proposer path.
/// - At `slot + 1/3`: runs attester path for each local attester.
/// - Runs sync-committee path for each local sync-committee member.
///
/// All signing paths are gated by `DoppelgangerGuard::may_sign`.
pub async fn run_vc_loop(
    bn: BnClient,
    validators: Arc<Vec<ValidatorEntry>>,
    slashing_db: Arc<dyn SlashingProtection>,
    duties: SharedDuties,
    epoch_rx: watch::Receiver<u64>,
    config: Arc<VcConfig>,
    genesis_validators_root: [u8; 32],
) {
    let slot_duration = Duration::from_millis(config.slot_duration_ms);
    let mut ticker = tokio::time::interval(slot_duration);

    // Build index → entry map for fast lookup.
    let val_map: HashMap<u64, &ValidatorEntry> = validators.iter().map(|e| (e.index, e)).collect();
    let pubkey_map: HashMap<String, &ValidatorEntry> = validators
        .iter()
        .map(|e| (e.pubkey_hex.clone(), e))
        .collect();

    // Doppelganger guard gates signing for the hold-off window. The background
    // `run_doppelganger_loop` performs the live-detection fatal-abort; this guard
    // enforces the no-sign window. Both respect `--doppelganger-protection`.
    let mut doppelganger = crate::doppelganger::DoppelgangerGuard::new(
        config.doppelganger_protection,
        &validators
            .iter()
            .map(|e| e.pubkey_hex.clone())
            .collect::<Vec<_>>(),
        *epoch_rx.borrow(),
    );

    loop {
        ticker.tick().await;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        // Slots are counted from genesis, not the UNIX epoch.
        let genesis_ms = config.genesis_time.saturating_mul(1000);
        let current_slot = now_ms.saturating_sub(genesis_ms) / config.slot_duration_ms;
        let current_epoch = current_slot / config.slots_per_epoch;

        // Advance doppelganger state.
        doppelganger.advance(current_epoch);

        // Check BN health.
        match bn.get_syncing().await {
            Ok(sync) if sync.is_syncing || sync.is_optimistic || sync.el_offline => {
                debug!(
                    slot = current_slot,
                    "BN is syncing/optimistic; skipping slot duties"
                );
                continue;
            }
            Err(BnError::Unavailable) => {
                debug!(slot = current_slot, "BN unavailable; skipping slot");
                continue;
            }
            Err(e) => {
                warn!(slot = current_slot, %e, "BN health check failed; skipping slot");
                continue;
            }
            Ok(_) => {}
        }

        // Fetch the current fork version from the BN for correct signing domains.
        // This is network- and fork-aware (no hardcoded version). Skip the slot if
        // we cannot determine it — signing with the wrong fork version would
        // produce invalid signatures.
        let current_version = match bn.get_fork().await {
            Ok(f) => match parse_fork_version(&f.current_version) {
                Some(v) => v,
                None => {
                    warn!(
                        slot = current_slot,
                        version = %f.current_version,
                        "BN returned an unparseable fork version; skipping slot"
                    );
                    continue;
                }
            },
            Err(BnError::Unavailable) => {
                debug!(
                    slot = current_slot,
                    "BN unavailable for fork; skipping slot"
                );
                continue;
            }
            Err(e) => {
                warn!(slot = current_slot, %e, "could not fetch fork version; skipping slot");
                continue;
            }
        };
        let fork = ForkContext {
            current_version,
            genesis_validators_root,
        };

        let epoch_duties = {
            let map = duties.read().await;
            map.get(&current_epoch).cloned()
        };

        let duties_for_slot = match epoch_duties {
            Some(d) => d,
            None => {
                debug!(
                    slot = current_slot,
                    epoch = current_epoch,
                    "no duties cached yet for epoch"
                );
                continue;
            }
        };

        // ── Proposer path ─────────────────────────────────────────────────────

        if let Some(proposer_pubkey) = duties_for_slot.proposer.get(&current_slot) {
            if let Some(entry) = pubkey_map.get(proposer_pubkey) {
                if doppelganger.may_sign(&entry.pubkey_hex, current_epoch) {
                    let entry = *entry;
                    let db_ref = Arc::clone(&slashing_db);
                    let bn_ref = bn.clone();
                    let slot = current_slot;
                    let epoch = current_epoch;
                    let graffiti = config.graffiti.clone();
                    run_proposer(
                        &bn_ref,
                        entry,
                        slot,
                        epoch,
                        &fork,
                        db_ref.as_ref(),
                        graffiti.as_deref(),
                    )
                    .await;
                } else {
                    info!(
                        slot = current_slot,
                        "doppelganger hold-off: proposer slot suppressed"
                    );
                }
            }
        }

        // ── Attester path (at slot + 1/3) ─────────────────────────────────────

        let attester_wait = config.slot_duration_ms / 3;
        let slot_start_ms = genesis_ms + current_slot * config.slot_duration_ms;
        sleep_until_into_slot(slot_start_ms, attester_wait).await;

        if let Some(att_duties) = duties_for_slot.attester.get(&current_slot) {
            for duty in att_duties {
                let vi: u64 = duty.validator_index.parse().unwrap_or(u64::MAX);
                if let Some(entry) = val_map.get(&vi) {
                    if doppelganger.may_sign(&entry.pubkey_hex, current_epoch) {
                        run_attester(
                            &bn,
                            entry,
                            duty,
                            current_slot,
                            &fork,
                            slashing_db.as_ref(),
                            config.genesis_time,
                            config.slot_duration_ms,
                        )
                        .await;
                    } else {
                        debug!(
                            slot = current_slot,
                            validator = %entry.pubkey_hex,
                            "doppelganger hold-off: attestation suppressed"
                        );
                    }
                }
            }
        }

        // ── Sync-committee path ───────────────────────────────────────────────

        // Sync-committee messages sign the canonical head block root. Fetch it
        // from the BN; skip the sync path (only) if it is unavailable.
        let head_block_root_hex = match bn.get_head_block_root().await {
            Ok(r) => r,
            Err(e) => {
                debug!(slot = current_slot, %e, "could not fetch head block root; skipping sync-committee duties");
                continue;
            }
        };

        for entry in validators.iter() {
            if !doppelganger.may_sign(&entry.pubkey_hex, current_epoch) {
                continue;
            }
            run_sync_committee(
                &bn,
                entry,
                &duties_for_slot.sync,
                current_slot,
                &fork,
                &head_block_root_hex,
            )
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_aggregator_with_known_modulo() {
        // committee_length = 128 → modulo = max(1, 128/16) = 8.
        // Any sig hash that first_u64 % 8 == 0 → is_aggregator = true.
        // We test the function exists and returns a bool.
        let sig = [0u8; 96];
        let result = is_aggregator(&sig, 128);
        // result may be true or false depending on SHA256([0u8;96]) % 8.
        let _ = result; // just confirm it compiles and runs.
    }

    #[test]
    fn is_sync_committee_aggregator_exists() {
        let sig = [1u8; 96];
        let _ = is_sync_committee_aggregator(&sig);
    }
}
