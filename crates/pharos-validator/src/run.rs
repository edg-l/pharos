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

use crate::bn_client::AttestationDataDto;
use crate::duties::SharedDuties;
use crate::signing::{
    ForkContext, bls_signature_from_hex, root_from_hex, sign_aggregate_and_proof, sign_attestation,
    sign_beacon_block, sign_contribution_and_proof, sign_randao_reveal, sign_selection_proof,
    sign_sync_committee_message, sign_sync_committee_selection_proof,
};
use crate::slashing::SlashingProtection;
use crate::web3signer::Signer;
use pharos_ssz::Decode as _;
use pharos_ssz::{Bitlist, Bitvector};
use pharos_types::altair::{
    MainnetContributionAndProof, MainnetSyncCommitteeContribution, SyncAggregatorSelectionData,
};
use pharos_types::electra::{
    MainnetAggregateAndProof as ElectraAggregateAndProof, MainnetAttestation as ElectraAttestation,
};
use pharos_types::phase0::misc::{AttestationData, Checkpoint};
use pharos_types::phase0::primitives::{CommitteeIndex, Epoch, Root, Slot, ValidatorIndex};
use pharos_types::phase0::{MainnetAggregateAndProof, MainnetAttestation};

/// Convert a wire `AttestationDataDto` (hex/decimal strings) into the typed
/// `AttestationData` SSZ container, so callers can sign over its real
/// `tree_hash_root`. Unparseable fields default to zero (the BN supplies
/// well-formed data; a zero here fails verification rather than panicking).
fn att_data_from_dto(dto: &AttestationDataDto) -> AttestationData {
    AttestationData {
        slot: Slot(dto.slot.parse().unwrap_or(0)),
        index: CommitteeIndex(dto.index.parse().unwrap_or(0)),
        beacon_block_root: Root::from(root_from_hex(&dto.beacon_block_root)),
        source: Checkpoint {
            epoch: Epoch(dto.source.epoch.parse().unwrap_or(0)),
            root: Root::from(root_from_hex(&dto.source.root)),
        },
        target: Checkpoint {
            epoch: Epoch(dto.target.epoch.parse().unwrap_or(0)),
            root: Root::from(root_from_hex(&dto.target.root)),
        },
    }
}

/// Decode a `0x`-prefixed (or bare) hex string into raw bytes; malformed input
/// yields an empty vec (an SSZ decode of which fails cleanly).
fn bytes_from_hex(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).unwrap_or_default()
}

/// Build the Web3Signer `BLOCK_V2` `beacon_block` payload (`{version, block_header}`)
/// from the decoded typed beacon block.
///
/// Used only by the remote-signer path's optional slashing plugin; the
/// `signing_root` Pharos sends alongside is the authoritative BLS message.
fn block_v2_payload(
    block: &pharos_types::state::MainnetBeaconBlock,
    version: Option<&serde_json::Value>,
) -> serde_json::Value {
    use pharos_ssz::TreeHash;
    use pharos_types::BeaconBlockView;
    use pharos_types::state::BeaconBlock;

    // `BeaconBlockView::body()` is unimplemented on the fork-enum; the body root
    // must be taken from the inner concrete variant.
    let body_root = match block {
        BeaconBlock::Phase0(b) => b.body.tree_hash_root(),
        BeaconBlock::Altair(b) => b.body.tree_hash_root(),
        BeaconBlock::Bellatrix(b) => b.body.tree_hash_root(),
        BeaconBlock::Capella(b) => b.body.tree_hash_root(),
        BeaconBlock::Deneb(b) => b.body.tree_hash_root(),
        BeaconBlock::Electra(b) => b.body.tree_hash_root(),
        BeaconBlock::Fulu(b) => b.body.tree_hash_root(),
    };
    let version_str = version
        .and_then(|v| v.as_str())
        .unwrap_or("bellatrix")
        .to_uppercase();
    json!({
        "version": version_str,
        "block_header": {
            "slot": block.slot().0.to_string(),
            "proposer_index": block.proposer_index().0.to_string(),
            "parent_root": format!("0x{}", hex::encode(block.parent_root().as_slice())),
            "state_root": format!("0x{}", hex::encode(block.state_root().as_slice())),
            "body_root": format!("0x{}", hex::encode(body_root.as_slice())),
        }
    })
}

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
/// Delegates to `pharos_stf::is_sync_committee_aggregator::<MainnetBeaconSpec>` —
/// the authoritative definition lives there so both the VC and the node's gossip
/// validator share one implementation. The VC operates exclusively on mainnet.
pub fn is_sync_committee_aggregator(selection_proof_sig: &[u8]) -> bool {
    pharos_stf::is_sync_committee_aggregator::<pharos_types::MainnetBeaconSpec>(selection_proof_sig)
}

// ── ValidatorEntry ────────────────────────────────────────────────────────────

/// A loaded validator with its index, pubkey, and signer.
///
/// The `signer` is either a [`crate::web3signer::LocalSigner`] (decrypted
/// EIP-2335 keystore) or a [`crate::web3signer::Web3RemoteSigner`] (remote
/// Web3Signer), selected per pubkey by the presence of `--signer-url`.
pub struct ValidatorEntry {
    pub index: u64,
    pub pubkey_hex: String,
    pub signer: Arc<dyn Signer>,
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
    /// The network's `ELECTRA_FORK_VERSION`, fetched from the BN spec at startup.
    ///
    /// `None` when the BN does not advertise an electra fork (pre-electra
    /// networks); in that case the VC always uses the phase0 v1 attestation
    /// submission path. When `Some(v)` and the live `current_version` equals `v`
    /// (or any post-electra version once newer forks exist), the VC switches to
    /// the EIP-7549 `SingleAttestation` v2 submission path.
    pub electra_fork_version: Option<[u8; 4]>,
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
    let randao_sig = match sign_randao_reveal(&*entry.signer, epoch, fork).await {
        Ok(s) => s,
        Err(e) => {
            error!(slot, %e, "RANDAO reveal signing failed; skipping slot");
            return;
        }
    };
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

    // Step 3 + 4: decode the BN's `block_ssz` (fork-enum `BeaconBlock`) and sign its
    // real `tree_hash_root` under `DOMAIN_BEACON_PROPOSER`. `sign_beacon_block`
    // commits the slashing record before using the key (`D-commit-before-sign`);
    // the BN and peers re-verify the signature over the same root, so a placeholder
    // would be rejected.
    let block_ssz_hex = block_json
        .get("block_ssz")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let block_ssz = match hex::decode(block_ssz_hex.strip_prefix("0x").unwrap_or(block_ssz_hex)) {
        Ok(b) if !b.is_empty() => b,
        _ => {
            error!(
                slot,
                "produce response missing block_ssz; cannot sign block; skipping"
            );
            return;
        }
    };
    let beacon_block = match pharos_types::state::MainnetBeaconBlock::from_ssz_bytes(&block_ssz) {
        Ok(b) => b,
        Err(e) => {
            error!(slot, ?e, "failed to decode produced block SSZ; skipping");
            return;
        }
    };
    // Web3Signer `BLOCK_V2` payload: `{version, block_header}`. The `signing_root`
    // Pharos computes is authoritative; this payload feeds the signer's optional
    // slashing plugin (the body root is the typed block's body `tree_hash_root`).
    let block_payload = block_v2_payload(&beacon_block, block_json.get("version"));
    let block_sig = match sign_beacon_block(
        &*entry.signer,
        &entry.pubkey_hex,
        &beacon_block,
        slot,
        fork,
        slashing_db,
        block_payload,
    )
    .await
    {
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
    is_electra: bool,
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

    // Build the TYPED AttestationData so we sign over its real `tree_hash_root`.
    // The STF verifies attestation signatures over
    // `compute_signing_root(AttestationData, DOMAIN_BEACON_ATTESTER)` when the
    // attestation is packed into a block, so a placeholder root would be rejected.
    // `att_hash` (= the data root) is reused as the `attestation_data_root` for
    // the aggregate query below.
    //
    // EIP-7549: at Electra the on-wire `AttestationData.index` is always 0 (the
    // committee index moved to `SingleAttestation.committee_index` /
    // `Attestation.committee_bits`). The validator MUST sign over the data with
    // `index = 0`, so we zero it before computing the signing root. The committee
    // index is preserved separately in `committee_index` for the SingleAttestation.
    use pharos_ssz::TreeHash;
    let mut typed_att = att_data_from_dto(&att_data);
    if is_electra {
        typed_att.index = CommitteeIndex(0);
    }
    let att_hash = typed_att.tree_hash_root();

    // Web3Signer `attestation` payload (the `AttestationData`); authoritative
    // BLS message is the `signing_root` Pharos computes from `typed_att`.
    let att_payload = json!({
        "slot": typed_att.slot.0.to_string(),
        "index": typed_att.index.0.to_string(),
        "beacon_block_root": format!("0x{}", hex::encode(typed_att.beacon_block_root.as_slice())),
        "source": {
            "epoch": typed_att.source.epoch.0.to_string(),
            "root": format!("0x{}", hex::encode(typed_att.source.root.as_slice())),
        },
        "target": {
            "epoch": typed_att.target.epoch.0.to_string(),
            "root": format!("0x{}", hex::encode(typed_att.target.root.as_slice())),
        },
    });

    // Step 2: Sign attestation (slashing check+record committed before signing).
    let att_sig = match sign_attestation(
        &*entry.signer,
        &entry.pubkey_hex,
        &typed_att,
        source_epoch,
        target_epoch,
        fork,
        slashing_db,
        att_payload,
    )
    .await
    {
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

    // Build the SSZ `Bitlist[committee_length]` aggregation_bits with only this
    // validator's bit set. An SSZ Bitlist encodes its length via a SENTINEL bit at
    // index `committee_length`; without it the decoder infers the wrong length
    // (the highest data bit), which the STF rejects as "aggregation bits length
    // mismatch". Total bytes = ceil((committee_length + 1) / 8).
    let bits_len = committee_length as usize;
    let mut agg_bits = vec![0u8; (bits_len + 1).div_ceil(8)];
    if validator_committee_index < committee_length {
        agg_bits[validator_committee_index as usize / 8] |= 1 << (validator_committee_index % 8);
    }
    // Length sentinel bit at index `bits_len`.
    agg_bits[bits_len / 8] |= 1 << (bits_len % 8);

    // Submit on the appropriate endpoint for the active fork.
    //
    // PEER-BAN HAZARD (EIP-7549): the `beacon_attestation_{subnet}` gossip topic
    // carries a `SingleAttestation` at/after Electra, NOT the multi-committee
    // `Attestation`. We post the `SingleAttestation` to the v2 pool endpoint and
    // the BN republishes it on the subnet topic. Conflating the two shapes earns
    // an instant ban from peers. Pre-Electra we keep the phase0 v1 `Attestation`
    // path unchanged. Per `specs/electra/validator.md:282-296`.
    if is_electra {
        // EIP-7549 SingleAttestation: committee_index carries the committee, the
        // data.index is 0 (already zeroed in `typed_att` above for signing).
        let single = json!([{
            "committee_index": committee_index.to_string(),
            "attester_index": entry.index.to_string(),
            "data": {
                "slot": att_data.slot,
                "index": "0",
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
        match bn.submit_attestations_v2(&single, "electra").await {
            Ok(()) => {
                info!(slot, validator = %entry.pubkey_hex, "single attestation submitted (electra)")
            }
            Err(BnError::Unavailable) => {
                warn!(slot, "BN unavailable (503) on single-attestation submit")
            }
            Err(e) => warn!(slot, %e, "single-attestation submit failed"),
        }
    } else {
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
    }

    // ── Aggregator path (slot + 2/3) ──────────────────────────────────────────

    // Compute selection proof.
    let selection_sig = match sign_selection_proof(&*entry.signer, slot, fork).await {
        Ok(s) => s,
        Err(e) => {
            warn!(slot, %e, "selection-proof signing failed; skipping aggregate");
            return;
        }
    };
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

    // PEER-BAN HAZARD (EIP-7549): at and after Electra the aggregate is the
    // multi-committee `Attestation` (committee_bits present, data.index == 0), and
    // `AggregateAndProof` wraps that electra `Attestation`. Signing a phase0-shaped
    // aggregate (no committee_bits, non-zero data.index) yields a signature that the
    // BN/peers reject as invalid over the recomputed SSZ root. Mirror the
    // `SingleAttestation` v2 path above: fetch + post on the electra-versioned v2
    // endpoints with `Eth-Consensus-Version: electra`. Per `specs/electra/validator.md`.
    if is_electra {
        let aggregate = match bn
            .get_aggregate_attestation_v2(&att_data_root_hex, slot, "electra")
            .await
        {
            Ok(a) => a,
            Err(BnError::Unavailable) => {
                warn!(
                    slot,
                    "BN unavailable (503) for aggregate (electra); skipping aggregate"
                );
                return;
            }
            Err(e) => {
                warn!(slot, %e, "aggregate fetch failed (electra); skipping aggregate");
                return;
            }
        };

        // Build the TYPED electra `AggregateAndProof` over the electra `Attestation`
        // (committee_bits + data.index == 0) and sign its real `tree_hash_root`. The
        // wire DTO below carries the same fields, so the signature verifies against it.
        let typed_agg = ElectraAttestation {
            aggregation_bits: Bitlist::from_ssz_bytes(&bytes_from_hex(&aggregate.aggregation_bits))
                .unwrap_or_default(),
            data: att_data_from_dto(&aggregate.data),
            signature: bls_signature_from_hex(&aggregate.signature),
            committee_bits: Bitvector::from_ssz_bytes(&bytes_from_hex(&aggregate.committee_bits))
                .unwrap_or_default(),
        };
        let typed_agg_and_proof = ElectraAggregateAndProof {
            aggregator_index: ValidatorIndex(entry.index),
            aggregate: typed_agg,
            selection_proof: selection_sig,
        };
        // Web3Signer `aggregate_and_proof` payload; `signing_root` is authoritative.
        let agg_payload = json!({
            "aggregator_index": entry.index.to_string(),
            "aggregate": {
                "aggregation_bits": aggregate.aggregation_bits,
                "committee_bits": aggregate.committee_bits,
                "data": {
                    "slot": aggregate.data.slot,
                    "index": aggregate.data.index,
                    "beacon_block_root": aggregate.data.beacon_block_root,
                    "source": { "epoch": aggregate.data.source.epoch, "root": aggregate.data.source.root },
                    "target": { "epoch": aggregate.data.target.epoch, "root": aggregate.data.target.root },
                },
                "signature": aggregate.signature,
            },
            "selection_proof": selection_sig_hex,
        });
        let agg_sig =
            match sign_aggregate_and_proof(&*entry.signer, &typed_agg_and_proof, fork, agg_payload)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    warn!(slot, %e, "aggregate-and-proof signing failed (electra); skipping");
                    return;
                }
            };
        let agg_sig_hex = format!("0x{}", hex::encode(agg_sig.as_ref()));

        let signed_agg = json!([{
            "message": {
                "aggregator_index": entry.index.to_string(),
                "aggregate": {
                    "aggregation_bits": aggregate.aggregation_bits,
                    "committee_bits": aggregate.committee_bits,
                    "data": {
                        "slot": aggregate.data.slot,
                        "index": aggregate.data.index,
                        "beacon_block_root": aggregate.data.beacon_block_root,
                        "source": {
                            "epoch": aggregate.data.source.epoch,
                            "root": aggregate.data.source.root,
                        },
                        "target": {
                            "epoch": aggregate.data.target.epoch,
                            "root": aggregate.data.target.root,
                        },
                    },
                    "signature": aggregate.signature,
                },
                "selection_proof": selection_sig_hex,
            },
            "signature": agg_sig_hex,
        }]);

        match bn
            .post_aggregate_and_proofs_v2(&signed_agg, "electra")
            .await
        {
            Ok(()) => {
                info!(slot, validator = %entry.pubkey_hex, "aggregate-and-proof submitted (electra)")
            }
            Err(BnError::Unavailable) => {
                warn!(slot, "BN unavailable (503) on aggregate submit (electra)")
            }
            Err(e) => warn!(slot, %e, "aggregate-and-proof submit failed (electra)"),
        }
    } else {
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

        // Build the TYPED `AggregateAndProof` and sign its real `tree_hash_root`.
        // Peers and the BN recompute the SSZ signing root over the submitted
        // `SignedAggregateAndProof`; the wire DTO carries the same fields, so signing
        // the typed object's root yields a signature that verifies against the DTO.
        let typed_agg = MainnetAttestation {
            aggregation_bits: Bitlist::<2048>::from_ssz_bytes(&bytes_from_hex(
                &aggregate.aggregation_bits,
            ))
            .unwrap_or_default(),
            data: att_data_from_dto(&aggregate.data),
            signature: bls_signature_from_hex(&aggregate.signature),
        };
        let typed_agg_and_proof = MainnetAggregateAndProof {
            aggregator_index: ValidatorIndex(entry.index),
            aggregate: typed_agg,
            selection_proof: selection_sig,
        };
        // Web3Signer `aggregate_and_proof` payload; `signing_root` is authoritative.
        let agg_payload = json!({
            "aggregator_index": entry.index.to_string(),
            "aggregate": {
                "aggregation_bits": aggregate.aggregation_bits,
                "data": {
                    "slot": aggregate.data.slot,
                    "index": aggregate.data.index,
                    "beacon_block_root": aggregate.data.beacon_block_root,
                    "source": { "epoch": aggregate.data.source.epoch, "root": aggregate.data.source.root },
                    "target": { "epoch": aggregate.data.target.epoch, "root": aggregate.data.target.root },
                },
                "signature": aggregate.signature,
            },
            "selection_proof": selection_sig_hex,
        });
        let agg_sig =
            match sign_aggregate_and_proof(&*entry.signer, &typed_agg_and_proof, fork, agg_payload)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    warn!(slot, %e, "aggregate-and-proof signing failed; skipping");
                    return;
                }
            };
        let agg_sig_hex = format!("0x{}", hex::encode(agg_sig.as_ref()));

        let signed_agg = SignedAggregateAndProofDto {
            message: AggregateAndProofDto {
                aggregator_index: entry.index.to_string(),
                aggregate,
                selection_proof: selection_sig_hex,
            },
            signature: agg_sig_hex,
        };

        match bn.post_aggregate_and_proofs(&[signed_agg]).await {
            Ok(()) => info!(slot, validator = %entry.pubkey_hex, "aggregate-and-proof submitted"),
            Err(BnError::Unavailable) => warn!(slot, "BN unavailable (503) on aggregate submit"),
            Err(e) => warn!(slot, %e, "aggregate-and-proof submit failed"),
        }
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
    let Some(duty) = sync_duties.iter().find(|d| d.pubkey == entry.pubkey_hex) else {
        return; // Not in this sync committee period.
    };

    debug!(slot, validator = %entry.pubkey_hex, "sync committee message");

    // Sign the head block root as a sync-committee message. The message signs
    // `compute_signing_root(beacon_block_root, DOMAIN_SYNC_COMMITTEE)`; the block
    // root is a `Root` (a 32-byte basic leaf), so we sign over its `tree_hash_root`.
    let head_root = Root::from(root_from_hex(head_block_root_hex));
    let sync_sig = match sign_sync_committee_message(
        &*entry.signer,
        &head_root,
        fork,
        head_block_root_hex,
        slot,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            warn!(slot, %e, "sync-committee message signing failed; skipping");
            return;
        }
    };
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

        // Sign the typed `SyncAggregatorSelectionData{slot, subcommittee_index}`
        // over its real `tree_hash_root` (the derived container root, NOT a
        // hand-hashed concatenation — basic-type leaves are padded, not hashed).
        let sel_data = SyncAggregatorSelectionData {
            slot: Slot(slot),
            subcommittee_index: subnet_id,
        };
        let sel_sig = match sign_sync_committee_selection_proof(
            &*entry.signer,
            &sel_data,
            fork,
            slot,
            subnet_id,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                warn!(slot, %e, "sync selection-proof signing failed; skipping subcommittee");
                continue;
            }
        };

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

        // Build the TYPED `ContributionAndProof` and sign its real `tree_hash_root`.
        // The wire DTO carries the same fields, so the signature verifies against it.
        let typed_contribution = MainnetSyncCommitteeContribution {
            slot: Slot(contribution.slot.parse().unwrap_or(0)),
            beacon_block_root: Root::from(root_from_hex(&contribution.beacon_block_root)),
            subcommittee_index: contribution.subcommittee_index.parse().unwrap_or(0),
            aggregation_bits: Bitvector::<128>::from_ssz_bytes(&bytes_from_hex(
                &contribution.aggregation_bits,
            ))
            .unwrap_or_default(),
            signature: bls_signature_from_hex(&contribution.signature),
        };
        let typed_cap = MainnetContributionAndProof {
            aggregator_index: ValidatorIndex(entry.index),
            contribution: typed_contribution,
            selection_proof: sel_sig,
        };
        // Web3Signer `contribution_and_proof` payload; `signing_root` is authoritative.
        let cap_payload = json!({
            "aggregator_index": entry.index.to_string(),
            "contribution": {
                "slot": contribution.slot,
                "beacon_block_root": contribution.beacon_block_root,
                "subcommittee_index": contribution.subcommittee_index,
                "aggregation_bits": contribution.aggregation_bits,
                "signature": contribution.signature,
            },
            "selection_proof": sel_sig_hex,
        });
        let cap_sig = match sign_contribution_and_proof(
            &*entry.signer,
            &typed_cap,
            fork,
            cap_payload,
        )
        .await
        {
            Ok(s) => s,
            Err(e) => {
                warn!(slot, %e, "contribution-and-proof signing failed; skipping subcommittee");
                continue;
            }
        };
        let cap_sig_hex = format!("0x{}", hex::encode(cap_sig.as_ref()));

        // Build the wire DTO (moves `contribution`).
        let cap = ContributionAndProofDto {
            aggregator_index: entry.index.to_string(),
            contribution,
            selection_proof: sel_sig_hex,
        };

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

    // Slots are counted from genesis, not the UNIX epoch.
    let genesis_ms = config.genesis_time.saturating_mul(1000);

    loop {
        // Align to the next slot boundary so the proposer path fires at t≈0.
        // A free-running `interval` would carry a fixed phase offset vs slot
        // starts (whatever the VC startup phase happened to be), pushing block
        // proposals past the t=1/3 attestation cutoff — attesters then vote the
        // parent, the block accrues zero weight, and a proposer-boost-aware peer
        // (e.g. a reference CL client) re-orgs it straight back out.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let current_slot = now_ms.saturating_sub(genesis_ms) / config.slot_duration_ms + 1;
        let slot_start_ms = genesis_ms + current_slot * config.slot_duration_ms;
        sleep_until_into_slot(slot_start_ms, 0).await;

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

        // EIP-7549: the active fork is Electra when the live fork version matches
        // the network's `ELECTRA_FORK_VERSION` (fetched from the BN spec at
        // startup). Drives the `SingleAttestation` v2 submission path and the
        // electra aggregator path in `run_attester`. `None` (pre-electra network)
        // → always phase0 path.
        //
        // FORWARD-COMPAT FAILURE MODE: this is an EXACT-equality match against the
        // electra fork version only. The first post-electra fork ships a NEW
        // `current_version`, which this predicate would treat as `false` and
        // silently revert the VC to the phase0 attestation/aggregate path — wrong
        // shapes, instant peer ban. When a post-electra fork is added this MUST
        // become a fork-ordering `>=` comparison (electra-or-later), keyed off the
        // ordered fork schedule rather than a single version equality.
        let is_electra = config
            .electra_fork_version
            .is_some_and(|v| v == current_version);

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

        if let Some(proposer_pubkey) = duties_for_slot.proposer.get(&current_slot)
            && let Some(entry) = pubkey_map.get(proposer_pubkey)
        {
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

        // ── Attester path (at slot + 1/3) ─────────────────────────────────────

        let attester_wait = config.slot_duration_ms / 3;
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
                            is_electra,
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
