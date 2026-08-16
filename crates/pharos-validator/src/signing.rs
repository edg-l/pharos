//! Per-message-type signing for the validator client.
//!
//! This module computes `signing_root = compute_signing_root(object, domain)`
//! for each message type the VC signs, builds a [`SigningRequest`], and
//! delegates the actual signature to a [`Signer`] (local BLS key or remote
//! Web3Signer — see [`crate::web3signer`]).
//!
//! All block and attestation signing paths are **gated through `SlashingProtection`
//! first** — the signing root is recorded to durable storage (via `check_and_record_*`)
//! before the [`Signer`] is invoked. This ordering holds for BOTH the local and
//! the remote signer: the slashing DB commit happens BEFORE any signature
//! (local key use OR remote HTTP request). If the slashing check fails the
//! method returns `Err(SigningError::Slashing(...))` and no signature is
//! produced (and, for the remote path, no network call is made).
//!
//! Domain derivation uses `compute_domain(domain_type, fork_version, genesis_validators_root)`
//! from `pharos_stf`. The `fork_version` is supplied by the caller (from the
//! beacon-node fork context received with each duty or produced-block response);
//! this module does not hold chain state. Domain derivation never leaves Pharos,
//! so a remote signer cannot compute a different domain.
//!
//! Domains covered (per `pharos_stf` constants):
//! - `DOMAIN_BEACON_PROPOSER` — block signing
//! - `DOMAIN_RANDAO` — RANDAO epoch reveal
//! - `DOMAIN_BEACON_ATTESTER` — attestation signing
//! - `DOMAIN_AGGREGATE_AND_PROOF` — signed `AggregateAndProof`
//! - `DOMAIN_SELECTION_PROOF` — slot selection proof (is_aggregator)
//! - `DOMAIN_SYNC_COMMITTEE` — sync committee message
//! - `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF` — sync committee selection proof
//! - `DOMAIN_CONTRIBUTION_AND_PROOF` — signed `ContributionAndProof`
//! - `DOMAIN_VOLUNTARY_EXIT` — signed `VoluntaryExit`
//! - `DOMAIN_BLS_TO_EXECUTION_CHANGE` — Capella BLS-to-execution-change (non-slashable)

use serde_json::{Value, json};

use pharos_ssz::TreeHash;
use pharos_stf::{
    DOMAIN_AGGREGATE_AND_PROOF, DOMAIN_BEACON_ATTESTER, DOMAIN_BEACON_PROPOSER,
    DOMAIN_BLS_TO_EXECUTION_CHANGE, DOMAIN_CONTRIBUTION_AND_PROOF, DOMAIN_RANDAO,
    DOMAIN_SELECTION_PROOF, DOMAIN_SYNC_COMMITTEE, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF,
    DOMAIN_VOLUNTARY_EXIT, compute_domain, compute_signing_root,
};
use pharos_utils::BLSSignature;

use crate::slashing::{SlashingError, SlashingProtection};
use crate::web3signer::{Signer, SignerError, SigningRequest, SigningType};

/// Error type for signing operations.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("slashing protection rejected signing: {0}")]
    Slashing(#[from] SlashingError),

    #[error("signer failed: {0}")]
    Signer(#[from] SignerError),
}

/// Fork context needed to compute the domain.
///
/// Sourced from the beacon node (via the `fork` field of beacon-state or
/// the `Eth-Consensus-Version` context carried with produced blocks).
#[derive(Debug, Clone)]
pub struct ForkContext {
    /// Current fork version (4 bytes, big-endian).
    pub current_version: [u8; 4],
    /// Genesis validators root (32 bytes).
    pub genesis_validators_root: [u8; 32],
}

// ── Internal domain computation ───────────────────────────────────────────────

/// Compute the BLS domain for a message type.
///
/// `domain_type` is one of the `DOMAIN_*` constants from `pharos_stf`.
fn domain_for(fork: &ForkContext, domain_type: [u8; 4]) -> pharos_utils::Bytes32 {
    let root = pharos_utils::Hash256::from_array(fork.genesis_validators_root);
    compute_domain(domain_type, fork.current_version, &root)
}

/// Convert a signing-root hash into the `[u8; 32]` the [`SigningRequest`] holds.
fn root_array(root: &pharos_utils::Hash256) -> [u8; 32] {
    let mut arr = [0u8; 32];
    arr.copy_from_slice(root.as_slice());
    arr
}

// ── Signing functions ─────────────────────────────────────────────────────────

/// Sign a `BeaconBlock`-like object (any type implementing `TreeHash`).
///
/// The slashing protection database is checked and updated BEFORE the signer is
/// invoked (local key OR remote HTTP). `payload` is the Web3Signer `beacon_block`
/// JSON object (`{version, block_header}`); for the local signer it is unused.
#[allow(clippy::too_many_arguments)]
pub async fn sign_beacon_block<T: TreeHash>(
    signer: &dyn Signer,
    pubkey_hex: &str,
    block_object: &T,
    slot: u64,
    fork: &ForkContext,
    slashing_db: &dyn SlashingProtection,
    payload: Value,
) -> Result<BLSSignature, SigningError> {
    let domain = domain_for(fork, DOMAIN_BEACON_PROPOSER);
    let signing_root = compute_signing_root(block_object, domain);
    let signing_root_hex = format!("0x{}", hex::encode(signing_root.as_slice()));

    // Slashing check + record BEFORE signing (local OR remote).
    slashing_db.check_and_record_block_proposal(pubkey_hex, slot, Some(&signing_root_hex))?;

    let req = SigningRequest::new(
        SigningType::BlockV2,
        root_array(&signing_root),
        fork.clone(),
        payload,
    );
    Ok(signer.sign(&req).await?)
}

/// Sign a RANDAO reveal for a given epoch.
///
/// The RANDAO reveal is `sign(epoch_ssz_encoded)` under `DOMAIN_RANDAO`.
/// Per spec: the epoch is encoded as a `uint64` (little-endian 8 bytes).
///
/// This is NOT gated by slashing protection (RANDAO is not slashable).
pub async fn sign_randao_reveal(
    signer: &dyn Signer,
    epoch: u64,
    fork: &ForkContext,
) -> Result<BLSSignature, SigningError> {
    let domain = domain_for(fork, DOMAIN_RANDAO);
    // Spec: signing_root = compute_signing_root(epoch, domain).
    let signing_root = compute_signing_root(&U64Leaf(epoch), domain);
    let req = SigningRequest::new(
        SigningType::RandaoReveal,
        root_array(&signing_root),
        fork.clone(),
        json!({ "epoch": epoch.to_string() }),
    );
    Ok(signer.sign(&req).await?)
}

/// A newtype over `u64` that implements `TreeHash` as the spec's `uint64` SSZ type
/// (the encoding shared by `Slot`, `Epoch`, and other uint64 primitives).
///
/// `tree_hash_root` of a uint64 (an SSZ basic type) is the value as 8 LE bytes
/// right-padded to a single 32-byte chunk — it is NOT hashed.
struct U64Leaf(u64);

impl TreeHash for U64Leaf {
    const TREE_HASH_TYPE: pharos_ssz::TreeHashType = pharos_ssz::TreeHashType::Basic;

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        self.0.to_le_bytes().to_vec()
    }

    fn tree_hash_root(&self) -> pharos_utils::Hash256 {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&self.0.to_le_bytes());
        pharos_utils::Hash256::from_array(bytes)
    }
}

/// Parse a `0x`-prefixed (or bare) hex string into a 32-byte root, zero-padded /
/// truncated to 32 bytes. Lenient: malformed hex yields all-zeros (which fails
/// downstream verification rather than panicking on bad BN input).
pub fn root_from_hex(s: &str) -> [u8; 32] {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let mut arr = [0u8; 32];
    if let Ok(b) = hex::decode(stripped) {
        let n = b.len().min(32);
        arr[..n].copy_from_slice(&b[..n]);
    }
    arr
}

/// Parse a `0x`-prefixed (or bare) hex string into a 96-byte `BLSSignature`.
/// Lenient like [`root_from_hex`]: malformed/short hex yields a zero signature.
pub fn bls_signature_from_hex(s: &str) -> BLSSignature {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    let mut arr = [0u8; 96];
    if let Ok(b) = hex::decode(stripped) {
        let n = b.len().min(96);
        arr[..n].copy_from_slice(&b[..n]);
    }
    BLSSignature::from_array(arr)
}

/// Sign an `AttestationData`-like object.
///
/// Gated through slashing protection. The `source_epoch` and `target_epoch`
/// are extracted from the attestation data by the caller and passed in. The
/// slashing DB commit happens BEFORE the signer is invoked (local OR remote).
/// `payload` is the Web3Signer `attestation` JSON object.
#[allow(clippy::too_many_arguments)]
pub async fn sign_attestation<T: TreeHash>(
    signer: &dyn Signer,
    pubkey_hex: &str,
    att_data: &T,
    source_epoch: u64,
    target_epoch: u64,
    fork: &ForkContext,
    slashing_db: &dyn SlashingProtection,
    payload: Value,
) -> Result<BLSSignature, SigningError> {
    let domain = domain_for(fork, DOMAIN_BEACON_ATTESTER);
    let signing_root = compute_signing_root(att_data, domain);
    let signing_root_hex = format!("0x{}", hex::encode(signing_root.as_slice()));

    // Slashing check + record BEFORE signing (local OR remote).
    slashing_db.check_and_record_attestation(
        pubkey_hex,
        source_epoch,
        target_epoch,
        Some(&signing_root_hex),
    )?;

    let req = SigningRequest::new(
        SigningType::Attestation,
        root_array(&signing_root),
        fork.clone(),
        payload,
    );
    Ok(signer.sign(&req).await?)
}

/// Sign an `AggregateAndProof`-like object.
///
/// Not gated by slashing protection (aggregate-and-proof is not slashable).
pub async fn sign_aggregate_and_proof<T: TreeHash>(
    signer: &dyn Signer,
    agg_and_proof: &T,
    fork: &ForkContext,
    payload: Value,
) -> Result<BLSSignature, SigningError> {
    let domain = domain_for(fork, DOMAIN_AGGREGATE_AND_PROOF);
    let signing_root = compute_signing_root(agg_and_proof, domain);
    let req = SigningRequest::new(
        SigningType::AggregateAndProof,
        root_array(&signing_root),
        fork.clone(),
        payload,
    );
    Ok(signer.sign(&req).await?)
}

/// Compute a slot selection proof (for attestation aggregator check).
///
/// `compute_signing_root(slot, DOMAIN_SELECTION_PROOF)` — the proof is the
/// validator's signature over the slot under the selection proof domain.
/// `is_aggregator` is determined externally by the caller from the modulo check.
pub async fn sign_selection_proof(
    signer: &dyn Signer,
    slot: u64,
    fork: &ForkContext,
) -> Result<BLSSignature, SigningError> {
    let domain = domain_for(fork, DOMAIN_SELECTION_PROOF);
    let signing_root = compute_signing_root(&U64Leaf(slot), domain);
    let req = SigningRequest::new(
        SigningType::AggregationSlot,
        root_array(&signing_root),
        fork.clone(),
        json!({ "slot": slot.to_string() }),
    );
    Ok(signer.sign(&req).await?)
}

/// Sign a sync committee message (`SyncCommitteeMessage.beacon_block_root`).
///
/// Not gated by slashing protection. `beacon_block_root_hex`/`slot` populate the
/// Web3Signer `sync_committee_message` payload.
pub async fn sign_sync_committee_message<T: TreeHash>(
    signer: &dyn Signer,
    message_object: &T,
    fork: &ForkContext,
    beacon_block_root_hex: &str,
    slot: u64,
) -> Result<BLSSignature, SigningError> {
    let domain = domain_for(fork, DOMAIN_SYNC_COMMITTEE);
    let signing_root = compute_signing_root(message_object, domain);
    let req = SigningRequest::new(
        SigningType::SyncCommitteeMessage,
        root_array(&signing_root),
        fork.clone(),
        json!({ "beacon_block_root": beacon_block_root_hex, "slot": slot.to_string() }),
    );
    Ok(signer.sign(&req).await?)
}

/// Compute a sync committee selection proof.
///
/// Signs `SyncAggregatorSelectionData{slot, subcommittee_index}` under
/// `DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF`.
pub async fn sign_sync_committee_selection_proof<T: TreeHash>(
    signer: &dyn Signer,
    selection_data: &T,
    fork: &ForkContext,
    slot: u64,
    subcommittee_index: u64,
) -> Result<BLSSignature, SigningError> {
    let domain = domain_for(fork, DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF);
    let signing_root = compute_signing_root(selection_data, domain);
    let req = SigningRequest::new(
        SigningType::SyncCommitteeSelectionProof,
        root_array(&signing_root),
        fork.clone(),
        json!({ "slot": slot.to_string(), "subcommittee_index": subcommittee_index.to_string() }),
    );
    Ok(signer.sign(&req).await?)
}

/// Sign a `ContributionAndProof`-like object.
///
/// Not gated by slashing protection.
pub async fn sign_contribution_and_proof<T: TreeHash>(
    signer: &dyn Signer,
    contribution: &T,
    fork: &ForkContext,
    payload: Value,
) -> Result<BLSSignature, SigningError> {
    let domain = domain_for(fork, DOMAIN_CONTRIBUTION_AND_PROOF);
    let signing_root = compute_signing_root(contribution, domain);
    let req = SigningRequest::new(
        SigningType::SyncCommitteeContributionAndProof,
        root_array(&signing_root),
        fork.clone(),
        payload,
    );
    Ok(signer.sign(&req).await?)
}

/// Sign a `VoluntaryExit`-like object.
///
/// Not gated by slashing protection.
pub async fn sign_voluntary_exit<T: TreeHash>(
    signer: &dyn Signer,
    exit_object: &T,
    fork: &ForkContext,
    epoch: u64,
    validator_index: u64,
) -> Result<BLSSignature, SigningError> {
    let domain = domain_for(fork, DOMAIN_VOLUNTARY_EXIT);
    let signing_root = compute_signing_root(exit_object, domain);
    let req = SigningRequest::new(
        SigningType::VoluntaryExit,
        root_array(&signing_root),
        fork.clone(),
        json!({ "epoch": epoch.to_string(), "validator_index": validator_index.to_string() }),
    );
    Ok(signer.sign(&req).await?)
}

/// Sign a Capella `BLSToExecutionChange`-like object.
///
/// Uses `DOMAIN_BLS_TO_EXECUTION_CHANGE` per the Capella spec.
/// Per spec, this domain uses the genesis fork version (not the current fork
/// version), so the caller must supply a `ForkContext` whose `current_version`
/// is set to the genesis fork version.
///
/// Not gated by slashing protection (BLS-to-execution-change is not slashable).
/// Web3Signer has no dedicated BLS-to-execution-change type in the duty loop's
/// hot path; this uses the local-signer-compatible `signing_root` path (a remote
/// signer signs the supplied root directly).
pub async fn sign_bls_to_execution_change<T: TreeHash>(
    signer: &dyn Signer,
    change_object: &T,
    fork: &ForkContext,
    payload: Value,
) -> Result<BLSSignature, SigningError> {
    let domain = domain_for(fork, DOMAIN_BLS_TO_EXECUTION_CHANGE);
    let signing_root = compute_signing_root(change_object, domain);
    let req = SigningRequest::new(
        // No dedicated Web3Signer enum variant; reuse VoluntaryExit shape only
        // for the `type` placeholder — the remote signer signs `signing_root`.
        SigningType::VoluntaryExit,
        root_array(&signing_root),
        fork.clone(),
        payload,
    );
    Ok(signer.sign(&req).await?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slashing::SqliteSlashingProtection;
    use crate::web3signer::LocalSigner;
    use pharos_utils::bls::{BLSSecretKey, fast_aggregate_verify};
    use tempfile::NamedTempFile;

    fn test_fork() -> ForkContext {
        ForkContext {
            current_version: [0x03, 0x00, 0x00, 0x00],
            genesis_validators_root: [0u8; 32],
        }
    }

    fn test_sk() -> BLSSecretKey {
        BLSSecretKey::key_gen(&[0x42u8; 32]).expect("test key gen")
    }

    fn local_signer() -> LocalSigner {
        LocalSigner::new(test_sk())
    }

    fn open_tmp_slashing_db() -> (SqliteSlashingProtection, NamedTempFile) {
        let tmp = NamedTempFile::new().expect("create tmp file");
        let db = SqliteSlashingProtection::open(tmp.path()).expect("open db");
        (db, tmp)
    }

    // ── A minimal TreeHash object for testing ──────────────────────────────────

    /// Wraps a 32-byte fixed value for use as a signing object in tests.
    struct TestRoot([u8; 32]);

    impl TreeHash for TestRoot {
        const TREE_HASH_TYPE: pharos_ssz::TreeHashType = pharos_ssz::TreeHashType::Basic;

        fn tree_hash_packed_encoding(&self) -> Vec<u8> {
            self.0.to_vec()
        }

        fn tree_hash_root(&self) -> pharos_utils::Hash256 {
            pharos_utils::Hash256::from_array(self.0)
        }
    }

    // ── Tests ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn randao_reveal_verifiable_with_fast_aggregate_verify() {
        let sk = test_sk();
        let pk = sk.to_pubkey();
        let fork = test_fork();
        let signer = LocalSigner::new(sk);
        let sig = sign_randao_reveal(&signer, 42, &fork)
            .await
            .expect("randao sign");
        let domain = domain_for(&fork, DOMAIN_RANDAO);
        let signing_root = compute_signing_root(&U64Leaf(42), domain);
        let agg = pharos_utils::bls::aggregate(&[sig]).expect("aggregate single sig");
        assert!(
            fast_aggregate_verify(&[pk], signing_root.as_slice(), &agg)
                .expect("fast_aggregate_verify"),
            "RANDAO reveal must verify"
        );
    }

    #[tokio::test]
    async fn sign_selection_proof_produces_verifiable_signature() {
        let sk = test_sk();
        let pk = sk.to_pubkey();
        let fork = test_fork();
        let signer = LocalSigner::new(sk);
        let sig = sign_selection_proof(&signer, 100, &fork)
            .await
            .expect("selection sign");
        let domain = domain_for(&fork, DOMAIN_SELECTION_PROOF);
        let signing_root = compute_signing_root(&U64Leaf(100), domain);
        let agg = pharos_utils::bls::aggregate(&[sig]).expect("aggregate");
        assert!(
            fast_aggregate_verify(&[pk], signing_root.as_slice(), &agg)
                .expect("fast_aggregate_verify"),
            "selection proof must verify"
        );
    }

    #[tokio::test]
    async fn sign_sync_committee_message_produces_verifiable_signature() {
        let sk = test_sk();
        let pk = sk.to_pubkey();
        let fork = test_fork();
        let signer = LocalSigner::new(sk);
        let root = TestRoot([0xAB; 32]);
        let sig = sign_sync_committee_message(&signer, &root, &fork, "0x00", 12)
            .await
            .expect("sync msg sign");
        let domain = domain_for(&fork, DOMAIN_SYNC_COMMITTEE);
        let signing_root = compute_signing_root(&root, domain);
        let agg = pharos_utils::bls::aggregate(&[sig]).expect("aggregate");
        assert!(
            fast_aggregate_verify(&[pk], signing_root.as_slice(), &agg)
                .expect("fast_aggregate_verify"),
            "sync committee message must verify"
        );
    }

    #[tokio::test]
    async fn sign_aggregate_and_proof_produces_verifiable_signature() {
        let sk = test_sk();
        let pk = sk.to_pubkey();
        let fork = test_fork();
        let signer = LocalSigner::new(sk);
        let obj = TestRoot([0xCC; 32]);
        let sig = sign_aggregate_and_proof(&signer, &obj, &fork, json!({}))
            .await
            .expect("agg sign");
        let domain = domain_for(&fork, DOMAIN_AGGREGATE_AND_PROOF);
        let signing_root = compute_signing_root(&obj, domain);
        let agg = pharos_utils::bls::aggregate(&[sig]).expect("aggregate");
        assert!(
            fast_aggregate_verify(&[pk], signing_root.as_slice(), &agg)
                .expect("fast_aggregate_verify"),
            "aggregate-and-proof must verify"
        );
    }

    #[tokio::test]
    async fn sign_voluntary_exit_produces_verifiable_signature() {
        let sk = test_sk();
        let pk = sk.to_pubkey();
        let fork = test_fork();
        let signer = LocalSigner::new(sk);
        let obj = TestRoot([0xDD; 32]);
        let sig = sign_voluntary_exit(&signer, &obj, &fork, 3, 1)
            .await
            .expect("exit sign");
        let domain = domain_for(&fork, DOMAIN_VOLUNTARY_EXIT);
        let signing_root = compute_signing_root(&obj, domain);
        let agg = pharos_utils::bls::aggregate(&[sig]).expect("aggregate");
        assert!(
            fast_aggregate_verify(&[pk], signing_root.as_slice(), &agg)
                .expect("fast_aggregate_verify"),
            "voluntary exit must verify"
        );
    }

    #[tokio::test]
    async fn sign_beacon_block_gated_by_slashing_db() {
        let sk = test_sk();
        let fork = test_fork();
        let signer = LocalSigner::new(sk);
        let (db, _tmp) = open_tmp_slashing_db();
        let pubkey_hex = format!("0x{}", hex::encode(test_sk().to_pubkey().as_ref()));

        let obj = TestRoot([0x11; 32]);
        // First signing must succeed.
        let sig = sign_beacon_block(&signer, &pubkey_hex, &obj, 50, &fork, &db, json!({}))
            .await
            .expect("first block signing must succeed");
        assert_eq!(sig.as_ref().len(), 96);

        // Second signing with DIFFERENT object at same slot must be rejected.
        let obj2 = TestRoot([0x22; 32]);
        let err = sign_beacon_block(&signer, &pubkey_hex, &obj2, 50, &fork, &db, json!({}))
            .await
            .expect_err("double proposal must be rejected");
        assert!(
            matches!(
                err,
                SigningError::Slashing(crate::slashing::SlashingError::DoubleBlockProposal {
                    slot: 50
                })
            ),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn sign_attestation_gated_by_slashing_db() {
        let sk = test_sk();
        let fork = test_fork();
        let signer = LocalSigner::new(sk);
        let (db, _tmp) = open_tmp_slashing_db();
        let pubkey_hex = format!("0x{}", hex::encode(test_sk().to_pubkey().as_ref()));

        // Establish min_source=1 with a first attestation at (1, 5).
        let att_low = TestRoot([0xA0; 32]);
        sign_attestation(&signer, &pubkey_hex, &att_low, 1, 5, &fork, &db, json!({}))
            .await
            .expect("first attestation (low baseline) must succeed");

        // Insert an inner attestation at (5, 15).
        let att_inner = TestRoot([0xAA; 32]);
        sign_attestation(
            &signer,
            &pubkey_hex,
            &att_inner,
            5,
            15,
            &fork,
            &db,
            json!({}),
        )
        .await
        .expect("inner attestation must succeed");

        // Surround vote: source=3 > min_source=1 (passes watermark), but 3 < 5 AND 20 > 15.
        let att_surround = TestRoot([0xBB; 32]);
        let err = sign_attestation(
            &signer,
            &pubkey_hex,
            &att_surround,
            3,
            20,
            &fork,
            &db,
            json!({}),
        )
        .await
        .expect_err("surround vote must be rejected");
        assert!(
            matches!(
                err,
                SigningError::Slashing(crate::slashing::SlashingError::SurroundVote { .. })
            ),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn sign_bls_to_execution_change_produces_verifiable_signature() {
        let sk = test_sk();
        let pk = sk.to_pubkey();
        // Per spec the genesis fork version is used; set current_version to genesis fork.
        let fork = ForkContext {
            current_version: [0x00, 0x00, 0x00, 0x00],
            genesis_validators_root: [0u8; 32],
        };
        let signer = LocalSigner::new(sk);
        let obj = TestRoot([0xEE; 32]);
        let sig = sign_bls_to_execution_change(&signer, &obj, &fork, json!({}))
            .await
            .expect("bls-to-exec sign");
        let domain = domain_for(&fork, DOMAIN_BLS_TO_EXECUTION_CHANGE);
        let signing_root = compute_signing_root(&obj, domain);
        let agg = pharos_utils::bls::aggregate(&[sig]).expect("aggregate");
        assert!(
            fast_aggregate_verify(&[pk], signing_root.as_slice(), &agg)
                .expect("fast_aggregate_verify"),
            "BLS-to-execution-change must verify"
        );
    }

    #[test]
    fn different_domains_produce_different_signing_roots() {
        let sk = test_sk();
        let fork = test_fork();
        let obj = TestRoot([0x55; 32]);

        // signing_root for RANDAO domain must differ from PROPOSER domain.
        let domain_proposer = domain_for(&fork, DOMAIN_BEACON_PROPOSER);
        let domain_randao = domain_for(&fork, DOMAIN_RANDAO);
        let root_proposer = compute_signing_root(&obj, domain_proposer);
        let root_randao = compute_signing_root(&obj, domain_randao);
        assert_ne!(
            root_proposer.as_slice(),
            root_randao.as_slice(),
            "different domains must produce different signing roots"
        );

        // Signing both must produce different signatures.
        let sig_proposer = sk.sign(root_proposer.as_slice());
        let sig_randao = sk.sign(root_randao.as_slice());
        assert_ne!(
            sig_proposer.as_ref(),
            sig_randao.as_ref(),
            "different signing roots must produce different signatures"
        );

        // local_signer() helper is exercised by other tests; keep referenced.
        let _ = local_signer();
    }
}
