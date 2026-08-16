//! Web3Signer (Consensys eth2 remote-signer) HTTP client + the `Signer`
//! abstraction the validator client signs through.
//!
//! # Design
//!
//! The VC computes every `signing_root = compute_signing_root(object, domain)`
//! locally (in `signing.rs`) — domain derivation never leaves Pharos, so there
//! is no risk of the remote signer computing a different domain. Each `sign_*`
//! function builds a [`SigningRequest`] carrying:
//!
//! - the precomputed `signing_root` (the BLS message),
//! - the [`SigningType`] discriminator + its type-specific JSON payload,
//! - the `fork_info` block Web3Signer expects (`fork` + `genesis_validators_root`).
//!
//! It then delegates to a [`Signer`]:
//!
//! - [`LocalSigner`] holds the `BLSSecretKey` and signs the `signing_root`
//!   directly (the existing local-keystore path, unchanged in behaviour).
//! - [`Web3RemoteSigner`] POSTs the type-specific JSON to
//!   `<signer-url>/api/v1/eth2/sign/<pubkey>` and parses the returned signature.
//!
//! # Slashing-protection ordering (CRITICAL)
//!
//! A remote signer does NOT absolve the VC of local slashing protection. The
//! `check_and_record_*` commit in `signing.rs` runs BEFORE `Signer::sign` is
//! invoked, for BOTH the local and the remote path, exactly as the original
//! local-only code did. The DB record is durable before any signature (local
//! key use OR remote HTTP request) is produced. See
//! `signing::sign_beacon_block` / `signing::sign_attestation`.
//!
//! # `VALIDATOR_REGISTRATION`
//!
//! [`SigningType::ValidatorRegistration`] is a builder-API signing type. The
//! builder API is out of scope; this enum variant + request shape exist for
//! completeness (a Web3Signer may receive it from other tooling) and are NOT
//! driven by the VC duty loop. There is no builder integration.

use std::time::Duration;

use serde_json::{Value, json};

use pharos_utils::BLSSignature;
use pharos_utils::bls::BLSSecretKey;

use crate::signing::ForkContext;

/// HTTP timeout for a single remote-signer request.
const SIGNER_HTTP_TIMEOUT: Duration = Duration::from_secs(6);

/// Error type for the signer abstraction.
#[derive(Debug, thiserror::Error)]
pub enum SignerError {
    /// The remote-signer HTTP transport failed (connect/timeout/etc.).
    #[error("web3signer transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// The remote signer returned a non-2xx status.
    #[error("web3signer returned status {status}: {body}")]
    Status { status: u16, body: String },

    /// The remote signer response could not be parsed.
    #[error("web3signer response parse error: {0}")]
    Response(String),

    /// The base signer URL could not be joined with the sign path.
    #[error("invalid web3signer URL: {0}")]
    Url(String),
}

/// The Web3Signer eth2 signing types (`type` discriminator in the request body).
///
/// Each variant maps to one `/api/v1/eth2/sign/<pubkey>` request shape. The
/// payload (the type-specific JSON object such as `beacon_block` or
/// `attestation`) is carried alongside the type in [`SigningRequest::payload`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningType {
    /// `BLOCK_V2` — a beacon block proposal (Altair+; carries `block_header`).
    BlockV2,
    /// `ATTESTATION` — an `AttestationData`.
    Attestation,
    /// `RANDAO_REVEAL` — the epoch RANDAO reveal.
    RandaoReveal,
    /// `AGGREGATION_SLOT` — the slot selection proof (attestation aggregator).
    AggregationSlot,
    /// `AGGREGATE_AND_PROOF` — a signed `AggregateAndProof`.
    AggregateAndProof,
    /// `SYNC_COMMITTEE_MESSAGE` — a sync-committee message.
    SyncCommitteeMessage,
    /// `SYNC_COMMITTEE_SELECTION_PROOF` — a sync-committee selection proof.
    SyncCommitteeSelectionProof,
    /// `SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF` — a signed `ContributionAndProof`.
    SyncCommitteeContributionAndProof,
    /// `VOLUNTARY_EXIT` — a signed `VoluntaryExit`.
    VoluntaryExit,
    /// `VALIDATOR_REGISTRATION` — builder-API validator registration.
    ///
    /// Supported-for-completeness only; NOT driven by the VC duty loop (the
    /// builder API is out of scope and there is no builder integration).
    ValidatorRegistration,
}

impl SigningType {
    /// The uppercase `type` string Web3Signer expects in the request body.
    pub fn as_str(self) -> &'static str {
        match self {
            SigningType::BlockV2 => "BLOCK_V2",
            SigningType::Attestation => "ATTESTATION",
            SigningType::RandaoReveal => "RANDAO_REVEAL",
            SigningType::AggregationSlot => "AGGREGATION_SLOT",
            SigningType::AggregateAndProof => "AGGREGATE_AND_PROOF",
            SigningType::SyncCommitteeMessage => "SYNC_COMMITTEE_MESSAGE",
            SigningType::SyncCommitteeSelectionProof => "SYNC_COMMITTEE_SELECTION_PROOF",
            SigningType::SyncCommitteeContributionAndProof => {
                "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
            }
            SigningType::VoluntaryExit => "VOLUNTARY_EXIT",
            SigningType::ValidatorRegistration => "VALIDATOR_REGISTRATION",
        }
    }

    /// The body field name carrying the type-specific data object.
    ///
    /// Web3Signer keys the type-specific payload under a per-type field name
    /// (e.g. `BLOCK_V2` → `beacon_block`, `ATTESTATION` → `attestation`).
    pub fn payload_field(self) -> &'static str {
        match self {
            SigningType::BlockV2 => "beacon_block",
            SigningType::Attestation => "attestation",
            SigningType::RandaoReveal => "randao_reveal",
            SigningType::AggregationSlot => "aggregation_slot",
            SigningType::AggregateAndProof => "aggregate_and_proof",
            SigningType::SyncCommitteeMessage => "sync_committee_message",
            SigningType::SyncCommitteeSelectionProof => "sync_aggregator_selection_data",
            SigningType::SyncCommitteeContributionAndProof => "contribution_and_proof",
            SigningType::VoluntaryExit => "voluntary_exit",
            SigningType::ValidatorRegistration => "validator_registration",
        }
    }
}

/// A fully-described signing request.
///
/// Built by the `signing.rs` `sign_*` functions and passed to a [`Signer`].
/// The `signing_root` is the BLS message; `payload` is the type-specific JSON
/// object (already shaped) the remote signer keys under
/// [`SigningType::payload_field`].
#[derive(Debug, Clone)]
pub struct SigningRequest {
    /// The signing type (`type` discriminator).
    pub ty: SigningType,
    /// The precomputed `compute_signing_root(object, domain)` — the BLS message.
    pub signing_root: [u8; 32],
    /// The fork context (current fork version + genesis validators root).
    pub fork: ForkContext,
    /// The type-specific data object (e.g. the `beacon_block` / `attestation`
    /// JSON), keyed under [`SigningType::payload_field`] in the request body.
    pub payload: Value,
}

impl SigningRequest {
    /// Construct a request.
    pub fn new(ty: SigningType, signing_root: [u8; 32], fork: ForkContext, payload: Value) -> Self {
        Self {
            ty,
            signing_root,
            fork,
            payload,
        }
    }

    /// Serialise to the Web3Signer eth2 request JSON.
    ///
    /// Shape (per the Consensys Web3Signer eth2 signing OpenAPI):
    ///
    /// ```json
    /// {
    ///   "type": "<TYPE>",
    ///   "fork_info": {
    ///     "fork": {
    ///       "previous_version": "0x..",
    ///       "current_version": "0x..",
    ///       "epoch": "0"
    ///     },
    ///     "genesis_validators_root": "0x.."
    ///   },
    ///   "signing_root": "0x..",
    ///   "<payload_field>": { ... }
    /// }
    /// ```
    ///
    /// `signing_root` is always included: Pharos computes the domain locally, so
    /// the remote signer signs this exact root (the `fork_info` / payload feed
    /// any slashing-validation plugin on the signer side). `previous_version` is
    /// set equal to `current_version` and `epoch` to `0`; these fields exist for
    /// the signer's optional re-derivation and never override the supplied
    /// `signing_root`.
    pub fn to_request_json(&self) -> Value {
        let current_version = format!("0x{}", hex::encode(self.fork.current_version));
        let gvr = format!("0x{}", hex::encode(self.fork.genesis_validators_root));
        let signing_root = format!("0x{}", hex::encode(self.signing_root));

        json!({
            "type": self.ty.as_str(),
            "fork_info": {
                "fork": {
                    "previous_version": current_version,
                    "current_version": current_version,
                    "epoch": "0",
                },
                "genesis_validators_root": gvr,
            },
            "signing_root": signing_root,
            self.ty.payload_field(): self.payload,
        })
    }
}

/// The signing abstraction: local BLS key vs remote Web3Signer.
///
/// `sign` is `async` because the remote path performs an HTTP request. The
/// local path is trivially `async` (no I/O). Slashing protection is committed
/// by the caller (`signing.rs`) BEFORE `sign` is invoked.
pub trait Signer: Send + Sync {
    /// Produce a BLS signature over `req.signing_root`.
    fn sign(
        &self,
        req: &SigningRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<BLSSignature, SignerError>> + Send + '_>,
    >;
}

/// Local-keystore signer: holds the decrypted `BLSSecretKey` and signs the
/// `signing_root` directly. Behaviourally identical to the pre-Phase-16
/// `sk.sign(signing_root)` path.
pub struct LocalSigner {
    secret_key: BLSSecretKey,
}

impl LocalSigner {
    /// Wrap a decrypted secret key.
    pub fn new(secret_key: BLSSecretKey) -> Self {
        Self { secret_key }
    }
}

impl Signer for LocalSigner {
    fn sign(
        &self,
        req: &SigningRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<BLSSignature, SignerError>> + Send + '_>,
    > {
        let sig = self.secret_key.sign(&req.signing_root);
        Box::pin(async move { Ok(sig) })
    }
}

/// Remote Web3Signer: POSTs the type-specific JSON to
/// `<base_url>/api/v1/eth2/sign/<pubkey>` and parses `{"signature": "0x.."}`.
pub struct Web3RemoteSigner {
    client: reqwest::Client,
    base_url: reqwest::Url,
    /// `0x`-prefixed compressed pubkey hex used as the path `<identifier>`.
    pubkey_hex: String,
}

impl Web3RemoteSigner {
    /// Construct a remote signer for one validator pubkey.
    ///
    /// `base_url` is the Web3Signer root (e.g. `http://127.0.0.1:9000`).
    /// `pubkey_hex` is the `0x`-prefixed compressed BLS pubkey.
    pub fn new(base_url: reqwest::Url, pubkey_hex: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(SIGNER_HTTP_TIMEOUT)
            .build()
            .expect("reqwest client construction is infallible with default TLS");
        Self {
            client,
            base_url,
            pubkey_hex,
        }
    }

    /// The full sign endpoint URL for this validator.
    fn sign_url(&self) -> Result<reqwest::Url, SignerError> {
        // Path identifier is the pubkey WITHOUT a leading slash collision.
        let path = format!("/api/v1/eth2/sign/{}", self.pubkey_hex);
        self.base_url
            .join(&path)
            .map_err(|e| SignerError::Url(e.to_string()))
    }

    async fn post(&self, body: &Value) -> Result<BLSSignature, SignerError> {
        let url = self.sign_url()?;
        let resp = self.client.post(url).json(body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            return Err(SignerError::Status {
                status: status.as_u16(),
                body,
            });
        }
        // Web3Signer may return `{"signature": "0x.."}` (JSON) or a bare
        // `"0x.."` body (text/plain). Handle both.
        let text = resp.text().await?;
        let sig_hex = parse_signature_body(&text)?;
        parse_signature_hex(&sig_hex)
    }
}

impl Signer for Web3RemoteSigner {
    fn sign(
        &self,
        req: &SigningRequest,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<BLSSignature, SignerError>> + Send + '_>,
    > {
        let body = req.to_request_json();
        Box::pin(async move { self.post(&body).await })
    }
}

/// Extract the signature hex from a Web3Signer response body.
///
/// Accepts either a JSON object `{"signature": "0x.."}` or a bare quoted/raw
/// hex string (`"0x.."` or `0x..`).
fn parse_signature_body(text: &str) -> Result<String, SignerError> {
    let trimmed = text.trim();
    if let Ok(v) = serde_json::from_str::<Value>(trimmed) {
        match v {
            Value::Object(map) => {
                let sig = map
                    .get("signature")
                    .and_then(|s| s.as_str())
                    .ok_or_else(|| {
                        SignerError::Response("missing `signature` field".to_string())
                    })?;
                Ok(sig.to_string())
            }
            Value::String(s) => Ok(s),
            other => Err(SignerError::Response(format!(
                "unexpected response JSON: {other}"
            ))),
        }
    } else {
        // Bare (unquoted) hex string.
        Ok(trimmed.to_string())
    }
}

/// Parse a `0x`-prefixed (or bare) 96-byte BLS signature hex string.
fn parse_signature_hex(s: &str) -> Result<BLSSignature, SignerError> {
    let stripped = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let bytes = hex::decode(stripped)
        .map_err(|e| SignerError::Response(format!("signature hex decode failed: {e}")))?;
    if bytes.len() != 96 {
        return Err(SignerError::Response(format!(
            "signature has {} bytes, expected 96",
            bytes.len()
        )));
    }
    let mut arr = [0u8; 96];
    arr.copy_from_slice(&bytes);
    Ok(BLSSignature::from_array(arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_fork() -> ForkContext {
        ForkContext {
            current_version: [0x03, 0x00, 0x00, 0x00],
            genesis_validators_root: [0xABu8; 32],
        }
    }

    fn req(ty: SigningType, payload: Value) -> SigningRequest {
        SigningRequest::new(ty, [0x11u8; 32], test_fork(), payload)
    }

    #[test]
    fn block_v2_request_shape() {
        let payload = json!({
            "version": "BELLATRIX",
            "block_header": {
                "slot": "5",
                "proposer_index": "1",
                "parent_root": "0x00",
                "state_root": "0x00",
                "body_root": "0x00",
            }
        });
        let r = req(SigningType::BlockV2, payload.clone());
        let v = r.to_request_json();
        assert_eq!(v["type"], "BLOCK_V2");
        assert_eq!(
            v["signing_root"],
            format!("0x{}", hex::encode([0x11u8; 32]))
        );
        assert_eq!(
            v["fork_info"]["fork"]["current_version"],
            "0x03000000".to_string()
        );
        assert_eq!(
            v["fork_info"]["fork"]["previous_version"],
            "0x03000000".to_string()
        );
        assert_eq!(v["fork_info"]["fork"]["epoch"], "0");
        assert_eq!(
            v["fork_info"]["genesis_validators_root"],
            format!("0x{}", hex::encode([0xABu8; 32]))
        );
        // The block payload is keyed under `beacon_block`.
        assert_eq!(v["beacon_block"], payload);
    }

    #[test]
    fn attestation_request_shape() {
        let payload = json!({
            "slot": "32",
            "index": "0",
            "beacon_block_root": "0x00",
            "source": {"epoch": "0", "root": "0x00"},
            "target": {"epoch": "1", "root": "0x00"},
        });
        let v = req(SigningType::Attestation, payload.clone()).to_request_json();
        assert_eq!(v["type"], "ATTESTATION");
        assert_eq!(v["attestation"], payload);
    }

    #[test]
    fn randao_reveal_request_shape() {
        let payload = json!({ "epoch": "7" });
        let v = req(SigningType::RandaoReveal, payload.clone()).to_request_json();
        assert_eq!(v["type"], "RANDAO_REVEAL");
        assert_eq!(v["randao_reveal"], payload);
    }

    #[test]
    fn aggregation_slot_request_shape() {
        let payload = json!({ "slot": "99" });
        let v = req(SigningType::AggregationSlot, payload.clone()).to_request_json();
        assert_eq!(v["type"], "AGGREGATION_SLOT");
        assert_eq!(v["aggregation_slot"], payload);
    }

    #[test]
    fn aggregate_and_proof_request_shape() {
        let payload =
            json!({ "aggregator_index": "1", "aggregate": {}, "selection_proof": "0x00" });
        let v = req(SigningType::AggregateAndProof, payload.clone()).to_request_json();
        assert_eq!(v["type"], "AGGREGATE_AND_PROOF");
        assert_eq!(v["aggregate_and_proof"], payload);
    }

    #[test]
    fn sync_committee_message_request_shape() {
        let payload = json!({ "beacon_block_root": "0x00", "slot": "12" });
        let v = req(SigningType::SyncCommitteeMessage, payload.clone()).to_request_json();
        assert_eq!(v["type"], "SYNC_COMMITTEE_MESSAGE");
        assert_eq!(v["sync_committee_message"], payload);
    }

    #[test]
    fn sync_committee_selection_proof_request_shape() {
        let payload = json!({ "slot": "12", "subcommittee_index": "2" });
        let v = req(SigningType::SyncCommitteeSelectionProof, payload.clone()).to_request_json();
        assert_eq!(v["type"], "SYNC_COMMITTEE_SELECTION_PROOF");
        assert_eq!(v["sync_aggregator_selection_data"], payload);
    }

    #[test]
    fn sync_committee_contribution_and_proof_request_shape() {
        let payload =
            json!({ "aggregator_index": "1", "contribution": {}, "selection_proof": "0x00" });
        let v = req(
            SigningType::SyncCommitteeContributionAndProof,
            payload.clone(),
        )
        .to_request_json();
        assert_eq!(v["type"], "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF");
        assert_eq!(v["contribution_and_proof"], payload);
    }

    #[test]
    fn voluntary_exit_request_shape() {
        let payload = json!({ "epoch": "3", "validator_index": "1" });
        let v = req(SigningType::VoluntaryExit, payload.clone()).to_request_json();
        assert_eq!(v["type"], "VOLUNTARY_EXIT");
        assert_eq!(v["voluntary_exit"], payload);
    }

    #[test]
    fn validator_registration_request_shape() {
        // Supported-for-completeness; not driven by the VC duty loop.
        let payload = json!({
            "fee_recipient": "0x0000000000000000000000000000000000000000",
            "gas_limit": "30000000",
            "timestamp": "100",
            "pubkey": "0x00",
        });
        let v = req(SigningType::ValidatorRegistration, payload.clone()).to_request_json();
        assert_eq!(v["type"], "VALIDATOR_REGISTRATION");
        assert_eq!(v["validator_registration"], payload);
    }

    #[test]
    fn parse_signature_body_json_object() {
        let sig_hex = format!("0x{}", hex::encode([0x22u8; 96]));
        let body = json!({ "signature": sig_hex }).to_string();
        let parsed = parse_signature_body(&body).expect("parse json object");
        assert_eq!(parsed, format!("0x{}", hex::encode([0x22u8; 96])));
    }

    #[test]
    fn parse_signature_body_bare_quoted_string() {
        let sig_hex = format!("\"0x{}\"", hex::encode([0x33u8; 96]));
        let parsed = parse_signature_body(&sig_hex).expect("parse quoted string");
        assert_eq!(parsed, format!("0x{}", hex::encode([0x33u8; 96])));
    }

    #[test]
    fn parse_signature_body_bare_unquoted_hex() {
        let sig_hex = format!("0x{}", hex::encode([0x44u8; 96]));
        let parsed = parse_signature_body(&sig_hex).expect("parse bare hex");
        assert_eq!(parsed, sig_hex);
    }

    #[test]
    fn parse_signature_hex_rejects_wrong_length() {
        let err = parse_signature_hex("0x1234").expect_err("must reject short sig");
        assert!(matches!(err, SignerError::Response(_)));
    }

    #[tokio::test]
    async fn local_signer_signs_the_signing_root() {
        let sk = BLSSecretKey::key_gen(&[0x42u8; 32]).expect("key gen");
        let pk = sk.to_pubkey();
        let signer = LocalSigner::new(sk);
        let r = req(SigningType::Attestation, json!({}));
        let sig = signer.sign(&r).await.expect("local sign");
        // The signature must verify over the exact signing root.
        let agg = pharos_utils::bls::aggregate(&[sig]).expect("aggregate");
        assert!(
            pharos_utils::bls::fast_aggregate_verify(&[pk], &r.signing_root, &agg).expect("verify"),
            "local signer must sign the signing_root"
        );
    }
}
