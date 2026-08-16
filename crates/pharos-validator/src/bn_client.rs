//! Beacon-node HTTP client for the validator client.
//!
//! Wraps `reqwest` with:
//! - Multi-BN failover: configured with `--beacon-node` (repeatable); each request
//!   tries the primary, then falls back to secondary nodes on error.
//! - Per-slot `/eth/v1/node/syncing` health probe.
//! - HTTP 503 → `BnError::Unavailable` (do-not-sign signal for production endpoints).
//!
//! Methods cover every endpoint the VC calls:
//! - Duties: proposer, attester, sync
//! - Production: produce_block (v3), attestation_data, aggregate_attestation,
//!   sync_committee_contribution
//! - Submission: aggregate_and_proofs, contribution_and_proofs, pool submissions
//! - Admin: prepare_beacon_proposer, register_validator,
//!   beacon_committee_subscriptions, sync_committee_subscriptions,
//!   beacon_committee_selections, sync_committee_selections
//! - Publish: POST /eth/v1/beacon/blocks, POST /eth/v2/beacon/blocks
//! - Events: SSE /eth/v1/events
//! - Liveness: POST /eth/v1/validator/liveness/{epoch}
//! - Node: GET /eth/v1/node/syncing

use std::time::Duration;

use reqwest::{Client, Response, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Error type for beacon-node client operations.
#[derive(Debug, thiserror::Error)]
pub enum BnError {
    /// The beacon node returned HTTP 503: node is syncing/optimistic.
    /// The caller MUST NOT sign any message when this is returned from a
    /// production endpoint.
    #[error("beacon node unavailable (HTTP 503): do not sign")]
    Unavailable,

    /// All configured beacon nodes returned errors.
    #[error("all beacon nodes failed: last error: {0}")]
    AllFailed(String),

    /// HTTP-level error other than 503.
    #[error("HTTP error {status}: {body}")]
    Http { status: u16, body: String },

    /// Transport / connection error.
    #[error("transport error: {0}")]
    Transport(#[from] reqwest::Error),

    /// JSON parse / serialize error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// URL construction error.
    #[error("URL error: {0}")]
    UrlParse(#[from] url::ParseError),
}

// ── Common BN response DTOs ───────────────────────────────────────────────────

/// Syncing status response from `/eth/v1/node/syncing`.
#[derive(Debug, Deserialize)]
pub struct SyncingData {
    pub head_slot: String,
    pub sync_distance: String,
    pub is_syncing: bool,
    #[serde(default)]
    pub is_optimistic: bool,
    #[serde(default)]
    pub el_offline: bool,
}

#[derive(Debug, Deserialize)]
pub struct SyncingResponse {
    pub data: SyncingData,
}

// ── State validators (index lookup) ───────────────────────────────────────────

/// One entry from `GET /eth/v1/beacon/states/{state_id}/validators`.
#[derive(Debug, Deserialize)]
pub struct StateValidatorEntry {
    pub index: String,
    pub validator: StateValidatorInner,
}

#[derive(Debug, Deserialize)]
pub struct StateValidatorInner {
    pub pubkey: String,
}

// ── Fork ──────────────────────────────────────────────────────────────────────

/// Fork data from `GET /eth/v1/beacon/states/{state_id}/fork`.
#[derive(Debug, Deserialize)]
pub struct ForkDataDto {
    pub previous_version: String,
    pub current_version: String,
    pub epoch: String,
}

// ── Block header ──────────────────────────────────────────────────────────────

/// Block header data from `GET /eth/v1/beacon/headers/{block_id}`.
#[derive(Debug, Deserialize)]
pub struct BlockHeaderDto {
    pub root: String,
}

/// Generic BN data wrapper.
#[derive(Debug, Deserialize)]
pub struct DataResponse<T> {
    pub data: T,
    #[serde(default)]
    pub dependent_root: Option<String>,
    #[serde(default)]
    pub execution_optimistic: Option<bool>,
}

// ── Proposer duty ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
pub struct ProposerDuty {
    pub pubkey: String,
    pub validator_index: String,
    pub slot: String,
}

// ── Attester duty ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AttesterDuty {
    pub pubkey: String,
    pub validator_index: String,
    pub committee_index: String,
    pub committee_length: String,
    pub committees_at_slot: String,
    pub validator_committee_index: String,
    pub slot: String,
}

// ── Sync duty ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SyncDuty {
    pub pubkey: String,
    pub validator_index: String,
    pub validator_sync_committee_indices: Vec<String>,
}

// ── Attestation data ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CheckpointDto {
    pub epoch: String,
    pub root: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AttestationDataDto {
    pub slot: String,
    pub index: String,
    pub beacon_block_root: String,
    pub source: CheckpointDto,
    pub target: CheckpointDto,
}

// ── Aggregate attestation ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct AggregateAttestationDto {
    pub aggregation_bits: String,
    pub data: AttestationDataDto,
    pub signature: String,
}

// ── SignedAggregateAndProof ───────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct AggregateAndProofDto {
    pub aggregator_index: String,
    pub aggregate: AggregateAttestationDto,
    pub selection_proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedAggregateAndProofDto {
    pub message: AggregateAndProofDto,
    pub signature: String,
}

// ── Sync committee contribution ───────────────────────────────────────────────

#[derive(Debug, Deserialize, Serialize)]
pub struct SyncContributionDto {
    pub slot: String,
    pub beacon_block_root: String,
    pub subcommittee_index: String,
    pub aggregation_bits: String,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContributionAndProofDto {
    pub aggregator_index: String,
    pub contribution: SyncContributionDto,
    pub selection_proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedContributionAndProofDto {
    pub message: ContributionAndProofDto,
    pub signature: String,
}

// ── Prepare beacon proposer ───────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct PrepareBeaconProposerItem {
    pub validator_index: String,
    pub fee_recipient: String,
}

// ── Register validator ────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidatorRegistrationData {
    pub fee_recipient: String,
    pub gas_limit: String,
    pub timestamp: String,
    pub pubkey: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedValidatorRegistration {
    pub message: ValidatorRegistrationData,
    pub signature: String,
}

// ── Committee subscriptions ───────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct BeaconCommitteeSubscription {
    pub validator_index: String,
    pub committee_index: String,
    pub committees_at_slot: String,
    pub slot: String,
    pub is_aggregator: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncCommitteeSubscription {
    pub validator_index: String,
    pub sync_committee_indices: Vec<String>,
    pub until_epoch: String,
}

// ── Validator liveness ────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct ValidatorLivenessItem {
    pub index: String,
    pub is_live: bool,
}

// ── Beacon-node committee/sync selections (non-DVT identity) ─────────────────

#[derive(Debug, Serialize, Deserialize)]
pub struct BeaconCommitteeSelection {
    pub validator_index: String,
    pub slot: String,
    pub selection_proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SyncCommitteeSelection {
    pub validator_index: String,
    pub slot: String,
    pub subcommittee_index: String,
    pub selection_proof: String,
}

// ── BnClient ─────────────────────────────────────────────────────────────────

/// Beacon-node HTTP client with failover.
///
/// Requests are tried against each node in `nodes` order; the first success is
/// returned. On error, the next node is tried. If all nodes fail, `BnError::AllFailed`
/// is returned.
#[derive(Clone)]
pub struct BnClient {
    client: Client,
    nodes: Vec<Url>,
}

impl BnClient {
    /// Construct a new client from a list of base URLs.
    ///
    /// `nodes` must be non-empty (validated at construction time by the CLI).
    pub fn new(nodes: Vec<Url>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client construction is infallible with default TLS");
        Self { client, nodes }
    }

    /// Try a request across all configured nodes (failover), returning the first
    /// success. `build` maps a per-node base URL to the request to send. A 503
    /// from any node short-circuits to [`BnError::Unavailable`]; otherwise the
    /// last error is reported once every node has been tried.
    async fn send_with_failover(
        &self,
        path: &str,
        build: impl Fn(Url) -> reqwest::RequestBuilder,
    ) -> Result<Response, BnError> {
        let mut last_err = String::new();
        for base in &self.nodes {
            let url = base.join(path)?;
            match build(url).send().await {
                Ok(resp) => {
                    if resp.status() == StatusCode::SERVICE_UNAVAILABLE {
                        return Err(BnError::Unavailable);
                    }
                    if resp.status().is_success() {
                        return Ok(resp);
                    }
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default();
                    last_err = format!("HTTP {status}: {body}");
                }
                Err(e) => {
                    last_err = e.to_string();
                }
            }
        }
        Err(BnError::AllFailed(last_err))
    }

    /// Try a GET request across all configured nodes (failover).
    async fn get(&self, path: &str) -> Result<Response, BnError> {
        self.send_with_failover(path, |url| self.client.get(url))
            .await
    }

    /// Try a POST request across all configured nodes (failover).
    async fn post<B: Serialize + ?Sized>(&self, path: &str, body: &B) -> Result<Response, BnError> {
        self.send_with_failover(path, |url| self.client.post(url).json(body))
            .await
    }

    // ── Genesis ───────────────────────────────────────────────────────────────

    /// `GET /eth/v1/beacon/genesis` — returns genesis info.
    pub async fn get_genesis(&self) -> Result<serde_json::Value, BnError> {
        let resp = self.get("eth/v1/beacon/genesis").await?;
        Ok(resp.json().await?)
    }

    // ── State validators / fork / head ──────────────────────────────────────────

    /// `GET /eth/v1/beacon/states/head/validators?id=<pubkey0>,<pubkey1>,...`
    ///
    /// Resolves on-chain validator indices for the given pubkeys. Validators not
    /// yet deposited/activated are simply absent from the response.
    pub async fn get_state_validators(
        &self,
        pubkeys_hex: &[String],
    ) -> Result<Vec<StateValidatorEntry>, BnError> {
        let ids = pubkeys_hex.join(",");
        let path = format!("eth/v1/beacon/states/head/validators?id={ids}");
        let resp = self.get(&path).await?;
        let parsed: DataResponse<Vec<StateValidatorEntry>> = resp.json().await?;
        Ok(parsed.data)
    }

    /// `GET /eth/v1/beacon/states/head/fork` — current fork data (for signing domains).
    pub async fn get_fork(&self) -> Result<ForkDataDto, BnError> {
        let resp = self.get("eth/v1/beacon/states/head/fork").await?;
        let parsed: DataResponse<ForkDataDto> = resp.json().await?;
        Ok(parsed.data)
    }

    /// `GET /eth/v1/beacon/headers/head` — canonical head block root.
    pub async fn get_head_block_root(&self) -> Result<String, BnError> {
        let resp = self.get("eth/v1/beacon/headers/head").await?;
        let parsed: DataResponse<BlockHeaderDto> = resp.json().await?;
        Ok(parsed.data.root)
    }

    // ── Health / syncing ──────────────────────────────────────────────────────

    /// `GET /eth/v1/node/syncing` — per-slot health probe.
    ///
    /// Returns `Err(BnError::Unavailable)` if the node returns 503. Otherwise
    /// returns the parsed `SyncingData`.
    pub async fn get_syncing(&self) -> Result<SyncingData, BnError> {
        let resp = self.get("eth/v1/node/syncing").await?;
        let sync: SyncingResponse = resp.json().await?;
        Ok(sync.data)
    }

    // ── Duties ────────────────────────────────────────────────────────────────

    /// `GET /eth/v1/validator/duties/proposer/{epoch}`
    pub async fn get_proposer_duties(
        &self,
        epoch: u64,
    ) -> Result<DataResponse<Vec<ProposerDuty>>, BnError> {
        let path = format!("eth/v1/validator/duties/proposer/{epoch}");
        let resp = self.get(&path).await?;
        Ok(resp.json().await?)
    }

    /// `POST /eth/v1/validator/duties/attester/{epoch}`
    ///
    /// `validator_indices`: list of validator indices to fetch duties for.
    pub async fn post_attester_duties(
        &self,
        epoch: u64,
        validator_indices: &[u64],
    ) -> Result<DataResponse<Vec<AttesterDuty>>, BnError> {
        let path = format!("eth/v1/validator/duties/attester/{epoch}");
        let body: Vec<String> = validator_indices.iter().map(|i| i.to_string()).collect();
        let resp = self.post(&path, &body).await?;
        Ok(resp.json().await?)
    }

    /// `POST /eth/v1/validator/duties/sync/{epoch}`
    pub async fn post_sync_duties(
        &self,
        epoch: u64,
        validator_indices: &[u64],
    ) -> Result<DataResponse<Vec<SyncDuty>>, BnError> {
        let path = format!("eth/v1/validator/duties/sync/{epoch}");
        let body: Vec<String> = validator_indices.iter().map(|i| i.to_string()).collect();
        let resp = self.post(&path, &body).await?;
        Ok(resp.json().await?)
    }

    // ── Block production ──────────────────────────────────────────────────────

    /// `GET /eth/v3/validator/blocks/{slot}` — returns 503 when syncing/optimistic.
    pub async fn produce_block_v3(
        &self,
        slot: u64,
        randao_reveal: &str,
        graffiti: Option<&str>,
    ) -> Result<JsonValue, BnError> {
        let mut path = format!("eth/v3/validator/blocks/{slot}?randao_reveal={randao_reveal}");
        if let Some(g) = graffiti {
            path.push_str(&format!("&graffiti={g}"));
        }
        let resp = self.get(&path).await?;
        Ok(resp.json().await?)
    }

    // ── Attestation production ────────────────────────────────────────────────

    /// `GET /eth/v1/validator/attestation_data` — returns 503 when syncing/optimistic.
    pub async fn get_attestation_data(
        &self,
        slot: u64,
        committee_index: u64,
    ) -> Result<AttestationDataDto, BnError> {
        let path = format!(
            "eth/v1/validator/attestation_data?slot={slot}&committee_index={committee_index}"
        );
        let resp = self.get(&path).await?;
        let data: DataResponse<AttestationDataDto> = resp.json().await?;
        Ok(data.data)
    }

    // ── Aggregate attestation ─────────────────────────────────────────────────

    /// `GET /eth/v2/validator/aggregate_attestation` — returns 503 when syncing/optimistic.
    pub async fn get_aggregate_attestation(
        &self,
        attestation_data_root: &str,
        slot: u64,
    ) -> Result<AggregateAttestationDto, BnError> {
        let path = format!(
            "eth/v2/validator/aggregate_attestation?attestation_data_root={attestation_data_root}&slot={slot}"
        );
        let resp = self.get(&path).await?;
        let data: DataResponse<AggregateAttestationDto> = resp.json().await?;
        Ok(data.data)
    }

    /// `POST /eth/v2/validator/aggregate_and_proofs`
    pub async fn post_aggregate_and_proofs(
        &self,
        proofs: &[SignedAggregateAndProofDto],
    ) -> Result<(), BnError> {
        self.post("eth/v2/validator/aggregate_and_proofs", proofs)
            .await?;
        Ok(())
    }

    // ── Proposer registration ─────────────────────────────────────────────────

    /// `POST /eth/v1/validator/prepare_beacon_proposer`
    pub async fn prepare_beacon_proposer(
        &self,
        items: &[PrepareBeaconProposerItem],
    ) -> Result<(), BnError> {
        self.post("eth/v1/validator/prepare_beacon_proposer", items)
            .await?;
        Ok(())
    }

    /// `POST /eth/v1/validator/register_validator`
    pub async fn register_validator(
        &self,
        registrations: &[SignedValidatorRegistration],
    ) -> Result<(), BnError> {
        self.post("eth/v1/validator/register_validator", registrations)
            .await?;
        Ok(())
    }

    // ── Committee / syncnets subscriptions ───────────────────────────────────

    /// `POST /eth/v1/validator/beacon_committee_subscriptions`
    pub async fn beacon_committee_subscriptions(
        &self,
        subs: &[BeaconCommitteeSubscription],
    ) -> Result<(), BnError> {
        self.post("eth/v1/validator/beacon_committee_subscriptions", subs)
            .await?;
        Ok(())
    }

    /// `POST /eth/v1/validator/sync_committee_subscriptions`
    pub async fn sync_committee_subscriptions(
        &self,
        subs: &[SyncCommitteeSubscription],
    ) -> Result<(), BnError> {
        self.post("eth/v1/validator/sync_committee_subscriptions", subs)
            .await?;
        Ok(())
    }

    // ── Sync committee contribution ───────────────────────────────────────────

    /// `GET /eth/v1/validator/sync_committee_contribution` — returns 503 when syncing/optimistic.
    pub async fn get_sync_committee_contribution(
        &self,
        slot: u64,
        subcommittee_index: u64,
        beacon_block_root: &str,
    ) -> Result<SyncContributionDto, BnError> {
        let path = format!(
            "eth/v1/validator/sync_committee_contribution?slot={slot}&subcommittee_index={subcommittee_index}&beacon_block_root={beacon_block_root}"
        );
        let resp = self.get(&path).await?;
        let data: DataResponse<SyncContributionDto> = resp.json().await?;
        Ok(data.data)
    }

    /// `POST /eth/v1/validator/contribution_and_proofs`
    pub async fn post_contribution_and_proofs(
        &self,
        contributions: &[SignedContributionAndProofDto],
    ) -> Result<(), BnError> {
        self.post("eth/v1/validator/contribution_and_proofs", contributions)
            .await?;
        Ok(())
    }

    // ── Non-DVT selection endpoints (identity pass-through, OQ2) ─────────────

    /// `POST /eth/v1/validator/beacon_committee_selections`
    ///
    /// Non-DVT: returns the input unchanged (identity pass-through per OQ2).
    pub async fn beacon_committee_selections(
        &self,
        selections: &[BeaconCommitteeSelection],
    ) -> Result<Vec<BeaconCommitteeSelection>, BnError> {
        let resp = self
            .post("eth/v1/validator/beacon_committee_selections", selections)
            .await?;
        let data: DataResponse<Vec<BeaconCommitteeSelection>> = resp.json().await?;
        Ok(data.data)
    }

    /// `POST /eth/v1/validator/sync_committee_selections`
    ///
    /// Non-DVT: returns the input unchanged (identity pass-through per OQ2).
    pub async fn sync_committee_selections(
        &self,
        selections: &[SyncCommitteeSelection],
    ) -> Result<Vec<SyncCommitteeSelection>, BnError> {
        let resp = self
            .post("eth/v1/validator/sync_committee_selections", selections)
            .await?;
        let data: DataResponse<Vec<SyncCommitteeSelection>> = resp.json().await?;
        Ok(data.data)
    }

    // ── Liveness (doppelganger detection) ────────────────────────────────────

    /// `POST /eth/v1/validator/liveness/{epoch}`
    ///
    /// Used by the doppelganger protection path (`D-doppelganger-bn-liveness-endpoint`).
    pub async fn validator_liveness(
        &self,
        epoch: u64,
        validator_indices: &[u64],
    ) -> Result<Vec<ValidatorLivenessItem>, BnError> {
        let path = format!("eth/v1/validator/liveness/{epoch}");
        let body: Vec<String> = validator_indices.iter().map(|i| i.to_string()).collect();
        let resp = self.post(&path, &body).await?;
        let data: DataResponse<Vec<ValidatorLivenessItem>> = resp.json().await?;
        Ok(data.data)
    }

    // ── Block pool submissions ────────────────────────────────────────────────

    /// `POST /eth/v1/beacon/blocks` — submit a signed beacon block (JSON).
    pub async fn publish_block_v1(&self, block: &JsonValue) -> Result<(), BnError> {
        self.post("eth/v1/beacon/blocks", block).await?;
        Ok(())
    }

    /// `POST /eth/v2/beacon/blocks` — submit a signed beacon block (JSON, fork-tagged).
    pub async fn publish_block_v2(
        &self,
        block: &JsonValue,
        consensus_version: &str,
    ) -> Result<(), BnError> {
        self.send_with_failover("eth/v2/beacon/blocks", |url| {
            self.client
                .post(url)
                .header("Eth-Consensus-Version", consensus_version)
                .json(block)
        })
        .await
        .map(|_| ())
    }

    // ── Pool submissions ──────────────────────────────────────────────────────

    /// `POST /eth/v1/beacon/pool/attestations`
    pub async fn submit_attestations(&self, attestations: &JsonValue) -> Result<(), BnError> {
        self.post("eth/v1/beacon/pool/attestations", attestations)
            .await?;
        Ok(())
    }

    /// `POST /eth/v1/beacon/pool/sync_committees`
    pub async fn submit_sync_committee_messages(
        &self,
        messages: &JsonValue,
    ) -> Result<(), BnError> {
        self.post("eth/v1/beacon/pool/sync_committees", messages)
            .await?;
        Ok(())
    }

    /// `POST /eth/v1/beacon/pool/voluntary_exits`
    pub async fn submit_voluntary_exit(&self, exit: &JsonValue) -> Result<(), BnError> {
        self.post("eth/v1/beacon/pool/voluntary_exits", exit)
            .await?;
        Ok(())
    }

    /// `POST /eth/v1/beacon/pool/attester_slashings`
    pub async fn submit_attester_slashing(&self, slashing: &JsonValue) -> Result<(), BnError> {
        self.post("eth/v1/beacon/pool/attester_slashings", slashing)
            .await?;
        Ok(())
    }

    /// `POST /eth/v1/beacon/pool/proposer_slashings`
    pub async fn submit_proposer_slashing(&self, slashing: &JsonValue) -> Result<(), BnError> {
        self.post("eth/v1/beacon/pool/proposer_slashings", slashing)
            .await?;
        Ok(())
    }

    /// `POST /eth/v1/beacon/pool/bls_to_execution_changes`
    pub async fn submit_bls_to_execution_change(&self, change: &JsonValue) -> Result<(), BnError> {
        self.post("eth/v1/beacon/pool/bls_to_execution_changes", change)
            .await?;
        Ok(())
    }

    // ── Events SSE ───────────────────────────────────────────────────────────

    /// Returns the number of configured beacon nodes.
    ///
    /// Phase-7 callers use this to reconnect the SSE duty-refresh stream to the
    /// next node on failure (round-robin with `events_url_for_node`).
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Returns the SSE events URL for the node at `idx`.
    ///
    /// `idx` must be less than `node_count()`. Returns `BnError::AllFailed` if
    /// `idx` is out of range or the URL cannot be constructed.
    pub fn events_url_for_node(&self, idx: usize, topics: &[&str]) -> Result<Url, BnError> {
        let base = self.nodes.get(idx).ok_or_else(|| {
            BnError::AllFailed(format!(
                "node index {idx} out of range (node_count={})",
                self.nodes.len()
            ))
        })?;
        let topics_str = topics.join(",");
        let url = base.join(&format!("eth/v1/events?topics={topics_str}"))?;
        Ok(url)
    }

    /// Returns the URL for `/eth/v1/events?topics=head,finalized_checkpoint,...`.
    ///
    /// Callers open the SSE stream themselves using `reqwest::Client::get(url).send()`.
    /// Convenience wrapper for `events_url_for_node(0, topics)`.
    pub fn events_url(&self, topics: &[&str]) -> Result<Url, BnError> {
        self.events_url_for_node(0, topics)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bn_client_constructs_with_valid_url() {
        let url = Url::parse("http://127.0.0.1:5052/").expect("valid URL");
        let _client = BnClient::new(vec![url]);
    }

    #[test]
    fn events_url_format() {
        let url = Url::parse("http://127.0.0.1:5052/").expect("valid URL");
        let client = BnClient::new(vec![url]);
        let events_url = client
            .events_url(&["head", "finalized_checkpoint"])
            .expect("events URL construction");
        let s = events_url.as_str();
        assert!(s.contains("eth/v1/events"), "must contain path: {s}");
        assert!(s.contains("head"), "must contain head topic: {s}");
        assert!(
            s.contains("finalized_checkpoint"),
            "must contain finalized_checkpoint topic: {s}"
        );
    }

    #[test]
    fn bn_error_unavailable_is_distinct() {
        // Confirm the error variant is correctly distinguished from AllFailed.
        let err = BnError::Unavailable;
        assert!(err.to_string().contains("503"), "must mention 503: {err}");
    }

    #[test]
    fn node_count_returns_correct_count() {
        let url1 = Url::parse("http://127.0.0.1:5052/").expect("valid URL");
        let url2 = Url::parse("http://127.0.0.1:5053/").expect("valid URL");
        let client = BnClient::new(vec![url1, url2]);
        assert_eq!(client.node_count(), 2);
    }

    #[test]
    fn events_url_for_node_uses_correct_base() {
        let url1 = Url::parse("http://127.0.0.1:5052/").expect("valid URL");
        let url2 = Url::parse("http://127.0.0.1:5053/").expect("valid URL");
        let client = BnClient::new(vec![url1, url2]);

        let u0 = client
            .events_url_for_node(0, &["head"])
            .expect("node 0 URL");
        assert!(
            u0.as_str().contains("5052"),
            "node 0 must use port 5052: {u0}"
        );

        let u1 = client
            .events_url_for_node(1, &["head"])
            .expect("node 1 URL");
        assert!(
            u1.as_str().contains("5053"),
            "node 1 must use port 5053: {u1}"
        );
    }

    #[test]
    fn events_url_for_node_out_of_range_errors() {
        let url = Url::parse("http://127.0.0.1:5052/").expect("valid URL");
        let client = BnClient::new(vec![url]);
        let err = client
            .events_url_for_node(5, &["head"])
            .expect_err("out-of-range index must error");
        assert!(
            matches!(err, BnError::AllFailed(_)),
            "expected AllFailed, got: {err}"
        );
    }

    #[test]
    fn events_url_convenience_delegates_to_node_zero() {
        let url = Url::parse("http://127.0.0.1:5052/").expect("valid URL");
        let client = BnClient::new(vec![url]);
        let via_convenience = client
            .events_url(&["head"])
            .expect("convenience events URL");
        let via_indexed = client
            .events_url_for_node(0, &["head"])
            .expect("indexed events URL");
        assert_eq!(via_convenience.as_str(), via_indexed.as_str());
    }
}
