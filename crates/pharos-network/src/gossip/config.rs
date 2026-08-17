//! Spec-conforming gossipsub configuration for Ethereum CL.
//!
//! Parameters per `specs/phase0/p2p-interface.md:439-450`.
//! Message-size helper per `p2p-interface.md:418-421`.

use std::time::Duration;

use libp2p::gossipsub::{self, MessageAuthenticity, ValidationMode};
use libp2p::gossipsub::{PeerScoreParams, PeerScoreThresholds, TopicScoreParams};
use pharos_types::BeaconSpec;

use crate::codec::MAX_PAYLOAD_SIZE;
use crate::error::NetworkError;
use crate::gossip::message_id::compute_message_id;
use crate::topics::GossipTopicKind;
use crate::types::ForkDigest;

/// Maximum gossipsub transmit size.
///
/// Per `p2p-interface.md:418-421`:
/// `max = 32 + MAX_PAYLOAD_SIZE + MAX_PAYLOAD_SIZE/6 + 1024`, floored at 1 MiB.
const fn max_message_size() -> usize {
    let a = 32 + MAX_PAYLOAD_SIZE + MAX_PAYLOAD_SIZE / 6 + 1024;
    if a > 1024 * 1024 { a } else { 1024 * 1024 }
}

/// Build a spec-conforming `gossipsub::Config` for preset `E`.
///
/// The `duplicate_cache_time` window is `2 * SLOTS_PER_EPOCH * SLOT_DURATION_MS`
/// so that it scales with the preset (mainnet: 12 s × 32 × 2 = 768 s).
///
/// `phase0_fork_digest` is captured once from the `ForkContext` at construction
/// time and used to dispatch between the phase-0 and altair message-id formulas
/// per `specs/altair/p2p-interface.md:163-171`.
///
/// Parameters per `p2p-interface.md:439-450`.
pub fn gossipsub_config<E: BeaconSpec>(
    phase0_fork_digest: ForkDigest,
) -> Result<gossipsub::Config, NetworkError> {
    let cache_ms = E::SLOT_DURATION_MS
        .saturating_mul(E::SLOTS_PER_EPOCH)
        .saturating_mul(2);
    let cache_duration = Duration::from_millis(cache_ms);

    // Capture the phase-0 fork digest once; the closure is called for every
    // incoming message, so we keep it as a `[u8; 4]` (Copy).
    let phase0_fd_bytes = phase0_fork_digest.into_inner();

    let cfg = gossipsub::ConfigBuilder::default()
        .mesh_n(8)
        .mesh_n_low(6)
        .mesh_n_high(12)
        .gossip_lazy(6)
        .heartbeat_interval(Duration::from_millis(700))
        .fanout_ttl(Duration::from_secs(60))
        .history_length(6)
        .history_gossip(3)
        .duplicate_cache_time(cache_duration)
        .validation_mode(ValidationMode::Anonymous)
        .message_id_fn(move |m| {
            gossipsub::MessageId::from(
                compute_message_id(m.topic.as_str(), &m.data, &phase0_fd_bytes).to_vec(),
            )
        })
        .max_transmit_size(max_message_size())
        .validate_messages()
        .build()
        .map_err(|e| NetworkError::Libp2p(format!("gossipsub config: {e}")))?;

    Ok(cfg)
}

/// Build an `Anonymous`-mode `gossipsub::Behaviour` using the spec config.
///
/// Anonymous mode matches `StrictNoSign` from the Ethereum gossipsub spec
/// (`p2p-interface.md:482-484`): no source, no seqno, no signature.
///
/// `phase0_fork_digest` is used to dispatch between the phase-0 and altair
/// message-id formulas per `specs/altair/p2p-interface.md:163-171`.
pub fn gossipsub_behaviour<E: BeaconSpec>(
    phase0_fork_digest: ForkDigest,
) -> Result<gossipsub::Behaviour, NetworkError> {
    let cfg = gossipsub_config::<E>(phase0_fork_digest)?;
    gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, cfg)
        .map_err(|e| NetworkError::Libp2p(format!("gossipsub behaviour: {e}")))
}

// ── Peer scoring (gossipsub v1.1) ───────────────────────────────────────────────
//
// Pharos-TUNED peer-score parameters per ADR `D-gossipsub-peer-scoring`. The
// spec (`p2p-interface.md:452-455`) leaves the v1.1 scoring numerics
// unspecified ("under investigation"); only the topology / decay-interval pieces
// (`D`, `D_low/high`, `D_lazy`, `heartbeat_interval`, `mcache*`, `seen_ttl` at
// `p2p-interface.md:439-450`) are spec-mandated and live in `gossipsub_config`.
// Lighthouse is a cross-check reference only; deviations are documented in the
// ADR. Native gossipsub is the SOLE authority for gossip-quality + slow-peer
// scoring; `RealScorer` no longer carries a gossip component (ADR §7.4).

/// Score counter `decay_interval`. The gossipsub engine REQUIRES this be at
/// least 1 s (`PeerScoreParams::validate`), so although the spec heartbeat is
/// 0.7 s (`p2p-interface.md:443`) we use the engine minimum of 1 s — the
/// smallest interval the engine accepts and the closest the engine permits to
/// the heartbeat tick (ADR `D-gossipsub-peer-scoring`, decay-interval decision).
const DECAY_INTERVAL: Duration = Duration::from_secs(1);

/// Counter value below which it is treated as 0 (1% of peak).
const DECAY_TO_ZERO: f64 = 0.01;

/// One epoch as a `Duration` for preset `E` (`SLOTS_PER_EPOCH * SLOT_DURATION_MS`).
fn epoch_duration<E: BeaconSpec>() -> Duration {
    Duration::from_millis(E::SLOT_DURATION_MS.saturating_mul(E::SLOTS_PER_EPOCH))
}

/// One slot as a `Duration` for preset `E`.
fn slot_duration<E: BeaconSpec>() -> Duration {
    Duration::from_millis(E::SLOT_DURATION_MS)
}

/// Decay factor that reaches [`DECAY_TO_ZERO`] after `span`, evaluated against
/// the [`DECAY_INTERVAL`] base (the rate at which gossipsub decays counters).
fn decay_over(span: Duration) -> f64 {
    gossipsub::score_parameter_decay_with_base(span, DECAY_INTERVAL, DECAY_TO_ZERO)
}

/// Build the Pharos-tuned global [`PeerScoreParams`] + [`PeerScoreThresholds`]
/// for preset `E` (ADR `D-gossipsub-peer-scoring`).
///
/// The returned `PeerScoreParams.topics` map is empty; per-topic params are
/// applied at subscription time via [`topic_score_params`] +
/// `Behaviour::set_topic_params`. Both structs pass the engine's own
/// `validate()`.
pub fn peer_score_params<E: BeaconSpec>() -> (PeerScoreParams, PeerScoreThresholds) {
    let ten_epochs = epoch_duration::<E>().saturating_mul(10);

    let params = PeerScoreParams {
        topics: std::collections::HashMap::new(),
        // Cap the positive aggregate topic contribution (anti score-farming).
        topic_score_cap: 3200.0,
        // App-specific bridge is not wired this phase; unity weight keeps a
        // future bridge 1:1. Pharos feeds 0 today.
        app_specific_weight: 1.0,
        // P6 IP-colocation: quadratic penalty past 10 peers/IP (NAT tolerance).
        ip_colocation_factor_weight: -8.0,
        ip_colocation_factor_threshold: 10.0,
        ip_colocation_factor_whitelist: std::collections::HashSet::new(),
        // P7 behaviour penalties (re-GRAFT before backoff, unfulfilled IWANT):
        // quadratic past 6 incidents, slow 10-epoch decay.
        behaviour_penalty_weight: -16.0,
        behaviour_penalty_threshold: 6.0,
        behaviour_penalty_decay: decay_over(ten_epochs),
        // Counter decay interval (engine-minimum 1 s; see DECAY_INTERVAL).
        decay_interval: DECAY_INTERVAL,
        decay_to_zero: DECAY_TO_ZERO,
        // Retain a disconnected peer's counters for one epoch (flap tolerance).
        retain_score: epoch_duration::<E>(),
        // Slow-peer penalty — subsumes the former RealScorer SlowPeer event.
        slow_peer_weight: -2.0,
        slow_peer_threshold: 0.0,
        slow_peer_decay: decay_over(ten_epochs),
    };

    let thresholds = PeerScoreThresholds {
        gossip_threshold: -4000.0,
        publish_threshold: -8000.0,
        graylist_threshold: -16000.0,
        accept_px_threshold: 100.0,
        opportunistic_graft_threshold: 5.0,
    };

    (params, thresholds)
}

/// Build the Pharos-tuned per-topic [`TopicScoreParams`] for `kind` under preset
/// `E` (ADR `D-gossipsub-peer-scoring`).
///
/// The load-bearing decision is the relative `topic_weight`: `beacon_block`
/// (0.8) strictly outweighs any attestation subnet (0.3). Each topic's P2/P3
/// caps + thresholds are sized to its expected message rate; the P4
/// invalid-message penalty is strongly negative on every topic.
pub fn topic_score_params<E: BeaconSpec>(kind: &GossipTopicKind) -> TopicScoreParams {
    let slot = slot_duration::<E>();
    let epoch = epoch_duration::<E>();

    // P1 time-in-mesh is uniform across topics: a small reward for stable
    // membership, capped so it cannot dominate delivery-based score.
    let time_in_mesh_weight = 0.03;
    let time_in_mesh_quantum = slot;
    let time_in_mesh_cap = 300.0;

    // Per-kind tuning: (topic_weight, P2 first-delivery weight/cap,
    // P3 mesh-delivery weight/cap/threshold, activation slots).
    let (topic_weight, p2_weight, p2_cap, p3_weight, p3_cap, p3_threshold, activation_slots) =
        match kind {
            // Highest-value, low-rate (~1 msg/slot).
            GossipTopicKind::BeaconBlock => (0.8, 1.0, 4.0, -0.5, 4.0, 1.0, 4),
            // Aggregates: moderate value, low rate.
            GossipTopicKind::BeaconAggregateAndProof => (0.5, 0.1, 200.0, -0.05, 200.0, 50.0, 4),
            // Unaggregated attestation subnets: high rate, individually low value;
            // strictly below beacon_block.
            GossipTopicKind::BeaconAttestation(_) => (0.3, 0.02, 300.0, -0.01, 300.0, 60.0, 16),
            // Sync-committee aggregate contribution.
            GossipTopicKind::SyncCommitteeContributionAndProof => {
                (0.3, 0.1, 200.0, -0.05, 200.0, 50.0, 4)
            }
            // Sync-committee subnets: subnet-style, below beacon_block.
            GossipTopicKind::SyncCommittee(_) => (0.2, 0.05, 200.0, -0.02, 200.0, 40.0, 16),
            // Blob-sidecar subnets: per-block, moderate rate.
            GossipTopicKind::BlobSidecar(_) => (0.3, 0.1, 50.0, -0.05, 50.0, 8.0, 4),
            // Data-column-sidecar subnets (PeerDAS).
            GossipTopicKind::DataColumnSidecar(_) => (0.3, 0.1, 50.0, -0.05, 50.0, 8.0, 4),
            // Low-rate operations: small positive weight, harsh on invalid.
            GossipTopicKind::VoluntaryExit
            | GossipTopicKind::ProposerSlashing
            | GossipTopicKind::AttesterSlashing
            | GossipTopicKind::BlsToExecutionChange => (0.05, 0.05, 5.0, 0.0, 0.0, 0.0, 4),
            // Light-client updates: low-rate informational.
            GossipTopicKind::LightClientFinalityUpdate
            | GossipTopicKind::LightClientOptimisticUpdate => (0.05, 0.05, 5.0, 0.0, 0.0, 0.0, 4),
        };

    // P3 is disabled (weight 0) for the low-rate operation/LC topics where a
    // mesh-delivery deficit penalty is meaningless; the engine requires the
    // associated cap/threshold/decay be inert in that case. The `0.5` decays
    // used in the disabled branch are arbitrary in-range placeholders: the
    // engine skips decay validation when the corresponding weight is 0, so the
    // value is never read. Keep the weight at 0 when changing them.
    let p3_disabled = p3_weight == 0.0;

    TopicScoreParams {
        topic_weight,
        // P1: time in mesh.
        time_in_mesh_weight,
        time_in_mesh_quantum,
        time_in_mesh_cap,
        // P2: first-message deliveries, decaying over one epoch.
        first_message_deliveries_weight: p2_weight,
        first_message_deliveries_decay: decay_over(epoch),
        first_message_deliveries_cap: p2_cap,
        // P3: mesh-message deliveries.
        mesh_message_deliveries_weight: p3_weight,
        mesh_message_deliveries_decay: if p3_disabled { 0.5 } else { decay_over(epoch) },
        mesh_message_deliveries_cap: if p3_disabled { 0.0 } else { p3_cap },
        mesh_message_deliveries_threshold: if p3_disabled { 0.0 } else { p3_threshold },
        mesh_message_deliveries_window: Duration::from_millis(20),
        mesh_message_deliveries_activation: slot.saturating_mul(activation_slots),
        // P3b: sticky mesh-failure penalty.
        mesh_failure_penalty_weight: if p3_disabled { 0.0 } else { p3_weight },
        mesh_failure_penalty_decay: if p3_disabled { 0.5 } else { decay_over(epoch) },
        // P4: invalid-message deliveries — strongly negative on every topic,
        // decaying over 10 epochs so a bad peer cannot quickly shed it.
        invalid_message_deliveries_weight: -100.0,
        invalid_message_deliveries_decay: decay_over(epoch.saturating_mul(10)),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_types::MainnetBeaconSpec;

    fn dummy_fork_digest() -> ForkDigest {
        ForkDigest::from_array([0x00, 0x00, 0x00, 0x01])
    }

    /// `gossipsub_config::<MainnetBeaconSpec>()` succeeds and produces a config
    /// where `mesh_n_low <= mesh_n <= mesh_n_high`.
    #[test]
    fn config_builds_for_mainnet() {
        let cfg = gossipsub_config::<MainnetBeaconSpec>(dummy_fork_digest())
            .expect("config build failed");
        assert!(
            cfg.mesh_n_low() <= cfg.mesh_n() && cfg.mesh_n() <= cfg.mesh_n_high(),
            "mesh invariant violated: low={} n={} high={}",
            cfg.mesh_n_low(),
            cfg.mesh_n(),
            cfg.mesh_n_high()
        );
    }

    /// Verify the specific mesh parameters match the spec.
    #[test]
    fn config_mesh_params() {
        let cfg = gossipsub_config::<MainnetBeaconSpec>(dummy_fork_digest())
            .expect("config build failed");
        assert_eq!(cfg.mesh_n(), 8);
        assert_eq!(cfg.mesh_n_low(), 6);
        assert_eq!(cfg.mesh_n_high(), 12);
        assert_eq!(cfg.gossip_lazy(), 6);
    }

    /// `peer_score_params::<E>()` produces params + thresholds that both pass
    /// the gossipsub engine's own `validate()` (so `with_peer_score` will
    /// accept them at construction).
    #[test]
    fn peer_score_params_validate() {
        let (params, thresholds) = peer_score_params::<MainnetBeaconSpec>();
        params
            .validate()
            .expect("Pharos PeerScoreParams must pass engine validation");
        thresholds
            .validate()
            .expect("Pharos PeerScoreThresholds must pass engine validation");
    }

    /// Every per-topic param set (one per `GossipTopicKind`) passes the engine's
    /// `TopicScoreParams::validate()`.
    #[test]
    fn topic_score_params_validate() {
        let kinds = [
            GossipTopicKind::BeaconBlock,
            GossipTopicKind::BeaconAggregateAndProof,
            GossipTopicKind::BeaconAttestation(7),
            GossipTopicKind::SyncCommitteeContributionAndProof,
            GossipTopicKind::SyncCommittee(2),
            GossipTopicKind::BlobSidecar(1),
            GossipTopicKind::DataColumnSidecar(3),
            GossipTopicKind::VoluntaryExit,
            GossipTopicKind::ProposerSlashing,
            GossipTopicKind::AttesterSlashing,
            GossipTopicKind::BlsToExecutionChange,
            GossipTopicKind::LightClientFinalityUpdate,
            GossipTopicKind::LightClientOptimisticUpdate,
        ];
        for kind in kinds {
            topic_score_params::<MainnetBeaconSpec>(&kind)
                .validate()
                .unwrap_or_else(|e| panic!("topic params for {kind:?} invalid: {e}"));
        }
    }

    /// Threshold ordering invariant: `graylist <= publish <= gossip <= 0 <=
    /// accept_px` and `0 <= opportunistic_graft` (gossipsub v1.1 requirement).
    #[test]
    fn thresholds_are_ordered() {
        let (_params, t) = peer_score_params::<MainnetBeaconSpec>();
        assert!(
            t.graylist_threshold <= t.publish_threshold,
            "graylist {} must be <= publish {}",
            t.graylist_threshold,
            t.publish_threshold
        );
        assert!(
            t.publish_threshold <= t.gossip_threshold,
            "publish {} must be <= gossip {}",
            t.publish_threshold,
            t.gossip_threshold
        );
        assert!(
            t.gossip_threshold <= 0.0,
            "gossip threshold {} must be <= 0",
            t.gossip_threshold
        );
        assert!(
            t.accept_px_threshold >= 0.0,
            "accept_px {} must be >= 0",
            t.accept_px_threshold
        );
        assert!(
            t.opportunistic_graft_threshold >= 0.0,
            "opportunistic_graft {} must be >= 0",
            t.opportunistic_graft_threshold
        );
    }

    /// The load-bearing topic-weight decision: `beacon_block` strictly outweighs
    /// an attestation subnet, so a single high-rate subnet cannot let a peer
    /// out-score block delivery.
    #[test]
    fn beacon_block_outweighs_attestation_subnet() {
        let block = topic_score_params::<MainnetBeaconSpec>(&GossipTopicKind::BeaconBlock);
        let attn = topic_score_params::<MainnetBeaconSpec>(&GossipTopicKind::BeaconAttestation(0));
        assert!(
            block.topic_weight > attn.topic_weight,
            "beacon_block weight {} must exceed attestation-subnet weight {}",
            block.topic_weight,
            attn.topic_weight
        );
    }
}
