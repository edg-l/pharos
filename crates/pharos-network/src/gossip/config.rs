//! Spec-conforming gossipsub configuration for Ethereum CL.
//!
//! Parameters per `specs/phase0/p2p-interface.md:439-450`.
//! Message-size helper per `p2p-interface.md:418-421`.

use std::time::Duration;

use libp2p::gossipsub::{self, MessageAuthenticity, ValidationMode};
use pharos_types::EthSpec;

use crate::codec::MAX_PAYLOAD_SIZE;
use crate::error::NetworkError;
use crate::gossip::message_id::compute_message_id;

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
/// Parameters per `p2p-interface.md:439-450`.
pub fn gossipsub_config<E: EthSpec>() -> Result<gossipsub::Config, NetworkError> {
    let cache_ms = E::SLOT_DURATION_MS
        .saturating_mul(E::SLOTS_PER_EPOCH)
        .saturating_mul(2);
    let cache_duration = Duration::from_millis(cache_ms);

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
        .message_id_fn(|m| gossipsub::MessageId::from(compute_message_id(&m.data).to_vec()))
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
pub fn gossipsub_behaviour<E: EthSpec>() -> Result<gossipsub::Behaviour, NetworkError> {
    let cfg = gossipsub_config::<E>()?;
    gossipsub::Behaviour::new(MessageAuthenticity::Anonymous, cfg)
        .map_err(|e| NetworkError::Libp2p(format!("gossipsub behaviour: {e}")))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_types::MainnetEthSpec;

    /// `gossipsub_config::<MainnetEthSpec>()` succeeds and produces a config
    /// where `mesh_n_low <= mesh_n <= mesh_n_high`.
    #[test]
    fn config_builds_for_mainnet() {
        let cfg = gossipsub_config::<MainnetEthSpec>().expect("config build failed");
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
        let cfg = gossipsub_config::<MainnetEthSpec>().expect("config build failed");
        assert_eq!(cfg.mesh_n(), 8);
        assert_eq!(cfg.mesh_n_low(), 6);
        assert_eq!(cfg.mesh_n_high(), 12);
        assert_eq!(cfg.gossip_lazy(), 6);
    }
}
