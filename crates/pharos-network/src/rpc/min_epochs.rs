//! Minimum retained history window for `BlocksByRange` / `BlocksByRoot`.
//!
//! Per `specs/phase0/p2p-interface.md:346-353`.

use pharos_types::EthSpec;

/// Minimum number of epochs of block history a node must serve.
///
/// Formula (per `p2p-interface.md:346-353`):
/// `MIN_VALIDATOR_WITHDRAWABILITY_DELAY + CHURN_LIMIT_QUOTIENT / 2`
///
/// Mainnet: 256 + 65536 / 2 = 33024 epochs.
/// Minimal: 256 + 32 / 2   = 272 epochs.
pub const fn compute_min_epochs_for_block_requests<E: EthSpec>() -> u64 {
    E::MIN_VALIDATOR_WITHDRAWABILITY_DELAY + E::CHURN_LIMIT_QUOTIENT / 2
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_types::MainnetEthSpec;

    #[test]
    fn mainnet_min_epochs_is_33024() {
        assert_eq!(
            compute_min_epochs_for_block_requests::<MainnetEthSpec>(),
            33024
        );
    }
}
