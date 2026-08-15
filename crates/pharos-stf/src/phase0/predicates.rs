//! Pure predicate functions from `specs/phase0/beacon-chain.md` "Predicates"
//! section (lines 694-816).

use crate::phase0::{
    accessors::{compute_signing_root, get_domain},
    helpers::{DOMAIN_BEACON_ATTESTER, FAR_FUTURE_EPOCH},
};
use pharos_types::{
    BeaconStateView, EthSpec,
    phase0::{AttestationData, Epoch, IndexedAttestation, Validator},
};

/// Check if a validator is active at `epoch`.
///
/// Per `specs/phase0/beacon-chain.md:699-703`.
pub fn is_active_validator(v: &Validator, epoch: u64) -> bool {
    v.activation_epoch.0 <= epoch && epoch < v.exit_epoch.0
}

/// Check if a validator is eligible to be placed into the activation queue.
///
/// Per `specs/phase0/beacon-chain.md:709-716`.
pub fn is_eligible_for_activation_queue<E: pharos_types::EthSpec>(v: &Validator) -> bool {
    v.activation_eligibility_epoch.0 == FAR_FUTURE_EPOCH
        && v.effective_balance.0 == E::MAX_EFFECTIVE_BALANCE
}

/// Check if a validator is eligible for activation given the finalized epoch.
///
/// Per `specs/phase0/beacon-chain.md:722-731`.
pub fn is_eligible_for_activation(finalized_epoch: Epoch, v: &Validator) -> bool {
    v.activation_eligibility_epoch <= finalized_epoch && v.activation_epoch.0 == FAR_FUTURE_EPOCH
}

/// Check if a validator is slashable at `epoch`.
///
/// Per `specs/phase0/beacon-chain.md:737-743`.
pub fn is_slashable_validator(v: &Validator, epoch: u64) -> bool {
    !v.slashed && v.activation_epoch.0 <= epoch && epoch < v.withdrawable_epoch.0
}

/// Check if two `AttestationData` are slashable under Casper FFG rules.
///
/// Per `specs/phase0/beacon-chain.md:749-759`.
pub fn is_slashable_attestation_data(d1: &AttestationData, d2: &AttestationData) -> bool {
    // Double vote
    (d1 != d2 && d1.target.epoch == d2.target.epoch)
        // Surround vote
        || (d1.source.epoch < d2.source.epoch && d2.target.epoch < d1.target.epoch)
}

/// `is_valid_indexed_attestation` per `specs/phase0/beacon-chain.md:765-779`.
///
/// Checks that attesting indices are sorted, unique, non-empty, and that the
/// aggregate signature is valid (when `verify_signatures` is true).
pub fn is_valid_indexed_attestation<E: EthSpec>(
    state: &E::BeaconState,
    indexed_att: &IndexedAttestation<2048>,
    verify_signatures: bool,
) -> bool {
    let indices = indexed_att.attesting_indices.as_slice();

    // Non-empty and sorted/unique.
    if indices.is_empty() {
        return false;
    }
    for w in indices.windows(2) {
        if w[0] >= w[1] {
            return false;
        }
    }

    if !verify_signatures {
        return true;
    }

    // Collect pubkeys.
    let pubkeys: Vec<pharos_utils::BLSPubkey> = indices
        .iter()
        .filter_map(|i| state.validators().get(i.0 as usize).map(|v| v.pubkey))
        .collect();

    if pubkeys.len() != indices.len() {
        return false;
    }

    let domain = get_domain::<E>(
        state,
        DOMAIN_BEACON_ATTESTER,
        Some(indexed_att.data.target.epoch),
    );
    let signing_root = compute_signing_root(&indexed_att.data, domain);

    pharos_utils::bls::fast_aggregate_verify(
        &pubkeys,
        signing_root.as_slice(),
        &indexed_att.signature,
    )
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use pharos_utils::{BLSPubkey, Bytes32, CommitteeIndex, Epoch, Gwei};

    use super::*;
    use crate::phase0::helpers::FAR_FUTURE_EPOCH;
    use pharos_types::EthSpec;
    use pharos_types::phase0::{Checkpoint, Root};

    fn default_validator() -> Validator {
        Validator {
            pubkey: BLSPubkey::from_array([0u8; 48]),
            withdrawal_credentials: Bytes32::from_array([0u8; 32]),
            effective_balance: Gwei(32_000_000_000),
            slashed: false,
            activation_eligibility_epoch: Epoch(0),
            activation_epoch: Epoch(0),
            exit_epoch: Epoch(FAR_FUTURE_EPOCH),
            withdrawable_epoch: Epoch(FAR_FUTURE_EPOCH),
            ..Validator::default()
        }
    }

    fn default_checkpoint(epoch: u64) -> Checkpoint {
        Checkpoint {
            epoch: Epoch(epoch),
            root: Root::default(),
        }
    }

    fn default_attestation_data(
        source_epoch: u64,
        target_epoch: u64,
        slot: u64,
    ) -> AttestationData {
        use pharos_utils::{CommitteeIndex, Slot};
        AttestationData {
            slot: Slot(slot),
            index: CommitteeIndex(0),
            beacon_block_root: Root::default(),
            source: default_checkpoint(source_epoch),
            target: default_checkpoint(target_epoch),
        }
    }

    #[test]
    fn is_active_validator_active_range() {
        let mut v = default_validator();
        v.activation_epoch = Epoch(5);
        v.exit_epoch = Epoch(10);
        assert!(!is_active_validator(&v, 4));
        assert!(is_active_validator(&v, 5));
        assert!(is_active_validator(&v, 9));
        assert!(!is_active_validator(&v, 10));
    }

    #[test]
    fn is_eligible_for_activation_queue_both_conditions() {
        use pharos_types::MinimalEthSpec;
        let mut v = default_validator();
        // Not eligible: activation_eligibility_epoch already set.
        v.activation_eligibility_epoch = Epoch(0);
        v.effective_balance = Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE);
        assert!(!is_eligible_for_activation_queue::<MinimalEthSpec>(&v));

        // Not eligible: wrong effective balance.
        v.activation_eligibility_epoch = Epoch(FAR_FUTURE_EPOCH);
        v.effective_balance = Gwei(1_000_000_000);
        assert!(!is_eligible_for_activation_queue::<MinimalEthSpec>(&v));

        // Eligible: both conditions met.
        v.activation_eligibility_epoch = Epoch(FAR_FUTURE_EPOCH);
        v.effective_balance = Gwei(MinimalEthSpec::MAX_EFFECTIVE_BALANCE);
        assert!(is_eligible_for_activation_queue::<MinimalEthSpec>(&v));
    }

    #[test]
    fn is_eligible_for_activation_conditions() {
        let mut v = default_validator();
        v.activation_eligibility_epoch = Epoch(3);
        v.activation_epoch = Epoch(FAR_FUTURE_EPOCH);

        // finalized epoch < eligibility epoch: not eligible
        assert!(!is_eligible_for_activation(Epoch(2), &v));
        // finalized epoch == eligibility epoch: eligible
        assert!(is_eligible_for_activation(Epoch(3), &v));

        // already activated: not eligible
        v.activation_epoch = Epoch(4);
        assert!(!is_eligible_for_activation(Epoch(10), &v));
    }

    #[test]
    fn is_slashable_validator_checks() {
        let mut v = default_validator();
        v.activation_epoch = Epoch(5);
        v.withdrawable_epoch = Epoch(20);

        assert!(!is_slashable_validator(&v, 4)); // before activation
        assert!(is_slashable_validator(&v, 5));
        assert!(is_slashable_validator(&v, 19));
        assert!(!is_slashable_validator(&v, 20)); // at withdrawable

        v.slashed = true;
        assert!(!is_slashable_validator(&v, 10)); // already slashed
    }

    #[test]
    fn is_slashable_attestation_data_double_vote() {
        let d1 = default_attestation_data(0, 5, 40);
        let mut d2 = d1.clone();
        // Same target epoch, different data: double vote
        d2.index = CommitteeIndex(1);
        assert!(is_slashable_attestation_data(&d1, &d2));
        // Identical: not slashable
        assert!(!is_slashable_attestation_data(&d1, &d1));
    }

    #[test]
    fn is_slashable_attestation_data_surround_vote() {
        // d1 surrounds d2: d2.source > d1.source and d2.target < d1.target
        let d1 = default_attestation_data(1, 10, 80);
        let d2 = default_attestation_data(2, 9, 72);
        assert!(is_slashable_attestation_data(&d1, &d2));
        // Reverse: not a surround
        assert!(!is_slashable_attestation_data(&d2, &d1));
    }
}
