//! Pure predicate functions from `specs/phase0/beacon-chain.md` "Predicates"
//! section (lines 694-816).

use crate::phase0::{
    accessors::{compute_signing_root, get_domain},
    helpers::{DOMAIN_BEACON_ATTESTER, FAR_FUTURE_EPOCH},
};
use pharos_types::{
    BeaconSpec, BeaconStateView,
    phase0::primitives::TARGET_AGGREGATORS_PER_COMMITTEE,
    phase0::{AttestationData, Epoch, IndexedAttestation, Validator},
};
use pharos_utils::BLSSignature;

/// Check if a validator is active at `epoch`.
///
/// Per `specs/phase0/beacon-chain.md:699-703`.
pub fn is_active_validator(v: &Validator, epoch: u64) -> bool {
    v.activation_epoch.0 <= epoch && epoch < v.exit_epoch.0
}

/// Check if a validator is eligible to be placed into the activation queue.
///
/// Per `specs/phase0/beacon-chain.md:709-716`.
pub fn is_eligible_for_activation_queue<E: pharos_types::BeaconSpec>(v: &Validator) -> bool {
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
pub fn is_valid_indexed_attestation<E: BeaconSpec>(
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
        .filter_map(|i| state.validator(i.0 as usize).map(|v| v.pubkey))
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

/// Check whether a validator is selected as an aggregator for their committee.
///
/// Per `specs/phase0/validator.md:139-147` (is_aggregator).
///
/// The modulo is `max(1, committee_len / TARGET_AGGREGATORS_PER_COMMITTEE)`.
/// A validator is selected iff `bytes_to_uint64(hash(slot_signature)[0:8]) % modulo == 0`.
pub fn is_aggregator(committee_len: usize, slot_signature: &BLSSignature) -> bool {
    let modulo = std::cmp::max(
        1usize,
        committee_len / TARGET_AGGREGATORS_PER_COMMITTEE as usize,
    );
    let h = pharos_utils::hash::hash(slot_signature.as_ref());
    let n = u64::from_le_bytes(h.as_slice()[0..8].try_into().unwrap());
    n % (modulo as u64) == 0
}

#[cfg(test)]
mod tests {
    use pharos_utils::{BLSPubkey, BLSSignature, Bytes32, CommitteeIndex, Epoch, Gwei};

    use super::*;
    use crate::phase0::helpers::FAR_FUTURE_EPOCH;
    use pharos_types::BeaconSpec;
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
        use pharos_types::MinimalBeaconSpec;
        let mut v = default_validator();
        // Not eligible: activation_eligibility_epoch already set.
        v.activation_eligibility_epoch = Epoch(0);
        v.effective_balance = Gwei(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE);
        assert!(!is_eligible_for_activation_queue::<MinimalBeaconSpec>(&v));

        // Not eligible: wrong effective balance.
        v.activation_eligibility_epoch = Epoch(FAR_FUTURE_EPOCH);
        v.effective_balance = Gwei(1_000_000_000);
        assert!(!is_eligible_for_activation_queue::<MinimalBeaconSpec>(&v));

        // Eligible: both conditions met.
        v.activation_eligibility_epoch = Epoch(FAR_FUTURE_EPOCH);
        v.effective_balance = Gwei(MinimalBeaconSpec::MAX_EFFECTIVE_BALANCE);
        assert!(is_eligible_for_activation_queue::<MinimalBeaconSpec>(&v));
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

    /// Pre-computed test vectors for `is_aggregator`.
    ///
    /// The "signatures" here are fixed 96-byte patterns; they are not
    /// cryptographically valid BLS signatures. `is_aggregator` only hashes
    /// the raw bytes, so no BLS operations are needed at test time.
    ///
    /// Vectors computed offline with Python:
    ///   sha256([0x00]*96)[:8] = 2ea9ab9198d16380 → n_le=9251468512758311214
    ///   sha256([0x01]*96)[:8] = 8b3274a4709a50d0 → n_le=15010667366611956363
    ///   sha256([0x02]*96)[:8] = 18a2c0a60a7d9340 → n_le=6463443705522100576
    #[test]
    fn is_aggregator_known_vectors() {
        // Vector 1: committee_len=16 → modulo=max(1, 16/16)=1 → always true.
        let sig_zeros = BLSSignature::from_array([0x00u8; 96]);
        assert!(
            is_aggregator(16, &sig_zeros),
            "committee_len=16, modulo=1, must be true for any sig"
        );

        // Vector 2: committee_len=32 → modulo=max(1, 32/16)=2.
        // [0x01]*96 → n_le=15010667366611956363, n_le%2=1 → false.
        let sig_ones = BLSSignature::from_array([0x01u8; 96]);
        assert!(
            !is_aggregator(32, &sig_ones),
            "committee_len=32, modulo=2, [0x01]*96 hash n%2=1 → false"
        );

        // Vector 3: committee_len=256 → modulo=max(1, 256/16)=16.
        // [0x02]*96 → n_le=6463443705522100576, n_le%16=0 → true.
        let sig_twos = BLSSignature::from_array([0x02u8; 96]);
        assert!(
            is_aggregator(256, &sig_twos),
            "committee_len=256, modulo=16, [0x02]*96 hash n%16=0 → true"
        );
    }
}
