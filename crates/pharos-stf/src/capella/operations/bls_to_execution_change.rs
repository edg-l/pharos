//! `process_bls_to_execution_change` for Capella.
//!
//! Per `specs/capella/beacon-chain.md` Block processing → New
//! `process_bls_to_execution_change`.
//!
//! The signing domain is FORK-AGNOSTIC:
//!   `compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, GENESIS_FORK_VERSION,
//!                   genesis_validators_root)`
//! — it uses `GENESIS_FORK_VERSION`, not the state's current fork version.

use pharos_ssz::SszSequence;
use pharos_types::{
    BeaconSpec,
    capella::{BeaconState, operations::SignedBLSToExecutionChange},
    fork::DOMAIN_BLS_TO_EXECUTION_CHANGE,
};

use crate::capella::helpers::{BLS_WITHDRAWAL_PREFIX, ETH1_ADDRESS_WITHDRAWAL_PREFIX};
use crate::error::StateTransitionError;
use crate::phase0::accessors::{compute_domain, compute_signing_root};

/// `process_bls_to_execution_change` per `specs/capella/beacon-chain.md`.
///
/// Checks:
/// 1. `validator_index < len(state.validators)` — validator index bound.
/// 2. `validator.withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX` — must be BLS cred.
/// 3. `validator.withdrawal_credentials[1:] == hash(from_bls_pubkey)[1:]` — pubkey hash.
/// 4. BLS signature over `compute_signing_root(address_change, domain)` with the
///    fork-agnostic domain (gated by `verify_signatures`).
///
/// On success, mutates `withdrawal_credentials` to:
///   `ETH1_ADDRESS_WITHDRAWAL_PREFIX || b"\x00"*11 || to_execution_address`.
pub fn process_bls_to_execution_change<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const BYTES_PER_LOGS_BLOOM: u64,
    const MAX_EXTRA_DATA_BYTES: u64,
    E: BeaconSpec,
>(
    state: &mut BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        BYTES_PER_LOGS_BLOOM,
        MAX_EXTRA_DATA_BYTES,
    >,
    signed_address_change: &SignedBLSToExecutionChange,
    verify_signatures: bool,
) -> Result<(), StateTransitionError> {
    let address_change = &signed_address_change.message;
    let num_validators = state.validators.len();

    // Check 1: validator index in bounds.
    if address_change.validator_index.0 as usize >= num_validators {
        return Err(StateTransitionError::InvalidBlsToExecutionChange(
            "validator index out of bounds",
        ));
    }

    let validator = state
        .validators
        .get(address_change.validator_index.0 as usize)
        .ok_or(StateTransitionError::InvalidBlsToExecutionChange(
            "validator index out of bounds",
        ))?;

    let creds = validator.withdrawal_credentials;

    // Check 2: withdrawal_credentials[0] == BLS_WITHDRAWAL_PREFIX (0x00).
    if creds.as_slice()[0] != BLS_WITHDRAWAL_PREFIX {
        return Err(StateTransitionError::InvalidBlsToExecutionChange(
            "withdrawal credentials not BLS prefix",
        ));
    }

    // Check 3: withdrawal_credentials[1:] == hash(from_bls_pubkey)[1:].
    let pubkey_hash = pharos_utils::hash::hash(address_change.from_bls_pubkey.as_slice());
    if creds.as_slice()[1..] != pubkey_hash.as_slice()[1..] {
        return Err(StateTransitionError::InvalidBlsToExecutionChange(
            "withdrawal credentials pubkey hash mismatch",
        ));
    }

    // Check 4: BLS signature (fork-agnostic domain).
    if verify_signatures {
        // Fork-agnostic domain: uses GENESIS_FORK_VERSION, not the current fork.
        let domain = compute_domain(
            DOMAIN_BLS_TO_EXECUTION_CHANGE,
            E::GENESIS_FORK_VERSION,
            &state.genesis_validators_root,
        );
        let signing_root = compute_signing_root(address_change, domain);

        let valid = pharos_utils::bls::verify(
            &address_change.from_bls_pubkey,
            signing_root.as_slice(),
            &signed_address_change.signature,
        )
        .unwrap_or(false);
        if !valid {
            return Err(StateTransitionError::InvalidBlsToExecutionChange(
                "invalid BLS signature",
            ));
        }
    }

    // Flip credentials to ETH1_ADDRESS_WITHDRAWAL_PREFIX + b"\x00"*11 + to_execution_address.
    let mut new_creds = [0u8; 32];
    new_creds[0] = ETH1_ADDRESS_WITHDRAWAL_PREFIX;
    // bytes [1..12] remain 0x00 (already zero-initialised).
    let addr_bytes = address_change.to_execution_address.as_slice();
    new_creds[12..32].copy_from_slice(addr_bytes);

    let mut validator = state
        .validators
        .get(address_change.validator_index.0 as usize)
        .expect("validator index already bounds-checked above")
        .clone();
    validator.withdrawal_credentials = pharos_utils::Bytes32::from_array(new_creds);
    validator.invalidate_cache();
    state.validators = state
        .validators
        .with_set(address_change.validator_index.0 as usize, validator)
        .map_err(StateTransitionError::Ssz)?;

    Ok(())
}
