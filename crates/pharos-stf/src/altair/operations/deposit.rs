//! `process_deposit` (modified in Altair) per `specs/altair/beacon-chain.md:556-572`.
//!
//! Key difference from phase0: when adding a new validator, also initialises
//! `previous_epoch_participation`, `current_epoch_participation`, and
//! `inactivity_scores` to zero.

use pharos_ssz::{SszSequence, TreeHash};
use pharos_types::{
    EthSpec,
    altair::BeaconState,
    phase0::{Deposit, DepositMessage, Epoch, Validator},
};
use pharos_utils::{Bytes32, Gwei, Hash256};

use crate::error::{DepositInvalidReason, StateTransitionError};
use crate::phase0::{
    accessors::compute_domain,
    helpers::{DOMAIN_DEPOSIT, FAR_FUTURE_EPOCH},
    operations::deposit::is_valid_merkle_branch,
};

/// `process_deposit` (modified in Altair) per `specs/altair/beacon-chain.md:556-572`.
///
/// Initialises participation entries and inactivity score when adding a new
/// validator (`add_validator_to_registry` per spec line 556-566).
pub fn process_deposit<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E,
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
    >,
    deposit: &Deposit<33>,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E: EthSpec<
        AltairBeaconState = BeaconState<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
        >,
    >,
{
    // Verify Merkle proof.
    let leaf = deposit.data.tree_hash_root();
    let index = state.eth1_deposit_index;
    let deposit_root = state.eth1_data.deposit_root;
    let depth = E::DEPOSIT_CONTRACT_TREE_DEPTH + 1;
    let branch: Vec<Hash256> = deposit.proof.as_slice().to_vec();

    if !is_valid_merkle_branch(&leaf, &branch, depth, index, &deposit_root) {
        return Err(StateTransitionError::InvalidDeposit {
            reason: DepositInvalidReason::InvalidMerkleProof,
        });
    }

    // Deposits must be processed in order.
    state.eth1_deposit_index += 1;

    apply_deposit_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(
        state,
        &deposit.data.pubkey,
        &deposit.data.withdrawal_credentials,
        deposit.data.amount.0,
        &deposit.data.signature,
        verify_signatures,
    )
}

/// `add_validator_to_registry` (modified in Altair) per
/// `specs/altair/beacon-chain.md:556-566`.
///
/// Appends the validator, balance, participation flags, and inactivity score.
fn apply_deposit_altair<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    E: EthSpec,
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
    >,
    pubkey: &pharos_utils::BLSPubkey,
    withdrawal_credentials: &Bytes32,
    amount: u64,
    signature: &pharos_utils::BLSSignature,
    verify_signatures: bool,
) -> Result<(), StateTransitionError> {
    let existing_index = state.validators.iter().position(|v| &v.pubkey == pubkey);

    match existing_index {
        Some(idx) => {
            // Top up: always increase balance.
            let cur = state
                .balances
                .as_slice()
                .get(idx)
                .copied()
                .unwrap_or(Gwei(0));
            state.balances = state
                .balances
                .with_set(idx, Gwei(cur.0 + amount))
                .map_err(|_| StateTransitionError::IndexOutOfRange(idx))?;
        }
        None => {
            // New validator: optionally verify BLS proof of possession.
            // Domain uses GENESIS_FORK_VERSION and zero genesis_validators_root
            // (fork-agnostic per spec apply_deposit).
            if verify_signatures {
                let deposit_message = DepositMessage {
                    pubkey: *pubkey,
                    withdrawal_credentials: *withdrawal_credentials,
                    amount: Gwei(amount),
                };
                let domain =
                    compute_domain(DOMAIN_DEPOSIT, E::GENESIS_FORK_VERSION, &Hash256::default());
                use pharos_ssz::TreeHash;
                use pharos_types::phase0::SigningData;
                let signing_root = SigningData {
                    object_root: deposit_message.tree_hash_root(),
                    domain,
                }
                .tree_hash_root();
                let valid = pharos_utils::bls::verify(pubkey, signing_root.as_slice(), signature)
                    .unwrap_or(false);
                if !valid {
                    // Per spec apply_deposit: silently skip invalid-sig new deposits.
                    return Ok(());
                }
            }

            let effective_balance =
                (amount - amount % E::EFFECTIVE_BALANCE_INCREMENT).min(E::MAX_EFFECTIVE_BALANCE);
            let validator = Validator {
                pubkey: *pubkey,
                withdrawal_credentials: *withdrawal_credentials,
                effective_balance: Gwei(effective_balance),
                slashed: false,
                activation_eligibility_epoch: Epoch(FAR_FUTURE_EPOCH),
                activation_epoch: Epoch(FAR_FUTURE_EPOCH),
                exit_epoch: Epoch(FAR_FUTURE_EPOCH),
                withdrawable_epoch: Epoch(FAR_FUTURE_EPOCH),
                ..Validator::default()
            };
            state.validators = state
                .validators
                .with_push(validator)
                .map_err(StateTransitionError::Ssz)?;
            state.balances = state
                .balances
                .with_push(Gwei(amount))
                .map_err(StateTransitionError::Ssz)?;

            // [New in Altair] initialise participation + inactivity_score.
            state.previous_epoch_participation = state
                .previous_epoch_participation
                .with_push(0u8)
                .map_err(StateTransitionError::Ssz)?;
            state.current_epoch_participation = state
                .current_epoch_participation
                .with_push(0u8)
                .map_err(StateTransitionError::Ssz)?;
            state.inactivity_scores = state
                .inactivity_scores
                .with_push(0u64)
                .map_err(StateTransitionError::Ssz)?;
        }
    }

    Ok(())
}
