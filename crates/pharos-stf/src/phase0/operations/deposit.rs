//! `process_deposit` per `specs/phase0/beacon-chain.md:2088-2111`.

use pharos_ssz::TreeHash;
use pharos_types::{
    BeaconSpec, BeaconStateView,
    phase0::{Deposit, DepositMessage, Epoch, Validator},
};
use pharos_utils::{Gwei, Hash256};

use crate::error::{DepositInvalidReason, StateTransitionError};
use crate::phase0::{
    accessors::{compute_domain, compute_signing_root},
    helpers::{DOMAIN_DEPOSIT, FAR_FUTURE_EPOCH},
    mutators::increase_balance,
    state_write::BeaconStateWrite,
};

/// `process_deposit` per `specs/phase0/beacon-chain.md:2088-2111`.
///
/// `DEPOSIT_PROOF_LENGTH = 33` in all current presets (derived from
/// `DEPOSIT_CONTRACT_TREE_DEPTH = 32`).
pub fn process_deposit<E: BeaconSpec>(
    state: &mut E::BeaconState,
    deposit: &Deposit<33>,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
{
    // Verify Merkle proof.
    let leaf = deposit.data.tree_hash_root();
    let index = state.eth1_deposit_index();
    let deposit_root = state.eth1_data().deposit_root;
    let depth = E::DEPOSIT_CONTRACT_TREE_DEPTH + 1;
    let branch: Vec<Hash256> = deposit.proof.as_slice().to_vec();

    if !is_valid_merkle_branch(&leaf, &branch, depth, index, &deposit_root) {
        return Err(StateTransitionError::InvalidDeposit {
            reason: DepositInvalidReason::InvalidMerkleProof,
        });
    }

    // Deposits must be processed in order.
    state.increment_eth1_deposit_index();

    apply_deposit::<E>(
        state,
        &deposit.data.pubkey,
        &deposit.data.withdrawal_credentials,
        deposit.data.amount.0,
        &deposit.data.signature,
        verify_signatures,
    )
}

fn apply_deposit<E: BeaconSpec>(
    state: &mut E::BeaconState,
    pubkey: &pharos_utils::BLSPubkey,
    withdrawal_credentials: &pharos_utils::Bytes32,
    amount: u64,
    signature: &pharos_utils::BLSSignature,
    verify_signatures: bool,
) -> Result<(), StateTransitionError>
where
    E::BeaconState: BeaconStateWrite,
{
    let existing_index = state.validators_iter().position(|v| &v.pubkey == pubkey);

    match existing_index {
        Some(idx) => {
            // Top up: always increase balance regardless of signature.
            increase_balance::<E>(
                state,
                pharos_types::phase0::ValidatorIndex(idx as u64),
                Gwei(amount),
            )?;
        }
        None => {
            // New validator: verify BLS proof of possession when required.
            // Domain uses GENESIS_FORK_VERSION and zero genesis_validators_root
            // (fork-agnostic per spec `apply_deposit`).
            if verify_signatures {
                let deposit_message = DepositMessage {
                    pubkey: *pubkey,
                    withdrawal_credentials: *withdrawal_credentials,
                    amount: Gwei(amount),
                };
                let domain =
                    compute_domain(DOMAIN_DEPOSIT, E::GENESIS_FORK_VERSION, &Hash256::default());
                let signing_root = compute_signing_root(&deposit_message, domain);
                let valid = pharos_utils::bls::verify(pubkey, signing_root.as_slice(), signature)
                    .unwrap_or(false);
                if !valid {
                    // Per spec `apply_deposit`: silently skip invalid-sig new deposits.
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
            state.push_validator(validator)?;
            state.push_balance(Gwei(amount))?;
        }
    }

    Ok(())
}

/// `is_valid_merkle_branch` per `specs/phase0/beacon-chain.md:803-816`.
pub fn is_valid_merkle_branch(
    leaf: &Hash256,
    branch: &[Hash256],
    depth: u64,
    index: u64,
    root: &Hash256,
) -> bool {
    if depth as usize != branch.len() {
        return false;
    }
    let mut value = *leaf;
    for i in 0..depth {
        let branch_hash = branch[i as usize];
        if (index >> i) & 1 == 1 {
            let mut input = [0u8; 64];
            input[..32].copy_from_slice(branch_hash.as_slice());
            input[32..].copy_from_slice(value.as_slice());
            value = pharos_utils::hash::hash(&input);
        } else {
            let mut input = [0u8; 64];
            input[..32].copy_from_slice(value.as_slice());
            input[32..].copy_from_slice(branch_hash.as_slice());
            value = pharos_utils::hash::hash(&input);
        }
    }
    value == *root
}
