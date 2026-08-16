//! Electra `BeaconState` container.
//!
//! Per `specs/electra/beacon-chain.md` (Modified containers → BeaconState).
//!
//! Changes from Deneb (EIP-6110/7002/7251):
//! - `deposit_requests_start_index: uint64` — next pending deposit index to be processed.
//! - `deposit_balance_to_consume: Gwei` — EIP-7251 deposit churn accumulator.
//! - `exit_balance_to_consume: Gwei` — EIP-7251 exit churn accumulator.
//! - `earliest_exit_epoch: Epoch` — earliest epoch at which a validator can exit.
//! - `consolidation_balance_to_consume: Gwei` — EIP-7251 consolidation churn accumulator.
//! - `earliest_consolidation_epoch: Epoch` — earliest epoch for consolidation.
//! - `pending_deposits: List[PendingDeposit, PENDING_DEPOSITS_LIMIT]` — pending deposit queue.
//! - `pending_partial_withdrawals: List[PendingPartialWithdrawal, PENDING_PARTIAL_WITHDRAWALS_LIMIT]`.
//! - `pending_consolidations: List[PendingConsolidation, PENDING_CONSOLIDATIONS_LIMIT]`.

use pharos_ssz::{Bitvector, Decode, Encode, SszError, SszList, SszSequence, SszVector, TreeHash};
use pharos_utils::{CachedRoot, Gwei, Hash256};

use crate::altair::constants::ParticipationFlags;
use crate::altair::operations::SyncCommittee;
use crate::capella::execution_payload::WithdrawalIndex;
use crate::capella::operations::HistoricalSummary;
use crate::deneb::execution_payload::ExecutionPayloadHeader;
use crate::electra::requests::{PendingConsolidation, PendingDeposit, PendingPartialWithdrawal};
use crate::phase0::misc::{Checkpoint, Eth1Data, Fork, Validator};
use crate::phase0::operations::BeaconBlockHeader;
use crate::phase0::primitives::{Epoch, Root, Slot, ValidatorIndex};
use crate::views::{BeaconStateView, ForkVariant, SyncCommitteePubkeys};

// ── BeaconState ───────────────────────────────────────────────────────────────

/// Electra `BeaconState` per `specs/electra/beacon-chain.md`.
///
/// Const parameters, in order:
/// 1.  `SLOTS_PER_HISTORICAL_ROOT` — `presets/*/phase0.yaml:42`
/// 2.  `HISTORICAL_ROOTS_LIMIT` — `presets/*/phase0.yaml:53`
/// 3.  `ETH1_DATA_VOTES_LIMIT` — derived: `EPOCHS_PER_ETH1_VOTING_PERIOD * SLOTS_PER_EPOCH`
/// 4.  `VALIDATOR_REGISTRY_LIMIT` — `presets/*/phase0.yaml:55`
/// 5.  `EPOCHS_PER_HISTORICAL_VECTOR` — `presets/*/phase0.yaml:49`
/// 6.  `EPOCHS_PER_SLASHINGS_VECTOR` — `presets/*/phase0.yaml:51`
/// 7.  `JUSTIFICATION_BITS_LENGTH` — `specs/phase0/beacon-chain.md:195`
/// 8.  `SYNC_COMMITTEE_SIZE` — `presets/*/altair.yaml:15`
/// 9.  `BYTES_PER_LOGS_BLOOM` — `presets/*/bellatrix.yaml`
/// 10. `MAX_EXTRA_DATA_BYTES` — `presets/*/bellatrix.yaml`
/// 11. `PENDING_DEPOSITS_LIMIT` — `presets/*/electra.yaml` (EIP-7251)
/// 12. `PENDING_PARTIAL_WITHDRAWALS_LIMIT` — `presets/*/electra.yaml` (EIP-7251)
/// 13. `PENDING_CONSOLIDATIONS_LIMIT` — `presets/*/electra.yaml` (EIP-7251)
#[derive(Encode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct BeaconState<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
> {
    /// `genesis_time: uint64`.
    pub genesis_time: u64,
    /// `genesis_validators_root: Root`.
    pub genesis_validators_root: Root,
    /// `slot: Slot`.
    pub slot: Slot,
    /// `fork: Fork`.
    pub fork: Fork,
    /// `latest_block_header: BeaconBlockHeader`.
    pub latest_block_header: BeaconBlockHeader,
    /// `block_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`.
    pub block_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    /// `state_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`.
    pub state_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    /// `historical_roots: List[Root, HISTORICAL_ROOTS_LIMIT]` — frozen in Capella+.
    pub historical_roots: SszList<Root, HISTORICAL_ROOTS_LIMIT>,
    /// `eth1_data: Eth1Data`.
    pub eth1_data: Eth1Data,
    /// `eth1_data_votes: List[Eth1Data, ETH1_DATA_VOTES_LIMIT]`.
    pub eth1_data_votes: SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>,
    /// `eth1_deposit_index: uint64`.
    pub eth1_deposit_index: u64,
    /// `validators: List[Validator, VALIDATOR_REGISTRY_LIMIT]`.
    pub validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT>,
    /// `balances: List[Gwei, VALIDATOR_REGISTRY_LIMIT]`.
    pub balances: SszList<Gwei, VALIDATOR_REGISTRY_LIMIT>,
    /// `randao_mixes: Vector[Bytes32, EPOCHS_PER_HISTORICAL_VECTOR]`.
    pub randao_mixes: SszVector<Hash256, EPOCHS_PER_HISTORICAL_VECTOR>,
    /// `slashings: Vector[Gwei, EPOCHS_PER_SLASHINGS_VECTOR]`.
    pub slashings: SszVector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>,
    /// `previous_epoch_participation: List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]`.
    pub previous_epoch_participation: SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>,
    /// `current_epoch_participation: List[ParticipationFlags, VALIDATOR_REGISTRY_LIMIT]`.
    pub current_epoch_participation: SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>,
    /// `justification_bits: Bitvector[JUSTIFICATION_BITS_LENGTH]`.
    pub justification_bits: Bitvector<JUSTIFICATION_BITS_LENGTH>,
    /// `previous_justified_checkpoint: Checkpoint`.
    pub previous_justified_checkpoint: Checkpoint,
    /// `current_justified_checkpoint: Checkpoint`.
    pub current_justified_checkpoint: Checkpoint,
    /// `finalized_checkpoint: Checkpoint`.
    pub finalized_checkpoint: Checkpoint,
    /// `inactivity_scores: List[uint64, VALIDATOR_REGISTRY_LIMIT]`.
    pub inactivity_scores: SszList<u64, VALIDATOR_REGISTRY_LIMIT>,
    /// `current_sync_committee: SyncCommittee`.
    pub current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// `next_sync_committee: SyncCommittee`.
    pub next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE>,
    /// `latest_execution_payload_header: deneb::ExecutionPayloadHeader`
    /// (re-typed from capella, adds `blob_gas_used` and `excess_blob_gas`).
    pub latest_execution_payload_header:
        ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>,
    /// `next_withdrawal_index: WithdrawalIndex` (from Capella).
    pub next_withdrawal_index: WithdrawalIndex,
    /// `next_withdrawal_validator_index: ValidatorIndex` (from Capella).
    pub next_withdrawal_validator_index: ValidatorIndex,
    /// `historical_summaries: List[HistoricalSummary, HISTORICAL_ROOTS_LIMIT]`
    /// (from Capella).
    pub historical_summaries: SszList<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>,
    // ── Electra-only fields ──────────────────────────────────────────────────
    /// `deposit_requests_start_index: uint64` (EIP-6110).
    ///
    /// Index of the first pending deposit not yet processed from the EL side.
    /// Initialized to `UNSET_DEPOSIT_REQUESTS_START_INDEX (u64::MAX)`.
    pub deposit_requests_start_index: u64,
    /// `deposit_balance_to_consume: Gwei` (EIP-7251).
    pub deposit_balance_to_consume: Gwei,
    /// `exit_balance_to_consume: Gwei` (EIP-7251).
    pub exit_balance_to_consume: Gwei,
    /// `earliest_exit_epoch: Epoch` (EIP-7251).
    pub earliest_exit_epoch: Epoch,
    /// `consolidation_balance_to_consume: Gwei` (EIP-7251).
    pub consolidation_balance_to_consume: Gwei,
    /// `earliest_consolidation_epoch: Epoch` (EIP-7251).
    pub earliest_consolidation_epoch: Epoch,
    /// `pending_deposits: List[PendingDeposit, PENDING_DEPOSITS_LIMIT]` (EIP-7251/6110).
    pub pending_deposits: SszList<PendingDeposit, PENDING_DEPOSITS_LIMIT>,
    /// `pending_partial_withdrawals: List[PendingPartialWithdrawal, PENDING_PARTIAL_WITHDRAWALS_LIMIT]` (EIP-7251).
    pub pending_partial_withdrawals:
        SszList<PendingPartialWithdrawal, PENDING_PARTIAL_WITHDRAWALS_LIMIT>,
    /// `pending_consolidations: List[PendingConsolidation, PENDING_CONSOLIDATIONS_LIMIT]` (EIP-7251).
    pub pending_consolidations: SszList<PendingConsolidation, PENDING_CONSOLIDATIONS_LIMIT>,
    /// Cached top-level Merkle root; `#[ssz(skip)]` so it is not SSZ-encoded.
    #[ssz(skip)]
    pub cached_root: CachedRoot,
}

impl<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
> Default
    for BeaconState<
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >
where
    Root: Default + Clone,
    Gwei: Default + Clone,
    Hash256: Default + Clone,
{
    fn default() -> Self {
        Self {
            genesis_time: 0,
            genesis_validators_root: Root::default(),
            slot: Slot::default(),
            fork: Fork::default(),
            latest_block_header: BeaconBlockHeader::default(),
            block_roots: SszVector::from_vec_tree(vec![
                Root::default();
                SLOTS_PER_HISTORICAL_ROOT as usize
            ])
            .expect("default block_roots tree init"),
            state_roots: SszVector::from_vec_tree(vec![
                Root::default();
                SLOTS_PER_HISTORICAL_ROOT as usize
            ])
            .expect("default state_roots tree init"),
            historical_roots: SszList::empty_tree(),
            eth1_data: Eth1Data::default(),
            eth1_data_votes: SszList::default(),
            eth1_deposit_index: 0,
            validators: SszList::empty_tree(),
            balances: SszList::default(),
            randao_mixes: SszVector::from_vec_tree(vec![
                Hash256::default();
                EPOCHS_PER_HISTORICAL_VECTOR as usize
            ])
            .expect("default randao_mixes tree init"),
            slashings: SszVector::default(),
            previous_epoch_participation: SszList::default(),
            current_epoch_participation: SszList::default(),
            justification_bits: Bitvector::default(),
            previous_justified_checkpoint: Checkpoint::default(),
            current_justified_checkpoint: Checkpoint::default(),
            finalized_checkpoint: Checkpoint::default(),
            inactivity_scores: SszList::default(),
            current_sync_committee: SyncCommittee::default(),
            next_sync_committee: SyncCommittee::default(),
            latest_execution_payload_header: ExecutionPayloadHeader::default(),
            next_withdrawal_index: 0,
            next_withdrawal_validator_index: ValidatorIndex(0),
            historical_summaries: SszList::default(),
            deposit_requests_start_index: u64::MAX,
            deposit_balance_to_consume: Gwei(0),
            exit_balance_to_consume: Gwei(0),
            earliest_exit_epoch: Epoch(0),
            consolidation_balance_to_consume: Gwei(0),
            earliest_consolidation_epoch: Epoch(0),
            pending_deposits: SszList::default(),
            pending_partial_withdrawals: SszList::default(),
            pending_consolidations: SszList::default(),
            cached_root: CachedRoot::default(),
        }
    }
}

impl<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
>
    BeaconState<
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >
where
    Root: Default + Clone,
    Hash256: Default + Clone,
{
    /// Convert the five hot list/vector fields from Naive to Tree backend.
    ///
    /// Same set as deneb: `block_roots`, `state_roots`, `historical_roots`,
    /// `validators`, `randao_mixes`.
    pub fn into_tree_backend(mut self) -> Result<Self, SszError> {
        self.block_roots = self.block_roots.into_tree()?;
        self.state_roots = self.state_roots.into_tree()?;
        self.historical_roots = self.historical_roots.into_tree()?;
        self.validators = self.validators.into_tree()?;
        self.randao_mixes = self.randao_mixes.into_tree()?;
        Ok(self)
    }

    /// Lazily compute and cache the top-level Merkle root.
    pub fn cached_tree_hash_root(&self) -> Hash256 {
        self.cached_root
            .get_or_init(|| <Self as TreeHash>::tree_hash_root(self))
    }

    /// Clear the cached top-level Merkle root.
    pub fn invalidate_root_cache(&mut self) {
        self.cached_root.invalidate();
    }
}

// ── Manual Decode impl ────────────────────────────────────────────────────────

impl<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
> Decode
    for BeaconState<
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >
where
    Root: Default + Clone,
    Hash256: Default + Clone,
{
    const IS_FIXED_SIZE: bool = false;

    fn ssz_fixed_len() -> usize {
        pharos_ssz::BYTES_PER_LENGTH_OFFSET
    }

    fn from_ssz_bytes(bytes: &[u8]) -> Result<Self, SszError> {
        use pharos_ssz::SszDecoder;
        let mut decoder = SszDecoder::new(bytes);
        decoder.register_type::<u64>()?;
        decoder.register_type::<Root>()?;
        decoder.register_type::<Slot>()?;
        decoder.register_type::<Fork>()?;
        decoder.register_type::<BeaconBlockHeader>()?;
        decoder.register_type::<SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>>()?;
        decoder.register_type::<SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>>()?;
        decoder
            .register_anonymous_variable_length_item::<SszList<Root, HISTORICAL_ROOTS_LIMIT>>()?;
        decoder.register_type::<Eth1Data>()?;
        decoder
            .register_anonymous_variable_length_item::<SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>>(
            )?;
        decoder.register_type::<u64>()?;
        decoder.register_anonymous_variable_length_item::<SszList<Validator, VALIDATOR_REGISTRY_LIMIT>>()?;
        decoder
            .register_anonymous_variable_length_item::<SszList<Gwei, VALIDATOR_REGISTRY_LIMIT>>()?;
        decoder.register_type::<SszVector<Hash256, EPOCHS_PER_HISTORICAL_VECTOR>>()?;
        decoder.register_type::<SszVector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>>()?;
        decoder.register_anonymous_variable_length_item::<SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>>()?;
        decoder.register_anonymous_variable_length_item::<SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>>()?;
        decoder.register_type::<Bitvector<JUSTIFICATION_BITS_LENGTH>>()?;
        decoder.register_type::<Checkpoint>()?;
        decoder.register_type::<Checkpoint>()?;
        decoder.register_type::<Checkpoint>()?;
        decoder
            .register_anonymous_variable_length_item::<SszList<u64, VALIDATOR_REGISTRY_LIMIT>>()?;
        decoder.register_type::<SyncCommittee<SYNC_COMMITTEE_SIZE>>()?;
        decoder.register_type::<SyncCommittee<SYNC_COMMITTEE_SIZE>>()?;
        decoder.register_anonymous_variable_length_item::<ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>()?;
        decoder.register_type::<WithdrawalIndex>()?;
        decoder.register_type::<ValidatorIndex>()?;
        decoder.register_anonymous_variable_length_item::<SszList<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>>()?;
        // Electra fields
        decoder.register_type::<u64>()?; // deposit_requests_start_index
        decoder.register_type::<Gwei>()?; // deposit_balance_to_consume
        decoder.register_type::<Gwei>()?; // exit_balance_to_consume
        decoder.register_type::<Epoch>()?; // earliest_exit_epoch
        decoder.register_type::<Gwei>()?; // consolidation_balance_to_consume
        decoder.register_type::<Epoch>()?; // earliest_consolidation_epoch
        decoder.register_anonymous_variable_length_item::<SszList<PendingDeposit, PENDING_DEPOSITS_LIMIT>>()?;
        decoder.register_anonymous_variable_length_item::<SszList<PendingPartialWithdrawal, PENDING_PARTIAL_WITHDRAWALS_LIMIT>>()?;
        decoder.register_anonymous_variable_length_item::<SszList<PendingConsolidation, PENDING_CONSOLIDATIONS_LIMIT>>()?;

        let genesis_time: u64 = decoder.decode_next::<u64>()?;
        let genesis_validators_root: Root = decoder.decode_next::<Root>()?;
        let slot: Slot = decoder.decode_next::<Slot>()?;
        let fork: Fork = decoder.decode_next::<Fork>()?;
        let latest_block_header: BeaconBlockHeader = decoder.decode_next::<BeaconBlockHeader>()?;
        let block_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT> =
            decoder.decode_next::<SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>>()?;
        let state_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT> =
            decoder.decode_next::<SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>>()?;
        let historical_roots: SszList<Root, HISTORICAL_ROOTS_LIMIT> =
            decoder.decode_next::<SszList<Root, HISTORICAL_ROOTS_LIMIT>>()?;
        let eth1_data: Eth1Data = decoder.decode_next::<Eth1Data>()?;
        let eth1_data_votes: SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT> =
            decoder.decode_next::<SszList<Eth1Data, ETH1_DATA_VOTES_LIMIT>>()?;
        let eth1_deposit_index: u64 = decoder.decode_next::<u64>()?;
        let validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT> =
            decoder.decode_next::<SszList<Validator, VALIDATOR_REGISTRY_LIMIT>>()?;
        let balances: SszList<Gwei, VALIDATOR_REGISTRY_LIMIT> =
            decoder.decode_next::<SszList<Gwei, VALIDATOR_REGISTRY_LIMIT>>()?;
        let randao_mixes: SszVector<Hash256, EPOCHS_PER_HISTORICAL_VECTOR> =
            decoder.decode_next::<SszVector<Hash256, EPOCHS_PER_HISTORICAL_VECTOR>>()?;
        let slashings: SszVector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR> =
            decoder.decode_next::<SszVector<Gwei, EPOCHS_PER_SLASHINGS_VECTOR>>()?;
        let previous_epoch_participation: SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT> =
            decoder.decode_next::<SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>>()?;
        let current_epoch_participation: SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT> =
            decoder.decode_next::<SszList<ParticipationFlags, VALIDATOR_REGISTRY_LIMIT>>()?;
        let justification_bits: Bitvector<JUSTIFICATION_BITS_LENGTH> =
            decoder.decode_next::<Bitvector<JUSTIFICATION_BITS_LENGTH>>()?;
        let previous_justified_checkpoint: Checkpoint = decoder.decode_next::<Checkpoint>()?;
        let current_justified_checkpoint: Checkpoint = decoder.decode_next::<Checkpoint>()?;
        let finalized_checkpoint: Checkpoint = decoder.decode_next::<Checkpoint>()?;
        let inactivity_scores: SszList<u64, VALIDATOR_REGISTRY_LIMIT> =
            decoder.decode_next::<SszList<u64, VALIDATOR_REGISTRY_LIMIT>>()?;
        let current_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE> =
            decoder.decode_next::<SyncCommittee<SYNC_COMMITTEE_SIZE>>()?;
        let next_sync_committee: SyncCommittee<SYNC_COMMITTEE_SIZE> =
            decoder.decode_next::<SyncCommittee<SYNC_COMMITTEE_SIZE>>()?;
        let latest_execution_payload_header: ExecutionPayloadHeader<
            BYTES_PER_LOGS_BLOOM,
            MAX_EXTRA_DATA_BYTES,
        > = decoder
            .decode_next::<ExecutionPayloadHeader<BYTES_PER_LOGS_BLOOM, MAX_EXTRA_DATA_BYTES>>()?;
        let next_withdrawal_index: WithdrawalIndex = decoder.decode_next::<WithdrawalIndex>()?;
        let next_withdrawal_validator_index: ValidatorIndex =
            decoder.decode_next::<ValidatorIndex>()?;
        let historical_summaries: SszList<HistoricalSummary, HISTORICAL_ROOTS_LIMIT> =
            decoder.decode_next::<SszList<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>>()?;
        // Electra fields
        let deposit_requests_start_index: u64 = decoder.decode_next::<u64>()?;
        let deposit_balance_to_consume: Gwei = decoder.decode_next::<Gwei>()?;
        let exit_balance_to_consume: Gwei = decoder.decode_next::<Gwei>()?;
        let earliest_exit_epoch: Epoch = decoder.decode_next::<Epoch>()?;
        let consolidation_balance_to_consume: Gwei = decoder.decode_next::<Gwei>()?;
        let earliest_consolidation_epoch: Epoch = decoder.decode_next::<Epoch>()?;
        let pending_deposits: SszList<PendingDeposit, PENDING_DEPOSITS_LIMIT> =
            decoder.decode_next::<SszList<PendingDeposit, PENDING_DEPOSITS_LIMIT>>()?;
        let pending_partial_withdrawals: SszList<
            PendingPartialWithdrawal,
            PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        > = decoder
            .decode_next::<SszList<PendingPartialWithdrawal, PENDING_PARTIAL_WITHDRAWALS_LIMIT>>(
            )?;
        let pending_consolidations: SszList<PendingConsolidation, PENDING_CONSOLIDATIONS_LIMIT> =
            decoder.decode_next::<SszList<PendingConsolidation, PENDING_CONSOLIDATIONS_LIMIT>>()?;

        decoder.finish()?;
        Ok(Self {
            genesis_time,
            genesis_validators_root,
            slot,
            fork,
            latest_block_header,
            block_roots,
            state_roots,
            historical_roots,
            eth1_data,
            eth1_data_votes,
            eth1_deposit_index,
            validators,
            balances,
            randao_mixes,
            slashings,
            previous_epoch_participation,
            current_epoch_participation,
            justification_bits,
            previous_justified_checkpoint,
            current_justified_checkpoint,
            finalized_checkpoint,
            inactivity_scores,
            current_sync_committee,
            next_sync_committee,
            latest_execution_payload_header,
            next_withdrawal_index,
            next_withdrawal_validator_index,
            historical_summaries,
            deposit_requests_start_index,
            deposit_balance_to_consume,
            exit_balance_to_consume,
            earliest_exit_epoch,
            consolidation_balance_to_consume,
            earliest_consolidation_epoch,
            pending_deposits,
            pending_partial_withdrawals,
            pending_consolidations,
            cached_root: CachedRoot::default(),
        })
    }
}

// ── BeaconStateView impl ──────────────────────────────────────────────────────

impl<
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
    const PENDING_DEPOSITS_LIMIT: u64,
    const PENDING_PARTIAL_WITHDRAWALS_LIMIT: u64,
    const PENDING_CONSOLIDATIONS_LIMIT: u64,
> BeaconStateView
    for BeaconState<
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
        PENDING_DEPOSITS_LIMIT,
        PENDING_PARTIAL_WITHDRAWALS_LIMIT,
        PENDING_CONSOLIDATIONS_LIMIT,
    >
where
    Root: Default + Clone,
    Hash256: Default + Clone,
{
    fn fork_variant(&self) -> ForkVariant {
        ForkVariant::Electra
    }

    fn genesis_time(&self) -> u64 {
        self.genesis_time
    }
    fn genesis_validators_root(&self) -> Root {
        self.genesis_validators_root
    }
    fn slot(&self) -> Slot {
        self.slot
    }
    fn fork(&self) -> &Fork {
        &self.fork
    }
    fn latest_block_header(&self) -> &BeaconBlockHeader {
        &self.latest_block_header
    }
    fn validators(&self) -> Vec<Validator> {
        self.validators.to_vec()
    }
    fn validators_iter(&self) -> Box<dyn Iterator<Item = &Validator> + '_> {
        Box::new(self.validators.iter())
    }
    fn validator(&self, idx: usize) -> Option<&Validator> {
        self.validators.get(idx)
    }
    fn num_validators(&self) -> usize {
        self.validators.len()
    }
    fn balances(&self) -> &[Gwei] {
        self.balances.as_slice()
    }
    fn block_roots(&self) -> Vec<Root> {
        self.block_roots.to_vec()
    }
    fn block_root_at(&self, idx: usize) -> Option<Root> {
        self.block_roots.get(idx).copied()
    }
    fn state_roots(&self) -> Vec<Root> {
        self.state_roots.to_vec()
    }
    fn state_root_at(&self, idx: usize) -> Option<Root> {
        self.state_roots.get(idx).copied()
    }
    fn randao_mixes(&self) -> Vec<Hash256> {
        self.randao_mixes.to_vec()
    }
    fn randao_mix_at(&self, idx: usize) -> Option<Hash256> {
        self.randao_mixes.get(idx).copied()
    }
    fn slashings(&self) -> &[Gwei] {
        self.slashings.as_slice()
    }
    fn eth1_data(&self) -> &Eth1Data {
        &self.eth1_data
    }
    fn eth1_data_votes(&self) -> Vec<Eth1Data> {
        self.eth1_data_votes.to_vec()
    }
    fn eth1_deposit_index_u64(&self) -> u64 {
        self.eth1_deposit_index
    }
    fn historical_roots(&self) -> Vec<Root> {
        self.historical_roots.to_vec()
    }
    fn justification_bits_bytes(&self) -> Vec<u8> {
        use pharos_ssz::Encode as _;
        self.justification_bits.as_ssz_bytes()
    }
    fn previous_justified_checkpoint(&self) -> &Checkpoint {
        &self.previous_justified_checkpoint
    }
    fn current_justified_checkpoint(&self) -> &Checkpoint {
        &self.current_justified_checkpoint
    }
    fn finalized_checkpoint(&self) -> &Checkpoint {
        &self.finalized_checkpoint
    }
    fn invalidate_root_cache(&mut self) {
        self.cached_root.invalidate();
    }
    fn into_tree_backend(self) -> Result<Self, SszError> {
        self.into_tree_backend()
    }
    fn sync_committee_pubkeys(&self) -> Option<SyncCommitteePubkeys> {
        Some((
            self.current_sync_committee
                .pubkeys
                .iter()
                .map(|pk| pk.into_inner())
                .collect(),
            self.next_sync_committee
                .pubkeys
                .iter()
                .map(|pk| pk.into_inner())
                .collect(),
        ))
    }
    fn previous_epoch_participation_u8s(&self) -> Vec<u8> {
        self.previous_epoch_participation.to_vec()
    }
    fn current_epoch_participation_u8s(&self) -> Vec<u8> {
        self.current_epoch_participation.to_vec()
    }
    fn inactivity_scores_u64s(&self) -> Vec<u64> {
        self.inactivity_scores.to_vec()
    }
    fn sync_committee_aggregate_pubkeys(&self) -> Option<([u8; 48], [u8; 48])> {
        Some((
            self.current_sync_committee.aggregate_pubkey.into_inner(),
            self.next_sync_committee.aggregate_pubkey.into_inner(),
        ))
    }
    fn previous_epoch_attestations_raw(&self) -> Option<Vec<crate::views::PendingAttestationRaw>> {
        None
    }
    fn current_epoch_attestations_raw(&self) -> Option<Vec<crate::views::PendingAttestationRaw>> {
        None
    }
    fn execution_payload_header_raw(&self) -> Option<crate::views::ExecutionPayloadHeaderRaw> {
        let h = &self.latest_execution_payload_header;
        Some(crate::views::ExecutionPayloadHeaderRaw {
            parent_hash: h.parent_hash.into_inner(),
            fee_recipient: h.fee_recipient.into_inner(),
            state_root: h.state_root.into_inner(),
            receipts_root: h.receipts_root.into_inner(),
            logs_bloom: h.logs_bloom.iter().copied().collect(),
            prev_randao: h.prev_randao.into_inner(),
            block_number: h.block_number,
            gas_limit: h.gas_limit,
            gas_used: h.gas_used,
            timestamp: h.timestamp,
            extra_data: h.extra_data.iter().copied().collect(),
            base_fee_per_gas_le: h.base_fee_per_gas.to_le_bytes(),
            block_hash: h.block_hash.into_inner(),
            transactions_root: h.transactions_root.into_inner(),
        })
    }
    fn execution_payload_withdrawals_root(&self) -> Option<[u8; 32]> {
        Some(
            self.latest_execution_payload_header
                .withdrawals_root
                .into_inner(),
        )
    }
    fn next_withdrawal_index_u64(&self) -> Option<u64> {
        Some(self.next_withdrawal_index)
    }
    fn next_withdrawal_validator_index_raw(&self) -> Option<u64> {
        Some(self.next_withdrawal_validator_index.0)
    }
    fn historical_summaries_raw(&self) -> Option<Vec<([u8; 32], [u8; 32])>> {
        Some(
            self.historical_summaries
                .iter()
                .map(|s| {
                    (
                        s.block_summary_root.into_inner(),
                        s.state_summary_root.into_inner(),
                    )
                })
                .collect(),
        )
    }
}

// ── Preset-specific aliases ───────────────────────────────────────────────────

/// Mainnet electra `BeaconState`.
pub type MainnetBeaconState = BeaconState<
    8192,              // SLOTS_PER_HISTORICAL_ROOT
    16_777_216,        // HISTORICAL_ROOTS_LIMIT
    2048,              // ETH1_DATA_VOTES_LIMIT
    1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
    65536,             // EPOCHS_PER_HISTORICAL_VECTOR
    8192,              // EPOCHS_PER_SLASHINGS_VECTOR
    4,                 // JUSTIFICATION_BITS_LENGTH
    512,               // SYNC_COMMITTEE_SIZE
    256,               // BYTES_PER_LOGS_BLOOM
    32,                // MAX_EXTRA_DATA_BYTES
    134_217_728,       // PENDING_DEPOSITS_LIMIT (EIP-7251)
    134_217_728,       // PENDING_PARTIAL_WITHDRAWALS_LIMIT (EIP-7251)
    262_144,           // PENDING_CONSOLIDATIONS_LIMIT (EIP-7251)
>;

/// Minimal electra `BeaconState`.
pub type MinimalBeaconState = BeaconState<
    64,                // SLOTS_PER_HISTORICAL_ROOT
    16_777_216,        // HISTORICAL_ROOTS_LIMIT
    32,                // ETH1_DATA_VOTES_LIMIT
    1_099_511_627_776, // VALIDATOR_REGISTRY_LIMIT
    64,                // EPOCHS_PER_HISTORICAL_VECTOR
    64,                // EPOCHS_PER_SLASHINGS_VECTOR
    4,                 // JUSTIFICATION_BITS_LENGTH
    32,                // SYNC_COMMITTEE_SIZE
    256,               // BYTES_PER_LOGS_BLOOM
    32,                // MAX_EXTRA_DATA_BYTES
    134_217_728,       // PENDING_DEPOSITS_LIMIT (EIP-7251)
    64,                // PENDING_PARTIAL_WITHDRAWALS_LIMIT (EIP-7251)
    64,                // PENDING_CONSOLIDATIONS_LIMIT (EIP-7251)
>;
