use thiserror::Error;

/// Top-level error returned by all state-transition functions.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum StateTransitionError {
    #[error("invalid attestation: {reason}")]
    InvalidAttestation { reason: AttestationInvalidReason },

    #[error("invalid block header: {reason}")]
    InvalidBlockHeader { reason: BlockHeaderInvalidReason },

    #[error("invalid deposit: {reason}")]
    InvalidDeposit { reason: DepositInvalidReason },

    #[error("invalid proposer slashing: {reason}")]
    InvalidProposerSlashing {
        reason: ProposerSlashingInvalidReason,
    },

    #[error("invalid attester slashing: {reason}")]
    InvalidAttesterSlashing {
        reason: AttesterSlashingInvalidReason,
    },

    #[error("invalid voluntary exit: {reason}")]
    InvalidVoluntaryExit { reason: VoluntaryExitInvalidReason },

    #[error("epoch processing error: {reason}")]
    EpochProcessing { reason: EpochProcessingError },

    #[error("slot out of range for block roots lookup")]
    SlotOutOfRange,

    #[error("target slot {target} is not after current slot {current}")]
    TargetSlotNotAfterCurrent {
        current: pharos_types::phase0::Slot,
        target: pharos_types::phase0::Slot,
    },

    #[error("invalid block signature")]
    InvalidBlockSignature,

    #[error("state root mismatch: expected {expected:?}, got {actual:?}")]
    StateRootMismatch {
        expected: pharos_types::phase0::Root,
        actual: pharos_types::phase0::Root,
    },

    #[error("invalid deposit count in block body")]
    InvalidDepositCount,

    #[error("invalid randao reveal: invalid signature")]
    InvalidRandaoReveal,

    #[error("ssz error: {0}")]
    Ssz(#[from] pharos_ssz::SszError),

    #[error("unsupported fork: STF not yet implemented for this fork")]
    UnsupportedFork,

    #[error("sync committee pubkey not found in validator registry")]
    InvalidSyncCommittee,

    /// `process_execution_payload` rejection per
    /// `specs/bellatrix/beacon-chain.md:383-398`.
    #[error("invalid execution payload: {0}")]
    InvalidExecutionPayload(&'static str),
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AttestationInvalidReason {
    #[error("attestation slot too old")]
    SlotTooOld,
    #[error("attestation slot too new")]
    SlotTooNew,
    #[error("target epoch mismatch")]
    TargetEpochMismatch,
    #[error("committee index out of range")]
    CommitteeIndexOutOfRange,
    #[error("aggregation bits length mismatch")]
    AggregationBitsLengthMismatch,
    #[error("invalid source checkpoint")]
    InvalidSourceCheckpoint,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("empty attesting indices")]
    EmptyAttestingIndices,
    #[error("attestation indices not sorted or not unique")]
    IndicesNotSortedOrUnique,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum BlockHeaderInvalidReason {
    #[error("slot does not match state slot")]
    SlotMismatch,
    #[error("block slot not later than latest block header slot")]
    SlotNotLater,
    #[error("parent root mismatch")]
    ParentRootMismatch,
    #[error("proposer is slashed")]
    ProposerSlashed,
    #[error("proposer index mismatch")]
    ProposerIndexMismatch,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum DepositInvalidReason {
    #[error("deposit index does not match state deposit index")]
    DepositIndexMismatch,
    #[error("invalid merkle proof")]
    InvalidMerkleProof,
    #[error("invalid BLS signature")]
    InvalidSignature,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum ProposerSlashingInvalidReason {
    #[error("headers have different slots")]
    SlotMismatch,
    #[error("headers have different proposer indices")]
    ProposerIndexMismatch,
    #[error("headers are the same")]
    HeadersIdentical,
    #[error("validator is not slashable")]
    ValidatorNotSlashable,
    #[error("invalid header signature")]
    InvalidSignature,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum AttesterSlashingInvalidReason {
    #[error("attestations are not slashable")]
    AttestationsNotSlashable,
    #[error("no slashable validator indices in intersection")]
    NoSlashableIndices,
    #[error("indexed attestation is not valid")]
    InvalidIndexedAttestation,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum VoluntaryExitInvalidReason {
    #[error("validator is not active")]
    ValidatorNotActive,
    #[error("validator has already initiated exit")]
    ExitAlreadyInitiated,
    #[error("current epoch is before minimum exit epoch")]
    EpochTooEarly,
    #[error("validator has not been active long enough")]
    InsufficientActiveEpochs,
    #[error("invalid signature")]
    InvalidSignature,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EpochProcessingError {
    #[error("balance index out of range: {index}")]
    BalanceIndexOutOfRange { index: usize },
    #[error("validator index out of range: {index}")]
    ValidatorIndexOutOfRange { index: usize },
    #[error("block root unavailable for epoch")]
    BlockRootUnavailable,
    #[error("invalid epoch for attestation lookup (not current or previous)")]
    InvalidEpochForAttestation,
    #[error("unsupported fork for this epoch processing path")]
    UnsupportedFork,
    #[error("ssz error: {0}")]
    Ssz(#[from] pharos_ssz::SszError),
}

impl From<StateTransitionError> for EpochProcessingError {
    fn from(e: StateTransitionError) -> Self {
        match e {
            StateTransitionError::Ssz(s) => EpochProcessingError::Ssz(s),
            _ => EpochProcessingError::ValidatorIndexOutOfRange { index: 0 },
        }
    }
}
