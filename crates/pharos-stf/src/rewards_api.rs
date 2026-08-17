//! Beacon API reward computation surface.
//!
//! The reward math already exists inside the STF but is FUSED into balance
//! mutation (epoch processing writes balances; block ops add proposer rewards
//! in place). The three Beacon API rewards endpoints
//! (`POST /eth/v1/beacon/rewards/attestations/{epoch}`,
//! `GET /eth/v1/beacon/rewards/blocks/{block_id}`,
//! `POST /eth/v1/beacon/rewards/sync_committee/{block_id}`) need the *values*,
//! decomposed per validator / per component, not the mutated state.
//!
//! This module exposes `E`-only entry points that the API (`pharos-api`,
//! generic over `E: BeaconSpec`, unable to spell the per-preset const generics)
//! can call. Each entry point dispatches over the concrete fork variant via the
//! existing `unwrap_*` `BeaconSpec` accessors and calls the FACTORED STF reward
//! fns (`accumulate_attestation_participation_altair`,
//! `sync_aggregate_rewards_altair`, the phase0 / altair delta fns, the
//! state-projection helpers) — NO reward math is duplicated here.
//!
//! Per-fork attestation-reward dispatch mirrors the conformance runner
//! (`crates/pharos-conformance/src/rewards.rs`), the authoritative per-fork
//! pattern: phase0 uses the phase0 deltas; altair runs the flag/inactivity
//! deltas directly; bellatrix..deneb / electra-fulu project to deneb→altair
//! first. The `phase0/rewards`, `altair/rewards`, and `electra/operations`
//! conformance categories gate that the factored fns stay behaviour-preserving.
//!
//! ADRs: `D-rewards-stf-factoring-not-duplication`,
//! `D-rewards-proposer-reward-fork-family-split`,
//! `D-rewards-altair-state-projection`,
//! `D-rewards-block-recompute-not-balance-diff`,
//! `D-rewards-eip7251-effective-balance-buckets`.

mod impls;

use pharos_types::views::{BeaconBlockBodyView, BeaconStateView, ForkVariant};
use pharos_types::{
    BeaconSpec,
    phase0::{Attestation, AttestationData, ValidatorIndex},
};
use pharos_utils::Gwei;

use crate::altair::helpers::{
    PROPOSER_WEIGHT, get_attestation_participation_flag_indices, get_base_reward_per_increment,
};
use crate::altair::operations::attestation::{
    accumulate_attestation_participation_altair, get_beacon_committee_altair,
};
use crate::error::{EpochProcessingError, StateTransitionError};
use crate::phase0::BeaconStateWrite;
use crate::phase0::accessors::compute_epoch_at_slot;

// Re-export the factored / existing delta and projection fns on a stable path.
pub use crate::altair::helpers::{
    get_flag_index_deltas, get_inactivity_penalty_deltas as get_inactivity_penalty_deltas_altair,
};
pub use crate::bellatrix::helpers::{
    bellatrix_state_to_altair, get_inactivity_penalty_deltas_bellatrix,
};
pub use crate::capella::helpers::{capella_state_to_altair, get_inactivity_penalty_deltas_capella};
pub use crate::deneb::helpers::{deneb_state_to_altair, get_inactivity_penalty_deltas_deneb};
pub use crate::electra::helpers::{electra_state_to_altair, electra_state_to_deneb};
pub use crate::fulu::fulu_state_to_electra;
pub use crate::phase0::epoch::{
    get_head_deltas, get_inactivity_penalty_deltas as get_inactivity_penalty_deltas_phase0,
    get_inclusion_delay_deltas, get_source_deltas, get_target_deltas,
};

// ── Output types ───────────────────────────────────────────────────────────────

/// One validator's attestation reward components (gwei, signed per the spec).
#[derive(Debug, Clone)]
pub struct AttestationReward {
    pub validator_index: u64,
    pub head: i64,
    pub target: i64,
    pub source: i64,
    /// phase0 only (the schema marks it "phase0 only"); altair+ omit it.
    pub inclusion_delay: Option<u64>,
    pub inactivity: i64,
}

/// One ideal-reward bucket keyed by effective balance.
#[derive(Debug, Clone)]
pub struct IdealAttestationReward {
    pub effective_balance: u64,
    pub head: i64,
    pub target: i64,
    pub source: i64,
    pub inclusion_delay: Option<u64>,
    pub inactivity: i64,
}

/// Full attestation-rewards response payload.
#[derive(Debug, Clone)]
pub struct AttestationRewardsData {
    pub ideal_rewards: Vec<IdealAttestationReward>,
    pub total_rewards: Vec<AttestationReward>,
}

/// The four proposer-reward components of a block (gwei, all non-negative).
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockRewardComponents {
    pub proposer_index: u64,
    pub attestations: u64,
    pub sync_aggregate: u64,
    pub proposer_slashings: u64,
    pub attester_slashings: u64,
}

impl BlockRewardComponents {
    /// `total = attestations + sync_aggregate + proposer_slashings + attester_slashings`.
    pub fn total(&self) -> u64 {
        self.attestations + self.sync_aggregate + self.proposer_slashings + self.attester_slashings
    }
}

/// One sync-committee member's reward (signed: positive when participated,
/// negative when not).
#[derive(Debug, Clone, Copy)]
pub struct SyncCommitteeReward {
    pub validator_index: u64,
    pub reward: i64,
}

/// Error surface for the reward computation entry points.
#[derive(Debug, thiserror::Error)]
pub enum RewardsError {
    /// The block / state predates a fork that supports the requested reward.
    #[error("fork {0:?} does not support this reward")]
    UnsupportedFork(ForkVariant),
    /// The fork-enum could not be unwrapped to its concrete inner type.
    #[error("internal: state/block variant mismatch")]
    VariantMismatch,
    /// A wrapped state-transition error from a factored STF helper.
    #[error(transparent)]
    Stf(#[from] StateTransitionError),
    /// A wrapped epoch-processing error from a factored phase0 delta fn.
    #[error(transparent)]
    Epoch(#[from] EpochProcessingError),
}

// ── Attestation rewards ─────────────────────────────────────────────────────────

/// Per-fork attestation-reward delta source, blanket-implemented on each
/// concrete `BeaconState` so the `E`-only `attestation_rewards` dispatcher can
/// call it without spelling const generics. The implementor projects to altair
/// (deneb→altair for electra/fulu) and runs the factored delta fns.
pub trait AttestationRewardDeltas<E: BeaconSpec> {
    /// Returns `[(src_r,src_p),(tgt_r,tgt_p),(head_r,head_p)]`, the inactivity
    /// `(rewards, penalties)`, and `base_reward_per_increment` for ideal buckets.
    #[allow(clippy::type_complexity)]
    fn attestation_reward_deltas(
        &self,
    ) -> ([(Vec<Gwei>, Vec<Gwei>); 3], (Vec<Gwei>, Vec<Gwei>), u64);
}

/// Compute attestation rewards for `epoch`, given `state` regenerated at the
/// FIRST slot of `epoch + 1` (the epoch-transition state whose deltas read
/// `epoch`'s participation). `filter` optionally restricts `total_rewards`.
///
/// Per-fork dispatch mirrors `crates/pharos-conformance/src/rewards.rs`.
pub fn attestation_rewards<E: BeaconSpec>(
    state: &E::BeaconState,
    filter: Option<&[u64]>,
) -> Result<AttestationRewardsData, RewardsError>
where
    E::BeaconState: BeaconStateView + BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
    E::AltairBeaconState: AttestationRewardDeltas<E>,
    E::BellatrixBeaconState: AttestationRewardDeltas<E>,
    E::CapellaBeaconState: AttestationRewardDeltas<E>,
    E::DenebBeaconState: AttestationRewardDeltas<E>,
    E::ElectraBeaconState: AttestationRewardDeltas<E>,
    E::FuluBeaconState: AttestationRewardDeltas<E>,
{
    match state.fork_variant() {
        ForkVariant::Phase0 => attestation_rewards_phase0::<E>(state, filter),
        ForkVariant::Altair
        | ForkVariant::Bellatrix
        | ForkVariant::Capella
        | ForkVariant::Deneb
        | ForkVariant::Electra
        | ForkVariant::Fulu => attestation_rewards_altairplus::<E>(state, filter),
    }
}

/// phase0 attestation rewards via the phase0 `get_*_deltas` fns (all `E`-only).
fn attestation_rewards_phase0<E: BeaconSpec>(
    state: &E::BeaconState,
    filter: Option<&[u64]>,
) -> Result<AttestationRewardsData, RewardsError>
where
    E::BeaconState: BeaconStateView + BeaconStateWrite,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    let source = get_source_deltas::<E>(state)?;
    let target = get_target_deltas::<E>(state)?;
    let head = get_head_deltas::<E>(state)?;
    let incl = get_inclusion_delay_deltas::<E>(state)?;
    let inact = get_inactivity_penalty_deltas_phase0::<E>(state)?;

    let n = state.num_validators();
    let total_rewards = (0..n)
        .filter(|i| filter.is_none_or(|f| f.contains(&(*i as u64))))
        .map(|i| AttestationReward {
            validator_index: i as u64,
            head: delta_signed(&head, i),
            target: delta_signed(&target, i),
            source: delta_signed(&source, i),
            inclusion_delay: Some(incl.rewards.as_slice().get(i).map(|g| g.0).unwrap_or(0)),
            inactivity: delta_signed(&inact, i),
        })
        .collect();

    Ok(AttestationRewardsData {
        ideal_rewards: phase0_ideal_rewards::<E>(),
        total_rewards,
    })
}

fn delta_signed(d: &pharos_types::phase0::Deltas<1_099_511_627_776u64>, i: usize) -> i64 {
    let r = d.rewards.as_slice().get(i).map(|g| g.0).unwrap_or(0) as i64;
    let p = d.penalties.as_slice().get(i).map(|g| g.0).unwrap_or(0) as i64;
    r - p
}

/// phase0 ideal-reward buckets: phase0 does not expose a closed-form ideal
/// reward via the delta fns (deltas depend on the full attestation set), so the
/// buckets enumerate effective balances `[INCREMENT ..= MAX_EFFECTIVE_BALANCE]`
/// with zero component values. The `total_rewards` array carries the real
/// per-validator phase0 values (incl. `inclusion_delay`).
fn phase0_ideal_rewards<E: BeaconSpec>() -> Vec<IdealAttestationReward> {
    let incr = E::EFFECTIVE_BALANCE_INCREMENT;
    let max_eb = E::MAX_EFFECTIVE_BALANCE;
    let mut buckets = Vec::new();
    let mut eb = incr;
    while eb <= max_eb {
        buckets.push(IdealAttestationReward {
            effective_balance: eb,
            head: 0,
            target: 0,
            source: 0,
            inclusion_delay: Some(0),
            inactivity: 0,
        });
        eb += incr;
    }
    buckets
}

/// altair..fulu attestation rewards via the `AttestationRewardDeltas` blanket impl.
fn attestation_rewards_altairplus<E: BeaconSpec>(
    state: &E::BeaconState,
    filter: Option<&[u64]>,
) -> Result<AttestationRewardsData, RewardsError>
where
    E::BeaconState: BeaconStateView,
    E::AltairBeaconState: AttestationRewardDeltas<E>,
    E::BellatrixBeaconState: AttestationRewardDeltas<E>,
    E::CapellaBeaconState: AttestationRewardDeltas<E>,
    E::DenebBeaconState: AttestationRewardDeltas<E>,
    E::ElectraBeaconState: AttestationRewardDeltas<E>,
    E::FuluBeaconState: AttestationRewardDeltas<E>,
{
    let variant = state.fork_variant();
    let (flags, inactivity, brpi) = match variant {
        ForkVariant::Altair => E::unwrap_altair_state(state)
            .ok_or(RewardsError::VariantMismatch)?
            .attestation_reward_deltas(),
        ForkVariant::Bellatrix => E::unwrap_bellatrix_state(state)
            .ok_or(RewardsError::VariantMismatch)?
            .attestation_reward_deltas(),
        ForkVariant::Capella => E::unwrap_capella_state(state)
            .ok_or(RewardsError::VariantMismatch)?
            .attestation_reward_deltas(),
        ForkVariant::Deneb => E::unwrap_deneb_state(state)
            .ok_or(RewardsError::VariantMismatch)?
            .attestation_reward_deltas(),
        ForkVariant::Electra => E::unwrap_electra_state(state)
            .ok_or(RewardsError::VariantMismatch)?
            .attestation_reward_deltas(),
        ForkVariant::Fulu => E::unwrap_fulu_state(state)
            .ok_or(RewardsError::VariantMismatch)?
            .attestation_reward_deltas(),
        ForkVariant::Phase0 => return Err(RewardsError::VariantMismatch),
    };

    let [(src_r, src_p), (tgt_r, tgt_p), (head_r, head_p)] = flags;
    let (inact_r, inact_p) = inactivity;
    // Per spec the inactivity delta fn emits rewards = 0 for all validators
    // (only penalties fire during an inactivity leak). Assert the invariant so
    // spec drift is caught early.
    debug_assert!(
        inact_r.iter().all(|g| g.0 == 0),
        "inactivity deltas are penalty-only — spec invariant violated"
    );
    let _inact_r = inact_r;

    let n = head_r.len();
    let total_rewards = (0..n)
        .filter(|i| filter.is_none_or(|f| f.contains(&(*i as u64))))
        .map(|i| AttestationReward {
            validator_index: i as u64,
            head: signed(&head_r, &head_p, i),
            target: signed(&tgt_r, &tgt_p, i),
            source: signed(&src_r, &src_p, i),
            inclusion_delay: None,
            // Inactivity deltas are penalty-only (empty `rewards` vec).
            inactivity: -(inact_p.get(i).map(|g| g.0).unwrap_or(0) as i64),
        })
        .collect();

    // EIP-7251 bucket cap: electra/fulu use `MAX_EFFECTIVE_BALANCE_ELECTRA`,
    // pre-electra forks use `MAX_EFFECTIVE_BALANCE` (exhaustive, no `_ =>`).
    let max_eb = match variant {
        ForkVariant::Electra | ForkVariant::Fulu => E::MAX_EFFECTIVE_BALANCE_ELECTRA,
        ForkVariant::Phase0
        | ForkVariant::Altair
        | ForkVariant::Bellatrix
        | ForkVariant::Capella
        | ForkVariant::Deneb => E::MAX_EFFECTIVE_BALANCE,
    };
    let ideal_rewards = altair_ideal_rewards::<E>(brpi, max_eb);

    Ok(AttestationRewardsData {
        ideal_rewards,
        total_rewards,
    })
}

fn signed(rewards: &[Gwei], penalties: &[Gwei], i: usize) -> i64 {
    let r = rewards.get(i).map(|g| g.0).unwrap_or(0) as i64;
    let p = penalties.get(i).map(|g| g.0).unwrap_or(0) as i64;
    r - p
}

/// altair+ ideal-reward buckets. For a fully-participating validator at
/// effective balance `eb` the ideal source/target/head reward is
/// `base_reward * weight / WEIGHT_DENOMINATOR` (unslashed == active, so the
/// `unslashed_increments / active_increments` ratio is 1), with
/// `base_reward = (eb / EFFECTIVE_BALANCE_INCREMENT) * base_reward_per_increment`.
fn altair_ideal_rewards<E: BeaconSpec>(brpi: u64, max_eb: u64) -> Vec<IdealAttestationReward> {
    let incr = E::EFFECTIVE_BALANCE_INCREMENT;
    let wd = E::WEIGHT_DENOMINATOR;
    let weights = E::PARTICIPATION_FLAG_WEIGHTS; // SOURCE=0, TARGET=1, HEAD=2
    let mut buckets = Vec::new();
    let mut eb = incr;
    while eb <= max_eb {
        let base_reward = (eb / incr) * brpi;
        buckets.push(IdealAttestationReward {
            effective_balance: eb,
            head: (base_reward * weights[2] / wd) as i64,
            target: (base_reward * weights[1] / wd) as i64,
            source: (base_reward * weights[0] / wd) as i64,
            inclusion_delay: None,
            inactivity: 0,
        });
        eb += incr;
    }
    buckets
}

// ── Block rewards ────────────────────────────────────────────────────────────────

/// Per-fork block-reward dispatch, blanket-implemented on each concrete
/// `SignedBeaconBlock` so the `E`-only `block_rewards` entry point can compute
/// the components without spelling const generics.
pub trait BlockRewardsDispatch<E: BeaconSpec> {
    fn block_rewards_dispatch(
        &self,
        pre_state: &E::BeaconState,
    ) -> Result<BlockRewardComponents, RewardsError>;
}

/// Compute the four proposer-reward components for `signed_block`, recomputed
/// against the block's pre-state (NOT balance-diffed).
///
/// `pre_state` MUST be the parent post-state advanced (via `process_slots_fork`)
/// to the block's slot and fork — the exact state the block was applied to.
pub fn block_rewards<E: BeaconSpec>(
    signed_block: &E::SignedBeaconBlock,
    pre_state: &E::BeaconState,
) -> Result<BlockRewardComponents, RewardsError>
where
    E::BeaconState: BeaconStateView,
    E::Phase0SignedBeaconBlock: BlockRewardsDispatch<E>,
    E::AltairSignedBeaconBlock: BlockRewardsDispatch<E>,
    E::BellatrixSignedBeaconBlock: BlockRewardsDispatch<E>,
    E::CapellaSignedBeaconBlock: BlockRewardsDispatch<E>,
    E::DenebSignedBeaconBlock: BlockRewardsDispatch<E>,
    E::ElectraSignedBeaconBlock: BlockRewardsDispatch<E>,
    E::FuluSignedBeaconBlock: BlockRewardsDispatch<E>,
{
    match pre_state.fork_variant() {
        ForkVariant::Phase0 => E::unwrap_phase0_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .block_rewards_dispatch(pre_state),
        ForkVariant::Altair => E::unwrap_altair_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .block_rewards_dispatch(pre_state),
        ForkVariant::Bellatrix => E::unwrap_bellatrix_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .block_rewards_dispatch(pre_state),
        ForkVariant::Capella => E::unwrap_capella_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .block_rewards_dispatch(pre_state),
        ForkVariant::Deneb => E::unwrap_deneb_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .block_rewards_dispatch(pre_state),
        ForkVariant::Electra => E::unwrap_electra_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .block_rewards_dispatch(pre_state),
        ForkVariant::Fulu => E::unwrap_fulu_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .block_rewards_dispatch(pre_state),
    }
}

// ── Sync committee rewards ────────────────────────────────────────────────────────

/// Per-fork sync-committee-reward dispatch, blanket-implemented on each altair+
/// concrete `SignedBeaconBlock`.
pub trait SyncCommitteeRewardsDispatch<E: BeaconSpec> {
    fn sync_committee_rewards_dispatch(
        &self,
        pre_state: &E::BeaconState,
        filter: Option<&[u64]>,
    ) -> Result<Vec<SyncCommitteeReward>, RewardsError>;
}

/// Compute per-member sync-committee rewards for `signed_block` against its
/// pre-state. Pre-altair (phase0) → `UnsupportedFork` (handler maps to 400).
pub fn sync_committee_rewards<E: BeaconSpec>(
    signed_block: &E::SignedBeaconBlock,
    pre_state: &E::BeaconState,
    filter: Option<&[u64]>,
) -> Result<Vec<SyncCommitteeReward>, RewardsError>
where
    E::BeaconState: BeaconStateView,
    E::AltairSignedBeaconBlock: SyncCommitteeRewardsDispatch<E>,
    E::BellatrixSignedBeaconBlock: SyncCommitteeRewardsDispatch<E>,
    E::CapellaSignedBeaconBlock: SyncCommitteeRewardsDispatch<E>,
    E::DenebSignedBeaconBlock: SyncCommitteeRewardsDispatch<E>,
    E::ElectraSignedBeaconBlock: SyncCommitteeRewardsDispatch<E>,
    E::FuluSignedBeaconBlock: SyncCommitteeRewardsDispatch<E>,
{
    match pre_state.fork_variant() {
        ForkVariant::Phase0 => Err(RewardsError::UnsupportedFork(ForkVariant::Phase0)),
        ForkVariant::Altair => E::unwrap_altair_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .sync_committee_rewards_dispatch(pre_state, filter),
        ForkVariant::Bellatrix => E::unwrap_bellatrix_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .sync_committee_rewards_dispatch(pre_state, filter),
        ForkVariant::Capella => E::unwrap_capella_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .sync_committee_rewards_dispatch(pre_state, filter),
        ForkVariant::Deneb => E::unwrap_deneb_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .sync_committee_rewards_dispatch(pre_state, filter),
        ForkVariant::Electra => E::unwrap_electra_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .sync_committee_rewards_dispatch(pre_state, filter),
        ForkVariant::Fulu => E::unwrap_fulu_signed_block(signed_block)
            .ok_or(RewardsError::VariantMismatch)?
            .sync_committee_rewards_dispatch(pre_state, filter),
    }
}

// ── Shared per-attestation altair reward replay ───────────────────────────────────

/// `proposer_reward_denominator` per `specs/altair/beacon-chain.md:540`.
pub(crate) fn proposer_reward_denominator<E: BeaconSpec>() -> u64 {
    (E::WEIGHT_DENOMINATOR - PROPOSER_WEIGHT) * E::WEIGHT_DENOMINATOR / PROPOSER_WEIGHT
}

/// The proposer's whistleblower share for slashing one validator (altair+):
/// `(effective_balance / WHISTLEBLOWER_REWARD_QUOTIENT) * PROPOSER_WEIGHT /
/// WEIGHT_DENOMINATOR`. `electra` selects `WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA`.
///
/// Mirrors the `proposer_reward` arithmetic in `altair::helpers::slash_validator`
/// (and `electra::helpers::slash_validator_electra`).
pub(crate) fn slashing_proposer_reward<E: BeaconSpec>(
    effective_balance: u64,
    electra: bool,
) -> u64 {
    let quotient = if electra {
        E::WHISTLEBLOWER_REWARD_QUOTIENT_ELECTRA
    } else {
        E::WHISTLEBLOWER_REWARD_QUOTIENT
    };
    let whistleblower_reward = effective_balance / quotient;
    whistleblower_reward * PROPOSER_WEIGHT / E::WEIGHT_DENOMINATOR
}

/// phase0 block `attestations` proposer-reward component: per attestation, the
/// proposer earns `get_base_reward(attester) / PROPOSER_REWARD_QUOTIENT` summed
/// over the attestation's attesting indices (the phase0 inclusion-proposer
/// reward, `specs/phase0/beacon-chain.md` `process_attestation` /
/// `get_inclusion_delay_deltas`). `E`-only via `BeaconStateView` + the phase0
/// accessors. The block's pre-state base reward is loop-invariant so the
/// active-balance sqrt is hoisted (bit-identical to per-attester `get_base_reward`).
pub(crate) fn phase0_block_attestations_reward<E: BeaconSpec>(
    pre_state: &E::BeaconState,
    attestations: &[Attestation<2048>],
) -> u64
where
    E::BeaconState: BeaconStateView,
    E::Phase0BeaconBlockBody: BeaconBlockBodyView<Attestation = Attestation<2048>>,
{
    use crate::phase0::accessors::{get_attesting_indices, get_total_active_balance};
    use crate::phase0::helpers::integer_squareroot;

    let sqrt_total = integer_squareroot(get_total_active_balance::<E>(pre_state).0);
    if sqrt_total == 0 {
        return 0;
    }
    let mut total = 0u64;
    for attestation in attestations {
        let indices =
            get_attesting_indices::<E>(pre_state, &attestation.data, &attestation.aggregation_bits);
        for idx in indices {
            let effective_balance = pre_state
                .validator(idx.0 as usize)
                .map(|v| v.effective_balance.0)
                .unwrap_or(0);
            let base_reward =
                effective_balance * E::BASE_REWARD_FACTOR / sqrt_total / E::BASE_REWARDS_PER_EPOCH;
            total += base_reward / E::PROPOSER_REWARD_QUOTIENT;
        }
    }
    total
}

/// Compute `(proposer_slashings, attester_slashings)` proposer-reward gwei from
/// the block's slashings against `pre_state`, replicating the spec's sequential
/// `slash_validator` order (proposer slashings first, then attester slashings)
/// and skipping validators already slashed earlier in the block. `E`-only via
/// `BeaconStateView`.
///
/// `proposer_slashed` carries the `proposer_index` of each `ProposerSlashing`'s
/// `signed_header_1`; `attester_slashed` carries, per `AttesterSlashing`, the
/// sorted intersection of the two indexed attestations' attesting indices.
pub(crate) fn block_slashing_rewards<E: BeaconSpec>(
    pre_state: &E::BeaconState,
    proposer_slashed: &[u64],
    attester_slashed: &[Vec<u64>],
    electra: bool,
) -> (u64, u64)
where
    E::BeaconState: BeaconStateView,
{
    use crate::phase0::predicates::is_slashable_validator;
    let epoch = compute_epoch_at_slot(pre_state.slot(), E::SLOTS_PER_EPOCH).0;
    let mut already: std::collections::HashSet<u64> = std::collections::HashSet::new();

    let reward_for = |index: u64, already: &mut std::collections::HashSet<u64>| -> u64 {
        if already.contains(&index) {
            return 0;
        }
        let Some(v) = pre_state.validator(index as usize) else {
            return 0;
        };
        if !is_slashable_validator(v, epoch) {
            return 0;
        }
        already.insert(index);
        slashing_proposer_reward::<E>(v.effective_balance.0, electra)
    };

    let mut proposer_total = 0u64;
    for &idx in proposer_slashed {
        proposer_total += reward_for(idx, &mut already);
    }
    let mut attester_total = 0u64;
    for indices in attester_slashed {
        for &idx in indices {
            attester_total += reward_for(idx, &mut already);
        }
    }
    (proposer_total, attester_total)
}

/// Replay one attestation's proposer-reward numerator against a (projected,
/// mutable) altair state, mirroring `process_attestation`'s pre-accumulation
/// derivation (committee lookup → attesting indices → participation flag
/// indices) then calling the factored `accumulate_attestation_participation_altair`.
///
/// `eip7045` selects the deneb+ target-flag rule (altair/bellatrix/capella =
/// `false`; deneb/electra/fulu = `true`).
///
/// `brpi` is `get_base_reward_per_increment(altair)`, which the CALLER must hoist
/// outside any enclosing attestation loop to avoid O(N_validators) active-balance
/// scans per attestation.
///
/// Returns the per-attestation numerator; the caller divides by
/// `proposer_reward_denominator` per attestation and sums.
#[allow(clippy::type_complexity)]
pub(crate) fn altair_attestation_numerator<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    E,
>(
    altair: &mut pharos_types::altair::BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    attestation: &Attestation<MAX_VALIDATORS_PER_COMMITTEE>,
    eip7045: bool,
    brpi: Gwei,
) -> Result<u64, RewardsError>
where
    E: BeaconSpec<
        AltairBeaconState = pharos_types::altair::BeaconState<
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
    let data: &AttestationData = &attestation.data;
    let current_epoch = compute_epoch_at_slot(altair.slot, E::SLOTS_PER_EPOCH);
    let is_current = data.target.epoch == current_epoch;

    let committee = get_beacon_committee_altair::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(altair, data.slot, data.index.0);

    let attesting_indices: Vec<ValidatorIndex> = committee
        .iter()
        .enumerate()
        .filter_map(|(i, &vi)| {
            if attestation.aggregation_bits.get(i).unwrap_or(false) {
                Some(vi)
            } else {
                None
            }
        })
        .collect();

    let inclusion_delay = altair.slot.0.saturating_sub(data.slot.0);
    let participation_flag_indices = get_attestation_participation_flag_indices::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(altair, data, inclusion_delay, eip7045)?;

    let numerator = accumulate_attestation_participation_altair::<
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
        altair,
        &attesting_indices,
        &participation_flag_indices,
        is_current,
        brpi,
    )?;

    Ok(numerator)
}

/// Compute the `attestations` block-reward component (proposer's share in gwei)
/// by replaying `attestations` against a CLONE of the (projected) altair
/// pre-state. Each attestation's proposer reward is `numerator_i /
/// proposer_reward_denominator` (per-attestation integer division, summed),
/// matching `process_attestation`'s per-attestation reward.
#[allow(clippy::type_complexity)]
pub(crate) fn altair_block_attestations_reward<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const MAX_VALIDATORS_PER_COMMITTEE: u64,
    E,
>(
    altair: &pharos_types::altair::BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    attestations: &[Attestation<MAX_VALIDATORS_PER_COMMITTEE>],
    eip7045: bool,
) -> Result<u64, RewardsError>
where
    E: BeaconSpec<
        AltairBeaconState = pharos_types::altair::BeaconState<
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
    let denom = proposer_reward_denominator::<E>();
    let mut projection = altair.clone();
    // BRPI is loop-invariant across all attestations in the block (total active
    // balance does not change as participation flags accumulate). Hoist once here
    // to avoid O(N_attestations × N_validators) active-balance scans.
    let brpi = get_base_reward_per_increment::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&projection);
    let mut total = 0u64;
    for attestation in attestations {
        let numerator = altair_attestation_numerator::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            MAX_VALIDATORS_PER_COMMITTEE,
            E,
        >(&mut projection, attestation, eip7045, brpi)?;
        total += numerator / denom;
    }
    Ok(total)
}

/// Electra (EIP-7549) variant of `altair_block_attestations_reward`: attesting
/// indices come from `get_attesting_indices_electra` (committee-bits iteration)
/// against the `E::BeaconState` pre-state, then the participation flags +
/// numerator accumulate on the electra→altair projection (eip7045 = true).
#[allow(clippy::type_complexity)]
pub(crate) fn electra_block_attestations_reward<
    const SLOTS_PER_HISTORICAL_ROOT: u64,
    const HISTORICAL_ROOTS_LIMIT: u64,
    const ETH1_DATA_VOTES_LIMIT: u64,
    const VALIDATOR_REGISTRY_LIMIT: u64,
    const EPOCHS_PER_HISTORICAL_VECTOR: u64,
    const EPOCHS_PER_SLASHINGS_VECTOR: u64,
    const JUSTIFICATION_BITS_LENGTH: u64,
    const SYNC_COMMITTEE_SIZE: u64,
    const MAX_AGGREGATION_BITS: u64,
    const MAX_COMMITTEES_PER_SLOT: u64,
    E,
>(
    pre_state: &E::BeaconState,
    altair: &pharos_types::altair::BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    attestations: &[pharos_types::electra::attestation::Attestation<
        MAX_AGGREGATION_BITS,
        MAX_COMMITTEES_PER_SLOT,
    >],
) -> Result<u64, RewardsError>
where
    E: BeaconSpec<
        AltairBeaconState = pharos_types::altair::BeaconState<
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
    let denom = proposer_reward_denominator::<E>();
    let mut projection = altair.clone();
    // BRPI is loop-invariant: total active balance does not change as we replay
    // attestations (only participation flags change). Hoist to avoid O(N²).
    let brpi = get_base_reward_per_increment::<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
        E,
    >(&projection);
    let mut total = 0u64;
    for attestation in attestations {
        let current_epoch = compute_epoch_at_slot(projection.slot, E::SLOTS_PER_EPOCH);
        let is_current = attestation.data.target.epoch == current_epoch;

        let attesting_indices = crate::electra::helpers::get_attesting_indices_electra::<
            MAX_AGGREGATION_BITS,
            MAX_COMMITTEES_PER_SLOT,
            E,
        >(pre_state, attestation);

        let inclusion_delay = projection.slot.0.saturating_sub(attestation.data.slot.0);
        let participation_flag_indices =
            get_attestation_participation_flag_indices::<
                SLOTS_PER_HISTORICAL_ROOT,
                HISTORICAL_ROOTS_LIMIT,
                ETH1_DATA_VOTES_LIMIT,
                VALIDATOR_REGISTRY_LIMIT,
                EPOCHS_PER_HISTORICAL_VECTOR,
                EPOCHS_PER_SLASHINGS_VECTOR,
                JUSTIFICATION_BITS_LENGTH,
                SYNC_COMMITTEE_SIZE,
                E,
            >(&projection, &attestation.data, inclusion_delay, true)?;

        let numerator = accumulate_attestation_participation_altair::<
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
            &mut projection,
            &attesting_indices,
            &participation_flag_indices,
            is_current,
            brpi,
        )?;
        total += numerator / denom;
    }
    Ok(total)
}

/// Compute the `sync_aggregate` block-reward component (proposer's share in
/// gwei): `sync_proposer_reward * participant_count`, where
/// `sync_proposer_reward` is from the factored `sync_aggregate_rewards_altair`
/// and `participant_count` is the number of set `sync_committee_bits`.
pub(crate) fn altair_block_sync_reward<
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
    altair: &pharos_types::altair::BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    participant_count: u64,
) -> u64
where
    E: BeaconSpec<
        AltairBeaconState = pharos_types::altair::BeaconState<
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
    let (_participant_reward, proposer_reward) =
        crate::altair::operations::sync_aggregate::sync_aggregate_rewards_altair::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(altair);
    proposer_reward.0 * participant_count
}

/// Compute per-member sync-committee rewards against a (projected) altair
/// pre-state: `+participant_reward` when the member's `sync_committee_bits` bit
/// is set, `-participant_reward` otherwise, mirroring `process_sync_aggregate`.
/// The pubkey→index map is built per the op's invariant (every sync-committee
/// pubkey appears in `state.validators`). `filter` restricts the output set.
#[allow(clippy::type_complexity)]
pub(crate) fn altair_sync_committee_rewards<
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
    altair: &pharos_types::altair::BeaconState<
        SLOTS_PER_HISTORICAL_ROOT,
        HISTORICAL_ROOTS_LIMIT,
        ETH1_DATA_VOTES_LIMIT,
        VALIDATOR_REGISTRY_LIMIT,
        EPOCHS_PER_HISTORICAL_VECTOR,
        EPOCHS_PER_SLASHINGS_VECTOR,
        JUSTIFICATION_BITS_LENGTH,
        SYNC_COMMITTEE_SIZE,
    >,
    sync_committee_bits: &pharos_ssz::Bitvector<SYNC_COMMITTEE_SIZE>,
    filter: Option<&[u64]>,
) -> Vec<SyncCommitteeReward>
where
    E: BeaconSpec<
        AltairBeaconState = pharos_types::altair::BeaconState<
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
    let (participant_reward, _proposer_reward) =
        crate::altair::operations::sync_aggregate::sync_aggregate_rewards_altair::<
            SLOTS_PER_HISTORICAL_ROOT,
            HISTORICAL_ROOTS_LIMIT,
            ETH1_DATA_VOTES_LIMIT,
            VALIDATOR_REGISTRY_LIMIT,
            EPOCHS_PER_HISTORICAL_VECTOR,
            EPOCHS_PER_SLASHINGS_VECTOR,
            JUSTIFICATION_BITS_LENGTH,
            SYNC_COMMITTEE_SIZE,
            E,
        >(altair);

    use pharos_ssz::SszSequence;
    let pubkey_to_index: std::collections::HashMap<pharos_utils::BLSPubkey, u64> = altair
        .validators
        .iter()
        .enumerate()
        .map(|(i, v)| (v.pubkey, i as u64))
        .collect();

    let pr = participant_reward.0 as i64;
    altair
        .current_sync_committee
        .pubkeys
        .as_slice()
        .iter()
        .enumerate()
        .filter_map(|(i, pk)| {
            let validator_index = *pubkey_to_index.get(pk)?;
            if filter.is_some_and(|f| !f.contains(&validator_index)) {
                return None;
            }
            let reward = if sync_committee_bits.get(i).unwrap_or(false) {
                pr
            } else {
                -pr
            };
            Some(SyncCommitteeReward {
                validator_index,
                reward,
            })
        })
        .collect()
}
