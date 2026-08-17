//! Miscellaneous Phase 0 containers.
//!
//! Containers from `specs/phase0/beacon-chain.md` Misc dependencies section
//! (lines 363-487). Containers defined after line 447 in that section
//! (`DepositMessage`, `DepositData`, `BeaconBlockHeader`, `SigningData`) live
//! in `operations.rs`.

use pharos_ssz::{Bitlist, Decode, Encode, SszList, SszVector, TreeHash, TreeHashType, merkleize};
use pharos_utils::{BLSPubkey, BLSSignature, Bytes32, Hash256};

use crate::phase0::primitives::{CommitteeIndex, Epoch, Gwei, Root, Slot, ValidatorIndex, Version};

// ── Fork ──────────────────────────────────────────────────────────────────────

/// `Fork` per `specs/phase0/beacon-chain.md:366-370`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Fork {
    /// `previous_version: Version` — `specs/phase0/beacon-chain.md:367`.
    pub previous_version: Version,
    /// `current_version: Version` — `specs/phase0/beacon-chain.md:368`.
    pub current_version: Version,
    /// `epoch: Epoch` — `specs/phase0/beacon-chain.md:369`.
    pub epoch: Epoch,
}

// ── ForkData ──────────────────────────────────────────────────────────────────

/// `ForkData` per `specs/phase0/beacon-chain.md:375-378`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct ForkData {
    /// `current_version: Version` — `specs/phase0/beacon-chain.md:376`.
    pub current_version: Version,
    /// `genesis_validators_root: Root` — `specs/phase0/beacon-chain.md:377`.
    pub genesis_validators_root: Root,
}

// ── Checkpoint ────────────────────────────────────────────────────────────────

/// `Checkpoint` per `specs/phase0/beacon-chain.md:383-386`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default, Hash)]
pub struct Checkpoint {
    /// `epoch: Epoch` — `specs/phase0/beacon-chain.md:384`.
    pub epoch: Epoch,
    /// `root: Root` — `specs/phase0/beacon-chain.md:385`.
    pub root: Root,
}

// ── Validator ─────────────────────────────────────────────────────────────────

/// `Validator` per `specs/phase0/beacon-chain.md:391-400`.
#[derive(Encode, Decode, Debug, Default)]
pub struct Validator {
    /// `pubkey: BLSPubkey` — `specs/phase0/beacon-chain.md:392`.
    pub pubkey: BLSPubkey,
    /// `withdrawal_credentials: Bytes32` — `specs/phase0/beacon-chain.md:393`.
    pub withdrawal_credentials: Bytes32,
    /// `effective_balance: Gwei` — `specs/phase0/beacon-chain.md:394`.
    pub effective_balance: Gwei,
    /// `slashed: boolean` — `specs/phase0/beacon-chain.md:395`.
    pub slashed: bool,
    /// `activation_eligibility_epoch: Epoch` — `specs/phase0/beacon-chain.md:396`.
    pub activation_eligibility_epoch: Epoch,
    /// `activation_epoch: Epoch` — `specs/phase0/beacon-chain.md:397`.
    pub activation_epoch: Epoch,
    /// `exit_epoch: Epoch` — `specs/phase0/beacon-chain.md:398`.
    pub exit_epoch: Epoch,
    /// `withdrawable_epoch: Epoch` — `specs/phase0/beacon-chain.md:399`.
    pub withdrawable_epoch: Epoch,
    /// Cached Merkle root — excluded from SSZ wire encoding.
    #[doc(hidden)]
    #[ssz(skip)]
    pub cached_root: std::sync::OnceLock<Hash256>,
}

impl TreeHash for Validator {
    const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;

    fn tree_hash_root(&self) -> Hash256 {
        *self.cached_root.get_or_init(|| {
            #[cfg(test)]
            VALIDATOR_HASH_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let roots: &[Hash256] = &[
                self.pubkey.tree_hash_root(),
                self.withdrawal_credentials.tree_hash_root(),
                self.effective_balance.tree_hash_root(),
                self.slashed.tree_hash_root(),
                self.activation_eligibility_epoch.tree_hash_root(),
                self.activation_epoch.tree_hash_root(),
                self.exit_epoch.tree_hash_root(),
                self.withdrawable_epoch.tree_hash_root(),
            ];
            // 8 fields = power-of-two; `merkleize(roots)` and
            // `merkleize_padded(roots, 8)` are equivalent here.
            merkleize(roots)
        })
    }

    fn tree_hash_packed_encoding(&self) -> Vec<u8> {
        unreachable!("containers are not basic types and are never packed")
    }
}

impl PartialEq for Validator {
    fn eq(&self, o: &Self) -> bool {
        self.pubkey == o.pubkey
            && self.withdrawal_credentials == o.withdrawal_credentials
            && self.effective_balance == o.effective_balance
            && self.slashed == o.slashed
            && self.activation_eligibility_epoch == o.activation_eligibility_epoch
            && self.activation_epoch == o.activation_epoch
            && self.exit_epoch == o.exit_epoch
            && self.withdrawable_epoch == o.withdrawable_epoch
    }
}

impl Eq for Validator {}

/// `Clone` resets `cached_root` to empty.
///
/// Without this, the clone-mutate-`with_set` pattern used throughout the STF
/// (e.g. `let mut v = state.validators.get(i).clone(); v.exit_epoch = X;
/// state.validators = state.validators.with_set(i, v)?;`) would carry the
/// pre-mutation root forward, producing stale `tree_hash_root()` results.
/// Resetting on clone makes cache invalidation automatic for every mutation
/// path that goes through clone-then-mutate.
impl Clone for Validator {
    fn clone(&self) -> Self {
        Self {
            pubkey: self.pubkey,
            withdrawal_credentials: self.withdrawal_credentials,
            effective_balance: self.effective_balance,
            slashed: self.slashed,
            activation_eligibility_epoch: self.activation_eligibility_epoch,
            activation_epoch: self.activation_epoch,
            exit_epoch: self.exit_epoch,
            withdrawable_epoch: self.withdrawable_epoch,
            cached_root: std::sync::OnceLock::new(),
        }
    }
}

impl Validator {
    /// Clears the cached Merkle root, forcing recomputation on the next
    /// `tree_hash_root()` call.
    ///
    /// `Clone` already resets the cache, so the common clone-mutate-`with_set`
    /// pattern does not need this. Use only when mutating a `&mut Validator`
    /// in place (i.e. without going through `clone`).
    pub fn invalidate_cache(&mut self) {
        self.cached_root.take();
    }

    /// Returns `true` if the cached Merkle root has been computed at least once.
    ///
    /// Used in tests to verify cache semantics.
    #[cfg(test)]
    pub fn cached_root_is_populated(&self) -> bool {
        self.cached_root.get().is_some()
    }
}

/// Counter incremented inside the `OnceLock` init closure (test-only).
/// Used to detect whether `tree_hash_root` recomputed or served from cache.
#[cfg(test)]
static VALIDATOR_HASH_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

// ── AttestationData ───────────────────────────────────────────────────────────

/// `AttestationData` per `specs/phase0/beacon-chain.md:405-411`.
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct AttestationData {
    /// `slot: Slot` — `specs/phase0/beacon-chain.md:406`.
    pub slot: Slot,
    /// `index: CommitteeIndex` — `specs/phase0/beacon-chain.md:407`.
    pub index: CommitteeIndex,
    /// `beacon_block_root: Root` — `specs/phase0/beacon-chain.md:408`.
    pub beacon_block_root: Root,
    /// `source: Checkpoint` — `specs/phase0/beacon-chain.md:409`.
    pub source: Checkpoint,
    /// `target: Checkpoint` — `specs/phase0/beacon-chain.md:410`.
    pub target: Checkpoint,
}

// ── Eth1Data ──────────────────────────────────────────────────────────────────

/// `Eth1Data` per `specs/phase0/beacon-chain.md:435-439`.
///
/// Note: spec field `block_hash` is `Hash32` (alias for `Bytes32`); we use
/// `pharos_utils::Hash256` which is the same type (`FixedBytes<32>`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct Eth1Data {
    /// `deposit_root: Root` — `specs/phase0/beacon-chain.md:436`.
    pub deposit_root: Root,
    /// `deposit_count: uint64` — `specs/phase0/beacon-chain.md:437`.
    pub deposit_count: u64,
    /// `block_hash: Hash32` (= Bytes32) — `specs/phase0/beacon-chain.md:438`.
    pub block_hash: pharos_utils::Hash256,
}

// ── HistoricalBatch ───────────────────────────────────────────────────────────

/// `HistoricalBatch` per `specs/phase0/beacon-chain.md:444-447`.
///
/// Generic over `SLOTS_PER_HISTORICAL_ROOT` (a flat `u64` const).
///
/// For mainnet: `SLOTS_PER_HISTORICAL_ROOT = 8192`
/// (`presets/mainnet/phase0.yaml:42`).
/// For minimal: `SLOTS_PER_HISTORICAL_ROOT = 64`
/// (`presets/minimal/phase0.yaml:42`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq)]
pub struct HistoricalBatch<const SLOTS_PER_HISTORICAL_ROOT: u64> {
    /// `block_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`
    /// — `specs/phase0/beacon-chain.md:445`.
    pub block_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>,
    /// `state_roots: Vector[Root, SLOTS_PER_HISTORICAL_ROOT]`
    /// — `specs/phase0/beacon-chain.md:446`.
    pub state_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>,
}

impl<const SLOTS_PER_HISTORICAL_ROOT: u64> Default for HistoricalBatch<SLOTS_PER_HISTORICAL_ROOT>
where
    Root: Default + Clone,
{
    fn default() -> Self {
        Self {
            block_roots: SszVector::default(),
            state_roots: SszVector::default(),
        }
    }
}

// ── IndexedAttestation ────────────────────────────────────────────────────────

/// `IndexedAttestation` per `specs/phase0/beacon-chain.md:416-420`.
///
/// Generic over `MAX_VALIDATORS_PER_COMMITTEE` (a flat `u64` const).
///
/// For mainnet and minimal: `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct IndexedAttestation<const MAX_VALIDATORS_PER_COMMITTEE: u64> {
    /// `attesting_indices: List[ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE]`
    /// — `specs/phase0/beacon-chain.md:417`.
    pub attesting_indices: SszList<ValidatorIndex, MAX_VALIDATORS_PER_COMMITTEE>,
    /// `data: AttestationData` — `specs/phase0/beacon-chain.md:418`.
    pub data: AttestationData,
    /// `signature: BLSSignature` — `specs/phase0/beacon-chain.md:419`.
    pub signature: BLSSignature,
}

// ── PendingAttestation ────────────────────────────────────────────────────────

/// `PendingAttestation` per `specs/phase0/beacon-chain.md:425-430`.
///
/// Generic over `MAX_VALIDATORS_PER_COMMITTEE` (a flat `u64` const).
///
/// For mainnet and minimal: `MAX_VALIDATORS_PER_COMMITTEE = 2048`
/// (`presets/mainnet/phase0.yaml:10`, `presets/minimal/phase0.yaml:10`).
#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]
pub struct PendingAttestation<const MAX_VALIDATORS_PER_COMMITTEE: u64> {
    /// `aggregation_bits: Bitlist[MAX_VALIDATORS_PER_COMMITTEE]`
    /// — `specs/phase0/beacon-chain.md:426`.
    pub aggregation_bits: Bitlist<MAX_VALIDATORS_PER_COMMITTEE>,
    /// `data: AttestationData` — `specs/phase0/beacon-chain.md:427`.
    pub data: AttestationData,
    /// `inclusion_delay: Slot` — `specs/phase0/beacon-chain.md:428`.
    pub inclusion_delay: Slot,
    /// `proposer_index: ValidatorIndex` — `specs/phase0/beacon-chain.md:429`.
    pub proposer_index: ValidatorIndex,
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_ssz::{Decode, Encode};

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test]
    fn validator_root_cache_populates() {
        let v = Validator::default();
        assert!(
            !v.cached_root_is_populated(),
            "cache must be empty before first call"
        );
        let root1 = v.tree_hash_root();
        assert!(
            v.cached_root_is_populated(),
            "cache must be populated after first call"
        );
        let root2 = v.tree_hash_root();
        assert_eq!(root1, root2, "both calls must return the same root");
    }

    #[test]
    fn validator_clone_resets_cache() {
        use std::sync::atomic::Ordering::SeqCst;

        let v = Validator::default();
        let before = VALIDATOR_HASH_CALLS.load(SeqCst);

        // First call: populates cache; counter increments by exactly 1.
        let root = v.tree_hash_root();
        let after_first = VALIDATOR_HASH_CALLS.load(SeqCst);
        assert_eq!(
            after_first - before,
            1,
            "exactly one computation on first call"
        );

        // Clone resets the cache by design (prevents stale roots after
        // clone-mutate-`with_set`). The cloned validator's cache is empty.
        let cloned = v.clone();
        assert!(
            !cloned.cached_root_is_populated(),
            "clone must reset cache (clone-resets-cache invariant)"
        );

        // tree_hash_root on clone recomputes — counter increments by 1.
        let clone_root = cloned.tree_hash_root();
        let after_clone = VALIDATOR_HASH_CALLS.load(SeqCst);
        assert_eq!(
            after_clone - after_first,
            1,
            "clone must recompute on first tree_hash_root call"
        );
        assert_eq!(root, clone_root, "clone root must equal original root");
    }

    #[test]
    fn with_set_resets_validator_cache() {
        use pharos_ssz::{SszList, SszSequence};

        // Use a generous limit constant (2^40, same as mainnet VALIDATOR_REGISTRY_LIMIT).
        const LIMIT: u64 = 1_099_511_627_776;

        // Build a list of 8 validators.
        let items: Vec<Validator> = (0u64..8)
            .map(|i| Validator {
                effective_balance: Gwei(i * 1_000_000_000),
                ..Validator::default()
            })
            .collect();
        let validators: SszList<Validator, LIMIT> =
            SszList::from_vec(items).expect("build validator list");

        let r0 = validators.tree_hash_root();

        // Mutate one validator via with_set — creates a new list with a fresh spine.
        let modified = Validator {
            effective_balance: Gwei(999_999_999_999),
            ..Validator::default()
        };
        let validators2 = validators
            .with_set(7, modified)
            .expect("with_set must succeed");
        let r1 = validators2.tree_hash_root();

        assert_ne!(r0, r1, "root must change when a validator changes");
    }

    #[test]
    fn validator_ssz_byte_identity() {
        let original = Validator {
            effective_balance: Gwei(32_000_000_000),
            slashed: false,
            activation_epoch: Epoch(10),
            ..Validator::default()
        };

        let bytes = original.as_ssz_bytes();
        let decoded = Validator::from_ssz_bytes(&bytes).expect("decode must succeed");

        assert_eq!(
            original, decoded,
            "decoded validator must equal original (cached_root excluded from PartialEq)"
        );
        assert!(
            !decoded.cached_root_is_populated(),
            "decoded validator cache must be empty (reset on decode)"
        );
    }

    #[test]
    fn validator_default_root_matches_pre_m4_perf() {
        // Pre-Phase-3 root of `Validator::default()`, computed from commit 9a54ccc
        // (before the OnceLock cache was introduced) via a throwaway panic probe:
        //   thread panicked: FixedBytes<32>(0xfa324a462bcb0f10c24c9e17c326a4e0ebad204feced523eccaf346c686f06ee)
        // Any change to the 8 Validator fields or their encoding must update this
        // value intentionally.
        let expected = Hash256::from_array([
            0xfa, 0x32, 0x4a, 0x46, 0x2b, 0xcb, 0x0f, 0x10, 0xc2, 0x4c, 0x9e, 0x17, 0xc3, 0x26,
            0xa4, 0xe0, 0xeb, 0xad, 0x20, 0x4f, 0xec, 0xed, 0x52, 0x3e, 0xcc, 0xaf, 0x34, 0x6c,
            0x68, 0x6f, 0x06, 0xee,
        ]);
        assert_eq!(Validator::default().tree_hash_root(), expected);
    }
}
