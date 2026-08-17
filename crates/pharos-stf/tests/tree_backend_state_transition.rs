//! Naive-vs-Tree backend equivalence for the full `state_transition`.
//!
//! Conformance decodes states as `Backend::Flat` (`D-no-tree-backend-on-decode`),
//! so it NEVER exercises the tree backend for the packed fields (`balances`,
//! `slashings`). The live node, however, converts states via `into_tree_backend()`
//! at every entry point. This test closes that verification gap: for each fork it
//! runs `state_transition` on a Naive pre-state and on the `into_tree_backend()`
//! conversion of the same state, and asserts the post-state roots are byte-
//! identical. For capella+ this exercises `process_withdrawals`, which reads
//! `balances` on the tree backend — the primary place a missed `as_slice()` would
//! panic.

use std::path::{Path, PathBuf};

use pharos_ssz::Decode;
use pharos_ssz::tree_hash::TreeHash;
use pharos_stf::{ForkEpochs, NullExecutionEngine, process_slots_fork, state_transition};
use pharos_types::MainnetBeaconSpec as E;
use pharos_types::config::RuntimeConfig;
use pharos_types::phase0::primitives::Slot;
use pharos_types::{BeaconSpec, BeaconStateView};

/// A `RuntimeConfig` with every fork epoch at `u64::MAX` so `process_slots_fork`
/// never upgrades — it just runs the current state-variant's slot/epoch
/// processing across the boundary.
fn no_upgrade_cfg() -> RuntimeConfig {
    RuntimeConfig {
        altair_fork_epoch: u64::MAX,
        bellatrix_fork_epoch: u64::MAX,
        capella_fork_epoch: u64::MAX,
        deneb_fork_epoch: u64::MAX,
        electra_fork_epoch: u64::MAX,
        fulu_fork_epoch: u64::MAX,
        ..Default::default()
    }
}

fn fixtures_root() -> Option<PathBuf> {
    let root = std::env::var("PHAROS_SPEC_TESTS").map_or_else(
        |_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_owned());
            PathBuf::from(home).join(".cache").join("pharos-spec-tests")
        },
        PathBuf::from,
    );
    root.join("mainnet").is_dir().then_some(root)
}

fn load_ssz_snappy<S: Decode>(path: &Path) -> S {
    let compressed = std::fs::read(path).unwrap_or_else(|_| panic!("missing fixture {path:?}"));
    let raw = snap::raw::Decoder::new()
        .decompress_vec(&compressed)
        .unwrap_or_else(|e| panic!("snappy {path:?}: {e}"));
    S::from_ssz_bytes(&raw).unwrap_or_else(|e| panic!("ssz {path:?}: {e:?}"))
}

/// Run `state_transition` over the `empty_block_transition` fixture on both
/// backends and assert byte-identical post-state roots.
macro_rules! check_fork {
    ($root:expr, $fork:literal, $State:ident, $Block:ident, $into_state:ident, $into_block:ident) => {{
        let dir = $root.join(format!(
            "mainnet/{}/sanity/blocks/pyspec_tests/empty_block_transition",
            $fork
        ));
        let pre: <E as BeaconSpec>::$State = load_ssz_snappy(&dir.join("pre.ssz_snappy"));
        let blk: <E as BeaconSpec>::$Block = load_ssz_snappy(&dir.join("blocks_0.ssz_snappy"));
        let naive_pre = E::$into_state(pre);
        let block = E::$into_block(blk);
        let tree_pre = naive_pre
            .clone()
            .into_tree_backend()
            .expect("into_tree_backend");

        let engine = NullExecutionEngine;
        let cfg = RuntimeConfig::default();
        let naive_post =
            state_transition::<E, NullExecutionEngine>(naive_pre, &block, &engine, false, &cfg)
                .map(|(s, _)| s)
                .unwrap_or_else(|e| panic!("{} naive state_transition: {e:?}", $fork));
        let tree_post =
            state_transition::<E, NullExecutionEngine>(tree_pre, &block, &engine, false, &cfg)
                .map(|(s, _)| s)
                .unwrap_or_else(|e| panic!("{} tree state_transition: {e:?}", $fork));

        assert_eq!(
            naive_post.tree_hash_root(),
            tree_post.tree_hash_root(),
            "{} post-state root differs between Naive and Tree backends",
            $fork
        );
    }};
}

#[test]
fn tree_and_naive_state_transition_agree() {
    let Some(root) = fixtures_root() else {
        eprintln!("skipping: no spec-test fixtures (run scripts/fetch-spec-tests.sh)");
        return;
    };

    check_fork!(
        root,
        "phase0",
        Phase0BeaconState,
        Phase0SignedBeaconBlock,
        phase0_into_state,
        phase0_into_signed_block
    );
    check_fork!(
        root,
        "altair",
        AltairBeaconState,
        AltairSignedBeaconBlock,
        altair_into_state,
        altair_into_signed_block
    );
    check_fork!(
        root,
        "bellatrix",
        BellatrixBeaconState,
        BellatrixSignedBeaconBlock,
        bellatrix_into_state,
        bellatrix_into_signed_block
    );
    check_fork!(
        root,
        "capella",
        CapellaBeaconState,
        CapellaSignedBeaconBlock,
        capella_into_state,
        capella_into_signed_block
    );
    check_fork!(
        root,
        "deneb",
        DenebBeaconState,
        DenebSignedBeaconBlock,
        deneb_into_state,
        deneb_into_signed_block
    );
    check_fork!(
        root,
        "electra",
        ElectraBeaconState,
        ElectraSignedBeaconBlock,
        electra_into_state,
        electra_into_signed_block
    );
    check_fork!(
        root,
        "fulu",
        FuluBeaconState,
        FuluSignedBeaconBlock,
        fulu_into_state,
        fulu_into_signed_block
    );
}

/// Advance the `over_epoch_boundary` slots fixture (32 slots) on both backends
/// and assert each reaches the fixture's post-state root. This is the gate the
/// block-only test can't provide: it exercises `process_epoch` — rewards,
/// `process_slashings`, inactivity updates, and effective-balance updates — on
/// the tree-backed `balances`/`slashings`/`inactivity_scores`/participation
/// fields. Asserting against the spec fixture's `post` proves the tree path is
/// not just self-consistent but spec-correct.
macro_rules! check_epoch {
    ($root:expr, $fork:literal, $State:ident, $into_state:ident) => {{
        let dir = $root.join(format!(
            "mainnet/{}/sanity/slots/pyspec_tests/over_epoch_boundary",
            $fork
        ));
        let pre: <E as BeaconSpec>::$State = load_ssz_snappy(&dir.join("pre.ssz_snappy"));
        let post: <E as BeaconSpec>::$State = load_ssz_snappy(&dir.join("post.ssz_snappy"));
        let naive_pre = E::$into_state(pre);
        let expected = E::$into_state(post).tree_hash_root();
        let target = Slot(naive_pre.slot().0 + 32);
        let cfg = no_upgrade_cfg();

        let mut naive = naive_pre.clone();
        process_slots_fork::<E>(&mut naive, target, ForkEpochs::from_runtime_cfg(&cfg), &cfg)
            .unwrap_or_else(|e| panic!("{} naive process_slots_fork: {e:?}", $fork));
        assert_eq!(
            naive.tree_hash_root(),
            expected,
            "{} fixture sanity: naive post-root != fixture post",
            $fork
        );

        let mut tree = naive_pre.into_tree_backend().expect("into_tree_backend");
        process_slots_fork::<E>(&mut tree, target, ForkEpochs::from_runtime_cfg(&cfg), &cfg)
            .unwrap_or_else(|e| panic!("{} tree process_slots_fork: {e:?}", $fork));
        assert_eq!(
            tree.tree_hash_root(),
            expected,
            "{} tree-backed epoch processing post-root != fixture post",
            $fork
        );
    }};
}

#[test]
fn tree_and_naive_epoch_processing_agree() {
    let Some(root) = fixtures_root() else {
        eprintln!("skipping: no spec-test fixtures");
        return;
    };

    check_epoch!(root, "phase0", Phase0BeaconState, phase0_into_state);
    check_epoch!(root, "altair", AltairBeaconState, altair_into_state);
    check_epoch!(
        root,
        "bellatrix",
        BellatrixBeaconState,
        bellatrix_into_state
    );
    check_epoch!(root, "capella", CapellaBeaconState, capella_into_state);
    check_epoch!(root, "deneb", DenebBeaconState, deneb_into_state);
    check_epoch!(root, "electra", ElectraBeaconState, electra_into_state);
    check_epoch!(root, "fulu", FuluBeaconState, fulu_into_state);
}
