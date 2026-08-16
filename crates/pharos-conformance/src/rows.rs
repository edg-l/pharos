//! Declarative row table for the conformance report.
//!
//! `row_table()` encodes the exact emission order of `lib.rs::run()` so that
//! Phase 3 can replace the sequential ladder with a single flat work-pool.
//!
//! Phase 1 scaffolding: data only, not yet wired into `run()`.

/// Specification for one row in the conformance report table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowSpec {
    /// Fork name (e.g. `"phase0"`, `"altair"`).
    pub fork: &'static str,
    /// Test category (e.g. `"ssz_static"`, `"operations"`).
    pub category: &'static str,
    /// Preset name, or `"-"` for preset-independent categories.
    pub preset: &'static str,
    /// Optional footnote text to attach to this row.
    ///
    /// Currently only the two `phase0/fork_choice` rows carry a footnote
    /// (the Q1 altair-fixtures note from `lib.rs::run()`).
    pub footnote: Option<&'static str>,
}

/// The exact Q1 footnote text, copied verbatim from the `report.add_footnote`
/// call in `lib.rs::run()`.
const FORK_CHOICE_Q1_FOOTNOTE: &str =
    "Phase-0 fork-choice fixtures do not exist upstream; runner exercises the M1 store against altair fork-choice fixtures. Resolved by M3b (commit `784d75b`): altair containers landed so anchor states now decode and the rows show real pass counts. The skip-unknown-step-keys policy is retained for bellatrix+ step types. Decision recorded in `docs/decisions.md` (Q1).";

/// All 107 conformance rows in the exact order that `lib.rs::run()` emits them.
///
/// The order here MUST match the top-to-bottom row emission in `run()`.
/// Row 0-based index corresponds to `row_ordinal` used by `CaseTask`.
pub fn row_table() -> &'static [RowSpec] {
    const fn r(fork: &'static str, category: &'static str, preset: &'static str) -> RowSpec {
        RowSpec {
            fork,
            category,
            preset,
            footnote: None,
        }
    }
    const fn rf(
        fork: &'static str,
        category: &'static str,
        preset: &'static str,
    ) -> RowSpec {
        RowSpec {
            fork,
            category,
            preset,
            footnote: Some(FORK_CHOICE_Q1_FOOTNOTE),
        }
    }

    static TABLE: &[RowSpec] = &[
        // ── phase0 ──────────────────────────────────────────────────────────
        r("phase0", "ssz_generic", "-"),       // 0
        r("phase0", "ssz_static", "mainnet"),  // 1
        r("phase0", "ssz_static", "minimal"),  // 2
        r("general", "bls", "-"),              // 3
        r("phase0", "shuffling", "mainnet"),   // 4
        r("phase0", "shuffling", "minimal"),   // 5
        r("phase0", "genesis", "minimal"),     // 6
        r("phase0", "operations", "mainnet"),  // 7
        r("phase0", "operations", "minimal"),  // 8
        r("phase0", "epoch_processing", "mainnet"), // 9
        r("phase0", "epoch_processing", "minimal"), // 10
        r("phase0", "sanity", "mainnet"),      // 11
        r("phase0", "sanity", "minimal"),      // 12
        r("phase0", "finality", "mainnet"),    // 13
        r("phase0", "finality", "minimal"),    // 14
        r("phase0", "random", "mainnet"),      // 15
        r("phase0", "random", "minimal"),      // 16
        r("phase0", "rewards", "mainnet"),     // 17
        r("phase0", "rewards", "minimal"),     // 18
        // fork_choice rows carry the Q1 footnote.
        rf("phase0", "fork_choice", "mainnet"), // 19
        rf("phase0", "fork_choice", "minimal"), // 20
        // ── altair ──────────────────────────────────────────────────────────
        r("altair", "transition", "mainnet"),  // 21
        r("altair", "transition", "minimal"),  // 22
        r("altair", "ssz_static", "mainnet"),  // 23
        r("altair", "ssz_static", "minimal"),  // 24
        r("altair", "operations", "mainnet"),  // 25
        r("altair", "operations", "minimal"),  // 26
        r("altair", "epoch_processing", "mainnet"), // 27
        r("altair", "epoch_processing", "minimal"), // 28
        r("altair", "sanity", "mainnet"),      // 29
        r("altair", "sanity", "minimal"),      // 30
        r("altair", "finality", "mainnet"),    // 31
        r("altair", "finality", "minimal"),    // 32
        r("altair", "random", "mainnet"),      // 33
        r("altair", "random", "minimal"),      // 34
        r("altair", "rewards", "mainnet"),     // 35
        r("altair", "rewards", "minimal"),     // 36
        r("altair", "light_client", "mainnet"), // 37
        r("altair", "light_client", "minimal"), // 38
        r("altair", "genesis", "mainnet"),     // 39
        r("altair", "genesis", "minimal"),     // 40
        // ── bellatrix ────────────────────────────────────────────────────────
        r("bellatrix", "transition", "mainnet"),  // 41
        r("bellatrix", "transition", "minimal"),  // 42
        r("bellatrix", "ssz_static", "mainnet"),  // 43
        r("bellatrix", "ssz_static", "minimal"),  // 44
        r("bellatrix", "operations", "mainnet"),  // 45
        r("bellatrix", "operations", "minimal"),  // 46
        r("bellatrix", "epoch_processing", "mainnet"), // 47
        r("bellatrix", "epoch_processing", "minimal"), // 48
        r("bellatrix", "sanity", "mainnet"),      // 49
        r("bellatrix", "sanity", "minimal"),      // 50
        r("bellatrix", "finality", "mainnet"),    // 51
        r("bellatrix", "finality", "minimal"),    // 52
        r("bellatrix", "random", "mainnet"),      // 53
        r("bellatrix", "random", "minimal"),      // 54
        r("bellatrix", "rewards", "mainnet"),     // 55
        r("bellatrix", "rewards", "minimal"),     // 56
        r("bellatrix", "fork_choice", "mainnet"), // 57
        r("bellatrix", "fork_choice", "minimal"), // 58
        // ── capella (transition + ssz_static) ───────────────────────────────
        r("capella", "transition", "mainnet"),  // 59
        r("capella", "transition", "minimal"),  // 60
        r("capella", "ssz_static", "mainnet"),  // 61
        r("capella", "ssz_static", "minimal"),  // 62
        // ── deneb/ssz_static (inserted here by run(), between capella ssz_static
        //    and capella operations) ──────────────────────────────────────────
        r("deneb", "ssz_static", "mainnet"),    // 63
        r("deneb", "ssz_static", "minimal"),    // 64
        // ── capella (remaining) ──────────────────────────────────────────────
        r("capella", "operations", "mainnet"),  // 65
        r("capella", "operations", "minimal"),  // 66
        r("capella", "epoch_processing", "mainnet"), // 67
        r("capella", "epoch_processing", "minimal"), // 68
        r("capella", "sanity", "mainnet"),      // 69
        r("capella", "sanity", "minimal"),      // 70
        r("capella", "finality", "mainnet"),    // 71
        r("capella", "finality", "minimal"),    // 72
        r("capella", "random", "mainnet"),      // 73
        r("capella", "random", "minimal"),      // 74
        r("capella", "rewards", "mainnet"),     // 75
        r("capella", "rewards", "minimal"),     // 76
        r("capella", "fork_choice", "mainnet"), // 77
        r("capella", "fork_choice", "minimal"), // 78
        r("capella", "light_client", "mainnet"), // 79
        r("capella", "light_client", "minimal"), // 80
        // ── sync/optimistic ──────────────────────────────────────────────────
        r("sync", "optimistic", "mainnet"),     // 81
        r("sync", "optimistic", "minimal"),     // 82
        // ── engine/yaml ──────────────────────────────────────────────────────
        r("engine", "yaml", "-"),               // 83
        // ── deneb (remaining) ────────────────────────────────────────────────
        r("deneb", "kzg", "-"),                 // 84
        r("deneb", "merkle_proof", "mainnet"),  // 85
        r("deneb", "merkle_proof", "minimal"),  // 86
        r("deneb", "transition", "mainnet"),    // 87
        r("deneb", "transition", "minimal"),    // 88
        r("deneb", "operations", "mainnet"),    // 89
        r("deneb", "operations", "minimal"),    // 90
        r("deneb", "epoch_processing", "mainnet"), // 91
        r("deneb", "epoch_processing", "minimal"), // 92
        r("deneb", "sanity", "mainnet"),        // 93
        r("deneb", "sanity", "minimal"),        // 94
        r("deneb", "finality", "mainnet"),      // 95
        r("deneb", "finality", "minimal"),      // 96
        r("deneb", "random", "mainnet"),        // 97
        r("deneb", "random", "minimal"),        // 98
        r("deneb", "rewards", "mainnet"),       // 99
        r("deneb", "rewards", "minimal"),       // 100
        r("deneb", "fork_choice", "mainnet"),   // 101
        r("deneb", "fork_choice", "minimal"),   // 102
        r("deneb", "light_client", "mainnet"),  // 103
        r("deneb", "light_client", "minimal"),  // 104
        // ── future forks (placeholders from fill_future_placeholders) ────────
        r("electra", "ssz_static", "-"),        // 105
        r("fulu", "ssz_static", "-"),           // 106
    ];
    TABLE
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard test: `row_table()` projected to `(fork, category, preset)` must
    /// exactly match the emission order of `lib.rs::run()`.
    ///
    /// This test transcribes the expected sequence literally — it is the
    /// byte-order anchor for Phase 3's flat-pool rewrite.
    #[test]
    fn row_table_matches_run_order() {
        let expected: &[(&str, &str, &str)] = &[
            // phase0 group
            ("phase0", "ssz_generic", "-"),
            ("phase0", "ssz_static", "mainnet"),
            ("phase0", "ssz_static", "minimal"),
            ("general", "bls", "-"),
            ("phase0", "shuffling", "mainnet"),
            ("phase0", "shuffling", "minimal"),
            ("phase0", "genesis", "minimal"),
            ("phase0", "operations", "mainnet"),
            ("phase0", "operations", "minimal"),
            ("phase0", "epoch_processing", "mainnet"),
            ("phase0", "epoch_processing", "minimal"),
            ("phase0", "sanity", "mainnet"),
            ("phase0", "sanity", "minimal"),
            ("phase0", "finality", "mainnet"),
            ("phase0", "finality", "minimal"),
            ("phase0", "random", "mainnet"),
            ("phase0", "random", "minimal"),
            ("phase0", "rewards", "mainnet"),
            ("phase0", "rewards", "minimal"),
            ("phase0", "fork_choice", "mainnet"),
            ("phase0", "fork_choice", "minimal"),
            // altair
            ("altair", "transition", "mainnet"),
            ("altair", "transition", "minimal"),
            ("altair", "ssz_static", "mainnet"),
            ("altair", "ssz_static", "minimal"),
            ("altair", "operations", "mainnet"),
            ("altair", "operations", "minimal"),
            ("altair", "epoch_processing", "mainnet"),
            ("altair", "epoch_processing", "minimal"),
            ("altair", "sanity", "mainnet"),
            ("altair", "sanity", "minimal"),
            ("altair", "finality", "mainnet"),
            ("altair", "finality", "minimal"),
            ("altair", "random", "mainnet"),
            ("altair", "random", "minimal"),
            ("altair", "rewards", "mainnet"),
            ("altair", "rewards", "minimal"),
            ("altair", "light_client", "mainnet"),
            ("altair", "light_client", "minimal"),
            ("altair", "genesis", "mainnet"),
            ("altair", "genesis", "minimal"),
            // bellatrix
            ("bellatrix", "transition", "mainnet"),
            ("bellatrix", "transition", "minimal"),
            ("bellatrix", "ssz_static", "mainnet"),
            ("bellatrix", "ssz_static", "minimal"),
            ("bellatrix", "operations", "mainnet"),
            ("bellatrix", "operations", "minimal"),
            ("bellatrix", "epoch_processing", "mainnet"),
            ("bellatrix", "epoch_processing", "minimal"),
            ("bellatrix", "sanity", "mainnet"),
            ("bellatrix", "sanity", "minimal"),
            ("bellatrix", "finality", "mainnet"),
            ("bellatrix", "finality", "minimal"),
            ("bellatrix", "random", "mainnet"),
            ("bellatrix", "random", "minimal"),
            ("bellatrix", "rewards", "mainnet"),
            ("bellatrix", "rewards", "minimal"),
            ("bellatrix", "fork_choice", "mainnet"),
            ("bellatrix", "fork_choice", "minimal"),
            // capella/transition + capella/ssz_static
            ("capella", "transition", "mainnet"),
            ("capella", "transition", "minimal"),
            ("capella", "ssz_static", "mainnet"),
            ("capella", "ssz_static", "minimal"),
            // deneb/ssz_static (emitted before capella/operations in run())
            ("deneb", "ssz_static", "mainnet"),
            ("deneb", "ssz_static", "minimal"),
            // capella remaining
            ("capella", "operations", "mainnet"),
            ("capella", "operations", "minimal"),
            ("capella", "epoch_processing", "mainnet"),
            ("capella", "epoch_processing", "minimal"),
            ("capella", "sanity", "mainnet"),
            ("capella", "sanity", "minimal"),
            ("capella", "finality", "mainnet"),
            ("capella", "finality", "minimal"),
            ("capella", "random", "mainnet"),
            ("capella", "random", "minimal"),
            ("capella", "rewards", "mainnet"),
            ("capella", "rewards", "minimal"),
            ("capella", "fork_choice", "mainnet"),
            ("capella", "fork_choice", "minimal"),
            ("capella", "light_client", "mainnet"),
            ("capella", "light_client", "minimal"),
            // sync/optimistic
            ("sync", "optimistic", "mainnet"),
            ("sync", "optimistic", "minimal"),
            // engine/yaml
            ("engine", "yaml", "-"),
            // deneb remaining
            ("deneb", "kzg", "-"),
            ("deneb", "merkle_proof", "mainnet"),
            ("deneb", "merkle_proof", "minimal"),
            ("deneb", "transition", "mainnet"),
            ("deneb", "transition", "minimal"),
            ("deneb", "operations", "mainnet"),
            ("deneb", "operations", "minimal"),
            ("deneb", "epoch_processing", "mainnet"),
            ("deneb", "epoch_processing", "minimal"),
            ("deneb", "sanity", "mainnet"),
            ("deneb", "sanity", "minimal"),
            ("deneb", "finality", "mainnet"),
            ("deneb", "finality", "minimal"),
            ("deneb", "random", "mainnet"),
            ("deneb", "random", "minimal"),
            ("deneb", "rewards", "mainnet"),
            ("deneb", "rewards", "minimal"),
            ("deneb", "fork_choice", "mainnet"),
            ("deneb", "fork_choice", "minimal"),
            ("deneb", "light_client", "mainnet"),
            ("deneb", "light_client", "minimal"),
            // future placeholders
            ("electra", "ssz_static", "-"),
            ("fulu", "ssz_static", "-"),
        ];

        let table = row_table();
        let actual: Vec<(&str, &str, &str)> = table
            .iter()
            .map(|s| (s.fork, s.category, s.preset))
            .collect();

        assert_eq!(
            actual.len(),
            expected.len(),
            "row count mismatch: got {}, want {}",
            actual.len(),
            expected.len()
        );

        for (i, (act, exp)) in actual.iter().zip(expected.iter()).enumerate() {
            assert_eq!(
                act, exp,
                "row {} mismatch: got {:?}, want {:?}",
                i, act, exp
            );
        }
    }

    /// Exactly the two `phase0/fork_choice` rows carry a footnote; all others
    /// have `footnote: None`.
    #[test]
    fn only_fork_choice_rows_have_footnotes() {
        let table = row_table();

        let footnoted: Vec<(usize, &RowSpec)> = table
            .iter()
            .enumerate()
            .filter(|(_, s)| s.footnote.is_some())
            .collect();

        assert_eq!(
            footnoted.len(),
            2,
            "expected exactly 2 footnoted rows, got {}",
            footnoted.len()
        );

        for (i, spec) in &footnoted {
            assert_eq!(
                spec.fork, "phase0",
                "footnoted row {} has unexpected fork {:?}",
                i,
                spec.fork
            );
            assert_eq!(
                spec.category, "fork_choice",
                "footnoted row {} has unexpected category {:?}",
                i,
                spec.category
            );
            assert!(
                spec.footnote.unwrap().contains("Phase-0 fork-choice"),
                "footnote text at row {} doesn't look right",
                i
            );
        }

        // All non-fork_choice rows must have footnote: None.
        let non_footnoted_wrong: Vec<(usize, &RowSpec)> = table
            .iter()
            .enumerate()
            .filter(|(_, s)| s.footnote.is_none())
            .filter(|(_, s)| s.category == "fork_choice" && s.fork == "phase0")
            .collect();
        assert!(
            non_footnoted_wrong.is_empty(),
            "some phase0/fork_choice rows are missing footnotes: {:?}",
            non_footnoted_wrong
                .iter()
                .map(|(i, _)| i)
                .collect::<Vec<_>>()
        );
    }

    /// Total row count is exactly 107.
    #[test]
    fn row_count_is_107() {
        assert_eq!(row_table().len(), 107);
    }
}
