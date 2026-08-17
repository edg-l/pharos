//! Per-case task types and outcome aggregation for the flat work-pool runner.

use crate::rows::RowSpec;

/// Outcome of running a single conformance test case.
#[derive(Debug, Clone)]
pub enum CaseOutcome {
    Pass,
    Skip,
    Fail(String),
}

/// A type-erased closure that executes one conformance case.
pub type CaseFn = Box<dyn FnOnce() -> CaseOutcome + Send>;

/// A single runnable conformance case, keyed by stable ordinals.
pub struct CaseTask {
    pub row_ordinal: u32,
    pub case_ordinal: u32,
    pub run: CaseFn,
}

/// Per-row aggregate counts after folding outcomes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowCounts {
    pub row_ordinal: u32,
    pub pass: u64,
    pub fail: u64,
    pub skip: u64,
}

/// Result of folding a set of case outcomes by `(row_ordinal, case_ordinal)`.
#[derive(Debug)]
pub struct FoldOutput {
    /// One entry per row_ordinal that appeared in `outcomes`, sorted by row_ordinal.
    pub rows: Vec<RowCounts>,
    /// Failure messages ordered by (row_ordinal, case_ordinal).
    pub failures: Vec<String>,
    /// Footnote texts for rows that carry one, in row_ordinal encounter order.
    /// Each entry is `(row_ordinal, footnote_text)`.
    pub footnotes: Vec<(u32, &'static str)>,
}

/// Fold a set of `(row_ordinal, case_ordinal, outcome)` tuples into per-row
/// counts and an ordered failure list.
///
/// - Groups by `row_ordinal`, then sorts each group by `case_ordinal`.
/// - Emits failures in `(row_ordinal, case_ordinal)` order.
/// - Emits `footnotes` in ascending `row_ordinal` order for any row in `table`
///   that has `footnote.is_some()` and appears in `outcomes`.
///
/// The `table` slice is used only to look up footnote text; ordinals match the
/// index position in `row_table()` (0-based index → row_ordinal).
pub fn fold(mut outcomes: Vec<(u32, u32, CaseOutcome)>, table: &[RowSpec]) -> FoldOutput {
    // Sort by (row_ordinal, case_ordinal) for deterministic output.
    outcomes.sort_by_key(|(r, c, _)| (*r, *c));

    let mut rows: Vec<RowCounts> = Vec::new();
    let mut failures: Vec<String> = Vec::new();
    let mut footnotes: Vec<(u32, &'static str)> = Vec::new();
    // Track which row_ordinals we have already emitted a footnote for.
    let mut footnoted_rows: std::collections::HashSet<u32> = std::collections::HashSet::new();

    for (row_ord, _case_ord, outcome) in &outcomes {
        // Outcomes are sorted by (row_ordinal, case_ordinal), so all cases for a
        // given row are consecutive — only the tail entry can match.
        if rows.last().map(|e| e.row_ordinal) != Some(*row_ord) {
            rows.push(RowCounts {
                row_ordinal: *row_ord,
                pass: 0,
                fail: 0,
                skip: 0,
            });
        }
        let entry = rows.last_mut().unwrap();

        match outcome {
            CaseOutcome::Pass => entry.pass += 1,
            CaseOutcome::Skip => entry.skip += 1,
            CaseOutcome::Fail(msg) => {
                entry.fail += 1;
                // Push the raw failure message verbatim. Ordering is already
                // guaranteed by the (row_ordinal, case_ordinal) sort above, so no
                // label prefix is needed — and a prefix would break the
                // byte-identity of the Failures section in docs/conformance.md.
                failures.push(msg.clone());
            }
        }

        // Attach footnote on first encounter of a footnoted row, in row_ordinal order.
        if !footnoted_rows.contains(row_ord)
            && let Some(spec) = table.get(*row_ord as usize)
            && let Some(footnote_text) = spec.footnote
        {
            footnotes.push((*row_ord, footnote_text));
            footnoted_rows.insert(*row_ord);
        }
    }

    // Sort rows by row_ordinal (they may have been inserted in encountered order).
    rows.sort_by_key(|r| r.row_ordinal);
    // Sort footnotes by row_ordinal (already in insertion order which is encounter order,
    // but re-sort to guarantee stability).
    footnotes.sort_by_key(|(ord, _)| *ord);

    FoldOutput {
        rows,
        failures,
        footnotes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rows::row_table;

    // ── helpers ──────────────────────────────────────────────────────────────

    fn pass(row: u32, case: u32) -> (u32, u32, CaseOutcome) {
        (row, case, CaseOutcome::Pass)
    }
    fn skip(row: u32, case: u32) -> (u32, u32, CaseOutcome) {
        (row, case, CaseOutcome::Skip)
    }
    fn fail(row: u32, case: u32, msg: &str) -> (u32, u32, CaseOutcome) {
        (row, case, CaseOutcome::Fail(msg.to_owned()))
    }

    // ── basic counts test ─────────────────────────────────────────────────────

    /// Shuffled input → deterministic per-row counts.
    #[test]
    fn fold_counts_are_deterministic_regardless_of_input_order() {
        let table = row_table();

        // Build outcomes for rows 0, 1, 2 in SHUFFLED order.
        let outcomes = vec![
            pass(1, 3),
            fail(0, 2, "bad ssz"),
            pass(0, 0),
            skip(2, 0),
            pass(1, 0),
            pass(0, 1),
            fail(1, 1, "mismatched root"),
            skip(0, 3),
        ];

        let out = fold(outcomes, table);

        // Verify row ordering.
        assert_eq!(out.rows.len(), 3);
        assert_eq!(out.rows[0].row_ordinal, 0);
        assert_eq!(out.rows[1].row_ordinal, 1);
        assert_eq!(out.rows[2].row_ordinal, 2);

        // Row 0: 2 pass, 1 fail, 1 skip.
        assert_eq!(out.rows[0].pass, 2);
        assert_eq!(out.rows[0].fail, 1);
        assert_eq!(out.rows[0].skip, 1);

        // Row 1: 2 pass, 1 fail, 0 skip.
        assert_eq!(out.rows[1].pass, 2);
        assert_eq!(out.rows[1].fail, 1);
        assert_eq!(out.rows[1].skip, 0);

        // Row 2: 0 pass, 0 fail, 1 skip.
        assert_eq!(out.rows[2].pass, 0);
        assert_eq!(out.rows[2].fail, 0);
        assert_eq!(out.rows[2].skip, 1);
    }

    /// Failure messages are ordered by (row_ordinal, case_ordinal) regardless
    /// of the order in which outcomes were supplied.
    #[test]
    fn fold_failures_are_ordered_by_row_then_case() {
        let table = row_table();

        // Deliberately supply failures in reverse order.
        let outcomes = vec![
            fail(2, 5, "err C"),
            fail(0, 3, "err B"),
            fail(0, 1, "err A"),
            fail(2, 0, "err D"),
        ];

        let out = fold(outcomes, table);

        assert_eq!(out.failures.len(), 4);
        // Expected order: (0,1), (0,3), (2,0), (2,5).
        assert!(out.failures[0].contains("err A"), "{:?}", out.failures[0]);
        assert!(out.failures[1].contains("err B"), "{:?}", out.failures[1]);
        assert!(out.failures[2].contains("err D"), "{:?}", out.failures[2]);
        assert!(out.failures[3].contains("err C"), "{:?}", out.failures[3]);
    }

    /// Identical input supplied in two different orderings produces identical output.
    #[test]
    fn fold_output_identical_regardless_of_input_shuffle() {
        let table = row_table();

        let outcomes_a = vec![
            pass(0, 0),
            fail(0, 1, "x"),
            pass(1, 0),
            skip(1, 1),
            fail(2, 2, "y"),
        ];
        // Same elements in reverse order.
        let outcomes_b = vec![
            fail(2, 2, "y"),
            skip(1, 1),
            pass(1, 0),
            fail(0, 1, "x"),
            pass(0, 0),
        ];

        let out_a = fold(outcomes_a, table);
        let out_b = fold(outcomes_b, table);

        assert_eq!(out_a.rows, out_b.rows);
        assert_eq!(out_a.failures, out_b.failures);
    }

    /// Footnote rows are surfaced in row_ordinal order regardless of input order.
    ///
    /// The two phase0/fork_choice rows (ordinals 19 and 20) carry footnotes.
    #[test]
    fn fold_footnotes_surfaced_in_row_ordinal_order() {
        let table = row_table();

        // Verify the expected footnote row ordinals first.
        let footnote_ordinals: Vec<u32> = table
            .iter()
            .enumerate()
            .filter(|(_, s)| s.footnote.is_some())
            .map(|(i, _)| i as u32)
            .collect();
        assert_eq!(
            footnote_ordinals.len(),
            2,
            "expected exactly 2 footnoted rows"
        );
        let fn_ord_0 = footnote_ordinals[0];
        let fn_ord_1 = footnote_ordinals[1];

        // Supply the higher-ordinal footnote row first.
        let outcomes = vec![pass(fn_ord_1, 0), pass(fn_ord_0, 0), pass(fn_ord_0, 1)];

        let out = fold(outcomes, table);

        assert_eq!(out.footnotes.len(), 2);
        // Must be sorted by row_ordinal, not by input order.
        assert_eq!(out.footnotes[0].0, fn_ord_0);
        assert_eq!(out.footnotes[1].0, fn_ord_1);
        // Both must carry the same footnote text (shared footnote).
        assert_eq!(out.footnotes[0].1, out.footnotes[1].1);
        assert!(!out.footnotes[0].1.is_empty());
    }

    /// Empty input yields empty output with no panics.
    #[test]
    fn fold_empty_input_is_valid() {
        let table = row_table();
        let out = fold(vec![], table);
        assert!(out.rows.is_empty());
        assert!(out.failures.is_empty());
        assert!(out.footnotes.is_empty());
    }

    /// A row with only pass outcomes has fail=0, skip=0.
    #[test]
    fn fold_all_pass_row() {
        let table = row_table();
        let outcomes = vec![pass(0, 0), pass(0, 1), pass(0, 2)];
        let out = fold(outcomes, table);
        assert_eq!(out.rows.len(), 1);
        assert_eq!(out.rows[0].pass, 3);
        assert_eq!(out.rows[0].fail, 0);
        assert_eq!(out.rows[0].skip, 0);
        assert!(out.failures.is_empty());
    }
}
