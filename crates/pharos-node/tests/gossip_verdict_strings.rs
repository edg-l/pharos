//! Spec verdict-string round-trip test.
//!
//! Task 4.2 (M4e Phase 4): assert that every IGNORE/REJECT verdict string in
//! `host_impl.rs` matches a hard-coded list, and that no string with the
//! `"block: "`, `"att: "`, or `"agg: "` prefix exists in the source that is
//! NOT in the list.
//!
//! Approach: `include_str!` the source file at test build time and check each
//! known string is present.  The orphan-string assertion (every prefixed string
//! in the source must also be in the list) catches silent renames or additions.
//!
//! Counts audited from source: block=14, att=15, agg=20, total=49.
//!
//! This test is the gating mechanism for Phase 6's audit, which will compare
//! strings against the spec rule inventory.  Do not modify the list without
//! also updating the corresponding spec-rule mapping in `docs/decisions.md`.

const SRC: &str = include_str!("../src/host_impl.rs");

/// All expected verdict strings, grouped by topic prefix.
const EXPECTED: &[&str] = &[
    // ── block (14) ────────────────────────────────────────────────────────────
    "block: clock unavailable",
    "block: duplicate proposer/slot",
    "block: finalized not ancestor",
    "block: from future slot",
    "block: invalid proposer signature",
    "block: not greater than finalized slot",
    "block: not higher than parent slot",
    "block: parent in invalid set",
    "block: parent invalid",
    "block: parent unseen",
    "block: proposer index out of range",
    "block: proposer mismatch",
    "block: shuffling unavailable",
    "block: unrecognised fork variant",
    // ── att (15) ──────────────────────────────────────────────────────────────
    "att: agg bits length mismatch",
    "att: clock unavailable",
    "att: committee index out of range",
    "att: committee unavailable",
    "att: duplicate validator/epoch",
    "att: finalized not ancestor",
    "att: head state unavailable",
    "att: invalid signature",
    "att: not unaggregated",
    "att: slot not in propagation range",
    "att: target epoch mismatch",
    "att: target not ancestor",
    "att: voted block invalid",
    "att: voted block unseen",
    "att: wrong subnet",
    // ── agg (20) ──────────────────────────────────────────────────────────────
    "agg: agg bits length mismatch",
    "agg: aggregator index out of range",
    "agg: aggregator not in committee",
    "agg: clock unavailable",
    "agg: committee index out of range",
    "agg: committee unavailable",
    "agg: duplicate aggregator/epoch",
    "agg: finalized not ancestor",
    "agg: head state unavailable",
    "agg: invalid aggregate signature",
    "agg: invalid aggregator signature",
    "agg: invalid selection proof signature",
    "agg: no participants",
    "agg: not selected as aggregator",
    "agg: slot not in propagation range",
    "agg: superset seen",
    "agg: target epoch mismatch",
    "agg: target not ancestor",
    "agg: voted block invalid",
    "agg: voted block unseen",
];

/// Extract all quoted strings from `src` that start with one of the topic
/// prefixes.  Returns a sorted, deduplicated `Vec<String>`.
fn extract_prefixed_strings(src: &str) -> Vec<String> {
    let prefixes = ["block: ", "att: ", "agg: "];
    let mut found = std::collections::BTreeSet::new();
    let mut chars = src.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        // Collect up to the closing quote (no multi-line strings in the source).
        let mut s = String::new();
        for ch in chars.by_ref() {
            if ch == '"' {
                break;
            }
            if ch == '\n' {
                // Unclosed quote on this line; discard and restart.
                s.clear();
                break;
            }
            s.push(ch);
        }
        if prefixes.iter().any(|p| s.starts_with(p)) {
            found.insert(s);
        }
    }
    found.into_iter().collect()
}

#[test]
fn verdict_strings_match_known_list() {
    // ── Part 1: every expected string is present in the source ────────────────
    let mut missing: Vec<&str> = Vec::new();
    for &expected in EXPECTED {
        if !SRC.contains(expected) {
            missing.push(expected);
        }
    }
    if !missing.is_empty() {
        panic!(
            "verdict strings missing from host_impl.rs ({} strings):\n  - {}",
            missing.len(),
            missing.join("\n  - ")
        );
    }

    // ── Part 2: no orphan strings in the source not in the expected list ──────
    // Every string with a "block: "/"att: "/"agg: " prefix that appears in the
    // source must be in EXPECTED.  This catches renames or silent additions.
    let in_source = extract_prefixed_strings(SRC);
    let expected_set: std::collections::BTreeSet<&str> = EXPECTED.iter().copied().collect();

    let orphans: Vec<&str> = in_source
        .iter()
        .filter(|s| !expected_set.contains(s.as_str()))
        .map(|s| s.as_str())
        .collect();

    if !orphans.is_empty() {
        panic!(
            "orphan verdict strings found in host_impl.rs not in EXPECTED list ({} strings):\n  - {}\n\nUpdate EXPECTED in gossip_verdict_strings.rs to include them.",
            orphans.len(),
            orphans.join("\n  - ")
        );
    }

    // ── Part 3: counts match expectation ─────────────────────────────────────
    let block_count = EXPECTED.iter().filter(|s| s.starts_with("block: ")).count();
    let att_count = EXPECTED.iter().filter(|s| s.starts_with("att: ")).count();
    let agg_count = EXPECTED.iter().filter(|s| s.starts_with("agg: ")).count();
    assert_eq!(block_count, 14, "expected 14 block: strings");
    assert_eq!(att_count, 15, "expected 15 att: strings");
    assert_eq!(agg_count, 20, "expected 20 agg: strings");
    assert_eq!(EXPECTED.len(), 49, "expected 49 total verdict strings");
}
