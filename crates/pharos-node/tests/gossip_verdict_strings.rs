//! Spec verdict-string round-trip test.
//!
//! Task 4.2 (M4e Phase 4): assert that every IGNORE/REJECT verdict string in
//! `host_impl.rs` matches a hard-coded list, and that no string with the
//! `"block: "`, `"att: "`, or `"agg: "` prefix exists in the source that is
//! NOT in the list.
//!
//! Approach: `include_str!` the source files at test build time and check each
//! known string is present.  The orphan-string assertion (every prefixed string
//! in the source must also be in the list) catches silent renames or additions.
//!
//! `GOSSIP_REASON_PARENT_UNSEEN` ("block: parent unseen") is a const defined in
//! `pharos-network/src/host.rs` (single source of truth per D-parent-unseen-sentinel).
//! Part 1 and Part 2 therefore scan both source files.
//!
//! Counts audited from source: block=14, att=15, agg=20, total=49.
//!
//! This test is the gating mechanism for Phase 6's audit, which will compare
//! strings against the spec rule inventory.  Do not modify the list without
//! also updating the corresponding spec-rule mapping in `docs/decisions.md`.

const SRC: &str = include_str!("../src/host_impl.rs");
/// Also scan the network crate's host.rs where `GOSSIP_REASON_PARENT_UNSEEN` is defined.
const NETWORK_HOST_SRC: &str = include_str!("../../../crates/pharos-network/src/host.rs");

/// All expected verdict strings, grouped by topic prefix.
///
/// `"block: parent unseen"` is intentionally absent from this list; its single
/// canonical definition is `GOSSIP_REASON_PARENT_UNSEEN` in
/// `pharos-network/src/host.rs`.  The `verdict_strings_match_known_list` test
/// verifies it separately via `pharos_network::host::GOSSIP_REASON_PARENT_UNSEEN`.
const EXPECTED: &[&str] = &[
    // ── block (13) ────────────────────────────────────────────────────────────
    "block: clock unavailable",
    "block: duplicate proposer/slot",
    "block: finalized not ancestor",
    "block: from future slot",
    "block: invalid proposer signature",
    "block: not greater than finalized slot",
    "block: not higher than parent slot",
    "block: parent in invalid set",
    "block: parent invalid",
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
    // Strings may live in host_impl.rs or in the network crate's host.rs
    // (e.g. GOSSIP_REASON_PARENT_UNSEEN).  Check both.
    let mut missing: Vec<&str> = Vec::new();
    for &expected in EXPECTED {
        if !SRC.contains(expected) && !NETWORK_HOST_SRC.contains(expected) {
            missing.push(expected);
        }
    }
    if !missing.is_empty() {
        panic!(
            "verdict strings missing from host_impl.rs and pharos-network/src/host.rs ({} strings):\n  - {}",
            missing.len(),
            missing.join("\n  - ")
        );
    }

    // ── Part 2: no orphan strings in the source not in the expected list ──────
    // Every string with a "block: "/"att: "/"agg: " prefix that appears in
    // either source must be in EXPECTED, UNLESS it is
    // `GOSSIP_REASON_PARENT_UNSEEN` (handled separately in Part 4).
    let mut in_source = extract_prefixed_strings(SRC);
    in_source.extend(extract_prefixed_strings(NETWORK_HOST_SRC));
    in_source.sort();
    in_source.dedup();
    let expected_set: std::collections::BTreeSet<&str> = EXPECTED.iter().copied().collect();

    let orphans: Vec<&str> = in_source
        .iter()
        .filter(|s| {
            s.as_str() != pharos_network::host::GOSSIP_REASON_PARENT_UNSEEN
                && !expected_set.contains(s.as_str())
        })
        .map(|s| s.as_str())
        .collect();

    if !orphans.is_empty() {
        panic!(
            "orphan verdict strings found not in EXPECTED list ({} strings):\n  - {}\n\nUpdate EXPECTED in gossip_verdict_strings.rs to include them.",
            orphans.len(),
            orphans.join("\n  - ")
        );
    }

    // ── Part 3: counts match expectation ─────────────────────────────────────
    // "block: parent unseen" is NOT in EXPECTED (it lives in the const); the
    // count therefore shows 13 inline block strings, not 14.
    let block_count = EXPECTED.iter().filter(|s| s.starts_with("block: ")).count();
    let att_count = EXPECTED.iter().filter(|s| s.starts_with("att: ")).count();
    let agg_count = EXPECTED.iter().filter(|s| s.starts_with("agg: ")).count();
    assert_eq!(
        block_count, 13,
        "expected 13 inline block: strings (parent-unseen lives in const)"
    );
    assert_eq!(att_count, 15, "expected 15 att: strings");
    assert_eq!(agg_count, 20, "expected 20 agg: strings");
    assert_eq!(EXPECTED.len(), 48, "expected 48 inline verdict strings");

    // ── Part 4: GOSSIP_REASON_PARENT_UNSEEN const is the canonical definition ──
    // The literal "block: parent unseen" must NOT appear anywhere in host_impl.rs
    // (it has been replaced by the const reference).  The const value itself lives
    // only in pharos-network/src/host.rs.
    assert!(
        !SRC.contains(pharos_network::host::GOSSIP_REASON_PARENT_UNSEEN),
        "host_impl.rs must NOT contain the bare literal \
         \"block: parent unseen\"; use GOSSIP_REASON_PARENT_UNSEEN instead"
    );
    assert!(
        NETWORK_HOST_SRC.contains(pharos_network::host::GOSSIP_REASON_PARENT_UNSEEN),
        "pharos-network/src/host.rs must contain the GOSSIP_REASON_PARENT_UNSEEN definition"
    );
}
