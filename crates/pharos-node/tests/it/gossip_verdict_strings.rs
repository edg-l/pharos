//! Spec verdict-string round-trip test.
//!
//! Assert that every IGNORE/REJECT verdict string in
//! `host_impl.rs` matches a hard-coded list, and that no string with a known
//! topic prefix exists in the source that is NOT in the list.
//!
//! Approach: `include_str!` the source files at test build time and check each
//! known string is present.  The orphan-string assertion (every prefixed string
//! in the source must also be in the list) catches silent renames or additions.
//!
//! `GOSSIP_REASON_PARENT_UNSEEN` ("block: parent unseen") is a const defined in
//! `pharos-network/src/host.rs` (single source of truth per D-parent-unseen-sentinel).
//! Part 1 and Part 2 therefore scan both source files.
//!
//! Also covers strings for the 3 folded phase0 validators
//! (`exit: `, `proposer_slashing: `, `attester_slashing: `) and the new
//! `bls_to_exec: ` validator.
//!
//! Counts audited from source: block=15, att=15, agg=20, exit=8, ps=8, as=8,
//! bte=7, sync_msg=7, sync_contrib=13, blob=19, total=120.
//! Six "clock unavailable" strings (block/att/agg/sync_msg/sync_contrib/blob) were
//! removed when all gossip-time reads were migrated to the injectable `self.now_ms()`
//! which never fails (uses `unwrap_or_default`). Three new block strings were added:
//! `block: parent EL-invalid`, `block: parent invalid with known EL result` (from the
//! EL-result-aware step-1 branching), and `block: incorrect execution payload timestamp`.
//!
//! There is no `"block: unrecognised fork variant"` string: an unrecognised
//! fork is a compile error in `BeaconSpec::signed_block_message` (exhaustive
//! match), so no runtime Reject string exists.
//!
//! This test is the gating mechanism for spec rule audit. Do not modify the list
//! without also updating the corresponding spec-rule mapping in `docs/decisions.md`.

const SRC: &str = include_str!("../../src/host_impl.rs");
/// Also scan the network crate's host.rs where `GOSSIP_REASON_PARENT_UNSEEN` is defined.
const NETWORK_HOST_SRC: &str = include_str!("../../../../crates/pharos-network/src/host.rs");

/// All expected verdict strings, grouped by topic prefix.
///
/// `"block: parent unseen"` is intentionally absent from this list; its single
/// canonical definition is `GOSSIP_REASON_PARENT_UNSEEN` in
/// `pharos-network/src/host.rs`.  The `verdict_strings_match_known_list` test
/// verifies it separately via `pharos_network::host::GOSSIP_REASON_PARENT_UNSEEN`.
const EXPECTED: &[&str] = &[
    // ── block (15) ────────────────────────────────────────────────────────────
    // "block: clock unavailable" removed: now_ms() uses unwrap_or_default, never
    // returns a clock error; all gossip time reads use the injectable self.now_ms().
    "block: duplicate proposer/slot",
    "block: finalized not ancestor",
    "block: from future slot",
    "block: incorrect execution payload timestamp",
    "block: invalid proposer signature",
    "block: not greater than finalized slot",
    "block: not higher than parent slot",
    "block: parent EL-invalid",
    "block: parent in invalid set",
    "block: parent invalid",
    "block: parent invalid with known EL result",
    "block: proposer index out of range",
    "block: proposer mismatch",
    "block: shuffling unavailable",
    "block: too many blob kzg commitments",
    // ── att (14) ──────────────────────────────────────────────────────────────
    "att: agg bits length mismatch",
    // "att: clock unavailable" removed: now_ms() uses unwrap_or_default.
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
    "att: voted block failed validation",
    "att: voted block invalid",
    "att: voted block unseen",
    "att: wrong subnet",
    // ── agg (19) ──────────────────────────────────────────────────────────────
    "agg: agg bits length mismatch",
    "agg: aggregator index out of range",
    "agg: aggregator not in committee",
    // "agg: clock unavailable" removed: now_ms() uses unwrap_or_default.
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
    "agg: voted block failed validation",
    "agg: voted block invalid",
    "agg: voted block unseen",
    // ── exit (7: 1 IGNORE + 6 REJECT) ────────────────────────────────────────
    "exit: already seen for this validator",
    "exit: exit epoch in the future",
    "exit: head state unavailable",
    "exit: invalid signature",
    "exit: validator already exiting",
    "exit: validator index out of range",
    "exit: validator not active",
    "exit: validator not active long enough",
    // ── proposer_slashing (7: 1 IGNORE + 6 REJECT) ────────────────────────────
    "proposer_slashing: already seen for this proposer",
    "proposer_slashing: header proposer indices do not match",
    "proposer_slashing: header slots do not match",
    "proposer_slashing: headers are not different",
    "proposer_slashing: head state unavailable",
    "proposer_slashing: invalid signature",
    "proposer_slashing: proposer index out of range",
    "proposer_slashing: proposer not slashable",
    // ── attester_slashing (7: 1 IGNORE + 6 REJECT) ────────────────────────────
    "attester_slashing: all indices already seen",
    "attester_slashing: attestation data not slashable",
    "attester_slashing: head state unavailable",
    "attester_slashing: index out of range in attestation_1",
    "attester_slashing: index out of range in attestation_2",
    "attester_slashing: invalid indexed attestation_1",
    "attester_slashing: invalid indexed attestation_2",
    "attester_slashing: no slashable validators in intersection",
    // ── bls_to_exec (7: 2 IGNORE + 5 REJECT) ─────────────────────────────────
    "bls_to_exec: already seen for this validator",
    "bls_to_exec: current epoch is pre-capella",
    "bls_to_exec: head state unavailable",
    "bls_to_exec: invalid signature",
    "bls_to_exec: not BLS withdrawal credentials",
    "bls_to_exec: pubkey hash mismatch",
    "bls_to_exec: validator index out of range",
    // ── sync_msg (7: 3 IGNORE + 4 REJECT) ────────────────────────────────────
    // "sync_msg: clock unavailable" removed: now_ms() uses unwrap_or_default.
    "sync_msg: duplicate (slot, validator, subnet)",
    "sync_msg: head state unavailable",
    "sync_msg: invalid signature",
    "sync_msg: no sync committee (pre-altair)",
    "sync_msg: slot not current",
    "sync_msg: subnet not valid for validator",
    "sync_msg: validator index out of range",
    // ── sync_contrib (13: 4 IGNORE + 9 REJECT) ───────────────────────────────
    "sync_contrib: aggregator index out of range",
    "sync_contrib: aggregator not in subcommittee",
    // "sync_contrib: clock unavailable" removed: now_ms() uses unwrap_or_default.
    "sync_contrib: contribution superset seen",
    "sync_contrib: duplicate aggregator/slot/subcommittee",
    "sync_contrib: head state unavailable",
    "sync_contrib: invalid aggregate signature",
    "sync_contrib: invalid aggregator signature",
    "sync_contrib: invalid selection proof signature",
    "sync_contrib: no participants",
    "sync_contrib: no sync committee (pre-altair)",
    "sync_contrib: not selected as aggregator",
    "sync_contrib: slot not current",
    "sync_contrib: subcommittee index out of range",
    // ── blob (19: 5 IGNORE + 14 REJECT) ──────────────────────────────────────
    // 14 spec rules (deneb/p2p-interface.md:497-585) + 5 defensive checks.
    // "blob: clock unavailable" removed: now_ms() uses unwrap_or_default.
    "blob: duplicate sidecar tuple",
    "blob: finalized not ancestor of block",
    "blob: from future slot",
    "blob: index >= MAX_BLOBS_PER_BLOCK",
    "blob: invalid inclusion proof",
    "blob: invalid kzg proof",
    "blob: invalid proposer signature",
    "blob: kzg proof error",
    "blob: not from a higher slot than parent",
    "blob: not from slot > finalized slot",
    "blob: parent failed validation",
    "blob: parent not seen",
    "blob: proposer_index does not match expected proposer",
    "blob: proposer index out of range",
    "blob: shuffling unavailable",
    "blob: wrong blob length",
    "blob: wrong commitment length",
    "blob: wrong proof length",
    "blob: wrong subnet for index",
];

/// Extract all quoted strings from `src` that start with one of the topic
/// prefixes.  Returns a sorted, deduplicated `Vec<String>`.
fn extract_prefixed_strings(src: &str) -> Vec<String> {
    let prefixes = [
        "block: ",
        "att: ",
        "agg: ",
        "exit: ",
        "proposer_slashing: ",
        "attester_slashing: ",
        "bls_to_exec: ",
        "sync_msg: ",
        "sync_contrib: ",
        "blob: ",
    ];
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
    // Every string with a known prefix that appears in either source must be in
    // EXPECTED, UNLESS it is `GOSSIP_REASON_PARENT_UNSEEN` (handled separately).
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
    // count therefore shows 12 inline block strings, not 13 ("block:
    // unrecognised fork variant" is a compile-time guarantee instead).
    let block_count = EXPECTED.iter().filter(|s| s.starts_with("block: ")).count();
    let att_count = EXPECTED.iter().filter(|s| s.starts_with("att: ")).count();
    let agg_count = EXPECTED.iter().filter(|s| s.starts_with("agg: ")).count();
    let blob_count = EXPECTED.iter().filter(|s| s.starts_with("blob: ")).count();
    let exit_count = EXPECTED.iter().filter(|s| s.starts_with("exit: ")).count();
    let ps_count = EXPECTED
        .iter()
        .filter(|s| s.starts_with("proposer_slashing: "))
        .count();
    let as_count = EXPECTED
        .iter()
        .filter(|s| s.starts_with("attester_slashing: "))
        .count();
    let bte_count = EXPECTED
        .iter()
        .filter(|s| s.starts_with("bls_to_exec: "))
        .count();
    let sync_msg_count = EXPECTED
        .iter()
        .filter(|s| s.starts_with("sync_msg: "))
        .count();
    let sync_contrib_count = EXPECTED
        .iter()
        .filter(|s| s.starts_with("sync_contrib: "))
        .count();
    assert_eq!(
        block_count, 15,
        "expected 15 inline block: strings (parent-unseen lives in const; 3 EL-state strings added; 1 clock removed)"
    );
    assert_eq!(
        att_count, 15,
        "expected 15 att: strings (1 clock removed; +1 failed-validation early-out)"
    );
    assert_eq!(
        agg_count, 20,
        "expected 20 agg: strings (1 clock removed; +1 failed-validation early-out)"
    );
    assert_eq!(
        exit_count, 8,
        "expected 8 exit: strings (1 IGNORE + 7 REJECT incl. head-state)"
    );
    assert_eq!(ps_count, 8, "expected 8 proposer_slashing: strings");
    assert_eq!(as_count, 8, "expected 8 attester_slashing: strings");
    assert_eq!(
        bte_count, 7,
        "expected 7 bls_to_exec: strings (2 IGNORE + 5 incl. head-state)"
    );
    assert_eq!(
        sync_msg_count, 7,
        "expected 7 sync_msg: strings (3 IGNORE + 4 REJECT; 1 clock removed)"
    );
    assert_eq!(
        sync_contrib_count, 13,
        "expected 13 sync_contrib: strings (4 IGNORE + 9 REJECT; 1 clock removed)"
    );
    assert_eq!(
        blob_count, 19,
        "expected 19 blob: strings (5 IGNORE + 14 REJECT; 14 spec rules + 5 defensive; 1 clock removed)"
    );
    assert_eq!(
        EXPECTED.len(),
        120,
        "expected 120 total inline verdict strings (6 clock strings removed, 3 EL-state block strings added, 2 failed-validation early-out strings added)"
    );

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
