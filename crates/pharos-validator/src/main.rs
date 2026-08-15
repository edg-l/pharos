pub mod bn_client;
pub mod interchange;
pub mod keystore;
pub mod signing;
pub mod slashing;

// ── Optimistic-sync contract ──────────────────────────────────────────────────
//
// Per `consensus-specs/sync/optimistic.md` "Validator assignments":
// "An optimistic node MUST NOT: propose blocks, attest, or participate in sync
//  committees until the node is no longer optimistic."
//
// When the produce_block, produce_attestation_data, aggregate-selection, and
// sync_committee_contribution endpoints are implemented in a future milestone,
// this VC binary MUST:
//
// 1. Treat any HTTP 503 response from those production endpoints as
//    "do not sign / skip this slot".  The BN returns 503 from production
//    endpoints whenever `is_optimistic_node()` is true (per the contract
//    documented in `crates/pharos-api/src/handlers/validator_duties.rs`).
//
// 2. Treat `execution_optimistic: true` in a duty-read response (proposer /
//    attester / sync duties) as a warning only — the VC may read duties even
//    when the BN is optimistic, but MUST NOT submit any signed messages until
//    the flag clears.
//
// Reference: `crates/pharos-api/src/handlers/validator_duties.rs` Task 5.4.

fn main() {
    println!("pharos-vc {}", env!("CARGO_PKG_VERSION"));
}
