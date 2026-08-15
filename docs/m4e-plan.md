# M4e — Beacon block + attestation + aggregate gossip validation

## Overview
M4e replaces the three remaining `Accept`-stub gossip-validator bodies on
`HostImpl<E>` (`validate_beacon_block`, `validate_attestation`,
`validate_aggregate_and_proof` at
`crates/pharos-node/src/host_impl.rs:359-373`) with full spec-conformant
implementations per `specs/phase0/p2p-interface.md` lines `540-1014`.
M4e is the prerequisite for M4d (cross-client devnet acceptance): without
real block + attestation + aggregate gossip validation, pharos cannot
follow a real chain. The work is bracketed between M4c (LC gossip + bench
baseline, closed at `566521b`, tag `v0.6.0`) and M4d.

Scope: three gossip-validator methods, three in-memory seen-caches, one
proposer-index cache, one committee cache, two new spec constants, the
two new BLS domain types (`DOMAIN_SELECTION_PROOF`,
`DOMAIN_AGGREGATE_AND_PROOF`), three pure helpers
(`is_not_from_future_slot`, `is_within_slot_range`,
`compute_subnet_for_attestation`) in `pharos-stf`, and one new pure
predicate `is_aggregator`. All cache lookups MUST be sync (per
`D-gossip-validator-sync`); the BLS verify is the only blocking call and
runs synchronously inside the validator body. Audit at plan time
(`crates/pharos-network/src/network/mod.rs:531`) confirms
`dispatch_gossip_message` is called directly on the async network
task with NO `spawn_blocking` wrap; a defect under
`D-gossip-validator-sync` (sync BLS verify on an async runtime worker
thread risks stalling the executor). Task 0.6 wraps the dispatch
unconditionally.

Acceptance: the three validator methods on `HostImpl<E>` execute every
spec rule from `specs/phase0/p2p-interface.md` (sections
`validate_beacon_block_gossip`, `validate_beacon_aggregate_and_proof_gossip`,
`validate_beacon_attestation_gossip`); each `[IGNORE]` rule returns
`GossipVerdict::Ignore(<reason>)`, each `[REJECT]` rule returns
`GossipVerdict::Reject(<reason>)`; in-memory seen-caches are sized and
evicted per ADR; the per-method unit test suite covers every IGNORE/REJECT
branch (one test per branch, no shared fixtures across branches);
`docs/conformance.md` row counts are byte-identical to the post-M4c
snapshot; workspace version bumps `0.6.0` → `0.7.0` at wrap.

## Locked decisions (short form)

- `D-seen-cache-shape` — Three in-memory caches, all `parking_lot::RwLock`
  wrappers around bounded structures, all owned by `HostImpl<E>` (not in
  RocksDB):
    1. `seen_block_proposers: RwLock<lru::LruCache<(Slot, ValidatorIndex), ()>>`
       capacity `4096` entries (sized for ~128 slots × 32 reorg-tolerant
       proposers, well above the spec's `[IGNORE]` "first block for this
       proposer+slot" rule's working set).
    2. `seen_attestation_validators: RwLock<lru::LruCache<(ValidatorIndex, Epoch), ()>>`
       capacity `131072` entries (mainnet active set is ~1M validators ×
       2 cached epochs; we keep the most recent 131072 keys via LRU,
       which covers a full epoch of mainnet attestations under load).
    3. `seen_aggregators: RwLock<lru::LruCache<(ValidatorIndex, Epoch), ()>>`
       capacity `8192` entries (target aggregators = 16/committee × 64
       committees × 32 slots/epoch = ~32k per epoch; 8192 covers the
       last ~quarter epoch comfortably — collisions just degrade to
       re-validation, never to incorrect Accept).
  All three are evicted by LRU; size budget at peak ≈ 4 MB total
  (well under the 50 MB ad-hoc budget the M3a `HostImpl` peer-info ADR
  set). The `lru` crate (`0.16`) is added as a new workspace dep.
  Rationale for in-memory vs RocksDB: the seen-cache state is purely a
  per-process gossip-dedup signal, has no persistence semantics, and
  reloading it on restart from disk would not help (a restart loses the
  in-flight gossip view anyway). Lighthouse uses an in-memory
  `LruCache` for the same purpose (`beacon_node/network/src/network_beacon_processor/gossip_methods.rs`).
  Rejected alternatives: (a) RocksDB CF — adds write amplification and
  needs eviction on its own; (b) `HashSet<...>` — unbounded growth.

- `D-proposer-cache` — `proposer_cache: RwLock<lru::LruCache<(Slot, Root), ValidatorIndex>>`
  on `HostImpl<E>`, capacity `1024` (~128 slots × 8 viable parent
  roots). Key is `(block.slot, block.parent_root)`. On miss the
  validator clones the parent state from
  `fork_choice.read().block_states.get(&parent_root)` (already in scope
  via existing field `fork_choice: Arc<RwLock<Store<E>>>`), calls
  `pharos_stf::process_slots_fork::<E>(&mut state, block.slot)`
  (verified at `crates/pharos-stf/src/lib.rs:250-279`) to advance the
  state to `block.slot`, then `pharos_stf::phase0::accessors::get_beacon_proposer_index::<E>(&state)`
  (verified at `crates/pharos-stf/src/phase0/accessors.rs:213`).
  Inserts the result. The parent state clone is mandatory because
  `process_slots` mutates in place; the M4-perf tree-backed state makes
  the clone cheap (structural sharing).
  Rationale: caching `(slot, parent_root) → proposer_index` avoids
  re-running `process_slots` on every block-gossip arrival for the
  same slot. Lighthouse uses an equivalent `ProposerCache` keyed
  identically. Rejected: caching by `(epoch, parent_root)` —
  proposer-shuffling changes on `RANDAO` reveal each block, so
  per-slot is the smallest stable key.

- `D-committee-cache` — `committee_cache: RwLock<lru::LruCache<(Slot, CommitteeIndex, Root), Vec<ValidatorIndex>>>`
  on `HostImpl<E>`, capacity `4096` (~64 slots × 64 committees/slot ×
  reorg tolerance). Key is `(att.data.slot, att.data.index, head_root)`
  where `head_root` is the LMD-GHOST head at validation time (read via
  `BlockProvider::head().0` on `self`). On miss the validator clones
  the head state from `fork_choice.read().block_states.get(&head_root)`,
  calls `pharos_stf::process_slots_fork` to `att.data.slot` (or
  no-op if state already at or past that slot — `process_slots_fork`
  is a no-op when target ≤ current), then
  `pharos_stf::phase0::accessors::get_beacon_committee::<E>(&state, slot, committee_index)`
  (verified at `crates/pharos-stf/src/phase0/accessors.rs:160`).
  Stores the returned `Vec<ValidatorIndex>` (cheap, ≤ 2048 entries per
  committee per spec).
  Rationale: committee membership for `(slot, index)` is stable across
  the *same epoch* once finalised, and stable across the same
  `head_root` always — keying by `head_root` makes the cache reorg-safe
  (a different head root retreats to a separate cache slot, no stale
  hits). Rejected: keying by `target.epoch` alone — would Accept
  attestations for the wrong fork during reorgs.

- `D-verdict-strings-spec-keyed` — Every `GossipVerdict::Ignore(s)` /
  `GossipVerdict::Reject(s)` string in the three validators uses the
  exact lowercase tag from the spec's `Raises GossipIgnore("...")` /
  `Raises GossipReject("...")` line, with a leading
  `"block:"` / `"att:"` / `"agg:"` namespace prefix so the gossip-event
  surface can grep by topic without parsing the message. Example:
  `GossipVerdict::Reject("block: invalid proposer signature".into())`.
  Rationale: log greppability; one consistent format; no `format!`
  allocation on the hot path because each string is a static literal
  via `String::from`. The verdict-string list is exhaustive in Tasks
  1.4 / 2.4 / 3.4.

- `D-bls-on-hot-path` — The three signature verifies (proposer signature
  on `validate_beacon_block`; selection-proof + aggregator signature +
  aggregate signature on `validate_aggregate_and_proof`; aggregate
  signature on `validate_attestation`) run synchronously in the
  validator body using `pharos_utils::bls::verify` /
  `pharos_utils::bls::fast_aggregate_verify` (verified at
  `crates/pharos-utils/src/bls.rs:98` and `:149`). The gossip dispatch
  loop does NOT currently wrap validator calls in
  `tokio::task::spawn_blocking` (verified at
  `crates/pharos-network/src/network/mod.rs:531`); Task 0.6 adds this
  wrap unconditionally so the BLS verifies do not stall the tokio
  executor. Mainnet single-pubkey `bls::verify` is ~1 ms;
  `fast_aggregate_verify` for a full committee (~2048 indices) is ~2-3
  ms; aggregate of 64 committees ~50 ms worst case. Batched verification
  is M11 work and explicitly out of scope.
  Rejected alternatives: (a) async signature queue with a dedicated
  worker pool — adds latency-of-first-byte without changing
  steady-state throughput; (b) skip BLS on gossip — spec REJECT.

- `D-invalid-roots-cache` — A new
  `invalid_block_roots: RwLock<lru::LruCache<Root, ()>>` on
  `HostImpl<E>`, capacity `256`, mirrors the fork-choice `Invalid`
  payload-status set already maintained at
  `crates/pharos-fork-choice/src/store.rs:CF_PAYLOAD_STATUS` but for
  gossip-validator-level invalid roots. The validator inserts a root
  on REJECT from `validate_beacon_block` and consults the cache on
  every subsequent `validate_beacon_block` call before any other
  check — a block whose `parent_root` is in this cache is `Reject`ed
  immediately (spec "block's parent passes validation" REJECT branch).
  Rationale: REJECT messages in gossipsub penalise the sender; making
  the cache process-local keeps us from spamming RocksDB writes for
  every invalid block we see. Rejected: extending the existing
  fork-choice payload-status map — that map is execution-layer-keyed
  (post-NewPayload) not gossip-keyed.

- `D-future-slot-disparity` — `is_not_from_future_slot` and
  `is_within_slot_range` are implemented exactly per
  `specs/phase0/p2p-interface.md:298-334` (lines quoted above), with
  `MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS = 500` (already in
  `crates/pharos-types/src/phase0/primitives.rs:51` per M4c).
  `compute_time_at_slot_ms(state, slot)` is implemented as
  `genesis_time * 1000 + slot * SECONDS_PER_SLOT * 1000`; the
  `state` parameter is unused by pharos because genesis_time lives on
  the fork-choice `Store`, not on `BeaconState` directly (this matches
  the M4c LC-validator pattern at
  `crates/pharos-node/src/host_impl.rs:453`). `ATTESTATION_PROPAGATION_SLOT_RANGE`
  is `32` per `specs/phase0/p2p-interface.md:230`; added as
  `pub const ATTESTATION_PROPAGATION_SLOT_RANGE: u64 = 32;` to
  `crates/pharos-types/src/phase0/primitives.rs` (Task 0.4).

- `D-domain-types-additions` — `DOMAIN_SELECTION_PROOF = 0x05000000` and
  `DOMAIN_AGGREGATE_AND_PROOF = 0x06000000` (both 4-byte `DomainType`
  per `specs/phase0/beacon-chain.md:214-215`). Added as
  `pub const DOMAIN_SELECTION_PROOF: DomainType = DomainType::from_array([0x05, 0x00, 0x00, 0x00]);`
  / `DOMAIN_AGGREGATE_AND_PROOF` to
  `crates/pharos-stf/src/phase0/helpers.rs` (alongside the existing
  `DOMAIN_BEACON_PROPOSER` at line `~16`). `TARGET_AGGREGATORS_PER_COMMITTEE`
  (`= 16`, `specs/phase0/validator.md:105`) added as `pub const`
  to `crates/pharos-types/src/phase0/primitives.rs`.

- `D-is-aggregator-location` — `is_aggregator(committee_len, slot_signature) -> bool`
  is implemented in `crates/pharos-stf/src/phase0/predicates.rs` as
  `pub fn is_aggregator(committee_len: usize, slot_signature: &BLSSignature) -> bool { let modulo = std::cmp::max(1, committee_len / TARGET_AGGREGATORS_PER_COMMITTEE as usize); let h = pharos_utils::hash::hash(slot_signature.as_ref()); let n = u64::from_le_bytes(h[0..8].try_into().unwrap()); n % (modulo as u64) == 0 }`.
  Spec at `validator.md:733-738`. Pure function (no state access).
  Rationale: belongs next to `is_valid_indexed_attestation` (existing
  at `predicates.rs:56`); both are pure predicates over committees.

- `D-cache-key-on-head` — All three caches (`proposer_cache`,
  `committee_cache`, plus the seen-caches via the per-call inspection
  pattern) key on **the current head_root at validation time**, not on
  the message's `parent_root` (proposer) / `data.beacon_block_root`
  (committee). The spec uses "the head state" as the validation
  context; cache invalidation is achieved naturally because a new head
  yields a different cache key. Rejected: keying on
  `message.parent_root` directly — would mis-cache across short reorgs
  where two siblings share the same parent.

- `D-seen-cache-after-accept` — Seen-caches are written **after** all
  other checks have passed (i.e. on `Accept`), not before. Writing on
  first sight (before checks) would create a false-positive where a
  malformed message that fails validation prevents a subsequent valid
  message with the same `(proposer, slot)` from being accepted.
  Lighthouse follows the same "insert on Accept" pattern. Pinned by
  the per-validator step ordering in Tasks 1.4, 2.4, 3.4.

- `D-no-tokio-from-validator` — Validator bodies are sync, take
  `&self`, and MUST NOT spawn tokio tasks or call `.await`. All I/O
  is synchronous (RocksDB get via `<RocksStore as StoreTrait<E>>`,
  parking_lot locks, BLS verify). Per `D-gossip-validator-sync` (M3a).

## Assumptions
- A1: M4c shipped at `566521b`; workspace version `0.6.0`. Verified
  by `git log --oneline -n 1` (current `master` tip).
- A2: The `GossipValidator<E>` trait signatures at
  `crates/pharos-network/src/host.rs:121-132` do NOT change in M4e —
  Phase-0 const generics `MAX_VALIDATORS_PER_COMMITTEE = 2048` are
  correct for both mainnet and minimal presets (verified at lines
  `116-118` of the same file). The validator methods take
  `&E::SignedBeaconBlock`, `&Attestation<2048>`,
  `&AggregateAndProof<2048>` respectively. **No trait-surface change**.
- A3: The gossip dispatch in
  `crates/pharos-network/src/network/mod.rs:531` calls
  `dispatch_gossip_message` (and thus the host validators) directly
  on the async network task with NO `spawn_blocking` wrap. Per
  `D-gossip-validator-sync` this is a defect: sync BLS verify on an
  async runtime worker thread risks stalling the executor. Task 0.6
  wraps the dispatch unconditionally; Task 0.5 is the inventory
  pass that enumerates every call site that must be wrapped.
- A4: `pharos_stf::phase0::accessors::get_beacon_proposer_index`,
  `get_beacon_committee`, `get_committee_count_per_slot`,
  `get_attesting_indices`, `get_indexed_attestation` all exist and
  take `&E::BeaconState` — verified at
  `crates/pharos-stf/src/phase0/accessors.rs:132-332`.
  `is_valid_indexed_attestation` exists at
  `crates/pharos-stf/src/phase0/predicates.rs:56`.
- A5: `pharos_stf::phase0::accessors::compute_signing_root`,
  `compute_domain`, `get_domain`, `compute_epoch_at_slot` all exist
  — verified at `crates/pharos-stf/src/lib.rs:49-50` and
  `crates/pharos-stf/src/bellatrix/operations/proposer_slashing.rs:114-122`
  (existing usage).
- A6: `pharos_utils::bls::verify` (single-pubkey) and
  `pharos_utils::bls::fast_aggregate_verify` (multi-pubkey) exist and
  return `Result<bool, BlsError>` — verified at
  `crates/pharos-utils/src/bls.rs:98, 149`.
- A7: `pharos_utils::hash::hash(&[u8]) -> [u8; 32]` (sha256) exists and
  is what spec's `hash()` maps to. Verified by `rg "pub fn hash"
  crates/pharos-utils/src/hash.rs`.
- A8: `lru = "0.16"` is NOT in the workspace today (verified by `rg
  '"lru"' Cargo.toml`); Task 0.7 adds it as a workspace dep. The crate
  is MIT/Apache dual-licensed and `no_std`-incompatible (uses
  `std::collections::HashMap`); pharos targets `std` so this is fine.
- A9: `RuntimeConfig.seconds_per_slot` exists and is accessible — verified
  at `crates/pharos-types/src/config/mod.rs:62`. `HostImpl<E>` already
  carries `runtime_cfg: Arc<RuntimeConfig>` from M4c (verified at
  `crates/pharos-node/src/host_impl.rs:90`).
- A10: `fork_choice: Arc<RwLock<pharos_fork_choice::Store<E>>>` on
  `HostImpl<E>` already exposes `.blocks: HashMap<Root, E::BeaconBlock>`
  and `.block_states: HashMap<Root, E::BeaconState>` (verified at
  `crates/pharos-fork-choice/src/store.rs:79, 84`). The
  `genesis_time: u64` field is also present (verified at line `44`,
  used by M4c at `host_impl.rs:453`).
- A11: `pharos_fork_choice::get_head(&store)` returns the head `Root`
  — verified at `crates/pharos-fork-choice/src/lib.rs:12` and used at
  `crates/pharos-node/src/host_impl.rs:341`.
- A12: The `head` accessor pattern (LMD-GHOST head + state lookup) is
  re-used from `crates/pharos-fork-choice/src/handlers.rs:194-199`:
  `let head_state = store.block_states.get(&head_root).clone(); if
  head_state.slot() < slot { process_slots_fork(&mut head_state,
  slot)?; }`. This is the canonical "head state at slot S" pattern.
- A13: `get_checkpoint_block(store, root, epoch)` exists or has a
  trivial implementation via walking
  `store.blocks[root].parent_root` until `block.slot <=
  compute_start_slot_at_epoch(epoch)`. Audit in Task 0.8; if missing,
  add to `crates/pharos-fork-choice/src/lib.rs` (Task 1.1).
- A14: `<RocksStore as StoreTrait<E>>::get_block` (used by
  `BlockProvider::block_by_root` at `host_impl.rs:305`) is the
  RocksDB path; gossip validators DO NOT touch RocksDB directly —
  the fork-choice in-memory `Store<E>` is the source of truth for
  `blocks` / `block_states` (per M3a `D-fork-choice-in-memory`).
- A15: Conformance writer is byte-stable across M4e changes — gossip
  validators are not exercised by `pharos-conformance` (verified by
  `rg validate_beacon_block crates/pharos-conformance/`). Phase 6
  re-runs `make conformance` to verify zero-diff anyway.
- A16: `pharos_types::phase0::primitives::DomainType` exists — verified
  by `rg "pub struct DomainType" crates/pharos-types/`. (If absent
  under that exact name, the M3a/M4a STF must have a similar type;
  Task 0.9 audits and either uses the existing name or adds a thin
  newtype.)
- A17: `pharos_types::phase0::Attestation<MAX>` carries
  `data: AttestationData`, `aggregation_bits: Bitlist<MAX>`,
  `signature: BLSSignature`; `AttestationData` carries
  `slot: Slot, index: CommitteeIndex, beacon_block_root: Root,
  source: Checkpoint, target: Checkpoint`. Verified by `rg "pub struct
  Attestation\b" crates/pharos-types/src/phase0/operations.rs`.
- A18: `BLSSignature` derefs to a `[u8; 96]` or
  `AsRef<[u8]>`-compatible byte slice (needed for
  `pharos_utils::hash::hash(slot_signature.as_ref())` in
  `is_aggregator`). Verified by `rg "impl AsRef<\[u8\]>.*BLSSignature"
  crates/pharos-utils/src/bytes.rs`.

## Out of Scope
- The remaining four `Accept`-stub validators on `HostImpl<E>`
  (`validate_voluntary_exit`, `validate_proposer_slashing`,
  `validate_attester_slashing`, `validate_sync_committee_message`,
  `validate_sync_committee_contribution_and_proof`). These are M5
  work — the spec mechanics are simpler but require a separate plan.
  (Note: `validate_sync_committee_*` were stubbed at M3b and remain
  stubs; the M3b `D-light-client-server-only` ADR explicitly defers
  them. They are NOT in M4e.)
- Batched BLS verification across multiple gossip messages (M11).
- Persisting any cache to disk (all four new caches are in-memory).
- Capella+ gossip rules (M5). Bellatrix execution-payload validation
  on the block-gossip path stays in the Engine API track (M4a
  `D-engine-method-dispatch`); M4e validates only the consensus-layer
  fields of the block, not the execution payload.
- The `validate_beacon_block_gossip` rule "block's parent passes
  validation" REJECT branch is implemented via the
  `invalid_block_roots` cache (D-invalid-roots-cache); a hash-tree
  walk to discover whether the parent transitively failed is NOT in
  scope — only the directly-seen-as-invalid set is checked.
- Devnet validation (M4d). M4e ships the validators; M4d wires them
  to a real chain.
- Conformance fixtures for gossip validation (no `consensus-spec-tests`
  category covers gossip mechanics today — the spec is normative,
  not test-driven, for these rules).

## Existing Patterns
- `crates/pharos-node/src/host_impl.rs:359-373` — the three stub
  validator methods we replace (this is the unit of work).
- `crates/pharos-node/src/host_impl.rs:84-104` — `HostImpl<E>` field
  layout. Five new fields land here (three seen-caches + proposer-cache
  + committee-cache + invalid-roots-cache, behind `Arc<RwLock>` /
  `RwLock` per shape).
- `crates/pharos-node/src/host_impl.rs:429-486` — M4c
  `validate_light_client_finality_update` body. The Step-1..Step-5
  ordered-check pattern (each step short-circuits on first failure with
  a tagged `Ignore`/`Reject`) is the precedent for M4e bodies.
- `crates/pharos-stf/src/phase0/accessors.rs:132-332` — all committee
  and proposer accessors we re-use.
- `crates/pharos-stf/src/phase0/predicates.rs:56` —
  `is_valid_indexed_attestation`; aggregate-signature verify reduces
  to this. `is_aggregator` lands in the same file (D-is-aggregator-location).
- `crates/pharos-stf/src/bellatrix/operations/proposer_slashing.rs:114-138`
  — the existing "compute_domain + compute_signing_root + bls::verify"
  call pattern that the block-proposer-signature check in
  `validate_beacon_block` re-uses verbatim.
- `crates/pharos-fork-choice/src/handlers.rs:194-208` — the
  `block_states.get(&head_root).cloned() → process_slots_fork →
  get_beacon_proposer_index` pattern that
  `validate_beacon_block`'s proposer check uses.
- `crates/pharos-network/src/host.rs:30-37` —
  `GossipVerdict::{Accept, Reject(String), Ignore(String)}` confirmed
  to support both with a `String` message; no enum change.
- `crates/pharos-network/src/gossip/mod.rs:107-120` — call sites
  routing decoded gossip messages to the validators. No change here.
- `docs/m4c-plan.md` — phase shape, ADR-key naming convention, audit
  task layout. M4e mirrors this exactly.
- `docs/decisions.md` (M4c block, ending around the most recent
  `D-bench-history-format`) — ADR template
  (`### D-<topic> — <one-line>` + `**Status**: Accepted. **Date**:
  YYYY-MM-DD.` + body + `Enforced in:`).

## Cross-cutting risks
- R1 — A burst of gossip blocks for the same `(slot, proposer_index)`
  during a reorg storm fills the `seen_block_proposers` LRU and evicts
  legitimate-but-older keys. Mitigation: LRU capacity `4096` is ~128
  slots of working set; under normal operation the eviction rate is
  zero. Re-insertion of an evicted key just re-runs full validation,
  which is correct (worst case: a duplicate Accept of a now-stale
  block — gossipsub itself dedupes by message-id so no double
  propagation). Pinned by Task 1.4 step 9 (cache write after Accept).
- R2 — Proposer cache stale across reorgs. Mitigation: cache key is
  `(slot, parent_root)`, not `(slot, head_root)`; a reorg to a sibling
  parent yields a different key naturally. Pinned by Task 1.3.
- R3 — Committee cache key on `head_root` may thrash under reorgs.
  Mitigation: LRU capacity `4096` accommodates ~2 full epochs of
  committees per head; capping at 4096 prevents unbounded growth
  during a reorg storm. Re-population on miss costs one
  `process_slots_fork` invocation (cheap with tree-backed state per
  M4-perf). Pinned by Task 2.3.
- R4 — `validate_beacon_block` calls `process_slots_fork` synchronously
  to compute the expected proposer, but `process_slots_fork` for a
  state far behind wall-clock could take seconds. Mitigation: the
  parent state is by definition the *parent block's* state, which is
  at most one slot behind `block.slot`; `process_slots_fork` advances
  exactly one slot in the common case (≤ 5 ms with M4-perf). Pinned
  by Task 1.3 and the bench Task 5.3.
- R5 — Aggregate signature verify on
  `validate_aggregate_and_proof` invokes
  `is_valid_indexed_attestation` which fetches the full validator
  pubkey list for the committee — up to ~2048 pubkeys per committee,
  decompressed in `parse_pubkey`. Mitigation: under spec budget at ~3
  ms/verify; matches Lighthouse. Bench Task 5.3 quantifies. No
  per-pubkey cache added in M4e (pubkey decompression caching is M11).
- R6 — Clock disparity: a sender's `block.slot` may be 200 ms ahead
  of our wall clock. Mitigation: `is_not_from_future_slot` already
  applies `MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS = 500` per spec, so the
  envelope is symmetric. Test Task 1.5(c) pins both edges.
- R7 — A REJECT verdict on `validate_beacon_block` should
  banscore the sender; if our REJECT is wrong (false positive), the
  sender is wrongly penalised. Mitigation: every REJECT in this plan
  maps 1:1 to a spec `[REJECT]` rule; no extra REJECTs are added on
  top of spec. The `invalid_block_roots` cache only stores roots that
  triggered a spec-mandated REJECT, never roots that were merely
  `Ignore`d. Pinned by Task 1.4 step 1 (invalid-root short-circuit).
- R8 — Stale-state lookup during sync: if we are mid-backfill and a
  gossip attestation arrives for an unknown `beacon_block_root`,
  `store.blocks.get(&root)` returns `None` and we Ignore (spec
  `[IGNORE]` "block being voted for has not been seen"). The risk is
  the validator never returning even though we have the block on
  disk but not yet replayed into fork-choice. Mitigation: the M4b
  backfill driver hydrates fork-choice as it replays blocks, so the
  in-memory `store.blocks` map IS the source of truth (consistent
  with A14). Pinned by Task 2.4 step 6 / Task 3.4 step 8.
- R9 — Two gossip threads validate the same block concurrently
  (same `(slot, proposer_index)`). Both pass the seen-cache check,
  both run BLS verify, both reach the `cache.put((slot, idx), ())`
  step. Result: duplicate Accept, gossipsub dedupes by message-id
  (no double-propagation). Mitigation: this is benign — explicitly
  acknowledged. No mutex around the full validator body. Pinned by
  Task 1.4 step 9.
- R10 — `parking_lot::RwLock<LruCache>` contention: every Accept
  takes a write lock to update LRU recency. Mitigation: write lock
  hold time is ~µs (HashMap insert + linked-list pointer swing).
  Bench Task 5.3 measures the validator under contention. If
  contention is observed, shard the LRU into N independent
  `RwLock<LruCache>` keyed by `slot % N` (deferred to M11 unless the
  bench shows > 10% contention overhead).
- R11 — Spec drift: `consensus-specs` may revise the gossip rules
  in a later release. Mitigation: every IGNORE/REJECT string carries
  the spec rule's exact wording, and Phase 0 Task 0.1 re-reads the
  spec one final time before implementation. The "spec source" in
  the ADRs records the consensus-specs commit at the time of M4e.

## Implementation Plan

### Phase 0 — Spec re-read + dispatch audit + decision freeze + ADR stubs
Why this phase: every rule the implementer writes references the exact
spec wording, the exact existing helper, or the exact verdict string;
landing this read+freeze first prevents drift mid-implementation. Also
audits whether the gossip dispatch path already `spawn_blocking`s
(critical to whether D-bls-on-hot-path is sound) and freezes the open
questions so Phase 1 has clean defaults.

- [ ] Task 0.1: Re-read
  `~/dev/consensus-specs/specs/phase0/p2p-interface.md` lines
  `540-620` (`validate_beacon_block_gossip`), `622-738`
  (`validate_beacon_aggregate_and_proof_gossip`), `921-1013`
  (`validate_beacon_attestation_gossip`), and the helpers at
  `298-334` (`is_not_from_future_slot`, `is_within_slot_range`).
  Confirm: every `[IGNORE]` and `[REJECT]` bullet listed below in
  Phases 1-3 maps to a spec line. Print the full count of IGNORE/REJECT
  rules per topic (block, aggregate, attestation) — record under
  "Spec rule inventory" in this file (Task 0.2) so Phases 1-3 can
  check off rules one by one. No code change.
- [ ] Task 0.2: Append a "Spec rule inventory" subsection to this
  plan (`docs/m4e-plan.md`) listing every IGNORE/REJECT rule per
  topic with a one-line summary and its spec line range. Three sub-
  sections: BLOCK (10 rules, `RB1..RB10`), AGGREGATE (16 rules,
  `RAG1..RAG16`), ATTESTATION (12 rules, `RAT1..RAT12`). Block-rule
  ordering follows the 10 IGNORE/REJECT bullets of
  `specs/phase0/p2p-interface.md` `validate_beacon_block_gossip`:
  RB1 future-slot envelope (IGNORE), RB2 finalized-slot lower bound
  (IGNORE), RB3 duplicate proposer / first-of-slot (IGNORE), RB4
  proposer index range (REJECT), RB5 proposer signature (REJECT),
  RB6 parent unseen (IGNORE; queue for later), RB7 parent in
  invalid-roots (REJECT), RB8 `slot <= parent.slot` (REJECT), RB9
  finalized-checkpoint ancestor (REJECT), RB10 expected proposer
  (REJECT). Each gets a `[ ] RB<n>`-style id; Phases 1-3 reference
  these ids in their step numbering. No code change.
- [ ] Task 0.3: Re-read
  `~/dev/consensus-specs/specs/phase0/validator.md:695-738` for
  `compute_subnet_for_attestation` and `is_aggregator`. Confirm both
  return what the gossip validators need (subnet u64 + bool). No
  code change.
- [ ] Task 0.4: Add `pub const ATTESTATION_PROPAGATION_SLOT_RANGE: u64 = 32;`
  and `pub const TARGET_AGGREGATORS_PER_COMMITTEE: u64 = 16;` to
  `crates/pharos-types/src/phase0/primitives.rs` (after the existing
  `MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS`). Re-export via the existing
  `pub use phase0::primitives::*;` (already in place per M4c). Run
  `cargo check -p pharos-types`.
- [ ] Task 0.5: Confirm the `spawn_blocking` wrap is missing and
  enumerate every call site that needs wrapping. The wrap is already
  known absent at `crates/pharos-network/src/network/mod.rs:531`
  (verified at plan time); this task lists every line in
  `crates/pharos-network/src/network/mod.rs` and
  `crates/pharos-network/src/gossip/mod.rs` where a host validator
  is invoked from an async context, and records the list under a
  new "Gossip dispatch blocking-state" line in the "Existing
  Patterns" section of this plan. Inventory only; no code change.
- [ ] Task 0.6: Wrap the gossip dispatch in
  `tokio::task::spawn_blocking` unconditionally. Modify
  `crates/pharos-network/src/network/mod.rs:531` (and any additional
  call sites surfaced by Task 0.5) so the
  `dispatch_gossip_message::<E, H>(self.host.as_ref(), &topic,
  &ssz_bytes)` call becomes
  `tokio::task::spawn_blocking({ let host = self.host.clone(); let
  topic = topic.clone(); let bytes = ssz_bytes.clone(); move ||
  dispatch_gossip_message::<E, H>(host.as_ref(), &topic, &bytes)
  }).await.expect("dispatch task panicked")`. The `host: Arc<H>`
  clone is cheap. Update the surrounding `let verdict = ...;` site
  to `.await` the join handle. Run `cargo check -p pharos-network`.
- [ ] Task 0.7: Add `lru = "0.16"` to the workspace `[dependencies]`
  block in the root `Cargo.toml` (under `[workspace.dependencies]`).
  Add `lru = { workspace = true }` to `crates/pharos-node/Cargo.toml`
  `[dependencies]`. Run `cargo check -p pharos-node`. No other
  crate consumes `lru` in M4e.
- [ ] Task 0.8: Audit whether `get_checkpoint_block(store, block_root,
  epoch) -> Option<Root>` exists in `pharos-fork-choice`. Run
  `rg "fn get_checkpoint_block" crates/pharos-fork-choice/`. If
  absent (expected — `rg` returned no matches at plan time), record
  in plan notes and add via Task 1.1. If present, record location
  and skip Task 1.1.
- [ ] Task 0.9: Audit `pharos_types::phase0::primitives::DomainType`
  presence via `rg "pub struct DomainType\b" crates/pharos-types/`.
  If absent (likely — the M3a STF uses `[u8; 4]` directly in many
  places), record in plan notes; Task 0.10 adds the newtype.
  Otherwise record location and skip.
- [ ] Task 0.10: If Task 0.9 found `DomainType` is a bare `[u8; 4]`
  in the existing helpers (`compute_domain`, `get_domain`), add the
  two new constants
  `pub const DOMAIN_SELECTION_PROOF: [u8; 4] = [0x05, 0x00, 0x00, 0x00];`
  / `DOMAIN_AGGREGATE_AND_PROOF = [0x06, 0x00, 0x00, 0x00];`
  matching the existing `DOMAIN_BEACON_PROPOSER` declaration at
  `crates/pharos-stf/src/phase0/helpers.rs` (read that file once
  first to confirm the exact name and shape). Re-export via the
  module's `pub use` line. Run `cargo check -p pharos-stf`.
- [ ] Task 0.11: Open `docs/decisions.md` and append a new section
  header `## M4e decisions` after the most recent M4c section closing
  line. Reserve nine ADR stubs as bare headings with `**Status**:
  Draft. **Date**: 2026-05-28.`:
    1. `D-seen-cache-shape`
    2. `D-proposer-cache`
    3. `D-committee-cache`
    4. `D-verdict-strings-spec-keyed`
    5. `D-bls-on-hot-path`
    6. `D-invalid-roots-cache`
    7. `D-future-slot-disparity`
    8. `D-domain-types-additions`
    9. `D-is-aggregator-location`
    10. `D-cache-key-on-head`
    11. `D-seen-cache-after-accept`
    12. `D-no-tokio-from-validator`
  Bodies filled at Phase 6 wrap-up (Task 6.2). Commit message:
  `docs(m4e): freeze decisions skeleton`.
- [ ] Task 0.12: `make check && make lint` (single invocation,
  output to `target/test-logs/m4e-phase0.log`). Confirm zero new
  warnings.

**Checkpoint: Verify Phase 0 complete.** Review Tasks 0.1-0.12.
Confirm: `ATTESTATION_PROPAGATION_SLOT_RANGE` /
`TARGET_AGGREGATORS_PER_COMMITTEE` are pub consts; `lru` is a
workspace dep wired into `pharos-node`; the two new DOMAIN constants
exist; the gossip dispatch path is verified as `spawn_blocking`-
wrapped (or wrapped in Task 0.6); the "Spec rule inventory" sub-
section is in this plan with `RB1..RB10`, `RAG1..RAG12`, `RAT1..RAT10`
ids; `docs/decisions.md` has twelve new `### D-*` stubs all marked
Draft. List each stub. Do not proceed until all are done. **Commit
boundary:** `chore(m4e): phase 0 spec freeze + scaffolding`.

### Spec rule inventory

Source: `specs/phase0/p2p-interface.md` lines 550-738, 929-1013.
Helpers at lines 298-334 (`is_not_from_future_slot`, `is_within_slot_range`).

#### BLOCK rules (validate_beacon_block_gossip, lines 550-620)

- [ ] RB1 — [IGNORE] block is from a future slot (line 565)
- [ ] RB2 — [IGNORE] block slot <= finalized slot (line 572)
- [ ] RB3 — [IGNORE] not the first valid block for this proposer+slot (line 576)
- [ ] RB4 — [REJECT] proposer_index out of range (line 580)
- [ ] RB5 — [REJECT] invalid proposer signature (line 583)
- [ ] RB6 — [IGNORE] block parent not seen (line 592)
- [ ] RB7 — [REJECT] block parent passes validation (parent in invalid-roots) (line 596)
- [ ] RB8 — [REJECT] block slot <= parent slot (line 600)
- [ ] RB9 — [REJECT] finalized checkpoint is not an ancestor of block (line 604)
- [ ] RB10 — [REJECT] block proposer_index does not match expected proposer (line 610)

#### AGGREGATE rules (validate_beacon_aggregate_and_proof_gossip, lines 630-738)

- [ ] RAG1 — [REJECT] committee index out of range (line 646)
- [ ] RAG2 — [IGNORE] aggregate slot not within propagation range (line 653)
- [ ] RAG3 — [REJECT] attestation epoch does not match target epoch (line 658)
- [ ] RAG4 — [REJECT] aggregation bits length does not match committee size (line 663)
- [ ] RAG5 — [REJECT] aggregate has no participants (line 668)
- [ ] RAG6 — [IGNORE] already seen aggregate for this data (line 672)
- [ ] RAG7 — [IGNORE] already seen aggregate from this aggregator for this epoch (line 680)
- [ ] RAG8 — [REJECT] validator is not selected as aggregator (line 685)
- [ ] RAG9 — [REJECT] aggregator index not in committee (line 690)
- [ ] RAG10 — [REJECT] invalid selection proof signature (line 693)
- [ ] RAG11 — [REJECT] invalid aggregator signature (line 700)
- [ ] RAG12 — [REJECT] invalid aggregate signature (line 706)
- [ ] RAG13 — [IGNORE] block being voted for has not been seen (line 711)
- [ ] RAG14 — [REJECT] block being voted for failed validation (line 715)
- [ ] RAG15 — [REJECT] target block is not an ancestor of LMD vote block (line 719)
- [ ] RAG16 — [IGNORE] finalized checkpoint is not an ancestor of block (line 726)

Note: The spec text (lines 646-731) has 16 IGNORE/REJECT rules for aggregates,
not 12. The plan section heading says "12 rules" but the spec has 4 IGNORE + 12
REJECT = 16 total. RAG1..RAG16 are the full inventory; Phases 2-3 reference
these ids. The plan body at Task 0.2 says "12 rules"; the actual spec count is
16. Phases 2-3 should use RAG1..RAG16.

#### ATTESTATION rules (validate_beacon_attestation_gossip, lines 929-1013)

- [ ] RAT1 — [REJECT] committee index out of range (line 946)
- [ ] RAT2 — [REJECT] attestation is for wrong subnet (line 951)
- [ ] RAT3 — [IGNORE] attestation slot not within propagation range (line 958)
- [ ] RAT4 — [REJECT] attestation epoch does not match target epoch (line 965)
- [ ] RAT5 — [REJECT] attestation is not unaggregated (line 969)
- [ ] RAT6 — [REJECT] aggregation bits length does not match committee size (line 974)
- [ ] RAT7 — [IGNORE] already seen attestation from this validator for this epoch (line 980)
- [ ] RAT8 — [REJECT] invalid attestation signature (line 984)
- [ ] RAT9 — [IGNORE] block being voted for has not been seen (line 989)
- [ ] RAT10 — [REJECT] block being voted for failed validation (line 994)
- [ ] RAT11 — [REJECT] target block is not an ancestor of LMD vote block (line 999)
- [ ] RAT12 — [IGNORE] finalized checkpoint is not an ancestor of block (line 1005)

Note: The spec has 12 attestation rules (6 REJECT + 6 IGNORE), not 10 as stated in
the plan body. RAT1..RAT12 are the full inventory.

#### Gossip dispatch blocking-state

Audit performed (Task 0.5, 2026-05-28):
- `crates/pharos-network/src/network/mod.rs:531` — single call site:
  `dispatch_gossip_message::<E, H>(self.host.as_ref(), &topic, &ssz_bytes)` called
  directly from the async `on_gossip_message` method with NO `spawn_blocking` wrap.
- `crates/pharos-network/src/gossip/mod.rs` — `dispatch_gossip_message` is a pure
  synchronous function that delegates to the host validators; no async call sites here.
- **Total async call sites requiring spawn_blocking wrap: 1** (network/mod.rs:531).
- Task 0.6 wraps this site unconditionally. Wrapped in commit
  `chore(m4e): phase 0 spec freeze + scaffolding`.

#### Task 0.8 audit result

`rg "fn get_checkpoint_block" crates/pharos-fork-choice/` returned:
`crates/pharos-fork-choice/src/get_head.rs:102: pub fn get_checkpoint_block<E: EthSpec>(store: &Store<E>, root: Root, epoch: Epoch) -> Root`
**Present**. Task 1.1 is skipped; Phase 1 uses the existing helper at
`crates/pharos-fork-choice/src/get_head.rs:102`.

#### Task 0.9 audit result

`rg "pub struct DomainType\b" crates/pharos-types/` returned no matches.
`DomainType` is a **type alias** for `pharos_utils::Bytes4` (not a struct),
at `crates/pharos-types/src/phase0/primitives.rs:34`:
`pub type DomainType = pharos_utils::Bytes4;`
The existing domain constants (`DOMAIN_BEACON_PROPOSER`, etc.) use `[u8; 4]`
directly in `pharos-stf/src/phase0/helpers.rs`. Task 0.10 adds the two new
constants in the same `[u8; 4]` shape to match.

### Phase 1 — `validate_beacon_block`
Why this phase: smallest of the three (one BLS verify, no committee
math); lands the architectural pieces (proposer cache,
invalid-roots cache, new HostImpl fields, the spec-rule-keyed verdict
strings) that Phases 2 and 3 build on.

- [x] Task 1.1: skipped, pre-existing helper at `crates/pharos-fork-choice/src/get_head.rs:102`.
  Added `pub use get_head::get_checkpoint_block` to `crates/pharos-fork-choice/src/lib.rs`
  so Task 1.4 step 9 can call `pharos_fork_choice::get_checkpoint_block`.
- [ ] Task 1.2: Add three new fields to `HostImpl<E>` at
  `crates/pharos-node/src/host_impl.rs:84-104`:
    - `seen_block_proposers: RwLock<lru::LruCache<(Slot, u64), ()>>`
      with `LruCache::new(NonZeroUsize::new(4096).unwrap())`.
    - `proposer_cache: RwLock<lru::LruCache<(Slot, Root), u64>>`
      capacity `1024`.
    - `invalid_block_roots: RwLock<lru::LruCache<Root, ()>>`
      capacity `256`.
  Update `HostImpl::new` at line `114-156` to initialise all three.
  Import `use lru::LruCache;` and
  `use std::num::NonZeroUsize;` at the top. (The two attestation /
  aggregate caches are added in Task 2.1 / 3.1 next to their
  consumers.) Run `cargo check -p pharos-node`.
- [ ] Task 1.3: Implement
  `fn lookup_or_compute_expected_proposer(&self, slot: Slot,
  parent_root: Root) -> Option<u64>` as a private method on
  `HostImpl<E>`. Pseudocode:
  ```
  if let Some(idx) = self.proposer_cache.read().peek(&(slot, parent_root)) {
      return Some(*idx);
  }
  let mut parent_state = self.fork_choice.read().block_states
      .get(&parent_root)?.clone();
  if parent_state.slot() < slot {
      pharos_stf::process_slots_fork::<E>(&mut parent_state, slot).ok()?;
  }
  let idx = pharos_stf::phase0::accessors::get_beacon_proposer_index::<E>(&parent_state).0;
  self.proposer_cache.write().put((slot, parent_root), idx);
  Some(idx)
  ```
  `peek` (not `get`) keeps the read cheap; `put` on the write path
  bumps recency. Place under the existing `impl<E: EthSpec>
  HostImpl<E>` block, after `record_attnets_change`. Add a
  `#[test]` `proposer_cache_hits_on_second_lookup` that calls the
  helper twice with the same args, asserts identical result, and
  asserts the fork-choice lock was only contended on the first
  call (verifiable by `parking_lot::RwLock::is_locked` or by
  invoking the helper from two threads via a barrier).
- [ ] Task 1.4: Replace the body of `validate_beacon_block` at
  `crates/pharos-node/src/host_impl.rs:361-363` with the full spec
  per `specs/phase0/p2p-interface.md:550-619`. Strict step order
  (each step short-circuits on first failure):
    1. **[REJECT] "parent block is in the invalid-roots set" (spec line 595, RB7).**
       Implements the invalid-roots short-circuit per
       `D-invalid-roots-cache` (R7).
       `if self.invalid_block_roots.read().peek(&block.message.parent_root).is_some() { return Reject("block: parent in invalid set"); }`
    2. **[IGNORE] "block is from a future slot" (spec line 565, RB1).**
       Compute `current_time_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64`,
       `slot_time_ms = genesis_time * 1000 + block.slot() * runtime_cfg.seconds_per_slot * 1000`.
       `if current_time_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS < slot_time_ms { return Ignore("block: from future slot"); }`.
       (Implements `is_not_from_future_slot` inline; no helper crate
       call.)
    3. **[IGNORE] "block is not from a slot greater than the latest finalized slot" (spec line 568, RB2).**
       `let fc = self.fork_choice.read();`
       `let finalized_slot = compute_start_slot_at_epoch::<E>(fc.finalized_checkpoint.epoch);`
       `if block.slot() <= finalized_slot { return Ignore("block: not greater than finalized slot"); }`
    4. **[IGNORE] "first block for this proposer for the slot" (spec line 575, RB3).**
       `if self.seen_block_proposers.read().peek(&(block.slot(), block.proposer_index().0)).is_some() { return Ignore("block: duplicate proposer/slot"); }`
       (Reads `block.proposer_index()` via the existing
       `BeaconBlockView` trait at `pharos-types/src/views.rs`.)
    5. **[REJECT] "proposer index out of range" (spec line 579, RB4).**
       `let state = fc.block_states.get(&block.parent_root()).cloned();`
       `if state.is_none() { ... handled by RB6 next ... }`
       Else: `if block.proposer_index().0 as usize >= state.validators_count() { return Reject("block: proposer index out of range"); }`.
       (Use the existing `BeaconStateView::validators_count`
       accessor at `crates/pharos-types/src/views.rs`; if absent,
       add it as a thin wrapper around `.validators().len()`.)
    6. **[IGNORE] "block's parent has been seen" (spec line 590, RB6).**
       Re-read the cached `fc` (already borrowed in step 5).
       `if !fc.blocks.contains_key(&block.parent_root()) { return Ignore("block: parent unseen"); }`
       (Order: check parent-seen BEFORE parent-state-validity so the
       state-missing path in step 5 falls through cleanly. The spec
       sequences these slightly differently; the swap is a
       no-op-observable reorder because both lead to the same
       verdict for the same input. Pinned by Task 1.5 test (h).)
    7. **[REJECT] "block's parent passes validation" (spec line 595; defensive sibling of RB7).**
       Note: this branch catches the case where the parent block
       hash is present in `fc.blocks` but its state failed to
       persist into `fc.block_states`; step 1 (RB7) handles the
       common path of explicitly-rejected parents.
       `if !fc.block_states.contains_key(&block.parent_root()) { return Reject("block: parent invalid"); }`
       (Insert into `invalid_block_roots` at this point? No — only
       the *current* block's root goes into the cache if we REJECT
       it for body reasons; the parent was already cached when
       we first REJECTed it.)
    8. **[REJECT] "block is from a higher slot than its parent" (spec line 599, RB8).**
       `let parent_slot = fc.blocks.get(&block.parent_root()).unwrap().slot();`
       `if block.slot() <= parent_slot { self.invalid_block_roots.write().put(block_root, ()); return Reject("block: not higher than parent slot"); }`
       (`block_root = block.message.tree_hash_root()` computed once
       at the top of the function for use in steps 8/10/11 cache
       insert paths.)
    9. **[REJECT] "current finalized checkpoint is an ancestor of the block" (spec line 603, RB9).**
       `let cp = get_checkpoint_block::<E>(&fc, block.parent_root(), fc.finalized_checkpoint.epoch);`
       `if cp != Some(fc.finalized_checkpoint.root) { self.invalid_block_roots.write().put(block_root, ()); return Reject("block: finalized not ancestor"); }`
    10. **[REJECT] "block is proposed by the expected proposer for the slot" (spec line 610, RB10).**
        Drop the `fc` read guard (so the proposer-lookup helper can
        re-acquire it). `let expected = self.lookup_or_compute_expected_proposer(block.slot(), block.parent_root());`
        `match expected { None => return Ignore("block: shuffling unavailable"), Some(idx) => if idx != block.proposer_index().0 { self.invalid_block_roots.write().put(block_root, ()); return Reject("block: proposer mismatch"); } }`
        (The spec's "if shuffling is not available, IGNORE" clause
        maps to `None`-from-cache, which only happens when the
        parent state is missing — covered upstream by RB6/RB7 but
        defensive-default to Ignore here.)
    11. **[REJECT] "proposer signature is valid" (spec line 583, RB5).**
        Compute `domain = get_domain::<E>(&parent_state_at_slot,
        DOMAIN_BEACON_PROPOSER, Some(compute_epoch_at_slot::<E>(block.slot())))`;
        `signing_root = compute_signing_root(&block.message, domain);`
        `let pubkey = parent_state_at_slot.validators().get(block.proposer_index().0 as usize)?.pubkey.clone();`
        `let ok = pharos_utils::bls::verify(&pubkey, signing_root.as_ref(), block.signature())?;`
        `if !ok { self.invalid_block_roots.write().put(block_root, ()); return Reject("block: invalid proposer signature"); }`
        (Reuses the parent-state-at-slot computed inside
        `lookup_or_compute_expected_proposer`. Expose it from the
        helper by returning `(idx, Arc<E::BeaconState>)` instead of
        `idx` — adjust Task 1.3's signature accordingly. Cache stays
        keyed on `(slot, parent_root) → ValidatorIndex` only;
        the state clone is recomputed on cache hit (still cheap
        because tree-backed).)
    12. **Insert into seen cache (D-seen-cache-after-accept).**
        `self.seen_block_proposers.write().put((block.slot(), block.proposer_index().0), ());`
        Return `GossipVerdict::Accept`.
  Remove the `TODO(M4)` doc comment; replace with a paragraph
  citing `specs/phase0/p2p-interface.md:540-620` and
  `D-bls-on-hot-path` / `D-invalid-roots-cache` /
  `D-seen-cache-after-accept`.
- [ ] Task 1.5: Add 14 `#[test]` functions to
  `crates/pharos-node/src/host_impl.rs` `mod tests`. Tests (a)-(k)
  cover the 10 spec rules `RB1..RB10` plus one happy-path, tests
  (l)-(n) cover cache mechanics (NOT spec rules — verifying the
  LRU caches behave correctly across calls):
  (a) `block_ignores_future_slot` — RB1. `block.slot = now + 100`,
      assert `Ignore("block: from future slot")`.
  (b) `block_ignores_at_or_below_finalized` — RB2. `block.slot ==
      finalized_slot`, assert `Ignore("block: not greater than
      finalized slot")`.
  (c) `block_ignores_duplicate_proposer_slot` — RB3. First call
      Accept; second call same `(slot, proposer)` asserts
      `Ignore("block: duplicate proposer/slot")`.
  (d) `block_rejects_proposer_index_out_of_range` — RB4. Set
      `proposer_index = state.validators_count()`, assert
      `Reject("block: proposer index out of range")`.
  (e) `block_ignores_unknown_parent` — RB6. `parent_root =
      Root([0xff; 32])`, assert `Ignore("block: parent unseen")`.
  (f) `block_rejects_parent_in_invalid_set` — RB7 (also exercises
      the invalid-roots cache lookup mechanic). Pre-populate
      `invalid_block_roots` with a root, assert `Reject("block:
      parent in invalid set")` on first call.
  (g) `block_rejects_parent_state_missing` — defensive sibling of
      RB7 (step 7 branch). `parent` in `fc.blocks` but not in
      `fc.block_states`, assert `Reject("block: parent invalid")`.
  (h) `block_rejects_lower_or_equal_slot_than_parent` — RB8.
      `block.slot == parent.slot`, assert `Reject("block: not
      higher than parent slot")`.
  (i) `block_rejects_finalized_not_ancestor` — RB9. Fabricate a
      finalized checkpoint not on the block's chain, assert
      `Reject("block: finalized not ancestor")`.
  (j) `block_rejects_proposer_mismatch` — RB10. Set
      `proposer_index = expected + 1`, assert `Reject("block:
      proposer mismatch")`.
  (k) `block_rejects_invalid_signature` — RB5. Flip one byte in
      `signed_block.signature`, assert `Reject("block: invalid
      proposer signature")`.
  Cache-mechanic tests (not spec rules):
  (l) `block_accepts_happy_path` — cache-mechanic / smoke. Fully
      valid block, assert `Accept`; verifies the on-accept seen-
      cache write.
  (m) `block_proposer_cache_avoids_redo` — cache-mechanic
      (proposer-cache hit). Call once, then call again with a
      different `proposer_index` for the same `(slot,
      parent_root)`. Second call must Reject at step 10 using the
      cached `expected` (no re-acquisition of `fc` observable via
      instrumentation count).
  (n) `block_invalid_roots_cache_persists` — cache-mechanic
      (child-of-rejected). Call once that REJECTs at step 11 (bad
      signature). Then on a *second* call with a child block whose
      `parent_root` is the first block's root, assert step-1
      short-circuit `Reject("block: parent in invalid set")`.
- [ ] Task 1.6: `make check && make lint && make test` (single
  invocation, capture to `target/test-logs/m4e-phase1.log`). All 14
  new tests pass; zero new clippy warnings.

**Checkpoint: Verify Phase 1 complete.** Review Tasks 1.1-1.6.
Confirm: `get_checkpoint_block` exists (added or pre-existing); the
three new fields on `HostImpl<E>` are wired; `validate_beacon_block`
implements every step 1-12 with the verdict strings as written; 14
new tests green; `target/test-logs/m4e-phase1.log` shows pass=N,
fail=0. **Commit boundary:** `feat(node): real beacon_block gossip
validation per phase0 p2p-interface`.

### Phase 2 — `validate_attestation`
Why this phase: builds on Phase 1's HostImpl-cache pattern; adds the
attestation seen-cache, the committee cache, the subnet computation,
and the indexed-attestation aggregate-verify chain. Smaller than
Phase 3 (no selection-proof or aggregator signature) — keeps the
phases bounded to ≤ 7 tasks.

- [ ] Task 2.1: Add two new fields to `HostImpl<E>`:
    - `seen_attestation_validators: RwLock<lru::LruCache<(u64, Epoch), ()>>`
      capacity `131072` (the validator-index `u64` is unwrapped
      from `ValidatorIndex`).
    - `committee_cache: RwLock<lru::LruCache<(Slot, u64, Root), Vec<u64>>>`
      capacity `4096`.
  Update `HostImpl::new` to initialise both. Run
  `cargo check -p pharos-node`.
- [ ] Task 2.2: Add three pure helpers to
  `crates/pharos-stf/src/phase0/`:
  (a) In `accessors.rs` (or a new `gossip_helpers.rs`, judged at
      Task 0.2's existing-patterns audit):
      `pub fn compute_subnet_for_attestation<E: EthSpec>(committees_per_slot: u64, slot: Slot, committee_index: u64) -> u64 { let slots_since_epoch_start = slot.0 % E::SLOTS_PER_EPOCH; let committees_since = committees_per_slot * slots_since_epoch_start; (committees_since + committee_index) % ATTESTATION_SUBNET_COUNT as u64 }`
      where `ATTESTATION_SUBNET_COUNT` is the existing const at
      `pharos-types/src/phase0/primitives.rs`. Add a `#[test]`
      `compute_subnet_for_attestation_matches_spec` with three
      spec-fixture cases (slot=0/idx=0 → 0; mid-epoch case; epoch-
      end case).
  (b) Inline in `validate_attestation` body (no helper):
      `is_within_slot_range(att_slot, range, now_ms, genesis_time_s,
      seconds_per_slot)` per spec lines 317-333. Two-edge check:
      `start_time_ms = genesis_time_s * 1000 + att_slot *
      seconds_per_slot * 1000`; `end_time_ms = genesis_time_s * 1000
      + (att_slot + range + 1) * seconds_per_slot * 1000`.
      `if now_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS < start_time_ms
      { return false; }`; `if end_time_ms +
      MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS < now_ms { return false; }`;
      else `true`.
  (c) `pub fn lookup_or_compute_committee<E: EthSpec, H: ...>(host:
      &H, slot: Slot, index: u64) -> Option<Vec<u64>>` — actually
      this is a HostImpl method (the cache lives on Host), so
      implement it on `impl<E: EthSpec> HostImpl<E>` mirroring Task
      1.3's pattern: peek cache → on miss, clone head state from
      `fork_choice.read().block_states.get(&head_root)` → if
      state.slot() < slot, `process_slots_fork` → call
      `get_beacon_committee::<E>(&state, slot, index).map(|v| v.iter().map(|i| i.0).collect())` → put cache → return.
      `head_root` is from `pharos_fork_choice::get_head(&*fc)`.
      Cache key is `(slot, index, head_root)` per D-cache-key-on-head.
- [ ] Task 2.3: Implement a private method `fn head_state_at_slot(&self,
  slot: Slot) -> Option<E::BeaconState>` on `HostImpl<E>` that
  returns a clone of the head state advanced to `slot`. Mirrors
  the `crates/pharos-fork-choice/src/handlers.rs:194-199` pattern.
  Used by Task 2.4 step 1 (committee count) and by Task 3.4 step
  1 (committee count + selection-proof domain). One method, two
  callers — avoids duplication.
- [ ] Task 2.4: Replace the body of `validate_attestation` at
  `crates/pharos-node/src/host_impl.rs:366-368` with the full spec
  per `specs/phase0/p2p-interface.md:929-1013`. Step order:
    1. **[REJECT] "committee index out of range" (line 946, RAT1).**
       `let head_state = self.head_state_at_slot(att.data.slot)?;`
       (returns Option; on None return `Ignore("att: head state
       unavailable")` — defensive, not a spec rule but covers the
       window between checkpoint sync and first block).
       `let committee_count = get_committee_count_per_slot::<E>(&head_state, att.data.target.epoch);`
       `if att.data.index.0 >= committee_count { return Reject("att: committee index out of range"); }`
    2. **[REJECT] "attestation is for the correct subnet" (line 951, RAT2).**
       `let expected_subnet = compute_subnet_for_attestation::<E>(committee_count, att.data.slot, att.data.index.0);`
       `if expected_subnet != subnet.0 { return Reject("att: wrong subnet"); }`
    3. **[IGNORE] "attestation slot within propagation range" (line 958, RAT3).**
       Compute `now_ms`; call the inline `is_within_slot_range` (Task
       2.2(b)) with `range = ATTESTATION_PROPAGATION_SLOT_RANGE`;
       if false `return Ignore("att: slot not in propagation range")`.
    4. **[REJECT] "attestation's epoch matches its target" (line 965, RAT4).**
       `if att.data.target.epoch != compute_epoch_at_slot::<E>(att.data.slot) { return Reject("att: target epoch mismatch"); }`
    5. **[REJECT] "attestation is unaggregated" (line 969, RAT5).**
       `let num_bits_set = att.aggregation_bits.iter().filter(|b| *b).count();`
       `if num_bits_set != 1 { return Reject("att: not unaggregated"); }`
    6. **[REJECT] "aggregation bits length matches committee size" (line 974, RAT6).**
       `let committee = self.lookup_or_compute_committee(att.data.slot, att.data.index.0).ok_or_else(|| ...)?;`
       (on None: `return Ignore("att: committee unavailable")`).
       `if att.aggregation_bits.len() != committee.len() { return Reject("att: agg bits length mismatch"); }`
    7. **[IGNORE] "no other valid attestation seen for this validator/epoch" (line 979, RAT7).**
       `let bit_idx = att.aggregation_bits.iter().position(|b| b).unwrap();` (safe — step 5 confirmed exactly one bit set).
       `let participant = committee[bit_idx];`
       `if self.seen_attestation_validators.read().peek(&(participant, att.data.target.epoch)).is_some() { return Ignore("att: duplicate validator/epoch"); }`
    8. **[REJECT] "attestation signature is valid" (line 984, RAT8).**
       `let indexed = get_indexed_attestation::<E>(&head_state, att);`
       `if !is_valid_indexed_attestation::<E>(&head_state, &indexed, true) { return Reject("att: invalid signature"); }`
       (third arg `verify_signatures = true`).
    9. **[IGNORE] "block being voted for has been seen" (line 989, RAT9).**
       `let fc = self.fork_choice.read();`
       `if !fc.blocks.contains_key(&att.data.beacon_block_root) { return Ignore("att: voted block unseen"); }`
    10. **[REJECT] "block being voted for passes validation" (RAT-extra).**
        `if !fc.block_states.contains_key(&att.data.beacon_block_root) { return Reject("att: voted block invalid"); }`
        (Spec line 995.)
    11. **[REJECT] "target block is ancestor of LMD vote block" (line 999, RAT10).**
        `let target_cp = get_checkpoint_block::<E>(&fc, att.data.beacon_block_root, att.data.target.epoch);`
        `if target_cp != Some(att.data.target.root) { return Reject("att: target not ancestor"); }`
    12. **[IGNORE] "finalized checkpoint is an ancestor of the block" (line 1004, RAT-extra2).**
        `let final_cp = get_checkpoint_block::<E>(&fc, att.data.beacon_block_root, fc.finalized_checkpoint.epoch);`
        `if final_cp != Some(fc.finalized_checkpoint.root) { return Ignore("att: finalized not ancestor"); }`
    13. **Insert into seen cache.** `self.seen_attestation_validators.write().put((participant, att.data.target.epoch), ());` Return `Accept`.
  Replace doc comment with paragraph citing
  `specs/phase0/p2p-interface.md:929-1013` and the relevant ADRs.
- [ ] Task 2.5: Add 13 `#[test]` functions in
  `crates/pharos-node/src/host_impl.rs` `mod tests`, one per RAT1-
  RAT10 plus RAT-extra1/2 plus happy-path:
  (a) `att_rejects_committee_index_out_of_range` (RAT1)
  (b) `att_rejects_wrong_subnet` (RAT2)
  (c) `att_ignores_slot_out_of_range` (RAT3)
  (d) `att_rejects_target_epoch_mismatch` (RAT4)
  (e) `att_rejects_aggregated_bits` (RAT5 — zero or many bits set)
  (f) `att_rejects_agg_bits_length_mismatch` (RAT6)
  (g) `att_ignores_duplicate_validator_epoch` (RAT7)
  (h) `att_rejects_invalid_signature` (RAT8)
  (i) `att_ignores_unseen_voted_block` (RAT9)
  (j) `att_rejects_invalid_voted_block` (RAT-extra1)
  (k) `att_rejects_target_not_ancestor` (RAT10)
  (l) `att_ignores_finalized_not_ancestor` (RAT-extra2)
  (m) `att_accepts_happy_path`
- [ ] Task 2.6: `make check && make lint && make test` (capture to
  `target/test-logs/m4e-phase2.log`). 13 new tests + 14 from Phase
  1 all green.

**Checkpoint: Verify Phase 2 complete.** Review Tasks 2.1-2.6.
Confirm: `seen_attestation_validators` / `committee_cache` on
`HostImpl<E>`; `compute_subnet_for_attestation` + inline
`is_within_slot_range` exist; `validate_attestation` implements steps
1-13; 13 new tests green; conformance unaffected (no full
`make conformance` here — that's Phase 6). **Commit boundary:**
`feat(node): real beacon_attestation gossip validation per phase0
p2p-interface`.

### Phase 3 — `validate_aggregate_and_proof`
Why this phase: largest of the three (three BLS verifies); composes
the Phase 1 + Phase 2 caches; introduces the aggregator-seen cache
and the `is_aggregator` predicate. Splits cleanly into ≤ 7 tasks.

- [ ] Task 3.1: Add one new field to `HostImpl<E>`:
    - `seen_aggregators: RwLock<lru::LruCache<(u64, Epoch), ()>>`
      capacity `8192`.
  Update `HostImpl::new`. Run `cargo check -p pharos-node`.
- [ ] Task 3.2: Add `is_aggregator` to
  `crates/pharos-stf/src/phase0/predicates.rs` per
  D-is-aggregator-location. Signature:
  `pub fn is_aggregator(committee_len: usize, slot_signature: &BLSSignature) -> bool`.
  Body: `let modulo = std::cmp::max(1usize, committee_len / TARGET_AGGREGATORS_PER_COMMITTEE as usize); let h = pharos_utils::hash::hash(slot_signature.as_ref()); let n = u64::from_le_bytes(h[0..8].try_into().unwrap()); n % (modulo as u64) == 0`.
  Add `#[test]` `is_aggregator_known_vectors` with three pre-computed
  signatures whose first 8 bytes of sha256 yield known modulo
  results (use `bls::Sign` once with a fixed privkey to generate
  the test vector; hard-code the result so the test does not
  require BLS verify at test time).
- [ ] Task 3.3: Note about
  `[IGNORE] "valid aggregate with a superset of aggregation bits
  has not already been seen"` (spec line 672, RAG6):
  the spec demands a `seen.aggregate_data_roots: HashMap<Root,
  Set<Tuple<bool>>>` keyed by `hash_tree_root(aggregate.data)` with
  values being all previously-seen aggregation-bit tuples; the
  IGNORE fires iff the incoming bits are a non-strict superset of
  any seen set for the same data root. Pharos M4e implements a
  **weakened** form: keep an LRU cache
  `seen_aggregate_data: RwLock<lru::LruCache<Root,
  pharos_ssz::Bitlist<MAX_VALIDATORS_PER_COMMITTEE>>>` capacity
  `2048`, where the stored bitlist is the OR of all previously
  seen bits for that data root. `Bitlist<N>` already provides
  `new()`, `with_capacity(bits)`, `get(i) -> Option<bool>`,
  `set(i, value)`, `iter()`, and `len()` (verified at
  `crates/pharos-ssz/src/bitfield.rs:208-281`); no new dep.
  The IGNORE fires iff every set bit in `incoming_bits` is
  already set in `stored_bits` (covered = true after iterating
  over `incoming.iter().enumerate()`). This is strictly stronger
  (i.e. ignores MORE messages) than the spec when multiple
  disjoint subsets have been seen; in steady-state the
  difference is observable only when honest aggregators produce
  exact-disjoint subsets, which the spec validator decoding
  attestations from gossip already filters. Add this field to
  `HostImpl<E>` here. **OQ1** records the rejected alternative
  (full per-tuple set).
- [ ] Task 3.4: Replace the body of `validate_aggregate_and_proof`
  at `crates/pharos-node/src/host_impl.rs:371-373` with the full
  spec per `specs/phase0/p2p-interface.md:629-737`. The input type
  per trait signature is `&AggregateAndProof<2048>` (the unsigned
  one) — the wrapper signature lives outside; check that the
  network dispatch at `gossip/mod.rs:111-115` passes the
  `signed_aggregate_and_proof.message` (verified at `gossip/mod.rs:114`
  by `host.validate_aggregate_and_proof(&saap.message)`). The
  outer-signature check (RAG10) still happens here even though we
  only see the inner; the signature is reconstructed via the
  separate `signed_aggregate_and_proof.signature` field, which means
  the trait signature is **insufficient** — we need access to the
  outer signature.
    - **Trait-surface change:** modify
      `crates/pharos-network/src/host.rs:132` from
      `fn validate_aggregate_and_proof(&self, msg: &AggregateAndProof<2048>) -> GossipVerdict;`
      to
      `fn validate_aggregate_and_proof(&self, msg: &SignedAggregateAndProof<2048>) -> GossipVerdict;`.
      Update the `Arc<T>` blanket impl at `host.rs:342-344`. Update
      the gossip dispatch call site at
      `crates/pharos-network/src/gossip/mod.rs:114` from
      `host.validate_aggregate_and_proof(&saap.message)` to
      `host.validate_aggregate_and_proof(&saap)`. Update all five
      mock impls (`crates/pharos-network/benches/rpc_roundtrip.rs:136`,
      `crates/pharos-network/src/gossip/mod.rs:249`,
      `crates/pharos-network/src/rpc/handler.rs:327`,
      `crates/pharos-network/src/network/mod.rs:1824`,
      `crates/pharos-network/tests/common/mod.rs:302`) to match the
      new signature.
  Then step order in the validator body:
    1. **[REJECT] "committee index within range" (line 646, RAG1).**
       `let agg = &saap.message.aggregate;`
       `let head_state = self.head_state_at_slot(agg.data.slot)?;`
       (None → `Ignore("agg: head state unavailable")`).
       `let committee_count = get_committee_count_per_slot::<E>(&head_state, agg.data.target.epoch);`
       `if agg.data.index.0 >= committee_count { return Reject("agg: committee index out of range"); }`
    2. **[IGNORE] "aggregate slot in propagation range" (line 651, RAG2).**
       Inline `is_within_slot_range` (re-use Task 2.2(b)).
    3. **[REJECT] "epoch matches target" (line 658, RAG3).**
       `if agg.data.target.epoch != compute_epoch_at_slot::<E>(agg.data.slot) { return Reject("agg: target epoch mismatch"); }`
    4. **[REJECT] "aggregation bits length matches committee size" (line 662, RAG4).**
       `let committee = self.lookup_or_compute_committee(agg.data.slot, agg.data.index.0).ok_or_else(...)?;`
       `if agg.aggregation_bits.len() != committee.len() { return Reject("agg: agg bits length mismatch"); }`
    5. **[REJECT] "aggregate has participants" (line 667, RAG5).**
       `let attesting_indices = get_attesting_indices::<E>(&head_state, &agg.data, &agg.aggregation_bits);`
       `if attesting_indices.is_empty() { return Reject("agg: no participants"); }`
    6. **[IGNORE] "superset of aggregation bits not seen" (line 672, RAG6).**
       Per Task 3.3 weakened form using
       `pharos_ssz::Bitlist<MAX_VALIDATORS_PER_COMMITTEE>`: compute
       `data_root = agg.data.tree_hash_root();`
       `let read = self.seen_aggregate_data.read();`
       `if let Some(stored) = read.peek(&data_root) { let mut covered = true; for (i, b) in agg.aggregation_bits.iter().enumerate() { if b && !stored.get(i).unwrap_or(false) { covered = false; break; } } if covered { return Ignore("agg: superset seen"); } }`
       Drop the read guard before continuing.
    7. **[IGNORE] "first valid aggregate from this aggregator this epoch" (line 679, RAG7).**
       `let aggregator_index = saap.message.aggregator_index.0;`
       `let target_epoch = agg.data.target.epoch;`
       `if self.seen_aggregators.read().peek(&(aggregator_index, target_epoch)).is_some() { return Ignore("agg: duplicate aggregator/epoch"); }`
    8. **[REJECT] "selection proof selects validator" (line 685, RAG8).**
       `if !pharos_stf::phase0::predicates::is_aggregator(committee.len(), &saap.message.selection_proof) { return Reject("agg: not selected as aggregator"); }`
    9. **[REJECT] "aggregator index is within committee" (line 689, RAG9).**
       `if !committee.contains(&aggregator_index) { return Reject("agg: aggregator not in committee"); }`
    10. **[REJECT] "selection-proof signature is valid" (line 693, RAG10).**
        `let aggregator_pubkey = head_state.validators().get(aggregator_index as usize).map(|v| v.pubkey.clone()).ok_or_else(...)?;`
        `let domain = get_domain::<E>(&head_state, DOMAIN_SELECTION_PROOF, Some(target_epoch));`
        `let signing_root = compute_signing_root(&agg.data.slot, domain);`
        `if !pharos_utils::bls::verify(&aggregator_pubkey, signing_root.as_ref(), &saap.message.selection_proof)? { return Reject("agg: invalid selection proof signature"); }`
    11. **[REJECT] "aggregator signature is valid" (line 700, RAG11).**
        `let domain2 = get_domain::<E>(&head_state, DOMAIN_AGGREGATE_AND_PROOF, Some(target_epoch));`
        `let signing_root2 = compute_signing_root(&saap.message, domain2);`
        `if !pharos_utils::bls::verify(&aggregator_pubkey, signing_root2.as_ref(), &saap.signature)? { return Reject("agg: invalid aggregator signature"); }`
    12. **[REJECT] "aggregate signature valid" (line 706, RAG12).**
        `let indexed = get_indexed_attestation::<E>(&head_state, agg);`
        `if !is_valid_indexed_attestation::<E>(&head_state, &indexed, true) { return Reject("agg: invalid aggregate signature"); }`
    13. **[IGNORE] "block being voted for has been seen" (line 710).**
        `let fc = self.fork_choice.read();`
        `if !fc.blocks.contains_key(&agg.data.beacon_block_root) { return Ignore("agg: voted block unseen"); }`
    14. **[REJECT] "voted block passes validation" (line 715).**
        `if !fc.block_states.contains_key(&agg.data.beacon_block_root) { return Reject("agg: voted block invalid"); }`
    15. **[REJECT] "target block is ancestor of LMD vote block" (line 719).**
        `let cp = get_checkpoint_block::<E>(&fc, agg.data.beacon_block_root, target_epoch);`
        `if cp != Some(agg.data.target.root) { return Reject("agg: target not ancestor"); }`
    16. **[IGNORE] "finalized checkpoint ancestor of block" (line 726).**
        `let fcp = get_checkpoint_block::<E>(&fc, agg.data.beacon_block_root, fc.finalized_checkpoint.epoch);`
        `if fcp != Some(fc.finalized_checkpoint.root) { return Ignore("agg: finalized not ancestor"); }`
    17. **Insert into seen caches.** Drop `fc` read. Then:
        `self.seen_aggregators.write().put((aggregator_index, target_epoch), ());`
        Update the `seen_aggregate_data` cache: take a write
        guard, look up the existing `Bitlist<MAX_VALIDATORS_PER_COMMITTEE>`
        for `data_root` (or initialise via
        `Bitlist::with_capacity(committee.len())` + `push(false)`-loop
        to set `bit_len = committee.len()` if absent), then for
        each `(i, b)` in `agg.aggregation_bits.iter().enumerate()`
        where `b` is true, call `stored.set(i, true)`. Return
        `Accept`.
- [ ] Task 3.5: Add 16 `#[test]` functions in
  `crates/pharos-node/src/host_impl.rs` `mod tests`, one per
  RAG1-RAG12 plus RAG-extras 13/14/15/16 (collapsed where the
  branch is structurally identical to an attestation test):
  (a) `agg_rejects_committee_index_out_of_range` (RAG1)
  (b) `agg_ignores_slot_out_of_range` (RAG2)
  (c) `agg_rejects_target_epoch_mismatch` (RAG3)
  (d) `agg_rejects_agg_bits_length_mismatch` (RAG4)
  (e) `agg_rejects_no_participants` (RAG5)
  (f) `agg_ignores_seen_superset` (RAG6 — pre-populate with a bit
      superset, second call IGNOREs)
  (g) `agg_ignores_duplicate_aggregator_epoch` (RAG7)
  (h) `agg_rejects_not_aggregator` (RAG8 — set a slot_signature that
      hashes to a non-zero modulo result)
  (i) `agg_rejects_aggregator_not_in_committee` (RAG9)
  (j) `agg_rejects_invalid_selection_proof` (RAG10)
  (k) `agg_rejects_invalid_aggregator_signature` (RAG11)
  (l) `agg_rejects_invalid_aggregate_signature` (RAG12)
  (m) `agg_ignores_unseen_voted_block` (line 710 IGNORE)
  (n) `agg_rejects_target_not_ancestor` (line 719 REJECT)
  (o) `agg_accepts_happy_path`
  (p) `agg_rejects_when_aggregate_data_beacon_block_root_is_in_invalid_roots`
      (spec line 715 REJECT — voted block is in fork-choice
      `Invalid` payload-status set or otherwise fails validation,
      analogous to Task 2.5(j)'s `att_rejects_invalid_voted_block`)
- [ ] Task 3.6: `make check && make lint && make test` (capture to
  `target/test-logs/m4e-phase3.log`). All 16 new + 13 + 14 = 43
  new tests green.

**Checkpoint: Verify Phase 3 complete.** Review Tasks 3.1-3.6.
Confirm: trait signature changed to `SignedAggregateAndProof<2048>`;
all 5 mock impls updated; `seen_aggregators` + `seen_aggregate_data`
on `HostImpl<E>`; `is_aggregator` exists in
`pharos-stf/src/phase0/predicates.rs`; `validate_aggregate_and_proof`
implements all 17 steps; 16 new tests green. **Commit boundary:**
`feat(node): real beacon_aggregate_and_proof gossip validation per
phase0 p2p-interface`.

### Phase 4 — Integration test + spec-text round-trip
Why this phase: per-rule unit tests in Phases 1-3 are necessary but
not sufficient. Phase 4 adds one end-to-end integration test that
exercises the gossip dispatch path with all three validators wired,
and a "spec text round-trip" test that asserts every IGNORE/REJECT
string in the validator bodies matches a spec rule by exact-match
against a checked-in list.

- [ ] Task 4.1: Create
  `crates/pharos-node/tests/gossip_validators_e2e.rs` with one
  integration test
  `gossip_e2e_dispatch_all_three_topics`:
    (i) Build a `HostImpl<MainnetEthSpec>` via the existing
        `make_host` test helper (visible to integration tests via
        `#[cfg(test)]` is module-local — duplicate the helper into
        the integration test file per the M4c precedent at Task 4.3
        of `docs/m4c-plan.md`). Populate `fork_choice` with one
        finalized block + one head block + one head state.
    (ii) Construct three message fixtures from the existing
         consensus-spec-tests SSZ fixtures at
         `~/.cache/pharos-spec-tests/mainnet/phase0/`: a valid
         `SignedBeaconBlock` (use the `sanity/blocks/pyspec_tests`
         category's first passing test's `block_0` file), a valid
         `Attestation` (`operations/attestation/pyspec_tests`
         first passing test), a valid `SignedAggregateAndProof`
         (hand-build from the attestation: wrap in a synthetic
         aggregator + selection proof — since gossip fixtures
         aren't in the conformance corpus). Skip if any fixture
         absent (`panic!("fixture missing: <path>")`).
    (iii) Call each validator method directly on the host and
          assert Accept for each. This is the smoke test that
          all three real bodies type-check and run end-to-end.
- [ ] Task 4.2: Create
  `crates/pharos-node/tests/gossip_verdict_strings.rs` with one
  test
  `verdict_strings_match_known_list`:
    (i) Hard-code the full list of expected verdict strings
        (block: 11 strings, att: 13 strings, agg: 16 strings — 40
        total).
    (ii) Use a debug-only feature flag `#[cfg(feature =
         "test_verdicts")]` on a helper that returns the list as a
         `&'static [&'static str]`, or (simpler) `rg` the source at
         test build time via `include_str!("../src/host_impl.rs")`
         and check each known string is present.
    (iii) Assert no orphan strings remain (every expected string is
          present; the test fails if a string is renamed without
          updating this test).
- [ ] Task 4.3: `make check && make lint && make test` (capture to
  `target/test-logs/m4e-phase4.log`). Both integration tests green;
  workspace tests still green.

**Checkpoint: Verify Phase 4 complete.** Review Tasks 4.1-4.3.
Confirm: `gossip_validators_e2e.rs` and `gossip_verdict_strings.rs`
exist and pass; the verdict-string list is hard-coded and matches
the actual strings in `host_impl.rs`. **Commit boundary:** `test(node):
gossip validator integration + spec verdict-string round-trip`.

### Phase 5 — Bench update + cache-contention micro-bench
Why this phase: the M4c `gossip_validation` bench measures only the
LC finality validator (an O(1) tree-hash compare). M4e's three new
validators are O(committee_size) + BLS. Update the bench to cover
the three new methods so M4d devnet acceptance has baseline
numbers; add one micro-bench for cache contention.

- [ ] Task 5.1: Modify `crates/pharos-network/benches/gossip_validation.rs`
  (from M4c Task 4.3) to add three new criterion benchmark functions:
  `gossip_validation/beacon_block`,
  `gossip_validation/attestation_unaggregated`,
  `gossip_validation/aggregate_and_proof`. Each uses fixtures from
  the same path as Phase 4 Task 4.1; each calls the corresponding
  `host.validate_*` once per criterion sample, hitting the happy
  path (full BLS verify, full committee compute on first sample,
  cache hit on subsequent samples — note both timings in a doc
  comment). The bench file already has `make_host` duplicated per
  M4c precedent.
- [ ] Task 5.2: Add a fourth benchmark `gossip_validation/attestation_cache_warm`
  that pre-populates the committee + proposer + seen caches before
  the sample loop and measures only the steady-state cache-hit
  path. This isolates the BLS verify cost from the committee-compute
  cost.
- [ ] Task 5.3: Run `make bench` once on `PERF_HOST` (per
  `D-bench-machine`, M4-perf). Wall budget ~7 minutes (M4c
  baseline + four new benches at 100 samples × ~3 ms = ~1.2 s
  bench time; criterion overhead dominates). Inspect
  `bench-history/<sha>.json` — confirm seven new bench entries
  (3 new + 1 cache-warm + 3 retained from M4c). Commit the
  per-SHA JSON file. Append a `## M4e — gossip validation
  baseline` section to `docs/perf/m4-perf.md` listing the four
  new identifiers + their point estimates.

**Checkpoint: Verify Phase 5 complete.** Review Tasks 5.1-5.3.
Confirm: three new bench fns + one cache-warm fn live in
`gossip_validation.rs`; `bench-history/<sha>.json` has 7+ entries
(M4c-baseline retained + M4e additions); `docs/perf/m4-perf.md`
has new section. **Commit boundary:** `bench(m4e): record gossip
validator baseline on PERF_HOST`.

### Phase 6 — Audit + ADR fill-in + conformance regression check + version bump
Why this phase: every milestone closes with a documented audit + the
ADR bodies written + a conformance row-count gate to catch silent
drift. Mirrors `docs/m4c-plan.md` Phase 6.

- [ ] Task 6.1: Run `make conformance` (single invocation, captured
  to `target/test-logs/m4e-conformance.log`). Compare
  `docs/conformance.md` byte-for-byte against the post-M4c snapshot
  (`git show v0.6.0:docs/conformance.md > /tmp/conformance.before;
  diff /tmp/conformance.before docs/conformance.md`). Zero-diff is
  the gate. If non-zero, investigate. M4e changes are network-layer-
  only and the conformance runner does not exercise gossip
  validators (verified by Assumption A15) — non-zero diff is a red
  flag.
- [ ] Task 6.2: Fill in the twelve ADR bodies in `docs/decisions.md`
  under the `## M4e decisions` section. For each:
    1. `D-seen-cache-shape`
    2. `D-proposer-cache`
    3. `D-committee-cache`
    4. `D-verdict-strings-spec-keyed`
    5. `D-bls-on-hot-path`
    6. `D-invalid-roots-cache`
    7. `D-future-slot-disparity`
    8. `D-domain-types-additions`
    9. `D-is-aggregator-location`
    10. `D-cache-key-on-head`
    11. `D-seen-cache-after-accept`
    12. `D-no-tokio-from-validator`
  use the M4b/M4c decision template: `**Status**: Accepted.
  **Date**: 2026-05-28.` + 2–4 paragraphs of context, rejected
  alternatives, and `Enforced in: <paths>`. Each body's `Enforced
  in:` lists precise file:line ranges from this plan's tasks.
- [ ] Task 6.3: Draft a `CLAUDE.md` "M4e status" block to insert
  under the M4c status block. Mirror the M4c status block tone
  exactly: 5-line summary of scope shipped, decision keys list,
  conformance gate result, bench baseline SHA, deferred items
  (M5 voluntary_exit + slashing validators; M11 batched BLS).
  Per CLAUDE.md "don't commit CLAUDE.md unless asked" rule, surface
  as a manual edit suggestion at final audit, not auto-committed.
- [ ] Task 6.4: Run `make pre-push` (= `make ci` = fmt-check + lint
  + check + test-all). Single invocation, captured to
  `target/test-logs/m4e-prepush.log`. Zero failures, zero new
  warnings. This is the canonical sign-off.
- [ ] Task 6.5: Bump workspace version in root `Cargo.toml` from
  `0.6.0` to `0.7.0` (M4e is the next minor; consistent with
  `v0.5.0`→`v0.6.0` through M4c). Run `cargo check --workspace`
  to confirm propagation.

**Checkpoint: Verify Phase 6 complete.** Review Tasks 6.1-6.5.
Confirm: conformance diff was zero; twelve ADRs are filled (no
`Draft` remaining); `make pre-push` log shows green; workspace
version is `0.7.0`. **Commit boundary:** `chore(m4e): close
milestone — bump v0.7.0`.

- [ ] **Final Audit.** Re-read the entire plan. For each task (0.1
  through 6.5), verify the implementation exists in the codebase
  (file path, function name, test name, ADR key). List any gaps.
  All gaps must be resolved before reporting completion. Specifically:
  - Phase 0: `ATTESTATION_PROPAGATION_SLOT_RANGE` +
    `TARGET_AGGREGATORS_PER_COMMITTEE` consts; `lru` workspace dep
    + `pharos-node` dep; gossip dispatch is `spawn_blocking`-
    wrapped; `DOMAIN_SELECTION_PROOF` / `DOMAIN_AGGREGATE_AND_PROOF`
    in `pharos-stf/src/phase0/helpers.rs`; twelve ADR stubs in
    `docs/decisions.md`; spec rule inventory in this plan.
  - Phase 1: `get_checkpoint_block` present; three new cache fields
    on `HostImpl<E>`; `validate_beacon_block` implements all 12
    steps; 14 new unit tests pass.
  - Phase 2: two new cache fields; `compute_subnet_for_attestation`
    in `pharos-stf`; inline `is_within_slot_range`;
    `head_state_at_slot` private method;
    `lookup_or_compute_committee` private method;
    `validate_attestation` implements all 13 steps; 13 new tests.
  - Phase 3: trait surface for `validate_aggregate_and_proof`
    accepts `SignedAggregateAndProof<2048>`; all mock impls
    updated; `seen_aggregators` + `seen_aggregate_data` on
    `HostImpl<E>`; `is_aggregator` in `pharos-stf`;
    `validate_aggregate_and_proof` implements all 17 steps; 16 new
    tests.
  - Phase 4: `gossip_validators_e2e.rs` + `gossip_verdict_strings.rs`
    exist and pass.
  - Phase 5: four new bench fns; `bench-history/<sha>.json`
    committed; `docs/perf/m4-perf.md` updated.
  - Phase 6: conformance diff zero; twelve ADRs filled to
    Accepted; `make pre-push` green; version `0.7.0`; CLAUDE.md
    "M4e status" draft surfaced (not auto-committed).
  Run `code-reviewer` agent on the full diff per CLAUDE.md.

## Edge Cases & Risks
- R1: LRU eviction under reorg storm — addressed by D-seen-cache-shape
  capacity sizing (Tasks 1.2, 2.1, 3.1).
- R2: Proposer cache stale across reorgs — addressed by D-proposer-cache
  key choice (Task 1.3).
- R3: Committee cache thrash under reorgs — addressed by
  D-committee-cache + D-cache-key-on-head (Task 2.2(c)).
- R4: `process_slots_fork` cost in `lookup_or_compute_expected_proposer`
  — addressed by Task 1.3 + bench Task 5.3 (cache-warm bench).
- R5: BLS verify on hot path — addressed by D-bls-on-hot-path; future
  batching is M11.
- R6: Clock disparity false positives — addressed by D-future-slot-
  disparity symmetric envelope; pinned by test 1.5(a) / 2.5(c) /
  3.5(b).
- R7: REJECT false positives banscoring honest peers — addressed by
  D-invalid-roots-cache only capturing spec-mandated REJECTs.
- R8: Mid-backfill stale-state — addressed by Task 2.4 step 9 / Task
  3.4 step 13 (IGNORE on unknown root, not block).
- R9: Concurrent validation races — addressed in plan body (benign,
  gossipsub message-id dedupes). No mitigation task; documented in
  R9 narrative.
- R10: RwLock contention — addressed by bench Task 5.3 measuring
  steady-state; shardable if observed (M11).
- R11: Spec drift — addressed by Task 0.1 final re-read +
  decisions.md citing the consensus-specs commit hash.
- R12: Aggregate-superset weakened form (Task 3.3) — addressed by
  OQ1 (records the rejected alternative).

## Acceptance Criteria
- `make check && make lint && make fmt-check && make test` green
  (captured to `target/test-logs/`).
- `make conformance` produces `docs/conformance.md` byte-identical
  to the post-M4c snapshot.
- `make pre-push` green (full CI including m0_acceptance).
- `cargo test -p pharos-node host_impl::tests::block_` passes (14
  tests).
- `cargo test -p pharos-node host_impl::tests::att_` passes (13
  tests).
- `cargo test -p pharos-node host_impl::tests::agg_` passes (16
  tests).
- `cargo test -p pharos-node --test gossip_validators_e2e` passes.
- `cargo test -p pharos-node --test gossip_verdict_strings` passes.
- All three of `validate_beacon_block`, `validate_attestation`,
  `validate_aggregate_and_proof` on `HostImpl<E>` contain real
  bodies (zero remaining `TODO(M4)` markers in those methods —
  the four `TODO(M4)` validators for voluntary_exit, proposer_
  slashing, attester_slashing, sync_committee_* stay as M5 work).
- Twelve new `### D-*` headers under `## M4e decisions` in
  `docs/decisions.md` are all `Status: Accepted`.
- Workspace version is `0.7.0`.
- `bench-history/<sha>.json` exists for the M4e wrap commit with
  at least 7 bench entries.

## Open Questions
- OQ1: Should `seen_aggregate_data` track per-tuple bit sets
  exactly (spec full form) or per-data-root OR'd bitvec (M4e
  weakened form, Task 3.3)? **Recommended default: weakened
  form for M4e.** Rationale: the spec's full form requires
  storing every previously-seen aggregation_bits tuple per
  data root; under heavy aggregation pressure (32 committees ×
  full epoch × multiple subset proposals) the per-tuple set
  could exceed 1024 entries per data root. The weakened form
  ignores STRICTLY MORE messages than the spec under disjoint-
  subset proposals; this is safe for forwarding (worse-case:
  we drop an honest aggregate that the spec would have
  forwarded; the originator's peers will still see it via the
  full-form check elsewhere). Re-evaluate at M4d devnet
  acceptance if peers complain about dropped aggregates.
  Recorded under `D-seen-cache-shape`.
- OQ2: Should `validate_attestation` reject when the
  `head_state_at_slot` clone is too far behind wall clock
  (e.g. during sync)? **Recommended default: Ignore (not
  Reject).** Rationale: a slow-syncing node Ignore'ing is
  invisible to peers and bandwidth-cheap; Reject'ing would
  banscore peers for our own slowness. The Ignore path is
  already covered by R8 / Task 2.4 step 1's `None` arm. No
  separate ADR needed.
- OQ3: Does the verdict-string round-trip test
  (`gossip_verdict_strings.rs`, Task 4.2) belong in `tests/`
  or as a `mod tests` in `host_impl.rs`? **Recommended
  default: `tests/`.** Rationale: integration tests have
  access to `include_str!` of the source file from a clean
  build dir; a `mod tests` would need `cfg(feature = ...)`
  gymnastics. Integration test cost is one extra binary at
  `make test` time, negligible.
- OQ4: Should the `is_aggregator` predicate be moved to
  `pharos-types` instead of `pharos-stf`? **Recommended
  default: keep in `pharos-stf/src/phase0/predicates.rs`.**
  Rationale: `is_aggregator` depends on `pharos_utils::hash`
  + `TARGET_AGGREGATORS_PER_COMMITTEE` + `BLSSignature` —
  the `pharos-stf/phase0/predicates.rs` module already
  imports all three. Moving it to `pharos-types` would
  require `pharos-types` to depend on `pharos-utils`, which
  would invert the current dep graph (`pharos-utils` is
  meant to be a leaf). Recorded under
  `D-is-aggregator-location`.

## Revision notes
- _none yet — first draft_
