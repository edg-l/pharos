# Pharos Decisions Log

Permanent record of architectural and policy decisions taken during Pharos
development. Each entry is ADR-style: short statement, why, where the
decision is enforced. Plan files (`docs/m*-plan.md`) are gitignored agent
artifacts; this file is the canonical home for decisions once a milestone
ships.

For project-wide locked decisions, see `docs/roadmap.md` (workspace shape,
runtime, deps philosophy). The Dx / Qx entries below are M1-scoped.

## M1 — Phase 0 STF + fork choice

### D1 — State mutation model: owned-mutate-return

STF functions take `state: E::BeaconState` by value and return
`Result<E::BeaconState, StateTransitionError>`. Internally they mutate
the owned state in place; for persistent `SszList` / `SszVector` fields,
helpers rebind via `field = field.with_set(i, new)?`.

Why: maps cleanly to the spec's mutating prose; one move at the boundary,
zero clones in the hot loop; persistent collections give structural
sharing for the list fields. A pure-return-fresh-state model would force
a deep clone on entry; an in-place `&mut BeaconState` model would
prevent callers from holding pre-state snapshots that the fork-choice
store needs.

Enforced in: `crates/pharos-stf/src/lib.rs::state_transition`,
`process_slots`, every `process_*` function in `phase0/`.

### D2 — Error strategy: single `StateTransitionError` enum in `pharos-stf`

One `thiserror` enum with structured variants
(`InvalidAttestation { reason: AttestationInvalidReason }` etc.). Per-op
sub-enums for fine-grained reasons. `pharos-ssz` and
`pharos-utils::BlsError` flow in via `#[from]`. Fork-choice gets its own
`ForkChoiceError` in `pharos-fork-choice` (different domain: store
invariants vs. STF rules).

Why: spec test fixtures only assert "this op rejects" vs. "accepts"; one
top-level enum keeps callers (and the conformance harness) on a single
`Result`. Sub-enums preserve diagnostic detail without polluting the
top-level surface.

Enforced in: `crates/pharos-stf/src/error.rs`,
`crates/pharos-fork-choice/src/error.rs`.

### D3 — Conformance harness: per-category dispatcher module + shared walker

`pharos-conformance` has one module per category (`operations.rs`,
`epoch_processing.rs`, `sanity.rs`, `finality.rs`, `random.rs`,
`rewards.rs`, `genesis.rs`, `shuffling.rs`, `bls.rs`, `fork_choice.rs`,
`ssz_static.rs`, `ssz_generic.rs`). Each exposes `run_*_preset` /
`run_*_mainnet` / `run_*_minimal`. Shared helpers in
`fixture_walker.rs` factor out the `walk_category` + `load_pre_post`
patterns.

Why: dispatchers are too heterogeneous (operations: pre/post + op;
epoch_processing: keyed by directory name; fork_choice: step tape) to
fold into one generic dispatcher, but the walking is identical. A
common walker keeps each module under ~300 LOC.

Enforced in: `crates/pharos-conformance/src/fixture_walker.rs`, each
per-category module.

### D4 — BLS verify policy: eager per-op verify in M1; batched at block boundary in M11

M1: each op that the spec verifies calls `bls::verify` /
`fast_aggregate_verify` eagerly. `process_block_header` does not check
the block sig; the outer `state_transition` does (per spec).

`state_transition` takes `validate_result: bool` (Q3): when `false`,
block-sig and final state-root checks are skipped, and the
`verify_signatures: bool` flag threaded into `process_block` / every
per-op processor disables per-op signature checks too. The flag is
wired through `bls_setting` in the conformance harness (S1).

Why: spec-correct, simplest, matches fixture expectations exactly.
Batched verify pays off only at gossip ingestion; without networking it
adds machinery for zero benefit and risks losing per-op error
localisation. The `SignatureSet` / `verify_signature_sets` API in
`pharos-utils::bls` is already in place, so the M11 swap is mechanical.

Enforced in: `crates/pharos-stf/src/lib.rs::state_transition`,
`process_block`, `process_randao`, `is_valid_indexed_attestation`, each
`process_<op>`.

### D5 — rayon strategy: global pool; parallel boundary inside epoch sub-routines only

`pharos-stf` does not own a pool. `process_rewards_and_penalties` and
`process_effective_balance_updates` use `rayon::iter` over the
validator-index range to compute per-validator deltas, then fold
sequentially into the balances list (since `SszList::with_set` is
single-writer CoW). STF API stays sync. Other epoch sub-routines
(`process_justification_and_finalization`, `process_registry_updates`,
`process_slashings`, all the `process_*_reset` routines,
`process_historical_roots_update`,
`process_participation_record_updates`) are not parallelised — they
have small fan-out or sequential dependencies; the spec wording forbids
reordering for `process_registry_updates` (churn-limit ordering
matters).

Why: avoids two thread pools when the node binary eventually adds its
own work; keeps `pharos-stf` dependency-light.

Enforced in:
`crates/pharos-stf/src/phase0/epoch/rewards_and_penalties.rs`,
`crates/pharos-stf/src/phase0/epoch/effective_balance_updates.rs`.

### D6 — Fork representation today: implicit per-preset monomorphisation via `EthSpec` associated types

`BeaconState<E>` as an enum-of-forks does NOT exist in M1.
`pharos-stf::state_transition` is
`pub fn state_transition<E: EthSpec>(state: E::BeaconState, signed_block: &E::SignedBeaconBlock, validate_result: bool) -> Result<E::BeaconState, StateTransitionError>`
and internally calls `phase0::state_transition::<E>(...)` directly. No
`match (&state, &block.message)` arm, no `BeaconState::Phase0(_)`
constructor.

M3 introduces an enum-of-forks wrapper and outer dispatch in
`state_transition`. The refactor is mechanical because every M1 call
site is already generic over `E`.

Why: with one fork, pretending to dispatch adds indirection for zero
benefit, and the enum cannot even be written today without first
introducing the second fork's container types.

The roadmap's "fork representation: enum-of-forks with shared trait"
applies from M3 onward; M1 ships the trait shape ahead of the variants.

### D7 — `EthSpec` carries container associated types

`EthSpec` declares
`type BeaconState`, `type BeaconBlock`, `type SignedBeaconBlock`,
`type BeaconBlockBody`, each bound by
`Encode + Decode + TreeHash + Clone + Debug + PartialEq + Eq + Default + Send + Sync + 'static`
plus the corresponding view trait (`BeaconBlockView<E = Self>` etc.).
Preset impls bind these to the per-preset aliases in `phase0::*`.

Every STF / fork-choice function signature reads `<E: EthSpec>` and
uses `E::BeaconState` etc. `Store<E>` follows the same pattern.

Why: with associated types on the spec trait, downstream call sites do
not need verbose `where` clauses to plumb the concrete container types,
and the M3 enum-of-forks migration is a single point of change.

Enforced in: `crates/pharos-types/src/eth_spec.rs`,
`crates/pharos-fork-choice/src/store.rs`, every STF entry point.

### D8 — Block-body field accessors via trait, not enum dispatch

`E::BeaconBlock`, `E::SignedBeaconBlock`, `E::BeaconBlockBody` are
opaque associated types. STF code accesses fields through the view
traits `BeaconBlockView`, `SignedBeaconBlockView`, `BeaconBlockBodyView`
in `crates/pharos-types/src/views.rs`. Const-generic parameters on
returned slices (`Attestation`, `AttesterSlashing`, `Deposit`) hang off
**associated types** on `BeaconBlockBodyView`, sidestepping the
unstable `generic_const_exprs` feature.

Why: stable Rust 1.85 cannot express
`fn attestations(&self) -> &[Attestation<{ <Self::E as EthSpec>::MAX_VALIDATORS_PER_COMMITTEE }>]`
directly. The associated-type indirection is the only stable form.

Enforced in: `crates/pharos-types/src/views.rs`,
`crates/pharos-stf/src/phase0/{block,operations,randao,eth1_data}.rs`.

## M1 — Resolved open questions

### Q1 — `phase0/fork_choice` row strategy

**Resolution**: the `phase0/fork_choice/{mainnet,minimal}` rows point at
`tests/{preset}/altair/fork_choice/`. Phase-0 fork-choice fixtures do
not exist upstream (consensus-spec-tests ships fork-choice cases
starting from altair).

**Footnote text** (must match verbatim across `docs/conformance.md` and
this entry):

> Phase-0 fork-choice fixtures do not exist upstream; runner exercises
> the M1 store against altair fork-choice fixtures, applying the
> skip-unknown-step-keys policy. Decision recorded in
> `docs/decisions.md` (Q1).

**Skip-unknown-step-keys policy**:

- Unknown top-level step variant (`on_merge_block`, `pow_block`,
  `on_payload_info`, `on_execution_payload_envelope`,
  `on_payload_attestation_message`, …) → the case is counted as
  **skip**, not fail.
- Unknown key inside a `checks` block is silently ignored. Examples:
  `viable_for_head_roots_and_weights`,
  `should_override_forkchoice_update`, `head_payload_status`,
  `payload_timeliness_vote`, `payload_data_availability_vote`,
  `genesis_time`.
- Anchor-state SSZ decode failure counts the case as **skip**. In M1
  the runner runs over `MainnetEthSpec` / `MinimalEthSpec` (phase-0),
  so every altair anchor state will fail to decode and every case will
  skip. The row goes live with `pass = 0`, `fail = 0`, `skip = N`.
  Altair types land in M3, at which point this runner produces real
  pass/fail counts without any code change.

Enforced in: `crates/pharos-conformance/src/fork_choice.rs`,
`crates/pharos-conformance/src/lib.rs` (per-preset row wiring + Q1
footnote registration).

### Q2 — BLS conformance row scope

**Resolution**: the BLS conformance row is named `general/bls`. Only the
two sub-categories that exist in v1.6.1 are walked:
`eth_aggregate_pubkeys` and `eth_fast_aggregate_verify`. The other six
(`sign`, `verify`, `aggregate`, `fast_aggregate_verify`,
`aggregate_verify`, `batch_verify`) have no upstream fixtures in
`tests/general/altair/bls/` for v1.6.1; this is the **R-bls coverage
gap** documented in `crates/pharos-conformance/src/bls.rs`.

Coverage will be revisited when upstream restores fixtures or when M3
brings altair-specific BLS suites.

Enforced in: `crates/pharos-conformance/src/bls.rs`,
`crates/pharos-conformance/src/lib.rs` (`general/bls` row).

### Q3 — `validate_result` parameter on `state_transition`

**Resolution**: `state_transition` takes `validate_result: bool` from
day one. When `false`, both the block signature check and the final
state-root check are skipped (BLS verification is also skipped via the
`verify_signatures` flag threaded through `process_block`,
`process_randao`, every per-op processor, and
`is_valid_indexed_attestation`).

The conformance harness maps `bls_setting` (from `meta.yaml`) to
`validate_result`: `2` → `false`; otherwise `true`.

Enforced in: `crates/pharos-stf/src/lib.rs::state_transition`,
`crates/pharos-conformance/src/sanity.rs`,
`crates/pharos-conformance/src/finality.rs`,
`crates/pharos-conformance/src/random.rs`,
`crates/pharos-conformance/src/operations.rs`.

### Q4 — Per-preset rows for every new category

**Resolution**: every new conformance category emits a per-preset row
pair (`mainnet` + `minimal`), matching `ssz_static`. Exceptions:

- `phase0/genesis` ships only the `minimal` row — no mainnet genesis
  fixtures exist in v1.6.1.
- `general/bls` and `phase0/ssz_generic` are preset-independent
  (single `-` row).

Enforced in: `crates/pharos-conformance/src/lib.rs` (the
`all_categories()` table and the per-category dispatch blocks).

## M2 — Networking layer (pharos-network Phase 1)

### Q-quic-enr — ENR QUIC port keys

**Status**: Accepted. **Date**: 2026-05-21.

Two custom ENR keys are used to advertise QUIC transport endpoints:
`"quic"` (IPv4 QUIC UDP port, u16) and `"quic6"` (IPv6 QUIC UDP port,
u16). Values are stored via `Enr::builder().add_value(key, &port)`, which
RLP-encodes the u16; `get_decodable::<u16>(key)` round-trips correctly.

Source/precedent: the de facto Rust CL ecosystem convention (Lighthouse and
other CL clients use these exact key names). The consensus-specs
`p2p-interface.md` is silent on QUIC ENR keys for Phase 0; the key names
follow established inter-client practice.

Enforced in: `crates/pharos-network/src/discovery/enr.rs`
(`build_local_enr`, `read_quic_port`, `read_quic6_port`).

<!-- M2 Phase 9.1 fills D-libp2p, D-discv5, D-runtime-ownership,
     D-trait-boundaries (stub below), D-fork-digest-source, D-channels,
     D-test-runner, D-peer-scoring. -->

### D-trait-boundaries — Host<E> owns inbound RPC dispatch

**Status**: Accepted. **Date**: 2026-05-22.

The `Host<E: EthSpec>` trait, composed of `ForkContext`, `BlockProvider`,
and `GossipValidator`, is held by the network task and dispatched
synchronously when an inbound req-resp message arrives. The earlier
Task 7.1 sketch included `NetworkEvent::RpcRequest { peer, request,
response: oneshot::Sender<RpcResponse<E>> }` which would have forwarded
inbound RPC out to the `NetworkHandle` consumer; this variant was
removed during Phase 7.

Rationale: throughput is equivalent (channel hop is ~200-400 ns, negligible
against ~10-100 ms storage-bound RPC like `BlocksByRange`). Tail latency is
strictly better under the Host pattern because the network task is not
coupled to a consumer queue — a slow consumer cannot stall inbound RPC.
The Host pattern also matches Phase 5's existing `handle_request` and
Phase 8 tests (which preload `TestHost::BlockProvider`).

Enforced in: `crates/pharos-network/src/network/mod.rs`
(`on_request_response_event` → `handle_request` → `Host` method calls).
`NetworkEvent` enum has no `RpcRequest` variant.

### D-network-event-surface — what NetworkEvent exposes (and what it doesn't)

**Status**: Accepted. **Date**: 2026-05-22.

The M2 `NetworkEvent` enum surfaces only the events a beacon-node
consumer needs for the M2-acceptance set: `PeerConnected`,
`PeerDisconnected`, `GossipMessage`, `NewListenAddr`, `LocalEnr`,
`Shutdown`. The following libp2p sub-protocol events are received but
not yet surfaced on the public API; each is logged at `tracing::debug!`
and routed to per-milestone follow-ups in `docs/roadmap.md`:

- M3 (Altair) follow-ups:
  - `gossipsub::Event::Subscribed`/`Unsubscribed` → `PeerSubscribed`/`PeerUnsubscribed`
  - `identify::Event::Received` → `PeerIdentified`
  - `SwarmEvent::OutgoingConnectionError` → `DialFailed`
  - `SwarmEvent::ExternalAddrConfirmed` → ENR auto-update path.
- M11 (productionization) follow-ups:
  - `gossipsub::Event::SlowPeer`, `GossipsubNotSupported` (real peer scoring).
  - `ping::Event` per-peer RTT (dead-peer detection).
  - Remaining `SwarmEvent` variants (`IncomingConnectionError`,
    `NewExternalAddrOfPeer`, `ExpiredListenAddr`, `ListenerError`,
    `ListenerClosed`).

Rationale: M2 acceptance is wire-level correctness, not operational
observability. Adding event variants at M2 cost only API surface; using
them productively requires the peer-scoring substrate that lives in M11
and the cross-fork ENR/topic logic that lives in M3. Locking the
follow-ups into the roadmap at M2-close prevents drift.

### M-networking-spec-source — consensus-specs has no networking suite

**Status**: Methodology note. **Date**: 2026-05-22.

`consensus-specs/tests/formats/` ships fixtures for SSZ, STF, fork
choice, light client, KZG/BLS, etc. — but NOT for networking, gossipsub,
or req-resp. This is industry-wide (Lighthouse, Prysm, Lodestar, Teku,
Nimbus all hand-roll their networking tests). Pharos spec rigor for the
network crate is therefore enforced via:

1. **Inline citations** from code to spec lines in
   `specs/phase0/p2p-interface.md` (varint `:1264-1267`,
   IrrelevantNetwork `:1394`, gossipsub `StrictNoSign` `:482-484`, etc.).
2. **Hand-written integration tests** in `crates/pharos-network/tests/`
   (TCP+QUIC connect, discovery, gossip with reject topology, RPC
   round-trips, fork-digest goodbye).
3. **Phase 9 Task 9.7** spec-vs-code line audit at every networking
   milestone (M2 close, M3 close).
4. **Cross-client interop tests** against Lighthouse + ethrex planned
   for M4 (before first merged sync), to be added in `crates/pharos-network/tests/interop/`.

`#[serial_test]` is used to serialize the gossip integration tests
within their binary (Phase 8 wrap-up amendment) because parallel libtest
execution causes gossipsub mesh-formation timing to race under CPU
contention; this is a test harness concern, not a production
correctness issue.
