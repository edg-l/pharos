# M6-Capella Implementation Plan

**Status**: planned (feature-planner → plan-reviewer GO-WITH-FIXES; all 4 critical
fixes integrated below). Milestone label **M6-Capella** — do NOT reuse "M5"
(the session ledger already used M5 for the M5-follow gossip-following milestone).

Capella is a CL-only fork in pharos terms: no new cryptographic primitive (unlike
Deneb/KZG). Work = STF + containers + Engine API V2 + a fork-digest gossip
migration mirroring the M4d Bellatrix bring-up, + the Capella `LightClientHeader`.
Mirrors the in-house Bellatrix implementation exactly; no `superstruct`, no rejected
deps. EL-side withdrawals are EIP-4895; CL side is `~/dev/consensus-specs/specs/capella/*`.

## Spec sources (read these — not training memory; prefer eipmcp for EIP/spec Qs)
- `~/dev/consensus-specs/specs/capella/beacon-chain.md` (containers, STF)
- `~/dev/consensus-specs/specs/capella/fork.md` (`upgrade_to_capella`)
- `~/dev/consensus-specs/specs/capella/p2p-interface.md` (gossip topic + validation)
- `~/dev/consensus-specs/specs/capella/light-client/*` (LC header)
- `~/dev/consensus-specs/specs/phase0/p2p-interface.md` (3 folded validators)
- `~/dev/execution-apis/src/engine/shanghai.md` (Engine V2 wire types)

## Preset constants (OQ3 RESOLVED — values differ per preset; MUST be `EthSpec` assoc consts)

| Constant | Mainnet | Minimal |
| --- | --- | --- |
| `MAX_BLS_TO_EXECUTION_CHANGES` | 16 | 16 |
| `MAX_WITHDRAWALS_PER_PAYLOAD` | 16 | 4 |
| `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP` | 16384 | 16 |
| `CAPELLA_FORK_VERSION` | `0x03000000` | `0x03000001` |

(Confirm `CAPELLA_FORK_VERSION` minimal value against `presets`/`configs`; mainnet is
`0x03000000`. Do NOT hardcode mainnet values into shared code.)

## Spec rule counts (verified by plan-reviewer against the spec text)
- `validate_bls_to_execution_change`: **2 IGNORE + 4 REJECT** (+ mark-seen on accept).
- `validate_voluntary_exit`: **1 IGNORE + 6 REJECT**.
- `validate_proposer_slashing`: **1 IGNORE + 6 REJECT**.
- `validate_attester_slashing`: **1 IGNORE + 6 REJECT**.
- Total = 27 rule paths across 4 validators → 27 unit-test paths required (Phase 6).

## process_block step order (verified — PER-STEP, NOT a delegate to bellatrix)
`process_block_header` → `process_withdrawals(state, payload)` →
`process_execution_payload` → `process_randao` → `process_eth1_data` →
`process_operations` (now incl. `process_bls_to_execution_change`) →
`process_sync_aggregate`. (`is_execution_enabled`/`is_merge_transition_complete`
guards removed in Capella.)

## Hard constraints
- Per-step `process_block` (order above). `process_withdrawals` BEFORE
  `process_execution_payload`, both before `process_randao`. The
  `assert payload.withdrawals == expected` is a consensus check →
  `StateTransitionError::WithdrawalsMismatch`.
- Enum-of-forks: new `Capella` variants in `BeaconState`/`BeaconBlock`/
  `BeaconBlockBody`; `CachedRoot` wired into the new state variant; `Tree`-backend
  field list re-checked (`historical_summaries` stays `Naive` — appended rarely).
  NO `superstruct`.
- Own everything in-house (no `ethereum_ssz`/`tree_hash`/`milhouse`/`alloy*`/
  `lighthouse_network`/`superstruct`).
- `historical_roots` FROZEN (never appended); `historical_summaries` is the
  replacement (`process_historical_summaries_update` replaces
  `process_historical_roots_update` in `process_epoch`).
- Engine V2: `engine_newPayloadV2` + `engine_forkchoiceUpdatedV2` required for
  import. `engine_getPayloadV2` is block-production-only → wire type + version arm
  added, live driver wiring DEFERRED to M8 (follow-only). [`D-capella-getpayload-deferral`]
- Independence Guarantee: implementer must NOT read other CL clients' source.
- `bls_to_execution_change` uses a fork-AGNOSTIC signing domain:
  `compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, GENESIS_FORK_VERSION, genesis_validators_root)`.

## Reviewer fixes integrated (do not re-litigate)
- **B1**: Phase 6 covers `Fork::Capella` (network `types.rs`), `rpc/codec.rs`
  context-bytes arms (incl. the 4 LC req-resp methods), `host_impl.rs::fork_from_context`,
  and the `block_ingestion.rs` gossip decode arm.
- **B2**: Phase 1 adds `ForkVariant::Capella` to `crates/pharos-types/src/views.rs`.
- **B3**: Phase 1 adds a STUB `main.rs` `ForkSchedule` literal update (new fields with
  `FAR_FUTURE_EPOCH` / `CAPELLA_FORK_VERSION` placeholders) so `cargo check` passes at the
  Phase 1 checkpoint; Phase 7 swaps in real config values.
- **B4**: LC conformance is NOT in Phase 3; it is the final task of Phase 5.
- Phase 1 note: the network `Fork` enum is extended in Phase 6, NOT Phase 1. Phase 1
  touches only `ForkVariant` (types crate).
- Phase 2 task 2.9 split into 2.9a/b/c.
- Phase 4: V2 conversion is a `From<capella::ExecutionPayload> for ExecutionPayloadV2`
  in `pharos-engine/src/types.rs`; dispatch in `engine_driver.rs` is fork-conditional
  on the `BeaconState::Capella` / capella-block variant.
- Phases 3/4/5 are independent but run sequentially (one implementer each), order 3→4→5.

---

## Phase 0 — Decision freeze (this doc + ADR stubs)
- 0.1: Create this `docs/m6-capella-plan.md`. ✅
- 0.2: Add `## M6-Capella decisions` section to `docs/decisions.md` with 10 PROPOSED ADR
  stubs (finalized ACCEPTED in Phase 8): `D-capella-state-shape`,
  `D-withdrawals-stf-shape`, `D-bls-to-exec-change-domain`, `D-engine-v2-dispatch`,
  `D-capella-getpayload-deferral`, `D-historical-summaries-field`,
  `D-capella-fork-digest`, `D-capella-lc-header`, `D-folded-phase0-validators`,
  `D-bls-to-exec-seen-cache`.
- Commit: `docs(m6): freeze M6-Capella decisions + plan`

## Phase 1 — Capella types
Depends: none. Touches `pharos-types` only (network `Fork` enum is Phase 6).
- 1.1 `crates/pharos-types/src/capella/execution_payload.rs`: `Withdrawal`,
  `ExecutionPayload<…>` (+`withdrawals`), `ExecutionPayloadHeader<…>` (+`withdrawals_root`).
- 1.2 `crates/pharos-types/src/capella/operations.rs`: `BLSToExecutionChange`,
  `SignedBLSToExecutionChange`, `HistoricalSummary`.
- 1.3 `crates/pharos-types/src/capella/body.rs`: `BeaconBlockBody<…>`
  (+`bls_to_execution_changes`) + `BeaconBlockBodyView`.
- 1.4 `crates/pharos-types/src/capella/block.rs`: `BeaconBlock`/`SignedBeaconBlock` + views.
- 1.5 `crates/pharos-types/src/capella/state.rs`: `BeaconState<…>` (+`next_withdrawal_index`,
  +`next_withdrawal_validator_index`, +`historical_summaries`, `cached_root: CachedRoot`
  `#[ssz(skip)]`); hand `Decode`+`Default`+`BeaconStateView`+`into_tree_backend` (same 5
  hot fields as bellatrix — `block_roots`, `state_roots`, `historical_roots`, `validators`,
  `randao_mixes`; the phase0-only attestation lists do NOT exist in bellatrix/capella;
  `historical_summaries` stays Naive); preset aliases.
- 1.6 `crates/pharos-types/src/capella/mod.rs` + `pub mod capella;` in `lib.rs`.
- 1.7 `crates/pharos-types/src/state.rs`: add `Capella` variant to `BeaconState`,
  `BeaconBlock`, `BeaconBlockBody` enums; extend EVERY match arm.
- 1.8 `crates/pharos-types/src/views.rs`: add `ForkVariant::Capella` (**B2**); extend
  exhaustive matches.
- 1.9 `crates/pharos-types/src/eth_spec.rs`: Capella const block (per-preset per the
  table above) + assoc types (`CapellaBeaconState`/`…Block`/`…SignedBeaconBlock`/
  `…BeaconBlockBody`/`…ExecutionPayload`/`…ExecutionPayloadHeader`) + unwrap/into helpers;
  extend `get_execution_block_hash`/`…parent_hash`/`…payload`/`is_merge_transition_block`.
- 1.10 `crates/pharos-types/src/fork.rs`: `capella_fork_version`/`capella_fork_epoch`
  fields; `fork_table()` → length 3; `DOMAIN_BLS_TO_EXECUTION_CHANGE` const (locate domain
  consts via `rg DOMAIN_BEACON_PROPOSER`); tests.
- 1.11 `crates/pharos-types/src/config.rs` (`RuntimeConfig`) + YAML loader: add
  `capella_fork_version`/`capella_fork_epoch` (YAML keys `CAPELLA_FORK_VERSION`/
  `CAPELLA_FORK_EPOCH`).
- 1.12 **(B3 stub)** `crates/pharos-node/src/main.rs`: extend the `ForkSchedule` struct
  literal with the two new fields using placeholder defaults
  (`capella_fork_epoch: FAR_FUTURE_EPOCH`-equiv, `capella_fork_version` from cfg/const) so
  the workspace compiles. Real config wiring is Phase 7.
- Checkpoint: `cargo check --workspace && cargo test -p pharos-types`.
- Commit: `feat(m6): capella containers, EthSpec consts, fork enums + schedule`

## Phase 2 — Capella STF
Depends: Phase 1.
- 2.1 `crates/pharos-stf/src/capella/helpers.rs`: predicates
  (`has_eth1_withdrawal_credential`, `is_fully_withdrawable_validator`,
  `is_partially_withdrawable_validator`) + state/block projections to bellatrix/altair.
- 2.2 `crates/pharos-stf/src/capella/operations/withdrawals.rs`:
  `get_balance_after_withdrawals`, `get_validators_sweep_withdrawals` (note
  `assert len(prior) < limit`), `get_expected_withdrawals`, `apply_withdrawals`,
  `update_next_withdrawal_index`, `update_next_withdrawal_validator_index`,
  `process_withdrawals` (equality check → `WithdrawalsMismatch`).
- 2.3 `crates/pharos-stf/src/capella/operations/bls_to_execution_change.rs`:
  `process_bls_to_execution_change` (fork-agnostic domain, credential flip).
- 2.4 `crates/pharos-stf/src/capella/operations/mod.rs`: `process_operations_capella`
  (+`bls_to_execution_changes` step).
- 2.5 `crates/pharos-stf/src/capella/operations/execution_payload.rs`: modified
  `process_execution_payload` (caches `withdrawals_root`, drops merge-transition check).
- 2.6 `crates/pharos-stf/src/capella/block.rs`: per-step `process_block` (exact order),
  body_root patch, no `is_execution_enabled` guard.
- 2.7 `crates/pharos-stf/src/capella/epoch/mod.rs`: `process_historical_summaries_update`
  (replaces roots update); Capella `process_epoch`.
- 2.8 `crates/pharos-stf/src/capella/upgrade.rs`: `upgrade_to_capella` (bellatrix→capella).
- 2.9a `crates/pharos-stf/src/error.rs`: add `WithdrawalsMismatch`.
- 2.9b `crates/pharos-stf/src/lib.rs`: `ForkVariant::Capella` arm in `state_transition`
  and `process_slots_fork`; `CapellaProcessSlotsDispatch` trait (mirror Bellatrix);
  live fork-upgrade trigger in `process_slots_fork` for ALL forks (phase0→altair→
  bellatrix→capella). Mechanism: `ForkEpochs` struct carries per-network fork epoch
  numbers (sourced from `Store.runtime_cfg` on the live path, `ForkEpochs::never()`
  for single-fork test/bench helpers). `Phase0UpgradeDispatch<E>` /
  `AltairUpgradeDispatch<E>` / `BellatrixUpgradeDispatch<E>` dispatch traits (blanket
  impls on concrete inner state types) delegate to the existing concrete `upgrade_to_*`
  free functions. The advance-then-upgrade loop in `process_slots_fork` advances the
  current fork to the boundary slot first (so `process_epoch` for the last pre-fork
  epoch runs), then applies the upgrade, then continues. A multi-fork jump (e.g.
  phase0 state advanced past altair + bellatrix + capella in one call) upgrades
  through each fork in order. Fork epochs stored in `Store` (`altair_fork_epoch`,
  `bellatrix_fork_epoch`, `capella_fork_epoch`, `runtime_cfg`) mirror the terminal-
  config precedent; `get_forkchoice_store` defaults all to `u64::MAX` (conformance
  fork_choice tests stay byte-identical); `get_forkchoice_store_with_config` sets
  real values. ADR: `D-live-fork-upgrade-trigger` in `docs/decisions.md`.
- 2.9c `crates/pharos-stf/src/capella/{mod.rs,state_transition.rs}` + `pub mod capella;`.
- Checkpoint: `cargo check -p pharos-stf && cargo test -p pharos-stf`.
- Commit: `feat(m6): capella STF — withdrawals, bls_to_exec_change, historical_summaries, upgrade`

## Phase 3 — Capella conformance (non-LC)
Depends: Phase 2. (LC conformance is Phase 5, per **B4**.)
- 3.1 `ssz_static.rs`: `run_ssz_static_capella_{mainnet,minimal}` (all containers).
- 3.2 `operations.rs`: `run_operations_capella_*` (incl. `withdrawals` +
  `bls_to_execution_change` handlers).
- 3.3 `{epoch_processing,sanity,finality,random,rewards}.rs`: `run_*_capella_*`
  (epoch_processing covers `historical_summaries_update`).
- 3.4 `transition.rs`: `run_transition_capella_*` (bellatrix→capella upgrade).
- 3.5 `fork_choice.rs`: `run_fork_choice_capella_*`.
- 3.6 `lib.rs`: add all `capella/<category>/{mainnet,minimal}` ladder entries (LC row added
  in Phase 5).
- Checkpoint: `cargo run -p pharos-conformance --release -- --filter capella` (background,
  capture) — every non-LC capella category `fail=0` on both presets.
- Commit: `test(m6): capella conformance categories green on both presets`

## Phase 4 — Engine API V2
Depends: Phase 1. Independent of 3/5 (run after 3).
- 4.1 `crates/pharos-engine/src/types.rs`: `WithdrawalV1`, `ExecutionPayloadV2`,
  `PayloadAttributesV2`; `From<capella::ExecutionPayload> for ExecutionPayloadV2`. Verify
  casing vs `shanghai.md`.
- 4.2 `crates/pharos-engine/src/client.rs`: `V2` arms on the three version enums; V2 methods;
  add V2 methods to advertised `exchange_capabilities` set.
- 4.3 `crates/pharos-engine/src/handle.rs`: extend `EngineRequest`/`EngineHandle` for V2.
- 4.4 `crates/pharos-node/src/engine_driver.rs`: `to_execution_payload_v2`; fork-conditional
  dispatch (Capella → V2) in `host_impl.rs` + block-ingestion.
- 4.5 `crates/pharos-conformance/src/engine.rs` + YAML runner: Capella V2 examples.
- Checkpoint: `cargo check -p pharos-engine -p pharos-node && cargo test -p pharos-engine`.
- Commit: `feat(m6): Engine API V2 (newPayloadV2 + forkchoiceUpdatedV2) for capella import`

## Phase 5 — Capella LightClientHeader + LC conformance
Depends: Phase 1 (types). Unblocks the deferred LC conformance.
- 5.1 `crates/pharos-types/src/capella/light_client.rs`: `LightClientHeader { beacon,
  execution: capella::ExecutionPayloadHeader, execution_branch: SszVector<Bytes32, 4> }`
  (`floorlog2(EXECUTION_PAYLOAD_GINDEX=25)=4`) + Capella LC bootstrap/update/finality/
  optimistic + views.
- 5.2 `crates/pharos-types/src/eth_spec.rs`: Capella LC assoc types.
- 5.3 `crates/pharos-stf/src/capella/light_client.rs`: `get_lc_execution_root` (epoch-gated),
  `is_valid_light_client_header` (merkle branch depth 4, index `get_subtree_index(25)`).
- 5.4 `crates/pharos-stf/src/altair/light_client_dispatch.rs`: build the Capella header for
  capella-or-later blocks (use STF-verified values per M4c `D-bellatrix-lc-header-uses-state-root`).
- 5.5 `crates/pharos-node/src/host_impl.rs`: LC finality/optimistic validators handle the
  Capella header shape. **PARTIALLY DEFERRED to Phase 6**: Phase 5 delivered the capella LC
  types/STF/storage/snapshot-writing + documented the migration point, but the validators
  remain `E::AltairLightClient*`-typed because capella LC gossip cannot be routed to the host
  until Phase 6 wires `Fork::Capella` + the capella fork-digest + the LC req-resp/gossip
  topics. The capella-typing of these validators (and the capella LC gossip *publish*) is a
  Phase 6 task (6.12). This is a phase-boundary move, not a skip — see Phase 6.
- 5.6 **(moved from 3.6)** `crates/pharos-conformance/src/light_client.rs` +
  `lib.rs` ladder: `run_light_client_capella_*`. Also un-defers the capella LC ssz_static
  cases (Phase 3 task 3.1 skipped them); only `PowBlock` remains skipped.
- Checkpoint: `cargo check --workspace`; `--filter capella/light_client` `fail=0` both presets.
- Commit: `feat(m6): capella LightClientHeader (execution payload + branch) + LC conformance`

## Phase 6 — Networking: fork-digest migration, bls_to_execution_change topic, 4 validators
Depends: Phases 1 + 2.
- 6.1 `crates/pharos-network/src/types.rs`: add `Fork::Capella` (**B1**).
- 6.2 `crates/pharos-network/src/rpc/codec.rs`: `Fork::Capella` arms for BlocksByRange/Root
  encode+decode AND the 4 LC req-resp context-bytes methods (**B1**).
- 6.3 `crates/pharos-node/src/host_impl.rs::fork_from_context`: recognise the Capella
  digest (**B1**).
- 6.4 `crates/pharos-node/src/block_ingestion.rs`: `Fork::Capella` gossip decode arm (**B1**).
- 6.5 `crates/pharos-network/src/topics.rs`: `GossipTopicKind::BlsToExecutionChange`
  (`bls_to_execution_change`) + parse/format/`TopicHash` round-trip.
- 6.6 `crates/pharos-node/src/fork_migration.rs`: `capella_gossip_topics` (= bellatrix +
  BlsToExecutionChange); select for capella version; doc → "phase0→altair→bellatrix→capella".
- 6.7 `crates/pharos-network/src/host.rs`: add `validate_bls_to_execution_change` to
  `GossipValidator<E>` + `Arc<T>` forwarder + noop/test host default.
- 6.8 `crates/pharos-network/src/network/mod.rs`: dispatch the new topic to the validator in
  `spawn_blocking` (M4e `D-no-tokio-from-validator` / `D-bls-on-hot-path`).
- 6.9 `crates/pharos-node/src/host_impl.rs`: implement `validate_bls_to_execution_change`
  (2 IGNORE + 4 REJECT, mark-seen on accept) + `bls_to_execution_change_indices` seen-cache.
- 6.10 `crates/pharos-node/src/host_impl.rs` (~1231/1236/1241): replace the 3 Accept stubs
  with full `validate_voluntary_exit`/`validate_proposer_slashing`/
  `validate_attester_slashing` (1 IGNORE + 6 REJECT each) + seen-cache extensions.
- 6.11 Tests: 27 rule-path unit tests (6 + 7×3) + verdict-string round-trip extension +
  `crates/pharos-node/tests/bls_to_exec_gossip_e2e.rs`.
- 6.12 **(carry-in from Phase 5 task 5.5)** Capella-type the host LC validators
  (`validate_light_client_finality_update` / `validate_light_client_optimistic_update` in
  `crates/pharos-node/src/host_impl.rs`) to accept `E::CapellaLightClient*` updates, and wire
  the capella LC gossip *publish* (block_ingestion already writes capella LC snapshots — now
  publish them on the capella LC topics with the capella fork-digest). Add the capella LC
  req-resp/gossip topic routing. This completes the LC gossip path that Phase 5 could not
  (capella LC updates cannot be routed until `Fork::Capella` + the digest land in this phase).
- 6.13 **(carry-in from Phase 3)** Tighten `EthSpec::BellatrixSignedBeaconBlock`'s bound to
  `SignedBeaconBlockView<Message = Self::BellatrixBeaconBlock>` for consistency with the
  capella assoc type (`eth_spec.rs` — non-functional, just removes a documentation trap).
- Checkpoint: `cargo check -p pharos-network -p pharos-node && cargo test -p pharos-network -p pharos-node`.
- Commit: `feat(m6): bls_to_execution_change topic + validator, fold in 3 phase0 validators, capella fork-digest migration`

## Phase 7 — Node integration + main.rs wiring
Depends: Phases 1–6.
- 7.1 `crates/pharos-node/src/main.rs`: Capella arm in block-ingestion decode dispatch;
  populate `ForkSchedule.capella_*` from `runtime_cfg` (replaces the Phase 1 stub).
- 7.2 `crates/pharos-node/src/checkpoint_sync.rs` + storage rehydrate: handle a
  `Eth-Consensus-Version: capella` anchor.
- 7.3 engine-driver head bridge: select Engine V2 for capella head blocks.
- 7.4 pipeline integration test: assert a Capella block import.
- Checkpoint: `cargo check --workspace && cargo test -p pharos-node`.
- Commit: `feat(m6): node wiring — capella block decode, fork schedule, checkpoint sync, engine V2 selection`

## Phase 8 — Devnet acceptance (M4d-style) + wrap-up
Depends: all prior.
- 8.1 Generate/extend a Bellatrix→Capella transition testnet-dir; document layout.
- 8.2 Run Lighthouse + ethrex devnet; pharos follows head PAST the Capella fork epoch with
  withdrawals applied, `engine_newPayloadV2` `VALID`, 0 bans, no panics/deadlocks over 10 min.
  Capture log evidence + diagnostics method.
- 8.3 `make conformance` (background, capture); regenerate `docs/conformance.md`; all capella
  rows `fail=0` both presets; pre-capella rows byte-identical.
- 8.4 Finalize `docs/decisions.md` M6-Capella ADRs PROPOSED→ACCEPTED (+ any devnet `D-`
  findings, mirroring M5-follow's correctness subsection if bugs surface).
- 8.5 Workspace version `0.8.0`→`0.9.0`; update CLAUDE.md M-status (do NOT `git add` CLAUDE.md).
- 8.6 `make pre-commit` green.
- Final audit: re-read this plan; grep each named symbol/file; resolve gaps before
  declaring done. Confirm 4 enum variants everywhere, per-step order, 27 validator rule
  paths, Engine V2 for capella, all capella conformance green both presets, devnet followed
  past fork epoch.
- Commit: `chore(m6): close out M6-Capella — devnet acceptance, conformance regen, ADRs, version 0.9.0`

## Open questions (resolved / dispositioned)
- OQ1 getPayloadV2 deferral → **resolved**: deferred to M8 (follow-only); add TODO in handle.rs.
- OQ2 devnet config → Phase 8 operational; decide there (existing lcli tooling preferred).
- OQ3 minimal preset values → **resolved**: see the preset table above (per-`EthSpec` consts).

## Risks (carried from planner, verified)
per-step order; withdrawals equality off-by-one (sweep wrap, partial vs full); sweep assert;
fork-agnostic domain; accidental `historical_roots` append; CachedRoot reset on clone; engine
wire casing drift; LC branch depth/index; validator rule under-count (mitigated by 27-path
test requirement); Tree-backend field omission (`historical_summaries` decided Naive); devnet
bugs (fixed in Phase 8, new `D-` keys, not deferred).
