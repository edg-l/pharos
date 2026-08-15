# CLAUDE.md — Pharos

This file is for Claude. It is excluded from git (`.git/info/exclude`).
Authoritative project context lives in `docs/roadmap.md`; this file is a
fast index for AI sessions.

## What Pharos is

An Ethereum proof-of-stake consensus client written in Rust. Solo project.
Performance is a first-class goal; we build with that in mind from day one
(no benches yet — bench-conscious dev, not premature optimization).

## Core principle

**If consensus-specs (or an EIP) publishes a conformance test suite for it,
we own the implementation.** Upstream deps only for generic infrastructure
without CL-specific test vectors, or for cryptographic primitives where the
test suite validates I/O but not side-channel safety (BLS via `blst`, KZG
via `c-kzg`).

We are not a thin wrapper around sigp/Lighthouse crates. We own SSZ,
Merkleization, types, STF, fork choice, networking glue, Beacon API,
Engine API client, storage abstraction, VC, slashing logic.

## Locked decisions (short form)

- Workspace, 11 crates under `crates/`, two binaries (`pharos`, `pharos-vc`)
- Sync STF, async I/O at the edges (`tokio` + `rayon`)
- Fork representation: enum-of-forks with shared trait. **No `superstruct`**
- Preset generic: `EthSpec` trait with associated constants
- Storage: `rocksdb` for chain, `rusqlite` for VC slashing protection
  (separate file). Behind a `Store` trait; hot/cold split designed in
- Networking: raw `libp2p` + `discv5` (no `lighthouse_network` vendoring)
- Engine API client: in-house, `reqwest` + `serde_json` + `jsonwebtoken`
  (no `alloy`)
- Sync: checkpoint sync first-class; backfill is required, not optional
- Persistent collections: in-house tree-backed `SszList`/`SszVector` (the
  persistent data structure *is* the SSZ Merkle tree). Naive `Vec`-backed
  impl behind the trait first, persistent tree later. **No `milhouse`**
- License: Apache-2.0 + MIT dual
- Errors: `thiserror` in libs, `anyhow` at binaries

## Explicitly rejected as deps

`ethereum_ssz`, `tree_hash`, `ethereum_hashing`, `ethereum_serde_utils`,
`alloy*`, `lighthouse_network`, `milhouse`, `ssz_rs`, `superstruct`.

## Workspace map

```
crates/
  pharos-utils          # base, no internal deps
  pharos-ssz            # SSZ + Merkleization + persistent collections
  pharos-types          # per-fork containers, EthSpec
  pharos-storage        # Store trait + rocksdb
  pharos-fork-choice    # LMD-GHOST + FFG  (M1)
                        #   pub: Store, get_forkchoice_store, on_block,
                        #   on_tick, on_attestation, on_attester_slashing,
                        #   get_head, get_proposer_head, compute_pulled_up_tip,
                        #   update_checkpoints, update_unrealized_checkpoints
  pharos-stf            # process_block / process_epoch  (M1)
                        #   pub: state_transition, process_slots,
                        #   process_block, process_epoch,
                        #   process_justification_and_finalization,
                        #   StateTransitionError, EpochProcessingError
  pharos-conformance    # spec-test runner + dashboard
  pharos-engine         # Engine API client (CL -> EL JSON-RPC)
  pharos-network        # libp2p/discv5 glue, gossip, req-resp  (M2)
                        #   pub: NetworkBuilder, NetworkHandle, Network,
                        #   NetworkCommand, NetworkEvent, NetworkError,
                        #   host::{Host, ForkContext, BlockProvider,
                        #     GossipValidator, GossipVerdict},
                        #   scoring::{PeerScorer, ScoreEvent, NoopScorer},
                        #   topics::{GossipTopic, ...},
                        #   rpc::{RpcRequest, RpcResponse, RpcMethod, ...}
  pharos-api            # Beacon API HTTP server (axum)
  pharos-node           # beacon-node binary (`pharos`)
  pharos-validator      # validator-client binary (`pharos-vc`)
```

## M1 status

Closed. All Phase 0 conformance categories live with `fail = 0`
(`docs/conformance.md`); `phase0/fork_choice/*` uses altair fixtures per
the Q1 footnote (see `docs/decisions.md`). State transition and fork
choice public surfaces are above.

## M2 status

Closed. `pharos-network` ships TCP + QUIC libp2p stack with gossipsub
(SSZ-snappy, StrictNoSign), discv5 discovery, five req-resp methods
(Status, Goodbye, Ping, MetaData, BeaconBlocksByRange, BeaconBlocksByRoot),
peer manager with Status handshake, `NoopScorer` stub, `NetworkHandle`
public API wired into the `pharos` binary. 59 unit + 11 integration tests
green. Per-decision rationale in `docs/decisions.md` (M2 section). Phase
9 wrap-up + audits in `docs/m2-plan.md`.

## M3b status

Closed. Altair STF (`process_sync_aggregate`, `process_inactivity_updates`,
participation-flag rewards/penalties, `process_sync_committee_updates`,
`upgrade_to_altair` transition), enum-of-forks `BeaconState<E>` /
`BeaconBlock<E>`, altair containers and light-client types, all shipped.
`pharos-network` extended with: context-bytes codec on
`BeaconBlocksByRange/2` + `BeaconBlocksByRoot/2` + four LC req-resp methods,
`MetaDataV2` (`syncnets` field) with v1/v2 dual-handle, four new gossip
topics (`sync_committee_*`, `light_client_*`), altair `message-id` formula,
`LightClientProvider<E>` trait, `DiscoveryHandle::update_enr_eth2`.
`pharos-node` extended with subnet-rotation loop and cross-fork ENR
migration driver, `RuntimeConfig` YAML loader with `--config-dir` CLI flag.
All `altair` conformance categories green (`transition`, `ssz_static`,
`operations`, `epoch_processing`, `sanity`, `finality`, `random`, `rewards`,
`light_client`) on both presets; `phase0/fork_choice` now shows real
pass counts (Q1 resolved). Per-decision rationale in `docs/decisions.md`
(M3b section: `D-altair-state-shape`, `D-context-bytes-codec`,
`D-metadata-v2-dual-handle`, `D-light-client-server-only`,
`D-ethspec-yaml-loader`, `D-altair-transition-test-strategy`,
`D-sync-aggregate-bls`, `D-fork-schedule-source`). Phase 9 wrap-up + audits
in `docs/m3b-plan.md`.

## M4a status

Closed. `pharos-engine` real implementation ships: `engine_newPayloadV1`,
`engine_forkchoiceUpdatedV1`, `engine_getPayloadV1`,
`engine_exchangeCapabilities`, `engine_exchangeTransitionConfigurationV1`, JWT
HS256 auth (`load_jwt_secret`), per-method version enums, `EngineHandle`
actor, `EngineClient` HTTP transport. Bellatrix STF ships:
`process_execution_payload`, `upgrade_to_bellatrix`, Bellatrix containers
(`ExecutionPayload`, `ExecutionPayloadHeader`, `BeaconBlockBody`,
`BeaconState`), `ExecutionEngine` trait. Fork-choice extended:
`payload_statuses: HashMap<Root, PayloadStatus>`,
`mark_payload_status`, `filter_block_tree` excludes `Invalid` roots,
`CF_PAYLOAD_STATUS` RocksDB column family. Engine driver loop
(`run_engine_driver_loop`) bridges fork-choice head changes to the EL via
`tokio::watch`. `pharos-network` backpressure upgraded from `try_send` to
`send().await` with 1-second timeout per `D-network-backpressure`. Engine API
conformance runner added to `pharos-conformance` (`src/engine.rs`). In-process
pipeline integration test in `crates/pharos-node/tests/engine_pipeline.rs`.
All `bellatrix` conformance categories green (`transition`, `ssz_static`,
`operations`, `epoch_processing`, `sanity`, `finality`, `random`,
`fork_choice`). Per-decision rationale in `docs/decisions.md` (M4a section:
`D-engine-method-dispatch`, `D-engine-head-driver`, `D-payload-status-store`,
`D-network-backpressure`, `D-engine-conformance-runner`,
`D-bellatrix-state-shape`). Phase 7 wrap-up + audits in `docs/m4a-plan.md`.
Deferred: `get_safe_execution_block_hash` reorg-aware walk (M11),
`engine_exchangeCapabilities` 60-second polling loop (M4b/M11), LC gossip
validation bodies (M4c).

## M4b status

Closed. JWT auto-generation ships (`ensure_jwt_secret` in `pharos-node/src/jwt_autogen.rs`:
auto-generates `<data_dir>/jwt.hex` via `OpenOptions::create_new(true)` if absent, reuses
if present, never overwrites). Engine keepalive ships (`run_transition_config_keepalive` in
`pharos-node/src/engine_keepalive.rs`: 60-second `engine_exchangeTransitionConfigurationV1`
poll, `HashSet`-deduplicated TTD-mismatch `WARN`). Cold-start TTD comparison ships in
`main.rs` before keepalive spawn. Checkpoint sync ships (`fetch_checkpoint` +
`apply_anchor` in `pharos-node/src/checkpoint_sync.rs`): `GET
/eth/v2/debug/beacon/states/finalized` SSZ + `GET /eth/v2/beacon/blocks/0x<root>` SSZ,
fork-version from `Eth-Consensus-Version` header, atomic anchor write via single
`BlockTransition`). Forward backfill ships (`run_backfill_loop` in
`pharos-node/src/backfill.rs`: `BeaconBlocksByRange` chunks, STF + fork-choice advance,
exits when within `BACKFILL_TAIL_LAG_SLOTS` of wall clock). Engine conformance YAML
runner extended (6 examples, `pass=6 fail=0`). Mock pipeline integration test
(`crates/pharos-node/tests/checkpoint_backfill_pipeline.rs`) exercises the full
fetch-anchor-backfill-engine path with axum mocks. Weak-subjectivity anchor semantic
fixed: anchor block treated as both finalized and justified root (`D-anchor-as-weak-subj-root`).
ADRs added to `docs/decisions.md` (M4b section): `D-anchor-as-weak-subj-root`,
`D-checkpoint-sync-source`, `D-anchor-state-on-disk`, `D-backfill-driver`,
`D-engine-config-keepalive`, `D-jwt-auto-gen`. Deferred: weak-subjectivity validation
(M11), historical backfill (M11). Phase 6 wrap-up + audits in `docs/m4b-plan.md`.

## M4-perf status

Closed. Full conformance writer ~11 min → 2:59 (3.7×); targeted `phase0/sanity/mainnet`
5:46 → ~19 s (18×). `docs/conformance.md` row counts byte-identical. Tree-backed
`SszList<T, N>`/`SszVector<T, N>` ships (`crates/pharos-ssz/src/sequence.rs`):
`Backend::{Naive, Tree(Arc<Node<T>>)}` with `Branch { OnceLock<Hash256> }`, `Leaf`,
`ZeroSubtree(depth)`, CoW path-copy writes, structural sharing. `FixedBytes<32>`
admitted to tree backend via `PACKED_AS_FULL_CHUNK` carveout. Seven hot `BeaconState`
fields flipped to `Tree` (`validators`, `historical_roots`, `state_roots`,
`block_roots`, `randao_mixes`, `previous/current_epoch_attestations`). `Validator`
ships an `OnceLock<Hash256>` cache with hand-written `Clone` that RESETS the cache
(`clone-mutate-with_set` is the dominant STF pattern; carrying the cache would yield
stale roots). `pharos_utils::CachedRoot` wrapper adds state-level top-root memoisation
with `Clone`-resets, transparent `PartialEq`, `#[ssz(skip)]` field annotation; wired
into all three fork variants of `BeaconState`. `#[derive(TreeHash)]` emits balanced
binary `rayon::join` for structs with ≥ 4 SSZ-visible fields
(`PAR_TREE_HASH_FIELD_THRESHOLD` in `crates/pharos-ssz-derive/src/lib.rs`).
`BeaconStateView` gains borrowing accessors (`validators_iter`, `validator(idx)`,
`num_validators`, `block_root_at`, `state_root_at`, `randao_mix_at`); all hot STF
call sites migrated; the `Vec<Validator>`-returning legacy methods are retained but
cold-path. Conformance decode lands `Backend::Naive` regardless of the
`D-tree-backend-fields` list — the Phase 2 attempt to flip on decode was a 22%
regression because the writer is single-shot per state and amortises nothing; the
explicit `into_tree_backend()` helpers exist on each `BeaconState` for live-node
entry points to call. Phase 5 outer `par_iter` over (fork, category, preset)
triples was attempted twice and dropped — nested rayon thrashes the global thread
pool. ADRs added to `docs/decisions.md` (M4-perf section): `D-tree-node-shape`,
`D-packed-as-full-chunk`, `D-tree-backend-fields`,
`D-validator-cache-clone-resets`, `D-cached-root-wrapper`,
`D-no-tree-backend-on-decode`, `D-state-view-borrowing-accessors`,
`D-treehash-rayon-strategy`, `D-conformance-parallelism-dropped`. Workspace version
bumped `0.4.0` → `0.5.0`. Phase 6 wrap-up in `docs/m4-perf-plan.md`. Latent wins
(Phase 3 + Phase 6 state cache) currently unused at runtime — pending live-node
caller migration to `cached_tree_hash_root()` + `into_tree_backend()` at storage /
checkpoint-sync / genesis entry points.

## M4c status

Closed. Three carry-ins from M3b/M4a/M4-perf landed: (1) full-node `GossipValidator`
bodies for `light_client_finality_update` and `light_client_optimistic_update` in
`crates/pharos-node/src/host_impl.rs` implementing the altair p2p-interface IGNORE
rule (snapshot lookup → monotonic finalized-slot / attested-slot check → clock-window
gate vs `get_sync_message_due_ms` ± `MAXIMUM_GOSSIP_CLOCK_DISPARITY` → `tree_hash_root`
equality short-circuit → exact equality against the locally produced update); (2) LC
snapshot writes from STF via `crates/pharos-stf/src/altair/light_client_dispatch.rs`,
fired by altair-or-later blocks and surfaced to the ingestion loop via
`IngestionEgress::has_lc_snapshots` so `run_block_ingestion_loop`
(`crates/pharos-node/src/block_ingestion.rs`) publishes
`light_client_finality_update` / `light_client_optimistic_update` to gossip
immediately after each head advance that produced a fresh snapshot (Approach B —
spec SHOULD-wait is intentionally deviated, accepted under
`D-lc-broadcast-from-ingestion`); (3) criterion bench harness with four benches —
`process_block` (phase0/altair/bellatrix), `tree_hash_beacon_state` (naive / tree /
cached_root), `gossip_validation` (in `crates/pharos-node/benches/` per
`D-bench-location-per-crate`, with RocksDB `put` lifted into unmeasured `iter_batched`
setup), and `rpc_roundtrip`. `bellatrix_cold` flips inner state to `Tree` backend
before the iter loop so we don't accidentally re-time a Naive full Vec clone
(`D-no-tree-backend-on-decode` guardrail). `make bench` drives all four and writes
`bench-history/<sha>.json`; `scripts/bench-summary.sh` exits 1 on empty
`target/criterion/` so we never silently record an empty baseline. Bellatrix LC
bootstrap/update header uses `block.state_root` (STF-verified), NOT a recomputed
`state.tree_hash_root()` on the Altair-projected state (commit `aaa5440`); the
projected state omits `execution_payload_header` so a recompute would never match
what a full-node consumer verifies. MSRV bumped `1.85` → `1.86` (criterion 0.8
requirement). First baseline recorded at SHA `d96e1f8` on the canonical `PERF_HOST`
(AMD Ryzen 5 5600); numbers ledgered in `docs/perf/m4-perf.md`. `docs/conformance.md`
row counts are byte-identical to v0.5.0 (only the date line moved). ADRs added to
`docs/decisions.md` (M4c section): `D-lc-gossip-validation-full-node-arm`,
`D-lc-snapshot-trait-on-host`, `D-lc-gossip-clock-window`,
`D-lc-broadcast-from-ingestion`, `D-lc-snapshot-write-trigger`,
`D-bench-location-per-crate`, `D-bench-history-format`. Workspace version bumped
`0.5.0` → `0.6.0`. Phase 6 wrap-up + audits in `docs/m4c-plan.md`. Deferred: bench
regression check in CI (M4d), real `validate_beacon_block` gossip validator (M5).

## M4e status

Closed. Three gossip-validator bodies (`validate_beacon_block`,
`validate_attestation`, `validate_aggregate_and_proof`) on `HostImpl<E>` in
`crates/pharos-node/src/host_impl.rs` now implement all spec rules from
`specs/phase0/p2p-interface.md` (12-step block pipeline, 13-step attestation
pipeline, 17-step aggregate pipeline). Gossip dispatch in
`crates/pharos-network/src/network/mod.rs:535` wrapped in `tokio::task::spawn_blocking`
so synchronous BLS verifies do not stall the tokio executor. 44 new unit tests
in `host_impl.rs` (14 block / 13 att / 17 agg) plus two integration tests:
`gossip_validators_e2e.rs` (full-path happy-path for all three topics) and
`gossip_verdict_strings.rs` (49-string round-trip audit: 14 block / 15 att /
20 agg). Criterion bench baseline recorded at SHA `821f5ef` on PERF_HOST (AMD
Ryzen 5 5600); numbers in `docs/perf/m4-perf.md`. `docs/conformance.md` row
counts byte-identical to v0.6.0 (only the date line moved; M4e is
network-layer-only and the conformance runner does not exercise gossip
validators). ADRs added to `docs/decisions.md` (M4e section):
`D-seen-cache-shape`, `D-proposer-cache`, `D-committee-cache`,
`D-verdict-strings-spec-keyed`, `D-bls-on-hot-path`, `D-invalid-roots-cache`,
`D-future-slot-disparity`, `D-domain-types-additions`, `D-is-aggregator-location`,
`D-cache-key-on-head`, `D-seen-cache-after-accept`, `D-no-tokio-from-validator`.
Deferred: `validate_voluntary_exit`, `validate_proposer_slashing`,
`validate_attester_slashing` validators (M4f or M5); batched BLS verification
(M11). Workspace version bumped `0.6.0` → `0.7.0`. Phase 6 wrap-up + audits
in `docs/m4e-plan.md`.

## M5-follow status

Closed. Full cross-client gossip block-following proven on the live Bellatrix
devnet (Lighthouse v8.1.3 + ethrex): pharos `head == wall` (exact, 0 lag),
`peers:1` stable to epoch 15, 0 bans, direct gossip import (no lookup-fallback
churn at the tip). Prior commit `8a76559` landed lookup-sync + in-flight dial
dedup; this milestone fixed the four remaining correctness gaps that surfaced
once pharos actually followed:
- `6b19e71` `D-blocksbyroot-bare-list`: `BeaconBlocksByRootRequest` was SSZ-encoded
  as a container (spurious 4-byte offset) instead of the bare `List[Root,N]`;
  Lighthouse `InvalidByteLength` → instant -100 ban. Hand-written transparent
  `Encode`/`Decode` in `crates/pharos-types/src/phase0/operations.rs`.
- `2b9d390` `D-lc-publish-due-time`: LC `optimistic/finality_update` published at
  slot start → Lighthouse `TooEarly` → `light_client_gossip_error` -1/slot bleed.
  `HostImpl::lc_publish_wait` + delayed publish in `block_ingestion.rs`.
- `c351622` `D-import-clock-nudge`: `on_block` future-slot guard read a `store.time`
  lagged by the 1s background ticker → every tip block rejected `FutureSlot`,
  re-fetched via lookup a slot late. Advance-only single-step `on_tick_per_slot`
  to wall-now before `on_block` in `import.rs` (NOT catch-up `on_tick` — it hangs
  on mock `genesis_time=0` and can regress the cursor).
- `4d49d24` `D-future-block-hold`: future blocks were dropped, not delayed
  (`fork-choice.md` says delay until in the past). Re-inject channel +
  `hold_future_block` replays at slot start (bounded `MAX_FUTURE_BLOCK_HOLD`).
ADRs in `docs/decisions.md` ("M5-follow correctness decisions" section). Tests:
`blocks_by_root_request_is_bare_list_no_offset` (exact wire bytes),
`lc_publish_wait_*`, `wait_until_slot_start_*`, `hold_future_block_*`. Full gate
green (670 tests). `docs/conformance.md` untouched (network-layer-only milestone;
runner does not exercise gossip/follow). Workspace version bumped `0.7.0` →
`0.8.0`. Diagnostic key: Lighthouse `--debug-level debug` surfaced `TooEarly`,
the `InvalidByteLength` RPC error, and `Peer has been banned ... Bad Score`.
Deferred: extend `D-future-block-hold` to the lookup direct-import path (self-heals
today); bench-regression check in CI (carry-in from M4c). NOTE: `D-byroot-lookup-deferred`
(M5 section) is now obsolete — `8a76559` shipped the `BeaconBlocksByRoot` lookup.

## M6-Capella status

Closed. Capella shipped as a bellatrix sibling across all crates (8-phase plan in
`docs/m6-capella-plan.md`): `pharos-types/capella` (containers + LC header with
execution payload + branch), `pharos-stf/capella` (withdrawals, bls_to_exec_change,
historical_summaries, `upgrade_to_capella`, per-step `process_block`), `pharos-engine`
Engine API V2 (`newPayloadV2`/`forkchoiceUpdatedV2`; `getPayloadV2` wire-only, deferred
to M8), `pharos-network` (`Fork::Capella` + fork-digest migration +
`bls_to_execution_change` topic), `pharos-conformance` capella runners, `pharos-node`
wiring (capella block decode, fork schedule from `runtime_cfg`, checkpoint-sync capella
anchor, engine-V2 head selection). All four phase0/capella gossip validators implemented
(`bls_to_execution_change` 2I+4R; the 3 folded phase0 validators 1I+6R each). All capella
conformance categories green both presets (`docs/conformance.md`); pre-capella rows
byte-identical (only the engine `yaml` row grew 6→8 from the new capella V2 examples).
**Live Bellatrix→Capella transition devnet acceptance PASSED** (lighthouse v8.1.3 +
ethrex v13, `CAPELLA_FORK_EPOCH=1`): pharos followed head 49 capella slots past the fork,
`head==wall±1`, live `upgrade_to_capella` fired, ethrex `newPayloadV2` VALID, 0 bans,
0 panics over 10 min. The devnet found TWO live-only correctness bugs (the M6 analogue of
M5-follow): `D-live-fork-trigger-in-state-transition` (`state_transition` never called the
Phase-2 `process_slots_fork`, so a bellatrix-state + capella-block crossing returned
`UnsupportedFork` and froze the node) and `D-runtime-cfg-threading-live-loops` (the
ingestion/backfill/lookup loops fed a default `RuntimeConfig` with `CAPELLA_FORK_EPOCH =
u64::MAX`, suppressing the upgrade); both fixed and re-verified live. ADRs in
`docs/decisions.md` (M6-Capella section: 10 ADRs + 2 devnet-correctness ADRs). Devnet
generator now capella-transition (`~/.cache/pharos-devnet/gen-testnet.sh`:
`CAPELLA_FORK_EPOCH=1` + genesis.json `shanghaiTime` + syncs pharos specdir config so
lighthouse/pharos configs can't drift). Workspace version bumped `0.8.0` → `0.9.0`.
Deferred: `engine_getPayloadV2` live block production (M8); extend `gossip_verdict_strings`
audit to capella LC verdict strings (minor).

## M-Storage status

Closed. Persistent hot/cold chain storage (6-phase plan in `docs/storage-plan.md`).
Motivation: an M7 code review found the live import path persisted NOTHING to
RocksDB (only startup + checkpoint-sync wrote), so `/eth/v2/beacon/blocks/{id}` 404'd
for any block imported after startup and nothing survived restart beyond the anchor.
Shipped: (1) **live block persistence** — `import_block` writes block + slot-index +
`StateSummary` + fc-snapshot + `head_state_root` every import in a SEPARATE
`spawn_blocking` AFTER the `on_block` write-lock drops (never under the lock); full
state only at epoch boundaries; real v1 header signatures sourced from the stored
`SignedBeaconBlock`. (2) **replay-on-read** — `StateRegenService` (`state_regen.rs`):
`nearest_stored_state` + `replay_to` (STF primitives unchanged) serve arbitrary
historical states; `ChainStateApi::regenerate_state` (no `pharos-api`→`pharos-node`
dep). (3) **hot/cold freezer** (`freezer.rs`) — driven off the head-watch; on
finalization migrates `(split_slot, finalized_slot]` to cold CFs in ONE atomic
`migrate_to_cold` WriteBatch (writes ALL interval-multiple restore points), then evicts
finalized in-memory fork-choice entries (incl. `latest_messages` by evicted root) under
read-then-short-write lock; `slot_to_block_root` index is NEVER pruned (cold regen +
`BeaconBlocksByRange` need it). (4) **orphan pruning + restart recovery** — orphans
identified via the authoritative `slot_to_block_root` index (NOT `get_ancestor`);
`rehydrate_fork_choice_store` rebuilds a DENSE `[split_slot, head_slot]` `block_states`
(intermediate states regenerated via `inline_replay_to` threading the REAL loaded
`runtime_cfg` fork schedule — fork-crossing-safe), anchor + `split_slot`/`anchor_slot`
seeded on the single anchor `BlockTransition`. Schema bumped v2→v3 (4 new CFs:
`state-summary`, `cold-blocks`, `cold-states`, `restore-points`; opening a v2 DB returns
`SchemaMismatch` → resync). ADRs in `docs/decisions.md` (M-Storage section, 10 ADRs
ACCEPTED): `D-persist-in-import-core`, `D-epoch-boundary-state-cadence`,
`D-replay-on-read`, `D-freezer-in-rocksdb`, `D-restore-point-interval`,
`D-prune-behind-finalized`, `D-schema-v3-migration`, `D-state-diffs-deferred`,
`D-store-signed-block-only`, `D-freezer-driver-off-head-watch`. Tests:
`live_block_persistence`, `state_replay`, `freezer_migration`, `restart_across_split`,
`state_summary_roundtrip`. `--restore-point-interval-epochs` (default 8) + `--no-freezer`
CLI flags. Workspace version bumped `0.9.0` → `0.10.0`. Deferred: on-disk state diffs
(`D-state-diffs-deferred`), historical genesis-ward backfill (M11), blob/data-column
sidecar persistence (Deneb+), a fork-crossing rehydrate integration test (code path is
fork-safe; existing restart test is same-fork).

## Reference repos (cloned in `~/dev/`)

- `consensus-specs/` — Python specs + reference tests (test fixtures live
  here; `consensus-spec-tests` was archived into this repo)
- `EIPs/` — canonical EIP texts
- `beacon-APIs/` — REST surface to implement
- `execution-apis/` — Engine API spec lives in `src/engine/`
- `builder-specs/` — MEV-Boost / builder API (later)

## EL pairing

Pharos talks to an external EL via the Engine API. Default pairing:
`ethrex` (in `~/dev/ethrex/`). Also compatible with reth/geth/etc.

## Workflow expectations

- **Prefer `make` targets over raw `cargo` invocations.** The Makefile
  bakes in output capture (`target/test-logs/<name>.log`), pipefail
  semantics, and the fast-vs-full test split. Agents that call raw
  `cargo test --workspace` end up re-running and losing output. Use
  `make help` to list targets.
  - Standard inner-loop: `make test` (fast, skips m0_acceptance),
    `make lint`, `make fmt-check`, `make check`.
  - Pre-commit gate: `make pre-commit` (= fmt + lint + fast tests).
  - Pre-push / full CI gate: `make pre-push` or `make ci` (includes
    the slow conformance walk).
  - Conformance regen: `make conformance` (`--release`, captured).
  - Single category profile: still use raw cargo with the `--filter`
    flag (e.g. `./target/debug/pharos-conformance --filter bellatrix/sanity/mainnet`),
    because that's not a make target. Capture to `target/test-logs/` manually.
- Rust 2024 edition, MSRV 1.85.
- `cargo fmt` and `cargo clippy` before commits (or just `make fmt lint`).
- `make check` (i.e. `cargo check --workspace`) must stay green.
- No Co-Authored-By lines in commits.
- Don't commit `CLAUDE.md` or planning artifacts unless explicitly asked.
- **Long-running test/conformance runs** — applies to anything > ~30 s
  wall, and ALWAYS to: `cargo test --workspace`, `cargo test -p
  pharos-conformance`, `cargo test -p pharos-conformance --test
  m0_acceptance`, `cargo run -p pharos-conformance -- --write`,
  `cargo flamegraph`, full-workspace `cargo build`/`check`/`clippy`
  cold runs.
  - **Run ONCE per session per command.** If you already ran
    `cargo test --workspace` this session, do not run it again unless
    source has changed since. A "sanity check" run followed by a
    "pre-commit" run is the same command twice — combine them.
  - **Always capture full output to a file.** Pattern:
    `mkdir -p target/test-logs && cargo X 2>&1 | tee target/test-logs/<name>.log`
    (use `tee` if you also want live tail; otherwise plain `>` redirect).
    Piping only to `tail -N` discards everything before the tail — if
    you later need an earlier line you re-execute, which is exactly
    what this rule forbids. ALWAYS pipe to a file first, then `tail`
    the file.
  - **Parse the captured file**, not the live stream. `rg`/`tail`/`grep`
    against `target/test-logs/<name>.log` for the result, never re-execute
    the command to filter its output.
  - **Background it** (`run_in_background: true`) so the harness notifies
    you on completion. While it runs, do other work; do not poll, do not
    start a second instance of the same command.
  - **Never run two tests/benches concurrently.** Cargo test (and the
    conformance writer) are CPU-bound and saturate all cores via rayon.
    Two of them at once fight for CPU and roughly double the wall time
    of each. Wait for one to finish before starting another. If you must
    interleave, kill the first before starting the second; do not let
    them overlap.
  - **One workspace test = the pre-commit gate.** Don't add a separate
    "verification" run. If `cargo test --workspace` passed once and
    nothing has changed since, that is the gate. Re-running it before
    commit when no source has changed is forbidden.
  - **For timing**, prefix `time (...)` and capture together:
    `{ time cargo X ; } 2>&1 | tee target/test-logs/<name>.log`. The
    `real`/`user`/`sys` lines land in the log.
  - **Reuse the log across iterations.** If a prior identical run's log
    already exists and the inputs haven't changed, read it instead of
    re-running.
  - **Watch disk; `cargo clean` when `target/` bloats.** `target/debug` can
    balloon over a long session (observed 456 GB), and version bumps invalidate
    the whole build cache. A full disk surfaces as a linker `Bus error`
    (SIGBUS, signal 7) or `No space left on device` mid-build, NOT an obvious
    "disk full" message. If you see those, check `df -h /` and
    `du -sh target`; run `cargo clean` to reclaim (it does NOT touch
    `docs/` or fixtures), then rebuild. Also clear `~/.cache/tmp` (build
    scratch) if it has grown.

## Spec-test workflow

Download fixtures once: `scripts/fetch-spec-tests.sh` (downloads to `~/.cache/pharos-spec-tests/`).
Then run: `cargo run -p pharos-conformance -- --write` to produce `docs/conformance.md`.

Fixture location: `$PHAROS_SPEC_TESTS` env var, default `~/.cache/pharos-spec-tests/`.
`cargo test --workspace` is always green without fixtures (conformance test skips cleanly).

## Where to read more

`docs/roadmap.md` — full roadmap: EIPs per fork, library philosophy,
milestones (M0–M11), persistent-collection design sketch.
`docs/decisions.md` — milestone-scoped ADR-style decisions (`D1`–`D8`,
`Q1`–`Q4` for M1; descriptive `D-<topic>` / `Q-<topic>` keys from M2
onward: `Q-quic-enr`, `D-libp2p`, `D-discv5`, `D-runtime-ownership`,
`D-trait-boundaries`, `D-fork-digest-source`, `D-channels`,
`D-test-runner`, `D-peer-scoring`, `D-network-event-surface`,
`M-networking-spec-source`; M3a: `D-rocksdb`, `D-store-trait`,
`D-gossip-validator-sync`, `D-block-encoding-on-disk`,
`D-storage-error-strategy`, `D-peer-info-shape`, `D-shutdown-protocol`,
`D-metadata-mutation`, `D-fork-schedule`; M3b: `D-altair-state-shape`,
`D-context-bytes-codec`, `D-metadata-v2-dual-handle`,
`D-light-client-server-only`, `D-ethspec-yaml-loader`,
`D-altair-transition-test-strategy`, `D-sync-aggregate-bls`,
`D-fork-schedule-source`).
