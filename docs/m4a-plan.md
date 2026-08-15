# M4a — Bellatrix + Engine API + first merged devnet sync

## Overview
M4a lands Bellatrix as a real fork, replaces the 7-line `pharos-engine` stub
with a real Engine API client (JWT-authenticated JSON-RPC over HTTP), wires the
CL ↔ EL feedback loop through fork choice, marks payload-invalid blocks in the
store, replaces the M2 drop-on-overflow network event channel with bounded
backpressure, adds an `engine` conformance category, and gates the milestone on
a real merged-sync run between `pharos` and `ethrex` on a local devnet. M3b
(Altair) is assumed shipped: enum-of-forks `BeaconState<E>` / `BeaconBlock<E>`,
real `Host<E>`, real storage, context-bytes codec, `RuntimeConfig` YAML loader.

## Requirements

### Explicit (from roadmap M4a + scope brief)
- `pharos-engine` real impl: `engine_newPayloadV1`,
  `engine_forkchoiceUpdatedV1`+`V2`, `engine_getPayloadV1`,
  `engine_exchangeCapabilities`, plus auxiliary `eth_chainId`,
  `eth_getBlockByHash`, `eth_getBlockByNumber`, `eth_syncing`. Method-version
  dispatch must extend cleanly to Capella V2/V3, Deneb V3/V4, Electra V4.
- JWT auth: HS256, secret loaded from `--jwt-secret <path>` (32 random bytes
  hex), per `~/dev/execution-apis/src/engine/authentication.md`. Uses
  `jsonwebtoken` (already in workspace deps as `jsonwebtoken = "10"`).
- Transport: `reqwest` (workspace dep) + `serde_json` (workspace dep). No
  `alloy`.
- EL health monitoring + simple primary/secondary failover for multi-EL
  setups (full failover is M11).
- Bellatrix STF: `BeaconBlockBodyBellatrix`, `ExecutionPayload`,
  `ExecutionPayloadHeader`, enum-of-forks extension to `BeaconState<E>` /
  `BeaconBlock<E>` / `SignedBeaconBlock<E>` / `BeaconBlockBody<E>` (third
  variant). `process_execution_payload` (Bellatrix-only),
  `upgrade_to_bellatrix`. Spec tests `bellatrix/{transition, ssz_static,
  operations, epoch_processing, sanity, finality, random, rewards}` green on
  both `mainnet` and `minimal` presets.
- fork-choice ↔ EL link: every head-promotion triggers
  `engine_forkchoiceUpdated`; reorgs trigger fresh fcU. Boundary kept
  async-aware (no HTTP inside the sync fork-choice store).
- Invalid-payload tracking: EL `{status: "INVALID"}` → CL marks block invalid
  in the fork-choice store so it never re-becomes head. `SYNCING` and
  `ACCEPTED` handled per spec.
- Backpressure on network event channel: replace `try_send` drop-on-overflow
  in `pharos-network` with bounded-but-non-dropping semantics; per-channel
  decision documented.
- Engine API conformance scaffold: `engine` category walking
  `~/dev/execution-apis/src/engine/openrpc/methods/*.yaml`. Bellatrix subset
  for M4a; Capella/Deneb/Electra YAMLs slot in without restructuring.
- First merged sync against an `ethrex` devnet as acceptance gate.

### Inferred / derived
- `EthSpec` grows Bellatrix associated constants
  (`INACTIVITY_PENALTY_QUOTIENT_BELLATRIX`,
  `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX`,
  `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX`, `MAX_BYTES_PER_TRANSACTION`,
  `MAX_TRANSACTIONS_PER_PAYLOAD`, `BYTES_PER_LOGS_BLOOM`,
  `MAX_EXTRA_DATA_BYTES`, `BELLATRIX_FORK_VERSION`, `BELLATRIX_FORK_EPOCH`).
  Default impls on `MainnetEthSpec` / `MinimalEthSpec` per
  `~/dev/consensus-specs/presets/{mainnet,minimal}/bellatrix.yaml` and
  `configs/{mainnet,minimal}.yaml`.
- `pharos_types::altair::state::BeaconState<E>` gains a Bellatrix successor
  (`pharos_types::bellatrix::state::BeaconState<E>`) carrying the same
  fields plus `latest_execution_payload_header: ExecutionPayloadHeader`. The
  fork-enum gains a `Bellatrix(_)` variant.
- `RuntimeConfig` gains `bellatrix_fork_epoch: Epoch`, plus the three
  consensus-side parameters from `configs/<network>.yaml`
  (`TERMINAL_TOTAL_DIFFICULTY: U256`, `TERMINAL_BLOCK_HASH: Hash32`,
  `TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH: Epoch`).
- `ForkSchedule` (`crates/pharos-types/src/fork.rs`) grows
  `bellatrix_fork_version: Version` + `bellatrix_fork_epoch: Epoch`. Existing
  accessors (`fork_at_epoch`, `current_fork_version`, `next_fork_version`,
  `next_fork_epoch`) extend to three forks via a small lookup table.
- `pharos-fork-choice::Store<E>` (`crates/pharos-fork-choice/src/store.rs:34`)
  grows a `payload_statuses: HashMap<Root, PayloadStatus>` field where
  `PayloadStatus` is `{ Valid, Invalid, NotValidated }`. The block-eligibility
  predicate (`filter_block_tree` in `get_head.rs`) excludes
  `PayloadStatus::Invalid` roots so an EL-rejected block never wins
  fork choice. The store is in-memory (M1 design); persistence of invalid
  flags to RocksDB is via the existing `BlockTransition` write path.
- `pharos-engine` exposes a sync-callable handle to the node: the engine
  client owns an async tokio runtime; the node calls into it via a
  `pharos_engine::EngineHandle` that wraps a `mpsc::Sender<EngineRequest>`
  + `oneshot::Receiver<EngineResponse>`. Calls from sync fork choice are
  fire-and-forget (`send` with timeout); the node has a separate driver
  that consumes head-change events and issues fcU.
- A new `NetworkEvent::HeadChanged { head, safe, finalized }` is NOT what
  we want — head changes originate from the node-level driver after STF +
  fork-choice, not from the network. The driver loop in `pharos-node`
  publishes head-change events on an internal `tokio::sync::watch` channel;
  the engine driver subscribes.

### Assumptions
- A1: M3b shipped. Enum-of-forks `BeaconState<E>` and friends exist with
  `Phase0(_)` and `Altair(_)` variants; M4a adds `Bellatrix(_)`.
- A2: M3b's `RuntimeConfig` YAML loader path is the canonical place for
  fork-epoch values; M4a extends fields, not the loader contract.
- A3: BLS path (`pharos_utils::bls::fast_aggregate_verify`) handles Bellatrix
  RANDAO and sync-aggregate verification unchanged.
- A4: `ethrex` checkout at `~/dev/ethrex` is buildable via
  `cargo build --release --bin ethrex` and accepts `--authrpc.addr`,
  `--authrpc.port`, `--authrpc.jwtsecret`, plus a `--network <genesis.json>`
  flag (verified by `rg -n authrpc /home/edgar/dev/ethrex/cmd/ethrex/cli.rs`).
- A5: Persistent collections (`SszList` / `SszVector`) remain naive
  `Vec`-backed; Bellatrix's `transactions: List[Transaction, MAX_TRANSACTIONS_PER_PAYLOAD]`
  is large but devnet payloads are small. Hot-path size concern documented,
  not optimised here.
- A6: Engine API conformance fixtures are JSON request/response pairs under
  `~/dev/execution-apis/src/engine/openrpc/methods/*.yaml`; the runner mocks
  an HTTP server (axum) bound to a loopback port, drives the `EngineClient`
  against it, and asserts JSON I/O equality.
- A7: The `--checkpoint-sync-url` flag is M4b; M4a's devnet acceptance
  starts from a genesis state (block 0) and runs forward, not from a
  finalized checkpoint.
- A8: `syncnets` ENR key stays deferred to M8 per `docs/decisions.md`
  M3b section; M4a does NOT pull it back in.

### Locked open-question resolutions (Cross-Cutting Decisions below)
- Method-version dispatch via per-method enum + version associated constant
  per `D-engine-method-dispatch`.
- fork-choice ↔ engine boundary via head-change watch channel + node-level
  driver per `D-engine-head-driver`.
- Invalid-flag persistence via `BlockTransition::set_payload_status` writes
  per `D-payload-status-store`.
- Backpressure policy: `send().await` with 1-second timeout, configurable;
  per-channel rationale documented per `D-network-backpressure`.
- Engine conformance via in-process axum mock server per
  `D-engine-conformance-runner`.
- Bellatrix state shape: third enum variant (no `Box`), per
  `D-bellatrix-state-shape`.
- Hand-rolled Lighthouse+ethrex devnet acceptance deferred to **M4d**
  per the M4 roadmap split; M4a's gate is the in-process pipeline
  integration test (`crates/pharos-node/tests/engine_pipeline.rs`,
  Task 4.9b).

## Out of Scope
- Capella V2/V3, Deneb V3/V4, Electra V4 Engine API methods (M5/M6/M9).
- Checkpoint sync (`--checkpoint-sync-url`) — M4b.
- Forward backfill (post-checkpoint slot-by-slot fill) — M4b.
- LC gossip validation bodies / LC gossip broadcasting — M4c (deferred from
  M3b spec audit).
- Performance regression suite (criterion benches) — M4c.
- `syncnets` ENR key — M8.
- Full multi-EL failover policy — M11 (M4a ships a simple primary/secondary
  switchover only).
- Real peer scoring — M11 (`NoopScorer` stays).
- Weak subjectivity — M11.
- IPC transport for Engine API — deferred indefinitely.
- WebSocket transport for Engine API — deferred (HTTP-only per roadmap).
- Beacon API HTTP server — M7.
- Gated `lighthouse_pair.rs` integration test (auto-launches a
  Lighthouse process under `cargo test`) — M4b. M4a covers
  Lighthouse interop via the manual checklist in M4d Lighthouse acceptance only;
  see `docs/roadmap.md` cross-cutting interop section.

## Existing Patterns
- `crates/pharos-types/src/altair/` flat module layout; M4a mirrors with
  `crates/pharos-types/src/bellatrix/`.
- `crates/pharos-stf/src/altair/` per-fork STF layout; M4a mirrors with
  `crates/pharos-stf/src/bellatrix/`.
- `crates/pharos-conformance/src/lib.rs` D3 per-category dispatcher; M4a
  adds `bellatrix` rows + `engine` rows following the same shape.
- `crates/pharos-types/src/state.rs` enum-of-forks with const-generic
  parameters per variant; M4a adds the `Bellatrix` arm.
- `crates/pharos-fork-choice/src/store.rs:34` flat `Store<E>` struct; M4a
  appends one field (`payload_statuses`) and one enum (`PayloadStatus`).
- `crates/pharos-node/src/main.rs` argument parsing via `clap::Parser`
  derive; M4a adds `--jwt-secret`, `--execution-endpoint`,
  `--execution-endpoint-secondary`.
- `crates/pharos-network/src/network/mod.rs:1163` `emit_event` uses
  `try_send`; M4a swaps to `send` + timeout. Same site for the shutdown
  path (line ~300).

## Cross-Cutting Decisions

### D-engine-method-dispatch — One `EngineClient`, per-method version enum, per-fork driver picks
`EngineClient` is a single struct; its public surface is one method per
JSON-RPC operation (`fn new_payload`, `fn forkchoice_updated`,
`fn get_payload`, `fn exchange_capabilities`). Each method takes a
`MethodVersion` enum argument:
```rust
pub enum NewPayloadVersion { V1 /* M5: V2, M6: V3, M9: V4 */ }
pub enum ForkchoiceUpdatedVersion { V1 /* M5: V2, M6: V3, M9: V4 */ }
pub enum GetPayloadVersion { V1 /* M5: V2, M6: V3, M9: V4 */ }
```
The version determines the JSON-RPC method name (`engine_newPayloadV1`
vs `engine_newPayloadV2`) and the input/output type. Inputs and outputs are
enum-of-versions:
```rust
pub enum NewPayloadRequest { V1(ExecutionPayloadV1) }
pub enum NewPayloadResponse { V1(PayloadStatusV1) }
```
The fork-driver (the node-level head driver, Phase 4) picks the version from
the current fork: Bellatrix → `V1`. Capella will add `V2`, Deneb `V3`,
Electra `V4` with no `EngineClient` rewrite; the driver's match on
`current_fork` grows arms. This avoids a per-fork trait (which would
explode at four forks) and keeps the JSON-RPC plumbing in one struct.

Rejected alternative: trait `EngineApi` with one impl per fork (e.g.
`BellatrixEngine`, `CapellaEngine`). Would duplicate the HTTP transport,
JWT signing, retry logic, and capabilities cache per fork; would force a
trait-object indirection at the call site. The version-enum approach keeps
all of that shared.

Rejected alternative: dynamic JSON-RPC dispatch (build the method name
from a `&str` and serialise an arbitrary value). Would lose compile-time
type safety on request/response pairs; the consensus-specs YAMLs are
strongly typed and we want our types to match.

### D-engine-head-driver — Head changes flow through a `tokio::watch` channel; sync fork choice never blocks on HTTP
`pharos-fork-choice` stays sync (M1 invariant). After each `on_block` or
`on_attestation` call, the node-level code computes the new head via
`get_head` and writes a `HeadChange { head_root, head_block_hash, safe,
finalized }` value into a `tokio::sync::watch::Sender<Option<HeadChange>>`
held in `pharos-node`. A separate tokio task (`run_engine_driver_loop`,
Phase 4) subscribes via `watch::Receiver`, debounces (only acts on
distinct head roots), and invokes the engine HTTP calls
(`new_payload` + `forkchoice_updated`) without ever blocking the STF.

Rejected alternative: spawn a one-shot tokio task per head change from
inside `on_block`. Would require fork choice to know about tokio; couples
unrelated layers; `watch` does the debouncing for free (only the latest
value is retained).

Rejected alternative: a new `NetworkEvent::HeadChanged`. The network
crate must not know about head changes; head is a node-level concept.
A `watch` channel in `pharos-node` is the right shape.

### D-payload-status-store — `Store<E>.payload_statuses` map; persisted alongside block bodies
`pharos-fork-choice::Store<E>` (in-memory) gains
`payload_statuses: HashMap<Root, PayloadStatus>` and a setter
`mark_payload_status(root, status)`. The fork-choice filter
(`filter_block_tree` in `get_head.rs`) skips any root marked `Invalid`.

`SYNCING` and `ACCEPTED` are reported by the EL when it hasn't validated
the payload yet (still syncing the EL chain) or has accepted but not made
it canonical. We model these as `PayloadStatus::NotValidated`; fork
choice continues to treat the block as eligible (does not exclude it).

Persistence: the in-memory store is reconstructed from RocksDB at startup
per the M3a `rehydrate_fork_choice_store` flow. `payload_statuses` are
persisted as a new column family `payload_status` (per-root mapping,
`Root` → `u8` discriminant), written by an extended `BlockTransition`
that takes an `Option<PayloadStatus>`. On rehydrate, the column is read
into the in-memory map.

Rejected alternative: keep invalid roots only in memory and re-query the
EL on restart. Slow (potentially thousands of EL calls on startup) and
the EL may not remember.

### D-network-backpressure — `send().await` with 1-second timeout, drop after timeout, log loudly
The M2 `try_send`-then-drop policy (D-channels) was a placeholder. M4a
replaces it with `send().await` wrapped in
`tokio::time::timeout(Duration::from_secs(1), ...)`. On timeout we still
drop the event but log at `WARN` with the event variant name and the
queue depth; the channel is left intact. The 1-second budget is the
slot duration / 12 — large enough that legitimate consumer hiccups don't
trip it, small enough that a stuck consumer doesn't melt the event loop.

Per channel:
- `NetworkEvent` (consumer is the node block-ingestion loop): timeout +
  drop. Acceptable because event loss is bounded; the network state is
  reconciled on the next peer interaction.
- `NetworkCommand` (producer is the node, consumer is the network task):
  `send().await` with no timeout. The node MUST wait; commands are
  authoritative and re-issuing complicates state (e.g.
  `UpdateMetaData` carries a fresh `seq_number`).
- `oneshot` reply channels (per-command result): unchanged. They have
  one sender and one receiver; closing them is OK on caller drop.

Per-channel rationale lives in
`crates/pharos-network/src/network/mod.rs:1158` doc comment after the
swap.

### D-engine-conformance-runner — In-process axum mock; `EngineClient` drives it; assert JSON equality
`crates/pharos-conformance/src/engine.rs` (new) implements a YAML-driven
runner. For each request/response pair in `~/dev/execution-apis/src/engine/openrpc/methods/*.yaml`:
1. Spin up an axum HTTP server on `127.0.0.1:0` (OS-assigned port).
2. Register a handler that asserts the incoming JSON-RPC request equals
   the YAML `request` field (after canonicalisation: stable field order,
   no whitespace), and replies with the YAML `response` field verbatim.
3. Build an `EngineClient` pointing at the loopback port with a known
   JWT secret.
4. Invoke the method through `EngineClient`; assert the parsed response
   matches the YAML response shape.
5. Tear down the server.

This avoids running a real EL and gives us a deterministic fixture
loop. Future forks (Capella, Deneb, Electra) get YAML coverage for free
once the runner is in place. The runner runs in tokio (the conformance
binary already has a multi-thread runtime via `#[tokio::main]` per M0's
established pattern; if not, we add it as `tokio::runtime::Runtime::new`
in the dispatcher).

### D-bellatrix-state-shape — Third enum variant, no `Box`; const-generic params extended
`pharos_types::state::BeaconState<...>` adds a `Bellatrix(_)` variant
carrying `bellatrix::BeaconState<...>`. New const-generic parameters
(`MAX_BYTES_PER_TRANSACTION`, `MAX_TRANSACTIONS_PER_PAYLOAD`,
`BYTES_PER_LOGS_BLOOM`, `MAX_EXTRA_DATA_BYTES`) are added to the enum
header so the Bellatrix variant compiles. The Phase 0 and Altair arms
carry `PhantomData` over the new params (they don't use them).

The variant size grows: Bellatrix carries `latest_execution_payload_header`
(a fixed-size struct of ~700 bytes) and the Altair fields. R-state-bloat
in Edge Cases tracks the pad cost across the enum.

Rejected alternative: `Box<bellatrix::BeaconState<...>>` to keep the
enum small. Loses the M3b "zero indirection in STF hot path" rule.
Bellatrix STF is no hotter than Altair; we accept the pad.

## Implementation Plan

### Phase 0 — Prep + `EthSpec` Bellatrix extensions
Why this phase: lock the trait surface and the spec-test pin first;
every later phase depends on it.

- [ ] Task 0.1: Bump `scripts/fetch-spec-tests.sh` `SPEC_TESTS_TAG`
  default if a newer tag than `v1.7.0-alpha.8` has been published that
  carries Bellatrix fixtures (it does; v1.7.0-alpha.8 already includes
  `tests/<preset>/bellatrix/`). Verify
  `ls $PHAROS_SPEC_TESTS/tests/mainnet/bellatrix/` lists the standard
  categories; if missing, re-run the script.
- [ ] Task 0.2: Read
  `~/dev/consensus-specs/specs/bellatrix/beacon-chain.md`
  end-to-end. Read `~/dev/execution-apis/src/engine/paris.md`,
  `~/dev/execution-apis/src/engine/authentication.md`,
  `~/dev/execution-apis/src/engine/common.md`. No code change; gate the
  rest of the plan on having internalised these.
- [ ] Task 0.3: Extend `pharos_types::EthSpec` in
  `crates/pharos-types/src/eth_spec.rs` with Bellatrix associated
  constants: `INACTIVITY_PENALTY_QUOTIENT_BELLATRIX: u64`,
  `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX: u64`,
  `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX: u64`,
  `MAX_BYTES_PER_TRANSACTION: u64`, `MAX_TRANSACTIONS_PER_PAYLOAD: u64`,
  `BYTES_PER_LOGS_BLOOM: u64`, `MAX_EXTRA_DATA_BYTES: u64`,
  `BELLATRIX_FORK_VERSION: [u8; 4]`, `BELLATRIX_FORK_EPOCH: u64`. Source
  values: `~/dev/consensus-specs/presets/{mainnet,minimal}/bellatrix.yaml`
  + `~/dev/consensus-specs/configs/{mainnet,minimal}.yaml:44-45`. Mainnet
  fork version `[0x02, 0x00, 0x00, 0x00]`; mainnet fork epoch `144_896`;
  minimal fork version `[0x02, 0x00, 0x00, 0x01]`; minimal fork epoch
  `u64::MAX` (`FAR_FUTURE_EPOCH`; `configs/minimal.yaml:41` is the
  literal `18446744073709551615`).
- [ ] Task 0.4: Extend `RuntimeConfig` in
  `crates/pharos-types/src/config.rs` with
  `bellatrix_fork_epoch: u64`, `bellatrix_fork_version: [u8; 4]`,
  `terminal_total_difficulty: pharos_utils::U256`,
  `terminal_block_hash: pharos_utils::Hash256`,
  `terminal_block_hash_activation_epoch: u64`. Default impl returns
  `MainnetEthSpec::default_runtime_config()` snapshot. Update
  `EthSpec::default_runtime_config()` on `MainnetEthSpec` and
  `MinimalEthSpec` to populate the new fields.
- [ ] Task 0.5: Extend `crates/pharos-types/src/config.rs` YAML loader
  `load_config_dir` to parse the new fields from `<dir>/config.yaml`
  (`BELLATRIX_FORK_VERSION`, `BELLATRIX_FORK_EPOCH`,
  `TERMINAL_TOTAL_DIFFICULTY`, `TERMINAL_BLOCK_HASH`,
  `TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH`) and `<dir>/bellatrix.yaml`
  (`INACTIVITY_PENALTY_QUOTIENT_BELLATRIX`,
  `MIN_SLASHING_PENALTY_QUOTIENT_BELLATRIX`,
  `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX`,
  `MAX_BYTES_PER_TRANSACTION`, `MAX_TRANSACTIONS_PER_PAYLOAD`,
  `BYTES_PER_LOGS_BLOOM`, `MAX_EXTRA_DATA_BYTES`). Extend
  `assert_matches_preset` to compare the new dimension-bearing fields
  (`MAX_BYTES_PER_TRANSACTION`, `MAX_TRANSACTIONS_PER_PAYLOAD`,
  `BYTES_PER_LOGS_BLOOM`, `MAX_EXTRA_DATA_BYTES`) and error on
  mismatch.
- [ ] Task 0.6: Extend `ForkSchedule` in
  `crates/pharos-types/src/fork.rs` with `bellatrix_fork_version: Version`
  + `bellatrix_fork_epoch: Epoch`. Rewrite `fork_at_epoch`,
  `current_fork_version`, `next_fork_version`, `next_fork_epoch` to
  handle three forks via a lookup table
  `[(epoch, version), ...]` sorted ascending. Unit tests in the file
  exercise Phase 0 → Altair → Bellatrix crossings.
- [ ] Task 0.7: **Checkpoint: Verify Phase 0 complete**. Run
  `cargo check -p pharos-types`; confirm
  `<MainnetEthSpec as EthSpec>::BELLATRIX_FORK_EPOCH == 144_896`,
  `MainnetEthSpec::default_runtime_config().bellatrix_fork_epoch == 144_896`,
  `ForkSchedule::fork_at_epoch(Epoch(144_896)).current_version == bellatrix_fork_version`.
  List each task and status.

**Commit boundary**: `feat(m4a): phase 0 — EthSpec Bellatrix consts +
ForkSchedule extension`.

### Phase 1 — Bellatrix containers + fork-enum third variant
Why this phase: Bellatrix STF, codec, conformance all decode Bellatrix
containers. Land them as standalone module before STF wiring.

- [ ] Task 1.1: Create `crates/pharos-types/src/bellatrix/mod.rs`
  mirroring `altair/mod.rs`: submodules `block`, `body`, `state`,
  `execution_payload`. Add `pub mod bellatrix;` to
  `crates/pharos-types/src/lib.rs`.
- [ ] Task 1.2: Create
  `crates/pharos-types/src/bellatrix/execution_payload.rs` defining
  `ExecutionPayload<const MAX_BYTES_PER_TRANSACTION: u64,
  const MAX_TRANSACTIONS_PER_PAYLOAD: u64,
  const BYTES_PER_LOGS_BLOOM: u64,
  const MAX_EXTRA_DATA_BYTES: u64>` and the matching
  `ExecutionPayloadHeader<...>`. Field layout from
  `~/dev/consensus-specs/specs/bellatrix/beacon-chain.md:156-193`.
  `Transaction = pharos_ssz::ByteList<MAX_BYTES_PER_TRANSACTION>` type
  alias. Derive `SszEncode`, `SszDecode`, `TreeHash`, `Clone`, `Debug`,
  `PartialEq`, `Eq`, `Default`.
- [ ] Task 1.3: Create `crates/pharos-types/src/bellatrix/body.rs`
  defining
  `BeaconBlockBody<E: EthSpec>`
  with altair fields plus `execution_payload: ExecutionPayload<...>`.
  Per `specs/bellatrix/beacon-chain.md:128-142`. Derive SSZ. Preset
  aliases `MainnetBeaconBlockBody`, `MinimalBeaconBlockBody`. Implement
  `BeaconBlockBodyView`.
- [ ] Task 1.4: Create `crates/pharos-types/src/bellatrix/block.rs`
  defining `BeaconBlock<E>`, `SignedBeaconBlock<E>` (mirror altair
  shape, body is bellatrix). Preset aliases. Implement
  `BeaconBlockView`, `SignedBeaconBlockView`.
- [ ] Task 1.5: Create `crates/pharos-types/src/bellatrix/state.rs`
  defining
  `BeaconState<E>` per
  `specs/bellatrix/beacon-chain.md:118-126`: same fields as altair plus
  `latest_execution_payload_header: ExecutionPayloadHeader<...>`. Preset
  aliases. Implement `BeaconStateView`.
- [ ] Task 1.6: Extend the fork-enum in `crates/pharos-types/src/state.rs`:
  add `Bellatrix(bellatrix::BeaconState<...>)` arm to `BeaconState`,
  ditto `BeaconBlock`, `SignedBeaconBlock`, `BeaconBlockBody`. Extend
  enum const-generic header with the four new params; Phase 0 and
  Altair arms get `PhantomData<(...)>` over the new params (since their
  inner types don't use them). Implement view-trait `match` arms for
  the third variant.
- [ ] Task 1.7: Update `EthSpec` associated-type bundles in
  `crates/pharos-types/src/eth_spec.rs`: re-stamp `type BeaconState`,
  `type BeaconBlock`, `type SignedBeaconBlock`, `type BeaconBlockBody`
  with the new const-generic param tail. Add inner-fork associated
  types: `type BellatrixBeaconState`, `type BellatrixBeaconBlock`,
  `type BellatrixSignedBeaconBlock`, `type BellatrixBeaconBlockBody`,
  `type ExecutionPayload`, `type ExecutionPayloadHeader`.
- [ ] Task 1.8: SSZ-roundtrip tests in
  `crates/pharos-types/src/bellatrix/{state,block,body,execution_payload}.rs`
  `#[cfg(test)]` modules: `decode(encode(default())) == default()` for
  every container, mainnet + minimal presets.
- [ ] Task 1.9: **Checkpoint: Verify Phase 1 complete**. Run
  `cargo check --workspace`; phase-0 + altair conformance categories
  produce identical counts to pre-M4a (run
  `cargo run -p pharos-conformance -- --filter altair/ssz_static` and
  diff against `docs/conformance.md`); new Bellatrix containers compile.
  List each task and status.

**Commit boundary**: `feat(m4a): phase 1 — Bellatrix containers +
fork-enum third variant`.

### Phase 2 — Bellatrix STF (`process_execution_payload` + `upgrade_to_bellatrix` + state-transition entry)
Why this phase: STF separate from Engine API because it's spec-vector
testable in isolation. Bellatrix is mostly an Altair derivative; only
`process_execution_payload` is new.

- [ ] Task 2.1: Create `crates/pharos-stf/src/bellatrix/mod.rs` with
  submodules `block`, `epoch`, `operations`, `state_transition`,
  `upgrade`, `helpers`, `execution_engine`. Add `pub mod bellatrix;`
  to `crates/pharos-stf/src/lib.rs`.
- [ ] Task 2.2: Create
  `crates/pharos-stf/src/bellatrix/execution_engine.rs` defining
  `pub trait ExecutionEngine: Send + Sync + 'static` with one method:
  `fn notify_new_payload<E>(&self, payload: &ExecutionPayload<...>) -> bool`.
  The trait is sync-callable; the real impl (`ExecutionEngineHandle`,
  defined in Phase 3 / Task 3.8) wraps the async `EngineClient` by
  submitting the request onto the engine actor's dedicated
  `Arc<tokio::runtime::Runtime>` via `runtime.block_on(oneshot_rx)`
  on the caller thread. The STF caller MUST itself run inside
  `tokio::task::spawn_blocking` (M3a invariant) so the call thread is
  not a tokio worker. A `NullExecutionEngine` returning `true` is
  provided for spec-test runs (conformance does not have an EL).
- [ ] Task 2.3: Create
  `crates/pharos-stf/src/bellatrix/operations/execution_payload.rs`
  exposing
  `pub fn process_execution_payload<E, EE: ExecutionEngine>(state: &mut bellatrix::BeaconState<E>, body: &bellatrix::BeaconBlockBody<E>, execution_engine: &EE) -> Result<(), StateTransitionError>`
  per `specs/bellatrix/beacon-chain.md:380-450`. Checks:
  parent-hash match against
  `state.latest_execution_payload_header.block_hash` when the merge
  transition is complete; timestamp matches the computed slot time;
  prev_randao matches `get_randao_mix(state, get_current_epoch(state))`;
  block_number == latest_header.block_number + 1; calls
  `execution_engine.verify_and_notify_new_payload(NewPayloadRequest { execution_payload: &body.execution_payload })`
  per `specs/bellatrix/beacon-chain.md:337-354` (which is the
  `verify_and_notify_new_payload` wrapper around
  `is_valid_block_hash` + the empty-transaction guard +
  `notify_new_payload`) and rejects on `false`. Extend the
  `ExecutionEngine` trait (Task 2.2) with
  `fn verify_and_notify_new_payload<E>(&self, req: NewPayloadRequest<E>) -> bool`;
  the default impl performs the empty-transaction guard and
  delegates `is_valid_block_hash` + `notify_new_payload` to the
  underlying EL via `engine_newPayloadV1` (the EL validates the
  block hash as part of `engine_newPayloadV1` response status —
  `INVALID_BLOCK_HASH` per `paris.md`); `NullExecutionEngine`
  short-circuits to `true`. The CL does NOT independently recompute
  the block hash. Document this delegation in
  `D-bellatrix-state-shape` ADR as a brief note (or a new short ADR
  `D-block-hash-delegation` — author's call at Phase 7 time).
  On success, copy fields from `body.execution_payload` into
  `state.latest_execution_payload_header` (computing
  `transactions_root` via `hash_tree_root` on the transactions
  list). Cite each spec assertion line.
- [ ] Task 2.4: Create `crates/pharos-stf/src/bellatrix/block.rs`
  exposing
  `pub fn process_block<E, EE: ExecutionEngine>(state: &mut bellatrix::BeaconState<E>, block: &bellatrix::BeaconBlock<E>, execution_engine: &EE, verify_signatures: bool) -> Result<(), StateTransitionError>`
  per `specs/bellatrix/beacon-chain.md:360-378`. Sequence:
  `process_block_header`, `process_randao`, `process_eth1_data`,
  `process_operations`, `process_sync_aggregate`,
  `process_execution_payload` (the new step). Operations + sync
  aggregate delegate to altair impls; only the execution payload step
  is new.
- [ ] Task 2.5: Create `crates/pharos-stf/src/bellatrix/upgrade.rs`
  exposing
  `pub fn upgrade_to_bellatrix<E: EthSpec>(pre: altair::BeaconState<E>, runtime_cfg: &RuntimeConfig) -> Result<bellatrix::BeaconState<E>, StateTransitionError>`
  per `~/dev/consensus-specs/specs/bellatrix/fork.md`. Sequence: set
  `state.fork = Fork { previous_version: altair_fork_version,
  current_version: bellatrix_fork_version, epoch: get_current_epoch(&pre) }`;
  copy all other fields verbatim; initialise
  `latest_execution_payload_header` to a zero-filled
  `ExecutionPayloadHeader`. No validator-registry mutation (the merge
  doesn't touch validators).
- [ ] Task 2.6: Create
  `crates/pharos-stf/src/bellatrix/epoch/mod.rs` re-exporting the altair
  epoch functions: Bellatrix epoch processing is identical to Altair
  except for the slashings denominator (uses
  `PROPORTIONAL_SLASHING_MULTIPLIER_BELLATRIX` per
  `specs/bellatrix/beacon-chain.md:453-466`). One sub-task: implement
  `pub fn process_slashings_bellatrix<E>(state: &mut bellatrix::BeaconState<E>) -> Result<(), EpochProcessingError>`
  using the Bellatrix multiplier; re-export all other altair
  functions unchanged.
- [ ] Task 2.7: Create
  `crates/pharos-stf/src/bellatrix/state_transition.rs` exposing
  `pub fn state_transition<E, EE: ExecutionEngine>(state: bellatrix::BeaconState<E>, signed_block: &bellatrix::SignedBeaconBlock<E>, execution_engine: &EE, validate_result: bool) -> Result<bellatrix::BeaconState<E>, StateTransitionError>`.
  Update top-level `crates/pharos-stf/src/lib.rs::state_transition` to
  match on the `BeaconState<E>` enum: `Phase0` → phase0 entry,
  `Altair` → altair entry, `Bellatrix` → bellatrix entry. Top-level
  signature takes an `&dyn ExecutionEngine`; non-Bellatrix arms ignore
  it. Spec-test paths pass `&NullExecutionEngine`.
- [ ] Task 2.8: **Checkpoint: Verify Phase 2 complete**.
  `cargo check -p pharos-stf` green; per-task spec citations present
  in doc comments. List each task and status.

**Commit boundary**: `feat(m4a): phase 2 — Bellatrix STF +
process_execution_payload + upgrade_to_bellatrix`.

### Phase 3 — `pharos-engine` real impl (JSON-RPC client + JWT + Engine + eth_* methods)
Why this phase: the engine client is independently testable (mock HTTP
server); finish it before wiring into the node.

- [ ] Task 3.1: Update `crates/pharos-engine/Cargo.toml` to add
  workspace deps: `reqwest`, `serde`, `serde_json`, `jsonwebtoken`,
  `tokio`, `thiserror`, `tracing`, `parking_lot`. Add the
  `pharos-types` dep (already present).
- [ ] Task 3.2: Create `crates/pharos-engine/src/error.rs` defining
  `pub enum EngineError` (`thiserror`): `Transport(reqwest::Error)`,
  `Json(serde_json::Error)`, `Jwt(jsonwebtoken::errors::Error)`,
  `JsonRpc { code: i64, message: String }`, `UnexpectedResponse(String)`,
  `Timeout`, `Unauthenticated`.
- [ ] Task 3.3: Create `crates/pharos-engine/src/jwt.rs` exposing
  `pub fn load_jwt_secret(path: &Path) -> Result<JwtSecret, EngineError>`
  reading 64 hex chars (32 bytes) from the file, stripping `0x` if
  present. `pub fn sign_token(secret: &JwtSecret) -> Result<String, EngineError>`
  issues an HS256 token with `iat` = current unix seconds and a
  60-second validity window per
  `~/dev/execution-apis/src/engine/authentication.md`. Uses
  `jsonwebtoken::encode` with `Algorithm::HS256` (verified API in
  jsonwebtoken 10.x: `encode(&Header::new(Algorithm::HS256), &claims,
  &EncodingKey::from_secret(secret))`).
- [ ] Task 3.4: Create `crates/pharos-engine/src/types.rs` defining the
  wire types for Bellatrix Engine API per
  `~/dev/execution-apis/src/engine/paris.md`: `ExecutionPayloadV1`
  (hex-encoded `parentHash`, `feeRecipient`, ...), `ForkchoiceStateV1`
  (`headBlockHash`, `safeBlockHash`, `finalizedBlockHash`),
  `PayloadAttributesV1` (`timestamp`, `prevRandao`,
  `suggestedFeeRecipient`), `PayloadStatusV1` (`status` enum +
  `latestValidHash` + `validationError`),
  `ForkchoiceUpdatedV1Response`, `PayloadIdV1` (`[u8; 8]` hex).
  Derive `Serialize`, `Deserialize`. Field-rename to JSON camelCase via
  `#[serde(rename_all = "camelCase")]`. Add `PayloadStatusStatus` enum
  with variants `Valid`, `Invalid`, `Syncing`, `Accepted`,
  `InvalidBlockHash`.
- [ ] Task 3.5: Create `crates/pharos-engine/src/client.rs` defining
  `pub struct EngineClient { http: reqwest::Client, endpoint: Url,
  jwt_secret: JwtSecret, capabilities: parking_lot::RwLock<Option<HashSet<String>>> }`
  with constructor
  `pub fn new(endpoint: Url, jwt_secret: JwtSecret) -> Result<Self, EngineError>`.
  Add a private helper
  `async fn rpc_call<P: Serialize, R: DeserializeOwned>(&self, method: &str, params: P) -> Result<R, EngineError>`
  that builds the JWT, posts `{ "jsonrpc": "2.0", "method": ..., "params": [...], "id": ... }`
  to the endpoint with `Authorization: Bearer <token>`, parses the
  envelope, and returns `result` or the JSON-RPC error.
- [ ] Task 3.6: Add per-method enum types and methods to
  `crates/pharos-engine/src/client.rs`:
  `pub enum NewPayloadVersion { V1 /* M5: V2, M6: V3, M7: V4 */ }`,
  `pub enum ForkchoiceUpdatedVersion { V1 /* M5: V2, M6: V3, M9: V4 */ }`,
  `pub enum GetPayloadVersion { V1 /* M5: V2, M6: V3, M7: V4 */ }`.
  Bellatrix is V1-only for all three methods; later forks add variants
  (Capella V2/V3 land in M5). Per-method:
  `pub async fn new_payload(&self, v: NewPayloadVersion, payload: ExecutionPayloadV1) -> Result<PayloadStatusV1, EngineError>`
  (dispatches on version to method name `engine_newPayloadV1`);
  `pub async fn forkchoice_updated(&self, v: ForkchoiceUpdatedVersion, state: ForkchoiceStateV1, attrs: Option<PayloadAttributesV1>) -> Result<ForkchoiceUpdatedV1Response, EngineError>`
  (dispatches `engine_forkchoiceUpdatedV1`; V2+ wired in M5);
  `pub async fn get_payload(&self, v: GetPayloadVersion, id: PayloadIdV1) -> Result<ExecutionPayloadV1, EngineError>`;
  `pub async fn exchange_capabilities(&self, our_methods: &[&str]) -> Result<HashSet<String>, EngineError>`
  (caches on first call into `self.capabilities`).
- [ ] Task 3.7: Add `eth_*` methods to
  `crates/pharos-engine/src/client.rs`:
  `pub async fn chain_id(&self) -> Result<u64, EngineError>`,
  `pub async fn get_block_by_hash(&self, hash: Hash256) -> Result<Option<BlockHeader>, EngineError>`,
  `pub async fn get_block_by_number(&self, number: u64) -> Result<Option<BlockHeader>, EngineError>`,
  `pub async fn syncing(&self) -> Result<SyncingStatus, EngineError>`. Define
  `BlockHeader` and `SyncingStatus` in
  `crates/pharos-engine/src/types.rs` with the minimal field set the CL
  actually consumes (`hash`, `number`, `parentHash`,
  `terminalTotalDifficulty`).
- [ ] Task 3.8: Create `crates/pharos-engine/src/handle.rs` defining
  the sync-callable surface used by the node and the STF.
  `pub struct EngineHandle { tx: mpsc::Sender<EngineRequest>,
  runtime: Arc<tokio::runtime::Runtime> }` — the handle carries a
  shared multi-thread tokio runtime (created once in `pharos-node`
  main and cloned into the handle). The async-context constructor
  `EngineHandle::new(runtime, tx)` accepts both. Sync methods build
  an `EngineRequest { params, reply_tx }`, push it on `tx` via
  `tx.blocking_send(req)`, then await the reply via
  `self.runtime.block_on(reply_rx)` (NOT `block_in_place`, which
  requires a tokio worker thread and is unsafe inside
  `spawn_blocking`). Callers MUST be on a thread that is not itself
  a tokio worker (the STF runs inside `tokio::task::spawn_blocking`
  per the M3a invariant, satisfying this). The matching
  `pub async fn run_engine_actor(client: EngineClient, mut rx: mpsc::Receiver<EngineRequest>)`
  loop drains requests and forwards to `EngineClient`. The actor task
  is spawned from `pharos-node` main on the shared runtime; the
  handle is `Clone` and passed to STF (`ExecutionEngine` impl wraps
  the handle) and to the engine driver loop.
- [ ] Task 3.9: Create `crates/pharos-engine/src/lib.rs` (replace
  existing 7-line stub):
  - Module declarations: `pub mod client; pub mod error; pub mod handle; pub mod jwt; pub mod types;`
  - Re-exports: `pub use client::{EngineClient, NewPayloadVersion,
    ForkchoiceUpdatedVersion, GetPayloadVersion};`
    `pub use handle::{EngineHandle, EngineRequest, run_engine_actor};`
    `pub use error::EngineError;`
    `pub use jwt::{load_jwt_secret, JwtSecret};`
    `pub use types::{ExecutionPayloadV1, ForkchoiceStateV1,
    PayloadAttributesV1, PayloadStatusV1, PayloadStatusStatus};`
- [ ] Task 3.10: Implement health monitor + simple failover in
  `crates/pharos-engine/src/handle.rs`. `EngineHandle::new` takes
  `primary: EngineClient` and `Option<EngineClient>` secondary. The
  actor pings the primary's `eth_syncing` every 12 seconds; on three
  consecutive failures (or HTTP timeout > 5s) it flips
  `active_client = secondary.take()`. Logs `WARN`/`ERROR` on
  failover. Full multi-EL failover (priority lists, rebalancing) is
  M11.
- [ ] Task 3.11: Unit tests in `crates/pharos-engine/src/client.rs` and
  `crates/pharos-engine/src/jwt.rs` using an in-process axum mock
  server (the same pattern used by Phase 5 conformance): JWT round-trip
  (issue + verify), `engine_exchangeCapabilities` request/response,
  `engine_forkchoiceUpdatedV1` happy path + error path,
  `engine_newPayloadV1` `VALID`/`INVALID`/`SYNCING` response handling.
- [ ] Task 3.12: **Checkpoint: Verify Phase 3 complete**.
  `cargo check -p pharos-engine` green; `cargo test -p pharos-engine`
  passes; `EngineClient` exposes all four Engine methods + four `eth_*`
  methods + `exchange_capabilities`. List each task and status.

**Commit boundary**: `feat(m4a): phase 3 — pharos-engine real impl
(JSON-RPC + JWT + Bellatrix Engine methods)`.

### Phase 4 — fork-choice ↔ EL wiring (invalid-payload tracking + head driver)
Why this phase: the engine client exists; now hook it into block
ingestion + head selection.

- [x] Task 4.1: Add `pub enum PayloadStatus { Valid, Invalid,
  NotValidated }` to
  `crates/pharos-fork-choice/src/store.rs`. Add field
  `pub payload_statuses: HashMap<Root, PayloadStatus>` to `Store<E>`.
  Initialize empty in `get_forkchoice_store`. Add method
  `pub fn mark_payload_status(&mut self, root: Root, status: PayloadStatus)`.
- [x] Task 4.2: Modify `crates/pharos-fork-choice/src/get_head.rs`:
  in `filter_block_tree`, skip roots whose `payload_statuses` entry is
  `Invalid`. Add a unit test that builds a 3-block chain, marks the
  middle block Invalid, and asserts `get_head` returns the
  pre-invalid parent.
- [x] Task 4.3: Modify `crates/pharos-fork-choice/src/handlers.rs::on_block`:
  after the existing validity checks, default-insert
  `PayloadStatus::NotValidated` into `store.payload_statuses` for the
  new block root. The actual `Valid`/`Invalid` mark comes later via
  `mark_payload_status` from the engine driver (Task 4.6).
- [x] Task 4.3b: Extend `crates/pharos-fork-choice/src/handlers.rs::on_block`
  with the Bellatrix merge-transition guard per
  `~/dev/consensus-specs/specs/bellatrix/fork-choice.md:303-304`.
  After the standard validity checks but BEFORE
  `compute_pulled_up_tip`, when
  `is_merge_transition_block(pre_state, block.body)` returns true,
  call `validate_merge_block(block, &pow_block_provider)`. The
  `PowBlockProvider` is a new trait
  (in `crates/pharos-fork-choice/src/pow_block.rs`) with one method:
  `fn get_pow_block(&self, hash: Root) -> Result<Option<PowBlock>, PowBlockError>`.
  `validate_merge_block` MUST: (a) if
  `TERMINAL_BLOCK_HASH != Hash32::zero()`, assert
  `block.body.execution_payload.parent_hash == TERMINAL_BLOCK_HASH`
  and assert the current epoch ≥
  `TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH`; (b) otherwise fetch
  `pow_block = pow_block_provider.get_pow_block(payload.parent_hash)?`
  and `pow_parent = pow_block_provider.get_pow_block(pow_block.parent_hash)?`,
  then call `is_valid_terminal_pow_block(pow_block, pow_parent)`
  which checks `pow_block.total_difficulty >= TTD` AND
  `pow_parent.total_difficulty < TTD`. Failure returns
  `OnBlockError::InvalidTerminalPowBlock`. Cite
  `specs/bellatrix/fork-choice.md:303-304` + `:200-260`
  (`validate_merge_block` body) + `:170-190`
  (`is_valid_terminal_pow_block`). Define `PowBlock`
  (`{ block_hash: Root, parent_hash: Root, total_difficulty: U256 }`)
  in `crates/pharos-fork-choice/src/pow_block.rs`. The production
  `PowBlockProvider` impl lives in `pharos-node` (Task 4.6b) and
  wraps `EngineHandle::get_block_by_hash`; conformance uses an
  in-memory `HashMap<Root, PowBlock>` impl. Spec-test fixtures
  exercising this path: `bellatrix/fork_choice/on_merge_block/{all_valid,
  too_early_for_merge, too_late_for_merge, block_lookup_failed,
  block_lookup_failed_total_difficulty}`.
- [x] Task 4.4: Add a new RocksDB column family `payload_status` in
  `crates/pharos-storage/src/db.rs`. Extend `BlockTransition` with
  `pub payload_status: Option<(Root, PayloadStatus)>`; the write
  path stores `Root → u8` (discriminant). Add
  `pub fn Store::payload_status(&self, root: Root) -> Result<Option<PayloadStatus>, StorageError>`
  and `pub fn Store::payload_statuses_iter(&self) -> impl Iterator<Item=(Root, PayloadStatus)>`
  for startup rehydration.
- [x] Task 4.4a: Schema migration for the new column family. In
  `crates/pharos-storage/src/cf.rs`, update `pub fn all_cfs() -> [&'static str; 12]`
  to return 12 elements (was 11) and append `CF_PAYLOAD_STATUS`. In
  `crates/pharos-storage/src/db.rs`, bump `SCHEMA_VERSION` from `1`
  to `2` (forward-only migration matching the M3a pattern: opening
  an older DB returns `StorageError::SchemaMismatch` and ops must
  delete + resync; documented in the schema-version doc comment).
  Register the new CF in `RocksStore::open` by virtue of the
  expanded `all_cfs()` list (the existing
  `ColumnFamilyDescriptor` loop picks it up). Add a unit test in
  `crates/pharos-storage/src/db.rs::tests`: open a v1 DB, assert
  `SchemaMismatch { found: 1, expected: 2 }`; open a fresh DB,
  assert `payload_status` CF is queryable.
- [x] Task 4.5: Modify `crates/pharos-node/src/startup.rs::rehydrate_fork_choice_store`
  to iterate `payload_statuses_iter` and seed the in-memory
  `Store::payload_statuses` map. Test: write three statuses, restart,
  assert in-memory map matches.
- [x] Task 4.6: Create
  `crates/pharos-node/src/engine_driver.rs` exposing
  `pub async fn run_engine_driver_loop<E: EthSpec>(engine: EngineHandle, store: Arc<RwLock<pharos_fork_choice::Store<E>>>, mut head_rx: watch::Receiver<Option<HeadChange>>, mut payload_rx: mpsc::Receiver<NewPayloadRequest<E>>)`.
  Loop: `tokio::select!` between
  (a) `head_rx.changed()` → call
    `engine.forkchoice_updated(ForkchoiceUpdatedVersion::V1,
    ForkchoiceStateV1 { head_block_hash, safe_block_hash, finalized_block_hash },
    None)`; on `Invalid` status, call
    `store.write().mark_payload_status(head_root, PayloadStatus::Invalid)`
    and reattempt head selection (emits a fresh `HeadChange` on the next
    iteration);
  (b) `payload_rx.recv()` → call
    `engine.new_payload(NewPayloadVersion::V1, payload)`; map the
    response to `PayloadStatus`; call
    `store.write().mark_payload_status(block_root, status)`.
  Define `HeadChange { head_root, head_block_hash, safe_block_hash, finalized_block_hash }`.
- [x] Task 4.6b: Define `compute_safe_block_hash<E>(store) -> Hash32`
  and `compute_finalized_block_hash<E>(store) -> Hash32` in
  `crates/pharos-node/src/engine_driver.rs`. For M4a (no proposer-boost
  re-org logic, no safe-head heuristics):
  `safe_block_hash = execution_block_hash_at_root(store, store.justified_checkpoint.root).unwrap_or(Hash32::zero())`
  and
  `finalized_block_hash = execution_block_hash_at_root(store, store.finalized_checkpoint.root).unwrap_or(Hash32::zero())`.
  `execution_block_hash_at_root` reads the block from
  `store.blocks[root]`, downcasts to `BeaconBlock::Bellatrix`, and
  returns `body.execution_payload.block_hash`; for `Phase0` / `Altair`
  variants it returns `Hash32::zero()` (pre-merge has no EL block).
  Wire both into the `HeadChange` builder in the head-publish path
  (called from Task 4.8b's ingestion loop). Cite
  `specs/bellatrix/fork-choice.md:93-100` (`safe_block_hash`
  derivation). Document the M4a simplification (using the
  justified-checkpoint head's EL hash, not the
  `get_safe_execution_block_hash` re-org-aware variant) in
  `D-engine-head-driver` ADR (extend the ADR with one
  paragraph noting full `get_safe_execution_block_hash` is deferred
  to M11 alongside proposer-boost re-org logic).
- [x] Task 4.6c: Create the production `PowBlockProvider` impl
  `EnginePowBlockProvider` in `crates/pharos-node/src/pow_block.rs`
  wrapping `EngineHandle`. `fn get_pow_block(&self, hash)` calls
  `engine.get_block_by_hash(hash)?` and maps the
  `Option<BlockHeader>` to `Option<PowBlock>` by reading
  `block_hash`, `parent_hash`, `total_difficulty`. Wire it into the
  fork-choice `on_block` path: the node-side block-ingestion loop
  (Task 4.8b) passes `&EnginePowBlockProvider` into the
  `pharos_fork_choice::on_block` call.
- [x] Task 4.7: Modify `crates/pharos-node/src/host_impl.rs`: add a
  `tokio::sync::watch::Sender<Option<HeadChange>>` field and a
  `mpsc::Sender<NewPayloadRequest<E>>`. Expose
  `pub fn HostImpl::on_new_block(&self, block_root: Root, payload: ExecutionPayloadV1)`
  which sends on the payload channel (used by the
  `GossipValidator::validate_block` path once it's wired in M4b/M4c).
  Add `pub fn HostImpl::on_head_change(&self, change: HeadChange)`.
- [x] Task 4.8: Modify `crates/pharos-node/src/main.rs` to: (a) parse
  `--jwt-secret <path>`, `--execution-endpoint <url>` (default
  `http://127.0.0.1:8551`),
  `--execution-endpoint-secondary <url>` (optional);
  (b) load the JWT secret;
  (c) construct `EngineClient` instances and spawn `run_engine_actor`;
  (d) spawn `run_engine_driver_loop` with the head-change watch
  receiver wired from `HostImpl`; (e) wire the
  `ExecutionEngineHandle` (a thin sync wrapper over `EngineHandle`)
  into the STF entry path.
- [x] Task 4.8b: Create `crates/pharos-node/src/block_ingestion.rs`
  defining
  `pub async fn run_block_ingestion_loop<E: EthSpec>(mut event_rx: mpsc::Receiver<NetworkEvent>, host: Arc<HostImpl<E>>, fc_store: Arc<RwLock<pharos_fork_choice::Store<E>>>, execution_engine: ExecutionEngineHandle, pow_provider: Arc<EnginePowBlockProvider>, head_tx: watch::Sender<Option<HeadChange>>, payload_tx: mpsc::Sender<NewPayloadRequest<E>>) -> Result<(), IngestionError>`.
  Loop:
  (a) `event_rx.recv()` for `NetworkEvent::GossipMessage { topic, data, .. }`
  where `topic` is the `BeaconBlock` topic for the current fork
  (resolve via `host.fork_context()`);
  (b) decode SSZ bytes into `SignedBeaconBlock<E>` using the
  fork-context codec (already exists in `pharos-network`);
  (c) fetch `pre_state = store.read().block_states[block.parent_root].clone()`;
  (d) call
  `let post = tokio::task::spawn_blocking(move || state_transition(pre_state, &block, &execution_engine, true)).await??;`
  per the M3a `spawn_blocking` invariant;
  (e) acquire `fc_store.write()` and call
  `pharos_fork_choice::on_block(&mut store, &block, post.clone(), now, &pow_provider)`;
  (f) for Bellatrix blocks, push the payload onto `payload_tx` so the
  engine driver issues `engine_newPayloadV1`;
  (g) call `let head = pharos_fork_choice::get_head(&store)?;`
  release the lock; (h) build a `HeadChange { head_root, head_block_hash,
  safe_block_hash, finalized_block_hash }` using the helpers from
  Task 4.6b and send via `head_tx.send(Some(change))`.
  Define `IngestionError` in the same file (`thiserror`):
  `Decode`, `MissingParentState`, `StateTransition(StateTransitionError)`,
  `ForkChoice(OnBlockError)`, `Storage(StorageError)`, `Join(tokio::task::JoinError)`.
  Wire the loop into `pharos-node` main (extend Task 4.8 to
  `tokio::spawn(run_block_ingestion_loop(...))` after subscribing
  `event_rx` from `NetworkHandle::event_receiver()`).
- [x] Task 4.9: Add integration test
  `crates/pharos-node/tests/engine_driver.rs` (new): build a
  `HostImpl` with a mock `EngineClient` that returns
  `INVALID` for a specific payload; assert
  `store.payload_statuses` contains the corresponding root with
  `PayloadStatus::Invalid`; assert `get_head` skips that block.
- [x] Task 4.9b: In-process pipeline integration test. Create
  `crates/pharos-node/tests/engine_pipeline.rs`. The test stands up an
  in-process axum mock implementing `engine_newPayloadV1`,
  `engine_forkchoiceUpdatedV1`, `engine_exchangeCapabilities`,
  `eth_chainId` (return values configurable per fixture); drives ~16
  bellatrix fixture blocks through `block_ingestion_loop` → STF →
  `pharos_fork_choice::on_block` → `HeadChange` watch → engine driver
  → axum mock; asserts: (a) `engine_newPayloadV1` called exactly once
  per fixture block with matching `ExecutionPayloadV1`; (b)
  `engine_forkchoiceUpdated` called per head advance with the expected
  `(head, safe, finalized)`; (c) head advances 16 slots; (d) one
  fixture block whose payload the mock returns `INVALID` for is
  recorded in `store.payload_statuses` as `Invalid` and not selected
  by `get_head`; (e) no panics, no `tokio::time::timeout` failures
  across the run. Block fixtures generated by a small helper test
  function (deterministic interop keys, immediate-Bellatrix), kept
  in-test (no separate fixture binary). This replaces the M4a-internal
  "first merged sync" gate; real-process acceptance lives in M4d.
- [x] Task 4.10: **Checkpoint: Verify Phase 4 complete**.
  `cargo check --workspace` green; `cargo test -p pharos-fork-choice`
  green; `cargo test -p pharos-node` includes the engine driver
  integration test (Task 4.9) and the in-process pipeline test
  (Task 4.9b). List each task and status.

**Commit boundary**: `feat(m4a): phase 4 — fork-choice ↔ engine
wiring + invalid-payload tracking + head driver`.

### Phase 5 — Bellatrix conformance + Engine API conformance scaffold
Why this phase: with Bellatrix containers + STF + Engine client in
place, conformance dispatchers wire the test fixtures.

- [x] Task 5.1: Extend
  `crates/pharos-conformance/src/operations.rs` with Bellatrix
  sub-categories: same six as altair (`attestation`, `attester_slashing`,
  `block_header`, `deposit`, `proposer_slashing`, `voluntary_exit`,
  `sync_aggregate`) plus `execution_payload` (NEW for Bellatrix). Each
  loads pre-state as `bellatrix::BeaconState`, applies the op (passing
  `NullExecutionEngine` for `execution_payload`), compares post. Wire
  dispatcher entries `run_operations_bellatrix_mainnet` /
  `run_operations_bellatrix_minimal`.
- [x] Task 5.2: Extend
  `crates/pharos-conformance/src/{sanity,finality,random,rewards,epoch_processing}.rs`
  with bellatrix preset dispatchers following the altair pattern.
- [x] Task 5.3: Extend
  `crates/pharos-conformance/src/transition.rs` with a
  Bellatrix-from-Altair walker: `tests/{preset}/bellatrix/transition/core/pyspec_tests/<case>/`,
  loads pre-state as `altair::BeaconState`, applies `fork_block`
  altair blocks, calls `upgrade_to_bellatrix`, applies remaining
  bellatrix blocks. `run_transition_bellatrix_mainnet` /
  `run_transition_bellatrix_minimal`.
- [x] Task 5.4: Extend
  `crates/pharos-conformance/src/ssz_static.rs` to add Bellatrix
  containers (`ExecutionPayload`, `ExecutionPayloadHeader`,
  `BeaconBlockBody`, `BeaconBlock`, `SignedBeaconBlock`,
  `BeaconState`). Add `run_ssz_static_bellatrix_mainnet` /
  `run_ssz_static_bellatrix_minimal` row entries.
- [x] Task 5.5: Create `crates/pharos-conformance/src/engine.rs`
  exposing `pub fn run_engine_yaml_suite(specs_dir: &Path) -> CategoryResult`
  per `D-engine-conformance-runner`. Walks
  `~/dev/execution-apis/src/engine/openrpc/methods/*.yaml`; for each
  example pair in each method's `examples:` block: spin up axum mock,
  drive `EngineClient` via `tokio::runtime::Runtime::new`, assert
  request matches and response parses. For M4a, scope to Bellatrix
  (Paris) V1 examples only: `forkchoice.yaml` V1 examples,
  `payload.yaml` V1 examples, `capabilities.yaml`. Skip
  `engine_forkchoiceUpdatedV2` examples (Capella+, M5) and any
  `engine_newPayloadV2+` / `engine_getPayloadV2+` examples — same
  pattern as Capella+ payload YAMLs. Each skipped example is reported
  with reason `"capella+ method, scoped out of m4a"` in the
  `CategoryResult.skip_reasons` map.
- [x] Task 5.5b: Extend
  `crates/pharos-conformance/src/fork_choice.rs` with Bellatrix
  support and dispatch entries. Sub-tasks:
  (a) Add `pow_block` step-type handler: when the YAML lists a step
  of shape `{ pow_block: <name> }`, load
  `tests/{preset}/bellatrix/fork_choice/<case>/<name>.ssz_snappy`
  and **SSZ-snappy decode** it (reuse the same framed-snappy +
  SSZ-decode helper already used by the block/state fixture loaders
  in `pharos-conformance`). `PowBlock` is a simple SSZ container
  with `block_hash: Hash32`, `parent_hash: Hash32`,
  `total_difficulty: Uint256`. Insert into a local
  `HashMap<String /* name suffix */, PowBlock>` keyed by the name
  suffix. The map is passed as the `PowBlockProvider` for that
  case (an in-memory impl over the map).
  (b) Add `should_override_forkchoice_update` check-type handler:
  the YAML check key `should_override_forkchoice_update: bool`
  triggers a call to
  `pharos_fork_choice::should_override_forkchoice_update(&store)`
  and asserts equality. Phase 0 already implements this from the
  fork-choice public surface; if missing, add the function as a
  thin wrapper returning `false` (proposer-boost re-orgs are M11)
  and gate the assertion on the YAML expecting `false`.
  (c) Add the `on_merge_block` check-type handler:
  `{ on_merge_block: { block: <name>, valid: bool } }` calls
  `on_block` with the named block and asserts the result matches
  `valid`. On failure path, asserts `OnBlockError::InvalidTerminalPowBlock`
  or `OnBlockError::PowBlockNotFound`.
  (d) Wire `run_fork_choice_bellatrix_mainnet` and
  `run_fork_choice_bellatrix_minimal` dispatchers covering
  sub-categories `get_head`, `get_proposer_head`, `on_block`,
  `ex_ante`, `should_override_forkchoice_update`, `on_merge_block`.
  Minimal preset additionally has `reorg` and `withholding`
  sub-categories (mainnet does not); include them in the
  `run_fork_choice_bellatrix_minimal` dispatcher. These use only
  `tick`/`block`/`checks` step types already handled by the
  existing phase0/altair runner — no new step handlers required.
  Sub-category `on_merge_block` cases that exercise paths requiring
  a live engine mock (none currently — the in-memory `PowBlock`
  map covers the spec fixtures) MUST NOT be auto-skipped; only skip
  individual cases that the in-memory provider genuinely can't
  service, and emit the skip reason (e.g.
  `"requires live engine mock — m4a in-memory provider"`).
  `get_head`, `get_proposer_head`, `on_block`, `ex_ante` MUST
  produce real pass/fail counts (no blanket skip).
- [x] Task 5.6: Modify `crates/pharos-conformance/src/lib.rs::run` to
  add: (a) one row per `(bellatrix, category, preset)` triple
  following the altair dispatch block layout. Categories include
  `transition`, `ssz_static`, `operations`, `epoch_processing`,
  `sanity`, `finality`, `random`, `rewards`, AND `fork_choice`
  (calling `run_fork_choice_bellatrix_{preset}` from Task 5.5b);
  (b) one row for `("engine", "yaml", "-")` calling
  `engine::run_engine_yaml_suite`. Resolve the engine specs dir by
  checking `~/dev/execution-apis/src/engine/openrpc/methods/`; if
  absent, the row is skipped (placeholder count).
- [x] Task 5.7: Run
  `cargo run -p pharos-conformance -- --write`. Inspect
  `docs/conformance.md`: every bellatrix row (including the new
  `bellatrix/fork_choice/*` rows) must have non-zero `pass`. For
  `bellatrix/fork_choice`, `get_head`, `get_proposer_head`,
  `on_block`, `ex_ante` MUST show `fail = 0`; `on_merge_block`
  MUST show `fail = 0` for cases serviced by the in-memory
  `PowBlock` provider. For any row with `fail > 0`, debug the
  offending path; do NOT relax the assertion. List remediation
  status of each red row in this task. Engine row should pass for
  the Bellatrix-scoped V1 method examples.
- [x] Task 5.8: **Checkpoint: Verify Phase 5 complete**.
  `cargo test --workspace` green; `docs/conformance.md` shows bellatrix
  rows with non-zero counts + engine yaml row pass count > 0. List
  each task and status.

**Commit boundary**: `feat(m4a): phase 5 — Bellatrix conformance +
Engine API conformance scaffold`.

### Phase 6 — Network backpressure (replace try_send drop-on-overflow)
Why this phase: scoped channel-policy change; keep it in its own
phase so the diff is small and the integration test is focused.

- [x] Task 6.1: Replace the `try_send` body of
  `crates/pharos-network/src/network/mod.rs:1163` (`emit_event`) with
  the bounded-with-timeout pattern. Signature change: the function
  becomes `async fn emit_event(&self, ev: NetworkEvent)` since it
  awaits the channel; OR (preferred for the existing callers that
  are inside the sync swarm-event handler) keep the function sync and
  use `self.event_tx.try_send(ev)` first, falling back to
  `tokio::runtime::Handle::current().block_on(timeout(Duration::from_secs(1), self.event_tx.send(ev)))`
  on `Full`. Pick the preferred path and document the rationale in the
  function doc comment per `D-network-backpressure`. The other
  `try_send` site (the shutdown path at
  `crates/pharos-network/src/network/mod.rs:300`) gets the same
  treatment.
- [x] Task 6.2: Audit every other `try_send` / `tx.send` in
  `crates/pharos-network/src/` (run `rg -n "try_send|tx\\.send" crates/pharos-network/`).
  Confirm `NetworkCommand` send sites (in `crates/pharos-network/src/handle.rs`)
  already use `send().await` with no timeout per
  `D-network-backpressure`; if any use `try_send`, swap them.
- [x] Task 6.3: Bump the event-channel capacity in
  `crates/pharos-network/src/network/mod.rs` (or wherever
  `mpsc::channel(N)` is constructed for `event_tx`) from the M2
  default to a configurable `NetworkBuilder::event_channel_capacity(usize)`
  (default 1024). Document the trade-off in the builder doc comment.
- [x] Task 6.4: Add integration test
  `crates/pharos-network/tests/backpressure.rs` (new): build a network
  with a tiny event channel (capacity 2), generate 100 events at the
  swarm; the consumer side reads at 10 events/second; assert no
  events are dropped (the producer should `await` on full channel,
  not `try_send`-then-drop). Also assert that if the consumer is
  fully stalled, after 1.5 seconds the warn log fires and the
  producer continues (timeout path).
- [x] Task 6.5: **Checkpoint: Verify Phase 6 complete**.
  `cargo test -p pharos-network --tests` green 10 consecutive runs.
  `rg -n "try_send" crates/pharos-network/` returns zero hits (or
  only intentional, documented exceptions). List each task and
  status.

**Commit boundary**: `refactor(m4a): phase 6 — bounded backpressure
on network event channel (replaces try_send drop-on-overflow)`.

### Phase 7 — Decisions log + final audit
Why this phase: same cadence as M3b Phase 9.

- [x] Task 7.1: Append to `docs/decisions.md` the M4a ADRs:
  `D-engine-method-dispatch`, `D-engine-head-driver`,
  `D-payload-status-store`, `D-network-backpressure`,
  `D-engine-conformance-runner`, `D-bellatrix-state-shape`. One
  paragraph each, mirroring M3b D-* style. Update the table of
  contents.
- [x] Task 7.2: Run `cargo fmt --all` and
  `cargo clippy --workspace --all-targets -- -D warnings`. Fix every
  new warning; do not blanket-allow.
- [x] Task 7.3: Run
  `mkdir -p target/test-logs && cargo test --workspace 2>&1 | tee target/test-logs/m4a-full.log`
  in the background per `CLAUDE.md` long-running-tests policy; tail
  for "test result: ok" on every crate. Then run
  `cargo test -p pharos-network --tests` 10 consecutive runs (pipe
  each to a separate log file in `target/test-logs/`). All green.
- [x] Task 7.4: Run
  `cargo run -p pharos-conformance -- --write` and commit
  `docs/conformance.md`. Verify all bellatrix rows present with
  non-zero `pass` and `fail = 0`; verify engine row pass count > 0.
- [x] Task 7.5: Update root `README.md`,
  `CLAUDE.md` ("M4a status" subsection mirroring the M3b status entry,
  listing the closed items + the ADRs added + the deferred items),
  and `docs/roadmap.md` M4 section to mark M4a complete. Move M4a
  items above M4b in the timeline.
- [x] Task 7.6: **Spec-vs-code line audit against
  `~/dev/execution-apis/src/engine/paris.md` and
  `~/dev/execution-apis/src/engine/authentication.md` and
  `~/dev/consensus-specs/specs/bellatrix/beacon-chain.md`**. Same
  methodology as M3b Task 9.7. Append `## Spec audit (Task 7.6)` to
  this plan with one bullet per MUST / SHOULD / MAY clause:
  IMPLEMENTED (file:line) / DEFERRED-TO-M<N> / GAP. Anything GAP must
  be filed as a deferred item in roadmap or fixed in M4a before
  close.
- [x] Task 7.7: Bump workspace `version` in `/Cargo.toml` from
  `0.2.0` to `0.3.0`. Commit as
  `chore(version): bump workspace to 0.3.0 for M4a release`. Tag
  `v0.3.0` after the final audit (Task 7.8) lands.
- [x] Task 7.8: **Final Audit**. Re-read every task in Phases 0–7.
  For each, verify the implementation exists in the codebase (file
  present, function present, test present). Cross-check
  `docs/decisions.md` against the seven M4a ADRs. List any gaps. All
  gaps must be resolved before reporting M4a complete. Tag `v0.3.0`
  only after this audit shows zero gaps.

**Commit boundary**: `docs(m4a): phase 7 — decisions log + final
audit + version bump` (and tag `v0.3.0`).

## Edge Cases & Risks

- **R1 — `engine_newPayloadV1` blocking the slot.** A slow EL keeps
  the CL waiting on the HTTP call; the slot expires, the block can't
  be gossiped. Mitigation: per `D-engine-head-driver`, fork-choice is
  sync and never blocks on HTTP; the driver loop calls `new_payload`
  asynchronously. STF treats `NotValidated` as eligible, so the
  block enters the chain even if the EL hasn't confirmed yet (we
  back-fill the status when the response arrives). Spec-compliant
  per `paris.md` payload validation section.
- **R2 — JWT clock skew.** EL rejects tokens with `iat` more than 60
  seconds off. Mitigation: token issued just before send via
  `SystemTime::now()`. If the CL and EL clocks drift, ops needs to
  install NTP; tracked but not auto-fixed.
- **R3 — Invalid-flag persistence drift.** Restart loses the
  in-memory `payload_statuses` map. Mitigation: addressed by Tasks
  4.4 + 4.5 (RocksDB CF + rehydrate); regression test in Phase 4.
- **R4 — Backpressure timeout under legitimate load.** A
  surge of network events (peer-flood attack) trips the 1-second
  timeout and drops events. Mitigation: addressed by Task 6.3
  (configurable capacity); the 1-second is a fallback, not the
  primary line of defence. Real peer scoring (M11) caps the surge.
- **R5 — Bellatrix state-bloat in the fork enum.** Adding
  `latest_execution_payload_header` (the field is fixed-size: 32 +
  20 + 32 + 32 + 256 + 32 + 8 + 8 + 8 + 8 + 32 + 32 + 32 = 532 bytes
  before the `extra_data` `ByteList` discriminant, conservatively
  ~600 bytes after padding) onto the Bellatrix variant grows the
  enum discriminant size. Earlier (Phase 0 / Altair) variants pad to
  the Bellatrix size. Mitigation: accepted per
  `D-bellatrix-state-shape`. Confirm the exact pad with
  `std::mem::size_of` in a doc-test under
  `crates/pharos-types/src/state.rs` after Phase 1 lands; if it
  exceeds 1 KiB pad we reconsider `Box`-ing in M5/M11. Box-vs-inline
  trade-off re-evaluated in M11 alongside the persistent-tree swap.
- **R6 — Devnet flakiness.** ethrex startup race vs pharos startup;
  jwt file read race; port collision. Mitigation: addressed in Task
  7.4 (script waits for ethrex `--authrpc` ready line before
  starting pharos); port is hard-coded to 8551 (devnet only); jwt
  file is generated by mktemp atomically. Script exits non-zero
  on timeout so CI can detect.
- **R7 — `process_execution_payload` accepting bad timestamps.** The
  spec mandates `payload.timestamp == compute_timestamp_at_slot(state, state.slot)`.
  Mistake here lets a malicious EL or block proposer slip an invalid
  block past fork choice. Mitigation: spec-test coverage via
  `bellatrix/operations/execution_payload` (Task 5.1) exercises the
  full assertion matrix; addressed by Task 2.3 with explicit
  per-line spec citation.
- **R8 — Engine API conformance runner brittleness.** YAML examples
  in `execution-apis/src/engine/openrpc/methods/*.yaml` use canonical
  JSON formatting that may not match `serde_json`'s default
  formatting bytewise. Mitigation: addressed by Task 5.5 — assert
  on parsed JSON values (`serde_json::Value` equality) not byte
  equality. Field order is irrelevant to JSON semantics.
- **R9 — Method-version explosion at Capella+.** Adding V2/V3/V4 of
  each method per fork creates a combinatorial space.
  Mitigation: per `D-engine-method-dispatch`, version is an enum
  arg, not a separate method; the driver picks per fork. Each new
  fork is one new arm per existing method, not a rewrite.
- **R10 — `terminal_total_difficulty` semantics post-merge.** Mainnet
  Bellatrix fork epoch is after the EL merge already happened
  (TTD-triggered). For devnet we set TTD=0 (immediate merge). The
  M4a STF path handles both cases via `is_merge_transition_complete`
  per spec. Mitigation: `tests/fixtures/devnet/` uses TTD=0; mainnet
  config (M11 production) uses the canonical
  58750000000000000000000.
- **R11 — Network event channel deadlock.** Switching `emit_event`
  to `send().await` on a sync swarm-event callback could deadlock
  if the consumer holds a lock on something the producer needs.
  Mitigation: addressed by Task 6.1 — the `try_send`-first path
  catches the common case; only on `Full` does it block; lock
  ordering audit (Task 6.2) confirms no producer-consumer lock
  cycle.
- **R12 — Spec-test pin must contain Bellatrix fixtures.** If
  `SPEC_TESTS_TAG` doesn't carry `tests/<preset>/bellatrix/`, Phase
  5 reports zero counts. Mitigation: addressed by Task 0.1
  (verify presence; bump pin if needed). v1.7.0-alpha.8 is known
  to include Bellatrix; no bump required.
- **R13 — ExecutionEngine sync wrapper deadlock.** STF calls
  `notify_new_payload` synchronously through `ExecutionEngineHandle`,
  which pushes the request onto the engine actor's mpsc and awaits
  the oneshot reply via `Arc<tokio::runtime::Runtime>::block_on`.
  `block_in_place` would NOT work here: it requires the calling
  thread to be a tokio worker, but `spawn_blocking` threads are not
  workers. Mitigation: STF runs inside `tokio::task::spawn_blocking`
  (M3a invariant). `runtime.block_on` on the engine's shared runtime
  from a non-worker thread is safe and well-defined. The deadlock
  shape to watch is if the engine actor were itself starved on the
  same runtime; we mitigate by always spawning the actor with
  `runtime.spawn(...)` (worker pool independent of the calling
  thread). Test: Task 2.3 unit test exercises the
  `NullExecutionEngine` path; Task 3.11 covers the `EngineHandle`
  reply path against the mock server; the real-engine path is
  exercised by the M4d hand-rolled Lighthouse+ethrex acceptance.

## Acceptance Criteria
- `cargo check --workspace` and
  `cargo clippy --workspace --all-targets -- -D warnings` green.
- `cargo test --workspace` green;
  `cargo test -p pharos-network --tests` passes 10 consecutive runs.
- `cargo test -p pharos-engine` green (Phase 3 mock-server tests).
- `cargo test -p pharos-node` green (Phase 4 engine-driver
  integration test).
- `cargo run -p pharos-conformance -- --write` writes a
  `docs/conformance.md` with every bellatrix row populated (non-zero
  `pass`, `fail = 0` for all `bellatrix/{transition, ssz_static,
  operations, epoch_processing, sanity, finality, random, rewards,
  fork_choice}` × `{mainnet, minimal}` pairs); for
  `bellatrix/fork_choice`, sub-categories `get_head`,
  `get_proposer_head`, `on_block`, `ex_ante` MUST have non-zero
  `pass` and `fail = 0`; `on_merge_block` and
  `should_override_forkchoice_update` MUST have non-zero `pass`
  (skipped cases allowed with documented reason); engine yaml row
  pass count > 0 for Bellatrix V1 method examples.
- `bash scripts/devnet-merged.sh` exits 0 in two consecutive runs;
  `target/devnet/pharos.log` contains ≥ 32 distinct
  `"merged sync progressing"` lines; `target/devnet/ethrex.log` shows
  `VALID` responses to `engine_newPayloadV1` calls.
- `docs/devnet-run-m4a.md` artefact present and committed.
- `docs/decisions.md` lists all 7 M4a D-* ADRs.
- `Cargo.toml` workspace version is `0.3.0`; git tag `v0.3.0`
  exists.

## Open Questions

Locked-in resolutions (no further input required):
- **Q-engine-transport** — LOCKED. HTTP only for M4a (per roadmap
  `~/dev/pharos/docs/roadmap.md:670-671`). IPC + WebSocket deferred
  indefinitely; HTTP covers ethrex + reth + geth + nethermind.
- **Q-jwt-secret-source** — LOCKED. File path only (`--jwt-secret <path>`).
  No env var, no inline hex. Matches ethrex / reth / geth ops norms.
- **Q-fcu-cadence** — LOCKED. Every head change triggers an
  `engine_forkchoiceUpdated`; idle slot fcU (head unchanged) is NOT
  sent. The EL doesn't need it to keep the chain alive; we trade a
  spec-compliant idle ping for less wire traffic. Reconsidered in M11
  if ELs complain (none have so far).
- **Q-payload-attributes-on-fcu** — LOCKED. Only the proposer-side CL
  sends `PayloadAttributesV1` on fcU (to trigger payload build). M4a's
  node has no validator client attached (VC is M8); so M4a always
  sends `attributes: None`. M8 wires the proposer-side path.
- **Q-getpayload-when** — LOCKED. M4a does NOT call
  `engine_getPayloadV1`. That's the proposer-side path; M4a is a
  follower-only node. The method is implemented in `EngineClient` for
  M8 consumers; M4a's driver loop never invokes it. Conformance row
  (Phase 5) still tests it.
- **Q-exchange-capabilities-cadence** — LOCKED. Called once on startup
  (after the engine actor is up). Cached for the process lifetime.
  No periodic re-fetch; if the EL is restarted with new capabilities,
  the CL needs a restart too — acceptable for devnet, revisited M11.

Still open (default behaviour applies unless overridden):
- **Q-bellatrix-fork-epoch-on-minimal**: minimal preset
  `BELLATRIX_FORK_EPOCH = 0` is the simplest devnet config (immediate
  Bellatrix). But the spec-test `bellatrix/transition/` fixtures
  require a non-zero pre-Bellatrix run. Confirmed by inspecting
  `~/.cache/pharos-spec-tests/tests/minimal/bellatrix/transition/`:
  fixtures encode their own `fork_block` so the preset value isn't
  required to be > 0 for fixture runs. **Recommendation**: keep
  minimal `BELLATRIX_FORK_EPOCH = 0`; tests provide their own override.
- **Q-engine-method-future-versions**: when M5 adds Capella V2 (e.g.
  `engine_newPayloadV2`), should the existing
  `NewPayloadRequest::V1` carry over verbatim, or does the V1 request
  type change shape across forks? Inspecting
  `~/dev/execution-apis/src/engine/shanghai.md`: V1's structure is
  stable; V2 strictly adds fields (`withdrawals`). **Recommendation**:
  V1 stays exactly as defined here; V2/V3/V4 are additive new
  variants. No retroactive churn.
- **Q-mock-http-server-port-allocation**: `axum` server binding to
  `127.0.0.1:0` returns the OS-assigned port; if the conformance
  binary runs in parallel with other binds to ephemeral ports
  (e.g. parallel `cargo test`), no collision because each test owns
  its socket. **Recommendation**: no special handling; if flakes
  appear, switch to a static high port range gated by an env var.

## ADR keys added (Task 7.1)
- `D-engine-method-dispatch`
- `D-engine-head-driver`
- `D-payload-status-store`
- `D-network-backpressure`
- `D-engine-conformance-runner`
- `D-bellatrix-state-shape`

## Spec audit (Task 7.6)

Sources: `~/dev/execution-apis/src/engine/paris.md`,
`~/dev/execution-apis/src/engine/authentication.md`,
`~/dev/consensus-specs/specs/bellatrix/beacon-chain.md`.

One bullet per MUST / SHOULD / MAY clause or normative structural requirement.

---

### `execution-apis/src/engine/paris.md`

#### ForkchoiceStateV1

- **[MUST] `safeBlockHash` MUST be equal to or an ancestor of `headBlockHash`** (paris.md:65):
  The CL sends `safe_block_hash` derived from the justified checkpoint's execution
  block hash (`D-engine-head-driver` M4a simplification). This is always an ancestor
  of or equal to `headBlockHash` on the canonical chain (justified checkpoint is always
  behind or equal to the head). Full reorg-aware walk deferred.
  **IMPLEMENTED** — `crates/pharos-node/src/engine_driver.rs` (`run_engine_driver_loop`,
  `safe_block_hash` derivation). DEFERRED-TO-M11 for full `get_safe_execution_block_hash`.

#### Payload validation (routines)

- **[MAY] Client MAY obtain parent state by executing ancestors** (paris.md:99):
  EL-side behaviour; not a CL obligation. Pharos passes the payload to the EL and
  trusts the EL to do this.
  **IMPLEMENTED** (delegated to EL via `engine_newPayloadV1`).

- **[MUST] Ancestors of a payload obtained by executing parent MUST also pass validation** (paris.md:99):
  EL-side behaviour; CL delegates.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] Validate PoW terminal block conditions for ancestors** (paris.md:101):
  EL-side behaviour; CL delegates.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] `INVALID` response on terminal block failure, zero latestValidHash** (paris.md:101):
  EL-side response format; CL consumes `PayloadStatus::Invalid` from the EL response.
  **IMPLEMENTED** — `crates/pharos-engine/src/types.rs:78-84` (`PayloadStatusV1` parsing),
  `crates/pharos-node/src/engine_driver.rs` (status mapping).

- **[MUST] Descendants of invalid terminal block MUST be deemed INVALID** (paris.md:101):
  EL-side behaviour; CL marks any block whose `newPayload` returns `INVALID` via
  `mark_payload_status`.
  **IMPLEMENTED** — `crates/pharos-fork-choice/src/store.rs:137-138`.

- **[MUST] Validate payload against block header and execution environment rules** (paris.md:103):
  EL-side behaviour; CL delegates.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] VALID response with `latestValidHash = payload.blockHash` on success** (paris.md:104):
  EL-side response format; CL handles it.
  **IMPLEMENTED** — `crates/pharos-engine/src/types.rs`.

- **[MUST] INVALID response with `latestValidHash = validHash` on failure** (paris.md:105):
  EL-side response format; CL handles `INVALID` status.
  **IMPLEMENTED** — `crates/pharos-node/src/engine_driver.rs`.

- **[MUST NOT] Do NOT surface INVALID payload over API/p2p** (paris.md:112):
  CL excludes `Invalid`-marked roots from fork choice via `filter_block_tree`.
  **IMPLEMENTED** — `crates/pharos-fork-choice/src/get_head.rs:274-276`.

- **[MUST] Idempotent validity: INVALID(INVALID_BLOCK_HASH) MUST NOT become VALID** (paris.md:114):
  `mark_payload_status` stores the status; `filter_block_tree` reads it. Once `Invalid`
  is stored in the RocksDB `CF_PAYLOAD_STATUS` CF, it persists.
  **IMPLEMENTED** — `crates/pharos-storage/src/db.rs:138-155` + `crates/pharos-fork-choice/src/store.rs:137-138`.

- **[MAY] Status MAY change from INVALID to SYNCING/ACCEPTED** (paris.md:114):
  Not implemented (EL-side behaviour). CL would overwrite via `mark_payload_status`.
  **IMPLEMENTED** (pass-through; EL controls status escalation).

- **[MAY] Provide additional details via `validationError`** (paris.md:116):
  EL-side. CL logs `validationError` on `INVALID` from both `newPayload` and `fcU`.
  **IMPLEMENTED** — `crates/pharos-node/src/engine_driver.rs` (warn log on INVALID).

- **[MUST NOT] Canonical-chain validation MUST NOT be affected by side-branch sync** (paris.md:118):
  EL-side constraint. Pharos sends `engine_newPayloadV1` per block; EL is responsible.
  **IMPLEMENTED** (delegated to EL).

#### Payload building (routines)

- **[MUST] Set payload field values per parameters** (paris.md:133): EL-side.
  **IMPLEMENTED** (EL-side; CL calls `fcU` with `PayloadAttributesV1`; M4a sends `None`
  because no validator client is attached yet — per `Q-payload-attributes-on-fcu`).

- **[MAY] EL MAY deviate `feeRecipient` from `suggestedFeeRecipient`** (paris.md:133): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[SHOULD] Build initial payload with empty transaction set** (paris.md:135): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[SHOULD] Update payload with local mempool state** (paris.md:137): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[SHOULD] Stop updating after `engine_getPayload` or SLOT_DURATION_MS** (paris.md:139): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] Begin a new build process if `PayloadAttributes` differ** (paris.md:141): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] New build process uniquely identified by returned `payloadId`** (paris.md:142): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[SHOULD NOT] SHOULD NOT restart existing build process with same attributes** (paris.md:144): EL-side.
  **IMPLEMENTED** (delegated to EL).

#### engine_newPayloadV1

- **[MUST] Validate all transactions have non-zero length** (paris.md:164):
  CL-side: `verify_and_notify_new_payload` default impl checks `tx.is_empty()` before
  calling `notify_new_payload`.
  **IMPLEMENTED** — `crates/pharos-stf/src/bellatrix/execution_engine.rs:89-96`.

- **[MUST] Run transaction-length validation in all cases** (paris.md:164):
  The check runs unconditionally in `verify_and_notify_new_payload`.
  **IMPLEMENTED** — `crates/pharos-stf/src/bellatrix/execution_engine.rs:89-96`.

- **[MUST] Validate `blockHash` = `Keccak256(RLP(ExecutionBlockHeader))`** (paris.md:166):
  CL delegates this to the EL: `notify_new_payload` calls `engine_newPayloadV1`; the
  EL returns `INVALID_BLOCK_HASH` on failure. CL does NOT recompute Keccak256/RLP.
  **IMPLEMENTED** (delegated to EL; `INVALID_BLOCK_HASH` handled by
  `crates/pharos-node/src/engine_driver.rs`).

- **[MUST] Run blockHash validation in all cases** (paris.md:166):
  Delegated to EL unconditionally.
  **IMPLEMENTED** (delegated to EL).

- **[MAY] Initiate sync if requisite data is missing** (paris.md:168): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] Validate payload if it extends canonical chain and data is available** (paris.md:170): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MAY NOT] MAY NOT validate if payload doesn't belong to canonical chain** (paris.md:172): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] Respond with correct `PayloadStatusV1`** (paris.md:174-186):
  EL returns `PayloadStatusV1`; CL parses and maps to `PayloadStatus`.
  **IMPLEMENTED** — `crates/pharos-engine/src/client.rs:143-153`,
  `crates/pharos-engine/src/types.rs:69-76`.

- **[MUST] Respond with error object on unrelated failure** (paris.md:187):
  `EngineClient::rpc_call` returns `EngineError` on HTTP/JSON-RPC errors.
  **IMPLEMENTED** — `crates/pharos-engine/src/client.rs:86-130`.

#### engine_forkchoiceUpdatedV1

- **[MAY] Initiate sync if head is unknown** (paris.md:211): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MAY] Skip forkchoice update / [MUST NOT] begin payload build if head is ancestor of finalized** (paris.md:213): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] Validate PoW terminal block conditions for head** (paris.md:215): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST NOT] Update forkchoice or begin payload build if PoW terminal check fails** (paris.md:215): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] Ensure validity of head payload before updating forkchoice** (paris.md:217): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MAY] Validate head payload while processing fcU** (paris.md:217): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST NOT] Update forkchoice or begin payload build if head validation fails** (paris.md:217): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] Return `-38002: Invalid forkchoice state` if safe/finalized don't belong to head chain** (paris.md:219): EL-side.
  CL handles the `-38002` error code by logging a warning.
  **IMPLEMENTED** — `crates/pharos-engine/src/error.rs` + `crates/pharos-node/src/engine_driver.rs`.

- **[MUST] Return `-38006: Too deep reorg` if reorg exceeds limitation** (paris.md:221): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] Update forkchoice state if head and finalized are VALID** (paris.md:223): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] Process POS_FORKCHOICE_UPDATED atomically** (paris.md:225): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] Process `payloadAttributes` after applying forkchoice** (paris.md:227): EL-side.
  CL sends `payloadAttributes: None` in M4a (no VC attached per `Q-payload-attributes-on-fcu`).
  **IMPLEMENTED** (M4a sends `null`; DEFERRED-TO-M8 for non-null `payloadAttributes`).

- **[MUST NOT] Roll back forkchoice update on `payloadAttributes` validation failure** (paris.md:233): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] Respond with correct status** (paris.md:235-243): EL returns; CL maps to `PayloadStatus`.
  **IMPLEMENTED** — `crates/pharos-engine/src/client.rs:155-166`,
  `crates/pharos-node/src/engine_driver.rs`.

- **[MUST] Respond with error on unrelated failure** (paris.md:245): EL error propagated.
  **IMPLEMENTED** — `crates/pharos-engine/src/client.rs:86-130`.

- **[MUST NOT] FCU-VALID MUST NOT overwrite prior newPayload-INVALID** (M4a design):
  CL only overwrites `PayloadStatus` from FCU when response is `INVALID`/`INVALID_BLOCK_HASH`.
  **IMPLEMENTED** — `crates/pharos-node/src/engine_driver.rs` (conditional status update logic).

#### engine_getPayloadV1

- **[MUST] Return most recent version of payload for given `payloadId`** (paris.md:263): EL-side.
  M4a CL does not call `engine_getPayloadV1` (no validator client; per `Q-getpayload-when`).
  **DEFERRED-TO-M8** (proposer path wired with VC).

- **[MUST] Return `-38001: Unknown payload` if `payloadId` doesn't exist** (paris.md:265): EL-side.
  **DEFERRED-TO-M8** (same as above).

- **[MAY] Stop build process after serving** (paris.md:267): EL-side.
  **DEFERRED-TO-M8**.

#### engine_exchangeTransitionConfigurationV1

- **[MUST] EL responds with configurable settings per EIP-3675** (paris.md:285): EL-side.
  CL calls `exchange_transition_configuration` to compare values.
  **IMPLEMENTED** — `crates/pharos-engine/src/client.rs:184-192`.

- **[SHOULD] EL surface error if local config mismatches received** (paris.md:287): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[SHOULD] CL surface error if local config mismatches response** (paris.md:289):
  `EngineClient::exchange_transition_configuration` returns the EL's config; `pharos-node`
  should compare TTD. Currently the method is implemented but the comparison + user-visible
  warning is not wired in the node.
  **GAP** — no TTD mismatch warning logged from `pharos-node`. Deferred to M4b/M11 (devnet
  only uses TTD=0 which always matches; production path deferred per `Q-engine-transport`
  locked resolution). Tracked as a deferred item in `docs/roadmap.md` M4b section.

- **[SHOULD] CL SHOULD poll this endpoint every 60 seconds** (paris.md:291):
  `exchange_transition_configuration` is called once on startup; no 60-second polling loop.
  **GAP** — polling loop not implemented. Deferred to M4b/M11.

- **[SHOULD] EL surface error if no request received in 120 seconds** (paris.md:293): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MAY] CL MAY use `0` for `terminalBlockNumber` if absent** (paris.md:295):
  `TransitionConfigurationV1::terminal_block_number` is set to `"0x0"` in the request.
  **IMPLEMENTED** — `crates/pharos-engine/src/types.rs:143-162`.

- **[MUST] CL and EL MUST use `2**256-2**10` for TTD if no TTD value decided** (paris.md:297):
  The `TransitionConfigurationV1` struct stores TTD as a `U256` string; callers set the
  value from `RuntimeConfig.terminal_total_difficulty`.
  **IMPLEMENTED** — `crates/pharos-engine/src/types.rs:148-151` (field present;
  value supplied by caller from `RuntimeConfig`).

---

### `execution-apis/src/engine/authentication.md`

- **[MUST] EL MUST expose Engine API at a port independent from JSON-RPC API** (auth.md:26): EL-side.
  CL connects to `--execution-endpoint` (default `http://127.0.0.1:8551`).
  **IMPLEMENTED** — `crates/pharos-node/src/main.rs:88-89`.

- **[MUST] EL MUST support at least HS256** (auth.md:28): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[MUST] EL MUST reject `alg: none`** (auth.md:29): EL-side.
  **IMPLEMENTED** (delegated to EL).

- **[SHOULD] CL/EL SHOULD accept `jwt-secret` config parameter** (auth.md:36):
  CL accepts `--jwt-secret <path>` CLI flag.
  **IMPLEMENTED** — `crates/pharos-node/src/main.rs:82-83`.

- **[SHOULD] If no parameter, SHOULD generate and store as `jwt.hex`** (auth.md:38):
  Auto-generation not implemented; `--jwt-secret` is optional (`Option<PathBuf>`). If absent,
  no JWT auth is used and the engine endpoint is unauthenticated.
  **GAP** — auto-generation of `jwt.hex` not implemented. Acceptable for dev use; tracked
  as deferred to M4b/M11 (devnet always provides the file explicitly; production path deferred).

- **[SHOULD] If parameter given but file unreadable or not 256-bit hex, treat as error** (auth.md:40):
  `load_jwt_secret` returns `Err` if file is unreadable or key is not 64 hex chars.
  **IMPLEMENTED** — `crates/pharos-engine/src/jwt.rs:34-52`.

- **[SHOULD] EL only accept `iat` within +-60 seconds** (auth.md:46): EL-side.
  CL mints `iat = now()` per request, staying within the window.
  **IMPLEMENTED** — `crates/pharos-engine/src/jwt.rs:63-74`.

- **[MAY] CL MAY use `id` claim** (auth.md:47):
  Not used; no `id` field in `Claims` struct.
  **IMPLEMENTED** (MAY clause; choice is to omit).

- **[MAY] CL MAY use `clv` claim** (auth.md:48):
  Not used.
  **IMPLEMENTED** (MAY clause; choice is to omit).

- **[MAY] Other claims MAY be included; EL MUST ignore unknown claims** (auth.md:50): EL-side.
  **IMPLEMENTED** (delegated to EL).

---

### `consensus-specs/specs/bellatrix/beacon-chain.md`

- **[Note/MUST] `process_execution_payload` MUST be called before `process_randao`** (beacon-chain.md:362-364):
  Spec note is a normative ordering requirement. `process_block` in Bellatrix calls
  `process_execution_payload` immediately after `process_block_header` and before `process_randao`.
  **IMPLEMENTED** — `crates/pharos-stf/src/bellatrix/block.rs:11-12` (module doc comment)
  and the call order in `process_block_bellatrix` (lines 44-60).

- **[MUST] Verify `parent_hash == state.latest_execution_payload_header.block_hash` if merge complete** (beacon-chain.md:389-390):
  `process_execution_payload` asserts this.
  **IMPLEMENTED** — `crates/pharos-stf/src/bellatrix/operations/execution_payload.rs:96-108`.

- **[MUST] Verify `prev_randao`** (beacon-chain.md:392):
  `process_execution_payload` asserts `payload.prev_randao == get_randao_mix(state, epoch)`.
  **IMPLEMENTED** — `crates/pharos-stf/src/bellatrix/operations/execution_payload.rs:111-121`.

- **[MUST] Verify `timestamp`** (beacon-chain.md:394):
  `process_execution_payload` asserts `payload.timestamp == compute_time_at_slot(state, slot)`.
  **IMPLEMENTED** — `crates/pharos-stf/src/bellatrix/operations/execution_payload.rs:123-131`.

- **[MUST] `verify_and_notify_new_payload` MUST return true** (beacon-chain.md:396-398):
  Asserted in `process_execution_payload`.
  **IMPLEMENTED** — `crates/pharos-stf/src/bellatrix/operations/execution_payload.rs:133-141`.

- **[MUST] Reject if any transaction is empty (`b""`)** (beacon-chain.md:348, via `verify_and_notify_new_payload`):
  Default impl of `verify_and_notify_new_payload` checks `tx.is_empty()`.
  **IMPLEMENTED** — `crates/pharos-stf/src/bellatrix/execution_engine.rs:89-96`.

- **[MUST] `is_valid_block_hash` check (blockHash = Keccak256(RLP(header)))** (beacon-chain.md:351):
  Delegated to EL via `engine_newPayloadV1`; EL returns `INVALID_BLOCK_HASH` on failure.
  **IMPLEMENTED** (delegated to EL per `D-engine-conformance-runner` design).

- **[MUST] Cache `latest_execution_payload_header`** (beacon-chain.md:399-415):
  `process_execution_payload` writes the header.
  **IMPLEMENTED** — `crates/pharos-stf/src/bellatrix/operations/execution_payload.rs:143-162`.

---

### GAP summary

Three items are classified as GAP or DEFERRED:

1. **GAP: `exchange_transition_configuration` TTD mismatch warning** (paris.md:289) — CL SHOULD
   log a user-visible error when EL's TTD mismatches local config. The method is wired but no
   comparison + warning is implemented in `pharos-node`. Filed as a deferred item in
   `docs/roadmap.md` M4b section.

2. **GAP: `exchange_transition_configuration` 60-second polling** (paris.md:291) — CL SHOULD
   poll every 60 seconds. Currently called once on startup (see `Q-exchange-capabilities-cadence`
   locked resolution). Filed as deferred in `docs/roadmap.md` M4b section.

3. **GAP: automatic `jwt.hex` generation** (authentication.md:38) — SHOULD generate if no
   `--jwt-secret` flag. Currently the node runs unauthenticated if the flag is absent. Filed
   as deferred in `docs/roadmap.md` M4b section.

All three are SHOULD-level requirements (not MUST), do not affect Bellatrix STF correctness,
and are acceptable for devnet operation. Production hardening is tracked in M4b/M11.
