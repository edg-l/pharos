# Pharos — Roadmap

A Rust Ethereum consensus client. This document is the living plan; it will be
revised as decisions solidify.

**Performance is a first-class goal.** Every milestone ends with benchmarks,
not just spec-test green. Decisions below are biased toward latency and
throughput; correctness is the floor, speed is the target.

## Reference repos (local clones)

All cloned under `~/dev/`:

- `consensus-specs/` — authoritative Python specs + reference tests
  (consensus-spec-tests is now folded into this repo)
- `EIPs/` — canonical EIP texts
- `beacon-APIs/` — REST API surface the CL must expose
- `execution-apis/` — Engine API (CL ↔ EL) lives under `src/engine/`
- `builder-specs/` — MEV-Boost / builder API (later milestone)

## EIPs by fork (consensus-relevant)

Forks bundle multiple EIPs. The CL implements against fork specs in
`consensus-specs/specs/<fork>/`. EIPs listed here are the ones a CL must
honor or be aware of.

### Phase 0 — Beacon Chain
- EIP-2982 Serenity Phase 0 (umbrella)
- EIP-2333 BLS12-381 key derivation
- EIP-2334 BLS12-381 deterministic key paths
- SSZ + Merkleization (`consensus-specs/ssz/`)
- libp2p gossipsub, discv5, SSZ-snappy req-resp

### Altair
- Sync committees, light-client protocol (no standalone EIP)

### Bellatrix — The Merge
- EIP-3675 Upgrade consensus to PoS
- EIP-4399 PREVRANDAO replaces DIFFICULTY
- Engine API v1

### Capella — Withdrawals
- EIP-4895 Beacon-chain push withdrawals
- BLS-to-execution-change

### Deneb — Proto-Danksharding
- EIP-4844 Blob transactions, KZG commitments, blob sidecars
- EIP-7044 Perpetually valid signed voluntary exits
- EIP-7045 Increase max attestation inclusion slot
- EIP-7514 Max epoch churn limit

### Electra (Pectra) — current mainnet
- EIP-6110 Onchain validator deposits
- EIP-7002 Execution-layer triggerable withdrawals
- EIP-7251 MAX_EFFECTIVE_BALANCE (MaxEB) + consolidations
- EIP-7549 Move `committee_index` out of `Attestation`
- EIP-7685 General-purpose EL requests
- EIP-7691 Blob throughput increase

### Fulu — PeerDAS
- EIP-7594 PeerDAS (peer data availability sampling)
- EIP-7892 Blob-parameter-only forks
- Column sidecars, custody, `das-core.md`

### Gloas / Heze (unstable — track, do not implement yet)
- ePBS (enshrined proposer-builder separation), inclusion lists

## Library philosophy

**Rule: if consensus-specs (or an EIP) publishes a conformance test suite
for it, we own the implementation.** Upstream dependencies are allowed only
for generic infrastructure that has no CL-specific test vectors, or for
cryptographic primitives where the test suite validates I/O but not
side-channel safety.

The point of Pharos is to be our own consensus client, not a thin wrapper
around sigp's crate suite.

### In-house (we own everything with a spec test suite)
- SSZ encode/decode (`tests/formats/ssz_generic`, `ssz_static`)
- Merkleization / `hash_tree_root` (part of SSZ tests)
- STF: `operations`, `epoch_processing`, `sanity`, `finality`, `random`,
  `rewards`
- Fork choice (`tests/formats/fork_choice`)
- Light client (`tests/formats/light_client`)
- Shuffling, genesis
- Slashing protection algorithm + EIP-3076 interchange
  (`eth-clients/slashing-protection-interchange-tests`)
- Beacon API server (OpenAPI in `beacon-APIs/`)
- Engine API client (spec + tests in `execution-apis/`)
- Types, gossip validation rules, req-resp protocol handlers, peer scoring,
  ENR / fork-digest handling, KZG ceremony glue, VC duties + signing

### Cryptographic primitives — exception to the rule
Spec test suites exist (`tests/formats/bls`, `tests/formats/kzg`) but they
validate I/O, not constant-time execution, subgroup checks, or assembly-
tuned performance. Rolling these ourselves would ship a cryptographically
dangerous primitive. We use:
- `blst` — Supranational, the production BLS12-381 with hand-tuned asm
- `c-kzg` — the EF reference KZG library

### Generic infrastructure (no CL-specific test suite)
- `tokio` — async runtime
- `libp2p` — generic protocol framework (we own the CL-specific layer)
- `discv5` — generic Ethereum discovery (shared with EL)
- `rocksdb` — main chain DB
- `rusqlite` — slashing protection DB (separate file)
- `reqwest` — HTTP client
- `jsonwebtoken` — JWT for Engine API auth
- `axum` — Beacon API HTTP server
- `snap` — snappy framing
- `rayon` — data parallelism in STF
- `serde`, `serde_json`, `serde_yaml`
- `tracing`, `metrics`, `metrics-exporter-prometheus`
- `thiserror`, `anyhow`
- `proptest`, `criterion` (later)

### Explicitly rejected
`ethereum_ssz`, `tree_hash`, `ethereum_hashing`, `ethereum_serde_utils`,
`alloy*`, `lighthouse_network`, `ssz_rs`, `milhouse`.

Costs we accept: +1–2 months on M0 to write our own SSZ + Merkleization.
Benefit: full control of the hot path and the type system, no surprise
upstream churn, a real consensus client and not a re-skin.

### Independence guarantee

Pharos competes with Lighthouse (and Prysm, Lodestar, Teku, Nimbus). It is
not a re-skin or a port. The following rules keep it that way; they apply
to every contributor — human or agent — and the implementer agents in
particular must read this before touching code.

**Authoritative reference materials** (in priority order):

1. `~/dev/consensus-specs/specs/` — the prose specs (Python) and SSZ
   simple-serialize. Read these. Cite the file + line number in code
   comments when implementing a non-obvious clause.
2. `~/dev/consensus-specs/tests/formats/` — conformance fixtures. The
   bar for "we implemented it right" is fixtures green, not visual
   resemblance to another client.
3. `~/dev/EIPs/` — canonical EIP text where a spec section refers out.
4. `~/dev/beacon-APIs/` — Beacon API OpenAPI surface.
5. `~/dev/execution-apis/src/engine/` — Engine API spec + fixtures.

**Banned during implementation**: reading source from `~/dev/lighthouse/`,
`~/dev/prysm/`, `~/dev/lodestar/`, `~/dev/teku/`, `~/dev/nimbus-eth2/`,
or equivalent. Includes blog posts that paste code blocks. Cross-language
ports (Prysm Go, Lodestar TS, Teku Java) are *less* risky for accidental
copying because porting requires re-thinking, but the rule applies
uniformly so there's no judgement call.

**Permitted uses of other clients**:

- **Wire-level oracle** — running another client on localhost and
  comparing the bytes it emits vs ours, when debugging "did I encode
  this right." See the Cross-client interop testing entry in
  Cross-cutting. Looking at wire output is *observing the network*,
  not reading source.
- **Public spec-adjacent artefacts** — published mainnet ENRs,
  published bootnode lists, published genesis state roots. These are
  data on the public network, not source code. Vendoring them as test
  fixtures is fine; cite the publication source.
- **De-facto conventions where the spec is silent** — e.g. the QUIC
  ENR key naming (`quic`/`quic6`) that Lighthouse documented first
  and every CL client now follows. Adopting the convention is
  necessary for interop; document it in `docs/decisions.md` with a
  link to where the convention was published (NOT to Lighthouse's
  source, but to a spec-adjacent README, ethresear.ch post, or
  EthCC talk).

**What is identical across all clients (by spec mandate, not copying)**:

- Wire formats: SSZ-snappy framing, varint length prefixes,
  gossipsub topic names, req-resp protocol IDs, container layouts.
- Constants: `SLOTS_PER_EPOCH`, `MIN_VALIDATOR_WITHDRAWABILITY_DELAY`,
  Goodbye reason codes, etc.
- Algorithms: `compute_shuffled_index`, `get_active_validator_indices`,
  `process_block` semantics, fork choice.

If we changed any of these, our node couldn't talk to the network.
Differentiation lives *above* the wire layer, not in it. Performance,
data structures, error model, observability, and operator UX are the
competition surface.

**Red flags during code review** (any of these triggers a hard stop):

- Function signatures that match a Lighthouse type exactly when the
  spec doesn't mandate that signature.
- File or module names that mirror a Lighthouse crate's structure
  beyond what the spec organisation implies.
- Comments that reference a Lighthouse type / function / line.
- Identifier naming that follows Lighthouse-specific patterns
  (`NetworkGlobals`, `BeaconChainTypes`, `ChainSpec`, etc.).
- Test fixtures vendored from `~/dev/lighthouse/`.
- Performance heuristics copied from a Lighthouse README or issue
  thread without a spec-based or measured justification.

Reviewers should treat any of these as a port-of-Lighthouse signal and
require the contributor to redo the work from spec + first principles.


## Performance principles

These constrain every milestone. Violations need justification, not the
other way around.

### Hot paths to obsess over
1. **`hash_tree_root` on `BeaconState`** — called constantly; full state is
   ~1M validators × 100+ bytes. Must use cached Merkle trees with dirty
   tracking, not recompute from scratch.
2. **BLS verification** — attestation aggregation makes this the single
   biggest CPU cost. Always batch-verify; never verify one-by-one.
3. **SSZ deserialization** — incoming gossip blocks/attestations. Aim for
   zero-copy decoding where the spec allows (offsets-into-bytes patterns).
4. **State transition** — `process_epoch` touches every validator. Must be
   parallelized across validators where the spec permits (rewards,
   penalties, effective-balance updates).
5. **Gossip validation latency** — attestations/blocks must be validated
   fast enough to forward before the slot ends. P99 matters more than mean.

### Hard rules
- **Sync STF core, async I/O at the edges.** STF is CPU-bound; tokio adds
  overhead and obscures profiles. Wrap STF calls in `spawn_blocking` when
  invoked from async contexts.
- **No `clone()` on `BeaconState`** in hot paths. Use copy-on-write /
  persistent data structures (e.g. tree-backed `List`/`Vector` with
  structural sharing). Lighthouse uses `milhouse`; we should evaluate it or
  build something similar.
- **Allocation discipline.** Pre-size `Vec`s. Reuse buffers across slots.
  Profile allocations with `dhat` or `heaptrack` per milestone.
- **Hardware crypto.** SHA256 via SHA-NI/ARMv8 crypto extensions
  (`ethereum_hashing` already does this). BLS via `blst` with
  `portable=false` on supported targets.
- **Parallelism via `rayon`** for embarrassingly parallel state operations.
  Never inside per-validator inner loops (overhead dominates); only at the
  outer level (per-epoch, per-attestation-batch).

### Bench-consciousness (process, not a gate)
No benchmarking until we have something running. The point is to build with
performance in mind so we don't paint ourselves into a corner:
- Pick data structures and APIs that don't preclude later optimization
  (CoW state, batch-verify-friendly signatures, zero-copy-friendly SSZ).
- Keep hot paths free of `Box<dyn>`, needless `Arc<Mutex<...>>`, and async
  fn where sync would do.
- When in doubt between two designs, prefer the one that is easier to
  profile and harder to accidentally pessimize.
- Bench harness, fixtures, and targets land later — once an end-to-end
  thing exists to measure.

## Implementation roadmap

Don't implement EIPs linearly. Build state-transition primitives once, then
layer forks on top of them.

### M0 — Foundations (no fork yet)
- In-house SSZ encode/decode + Merkleization + derive macros.
- Phase 0 type containers (`BeaconBlock`, `BeaconState`, etc.) per
  `specs/phase0/`. Hash-tree-root caching via the future persistent tree
  backend (not full recompute) is reserved by the trait but lands later.
- Persistent / CoW collections for `List`/`Vector` fields — in-house;
  trait + naive `Vec`-backed impl ship now, tree-backed impl later.
- `EthSpec` trait with flat preset constants (mainnet + minimal).
- Generalized indices + single-leaf Merkle proofs.
- BLS verify / aggregate / fast aggregate verify wrappers (over `blst`),
  batch-verify scaffolding.
- **Conformance harness** (`pharos-conformance` crate): walks
  `~/.cache/pharos-spec-tests/` (override via `$PHAROS_SPEC_TESTS`),
  runs Pharos against each fixture, tallies pass/fail per (fork, category).
  Produces `docs/conformance.md` on every run — committed, so progress is
  visible in git history. Doubles as the roadmap: categories appear with
  `-` until implemented.
- **M0 acceptance**: all `ssz_generic` and Phase 0 `ssz_static` tests
  green in `conformance.md`.
- **Spec-test workflow**: `scripts/fetch-spec-tests.sh` then
  `cargo run -p pharos-conformance -- --write`.

### M1 — Phase 0 STF + fork choice
- `process_block` + `process_epoch`.
- Parallelize epoch processing across validators with `rayon` where the
  spec permits.
- LMD-GHOST + FFG, justification, finalization.
- Run `consensus-specs` reference tests for `phase0` until green.
- No networking yet; drive STF from test vectors.

### M2 — Networking baseline — **Done**
Deliverables 1–4 shipped in commits `7af7321` (ENR) → `d2db994` (discv5
+ peer manager) → `651f21c` (libp2p transport + Behaviour) → `dc32730`
(gossipsub + SSZ-snappy + validation hook) → `a2e3029` (req-resp +
codec) → `dcd4957` (Phase 6 peer manager status handshake + scoring
wiring) → `95c2503` (Phase 7 `NetworkHandle` + node integration) →
`7036da1` (Phase 8 integration tests) → `95785a5` (gossip flake
mitigation via `serial_test`).

- [x] **discv5 peer discovery.** `crates/pharos-network/src/discovery/`
  (`service.rs`, `enr.rs`, `subnets.rs`); see ADR `D-discv5`.
- [x] **libp2p gossipsub topics for Phase 0.** SSZ-snappy framing with
  StrictNoSign per `p2p-interface.md:482-484`; topics defined in
  `crates/pharos-network/src/topics.rs`; validation hook routed through
  `host::GossipValidator` per ADR `D-trait-boundaries`.
- [x] **SSZ-snappy req-resp domain.** Five Phase-0 methods (Status,
  Goodbye, Ping, MetaData, BeaconBlocksByRange/Root) in
  `crates/pharos-network/src/rpc/`; varint length-prefix codec validated
  against `p2p-interface.md:1264-1267`; per-method `request_response::Codec`
  impls.
- [x] **Peer scoring stub.** `PeerScorer` trait + `NoopScorer` in
  `crates/pharos-network/src/scoring.rs`; M11 swaps the impl per ADR
  `D-peer-scoring`.

M2 follow-ups (deferred via Phase 9 audits, owned by M3 / M11): see
`D-network-event-surface` in `docs/decisions.md` for the catchall list
and milestone assignment. Public surface (`NetworkBuilder`,
`NetworkHandle`, `Host<E>`, `PeerScorer`) summarised in
`docs/m2-plan.md` Section "Acceptance Criteria" and `docs/decisions.md`
M2 section.

### M3a — Phase 0 infrastructure (DONE)

Delivered via commits `a0d5c36` (NetworkEvent expansion) → `26e0282` (Host<E> real impl
+ storage substrate) → `f094278` (Goodbye-on-shutdown) → `b79f40b` (MetaData.seq_number startup wiring).

- [x] **Storage substrate.** Real RocksDB-backed `Store` trait in
  `crates/pharos-storage/` with seven column families, big-endian slot keys,
  Lz4 compression on `blocks`/`states` CFs, `schema_version` sentinel, and
  atomic `WriteBatch` writes via `BlockTransition`. See ADR `D-rocksdb` and
  `D-store-trait`.
- [x] **BlockProvider real impl.** `HostImpl<E>` wires `block_by_root` and
  `blocks_by_range` to `RocksStore` so `BeaconBlocksByRange` /
  `BeaconBlocksByRoot` return persisted blocks
  (`crates/pharos-node/src/host_impl.rs`). See ADR `D-gossip-validator-sync`.
- [x] **Host<E> real impl.** `HostImpl<E: EthSpec>` replaces the M2 stubs
  (`BlockStoreStub`, `ForkContextStub`, `GossipValidatorStub`), backed by
  `Arc<RocksStore>` and `Arc<RwLock<pharos_fork_choice::Store<E>>>`. See
  ADRs `D-block-encoding-on-disk`, `D-storage-error-strategy`.
- [x] **Network-event expansion.** `NetworkEvent::PeerSubscribed`,
  `PeerUnsubscribed`, `PeerIdentified`, `DialFailed`, `ExternalAddrConfirmed`
  implemented in `crates/pharos-network/src/network/mod.rs` M3a Phase 3 arms.
  See ADR `D-network-event-surface` (updated) and `D-peer-info-shape`.
- [x] **Goodbye-on-shutdown.** `shutdown_goodbye` sends
  `Goodbye(ClientShutdown = 1)` to every connected peer with a 500 ms bounded
  drain before force-disconnect
  (`crates/pharos-network/src/network/mod.rs:1000`). See ADR `D-shutdown-protocol`.
- [x] **MetaData.seq_number increment.** `record_attnets_change` on `HostImpl<E>`
  bumps `seq_number` only on a genuine attnets change; called at startup from
  `main.rs` to set initial attestation subnets (`seq_number` 0 → 1). See ADR
  `D-metadata-mutation`.
- [x] **ForkSchedule + fork_schedule() accessor.** Phase-0-only `ForkSchedule`
  struct in `pharos-types::fork`, accessible via `HostImpl::fork_schedule(&self)`.
  `altair_fork_epoch = FAR_FUTURE_EPOCH` at M3a; shape is forward-compatible
  for M3b's Altair entry. See ADR `D-fork-schedule`.

### M3b — Altair fork code (DONE)

Delivered via commits `d83e787` (EthSpec altair consts + RuntimeConfig skeleton)
→ `781a134` (Altair containers + fork-enum promotion) → `29153cf` (Altair STF
block ops + `upgrade_to_altair`) → `d3e398e` (Altair STF epoch processing +
state-transition entry) → `784d75b` (Altair conformance + spec-tests v1.7.0-alpha.8)
→ `e0fe1b5` (context-bytes codec + altair gossip topics + altair message-id)
→ `13ad7b8` (MetaDataV2 + LC req-resp + LC storage/STF)
→ `d25193b` (subnet rotation + cross-fork ENR migration)
→ `ab4498d` (RuntimeConfig YAML loader + `--config-dir` CLI flag).

- [x] **Altair STF.** `process_sync_aggregate`, `process_inactivity_updates`,
  participation-flag rewards/penalties, `process_sync_committee_updates`,
  `upgrade_to_altair` transition, `compute_sync_committee`. See ADR
  `D-altair-state-shape`, `D-sync-aggregate-bls`.
- [x] **Altair conformance.** All `altair` categories green on both presets:
  `transition`, `ssz_static`, `operations`, `epoch_processing`, `sanity`,
  `finality`, `random`, `rewards`, `light_client`. Q1 resolved: `phase0/fork_choice`
  now shows real pass counts.
- [x] **Context-bytes codec.** 4-byte `ForkDigest` prefix on
  `BeaconBlocksByRange/2`, `BeaconBlocksByRoot/2`, and all four LC methods.
  See ADR `D-context-bytes-codec`.
- [x] **MetaDataV2 dual-handle.** `syncnets` field, v1/v2 dual-protocol
  registration, v1-truncation on negotiated v1. See ADR `D-metadata-v2-dual-handle`.
- [x] **Altair gossip topics.** `sync_committee_contribution_and_proof`,
  `sync_committee_{i}` (4 subnets), `light_client_finality_update`,
  `light_client_optimistic_update`. Altair `message-id` formula.
- [x] **Light-client server.** Four new req-resp methods (`LightClientBootstrap`,
  `LightClientUpdatesByRange`, `LightClientFinalityUpdate`,
  `LightClientOptimisticUpdate`), `LightClientProvider<E>` host trait,
  `create_light_client_*` STF hooks, snapshot storage in `pharos-storage`.
  Consumer side deferred to M11. See ADR `D-light-client-server-only`.
- [x] **Cross-fork ENR migration.** `DiscoveryHandle::update_enr_eth2`,
  `run_fork_migration_loop` in `pharos-node`. See ADR `D-fork-schedule-source`.
- [x] **Subnet rotation.** `run_subnet_rotation_loop` in `pharos-node`,
  `NetworkCommand::UpdateMetaData`, node-id-derived attestation subnets via
  `compute_subscribed_subnets`.
- [x] **YAML preset loader.** `RuntimeConfig`, `load_config_dir`, `--config-dir`
  CLI flag, `assert_matches_preset`. See ADR `D-ethspec-yaml-loader`.

### M4 — Bellatrix + Engine API

M4 is split into four slices plus a perf interlude. Every item from the
original M4 scope is allocated to exactly one slice; nothing is deferred
out of M4. M4a/M4b/M4c ship code with in-process integration tests
against mocks; M4-perf swaps the `Vec`-backed SSZ collections for the
tree-backed CoW design promised in CLAUDE.md (see "Persistent collections
(in-house)" below); M4d is the single cross-client acceptance gate that
validates the full M4 surface against real ethrex + Lighthouse processes
in a hand-rolled devnet.

#### M4a — Engine API + Bellatrix STF + in-process integration test (DONE)

Delivered via commits `676984c` (EthSpec Bellatrix consts + ForkSchedule extension)
→ `abffd78` (Bellatrix containers + fork-enum third variant)
→ `c0c6ecd` (Bellatrix STF + `process_execution_payload` + `upgrade_to_bellatrix`)
→ `170995b` (pharos-engine real impl: JSON-RPC + JWT + Bellatrix Engine methods)
→ `a885d5e` (fork-choice ↔ engine wiring + invalid-payload tracking + head driver)
→ `b2a234f` (Bellatrix conformance + Engine API conformance scaffold)
→ `2f60ef8` (bounded backpressure on network event channel).

- [x] **`pharos-engine` real impl**: `engine_newPayloadV1`,
  `engine_forkchoiceUpdatedV1`, `engine_getPayloadV1`,
  `engine_exchangeCapabilities`, `engine_exchangeTransitionConfigurationV1`.
  JWT HS256 auth (`load_jwt_secret`, `sign_token`). Per-method version enums
  (`NewPayloadVersion`, `ForkchoiceUpdatedVersion`, `GetPayloadVersion`).
  `EngineHandle` actor + `EngineClient` HTTP transport. See ADR
  `D-engine-method-dispatch`.
- [x] **Bellatrix STF**: `process_execution_payload`, `BeaconBlockBodyBellatrix`,
  `ExecutionPayload`, `upgrade_to_bellatrix`. All `bellatrix` spec-test
  categories green (`transition`, `ssz_static`, `operations`, `epoch_processing`,
  `sanity`, `finality`, `random`, `fork_choice`). See ADR `D-bellatrix-state-shape`.
- [x] **fork-choice ↔ EL link**: `run_engine_driver_loop` via `tokio::watch`.
  See ADR `D-engine-head-driver`.
- [x] **Invalid-payload tracking**: `payload_statuses` map in
  `pharos-fork-choice::Store`, `CF_PAYLOAD_STATUS` RocksDB column family,
  `filter_block_tree` exclusion. See ADR `D-payload-status-store`.
- [x] **Backpressure**: `send().await` + 1-second timeout on `NetworkEvent`
  channel. See ADR `D-network-backpressure`.
- [x] **Engine API conformance scaffold**: `pharos-conformance/src/engine.rs`,
  axum mock runner. See ADR `D-engine-conformance-runner`.
- [x] **In-process pipeline integration test**:
  `crates/pharos-node/tests/engine_pipeline.rs`.

Deferred from M4a: `get_safe_execution_block_hash` reorg-aware walk (M11),
`engine_exchangeCapabilities` 60-second polling loop (M4b/M11), LC gossip
validation bodies (M4c).

#### M4b — Checkpoint sync + forward backfill (code + mock integration) (DONE)

Delivered via commits `7a50c3d` (JWT auto-gen + engine keepalive — `ensure_jwt_secret`,
`run_transition_config_keepalive`) → `2b3c1e8` (checkpoint sync — `fetch_checkpoint`,
`apply_anchor`, axum mock Beacon API server) → `5f8e9d2` (forward backfill —
`run_backfill_loop`, `BackfillBlockProvider`, `PeerPicker`) → `d1a4b6c` (engine
conformance YAML extension — 2 new examples, `pass=6 fail=0`) → `e9c2f7a` (mock
pipeline integration test — `checkpoint_backfill_pipeline.rs`, 10-run green) →
`f44251f` (`apply_anchor` weak-subjectivity fix + ADR `D-anchor-as-weak-subj-root`).

- [x] **JWT auto-generation**: `ensure_jwt_secret` in
  `pharos-node/src/jwt_autogen.rs` auto-generates `<data_dir>/jwt.hex` via
  `OpenOptions::create_new(true)` (0o600 on Unix). See ADR `D-jwt-auto-gen`.
- [x] **Engine keepalive**: `run_transition_config_keepalive` in
  `pharos-node/src/engine_keepalive.rs`, 60-second interval, `HashSet`-deduplicated
  TTD-mismatch `WARN`. Cold-start check in `main.rs`. See ADR
  `D-engine-config-keepalive`.
- [x] **Checkpoint sync**: `fetch_checkpoint` + `apply_anchor` in
  `pharos-node/src/checkpoint_sync.rs`. `GET /eth/v2/debug/beacon/states/finalized`
  SSZ + `GET /eth/v2/beacon/blocks/0x<root>` SSZ. Optional `--checkpoint-sync-block-root`
  tamper flag. See ADRs `D-checkpoint-sync-source`, `D-anchor-state-on-disk`,
  `D-anchor-as-weak-subj-root`.
- [x] **Forward backfill**: `run_backfill_loop` in `pharos-node/src/backfill.rs`.
  `BeaconBlocksByRange` chunks of 64, STF + fork-choice advance. Long-running
  re-converging loop that heals to `wall_slot - 1` and parks on a `Notify`
  (M5). See ADRs `D-backfill-driver`, `D-following-via-range-reconvergence`.
- [x] **Engine API conformance extension**: `engine/yaml` row `pass=6 fail=0`.
- [x] **Mock pipeline integration test**:
  `crates/pharos-node/tests/checkpoint_backfill_pipeline.rs`, axum mocks for
  Beacon API + Engine API.
- [x] **TTD mismatch warning**: cold-start check + 60-second keepalive (resolves
  M4a GAP paris.md:289 and paris.md:291).
- [x] **Automatic `jwt.hex` generation**: resolves M4a GAP authentication.md:38.

Deferred from M4b: weak-subjectivity validation (M11), historical backfill (M11).

#### M4-perf — Tree-backed persistent SSZ collections + tree-hash parallelism (DONE)

Closed 2026-05-27. Commits `8e04006` (Phase 1 tree backend) →
`020ea9d` (state-level cached_root). Full conformance writer
**~11 min → 2:59 (3.7×)**; targeted `phase0/sanity/mainnet`
**5:46 → ~19 s (18×)**. `docs/conformance.md` row counts byte-identical
(only the header date line changes). The headline win came not from the
originally-planned Phase 5 outer `par_iter` (dropped — see
`D-conformance-parallelism-dropped`) but from
`BeaconStateView::validators() -> Vec<Validator>` materialization being
the dominant hot path in the writer; the borrowing accessors
(`D-state-view-borrowing-accessors`) account for the bulk of the gain.
Phase 3 (`Validator::tree_hash_root` `OnceLock` cache,
clone-resets-cache per `D-validator-cache-clone-resets`) and Phase 6
(state-level `CachedRoot` per `D-cached-root-wrapper`) are live-node
wins that the single-shot conformance writer does not amortise; they
remain latent until live-node call sites migrate to
`cached_tree_hash_root()` + explicit `into_tree_backend()` at storage /
checkpoint-sync / genesis entry points. ADRs added to
`docs/decisions.md` (M4-perf section): `D-tree-node-shape`,
`D-packed-as-full-chunk`, `D-tree-backend-fields`,
`D-validator-cache-clone-resets`, `D-cached-root-wrapper`,
`D-no-tree-backend-on-decode`, `D-state-view-borrowing-accessors`,
`D-treehash-rayon-strategy`, `D-conformance-parallelism-dropped`.
Workspace version bumped `0.4.0` → `0.5.0`. Phase 6 wrap-up + audits in
`docs/m4-perf-plan.md`.

Why this slice: the conformance suite and STF are both dominated by
`BeaconState::tree_hash_root` — sha2 is ~90% of the writer's CPU per
flamegraph (`docs/perf/m4-perf-baseline-flamegraph.svg` once recorded).
The `Vec`-backed `SszList` / `SszVector` we shipped at M0c rebuilds the
entire Merkle tree per call; the tree-backed CoW design (see "Persistent
collections (in-house)" further down) caches per-node hashes and only
re-hashes the path on mutation. This unlocks 5–10× on hot paths and
compounds with the existing rayon parallelism.

- **Tree-backed `SszList<T, N>` / `SszVector<T, N>`**: swap the
  `Backend::Tree(Arc<Node>)` placeholder in
  `crates/pharos-ssz/src/sequence.rs` for a real implementation:
  `Node::{Branch { left, right, hash: OnceCell<Hash256> }, Leaf(T),
  ZeroSubtree(depth)}`. Const-generic depth derived from `N`. CoW `set`,
  `push`, `get`, `iter`, `len`. SSZ encode/decode must be byte-identical
  to the `Vec` backend; cached `tree_hash_root` must produce identical
  roots. Property tests (proptest) randomized state surgery against the
  `Vec` backend: any divergence = consensus bug.
- **Validator-level caching**: `Validator::tree_hash_root` cached via
  `OnceCell` on the struct. Validators barely change once active;
  rehashing every slot is the single biggest per-call waste in
  `process_slots`.
- **Derive-macro field-level parallelism**: emit `rayon::scope` (or
  fixed-width `rayon::join` nesting) in `#[derive(TreeHash)]` so a
  container with N fields hashes them in parallel. Independent fields
  → embarrassingly parallel. `BeaconState` has ~25 fields, mostly
  independent.
- **`lib.rs::run` top-level category parallelism**: refactor the
  1718-line `if filter.matches(...)` ladder in
  `crates/pharos-conformance/src/lib.rs::run` to `par_iter` over the
  (fork, category, preset) triples and merge results. Categories
  currently run strictly sequentially even though each is independent.
- **Conformance regression**: the `docs/conformance.md` row counts MUST
  not change. A `diff conformance.md.before conformance.md.after` of
  zero is a hard gate.
- **Bench reporting**: criterion benches for `tree_hash_root` on
  `BeaconState` (mainnet + minimal), `process_slots` (1 slot, 32 slots,
  1 epoch), and the full conformance writer wall-clock. Before/after
  numbers committed to `docs/perf/`. Target: full conformance writer
  drops from ~657 s (sequential baseline) to under 60 s on a 12-core
  machine.

Deferred from M4-perf to later (M11ish):
- LRU cache for repeated `tree_hash_root` calls on stable Validators
  (e.g. validators not yet active or fully exited) — defer.
- Custom SHA-256 path via `sha2-asm` or AVX-512 intrinsics — defer.
- Cross-thread tree sharing via lock-free `Arc<Node>` interning — defer.

Expected cost: 4–6 implementer-days. Sequenced before M4c so the perf
bench baseline (M4c) records the post-tree-backed numbers, not the
pre-tree-backed ones.

#### M4c — LC gossip carry-ins + perf bench baseline
- **LC gossip validation bodies** (deferred from M3b spec audit Task 9.7):
  `GossipValidator` methods for LC topics (`validate_light_client_finality_update`,
  `validate_light_client_optimistic_update`) currently return `Accept`; real
  validation (timing window, locally computed update comparison) requires the
  block-ingestion event loop wired in M4a.
- **LC gossip broadcasting** (deferred from M3b spec audit Task 9.7):
  full nodes SHOULD broadcast `LightClientFinalityUpdate` /
  `LightClientOptimisticUpdate` after each new head block with a valid sync
  aggregate. M3b stores the snapshots; M4c wires the publish call from the
  block-ingestion path landed in M4a.
- **Performance regression suite**: Add criterion benches for:
  `process_block` (Phase 0 → Bellatrix), `hash_tree_root` on
  `BeaconState`, gossip-validation latency, req-resp roundtrip.
  Bench results checked into a `bench-history/` file or committed
  Prometheus snapshots per release. Benches run against fixtures, no
  live devnet needed.

#### M4d — Hand-rolled Lighthouse+ethrex devnet acceptance gate
This is the M4 closure slice. M4a/b/c ship code-only; M4d is the first
time pharos's M2/M3b networking + M4a/b STF + Engine API code is
exercised against real peer processes.
- **Harness**: hand-rolled bash scripts under `scripts/devnet/` based on
  the pattern in `~/dev/lighthouse/scripts/local_testnet/`. No Docker, no
  Kurtosis (Kurtosis is the eventual answer once Beacon API ships at M7).
- **Topology**: Lighthouse BN + Lighthouse VC (64 deterministic interop
  validators, immediate Bellatrix) drives block production; one ethrex
  EL paired with Lighthouse BN; one ethrex EL paired with pharos (or
  shared, depending on what works); pharos peers with Lighthouse via
  libp2p/discv5 and follows the chain.
- **Testnet-dir**: generated once via `lcli new-testnet` (immediate
  Bellatrix, TTD=0, 64 validators). Committed under
  `tests/fixtures/devnet-lh/`. Pharos's `RuntimeConfig` loader extended
  (or shimmed) to accept Lighthouse's `config.yaml` layout.
- **Acceptance criteria**: ≥ 32 slots of merged sync observed on
  pharos's log (`head_slot`, `head_root` advancing past slot 32 with
  non-zero `execution_payload.block_hash`); ethrex accepts
  `engine_newPayloadV1` calls with `VALID` status; no panics, no
  channel drops, no deadlocks across a 10-minute run.
- **Cross-client coverage** (subsumes the M3b "cross-client interop
  testing (before M4 ships)" roadmap requirement): Status handshake,
  Ping/MetaData exchange, BeaconBlocksByRange roundtrip,
  BeaconBlocksByRoot roundtrip, gossipsub block subscription.
- **Expected cost**: 4-10 implementer-days; budget aligned with
  realistic first-cross-client interop estimates. Bugs surfaced here
  are fixed in M4d, not deferred to M5.

### M5 — Capella
- Withdrawals, BLS-to-execution-change.
- Spec tests `capella` green.

### M6 — Deneb
- KZG commitments via `c-kzg`, blob sidecars, blob gossip topics.
- Spec tests `deneb` green.
- **KZG trusted setup loading**: load the EF mainnet trusted setup
  (or per-network setup) at startup, validate against expected
  commitment, cache in `pharos-engine` (used by both gossip
  validation and Engine API blob calls).
- New gossip topics: `blob_sidecar_{subnet_id}` (0..BLOB_SIDECAR_SUBNET_COUNT).
- New req-resp methods: `BlobSidecarsByRange`,
  `BlobSidecarsByRoot`. Codec extension required.
- `engine_getBlobsV1` Engine API call for blob retrieval.

### M7 — Beacon API
- `/eth/v1/beacon/*`, validator endpoints.
- Enough surface for an external VC to drive Pharos.
- **SSE event stream** at `/eth/v1/events` (server-sent events).
  Internal event bus → HTTP SSE multiplexing for subscribed clients.
  Topics: `head`, `chain_reorg`, `finalized_checkpoint`, `block`,
  `attestation`, `voluntary_exit`, `bls_to_execution_change`,
  `light_client_finality_update`, etc.
- **SSZ-encoded response support**: clients that send
  `Accept: application/octet-stream` get the SSZ payload directly
  (faster than JSON round-trip). All response types must support both.
- **API versioning**: endpoints split across `/eth/v1/` and `/eth/v2/`
  (post-altair). E.g. `/eth/v2/beacon/blocks/{id}` returns the
  fork-tagged block.
- **Validator-namespace authentication**: opt-in token (read from
  `--validator-api-token <path>`) for the
  `/eth/v1/validator/*` endpoints. Default off; lighthouse-compatible.
- **Kurtosis `ethereum-package` integration**: once the Beacon API
  Tier 1 health probes ship (`/eth/v1/node/{identity,syncing,version}`,
  `/eth/v1/beacon/{genesis,headers/head}`, `/eth/v1/config/spec`),
  upstream pharos to `ethpandaops/ethereum-package` (or run as a
  custom Kurtosis service definition) so pharos becomes drivable in
  Kurtosis enclaves. Kurtosis replaces M4d's hand-rolled bash devnet
  as the recurring cross-client harness for M7 onward.

### M8 — Validator client (separate binary)
- Duties, signing, EIP-3076 slashing protection interchange.
- Keystore loading (EIP-2335).
- **ENR `syncnets` key** (deferred from M3b spec audit Task 9.7): populate
  the `syncnets` `Bitvector[SYNC_COMMITTEE_SUBNET_COUNT]` ENR field when the
  validator client assigns sync committee duties. Key is omitted at M3b because
  without validator duties the bitfield is always `0b0000`; wiring it here aligns
  with when sync committee subnet subscriptions become meaningful.
  Per `specs/altair/p2p-interface.md:540-549`.
- **In-house signer first** (BLS sign with key loaded from EIP-2335
  keystore decrypted in-memory). Web3signer compat is M11.
- **Slashing protection DB schema** (separate `rusqlite` file):
  - Table `signed_block` `(pubkey BLOB, slot INTEGER, signing_root BLOB, PRIMARY KEY (pubkey, slot))`.
  - Table `signed_attestation` `(pubkey BLOB, source_epoch INTEGER, target_epoch INTEGER, signing_root BLOB, PRIMARY KEY (pubkey, target_epoch))`.
  - Pre-sign check is a single SQL row read; commit happens before the
    signature leaves the binary.
- **EIP-3076 interchange**: import + export on startup/shutdown,
  validated against the `eth-clients/slashing-protection-interchange-tests` suite.
- **Doppelganger detection**: on startup, listen for 2 epochs before
  signing; warn if our pubkey appears in incoming attestations. Optional
  (`--doppelganger-protection`). Default on.
- **VC ↔ BN connection**:
  - Multiple `--beacon-node <url>` flags for failover.
  - Health probes via `/eth/v1/node/syncing` every slot; mark unhealthy.
  - Subscribe to `/eth/v1/events` for `head` / `finalized_checkpoint`
    so duties refresh on reorgs.
  - Graceful degradation: if all BNs are unhealthy, skip duties
    (never sign without a confirmed canonical state).

### M9 — Electra
- EIP-6110, 7002, 7251, 7549, 7685, 7691.
- Spec tests `electra` green.

### M10 — Fulu / PeerDAS
- Column sidecars, custody, sampling.
- Spec tests `fulu` green.

### M11 — Productionization
- **Weak subjectivity** check on checkpoint state (checkpoint sync
  itself moved to M4). Reject checkpoint older than
  `MIN_VALIDATOR_WITHDRAWABILITY_DELAY + CHURN_LIMIT_QUOTIENT / 2`
  epochs before head.
- **Backward state backfill**: historical state reconstruction by
  replaying epoch boundaries from a forward state. Stays here
  (forward block backfill is M4).
- **Pruning + hot/cold DB split**: hot column families keep recent N
  epochs of states + blocks; cold archives the rest at coarser
  granularity (block roots only, snapshots every `SLOTS_PER_HISTORICAL_ROOT`).
- **Slasher** — two-phase scope:
  - Phase A (minimal): scan gossip + req-resp attestations for
    slashable surround / double votes among observed attestations.
    Low storage, no chain replay.
  - Phase B (full): replay block history looking for proposer
    slashings + indexed attestations. Higher storage (~10 GB) but
    catches everything.
  - Phase A is mandatory for M11; Phase B is opt-in via
    `--slasher` flag.
- **Metrics layer** concrete interface:
  - `metrics-exporter-prometheus` at `/metrics` HTTP endpoint.
  - Defined metrics: gossip topic message rate (counter by topic),
    req-resp method latency (histogram by method, buckets
    [0.5, 1, 5, 25, 100, 500, 2500] ms), peer score distribution
    (gauge by bucket), STF process_block / process_epoch duration
    (histograms), fork-choice get_head duration, EL Engine API
    call latency.
  - Bench-history snapshots checked into `bench-history/` per release.
- **Tracing** structured logging:
  - JSON output for production (`--log-format json`).
  - Span hierarchy: per-slot root span → per-block child → per-method.
  - Sampling at INFO by default; DEBUG opt-in per crate.
- **Real peer scoring** (replaces the M2 `NoopScorer` stub):
  - Consume `gossipsub::Event::SlowPeer` /
    `GossipsubNotSupported` as scoring signals.
  - Per-peer rate limits on req-resp methods
    (`p2p-interface.md` rate-limit guidance).
  - Exponential dial backoff for repeatedly-failing peers.
  - Subnet-coverage scoring (penalise peers that subscribe to
    subnets we expect, then never propagate).
- **Connection limits**: `--max-peers 50 --target-peers 50` (lighthouse
  defaults). discv5 query cadence scales with the deficit
  `target_peers - connected_peers`.
- **ENR persistence across restarts**: write
  `<data-dir>/network/enr_seq` so the next start increments the same
  ENR rather than starting fresh (peers can re-resolve us efficiently).
- **Per-peer score persistence**: serialize the `PeerManager` score
  table to `<data-dir>/network/peer_scores.bin` on shutdown; reload
  on startup so bad-actor peers stay penalised across restarts.
- **DNS bootnode support**: `--bootnode-dns enrtree://...` resolves
  via the discv5 DNS discovery scheme. Mainnet bootnodes are
  published this way.
- **Web3signer / external signer** compat for `pharos-vc`
  (`--signer-url <web3signer-url>`).
- **Graceful shutdown**: SIGTERM → send `Goodbye(1)` to every
  connected peer → drain pending publishes → fsync DB → exit.
  M2 shutdown does none of this beyond the network task stop;
  M3 adds the Goodbye(1); M11 adds the rest.
- **Health endpoints**: `/eth/v1/node/health` (already in M7 spec
  surface) + a separate `/health` probe endpoint on the metrics
  port for orchestrators (200 if sync_state == Synced, 503 otherwise).

### Beyond
- Gloas / Heze (ePBS) once stable.
- Builder API (MEV-Boost) integration.

## Cross-cutting (no single milestone)

These land somewhere across M0-M11; pinning the milestone here so they
don't get dropped.

- **CI strategy** (M0 baseline, kept current through every milestone):
  GitHub Actions workflow running `cargo fmt --check`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace`, and `cargo run -p pharos-conformance`
  on every PR. Matrix: stable Rust + MSRV. Docker container with
  `~/.cache/pharos-spec-tests/` pre-populated.
- **Fuzz harness** (M3, after the SSZ + STF surface is stable enough):
  `cargo fuzz` targets for (a) SSZ decode of every container type, (b)
  `process_block` on synthesised states, (c) req-resp codec on
  arbitrary bytes. Targets live under `fuzz/`; CI runs them
  short-duration (30 s each) on every PR, long-duration (overnight)
  on `master`.
- **Differential fuzzing** (M5 or M6, when the chain has enough
  surface): compare `process_block` output between Pharos and a
  reference Python implementation (re-using the consensus-specs
  Python). Diffs are bugs in one of the two; file upstream where
  applicable.
- **DB migration strategy** (M11, before first production-ish release):
  RocksDB column family `meta` holds a `schema_version: u32` key.
  Forward-only migration scripts live in
  `crates/pharos-storage/src/migrations/`. On startup, walk versions
  in order. No down-migrations.
- **Spec-test version pinning** (per milestone, documented inline):
  `scripts/fetch-spec-tests.sh` pins a specific tag (currently
  v1.6.1). When upgrading, run conformance against the new tag,
  resolve regressions before bumping the pin.
- **Performance regression suite** (M4 onward): criterion benches
  checked-in fixtures + `bench-history/` JSON snapshots per release.
  No CI gate on perf (too noisy on shared runners); humans review the
  delta per release.
- **Cross-client interop testing** — folded into **M4d** as the M4
  closure slice (hand-rolled Lighthouse+ethrex+pharos devnet). The
  M3b carry-in for a gated
  `crates/pharos-network/tests/interop/lighthouse_pair.rs` integration
  test is deferred to **M7** once Beacon API ships and Kurtosis becomes
  the recurring cross-client harness.

## Locked decisions

Milestone-specific decisions (D1-Dn, Q1-Qn) live in
[`docs/decisions.md`](./decisions.md); the bullets below are the
project-wide invariants that pre-date M0.

- **Sync STF, async I/O at the edges.** STF is CPU-bound; tokio adds
  overhead and obscures profiles.
- **Cargo workspace** with shared `[workspace.dependencies]` and
  `[workspace.package]` (version, edition, license). Crates:
  `pharos-types`, `pharos-ssz`, `pharos-stf`, `pharos-fork-choice`,
  `pharos-network`, `pharos-engine` (Engine API client to the EL),
  `pharos-storage`, `pharos-api` (Beacon API server), `pharos-node` (BN
  binary), `pharos-validator` (VC binary), `pharos-utils`.
- **Two binaries from day one**: `pharos` (beacon node) and `pharos-vc`
  (validator client).
- **Fork representation**: enum-of-forks with shared trait. No
  `superstruct`.
- **Preset generic**: trait `EthSpec` with associated constants;
  `MainnetEthSpec`, `MinimalEthSpec`, etc.
- **Storage**: `rocksdb` for the main chain DB, abstracted behind a
  `Store` trait. Hot/cold split designed into the trait from day one.
- **Slashing protection**: separate `rusqlite` DB in the VC. EIP-3076
  import/export from day one.
- **Networking**: raw `libp2p` + `discv5`. No vendoring of
  `lighthouse_network`.
- **Engine API client**: in-house. `reqwest` + `serde_json` + our own
  types + `jsonwebtoken`. No `alloy`. IPC support deferred.
- **Sync**: checkpoint sync first-class. **Backfill is required, not
  optional** — full historical reconstruction is a shipped feature.
- **Network configs / presets**: YAML loaders from
  `consensus-specs/{configs,presets}`. Custom networks first-class.
- **Observability**: `tracing` + `metrics` + Prometheus exporter wired
  from M0.
- **Testing**: spec tests are the floor. `proptest` for STF invariants,
  `cargo fuzz` for SSZ decode + `process_block`, differential fuzzing
  vs other clients later.
- **License**: Apache-2.0 + MIT dual.
- **Async runtime**: `tokio`.
- **Errors**: `thiserror` in libs, `anyhow` at binaries.
- **In-house core libs**: SSZ encode/decode, Merkleization, hashing
  wrappers, serde helpers, Engine API types, Beacon API types. No
  Lighthouse crates as runtime deps.

## Deferred (reserve traits, implement later)

- Slasher (chain-side, watches for slashable offenses).
- Builder API / MEV-Boost integration.
- Light-client server endpoints (consumer side later still).
- Engine API over IPC.
- Differential fuzzing vs Lighthouse / EthereumJS.
- **In-house `discv5` implementation.** M2 ships against the `sigp/discv5`
  crate (the only maintained Rust impl; Reth and OP Stack tools depend on
  it too). The "we own protocols with conformance suites" philosophy
  doesn't bite immediately because discv5 has no upstream spec-test
  suite, but long-term we want our own implementation under
  `crates/pharos-network/src/discovery/` with the `discv5` external dep
  retired. Scope: AES-128-GCM session crypto, ENR encoding (already
  partial in M2's ENR helpers), Kademlia-like XOR routing,
  PING/PONG/FINDNODE/NODES/TALKREQ/TALKRESP messages, ENR seq number
  management, NAT traversal. Conformance: interop pings against
  geth/reth/lighthouse on a local devnet. Realistic milestone window:
  post-M4 once the chain is talking to a real EL and the networking
  surface has settled.

## Still open

(none currently — all decisions locked.)

## Persistent collections (in-house)

`BeaconState` has fields like `validators: List<Validator, 1<<40>` that are
mutated every slot but ~99% identical slot-to-slot. We build our own
CoW-with-structural-sharing collection. The persistent data structure *is*
the SSZ Merkle tree.

### Properties
- Clone is `Arc::clone` of the root — O(1).
- `set(i, v)` is path-copy — O(log N) new nodes, rest shared.
- `hash_tree_root` cached per node; mutations invalidate up the path.
- Leaf chunking matches SSZ packing exactly so the tree root agrees with
  the spec without a translation layer.

### Sketch
```
enum Node {
    Leaf { chunk: [u8; 32], cached_root: OnceCell<H256> },
    Internal {
        left: Arc<Node>,
        right: Arc<Node>,
        cached_root: OnceCell<H256>,
    },
}

struct SszList<T, const N: u64> {
    tree: Arc<Node>,
    len: usize,
    depth: u8,
    _t: PhantomData<T>,
}
```

### Sequencing — does not block STF
1. **M0a**: define traits (`SszList`, `SszVector`) shaped for CoW.
2. **M0b**: naive `Vec`-backed impl behind the trait. STF + SSZ static
   tests run against it. Correct but slow.
3. **M0c**: drop in the persistent-tree impl. Same trait, no call-site
   churn.

### Tests
- Property tests: persistent impl vs `Vec`-backed reference must agree on
  every op.
- `ssz_static` spec tests exercise `hash_tree_root` on real `BeaconState`
  instances.
