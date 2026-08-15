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

### M3 — Altair
- Sync committees, light-client gossip + req-resp.
- Spec tests `altair` green.
- **Spec wire-format changes**:
  - Context-aware req-resp encoding: each response chunk is prefixed with
    a fork-digest so the codec can decode per-fork types. M2 codec only
    handles Phase-0 encoding; M3 bumps the codec to handle context bytes.
  - `MetaDataV2` with the new `syncnets: BitVector<SYNC_COMMITTEE_SUBNET_COUNT>`
    field; bump req-resp protocol from `/metadata/1/ssz_snappy` to
    `/metadata/2/ssz_snappy` and dual-handle peers that negotiated v1.
  - New gossip topics: `sync_committee_*`, `sync_committee_contribution_and_proof`,
    `light_client_finality_update`, `light_client_optimistic_update`.
  - New req-resp methods: `LightClientBootstrap`, `LightClientUpdatesByRange`,
    `LightClientFinalityUpdate`, `LightClientOptimisticUpdate`.
- **Storage substrate** (currently 8 LOC of `pharos-storage/src/lib.rs`):
  - Real RocksDB-backed `Store` trait impl with hot/cold split design hooks
    (full impl is M11; M3 ships the schema + writes).
  - Column families: blocks, states (snapshots), block_root→slot index,
    forkchoice, metadata. Migrate-friendly schema version key.
  - `BlockProvider` real impl backing `pharos-network`'s `Host<E>` so
    `BeaconBlocksByRange` / `BeaconBlocksByRoot` return persisted blocks.
- **Host<E> + GossipValidator real impl** (replaces M2 stubs in
  `pharos-node/src/host_impl.rs`):
  - Decision per M2 R10: refactor `GossipValidator` to async (preferred) or
    keep sync and wrap STF calls in `tokio::task::spawn_blocking` at the
    call site. ADR before implementing.
  - `ForkContextImpl` wires `current_fork_digest()` to actual epoch (fork
    schedule from config / preset).
- **Network-event expansion** (deferred from M2 integration testing):
  - `NetworkEvent::PeerSubscribed { peer, topic }` /
    `PeerUnsubscribed { peer, topic }` — surface
    `gossipsub::Event::Subscribed`/`Unsubscribed` for peer scoring
    and mesh diagnostics.
  - `NetworkEvent::PeerIdentified { peer, info }` — surface
    `identify::Event::Received` for client tracking
    (agent_string, protocols).
  - `NetworkEvent::DialFailed { peer, error }` — surface
    `SwarmEvent::OutgoingConnectionError` so the peer manager can
    mark dead peers.
  - `NetworkEvent::ExternalAddrConfirmed { address }` — surface
    `SwarmEvent::ExternalAddrConfirmed` (AutoNAT/identify) so ENR
    can be updated with the observed address.
- Goodbye-on-shutdown: send `Goodbye(1 = ClientShutdown)` to every
  connected peer before tearing down the swarm
  (`specs/phase0/p2p-interface.md:1393`).
- `MetaData.seq_number` monotonic increment on attnets / syncnets
  change (M2 R13, `p2p-interface.md:391-393`).
- Cross-fork ENR migration + topic re-subscription at fork epochs
  (`eth2` ENR field re-publish with new sequence number).
- **Subnet rotation** driver in `pharos-node`: subscribe to attestation
  subnets per the spec's `compute_subscribed_subnets(node_id, epoch)`,
  rotate at epoch boundaries. Validator-duties-driven subscription is M8.
- **Light-client server side**: serve `LightClientBootstrap` etc. to
  light-client peers. Consumer-side (running a light client ourselves)
  stays deferred.
- `EthSpec` YAML preset loader (replaces hardcoded mainnet/minimal
  constants) — needed once custom networks become realistic.

### M4 — Bellatrix + Engine API
- Engine API client talking to a real EL (reth/geth/ethrex). In-house,
  no `alloy` (per locked decision).
- First merged sync against a devnet.
- Spec tests `bellatrix` green.
- **`pharos-engine` real impl** (currently 7 LOC of `lib.rs`):
  - Per-method endpoints: `engine_newPayloadV{1..N}`,
    `engine_forkchoiceUpdatedV{1..N}`, `engine_getPayloadV{1..N}`,
    `engine_exchangeCapabilities`. N grows with each fork (capella v2,
    deneb v3, electra v4).
  - Auxiliary `eth_*` endpoints the CL calls: `eth_chainId`,
    `eth_getBlockByHash`, `eth_getBlockByNumber`,
    `eth_syncing` (for EL health probes).
  - JWT auth: HMAC-SHA256 token signing per the
    `~/dev/execution-apis/src/engine/authentication.md` spec.
    Secret loaded from `--jwt-secret <path>` (32 random bytes hex).
  - EL health monitoring + simple failover for multi-EL setups
    (full failover policy is M11).
- **Engine API conformance**: add an `engine` category to
  `pharos-conformance`, walking `~/dev/execution-apis/src/engine/*.yaml`
  fixtures. Each YAML defines a method + expected I/O.
- **Checkpoint sync** (moved here from M11): mainnet has 11M+ slots;
  syncing from genesis is not viable. CLAUDE.md already commits to
  "checkpoint sync first-class." Wire endpoint:
  `--checkpoint-sync-url <beacon-api-url>` fetches finalized state +
  block from a trusted source, jumps fork choice to it. Weak
  subjectivity validation lives in M11.
- **Forward backfill** (moved here from M11): after checkpoint-sync
  jump, fill blocks slot-by-slot until head via `BeaconBlocksByRange`
  requests. Backward historical-state backfill stays M11.
- **fork-choice ↔ EL link**: every `on_block` that promotes the head
  triggers `engine_forkchoiceUpdated` to the EL with
  `(head_block_hash, safe_block_hash, finalized_block_hash)`. Reorgs
  trigger fresh fcU.
- **Invalid-payload tracking**: EL returns `{status: "INVALID"}` →
  CL marks the block invalid in fork choice (new flag on
  `ProtoArrayNode`) so it never re-becomes head.
- **Backpressure on network event channel**: M2 uses
  `try_send` which silently drops events under load. Bellatrix +
  Engine API load (every slot drives fcU + payload validation) needs
  bounded-but-non-dropping semantics. Bound the channel; switch to
  `send().await` with timeout where slow consumer is acceptable;
  document the choice per channel.
- **Performance regression suite**: first end-to-end thing exists at
  M4 (CL → EL → devnet). Add criterion benches for:
  `process_block` (Phase 0 → Bellatrix), `hash_tree_root` on
  `BeaconState`, gossip-validation latency, req-resp roundtrip.
  Bench results checked into a `bench-history/` file or committed
  Prometheus snapshots per release.

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

### M8 — Validator client (separate binary)
- Duties, signing, EIP-3076 slashing protection interchange.
- Keystore loading (EIP-2335).
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
- **Cross-client interop testing** (before M4 ships, since M4 = first
  merged sync): bring up Lighthouse + ethrex on localhost, have
  Pharos connect, verify Status / Ping / MetaData / BlocksByRange
  / BlocksByRoot roundtrips. Add as
  `crates/pharos-network/tests/interop/lighthouse_pair.rs` (gated
  behind a `--features lighthouse-interop` flag so it doesn't run
  in default `cargo test`).

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
