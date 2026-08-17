# Pharos — Design reference

A Rust Ethereum consensus client. This document captures the durable design:
library philosophy, EIPs by fork, performance principles, project-wide locked
decisions, and the persistent-collection design. The shipped milestone history
lives in `CLAUDE.md` and `docs/decisions.md`.

**Performance is a first-class goal.** Correctness is the floor, speed is the
target; decisions below are biased toward latency and throughput.

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
`alloy*`, other-client networking crates, `ssz_rs`, `milhouse`.

Costs we accept: +1–2 months on M0 to write our own SSZ + Merkleization.
Benefit: full control of the hot path and the type system, no surprise
upstream churn, a real consensus client and not a re-skin.

### Independence guarantee

Pharos competes with the major CL clients (Prysm, Lodestar, Teku, Nimbus). It is
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

**Banned during implementation**: reading source from any other CL
client checkout (`~/dev/prysm/`, `~/dev/lodestar/`, `~/dev/teku/`, `~/dev/nimbus-eth2/`, etc.),
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
  ENR key naming (`quic`/`quic6`) that a CL client documented first
  and every CL client now follows. Adopting the convention is
  necessary for interop; document it in `docs/decisions.md` with a
  link to where the convention was published (NOT to another client's
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

- Function signatures that match another client's type exactly when the
  spec doesn't mandate that signature.
- File or module names that mirror another client's crate structure
  beyond what the spec organisation implies.
- Comments that reference another client's type / function / line.
- Identifier naming that follows another client's specific patterns
  (`NetworkGlobals`, `BeaconChainTypes`, `ChainSpec`, etc.).
- Test fixtures vendored from another client's checkout.
- Performance heuristics copied from another client's README or issue
  thread without a spec-based or measured justification.

Reviewers should treat any of these as a port-of-another-client signal and
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
  structural sharing). Some CL clients use `milhouse`; we should evaluate it or
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

## Cross-cutting (no single milestone)

These land somewhere across M0-M13; pinning the milestone here so they
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
  closure slice (hand-rolled reference-CL+ethrex+pharos devnet). The
  M3b carry-in for a gated
  `crates/pharos-network/tests/interop/cl_client_pair.rs` integration
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
- **Networking**: raw `libp2p` + `discv5`. No vendoring of another
  client's networking crate.
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
  other-client crates as runtime deps.

## Deferred (reserve traits, implement later)

- Slasher (chain-side, watches for slashable offenses).
- Builder API / MEV-Boost integration.
- Light-client server endpoints (consumer side later still).
- Engine API over IPC.
- Differential fuzzing vs another CL client / EthereumJS.
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
  geth/reth and a reference CL client on a local devnet. Realistic milestone window:
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
