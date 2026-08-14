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
- Wire up `ethereum_ssz`, `tree_hash`, `blst`, `c-kzg` behind thin internal
  modules.
- `BeaconState` containers per fork, hash-tree-root caching with dirty
  tracking (not full recompute).
- Persistent / CoW collections for `List`/`Vector` fields — evaluate
  `milhouse` (sigp) vs rolling our own.
- Generalized indices + Merkle proofs.
- BLS verify / aggregate / fast aggregate verify wrappers, batch-verify
  helpers.

### M1 — Phase 0 STF + fork choice
- `process_block` + `process_epoch`.
- Parallelize epoch processing across validators with `rayon` where the
  spec permits.
- LMD-GHOST + FFG, justification, finalization.
- Run `consensus-specs` reference tests for `phase0` until green.
- No networking yet; drive STF from test vectors.

### M2 — Networking baseline
- discv5 peer discovery.
- libp2p gossipsub topics for Phase 0.
- SSZ-snappy req-resp domain.
- Peer scoring stub.

### M3 — Altair
- Sync committees, light-client gossip + req-resp.
- Spec tests `altair` green.

### M4 — Bellatrix + Engine API
- Engine API client (alloy) talking to a real EL (reth/geth/ethrex).
- First merged sync against a devnet.
- Spec tests `bellatrix` green.

### M5 — Capella
- Withdrawals, BLS-to-execution-change.
- Spec tests `capella` green.

### M6 — Deneb
- KZG commitments via `c-kzg`, blob sidecars, blob gossip topics.
- Spec tests `deneb` green.

### M7 — Beacon API
- `/eth/v1/beacon/*`, validator endpoints.
- Enough surface for an external VC to drive Pharos.

### M8 — Validator client (separate binary)
- Duties, signing, EIP-3076 slashing protection interchange.
- Keystore loading (EIP-2335).

### M9 — Electra
- EIP-6110, 7002, 7251, 7549, 7685, 7691.
- Spec tests `electra` green.

### M10 — Fulu / PeerDAS
- Column sidecars, custody, sampling.
- Spec tests `fulu` green.

### M11 — Productionization
- Checkpoint sync, weak subjectivity, backfill.
- Pruning, hot/cold DB split.
- Slasher.
- Metrics + tracing.

### Beyond
- Gloas / Heze (ePBS) once stable.
- Builder API (MEV-Boost) integration.

## Locked decisions

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
