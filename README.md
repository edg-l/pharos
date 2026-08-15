<p align="center">
  <img src="assets/logo.svg" alt="Pharos" width="128">
</p>

# Pharos

A from-scratch Rust Ethereum proof-of-stake consensus client.

**Status: pre-alpha, M3a done; M3b (Altair) in flight.** Not usable as a
node yet. Phase 0 conformance is at 100% (SSZ static + generic, operations,
epoch processing, sanity, finality, random, rewards, genesis, shuffling,
BLS) on both `mainnet` and `minimal` presets, zero failures. State
transition, LMD-GHOST + FFG fork choice, the M2 networking baseline
(`discv5`, `libp2p` gossipsub + req-resp, peer manager, Status/Goodbye
handshake), and the M3a infrastructure (`pharos-storage` + RocksDB,
real `Host<E>`, persistent restart) are in. Altair containers, STF
(block operations, `upgrade_to_altair`, epoch processing, state-transition
entry), and the enum-of-forks state shape have landed; Altair conformance,
context-bytes codec, MetaDataV2, light-client server, and the YAML preset
loader are the remaining M3b phases. Engine API client, Beacon API, and
validator client are on the M4+ roadmap.

## Philosophy

> If consensus-specs publishes a conformance test suite for it, we own the
> implementation.

The SSZ codec, Merkleization, persistent collections, type containers, fork
choice, STF, networking glue, Beacon API, and Engine API client are all
in-house. Pharos leans on upstream crates only for generic infrastructure
(async runtime, p2p, storage, HTTP, serde) and for cryptographic primitives
where the conformance suite validates I/O but not side-channel safety
(BLS12-381, KZG).

Performance is a first-class goal: sync STF core with async I/O at the edges,
CoW-friendly persistent collections, no `clone()` on `BeaconState` in hot
paths, hardware crypto, `rayon` for embarrassingly parallel state operations.
We build bench-conscious; benchmarks come once there is something end-to-end
to measure.

## Workspace

```
crates/
  pharos-utils         # primitives (hashes, BLS, Uint256, newtypes)
  pharos-ssz           # in-house SSZ encode/decode + Merkleization
  pharos-ssz-derive    # #[derive(Encode, Decode, TreeHash)]
  pharos-types         # Phase 0 + Altair containers, EthSpec, fork enum
  pharos-conformance   # spec-test runner + progress dashboard
  pharos-storage       # Store trait + rocksdb backend
  pharos-fork-choice   # LMD-GHOST + FFG Casper
  pharos-stf           # process_block / process_epoch (phase0 + altair)
  pharos-engine        # Engine API client (CL -> EL)    (skeleton)
  pharos-network       # libp2p + discv5 + gossip + req-resp
  pharos-api           # Beacon API HTTP server          (skeleton)
  pharos-node          # beacon-node binary `pharos`
  pharos-validator     # validator-client binary `pharos-vc` (skeleton)
```

Two binaries from day one: `pharos` (beacon node) and `pharos-vc` (validator
client). Separation is mandatory for sane key handling and a clean Beacon API
boundary.

## Roadmap (abbreviated)

- **M0 — Foundations.** SSZ + Merkleization, persistent collections, BLS
  wrappers, Phase 0 containers, EthSpec, conformance harness. **Done.**
- **M1 — Phase 0 STF + fork choice.** `process_block`, `process_epoch`,
  LMD-GHOST, justification, finalization. All Phase 0 conformance
  categories green. **Done.**
- **M2 — Networking baseline.** `discv5`, `libp2p` gossipsub, req-resp,
  Status/Goodbye, peer scoring stub. `NetworkHandle` + `NetworkBuilder`
  public surface, `Host<E>` trait family for the node binary to plug
  block-provider / fork-context / gossip-validator. **Done.**
- **M3a — Phase 0 infrastructure.** `pharos-storage` over RocksDB (atomic
  block transitions, snapshot-rehydration warm restart), real `Host<E>`
  replacing the M2 stub, `NetworkEvent` expansion (`PeerSubscribed`,
  `PeerIdentified`, `DialFailed`, `ExternalAddrConfirmed`),
  Goodbye-on-shutdown, monotonic `MetaData.seq_number`. **Done.**
- **M3b — Altair.** Sync committees, light-client server, MetaDataV2,
  context-aware req-resp codec, cross-fork ENR migration, YAML preset
  loader. Phases 0–3 in (EthSpec consts, containers + fork enum,
  STF block ops + `upgrade_to_altair`, STF epoch processing).
- **M4 — Bellatrix + Engine API.** First merged sync against a devnet.
- **M5–M10 — Capella, Deneb, Beacon API, validator client, Electra,
  Fulu (PeerDAS).**
- **M11 — Productionization.** Checkpoint sync, weak subjectivity, backfill,
  pruning, slasher, metrics.

Full roadmap: [`docs/roadmap.md`](docs/roadmap.md).

## Current conformance

Run the harness against the local fixtures cache:

```sh
make fetch-spec-tests        # one-time, downloads to ~/.cache/pharos-spec-tests
make conformance             # runs the suite and rewrites docs/conformance.md
```

The result lands at [`docs/conformance.md`](docs/conformance.md) and is
committed to git so progress is visible in history. Categories not yet
implemented appear as `-` so the table doubles as a roadmap.

## Building

A `Makefile` wraps the common cargo invocations. `make` (no arguments)
lists every target.

```sh
make build                   # release build of `pharos` and `pharos-vc`
make test                    # full workspace test suite
make lint                    # clippy --workspace --all-targets -D warnings
make fmt                     # cargo fmt --all
make ci                      # full CI gate: fmt-check + lint + check + test
```

Want raw cargo? Everything still works:

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Rust 2024 edition, MSRV 1.85. No nightly features.

## Running

The beacon node needs an SSZ-encoded genesis `BeaconState` at startup
(`--genesis-state-path`); there is no in-tree default. Once that is in
hand:

```sh
make run GENESIS_PATH=/path/to/genesis.ssz
# or override the data directory:
make run GENESIS_PATH=/path/to/genesis.ssz DATA_DIR=/var/lib/pharos
# pass extra flags through:
make run GENESIS_PATH=/path/to/genesis.ssz ARGS="--quic-only"
```

`make install` puts `pharos` and `pharos-vc` in `~/.cargo/bin`.

## Docker

A multi-stage Dockerfile is provided. It uses
[`cargo-chef`](https://github.com/LukeMathWalker/cargo-chef) plus BuildKit
cache mounts so dependency layers stay cached across source changes; the
runtime image is a slim Debian carrying only the two binaries, a
non-root `pharos` user, and `tini` for clean signal handling under
orchestrators (Kurtosis, k8s, compose).

```sh
make docker-build                          # builds pharos:dev
make docker-run GENESIS_PATH=$PWD/genesis.ssz
```

Ports exposed: `9000/tcp` (libp2p), `9000/udp` (discv5), `9001/udp`
(QUIC, optional). The container writes state under `/var/lib/pharos`;
mount a volume there for persistence.

## Pairing

Pharos talks to an external execution layer via the Engine API. Planned
default pairing is [`ethrex`](https://github.com/lambdaclass/ethrex);
`reth` and `geth` should also work once `pharos-engine` is wired up.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.
