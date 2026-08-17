<p align="center">
  <img src="assets/logo.svg" alt="Pharos" width="128">
</p>

# Pharos

A from-scratch Ethereum proof-of-stake consensus client, written in Rust.

Pharos is a beacon node and validator client that implements the Ethereum
consensus layer directly from the specifications: the SSZ codec and
Merkleization, the typed state containers, the state-transition function,
LMD-GHOST + Casper FFG fork choice, the libp2p/discv5 networking stack, the
Beacon API, the Engine API client, storage, and the validator. It is not a
wrapper around existing client crates.

Every consensus fork through **Fulu** (Fusaka) is implemented: Phase 0,
Altair, Bellatrix, Capella, Deneb, Electra, and Fulu, on both the `mainnet`
and `minimal` presets. Pharos tracks the live network: it peers, syncs,
imports, and produces blocks across cross-client devnets, and passes the
full consensus-specs conformance suite.

## Philosophy

> If consensus-specs (or an EIP) publishes a conformance test suite for it,
> we own the implementation.

The SSZ codec, Merkleization, persistent collections, type containers, fork
choice, state-transition function, networking glue, Beacon API, Engine API
client, storage, and validator logic are all in-house. Pharos depends on
upstream crates only for generic infrastructure (async runtime, p2p,
storage engine, HTTP, serde) and for cryptographic primitives where the
conformance suite validates I/O but not side-channel safety (BLS12-381 via
`blst`, KZG via `c-kzg`).

## Performance

Performance is a first-class goal, designed in rather than bolted on:

- A synchronous state-transition core with async I/O confined to the edges
  (`tokio` for I/O, `rayon` for parallel state operations).
- In-house copy-on-write persistent collections (`SszList`/`SszVector`)
  where the persistent data structure *is* the SSZ Merkle tree, with
  structural sharing and memoized subtree roots.
- Cached tree-hash roots on `Validator` and `BeaconState`, and
  derive-emitted field-level parallel Merkleization.
- Borrowing state accessors so hot paths never clone `BeaconState`.

## Architecture

Two binaries, separated from day one for clean key handling and a clean
Beacon API boundary: `pharos` (beacon node) and `pharos-vc` (validator
client).

```
crates/
  pharos-utils         # primitives (hashes, BLS, Uint256, newtypes)
  pharos-ssz           # in-house SSZ encode/decode + Merkleization
  pharos-ssz-derive    # #[derive(Encode, Decode, TreeHash)]
  pharos-types         # per-fork containers, EthSpec, fork enum
  pharos-kzg           # KZG wrappers over c-kzg (blob commitments/proofs)
  pharos-storage       # Store trait + RocksDB backend (hot/cold freezer)
  pharos-fork-choice   # LMD-GHOST + Casper FFG, optimistic sync
  pharos-stf           # process_block / process_epoch (all forks)
  pharos-engine        # Engine API client (CL -> EL JSON-RPC)
  pharos-network       # libp2p + discv5 + gossip + req-resp
  pharos-api           # Beacon API HTTP server (axum)
  pharos-conformance   # spec-test runner + progress dashboard
  pharos-node          # beacon-node binary `pharos`
  pharos-validator     # validator-client binary `pharos-vc`
```

Other locked design choices: enum-of-forks state with a shared trait (no
`superstruct`); a preset-generic `EthSpec` trait with associated constants;
RocksDB for chain data behind a `Store` trait with a hot/cold split, and a
separate `rusqlite` file for validator slashing protection; an in-house
Engine API client (`reqwest` + `serde_json` + `jsonwebtoken`); checkpoint
sync as a first-class path with required backfill.

## Conformance

Pharos is validated against the consensus-specs reference test vectors. Run
the harness against the local fixtures cache:

```sh
make fetch-spec-tests        # one-time, downloads to ~/.cache/pharos-spec-tests
make conformance             # runs the suite and rewrites docs/conformance.md
```

The result lands at [`docs/conformance.md`](docs/conformance.md) and is
committed to git so coverage is visible in history.

## Building

A `Makefile` wraps the common cargo invocations. `make help` lists every
target.

```sh
make build                   # release build of `pharos` and `pharos-vc`
make test                    # workspace test suite
make lint                    # clippy --workspace --all-targets -D warnings
make fmt                     # cargo fmt --all
make ci                      # full CI gate: fmt-check + lint + check + test
```

Raw cargo works too:

```sh
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

Rust 2024 edition, MSRV 1.86. No nightly features.

## Running

A live node uses checkpoint sync; alternatively the beacon node can start
from an SSZ-encoded genesis `BeaconState` via `--genesis-state-path` (there
is no in-tree default).

```sh
make run GENESIS_PATH=/path/to/genesis.ssz
# override the data directory:
make run GENESIS_PATH=/path/to/genesis.ssz DATA_DIR=/var/lib/pharos
# pass extra flags through:
make run GENESIS_PATH=/path/to/genesis.ssz ARGS="--quic-only"
```

`make install` puts `pharos` and `pharos-vc` in `~/.cargo/bin`.

Pharos talks to an external execution layer over the Engine API. The default
pairing is [`ethrex`](https://github.com/lambdaclass/ethrex); `reth`, `geth`,
and other EL clients work as well.

## Cross-client devnet

[`scripts/devnet/`](scripts/devnet/) brings up a hand-rolled, host-process
devnet (no Docker): a `lighthouse` BN+VC plus an `ethrex` EL produce a
reference chain, and `pharos` runs alongside driving its own `ethrex` EL over
the Engine API, peering in to follow the chain (and, with `pharos-vc`, to
propose).

```sh
scripts/devnet/gen-testnet.sh    # fresh genesis + testnet-dir + keys
scripts/devnet/run-devnet.sh     # lighthouse + ethrex (reference chain)
scripts/devnet/run-pharos.sh     # pharos + its own ethrex EL, peered in
scripts/devnet/stop-devnet.sh    # tear down
```

Prerequisites, ports, and interop notes are in
[`scripts/devnet/README.md`](scripts/devnet/README.md).

## Docker

A multi-stage Dockerfile uses
[`cargo-chef`](https://github.com/LukeMathWalker/cargo-chef) plus BuildKit
cache mounts so dependency layers stay cached across source changes. The
runtime image is a slim Debian carrying the two binaries, a non-root
`pharos` user, and `tini` for clean signal handling.

```sh
make docker-build                          # builds pharos:dev
make docker-run GENESIS_PATH=$PWD/genesis.ssz
```

Ports: `9000/tcp` (libp2p), `9000/udp` (discv5), `9001/udp` (QUIC,
optional). State is written under `/var/lib/pharos`; mount a volume there
for persistence.

## License

Dual-licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <https://www.apache.org/licenses/LICENSE-2.0>)
- MIT License ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.
