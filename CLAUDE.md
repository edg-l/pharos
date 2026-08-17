# CLAUDE.md — Pharos

Fast index for AI sessions. Authoritative context: `docs/roadmap.md` (design),
`docs/decisions.md` (ADRs).

## What Pharos is

A from-scratch Ethereum proof-of-stake consensus client in Rust — beacon node
(`pharos`) + validator client (`pharos-vc`). Solo project; performance is a
first-class goal.

## Core principle

**If consensus-specs or an EIP ships a conformance test suite, we own the
implementation.** Upstream deps only for generic infra or crypto primitives
(BLS via `blst`, KZG via `c-kzg`). Not a wrapper around another client's crates: we
own SSZ, Merkleization, types, STF, fork choice, networking, Beacon/Engine API,
storage, VC, slashing.

## Locked decisions

- Workspace, 14 crates under `crates/`, two binaries.
- Sync STF, async I/O at the edges (`tokio` + `rayon`).
- Enum-of-forks with a shared trait. **No `superstruct`**.
- Preset-generic `BeaconSpec` trait (assoc constants); module path is still
  `pharos-types/src/eth_spec.rs`.
- Storage: `rocksdb` (chain, hot/cold) behind a `Store` trait; separate
  `rusqlite` file for VC slashing protection.
- Networking: raw `libp2p` + `discv5` (no vendored other-client networking crates).
- Engine API client: in-house `reqwest` + `serde_json` + `jsonwebtoken` (no `alloy`).
- Checkpoint sync first-class; backfill required.
- In-house persistent collections `SszList`/`SszVector` (the data structure IS
  the SSZ Merkle tree): `Flat` backend for decode/single-shot, `Tree` (CoW,
  `PackedLeaf` for packed basics) for live state. **No `milhouse`**.
- License Apache-2.0 + MIT. Errors: `thiserror` in libs, `anyhow` at binaries.

Rejected deps: `ethereum_ssz`, `tree_hash`, `ethereum_hashing`,
`ethereum_serde_utils`, `alloy*`, other-client networking crates, `milhouse`, `ssz_rs`,
`superstruct`.

## Workspace map

```
pharos-utils         base primitives (hashes, BLS, bytes)
pharos-ssz(-derive)  SSZ codec + Merkleization + persistent collections
pharos-types         per-fork containers, BeaconSpec
pharos-kzg           KZG over c-kzg
pharos-storage       Store trait + rocksdb hot/cold freezer
pharos-fork-choice   LMD-GHOST + FFG, optimistic sync, fast confirmation
pharos-stf           process_block / process_epoch (all forks)
pharos-engine        Engine API client (CL -> EL)
pharos-network       libp2p/discv5, gossip, req-resp
pharos-api           Beacon API server (axum)
pharos-conformance   spec-test runner + dashboard
pharos-node          beacon-node binary `pharos`
pharos-validator     validator binary `pharos-vc`
```

## Workflow

- Prefer `make` targets over raw cargo (output capture, pipefail, fast/full
  split). `make help`. Inner loop: `make test` / `make lint` / `make check`.
  Pre-commit: `make pre-commit`. Full gate: `make ci`.
- Rust 2024, MSRV 1.86. `cargo fmt` + clippy before commits.
- **Commit directly to `master`** (solo repo); no auto feature branches. No
  Co-Authored-By lines. Don't commit `CLAUDE.md` or planning artifacts.
- **Long runs** (workspace test, conformance, flamegraph, cold full builds):
  run ONCE per session; capture full output to `target/test-logs/<name>.log`
  then grep the file (don't re-run to filter); background them; never run two
  CPU-bound runs at once.
- **Conformance runs in the release / `conformance` profile, never debug**
  (debug times out). The harness's foreground Bash caps at 2 min — background
  anything longer.
- Watch disk: `target/debug` can balloon to 100s of GB; a full disk surfaces
  as a linker `Bus error`/SIGBUS (not "disk full") — `cargo clean` to reclaim,
  and clear `~/.cache/tmp`.

## Spec tests

Fixtures: `scripts/fetch-spec-tests.sh` → `~/.cache/pharos-spec-tests/`
(`$PHAROS_SPEC_TESTS`). `make conformance` writes `docs/conformance.md`.
`cargo test` is green without fixtures (conformance skips cleanly).

## EL pairing & reference repos

External EL over the Engine API; default `ethrex` (`~/dev/ethrex/`); reth/geth
also work. Spec/reference clones in `~/dev/`: `consensus-specs/` (specs +
fixtures), `EIPs/`, `beacon-APIs/`, `execution-apis/`.
