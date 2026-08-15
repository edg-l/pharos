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
