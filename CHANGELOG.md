# Changelog

All notable changes to Pharos are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Pre-1.0 versions bump the minor segment on each milestone close.

## [Unreleased]

### Added — M3b (Altair, in flight)

- **Phase 3** — Altair STF epoch processing + state-transition entry. Twelve
  routines per `specs/altair/beacon-chain.md`: `process_justification_and_finalization`
  driven by participation flags, `process_inactivity_updates`,
  `process_rewards_and_penalties` over the three flag indices,
  `process_sync_committee_updates`, `process_participation_flag_updates`,
  `process_slashings` with the altair multiplier, plus seven thin
  resets/wrappers. Lib-level `state_transition` dispatcher matches the
  `BeaconState` fork enum and rejects phase0/altair mismatches with
  `UnsupportedFork`.
- **Phase 2** — Altair STF block operations and `upgrade_to_altair`.
  `process_attestation` with participation flags, `process_sync_aggregate`
  with the `G2_POINT_AT_INFINITY` edge case, `process_deposit` initialising
  participation entries, altair slashing operations.
- **Phase 1** — Altair containers and fork-enum promotion. `BeaconState`,
  `BeaconBlock`, `SignedBeaconBlock`, `BeaconBlockBody` become enums
  (`Phase0 | Altair`) in `pharos-types::state`; view-trait blanket impls
  delegate via match. Light-client containers per
  `specs/altair/light-client/sync-protocol.md`.
- **Phase 0** — `EthSpec` altair associated constants
  (`SYNC_COMMITTEE_SIZE`, `EPOCHS_PER_SYNC_COMMITTEE_PERIOD`,
  `INACTIVITY_PENALTY_QUOTIENT_ALTAIR`, etc.), `RuntimeConfig` skeleton.

### Added — tooling

- `Makefile` with user / dev / CI / utility / docker target groups; `make`
  with no arguments lists every target.
- Multi-stage `Dockerfile` (cargo-chef + BuildKit cache mounts, slim
  Debian runtime, non-root user, `tini`), `.dockerignore`.
- Build-time version metadata in `pharos-utils::version` (`PKG_VERSION`,
  `GIT_SHA`, `TARGET`, `BUILD_PROFILE`, `AGENT_STRING`, `LONG_VERSION`)
  via a `build.rs` that captures the short git SHA (with `-dirty`
  suffix). Wired into libp2p identify (`agent_version`) and
  `pharos --version`.

## [0.1.0] — milestone progress

### M3a — Phase 0 infrastructure (closed 2026-05-22)

- `pharos-storage` over RocksDB: schema-versioned column families, atomic
  `BlockTransition` via `WriteBatch`, snapshot-rehydration walk on warm
  restart.
- Real `Host<E>` replacing the M2 stub; `BlockProvider` reads from
  `pharos-storage`; `GossipValidator` runs the sync STF inside
  `tokio::task::spawn_blocking`; `MetaData` mutation guarded by
  `RwLock`.
- `NetworkEvent` expansion: `PeerSubscribed`, `PeerUnsubscribed`,
  `PeerIdentified`, `DialFailed`, `ExternalAddrConfirmed`.
- Goodbye-on-shutdown with `GOODBYE_CLIENT_SHUTDOWN = 1` and a bounded
  500ms broadcast.
- Monotonic `MetaData.seq_number` with `record_attnets_change`.
- Persistence smoke tests on `pharos-node` (single-host restart + two-node
  blocks-by-range round-trip across restart).
- Nine M3a ADRs in `docs/decisions.md`; roadmap split into M3a / M3b
  subsections.

### M2 — Networking baseline (closed)

- Raw `libp2p` 0.56 + `discv5` 0.10 (no vendored other-client networking crates).
  TCP + QUIC transports, gossipsub (SSZ-snappy, StrictNoSign), discv5
  discovery.
- Five req-resp methods: `Status`, `Goodbye`, `Ping`, `MetaData`,
  `BeaconBlocksByRange`, `BeaconBlocksByRoot`.
- Peer manager with Status handshake, `NoopScorer` stub.
- `NetworkBuilder` / `NetworkHandle` public surface; `Host<E>` trait
  family for block-provider / fork-context / gossip-validator.

### M1 — Phase 0 STF + fork choice (closed)

- `process_block`, `process_epoch`, all Phase 0 conformance categories
  green (`docs/conformance.md`).
- LMD-GHOST + FFG Casper (`pharos-fork-choice`): `on_block`, `on_tick`,
  `on_attestation`, `on_attester_slashing`, `get_head`,
  `get_proposer_head`, `update_checkpoints`.

### M0 — Foundations (closed)

- In-house SSZ encode/decode + Merkleization (no `ethereum_ssz` /
  `tree_hash`).
- `pharos-ssz-derive` for `#[derive(Encode, Decode, TreeHash)]`.
- Phase 0 containers, `EthSpec` preset trait, mainnet / minimal presets.
- BLS via `blst`; conformance harness.

[Unreleased]: https://github.com/edg-l/pharos/compare/master...HEAD
[0.1.0]: https://github.com/edg-l/pharos/releases/tag/v0.1.0
