# Pharos Decisions Log

Permanent record of architectural and policy decisions taken during Pharos
development. Each entry is ADR-style: short statement, why, where the
decision is enforced. Plan files (`docs/m*-plan.md`) are gitignored agent
artifacts; this file is the canonical home for decisions once a milestone
ships.

For project-wide locked decisions, see `docs/roadmap.md` (workspace shape,
runtime, deps philosophy). Entries are grouped by milestone; M1 uses
numeric `D1`–`D8` / `Q1`–`Q4` keys, M2 onward uses descriptive
`D-<topic>` / `Q-<topic>` keys.

## Table of Contents

- [M1 — Phase 0 STF + fork choice](#m1--phase-0-stf--fork-choice)
  - D1 D2 D3 D4 D5 D6 D7 D8
  - Q1 Q2 Q3 Q4
- [M2 — Networking layer](#m2--networking-layer-pharos-network-phase-1)
  - Q-quic-enr D-libp2p D-discv5 D-runtime-ownership D-trait-boundaries
  - D-fork-digest-source D-channels D-test-runner D-peer-scoring
  - D-network-event-surface M-networking-spec-source
- [M3a — Infrastructure split of M3](#m3a--infrastructure-split-of-m3)
  - D-rocksdb D-store-trait D-gossip-validator-sync D-block-encoding-on-disk
  - D-storage-error-strategy D-peer-info-shape D-shutdown-protocol
  - D-metadata-mutation D-fork-schedule
- [M3b — Altair fork code](#m3b--altair-fork-code)
  - D-altair-state-shape D-context-bytes-codec D-metadata-v2-dual-handle
  - D-light-client-server-only D-ethspec-yaml-loader
  - D-altair-transition-test-strategy D-sync-aggregate-bls D-fork-schedule-source
- [M4a — Engine API + Bellatrix STF](#m4a-decisions)
  - D-engine-method-dispatch D-engine-head-driver D-payload-status-store
  - D-network-backpressure D-engine-conformance-runner D-bellatrix-state-shape
- [M4b — Checkpoint sync + forward backfill](#m4b-decisions)
  - D-anchor-as-weak-subj-root D-checkpoint-sync-source D-anchor-state-on-disk
  - D-backfill-driver D-engine-config-keepalive D-jwt-auto-gen
- [M4-perf — Tree-backed SSZ + tree-hash caching](#m4-perf-decisions)
  - D-tree-node-shape D-packed-as-full-chunk D-tree-backend-fields
  - D-validator-cache-clone-resets D-cached-root-wrapper D-no-tree-backend-on-decode
  - D-state-view-borrowing-accessors D-treehash-rayon-strategy
  - D-conformance-parallelism-dropped
- [M4c — LC gossip validation + broadcasting + criterion bench baseline](#m4c-decisions)
  - D-lc-gossip-validation-full-node-arm D-lc-snapshot-trait-on-host
  - D-lc-gossip-clock-window D-lc-broadcast-from-ingestion
  - D-lc-snapshot-write-trigger D-bench-location-per-crate D-bench-history-format
- [M4e — Beacon block + attestation + aggregate gossip validation](#m4e-decisions)
  - D-seen-cache-shape D-proposer-cache D-committee-cache D-verdict-strings-spec-keyed
  - D-bls-on-hot-path D-invalid-roots-cache D-future-slot-disparity
  - D-domain-types-additions D-is-aggregator-location D-cache-key-on-head
  - D-seen-cache-after-accept D-no-tokio-from-validator
- [M4d — Bellatrix gossip fork-migration](#m4d-decisions)
  - D-epoch-driven-fork-digest D-bellatrix-migration-startup-no-op
  - D-bellatrix-startup-topic-set D-gossip-block-decode-by-digest
  - D-bellatrix-reqresp-both-paths
- [M5 — Full block-following over gossip](#m5-decisions)
  - D-following-via-range-reconvergence D-byroot-lookup-deferred
- [M7-BeaconAPI](#m7-beaconapi)
  - D-api-chain-accessor D-api-dto-serde D-api-content-negotiation
  - D-api-fork-tag-envelope D-api-id-resolution D-api-sse-broadcast
  - D-api-axum-state D-api-validator-auth D-api-node-identity-cache

## M1 — Phase 0 STF + fork choice

### D1 — State mutation model: owned-mutate-return

STF functions take `state: E::BeaconState` by value and return
`Result<E::BeaconState, StateTransitionError>`. Internally they mutate
the owned state in place; for persistent `SszList` / `SszVector` fields,
helpers rebind via `field = field.with_set(i, new)?`.

Why: maps cleanly to the spec's mutating prose; one move at the boundary,
zero clones in the hot loop; persistent collections give structural
sharing for the list fields. A pure-return-fresh-state model would force
a deep clone on entry; an in-place `&mut BeaconState` model would
prevent callers from holding pre-state snapshots that the fork-choice
store needs.

Enforced in: `crates/pharos-stf/src/lib.rs::state_transition`,
`process_slots`, every `process_*` function in `phase0/`.

### D2 — Error strategy: single `StateTransitionError` enum in `pharos-stf`

One `thiserror` enum with structured variants
(`InvalidAttestation { reason: AttestationInvalidReason }` etc.). Per-op
sub-enums for fine-grained reasons. `pharos-ssz` and
`pharos-utils::BlsError` flow in via `#[from]`. Fork-choice gets its own
`ForkChoiceError` in `pharos-fork-choice` (different domain: store
invariants vs. STF rules).

Why: spec test fixtures only assert "this op rejects" vs. "accepts"; one
top-level enum keeps callers (and the conformance harness) on a single
`Result`. Sub-enums preserve diagnostic detail without polluting the
top-level surface.

Enforced in: `crates/pharos-stf/src/error.rs`,
`crates/pharos-fork-choice/src/error.rs`.

### D3 — Conformance harness: per-category dispatcher module + shared walker

`pharos-conformance` has one module per category (`operations.rs`,
`epoch_processing.rs`, `sanity.rs`, `finality.rs`, `random.rs`,
`rewards.rs`, `genesis.rs`, `shuffling.rs`, `bls.rs`, `fork_choice.rs`,
`ssz_static.rs`, `ssz_generic.rs`). Each exposes `run_*_preset` /
`run_*_mainnet` / `run_*_minimal`. Shared helpers in
`fixture_walker.rs` factor out the `walk_category` + `load_pre_post`
patterns.

Why: dispatchers are too heterogeneous (operations: pre/post + op;
epoch_processing: keyed by directory name; fork_choice: step tape) to
fold into one generic dispatcher, but the walking is identical. A
common walker keeps each module under ~300 LOC.

Enforced in: `crates/pharos-conformance/src/fixture_walker.rs`, each
per-category module.

### D4 — BLS verify policy: eager per-op verify in M1; batched at block boundary in M11

M1: each op that the spec verifies calls `bls::verify` /
`fast_aggregate_verify` eagerly. `process_block_header` does not check
the block sig; the outer `state_transition` does (per spec).

`state_transition` takes `validate_result: bool` (Q3): when `false`,
block-sig and final state-root checks are skipped, and the
`verify_signatures: bool` flag threaded into `process_block` / every
per-op processor disables per-op signature checks too. The flag is
wired through `bls_setting` in the conformance harness (S1).

Why: spec-correct, simplest, matches fixture expectations exactly.
Batched verify pays off only at gossip ingestion; without networking it
adds machinery for zero benefit and risks losing per-op error
localisation. The `SignatureSet` / `verify_signature_sets` API in
`pharos-utils::bls` is already in place, so the M11 swap is mechanical.

Enforced in: `crates/pharos-stf/src/lib.rs::state_transition`,
`process_block`, `process_randao`, `is_valid_indexed_attestation`, each
`process_<op>`.

### D5 — rayon strategy: global pool; parallel boundary inside epoch sub-routines only

`pharos-stf` does not own a pool. `process_rewards_and_penalties` and
`process_effective_balance_updates` use `rayon::iter` over the
validator-index range to compute per-validator deltas, then fold
sequentially into the balances list (since `SszList::with_set` is
single-writer CoW). STF API stays sync. Other epoch sub-routines
(`process_justification_and_finalization`, `process_registry_updates`,
`process_slashings`, all the `process_*_reset` routines,
`process_historical_roots_update`,
`process_participation_record_updates`) are not parallelised — they
have small fan-out or sequential dependencies; the spec wording forbids
reordering for `process_registry_updates` (churn-limit ordering
matters).

Why: avoids two thread pools when the node binary eventually adds its
own work; keeps `pharos-stf` dependency-light.

Enforced in:
`crates/pharos-stf/src/phase0/epoch/rewards_and_penalties.rs`,
`crates/pharos-stf/src/phase0/epoch/effective_balance_updates.rs`.

### D6 — Fork representation today: implicit per-preset monomorphisation via `EthSpec` associated types

`BeaconState<E>` as an enum-of-forks does NOT exist in M1.
`pharos-stf::state_transition` is
`pub fn state_transition<E: EthSpec>(state: E::BeaconState, signed_block: &E::SignedBeaconBlock, validate_result: bool) -> Result<E::BeaconState, StateTransitionError>`
and internally calls `phase0::state_transition::<E>(...)` directly. No
`match (&state, &block.message)` arm, no `BeaconState::Phase0(_)`
constructor.

M3 introduces an enum-of-forks wrapper and outer dispatch in
`state_transition`. The refactor is mechanical because every M1 call
site is already generic over `E`.

Why: with one fork, pretending to dispatch adds indirection for zero
benefit, and the enum cannot even be written today without first
introducing the second fork's container types.

The roadmap's "fork representation: enum-of-forks with shared trait"
applies from M3 onward; M1 ships the trait shape ahead of the variants.

### D7 — `EthSpec` carries container associated types

`EthSpec` declares
`type BeaconState`, `type BeaconBlock`, `type SignedBeaconBlock`,
`type BeaconBlockBody`, each bound by
`Encode + Decode + TreeHash + Clone + Debug + PartialEq + Eq + Default + Send + Sync + 'static`
plus the corresponding view trait (`BeaconBlockView<E = Self>` etc.).
Preset impls bind these to the per-preset aliases in `phase0::*`.

Every STF / fork-choice function signature reads `<E: EthSpec>` and
uses `E::BeaconState` etc. `Store<E>` follows the same pattern.

Why: with associated types on the spec trait, downstream call sites do
not need verbose `where` clauses to plumb the concrete container types,
and the M3 enum-of-forks migration is a single point of change.

Enforced in: `crates/pharos-types/src/eth_spec.rs`,
`crates/pharos-fork-choice/src/store.rs`, every STF entry point.

### D8 — Block-body field accessors via trait, not enum dispatch

`E::BeaconBlock`, `E::SignedBeaconBlock`, `E::BeaconBlockBody` are
opaque associated types. STF code accesses fields through the view
traits `BeaconBlockView`, `SignedBeaconBlockView`, `BeaconBlockBodyView`
in `crates/pharos-types/src/views.rs`. Const-generic parameters on
returned slices (`Attestation`, `AttesterSlashing`, `Deposit`) hang off
**associated types** on `BeaconBlockBodyView`, sidestepping the
unstable `generic_const_exprs` feature.

Why: stable Rust 1.85 cannot express
`fn attestations(&self) -> &[Attestation<{ <Self::E as EthSpec>::MAX_VALIDATORS_PER_COMMITTEE }>]`
directly. The associated-type indirection is the only stable form.

Enforced in: `crates/pharos-types/src/views.rs`,
`crates/pharos-stf/src/phase0/{block,operations,randao,eth1_data}.rs`.

## M1 — Resolved open questions

### Q1 — `phase0/fork_choice` row strategy

**Resolution**: the `phase0/fork_choice/{mainnet,minimal}` rows point at
`tests/{preset}/altair/fork_choice/`. Phase-0 fork-choice fixtures do
not exist upstream (consensus-spec-tests ships fork-choice cases
starting from altair).

**Footnote text** (must match verbatim across `docs/conformance.md` and
this entry):

> Phase-0 fork-choice fixtures do not exist upstream; runner exercises
> the M1 store against altair fork-choice fixtures, applying the
> skip-unknown-step-keys policy. Decision recorded in
> `docs/decisions.md` (Q1).

**Skip-unknown-step-keys policy**:

- Unknown top-level step variant (`on_merge_block`, `pow_block`,
  `on_payload_info`, `on_execution_payload_envelope`,
  `on_payload_attestation_message`, …) → the case is counted as
  **skip**, not fail.
- Unknown key inside a `checks` block is silently ignored. Examples:
  `viable_for_head_roots_and_weights`,
  `should_override_forkchoice_update`, `head_payload_status`,
  `payload_timeliness_vote`, `payload_data_availability_vote`,
  `genesis_time`.
- Anchor-state SSZ decode failure counts the case as **skip**. In M1
  the runner runs over `MainnetEthSpec` / `MinimalEthSpec` (phase-0),
  so every altair anchor state will fail to decode and every case will
  skip. The row goes live with `pass = 0`, `fail = 0`, `skip = N`.
  Altair types land in M3, at which point this runner produces real
  pass/fail counts without any code change.

Enforced in: `crates/pharos-conformance/src/fork_choice.rs`,
`crates/pharos-conformance/src/lib.rs` (per-preset row wiring + Q1
footnote registration).

**M3b resolution** (commit `784d75b`): Altair containers and the enum-of-forks
`BeaconState<E>` landed in M3b Phase 1 (`781a134`) and conformance wiring in
M3b Phase 4 (`784d75b`). The `phase0/fork_choice/{mainnet,minimal}` rows now
produce real non-zero pass counts; anchor states decode as `altair::BeaconState`
and all fork-choice steps execute against the M1 store. The skip-unknown-step-keys
policy is retained for bellatrix+ step types (e.g. `on_merge_block`, `pow_block`)
which continue to appear in the same fixture directory.

### Q2 — BLS conformance row scope

**Resolution**: the BLS conformance row is named `general/bls`. Only the
two sub-categories that exist in v1.6.1 are walked:
`eth_aggregate_pubkeys` and `eth_fast_aggregate_verify`. The other six
(`sign`, `verify`, `aggregate`, `fast_aggregate_verify`,
`aggregate_verify`, `batch_verify`) have no upstream fixtures in
`tests/general/altair/bls/` for v1.6.1; this is the **R-bls coverage
gap** documented in `crates/pharos-conformance/src/bls.rs`.

Coverage will be revisited when upstream restores fixtures or when M3
brings altair-specific BLS suites.

Enforced in: `crates/pharos-conformance/src/bls.rs`,
`crates/pharos-conformance/src/lib.rs` (`general/bls` row).

### Q3 — `validate_result` parameter on `state_transition`

**Resolution**: `state_transition` takes `validate_result: bool` from
day one. When `false`, both the block signature check and the final
state-root check are skipped (BLS verification is also skipped via the
`verify_signatures` flag threaded through `process_block`,
`process_randao`, every per-op processor, and
`is_valid_indexed_attestation`).

The conformance harness maps `bls_setting` (from `meta.yaml`) to
`validate_result`: `2` → `false`; otherwise `true`.

Enforced in: `crates/pharos-stf/src/lib.rs::state_transition`,
`crates/pharos-conformance/src/sanity.rs`,
`crates/pharos-conformance/src/finality.rs`,
`crates/pharos-conformance/src/random.rs`,
`crates/pharos-conformance/src/operations.rs`.

### Q4 — Per-preset rows for every new category

**Resolution**: every new conformance category emits a per-preset row
pair (`mainnet` + `minimal`), matching `ssz_static`. Exceptions:

- `phase0/genesis` ships only the `minimal` row — no mainnet genesis
  fixtures exist in v1.6.1.
- `general/bls` and `phase0/ssz_generic` are preset-independent
  (single `-` row).

Enforced in: `crates/pharos-conformance/src/lib.rs` (the
`all_categories()` table and the per-category dispatch blocks).

## M2 — Networking layer (pharos-network Phase 1)

### Q-quic-enr — ENR QUIC port keys

**Status**: Accepted. **Date**: 2026-05-21.

Two custom ENR keys are used to advertise QUIC transport endpoints:
`"quic"` (IPv4 QUIC UDP port, u16) and `"quic6"` (IPv6 QUIC UDP port,
u16). Values are stored via `Enr::builder().add_value(key, &port)`, which
RLP-encodes the u16; `get_decodable::<u16>(key)` round-trips correctly.

Source/precedent: the de facto Rust CL ecosystem convention (Lighthouse and
other CL clients use these exact key names). The consensus-specs
`p2p-interface.md` is silent on QUIC ENR keys for Phase 0; the key names
follow established inter-client practice.

Enforced in: `crates/pharos-network/src/discovery/enr.rs`
(`build_local_enr`, `read_quic_port`, `read_quic6_port`).

### D-libp2p — libp2p 0.56, TCP + QUIC, umbrella crate

**Status**: Accepted. **Date**: 2026-05-22.

The network crate consumes the libp2p umbrella crate at workspace
version `0.56` (`Cargo.toml:51`) with the feature set
`["tokio","tcp","quic","noise","yamux","gossipsub","dns","identify","ping","macros","secp256k1","request-response"]`.
No per-crate libp2p sub-dependency is pulled in directly.

Why the umbrella crate: a typed `SwarmBuilder` and a single semver
pin avoid the per-crate API churn that hit `libp2p-quic`, `libp2p-noise`,
and `libp2p-gossipsub` across 0.55–0.57. `quic` is a first-class flag
on the umbrella crate from 0.56 onward and pulls in `libp2p-quic 0.13`
(stable since June 2025).

Why `secp256k1`: discv5 ENRs are secp256k1-signed; reusing the same key
to derive the libp2p `PeerId` gives us a single identity across discv5
and libp2p without an adapter layer.

Why TCP + QUIC at M2 baseline: TCP is mandatory per
`specs/phase0/p2p-interface.md`; QUIC is the cross-client de-facto
upgrade path and is already deployed by Lighthouse, Prysm, and Teku.
WebRTC and WebTransport are deferred to M11.

Enforced in: `crates/pharos-network/Cargo.toml`,
`crates/pharos-network/src/network/mod.rs` (`NetworkBuilder::spawn`
`SwarmBuilder` chain),
`crates/pharos-network/src/network/behaviour.rs` (`NetworkBehaviour`
derives),
`crates/pharos-network/src/network/transport.rs` (TCP + QUIC stack).

### D-discv5 — discv5 0.10, no libp2p adapter, separate UDP port

**Status**: Accepted. **Date**: 2026-05-22.

Discovery uses `discv5 = 0.10.4` directly via `discv5::Discv5`, not the
`libp2p-discv5` adapter. It runs on its own UDP socket on the configured
discovery port (default `9000`), independent of the libp2p TCP/QUIC
sockets. The discv5 event loop runs in its own `tokio::task` and feeds
`Discv5Event::Discovered` peers into the peer manager via an internal
channel.

Why not the adapter: the libp2p discv5 adapter trails the upstream
`sigp/discv5` release stream and historically lags new ENR features by
several months. We need direct access to `Enr::add_value` (for the
`"quic"`/`"quic6"` keys per Q-quic-enr) and to the raw `Discv5Event`
stream for fork-digest-aware filtering in M3. Going through the adapter
would lose both.

API divergences captured during implementation (`mem_b7efb7d5`):
`discv5::Enr` is a type alias to `enr::Enr<CombinedKey>` (not generic);
`discv5::Discv5::new` returns `Result<Self, _>`; the configured
listener address is read via `Discv5::local_enr().udp4_socket()`.

Enforced in: `crates/pharos-network/src/discovery/service.rs`,
`crates/pharos-network/src/discovery/enr.rs`.

### D-runtime-ownership — Swarm owned by a single network task; NetworkHandle is a cheap command sender

**Status**: Accepted. **Date**: 2026-05-22.

`pharos-network::Network<E, H, S>` holds the libp2p `Swarm<Behaviour>`
and runs `Swarm::select_next_some` in a single `tokio::task` driven by
`Network::run` (`crates/pharos-network/src/network/mod.rs:180`).
`NetworkHandle` (`crates/pharos-network/src/handle.rs`) is a clone-cheap
struct holding `mpsc::Sender<NetworkCommand<E>>` plus an
`mpsc::Receiver<NetworkEvent>` cursor. All outbound operations cross the
command channel:

- `Publish { topic, data }`
- `Subscribe { topic, reply }`
- `Dial { addr, reply }`
- `Disconnect { peer_id }` (Goodbye reason carried via behaviour
  bookkeeping, see Phase 6/8 work)
- `OutgoingRequest { peer, req, reply }`
- `Shutdown`

Why: keeps the `Swarm` single-owner (no `Arc<Mutex<_>>`), matches
canonical libp2p idioms, and gives `pharos-node` an ergonomic surface
that does not require holding the runtime. The `_, H: Host<E>, S:
PeerScorer` generics keep the network task plumbing-only; concrete
host/scorer impls live in `pharos-node` (M2/M3).

Enforced in: `crates/pharos-network/src/network/mod.rs`
(`Network`, `NetworkCommand`, `on_command`),
`crates/pharos-network/src/handle.rs`,
`crates/pharos-network/src/network/mod.rs` (`NetworkBuilder::spawn`).

### D-trait-boundaries — Host<E> owns inbound RPC dispatch

**Status**: Accepted. **Date**: 2026-05-22.

The `Host<E: EthSpec>` trait, composed of `ForkContext`, `BlockProvider`,
and `GossipValidator`, is held by the network task and dispatched
synchronously when an inbound req-resp message arrives. The earlier
Task 7.1 sketch included `NetworkEvent::RpcRequest { peer, request,
response: oneshot::Sender<RpcResponse<E>> }` which would have forwarded
inbound RPC out to the `NetworkHandle` consumer; this variant was
removed during Phase 7.

Rationale: throughput is equivalent (channel hop is ~200-400 ns, negligible
against ~10-100 ms storage-bound RPC like `BlocksByRange`). Tail latency is
strictly better under the Host pattern because the network task is not
coupled to a consumer queue — a slow consumer cannot stall inbound RPC.
The Host pattern also matches Phase 5's existing `handle_request` and
Phase 8 tests (which preload `TestHost::BlockProvider`).

Enforced in: `crates/pharos-network/src/network/mod.rs`
(`on_request_response_event` → `handle_request` → `Host` method calls).
`NetworkEvent` enum has no `RpcRequest` variant.

### D-fork-digest-source — `pharos-types::fork`

**Status**: Accepted. **Date**: 2026-05-22.

`compute_fork_data_root` and the new `compute_fork_digest` both live in
`crates/pharos-types/src/fork.rs` and are re-exported as
`pharos_types::fork::{compute_fork_data_root, compute_fork_digest}`.
`pharos-stf::phase0::accessors::compute_fork_data_root` is now a
`pub use` re-export so STF callers are unchanged.

Why: `pharos-network` needs the digest computation (ENR `eth2` field,
gossipsub topic prefixes, Status handshake) and depending on
`pharos-stf` from the network crate would invert the layering
(net → stf → types is wrong; net → types is right). `pharos-utils` is
the alternative home but `Root` and `Version` live in
`pharos-types::phase0::primitives`, so the math belongs there.

Spec refs are inlined: `compute_fork_data_root` →
`specs/phase0/beacon-chain.md:936-948`; `compute_fork_digest` →
`specs/phase0/p2p-interface.md:269-285`.

Enforced in: `crates/pharos-types/src/fork.rs`,
`crates/pharos-stf/src/phase0/accessors.rs` (re-export shim),
`crates/pharos-network/src/discovery/enr.rs` (consumer for ENR `eth2`),
`crates/pharos-network/src/topics.rs` (consumer for topic prefix).

### D-channels — `tokio::sync::mpsc`, bounded, drop-on-full for inbound

**Status**: Accepted. **Date**: 2026-05-22.

The network task uses bounded `tokio::sync::mpsc` channels with explicit
sizing tuned for ~2 slots of worst-case mainnet load:

- **Outbound command channel** `NetworkHandle → Network`:
  `mpsc::channel(64)`. Callers `.await` on full — back-pressure is
  acceptable because commands are infrequent and the handle is in user
  code paths that can yield.
- **Outbound event channel** `Network → NetworkHandle`:
  `mpsc::channel(1024)`. The Phase 7 design unified the M2-acceptance
  event surface into one stream (`NetworkEvent`); per-domain channels
  (gossip / req-resp / validator-result) sketched in the original
  plan were collapsed because the consumer side does a single
  `select!` over them.

Inbound req-resp does NOT cross a channel: the `Host<E>` traits are
called synchronously from the network task (see D-trait-boundaries),
which removes a class of head-of-line stalls.

Why bounded + drop / await: networking is naturally lossy. Unbounded
channels are a memory-DoS surface against a hostile peer. Drop-on-full
on the inbound path prevents head-of-line blocking; await on the
outbound command path is fine because the publisher set is small and
trusted (`pharos-node` + integration tests). Dedicated drop counters
(`gossip_dropped_total{topic=…}`, `req_resp_dropped_total{method=…}`,
`validator_result_dropped_total`) land with the metrics work in M11; the
channels and overflow paths are wired today.

Enforced in: `crates/pharos-network/src/network/mod.rs:1163-1164`
(`mpsc::channel::<NetworkCommand<E>>(64)`,
`mpsc::channel::<NetworkEvent>(1024)` inside `NetworkBuilder::spawn`),
`crates/pharos-network/src/handle.rs`.

### D-test-runner — integration tests live in `crates/pharos-network/tests/`

**Status**: Accepted. **Date**: 2026-05-22.

M2 wire-level behaviour is verified by hand-written integration tests
under `crates/pharos-network/tests/`
(`discovery.rs`, `goodbye.rs`, `gossip.rs`, `quic_connect.rs`, `rpc.rs`,
plus a `common/` module for shared spin-up). Each test is a
`#[tokio::test(flavor = "multi_thread")]` that:

1. Builds a `MockHost` (in-memory `BlockProvider` + `ForkContext` +
   `GossipValidator` returning fixed values).
2. Spins up two `NetworkHandle`s on `127.0.0.1:0` (OS-assigned ports).
3. Wires one peer's listen `Multiaddr` as the other's bootnode.
4. Drives the public `NetworkHandle` API and asserts protocol-level
   behaviour (subscription, message delivery, request/response,
   goodbye reason routing).

Per the gossipsub flake mitigation (`95785a5`), the gossip integration
tests are annotated with `#[serial_test::serial]` to serialize them
within the `gossip` test binary, because parallel libtest execution
caused mesh-formation timing to race under CPU contention. Other test
binaries (`discovery`, `rpc`, `quic_connect`, `goodbye`) remain
parallel. `serial_test = "3"` is a `dev-dependency` of `pharos-network`
only (`crates/pharos-network/Cargo.toml:41`).

Why not a dedicated test crate: workspace lean-ness. The tests already
need to import `pharos-network` internals (`MockHost`, `NetworkBuilder`,
codec helpers) and a sibling crate would either re-export those as `pub`
(polluting the public API) or be redundant. Why not consensus-specs
fixtures: there are none for networking — see `M-networking-spec-source`.

Enforced in: `crates/pharos-network/tests/*.rs`,
`crates/pharos-network/tests/common/`,
`crates/pharos-network/Cargo.toml` (`dev-dependencies`).

### D-peer-scoring — `PeerScorer` trait, `ScoreEvent` enum, `NoopScorer` for M2

**Status**: Accepted. **Date**: 2026-05-22.

`crates/pharos-network/src/scoring.rs` defines:

```rust
pub trait PeerScorer: Send + Sync + 'static {
    fn record(&mut self, peer: PeerId, event: ScoreEvent);
    fn score(&self, peer: &PeerId) -> f64;
    fn worst_peers(&self, n: usize) -> Vec<PeerId>;
}

pub enum ScoreEvent {
    GossipAccept { topic: TopicHash },
    GossipReject { topic: TopicHash, reason: String },
    GossipIgnore { topic: TopicHash, reason: String },
    RpcSuccess   { method: RpcMethod },
    RpcError     { method: RpcMethod, kind: RpcErrorKind },
    RpcTimeout   { method: RpcMethod },
    PeerConnected,
    PeerDisconnected { reason: DisconnectReason },
    HandshakeFail    { kind: HandshakeFailKind },
}
```

`Network<E, H, S: PeerScorer>` is generic over the scorer. M2 ships
`NoopScorer`, which returns `0.0` from `score`, an empty `Vec` from
`worst_peers`, and ignores `record`. Every call site that should emit a
scoring event already calls `record(...)` with the correct variant; the
real algorithm lands in M11 by swapping the scorer impl without
touching network plumbing.

Plan-deviation: the original m2-plan listed `RpcErrorKind::Timeout` as a
nested variant; Phase 0 introduced a top-level `ScoreEvent::RpcTimeout
{ method }` instead, because timeouts are transport-level (no protocol
error code on the wire) and shoehorning them under `RpcErrorKind` would
have leaked transport semantics into the protocol-error type. Captured
in `mem_af337e8a`. The doc-comment at
`crates/pharos-network/src/scoring.rs:55` records the rationale inline.

Why pre-wire the trait now: avoids API churn in dependent crates when
the real implementation lands. Every `Score{Event,r}` consumer (gossip
validator dispatch, RPC handler, peer manager) is already in place.

Enforced in: `crates/pharos-network/src/scoring.rs`,
`crates/pharos-network/src/network/mod.rs`
(`Network<E, H, S>`, `record` call sites),
`crates/pharos-network/src/peer/`,
`crates/pharos-network/src/rpc/`.

### D-network-event-surface — what NetworkEvent exposes (and what it doesn't)

**Status**: Accepted. **Date**: 2026-05-22.

The M2 `NetworkEvent` enum surfaces only the events a beacon-node
consumer needs for the M2-acceptance set: `PeerConnected`,
`PeerDisconnected`, `GossipMessage`, `NewListenAddr`, `LocalEnr`,
`Shutdown`. The following libp2p sub-protocol events are received but
not yet surfaced on the public API; each is logged at `tracing::debug!`
and routed to per-milestone follow-ups in `docs/roadmap.md`:

- M3a (infrastructure split) — implemented in M3a Phase 3
  (`crates/pharos-network/src/network/mod.rs` gossip/swarm arms):
  - `gossipsub::Event::Subscribed`/`Unsubscribed` → `PeerSubscribed`/`PeerUnsubscribed`
    (lines 356-375, `on_gossip_event`). `PeerUnsubscribed` ships but has no
    dedicated integration-test coverage; a test is deferred to M11 or a
    future maintenance pass per the Phase 6 audit.
  - `identify::Event::Received` → `PeerIdentified` (line 312, `on_identify` helper).
  - `SwarmEvent::OutgoingConnectionError` → `DialFailed` (line 316).
  - `SwarmEvent::ExternalAddrConfirmed` → `ExternalAddrConfirmed` (line 332).
    ENR update remains deferred to M3b (cross-fork ENR migration).
- M11 (productionization) follow-ups:
  - `gossipsub::Event::SlowPeer`, `GossipsubNotSupported` (real peer scoring).
  - `ping::Event` per-peer RTT (dead-peer detection).
  - Remaining `SwarmEvent` variants (`IncomingConnectionError`,
    `NewExternalAddrOfPeer`, `ExpiredListenAddr`, `ListenerError`,
    `ListenerClosed`).

Rationale: M2 acceptance is wire-level correctness, not operational
observability. Adding event variants at M2 cost only API surface; using
them productively requires the peer-scoring substrate that lives in M11
and the cross-fork ENR/topic logic that lives in M3. Locking the
follow-ups into the roadmap at M2-close prevents drift.

### M-networking-spec-source — consensus-specs has no networking suite

**Status**: Methodology note. **Date**: 2026-05-22.

`consensus-specs/tests/formats/` ships fixtures for SSZ, STF, fork
choice, light client, KZG/BLS, etc. — but NOT for networking, gossipsub,
or req-resp. This is industry-wide (Lighthouse, Prysm, Lodestar, Teku,
Nimbus all hand-roll their networking tests). Pharos spec rigor for the
network crate is therefore enforced via:

1. **Inline citations** from code to spec lines in
   `specs/phase0/p2p-interface.md` (varint `:1264-1267`,
   IrrelevantNetwork `:1394`, gossipsub `StrictNoSign` `:482-484`, etc.).
2. **Hand-written integration tests** in `crates/pharos-network/tests/`
   (TCP+QUIC connect, discovery, gossip with reject topology, RPC
   round-trips, fork-digest goodbye).
3. **Phase 9 Task 9.7** spec-vs-code line audit at every networking
   milestone (M2 close, M3 close).
4. **Cross-client interop tests** against Lighthouse + ethrex planned
   for M4 (before first merged sync), to be added in `crates/pharos-network/tests/interop/`.

`#[serial_test]` is used to serialize the gossip integration tests
within their binary (Phase 8 wrap-up amendment) because parallel libtest
execution causes gossipsub mesh-formation timing to race under CPU
contention; this is a test harness concern, not a production
correctness issue.

## M3a — Infrastructure split of M3

### D-rocksdb — Column-family layout, schema versioning, big-endian slot keys

**Status**: Accepted. **Date**: 2026-05-22.

`pharos-storage` opens a single RocksDB directory with seven column
families (CFs): `default` (required by RocksDB, left empty), `blocks`,
`block_root_to_slot`, `slot_to_block_root`, `states`, `forkchoice`, and
`metadata`. All seven are registered at open time via
`DB::open_cf_descriptors`
(`crates/pharos-storage/src/db.rs:71`).

Key/value shapes per CF:

| CF | Key | Value |
|---|---|---|
| `blocks` | `Root` (32 B) | SSZ `SignedBeaconBlock` |
| `block_root_to_slot` | `Root` (32 B) | `u64` LE (slot) |
| `slot_to_block_root` | `u64` BE (slot) | `Root` (32 B) |
| `states` | `Root` (32 B) | SSZ `BeaconState` |
| `forkchoice` | `b"forkchoice"` (literal) | SSZ `ForkChoiceSnapshot` |
| `metadata` | string bytes | raw bytes |

Slot keys in `slot_to_block_root` are stored as big-endian `u64` so that
RocksDB's default lexicographic comparator produces ascending numeric
order, enabling correct `Iterator::seek`-based range scans without a
custom comparator
(`crates/pharos-storage/src/keys.rs:19`, `crates/pharos-storage/src/cf.rs:21`).

Schema versioning: on first open, `metadata[b"schema_version"]` is
written as `1u32` (little-endian 4 bytes). On subsequent opens the
stored value is read and compared to `SCHEMA_VERSION = 1`; a mismatch
returns `StorageError::SchemaMismatch { found, expected }` so an
out-of-date binary fails fast rather than misreading data
(`crates/pharos-storage/src/db.rs:29`, `db.rs:76-96`).

Warm-restart rehydration walk: on node restart, `get_forkchoice_snapshot`
returns the persisted `ForkChoiceSnapshot` (finalized checkpoint, head
root, genesis time, `last_known_time`). The node binary calls
`rehydrate_fork_choice_store` (`crates/pharos-node/src/startup.rs`) which
anchors at `finalized_checkpoint.root` and walks forward through
`slot_to_block_root` to rebuild the in-memory `pharos_fork_choice::Store<E>`
block and state maps. After rehydration, `on_tick` is called with the
current wall-clock time to advance the fork-choice time cursor from the
stale `last_known_time`
(`crates/pharos-node/src/main.rs:155-159`).

### D-store-trait — Sync storage trait, BlockTransition atomic batches, non-generic ForkChoiceSnapshot

**Status**: Accepted. **Date**: 2026-05-22.

`Store<E: EthSpec>` is a synchronous trait (`crates/pharos-storage/src/store.rs:22`).
RocksDB is a synchronous library; the STF and fork-choice algorithms
are also synchronous. Async callers (the network task, the gossip
validator dispatcher) wrap calls in `tokio::task::spawn_blocking`.
`Send + Sync + 'static` bounds on `Store<E>` allow sharing behind
`Arc<dyn Store<E>>`.

Multi-row writes (block + state + fork-choice snapshot + slot indices)
are committed as a single `rocksdb::WriteBatch` via
`write_block_transition(&self, batch: BlockTransition<E>)`
(`crates/pharos-storage/src/store.rs:78`,
`crates/pharos-storage/src/db.rs:230`). A crash between two un-batched
writes would leave the slot index out of sync with the `blocks` CF; the
WriteBatch WAL contract prevents this.

`ForkChoiceSnapshot` (`crates/pharos-storage/src/forkchoice.rs:32`) is
non-generic: it holds only cursor scalars (checkpoints, roots, `last_known_time`,
`genesis_time`, `head_root`, `head_slot`). The in-memory `blocks` and
`block_states` HashMaps of `pharos_fork_choice::Store<E>` are NOT
persisted; they are rebuilt from the `blocks`/`states` CFs on warm
restart. This avoids any proto-array fiction: the snapshot stores what the
spec checkpoints dictate, nothing more.

### D-gossip-validator-sync — Sync GossipValidator trait, spawn_blocking at call site

**Status**: Accepted. **Date**: 2026-05-22.

`GossipValidator<E>` methods (`validate_beacon_block`,
`validate_attestation`, etc.) are synchronous
(`crates/pharos-network/src/host.rs`). The gossip dispatch path in the
network task calls them directly via `dispatch_gossip_message`
(`crates/pharos-network/src/network/mod.rs:436`). For M3a the methods
return `GossipVerdict::Accept` immediately (bodies are M4); no blocking
actually occurs.

When M4 fills the validation bodies with real STF calls, the call site
(`dispatch_gossip_message`) must be wrapped in
`tokio::task::spawn_blocking` because STF is CPU-bound and would stall
the network event loop. The decision to keep the trait sync (rather than
`async fn`) is intentional: sync traits are object-safe, easier to test
without an async runtime, and align with the "sync STF, async I/O at the
edges" project principle. The wrapping responsibility lies at the
`on_gossip_message` call site, not inside the trait.

Risk note: tokio's default blocking pool has 512 threads. A sustained
gossip flood of more than 512 simultaneous in-flight validations would
exhaust the pool. M11 peer scoring rate-limits per-peer gossip ingest
before it reaches the validator, which is the intended mitigation path.

### D-block-encoding-on-disk — SSZ-only encoding, Lz4 compression on blocks and states CFs

**Status**: Accepted. **Date**: 2026-05-22.

All values written to `blocks` and `states` CFs are raw SSZ bytes
(`block.as_ssz_bytes()`, `state.as_ssz_bytes()`) with no additional
framing or checksum. SSZ is the Ethereum canonical wire and archival
format; using it on disk means the stored bytes are exactly what
`BeaconBlocksByRange` would send on the wire, eliminating a
serialization step on the read path.

RocksDB-level Lz4 block compression is enabled on the `blocks` and
`states` CFs via `DBCompressionType::Lz4` in per-CF `Options`
(`crates/pharos-storage/src/db.rs:117`). Other CFs (`slot_to_block_root`,
`block_root_to_slot`, `forkchoice`, `metadata`) use RocksDB's default
(no compression; rows are too small to benefit). Lz4 was chosen over
snappy to avoid confusion with the gossipsub snappy-block framing used
on the wire, and over zstd for its lower decompression latency.

### D-storage-error-strategy — Single StorageError enum, thiserror, #[from] from upstream

**Status**: Accepted. **Date**: 2026-05-22.

All `pharos-storage` operations return `Result<_, StorageError>` where
`StorageError` is a single `thiserror`-derived enum
(`crates/pharos-storage/src/error.rs:8`). `#[from]` is used for the two
upstream error sources: `rocksdb::Error` (variant `RocksDb`) and
`pharos_ssz::SszError` (variant `SszDecode`). Remaining variants are
structured (`SchemaMismatch { found, expected }`, `ColumnFamilyNotFound`,
`KeyNotFound`, `InvalidKeyLength { got, expected }`, `Io`). This mirrors
the M1 `D2` decision for `StateTransitionError` and keeps callers on a
single `Result` type without sub-enums.

### D-peer-info-shape — PeerInfo fields, identify-flood mitigation, unknown-peer drop

**Status**: Accepted. **Date**: 2026-05-22.

`PeerInfo` (`crates/pharos-network/src/types.rs:69`) holds:
- `agent_string: Option<String>` — agent version from the identify protocol
  (e.g. `"Lighthouse/v4.0.0"`).
- `protocols: Vec<String>` — protocol IDs advertised by the peer via identify.
- `observed_addr: Option<Multiaddr>` — the address the peer reports it
  observed for our local node.

These three fields are populated from `identify::Event::Received` in
`on_identify` (`crates/pharos-network/src/network/mod.rs:767`). They are
`None` / empty until the first identify exchange completes.

Identify-flood mitigation: `on_identify` calls
`peer_manager.update_identify`, which returns `None` when the peer is not
in the connected-peer map. Unknown-peer identify events are silently dropped
(`crates/pharos-network/src/network/mod.rs:779`). For known peers,
`update_identify` overwrites the previous `agent_string`, `protocols`, and
`observed_addr` in place (per-peer overwrite), so memory stays `O(num_peers)`
regardless of how many times a peer pushes identify.

### D-shutdown-protocol — Best-effort Goodbye on shutdown, 500ms timeout, ClientShutdown=1

**Status**: Accepted. **Date**: 2026-05-22.

When the network task receives `NetworkCommand::Shutdown` (or the
shutdown signal fires), `shutdown_goodbye` is called before exiting the
event loop (`crates/pharos-network/src/network/mod.rs:1000`). The method:

1. Collects all `Connected` peers from the peer manager.
2. For each peer, pre-registers `DisconnectReason::Goodbye(1)` and sends
   `RpcRequest::Goodbye(GOODBYE_CLIENT_SHUTDOWN)` fire-and-forget.
3. Runs `drain_outbound_requests` inside a 500 ms `tokio::time::timeout`.
   The timeout result is discarded (ok = all acknowledged, Err = timed out;
   either path continues to step 4).
4. Force-disconnects each peer via `swarm.disconnect_peer_id`.

`GOODBYE_CLIENT_SHUTDOWN = 1` matches the reason code table in
`specs/phase0/p2p-interface.md:1393`
(`crates/pharos-network/src/types.rs:106`). The 500 ms bound prevents a
slow or unresponsive peer from delaying a clean shutdown indefinitely.

### D-metadata-mutation — RwLock<MetaData> on HostImpl, record_attnets_change idempotency

**Status**: Accepted. **Date**: 2026-05-22.

`HostImpl<E>` holds `metadata: RwLock<MetaData>` (via `parking_lot::RwLock`)
(`crates/pharos-node/src/host_impl.rs:75`). All `ForkContext::local_metadata`
calls take a read lock and clone the 16-byte struct; `record_attnets_change`
takes a write lock only when the caller provides a new attnets bitvector.

`record_attnets_change(new_attnets)` (`crates/pharos-node/src/host_impl.rs:138`)
bumps `seq_number` only when `new_attnets != md.attnets` (idempotent on
the same value). Increment is wrapping-add per the spec
(`p2p-interface.md:391-393`). At startup, the method is called once from
`main.rs` to set the initial attestation subnet bitfield computed by
`compute_subscribed_subnets`, which bumps `seq_number` from 0 to 1
(`crates/pharos-node/src/main.rs:200`). The M3b subnet-rotation epoch
driver will call it every `EPOCHS_PER_SUBNET_SUBSCRIPTION` epochs.

Lock contention is negligible: reads are concurrent; writes happen at most
once per epoch boundary (roughly every 384 seconds on mainnet).

### D-fork-schedule — Phase-0-only ForkSchedule, fork_schedule() accessor, forward-compatible shape

**Status**: Accepted. **Date**: 2026-05-22.

`ForkSchedule` (`crates/pharos-types/src/fork.rs:50`) lives in
`pharos-types::fork` so both `pharos-node` and `pharos-network` can
depend on it without a back-edge. Flat-field shape:

```rust
pub struct ForkSchedule {
    pub genesis_fork_version: Version,
    pub altair_fork_version: Version,
    pub altair_fork_epoch: Epoch,
    pub genesis_validators_root: Root,
}
```

At M3a, `altair_fork_epoch` is set to `Epoch(u64::MAX)` (`FAR_FUTURE_EPOCH`)
in `HostImpl::new`
(`crates/pharos-node/src/host_impl.rs:97-102`). `fork_at_epoch(epoch)`
returns Phase 0 for all `epoch` values at M3a. M3b's YAML preset loader
overwrites `altair_fork_epoch` with the real value; the struct shape does
not change.

`HostImpl::fork_schedule(&self) -> &ForkSchedule`
(`crates/pharos-node/src/host_impl.rs:129`) provides read-only access to
the schedule. The M3b subnet-rotation driver and ENR updater hold an
`Arc<HostImpl<E>>` and call this accessor to determine the current fork
without re-reading the field under a lock (the schedule is immutable after
construction).

## M3b — Altair fork code

### D-altair-state-shape — `BeaconState<E>` extended as enum-of-forks; Altair variant carries participation lists, inactivity scores, and sync committees

**Status**: Accepted. **Date**: 2026-05-22.

`BeaconState<E>` (`crates/pharos-types/src/state.rs`) is an enum with two
variants: `Phase0(phase0::BeaconState<E>)` and `Altair(altair::BeaconState<E>)`.
The Altair inner struct extends the Phase-0 fields with:

- `previous_epoch_participation: SszList<ParticipationFlags, E::VALIDATOR_REGISTRY_LIMIT>`
- `current_epoch_participation: SszList<ParticipationFlags, E::VALIDATOR_REGISTRY_LIMIT>`
- `inactivity_scores: SszList<u64, E::VALIDATOR_REGISTRY_LIMIT>`
- `current_sync_committee: SyncCommittee<E>`
- `next_sync_committee: SyncCommittee<E>`

per `specs/altair/beacon-chain.md` (new fields section). `previous_epoch_attestations`
from Phase 0 is absent in Altair; `upgrade_to_altair` translates accumulated
phase-0 attestations to the new participation-flag representation via
`translate_participation`.

All STF functions that previously took `E::BeaconState` now match on the outer
enum via the `BeaconStateView<E>` trait and the new altair-specific accessors.
`D6` (M1) deferred the enum until M3; this decision resolves that deferral.

Enforced in: `crates/pharos-types/src/state.rs`,
`crates/pharos-types/src/altair/state.rs`,
`crates/pharos-stf/src/lib.rs` (outer dispatch),
`crates/pharos-stf/src/altair/` (all Altair STF modules).

### D-context-bytes-codec — 4-byte `ForkDigest` prefix on all v2 req-resp response chunks

**Status**: Accepted. **Date**: 2026-05-23.

Starting with Altair, every response chunk for `BeaconBlocksByRange/2`,
`BeaconBlocksByRoot/2`, and all four light-client methods carries a 4-byte
`<context-bytes>` field immediately after the result byte:

```
response_chunk ::= <result> | <context-bytes> | <encoding-dependent-header> | <encoded-payload>
```

`<context-bytes>` is the `ForkDigest` for the epoch of the payload (empty on
error chunks). Per `specs/altair/p2p-interface.md:445-461`.

In the codec (`crates/pharos-network/src/rpc/codec.rs`), `RpcMethod::has_context_bytes()`
gates which methods write/read the 4-byte prefix. The fork digest is resolved at
encode time via `ForkContext::fork_digest_for(epoch)` and at decode time via
`ForkContext::fork_from_context([u8; 4])`. Both methods live on the `ForkContext`
trait (`crates/pharos-network/src/host.rs`) and are implemented by `HostImpl<E>`.

Why 4 bytes, not more: spec mandates exactly 4 bytes (one `ForkDigest`); no other
context encoding is defined for Altair.

Enforced in: `crates/pharos-network/src/rpc/codec.rs` (`has_context_bytes` dispatch),
`crates/pharos-network/src/rpc/protocol.rs` (`RpcMethod::has_context_bytes`),
`crates/pharos-network/src/host.rs` (`ForkContext::fork_digest_for`,
`fork_from_context`),
unit test `context_bytes_codec` in `crates/pharos-network/tests/rpc.rs`.

### D-metadata-v2-dual-handle — Serve `MetaDataV2` by default; truncate to `MetaDataV1` on negotiated v1 protocol

**Status**: Accepted. **Date**: 2026-05-23.

The inbound `GetMetaData` request handler inspects which protocol ID
multistream-select negotiated and acts accordingly:

- `/eth2/beacon_chain/req/metadata/2/ssz_snappy` → respond with the full
  `altair::MetaData` (seq_number + attnets + syncnets, 17 bytes SSZ).
- `/eth2/beacon_chain/req/metadata/1/ssz_snappy` → truncate: respond with
  `phase0::MetaData` (seq_number + attnets, 16 bytes SSZ), dropping `syncnets`.

Both protocol IDs are registered on the inbound listener so multistream-select
can negotiate either. The dispatcher uses `MetaDataResponse::V1(md)` /
`MetaDataResponse::V2(md)` to select the encoding branch in the response codec.

Why dual-handle: the spec says v1 is deprecated but not removed; a v1-only peer
MUST still receive a well-formed v1 response. The truncation logic is trivial
(copy seq_number + attnets); no data is lost on the serving side.

Per `specs/altair/p2p-interface.md` "Transitioning from v1 to v2" and
`D-metadata-v2-dual-handle` from the M3b plan.

Enforced in: `crates/pharos-network/src/rpc/types.rs` (`MetaDataResponse`),
`crates/pharos-network/src/rpc/handler.rs` (`handle_metadata`, protocol-ID dispatch),
`crates/pharos-network/src/rpc/protocol.rs` (`RpcMethod::MetaDataV1` + `MetaData`),
integration test `metadata_v1_v2_dual_handle` in `crates/pharos-network/tests/rpc.rs`.

### D-light-client-server-only — M3b implements LC server-side req-resp and STF hooks; LC consumer is M11

**Status**: Accepted. **Date**: 2026-05-23.

M3b ships the full server (responder) side of the light-client protocol:
the four req-resp methods (`LightClientBootstrap`, `LightClientUpdatesByRange`,
`LightClientFinalityUpdate`, `LightClientOptimisticUpdate`) are wired into
`pharos-network`; `LightClientProvider<E>` trait bridges them to the node; the
STF hooks (`create_light_client_bootstrap`, `create_light_client_finality_update`,
`create_light_client_optimistic_update`) execute after each finality advance and
store the produced snapshots in `pharos-storage`.

The consumer side (running a light client, verifying updates via
`process_light_client_*`, maintaining a `LightClientStore`) is deferred to M11.
The reason: the consumer path requires its own sync protocol, independent of the
full-node sync, and is a substantial body of work that does not block M3b's
correctness on the server path.

Per `specs/altair/light-client/full-node.md` (production side),
`specs/altair/light-client/light-client.md` (consumer side, deferred).

Enforced in: `crates/pharos-network/src/host.rs` (`LightClientProvider<E>` trait),
`crates/pharos-network/src/rpc/handler.rs` (four LC handlers),
`crates/pharos-stf/src/altair/light_client.rs` (`create_*` functions),
`crates/pharos-node/src/host_impl.rs` (`LightClientProviderImpl`).
Deferred consumer path: `docs/roadmap.md` M11 section.

### D-ethspec-yaml-loader — `RuntimeConfig` loaded from `configs/<network>.yaml` + `presets/<name>/*.yaml`; dimension fields guarded by `assert_matches_preset`

**Status**: Accepted. **Date**: 2026-05-23.

`RuntimeConfig` (`crates/pharos-types/src/config/mod.rs`) is a flat struct of
non-dimension runtime-tunable fields: fork epochs, fork versions, genesis
parameters, slot duration, churn limits, etc. It is loaded at node startup via
`load_config_dir(path)` (`crates/pharos-types/src/config/loader.rs`), which reads:

- `<path>/config.yaml` for fork-version and epoch fields (matches the layout
  of `~/dev/consensus-specs/configs/mainnet.yaml` / `minimal.yaml` exactly).
- `<path>/phase0.yaml` + `<path>/altair.yaml` under `<path>/presets/` for
  preset-level constants.

Fields that drive const-generic array sizing (`SYNC_COMMITTEE_SIZE`,
`VALIDATOR_REGISTRY_LIMIT`, `MAX_COMMITTEES_PER_SLOT`,
`MAX_VALIDATORS_PER_COMMITTEE`) cannot be overridden at runtime; they are
compile-time `EthSpec` constants. `RuntimeConfig::assert_matches_preset::<E>()`
panics at startup if any shared numeric field diverges from the compile-time
constant, preventing silent divergence between YAML and binary.

For custom networks with different dimension values, operators must recompile
with a new `EthSpec` binding. This matches how Lighthouse and other CL clients
handle custom presets.

Enforced in: `crates/pharos-types/src/config/mod.rs`,
`crates/pharos-types/src/config/loader.rs`,
`crates/pharos-node/src/main.rs` (`--config-dir` flag, `assert_matches_preset` call).

### D-altair-transition-test-strategy — Phase0→Altair `transition` fixtures handled by the Altair conformance dispatcher

**Status**: Accepted. **Date**: 2026-05-23.

`consensus-specs/tests/altair/transition/` contains fixtures that start with a
phase-0 pre-state and drive the fork through `upgrade_to_altair`. These are
dispatched by the Altair conformance module (`crates/pharos-conformance/src/transition.rs`),
not the Phase-0 one, because:

1. The fixtures require decoding the post-state as `altair::BeaconState`, which
   is only available after M3b's type promotion.
2. The fork boundary is Altair-specific; Phase-0 STF has no concept of it.
3. The upstream spec-test layout already places these fixtures under `altair/`
   not `phase0/`.

The dispatcher loads a phase-0 pre-state, calls `state_transition` (which routes
to `upgrade_to_altair` at the boundary slot), and asserts the post-state SSZ-equals
the fixture's expected post-state. Phase-0 calling conventions (no blocks for pure
slot-processing transitions) are preserved.

Enforced in: `crates/pharos-conformance/src/transition.rs`,
`crates/pharos-conformance/src/lib.rs` (row wiring).

### D-sync-aggregate-bls — Single-block `fast_aggregate_verify` for M3b; batched verify deferred to M11

**Status**: Accepted. **Date**: 2026-05-23.

`process_sync_aggregate` (`crates/pharos-stf/src/altair/block.rs`) verifies the
sync committee aggregate signature using a single call to
`pharos_utils::bls::fast_aggregate_verify(pubkeys, msg, sig)` over the 512
(mainnet) participant public keys, collected from `state.current_sync_committee`
filtered by `sync_aggregate.sync_committee_bits`.

Single-block verify is correct and complete. It is slower than batched verify
across multiple blocks (the `SignatureSet` batching path in `pharos-utils::bls`
is already in place for M1 attestation verification), but in M3b there is no
block-validation pipeline running concurrently to batch across; the STF is called
one block at a time. The performance concern is documented in R4 of the M3b plan.

Batched verify (amortizing pairing cost across many sync aggregates at once) is
deferred to M11, where the gossip-ingestion pipeline will provide the natural
batching boundary. The `SignatureSet` API extension to support batched sync-committee
verify will be a mechanical swap at `process_sync_aggregate` with no STF interface
change.

Per `specs/altair/beacon-chain.md` `process_sync_aggregate`, and R4 in the M3b plan.

Enforced in: `crates/pharos-stf/src/altair/block.rs` (`process_sync_aggregate`).
Deferred batched path: `docs/roadmap.md` M11 section.

### D-fork-schedule-source — `ForkSchedule` owned by M3a's `HostImpl`; M3b's YAML loader sets `altair_fork_epoch` at startup

**Status**: Accepted. **Date**: 2026-05-23.

The canonical `ForkSchedule` struct (flat fields: `genesis_fork_version`,
`altair_fork_version`, `altair_fork_epoch`, `genesis_validators_root`) and its
accessor methods (`fork_at_epoch`, `fork_digest_at_epoch`, `current_enr_fork_id`)
are defined in `crates/pharos-types/src/fork.rs` (owned by M3a Phase 0).
`HostImpl<E>` (`crates/pharos-node/src/host_impl.rs`) holds a `ForkSchedule`
field; `HostImpl::fork_schedule(&self) -> &ForkSchedule` exposes it to the
subnet-rotation driver and the ENR migration loop.

At M3a, `altair_fork_epoch` is initialised to `FAR_FUTURE_EPOCH`, so
`fork_at_epoch` always returns Phase 0. M3b's `--config-dir` CLI flag
(Phase 8) calls `load_config_dir` and overwrites `altair_fork_epoch` with the
real value from `configs/<network>.yaml` before `HostImpl::new` is called.
The struct shape is forward-compatible: Bellatrix will add
`bellatrix_fork_epoch` as a new optional field in M4.

This separation (types crate owns the shape, node binary sets the value, network
crate reads via `ForkContext`) means neither `pharos-network` nor `pharos-stf`
depend on the node binary; the dependency graph stays acyclic.

Enforced in: `crates/pharos-types/src/fork.rs` (struct + accessors),
`crates/pharos-node/src/host_impl.rs` (construction + `fork_schedule()` accessor),
`crates/pharos-node/src/main.rs` (YAML load → `ForkSchedule` wiring),
`crates/pharos-node/src/fork_migration.rs` (consumer),
`crates/pharos-node/src/subnet_rotation.rs` (consumer).

---

## M4a decisions

### D-engine-method-dispatch — One `EngineClient`, per-method version enum, per-fork driver picks

**Status**: Accepted. **Date**: 2026-05-26.

`EngineClient` is a single struct; its public surface is one method per JSON-RPC operation
(`fn new_payload`, `fn forkchoice_updated`, `fn get_payload`, `fn exchange_capabilities`,
`fn exchange_transition_configuration`). Each method takes a version enum:

```rust
pub enum NewPayloadVersion { V1 /* M5: V2, M6: V3, M9: V4 */ }
pub enum ForkchoiceUpdatedVersion { V1 /* M5: V2, M6: V3, M9: V4 */ }
pub enum GetPayloadVersion { V1 /* M5: V2, M6: V3, M9: V4 */ }
```

The version determines the JSON-RPC method name (`engine_newPayloadV1` vs
`engine_newPayloadV2`) and the input/output type. Inputs and outputs are
enum-of-versions. The fork-driver picks the version from the current fork:
Bellatrix → `V1`. Capella will add `V2`, Deneb `V3`, Electra `V4` with no
`EngineClient` rewrite; the driver's match on `current_fork` grows arms. This
avoids a per-fork trait (which would explode at four forks) and keeps the JSON-RPC
plumbing in one struct.

Rejected alternative: trait `EngineApi` with one impl per fork (e.g.
`BellatrixEngine`, `CapellaEngine`). Would duplicate the HTTP transport, JWT
signing, retry logic, and capabilities cache per fork; would force a
trait-object indirection at the call site.

Rejected alternative: dynamic JSON-RPC dispatch (build the method name from a
`&str` and serialise an arbitrary value). Would lose compile-time type safety on
request/response pairs.

Enforced in: `crates/pharos-engine/src/client.rs:32-46` (version enums),
`crates/pharos-engine/src/client.rs:143-207` (per-method dispatch).

### D-engine-head-driver — Head changes flow through a `tokio::watch` channel; sync fork choice never blocks on HTTP

**Status**: Accepted. **Date**: 2026-05-25.

`pharos-fork-choice` stays sync (M1 invariant). After each `on_block` or
`on_attestation` call, the node-level code computes the new head via `get_head`
and writes a `HeadChange { head_root, head_block_hash, safe_block_hash,
finalized_block_hash }` value into a `tokio::sync::watch::Sender<Option<HeadChange>>`
held in `pharos-node`. A separate tokio task (`run_engine_driver_loop` in
`crates/pharos-node/src/engine_driver.rs`, Phase 4) subscribes via
`watch::Receiver`, and invokes the engine HTTP calls (`new_payload` +
`forkchoice_updated`) without ever blocking the STF. The driver loop also
receives `NewPayloadRequest<E>` events via a `tokio::sync::mpsc::Receiver` from
the block-ingestion loop; each Bellatrix block's execution payload is sent for
`engine_newPayloadV1` validation and the returned `PayloadStatus` is recorded in
the in-memory fork-choice store.

`engine_forkchoiceUpdatedV1` responses with status `VALID` do not overwrite
the `PayloadStatus` set by a prior `engine_newPayloadV1` call. This preserves
the `Invalid` verdict in any race between newPayload-INVALID and FCU-VALID for
the same block root. Only `INVALID`/`INVALID_BLOCK_HASH` from FCU cause the
status to be updated.

Rejected alternative: spawn a one-shot tokio task per head change from inside
`on_block`. Would require fork choice to know about tokio; couples unrelated
layers; `watch` does the debouncing for free (only the latest value is retained).

Rejected alternative: a new `NetworkEvent::HeadChanged`. The network crate must
not know about head changes; head is a node-level concept. A `watch` channel in
`pharos-node` is the right shape.

M4a simplification: `safe_block_hash` is derived as
`execution_block_hash_at_root(store, justified_checkpoint.root)` per
`specs/bellatrix/fork-choice.md:93-100`. The full spec-compliant
`get_safe_execution_block_hash` is re-org-aware and considers proposer-boost
(it walks the canonical chain to find the "safe" EL block rather than using the
justified-checkpoint EL block directly). That logic is deferred to M11 alongside
the proposer-boost re-org implementation. Until then, the EL receives the
justified checkpoint's execution block hash as `safe_block_hash`, which is
conservative and correct for a non-reorg-aware head driver.

Enforced in: `crates/pharos-node/src/engine_driver.rs` (driver loop + types),
`crates/pharos-node/src/block_ingestion.rs` (publisher),
`crates/pharos-node/src/main.rs` (wiring).

### D-payload-status-store — `Store<E>.payload_statuses` map; persisted alongside block bodies

**Status**: Accepted. **Date**: 2026-05-26.

`pharos-fork-choice::Store<E>` (in-memory) gains
`payload_statuses: HashMap<Root, PayloadStatus>` and a setter
`mark_payload_status(root, status)`. The fork-choice filter (`filter_block_tree`
in `get_head.rs`) skips any root marked `Invalid`.

`SYNCING` and `ACCEPTED` are reported by the EL when it hasn't validated the
payload yet or has accepted but not made it canonical. These are modelled as
`PayloadStatus::NotValidated`; fork choice continues to treat the block as
eligible (does not exclude it).

Persistence: the in-memory store is reconstructed from RocksDB at startup per
the M3a `rehydrate_fork_choice_store` flow. `payload_statuses` are persisted
as a new column family `CF_PAYLOAD_STATUS` (per-root mapping, `Root` → `u8`
discriminant), written by an extended `BlockTransition` that takes an
`Option<PayloadStatus>`. On rehydrate, the column is read into the in-memory map.

Rejected alternative: keep invalid roots only in memory and re-query the EL on
restart. Slow (potentially thousands of EL calls on startup) and the EL may not
remember.

Enforced in: `crates/pharos-fork-choice/src/store.rs:110-138` (`payload_statuses`
field + `mark_payload_status`), `crates/pharos-fork-choice/src/get_head.rs:274-276`
(`filter_block_tree` exclusion), `crates/pharos-storage/src/db.rs:133-310`
(`CF_PAYLOAD_STATUS` column family + encode/decode helpers).

### D-network-backpressure — `send().await` with 1-second timeout, drop after timeout, log loudly

**Status**: Accepted. **Date**: 2026-05-26.

The M2 `try_send`-then-drop policy (`D-channels`) was a placeholder. M4a replaces
it with `send().await` wrapped in `tokio::time::timeout(Duration::from_secs(1), ...)`.
On timeout the event is dropped but logged at `WARN` with the event variant name and
the queue depth; the channel is left intact. The 1-second budget is slot_duration / 12
— large enough that legitimate consumer hiccups don't trip it, small enough that a stuck
consumer doesn't stall the event loop.

Per channel:

- `NetworkEvent` (consumer is the node block-ingestion loop): timeout + drop. Acceptable
  because event loss is bounded; the network state is reconciled on the next peer interaction.
- `NetworkCommand` (producer is the node, consumer is the network task): `send().await`
  with no timeout. The node MUST wait; commands are authoritative and re-issuing complicates
  state (e.g. `UpdateMetaData` carries a fresh `seq_number`).
- `oneshot` reply channels (per-command result): unchanged.

Enforced in: `crates/pharos-network/src/network/mod.rs:1191-1224` (back-pressure policy
doc comment + `tokio::time::timeout` send in `emit_event`),
`crates/pharos-network/src/network/mod.rs:188-210` (`NetworkEvent::variant_name()`).

### D-engine-conformance-runner — In-process axum mock; `EngineClient` drives it; assert JSON equality

**Status**: Accepted. **Date**: 2026-05-26.

`crates/pharos-conformance/src/engine.rs` implements a YAML-driven runner. For each
request/response example in `execution-apis/src/engine/openrpc/methods/*.yaml`:

1. Spin up an axum HTTP server on `127.0.0.1:0` (OS-assigned port).
2. Register a handler that stores the incoming JSON-RPC body in a shared `MockState`
   and replies with the YAML `result` field verbatim.
3. Build an `EngineClient` pointing at the loopback port with a known JWT secret.
4. Invoke the method through `EngineClient`; assert the parsed response matches the
   YAML example shape.
5. Tear down the server after each example.

This avoids running a real EL and gives a deterministic fixture loop. Future forks
(Capella, Deneb, Electra) get YAML coverage for free once the runner is in place.
The runner runs in tokio via `tokio::runtime::Runtime::new` in the conformance
dispatcher.

Enforced in: `crates/pharos-conformance/src/engine.rs:81-350` (`run_engine_yaml_suite`
at 81, `run_method_examples` at 191, `mock_handler` at 254, `run_single_example` at 287),
`crates/pharos-conformance/src/lib.rs:1632` (engine row wiring).

### D-bellatrix-state-shape — Third enum variant, no `Box`; const-generic params extended

**Status**: Accepted. **Date**: 2026-05-26.

`pharos_types::state::BeaconState<...>` adds a `Bellatrix(_)` variant carrying
`bellatrix::BeaconState<...>`. New const-generic parameters
(`MAX_BYTES_PER_TRANSACTION`, `MAX_TRANSACTIONS_PER_PAYLOAD`,
`BYTES_PER_LOGS_BLOOM`, `MAX_EXTRA_DATA_BYTES`) are added to the enum header so
the Bellatrix variant compiles. The Phase 0 and Altair arms carry `PhantomData`
over the new params (they don't use them).

The variant size grows: Bellatrix carries `latest_execution_payload_header` (a
fixed-size struct of ~700 bytes) plus all Altair fields. The R-state-bloat edge
case in the M4a plan tracks the pad cost across the enum.

Rejected alternative: `Box<bellatrix::BeaconState<...>>` to keep the enum small.
Loses the M3b "zero indirection in STF hot path" rule. Bellatrix STF is no hotter
than Altair; we accept the pad. Box-vs-inline trade-off re-evaluated in M11 alongside
the persistent-tree swap.

Enforced in: `crates/pharos-types/src/state.rs:36-90` (`BeaconState` enum definition
with Bellatrix variant), `crates/pharos-types/src/bellatrix/state.rs` (Bellatrix inner
state struct), `crates/pharos-stf/src/lib.rs` (outer fork dispatch for Bellatrix),
`crates/pharos-stf/src/bellatrix/` (Bellatrix STF modules).

---

## M4b decisions

### D-anchor-as-weak-subj-root — Anchor block is the local finalized/justified root

**Status**: Accepted. **Date**: 2026-05-26.

`apply_anchor` (in `crates/pharos-node/src/checkpoint_sync.rs:262-322`) previously
copied `state.finalized_checkpoint` and `state.current_justified_checkpoint` verbatim
into the synthesised `ForkChoiceSnapshot`. For a real Bellatrix anchor state fetched
from `GET /eth/v2/debug/beacon/states/finalized`, those fields reference blocks at
earlier epoch boundaries, not the anchor block itself. Only the anchor block is written
to storage by `apply_anchor`, so `rehydrate_fork_choice_store` (`startup.rs:79-81`)
failed with `KeyNotFound` when it tried to load the finalized block, and
`checkpoint_states` ended up empty (`startup.rs:124-140`) because neither checkpoint
root existed in `block_states`.

The fix treats the anchor block as the local finalized/justified root, matching the
weak-subjectivity sync convention used by all major CL implementations (Lighthouse,
Teku, Prysm). Pre-anchor history is opaque and trusted via the operator's choice of
checkpoint-sync URL per `D-checkpoint-sync-source`.

`finalized_checkpoint` is set to `{ epoch: anchor_epoch, root: anchor.block_root }`.
This ensures `get_checkpoint_block(store, block_root, finalized_epoch)` in
`filter_block_tree` walks back to `anchor_epoch * SLOTS_PER_EPOCH = anchor_slot` and
returns `anchor_block_root`, satisfying the `correct_finalized` check.

`justified_checkpoint` is set to `{ epoch: 0 (GENESIS_EPOCH), root: anchor.block_root }`.
Without attestations, `get_voting_source` returns epoch 0 for all blocks (the
`unrealized_justifications` map is empty; `block_states` post-state
`current_justified_checkpoint` is epoch 0). Using `anchor_epoch` for the justified
epoch would fail the `correct_justified` check because neither the GENESIS_EPOCH
shortcut nor `voting_source + 2 >= current_epoch` would hold. The GENESIS_EPOCH
shortcut (`epoch.0 == 0`) is the correct and spec-aligned choice for an anchor with
no prior attestation history.

Enforced in: `crates/pharos-node/src/checkpoint_sync.rs:272-303` (comment + checkpoint
construction in `apply_anchor`). The test workaround that previously patched the snapshot
post-`apply_anchor` at `checkpoint_backfill_pipeline.rs` has been removed; the snapshot
is now correct as returned.

### D-checkpoint-sync-source — Single trusted Beacon API URL; no quorum; optional tamper flag

**Status**: Accepted. **Date**: 2026-05-26.

Checkpoint sync trusts a single operator-supplied Beacon API URL. `fetch_checkpoint`
issues `GET /eth/v2/debug/beacon/states/finalized` with `Accept: application/octet-stream`,
reads the `Eth-Consensus-Version` response header to select the per-fork SSZ decoder,
then fetches the matching block via `GET /eth/v2/beacon/blocks/0x<root>`. Rejected
alternatives: quorum across multiple checkpoint-sync sources (adds latency and operational
complexity with marginal security gain for the weak-subjectivity use case; the operator's
choice of URL is itself the trust anchor), embedded weak-subjectivity root in the binary
(breaks mainnet-compat when the root ages past the weak-subjectivity period), and
peer-discovery-based bootstrap (requires a live P2P network before fork choice exists).
An optional `--checkpoint-sync-block-root` flag accepts an out-of-band root override for
tamper detection; the flag is validated in `fetch_checkpoint` after the block root is
derived from the downloaded state. Enforced in `crates/pharos-node/src/checkpoint_sync.rs`
(`fetch_checkpoint`, lines 110-245).

### D-anchor-state-on-disk — Single atomic `BlockTransition` write; no per-CF puts

**Status**: Accepted. **Date**: 2026-05-26.

The anchor block, state, slot-index entry, and `ForkChoiceSnapshot` are written together
via a single `<RocksStore as Store<E>>::write_block_transition` call, which maps the four
payloads to a single RocksDB `WriteBatch` committed atomically. No individual
`put_block`, `put_state`, or `put_forkchoice_snapshot` calls are made from `apply_anchor`.
Rejected alternative: separate writes per column family (creates a crash window between
writes; a crash mid-sequence leaves the DB in a state where the snapshot references a
block root that has no corresponding block body, causing `rehydrate_fork_choice_store` to
fail with `KeyNotFound`). This decision is orthogonal to `D-anchor-as-weak-subj-root`,
which governs the checkpoint-field semantics of the synthesised snapshot; both decisions
are required for a correct anchor write. Enforced in
`crates/pharos-node/src/checkpoint_sync.rs:317-323` (`apply_anchor` → `write_block_transition`).

### D-backfill-driver — `pharos-node` owns the backfill loop; network crate is plumbing only

**Status**: Accepted. **Date**: 2026-05-26.

`run_backfill_loop` and the `BackfillBlockProvider` trait live in `pharos-node`, not
`pharos-network`. The network crate exposes `BeaconBlocksByRange` as a raw req-resp
primitive; the node crate decides when and how to issue requests, validates responses,
and drives STF + fork-choice updates. Rejected alternative: a `BackfillService` inside
`pharos-network` (would require the network crate to know about the STF, fork choice,
and storage layers — coupling that violates the layering rule established in M2 and M3a).
`BackfillBlockProvider` uses native async-fn-in-trait syntax (stable in Rust 1.85), not
`#[async_trait]`, because it is always used as a monomorphised generic `P: BackfillBlockProvider<E>`;
`PeerPicker` uses `#[async_trait]` because it is used as `Arc<dyn PeerPicker>` where
dyn-safety is the genuine requirement. Enforced in `crates/pharos-node/src/backfill.rs`
(`run_backfill_loop` at line 1, `BackfillBlockProvider` trait, `PeerPicker` trait).

### D-engine-config-keepalive — 60-second `engine_exchangeTransitionConfigurationV1` loop owned by `pharos-node`

**Status**: Accepted. **Date**: 2026-05-26.

`run_transition_config_keepalive` lives in `pharos-node` (not `pharos-engine`) because
`RuntimeConfig.terminal_total_difficulty` — the CL-side TTD value to compare against
the EL's response — is loaded by the node binary and is not available to the engine
transport crate. The 60-second interval is hardcoded per `paris.md:291` ("Consensus Layer
client software SHOULD poll this endpoint every 60 seconds"); no config knob is exposed.
A `HashSet<Uint256>` of already-warned EL TTD values deduplicates `WARN` log lines so
the same mismatch does not flood the log across successive ticks (risk R5 in the M4b
plan). The cold-start TTD comparison runs in `main.rs` before the keepalive task is
spawned, so the very first tick (which the keepalive skips via `ticker.tick().await` on
entry) does not duplicate the startup check. Enforced in
`crates/pharos-node/src/engine_keepalive.rs` (`run_transition_config_keepalive` at line 120,
60-second interval at line 126) and `crates/pharos-node/src/main.rs` (cold-start check at
lines 405-453, keepalive spawn at line 450).

### D-jwt-auto-gen — Auto-generate `jwt.hex` if absent; never overwrite existing; hex-only format

**Status**: Accepted. **Date**: 2026-05-26.

`ensure_jwt_secret` (in `crates/pharos-node/src/jwt_autogen.rs`) resolves the JWT secret
by three-way priority: (1) explicit `--jwt-secret <path>` arg loads from that path; (2)
`<data_dir>/jwt.hex` exists — reload it; (3) neither — generate 32 bytes via `OsRng`,
write as 64 lowercase hex characters to `<data_dir>/jwt.hex` using `OpenOptions::create_new(true)`
so the write fails atomically if another process raced to create the same file. On Unix,
the file is created with mode `0o600`. Rejected alternatives: in-memory ephemeral secret
(breaks EL pairing across process restarts because the EL node caches the secret per
session; a fresh random key after restart requires the operator to re-provision the EL),
and a `jwt-secret` entry in the YAML config file (adds config surface for a value that
benefits from automatic rotation on first boot; file-based auto-gen matches what Lighthouse
and Teku do). Enforced in `crates/pharos-node/src/jwt_autogen.rs` (`ensure_jwt_secret`
at line 26, `open_for_write` at line 65).

## M4-perf decisions

### D-tree-node-shape — Persistent CoW tree with per-node `OnceLock<Hash256>`

**Status**: Accepted. **Date**: 2026-05-27.

`SszList<T, N>` / `SszVector<T, N>` keep a `Backend::{Naive(Vec<T>), Tree(Arc<Node<T>>)}`
discriminant. The `Tree` variant uses `Node<T> { Branch { left: Arc<Node<T>>, right:
Arc<Node<T>>, hash: OnceLock<Hash256> }, Leaf(T), ZeroSubtree(u8) }` with a const-generic
depth derived from `N`. `Arc` enables structural sharing across CoW writes; `with_set(i, v)`
allocates fresh `Branch` nodes only along the spine from the root to leaf `i`, reusing
all sibling subtrees. Per-node `OnceLock<Hash256>` caches the Merkle root so subsequent
`tree_hash_root()` calls only recompute the dirty spine. `ZeroSubtree(d)` represents an
all-zero subtree at depth `d` without allocating, matching the SSZ default for unpopulated
list slots. Enforced in `crates/pharos-ssz/src/sequence.rs` (`Node` at line 74, tree
backend implementation throughout).

### D-packed-as-full-chunk — `FixedBytes<32>` admitted to tree backend via per-type carveout

**Status**: Accepted. **Date**: 2026-05-27.

`TreeHash::PACKED_AS_FULL_CHUNK: bool` is a new associated const on the `TreeHash` trait,
default `false`. `FixedBytes<N>` overrides it to `N == 32` so `Root`, `Hash256`, and
`Bytes32` qualify. The `Tree` backend's invariant — one element per leaf — is
incompatible with genuine multi-per-chunk basics (`u8`/`u32`/`u64`), which SSZ packs
multiple-per-32-byte-chunk. The carveout admits `FixedBytes<32>` while still rejecting
those, which unlocks tree-backing for `state_roots`/`block_roots`/`randao_mixes`/`historical_roots`
(all `SszVector<Root, _>`-shaped) without writing a translation layer. Rejected
alternatives: bespoke `SszList<u8, _>` packing rule (deferred to M11; basic-element
trees stay on `Backend::Naive(_)`); a separate `PackedTree` backend (doubles backend
surface for a single special case). Enforced at `crates/pharos-ssz/src/tree_hash.rs:83`
(default) and `crates/pharos-ssz/src/tree_hash.rs:354` (`FixedBytes<N>` override), gated
in `sequence.rs` at lines 448, 476, 731, 1706.

### D-tree-backend-fields — Seven hot `BeaconState` fields flipped to `Tree`; the rest stay `Naive`

**Status**: Accepted. **Date**: 2026-05-27.

The following fields on every fork's `BeaconState` are constructed with `Backend::Tree`
in their respective `Default` / `into_tree_backend` paths: `validators`, `historical_roots`,
`state_roots`, `block_roots`, `randao_mixes`, `previous_epoch_attestations`,
`current_epoch_attestations` (the latter two are Phase 0 only; Altair onwards uses
participation flags). These are the structurally large, hash-hot fields. All other
list/vector fields (`balances`, `slashings`, `eth1_data_votes`, etc.) stay
`Backend::Naive(_)`: either they are basic-element packed and so excluded by
`D-packed-as-full-chunk`, or they are small enough that the tree-backend overhead
beats the cache win. Enforced in `crates/pharos-types/src/{phase0,altair,bellatrix}/state.rs`
(`into_tree_backend` methods).

### D-validator-cache-clone-resets — `Validator::tree_hash_root` cached via `OnceLock`; `Clone` resets the cache

**Status**: Accepted. **Date**: 2026-05-27.

`Validator` gains a hand-written `TreeHash` impl that memoises `tree_hash_root()` in a
private `OnceLock<Hash256>` field (`cached_root`). The field is skipped by SSZ
`Encode`/`Decode` and excluded from `PartialEq`/`Eq`/`Hash` (semantic transparency).
`Clone` is hand-written to RESET the cache, not propagate it. This corrects the
original plan's `validator_clone_carries_cache` semantic, which caused 215 conformance
failures during implementation: STF call sites do
`let mut v = validators[i].clone(); v.exit_epoch = ...; with_set(i, v)`, and a populated
clone-carried cache would yield a stale root after the mutation. Resetting on clone is
the safe default and the cost is one re-hash per cloned validator on first access. The
miss rate is bounded — active validators are rarely cloned per slot. Enforced in
`crates/pharos-types/src/phase0/misc.rs` (`Validator` `Clone` and `TreeHash` impls).

### D-cached-root-wrapper — `pharos-utils::CachedRoot` helper with `Clone`-resets + transparent `PartialEq`

**Status**: Accepted. **Date**: 2026-05-27.

`pharos_utils::CachedRoot` wraps `OnceLock<Hash256>` with: `Clone` produces an empty
`CachedRoot` (matching `D-validator-cache-clone-resets`), `PartialEq` returns `true`
unconditionally (so two states that hash-equal but differ in cache population status
still compare equal), `Default` returns empty, and the wrapper is annotated
`#[ssz(skip)]` at field sites so SSZ encode/decode treats it as invisible. The
wrapper is used at the `BeaconState` level (per-fork `cached_root` field) to memoise
the top-level state root; it composes with the per-validator `Validator::cached_root`
to cache at two granularities. Rejected alternatives: re-deriving `Clone` /
`PartialEq` everywhere it appears (forces hand-written impls on every container
that carries a cache); a separate trait (`CacheField`) and blanket impls (more code
for the same effect). Enforced in `crates/pharos-utils/src/cached_root.rs`
(struct at line 16, `Clone` at line 35, `PartialEq` at line 48).

### D-no-tree-backend-on-decode — SSZ decode lands `Backend::Naive`; tree flip is explicit at runtime entry points

**Status**: Accepted. **Date**: 2026-05-27.

`BeaconState::from_ssz_bytes` for every fork decodes list/vector fields into
`Backend::Naive(Vec<T>)` regardless of whether the field is on the
`D-tree-backend-fields` list. The Phase 2 commit that wired `.into_tree_backend()`
inside `from_ssz_bytes` was a regression: it forced every spec-test fixture to
allocate full `Arc<Node<T>>` trees up-front for 8192-element `state_roots`/`block_roots`
and 65536-element `randao_mixes`, then build trees that are immediately discarded
when the next assertion runs. The conformance writer is single-shot per state and
sees no cache amortisation; the up-front tree build cost was a 22% regression.
Decode therefore lands `Naive`; live-node code paths that benefit from the tree
backend (storage rehydration, checkpoint sync apply, genesis init) call
`into_tree_backend()` explicitly at those entry points. The conformance writer
keeps `Naive` end-to-end. Enforced by absence: `rg "into_tree_backend" crates/pharos-types/src`
shows the helper but no `from_ssz_bytes` call site invokes it.

### D-state-view-borrowing-accessors — `BeaconStateView::validators_iter`/`validator(idx)`/`num_validators` replace `validators() -> Vec<Validator>`

**Status**: Accepted. **Date**: 2026-05-27.

`BeaconStateView::validators()` previously returned `Vec<Validator>` via
`self.validators.iter().cloned().collect()`. Hot STF accessors (`get_total_balance`,
`get_active_validator_indices`, `process_rewards_and_penalties`, etc.) called it
once per indexed access, producing O(N) `Validator` clones per call and O(N²) clone
cost per epoch transition. Borrowing accessors were added — `validators_iter(&self)`,
`validator(&self, idx)`, `num_validators(&self)`, plus position-borrowing siblings
`block_root_at`, `state_root_at`, `randao_mix_at` — and every hot caller migrated.
The original `Vec`-returning methods are retained for legacy callers and tests but
flagged as cold-path. This single change accounts for the bulk of the conformance
wall-clock improvement (the writer never amortises the per-state caches, so its
speedup came almost entirely from killing the Vec materialization). Enforced at
`crates/pharos-types/src/views.rs:120-126` (trait methods) and
`crates/pharos-types/src/views.rs:284-294` (impls).

### D-treehash-rayon-strategy — `#[derive(TreeHash)]` emits field-level `rayon::join` for structs with ≥ 4 fields

**Status**: Accepted. **Date**: 2026-05-27.

`pharos-ssz-derive`'s `#[derive(TreeHash)]` macro emits a balanced binary
`rayon::join` tree over per-field roots when the struct has at least four SSZ-visible
fields (`#[ssz(skip)]` fields do not count); structs with fewer keep the serial array
build, where the `rayon::join` overhead exceeds the work. `rayon` is re-exported from
`pharos-ssz` (`pub use ::rayon;`) so consumer crates do not need a direct `rayon`
dependency; the macro emits `::pharos_ssz::rayon::join`. The threshold is a constant
on the derive macro side, not a runtime branch. Enforced in
`crates/pharos-ssz-derive/src/lib.rs` (`PAR_TREE_HASH_FIELD_THRESHOLD = 4` at line 36,
balanced `rayon::join` builder at line 382).

### D-conformance-parallelism-dropped — Phase 5 outer `par_iter` over (fork, category, preset) abandoned

**Status**: Rejected. **Date**: 2026-05-27.

The original M4-perf plan included a Phase 5 that would `par_iter` over the ~60
(fork, category, preset) triples consumed by `pharos_conformance::lib::run`. The
phase was attempted twice and dropped both times. Cause: nested rayon `par_iter`
(the outer 60-spec parallelism dispatching closures that themselves call
`into_par_iter` over per-spec cases) thrashes the global thread pool — workers
split across outer and inner work, and a heavy outer item (e.g. `phase0/sanity/mainnet`)
cannot get a full thread-pool slice. The agent implementation was ~4× slower than
the sequential ladder on a filtered solo run and roughly matched the ladder on a
full run, with no net win. The conformance writer stays sequential at the outer
level; per-case inner parallelism (the existing `par_iter` over fixture cases
inside each category) is preserved. See also: `mem_98f64695` (rayon nested
par_iter pitfall pattern, global memory). Recorded for posterity; not enforced
in code (the rejected refactor never landed).

## M4c decisions

### D-lc-gossip-validation-full-node-arm — Full-node IGNORE rule for LC gossip: exact local match

**Status**: Accepted. **Date**: 2026-05-28.

The `light_client_finality_update` and `light_client_optimistic_update` gossip topics
have two compliance arms in `specs/altair/light-client/p2p-interface.md`: a light-client
arm (accept any spec-valid update, including supermajority exceptions and re-org skips)
and a full-node arm (accept only updates that match the node's own canonical snapshot).
Pharos is a full node serving the LC, not a consuming LC, so it follows the full-node
arm: after the snapshot-lookup, monotonic-slot, and clock-window steps, the validator
compares `tree_hash_root(msg)` against `tree_hash_root(local_snapshot)`. Any mismatch
returns `IGNORE` with a diagnostic string (`"lc_finality: snapshot mismatch"`,
`"lc_optimistic: snapshot mismatch"`). Rejected alternatives: re-deriving the signing
domain and verifying the sync-committee aggregate signature here (the snapshot we
generated already passed that verification at write time — re-running it on every
forwarded message is wasted work); the light-client arm's supermajority exception
(would require us to construct a hypothetical "best known" update on the fly, which
is exactly what the full-node arm avoids). Enforced in
`crates/pharos-node/src/host_impl.rs` (`validate_light_client_finality_update` at
line 415, `validate_light_client_optimistic_update` at line 501) and exercised by the
`validator_accepts_exact_match_finality` / `validator_accepts_exact_match_optimistic`
tests in the same file.

### D-lc-snapshot-trait-on-host — `LightClientSnapshot` trait injected via `Host` for gossip validator access

**Status**: Accepted. **Date**: 2026-05-28.

The gossip validator needs read-only access to the latest finality and optimistic
snapshots without taking a write lock on the fork-choice store, without round-tripping
through `pharos-network`'s req-resp serve path, and without coupling the
validator to RocksDB column-family details. Pharos exposes those reads through the
existing `LightClientProvider<E>` trait on `Host<E>` (already used by the req-resp
serve handlers) and consumes them inside `HostImpl<E>::validate_light_client_*` via
`self.light_client_finality_update()` / `self.light_client_optimistic_update()`. This
keeps the validator's dependency surface to the `Host<E>` super-trait the network
crate already requires. Rejected alternatives: a fresh `LightClientSnapshotStore`
trait (would duplicate the four methods already on `LightClientProvider<E>` and force
`HostImpl<E>` to carry two near-identical impls); reading directly from
`Arc<RocksStore>` inside the validator (couples gossip validation to the storage
backend, making swap-out for an alternative `Store` impl harder). Enforced in
`crates/pharos-network/src/host.rs` (`LightClientProvider<E>` trait) and in
`crates/pharos-node/src/host_impl.rs` (`impl<E: EthSpec> LightClientProvider<E> for
HostImpl<E>` at line 567).

### D-lc-gossip-clock-window — Clock-window check for LC gossip: `get_sync_message_due_ms` basis-points deadline

**Status**: Accepted. **Date**: 2026-05-28.

Spec wording in `specs/altair/light-client/p2p-interface.md` requires that an LC
gossip message arrive no earlier than one full slot interval after its
`signature_slot`'s start, modulo `MAXIMUM_GOSSIP_CLOCK_DISPARITY` (500 ms). Pharos
implements this as `now_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS < due_ms` where
`due_ms = genesis_ms + signature_slot * seconds_per_slot * 1000 + (seconds_per_slot *
1000) / INTERVALS_PER_SLOT`. `INTERVALS_PER_SLOT = 3` matches `consensus-specs`
`config/mainnet.yaml`. The check runs AFTER the monotonic-slot guard so a non-
monotonic update never reaches `SystemTime::now()` (cheap-rejection first), and
BEFORE the snapshot equality check so an early-arrival update is dropped without
the tree_hash cost. Rejected alternatives: using `get_sync_message_due_ms` from the
spec directly (it operates on slots, not millisecond timestamps, so the millisecond
disparity check would re-derive the same arithmetic); per-validator wall-clock
caching (the slot interval is fixed, so re-deriving on every call is two integer
multiplications). Enforced in `crates/pharos-node/src/host_impl.rs`
(`validate_light_client_finality_update` clock arithmetic at lines 449-460,
`validate_light_client_optimistic_update` at lines 519-530).

### D-lc-broadcast-from-ingestion — LC gossip broadcast triggered from the block-ingestion path

**Status**: Accepted. **Date**: 2026-05-28.

LC finality and optimistic updates are broadcast immediately after the block-
ingestion loop advances the head. The trigger is colocated with the head-change
detection because (a) the snapshot the validator will hash against has just been
written (D-lc-snapshot-write-trigger), so we publish exactly what local subscribers
will validate; (b) ingestion already owns the `NetworkCommandSender` clone needed
for non-blocking publish; (c) it avoids a separate background task with its own
shutdown/error handling. The publish is gated by an `IngestionEgress<E>::has_lc_snapshots`
flag so phase0-only nodes (no altair fork transition yet) skip the publish without
allocating an empty update. Rejected alternatives: a dedicated `lc_publisher` task
polling fork-choice (extra task lifecycle, extra channel, harder to reason about
ordering with snapshot writes); publishing from inside the STF (the STF is
sync-only by contract per the project-level decisions in `CLAUDE.md` — pushing a
tokio handle through it would invert that boundary). Enforced in
`crates/pharos-node/src/block_ingestion.rs` (`run_block_ingestion_loop` post-head
publish path, gated on `egress.has_lc_snapshots`) and verified by the
`publish_called_after_head_change` / `no_publish_for_phase0_block` integration tests
in `crates/pharos-node/tests/lc_gossip_publish.rs`.

### D-lc-snapshot-write-trigger — When to update the cached LC snapshot used by the validator

**Status**: Accepted. **Date**: 2026-05-28.

The LC `finality_update` and `optimistic_update` snapshots are recomputed and
stored when the STF dispatches an altair-or-later block in
`pharos-stf::altair::light_client_dispatch`. Triggers: any block-import that
advances the optimistic head writes a fresh `LightClientOptimisticUpdate`; any
block-import that advances the finalized checkpoint additionally writes a fresh
`LightClientFinalityUpdate`. Phase0 blocks bypass the dispatcher entirely (no
sync committee, no LC structures), so no snapshot write fires there. The
projected-state-root for the snapshot header is the canonical, STF-verified
`block.state_root` field (not a recomputed `state.tree_hash_root()`); this is
critical for bellatrix where the projected state omits `execution_payload_header`
and a recomputed hash would not match what the consuming light client validates
against. Rejected alternatives: writing the snapshot on every slot tick
regardless of head change (wastes RocksDB writes when no head moved);
writing only on epoch boundaries (delays finality-update propagation for up to
32 slots). Enforced in `crates/pharos-stf/src/altair/light_client_dispatch.rs`
(dispatcher entry point; bellatrix arm uses `block.state_root` at lines around
607 and 762 — see commit `aaa5440` for the rationale of the Altair-projected
state-hash fix).

### D-bench-location-per-crate — Criterion bench binaries live under each crate's `benches/` directory

**Status**: Accepted. **Date**: 2026-05-28.

Each criterion bench lives in the `benches/` directory of the crate whose code
it primarily exercises: `process_block` under `pharos-stf`, `tree_hash_beacon_state`
under `pharos-ssz`, `gossip_validation` under `pharos-node` (where `HostImpl` is
defined), `rpc_roundtrip` under `pharos-network`. The bench file is registered
with `[[bench]] name = "<file>" harness = false` in that crate's `Cargo.toml` and
criterion is a `[dev-dependencies]` entry. This keeps `cargo bench -p <crate>
--bench <name>` working in isolation and lets a developer iterating on (say)
`pharos-ssz` re-run only the tree-hash bench without recompiling the full
workspace. The `gossip_validation` bench deviates from the original plan
(planned for `pharos-network/benches/`) because `HostImpl<E>` is defined in
`pharos-node`, and the plan's "duplicate `make_host` into the bench file"
guidance presupposes the bench can construct that type — which requires
importing from `pharos-node`, which `pharos-network` cannot do without a
circular dependency. Rejected alternatives: a top-level `benches/` workspace
crate (`cargo bench` would require `-p benches --bench <name>`, hiding which
crate is under test); promoting `make_host` to a `pub mod test_helpers` (would
pollute the `pharos-node` library surface for a single bench consumer). Enforced
in `crates/pharos-{stf,ssz,network,node}/Cargo.toml` (`[[bench]]` entries) and
the corresponding `benches/` directories.

### D-bench-history-format — Criterion baseline storage format and retention policy

**Status**: Accepted. **Date**: 2026-05-28.

`make bench` invokes the four criterion binaries sequentially, then runs
`scripts/bench-summary.sh` which walks `target/criterion/*/new/estimates.json`
and emits `bench-history/<sha>.json` (one file per committed bench-recording
SHA). Each JSON has top-level fields `sha`, `host`, `toolchain`, `date`, and
a `benches` array of `{name, ns, stderr_ns}` triples. The script refuses to
write an empty `benches` array (it `exit 1`s if `target/criterion/` has no
`estimates.json`) so a partial or aborted run cannot land a misleadingly
"clean" empty record. `BENCH_FORCE=1` overrides the file-already-exists guard
for re-runs from the same SHA. Rejected alternatives: appending to a single
`bench-history.jsonl` (merge conflicts on every parallel feature branch);
checking in HTML criterion reports under `target/criterion/` (huge, regenerated
on every run, not human-diffable). Retention: every committed SHA's JSON is
permanent — these files are the diff target for `D-bench-regression-check`.
Enforced in `scripts/bench-summary.sh` and the `bench` target in `Makefile`.

### D-bench-regression-check — local, PERF_HOST-gated perf-regression check

**Status**: Accepted. **Date**: 2026-05-29.

`scripts/bench-check.sh` (target `make bench-check`) compares HEAD's
`bench-history/<sha>.json` against the most recent prior baseline (by `date`,
or explicit positional args for ad-hoc comparison) and exits non-zero on
regression. A bench is flagged `REGRESS` only when it is **both** slower by more
than `REGRESSION_PCT` (default 10) **and** the slowdown clears a `NOISE_SIGMA`
(default 2) band derived from criterion's reported `stderr_ns` — the two-gate
rule keeps run-to-run jitter on sub-microsecond benches from tripping the check.

Decided against a cloud-CI bench gate: there is no GitHub Actions in this repo,
and per `D-bench-history-format`'s PERF_HOST invariant bench numbers are only
comparable on the canonical machine — a hosted runner's numbers are noise. The
script enforces this by reading the `host` field of both records: on mismatch it
prints the comparison but does **not** gate (informational only). Deliberately
**not** wired into `make ci`/`pre-push`: the benches are slow, CPU-bound, and
PERF_HOST-only, so the gate would be machine-dependent and slow the general
loop. Run manually on PERF_HOST after `make bench`. Resolves the
"continuous benchmarking / CI bench-gate" carry-in deferred at M4c
(`docs/m4c-plan.md:235`) and the M5-follow deferred ledger item.

## M4e decisions

### D-seen-cache-shape

**Status**: Accepted. **Date**: 2026-05-28.

Three in-memory `parking_lot::RwLock`-wrapped `lru::LruCache` instances on
`HostImpl<E>` track gossip-dedup state for the three gossip-validator methods:
`seen_block_proposers: LruCache<(Slot, ValidatorIndex), ()>` (capacity 4096),
`seen_attestation_validators: LruCache<(ValidatorIndex, Epoch), ()>` (capacity
131072), and `seen_aggregators: LruCache<(ValidatorIndex, Epoch), ()>` (capacity
8192). A fourth cache, `seen_aggregate_data: LruCache<Root, Bitlist<2048>>`
(capacity 2048), stores the OR of all previously-seen aggregation bitlists per
`data_root` to implement the RAG6 weakened-superset IGNORE rule.

Capacity sizing rationale: 4096 block-proposer entries covers ~128 slots of
mainnet validator-set depth with reorg tolerance. 131072 attestation-validator
entries covers a full epoch of mainnet attestations under load (~1M active
validators × 2 recent epochs, LRU-evicted). 8192 aggregator entries covers the
last quarter-epoch of mainnet target aggregators (16/committee × 64 committees ×
32 slots ≈ 32k/epoch; 8192 means only the freshest quarter fits, which is
sufficient — cache miss on an evicted entry degrades to re-validation, never to
incorrect Accept). 2048 aggregate-data entries covers ~32 committees × 64 slots
of recent data roots. Total peak memory ≈ 4 MB, well under the 50 MB ad-hoc
budget set by `D-peer-info-shape`.

Rejected alternatives: (a) RocksDB column family — adds write amplification and
requires its own eviction policy, with no persistence benefit (the cache is
purely a per-process gossip-dedup signal; reloading from disk after a restart
yields no advantage because the in-flight gossip view is lost on restart anyway);
(b) unbounded `HashSet` — grows without bound under spam.

Enforced in: `crates/pharos-node/src/host_impl.rs:107-139` (field declarations),
`crates/pharos-node/src/host_impl.rs:191-199` (construction with capacities).

### D-proposer-cache

**Status**: Accepted. **Date**: 2026-05-28.

`proposer_cache: RwLock<LruCache<(Slot, Root), u64>>` on `HostImpl<E>`, capacity
1024, caches `(block.slot, block.parent_root) → expected_proposer_index`. On
cache miss the validator clones the parent state from
`fork_choice.block_states.get(&parent_root)`, advances it to `block.slot` via
`pharos_stf::process_slots_fork`, then calls `get_beacon_proposer_index` on the
advanced state. The cache inserts the result. The key is `(slot, parent_root)` so
that entries evict naturally when the parent root changes under a reorg —
different siblings sharing the same slot but different parent roots get distinct
entries.

Rationale: proposer shuffling is computed by RANDAO from the epoch's beacon
state. For a given `(slot, parent_root)` the proposer is deterministic; caching
avoids re-running `process_slots_fork` on every block-gossip arrival for the
same slot. Lighthouse uses an equivalent `ProposerCache` keyed identically.
Rejected: keying by `(epoch, parent_root)` — proposer-shuffling changes per
RANDAO reveal on each slot within an epoch, so per-slot is the minimal stable
key.

Enforced in: `crates/pharos-node/src/host_impl.rs:114` (field declaration),
`crates/pharos-node/src/host_impl.rs:192` (capacity 1024 at construction),
`crates/pharos-node/src/host_impl.rs:386-431` (`lookup_or_compute_expected_proposer`
implementation).

### D-committee-cache

**Status**: Accepted. **Date**: 2026-05-28.

`committee_cache: RwLock<LruCache<(Slot, CommitteeIndex, Root), Vec<ValidatorIndex>>>`
on `HostImpl<E>`, capacity 4096, caches `(slot, index, head_root) →
committee_members`. On cache miss the validator clones the head state from
`fork_choice.block_states.get(&head_root)`, advances it to `slot` via
`process_slots_fork` (no-op when already past that slot), then calls
`get_beacon_committee`. The `head_root` component of the key implements
`D-cache-key-on-head`: entries for a stale head are never reused after a reorg.

Capacity 4096 covers ~64 slots × 64 committees/slot with reorg tolerance. A
cache miss degrades to one `process_slots_fork` call; on a warm mainnet node
the fork-choice state is already at the right slot so the no-op fast path
dominates.

Rejected alternatives: (a) keying by `target.epoch` alone — would Accept
attestations for the wrong fork during reorgs where two chains share an epoch
boundary; (b) no cache at all — would run `get_beacon_committee` on every
attestation, hitting the full shuffling computation every call.

Enforced in: `crates/pharos-node/src/host_impl.rs:129` (field declaration),
`crates/pharos-node/src/host_impl.rs:197` (capacity 4096 at construction),
`crates/pharos-node/src/host_impl.rs:319-374` (`lookup_or_compute_committee`
implementation).

### D-verdict-strings-spec-keyed

**Status**: Accepted. **Date**: 2026-05-28.

Every `GossipVerdict::Ignore(s)` and `GossipVerdict::Reject(s)` string in the
three validator bodies uses a static `&str`-to-`String` literal with an
`"block: "`, `"att: "`, or `"agg: "` namespace prefix. The suffix matches the
lowercase spec tag from the relevant `Raises GossipIgnore("…")` /
`Raises GossipReject("…")` line in `specs/phase0/p2p-interface.md` wherever
spec wording exists, or a brief spec-rule-keyed description where the spec does
not provide an explicit string. 49 strings total: 14 block, 15 att, 20 agg.

Rationale: log greppability by topic without parsing the full message. Each
string is a static literal compiled into the binary; no `format!` allocation
occurs on the hot path. The exhaustive list enables the round-trip test to catch
silent renames or additions.

The gossip_verdict_strings integration test (`crates/pharos-node/tests/
gossip_verdict_strings.rs`) `include_str!`s the `host_impl.rs` source at build
time and asserts (a) every known string appears in the source, and (b) every
`"block: "` / `"att: "` / `"agg: "` prefixed string in the source also appears
in the hard-coded list. This creates a two-sided audit: the test fails if a
string is added to the source without updating the list, and also if a string
is removed from the source while the list still references it.

Enforced in: `crates/pharos-node/src/host_impl.rs:585-1131` (validator bodies,
all 49 verdict strings), `crates/pharos-node/tests/gossip_verdict_strings.rs:21-106`
(hard-coded EXPECTED list and round-trip assertions).

### D-bls-on-hot-path

**Status**: Accepted. **Date**: 2026-05-28.

The three BLS signature verifies run synchronously inside the validator body:
`pharos_utils::bls::verify` for the proposer signature in
`validate_beacon_block`; `pharos_utils::bls::fast_aggregate_verify` for the
aggregate signature in both `validate_attestation` (via `is_valid_indexed_attestation`)
and `validate_aggregate_and_proof` (three BLS calls: selection proof, aggregator
signature, aggregate signature). None of these call `.await` or spawn tasks.

The gossip dispatch loop at `crates/pharos-network/src/network/mod.rs:535` wraps
the entire `dispatch_gossip_message` call in `tokio::task::spawn_blocking` so
that the synchronous BLS verifies do not stall the tokio executor. Mainnet
`bls::verify` is ~1 ms; `fast_aggregate_verify` for a full committee (~2048
indices) is ~2-3 ms; aggregate of 64 committees ~50 ms worst case. Batched
verification is M11 work; in M4e single-pubkey verify is the bottleneck and the
`spawn_blocking` wrapper is sufficient.

Rejected alternatives: (a) async BLS signature queue with a dedicated worker
pool — adds first-byte latency and substantial complexity without changing
steady-state throughput; (b) skip BLS on gossip — not permissible per spec
REJECT rule.

Enforced in: `crates/pharos-network/src/network/mod.rs:535` (spawn_blocking
wrap), `crates/pharos-node/src/host_impl.rs:734` (proposer BLS verify in
`validate_beacon_block`), `crates/pharos-node/src/host_impl.rs:858-860`
(`is_valid_indexed_attestation` BLS call in `validate_attestation`),
`crates/pharos-node/src/host_impl.rs:940-941` (BLS imports in
`validate_aggregate_and_proof`).

### D-invalid-roots-cache

**Status**: Accepted. **Date**: 2026-05-28.

`invalid_block_roots: RwLock<LruCache<Root, ()>>` on `HostImpl<E>`, capacity
256, records block roots that triggered any REJECT in `validate_beacon_block`.
On every subsequent call to `validate_beacon_block`, step 1 consults this cache:
if the incoming block's `parent_root` is present, the block is immediately
REJECTed without running any other check (spec rule "block's parent passes
validation"). Capacity 256 covers the expected REJECT storm from a single bad
subtree while remaining negligible in memory.

Rationale: gossipsub penalises senders of REJECTed messages; propagating the
REJECT quickly to all children of a known-bad block is important for peer
scoring. Making the cache process-local avoids RocksDB write amplification for
every invalid block seen. It mirrors the existing fork-choice `payload_statuses`
`Invalid`-root set (`D-payload-status-store`) but at the gossip-validator layer
rather than the execution-layer layer.

Rejected alternatives: (a) extending `payload_statuses` — that map is keyed on
execution-layer validity (post-`engine_newPayloadV1`) not gossip-layer validity;
reusing it would conflate the two failure modes; (b) no cache — each child of a
known-bad block would run through the full 11-step pipeline before REJECTing,
wasting CPU and delaying peer scoring.

Enforced in: `crates/pharos-node/src/host_impl.rs:118` (field declaration),
`crates/pharos-node/src/host_impl.rs:193` (capacity 256 at construction),
`crates/pharos-node/src/host_impl.rs:610-618` (step 1 parent-root cache
lookup), `crates/pharos-node/src/host_impl.rs:680-741` (cache write on REJECT
at steps 8-11).

### D-future-slot-disparity

**Status**: Accepted. **Date**: 2026-05-28.

All three validators apply a symmetric `MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS = 500`
ms clock-tolerance envelope on both edges of the propagation window. For the
block validator (step 2, RB1): a block is NOT ignored if
`now_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS >= slot_time_ms` — i.e., blocks
arriving up to 500 ms before their nominal slot start are accepted. For the
attestation and aggregate validators (slot-range check): the window `[start_ms -
500, end_ms + 500]` is used on both sides, matching the spec formulation at
`specs/phase0/p2p-interface.md:298-334`. `ATTESTATION_PROPAGATION_SLOT_RANGE =
32` defines the attestation window width (`32` slots ≈ 6.4 minutes on mainnet),
added as a `pub const` to `crates/pharos-types/src/phase0/primitives.rs:63`.

The constant `MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS = 500` was already present from
M4c (`crates/pharos-types/src/phase0/primitives.rs:51`). `genesis_time` lives on
the fork-choice `Store` rather than on `BeaconState`, so the slot-time formula
`genesis_time * 1000 + slot * SECONDS_PER_SLOT * 1000` reads from
`self.fork_choice.read().genesis_time` and `self.runtime_cfg.seconds_per_slot`.

Rejected alternatives: (a) asymmetric window (wider on one edge) — would accept
future blocks while still rejecting past blocks, creating a peer-scoring
asymmetry; spec requires symmetric 500 ms on both edges.

Enforced in: `crates/pharos-node/src/host_impl.rs:782-822` (attestation slot
range check with both-edge disparity), `crates/pharos-node/src/host_impl.rs:944-975`
(aggregate slot range check), `crates/pharos-node/src/host_impl.rs:620-632`
(block future-slot check), `crates/pharos-types/src/phase0/primitives.rs:61-63`
(`ATTESTATION_PROPAGATION_SLOT_RANGE` const).

### D-domain-types-additions

**Status**: Accepted. **Date**: 2026-05-28.

`DOMAIN_SELECTION_PROOF = [0x05, 0x00, 0x00, 0x00]` and
`DOMAIN_AGGREGATE_AND_PROOF = [0x06, 0x00, 0x00, 0x00]` are added as `pub
const [u8; 4]` to `crates/pharos-stf/src/phase0/helpers.rs` alongside the
existing `DOMAIN_BEACON_PROPOSER` constant. Values are per
`specs/phase0/beacon-chain.md:214-215`. Both are 4-byte `DomainType` arrays
matching the existing constant shape in that file.

These two domain types are required by `validate_aggregate_and_proof`: the
selection-proof signature (step 10, RAG10) is signed over `(slot, DOMAIN_SELECTION_PROOF)`,
and the aggregator signature (step 11, RAG11) is signed over
`(AggregateAndProof, DOMAIN_AGGREGATE_AND_PROOF)`.

Rejected alternatives: (a) placing them in `pharos-types/src/phase0/primitives.rs`
alongside `MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS` — domain types belong with the
other domain constants in `pharos-stf` helpers because they are STF-layer
concepts, not wire-layer primitives; (b) inline literals in the validator body
— harder to audit against spec.

Enforced in: `crates/pharos-stf/src/phase0/helpers.rs:89-96` (`DOMAIN_SELECTION_PROOF`
and `DOMAIN_AGGREGATE_AND_PROOF` declarations), `crates/pharos-node/src/host_impl.rs:940`
(import and use in `validate_aggregate_and_proof`).

### D-is-aggregator-location

**Status**: Accepted. **Date**: 2026-05-28.

`is_aggregator(committee_len: usize, slot_signature: &BLSSignature) -> bool` is
implemented as a `pub fn` in `crates/pharos-stf/src/phase0/predicates.rs`,
adjacent to the existing `is_valid_indexed_attestation`. The predicate computes
`modulo = max(1, committee_len / TARGET_AGGREGATORS_PER_COMMITTEE)`, hashes the
signature bytes via `pharos_utils::hash::hash(slot_signature.as_ref())`, reads
a `u64` from the first 8 bytes of the hash (little-endian), and returns `n %
modulo == 0`. Spec reference: `specs/phase0/validator.md:139-147`.

Rationale: `is_aggregator` is a pure predicate over committee data with no
state dependency; it belongs next to `is_valid_indexed_attestation` (existing
at `predicates.rs:56`) rather than as a method on `HostImpl` (which would make
it test-awkward and prevent STF reuse) or in `pharos-types` (which contains
types, not predicates).

Rejected alternatives: (a) inline in the `validate_aggregate_and_proof` body
— duplicates the spec rule, harder to unit-test independently; (b) in
`pharos-utils` — that crate is generic infrastructure, not spec predicates.

Enforced in: `crates/pharos-stf/src/phase0/predicates.rs:110-118`
(`is_aggregator` function declaration and implementation), `crates/pharos-node/src/host_impl.rs:941`
(import and use at step 8 in `validate_aggregate_and_proof`).

### D-cache-key-on-head

**Status**: Accepted. **Date**: 2026-05-28.

Both the proposer cache and the committee cache include the LMD-GHOST head root
at validation time as part of their cache key, rather than keying only on the
message-derived roots. For `proposer_cache` the key is `(slot, parent_root)`:
`parent_root` is message-derived and is itself a proxy for the head because the
block's parent must be on the canonical chain for the block to be valid. For
`committee_cache` the key is `(slot, committee_index, head_root)` where
`head_root` is read via `pharos_fork_choice::get_head(&*fc)` at validation time.
On a reorg the head root changes, so cache entries from the pre-reorg chain
occupy different key slots and are never served to the post-reorg chain. LRU
eviction eventually reclaims the stale entries.

Rationale: keying on message-derived data alone (e.g. `(slot, data.beacon_block_root)`)
would serve stale committee membership from a fork that has been reorganised away.
The `head_root` component adds exactly one `RwLock::read` acquisition per cache
miss, which is negligible compared to the `process_slots_fork` call it replaces.

Rejected alternatives: (a) invalidating the cache on every reorg notification —
requires a pub invalidation method on `HostImpl`, adds coupling to the
block-ingestion loop, and forces synchronisation; (b) keying by epoch alone —
committee membership is stable within an epoch on the same chain, but not across
forks at the same epoch boundary.

Enforced in: `crates/pharos-node/src/host_impl.rs:344-349` (`committee_cache`
key construction with `head_root`), `crates/pharos-node/src/host_impl.rs:404`
(`proposer_cache` key `(slot, parent_root)`).

### D-seen-cache-after-accept

**Status**: Accepted. **Date**: 2026-05-28.

All three seen-caches (`seen_block_proposers`, `seen_attestation_validators`,
`seen_aggregators`, `seen_aggregate_data`) are written only when all validation
steps have passed, i.e. immediately before returning `GossipVerdict::Accept`.
They are never written on IGNORE or REJECT. This ensures that a malformed or
invalid message cannot poison the cache and cause a subsequent valid message
with the same key to be silently dropped.

Rationale: if a cache write were performed on first sight (before validation),
an attacker could send a malformed message with a valid `(proposer, slot)` or
`(validator, epoch)` key to preemptively block acceptance of the honest
message. The "insert on Accept" pattern is used by Lighthouse for the same
reason. The cost is that the full validation pipeline runs twice if two
messages with the same key arrive in rapid succession, but this is acceptable
because (a) it is rare on a well-connected network and (b) correctness is more
important than deduplication efficiency.

Enforced in: `crates/pharos-node/src/host_impl.rs:748-752` (block: step 12
cache write after all checks), `crates/pharos-node/src/host_impl.rs:898-902`
(attestation: step 14 cache write after all checks), `crates/pharos-node/src/host_impl.rs:1110-1130`
(aggregate: step 17 cache writes after all checks).

### D-no-tokio-from-validator

**Status**: Accepted. **Date**: 2026-05-28.

The three validator methods (`validate_beacon_block`, `validate_attestation`,
`validate_aggregate_and_proof`) are synchronous, take `&self`, and do not
spawn tokio tasks, call `.await`, or otherwise interact with the async runtime.
All I/O inside the validator bodies is synchronous: `parking_lot::RwLock`
acquisitions, `lru::LruCache` reads/writes, and `pharos_utils::bls` calls.
This is a consequence of `D-gossip-validator-sync` (M3a), which established
that the `GossipValidator<E>` trait methods are sync.

The gossip dispatch loop at `crates/pharos-network/src/network/mod.rs:535`
wraps the entire dispatch in `tokio::task::spawn_blocking`, which is the
correct boundary: the async runtime calls `spawn_blocking`, and the blocking
work (including BLS verify) runs on a thread-pool thread. No tokio constructs
are needed inside the validator body itself.

Negative enforcement: `rg 'tokio::spawn' crates/pharos-node/src/host_impl.rs`
returns empty, confirming no `tokio::spawn` call is present in the file.

Enforced in: `crates/pharos-node/src/host_impl.rs:585-1131` (entire
GossipValidator impl block — no `.await`, no `tokio::spawn`), `crates/pharos-network/src/network/mod.rs:535`
(the spawn_blocking boundary that makes sync validators safe to call from async context).

---

## M4d decisions

### D-epoch-driven-fork-digest

**Status**: Accepted. **Date**: 2026-05-28.

`HostImpl<E>::current_fork_digest()` computes the active fork digest on every call
from `fork_schedule.current_fork_version(current_epoch())` + `genesis_validators_root`,
where `current_epoch()` is derived from `genesis_time_secs` + wall-clock via the same
arithmetic as the migration loop. There is no frozen `current_fork_digest` field and no
`RwLock` holding a cached value. Because the digest is always derived from the live
wall-clock epoch, `Status` responses, the ENR `eth2` field, and gossip message-id
computations all stay correct across fork crossings automatically — no mutation path is
needed and no window exists where the cached value diverges from the active fork.

`ForkContextInner` (the private struct inside `HostImpl<E>`) stores `fork_schedule:
ForkSchedule` and `genesis_time_secs: u64`; `current_epoch()` and `current_fork_version_now()`
are small private helpers that read these fields without any shared state. Rejected
alternative: a `parking_lot::RwLock<ForkDigest>` written by the migration loop — would
require the loop and every caller to coordinate writes and reads; the dynamic-derive
approach is simpler and strictly correct.

Enforced in: `crates/pharos-node/src/host_impl.rs:267` (`current_epoch` helper),
`crates/pharos-node/src/host_impl.rs:286` (`current_fork_version_now` helper),
`crates/pharos-node/src/host_impl.rs:470` (`current_fork_digest` impl — no cache field),
`crates/pharos-node/src/host_impl.rs:481` (`enr_fork_id` reads from same dynamic path).

### D-bellatrix-migration-startup-no-op

**Status**: Accepted. **Date**: 2026-05-28.

`run_fork_migration_loop` tracks the last-applied fork version in `prior: Option<Version>`.
On the first loop tick, `prior` is `None`; the loop sets `prior = Some(current)` WITHOUT
calling `do_migration`, regardless of whether `current` matches the genesis fork version.
For a node that starts already at the Bellatrix fork (e.g. `ALTAIR_FORK_EPOCH ==
BELLATRIX_FORK_EPOCH == 0`), the first tick sees `current = bellatrix_fork_version` and
records it; no spurious phase0-to-altair or altair-to-bellatrix migration fires. This
avoids duplicate subscribes and spurious unsubscribes on the gossip topics that the
startup subscription (Phase 4) already set up correctly under the active digest.

Subsequent ticks compare `current` against `prior`; if they differ, `do_migration` is
called and `prior` is updated. The loop does NOT exit after the first crossing, so the
same instance handles both the phase0→altair and altair→bellatrix boundaries.

Enforced in: `crates/pharos-node/src/fork_migration.rs:103-111` (first-tick `None` arm:
`prior = Some(current)` with no migration call), `crates/pharos-node/src/fork_migration.rs:113-125`
(subsequent-tick arm: migrate only when `current != prior_version`).

### D-bellatrix-startup-topic-set

**Status**: Accepted. **Date**: 2026-05-28.

At startup the node subscribes the base beacon topics (5 non-attestation topics +
attestation subnet topics) under the ACTIVE fork digest, computed via
`host.current_fork_digest()` (dynamic per `D-epoch-driven-fork-digest`). When the
active fork is altair or bellatrix, the altair-era extras (`sync_committee_contribution_and_proof`,
`sync_committee_<i>` for each subnet, `light_client_finality_update`,
`light_client_optimistic_update`) are also subscribed under the same active digest.
A bellatrix-at-genesis node therefore starts with the full bellatrix topic set without
needing to wait for a migration tick.

The startup subscription calls `subscribe_base_topics` unconditionally, then checks
`host.fork_from_context(&fork_digest.into_inner())` and calls
`subscribe_altair_extra_topics` when the result is `Some(Fork::Altair)` or
`Some(Fork::Bellatrix)`. Phase0-only nodes skip the extra topics without branching logic.

Enforced in: `crates/pharos-network/src/network/mod.rs:1650` (`subscribe_base_topics`
call at startup), `crates/pharos-network/src/network/mod.rs:1653-1665`
(active-fork check and `subscribe_altair_extra_topics` conditional call),
`crates/pharos-network/src/gossip/mod.rs:52` (`subscribe_base_topics` function),
`crates/pharos-network/src/gossip/mod.rs:102` (`subscribe_altair_extra_topics` function).

### D-gossip-block-decode-by-digest

**Status**: Accepted. **Date**: 2026-05-28.

The `beacon_block` gossip handler in `dispatch_gossip_message`
(`crates/pharos-network/src/gossip/mod.rs`) dispatches SSZ decode to the fork-appropriate
block type by calling `host.fork_from_context(&topic.fork_digest.into_inner())`:
`Fork::Bellatrix` decodes as `E::BellatrixSignedBeaconBlock`, `Fork::Altair` as
`E::AltairSignedBeaconBlock`, and `Fork::Phase0` or an unknown digest as
`E::Phase0SignedBeaconBlock`. This matches the spec rule that the fork-digest topic
segment identifies the block type; a gossip client MUST send the block type that matches
the active fork digest.

Prior to M4d the dispatch was hardcoded to Phase0; adding the match on
`fork_from_context` is the change that enables a bellatrix-genesis node to accept
bellatrix `beacon_block` messages from peers without returning `Reject("ssz decode")`.
The `fork_from_context` method is already implemented on `HostImpl<E>` for all three
forks, so the dispatch is exhaustive.

Enforced in: `crates/pharos-network/src/gossip/mod.rs:170-198` (`beacon_block` match on
`fork_from_context`, three arms for Bellatrix / Altair / Phase0), verified by
`crates/pharos-network/tests/bellatrix_fork_migration.rs` (`bellatrix_beacon_block_dispatch_no_ssz_reject`
test and `bellatrix_subscription_round_trip` integration test).

### D-bellatrix-reqresp-both-paths

**Status**: Accepted. **Date**: 2026-05-28.

The `BeaconBlocksByRange/2` and `BeaconBlocksByRoot/2` codec in
`crates/pharos-network/src/rpc/codec.rs` handles `Fork::Bellatrix` on BOTH the receive
(decode) and the send (encode) paths. On receive, the `chunk_fork` discriminant
(`Some(Fork::Bellatrix)`) routes to
`read_ssz_snappy_payload::<_, E::BellatrixSignedBeaconBlock>` before wrapping via
`E::bellatrix_into_signed_block`. On send, the per-block dispatch unwraps via
`E::unwrap_bellatrix_signed_block` and writes the Bellatrix fork digest as the 4-byte
context bytes followed by the inner SSZ.

Both paths are required for real operation: the receive path is exercised during backfill
(the node receives Bellatrix blocks from peers via `BeaconBlocksByRange`) and during
sync from a peer that serves Bellatrix blocks; the send path is exercised when a
connected peer (e.g. Lighthouse) requests blocks by range or root and the local DB
contains Bellatrix blocks.

Rejected alternative: implement receive only and stub send — would break any peer that
requests Bellatrix blocks from Pharos, blocking interop with Lighthouse in a
Bellatrix-genesis devnet.

Enforced in: `crates/pharos-network/src/rpc/codec.rs:224` (receive path
`Some(Fork::Bellatrix)` arm), `crates/pharos-network/src/rpc/codec.rs:436-438`
(send path `unwrap_bellatrix_signed_block` dispatch and `Fork::Bellatrix` context bytes).

---

## M5 decisions

### D-following-via-range-reconvergence — Long-running backfill loop heals to wall_slot-1; parks on hybrid Notify+fallback select!

**Status**: Accepted. **Date**: 2026-05-29.

The forward-backfill loop never returns when caught up. Instead, it heals the
chain to `wall_slot - 1` (tolerating the in-progress slot), then parks on a
`tokio::select!` that wakes on (a) a `tokio::sync::Notify` fired by the ingestion
loop when it defers an orphan block; (b) a `BACKFILL_FOLLOW_FALLBACK` backstop
timer (48 s, ~4 mainnet slots); or (c) a `shutdown_rx` change. The `Notify` path
is the primary wake; the 48-second fallback ensures the loop also catches up if
the node is behind and no gossip blocks arrive.

The orphan deferral path in `run_block_ingestion_loop`: when `block_states.get(&parent_root)`
returns `None`, the loop logs a `debug!` message and calls `egress.notify_backfill.notify_one()`,
then `continue`s. No orphan buffer exists; if the backfill loop heals the parent before the
gossip peer retransmits, the next retransmission will succeed.

`BACKFILL_TAIL_LAG_SLOTS` (the old 2-slot lag constant) is removed entirely.
The old early-exit on caught-up left a permanent 2-slot tip gap and gossip alone
cannot heal a gap because dropped orphans are never returned by the gossip mesh.

Rejected alternative: an in-memory orphan buffer — would require eviction policy,
bounded memory, re-processing on every backfill advance, and synchronisation
between the ingestion and backfill loops; the range-reconvergence approach avoids
all of this because the backfill loop already has the machinery to fetch and apply
a range of blocks.

Rejected alternative: `BeaconBlocksByRoot` fetch for the unknown parent at the
orphan-defer site — see `D-byroot-lookup-deferred`.

Enforced in: `crates/pharos-node/src/backfill.rs` (`run_backfill_loop` caught-up
arm, `BACKFILL_FOLLOW_FALLBACK` const, `notify` parameter), `crates/pharos-node/src/block_ingestion.rs`
(`IngestionEgress::notify_backfill` field, missing-parent `notify_one()` call),
`crates/pharos-node/src/main.rs` (shared `Arc<Notify>` creation and threading to
both ingestion and backfill). Verified by `backfill_idles_when_caught_up` (in-module)
and `orphan_defers_and_backfill_heals` (integration test in
`crates/pharos-node/tests/orphan_backfill_recovery.rs`).

### D-byroot-lookup-deferred — BeaconBlocksByRoot unknown-parent import is future work

**Status**: Accepted. **Date**: 2026-05-29.

When the ingestion loop receives a gossip block whose parent state is absent from
the fork-choice store, a `BeaconBlocksByRoot` lookup of the unknown parent is
NOT attempted. The block is deferred to the range-reconvergence path
(`D-following-via-range-reconvergence`) instead.

Rationale: `BeaconBlocksByRoot` unknown-parent import is required for side-branch
and reorg correctness (fetching a sibling block that the canonical backfill range
would never reach), not for canonical-following correctness.  The canonical-following
M5 goal is fully satisfied by range re-convergence: the backfill loop heals to
`wall_slot - 1` which covers the canonical chain tip.  Adding `BeaconBlocksByRoot`
lookup at the orphan-defer site would require multi-fork test scenarios (the
fetched block might be on a side fork), a parent-chain walk, and careful integration
with the fork-choice's block-validity pipeline.  These are distinct engineering
requirements that belong in a dedicated milestone (reorg handling / side-branch sync).

Enforced by absence: `rg 'BeaconBlocksByRoot' crates/pharos-node/src/block_ingestion.rs`
returns empty; the orphan-defer site calls `notify_one()` only.

## M5-follow correctness decisions (cross-client follow hardening)

These four fixes closed the remaining correctness gaps that surfaced once
Pharos actually followed Lighthouse v8.1.3 + ethrex on the live Bellatrix
devnet. All live-verified: pharos `head == wall` (exact, 0 lag), `peers:1`
stable to epoch 15, 0 Lighthouse bans.

### D-blocksbyroot-bare-list — BeaconBlocksByRoot request is the bare List, not a container

**Status**: Accepted. **Date**: 2026-05-29. **Commit**: `6b19e71`.

The req/resp `BeaconBlocksByRootRequest` is a single-field wrapper around
`SszList<Root, MAX_REQUEST_BLOCKS>`. Per the p2p single-field rule
(`p2p-interface.md`) it serializes as the bare `List[Root, N]` — but
`#[derive(Encode, Decode)]` treated it as an SSZ container and prepended a
4-byte offset for its lone variable-length field (an empty request became
exactly the 4 offset bytes). Lighthouse decoded that as
`InvalidByteLength { len: 4, expected: 32 }`, classified it a fault, and
**banned pharos to -100 on the spot** — the true "not peering" cause, latent
until a checkpoint gap forced the lookup's by-root request onto the wire.

Fix: hand-written transparent `Encode`/`Decode` over `block_roots` (no
container offset) in `crates/pharos-types/src/phase0/operations.rs`.

A symmetric pharos↔pharos round-trip test could NOT catch this (the wrong
layout is self-consistent in both directions), so an **exact-wire-byte** test
(`blocks_by_root_request_is_bare_list_no_offset`) asserts `len == 32·n` with no
offset. Other req/resp methods are unaffected: `BeaconBlocksByRange` is all
fixed-size fields, LC requests are empty or single-fixed-field.

### D-lc-publish-due-time — LC gossip updates are published at the spec due-time, not at import

**Status**: Accepted. **Date**: 2026-05-29. **Commit**: `2b9d390`.
**Supersedes** the immediate-send half of `D-lc-broadcast-from-ingestion` (M4c).

pharos published `light_client_finality_update` / `light_client_optimistic_update`
the instant a head advanced (slot start). The altair p2p rule forwards an LC
update only after `get_sync_message_due_ms` (one `INTERVALS_PER_SLOT` fraction =
4 s for 12 s slots) has transpired since the start of `signature_slot`.
Lighthouse logged `Light client optimistic update too early error: TooEarly` and
applied a `light_client_gossip_error` penalty (~-1.00/slot), bleeding toward a
ban in ~15 min. The update *content* was correct (Lighthouse deduped pharos's
bytes as identical to its own) — purely a timing defect.

Fix: `HostImpl::lc_publish_wait(signature_slot)` (the publish-side mirror of the
inbound validator's `due_ms` gate) + a delayed `tokio::spawn` publish in
`block_ingestion.rs`. Publishes at the full `due_ms` (no disparity shaving) so
the message stays inside the receiver's window under modest clock skew; a newer
head arriving first just makes the older update a no-penalty IGNORE on peers.

### D-import-clock-nudge — advance the fork-choice clock to wall-now before on_block

**Status**: Accepted. **Date**: 2026-05-29. **Commit**: `c351622`.

`on_block`'s future-slot guard reads `get_current_slot(store) = store.time`,
advanced only by a 1 s background `on_tick` driver. That driver fires at an
arbitrary sub-second phase and floors `now` to whole seconds, so right after a
slot boundary `store.time` still reported the previous slot — and a
just-proposed gossip block was rejected `FutureSlot`, then re-fetched via lookup
a full slot later (measured: 91 rejects / 90 lookup re-imports / 0 direct gossip
imports in a 2-minute run; head perpetually 1 slot behind wall).

Fix: nudge `store.time` to wall-now inside the import write-lock, immediately
before `on_block`, in `crates/pharos-node/src/import.rs`. Crucially
**advance-only and single-step** via `on_tick_per_slot`, NOT the catch-up
`on_tick`:
- advance-only (`if now > store.time`): never regress a cursor a caller or the
  background ticker set further ahead (a first attempt regressed a test's
  pre-advanced clock);
- single-step / O(1): `on_tick`'s slot-by-slot catch-up loop explodes against a
  mock `genesis_time = 0` (it hung `checkpoint_backfill_pipeline` for 30 s).

The background `on_tick` stays the primary clock driver; this is only a sub-slot
freshness nudge. `on_block`'s `get_current_slot(store) >= block.slot` assert is
untouched. Result: 0 future-block rejects, direct gossip import, `head == wall`.

### D-future-block-hold — future blocks are held until their slot, not dropped

**Status**: Accepted. **Date**: 2026-05-29. **Commit**: `4d49d24`.

Per `fork-choice.md` `on_block`, a future block's "consideration must be delayed
until they are in the past" — but the ingestion loop *dropped* any block
`on_block` rejected as `FutureSlot`. With `D-import-clock-nudge` this is now
reachable only for a block arriving within `MAXIMUM_GOSSIP_CLOCK_DISPARITY`
before its slot (clock skew), and dropping it costs a full slot of lookup
re-fetch.

Fix: a re-inject `mpsc` channel. `run_block_ingestion_loop` now `select!`s over
network events and re-injected blocks; on `FutureSlot`, `hold_future_block`
parks `(topic, data)` and a `tokio::spawn` sleeps until the slot opens
(`HostImpl::wait_until_slot_start`) then re-sends it for another import attempt.
Bounded by `MAX_FUTURE_BLOCK_HOLD` (24 s) so the hold can't pin memory — the
gossip validator already IGNOREs blocks further ahead. `on_block`'s assert is
untouched.

**Extension (2026-05-29): the lookup-sync path now holds too.** Originally the
lookup path was left dropping future blocks (self-heal via the next block's
re-lookup, one slot late). `run_lookup_loop` now threads the same ingestion
`reinject_tx`; `try_import` distinguishes `FutureSlot` via a new
`ImportAttempt::FutureSlot { block_slot }` variant (previously folded into
`Rejected` → dropped), and all three import sites — the parent-known
direct-import, `fetch_and_walk`, and `drain_and_replay` — call
`hold_future_block` (promoted to `pub(crate)`) instead of dropping. Re-injection
flows through the ingestion channel, which decodes + `import_block`s without
re-running gossip validation, so lookup-fetched (non-gossip) blocks re-imported
this way are not subject to gossip rules. The direct-import site re-injects the
original gossip `(topic, data)` verbatim; the fetch/replay sites reconstruct
`(topic, data)` from the block's own fork digest via
`encode_signed_block_as_gossip_bytes`.

Verified by unit tests `hold_future_block_replays_when_due`,
`hold_future_block_drops_when_too_far`, `wait_until_slot_start_past_and_future`,
and integration test `lookup_direct_import_holds_future_block` (anchors genesis
at wall-now so block1 is genuinely one slot ahead — `D-import-clock-nudge`'s
wall-now advance means a block is only `FutureSlot` when its slot is ahead of
the wall clock, not the store cursor — then asserts the block is re-injected
verbatim and not imported).

## M6-Capella decisions

**Status of this section**: ACCEPTED (finalized at Phase 8 after the
Bellatrix→Capella devnet acceptance). Plan: `docs/m6-capella-plan.md`. Spec:
`~/dev/consensus-specs/specs/capella/*`. Two correctness ADRs
(`D-live-fork-trigger-in-state-transition`, `D-runtime-cfg-threading-live-loops`)
were added from devnet findings — see the "M6-Capella devnet correctness
decisions" subsection at the end.

### D-capella-state-shape — Capella `BeaconState` field additions, `historical_roots` frozen

**Status**: Accepted. **Date**: 2026-05-29 (finalized 2026-05-30).

Capella `BeaconState` adds `next_withdrawal_index: u64`,
`next_withdrawal_validator_index: ValidatorIndex (u64)`, and
`historical_summaries: SszList<HistoricalSummary, HISTORICAL_ROOTS_LIMIT>`;
`latest_execution_payload_header` is re-typed to `capella::ExecutionPayloadHeader`
(+`withdrawals_root`). `historical_roots` is RETAINED in the container (SSZ layout
stability) but FROZEN — `process_epoch` no longer appends to it. New enum variant
`BeaconState::Capella` (and `BeaconBlock`/`BeaconBlockBody::Capella`), plus
`ForkVariant::Capella` in `views.rs`. `CachedRoot` wired into the Capella inner
state with the clone-resets semantics from `D-validator-cache-clone-resets` /
`D-cached-root-wrapper`.

### D-withdrawals-stf-shape — `process_withdrawals` native on Capella state

**Status**: Accepted. **Date**: 2026-05-29 (finalized 2026-05-30).

`process_withdrawals(state, payload)` runs natively on the Capella state (not via
projection — it touches Capella-only fields). `get_expected_withdrawals` returns the
expected `Withdrawal` list (+ a `processed_sweep_count` for fidelity, currently
unused). The spec's `assert payload.withdrawals == expected` becomes
`StateTransitionError::WithdrawalsMismatch`. The validator sweep wraps modulo
`len(validators)` and respects `MAX_VALIDATORS_PER_WITHDRAWALS_SWEEP` (per-preset) and
`MAX_WITHDRAWALS_PER_PAYLOAD` (per-preset) with the spec assert
`len(prior_withdrawals) < withdrawals_limit`.

### D-bls-to-exec-change-domain — fork-agnostic signing domain

**Status**: Accepted. **Date**: 2026-05-29 (finalized 2026-05-30).

`DOMAIN_BLS_TO_EXECUTION_CHANGE = 0x0A000000`. `process_bls_to_execution_change`
verifies the signature with a FORK-AGNOSTIC domain:
`compute_domain(DOMAIN_BLS_TO_EXECUTION_CHANGE, GENESIS_FORK_VERSION,
genesis_validators_root)` — NOT the state's current fork version (address changes
are valid across forks). Credential flip: `BLS_WITHDRAWAL_PREFIX` →
`ETH1_ADDRESS_WITHDRAWAL_PREFIX + 11×0x00 + to_execution_address`.

### D-engine-v2-dispatch — Engine API V2 method dispatch

**Status**: Accepted. **Date**: 2026-05-29 (finalized 2026-05-30).

Add a `V2` arm to the existing `NewPayloadVersion` / `ForkchoiceUpdatedVersion` /
`GetPayloadVersion` enums (per `D-engine-method-dispatch` from M4a). New wire types
`WithdrawalV1`, `ExecutionPayloadV2` (= V1 + `withdrawals`), `PayloadAttributesV2`
(+`withdrawals`). V2 conversion is `From<capella::ExecutionPayload> for
ExecutionPayloadV2` in `pharos-engine/src/types.rs`; the engine-driver dispatch is
fork-conditional (Capella head/block → V2, else V1). Wire casing verified against
`~/dev/execution-apis/src/engine/shanghai.md`.

### D-capella-getpayload-deferral — `engine_getPayloadV2` live wiring deferred to M8

**Status**: Accepted. **Date**: 2026-05-29 (finalized 2026-05-30).

`engine_getPayloadV2` wire type + version arm are added, but the live
block-production driver path is NOT wired (Pharos is follow-only through M6).
`engine_newPayloadV2` + `engine_forkchoiceUpdatedV2` ARE required for Capella block
import. Full block production (getPayloadV2 → assembly, `PayloadAttributesV2` driver)
deferred to M8. A TODO marks the deferral in `handle.rs`.

### D-historical-summaries-field — `historical_summaries` stays Naive backend

**Status**: Accepted. **Date**: 2026-05-29 (finalized 2026-05-30).

`historical_summaries` is appended at most once per `SLOTS_PER_HISTORICAL_ROOT /
SLOTS_PER_EPOCH` epochs (rare; not a hot per-block field), so it uses the `Naive`
SSZ backend, NOT `Tree` — matching `historical_roots` in Bellatrix. The `Tree`-backend
hot-field list (`D-tree-backend-fields`) was re-checked for Capella and is unchanged
(the same 7 fields carry over). Recorded explicitly so the field list audit is on record.

### D-capella-fork-digest — Capella fork version + schedule growth

**Status**: Accepted. **Date**: 2026-05-29 (finalized 2026-05-30).

Capella fork version `0x03000000` (mainnet; minimal `0x03000001` — confirm against
preset/config). `ForkSchedule.fork_table()` grows from length 2 to length 3 with the
Capella entry; `compute_fork_version`/digest derivation add the Capella tier. The
generalized fork-migration loop (M4d) extends to `phase0→altair→bellatrix→capella`.
Network `Fork` enum gains `Fork::Capella`; `rpc/codec.rs` context-bytes and the four
LC req-resp methods gain Capella arms; `fork_from_context` recognises the Capella digest.

### D-capella-lc-header — Capella `LightClientHeader` execution payload + branch

**Status**: Accepted. **Date**: 2026-05-29 (finalized 2026-05-30).

Capella `LightClientHeader` adds `execution: capella::ExecutionPayloadHeader` and
`execution_branch: SszVector<Bytes32, 4>` (`floorlog2(EXECUTION_PAYLOAD_GINDEX=25)=4`).
`get_lc_execution_root` is epoch-gated at `CAPELLA_FORK_EPOCH` (pre-Capella headers must
carry default execution + branch); `is_valid_light_client_header` checks the merkle
branch (depth 4, subtree index of gindex 25) against `beacon.body_root`. Header values
are STF-verified (per M4c `D-bellatrix-lc-header-uses-state-root` precedent).

### D-folded-phase0-validators — implement the 3 deferred phase0 gossip validators

**Status**: Accepted. **Date**: 2026-05-29 (finalized 2026-05-30).

`validate_voluntary_exit`, `validate_proposer_slashing`, `validate_attester_slashing`
(currently `Accept` stubs in `host_impl.rs`) implemented in this milestone alongside
`validate_bls_to_execution_change`. Rule counts verified vs `specs/phase0/p2p-interface.md`:
voluntary_exit 1 IGNORE + 6 REJECT; proposer_slashing 1 IGNORE + 6 REJECT;
attester_slashing 1 IGNORE + 6 REJECT. Seen-caches extended per `D-seen-cache-shape` (M4e).

### D-live-fork-upgrade-trigger — Live fork-upgrade trigger in `process_slots_fork`

**Status**: Accepted. **Date**: 2026-05-29.

**Gap**: `upgrade_to_altair`, `upgrade_to_bellatrix`, and `upgrade_to_capella` were
called only from the conformance transition runner — never in the live STF path. A
running node could not cross a fork boundary.

**Fix location**: `process_slots_fork` in `crates/pharos-stf/src/lib.rs`. The function
takes a new `fork_epochs: ForkEpochs` argument (carrying `altair`, `bellatrix`, `capella`
epoch numbers) and a `runtime_cfg: &RuntimeConfig`. While advancing to `target_slot`, it
detects fork boundaries and applies the irregular upgrade in-place before continuing.

**Spec ordering**: `process_slots` advances to the boundary slot first (so `process_epoch`
for the last pre-fork epoch runs), THEN the upgrade is applied. The strict `current_slot <
boundary` guard enforces this.

**Fork epochs in Store**: `Store<E>` gains three fork epoch fields plus a `runtime_cfg:
RuntimeConfig` clone, mirroring the terminal-config precedent (`D-engine-head-driver`).
`get_forkchoice_store` defaults all epochs to `u64::MAX` (FAR_FUTURE_EPOCH — no upgrade
ever fires). Conformance `fork_choice` tests use this default; behaviour is byte-identical.
`get_forkchoice_store_with_config` wires real per-network values. `main.rs` calls
`set_fork_epochs` + assigns `runtime_cfg` after store construction.

**Upgrade-dispatch traits**: `Phase0UpgradeDispatch<E>`, `AltairUpgradeDispatch<E>`,
`BellatrixUpgradeDispatch<E>` — blanket impls on the concrete inner state types, each
delegating to the existing const-generic free function. Parallel pattern to
`*ProcessSlotsDispatch`. Added to the where-clauses of every function that calls
`process_slots_fork` on the live path.

**Single-fork callers**: test helpers and benches that construct single-fork chains pass
`ForkEpochs::never()`, preserving byte-identical behaviour.

**Multi-fork advance**: a phase0 state advanced past multiple fork boundaries in one
`process_slots_fork` call crosses each boundary in order (e.g. phase0 → altair →
bellatrix → capella on checkpoint catch-up).

**Distinct-epoch assumption**: coincident non-genesis fork epochs are not supported (real
networks use distinct epochs). The `current_slot < boundary` guard is intentional.

### D-bls-to-exec-seen-cache — seen-cache key for bls_to_execution_change gossip

**Status**: Accepted. **Date**: 2026-05-29 (finalized 2026-05-30).

The gossip seen-cache gains `bls_to_execution_change_indices: HashSet<ValidatorIndex>`
(spec: IGNORE a second change for an already-seen validator index). Marked seen only
AFTER an Accept verdict (per M4e `D-seen-cache-after-accept`). `validate_bls_to_execution_change`
= 2 IGNORE (pre-CAPELLA_FORK_EPOCH; already-seen index) + 4 REJECT (index out of range;
not a BLS withdrawal credential; pubkey-hash mismatch; bad signature).

## M6-Capella devnet correctness decisions

Two bugs surfaced ONLY on the live Bellatrix→Capella transition devnet (lighthouse
v8.1.3 + ethrex v13, `CAPELLA_FORK_EPOCH=1`), not by any conformance category — the
M6 analogue of the M5-follow live-only findings. Conformance is green because the
`transition` runner drives the upgrade itself and the capella `sanity`/`operations`
categories start from a capella anchor state; a real bellatrix→capella crossing only
happens on a live network. Both fixed and re-verified live (pharos followed head 49
capella slots past the fork, head==wall±1, 0 bans, 0 panics, ethrex `newPayloadV2`
VALID, over 10 minutes).

### D-live-fork-trigger-in-state-transition — wire `process_slots_fork` into the live STF entry

**Status**: Accepted. **Date**: 2026-05-30.

**Gap**: `D-live-fork-upgrade-trigger` (Phase 2) built and unit-tested
`process_slots_fork` (cross-fork advance + irregular `upgrade_to_*` at the boundary)
but never called it from the live STF entry point. `crates/pharos-stf/src/lib.rs::state_transition`
dispatched purely on the PRE-STATE's `fork_variant()`: a bellatrix pre-state (slot 31)
+ a capella block (slot 32) entered the Bellatrix arm, `unwrap_bellatrix_signed_block`
returned `None`, and the node returned `StateTransitionError::UnsupportedFork` and froze
at the fork, retrying the first capella block forever.

**Fix**: `state_transition` now calls
`process_slots_fork(&mut state, E::signed_block_slot(signed_block), ForkEpochs::from_runtime_cfg(runtime_cfg), runtime_cfg)`
BEFORE the per-fork dispatch. The block's slot is read fork-agnostically via a new
`EthSpec::signed_block_slot` accessor (the block's fork never changes with the state).
After the advance+upgrade the state matches the block's fork, and the per-fork
`apply_signed_block`'s internal `process_slots_*(block.slot)` is a no-op because
`process_slots_*` tolerate `target == state.slot` (they only error on `target < state.slot`).
`ForkEpochs::from_runtime_cfg` derives the three fork epochs from `RuntimeConfig`, so no
signature change. The `process_slots_fork` `*ProcessSlotsDispatch`/`*UpgradeDispatch`
where-clause bounds were propagated to `state_transition` and the generic conformance
runners (`finality`/`random`/`sanity`/`transition`); concrete-`EthSpec` callers satisfy
them via blanket impls. No double-upgrade in the conformance transition runners: after a
manual `upgrade_to_*` the state is already at the target fork, so `process_slots_fork`'s
boundary check returns `None`. Regression test:
`state_transition_crosses_bellatrix_to_capella`.

### D-runtime-cfg-threading-live-loops — live import loops must use the loaded `RuntimeConfig`

**Status**: Accepted. **Date**: 2026-05-30.

**Gap**: even with `D-live-fork-trigger-in-state-transition` in place, the live import
loops fed `state_transition` a DEFAULT `RuntimeConfig` (mainnet defaults have
`CAPELLA_FORK_EPOCH = u64::MAX`), so `ForkEpochs::from_runtime_cfg` saw "never" and no
upgrade fired — the node still froze at the fork. The three live import paths each
hardcoded a default: `block_ingestion.rs` (`RuntimeConfig::default()`), `backfill.rs` and
`lookup.rs` (`E::default_runtime_config()`). This was latent until M6 because no fork
boundary was ever crossed live (M4d/M5-follow were bellatrix-at-genesis, no transition).

**Fix**: all three loops now read the node's loaded config from the fork-choice store
(`fc_store.read().runtime_cfg.clone()`), which `main.rs` populates from `--config-dir`
before spawning the loops. The store already carried `runtime_cfg` (set alongside
`set_fork_epochs`); the loops simply use it instead of a default. Falls back to default
semantics naturally when `--config-dir` is absent (store defaults to `RuntimeConfig::default()`).

## M7-BeaconAPI

**Status of this section**: PROPOSED (to be finalized at Phase 6 after the
Kurtosis interop gate). Plan: `docs/m7-plan.md`. Spec:
`~/dev/beacon-APIs/beacon-node-oapi.yaml` + per-namespace YAML files under
`~/dev/beacon-APIs/apis/`.

### D-api-chain-accessor — read-only `ChainStateApi` trait over existing shared state

**Status**: Proposed.

A thin `ChainStateApi<E>` trait implemented by `NodeChainState<E>`, which
holds `Arc<RocksStore>`, `Arc<RwLock<pharos_fork_choice::Store<E>>>`, and a
`NodeIdentityCache` snapshot. All reads are synchronous and executed behind
`tokio::task::spawn_blocking`; the axum handler acquires a read guard, extracts
the needed data, drops the guard, then serializes. No API-specific actor or
channel is introduced for reads, because reads have no ordering requirements and
an actor would add a hop for zero benefit. This mirrors `D-store-trait` (sync
core, async at edges) exactly.

### D-api-dto-serde — in-house DTO structs with `quoted_int` / `hex_bytes` helpers

**Status**: Proposed.

`pharos-types` carries zero serde derives; the API layer owns all JSON
serialization via dedicated DTO structs in `pharos-api`. Two in-house helper
modules handle the beacon-API wire quirks: `quoted_int` (serialize/deserialize
`u64` as a quoted decimal string, e.g. `"slot": "10"`) and `hex_bytes`
(serialize `[u8; N]`, `Vec<u8>`, and `Root` as `0x`-prefixed lowercase hex).
This avoids coupling canonical SSZ types to a JSON wire format that diverges
per fork-tag/version envelope, and keeps the rejected-dep boundary clean
(`ethereum_serde_utils` stays out).

### D-api-content-negotiation — single response extractor branching on `Accept`

**Status**: Proposed.

A single `ApiResponse<T>` axum `IntoResponse` type inspects the `Accept`
request header: `application/octet-stream` produces a raw SSZ body via
`pharos_ssz::Encode` on the canonical inner type, with
`Content-Type: application/octet-stream`; any other value (or absent `Accept`)
produces a JSON body via the DTO. Fork-tagged SSZ responses still set the
`Eth-Consensus-Version` response header. A 406 is returned when the client
sends an explicit `Accept` for a format the endpoint does not support. The
SSZ path reuses the canonical type's `Encode` directly; no DTO is involved
in the SSZ branch.

### D-api-fork-tag-envelope — `/eth/v2` responses wrap data in a version envelope

**Status**: Proposed.

Endpoints under `/eth/v2` (and `/eth/v3`) whose payload is fork-dependent
wrap the response DTO in `{ version, execution_optimistic, finalized, data }`
and set the `Eth-Consensus-Version` response header. The `version` string is
derived from the block or state's `fork_variant()` (e.g. `"capella"`); it is
never recomputed from the post-state. A `ForkTagged<T>` envelope DTO in
`pharos-api/src/fork_tag.rs` handles both the body wrapping and the header
injection in its `IntoResponse` impl. Non-fork-dependent v1 endpoints emit
`{ data: <T> }` with optional `execution_optimistic` and `finalized` where
the spec mandates them, but no `version` field.

### D-api-id-resolution — `resolve_state_id` / `resolve_block_id` helper module

**Status**: Proposed.

A `resolve.rs` module maps the six beacon-API id forms
(`head`, `genesis`, `finalized`, `justified`, `<slot>`, `0x<root>`) to a
`(Root, Slot, optimistic: bool, finalized: bool)` tuple. Resolution order:
in-memory fork-choice store first (covers head, recent slots, all checkpoints),
then `RocksStore` for cold slots and historical roots. Returns 400 on a
malformed id and 404 on an unknown root or pruned slot. `justified` is
resolved identically to `finalized` for state reads (both yield the
checkpoint block/state). The same helper is shared across all beacon, block,
and debug handlers.

### D-api-sse-broadcast — `tokio::sync::broadcast` bus with `watch`-to-broadcast adapter

**Status**: Proposed.

A single `tokio::sync::broadcast::Sender<ApiEvent>` is held in `ApiState`.
A `run_api_event_adapter` task clones the existing
`watch::Receiver<Option<HeadChange>>` from the block-ingestion loop and the
`Arc<RwLock<pharos_fork_choice::Store<E>>>`. On each head change it reads
`fork_choice.read().finalized_checkpoint` to derive `finalized_checkpoint`
events without adding a separate finalized channel. It emits `head`, `block`,
`chain_reorg` (via `get_ancestor` walk), and `finalized_checkpoint` events.
`broadcast` (not `watch`) is chosen because SSE needs every event delivered
to every subscriber independently; lagged receivers skip missed events and
continue. Accepted-but-never-emitted topics (e.g. `payload_attributes`) are
not 400-rejected at the subscription endpoint; the filter simply produces no
frames for them.

### D-api-axum-state — `Arc<ApiState<E>>` via `axum::extract::State`

**Status**: Proposed.

`ApiState<E>` is the single axum application state, injected via
`axum::extract::State(Arc<ApiState<E>>)`. It holds the `ChainStateApi`
implementation and the `EventBus`. One router is built per concrete `EthSpec`
(only `MainnetEthSpec` is wired in the node binary at M7); the
`Arc<ApiState<E>>` is cheaply clonable across handlers. No separate actor or
channel is introduced for API reads; read handlers acquire a short-lived
`fork_choice.read()` guard inside a `spawn_blocking` closure, extract data,
drop the guard, then serialize.

### D-api-validator-auth — opt-in bearer token middleware on `/eth/v1/validator/*` only

**Status**: Proposed.

A `tower`/axum middleware layer (`validator_auth_layer(token: Option<String>)`)
is applied only to the `/eth/v1/validator/*` nested sub-router. When a token
path is provided via `--validator-api-token <path>`, the middleware requires
`Authorization: Bearer <token>` and returns 401 on missing credentials or 403
on a wrong token; when no path is given (default), the middleware is a no-op
pass-through. Auth is scoped strictly to the validator sub-router; node,
config, beacon, debug, and events namespaces are never gated. The token file
is read once at startup in trimmed form (lighthouse-compatible); rotation
requires a restart.

### D-api-node-identity-cache — `NodeIdentityCache` snapshot instead of `NetworkHandle`

**Status**: Proposed.

`NetworkHandle` is not `Clone` (it owns a single `mpsc::Receiver<NetworkEvent>`
already consumed by the node binary at startup) and cannot be embedded in the
(sync, `spawn_blocking`) API state. Instead, the binary builds a
`NodeIdentityCache` once at startup, after `handle.wait_for_local_enr()` and
`handle.wait_for_listen_addr()` resolve (both are `async fn &mut self`; they
must be called before the receiver is moved into the ingestion loop). The
cache holds `peer_id`, `enr`, `listen_addrs`, `discovery_addrs`, and
`metadata: Arc<ArcSwap<AltairMetaData>>`. A new
`NetworkHandle::metadata_ref()` accessor exposes the live metadata `ArcSwap`
clone so the `node/identity` handler can read the current metadata sequence
number without a stale snapshot.

## M-Storage

**Status of this section**: ACCEPTED (M-Storage closed 2026-06-01; Phases 0-5 landed, restart-across-split + replay + freezer-migration gates green).
wrap-up phase after the restart-recovery + replay-correctness gates).
Plan: `docs/storage-plan.md`. Motivation: an M7 code review found the live
import path (`crates/pharos-node/src/import.rs:import_block`) persists nothing
to RocksDB — only startup and checkpoint-sync write to disk — so blocks
imported after startup are invisible to `GET /eth/v2/beacon/blocks/{id}` and
do not survive a restart.

### D-persist-in-import-core — persist at the tail of `import_block`, after the lock drops

**Status**: Accepted. **Date**: 2026-06-01.

The unconditional block + slot-index + `state-summary` + fork-choice-snapshot
write lives at the tail of `import_block`, the single convergence point for the
ingestion, backfill, and lookup producers. It is issued in a SEPARATE
`spawn_blocking` worker that runs AFTER the `on_block` closure returns (so the
fork-choice WRITE guard is already dropped) and takes only a `fc.read()` guard
to snapshot the cursors — mirroring the LC-snapshot precedent at
`block_ingestion.rs:277-298`. The DB write is NEVER inside the `on_block`
closure: a per-slot disk write under the write lock would stall every
fork-choice reader (`get_head`, gossip validators, the Beacon API, the SSE
adapter). The persist worker is `.await`-ed before the `HeadChange` is returned,
so a head is never published referencing an unpersisted block, yet no await is
added to the `on_block` critical section. The per-import batch ALWAYS includes
`forkchoice = Some(snapshot)`; without it a restart after live imports would
rehydrate from the stale checkpoint-sync snapshot and rewind the
head/justified/finalized cursors.

### D-epoch-boundary-state-cadence — store a full state only at epoch boundaries

**Status**: Accepted. **Date**: 2026-06-01.

Store a full post-state only when `slot % SLOTS_PER_EPOCH == 0` (plus a single
`head_state_root` metadata pointer row); intermediate states are reconstructed
by replay. Bounds the per-epoch state-write cost to one SSZ encode rather than
one per slot. The dominant cost is the validator-registry encode (tens of MB at
mainnet scale); pinning it to epoch boundaries keeps the per-slot write budget
to small rows only.

### D-replay-on-read — regenerate intermediate states by load-nearest + replay

**Status**: Accepted. **Date**: 2026-06-01.

An arbitrary historical state is served by loading the nearest stored
epoch-boundary state (or cold restore point) at-or-below the target and
replaying persisted blocks forward via `process_slots_fork` / `state_transition`
(the existing STF primitives). Cold reads cost at most `restore-point-interval`
block applies. This is the universal CL approach (Lighthouse/Prysm/Teku) and
avoids storing a state per slot.

### D-freezer-in-rocksdb — cold region is a CF set in the same RocksDB instance

**Status**: Accepted. **Date**: 2026-06-01.

The cold/freezer region is a dedicated set of column families in the SAME
RocksDB instance (`cold-blocks`, `cold-states` keyed by restore-point slot,
`restore-points` index), not a separate file or flat-file format. Migration at
finalization is a single atomic `WriteBatch` per step (copy-then-delete folded
into one batch), reusing the existing `BlockTransition` atomic-write convention
(`D-rocksdb`).

### D-restore-point-interval — configurable coarse cold-state cadence

**Status**: Accepted. **Date**: 2026-06-01.

Cold states are kept at a configurable restore-point cadence (a coarse multiple
of `SLOTS_PER_EPOCH`, default every N epochs via `--restore-point-interval-epochs`),
not at every finalized epoch boundary, trading replay length for cold-state
count. At mainnet scale a `BeaconState` SSZ-encodes to ~50–200 MB, so the
interval directly sets cold-DB growth (see `docs/storage-plan.md` write-budget
appendix).

### D-prune-behind-finalized — delete hot data below the finalized slot after migration

**Status**: Accepted. **Date**: 2026-06-01.

After cold migration, hot blocks/states strictly below the finalized slot are
deleted (the finalized boundary becomes the new hot anchor); orphaned
(non-canonical, pre-finalization) blocks/states are pruned in the same pass.
Orphan detection uses the authoritative persisted `slot_to_block_root` index (a
root is canonical iff `slot_to_block_root[slot] == root`), NOT the in-memory
`get_ancestor` walk, which is unreliable once blocks are evicted from the
in-memory map. `latest_messages` and the other per-block fork-choice maps are
pruned alongside `block_states` eviction.

### D-schema-v3-migration — bump SCHEMA_VERSION 2→3, no in-place migration

**Status**: Accepted. **Date**: 2026-06-01.

Bump `SCHEMA_VERSION` 2→3; opening a v2 DB returns `SchemaMismatch` and the
operator resyncs from checkpoint — the same policy as the v1→v2 bump. No
in-place data migration: the live node had no post-startup block/state
persistence to preserve, so there is nothing to migrate. All schema-v3 CFs
(including the Phase-3 cold CFs) are declared at first boot because RocksDB
requires every CF at `open()` time.

### D-state-diffs-deferred — full-SSZ per stored state; on-disk diffs out of scope

**Status**: Accepted. **Date**: 2026-06-01.

On-disk state diffs (Lighthouse `hdiff`-style hierarchical layers) are
explicitly out of scope for this milestone; each stored state is full SSZ.
Structural sharing (the tree-backed `SszList`/`SszVector`) is exploited in RAM
for cheap hot-state retention only. Revisit on-disk diffs as a dedicated perf
milestone if cold-state volume warrants.

### D-store-signed-block-only — persist the SignedBeaconBlock; derive header/block from it

**Status**: Accepted. **Date**: 2026-06-01.

The canonical persisted block is the `SignedBeaconBlock` (already the `blocks`
CF shape); the API derives both the unsigned header (with the REAL signature)
and the full block from it. Fork-choice keeps its unsigned in-memory
`BeaconBlock` copy unchanged. This fixes the v1 header endpoints that previously
zeroed the signature (the signed block was dropped after import).

### D-freezer-driver-off-head-watch — drive freezer/prune off the existing head watch

**Status**: Accepted. **Date**: 2026-06-01.

The freezer/prune loop is driven by the existing
`watch::Receiver<Option<HeadChange>>` (reading
`fork_choice.read().finalized_checkpoint` on each head advance), mirroring the
M7 `D-api-sse-broadcast` adapter pattern — no new channel or task-coordination
primitive is introduced.
