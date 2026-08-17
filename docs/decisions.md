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
  - D-m7-gate-harness D-api-debug-state-full-per-fork

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

Source/precedent: the de facto Rust CL ecosystem convention (CL clients
use these exact key names). The consensus-specs
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
upgrade path and is already deployed by Prysm and Teku.
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
or req-resp. This is industry-wide (Prysm, Lodestar, Teku,
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
4. **Cross-client interop tests** against a reference CL client + ethrex planned
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
  (e.g. `"<client>/v4.0.0"`).
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
with a new `EthSpec` binding. This matches how other CL clients
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
weak-subjectivity sync convention used by all major CL implementations (Teku, Prysm,
and others). Pre-anchor history is opaque and trusted via the operator's choice of
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
benefits from automatic rotation on first boot; file-based auto-gen matches what Teku
and other CL clients do). Enforced in `crates/pharos-node/src/jwt_autogen.rs` (`ensure_jwt_secret`
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

**SUPERSEDED (2026-06-13) by `D-flat-conformance-workpool`** (M-Conf-Perf): the
nested-rayon thrash was the failure of a *two-level* design. The correct
realization is a *single-level* flat pool — every category produces a flat
`Vec<CaseTask>`, all collected into one `Vec`, run through ONE top-level
`into_par_iter` with zero inner `par_iter`. That landed and is byte-identical
(full walk 3:53 → 2:31, CPU 617% → 905%).

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
same slot. Some CL clients use an equivalent `ProposerCache` keyed identically.
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
message. The "insert on Accept" pattern is used by other CL clients for the same
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
connected peer (e.g. a reference CL client) requests blocks by range or root and the local DB
contains Bellatrix blocks.

Rejected alternative: implement receive only and stub send — would break any peer that
requests Bellatrix blocks from Pharos, blocking interop with other CL clients in a
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
Pharos actually followed a reference CL client + ethrex on the live Bellatrix
devnet. All live-verified: pharos `head == wall` (exact, 0 lag), `peers:1`
stable to epoch 15, 0 bans from the reference CL.

### D-blocksbyroot-bare-list — BeaconBlocksByRoot request is the bare List, not a container

**Status**: Accepted. **Date**: 2026-05-29. **Commit**: `6b19e71`.

The req/resp `BeaconBlocksByRootRequest` is a single-field wrapper around
`SszList<Root, MAX_REQUEST_BLOCKS>`. Per the p2p single-field rule
(`p2p-interface.md`) it serializes as the bare `List[Root, N]` — but
`#[derive(Encode, Decode)]` treated it as an SSZ container and prepended a
4-byte offset for its lone variable-length field (an empty request became
exactly the 4 offset bytes). The reference CL decoded that as
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
The reference CL logged `Light client optimistic update too early error: TooEarly` and
applied a `light_client_gossip_error` penalty (~-1.00/slot), bleeding toward a
ban in ~15 min. The update *content* was correct (the reference CL deduped pharos's
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

Two bugs surfaced ONLY on the live Bellatrix→Capella transition devnet (a reference
CL client + ethrex v13, `CAPELLA_FORK_EPOCH=1`), not by any conformance category — the
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

**Status of this section**: ACCEPTED (M7 closed 2026-06-01; Beacon API ships
across 6 phases, cross-client read gate green on the live Bellatrix→Capella
devnet). Plan: `docs/m7-plan.md`. Spec:
`~/dev/beacon-APIs/beacon-node-oapi.yaml` + per-namespace YAML files under
`~/dev/beacon-APIs/apis/`.

### D-api-chain-accessor — read-only `ChainStateApi` trait over existing shared state

**Status**: Accepted. **Date**: 2026-06-01.

A thin `ChainStateApi<E>` trait implemented by `NodeChainState<E>`, which
holds `Arc<RocksStore>`, `Arc<RwLock<pharos_fork_choice::Store<E>>>`, and a
`NodeIdentityCache` snapshot. All reads are synchronous and executed behind
`tokio::task::spawn_blocking`; the axum handler acquires a read guard, extracts
the needed data, drops the guard, then serializes. No API-specific actor or
channel is introduced for reads, because reads have no ordering requirements and
an actor would add a hop for zero benefit. This mirrors `D-store-trait` (sync
core, async at edges) exactly.

### D-api-dto-serde — in-house DTO structs with `quoted_int` / `hex_bytes` helpers

**Status**: Accepted. **Date**: 2026-06-01.

`pharos-types` carries zero serde derives; the API layer owns all JSON
serialization via dedicated DTO structs in `pharos-api`. Two in-house helper
modules handle the beacon-API wire quirks: `quoted_int` (serialize/deserialize
`u64` as a quoted decimal string, e.g. `"slot": "10"`) and `hex_bytes`
(serialize `[u8; N]`, `Vec<u8>`, and `Root` as `0x`-prefixed lowercase hex).
This avoids coupling canonical SSZ types to a JSON wire format that diverges
per fork-tag/version envelope, and keeps the rejected-dep boundary clean
(`ethereum_serde_utils` stays out).

### D-api-content-negotiation — single response extractor branching on `Accept`

**Status**: Accepted. **Date**: 2026-06-01.

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

**Status**: Accepted. **Date**: 2026-06-01.

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

**Status**: Accepted. **Date**: 2026-06-01.

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

**Status**: Accepted. **Date**: 2026-06-01.

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

**Status**: Accepted. **Date**: 2026-06-01.

`ApiState<E>` is the single axum application state, injected via
`axum::extract::State(Arc<ApiState<E>>)`. It holds the `ChainStateApi`
implementation and the `EventBus`. One router is built per concrete `EthSpec`
(only `MainnetEthSpec` is wired in the node binary at M7); the
`Arc<ApiState<E>>` is cheaply clonable across handlers. No separate actor or
channel is introduced for API reads; read handlers acquire a short-lived
`fork_choice.read()` guard inside a `spawn_blocking` closure, extract data,
drop the guard, then serialize.

### D-api-validator-auth — opt-in bearer token middleware on `/eth/v1/validator/*` only

**Status**: Accepted. **Date**: 2026-06-01.

A `tower`/axum middleware layer (`validator_auth_layer(token: Option<String>)`)
is applied only to the `/eth/v1/validator/*` nested sub-router. When a token
path is provided via `--validator-api-token <path>`, the middleware requires
`Authorization: Bearer <token>` and returns 401 on missing credentials or 403
on a wrong token; when no path is given (default), the middleware is a no-op
pass-through. Auth is scoped strictly to the validator sub-router; node,
config, beacon, debug, and events namespaces are never gated. The token file
is read once at startup in trimmed form (the common CL client format); rotation
requires a restart.

### D-api-node-identity-cache — `NodeIdentityCache` snapshot instead of `NetworkHandle`

**Status**: Accepted. **Date**: 2026-06-01.

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

### D-m7-gate-harness — M7 interop gate reuses the hand-rolled devnet, not Kurtosis

**Status**: Accepted. **Date**: 2026-06-01.

The M7 plan (Task 6.1) specified a Kurtosis `ethereum-package` enclave as the
cross-client gate. We kept the existing hand-rolled host-process devnet
(`scripts/devnet/`, runtime `~/.cache/pharos-devnet/run-tmux.sh`) instead. It
already drives the exact reference-CL + ethrex v13 Bellatrix→Capella
transition chain the M5-follow and M6-Capella live acceptances used, with every
cross-client gotcha already baked into the scripts. A Kurtosis custom-service
definition would re-derive the same topology in a heavier runtime for no extra
coverage on a solo devnet. The M7 additions are minimal: `run-pharos.sh` launches
pharos with `--http --http-port 5053` (5052 is the reference CL BN), and
`run-vc-vs-pharos.sh` points an external reference CL VC at pharos plus a curl
read-probe of the VC-critical endpoints. The gate is duties-READ + a stable VC
connection over ≥2 epochs, NOT attestation submission (production/POST publish is
M8; the VC's publish errors against pharos are expected). Upstreaming a pharos
service to `ethpandaops/ethereum-package` remains a later follow-up.

### D-api-debug-state-full-per-fork — `debug/beacon/states` JSON serializes the complete per-fork state

**Status**: Accepted. **Date**: 2026-06-01.

`GET /eth/v2/debug/beacon/states/{id}` returns the FULL `BeaconState` in JSON,
not a common-fields subset. Because `pharos-types` is serde-free
(`D-api-dto-serde`), the complete serialization lives in
`pharos_api::beacon_state_to_json_full`, which fork-dispatches on the
enum-of-forks `BeaconState<E>` and emits every spec field per fork (phase0
attestations; altair+ participation flags / inactivity scores / sync committees;
bellatrix+ `latest_execution_payload_header`; capella+ withdrawal indices +
`historical_summaries`). This required adding borrowing accessors to
`BeaconStateView` for the per-fork fields rather than a `Vec`-cloning path. The
SSZ branch (`Accept: application/octet-stream`) encodes the canonical type
directly and is authoritative; the JSON branch is the schema-complete mirror a
conforming client validates. A partial JSON body (the initial Phase-5 cut) was
rejected in review as non-conformant.

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
block applies. This is the universal CL approach (Prysm/Teku and others) and
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

On-disk state diffs (`hdiff`-style hierarchical layers, as some CL clients use) are
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

## M8-OptimisticSync decisions

Full spec-correct optimistic sync per `specs/sync/optimistic.md` +
`specs/bellatrix/fork-choice.md`. Unblocks the live VC write/duties gate that M7
(read gate) could not pass against a still-syncing EL. Plan:
`docs/m8-optimistic-plan.md`. Operational prerequisite (not code): the EL MUST
have its own p2p enabled to backward-sync execution toward the FCU head target;
a `--p2p.disabled` EL can never satisfy optimistic sync.

### D-engine-edge-stf-relaxation — relax the EL-verdict bool at the single wire edge

**Status**: Accepted. **Date**: 2026-06-02.

`ExecutionEngineHandle::new_payload_wire` returns "not rejected" for VALID /
SYNCING / ACCEPTED and only `false` for INVALID / INVALID_BLOCK_HASH (engine
error also rejects, per spec "Execution Engine Errors"). This is the minimal
change that stops a checkpoint-synced node rejecting every tip block while the
EL is still syncing. The relaxation lives ONLY at the live wire edge; the
`FixedExecutionEngine` conformance mock is untouched so `execution_valid:false`
fixtures still drive STF rejection. Both `notify_new_payload` and
`notify_new_payload_capella` inherit it via the shared helper.

### D-preseed-notvalidated-on-import — seed payload_statuses=NotValidated at import time

**Status**: Accepted. **Date**: 2026-06-02.

Every execution-carrying block gets `payload_statuses[root] = NotValidated`
(if-absent, in-memory + persisted) in the import persist worker, independent of
the fire-and-forget `payload_tx` send. Without this a dropped/lagging newPayload
send would leave a post-merge block with no status entry, which the optimism
derivation would alias as non-optimistic — the unsafe direction. The async
engine driver later overwrites with Valid/Invalid.

### D-is-optimistic-execution-block-derivation — derive optimism from payload_statuses, no parallel flag

**Status**: Accepted. **Date**: 2026-06-02.

`is_optimistic(store, root) = block_is_execution_enabled(block) &&
payload_statuses.get(root) != Some(Valid)`. Single source of truth (the
`payload_statuses` map); no parallel `optimistic` bool to drift. The
execution-block guard + the Phase-1 pre-seed together disambiguate pre-merge
blocks (no entry, not execution-enabled → false) from not-yet-validated
post-merge blocks (entry present → optimistic until Valid).

### D-optimistic-candidate-gates-import — gate optimistic import on is_optimistic_candidate_block

**Status**: Accepted. **Date**: 2026-06-02.

`is_optimistic_candidate_block` (SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY = 128, spec
constant) gates whether a block may be imported optimistically: parent is an
execution block OR the block is ≥ SAFE_SLOTS old. The gate runs AFTER the STF
(Phase 3b) and rejects only when the EL verdict is NotValidated AND the block is
not a candidate AND it is eligible for import now (`block_slot <= current_slot`).
A VALID non-candidate block still imports (the gate is MAY-optimistic only).
Future blocks bypass the gate to the future-slot hold path. On capella+ every
block's parent is execution-enabled, so the gate is inert in normal operation;
it only bites a merge-transition block near the tip (fork-choice poisoning
protection). Backfill backs off slot-aware on `NotOptimisticCandidate`.

### D-reorg-notvalidated-by-weight — filter_block_tree excludes only Invalid, never NotValidated

**Status**: Accepted. **Date**: 2026-06-02.

`filter_block_tree` continues to exclude only `Some(Invalid)`. NotValidated
(optimistic) blocks stay in the viable set, so re-orgs between two optimistic
tips resolve by normal LMD-GHOST weight (spec MUST-support: re-orgs not
affecting the justified checkpoint). No extra code; guarded by comment + test.

### D-payload-verification-status — thread a 3-valued EL verdict out of the STF

**Status**: Accepted. **Date**: 2026-06-02.

The `ExecutionEngine` trait returns `PayloadVerificationStatus
{Valid, NotValidated, Invalid}` instead of `bool`; `process_execution_payload`
maps Invalid→`Err(InvalidExecutionPayload)` (so Invalid is NEVER a successful
return) and otherwise returns the status; `state_transition` returns
`(state, Option<PayloadVerificationStatus>)` threaded through `process_block`
(None pre-merge). This surfaces the EL verdict to the import-layer candidate gate
without the STF knowing fork-choice concepts. `FixedExecutionEngine` maps
true→Valid / false→Invalid (conformance preserved); `NullExecutionEngine`→Valid.

### D-latest-valid-hash-resolution — 3-case latestValidHash table + transitive invalidation

**Status**: Accepted. **Date**: 2026-06-02.

On an EL INVALID (from newPayload OR forkchoiceUpdated), `resolve_invalid_block`
implements the spec 3-case `latestValidHash` table (null → the block in
question; zero → the first execution block on the chain; nonzero → the child,
toward the block in question, of the block whose execution block_hash == LVH,
falling back to null behaviour when no match). `apply_invalid_payload` then marks
the resolved block AND all transitive descendants Invalid (forward BFS over the
block graph), which `filter_block_tree` excludes from head selection. Invalid is
kept in-memory only (the driver has no DB handle); it self-heals on restart via
EL re-report.

### D-async-engine-error-notvalidated — async driver keeps NotValidated on transient error

**Status**: Accepted. **Date**: 2026-06-02.

The synchronous STF path returns Invalid on an EL error (MUST NOT import). The
asynchronous engine-driver recheck of an already-imported block instead keeps
the block NotValidated on a transient RPC/join error: a connection blip is not a
protocol INVALID verdict, and marking Invalid would permanently evict a possibly
valid block from fork choice. The next newPayload/FCU re-evaluates it.

### D-valid-ancestor-promotion — NOT_VALIDATED→VALID promotes all ancestors

**Status**: Accepted. **Date**: 2026-06-02.

On a newPayload VALID, `promote_valid_ancestors` walks parent_root marking every
NotValidated ancestor (and the block itself) Valid, stopping at the first
already-Valid ancestor or the anchor (spec MUST). Without it the
`execution_optimistic` flag stays wrongly true for transitively-validated
ancestors. The driver marks the block Valid explicitly before promotion.

### D-merge-block-syncing-on-unknown-pow — relax validate_merge_block when PoW unavailable

**Status**: Accepted. **Date**: 2026-06-02.

In `on_block`, a `validate_merge_block` failure with `PowBlockNotFound` (terminal
PoW block unknown to the EL ⇒ pow_parent also unknown, the spec's "both unknown")
imports the merge-transition block optimistically as NotValidated instead of
rejecting. All other merge errors (TERMINAL_BLOCK_HASH, TTD, PowParentNotFound,
provider) still reject. On a later VALID the merge block is re-validated via the
real `EnginePowBlockProvider` threaded into the driver; failure → invalidation.
Known limitation (documented, genesis-sync-through-merge only — unreachable for
checkpoint-synced Pharos whose anchor is post-merge): PowBlockNotFound at the
VALID re-validation has no retry, and `promote_valid_ancestors` does not re-run
`validate_merge_block` when indirectly promoting a merge block.

### D-fcu-safe-finalized-verified-ancestor — FCU safe/finalized never an optimistic hash

**Status**: Accepted. **Date**: 2026-06-02.

`compute_safe_block_hash` / `compute_finalized_block_hash` resolve
`latest_verified_ancestor` of the justified / finalized root before taking the EL
block hash, so forkchoiceUpdated never sends an optimistic block hash as
`safe`/`finalized`. `head_block_hash` is left as-is (the head MAY be optimistic —
that is the point of optimistic FCU). `latest_verified_ancestor` falls back to
the finalized root on a fragmented hot window.

### D-anchor-payload-status-valid — seed the checkpoint anchor as Valid

**Status**: Accepted. **Date**: 2026-06-02.

The anchor block is seeded `PayloadStatus::Valid` in `get_forkchoice_store`,
`apply_anchor` (checkpoint sync), and `rehydrate_fork_choice_store` (restart).
Per spec "Checkpoint Sync (Weak Subjectivity Sync)" a CL MAY assume the anchor's
ExecutionPayload is VALID. Without this, a post-merge checkpoint-synced anchor
(execution-enabled, no status entry) would read as optimistic, making
`latest_verified_ancestor` walk past it and FCU send a zero/optimistic
safe/finalized hash.

### D-optimistic-node-no-viable-branch — is_optimistic_node = head-optimistic OR all-branches-invalidated

**Status**: Accepted. **Date**: 2026-06-02.

`is_optimistic_node` returns true if (1) the head is optimistic, OR (2) the head
fell back to the base because every viable branch was INVALIDATED — detected by
the base having an execution-enabled child explicitly marked `Invalid` (NOT
merely FFG-non-viable, which would false-positive). Condition (1) covers the
common case; condition (2) is the spec's "no viable branch" state.

### D-validator-optimistic-gate — 503 production endpoints only; duty reads stay 200

**Status**: Accepted. **Date**: 2026-06-02.

Duty-READ endpoints stay 200 and surface `execution_optimistic` (from
`is_optimistic_node`) in the body; they are NOT 503'd on optimism. Production /
signing endpoints (produce_block, attestation_data, aggregate selection,
sync_committee_contribution) MUST 503 when `is_optimistic_node()` — but those do
not exist yet (block production deferred past M7), so the contract is documented
at the validator handler module + a do-not-sign marker in the VC stub, to be
wired when production lands. Spec: optimistic validator MUST NOT
propose/attest/sync-sign.

### D-optimistic-conformance-runner — replay the sync/optimistic tape via an out-of-band verdict map

**Status**: Accepted. **Date**: 2026-06-02.

The `sync/optimistic` runner replays tick/checks/block/payload_status steps.
Blocks import via `NullExecutionEngine` STF (matching pyspec
`run_on_block(valid=True)` for optimistic blocks — `valid:false` blocks ARE
imported, then excluded from head by the separately-declared INVALID
payload_status); the declared EL verdict is applied out-of-band keyed by an
`el_block_hash → verdict` + `el_block_hash → CL_root` map, driving
`promote_valid_ancestors` / `apply_invalid_payload` / `mark_payload_status`. STF
or missing-parent errors fail the case (no silent skip). bellatrix + capella,
mainnet + minimal, pass=2 fail=0 each.


---

## M7-followup: Light-client REST endpoints

### D-api-lc-bridge — LcEnvelope raw bytes vs typed container

**Status**: Accepted. **Date**: 2026-06-02.

The `LcEnvelope` DTO in `pharos-api::dto::light_client` carries pre-built
`ssz_bytes: Vec<u8>` (raw, unframed) and `json: serde_json::Value` (hand-built),
instead of holding the typed container (`E::AltairLightClientBootstrap` etc.).
Rationale: (1) the LC container types live behind the opaque `EthSpec` associated
types; holding a `dyn`-object would require object-safe accessor methods for every
field; (2) `LcEnvelope` is passed across a `spawn_blocking` boundary into the
axum handler, which requires `Send + 'static` — erasing the concrete type is the
simplest way to satisfy that constraint without additional bound proliferation;
(3) `pharos-types` is serde-free per `D-api-dto-serde`, so JSON must be built in
`pharos-api` anyway. The `LcApiSerializer` trait (analogous to `BlockApiSerializer`)
is implemented for each concrete altair/capella preset alias in `dto/light_client.rs`.
The STF mutual-exclusion invariant (exactly one of altair-CF or capella-CF is
written per root per `pharos-stf/src/altair/light_client_dispatch.rs`) is exploited
by `NodeChainState`: capella is probed first; if absent, the altair CF is tried.

### D-api-lc-trait-defaults — default bodies on ChainStateApi, no mock edits

**Status**: Accepted. **Date**: 2026-06-02.

The four new LC methods on `ChainStateApi<E>` (`light_client_bootstrap`,
`light_client_updates`, `light_client_finality_update`,
`light_client_optimistic_update`) carry default bodies that return `Ok(None)` /
`Ok(vec![])`. This deliberately deviates from the normal Rust style of requiring
every impl to provide a body, for a documented reason: the five existing mock
`ChainStateApi` impls in `pharos-api/tests/` must not be edited (they are large
and correct). Default bodies serve that goal without loss of correctness —
`NodeChainState` overrides all four with real storage reads. Any future mock that
DOES need LC data simply overrides the relevant method.

### D-api-lc-fork-tag-by-attested-slot — fork variant derived from the attested header slot

**Status**: Accepted. **Date**: 2026-06-02.

The `version` field and `Eth-Consensus-Version` header in light-client REST
responses are derived from the LC object's attested-header slot, not from the
current chain head. Per the beacon-APIs spec, the version tags the CONTENT of the
object, not the node's current fork. Implementation: `fork_variant_at_slot(cfg,
attested_slot, slots_per_epoch)` in `pharos-api::fork_tag`, returning the highest
fork activated at `epoch = attested_slot / slots_per_epoch`. The `slots_per_epoch`
is derived at runtime from `RuntimeConfig::update_timeout /
epochs_per_sync_committee_period` (both fields exist) rather than via a new
`slots_per_epoch` field or making `make_lc_envelope` generic over `E`, keeping the
helper fork-agnostic. For `get_updates` SSZ framing, `fork_version_for_variant`
maps the envelope's variant to the right fork-version bytes from `RuntimeConfig`.

### D-api-lc-gvr-from-head-state — genesis_validators_root sourced from chain.genesis()

**Status**: Accepted. **Date**: 2026-06-02.

The `genesis_validators_root` (gvr) used for `compute_fork_digest` in SSZ
`get_updates` framing is read from `chain.genesis()` — which in `NodeChainState`
falls back to the head state's `genesis_validators_root()` field, NOT from
`runtime_cfg.genesis_validators_root`. The `runtime_cfg` field stays zeroed on
checkpoint-sync nodes until the first head state is loaded. Using the live head
state value ensures the fork digest is correct for Ethereum mainnet and real
devnets. This matches the same reasoning as the `get_genesis` endpoint fix
(commit `4d1a2b3` in M7). Mock tests use a fixed non-zero `TEST_GVR` constant
to exercise the digest computation path.

## M9-Validator decisions

In-house validator client (`pharos-vc` binary) + the beacon-node production
surface it drives: operation pools, live Engine-API V2 block production, CL
block/attestation assembly via STF reuse, validator/beacon production REST
endpoints, EIP-2335 keystores, rusqlite slashing protection, duty scheduling,
doppelganger detection. Plan: `docs/m9-validator-plan.md`. Live
bellatrix→capella devnet acceptance (a reference CL client + ethrex v13) is the
gate; see `D-vc-proposer-slot-alignment` for the one live-only correctness bug
the devnet surfaced.

### D-vc-separate-process — VC↔BN topology is separate-process HTTP

**Status**: Accepted. **Date**: 2026-06-06. (OQ1 resolved.)

`pharos-vc` is a standalone binary that talks to the beacon node only over the
Beacon REST API (`--beacon-node <url>`, failover-ordered list). No in-process
coupling, no shared state. Matches the standard CL deployment model and lets the
VC run against any spec-compliant BN; the BN's 503 contract
(`D-503-on-optimistic-or-syncing`) is the sole liveness signal.

### D-op-pools-in-memory — in-memory operation pools, aggregate-on-insert

**Status**: Accepted. **Date**: 2026-06-06.

`OperationPools<E>` (`pharos-node/src/op_pools.rs`) holds attestations, proposer/
attester slashings, voluntary exits, BLS-to-exec changes, and sync-committee
contributions in memory, fed from the gossip-accept path. Attestations merge
on insert only when `AttestationData` matches and aggregation bits are disjoint
(no double-count). Pools are volatile (rebuilt from gossip after restart); no
persistence — block production drains them at assembly time.

### D-process-block-verify-flag — thread `verify_signatures: bool` through process_block

**Status**: Accepted. **Date**: 2026-06-06.

The per-fork `process_block` takes a `verify_signatures: bool`. Block production
runs the STF with signature verification OFF (the proposer's own sigs aren't
attached yet) to compute the post-state and `state_root`; the node re-runs with
verification ON when the signed block is imported. One STF, two modes — no
divergent "production" code path that could drift from consensus.

### D-produce-empty-then-fill-stf — build block by STF reuse, not a bespoke assembler

**Status**: Accepted. **Date**: 2026-06-06.

`produce_block` assembles an empty block shell, fills it from the operation pools
+ the live execution payload, then runs the real STF to obtain the `state_root`.
No parallel block-builder logic: the same `process_block` that validates on
import produces on the way out, so a produced block re-imports VALID by
construction (verified by `produce_block_signed_*_validated_capella`).

### D-keystore-eip2335-in-house — in-house EIP-2335 keystore decryption

**Status**: Accepted. **Date**: 2026-06-06.

Keystore decrypt is hand-rolled in `pharos-validator/src/keystore.rs`: parse
`crypto.kdf` (scrypt or pbkdf2), derive the key, AES-128-CTR decrypt, verify the
SHA-256 checksum before use. Deps are primitives only (`aes`, `scrypt`,
`pbkdf2`, `sha2`) — no wallet/keystore crate. Consistent with the project's
"own everything with a conformance vector" principle.

### D-slashing-sqlite-separate-file — slashing protection in a separate rusqlite file

**Status**: Accepted. **Date**: 2026-06-06.

Slashing protection is a `rusqlite` DB in its own file under the VC data dir
(distinct from the BN's RocksDB chain store, per the locked storage decision).
Implements the EIP-3076 interchange import/export and surround/double-vote
checks; validated by the vendored `slashing-protection-interchange-tests`
(`tests/interchange_conformance.rs`, `scripts/fetch-interchange-tests.sh`).

### D-commit-before-sign — record in the slashing DB before signing

**Status**: Accepted. **Date**: 2026-06-06.

The VC writes the proposal/attestation record to the slashing DB and only signs
if that write succeeds and passes the slashing check. The DB is the final
authority on "may I sign this", so a crash between commit and broadcast can never
produce an un-recorded signature — the safe direction across restarts and reorgs.

### D-doppelganger-bn-liveness-endpoint — doppelganger via the BN liveness endpoint

**Status**: Accepted. **Date**: 2026-06-06. (OQ4 resolved.)

Doppelganger protection polls the BN's `POST /eth/v1/validator/liveness/{epoch}`
(added in Phase 5) rather than sniffing gossip directly — the standard mechanism
for a separate-process VC. `--doppelganger-protection` (default on) holds off
signing for the first 2 complete epochs and aborts FATALLY if any local
validator appears live elsewhere. The devnet runs it OFF (single signer per key,
disjoint partition).

### D-503-on-optimistic-or-syncing — production endpoints 503 when optimistic or syncing

**Status**: Accepted. **Date**: 2026-06-06.

`ChainStateApi::is_optimistic_node` / syncing status gate the validator
production endpoints: they MUST return HTTP 503 when the node is optimistic or
syncing (`pharos-api/src/state.rs`). The VC treats 503 as "do not sign". This is
the write-side counterpart to M8's read gate and the mechanism that makes a
checkpoint-synced VC safe against a still-syncing EL.

### D-register-validator-accept-and-store — register_validator stores, no relay

**Status**: Accepted. **Date**: 2026-06-06. (OQ5 resolved.)

`POST /eth/v1/validator/register_validator` accepts and stores the fee recipient
+ gas limit in an `Arc<RwLock<HashMap<BLSPubkey, ExecutionAddress>>>` in
`NodeChainState`; there is no builder/relay forwarding (no MEV-Boost yet). Fee
recipient flows into `prepare_execution_payload`.

### D-eth1-data-default / D-no-deposit-source — no eth1 following, zero new deposits

**Status**: Accepted. **Date**: 2026-06-06. (OQ6 resolved; deferred to M11.)

Pharos does not follow the eth1 deposit contract. Produced blocks carry a
default `eth1_data` (vote for the current value) and zero new deposits — valid on
a genesis-funded devnet where the full validator set exists at genesis. Real
deposit following is an M11 productionization item.

### D-syncnets-enr-on-subscription — syncnets ENR updated on sync-committee subscription

**Status**: Accepted. **Date**: 2026-06-06.

When the VC subscribes to sync-committee subnets, the BN updates the `syncnets`
bitfield in its ENR (reusing the M3b `update_enr_eth2` path) so peers discover
the node on the right subnets. Mirrors the existing attnets/subnet-rotation
machinery rather than introducing a parallel ENR mutation path.

### D-vc-proposer-slot-alignment — slot-align the VC loop so proposals fire at t≈0

**Status**: Accepted. **Date**: 2026-06-06. (Live-only correctness bug; the M9
analogue of the M5-follow / M6-Capella devnet bugs.)

`run_vc_loop` originally used a free-running `tokio::time::interval(slot)`, which
ticks relative to VC startup and therefore carries a fixed phase offset against
true slot boundaries. The proposer path fired at that arbitrary offset (~4.3s
into the slot on the failing run) plus health-check RTTs, pushing block
publication past the reference CL's t=1/3 attestation cutoff. Attesters then voted the
parent, the pharos block accrued `head_weight: 0`, and the reference CL's
proposer-boost re-org dropped it one slot later — the block was spec-valid and
gossip-delivered, but never stuck. Fix: at the top of the loop compute the next
slot boundary and `sleep_until_into_slot(start, 0)`, dispatching the proposer at
t≈0; the attester/aggregate paths already self-aligned via `sleep_until_into_slot`
and are unchanged. Verified live (commit `e77691c`): all 9 pharos-vc proposals —
including capella slots 35/47/53/61 — were received by the reference CL over gossip and
kept canonical with 0 re-orgs over 2+ epochs; every proposal fired 2–5 ms into
its slot.

### D-genesis-cold-start-phase0-only — `--genesis-state-path` decodes only a phase0 genesis (deferred)

**Status**: Accepted (known limitation). **Date**: 2026-06-06.

The cold-start path (`pharos-node/src/main.rs:363`) hardcodes
`Phase0MainnetBeaconState::from_ssz_bytes`, so `--genesis-state-path` only works
for a phase0 genesis blob. A post-phase0 genesis (e.g. the bellatrix-genesis
devnet) fails with `extra bytes: N remaining`. Live nodes use
`--checkpoint-sync-url` instead, whose anchor decode IS fork-aware (via the
`Eth-Consensus-Version` header); at epoch 0 the reference CL serves the genesis state
as the finalized checkpoint, so checkpoint-sync covers the genesis case.
Fork-aware cold-start decode (dispatch on the runtime-config fork schedule) is
deferred to M11.

## M10-DA decisions

Data-availability substrate for Deneb: KZG crate, blob SSZ types, blob gossip
and req-resp, blob storage, and the `is_data_available` import gate. This is the
DA SUBSTRATE only; the full Deneb STF, Engine API V3, and EIP-7044/7045/7514
are the M10-Deneb follow-on. Plan: `docs/m10-da-plan.md`. Live Deneb devnet
acceptance (a reference CL client + ethrex, `DENEB_FORK_EPOCH=1`) is deferred to M10-Deneb.

### D-kzg-crate — KZG lives in its own `pharos-kzg` crate over `c-kzg`

**Status**: Accepted. **Date**: 2026-06-07.

`pharos-kzg` is a thin, focused wrapper over `c_kzg::KzgSettings` exposing
`KzgVerifier` (verify_blob_kzg_proof_batch, verify_blob_kzg_proof,
blob_to_kzg_commitment) and `KzgError`. Separating it from `pharos-engine` (which
handles JSON-RPC) avoids a circular-dep risk (the node needs KZG both in the
storage gate and in gossip validation, neither of which touches the Engine API).
Separating it from `pharos-types` keeps the blob SSZ types dep-free from
cryptographic primitives, matching the crate philosophy. The crate is validated
directly by the KZG conformance runner (`deneb/kzg/blob_to_kzg_commitment`,
`verify_blob_kzg_proof`, `verify_blob_kzg_proof_batch` — all three sub-categories
pass with `fail=0`).

### D-da-checker-trait — fork-generic `trait DataAvailabilityChecker<E>`

**Status**: Accepted. **Date**: 2026-06-07. (W6 resolved.)

`DataAvailabilityChecker<E>` takes `(block_root: Root, kzg_commitments: &[KZGCommitment])`
and returns `DataAvailabilityVerdict { Available, NotAvailable, Irrelevant }`.
The caller (import path) extracts commitments from the Deneb block body once; the
trait impl does no fork-dispatch internally. This signature is the Fulu/PeerDAS
seam: the Fulu impl can replace `BlobAvailabilityChecker` with a PeerDAS
`DataColumnAvailabilityChecker` without touching the import path. Placed in
`pharos-node/src/data_availability.rs` (needs store + KZG; lives with the node,
not in `pharos-fork-choice`). Pre-Deneb blocks return `Irrelevant`; the import
path passes through immediately.

### D-blob-hold-reuses-reinject — DA-pending blocks reuse `reinject_tx`

**Status**: Accepted. **Date**: 2026-06-07. (W10 partially; see below.)

When `import_block` returns `DataNotAvailable`, the ingestion loop parks the block
in `BlobAwaitingBlocks` (keyed by `block_root`). When the blob ingestion loop
(`run_blob_ingestion_loop`) completes the set for that root, it re-injects the
block via the existing `reinject_tx` channel (the same `ReinjectBlock` type used
for future-block hold). No new channel or delivery mechanism is introduced.
`MAX_BLOB_AWAIT_HOLD` (a `Duration`) provides a time-based eviction (one
`tokio::spawn` timer per parked entry) to bound memory. Dedup on re-arrival
(second sidecar for the same `(root, index)` is discarded once the set is
already complete). Mirrors the `hold_future_block` pattern (M5-follow).

### D-blob-store-cf-keyed-by-root-index — blob-sidecars CF keyed `block_root || index_be`

**Status**: Accepted. **Date**: 2026-06-07.

`CF_BLOB_SIDECARS` (`"blob-sidecars"`) stores SSZ-encoded `BlobSidecar` values
under a 40-byte key: `block_root` (32 B) `||` blob index (8 B big-endian u64).
This layout enables (a) point-read for a single `(root, index)` pair (O(1));
(b) prefix-scan over all blobs for a root (used by `get_blob_sidecars_by_root`
and req-resp `BlobSidecarsByRoot`); (c) `prune_blob_sidecars_below_slot`, which
scans the CF, SSZ-decodes each sidecar to read its
`signed_block_header.message.slot` (a full decode rather than a fragile byte
offset, since pruning is a cold head-watch path), and deletes keys below the
threshold atomically in a `WriteBatch`. The `slot_to_block_root` index is
never pruned (cold regen and `BlobSidecarsByRange` both need it), matching the
M-Storage invariant.

### D-sidecar-substrate-generic-naming — substrate types use spec-exact names without fork prefix

**Status**: Accepted. **Date**: 2026-06-07.

`BlobSidecar`, `BlobIdentifier`, `BlobSidecarsByRangeRequest`, `BlobSidecarsByRootRequest`
are placed in `pharos-types/src/deneb/` and named exactly as in the spec (no
`DenebBlobSidecar` prefix). This matches the established pattern for capella
(`WithdrawalCredential`, `BlsToExecutionChange`) — fork-scoped module, spec-exact
name. The `deneb::` module prefix provides the needed disambiguation at use sites.
The DA substrate code (storage, gossip, req-resp) is written once and is
forward-compatible: the same `BlobSidecar` type is used by the M10-Deneb STF.

### D-kzg-trusted-setup-source — embedded setup via `c_kzg::ethereum_kzg_settings`

**Status**: Accepted. **Date**: 2026-06-07. (R2 resolved.)

`KzgVerifier::mainnet()` calls `c_kzg::ethereum_kzg_settings(precompute=0)`,
which returns the canonical Ethereum mainnet trusted setup embedded in the
`c-kzg` crate itself (same source as Prysm/Teku and other CL clients). `precompute=0`
disables precomputed tables, which are not needed for verification workloads
(proving is not in scope). For non-mainnet setups (devnets, tests),
`KzgVerifier::from_trusted_setup_str` and `from_trusted_setup_file` accept the
standard format produced by `gen_testnet.sh`. This avoids vendoring an
18-MB trusted-setup JSON in the pharos repository.

### D-da-block-not-in-forkchoice-until-available — DA gate runs before `state_transition`

**Status**: Accepted. **Date**: 2026-06-07. (RI-1 / RI-2 resolved.)

Per `fork-choice.md on_block`: `is_data_available` must precede `state_transition`.
`import_block` calls `da_checker.is_data_available` inside `spawn_blocking` BEFORE
the `state_transition` call, so a `DataNotAvailable` result causes an early return
with `ImportError::DataNotAvailable` before any fork-choice write has occurred.
The block is thus never in the fork-choice store while its blobs are missing —
the invariant is structural, not guarded by a flag. This satisfies the spec's
"a block MUST be considered unavailable until all its blobs are available" rule
and prevents an optimistic-import attack where a proposer withholds blobs to split
the network.

### D-schema-v4-migration — schema 3 → 4 adds `blob-sidecars` CF; resync on mismatch

**Status**: Accepted. **Date**: 2026-06-07. (R7 resolved.)

`SCHEMA_VERSION` increments from 3 to 4. Opening a v3 database returns
`StorageError::SchemaMismatch` immediately, prompting a resync (same policy as
the v2 → v3 bump in M-Storage). No in-place migration: blob sidecars from before
M10-DA were never stored (the column family did not exist), so there is no data to
migrate. The v4 CF set is the v3 set (20 CFs) plus `CF_BLOB_SIDECARS`, registered
in `all_cfs()` and opened in `RocksStore::open`.

---

## M10-Deneb decisions

Full Deneb STF, Engine API V3, Deneb block+sidecar production, full conformance,
and live devnet acceptance. Built on the M10-DA substrate (KZG crate, blob types,
`Fork::Deneb` plumbing, blob gossip/req-resp/storage, DA gate). Plan:
`docs/m10-deneb-plan.md`.

### D-deneb-stf-delegates-to-capella — Deneb STF delegates unchanged logic to Capella

**Status**: Accepted.

Deneb adds three consensus-layer EIP deltas on top of Capella: EIP-4844
(`process_execution_payload` with versioned hashes), EIP-7044 (fixed voluntary-exit
domain), EIP-7045 (widened attestation inclusion range), and EIP-7514 (activation
churn cap). Every other STF step, epoch sub-routine, and block-processing helper
is identical to Capella. The implementation delegates to Capella via state projection
(`deneb_state_to_capella`) for all unchanged paths, overriding only the four EIP
delta operations. This mirrors how Capella delegates to Bellatrix/Altair. The
`DenebDispatch`, `DenebJaFDispatch`, `DenebProcessSlotsDispatch`, and
`DenebUpgradeDispatch` blanket-impl traits in `pharos-stf/src/lib.rs` wire the
fork-dispatch entry points.

### D-eip7044-voluntary-exit-fixed-domain — voluntary exits use capella_fork_version regardless of state fork

**Status**: Accepted.

EIP-7044 (`specs/deneb/beacon-chain.md:510-513`): starting at Deneb, voluntary
exits always sign with `compute_domain(DOMAIN_VOLUNTARY_EXIT, CAPELLA_FORK_VERSION,
genesis_validators_root)`, ignoring the state's current fork version. This makes
exits signed in the Capella era valid forever in subsequent forks. The Deneb
`process_voluntary_exit` accepts `runtime_cfg: &RuntimeConfig` and reads
`runtime_cfg.capella_fork_version` to compute the domain. All callers through
`process_operations_deneb` and `process_block` (deneb) thread `runtime_cfg`.

### D-eip7045-attestation-range — deneb drops the upper slot bound for attestations

**Status**: Accepted.

EIP-7045 (`specs/deneb/beacon-chain.md`): the `state.slot <= data.slot +
SLOTS_PER_EPOCH` upper-bound check is removed from `process_attestation` in Deneb.
Only the lower bound `data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot`
remains. In practice this doubles the attestation inclusion window from one epoch
to two, allowing attestations to be included later without being penalised.

EIP-7045 is in fact THREE surfaces, not two (a Phase-2 conformance failure caught
the missing third): (1) the STF upper-bound removal above; (2) the gossip window
(`D-eip7045-gossip-window-node-epoch`); and (3) `get_attestation_participation_flag_indices`
also changes — the `TIMELY_TARGET_FLAG_INDEX` condition drops its
`inclusion_delay <= SLOTS_PER_EPOCH` gate and becomes unconditional on
`is_matching_target` (`specs/deneb/beacon-chain.md`). Deneb reuses the shared Altair
helper via a new `eip7045_target_flag: bool` parameter (deneb passes `true`;
altair/upgrade pass `false`, behavior-preserving). Without (3), attestations included
at the new maximum distance silently miss the target reward — surfaced as the
`at_max_inclusion_slot` / `new_range` conformance failures. All other attestation
logic delegates to the Altair implementation via projection.

### D-eip7045-gossip-window-node-epoch — gossip-level EIP-7045 window gated on wall epoch

**Status**: Accepted.

Per OQ1 resolution: the gossip validator in `host_impl.rs` widens the attestation
`data.slot` acceptance window to the previous-or-current epoch when the node's
wall epoch is at or after `DENEB_FORK_EPOCH`. This is Phase 4 work (`4.1`); the
STF-level change (task 1.6) is independent and applies in the Deneb STF path
regardless of fork epoch. The two surfaces must agree: the gossip window controls
which messages are admitted for STF processing, and the STF controls what the
`process_attestation` rule rejects on import.

### D-eip7514-activation-churn — deneb caps validator activation queue via MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT

**Status**: Accepted.

EIP-7514 (`specs/deneb/beacon-chain.md`): `process_registry_updates` uses
`get_validator_activation_churn_limit = min(MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT,
get_validator_churn_limit(state))` for the activation queue instead of the
unbounded `get_validator_churn_limit`. `MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT` is
8 on mainnet and 4 on minimal (from `configs/{mainnet,minimal}.yaml`). This is a
runtime constant stored in `RuntimeConfig.max_per_epoch_activation_churn_limit`
and threaded through `process_epoch_deneb` into `process_registry_updates_deneb`.

### D-engine-v3-newpayload-wire — Engine V3 newPayloadV3 carries versioned hashes and parent beacon block root

**Status**: Accepted.

`engine_newPayloadV3` (cancun.md) takes three parameters:
`(executionPayload: ExecutionPayloadV3, expectedBlobVersionedHashes: List[Hash32],
parentBeaconBlockRoot: DATA)`. The JSON field name is `expectedBlobVersionedHashes`
(camelCase). `ExecutionPayloadV3` extends V2 with `blobGasUsed` and `excessBlobGas`.
The `NewPayloadWire::V3` variant in `pharos-engine/src/client.rs` carries these
three fields. The version is selected for Deneb heads in the engine driver. Phase 3
work.

### D-versioned-hash-in-kzg-crate — kzg_commitment_to_versioned_hash lives in pharos-kzg

**Status**: Accepted.

The helper `kzg_commitment_to_versioned_hash(commitment: &[u8;48]) -> [u8;32]`
(EIP-4844: SHA-256 of the 48-byte commitment, overwrite byte[0] = `0x01`) is
implemented in `pharos-kzg/src/lib.rs`. It is the only place in the codebase that
performs this transformation, and it is tightly coupled to KZG operations. The
`pharos-stf` crate depends on `pharos-kzg` (already does for blob inclusion proof
verification), so `process_execution_payload` in `deneb/operations/execution_payload.rs`
can call it directly. `sha2` is added as a dependency of `pharos-kzg` for the
SHA-256 computation.

### D-engine-v3-version-selection — V3 methods selected for Deneb fork heads

**Status**: Accepted.

The engine driver in `pharos-node/src/engine_driver.rs` selects `engine_newPayloadV3`,
`engine_forkchoiceUpdatedV3`, and `engine_getPayloadV3` for Deneb, falling back to V2
for Capella, V1 for Bellatrix/Altair/Phase0. FCU version is chosen by an EXHAUSTIVE
`match` on the head STATE's `fork_variant()` (`BeaconStateView`) — not an
`E::unwrap_<fork>_block().is_some()` if-let chain (the head block view exposes no fork
discriminant, and unwrap-chains silently mis-route at the next fork per
`D-runtime-cfg-threading-live-loops`/the fork-dispatch convention). newPayload version
follows the `NewPayloadWire` enum variant directly. The `GetPayloadVersion`,
`NewPayloadVersion`, and `ForkchoiceUpdatedVersion` enums in
`pharos-engine/src/client.rs` each gain a `V3` variant; `NewPayloadWire` is boxed in
`EngineRequest::NewPayload` to keep the actor-message enum small
(`clippy::large_enum_variant`, since `ExecutionPayloadV3` is large). Phase 3 work.

### D-getpayloadv3-blobs-bundle — getPayloadV3 returns BlobsBundleV1 alongside the payload

**Status**: Accepted.

`engine_getPayloadV3` (cancun.md) returns `GetPayloadV3Response { executionPayload,
blockValue, blobsBundle: BlobsBundleV1, shouldOverrideBuilder }`. `BlobsBundleV1`
contains parallel `commitments`, `proofs`, and `blobs` lists. The node extracts
`commitments` to populate `block.body.blob_kzg_commitments` and stores the full
bundle to produce `BlobSidecar`s for publishing. Phase 3/4 work.

### D-getblobsv1-da-fallback — getBlobsV1 is the DA-gate fallback when gossip sidecars are missing

**Status**: Accepted.

Per OQ2 resolution: when the DA checker returns `NotAvailable` (missing sidecars),
the import path calls `engine_getBlobsV1(versioned_hashes)` on the local EL before
parking the block to wait for gossip sidecars. If the EL returns all blobs (no
null entries), the blobs are converted to `BlobSidecar`s, stored, and the DA check
is re-run immediately. This avoids gossip latency on self-produced blocks and on
reorgs where the EL already has the blobs in its pool. Phase 3 work (`3.7`).

### D-deneb-block-production-sidecars — BlobSidecars built from BlobsBundleV1 at proposal time

**Status**: Accepted.

When proposing a Deneb block, the VC triggers `prepare_execution_payload_v3` which
calls `engine_getPayloadV3` to obtain `(ExecutionPayloadV3, BlobsBundleV1,
block_value)`. The node assembles the `SignedBeaconBlock`, then builds one
`BlobSidecar` per blob in the bundle: `blob`, `commitment`, `proof` from the bundle;
`signed_block_header` from the signed block; `kzg_commitment_inclusion_proof` via the
Merkle proof machinery. The plan text's gindex (`8192 + index`) was WRONG — the
correct per-element generalized index is the positional base `11 * MAX_BLOB_COMMITMENTS_PER_BLOCK
= 11 * 8192 = 90112` plus `index`, at depth 17 (fixture-verified against
`deneb/merkle_proof`: `leaf_index 221184` for blob 0; `221184 - 2^17 = 90112`).
`build_blob_sidecar_inclusion_proof` reuses the exact constant from the M10-DA
`verify_blob_sidecar_inclusion_proof`, and a round-trip unit test
(`blob_sidecar_inclusion_proof_round_trip`) asserts a produced proof verifies. Bundle
lengths `blobs == commitments == proofs` are enforced (commitment hex decode is
fail-fast, not silent-drop, to keep the 1:1 correspondence). Sidecars are published on
the blob-sidecar gossip topics alongside the block. The cached sidecars' zero
`signed_block_header.signature` is patched with the real VC signature before publish
(else gossip peers `[REJECT]` on the proposer-signature rule). Phase 4 work.

### D-deneb-lc-header — Deneb light-client header uses STF-verified block.state_root

**Status**: Accepted.

Per the M4c lesson (`D-bellatrix-lc-header-uses-state-root`): the Deneb
`LightClientHeader` beacon field is constructed using `block.state_root` (the
STF-verified value written by the proposer) rather than a recomputed
`state.tree_hash_root()` on a projected state. A projected Deneb→Capella state
would omit `blob_gas_used` and `excess_blob_gas` from
`latest_execution_payload_header`, producing a different root than what consumers
verify against. The `EXECUTION_PAYLOAD_GINDEX = 25`, `depth = 4` constants for the
execution branch proof are the same as Capella (the body structure is identical at
the field-9 position). Deneb LC types (`LightClientHeader`,
`LightClientBootstrap`/`Update`/`FinalityUpdate`/`OptimisticUpdate`) mirror the
Capella types but use `deneb::ExecutionPayloadHeader` (adds `blob_gas_used`,
`excess_blob_gas`).

### D-deneb-execution-engine-trait-arm — notify_new_payload_deneb is a defaulted method on ExecutionEngine

**Status**: Accepted.

`ExecutionEngine` gains a defaulted `notify_new_payload_deneb` method that accepts
the Deneb `ExecutionPayload` plus `versioned_hashes: &[[u8;32]]` and
`parent_beacon_block_root: Root`. The default implementation strips the Deneb-only
fields and forwards to `notify_new_payload_capella` (which in turn strips withdrawals
for V1). This keeps `NullExecutionEngine` and `FixedExecutionEngine` working for
conformance tests without changes. The production `ExecutionEngineHandle` in
`pharos-node` overrides this to call `engine_newPayloadV3` (Phase 3). The
`parent_beacon_block_root` source is `state.latest_block_header.parent_root`, read
before any header mutation in `process_execution_payload` (per plan 1.4).

### D-deneb-forkchoice-conformance-da-gate — deneb fork_choice runner exercises is_data_available

**Status**: Accepted.

The `deneb/fork_choice` spec fixtures carry `blobs`/`proofs` on block steps with
`valid: true/false` (e.g. `simple_blob_data`, `invalid_data_unavailable`,
`invalid_incorrect_proof`, `invalid_wrong_{blobs,proofs}_length`). Per
`specs/deneb/fork-choice.md`, the deneb `on_block` test handler asserts
`is_data_available` → `verify_blob_kzg_proof_batch(blobs, blob_kzg_commitments,
proofs)`; absent step fields mean empty lists
(`tests/formats/fork_choice/README.md`). The conformance fork_choice runner therefore
parses the block step's `blobs`/`proofs`, runs the DA check via
`pharos_kzg::KzgVerifier::verify_blob_kzg_proof_batch` (a length mismatch surfaces as
`Err`, i.e. not available), and folds the verdict into the block's `valid` expectation
before `on_block`. A capella-clone runner that ignored these steps would import the
`invalid_*` blocks and fail the head checks. The pharos fork-choice `on_block` itself
does NOT run DA (DA lives at the node import layer per the M10-DA `D-da-block-not-in-forkchoice-until-available`);
the conformance runner reproduces the spec test harness's `retrieve_blobs_and_proofs`
mock instead.

Two conformance-runner robustness notes recorded here for completeness: (a) the engine
V3 conformance examples' upstream payload-id `0x0000000038fa5dd` is QUANTITY-trimmed
(15 hex chars, malformed for the 8-byte `PayloadIdV1` DATA type), so
`params_to_payload_id` left-pads to 8 bytes and getPayload\* params are compared
semantically rather than byte-exact; (b) deneb withdrawals reuse the single capella
`get_expected_withdrawals` via a `deneb_state_to_capella` projection rather than a
duplicated sweep, to prevent drift.

## M-Conf-Perf decisions

### D-flat-conformance-workpool — single-level flat rayon pool for conformance

**Status**: Accepted. **Date**: 2026-06-13. **Supersedes**: `D-conformance-parallelism-dropped`.

`pharos_conformance::run` was a sequential ladder of ~107 `if filter.matches { run_* }`
blocks, each category internally `into_par_iter`-ing its own cases — a hard barrier
between categories left cores idle on the tail of small categories. The flip: every
category exposes `enumerate_*(root, fork, preset, row_ordinal) -> Vec<CaseTask>`; `run`
collects ALL of them into one `Vec`, runs ONE top-level `into_par_iter`, and aggregates
via `task::fold` keyed by `(row_ordinal, case_ordinal)`. Exactly ONE `into_par_iter` in
the crate; zero nesting (the trap that killed the earlier attempt). Byte-identical output
(full walk 3:53 → 2:31, CPU 617% → 905%). Not full 12-thread saturation: a few heavy
single cases dominate the tail and the directory-walk/enumerate step is still sequential.

### D-conformance-descriptor-table — per-fork `(sub, ApplyFn)` tables replace duplicated boilerplate

**Status**: Accepted. **Date**: 2026-06-13.

`operations.rs` was 5,806 lines: ~50 near-identical `run_*_case` fns + ~70
walk+`into_par_iter`+tally blocks, one per fork×preset×sub-op. Replaced with a generic
`apply_op` (load pre/post → run `process_*` → compare htr / expect-Err) + `enumerate_op`
(walk + box per-case closures) + per-fork `<fork>_op_table` of `(sub_name, ApplyFn)`
entries. Bespoke state-projection subs (block_header/sync_aggregate/execution_payload/
withdrawals, which project to altair/capella) stay as explicit table closures — the
deletion is the wrapper, not the projection body. Net: the duplicated boilerplate is
gone; adding a fork is a small table. Each fork converted in its own phase, byte-identical
per `--filter <fork>/operations`.

### D-apply-op-no-ethspec-bound — generics strategy that keeps the tables compilable

**Status**: Accepted. **Date**: 2026-06-13.

`apply_op<S: Encode, Op: Decode>` carries NO `EthSpec` bound and a CONCRETE error type
(`pharos_stf::StateTransitionError`, not a generic). All the gnarly per-fork associated-type
`where`-clauses live on the per-fork table-builder fn (one place), exactly as the old
`run_<fork>_op_preset` helpers did. This is what makes the generic operations code tractable.

### D-case-ordinal-byte-identity — deterministic output under the parallel pool

**Status**: Accepted. **Date**: 2026-06-13.

Parallel completion order must not leak into output. `enumerate_*` assigns `case_ordinal`
from the sorted `walk_category`/`read_dir_sorted` position, threaded across sub-sweeps in
the SAME order the old dispatcher merged them; `task::fold` sorts outcomes by
`(row_ordinal, case_ordinal)` before emitting rows + failures + footnotes. `rows::row_table`
is the single source of row order (107 rows, in `run()` emission order) and footnotes (the
`phase0/fork_choice` `[^1]`). Guarded by per-fork filtered byte-diffs, 30 `enumerate_*`
parity unit tests, and the full-walk byte-diff at the flip.

### D-conformance-bail-run-all — `--bail` no longer stops early

**Status**: Accepted. **Date**: 2026-06-13.

Under the single flat pool, rayon cannot cleanly short-circuit mid-`par_iter` while keeping
deterministic output. `--bail` now runs all cases and exits non-zero if any failed (the
exit-code contract `main.rs` relies on is preserved); the "stop after first failing category"
behavior is dropped. For fast-fail feedback, use `--filter`.

## M12-Electra decisions

Full Electra (Pectra) consensus-layer fork. New `Fork::Electra` arm across all crates,
EIP-7549 (attestation reshape), EIP-7251 (MaxEB + consolidations), EIP-6110 (deposit
requests), EIP-7002 (withdrawal requests), EIP-7685 (execution requests list), Engine API
V4. Plan: `docs/m12-electra-plan.md`.

### D-electra-stf-delegates-to-deneb — Electra STF delegates unchanged logic to Deneb

**Status**: Accepted.

Electra is a Deneb sibling in the same way Deneb is a Capella sibling. Only the two
reshaped sub-surfaces (EIP-7549 attestation, EIP-7251 epoch processing) require
electra-native implementations; every other step delegates to Deneb via state projection
(`electra_state_to_deneb` / `update_electra_from_deneb`) in `crates/pharos-stf/src/electra/helpers.rs`.
The `ElectraDispatch`, `ElectraJaFDispatch`, `ElectraProcessSlotsDispatch`, and
`ElectraUpgradeDispatch` blanket-impl traits in `crates/pharos-stf/src/lib.rs` wire the
fork-dispatch entry points. Decode-time projection to the Deneb shape was considered and
rejected because the EIP-7549 `Attestation` has no phase0/Deneb representation (multi-committee
aggregation cannot be projected); native electra types are required at the import boundary.

### D-eip7549-attestation-reshape — committee_bits replaces committee_index in Attestation

**Status**: Accepted.

EIP-7549 removes `committee_index` from the `Attestation` container and replaces it with
`committee_bits: Bitvector[MAX_COMMITTEES_PER_SLOT]`, while `aggregation_bits` is widened
to `Bitlist[MAX_AGGREGATION_BITS]` (`MAX_COMMITTEES_PER_SLOT * MAX_VALIDATORS_PER_COMMITTEE`).
This breaks any projection to phase0 `Attestation`. The electra `Attestation<MAX_AGGREGATION_BITS, MAX_COMMITTEES_PER_SLOT>` is a distinct Rust type parameterised by two preset-specific const generics
(mainnet 131072/64, minimal 8192/4; compound const generics are not yet stable so the
values are pre-computed literals). `get_attesting_indices_electra` iterates committees
in `committee_bits` order with a running `committee_offset`; `get_indexed_attestation_electra`
sorts the accumulated `attesting_indices`. Both live in `crates/pharos-stf/src/electra/helpers.rs`.

### D-eip7549-single-attestation-on-subnet — subnet gossip carries SingleAttestation

**Status**: Accepted.

Per EIP-7549 + `specs/electra/p2p-interface.md`: the `beacon_attestation_{subnet_id}` gossip
topic in the Electra epoch carries `SingleAttestation` (a new 4-field container: committee
index, attester index, data, signature), NOT the old `Attestation`. The `beacon_aggregate_and_proof`
topic continues to carry `SignedAggregateAndProof` but with the electra `Attestation` shape
(committee_bits + wide aggregation_bits). The `GossipValidator` trait
(`crates/pharos-network/src/host.rs`) gains `validate_single_attestation`, with a
`spawn_blocking` dispatch path in the network gossip handler
(`crates/pharos-network/src/gossip/mod.rs`). Conflating `SingleAttestation` and the
aggregate-topic `Attestation` would cause instant peer bans (wrong encoding on either topic).
The VC publishes `SingleAttestation` to its committee's subnet; the BN includes a per-committee
attester snapshot in the op-pool for block production.

### D-eip7549-onchain-aggregate — block body uses committee_bits Attestation, built per-committee

**Status**: Accepted.

Block production (`crates/pharos-node/src/block_production.rs`, `build_electra_on_chain_aggregates`)
converts per-committee op-pool entries into on-chain electra `Attestation`s via
`compute_on_chain_aggregate` (per `specs/electra/validator.md:124-147`): each resulting
attestation has exactly one `committee_bits` bit set, `aggregation_bits` wide over the
full `MAX_COMMITTEES_PER_SLOT * MAX_VALIDATORS_PER_COMMITTEE` domain, and carries all
attesters for that single committee. Cross-committee merging (same `data` across committees)
is deferred: the complexity is a performance concern (M-perf/M11), and correctness is
maintained by the single-committee path.

### D-eip7251-churn-as-balance — activation/exit churn measured in Gwei, not validator count

**Status**: Accepted.

EIP-7251 replaces the phase0 validator-count churn limit with a Gwei-denominated balance
churn (`get_balance_churn_limit_electra`, `get_activation_exit_churn_limit_electra`,
`get_consolidation_churn_limit_electra` in `crates/pharos-stf/src/electra/helpers.rs`).
Exit/consolidation churn balances accumulate across epochs via `exit_balance_to_consume`
and `consolidation_balance_to_consume` in the state. `compute_exit_epoch_and_update_churn_electra`
and `compute_consolidation_epoch_and_update_churn_electra` update these fields and return
the epoch at which the queued event will be processed. `initiate_validator_exit_electra` and
`process_consolidation_request` consume these helpers, replacing the phase0 epoch-scan queue.

### D-eip7251-pending-deposit-queue — deposits become a pending-queue with churn accounting

**Status**: Accepted.

EIP-7251 changes deposit processing from immediate balance credit to a pending-queue. The
electra `process_deposit` appends a `PendingDeposit` to `state.pending_deposits` instead of
crediting balance directly. `process_pending_deposits` (epoch processing,
`crates/pharos-stf/src/electra/epoch/pending_deposits.rs`) drains the queue per epoch under
four gates: eth1-bridge ordering, finalization, `MAX_PENDING_DEPOSITS_PER_EPOCH` cap, and
activation-exit churn. Exiting-validator deposits are postponed (reattached at END of queue);
`next_deposit_index` advances for applied, postponed, AND withdrawn-credit deposits
(ordering is load-bearing). `deposit_balance_to_consume` carries leftover churn forward
only when the churn break fires.

### D-eip7251-pending-consolidation-queue — consolidations queue with withdrawable-epoch drain

**Status**: Accepted.

EIP-7251 introduces `state.pending_consolidations: List[PendingConsolidation, 2^18]`.
`process_consolidation_request` appends to this list.
`process_pending_consolidations` (`crates/pharos-stf/src/electra/epoch/pending_consolidations.rs`)
drains consolidations whose source validator is withdrawable: it moves `min(source_balance,
source_effective_balance)` to the target and zeroes the source, stopping when a non-withdrawable
source is encountered (queue is ordered).

### D-eip7251-compounding-effective-balance — compounding validators use MaxEB as effective balance ceiling

**Status**: Accepted.

EIP-7251 introduces a `0x02` compounding withdrawal credential prefix.
`get_max_effective_balance` (`crates/pharos-stf/src/electra/helpers.rs`) returns
`MAX_EFFECTIVE_BALANCE_ELECTRA` (2048 ETH mainnet) for compounding validators, or
`MIN_ACTIVATION_BALANCE` (32 ETH) for the rest. `process_effective_balance_updates_electra`
(`crates/pharos-stf/src/electra/epoch/effective_balance_updates.rs`) uses this ceiling
for the hysteresis update, replacing the phase0/deneb `MAX_EFFECTIVE_BALANCE` constant.
`is_fully_withdrawable_validator_electra` / `is_partially_withdrawable_validator_electra`
similarly use `get_max_effective_balance` per validator.

### D-electra-compute-proposer-index — 16-bit random sample with MaxEB-weighted shuffle

**Status**: Accepted.

EIP-7251 changes `compute_proposer_index` to draw a 16-bit random sample per iteration
(`bytes_to_uint64(seed[i:i+2]) % (MAX_EFFECTIVE_BALANCE_ELECTRA / ETH_TO_GWEI)`)
instead of the phase0 8-bit sample. Without this fix every op that pays or validates the
block proposer (block_header, proposer_slashing, sync_aggregate, attestation proposer
reward) fails. This was the root cause of the P2 revert. Implemented as
`compute_proposer_index_electra` in `crates/pharos-stf/src/electra/helpers.rs`; unit-tested
against a fixture proposer index (expected value = 14, verified against the pyspec output).
`get_next_sync_committee_indices_electra` applies the same 16-bit pattern for sync committee
selection.

### D-eip6110-deposit-requests — deposit requests arrive via execution payload, append PendingDeposit

**Status**: Accepted.

EIP-6110 (`specs/electra/beacon-chain.md:1809-1824`): the execution payload now carries
`deposit_requests` (accessed via `ExecutionRequests.deposit_requests`). `process_deposit_request`
(`crates/pharos-stf/src/electra/operations/deposit_request.rs`) sets
`state.deposit_requests_start_index` on first receipt (initialises from
`UNSET_DEPOSIT_REQUESTS_START_INDEX = u64::MAX`), then appends a `PendingDeposit` with
`slot = state.slot`. The `process_operations` deposit-count assert is also modified to use
`min(eth1_deposit_count, deposit_requests_start_index)` so the old eth1-bridge path and the
new request path are mutually exclusive once the start index is set.

### D-eip7002-withdrawal-requests — EL-triggerable withdrawals via execution payload

**Status**: Accepted.

EIP-7002 (`specs/electra/beacon-chain.md:1735-1802`): `execution_requests.withdrawal_requests`
carries EL-originated withdrawal requests. `process_withdrawal_request`
(`crates/pharos-stf/src/electra/operations/withdrawal_request.rs`) distinguishes full-exit
requests (`FULL_EXIT_REQUEST_AMOUNT = 0`) from partial-withdrawal requests: full exits call
`initiate_validator_exit_electra`; partial requests append to `pending_partial_withdrawals`
under the `PENDING_PARTIAL_WITHDRAWALS_LIMIT` queue-full guard. Credential validation
(must have execution withdrawal credential) and source-address checks precede any mutation.

### D-eip7685-execution-requests-list — execution_requests lives in the block body, transmitted as Array of DATA

**Status**: Accepted.

EIP-7685 places `execution_requests: ExecutionRequests` in the `BeaconBlockBody` (NOT in
the `ExecutionPayload`; payload/header are byte-identical to Deneb). The Engine API transmits
requests as a separate `executionRequests: Array<DATA>` parameter on `newPayloadV4` and
as a field in `GetPayloadV4Response` — each element is a hex-encoded byte string (request
type byte + SSZ-serialised request data). `get_execution_requests_list`
(`crates/pharos-stf/src/electra/helpers.rs`) encodes: for each non-empty list in order
(deposit `0x00`, withdrawal `0x01`, consolidation `0x02`) prepend the type byte and SSZ-encode
the list. Empty lists are omitted (skip-empty rule). `ExecutionPayloadV3` is reused as the
payload wire type for V4.

### D-engine-v4-version-selection — V4 methods selected for Electra fork heads

**Status**: Accepted.

The engine driver in `crates/pharos-node/src/engine_driver.rs` and `block_ingestion.rs`
selects `engine_newPayloadV4`, `engine_forkchoiceUpdatedV3` (FCU version unchanged at V3
for Electra per `prague.md`), and `engine_getPayloadV4` for Electra heads via an exhaustive
`match` on the head state's `fork_variant()`. `NewPayloadVersion::V4` carries an additional
`execution_requests: Vec<String>` parameter. `GetPayloadV4Response` extends V3 with
`execution_requests: Vec<String>` + `shouldOverrideBuilder`. `getBlobsV1` is reused
unchanged (blob RPC is per-blob, not per-fork).

### D-electra-fork-digest-migration — Electra fork digest wired via ForkSchedule + fork-context

**Status**: Accepted.

`ForkSchedule::compute_fork_version` gained an `electra_fork_epoch` arm in `pharos-types`.
The Electra fork digest is computed from `ELECTRA_FORK_VERSION` (mainnet `0x05000000`,
minimal `0x05000001`) and included in `ForkContext`
(`crates/pharos-network/src/topics.rs`). The context-bytes codec arms for
`BeaconBlocksByRange/2`, `BeaconBlocksByRoot/2`, and blob-sidecar methods each received
an `Electra` arm (no `_ =>` fallback). The `subscribe_*_topics` function in
`crates/pharos-node/src/main.rs` gained an `Electra` arm (a historically-broken
hand-written dispatch site). `fork_migration::topics_for_version` and the ENR cross-fork
migration driver also gained electra arms.

### D-electra-api-endpoints — electra-specific Beacon API endpoints derived from state fields

**Status**: Accepted.

Four new REST endpoints expose the new electra state fields:
`GET /eth/v1/beacon/states/{state_id}/pending_deposits`,
`…/pending_consolidations`,
`…/pending_partial_withdrawals`, and
`GET /eth/v1/validator/duties/proposer/{epoch}` extended with `proposer_lookahead`
(derived on-the-fly via `get_beacon_proposer_index` over the lookahead window;
`proposer_lookahead` is NOT an SSZ field in `BeaconState`). `GET/POST
…/validator_identities` was also added. All electra arms in
`crates/pharos-api/src/{state,fork_tag,dto/block,handlers/light_client}.rs` are
wired without `_ =>` fallback (a historically-broken fork-dispatch site).

### D-electra-placeholder-categories — networking and fast_confirmation deferred

**Status**: Accepted.

`electra/networking` (gossip rule enforcement spec-tests) requires a running EL+CL stack
with a real peer, which is integration-test territory beyond the conformance harness. It is
deferred to M13 devnet testing. `electra/fast_confirmation` (minimal preset only) is a new
upstream spec category introduced in v1.7.0-alpha.8 that validates the fast-confirmation
algorithm; it requires no new STF work but is gated behind the `pharos-fork-choice` fast
confirmation extension (M13). Both categories appear as placeholder rows in
`docs/conformance.md` and `crates/pharos-conformance/src/rows.rs`.

### D-electra-lc-uses-block-state-root — electra LC writer uses STF-verified block.state_root

**Status**: Accepted.

The electra light-client header uses `block.state_root` (the STF-committed state root),
not a recomputed `state.tree_hash_root()`. This matches the Deneb LC convention
(`D-lc-header-uses-block-state-root`): a recomputed root on the electra-projected state
would omit `execution_payload_header` and diverge from what validators verify. The LC writer
in `crates/pharos-stf/src/electra/light_client.rs` reads `block.state_root` directly.

### D-schema-v6-migration — electra LC column families bump schema to v6

**Status**: Accepted.

Four new RocksDB column families store electra light-client snapshots:
`electra-light-client-bootstrap`, `electra-light-client-update`,
`electra-latest-finality-update`, `electra-latest-optimistic-update`
(in `crates/pharos-storage/src/cf.rs`). Opening a v5 DB returns `SchemaMismatch` →
resync. The pattern mirrors the Deneb schema-v5 / Capella schema-v2 precedents.
`SCHEMA_VERSION` in `crates/pharos-storage/src/db.rs` is bumped from 5 to 6.

### D-electra-vc-single-attestation — VC publishes SingleAttestation per attester to committee subnet

**Status**: Accepted.

Per `specs/electra/validator.md:282-296`: in the Electra epoch, the VC builds a
`SingleAttestation` (committee_index, attester_index, AttestationData, signature) and
publishes it to the `beacon_attestation_{committee_index % ATTESTATION_SUBNET_COUNT}`
subnet. The VC does NOT build an `Attestation` with `committee_bits`; that is the
aggregator's job. The electra VC duty scheduler branches on `ELECTRA_FORK_EPOCH` to
choose between pre-electra `Attestation` publication and electra `SingleAttestation`
publication. Syncnets and other duties are unchanged.

### D-electra-sync-optimistic-runner — sync/optimistic conformance runner extended to electra

**Status**: Accepted.

The `sync/optimistic` conformance row (`("sync", "optimistic", preset)`) is a single row
that covers all forks in one `enumerate_optimistic` pass. For Electra the runner was
extended with electra anchor state loading, deneb/electra block decode paths, and an
`OptimisticElectraFeed` trait (matching `ElectraFcSpec` from `fork_choice.rs`) to feed
block body attestations via `on_attestation_electra` with preset-specific const generics.
The electra fork loop adds `"electra"` to the existing `["bellatrix", "capella", "deneb"]`
walk. Fixtures at `{preset}/electra/sync/optimistic/pyspec_tests/from_syncing_to_invalid/`
both pass, and the row is no longer a placeholder.

### D-electra-produce-block-serialize-arm — produce_block API handler electra serialize arm (devnet-found)

**Status**: Accepted. Live-only correctness bug, found on the M12-Electra transition devnet
(a reference CL client + ethrex v13, `ELECTRA_FORK_EPOCH=1`).

Phase 6d wired `ElectraBlockAssembler` and the electra `produce_block` core, but the
`produce_block` HTTP-API handler in `crates/pharos-node/src/main.rs` has a *separate*
hand-written match that SSZ-encodes the produced `SignedBeaconBlock` and builds the
VC-facing JSON/`block_ssz` (one DTO per fork). That match still had an
`unreachable!("Electra block production reached signed-block match")` arm with a stale
comment claiming `produce_block` returns `Err(WrongFork)` before reaching it — no longer
true once 6d made electra production real. The first post-fork pharos-vc proposal (an
electra slot) therefore reached the arm and panicked the beacon node. Fixed by mirroring
the Deneb arm: SSZ-encode, discriminant byte `5u8` (electra), `ForkVariant::Electra`, and
the stub JSON carrying `message.slot`/`proposer_index`/`parent_root`/`state_root` (the VC
signs over `block_ssz`, not the JSON). Re-verified live: pharos-vc built+published an
electra block (slot 50) with the node panic-free. This is the M12 analogue of the
M5-follow / M6-Capella / M9 live-only correctness bugs: a hand-written fork-dispatch site
the conformance suite does not exercise. All other `unreachable!()` arms in the live node
path were audited and confirmed to be correct catch-alls (real electra arm present before
the catch-all).

### D-electra-devnet-prague-syscontracts — EL genesis requires Prague system-contract predeploys

**Status**: Accepted (devnet-infra, not a pharos code change).

An Electra/Prague EL genesis MUST include the Prague system-contract predeploys in `alloc`
with bytecode: EIP-7002 withdrawal requests (`0x00000961ef480eb55e80d19ad83579a64c007002`),
EIP-7251 consolidation requests (`0x0000bbddc7ce488642fb579f8b00f3a590007251`), and EIP-2935
history storage (`0x0000f90827f1c53a10cb7a02335b175320002935`). Without them ethrex's
`getPayload` fails with "System contract: 0x0000…7002 has no code after deployment" and the
chain freezes at the fork. The Deneb-genesis devnet never needed them; Electra is the first
fork that does. The devnet generator (`~/.cache/pharos-devnet/gen-testnet.sh`) now merges
these predeploys (extracted from `ethrex/fixtures/genesis/l1.json`) into the EL genesis and
sets `pragueTime` to the electra fork wall-clock plus a `prague` blob-schedule entry.

### D-electra-duties-proposer-16bit — proposer-duties endpoint must use the electra 16-bit accessor (devnet-found)

**Status**: Accepted. Live-only correctness bug, found on the M12-Electra transition devnet
after the produce-serialize-arm fix (`D-electra-produce-block-serialize-arm`).

`proposer_index_at_slot` in `crates/pharos-api/src/handlers/validator_duties.rs` (backing
`GET /eth/v1/validator/duties/proposer/{epoch}`) unconditionally used the phase0 8-bit
`compute_proposer_index`. On a multi-validator electra network the 8-bit and the EIP-7251
16-bit `compute_proposer_index_electra` select DIFFERENT validators for some slots. The VC
asks the duties endpoint who proposes a slot, signs the produced block as that validator,
but `produce_block` (correctly) stamps the block with the 16-bit electra proposer; the STF
then verifies `state.validators[electra_proposer].pubkey` against the phase0-proposer's
signature and rejects with `InvalidBlockSignature`. Fixed by fork-gating the final
selection to `compute_proposer_index_electra` for `ForkVariant::Electra` (mirroring the
already-fixed lookahead handler in `states.rs` and `produce_block`). Single-validator
setups and the in-process 6d round-trip test masked it (both accessors return index 0).
This was the THIRD site of the recurring electra 16-bit-proposer dispatch gotcha (after
block production in 6d and proposer-lookahead in 6e); all proposer-selection sites must
route through the electra accessor on electra states. The serialization path itself is
sound — proven by the `electra_signing_root_repro.rs` regression test (VC-side and
STF-side signing roots are byte-identical).

## M11 Phase 9 — Slasher Phase B (chain-history replay, opt-in `--slasher`)

### D-slasher-proposer-index-cf — proposer double-block index is a new RocksDB CF (schema v8)

**Status**: Accepted. **Date**: 2026-06-14.

Phase B's proposer double-block detector needs to remember every block header a proposer
signed at each slot over the replayed history. The Phase A attestation slasher is purely
in-memory with a bounded eviction window; the proposer history is the "higher-storage"
half of the roadmap's opt-in slasher, so it is persisted in a dedicated column family
`slasher-proposers` rather than an in-memory map. Key layout is
`slot (8 B BE) || proposer_index (8 B BE) || header_root (32 B)`, value SSZ
`SignedBeaconBlockHeader`. The 16-byte `slot || proposer_index` prefix groups every header
a proposer signed at a slot; the 32-byte `header_root` suffix keeps two distinct blocks (a
double-block) under separate keys so both survive and a prefix scan finds the slashable
pair. Adding the CF bumped `SCHEMA_VERSION` 7→8; the v7→v8 migration is identity (the CF
is auto-created by `create_missing_column_families` on open, and the index is rebuilt from
scratch on each `--slasher` replay so an empty CF after migration is correct). Storage cost
is one `SignedBeaconBlockHeader` (~112 B SSZ) per stored block over the retained history,
which is the roadmap's "~10 GB higher-storage" path on mainnet.

### D-slasher-replay-reuses-phase-a-detector — replay feeds the Phase A `AttestationSlasher`, no duplicated double/surround logic

**Status**: Accepted. **Date**: 2026-06-14.

The plan requires reusing the Phase 8 detection cores, not reimplementing them. The replay
scanner (`ChainReplaySlasher`) holds its own `Arc<AttestationSlasher<E>>` (sharing the
node's `op_pools`) and feeds each historical block's attestations through
`AttestationSlasher::observe`, the exact entry point the live gossip path uses. The
double-vote / surround-vote predicate (`is_slashable_pair`) lives in one place
(`slasher/mod.rs`). Attestation→`IndexedAttestation` conversion reuses
`pharos_stf::phase0::accessors::get_indexed_attestation` against the per-slot state from
`StateRegenService::state_at_slot` (which itself reuses `replay_to`), so no STF or committee
logic is duplicated either. Detected `AttesterSlashing`s and `ProposerSlashing`s flow into
`op_pools` and increment `pharos_slasher_detections_total` (kinds `double_vote`,
`surround_vote`, `proposer_double_block`).

### D-slasher-replay-att-scope — attestation replay covers phase0..deneb; electra attestations observed on gossip

**Status**: Accepted. **Date**: 2026-06-14.

Block-replay attestation extraction (`block_phase0_attestations`) covers the phase0-family
`Attestation<2048>` shape, which is identical for phase0 through deneb, via the per-fork
`unwrap_*_signed_block` borrowing accessors. Electra blocks carry the EIP-7549 aggregated
`Attestation<MAX_AGGREGATION_BITS, MAX_COMMITTEES_PER_SLOT>` whose const generics are
preset-dependent runtime constants (`E::MAX_AGGREGATION_BITS_ELECTRA`,
`E::MAX_COMMITTEES_PER_SLOT`) and therefore cannot be supplied to the const-generic
`get_indexed_attestation_electra` indexer in fully-generic `E` replay code. Electra block
attestations are instead observed by the always-on Phase A gossip path
(`HostImpl::validate_attestation` feeds the same `AttestationSlasher`), so this is a
fork-coverage boundary of the *replay* path, not a slashing-detection gap. Proposer
double-block detection is fully fork-agnostic (it operates on `SignedBeaconBlockHeader`)
and covers every fork including electra.

### D-slasher-replay-one-shot-at-startup — Phase B replay is a single startup pass gated by `--slasher`

**Status**: Accepted. **Date**: 2026-06-14.

The `--slasher` flag (default off) gates the entire Phase B path in `main.rs`. When off,
only the always-on Phase A in-memory attestation slasher (inside `HostImpl`, fed from
gossip) runs. When on, a one-shot background task (`run_replay`, inside `spawn_blocking`)
walks the stored block history from `anchor_slot` (metadata lower bound on a
checkpoint-synced node) to the current wall-clock slot, feeding every block's header and
attestations through the detectors. Errors are logged, never propagated, so a slasher
failure never takes the node down. Live (post-startup) blocks continue to be covered by the
always-on Phase A gossip detector; a continuous replay loop driven off the head-watch is a
later refinement and not required for the Phase B checkpoint (replay-detects-historical-
double-block + proposer-double-block, flag-off-skips).

## M11 Phase 15 — DNS bootnode support (in-house EIP-1459 enrtree)

### D-dns-bootnode-resolver — in-house EIP-1459 resolver over hickory-resolver TXT lookups

**Status**: Accepted. **Date**: 2026-06-14.

The pinned `discv5` 0.10.4 ships NO enrtree/DNS support (confirmed in M11 Phase 0:
its only features are `libp2p` and `serde`, and the source has zero `enrtree`/`dns`/`TXT`
references). Mainnet bootnodes are published as `enrtree://` node lists (EIP-1459), so the
Merkle-tree-over-TXT-records protocol is implemented from scratch in
`crates/pharos-network/src/discovery/dns/mod.rs`.

**DNS crate**: `hickory-resolver` 0.25 — already a transitive dep of `libp2p-dns`, so no
new dependency edge; async-native TXT lookups (`Resolver::builder_tokio().build()` then
`txt_lookup(name).await`). The TXT source is abstracted behind a `TxtResolver` trait so
the resolution logic is exercised against hand-built static fixtures in tests with zero
live-network access; `HickoryTxtResolver` is the production impl.

**Crypto reuse, no new primitive deps**: the EIP-1459 root signature is a 65-byte
recoverable secp256k1 ECDSA over keccak256 of the record content excluding `sig=`. We
reuse `k256` (already pulled by the `enr` crate) for `VerifyingKey::recover_from_prehash`
+ compressed-SEC1 comparison against the URL pubkey, and `sha3::Keccak256` (also already
via `enr`) for the hash. Base32 (RFC-4648 no-pad) for the pubkey + subtree hashes and
url-safe base64 (no-pad) for the signature both come from `data-encoding` (already in the
tree). These three are promoted from transitive to direct deps on `pharos-network`.

**Bounds (DoS guard, Phase 0 decision)**: `MAX_TREE_DEPTH = 16` recursion levels and
`MAX_RECORDS = 1024` total TXT fetches, plus a visited-set keyed on `(domain, hash)` and
linked-tree domain to break cycles. A bad ROOT signature rejects the WHOLE tree
(`RootSignatureInvalid`); a single subtree-hash mismatch rejects only that branch
(logged + skipped) so one tampered branch cannot discard an otherwise-valid list.

**Feed point**: `--bootnode-dns enrtree://...` (repeatable) in `pharos-node/src/main.rs`;
resolved ENRs are appended to the same `bootnodes` vector that static `--bootnode` ENRs
feed, so DNS and static bootnodes mix. A failed `--bootnode-dns` URL logs a warning and is
skipped rather than aborting startup (other bootnodes may still succeed).

## M11-Productionization decisions

### D-weak-subjectivity-reject — `compute_weak_subjectivity_period` from consensus-specs; reject stale anchors

**Status**: Accepted. **Date**: 2026-06-14.

The spec formula (`consensus-specs/specs/phase0/weak-subjectivity.md` equations 1–4) is
transcribed verbatim into `pharos-types/src/weak_subjectivity.rs`:
`compute_weak_subjectivity_period(active_validator_count, total_active_balance_gwei)` and
`is_within_weak_subjectivity_period(ws_state_epoch, current_epoch, ...)`. On checkpoint
sync, `main.rs` loads the anchor state, derives `(active_validator_count,
total_active_balance_gwei)`, calls `is_within_weak_subjectivity_period`, and aborts with
a fatal log if the check fails, preventing the node from starting on a stale anchor. No
simplified approximation is used — the plan noted the roadmap's simplified formula was
NOT spec-correct; Phase 1 transcribes the real spec.

### D-backward-state-backfill — restore-point-chained STF walk from anchor down to genesis

**Status**: Accepted. **Date**: 2026-06-14.

`run_backward_backfill_loop` in `crates/pharos-node/src/backward_backfill.rs` fills the
gap between genesis and the checkpoint-sync anchor. It starts from the lowest stored
restore-point state, walks backwards through stored block roots (via
`slot_to_block_root`, which is never pruned — see `D-prune-behind-finalized`), and
replays blocks forward using the STF to regenerate each slot's state. A
`BackfillProgressSignal` (`Notify`) is posted from the forward backfill loop so the
backward loop parks until the needed blocks are on disk. State-root mismatch aborts
with `BackwardBackfillError::BackfillStateMismatch` — no silent corruption. The loop runs
in a detached `tokio::spawn` so it never blocks startup.

### D-cold-granularity-restore-points-only — cold-states CF stores only restore-point-interval states

**Status**: Accepted. **Date**: 2026-06-14.

The `cold-states` CF only stores states whose slot is a multiple of
`RESTORE_POINT_INTERVAL` (default 8 epochs). Non-restore-point slots are regenerated
via `StateRegenService::replay_to` from the nearest earlier restore point. This is the
correct extent of the M-Storage `D-restore-point-interval` design; Phase 3 confirmed
empirically (`cold_state_density_equals_restore_points` test: cold-state CF count ==
restore-point count for a 3-epoch / interval-1-epoch chain).

### D-forward-only-migrations — forward-only DB migration framework from `MIGRATION_BASELINE` (v6)

**Status**: Accepted. **Date**: 2026-06-14.

`crates/pharos-storage/src/migrations/mod.rs` implements a table-driven forward walk:
each entry is `(from: u32, migration: &dyn Migration)`; `run_migrations(db, found,
target)` applies the chain `found → found+1 → … → target` atomically per step. The
baseline is `MIGRATION_BASELINE = 6` — databases below v6 still hard-error
`SchemaMismatch` and force resync (pre-v6 layouts have no forward migration). The seed
step `v6_to_v7` is a no-op identity migration proving the walk compiles and runs. Future
steps extend the table without touching the walk logic. A future-schema hard-error
(`found > target`) is retained so a node running stale code never silently processes a
newer DB.

### D-metrics-prometheus-optin — opt-in metrics recorder under `--metrics`; `pharos-utils` hosts the registry

**Status**: Accepted. **Date**: 2026-06-14.

`pharos-utils/src/metrics.rs` provides `init_metrics(addr)` (installs the global
`metrics` recorder via `PrometheusBuilder::install_recorder`, returns a
`PrometheusHandle`) and `describe_metrics()` (registers units/descriptions for every
counter/gauge/histogram declared in the workspace). The `metrics::counter!` / `gauge!`
/ `histogram!` macros are no-ops if no recorder is installed, so crates emit freely;
they only incur cost when `--metrics` is passed. The health probe (`D-health-probe-on-
metrics-port`) reuses the same axum server and handle so there is one network listener
for both `/metrics` and `/health`.

### D-safe-hash-verified-ancestor — `compute_safe_block_hash` resolves `latest_verified_ancestor` of justified checkpoint

**Status**: Accepted. **Date**: 2026-06-14.

`compute_safe_block_hash` in `crates/pharos-node/src/engine_driver.rs` was stale before
Phase 6: it returned the justified checkpoint root directly, which could be an
optimistically-imported (not-yet-EL-validated) block. Phase 6 added
`latest_verified_ancestor(store, justified_root)` so the returned hash is always
execution-valid. The finalized hash follows the same pattern via
`compute_finalized_block_hash`. The stale deferral comments at `engine_driver.rs:508-523`
(left from M4a) were retired.

### D-json-tracing — `init_tracing(LogFormat, filter)` in pharos-utils; JSON with ENTER/EXIT span events

**Status**: Accepted. **Date**: 2026-06-14.

`pharos-utils/src/tracing.rs` exports `init_tracing(format: LogFormat, filter: &str)`
wiring `tracing_subscriber` with either a pretty terminal layer or a JSON layer
configured with `FmtSpan::ENTER | FmtSpan::EXIT` so every span boundary emits a
structured event. Both binaries (`pharos`, `pharos-vc`) accept `--log-format json|pretty`
and `--log-level` CLI flags. Per-slot root spans (`process_slot`) and per-block child
spans (`import_block`) are instrumented in `block_ingestion.rs` using explicit parent
linkage so futures remain `Send` for `tokio::spawn`. Per-method `rpc_handle` spans live
in `rpc/handler.rs`. `tracing-serde` enters the non-dev dep tree via the JSON layer,
which triggered a type-inference ambiguity in `pharos-ssz/src/sequence.rs` that was
fixed (explicit type annotation on `Backend::Naive`).

### D-slasher-in-memory — Phase A attestation slasher in `pharos-node/src/slasher/mod.rs`; always-on, no flag

**Status**: Accepted. **Date**: 2026-06-14.

`AttestationSlasher<E>` in `crates/pharos-node/src/slasher/mod.rs` is always-on:
`HostImpl::validate_attestation` feeds every gossip-accepted `IndexedAttestation` through
`AttestationSlasher::observe`, which checks the in-memory per-validator history for
double-vote (same target epoch, different data root) and surround-vote (target epoch
contained inside a prior vote pair). Detected slashings are pushed to `op_pools` as
`AttesterSlashing` and increment `pharos_slasher_detections_total` (kind `double_vote` /
`surround_vote`). The in-memory map is bounded by `MAX_ATTESTATION_HISTORY_EPOCHS` so it
cannot grow unboundedly. No `--slasher` flag is needed; the Phase A detector costs only
a HashMap lookup per gossip attestation.

### D-real-peer-scoring — gossipsub-model additive score; `RealScorer` replaces `NoopScorer` behind `PeerScorer` trait

**Status**: Accepted. **Date**: 2026-06-14.

`RealScorer` in `crates/pharos-network/src/scoring.rs` maintains a per-peer additive
score (`gossip + req_resp + app`), per-peer/per-method req-resp `TokenBucket` rate
limiters, and exponential `DialBackoff`. The model is patterned after gossipsub v1.1:
additive component scores, a single float total, score bounds applied at connection time.
The drop-in replaces `NoopScorer` behind `PeerScorer` in `NetworkBuilder` without
changing the trait surface.

### D-scorer-decay-lazy — lazy exponential decay on `score()` / `record()`; no explicit tick method

**Status**: Accepted. **Date**: 2026-06-14.

Decay is applied lazily: each `PeerState` stores `last_decay: Instant`. On every
`score()` or `record()` call, the elapsed time since `last_decay` is used to compute
`factor = DECAY_PER_SECOND.powf(elapsed)` and all three components are scaled in place,
then `last_decay` is advanced to now. The alternative (explicit `tick` driven from the
swarm loop) was considered and rejected: it would add a `tick` method to the `PeerScorer`
trait and require the swarm loop to carry a decay-driver. Lazy decay delivers
equivalent accuracy with no trait change and no swarm-loop complexity.

### D-rpc-rate-limit-token-bucket — per-peer/per-method token bucket in `RealScorer`

**Status**: Accepted. **Date**: 2026-06-14.

Each `PeerState` maintains a `HashMap<RpcMethod, TokenBucket>`. A `TokenBucket` refills
at `refill_per_second` tokens/second up to `capacity`; `try_consume` attempts to drain
one token, returning `true` (allowed) or `false` (rate-limited). The
`ScoreEvent::RpcRateExceeded` variant is emitted on `false` and causes a `req_resp`
score penalty. This per-method granularity prevents one method (e.g. heavy
`BeaconBlocksByRange` requests) from consuming the budget for others.

### D-dial-backoff-exponential — exponential dial backoff in `RealScorer` via `DialBackoff`

**Status**: Accepted. **Date**: 2026-06-14.

`DialBackoff` in `RealScorer` tracks `failures: u32` and `next_allowed: Instant`. On
`ScoreEvent::DialFailed`, `next_allowed = now + BASE_DIAL_BACKOFF * 2^failures` (capped
at `MAX_DIAL_BACKOFF`). `PeerScorer::can_dial(peer, now)` returns `false` while
`now < next_allowed`. This prevents tight reconnect storms against unresponsive peers
and is the natural dual to the `TokenBucket` on the inbound side.

### D-connection-limit-prefer-high-score — inbound connections beyond `max_peers` evict the lowest-scored peer

**Status**: Accepted. **Date**: 2026-06-14.

When a new inbound connection would exceed `max_peers`, the `Network` looks up the
existing peer with the lowest `PeerScorer::score` and disconnects it before accepting
the new peer. This ensures that a high-scoring (well-behaved) peer is never displaced
by a new arrival when the table is full — the eviction policy prefers keeping peers with
a positive track record. CLI flags `--max-peers` and `--target-peers` wire the limits
into `NetworkBuilder`; `PeerManager::query_interval` scales the discv5 discovery cadence
with the peer-deficit (`target - connected`) so the node converges faster when below
target.

### D-enr-seq-persistence — ENR sequence number persisted in `<data_dir>/enr_seq`; bumped on restart

**Status**: Accepted. **Date**: 2026-06-14.

`save_enr_seq` / `load_enr_seq` in `crates/pharos-network/src/discovery/enr.rs` persist
the ENR sequence number as a little-endian u64 text file at `<data_dir>/enr_seq`. On
startup, the saved seq is loaded (default 1 if absent) and passed to `build_enr` as the
starting sequence number; after a successful ENR update the new seq is written back.
Persisting the seq prevents EIP-778 spec violation (seq must be monotonically increasing
across restarts); without persistence, a restarted node would reset to seq=1, breaking
peers that cached a higher seq and expect only forward progress.

### D-peer-score-persist-format — flat packed SSZ records at `<data_dir>/peer_scores.ssz`; unknown peers ignored on load

**Status**: Accepted. **Date**: 2026-06-14.

`serialize_scores` / `deserialize_scores` in `crates/pharos-network/src/scoring.rs`
write/read a flat array of `PeerScoreRecord` structs (each 80 bytes: 32-byte `PeerId`
bytes + 3 × f64 components + padding). No outer length prefix or version field is needed
— the format is self-delimiting as a multiple of `RECORD_SIZE`. On `deserialize_scores`
the `PeerScoreRecord::peer_id` bytes are decoded into `libp2p::PeerId`; records for
peers not currently in the scorer's map are silently ignored (peer sets differ across
restarts, and importing a stale score for a never-seen peer would pollute the scorer).
The file is atomic-written (`tmp → rename`) so a crash during save never produces a
partial file.

### D-web3signer-commit-before-sign — slashing-DB commit precedes every Web3Signer HTTP call

**Status**: Accepted. **Date**: 2026-06-14.

`pharos-validator/src/web3signer.rs` implements `Web3RemoteSigner` behind the existing
`Signer` enum. The VC's signing path in `signing.rs` already commits the slashing-DB
record before calling `sign()` on a local key; the same `commit_before_sign` contract
applies to the remote path: `SlashingProtectionDb::commit` is called, then
`Web3RemoteSigner::sign`, then the VC publishes. A crash between commit and
HTTP call leaves a slashing-DB entry but no published object — safe. A crash between
HTTP response and publish leaves a signed-but-not-published object — also safe (the
commitment already exists, so a retry will be rejected by the slashing DB). All six
Web3Signer signing types (`BLOCK_V2`, `ATTESTATION`, `RANDAO_REVEAL`, `AGGREGATE_AND_PROOF`,
`SYNC_COMMITTEE_MESSAGE`, `SYNC_COMMITTEE_SELECTION_PROOF`) are implemented; `VALIDATOR_REGISTRATION`
is included for completeness (builder integration is out of scope).

### D-graceful-shutdown-order — ordered 6-step shutdown sequence on SIGTERM/SIGINT

**Status**: Accepted. **Date**: 2026-06-14.

`run_shutdown_sequence` in `crates/pharos-node/src/shutdown.rs` drives:
(a) drain in-flight gossip validators (bounded `GOSSIP_DRAIN_TIMEOUT`);
(b) send `Goodbye(1)` to all peers (existing M3a `D-shutdown-protocol`, 500 ms drain);
(c) flush pending gossip publishes (bounded drain);
(d) save peer scores to disk (`D-peer-score-persist-format`);
(e) fsync chain DB (`RocksStore::flush_wal + flush`);
(f) signal the remaining loops to exit.
The signal handler uses `tokio::signal::ctrl_c` + `unix::signal(SIGTERM)` in `main.rs`
and races them on a `select!`; the first arrival triggers the shutdown sequence. Steps
are ordered so data-integrity operations (DB fsync) precede loop teardown.

### D-health-probe-on-metrics-port — `/health` endpoint on the metrics axum server; 200 = Synced, 503 otherwise

**Status**: Accepted. **Date**: 2026-06-14.

The health probe lives on the same axum router as `/metrics` (same TCP port,
`--metrics-addr`), not on the beacon-API port. The `/eth/v1/node/health` endpoint
(shipped in M7) is the per-spec sync-state endpoint for clients; the `/health` probe is
a separate operational endpoint for load-balancers and container orchestrators. `SyncState`
(`Synced` / `Syncing`) is supplied as an `Arc<dyn Fn() -> SyncState>` closure at startup
from `pharos-node/src/main.rs`. `None` serves 503 unconditionally (useful before the
ingestion loop is ready). The probe is served by `start_metrics_server` in `pharos-utils`
alongside the Prometheus scrape endpoint.

### D-fuzz-harness — three `cargo-fuzz` panic-finding targets; oracle: no panics, only `Err`

**Status**: Accepted. **Date**: 2026-06-14.

Three fuzz targets in `fuzz/fuzz_targets/`: `ssz_decode` (arbitrary SSZ bytes into a
`phase0::BeaconBlock<MinimalEthSpec>`), `process_block` (arbitrary block bytes applied to
a fixed valid base state with `verify_signatures: false`), and `rpc_codec` (arbitrary
bytes into `RpcRequest` / `RpcResponse` SSZ codec). The oracle is: no panics, only
`Err` returns. `make fuzz-build` / `make fuzz-smoke` (30 s per target) wired in the
Makefile. `fuzz/` is a non-workspace crate so it does not affect `cargo build --workspace`
or the test suite. Campaign notes and overnight workflow in `docs/fuzz.md`.

### D-ci-github-actions — GitHub Actions CI on stable + MSRV (1.86) matrix; fuzz-build in nightly job

**Status**: Accepted. **Date**: 2026-06-14.

`.github/workflows/ci.yml` runs three jobs on push/PR to master:
(1) `fmt` — `cargo fmt --check` on stable;
(2) `clippy` + `test` — matrix `[stable, "1.86"]` covering both the current compiler
and the workspace MSRV declared in `Cargo.toml`; clippy runs `--deny warnings`;
(3) `fuzz-build` — `cargo +nightly build` for each fuzz target on nightly (nightly is
required by `libfuzzer_sys`; failures are non-blocking because fuzz targets use unstable
features). The matrix ensures MSRV regressions are caught before merge.

### D-replay-bounds-extraction — `ReplayBounds` type alias extracted to co-locate with `SignedBeaconBlockHeader`

**Status**: Accepted. **Date**: 2026-06-14.

A hygiene cleanup landed after Phase 20: the `(Slot, Slot)` tuple used as the inclusive
`(start, end)` range for the chain-replay slasher was inlined at every call site. It is
extracted to a `ReplayBounds` type alias in the same module as `SignedBeaconBlockHeader`
usage (`pharos-node/src/slasher/mod.rs`), removing duplication and making the intent of
the range arguments explicit.

## M13-Fulu decisions

Fulu (Fusaka/Osaka) consensus-layer fork — an Electra sibling. EIP-7594 (PeerDAS),
EIP-7892 (BPO hardforks), EIP-7917 (deterministic proposer lookahead). Mainnet activated
Fulu at epoch 411392 (Dec 3, 2025), so this is the live production fork. Plan in
`docs/m13-fulu-plan.md`. All ADRs Accepted, date 2026-06-25 unless noted.

### D-fulu-stf-delegates-to-electra — fulu STF is an electra sibling that projects state

The `crates/pharos-stf/src/fulu/` STF delegates unchanged steps to electra via
`fulu_state_to_electra` / `update_fulu_from_electra` projection helpers, mirroring the
electra→deneb pattern. The only new state field is `proposer_lookahead`
(EIP-7917); `process_epoch` adds `process_proposer_lookahead` as the final step;
`process_operations` asserts `len(body.deposits) == 0` and drops the legacy
`process_deposit` path (deposits arrive only via `process_deposit_request`). Per
`specs/fulu/beacon-chain.md`.

### D-eip7594-column-sidecar-shape — `DataColumnSidecar` + DAS containers in `pharos-types/fulu`

`DataColumnSidecar { index, column: List[Cell, MAX_BLOB_COMMITMENTS_PER_BLOCK],
kzg_commitments, kzg_proofs, signed_block_header, kzg_commitments_inclusion_proof:
Vector[Bytes32, 4] }` per `specs/fulu/das-core.md`. `Cell = ByteVector<2048>`
(SSZ type owned by `pharos-types`, not `pharos-kzg`). The inclusion proof is a fixed
`Vector[_, 4]` (NOT a `List`), gindex `16 + 11 = 27` (field 11 of `BeaconBlockBody`),
depth `KZG_COMMITMENTS_INCLUSION_PROOF_DEPTH = 4`, validated by `fulu/merkle_proof`.

### D-eip7594-da-checker-column-impl — `ColumnAvailabilityChecker` over the fork-agnostic trait

`ColumnAvailabilityChecker<E>` implements the unchanged `DataAvailabilityChecker<E>`
trait. The expected-column set is the custody+sampling union: `sampling_size =
max(SAMPLES_PER_SLOT, custody_group_count)` clamped to `NUMBER_OF_CUSTODY_GROUPS`, then
the union of `compute_columns_for_custody_group(g)` over
`get_custody_groups(node_id, sampling_size)` (RI-1 — NOT all 128 columns). Missing any
expected column → `NotAvailable` (the block parks; the column ingestion loop re-injects
on set completion).

### D-custody-uint-to-bytes-little-endian — `get_custody_groups` hashes the SSZ (LE) node id

`get_custody_groups` (`pharos-stf/src/fulu/data_columns.rs`) holds the `NodeID` as a
32-byte big-endian array (discv5 canonical form) but the spec hashes
`uint_to_bytes(current_id)`, which is the SSZ encoding (`ENDIANNESS = "little"`,
`specs/phase0/beacon-chain.md:652`). The initial implementation hashed the big-endian
bytes directly — a bug caught by the new `fulu/networking` custody conformance vectors
(`got [11], want [65]` for `node_id=1048576, cgc=1`). Fix: reverse the BE bytes to LE
before `hash()`; the increment stays on the BE buffer (a numerically-correct uint256
`+= 1`). On a live node a wrong custody set means failing PeerDAS sampling against real
peers, so this was a true correctness bug, not cosmetic.

### D-fulu-networking-custody-runner — real conformance runner for the DAS custody helpers

`fulu/networking` is not a blanket placeholder (unlike `electra/networking`,
`D-electra-placeholder-categories`). The two pure-function handlers
(`get_custody_groups`, `compute_columns_for_custody_group`) have trivial
`node_id/custody_group → result:[...]` `meta.yaml` fixtures and pharos already ships the
functions, so `crates/pharos-conformance/src/networking.rs` runs them for real
(pass=16 fail=0 both presets). The gossip-validator handlers (attester_slashing,
bls_to_execution_change, proposer_slashing, sync_committee_*) are enumerated as skips
(they need a live store + wired gossip harness). `node_id` is read as raw decimal digits
from the fixture text because it can be `2**256 - 1` (serde parses it lossily as `f64`).

### D-eip7892-blob-schedule-config — `BLOB_SCHEDULE` + `get_blob_parameters`

`RuntimeConfig` gains `blob_schedule: Vec<BlobScheduleEntry { epoch, max_blobs_per_block }>`.
`get_blob_parameters(epoch, blob_schedule, electra_fork_epoch,
max_blobs_per_block_electra)` walks the schedule reverse-sorted by epoch (first entry
with `epoch <= given`), falling back to the electra limit. The fulu
`process_execution_payload` blob-commitment limit is epoch-driven via this helper, not a
fixed const. Per `specs/fulu/beacon-chain.md`.

### D-eip7892-bpo-fork-digest-rotation — fork digest rotates WITHIN fulu at BPO boundaries

`compute_fork_digest_for_epoch(version, gvr, epoch, blob_schedule)` returns the plain
digest for `epoch < FULU_FORK_EPOCH` and, for fulu epochs, XORs the base digest with the
first 4 bytes of `hash(uint_to_bytes(epoch) ++ uint_to_bytes(max_blobs_per_block))`
(SHA256 of 16 LE bytes per `beacon-chain.md:216-246` — NOT SSZ `hash_tree_root` of the
`BlobParameters` container; the two differ). The digest changes at every BPO boundary,
making it a new mid-fork migration surface (`D-fulu-fork-digest-migration`).

### D-fulu-fork-digest-migration — BPO-boundary migration loop distinct from fork boundaries

`run_bpo_migration_loop` (`pharos-node/src/fork_migration.rs`) schedules a migration at
each `BLOB_SCHEDULE` entry's epoch (distinct from the regular fork-boundary migration).
At each boundary it recomputes the fork digest, unsubscribes the old-digest topics,
subscribes the new-digest topics, and updates ENR `eth2` + `nfd`. The fulu fork version
itself does NOT change at a BPO boundary — only the blob params and hence the digest.

### D-eip7917-proposer-lookahead — `proposer_lookahead` state field; every site reads it

`BeaconState` gains `proposer_lookahead: Vector[ValidatorIndex, LOOKAHEAD_WINDOW]`.
`get_beacon_proposer_index` reads `proposer_lookahead[slot % SLOTS_PER_EPOCH]` instead of
computing on demand; `process_proposer_lookahead` shifts the window each epoch;
`initialize_proposer_lookahead` seeds it in `upgrade_to_fulu`. RI-6: every
proposer-selection site reads the lookahead — block production
(`block_production.rs` `produce_block` fulu arm), the proposer-duties endpoint
(`pharos-api/src/handlers/validator_duties.rs`), and the
`/states/{id}/proposer_lookahead` endpoint (`handlers/states.rs`). This is the M12
16-bit-proposer gotcha's fulu analogue; all three sites were audited.

### D-kzg-cell-sampling-wrappers — thin c-kzg cell wrappers, no fulu/kzg conformance dir

`pharos-kzg` adds `compute_cells`, `compute_cells_and_kzg_proofs`,
`verify_cell_kzg_proof_batch`, `recover_cells_and_kzg_proofs` over c-kzg 2.1.7 (no
version bump, no new crypto). There is no `fulu/kzg` fixture dir; cell KZG is covered by
`general/fulu/kzg/*` (the existing `fulu_kzg` runner) and c-kzg's own vectors.

### D-data-column-sidecar-storage — `CF_DATA_COLUMN_SIDECARS` keyed `root || index_be`

Column sidecars persist in `CF_DATA_COLUMN_SIDECARS` keyed `block_root (32 B) ||
index_be (8 B)`, mirroring the M10-DA blob CF (`D-blob-store-cf-keyed-by-root-index`).
`run_column_ingestion_loop` persists on gossip accept and re-injects on set completion;
`run_column_prune_loop` prunes at `MIN_EPOCHS_FOR_DATA_COLUMN_SIDECARS_REQUESTS = 4096`
epochs behind head.

### D-schema-v9-migration — schema bump 8 → 9 for the column-sidecar CF

`SCHEMA_VERSION = 9`; `v8_to_v9` opens the new `CF_DATA_COLUMN_SIDECARS` column family.
Opening a v8 DB returns `SchemaMismatch` → resync (mirror `D-schema-v4-migration`).

### D-fork-aware-live-da-checker — live node delegates DA to both blob + column checkers

A long-running node spans Electra→Fulu and imports both blob-carrying (pre-Fulu) and
column-carrying (Fulu+) blocks. The `DataAvailabilityChecker` trait is fork-agnostic
(sees only `(block_root, kzg_commitments)`, never the slot), so a static
`BlobAvailabilityChecker` would gate Fulu blocks against blob sidecars that never arrive
post-Fulu and park them forever. `ForkAwareDataAvailabilityChecker`
(`pharos-node/src/data_availability.rs`) delegates to BOTH sub-checkers and combines:
`Available` if either is, `Irrelevant` only if both are (empty commitments), else
`NotAvailable`. Each sub-checker returns `Available` only when ITS sidecar type is
present, and a node only ingests the fork-correct sidecar type for a given block, so the
combine is exact. Column is checked first (Fulu is the active mainnet fork) so the common
path short-circuits without a redundant blob-store scan. Surfaced by the Phase 6b
implementer as an out-of-scope live-correctness gap; fixed before the devnet phase.

### D-engine-v5-getpayload — `engine_getPayloadV5` for production; `newPayloadV4` on import

Fulu block production uses `engine_getPayloadV5` (returns `BlobsBundleV2` with
`CELLS_PER_EXT_BLOB * len(blobs)` cell proofs); the import path keeps `newPayloadV4`.
This matches ethrex's actual Osaka gating: getPayloadV4 returns `UnsupportedFork(Osaka)`
for Osaka-timestamp blocks (must use V5), while newPayloadV4 covers Prague+Osaka and
newPayloadV5 is the *Amsterdam* (BAL) variant, not Osaka. FCU stays V3 (no V4/V5 FCU
exists). `engine_getBlobsV2`/`V3` (distributed blob publishing) are deferred. Per
`~/dev/execution-apis/src/engine/osaka.md` + ethrex `crates/networking/rpc/engine/payload.rs`.

### D-cgc-enr-field / D-nfd-enr-field — custody-group-count + next-fork-digest ENR fields

ENR gains `cgc` (custody group count, uint64 big-endian, no leading zeros, 0 = empty
string) and `nfd` (next fork digest, SSZ Bytes4 — regular + BPO aware). Written via
`DiscoveryHandle::update_enr_eth2_fulu`. The custody adjustment loop
(`pharos-node/src/custody.rs`) is sticky-high on `cgc`: increases update the ENR + the
custody subscription set immediately; decreases keep the highest `cgc` seen and persist
across restarts. `get_validators_custody_requirement` per `specs/fulu/validator.md`.

### D-partial-columns-deferred — full DataColumnSidecar gossip only; partial columns deferred

libp2p-gossipsub 0.49.4 has no Partial Message Extension (PR #685), so
`specs/fulu/partial-columns/p2p-interface.md` cannot be implemented. Partial-column types
(`PartialDataColumnSidecar`, `PartialDataColumnHeader`,
`PartialDataColumnPartsMetadata`) are defined for `ssz_static` but carry NO gossip
wiring. The `fulu/networking` conformance gate does not require partial columns. A libp2p
upgrade is the prerequisite for full mainnet partial-columns participation (RI-3).

### D-fulu-lc-uses-block-state-root — fulu LC header uses the STF-verified `block.state_root`

Fulu light-client snapshot writes (`pharos-stf/src/fulu/light_client.rs`, dispatched from
the ingestion loop) use the STF-verified `block.state_root` for the LC header, not a
recomputed root over a projected state (the M4c `D-bellatrix-lc-header-uses-state-root`
invariant carried forward). Fulu LC containers reuse the electra shape.

## M13-Fulu live-acceptance decisions

Found while driving the live Electra→Fulu devnet acceptance (a reference CL client +
ethrex v13, electra genesis → fulu@epoch1, 6s slots, fulu digest `0x4ce02029`). All
Accepted, date 2026-06-25. Verified live: pharos stays peered (`connected=1`, 0 bans),
follows head past the fulu crossing (`head==wall±1`, head `version=fulu` at slot 60),
0 panics. These are the M13 analogue of the per-milestone live-only bug
(M5-follow/M6-Capella/M9/M10/M12).

### D-fulu-metadata-cgc-nonzero — MetaDataV3 must advertise a valid (non-zero) custody_group_count

`HostImpl` had no `Host::custody_group_count()` override, so the Fulu MetaDataV3 served
on the wire carried the trait default of `0`. EIP-7594 requires `cgc` in
`1..=NUMBER_OF_CUSTODY_GROUPS`; a `0` is out-of-range. The reference CL rejects it
(`"Invalid custody group count in metadata: out of range"`), sends `Goodbye(Fault)`, and
bans the peer at `-100`; every subsequent re-dial is then refused
(`"Connection to peer rejected: peer has a bad score"`), which surfaced downstream as the
permanent `backfill: no peers available` stall. Fix: create the shared `Arc<CustodyState>`
(seeded at `CUSTODY_REQUIREMENT = 4`) before `HostImpl::new` and wire it in via
`HostImpl::wire_custody` (mirroring `wire_engine`); `custody_group_count()` and
`custody_columns()` now both read the live sticky-high count through `effective_cgc()`
(never `0`), the single source of truth shared with the custody-adjustment loop and the
ENR `cgc`. The diagnostic key was the reference CL's `--debug-level debug`.

### D-no-libp2p-ping — drop the libp2p `/ipfs/ping/1.0.0` behaviour

eth2 peers do not implement libp2p's standard ping protocol; they use the consensus-layer
RPC `Ping` method (`specs/phase0/p2p-interface.md`). Pharos previously included
`ping::Behaviour`, which produced a `Failure::Unsupported` event against every eth2 peer
(the misleading `Ping Err(Unsupported)` symptom that masked the real custody-ban issue).
Verified against `libp2p-ping 0.47`: an `Unsupported` failure moves the handler to
`State::Inactive`/`Poll::Pending` and the `Behaviour` never calls `close_connection`, so
it never managed keep-alive — it was pure log noise. Removed the behaviour, its
`PharosBehaviourEvent::Ping` variant, and the swarm-construction wiring. Liveness is
driven solely by the RPC `Ping` tick (`Network::tick_ping`, every 15 s).

### D-redial-bootnodes-on-deficit — re-dial configured bootnodes when below target peers

On small/static devnets discv5 FINDNODE routinely returns `discovered=0`, so the only
path to a peer is the startup bootnode dial. When that single connection dropped, the node
was permanently peerless. The startup dial loop was extracted into
`Network::dial_bootnodes()` and is now also invoked from the discovery tick whenever
`peer_count() < target_peers()`. `dial_peer` already dedups against connected/pending
peers and honours dial backoff (a clean `ConnectionClosed` records no dial failure and no
ban, so `next_dial_allowed` stays `now`), making the re-dial a safe no-op once connected
and an immediate recovery when the peer is lost. Robustness improvement independent of the
cgc ban above.

### D-fulu-api-fork-tag-from-enum-variant — fulu blocks tag as `fulu`, not the reused electra type

`fulu::SignedBeaconBlock` is a re-export of `electra::SignedBeaconBlock`, so the shared
`BlockApiSerializer` impl tags the DTO `ForkVariant::Electra`. The Beacon API read path
(`block_by_root_for_api`) reached the fulu block via the authoritative outer enum variant
(`unwrap_fulu_signed_block`) but then returned the electra tag, so
`/eth/v2/beacon/blocks/{id}` reported `version=electra` (and `Eth-Consensus-Version:
electra`) for a fulu block. Fix: override `for_api.variant = ForkVariant::Fulu` at the fulu
dispatch arm (the DTO body is structurally identical to electra, so only the tag is
wrong). Also added the missing fulu arm to `fork_variant_at_slot` (LC envelope versioning).
Verified live: head block at the fulu epoch reports `version=fulu`.

## M14-ConformanceCompleteness

Drive every `docs/conformance.md` row to `Skip = 0`, `Fail = 0` (no `-`
placeholders), with no silently-unenumerated subcategory. Final state: 174 rows,
~56,032 pass, 0 fail, 0 skip. The milestone also surfaced and fixed several real
live-node correctness gaps that the skipped tests had been masking.

### D-ssz-static-unknown-type-is-fail — complete the dispatch, fail on unknown

The `ssz_static` runner skipped any fixture type absent from a hand-rolled
per-`(fork,preset)` dispatch table (`_ => Ok(false)` ⇒ Skip), so core types
(`Validator`, `Checkpoint`, `AttestationData`, `Deposit`, LC types, …) were
implemented but never validated against their standalone vectors. Added an arm
for every fixture type (bellatrix..fulu, both presets), refactored the 14 blocks
into a single `dispatch_type!` macro, and replaced every trailing skip arm
(including the outer fork router) with `Err(ConformanceError::UnknownSszStaticType)`.
An unmapped type now fails loudly instead of vanishing.

### D-ssz-generic-unknown-length-is-fail — enumerate every generic case, fail on unknown

`ssz_generic` skipped uint sizes / vector-bitlist lengths / container structs not
in dispatch, and dropped progressive/union handlers from the denominator
entirely (early `continue`). Now every handler is enumerated (progressive/union
cases emit Skip tasks until Phase 7 rather than being absent), and `run_uint` /
`dispatch_vec!` / `dispatch_bv!` / `dispatch_bl!` / `run_container` fail on an
unknown length/struct.

### D-engine-yaml-full-method-coverage — all 25 engine_* methods round-trip

The engine conformance runner ran ~13 of 25 `execution-apis` `engine_*` methods
and skipped the rest behind `DEFERRED_V1`/`V4_DEFERRED`/not-in-scope lists. Removed
the gates; added the missing `EngineClient` methods (`get_blobs_v2/v3/v4`,
`get_payload_bodies_by_{hash,range}_v1/v2`, `forkchoice_updated_v4`,
`get_payload_v6`, `new_payload_v5`) + DTOs + version-enum variants, and a
`dispatch_engine_call` arm per method (full mock-server round-trip). Corrected the
fork→version doc mapping in the process (Fulu uses FCU V3 + newPayload V4; V4-FCU /
V5-newPayload / V6-getPayload are Amsterdam-only).

### D-kzg-full-subcat-enumeration — `Skip=0` was hiding 4 unwalked subcats

`deneb/kzg` reported `Skip=0` while only walking 3 of 7 fixture subcategories —
`compute_blob_kzg_proof`, `compute_challenge`, `compute_kzg_proof`,
`verify_kzg_proof` were simply absent from the denominator (64 cases instead of
262). This is the canonical "zero-skip can still hide missing coverage" hazard;
the milestone exit criterion was hardened to require every subcategory be walked,
unknown ⇒ Fail. Added the 4 deneb runners + the fulu
`compute_verify_cell_kzg_proof_batch_challenge` subcat.

### D-kzg-challenge-in-house — Fiat-Shamir helpers over sha2, not new deps

c-kzg 2.1.7's safe API lacks `compute_challenge` (EIP-4844) and
`compute_verify_cell_kzg_proof_batch_challenge` (EIP-7594). Implemented both
in-house in `pharos-kzg`: SHA256 transcript over the spec-defined domain +
inputs, reduced mod `BLS_MODULUS` via a hand-rolled big-endian reduction (≤2
subtractions, since `floor(2^256 / BLS_MODULUS) = 2`). sha2 only; c-kzg stays the
validated-I/O primitive.

### D-lc-cross-fork-sync — fork-aware sync + walk update_ranking/data_collection

The light_client runner walked only `single_merkle_proof` and `sync`, and the
`sync` runner skipped cross-fork cases (`*_store_with_legacy_data`, `*_fork`).
Added `update_ranking` + `data_collection` sub-sweeps, made the sync runner handle
`upgrade_store` and decode each update at its own `update_fork_digest` fork, and
hardened in-scope decode failures to Fail.

### D-lc-gloas-out-of-scope — post-fulu cases filtered at enumeration

`gloas_*` light-client cases ship under `minimal/{electra,fulu}/light_client/`,
but gloas is post-fulu and not in `rows.rs`. They are excluded by an explicit
name filter during enumeration (no task emitted, no Skip row) — an out-of-fork-scope
exclusion, not a silent skip; recorded here rather than dropped.

### D-hostimpl-injectable-clock — additive clock override for the gossip runner

The gossip validators read wall-clock time via `SystemTime::now()` directly, so
time-gated verdicts can't be reproduced from fixtures (which carry
`current_time_ms` + per-message `offset_ms`). Added
`HostImpl::now_ms_override: Option<Arc<AtomicU64>>` (default `None`) funnelled
through one `now_ms()`; the conformance runner sets it per message. Never set on
the live node — production stays on real `SystemTime::now()`.

### D-gossip-conformance-runner — drive the live validators from networking fixtures

New `networking.rs` runner builds a real `HostImpl<E>` (RocksStore tempdir,
fork-choice store seeded from the fixture state, GVR) and drives the actual gossip
validators against the `gossip_*` fixtures for phase0..fulu, mapping
`GossipVerdict` → `{Accept,Ignore,Reject}` and asserting against `expected`.
Messages feed in fixture order against one `HostImpl` so the seen-cache carries
(`ignore_already_seen_*`). Non-time-gated topics (slashing/exit/bls_change) have no
`current_time_ms` and must not fail on its absence. Required adding a
`pharos-node` dep to `pharos-conformance`. Head-state-missing returns `None` ⇒
IGNORE (a conformance-only justified-checkpoint fallback that leaked into the live
validators was caught in review and reverted — it would have caused false
attestation REJECTs on the live node; the runner seeds `block_states` instead).

### D-gossip-eip7045-time-window — live attestation window fix surfaced by fixtures

The gossip fixtures exposed that `validate_attestation` / `validate_aggregate_and_proof`
/ `validate_single_attestation` used an integer-epoch comparison instead of the
spec's time-based window with `MAXIMUM_GOSSIP_CLOCK_DISPARITY` tolerance
(deneb p2p-interface, EIP-7045). Fixed all sites via a shared
`is_att_slot_in_eip7045_window` helper — a real live-node correctness fix.

### D-gossip-block-timestamp-reject — add the missing payload-timestamp REJECT

The block gossip validator never checked the bellatrix p2p `[REJECT]` rule that
the execution payload timestamp equals `genesis_time + slot * seconds_per_slot`.
Added `BeaconSpec::execution_payload_timestamp` (exhaustive fork-enum match;
`None` for pre-merge) and moved the check before the proposer-signature BLS verify
so a wrong-timestamp block is rejected cheaply and in spec order.

### D-progressive-ssz-eip7916 — in-house ProgressiveList + progressive Merkleization

Implemented `ProgressiveList<T>` and `ProgressiveBitlist` (`progressive.rs`) with
EIP-7916 geometric progressive Merkleization behind the existing
`Encode`/`Decode`/`TreeHash` traits. The `#[derive]` macros are UNCHANGED — the new
scheme is reached only via the new types / manual impls, so existing containers
(`BeaconState`, `BeaconBlock`, …) hash byte-identically (verified: ssz_static all
forks + operations + sanity unchanged).

### D-compatible-union-eip7495 — CompatibleUnion via mix_in_selector

Implemented `CompatibleUnion` (`union.rs`) per EIP-7495: selector byte `1..=127`
validated on decode, root via `mix_in_selector(hash_tree_root(data), selector)`.
`TREE_HASH_TYPE` advertises `Container` (the only composite variant, correct for
parent packing decisions); the root itself is not container-merkleized.

### D-ssz-decoder-first-offset-exact — reject a gap before the variable region

The progressive-container invalid-case fixtures exposed that the core SSZ decoder
was lenient: it accepted encodings whose first variable-field offset is greater
than the fixed-region size (a gap). The spec (and remerkleable/py-ssz) require the
first offset to equal the fixed-region size exactly. Tightened `decode.rs`
(`k == 0 && offset != fixed_len ⇒ Err`); this hardens decoding for every container
type and was verified non-regressing across ssz_static (all forks) + operations +
sanity.

### D-fast-confirmation-rule — in-house FCR + runner

Implemented the phase0 Fast Confirmation Rule (`fast_confirmation.rs`:
`FastConfirmationStore`, the LMD-GHOST confirmation helpers, the FFG
`will_*_be_justified` set, `on_fast_confirmation`) and a conformance runner that
reuses the `fork_choice` step machinery and runs `on_fast_confirmation` once per
slot start after past-slot attestations. All 6 forks altair..fulu
`fast_confirmation/minimal` = 169/0/0; regular `fork_choice` rows unchanged.

### D-fcr-block-support-exact-equality — support counts exact latest-message roots

`get_block_support_between_slots` initially reused `get_ancestor(...) == block_root`
(LMD-GHOST style), but fast-confirmation.md:348 requires exact
`latest_messages[i].root == block_root`. The descendant form over-counted support,
inflated the empty-slot discount, lowered `compute_safety_threshold`, and let
`is_one_confirmed` over-advance the confirmed root (proven against the pyspec with
the failing `fcr_previous_epoch_053` numbers). Fixed to exact equality.

### D-fcr-optimistic-valid-gate — is_one_confirmed must reject non-VALID blocks

Per fast-confirmation.md:619, `is_one_confirmed` MUST return false if the block's
payload status is not `VALID` (a live-node safety requirement — never confirm an
optimistic block). Added the `is_optimistic` gate (no-op for pre-merge blocks).
Because the FCR conformance runner has no engine driver, it now marks `valid:true`
step blocks as `PayloadStatus::Valid` (mirroring the pyspec) so the gate is
satisfied and the fixtures stay 169/0/0; the regular fork_choice runner is
untouched. Also removed an incorrect early-return in `compute_safety_threshold`
for empty slot ranges (the full formula, incl. `proposer_score`, must apply).

### D-fast-confirmation-dispatch-all-forks — rows + dispatch for altair..fulu

`lib.rs` dispatched `fast_confirmation` only for fulu; altair..electra fell to
`_ => None` (placeholder `-` rows). Added dispatch arms + real `rows.rs` rows for
altair/bellatrix/capella/deneb (electra/fulu placeholders converted) and updated
the `row_table_matches_run_order` guard. The runner's fork-enum block handling was
fixed to read `parent_root` from the inner signed block (the fork-enum
`SignedBeaconBlock` has no `message()`), with a Fulu re-wrap of the
electra-shaped decode.

## M15-BeaconAPIGaps

Implement the in-scope missing Beacon API endpoints found in an audit against
beacon-APIs `v1.7.0-alpha.2` (12 endpoints across node, validator, pool, blob,
column, and rewards namespaces). ePBS/Gloas + builder/blinded endpoints are out
of scope (future forks). No Beacon API test vectors exist, so verification is
OpenAPI schema-shape validation + per-endpoint tests, not a conformance row.
Version `0.21.0` → `0.22.0`.

### D-node-version-v2-commit-placeholder — `commit` is `0x00000000`

`GET /eth/v2/node/version` returns `ClientVersionV1{code:"PH", name:"Pharos",
version, commit}`. Pharos does not bake a git commit hash at build time, so
`commit` is the zero 4-byte value. `execution_client` is omitted (optional;
`engine_getClientVersionV1` is not wired).

### D-proposer-dependent-root-fulu-fix — shared helper, exhaustive fork match

`proposer_dependent_root` is an exhaustive `fork_variant` match: pre-Fulu uses
`compute_start_slot_at_epoch(epoch) - 1`; Fulu (EIP-7917 deterministic
lookahead) uses `compute_start_slot_at_epoch(epoch - 1) - 1`, underflow-guarded
to the genesis block root. Both v1 and the new `GET /eth/v2/validator/duties/
proposer/{epoch}` route through it, so adding the Fulu arm also corrected a
latent v1 bug (Fulu nodes had returned the pre-Fulu formula). v2 is otherwise a
thin alias of v1 (identical body shape) and inherits the v1 `is_syncing()` 503
guard; no `is_optimistic_node()` 503 (duty reads stay 200 per the M8 contract).

### D-pool-v2-eip7549-submit-wires-real-pool — v2 POST is not a no-op

`POST /eth/v2/beacon/pool/{attestations,attester_slashings}` are header-driven
(`Eth-Consensus-Version`, exhaustive fork map, 400 on missing/unknown). The
electra paths submit to the REAL op-pool, not a stub: an electra
`SingleAttestation` is converted to a single-aggregation-bit `Attestation` and
`pools.insert_attestation`'d (proven by a POST-then-GET test); an electra
`AttesterSlashing` (same outer shape as phase0) is downcast to the phase0 pool
type and inserted. An empty POST array is a 200 no-op (spec-permitted), not 400.
(An earlier pass returned 200 while silently dropping the payload — caught in
review and wired for real.)

### D-pool-v2-get-per-fork-data-type — GET v2 shapes per fork

`GET /eth/v2/beacon/pool/{attestations,attester_slashings}` return `{version,
data}` + `Eth-Consensus-Version` header. The data array is the spec `anyOf`:
pre-electra `Phase0.Attestation` / electra+ `Electra.Attestation` (aggregated
form with `committee_bits`), and `Phase0`/`Electra.AttesterSlashing`
respectively. The pool stores phase0-shaped attestations; for electra+ the GET
synthesizes `committee_bits` with a width derived from `E::MAX_COMMITTEES_PER_SLOT`
(preset-correct). Fixed a pre-existing serializer bug where
`pool_attester_slashings` emitted `data: {}` instead of the full
`AttestationData`.

### D-blobs-rest-expose-storage — GET blobs reads persisted sidecars

`GET /eth/v1/beacon/blobs/{block_id}` resolves the block_id, reads
`Store::get_blob_sidecars_by_root` via a `ChainStateApi` method, optional
`versioned_hashes` filter (`kzg_commitment_to_versioned_hash`, block order
preserved), JSON (`[Blob]` hex) + SSZ. Pre-deneb/no-blobs → 200 empty; unknown
block → 404. The `versioned_hashes` filter uses CSV encoding (serde_urlencoded
has no repeated-key `Vec` support); the unfiltered path (the common case) is
unaffected.

### D-data-columns-rest-expose-storage — GET data_column_sidecars reads storage

`GET /eth/v1/debug/beacon/data_column_sidecars/{block_id}` mirrors the blobs
endpoint for fulu PeerDAS columns: reads
`Store::get_all_data_column_sidecars_by_root`, optional `indices` filter,
all six `DataColumnSidecar` fields serialized, fork-tagged `{version,...,data}`
+ header, JSON + SSZ. Pre-fulu/no-columns → 200 empty; unknown block → 404.

### D-rewards-factor-not-reimplement — expose STF reward math as pub helpers

The three rewards endpoints reuse the live STF reward math rather than
reimplementing it. `accumulate_attestation_participation_altair` (participation-
flag + proposer-reward numerator) and `sync_aggregate_rewards_altair` were
extracted from the live attestation/sync ops into pub helpers the ops now call;
the phase0/altair/deneb/electra delta fns and `*_state_to_*` projections were
re-exported. The full conformance suite is byte-identical after the factoring
(behavior-preserving oracle: `phase0/rewards` + `altair/rewards` +
`electra/operations`, all rows 0 fail/0 skip).

### D-rewards-proposer-reward-fork-family-split — three helpers, no shared trait

The block-attestation proposer reward cannot be a single generic fn (phase0
`Attestation<2048>` vs electra `Attestation<MAX_AGGREGATION_BITS,
MAX_COMMITTEES_PER_SLOT>` share no trait). Split into
`block_attestation_proposer_reward_{phase0,altair,electra}<E>`; `get_block_rewards`
dispatches by exhaustive `fork_variant`. The phase0 helper computes the real
inclusion-proposer value (`sum base_reward / PROPOSER_REWARD_QUOTIENT`), not 0.

### D-rewards-altair-state-projection — attestation rewards project per fork

`get_flag_index_deltas` takes a concrete altair `BeaconState`, so attestation
rewards project the state per fork before calling it (altair direct; bellatrix/
capella/deneb via `*_state_to_altair` + the matching
`get_inactivity_penalty_deltas_*` variant; electra/fulu via
`electra_state_to_deneb` → `deneb_state_to_altair`). This mirrors the
authoritative `pharos-conformance/src/rewards.rs` dispatch (followed over the
plan prose, which named a shorter projection). `ideal_rewards` buckets use
`E::MAX_EFFECTIVE_BALANCE` (EIP-7251 raises it for electra+).

### D-rewards-block-recompute-not-balance-diff — block rewards vs parent state

Block rewards are recomputed against the parent post-state (advanced to the
block slot via the state-regen path), not derived by balance-diffing, matching
how the spec attributes per-component proposer rewards.

### D-rewards-brpi-hoisted — keep the live attestation path O(N)

`get_base_reward_per_increment` is loop-invariant, so it is hoisted out of the
per-attester loop and passed into `accumulate_attestation_participation_altair`
as a `brpi` parameter at every call site (live ops + reward helpers). The
per-attester base reward is `effective_balance_increments * brpi` (numerically
identical to `get_base_reward`), avoiding an O(N²) full-validator scan per
attestation on the live electra block-processing path.

### D-rewards-no-test-vectors-shape-only — verification strategy

No Beacon API reward test vectors exist. The endpoint tests assert response
shape, the `BlockRewards.total == sum(components)` identity, signed/unsigned
JSON-string encoding, and 404/400/503; the reward MATH (and the electra
projection path) is proven by the conformance regression gate, not by
hand-built electra states.

## M-PeeringHardening decisions

Findings from a peering-robustness audit of `pharos-network`. Each finding is
a discrete hardening item; this section records the ADRs as the phases land.

### D-enr-external-addr-update — confirmed external address propagates into the local ENR

**Finding 9.** When libp2p's swarm autonat/observed-address machinery confirms a
routable external address, the local discv5 ENR previously did NOT learn about
it (the `SwarmEvent::ExternalAddrConfirmed` arm only logged + re-emitted the
event for the Beacon API identity cache). A node behind NAT therefore kept
advertising its (possibly wrong) configured TCP socket in the ENR, so peers
discovering us over discv5 could not dial us. This ADR wires the confirmed
external address through to the ENR.

**Flow.** `Network` event loop receives `SwarmEvent::ExternalAddrConfirmed
{ address: Multiaddr }`. The `Multiaddr` carries `/ip{4,6}/.../tcp/<port>`
(libp2p's external transport is TCP). The arm:

1. Parses the `Multiaddr` into a `SocketAddr` by walking its protocol stack for
   an `Ip4`/`Ip6` component plus a `Tcp` port. A `Multiaddr` without both is
   ignored (e.g. a QUIC-only or DNS multiaddr we cannot map to a discv5 socket).
2. Compares against `Network::last_external_addr` (an `Option<SocketAddr>`
   cached on the event loop). If the parsed socket equals the last one we
   already dispatched, the arm does nothing — **change-only dispatch** prevents
   redundant commands and redundant ENR seq churn from libp2p re-confirming the
   same address repeatedly. Only on an actual change do we update
   `last_external_addr` and send the discovery command.
3. Dispatches `DiscoveryCommand::UpdateExternalSocket(SocketAddr)` to the
   discovery actor (the same channel cross-fork ENR updates already use), then
   re-emits `NetworkEvent::ExternalAddrConfirmed` for downstream consumers
   exactly as before.

**discv5 0.10.4 ENR-update API.** The plan text referenced 0.10.2; the pinned
dependency is **discv5 0.10.4** (`Cargo.lock`). The real API is
`Discv5::update_local_enr_socket(&self, socket_addr: SocketAddr, is_tcp: bool)
-> bool` (`discv5-0.10.4/src/discv5.rs:403`). It takes `&self` (interior
mutability via `RwLock`), so the handler needs no `&mut`. We call it with
`is_tcp = true` because the confirmed libp2p external address is the TCP
transport socket (the discv5 UDP socket is managed by discv5's own
connectivity-state machine, not by libp2p). The method already encodes
**only-on-change + seq-bump-on-change semantics internally**: it returns early
with `false` when the supplied socket equals the current `tcp{4,6}_socket()`,
and only calls `set_tcp_socket` (which bumps the ENR seq and re-signs) when the
socket actually differs, returning `true`. We layer our own `last_external_addr`
guard on top so we never even issue the command for an unchanged address; the
discv5 internal guard is the second line of defence. The handler persists the
ENR seq (`persist_enr_seq`, `D-enr-seq-persistence`) only when
`update_local_enr_socket` returns `true`.

**Debounce / only-on-change decision.** Two layers: (1) the event-loop
`last_external_addr` cache short-circuits identical confirmations before any
command is sent; (2) `update_local_enr_socket` itself is a no-op (returns
`false`, no seq bump) when the socket is unchanged. The net guarantee, asserted
by the integration test, is that **two identical `ExternalAddrConfirmed` events
bump the ENR seq exactly once.** No timer-based debounce is added: libp2p only
emits `ExternalAddrConfirmed` on a state transition, and the two-layer
change-only guard already collapses duplicates, so a timer would add latency
without removing churn.

**IP-clobber caveat.** `update_local_enr_socket(is_tcp=true)` calls
`set_tcp_socket`, which also rewrites the ENR `ip`/`ip6` field that discv5 uses
for UDP reachability. Under asymmetric NAT the TCP-observed external IP can
differ from the UDP one; this is a known limitation. The handler emits a
`tracing::warn!` when the incoming IP differs from `enr.ip4()`/`enr.ip6()` so
the skew is visible in logs. The update still proceeds: libp2p's confirmed
address is the best available signal for our TCP advertisement.

**Verification.** Two test suites together cover the full path. A
`multi_thread` test in `network/mod.rs` builds a real `Network`, calls the
`test_on_external_addr_confirmed` seam (which runs the real `multiaddr_to_tcp_socket`
parse and `last_external_addr` change-only gate), and asserts the ENR seq
advances exactly once across two identical multiaddr confirmations. A companion
test in `discovery/service.rs` directly exercises `handle_discovery_command` +
`update_local_enr_socket`, asserting the ENR tcp4 socket and seq. Unit tests for
`multiaddr_to_tcp_socket` cover IPv4, IPv6, no-TCP, UDP/QUIC-only, and
multi-IP (rejected) inputs.

### D-gossipsub-peer-scoring — native gossipsub v1.1 peer scoring (Pharos-tuned)

**Finding 3.** Pharos built `gossipsub::Behaviour` without ever calling
`with_peer_score`, so libp2p's native gossipsub v1.1 peer-scoring engine was
dormant: no mesh pruning by score, no graylist, no opportunistic grafting. The
only scoring in play was the in-house `RealScorer` (`scoring.rs`), which records
a `gossip` component from validator verdicts. This ADR activates native
gossipsub v1.1 scoring with **Pharos-tuned** parameters and reconciles it with
`RealScorer` so the same gossip event is never penalised twice.

**Spec basis (what the spec does and does NOT mandate).** `specs/phase0/p2p-interface.md:439-455`
prescribes only the gossip **topology / decay-interval** params: `D=8`,
`D_low=6`, `D_high=12`, `D_lazy=6`, `heartbeat_interval=0.7s`, `fanout_ttl=60s`,
`mcache_len=6`, `mcache_gossip=3`, `seen_ttl=SLOT_DURATION_MS*SLOTS_PER_EPOCH*2//1000`.
These already live in `gossip/config.rs::gossipsub_config`. The same section
(lines 452-455) states the v1.1 **peer-scoring** params (topic weights, decays,
thresholds) are "currently under investigation and will be specified ... when
they are ready" — i.e. **there is no spec-mandated numeric scoring table**. The
spec only says clients *MAY* descore (`p2p-interface.md:519`). Therefore the
numeric weights/decays/thresholds below are a deliberate **Pharos-tuned** choice;
Lighthouse's `beacon_chain/src/gossipsub_scoring_parameters.rs` is used as a
cross-check reference only, and every deviation from it is documented inline.

**Decay interval (decision: 1 s, the engine minimum).** The spec heartbeat is
0.7 s (`p2p-interface.md:443`) and the original intent was to pin `decay_interval`
to it. The pinned gossipsub crate (libp2p-gossipsub 0.49.4) however **rejects any
`decay_interval < 1 s`** (`PeerScoreParams::validate` → "Invalid decay_interval;
must be at least 1s"), so `with_peer_score` would fail at construction with a
700 ms interval. The engine therefore clamps the choice: Pharos uses **1 s**, the
smallest interval the engine accepts and the closest it permits to the heartbeat
tick. This is verified by the construction path (every `Network::build` calls
`with_peer_score`, and three `network::tests` build a live `Network`) plus
`config::tests::peer_score_params_validate`. Lighthouse uses the slot duration as
its decay base; Pharos uses 1 s as the base and expresses all longer decays
(epoch, 10-epoch) relative to it via `score_parameter_decay_with_base`.
`retain_score` is `SLOTS_PER_EPOCH * SLOT_DURATION` (one epoch) so a disconnected
peer's counters survive a brief flap but not a long absence.

**`PeerScoreThresholds` (Pharos-tuned, validated ordering).** The five
thresholds, with the engine's invariant
`graylist <= publish <= gossip <= 0 <= accept_px, opportunistic_graft`:
- `gossip_threshold = -4000.0` — below this we stop emitting/relaying IHAVE
  gossip to the peer.
- `publish_threshold = -8000.0` — below this we stop including the peer when
  flood-publishing / picking fanout peers.
- `graylist_threshold = -16000.0` — below this gossipsub ignores the peer's
  RPCs entirely (effective graylist). This is the native analogue of the
  `RealScorer` `BAN_THRESHOLD`; the two operate on different score spaces (native
  topic-weighted vs `RealScorer` flat event weights) and are intentionally
  independent (see §double-penalty).
- `accept_px_threshold = 100.0` — only peers above this positive score have
  their Peer-eXchange (PX) suggestions trusted; bootstrappers/long-lived good
  peers clear it.
- `opportunistic_graft_threshold = 5.0` — a small positive median-mesh score
  that triggers opportunistic grafting to lift mesh quality.
These magnitudes are scaled to the topic-weighted score space (topic weights of
order 0.5-0.8 times caps/counters of order 10^2-10^3 yield per-topic
contributions in the thousands), so the thresholds are in the thousands rather
than the tens that `RealScorer` uses. The ordering is asserted by a unit test
(`config::tests::thresholds_are_ordered`) in addition to the engine's own
`PeerScoreThresholds::validate`.

**`PeerScoreParams` (global, Pharos-tuned).**
- `topic_score_cap = 3200.0` — caps the *positive* aggregate topic contribution
  so a peer cannot farm unbounded positive score from many topics; chosen so a
  well-behaved peer on the high-weight `beacon_block` topic plus several subnets
  saturates near, not far above, the cap.
- `app_specific_weight = 1.0` — the multiplier applied to the per-peer
  application score fed via `set_application_score`. Pharos currently feeds **0**
  here (the app-specific bridge is out of this phase's scope), so this weight is
  inert today; it is left at unity so that if/when a future phase bridges
  `RealScorer::score` into `set_application_score`, the contribution is 1:1.
- `ip_colocation_factor_weight = -8.0`, `ip_colocation_factor_threshold = 10.0` —
  penalise more than `ip_colocation_factor_threshold` peers sharing one IP
  (sybil/colocation mitigation), quadratic in the excess. Threshold 10 tolerates
  NAT/datacenter colocation; weight -8 makes a colocation cluster expensive.
- `behaviour_penalty_weight = -16.0`, `behaviour_penalty_threshold = 6.0`,
  `behaviour_penalty_decay = decay(10 epochs)` — penalise protocol misbehaviour
  (re-GRAFT before backoff, unfulfilled IWANT) quadratically past a tolerance of
  6 incidents, decaying slowly (10 epochs) so persistent griefers accumulate.
- `decay_to_zero = 0.01` — a counter below 1% of its peak is treated as 0.
- `slow_peer_weight = -2.0`, `slow_peer_threshold = 0.0`,
  `slow_peer_decay = decay(10 epochs)` — native penalty for peers that cannot
  keep up with delivery. **This subsumes the former `RealScorer`
  `ScoreEvent::SlowPeer` penalty** (see §double-penalty).
Deviations from Lighthouse: Lighthouse derives many of these from the active
slot duration and a target validator/peer count; Pharos picks fixed,
preset-independent magnitudes for the global params and only scales the
per-interval *decays* via the preset (through `decay()` over epoch durations),
because Pharos has no equivalent of Lighthouse's validator-count tuning input at
network-construction time.

**`TopicScoreParams` (per-topic, Pharos-tuned).** Built by
`topic_score_params<E>(kind)` keyed on `GossipTopicKind`. The load-bearing
decision is the **relative topic weights**, asserted by unit test:
- `beacon_block`: `topic_weight = 0.8` — the highest-value topic; a peer that
  reliably first-delivers blocks earns the most mesh-quality credit, and a peer
  that delivers invalid blocks is penalised hardest. P2 (first-message) reward
  cap is small (the topic is low-rate: ~1 msg/slot) so the weight, not the
  counter, dominates.
- `beacon_aggregate_and_proof`: `topic_weight = 0.5`.
- `beacon_attestation_<subnet>`: `topic_weight = 0.3` — **strictly less than
  `beacon_block`** (asserted by `config::tests::beacon_block_outweighs_attestation_subnet`).
  Unaggregated attestation subnets are high-rate and individually low-value, so a
  single subnet must not let a peer out-score block delivery.
- `beacon_aggregate_and_proof`, `sync_committee_contribution_and_proof`,
  `voluntary_exit`, `proposer_slashing`, `attester_slashing`,
  `bls_to_execution_change`, `light_client_*`: low weights (0.05-0.5) reflecting
  rate and value; low-rate slashing/exit/bls topics get a small weight with a
  high `invalid_message_deliveries` penalty (any invalid here is strong evidence
  of a bad peer).
- `sync_committee_<subnet>`, `blob_sidecar_<subnet>`,
  `data_column_sidecar_<subnet>`: subnet-style weights (0.05-0.3), all `<`
  `beacon_block`.
Each topic's P2/P3 caps and the P3 `mesh_message_deliveries` threshold/decay are
sized to the topic's expected message rate (block: ~1/slot; aggregate/sync: low;
attestation/blob/column subnets: higher), with the invalid-message P4 weight
fixed strongly negative across all topics. The exact per-topic numbers are
encoded in `topic_score_params` and pass `TopicScoreParams::validate`.

**7.4 double-penalty resolution — SUBSUME gossip scoring into native gossipsub.**
Before this ADR, every gossip message verdict was penalised **twice**:
1. **Native (once enabled):** `Behaviour::report_message_validation_result(id,
   source, Accept|Reject|Ignore)` already feeds gossipsub's native P2 (first
   deliveries), P3 (mesh deliveries) and P4 (invalid-message) topic counters.
   `Behaviour::SlowPeer` feeds the native slow-peer penalty.
2. **`RealScorer`:** the verdict site also recorded `ScoreEvent::Gossip{Accept,
   Ignore,Reject}` (`network/mod.rs`) adding `W_GOSSIP_ACCEPT=+1.0`,
   `W_GOSSIP_IGNORE=-1.0`, `W_GOSSIP_REJECT=-10.0` into `PeerState.gossip`, and
   `gossipsub::Event::SlowPeer` recorded `ScoreEvent::SlowPeer` into the same
   component.

**Decision: native gossipsub v1.1 is the sole authority for gossip-quality
scoring (mesh deliveries, invalid messages, slow-peer behaviour); `RealScorer`
drops its `gossip` component entirely.** Rationale: the native engine is what
actually *acts* on gossip-quality scores — it prunes the mesh, graylists, and
opportunistically grafts based on the topic-weighted score and the thresholds
above. `RealScorer`'s flat per-event weights could never drive those mesh
decisions; they only contributed to the Pharos ban/disconnect aggregate, where
they overlapped exactly with what the native engine already measures more
precisely (per-topic, decayed, capped). Keeping both is a literal double-count.
`RealScorer` retains everything the native engine does NOT cover and that drives
Pharos's own ban/disconnect/dial-backoff machinery: **req-resp** behaviour
(`RpcSuccess`/`RpcError`/`RpcTimeout`/`RateLimitExceeded`/`InboundStreamReset`),
**handshake** failures, **dial** backoff, banned-reconnect, and
subnet-coverage/`Unsubscribed` app penalties. Division of authority:
- **Native gossipsub** → mesh membership, graylist, PX, opportunistic graft,
  and all gossip-message + slow-peer quality scoring.
- **`RealScorer`** → Pharos ban/disconnect decisions and dial backoff, fed by
  req-resp / handshake / dial / subnet-coverage signals only.

**Concrete code retired (no double-penalty remains).** At the verdict site
(`network/mod.rs`, the `gossip_tasks.join_next()` arm) the
`ScoreEvent::Gossip{Accept,Ignore,Reject}` construction and the following
`peer_manager.record_event(source, score_event)` for gossip verdicts are
removed; `report_message_validation_result` (native feed) stays. The
snappy-decode-failure path's `record_event(.., GossipReject{..})` is removed
(the `report_message_validation_result(.., Reject)` native feed stays). The
`gossipsub::Event::SlowPeer` arm no longer records `ScoreEvent::SlowPeer`
(native `slow_peer_weight` handles it). In `scoring.rs`: the `W_GOSSIP_ACCEPT`,
`W_GOSSIP_IGNORE`, `W_GOSSIP_REJECT`, and `W_SLOW_PEER_PER_MSG` constants and the
`record_at` arms for `GossipAccept`/`GossipIgnore`/`GossipReject`/`SlowPeer` are
removed; those four `ScoreEvent` variants are removed from the enum. After this,
no gossip-message verdict or slow-peer signal touches `RealScorer` at all, so the
event can only be scored by the native engine — double-penalty is structurally
impossible, not merely avoided by convention.

**SSZ-layout / persisted-score compatibility (decision: layout UNCHANGED).** The
persisted record `PeerScoreRecord` (`scoring.rs`, fixed 80 bytes:
`FixedBytes<64>` peer id + `u64 app_score_bits` + `u64 saved_at_unix_secs`)
serialises **only the `app` component** — `serialize`/`from_bytes` never read or
write `gossip` or `req_resp` (the doc comment and the
`peer_scores_roundtrip` test already assert `gossip`/`req_resp` reset to 0 on
reload). Dropping the `gossip` component therefore **does not touch the on-disk
layout at all**: the 80-byte record is unchanged, `RECORD_SIZE` stays 80, and
existing `peer_scores.ssz` files load byte-for-byte identically. To keep this
guarantee robust we **retain the `gossip: f64` field in the in-memory
`PeerState` struct** (it stays `0.0`, written by nothing) rather than deleting
it; this keeps `PeerState`'s shape and the `total()` arithmetic stable and makes
the "native owns gossip" intent explicit in the type. `total()` is changed to
`req_resp + app` (excluding the always-zero `gossip`), which is numerically
identical to the old `gossip + req_resp + app` now that `gossip` is always 0, so
no behaviour or persisted-value change results. No `from_bytes` fallback or
version bump is needed because the wire format is provably unchanged.

**Wiring.** `gossip/config.rs` gains `peer_score_params<E>() ->
(PeerScoreParams, PeerScoreThresholds)` and `topic_score_params<E>(kind:
&GossipTopicKind) -> TopicScoreParams`. `Network::build` calls
`behaviour.gossipsub.with_peer_score(params, thresholds)` immediately after the
swarm is built and before listeners are added, then — after the startup topic
set is subscribed and `topic_map` is populated — iterates the `topic_map` and
calls `gossipsub.set_topic_params(IdentTopic::new(topic.topic_str()),
topic_score_params::<E>(&topic.kind))` for each subscribed topic, so every live
mesh topic carries its tuned weights from the first heartbeat.

**Verification.** `config.rs` unit tests assert (1) `peer_score_params::<E>()`
validates (engine `PeerScoreParams::validate` + `PeerScoreThresholds::validate`
both pass), (2) threshold ordering `graylist <= publish <= gossip <= 0 <=
accept_px`, and (3) `topic_score_params` for `BeaconBlock` has a strictly greater
`topic_weight` than for a `BeaconAttestation` subnet. The full
`pharos-network` lib test suite is re-run after the `W_GOSSIP_*`/`SlowPeer`
removal; the `scoring.rs` tests that previously exercised gossip verdicts are
re-pointed to surviving negative events (req-resp / handshake) that drive the
same decay/ban/worst-peer code paths.
