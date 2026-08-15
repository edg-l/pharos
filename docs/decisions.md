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
