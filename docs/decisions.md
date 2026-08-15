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

- M3 (Altair) follow-ups:
  - `gossipsub::Event::Subscribed`/`Unsubscribed` → `PeerSubscribed`/`PeerUnsubscribed`
  - `identify::Event::Received` → `PeerIdentified`
  - `SwarmEvent::OutgoingConnectionError` → `DialFailed`
  - `SwarmEvent::ExternalAddrConfirmed` → ENR auto-update path.
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
