# M4c — LC gossip carry-ins + perf bench baseline

## Overview
M4c closes the three deferred items from the M3b/M4a/M4-perf wrap-ups:
the two real `GossipValidator` bodies for `light_client_finality_update` /
`light_client_optimistic_update` (deferred at M3b spec audit Task 9.7),
the full-node SHOULD broadcast of those two messages after each new head
(also deferred at M3b 9.7, blocked on the M4a block-ingestion loop), and
the criterion-based performance regression baseline that M4-perf called
for but did not land (Phase 5 of the perf plan was dropped after the
ledger in `docs/perf/m4-perf.md` shipped). M4-perf is assumed shipped per
commits `ffb9736` (`v0.5.0` workspace bump + tree-backed `SszList` /
`SszVector` + `Validator` cache + derive-macro rayon::join) and `760f509`
(state-level `cached_root` reuse). M4a and M4b plumbing for block
ingestion, head broadcasting, and the `HostImpl<E>` host trait stack is
also assumed shipped per `crates/pharos-node/src/block_ingestion.rs:88`
and `crates/pharos-node/src/host_impl.rs:77`.

Acceptance: the two gossip-validator methods on `HostImpl<E>` perform
real validation per `specs/altair/light-client/p2p-interface.md`; a
single new code path in the block-ingestion loop publishes the locally
computed LC updates to the existing `light_client_finality_update` and
`light_client_optimistic_update` gossip topics after each head advance
that yields a fresh update; `docs/conformance.md` row counts are
byte-identical to the post-M4-perf snapshot; the criterion bench harness
under `crates/<crate>/benches/` runs via `make bench`, captures results
to `bench-history/<commit>.json`, and ships baseline numbers for the
four required benches.

## Locked decisions (short form)

- `D-lc-gossip-validation-full-node-arm` — Implement the **full-node arm**
  of the spec (forward iff the message matches the locally computed
  update exactly), not the light-client arm. Pharos is a full node;
  re-running `process_light_client_*_update` against an in-memory
  `LightClientStore` would require carrying that store, which we do not
  do and which the spec only mandates for light clients. The local
  recompute uses the existing
  `pharos_stf::altair::light_client::create_light_client_finality_update`
  / `create_light_client_optimistic_update` helpers (verified at
  `crates/pharos-stf/src/altair/light_client.rs:1165` and `:1186`).
- `D-lc-snapshot-trait-on-host` — The validator methods read the
  "latest locally produced" finality + optimistic update via the
  existing `LightClientProvider<E>` trait already implemented on
  `HostImpl<E>` (verified at `crates/pharos-node/src/host_impl.rs:404`).
  No new trait, no new store column family. Per-message compare is
  `received == provider.light_client_*_update()` after a `tree_hash_root`
  equality short-circuit. **Open question OQ1** records the fallback if
  the snapshot is absent (e.g. first slots after checkpoint-sync).
- `D-lc-gossip-clock-window` — The "received after `signature_slot`
  propagated" IGNORE rule (third bullet of the spec's full-node section)
  is enforced as `wall_clock_ms >= start_of_slot(signature_slot)_ms +
  (SECONDS_PER_SLOT * 1000 / 3) - MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS`.
  `MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS` is the existing
  `specs/phase0/p2p-interface.md` constant (500 ms). The "1/3 slot"
  comes from `get_sync_message_due_ms` which is defined in
  `specs/altair/light-client/p2p-interface.md` as start-of-slot +
  `SECONDS_PER_SLOT / INTERVALS_PER_SLOT` (= `SECONDS_PER_SLOT / 3`).
  Both `SECONDS_PER_SLOT` and the slot epoch base come from
  `RuntimeConfig` (verified loaded in
  `crates/pharos-node/src/block_ingestion.rs:130`).
- `D-lc-broadcast-from-ingestion` — The publish call lives **inside**
  the block-ingestion loop (`run_block_ingestion_loop` at
  `crates/pharos-node/src/block_ingestion.rs:88`), immediately after
  the existing `host.on_head_change` + `head_tx.send` at lines
  `273-274`. The trigger is "the head-change resulted in a newly stored
  LC update". The `host` arg already carries
  `LightClientProvider` so the publish call uses
  `host.light_client_finality_update()` /
  `host.light_client_optimistic_update()` snapshots; the
  `NetworkCommandSender<E>` is a NEW arg threaded into the loop via
  the `IngestionEgress<E>` struct (Task 2.1). No background "LC
  publisher" task — keeping it in the ingestion loop preserves
  per-block ordering and matches Lighthouse's
  `BeaconChain::recompute_and_cache_light_client_data` placement.
- `D-lc-broadcast-timing` — **Approach (B): publish immediately,
  accept the spec SHOULD deviation.** The spec
  (`specs/altair/light-client/p2p-interface.md:358-376`) recommends
  full nodes wait `get_sync_message_due_ms()` (= `SECONDS_PER_SLOT *
  1000 / INTERVALS_PER_SLOT`, i.e. one third of a slot, ~4000 ms on
  mainnet) **after the slot start** before broadcasting
  `LightClient{Finality,Optimistic}Update`, and SHOULD NOT broadcast
  earlier. Receiving peers' clock-window IGNORE rule (Task 1.3 step 3)
  drops messages that arrive before that point. Pharos M4c publishes
  immediately from inside the block-ingestion loop and accepts that
  peers running the same check will IGNORE our early publishes.
  Rationale: solo project, no validator client yet driving the
  attestation cycle, no real peers consuming these publishes — the
  observable cost of the deviation is zero today. Rejected alternative
  (A): schedule a delayed publish via `tokio::time::sleep_until(slot_start
  + 1/3 slot)`. (A) is materially more complex because the head may
  reorg between schedule and fire, so it needs a watch-channel-based
  cancellation path; that complexity buys nothing until M4d devnet
  acceptance has real peers. Productionization deferred to **M11**
  (also listed in the M11 deferral block of `docs/decisions.md`).
- `D-lc-snapshot-write-trigger` — Block ingestion calls
  `update_light_client_snapshots` (already shipped at
  `crates/pharos-stf/src/altair/light_client.rs:748`, currently
  **unused** — verified by `rg` returning only the definition site)
  immediately after a successful `on_block` for any
  post-Altair block. Without this call the snapshots that the
  validators and the publisher rely on never get written. This is a
  consequence of M4c, not an extension of scope — the broadcasting
  deliverable explicitly assumed the snapshots exist.
- `D-bench-location-per-crate` — Criterion benches live **per-crate**
  under `crates/<crate>/benches/`, not in a top-level workspace member.
  Each bench imports types from its own crate without re-exporting them
  through an aggregator crate, matching the layout the M4-perf plan
  drafted (Task 0.2 in `docs/m4-perf-plan.md`) and the per-crate
  `[[bench]]` block convention. Specifically:
    - `crates/pharos-stf/benches/process_block.rs`
    - `crates/pharos-ssz/benches/tree_hash_beacon_state.rs`
    - `crates/pharos-network/benches/gossip_validation.rs`
    - `crates/pharos-network/benches/rpc_roundtrip.rs`
- `D-bench-history-format` — Bench results are checked into
  `bench-history/<git-short-sha>.json` (one file per measured commit);
  the format is criterion's own `--save-baseline` JSON sidecar plus a
  hand-rolled top-level `summary.json` that aggregates per-bench
  `(name, point_estimate_ns, std_dev_ns, sample_size)` tuples for
  diffing. JSON beats text-only because criterion already emits it and
  it is greppable with `jq`; Prometheus snapshots were considered and
  rejected (Prometheus is a metrics store, not a flat-file format; we
  do not run Prometheus). Plain text was rejected because field
  alignment drifts and a `diff` between commits is noisy. The
  `summary.json` is regenerated by a `scripts/bench-summary.sh` helper
  (Task 5.4) that walks the criterion output dir and emits one record
  per bench.
- `D-bench-machine` — Bench numbers MUST be recorded on the same
  `PERF_HOST` as M4-perf used (the developer's 12-core Ryzen
  workstation, per the existing `D-perf-bench-machine` ADR from M4-perf).
  Each `bench-history/<sha>.json` carries a `host` field. Across-machine
  comparisons remain explicitly out of scope; M4d devnet acceptance is
  the next milestone and uses different numbers entirely.

## Assumptions
- A1: M4-perf shipped per commits `ffb9736` + `760f509`; workspace
  version `0.5.0`; tree-backed `SszList`/`SszVector`, `Validator` cache,
  and field-level `rayon::join` in `#[derive(TreeHash)]` are all live.
  Verified by `git log --oneline -n 5`.
- A2: M4a/M4b ingestion code path is live. The block-ingestion loop at
  `crates/pharos-node/src/block_ingestion.rs:88-278` reads gossip
  blocks, runs `state_transition`, calls `on_block`, and publishes
  `HeadChange`. M4c hooks into this exact loop without restructuring it.
- A3: `criterion = "0.8"` is already a workspace dep (verified at
  `Cargo.toml:88`). The dep is unused by any current `[[bench]]` block
  (verified by `rg "criterion"` returning only the dep declarations);
  M4c is the first criterion landing.
- A4: `LightClientProvider<E>` is implemented on `HostImpl<E>` and
  exposes `light_client_finality_update()` /
  `light_client_optimistic_update()` returning
  `Option<E::AltairLightClientFinalityUpdate>` /
  `Option<E::AltairLightClientOptimisticUpdate>` (verified at
  `crates/pharos-node/src/host_impl.rs:444-465`).
- A5: `update_light_client_snapshots` in
  `crates/pharos-stf/src/altair/light_client.rs:748` is the canonical
  STF helper that builds and persists all four LC snapshot kinds for a
  given (post_state, block, attested_*, finalized_block) tuple. It is
  not yet called from anywhere (verified by `rg` returning only its
  definition). M4c wires it from block ingestion. Its signature carries
  fifteen const generics + `E: EthSpec` + `S: Store<E>`; the call site
  passes the same const generics that
  `crates/pharos-stf/src/altair/state_transition.rs` already passes for
  Altair operations (no new monomorphisation).
- A6: `NetworkHandle::publish(topic, payload)` accepts any `impl Encode`
  and returns `Result<MessageId, NetworkError>` (verified at
  `crates/pharos-network/src/handle.rs:221-237`). `NetworkHandle<E>`
  is non-`Clone`; the clonable producer is `NetworkCommandSender<E>`
  (verified at `crates/pharos-network/src/handle.rs:31-32`), which
  currently exposes `send` + `request` but not `publish`. Task 2.0
  adds `NetworkCommandSender::publish` (accepts a pre-encoded
  `Vec<u8>` payload, forwards a `NetworkCommand::Publish` via
  oneshot). The
  `light_client_finality_update` and `light_client_optimistic_update`
  gossip topics already exist as `GossipTopicKind::LightClientFinalityUpdate`
  and `GossipTopicKind::LightClientOptimisticUpdate` (verified at
  `crates/pharos-network/src/topics.rs:46-49`).
- A7: `MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS = 500` is the spec constant
  from `specs/phase0/p2p-interface.md`. It is NOT currently defined as
  a named constant in the workspace (`rg` confirms no match in
  `crates/pharos-types` or `crates/pharos-utils`); M4c adds it in
  `crates/pharos-types/src/phase0/primitives.rs` as a `pub const`
  alongside the other phase-0 spec constants (Task 1.1).
- A8: `SECONDS_PER_SLOT` is on `RuntimeConfig` (verified by `rg` against
  `crates/pharos-types/src/config.rs`); the validator needs read access
  to it. The `HostImpl<E>` constructor at
  `crates/pharos-node/src/host_impl.rs:98` does NOT currently take a
  `RuntimeConfig`; Task 1.2 adds one optional field
  (`runtime_cfg: Arc<RuntimeConfig>`) constructed at the same time as
  `fork_schedule`. Existing call sites (`main.rs` cold start, unit
  tests in `host_impl.rs` lines `477-500`) are updated. The genesis
  time for the slot-window check is read from the existing
  `fork_choice: Arc<RwLock<Store<E>>>` field
  (`Store.genesis_time`, `crates/pharos-fork-choice/src/store.rs:44`);
  `RuntimeConfig` has no `min_genesis_time` field and is not the source.
- A9: Each `[[bench]]` block requires `harness = false`; criterion's
  custom main is invoked via `criterion_group!` / `criterion_main!`.
  Verified from the criterion 0.8 docs (https://docs.rs/criterion/0.8).
- A10: A canonical "post-Altair" `BeaconState` fixture for benches is
  available from `~/.cache/pharos-spec-tests/mainnet/altair/genesis/`
  (a `genesis.ssz_snappy` file per the consensus-spec-tests v1.6.1
  layout). The bench harness decodes it once at startup via
  `<E as EthSpec>::BeaconState::from_ssz_bytes`. If the fixture is
  absent, the bench `panic!`s with a clear message rather than
  silently passing — Task 5.1 documents the bench-startup contract.
- A11: There is currently no `validate_full_lc_update_recompute_matches`
  unit test for the gossip validators (the methods are stubs returning
  `Accept`). Task 1.4 adds the first such tests.
- A12: `head_tx`/`payload_tx` are already threaded into the ingestion
  loop (verified at `block_ingestion.rs:94-95`); adding a third channel
  for the network handle does NOT exceed the
  `#[allow(clippy::too_many_arguments)]` already on the function (line
  `87`).
- A13: `git rev-parse --short HEAD` is the source of the
  `bench-history` filename's `<sha>` segment; the bench-record script
  reads it via `std::process::Command` (no extra dep).

## Out of Scope
- Light-client client mode (i.e. pharos acting as a sync-protocol
  consumer rather than a server). The spec's light-client arm
  (`process_light_client_finality_update` against a local
  `LightClientStore`) is deferred to a future milestone.
- Capella+ LC types (`LightClientFinalityUpdate` post-Capella has a
  different field layout per `specs/capella/light-client/sync-protocol.md`).
  M4c only ships Altair and Bellatrix LC types because that's all the
  current EthSpec assoc types cover (`crates/pharos-types/src/eth_spec.rs:841,853`).
- LC sync committee BLS aggregate verification on the gossip path.
  The existing `validate_light_client_update` STF helper (`light_client.rs:286`)
  performs all spec validation **except** the BLS aggregate; that
  follows the M3b decision `D-sync-aggregate-bls` (BLS verified by the
  block STF, not in LC gossip). The full-node arm we implement
  short-circuits via `received == locally_computed` and therefore does
  not need to re-verify BLS.
- Devnet bench validation (M4d). M4c records bench numbers; M4d's
  cross-client acceptance gate consumes them as baseline.
- Continuous benchmarking / CI bench-gate / regression detection on
  PRs. M4c lands the harness + the first numbers; automated drift
  detection is a follow-up (rough M11).
- Custom benchmark targets for `process_epoch` / `process_slots` /
  `state_transition_full`. M4c benches exactly the four roadmap
  bullets: `process_block`, `hash_tree_root(BeaconState)`, gossip
  validation latency, req-resp roundtrip.
- Removing the `update_light_client_snapshots` const-generic surface.
  The fifteen const generics stay; M4c just wires the existing fn.

## Existing Patterns
- `crates/pharos-node/src/host_impl.rs:380-393` — the two stub
  validator methods we replace.
- `crates/pharos-node/src/host_impl.rs:444-465` — `LightClientProvider`
  read methods we re-use from inside the new validator bodies.
- `crates/pharos-network/src/handle.rs:221-237` — `NetworkHandle::publish`
  signature for the broadcast call.
- `crates/pharos-stf/src/altair/light_client.rs:748` — STF helper to
  call after each `on_block`.
- `crates/pharos-stf/src/altair/light_client.rs:1165,1186` — local
  recompute helpers used inside the validator bodies.
- `crates/pharos-network/src/topics.rs:46-49,179-181` —
  `GossipTopicKind::LightClient{Finality,Optimistic}Update` and their
  wire-name mapping.
- `crates/pharos-node/src/block_ingestion.rs:88-275` — the loop we
  extend with snapshot updates + publish.
- `docs/m4b-plan.md` — phase shape, decision-key naming, audit-task
  convention.
- `docs/decisions.md:1266+` — M4b ADR template (`### D-<topic> — <one-line>`
  + `**Status**: Accepted. **Date**: YYYY-MM-DD.` + paragraph +
  `Enforced in: <paths>`).
- `docs/m4-perf-plan.md:42-80` — bench-block declaration shape (`[[bench]]`
  + `harness = false` + criterion).

## Cross-cutting risks (referenced by Phase tasks)
- R1 — A locally produced LC update arriving on gossip from a peer that
  produced the same one independently must be `Accept`ed (not `Ignore`d
  as a duplicate). Mitigation: the full-node arm explicitly forwards
  exact matches; the spec says "matches locally computed one exactly"
  is the forwarding criterion, not a rejection criterion. Pinned by
  Task 1.4(a) (`validator_accepts_exact_match`).
- R2 — During the first slots after checkpoint sync the local LC
  snapshots are absent (`update_light_client_snapshots` not yet called
  for any block because the post-Altair STF path may not have run
  yet). Mitigation: when `provider.light_client_*_update()` returns
  `None`, the validator returns `GossipVerdict::Ignore` and the publish
  call is a no-op. **Open question OQ1** records the alternative
  ("temporarily Accept") and picks `Ignore` as default per spec
  intent.
- R3 — `update_light_client_snapshots` is generic over fifteen const
  parameters; calling it from `run_block_ingestion_loop` requires
  another set of trait bounds that may collide with the existing 25-line
  `where` clause on the loop (`block_ingestion.rs:99-127`). Mitigation:
  wrap the snapshot call in a per-fork dispatcher (Task 2.3) that
  routes `AltairBeaconState` / `BellatrixBeaconState` to the right
  `update_light_client_snapshots` monomorphisation; the dispatcher
  lives in `pharos-stf` so the const generics are resolved inside the
  STF crate, not at the call site in `pharos-node`. Pinned by Task 2.3
  + the `cargo check -p pharos-node` checkpoint in Phase 2.
- R4 — The publish call from inside `run_block_ingestion_loop` requires
  passing the `NetworkHandle<E>` (or `NetworkCommandSender<E>`) into
  the loop. The loop is already at `clippy::too_many_arguments` (line
  87). Mitigation: collapse the new sender + the existing `head_tx`
  /`payload_tx` into a new `IngestionEgress<E>` struct (Task 2.1)
  carrying all three. This is also a future-proofing improvement
  (M5+ will add more egress channels).
- R5 — A gossip-clock-window false positive: the validator rejects a
  legitimate message because the local wall-clock is 600 ms behind the
  sender. Mitigation: the `MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS` (500 ms)
  envelope from the spec is applied on **both** sides of the inequality;
  the validator additionally accepts if the message's `signature_slot`
  is the **current** wall-clock slot or any past slot (no upper bound).
  The lower-bound check only fails for messages from "the future".
  Pinned by Task 1.4(c) (`validator_clock_window_just_past`).
- R6 — Bench results drift between toolchain versions
  (rustc 1.85 vs 1.95). Mitigation: each `bench-history/<sha>.json`
  records `rustc --version` output in the `toolchain` field; the M4d
  baseline-consumer compares only same-toolchain numbers. Recorded in
  the `summary.json` schema (Task 5.4).
- R7 — Criterion bench for gossip validation needs a real "received
  LC update" that matches a real local snapshot. Mitigation: the bench
  fixture (Task 5.2) builds both by calling the same helpers the
  ingestion path calls; the bench measures the validator method only,
  not the snapshot construction.
- R8 — The `update_light_client_snapshots` call writes to RocksDB on
  every block; ingestion latency rises. Mitigation: the call is wrapped
  in `tokio::task::spawn_blocking` matching the M3a invariant for STF
  + storage work (already noted at `block_ingestion.rs:168-181`). Bench
  numbers from Task 5.2 will quantify the actual overhead.
- R9 — The new bench `[[bench]]` blocks in `crates/pharos-stf/Cargo.toml`
  and friends bring a new compile-time dependency on criterion. The
  `make test` (workspace tests) target invokes `cargo test --workspace`
  which **includes** `--all-targets` for unit tests but NOT benches;
  verified by reading the Makefile (`make test` runs
  `cargo test --workspace -- --skip m0_acceptance`, no `--all-targets`).
  Benches are compiled only by `cargo bench`. No impact on the
  fast-test gate.
- R10 — Conformance row regression from snapshot-write side effects.
  Mitigation: snapshot writes touch only the four LC-dedicated column
  families (verified at `host_impl.rs:407-465`); they do not affect
  any data the conformance runner reads. Pinned by Phase 6's
  `make conformance` re-run gate (byte-identical row counts).

## Implementation Plan

### Phase 0 — Spec re-read + decision freeze + ADR stubs
Why this phase: every later phase references the exact spec wording for
the IGNORE/REJECT rules and the create_light_client_* helpers' return
types; landing this read first prevents drift mid-implementation. Also
freezes the open questions so Phase 1 has clean defaults.

- [ ] Task 0.1: Re-read
  `~/dev/consensus-specs/specs/altair/light-client/p2p-interface.md`
  lines covering `light_client_finality_update` and
  `light_client_optimistic_update` (the full-node arm bullets).
  Confirm the exact wording: "matches the locally computed one
  exactly". Confirm the `get_sync_message_due_ms` definition references
  `SECONDS_PER_SLOT / INTERVALS_PER_SLOT` and that
  `INTERVALS_PER_SLOT = 3`. No code change.
- [ ] Task 0.2: Re-read
  `~/dev/consensus-specs/specs/altair/light-client/full-node.md`
  end-to-end for `create_light_client_finality_update` and
  `create_light_client_optimistic_update`. Confirm both helpers take a
  `LightClientUpdate` (not raw state/block) and project it down. This
  matches the existing pharos signatures at `light_client.rs:1165,1186`.
  No code change.
- [ ] Task 0.3: Re-read `docs/m4b-plan.md` lines 1–250 for phase shape
  + decision-key style; this plan must mirror that template. No code
  change.
- [ ] Task 0.4: Open `docs/decisions.md` and append a new section header
  `## M4c decisions` after the M4b section closing line (currently the
  last decision before line 1545 — confirm by `tail`). Reserve the
  seven ADR stubs (`D-lc-gossip-validation-full-node-arm`,
  `D-lc-snapshot-trait-on-host`, `D-lc-gossip-clock-window`,
  `D-lc-broadcast-from-ingestion`, `D-lc-snapshot-write-trigger`,
  `D-bench-location-per-crate`, `D-bench-history-format`) as bare
  headings with `Status: Draft. Date: 2026-05-27.`; bodies filled at
  Phase 6 wrap-up. Commit message: `docs(m4c): freeze decisions skeleton`.

**Checkpoint: Verify Phase 0 complete.** Review Tasks 0.1–0.4. Confirm
`docs/decisions.md` has seven new `### D-*` stubs all marked `Draft`.
List each stub and its status. Do not proceed until all are done.

### Phase 1 — LC gossip validator bodies
Why this phase: smallest blast radius; touches only `host_impl.rs` and
adds one new spec-constant module entry. No network or storage changes
yet. Lands the validator logic so Phase 2 can rely on it being correct
before wiring broadcasting.

- [ ] Task 1.1: Add `pub const MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS: u64 = 500;`
  and `pub const INTERVALS_PER_SLOT: u64 = 3;` to
  `crates/pharos-types/src/phase0/primitives.rs` (place after the
  existing `ATTESTATION_SUBNET_COUNT` const). Re-export from
  `crates/pharos-types/src/lib.rs` if `pub use phase0::primitives::*;`
  is not already there (it is — verified by `rg`).
- [ ] Task 1.2: Modify `crates/pharos-node/src/host_impl.rs:77-89` to
  add a private field `runtime_cfg: Arc<pharos_types::config::RuntimeConfig>`
  to `HostImpl<E>`. Modify
  `HostImpl::new` at line `98-136` to accept
  `runtime_cfg: Arc<RuntimeConfig>` as an additional argument (place
  after `current_fork_version`); store it in the new field. Update both
  call sites:
  (a) `crates/pharos-node/src/main.rs` (search for `HostImpl::new` —
      only one match — and thread the `runtime_cfg` already in scope),
  (b) `crates/pharos-node/src/host_impl.rs:477-500` `make_host` test
      helper (build a `RuntimeConfig::default()` inside the helper).
  No other behaviour change in this task. Also add two private
  `std::sync::atomic::AtomicU64` fields to `HostImpl<E>`:
  `last_forwarded_finality_slot: AtomicU64` and
  `last_forwarded_optimistic_slot: AtomicU64` (both initialised to `0`
  in `HostImpl::new`). These back the first IGNORE rule from
  `specs/altair/light-client/p2p-interface.md` (the message's
  `finalized_header.beacon.slot` for the finality topic, and
  `attested_header.beacon.slot` for the optimistic topic, MUST be
  strictly greater than all previously forwarded values for that
  topic). All loads/stores use `Ordering::Relaxed`; the
  compare-and-swap pattern lives in Tasks 1.3 / 1.4.
- [ ] Task 1.3: Replace the body of
  `crates/pharos-node/src/host_impl.rs:380-385`
  (`validate_light_client_finality_update`) with the full-node arm:
    1. Read `local = self.light_client_finality_update()`. If `None`,
       return `GossipVerdict::Ignore` (R2 default per OQ1).
    2. **First IGNORE rule (per-topic monotonic forwarded slot).** Read
       `prev = self.last_forwarded_finality_slot.load(Ordering::Relaxed)`
       and `incoming = msg.finalized_header.beacon.slot.0`. If
       `incoming <= prev`, return `GossipVerdict::Ignore` (the spec
       requires strictly greater than any previously forwarded
       finality update's slot). Otherwise, after all subsequent checks
       pass and just before returning `Accept`, perform a relaxed
       compare-and-swap via
       `self.last_forwarded_finality_slot.compare_exchange(prev,
       incoming, Ordering::Relaxed, Ordering::Relaxed)` — on CAS
       failure (a concurrent gossip thread won the race with a higher
       slot) re-load and re-check; if `incoming` is still strictly
       greater, retry the CAS, else return `Ignore`.
    3. Use `pharos_ssz::TreeHash`; compare
       `local.tree_hash_root() == msg.tree_hash_root()`. On mismatch
       return `GossipVerdict::Ignore` (not `Reject` — the spec marks
       all three bullets as `[IGNORE]`).
    4. Compute slot-window check:
       `now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis()`,
       `genesis_ms = self.fork_choice.read().genesis_time * 1000`
       (the fork-choice `Store.genesis_time` at
       `crates/pharos-fork-choice/src/store.rs:44` is the canonical
       seconds-since-epoch genesis; `HostImpl<E>` already holds
       `fork_choice: Arc<RwLock<Store<E>>>`, no new field needed),
       `slot_start_ms = genesis_ms + msg.signature_slot.0 * self.runtime_cfg.seconds_per_slot * 1000`,
       `due_ms = slot_start_ms + (self.runtime_cfg.seconds_per_slot * 1000) / INTERVALS_PER_SLOT`.
       Require `now_ms + MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS >= due_ms`;
       on failure return `GossipVerdict::Ignore`.
    5. Perform the deferred CAS from step 2 (commit
       `last_forwarded_finality_slot = incoming`), then return
       `GossipVerdict::Accept`.
  Remove the `TODO(M4)` doc comment; replace with a doc paragraph
  citing `specs/altair/light-client/p2p-interface.md` and
  `D-lc-gossip-validation-full-node-arm`.
- [ ] Task 1.4: Replace the body of
  `crates/pharos-node/src/host_impl.rs:388-393`
  (`validate_light_client_optimistic_update`) with the parallel
  full-node arm using `self.light_client_optimistic_update()`. The
  spec uses `optimistic_update.signature_slot` for the timing window
  (same field name); the snapshot equality check uses
  `tree_hash_root` exactly as in Task 1.3. Same `Ignore`-on-`None`
  default. Same doc comment swap. Apply the parallel first-IGNORE
  rule using `self.last_forwarded_optimistic_slot` against
  `msg.attested_header.beacon.slot.0` (per the spec the optimistic
  topic's monotonic field is `attested_header.beacon.slot`, NOT
  `finalized_header.beacon.slot`).
- [ ] Task 1.5: Add seven `#[test]` functions to the existing
  `mod tests` block at `crates/pharos-node/src/host_impl.rs:471`:
  (a) `validator_accepts_exact_match_finality` — construct a fake
      `LightClientFinalityUpdate`, write it to the LC finality CF via
      `put_light_client_finality_update`, call
      `validate_light_client_finality_update(&msg)` with the same
      bytes, assert `Accept`.
  (b) `validator_ignores_when_snapshot_absent_finality` — fresh store,
      call validator, assert `Ignore`.
  (c) `validator_clock_window_just_past_finality` — fixture where
      `signature_slot` puts `due_ms == now_ms`, assert `Accept`;
      `signature_slot` putting `due_ms == now_ms + 1000` (1s in
      the future), assert `Ignore`.
  (d) `validator_accepts_exact_match_optimistic` — same as (a) but
      for the optimistic topic.
  (e) `validator_clock_window_just_past_optimistic` — same as (c) but
      for the optimistic topic.
  (f) `validator_ignores_non_monotonic_finality` — two sequential calls
      with the same `finalized_header.beacon.slot`: first `Accept`,
      second `Ignore`. Then a third call with a strictly greater slot:
      `Accept`. Confirms the per-topic monotonic CAS.
  (g) `validator_ignores_non_monotonic_optimistic` — parallel to (f)
      using `attested_header.beacon.slot` and
      `last_forwarded_optimistic_slot`.
- [ ] Task 1.6: `make check && make lint && make test` (single
  invocation, output to `target/test-logs/m4c-phase1.log`). Confirm
  zero new warnings, all seven new tests pass, no regressions.

**Checkpoint: Verify Phase 1 complete.** Review Tasks 1.1–1.6. Confirm:
two constants added; `HostImpl` carries `runtime_cfg`; both validator
methods removed `TODO(M4)` and contain real logic referencing
`light_client_*_update()`; seven new tests green; `target/test-logs/m4c-phase1.log`
shows pass=N, fail=0. **Commit boundary:** `feat(node): real LC gossip validation per altair p2p-interface`.

### Phase 2 — LC snapshot write + broadcast wiring
Why this phase: Phase 1's validator bodies depend on snapshots
existing in the RocksDB CFs; they are not currently written. Wire
`update_light_client_snapshots` into the ingestion loop, then publish
the two updates after each head change.

- [ ] Task 2.0: Add a `publish` method to `NetworkCommandSender<E>` in
  `crates/pharos-network/src/handle.rs` (mirror the existing
  `NetworkHandle::publish` at lines `221-237` byte-for-byte, including
  its `<impl Encode>` payload binding and internal `.as_ssz_bytes()`
  encode step; mirror the channel scaffolding from
  `NetworkCommandSender::request` at lines `49-68`). Signature:
  ```
  pub async fn publish(
      &self,
      topic: GossipTopic,
      payload: &impl pharos_ssz::Encode,
  ) -> Result<libp2p::gossipsub::MessageId, NetworkError> {
      let ssz_payload = payload.as_ssz_bytes();
      let (reply_tx, reply_rx) = oneshot::channel();
      self.0
          .send(NetworkCommand::Publish { topic, ssz_payload, reply: reply_tx })
          .await
          .map_err(|_| NetworkError::ChannelClosed)?;
      reply_rx.await.map_err(|_| NetworkError::ChannelClosed)?
  }
  ```
  Required imports inside `handle.rs` already cover `GossipTopic`,
  `NetworkCommand`, `NetworkError`, `oneshot`, and `pharos_ssz::Encode`
  (imported at `handle.rs:15`). Rationale: `NetworkHandle<E>`
  is non-`Clone` (owns the event `mpsc::Receiver`, see
  `handle.rs:1-9, 82-102`), so the ingestion loop must use the clonable
  `NetworkCommandSender<E>` for publish — but `NetworkCommandSender`
  currently exposes only `send` and `request`. The `<impl Encode>`
  binding (rather than a pre-encoded `Vec<u8>`) matches `NetworkHandle::publish`
  exactly so Task 2.4 can pass `&fu` / `&ou` directly without an
  intermediate `.as_ssz_bytes()` at the call site. Failure surfaces:
  `mpsc::Sender::send` errors map to `NetworkError::ChannelClosed`;
  `oneshot::Receiver::await` errors map to `NetworkError::ChannelClosed`
  as well — identical to the `NetworkHandle::publish` failure semantics.
  Publish failures are NOT silent: Task 2.4 logs each via `warn!`.
  This task is the pre-requisite for Task 2.4.
- [ ] Task 2.1: Define a new struct
  `IngestionEgress<E: EthSpec>` in
  `crates/pharos-node/src/block_ingestion.rs` (just above
  `run_block_ingestion_loop`) carrying:
    - `head_tx: watch::Sender<Option<HeadChange>>`,
    - `payload_tx: mpsc::Sender<NewPayloadRequest<E>>`,
    - `network: pharos_network::NetworkCommandSender<E>` (NEW;
      `NetworkCommandSender<E>` is `Clone`, so no `Arc` wrapper is
      needed — see `crates/pharos-network/src/handle.rs:31-32` for the
      `#[derive(Clone)]`).
  Convert the loop signature to accept `egress: IngestionEgress<E>`
  in place of the current `head_tx, payload_tx` pair. Update the one
  call site in `crates/pharos-node/src/main.rs:583-597` to build the
  struct from the existing `head_tx_clone`, `payload_tx_clone`, and a
  clone of the existing `command_sender` already used at
  `main.rs:536,547,608` (matching the
  `network_backfill_provider.rs:608` pattern). No `NetworkHandle<E>`
  clone is involved anywhere in this plan.
- [ ] Task 2.2: Inside `run_block_ingestion_loop`, immediately after
  the existing `on_block_outcome` success path at
  `block_ingestion.rs:228-231` and **before** the
  Bellatrix payload push at line `233`, add a call to a new
  per-fork dispatcher `dispatch_update_light_client_snapshots::<E, _>(
  &post_state, &signed_block, &fc_store_handle, &*self.store)` (see
  Task 2.3 for the dispatcher). Wrap in `tokio::task::spawn_blocking`
  per the M3a invariant (R8) AND `.await` the returned `JoinHandle`
  before the next step (matching the existing STF
  `spawn_blocking` pattern at `block_ingestion.rs:172-181`). On
  `JoinError` log via `tracing::warn!(error = %e, "lc snapshot
  dispatch task failed")` and continue. **Do not discard the
  handle** — the publish step (Task 2.4) and any later reader rely on
  the snapshot CF being written before they run; dropping the handle
  introduces a read-before-write race.
- [ ] Task 2.3a: Extend `EthSpec` (in `crates/pharos-types/src/eth_spec.rs`)
  with two new trait methods mirroring the existing
  `unwrap_bellatrix_block` (at `eth_spec.rs:496, 1206, 1685`) but for the
  earlier forks:
  ```
  fn unwrap_phase0_block(s: &Self::BeaconBlock) -> Option<&Self::Phase0BeaconBlock>;
  fn unwrap_altair_block(s: &Self::BeaconBlock) -> Option<&Self::AltairBeaconBlock>;
  ```
  Both project the unsigned `E::BeaconBlock` fork-enum to the
  per-fork unsigned concrete variant; return `None` on fork mismatch.
  Implement on both `MainnetEthSpec` (around lines `1112-1206`) and
  `MinimalEthSpec` (around lines `1591-1685`) by matching on the
  `BeaconBlock` enum variant — identical pattern to the existing
  `unwrap_bellatrix_block` impls. Rationale: `Store.blocks` is
  `HashMap<Root, E::BeaconBlock>` (unsigned blocks, verified at
  `crates/pharos-fork-choice/src/store.rs:79`); Task 2.3's dispatcher
  fetches from this map and needs unsigned projections. The signed
  variants `unwrap_*_signed_block` already exist (lines `429, 437, 474`)
  but are wrong here — the store does NOT hold signed blocks.
- [ ] Task 2.3b: Change the signatures of
  `pharos_stf::altair::light_client::update_light_client_snapshots`
  (definition at `crates/pharos-stf/src/altair/light_client.rs:748`) and
  `pharos_stf::altair::light_client::block_to_light_client_header`
  (definition at `light_client.rs:551`) and
  `pharos_stf::altair::light_client::create_light_client_bootstrap`
  (definition at `light_client.rs:912`) and
  `pharos_stf::altair::light_client::create_light_client_update`
  (definition at `light_client.rs:1005`) so the `block` /
  `attested_block` / `finalized_block` parameters take
  `&BeaconBlock<...>` (unsigned) instead of `&SignedBeaconBlock<...>`.
  Justification (verified in the helper bodies): each helper accesses
  the block only via `block_to_light_client_header(block)`, which in
  turn reads `block.message.{slot, proposer_index, parent_root,
  state_root, body.tree_hash_root()}` (verified at
  `light_client.rs:585-594`). The signature field is never read.
  Update each helper body to dereference fields off `block` directly
  rather than `block.message`. Update every internal/test call site
  (`rg "block_to_light_client_header\|create_light_client_bootstrap\|create_light_client_update\|update_light_client_snapshots"` against
  `crates/pharos-stf/`) to pass `&signed.message` instead of `&signed`
  where the caller still holds a `SignedBeaconBlock`. Rationale: the
  STF helper signature should match the data the only call site
  (Task 2.3 dispatcher) actually has — `fc_store.blocks` stores
  unsigned blocks. Option (b) chosen over Option (c)-alone because
  Option (c) by itself doesn't bridge the signed/unsigned gap; this
  rewrite removes the gap entirely. (Task 2.3a is still useful: the
  dispatcher needs the per-fork unsigned-block projection.)
- [ ] Task 2.3: Create
  `crates/pharos-stf/src/altair/light_client_dispatch.rs` exposing
  `pub fn dispatch_update_light_client_snapshots<E, S>(post_state: &E::BeaconState, signed_block: &E::SignedBeaconBlock, fc_store: &Store<E>, store: &S) where E: EthSpec, S: Store<E>, /* plus the fifteen-const-generic projection bounds on E::AltairBeaconState that `update_light_client_snapshots` requires — see the `where` clause on `pharos_stf::state_transition` in `crates/pharos-stf/src/altair/state_transition.rs` for the template */`.
  Match on the fork-enum variant of `post_state`:
  - **Phase 0** → no-op (LC types are Altair-onward).
  - **Altair** arm:
    1. `attested_root = extract_parent_root::<E>(signed_block)`
       (re-use the helper at `block_ingestion.rs:286`; or, inside
       `pharos-stf`, project via `E::unwrap_altair_signed_block(signed_block)`
       then read `.message.parent_root`).
    2. `finalized_root = post_state.finalized_checkpoint().root`
       (project via `E::unwrap_altair_state(post_state)` first).
    3. `current_block_unsigned = E::unwrap_altair_block(&signed_block_unsigned)`
       where `signed_block_unsigned` is obtained from
       `signed_block` by reading `.message` after first projecting
       `E::unwrap_altair_signed_block(signed_block)` (signed → altair
       signed → altair unsigned). The point is to feed the rewritten
       Task 2.3b helper, which now takes unsigned blocks.
    4. `attested_block_enum = fc_store.blocks.get(&attested_root)` —
       `Option<&E::BeaconBlock>` (UNSIGNED; per `store.rs:79`).
    5. `attested_state_enum = fc_store.block_states.get(&attested_root)`
       — `Option<&E::BeaconState>`.
    6. `finalized_block_enum = fc_store.blocks.get(&finalized_root)` —
       `Option<&E::BeaconBlock>` (UNSIGNED).
    7. For each `Some(...)` from steps 4-6, project via
       `E::unwrap_altair_block` (NEW in Task 2.3a) for blocks, and
       `E::unwrap_altair_state` (existing) for state, to the
       per-fork concrete unsigned types
       `update_light_client_snapshots` (post Task 2.3b) expects.
       `None` enums and unwrap-mismatch (Some-but-wrong-fork; e.g.
       attested parent is still Phase 0 across the fork boundary)
       propagate as `None` per
       `light_client.rs:856-857` (`attested_state.zip(attested_block)`).
    8. Call
       `update_light_client_snapshots(post_state_altair_concrete,
       current_block_altair_concrete, attested_state_altair_concrete,
       attested_block_altair_concrete, finalized_block_altair_concrete,
       store)`. If `attested_state` is `None`, the inner
       `LightClientUpdate` iteration is a no-op per
       `light_client.rs:856-857` (the bootstrap and optimistic-update
       writes still happen via the `block_root` path at
       `light_client.rs:848-853, 896-898`).
  - **Bellatrix** arm: identical control flow to the Altair arm, but
    project via `E::unwrap_bellatrix_signed_block` /
    `E::unwrap_bellatrix_block` (already exists at `eth_spec.rs:496`) /
    `E::unwrap_bellatrix_state` (NOT the altair unwraps — the state
    and block layouts differ even though
    `E::BellatrixLightClientFinalityUpdate` is the same Altair-shaped
    type via the EthSpec alias at
    `crates/pharos-types/src/eth_spec.rs:1332`). The match arms are
    spelled separately to make the per-fork unwrap site explicit.
  Re-export from `crates/pharos-stf/src/altair/mod.rs`. Per **R3** this
  isolates the fifteen const generics inside the STF crate.
- [ ] Task 2.4: Inside `run_block_ingestion_loop`, after the existing
  `host.on_head_change(change.clone())` + `head_tx.send` lines `273-274`,
  add (gated by `if has_lc_snapshots`, see Task 2.5):
  ```
  if let Some(fu) = host.light_client_finality_update() {
      let topic = GossipTopic { fork_digest: host.current_fork_digest(),
          kind: GossipTopicKind::LightClientFinalityUpdate };
      if let Err(e) = egress.network.publish(topic, &fu).await {
          warn!(error = %e, "lc finality update publish failed");
      }
  }
  if let Some(ou) = host.light_client_optimistic_update() {
      let topic = GossipTopic { fork_digest: host.current_fork_digest(),
          kind: GossipTopicKind::LightClientOptimisticUpdate };
      if let Err(e) = egress.network.publish(topic, &ou).await {
          warn!(error = %e, "lc optimistic update publish failed");
      }
  }
  ```
  The `host.current_fork_digest()` call resolves via the
  `pharos_network::host::ForkContext` impl on `HostImpl<E>`, verified at
  `crates/pharos-node/src/host_impl.rs:214-217`
  (`impl<E: EthSpec> ForkContext for HostImpl<E>` with
  `fn current_fork_digest(&self) -> ForkDigest`). Both arms call
  `egress.network.publish(topic, &fu)` / `(topic, &ou)` passing a
  reference to the LC update; the Task 2.0 `NetworkCommandSender::publish`
  signature now takes `&impl pharos_ssz::Encode`, so `&LightClientFinalityUpdate` /
  `&LightClientOptimisticUpdate` bind directly (both impl `pharos_ssz::Encode`
  via `#[derive(Encode)]` at their definition sites — verified by `rg`).
  Required imports: `pharos_network::topics::{GossipTopic, GossipTopicKind}`,
  `pharos_network::host::ForkContext` (brings the
  `current_fork_digest` method into scope at the call site).
- [ ] Task 2.5: Add the `has_lc_snapshots` gate. The publish only runs
  when the head block is post-Altair: read
  `host.fork_schedule().altair_fork_epoch`, derive
  `signed_block_epoch = signed_block.slot() / SLOTS_PER_EPOCH`, compare
  `signed_block_epoch >= altair_fork_epoch`. Phase 0 blocks must not
  publish LC updates. Pinned by Task 2.7(c) below.
- [ ] Task 2.6: Add `pharos-network` to `pharos-stf` dev-dependencies?
  **No** — confirm cycles: `pharos-stf` must not depend on
  `pharos-network`. The dispatcher in Task 2.3 only touches `pharos-stf`
  + `pharos-storage` + `pharos-types`; the publish call in Task 2.4 is
  in `pharos-node` (which already depends on both `pharos-network` and
  `pharos-stf`). No new cycles. Run `cargo tree -p pharos-stf` to
  confirm.
- [ ] Task 2.7: Add three integration-flavoured tests to a new file
  `crates/pharos-node/tests/lc_gossip_publish.rs`:
  (a) `snapshots_written_after_altair_block` — build a minimal Altair
      block + state pair (re-use the conformance fixtures from
      `~/.cache/pharos-spec-tests/`), run the ingestion path once,
      assert
      `<RocksStore as Store<E>>::get_light_client_finality_update`
      returns `Some`.
  (b) `publish_called_after_head_change` — wire a mock
      `NetworkHandle<E>` (matching the pattern at
      `crates/pharos-node/tests/checkpoint_backfill_pipeline.rs` mocks,
      see lines 75-130 referenced from M4b plan task 5.5), feed one
      Altair block, assert two `publish` calls observed with the right
      topic kinds.
  (c) `no_publish_for_phase0_block` — feed a Phase 0 block, assert
      zero `publish` calls.
- [ ] Task 2.8: `make check && make lint && make test` (capture to
  `target/test-logs/m4c-phase2.log`). Confirm new tests green, no
  regressions, no clippy warnings.

**Checkpoint: Verify Phase 2 complete.** Review Tasks 2.1–2.8. Confirm:
`IngestionEgress` exists; `dispatch_update_light_client_snapshots` is
exported from `pharos_stf::altair`; ingestion loop writes snapshots +
publishes both topics; three integration tests green; `make test` log
shows no regressions. **Commit boundary:** `feat(node): publish LC finality+optimistic updates after each head advance`.

### Phase 3 — Bench harness scaffolding
Why this phase: lays down the directory structure, the per-crate
`[[bench]]` blocks, and the `make bench` target before any individual
bench code is written. Splits the high-velocity bench-writing in Phase
4 from the cross-cutting harness wiring here.

- [ ] Task 3.1: Add to `crates/pharos-stf/Cargo.toml`:
  ```
  [dev-dependencies]
  criterion = { workspace = true }
  pharos-types = { path = "../pharos-types" }   # if not already there
  pharos-storage = { path = "../pharos-storage" }  # if not already there

  [[bench]]
  name = "process_block"
  harness = false
  ```
  Run `cargo check -p pharos-stf --benches` to confirm the manifest
  parses.
- [ ] Task 3.2: Add to `crates/pharos-ssz/Cargo.toml`:
  ```
  [dev-dependencies]
  criterion = { workspace = true }
  pharos-types = { path = "../pharos-types" }

  [[bench]]
  name = "tree_hash_beacon_state"
  harness = false
  ```
- [ ] Task 3.3: Add to `crates/pharos-network/Cargo.toml`:
  ```
  [dev-dependencies]
  criterion = { workspace = true }

  [[bench]]
  name = "gossip_validation"
  harness = false

  [[bench]]
  name = "rpc_roundtrip"
  harness = false
  ```
- [ ] Task 3.4: Replace the current placeholder `make bench` target
  (Makefile lines 124-126 per `tail -120`) with a real one:
  ```
  .PHONY: bench
  bench: ## Run criterion benches. Captured to $(LOGS)/bench.log. Records bench-history/<sha>.json.
  	@mkdir -p $(LOGS) bench-history
  	@: > $(LOGS)/bench.log
  	$(CARGO) bench -p pharos-stf --bench process_block 2>&1 | tee -a $(LOGS)/bench.log
  	$(CARGO) bench -p pharos-ssz --bench tree_hash_beacon_state 2>&1 | tee -a $(LOGS)/bench.log
  	$(CARGO) bench -p pharos-network --bench gossip_validation 2>&1 | tee -a $(LOGS)/bench.log
  	$(CARGO) bench -p pharos-network --bench rpc_roundtrip 2>&1 | tee -a $(LOGS)/bench.log
  	./scripts/bench-summary.sh
  ```
  The leading `@: > $(LOGS)/bench.log` truncates any prior log before
  the first bench runs, so `tee -a` on every subsequent line behaves
  consistently (no stale content leaks across `make bench`
  invocations).
- [ ] Task 3.5: Create `scripts/bench-summary.sh` (executable, `set
  -euo pipefail`, bash):
    1. `SHA=$(git rev-parse --short HEAD)`.
    2. `HOST=$(hostname)`.
    3. `TOOLCHAIN=$(rustc --version)`.
    4. Walk `target/criterion/*/new/estimates.json`, extract
       `mean.point_estimate` and `mean.standard_error` per bench id via
       `jq`.
    5. Emit `bench-history/${SHA}.json` with schema:
       ```
       { "sha": "...", "host": "...", "toolchain": "...",
         "date": "<ISO8601>",
         "benches": [
           { "name": "process_block/phase0", "ns": <number>, "stderr_ns": <number> },
           ...
         ]
       }
       ```
    6. Print the same JSON to stdout. Refuse to overwrite an existing
       file for the same SHA unless `BENCH_FORCE=1` is set.
- [ ] Task 3.6: Add the directory `bench-history/` to the repo with a
  `.gitkeep` file. Add a `bench-history/README.md` documenting the
  schema, the `BENCH_FORCE=1` override, and the `PERF_HOST` invariant
  from `D-bench-machine`. **Immediately** verify the directory is
  tracked (not ignored) by running `git status bench-history/` and
  confirming both files appear as untracked (i.e. ready to be `git
  add`'d). If either is suppressed by a `.gitignore` rule (e.g. an
  ancestor `target/` rule, an explicit `bench*` glob, or similar),
  update the offending `.gitignore` in this same task — do NOT defer
  the fix to Phase 5.
- [ ] Task 3.7: Create the four empty bench source files with the
  criterion boilerplate (just `fn criterion_benchmark(c: &mut
  Criterion) { /* TODO Phase 4 */ }` + `criterion_group!` +
  `criterion_main!`):
  (a) `crates/pharos-stf/benches/process_block.rs`,
  (b) `crates/pharos-ssz/benches/tree_hash_beacon_state.rs`,
  (c) `crates/pharos-network/benches/gossip_validation.rs`,
  (d) `crates/pharos-network/benches/rpc_roundtrip.rs`.
- [ ] Task 3.8: `cargo check --workspace --benches` (capture to
  `target/test-logs/m4c-phase3-check.log`). Confirm all four bench
  binaries compile. Do NOT yet run `make bench` (the benches are
  empty TODO stubs).

**Checkpoint: Verify Phase 3 complete.** Review Tasks 3.1–3.8. Confirm:
three Cargo.toml files have new `[[bench]]` blocks; `make bench` target
is real (not the placeholder); `bench-history/` directory exists with
README; four bench files exist as compilable stubs; `cargo check
--workspace --benches` is green. **Commit boundary:** `feat(bench): criterion harness scaffolding + bench-history layout`.

### Phase 4 — Write the four benches
Why this phase: now that the harness compiles, fill in each bench
body. Each task is one bench file; all four are independent and could
in principle parallelise but a single sequential pass keeps the diff
reviewable.

- [ ] Task 4.1: Implement
  `crates/pharos-stf/benches/process_block.rs`:
    - Setup: load three fixtures from `~/.cache/pharos-spec-tests/mainnet`:
      a Phase 0 (state, block), an Altair (state, block), a Bellatrix
      (state, block). Use `<E as EthSpec>::BeaconState::from_ssz_bytes`
      / `<E as EthSpec>::SignedBeaconBlock::from_ssz_bytes` against
      the snappy-decompressed test-vector pairs. If a fixture file is
      missing, `panic!("bench fixture missing: <path>")`.
    - Bench: three `c.bench_function` calls named
      `process_block/phase0`, `process_block/altair`,
      `process_block/bellatrix`, each calling
      `pharos_stf::state_transition::<MainnetEthSpec, NoopEngine>(
      pre_state.clone(), &signed_block, &engine, /* validate_result */ true,
      &RuntimeConfig::default())` inside the closure.
    - `NoopEngine` is a tiny in-bench struct implementing
      `pharos_stf::ExecutionEngine` with `notify_new_payload` always
      returning `PayloadStatus::Valid`. Defined inline in the bench
      file.
- [ ] Task 4.2: Implement
  `crates/pharos-ssz/benches/tree_hash_beacon_state.rs`:
    - Setup: load mainnet `BeaconState<MainnetEthSpec>` once at startup
      (same fixture loader as Task 4.1, factored into a shared helper
      module `benches/bench_helpers.rs` per Cargo's bench convention —
      add `path = "benches/bench_helpers.rs"` as a `pub mod` from a
      single file is the cargo-blessed pattern).
    - Bench: two `c.bench_function` calls:
      `tree_hash_beacon_state/altair_mainnet` (Altair state),
      `tree_hash_beacon_state/bellatrix_mainnet` (Bellatrix state).
      Each calls `state.tree_hash_root()` inside the closure. After
      the M4-perf cached_root work this hits the cached path on the
      second iteration; document the warmup in a doc comment.
    - Add a third bench
      `tree_hash_beacon_state/bellatrix_cold` that mutates one
      validator's effective_balance (via a `with_set` if accessible,
      else build a fresh state) on every iteration to defeat the
      cache; this measures the unhappy path.
- [ ] Task 4.3: Implement
  `crates/pharos-network/benches/gossip_validation.rs`:
    - Setup: build a minimal in-memory `HostImpl<MainnetEthSpec>` by
      **duplicating** the body of the existing `make_host` test helper
      (`crates/pharos-node/src/host_impl.rs:477-500`) into the bench
      file (~two dozen lines). Do NOT promote `make_host` to a
      `pub mod test_helpers` module — that would pollute the
      `pharos-node` library surface for a single bench consumer.
      Add a brief comment above the duplicated function pointing back
      to the original. Construct a valid `LightClientFinalityUpdate`
      fixture, write it to the store via
      `put_light_client_finality_update`.
    - Bench: one `c.bench_function`
      `gossip_validation/lc_finality_update` calling
      `host.validate_light_client_finality_update(&msg)`. Single
      bench for now; Phase 4 does not chase
      `validate_beacon_block` because those validators are still
      `Accept`-stubs (M5 work).
- [ ] Task 4.4: Implement
  `crates/pharos-network/benches/rpc_roundtrip.rs`:
    - Setup: spawn two `Network<E>` instances on loopback (re-use
      the integration-test scaffolding from
      `crates/pharos-network/tests/`); have them complete the Status
      handshake.
    - Bench: one `c.bench_function`
      `rpc_roundtrip/blocks_by_range_count_1` calling
      `node_a.request(node_b_peer_id, RpcRequest::BlocksByRange {
      start_slot: Slot(1), count: 1, step: 1 }, Duration::from_secs(2))`
      inside the closure. The peer responds via the
      `BlockProvider::blocks_by_range` impl on `node_b`'s host (which
      will return an empty Vec — the bench measures the wire roundtrip
      cost, not body fetching).
    - Build the tokio runtime ONCE in the bench setup block
      (`let rt = tokio::runtime::Runtime::new().unwrap();` outside the
      `c.bench_function` closure); inside the closure call
      `rt.block_on(async { ... })`. Building a fresh `Runtime` on every
      criterion sample would create thousands of runtimes per bench
      run and dominate the wire-roundtrip measurement; criterion's
      docs flag this exact anti-pattern.
- [ ] Task 4.5: Run `cargo check -p pharos-stf -p pharos-ssz -p
  pharos-network --benches` (capture to
  `target/test-logs/m4c-phase4-check.log`). All four bench targets
  must compile.

**Checkpoint: Verify Phase 4 complete.** Review Tasks 4.1–4.5. Each
bench file MUST contain real `c.bench_function` calls (no `TODO`
stubs). Confirm `cargo check ... --benches` green. **Commit boundary:**
`feat(bench): process_block, tree_hash, gossip validation, rpc roundtrip benches`.

### Phase 5 — First baseline run + numbers committed
Why this phase: with the harness real, record the baseline numbers
that M4d will compare against. Single bench run on `PERF_HOST` per
`D-bench-machine`.

- [ ] Task 5.1: Run `make bench` once on the `PERF_HOST` (12-core Ryzen,
  see `D-bench-machine` in `docs/decisions.md:M4-perf`). Output is
  captured by the Makefile to `target/test-logs/bench.log` and
  `bench-history/<sha>.json` is auto-generated by the
  `scripts/bench-summary.sh` post-step. Single invocation; if it
  fails for one bench, fix that bench in Phase 4 and re-run (do NOT
  partial-commit). Total wall budget ~5 minutes (criterion default of
  100 samples × four benches).
- [ ] Task 5.2: Inspect `bench-history/<sha>.json`. Confirm:
  (a) `host` matches `D-bench-machine`,
  (b) `toolchain` is a sensible `rustc 1.x.x`,
  (c) `benches` array has at least 7 entries (3 process_block + 3
      tree_hash variants + 1 gossip + 1 rpc),
  (d) all `ns` values are positive.
  If any check fails, repair Phase 4 and re-run.
- [ ] Task 5.3: Commit `bench-history/<sha>.json` and any per-bench
  criterion HTML output that lands outside `target/` (typically none —
  criterion writes everything under `target/criterion/`, which is
  gitignored). The `bench-history/` tracking invariant was already
  verified in Task 3.6; no `.gitignore` work happens here.
- [ ] Task 5.4: Append a one-line entry to `docs/perf/m4-perf.md` (the
  M4-perf ledger) under a new `## M4c — bench baseline` section: the
  short SHA + the four bench identifiers + their point estimates.
  This is the human-readable summary; the JSON file is the canonical
  source.

**Checkpoint: Verify Phase 5 complete.** Review Tasks 5.1–5.4. Confirm
`bench-history/<sha>.json` exists, is well-formed, and is committed
(`git status` clean). `docs/perf/m4-perf.md` has the new section.
**Commit boundary:** `bench(m4c): record baseline bench numbers on PERF_HOST`.

### Phase 6 — Audit + ADR fill-in + conformance regression check
Why this phase: every milestone closes with a documented audit + the
ADR bodies written + a conformance row-count gate to catch silent
drift. Mirrors `docs/m4b-plan.md` Phase 6/Phase 9 closure.

- [ ] Task 6.1: Run `make conformance` (single invocation, captured to
  `target/test-logs/conformance.log`). Compare `docs/conformance.md`
  byte-for-byte against the post-M4-perf snapshot (e.g.
  `git show v0.5.0:docs/conformance.md > /tmp/conformance.before` then
  `diff /tmp/conformance.before docs/conformance.md`). Zero-diff is
  the gate. If non-zero, the snapshot writes or the publish call
  side-effected the conformance data — investigate and fix BEFORE
  shipping.
- [ ] Task 6.2: Fill in the seven ADR bodies in `docs/decisions.md`
  under the `## M4c decisions` section. For each of:
    - `D-lc-gossip-validation-full-node-arm`
    - `D-lc-snapshot-trait-on-host`
    - `D-lc-gossip-clock-window`
    - `D-lc-broadcast-from-ingestion`
    - `D-lc-snapshot-write-trigger`
    - `D-bench-location-per-crate`
    - `D-bench-history-format`
  use the M4b decision template: `**Status**: Accepted. **Date**:
  YYYY-MM-DD.` + 2–4 paragraphs of context, rejected alternatives, and
  `Enforced in: <paths>`. Each body's `Enforced in:` lists the precise
  file:line ranges from this plan's tasks.
- [ ] Task 6.3: Update `CLAUDE.md` "M4c status" section (insert under
  the M4b status block) with a 5-line summary: scope shipped, decision
  keys, conformance gate result, bench baseline SHA, deferred items.
  Mirror the M4b status block tone exactly. (Per CLAUDE.md "don't
  commit CLAUDE.md unless asked" rule: do NOT auto-commit; surface as
  a manual edit suggestion in the final audit message.)
- [ ] Task 6.4: Run `make pre-push` (= `make ci` = fmt-check + lint +
  check + test-all). Single invocation, captured to
  `target/test-logs/m4c-prepush.log`. Zero failures, zero new
  warnings. This is the canonical sign-off.
- [ ] Task 6.5: Bump workspace version in `Cargo.toml` from `0.5.0` to
  `0.6.0` (M4c is the next minor; consistent with `v0.3.0`→`v0.4.0`→`v0.5.0`
  through M4a/M4b/M4-perf). Run `cargo check --workspace` to confirm
  the bump propagates.

**Checkpoint: Verify Phase 6 complete.** Review Tasks 6.1–6.5. Confirm:
conformance diff was zero; seven ADRs are filled (no `Draft` remaining);
`make pre-push` log shows green; workspace version is `0.6.0`. **Commit
boundary:** `chore(m4c): close milestone — bump v0.6.0`.

- [ ] **Final Audit.** Re-read the entire plan. For each task (0.1
  through 6.5), verify the implementation exists in the codebase
  (file path, function name, test name, ADR key). List any gaps. All
  gaps must be resolved before reporting completion. Specifically:
  - Phase 0: seven ADR stubs present in `docs/decisions.md`.
  - Phase 1: `MAXIMUM_GOSSIP_CLOCK_DISPARITY_MS` const exists;
    `HostImpl::new` takes `runtime_cfg`; both validator methods have
    real bodies; seven new unit tests exist and pass (five validator behaviour + two monotonic-IGNORE).
  - Phase 2: `IngestionEgress` struct exists; ingestion loop calls
    snapshot dispatcher + publish; three integration tests exist and
    pass.
  - Phase 3: four `[[bench]]` blocks exist; `make bench` is real;
    `bench-history/` directory + README exist; four stub bench files
    compile.
  - Phase 4: each bench file has real `c.bench_function` calls.
  - Phase 5: `bench-history/<sha>.json` committed; `docs/perf/m4-perf.md`
    has new section.
  - Phase 6: conformance diff zero; seven ADRs filled to Accepted;
    `make pre-push` green; version `0.6.0`.
  Run `code-reviewer` agent on the full diff per CLAUDE.md.

## Edge Cases & Risks
- R1: duplicate LC update on gossip — addressed by Task 1.3 / 1.4.
- R2: missing local snapshot during cold start — addressed by Task 1.3
  step 1 + OQ1 default `Ignore`.
- R3: const-generic collision at the snapshot call site — addressed by
  Task 2.3 dispatcher.
- R4: `clippy::too_many_arguments` on ingestion loop — addressed by
  Task 2.1 `IngestionEgress` struct.
- R5: false-positive clock-window rejection — addressed by Task 1.3
  step 3 + Task 1.5(c) test.
- R6: toolchain bench drift — addressed by Task 3.5 `toolchain` field.
- R7: gossip bench needs paired fixture — addressed by Task 4.3 inline
  fixture build.
- R8: snapshot-write latency — addressed by Task 2.2 `spawn_blocking`.
- R9: bench dep affects fast-test gate — addressed by reading the
  Makefile (no `--all-targets` on `make test`); no mitigation task
  needed.
- R10: conformance row regression — addressed by Task 6.1
  byte-identical diff gate.

## Acceptance Criteria
- `make check && make lint && make fmt-check && make test` green
  (captured to `target/test-logs/`).
- `make conformance` produces `docs/conformance.md` byte-identical to
  the post-M4-perf snapshot.
- `make pre-push` green (full CI including m0_acceptance).
- `make bench` runs the four bench binaries and produces a single
  new file `bench-history/<sha>.json` with valid schema.
- `cargo test -p pharos-node --test lc_gossip_publish` passes (three
  tests).
- `cargo test -p pharos-node host_impl::tests::validator_` passes
  (seven new tests under the existing `mod tests`, including the two per-topic monotonic-IGNORE cases).
- Both `validate_light_client_finality_update` and
  `validate_light_client_optimistic_update` on `HostImpl<E>` contain
  real bodies (zero remaining `TODO(M4)` markers in those methods —
  the other seven `TODO(M4)` validators stay as M5 work).
- The ingestion loop publishes the two LC topics after each post-Altair
  head advance, verified by the
  `publish_called_after_head_change` integration test.
- Seven new `### D-*` headers under `## M4c decisions` in
  `docs/decisions.md` are all `Status: Accepted`.
- Workspace version is `0.6.0`.

## Open Questions
- OQ1: When the local snapshot is absent (cold-start window before
  the first post-Altair block has produced an LC update), should the
  validator return `Ignore` (drop the message) or `Accept` (let the
  network propagate the peer's view)?
  **Recommended default: `Ignore`.** Rationale: the spec full-node
  arm phrasing is "matches the locally computed one exactly"; with no
  local one, "matches" is vacuously false, and `Ignore` is the
  correct verdict per the spec's IGNORE bracket (vs `Reject` which
  would penalise the sender). The window is bounded (~one slot after
  the first post-Altair block hits ingestion). Recorded under
  `D-lc-snapshot-trait-on-host`.
- OQ2: Should `make bench` be part of the pre-push gate? **Recommended
  default: no.** Rationale: bench wall-clock is ~5 minutes; pre-push
  is the fast-iteration gate. M4c records benches only on manual
  invocation. M11 (continuous benchmarking) revisits this.
- OQ3: Should we ship a `bench-history/CHANGELOG.md` summarising
  bench movement across SHAs in addition to the per-SHA JSON?
  **Recommended default: no for M4c, yes when M4d gates against
  these numbers.** A single baseline doesn't benefit from a changelog;
  the baseline is the changelog.
- OQ4: Does the LC publisher need a rate limit (e.g. "publish at most
  once per slot per topic")? Spec does not mandate one and the
  ingestion loop fires once per accepted block (≤1 per slot under
  honest behaviour); under reorg storms it could fire several times
  per slot. **Recommended default: no rate limit for M4c.** The
  worst-case duplicate publish is harmless (the receiver IGNOREs the
  duplicate per Task 1.3); a rate-limit adds state for no observable
  win. Re-evaluate if M4d devnet logs show problematic publish
  volume.


## Revision notes
- **BLOCKER 1** fixed by switching the slot-window genesis source from the non-existent `RuntimeConfig.min_genesis_time` to `self.fork_choice.read().genesis_time` (Task 1.3 step 3), and updating Assumption A8 to drop the `min_genesis_time` reference and document the fork-choice `Store` as the canonical genesis-time source.
- **BLOCKER 2** fixed by expanding Task 2.3 to fetch the `attested_state` from `fc_store.block_states.get(&attested_root)` alongside the attested block, with explicit per-fork unwrap arms (`E::unwrap_altair_*` vs `E::unwrap_bellatrix_*`), documented `None`-propagation when the parent state is absent, and a pointer to the `state_transition` `where` clause as the template for the dispatcher's projection bounds.
- **BLOCKER 3** fixed by inserting a new Task 2.0 that adds `pub async fn publish` to `NetworkCommandSender<E>` (mirroring the existing `request` pattern at `handle.rs:49-68`) and rewriting `IngestionEgress.network` to be `NetworkCommandSender<E>` (Clone, no `Arc`) instead of `Arc<NetworkHandle<E>>`. Assumption A6 was updated to record the new `publish` method and the non-`Clone` invariant on `NetworkHandle<E>`.
- **BLOCKER 4** fixed by adding a new locked decision `D-lc-broadcast-timing` committing to approach (B) — publish immediately, accept the spec SHOULD deviation, defer the delayed-publish scheduler to M11 — with the rejected alternative (A) and rationale documented inline.
- **Warning 5** addressed by adding `last_forwarded_finality_slot` / `last_forwarded_optimistic_slot` `AtomicU64` fields to `HostImpl<E>` (Task 1.2 tail), per-topic monotonic compare-and-swap steps in Tasks 1.3 (step 2 / commit in step 5) and 1.4, and two new unit tests `validator_ignores_non_monotonic_finality` / `validator_ignores_non_monotonic_optimistic` in Task 1.5 (test count now seven, cross-references updated).
- **Warning 6** addressed by committing Task 4.3 to duplicating `make_host` into the bench file rather than promoting it to a public `test_helpers` module.
- **Warning 7** addressed by moving the `bench-history/` `git status` verification into Task 3.6 (and any `.gitignore` fix into that same task), and trimming Task 5.3's redundant `.gitignore` clause.
- **Warning 8** addressed by changing Task 2.2 to `.await` the `spawn_blocking` `JoinHandle` (matching `block_ingestion.rs:172-181`) before the publish step, eliminating the read-before-write race.
- **Warning 9** addressed by prepending `@: > $(LOGS)/bench.log` to the `make bench` target so `tee -a` no longer leaks stale content across invocations.
- **Warning 10** addressed by lifting the tokio `Runtime` construction out of the criterion closure in Task 4.4.
- **Warning 11** addressed inline in the rewritten Task 2.3 — Bellatrix and Altair arms each explicitly call their fork-specific `E::unwrap_*_signed_block` / `E::unwrap_*_state`, with a note that the LC types themselves are Altair-shaped via the EthSpec alias at `eth_spec.rs:1332` but the state/block unwraps are NOT.

### Second revision
- **CRITICAL A** (Task 2.3 signed/unsigned type mismatch between `fc_store.blocks: HashMap<Root, E::BeaconBlock>` and `update_light_client_snapshots`'s `&SignedBeaconBlock<...>` parameters) fixed by adopting **Option (b)+(c) hybrid**: a new Task 2.3a adds `unwrap_phase0_block` + `unwrap_altair_block` to the `EthSpec` trait (mirroring the existing `unwrap_bellatrix_block` at `eth_spec.rs:496, 1206, 1685`), and a new Task 2.3b rewrites `update_light_client_snapshots`, `block_to_light_client_header`, `create_light_client_bootstrap`, and `create_light_client_update` to accept unsigned `&BeaconBlock<...>` parameters in place of `&SignedBeaconBlock<...>`. The rewrite is sound because each helper accesses the block only via `block_to_light_client_header`, which reads `block.message.{slot, proposer_index, parent_root, state_root, body.tree_hash_root()}` (verified at `light_client.rs:585-594`); the signature field is never read. Task 2.3 itself is rewritten to fetch unsigned blocks from `fc_store.blocks` and project them via the new `E::unwrap_altair_block` / existing `E::unwrap_bellatrix_block`.
- **CRITICAL B** (Task 2.0's `publish(topic, payload: Vec<u8>)` signature mismatched Task 2.4's `egress.network.publish(topic, &fu)` call site where `&fu` is `&LightClientFinalityUpdate`) fixed by rewriting Task 2.0's signature to mirror `NetworkHandle::publish` at `handle.rs:221-237` exactly: `pub async fn publish(&self, topic: GossipTopic, payload: &impl pharos_ssz::Encode) -> Result<MessageId, NetworkError>`. The method now performs `let ssz_payload = payload.as_ssz_bytes()` internally before constructing `NetworkCommand::Publish`. Task 2.4's call sites stay as `egress.network.publish(topic, &fu).await` / `(topic, &ou).await` — they now type-check.
- **WARNING** (Task 2.4's reliance on `host.current_fork_digest()`) addressed by inlining a verification line in Task 2.4 citing `crates/pharos-node/src/host_impl.rs:214-217` (`impl<E: EthSpec> ForkContext for HostImpl<E>`); the impl exists and is concrete, no fallback to `fork_schedule().current_fork_version(slot)` is needed.
- **INFO** (channel-closed failure semantics on `NetworkCommandSender::publish`) addressed in Task 2.0's rationale: both the `mpsc::Sender::send` error and the `oneshot::Receiver::await` error map to `NetworkError::ChannelClosed`, identical to `NetworkHandle::publish`. Publish failures surface to Task 2.4 as `Err(NetworkError::ChannelClosed)` and are logged via `warn!` — not silently swallowed.
