# M5 — Full block-following over gossip (Bellatrix devnet)

Goal: make Pharos follow the canonical head over gossip on the live Lighthouse
v8.1.3 + ethrex v13 Bellatrix devnet. Peering, Status handshake, and gossip-mesh
formation already work (commit 211fd00). Three root causes block following.

Locked design decisions (see rationale in chat / ADRs at end):
- RC1 = one-liner reading the Store's already-correct genesis_time.
- RC2 = gate on libp2p `num_established` in the swarm handlers; store NOTHING.
- RC3 = corrected option (b): re-converging range sync that HEALS TO THE TIP,
  runs forever, woken by a `tokio::sync::Notify` fired when ingestion defers an
  orphan; hybrid `select!` with a fallback sleep backstop. No orphan buffer.
  By-root unknown-parent/side-branch import (reorg correctness) is explicitly
  future work, ADR `D-byroot-lookup-deferred`.

## Out of scope (future)
- `BeaconBlocksByRoot` unknown-parent / side-branch import (reorg/side-fork
  correctness; needs multi-fork test scenarios). ADR D-byroot-lookup-deferred.
- Orphan buffering pool (replaced by Notify + range re-convergence).
- Per-peer connection accounting in PeerInfo (libp2p is the source of truth).
- Weak-subjectivity validation, historical backfill, batched BLS (M11).

---

## Phase 1 — RC1: anchor slot clock to real genesis_time

Anchor genesis_time is already correct on the fork-choice Store in all three
startup branches: cold (`get_forkchoice_store`, store.rs:203,220), checkpoint
(`apply_anchor`, checkpoint_sync.rs:268,306), warm (`rehydrate_fork_choice_store`,
startup.rs:157). `Store::genesis_time` is `pub` (store.rs:44).

- [ ] 1.1 Characterization test (NOT fail-first) in `crates/pharos-fork-choice/src/get_head.rs`
  tests module, `current_slot_tracks_store_genesis_not_wallclock`: Store with
  `genesis_time = wall_now` ⇒ `get_current_slot == Slot(0)`; `genesis_time =
  wall_now - N*SECONDS_PER_SLOT` ⇒ `Slot(N)`. Pins the contract; RC1's real gate
  is the Phase-4 live "current_slot != 0" assertion.
- [ ] 1.2 `crates/pharos-node/src/main.rs:475`: replace
  `let genesis_time_secs = wall_clock_secs;` with
  `let genesis_time_secs = fork_choice.read().genesis_time;` (Arc built at line
  349; no lock held across await at 475). Remove the stale 472-474 comment;
  replace with one line noting the value is the chain genesis from the Store.
  Do NOT change the startup tuple binding or add per-branch extraction.
- [ ] 1.3 (a) Add `pub use get_head::get_current_slot;` to
  `crates/pharos-fork-choice/src/lib.rs` (extend the existing
  `pub use get_head::{...}` re-export). (b) Startup log right after 1.2:
  `info!(genesis_time = genesis_time_secs, current_slot = %pharos_fork_choice::get_current_slot(&fork_choice.read()), "slot clock anchored");`
- [ ] 1.4 Checkpoint: `make check` + run 1.1. RC1 has no fail-first unit test by
  design; verified by characterization test + Phase-4 live.

## Phase 2 — RC2: gate peer (de)registration on libp2p num_established

`on_connected` does `self.peers.insert` (overwrites, wipes `last_status`);
`on_disconnected` does `self.peers.remove`. Redundant connections to one peer
therefore corrupt the table. Fix = gate in the swarm handlers on `num_established`
(libp2p provides it in both events; semantics verified for libp2p-swarm 0.47.x:
`ConnectionEstablished.num_established: NonZeroU32` includes the new conn so
`.get()==1` is first; `ConnectionClosed.num_established: u32` is the remaining
count so `==0` is last). Store nothing — no PeerInfo field, no signature change.

- [ ] 2.1 Fail-first integration test `crates/pharos-network/tests/redundant_connection.rs`
  (two-node harness per `tests/events_m3a.rs` + `tests/common`): handshake, open a
  2nd connection between the same pair, close it; assert the peer stays in
  `connected_peers_with_status` with `last_status` intact, `PickHighestHeadPeer`
  still returns it, and no spurious `PeerDisconnected` was emitted. FALLBACK (if
  libp2p transport dedups/refuses redundant connections, making it flaky): a
  direct unit test calling `on_swarm_connection_established`/`_closed` with
  num_established = 2 then 1 then 0 and asserting peer-table state. State the
  fallback in the test file comment.
- [ ] 2.2 `crates/pharos-network/src/network/mod.rs:465-469` ConnectionEstablished
  arm: destructure `num_established` (drop the `..` covering it), pass to
  `on_swarm_connection_established(peer_id, endpoint, num_established)`.
- [ ] 2.3 `crates/pharos-network/src/network/mod.rs:470-473` ConnectionClosed arm:
  destructure `num_established`, pass to
  `on_swarm_connection_closed(peer_id, cause.as_ref(), num_established).await`.
- [ ] 2.4 `on_swarm_connection_established` (mod.rs:1105): add param
  `num_established: std::num::NonZeroU32`; wrap the whole body (the `on_connected`
  call at 1113 through the outbound Status-send block ending ~1138, plus the
  inbound comment branch) in `if num_established.get() == 1 { ... }`. For >1 emit a
  `trace!` and do nothing.
- [ ] 2.5 `on_swarm_connection_closed` (mod.rs:1154): add param
  `num_established: u32`; wrap the body (reason resolution 1163-1170,
  `on_disconnected` 1172, `emit_event(PeerDisconnected)` 1173-1174) in
  `if num_established == 0 { ... }`. For >0 emit a `trace!` and do nothing.
- [ ] 2.6 Add a code comment at both gate sites: `ban()` lives in the Goodbye path
  (`on_request_response_event`, mod.rs:674) and is intentionally OUTSIDE the
  num_established gate — a fork-mismatch ban must remove the peer unconditionally.
  No change to the ban path.
- [ ] 2.7 Checkpoint: 2.1 passes; existing `cargo test -p pharos-network --test events_m3a` still green.

## Phase 3 — RC3: re-converging tip-healing follow loop + Notify orphan recovery

Plain (b) bug: with the 2-slot lag the loop idles within 2 slots of the tip, so a
gossip block dropped in that window is never re-fetched. Corrected: heal to
`wall_slot-1`; run forever; wake via Notify on every deferred orphan.

- [ ] 3.1 `IngestionEgress<E>` (block_ingestion.rs:83-88): add
  `pub notify_backfill: Arc<tokio::sync::Notify>`. Add `Notify` to the import at
  block_ingestion.rs:17 (`use tokio::sync::{Notify, mpsc, watch};`).
- [ ] 3.2 block_ingestion.rs:208-214 missing-parent site: replace
  `warn!(... "missing parent state; dropping block"); continue;` with
  `debug!(%parent_root, "block_ingestion: missing parent; deferring to backfill"); egress.notify_backfill.notify_one(); continue;`.
  NO orphan buffer.
- [ ] 3.3 backfill.rs:222-231 mid-chunk missing-parent: keep the `break`, downgrade
  `warn!` → `debug!`.
- [ ] 3.4 `run_backfill_loop` (backfill.rs:103): add param
  `notify: Arc<tokio::sync::Notify>` after `shutdown_rx`. Rewrite:
  - `let fetch_target = wall_slot.saturating_sub(1);` (tolerate in-progress slot).
  - Replace the caught-up `return Ok(())` (170-178): if `head_slot.0 >= fetch_target`,
    `tokio::select! { _ = notify.notified() => {}, _ = tokio::time::sleep(BACKFILL_FOLLOW_FALLBACK) => {}, _ = shutdown_rx.changed() => {} }`
    then `if *shutdown_rx.borrow() { return Ok(()); }` else `continue;`. NEVER
    return on caught-up.
  - Fetch range (180-182): `start = head_slot.0 + 1`,
    `remaining = fetch_target.saturating_sub(start) + 1`,
    `count = remaining.min(BACKFILL_CHUNK_SIZE)`.
  - Update module doc (backfill.rs:7) to describe long-running tip-following +
    Notify; drop "exits when caught up" wording.
- [ ] 3.5 Remove `BACKFILL_TAIL_LAG_SLOTS` (backfill.rs:52) — deterministically dead
  after 3.4 — and its doc references (backfill.rs:7, 50, 94, 753). Add
  `pub const BACKFILL_FOLLOW_FALLBACK: Duration = Duration::from_secs(48);` with a
  comment "backstop wake (~4 mainnet slots); Notify is the primary wake".
- [ ] 3.6 Thread the shared Notify through main.rs: before the ingestion spawn (578)
  `let notify_backfill = Arc::new(tokio::sync::Notify::new());`; add
  `notify_backfill: notify_backfill.clone()` to the `IngestionEgress { ... }`
  literal (578-582); pass `notify_backfill` as the new final arg to
  `run_backfill_loop` (614-629). Update ALL other `run_backfill_loop` call sites
  (`rg -n run_backfill_loop`): `tests/checkpoint_backfill_pipeline.rs:451` and the
  three in-module unit tests `backfill.rs:777,839,964` → pass
  `Arc::new(tokio::sync::Notify::new())` (or a test-controlled notify for 3.7/3.8).
- [ ] 3.7 Rewrite existing `backfill_exits_when_caught_up` (backfill.rs:758-804) as
  `backfill_idles_when_caught_up`: spawn the loop caught-up with a fresh Notify;
  use `tokio::time::timeout(~1s, &mut handle)` (real clock, NOT fake time) to
  assert the task has NOT completed and head is unchanged; then fire `shutdown_rx`
  and assert it returns `Ok(())`. Fails against the old return-immediately code.
- [ ] 3.8 Integration test `crates/pharos-node/tests/orphan_backfill_recovery.rs`:
  feed `run_block_ingestion_loop` a gossip block whose parent is absent ⇒ assert
  it's deferred (loop alive, head unchanged) and the Notify is signaled; then run
  the re-converging backfill with a provider supplying `[head+1 ..= orphan_slot]`
  ⇒ assert head advances to include the orphaned slot. Model on
  `tests/checkpoint_backfill_pipeline.rs` + the backfill test provider.
- [ ] 3.9 ADRs in docs/decisions.md (M5 section): `D-following-via-range-reconvergence`
  (corrected (b): tip-heal to wall_slot-1, long-running, hybrid Notify+fallback, no
  buffer; rationale that the lag heuristic alone leaves a tip gap) and
  `D-byroot-lookup-deferred` (BeaconBlocksByRoot unknown-parent/side-branch import
  is future reorg-correctness work needing multi-fork scenarios, NOT part of
  canonical-following M5 which corrected-(b) fully satisfies).
- [ ] 3.10 Checkpoint: 3.7 + 3.8 pass; `make check`/`make lint` green.

## Phase 4 — live cross-client devnet verification

- [ ] 4.1 `make pre-commit` (fmt+lint+fast tests) green, captured to
  target/test-logs/m5-precommit.log. Confirm clippy clean after the dead-const
  removal.
- [ ] 4.2 `make test` once, backgrounded, captured to target/test-logs/m5-test.log.
  Confirm new Phase 1-3 tests + existing `events_m3a`,
  `checkpoint_backfill_pipeline`, `two_node_persisted_blocks` green. HARD gate.
- [ ] 4.3 (Conditional on harness at ~/.cache/pharos-devnet/.) Start
  `run-devnet.sh` then `run-pharos.sh`; capture pharos log. Verify "slot clock
  anchored" shows current_slot != 0 (RC1 live gate).
- [ ] 4.4 Confirm head tracks Lighthouse within a few slots over ≥2 epochs;
  "deferring to backfill" debug lines followed by head catch-up (RC3); no
  "dropping block" warns; no peer-disconnect churn under redial (RC2).
- [ ] 4.5 Tear down; record observed head-lag + duration in this file's wrap-up.
- [ ] 4.6 Confirm docs/conformance.md row counts byte-identical (runtime-only fixes).
- [ ] 4.7 Final audit: grep each named symbol/site; `rg BACKFILL_TAIL_LAG_SLOTS
  crates/` returns zero. Resolve any gap before declaring done.

Note: 4.3-4.4 are the acceptance gate but conditional on harness availability;
4.1/4.2 are the unconditional CI blocker.
