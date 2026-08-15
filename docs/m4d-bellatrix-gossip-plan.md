# M4d — Bellatrix gossip fork-migration (revised plan, post-review)

Goal: pharos computes the **Bellatrix** fork-digest and uses it for gossip topics,
the ENR `eth2` field, and the Status handshake, so it peers with lighthouse and
follows a Bellatrix chain. Currently capped at Altair. Target: bellatrix-at-genesis
(ALTAIR_FORK_EPOCH = BELLATRIX_FORK_EPOCH = 0) AND mid-run crossing. No STF changes,
no new deps.

## Core design decision (resolves review CRITICALs 1,2,3,5)

`current_fork_digest()` becomes **dynamic**: computed on every call from
`fork_schedule.current_fork_version(current_epoch())` + `genesis_validators_root`,
where `current_epoch()` is derived from `genesis_time_secs` + wall clock (same
arithmetic as `fork_migration.rs:77-85`, `genesis_time_secs==0 → epoch 0`).
- NO frozen `current_fork_digest` field, NO `RwLock` — the value tracks wall-clock
  epoch automatically, so Status / ENR / message-id all stay correct across the
  crossing with no mutation path needed. ADR `D-epoch-driven-fork-digest`.
- `HostImpl` stores `fork_schedule: ForkSchedule` and `genesis_time_secs: u64`.
- Remove the stub single-fork `ForkSchedule` built inside `HostImpl::new`
  (host_impl.rs:161-168) — store the real passed-in schedule.

## Phase 1 — Network-layer `Fork::Bellatrix` + gossip/codec decode dispatch
1.1 Add `Bellatrix` to `Fork` enum (pharos-network/src/types.rs:23).
1.2 `gossip/mod.rs:104` `dispatch_gossip_message`: replace hardcoded phase0 block
    decode with match on `host.fork_from_context(topic.fork_digest)` →
    Phase0/Altair/Bellatrix block type + matching `*_into_signed_block`.
1.3 Fix `MockForkContext` (network/mod.rs:1746) + any in-crate test `ForkContext`
    impls: exhaustive `Fork::Bellatrix` arms.
1.4 `rpc/codec.rs`: add `Fork::Bellatrix` arms on BOTH receive (line ~224) AND
    send (lines ~419-439, the `unwrap_*_signed_block` chain) paths for
    BlocksByRange/ByRoot v2 — full bellatrix req-resp, not just compile-level
    (review WARNING 6: backfill + serving lighthouse needs both). LC guard at
    line 177 unchanged.
1.5 Checkpoint (LAST task): `cargo check -p pharos-network`.

## Phase 2 — HostImpl dynamic three-fork ForkContext
2.1 `HostImpl::new` (host_impl.rs:151): accept `fork_schedule: ForkSchedule` +
    `genesis_time_secs: u64`, drop `current_fork_version: Version`. Store both on
    `ForkContextInner`. REMOVE stub schedule (161-168) and the frozen
    `current_fork_digest` field.
2.2 Add private `current_epoch(&self)->Epoch` (wall-clock from genesis_time_secs,
    ==0→0) and `current_fork_version_now(&self)->Version` =
    `fork_schedule.current_fork_version(current_epoch())`.
2.3 `current_fork_digest()` (437): `compute_fork_digest(current_fork_version_now(), &gvr)`.
2.4 `enr_fork_id()` (445): `{ fork_digest: current_fork_digest(),
    next_fork_version: fork_schedule.next_fork_version(epoch),
    next_fork_epoch: fork_schedule.next_fork_epoch(epoch) }`.
2.5 `fork_digest_for` (461) + `fork_from_context` (474): add bellatrix arms
    (digest from `fork_schedule.bellatrix_fork_version`).
2.6 Update in-crate test ctor (host_impl.rs:1428) + all callers to pass a real
    ForkSchedule (phase0-only tests: altair/bellatrix epoch = Epoch(u64::MAX),
    genesis_time_secs=0).
2.7 main.rs: move `fork_schedule` + `genesis_time_secs`/`wall_clock_secs`
    construction ABOVE `HostImpl::new` (465); pass them in; delete hardcoded
    `fork_version` derivation (331-332). Single `Arc<ForkSchedule>` shared with
    the migration loop.
2.8 Checkpoint (LAST): `cargo check -p pharos-node`.

## Phase 3 — Generalize fork-migration loop to phase0→altair→bellatrix
3.1 Rewrite `run_fork_migration_loop` (fork_migration.rs:51) to track the current
    fork *version* (not a phase0 bool); handle BOTH crossings in one run; do not
    `return` after the first. Each tick: epoch → `current = current_fork_version(epoch)`;
    if `current != prior` → `do_migration(prior, current)`; update prior.
3.2 Startup-already-past-fork: on first tick if `current != genesis_fork_version`,
    record `prior = current` and do NOT migrate (startup subscription already on
    the right digest). For ALTAIR==BELLATRIX==0: first tick `current = bellatrix`,
    so it records bellatrix and no-ops — NO intermediate altair migration (review
    INFO 10). ADR `D-bellatrix-migration-startup-no-op`.
3.3 `do_migration(old_version, new_version)`: compute old/new digests; ENRForkID
    from new_digest + `next_fork_version(epoch)` + `next_fork_epoch(epoch)`
    (replace hardcoded FAR_FUTURE at 135-136); unsubscribe full old-digest topic
    set, subscribe full new-digest topic set.
3.4 Add `base_beacon_topics(digest)` shared private fn; refactor `altair_gossip_topics`
    to use it; add `bellatrix_gossip_topics(digest)` = base 5 + altair extras
    (sync_committee_*, light_client_*) all under the new digest (review WARNING 9 /
    Q2: bellatrix changes only beacon_block TYPE, all topics' digest segment bumps).
3.5 Add `bellatrix_topic_list(digest)` public helper (mirror altair_topic_list:244).
3.6 Verify main.rs migration-loop spawn compiles with rewritten signature; same
    Arc<ForkSchedule> as HostImpl.
3.7 Checkpoint: `cargo check -p pharos-node`.

## Phase 4 — Startup subscription at the active fork digest
4.1 The builder passes `host.current_fork_digest()` (now active digest after Ph2)
    to the startup subscribe (network/mod.rs:1528,1629). Confirm topic_map keyed
    under that digest.
4.2 Rename `subscribe_phase0_topics`→`subscribe_base_topics` (gossip/mod.rs:45 +
    ALL callsites via `rg -n subscribe_phase0_topics`, incl tests — replace_all,
    review INFO 11). When active fork ≥ altair, also subscribe altair extra topics
    under the active digest. ADR `D-bellatrix-startup-topic-set`.
4.3 message-id phase0 capture (network/mod.rs:1548-1549 `fork_digest_for(Fork::Phase0)`):
    correct as-is ONLY because Ph2 makes fork_digest_for(Phase0) the real phase0
    digest (≠ bellatrix); altair/bellatrix take the spec-correct else branch. Add
    inline comment. (review CRITICAL 5 resolved by Ph2.)
4.4 Checkpoint: `cargo check -p pharos-network`.

## Phase 5 — Tests
5.1 fork.rs: bellatrix digest ≠ altair; enr next_fork at bellatrix boundary.
5.2 host_impl.rs: bellatrix-genesis HostImpl reports bellatrix digest; phase0
    regression; (review) assert fork_digest_for(Phase0) ≠ bellatrix digest.
5.3 host_impl.rs: fork_from_context bellatrix round-trip + unknown→None.
5.4 fork_migration.rs: bellatrix_topic_list = 5 base + altair extras, all bellatrix
    digest.
5.5 integration test bellatrix_fork_migration.rs (mirror fork_epoch_migration.rs):
    phase0→altair→bellatrix AND bellatrix-at-genesis; assert bellatrix-digest topic
    set; assert bellatrix beacon_block gossip decodes (no Reject).
5.6 Checkpoint: `make test`.

## Phase 6 — Wrap-up
6.1 ADRs in docs/decisions.md (M4d): D-epoch-driven-fork-digest,
    D-bellatrix-migration-startup-no-op, D-bellatrix-startup-topic-set,
    D-gossip-block-decode-by-digest, D-bellatrix-reqresp-both-paths.
6.2 `make lint` + `make fmt-check`.
6.3 Final audit: every task → diff hunk; `git diff --stat` shows NO pharos-stf
    changes; no new deps; all ADRs present; CLAUDE.md not prematurely bumped.

## Q1/Q3 resolutions (from review)
- Q1: NOT a blocker. Migration loop uses wall_clock_secs → epoch 0 → bellatrix
  (correct for at-genesis). Gossip future-slot check uses `fork_choice.genesis_time`
  (from anchor state via checkpoint sync), NOT wall_clock — so no spurious future-slot
  rejection. Real genesis_time threading deferred to M5.
- Q3: req-resp BOTH paths implemented (1.4), so backfill + serving lighthouse work
  (not deferred).

## Acceptance
`cargo check` both crates green; `make test` green; bellatrix-genesis HostImpl reports
bellatrix digest; bellatrix beacon_block gossip decodes; manual interop: pharos logs
bellatrix digest (not 0x5e9205c6), Status handshake with lighthouse succeeds, head
advances via gossip; `git diff --stat` zero pharos-stf changes.
