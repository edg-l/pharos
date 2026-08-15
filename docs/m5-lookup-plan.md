# M5 lookup-sync — gossip-driven following (plan)

Goal: real-time gossip following on the Bellatrix devnet. Today an orphan gossip
block (parent unseen, RB6) is IGNOREd by `validate_beacon_block` and dropped by
the dispatcher — no queue, no parent fetch — so the 48s range-backfill fallback
is the only sync. Fix: queue the orphan + fetch its missing ancestors by root
(`BeaconBlocksByRoot`) + replay on import. Range backfill demoted to large-gap
fallback. (feature-planner → plan-reviewer → revised; review-clean.)

## Key design decisions
- **D-import-block-core-only**: extract `import::import_block<E,EE,PP>` = pre-state
  fetch → STF (spawn_blocking) → on_block (spawn_blocking) → payload_tx → HeadChange.
  NO LC-snapshot dispatch (stays in ingestion, keeps its bounds off import_block /
  backfill). Shared by ingestion, backfill, lookup. Resolves the bound-explosion risk.
- **D-decode-block-by-topic-helper**: extract `decode_block_by_topic` (Phase 1),
  reused by ingestion + lookup.
- **D-parent-unseen-sentinel**: `GOSSIP_REASON_PARENT_UNSEEN` const in
  pharos-network::host, used at host_impl.rs:711 AND the dispatcher comparison
  (single source of truth).
- **NetworkEvent::UnknownParentBlock{peer,data}**: emitted from the Ignore arm only
  for beacon_block + sentinel reason (pharos-network has only SSZ bytes; pharos-node
  re-decodes — accepted double-decode, ~1ms/orphan).
- **PendingBlocks** = `parking_lot::Mutex<{by_parent, per_peer_count, total}>`, caps
  MAX_PENDING_PER_PEER=256 / MAX_PENDING_BLOCKS=4096, FIFO evict, per-peer reject.
  INVARIANT: guard never held across `.await`.
- **run_lookup_loop**: select on lookup_rx (fetch_and_walk, depth ≤ MAX_LOOKUP_DEPTH=32,
  exhaustion → notify_backfill), parent_imported_rx (drain children + replay), shutdown.
- **Coordination**: lookup small-gap by-root, backfill large-gap by-range; on_block +
  engine_newPayloadV1 idempotent → lookup/backfill race safe.

## Phases (each ends with a checkpoint; final audit at end)
1. **Extract shared import core** — `import.rs` (`import_block`, `ImportOutcome`,
   `ImportError`), `decode_block_by_topic`; migrate ingestion + backfill to call it;
   checkpoint verifies BOTH compile + inline copies deleted (`rg spawn_blocking`).
2. **Network event + sentinel** — `GOSSIP_REASON_PARENT_UNSEEN`, `NetworkEvent::
   UnknownParentBlock` (+ variant_name arm), emit from Ignore arm; unit test mapping.
3. **PendingBlocks store** — `pending_blocks.rs`, caps + sync insert/drain/total; unit tests.
4. **Lookup loop + provider** — `lookup.rs` (LookupRequest/ParentImported/LookupError,
   LookupBlockProvider, fetch_and_walk, run_lookup_loop), `network_lookup_provider.rs`
   (NetworkLookupProvider via PeerPicker + BlocksByRoot); checkpoint: no guard across await.
5. **Wire-up** — add required `lookup_tx`/`parent_imported_tx`/`pending` to IngestionEgress;
   main.rs channels + spawn run_lookup_loop; update ALL 5 test construction sites
   (orphan_backfill_recovery, lc_gossip_publish ×3, engine_pipeline, checkpoint_backfill_pipeline,
   gossip_validators_e2e if present); checkpoint: `cargo check -p pharos-node --tests`.
5b. **Integration tests** — lookup_replay (head==block3), lookup_depth_exhaustion
   (notify fires), lookup_eviction (caps); `make test`; conformance row-count byte-identical.
6. **Live devnet + docs** — run devnet, verify pass/fail (head ≥ lh-2 over 5min,
   received-gossip-block>0, ~12s cadence not 48s bursts); ADRs; version bump.

## Acceptance (pass/fail)
- Integration: lookup_replay head==block3_root; depth-exhaustion notify within 2s;
  eviction total≤4096 + 257th per-peer insert false.
- `make test` zero failures; conformance.md row counts byte-identical.
- Live: pharos head ≥ lighthouse head − 2 sustained 5min; received gossip block > 0;
  head cadence ~12s (gossip), not 48s (backfill-fallback-only).

## OQ closures
- Reorg evicts parent between RB6 and Accept-path import → defensive notify_backfill (no enqueue).
- lighthouse may not serve recent-tip BlocksByRoot → depth-exhaustion → range-sync fallback (still follows).
- Channel capacities 256, try_send drop-on-full.

Full plan detail: see feature-planner output in session transcript.
