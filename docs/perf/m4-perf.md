# Pharos perf ledger

Human-readable summary of bench baselines. Canonical numbers live in
`bench-history/<sha>.json` (one file per recorded run); this file is a
narrative index pointing at them.

Host: AMD Ryzen 5 5600 (6c/12t), Debian 13. Toolchain: rustc 1.95.0
stable. Bench profile: `opt-level=3`, `lto=thin`, `debug=true` (see
`Cargo.toml [profile.bench]`).

## M4c — bench baseline

First baseline. SHA `d96e1f8` (post Phase 4 fixes). Recorded
`2026-05-28T08:23Z`. Source: `bench-history/d96e1f8.json`.

| bench                                            | mean       | stderr      |
| ------------------------------------------------ | ----------:| -----------:|
| process_block/phase0                             |  1.549 ms  |  2.8 µs     |
| process_block/altair                             |  1.693 ms  |  2.5 µs     |
| process_block/bellatrix                          |  1.805 ms  |  6.1 µs     |
| tree_hash_beacon_state/altair_mainnet            |  1.421 ms  |  4.3 µs     |
| tree_hash_beacon_state/bellatrix_mainnet         |  1.416 ms  |  2.5 µs     |
| tree_hash_beacon_state/bellatrix_cold            |  3.017 ms  |  7.8 µs     |
| gossip_validation/lc_finality_update             | 18.10 µs   | 38 ns       |
| rpc_roundtrip/blocks_by_range_count_1            |   173.7 µs | 944 ns      |

Notes:
- `process_block/*` uses the `empty_block_transition` mainnet
  fixtures with `validate_result=false` (no sig re-check); this is
  pure STF body cost.
- `tree_hash_*_mainnet` hits the warm `CachedRoot` path after the
  first sample populates the cache; `bellatrix_cold` clones the
  inner state per iteration (Clone resets the cache per
  `D-validator-cache-clone-resets`), path-copies one validator on
  the `Tree` backend, then rehashes from scratch.
- `gossip_validation/lc_finality_update` measures only the validator
  body; the per-iter RocksDB `put_light_client_finality_update` is
  inside `iter_batched`'s setup phase (unmeasured).
- `rpc_roundtrip/blocks_by_range_count_1` is the full wire cost
  between two loopback libp2p `Network<E>` instances after a
  Status handshake; the responder returns `Vec::new()`, so this is
  request-frame + response-frame + decode, not block body retrieval.
