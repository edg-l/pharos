# M1 perf baseline — `phase0/sanity`

Date: 2026-05-21. Workload: `cargo run -p pharos-conformance --profile bench
-- --filter phase0/sanity` (47 mainnet + 52 minimal cases). Samples: 69,106
across user-space, captured with `perf record -F 997 --call-graph=dwarf`
and rendered via `cargo flamegraph`. SVG: `/tmp/pharos-sanity.svg`.

Profile is `bench` (LTO=thin, debug=true) rather than `release` (LTO=fat) to
get symbol names. Hotspot ordering is representative; absolute timings would
shift a few percent under fat LTO.

## Headline

SHA-256 dominates. **~55-60% of all sampled user-space cycles** are spent
inside `pharos_utils::hash::hash_concat` and the SHA-256 SIMD intrinsics it
calls (`_mm_sha256msg1_epu32`, `_mm_sha256msg2_epu32`, `_mm_sha256rnds2_epu32`,
`_mm_shuffle_epi32`, `_mm_add_epi32`). The hash is already on the SHA-NI
hardware path — there is no faster way to compute it. The only remaining
lever is **calling it less often.**

## Top pharos_* leaf samples

| Samples | Symbol                                                          |
|---------|-----------------------------------------------------------------|
| 38,609  | `pharos_utils::hash::hash_concat`                               |
| 3,870   | `pharos_ssz::tree_hash::merkleize_padded_inner`                 |
| 2,711   | `pharos_ssz::tree_hash::pack_basic_elems_bytes`                 |
| 2,104   | `pharos_ssz::tree_hash::pack_bytes_to_chunks` (closure)         |
| 1,623   | `pharos_ssz::tree_hash::pack_bytes_to_chunks`                   |
| 1,457   | `pharos_stf::phase0::slot::process_slot`                        |
| 269     | `pharos_utils::bls::verify`                                     |
| 218     | `pharos_utils::bls::fast_aggregate_verify`                      |
| 160     | `pharos_stf::phase0::epoch::final_updates::process_randao_mixes_reset` |
| 151     | `pharos_utils::bls::parse_pubkey_validated`                     |

Everything else is < 100 samples per function — STF operations, accessors,
predicates are well-distributed and not individually hot.

## Memcpy attribution

The 6,000-odd `__memcpy_avx_unaligned_erms` / `copy_nonoverlapping` samples
do **not** indicate buffer thrash. Tracing parent frames:

| Memcpy samples | Originating pharos_* / sha2 frame                                |
|----------------|------------------------------------------------------------------|
| 2,722          | `pharos_ssz::tree_hash::merkleize_padded_inner`                  |
| 2,554          | `pharos_utils::hash::hash_concat`                                |
| 2,162          | `pharos_ssz::tree_hash::pack_basic_elems_bytes`                  |
| 1,000          | `sha2::sha256::x86_sha::compress`                                |
| 683            | `pharos_ssz::tree_hash::pack_bytes_to_chunks` (closure)          |

All five are on the SHA-256 critical path — they're moving 32-byte chunks
into hash inputs. Eliminating these means eliminating the hash calls
themselves, which routes back to the headline.

## What the profile says about M1 code

1. **State-root recompute in `process_slot`** is the single largest
   pharos-controlled hotspot. R13 in the M1 plan flagged this; the profile
   confirms it. `state.tree_hash_root()` is called every slot inside
   `process_slot` and re-merkleizes the entire `BeaconState`. The roadmap
   defers caching to **M11 (productionization)**; the data here is the
   first concrete evidence for that decision.
2. **No surprises in epoch processing.** The eleven sub-routines combined
   contribute < 500 samples (< 1%). Rayon-parallelised
   `process_rewards_and_penalties` and `process_effective_balance_updates`
   are not visible at the leaf level, which is the desired outcome.
3. **BLS is < 1%** in `phase0/sanity` (sparse attestations per block).
   `phase0/operations` and `phase0/random` will show higher BLS share.
   `general/bls` ran cleanly with hardware acceleration.
4. **No duplicate patterns** that fork-choice (Phase 8) might have copied.
   `pharos_fork_choice::*` does not appear in the top 25 because sanity
   doesn't drive fork-choice; the only place it would land is the
   `lmd_ghost_smoke` unit test.

## Levers, ranked by realistic payoff

1. **Cache `BeaconState::tree_hash_root` subtree hashes** (M11). Two
   places to amortise:
   - **Validator-list subtree.** `state.validators` is a `List[Validator,
     VALIDATOR_REGISTRY_LIMIT]`; the leaf hashes for the validator
     records are stable across slots that do not touch the registry.
     Caching the per-validator `tree_hash_root` and the partial
     Merkle layers in the `SszList` itself (the "persistent collection
     **is** the SSZ tree" promise from the roadmap) lets `process_slot`
     skip most of the registry hash. This is the single biggest win.
   - **`block_roots` / `state_roots` ring buffers.** Each slot mutates
     exactly one element; the surrounding Merkle layers can be
     incrementally updated rather than fully rebuilt.
2. **Avoid SSZ-encoding state for equality compare in conformance.**
   `sanity::run_blocks_case` currently compares states via
   `as_ssz_bytes()` on both sides. Switching to a direct PartialEq on
   `E::BeaconState` (already derived) skips a re-encode and a buffer
   alloc. Small effect on bench numbers (conformance harness time is
   not on the node hot path), but is a free cleanup.
3. **Don't deep-copy in `state_transition`.** The owned-mutate-return
   convention (D1) already avoids this. Profile confirms no rogue clone
   shows up.

## Out of scope until benches exist

`cargo bench` infrastructure is not in this repo yet. Once it ships
(targeted post-M2), the recommendation is `criterion` benches on:

- `<MainnetBeaconState as TreeHash>::tree_hash_root()` (cold vs. warm cache)
- `process_slots` over N slots with a typical state size
- `state_transition` on a representative sanity fixture

Those benches set up the metrics M11 needs to validate the caching work.

## Reproducing

```sh
cargo install flamegraph
cargo flamegraph --profile bench --bin pharos-conformance \
  -o /tmp/pharos-sanity.svg -- --filter phase0/sanity
```

`profile bench` is required for symbols (release strips debug). On AMD
Zen 4 / Linux 6.12 with `perf_event_paranoid = -1`, the run takes ~80s
and produces a ~4 GB `perf.data` (delete after rendering).
