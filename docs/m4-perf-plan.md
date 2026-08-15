# M4-perf — Tree-backed persistent SSZ collections + tree-hash parallelism

## Overview
M4-perf swaps the placeholder `Backend::Tree(Arc<Node>)` slot in
`crates/pharos-ssz/src/sequence.rs` for a real persistent tree-backed
`SszList<T, N>` / `SszVector<T, N>`, caches `Validator::tree_hash_root`
via a manual `OnceLock` wrapper, emits field-level `rayon::join` nesting
in the `#[derive(TreeHash)]` macro, and parallelises the top-level
(fork, category, preset) ladder in `pharos_conformance::lib::run`.
Acceptance: conformance writer wall-clock drops from the ~657 s
sequential baseline (recorded in Phase 0) to under 60 s on a 12-core
machine; `docs/conformance.md` row counts are byte-identical before and
after; criterion benches for `tree_hash_root(BeaconState)`,
`process_slots`, and the conformance writer are committed to
`docs/perf/` for both `before` and `after`. M4a (Bellatrix STF + engine
wiring) and M4b (checkpoint sync + backfill + keepalive) are assumed
shipped per commits `676984c` → `f44251f`; current workspace version
`0.4.0`.

## Locked decisions (short form)
- `D-tree-node-shape` — `Node<T> { Branch { left: Arc<Node<T>>, right: Arc<Node<T>>, hash: OnceLock<Hash256> }, Leaf(T), ZeroSubtree(u8) }`; const-generic-derived depth on the wrapping `SszList` / `SszVector`; `Arc<Node<T>>` for structural sharing across CoW writes.
- `D-validator-cache` — `Validator::tree_hash_root` is cached via a private `OnceLock<Hash256>` field on `Validator`, populated by a hand-written `TreeHash` impl that replaces the previous `#[derive(TreeHash)]`. The `OnceLock` is skipped by `PartialEq`, `Eq`, `Hash`, SSZ `Encode`, and SSZ `Decode` to keep wire encoding byte-identical to the derived impl. `Clone` is derived; `OnceLock<T: Clone>` clones to a populated `OnceLock<T>` (verified empirically against rustc 1.95 stdlib), so cloned validators carry the cache. This is safe because `Validator` fields are never mutated in place: STF call sites always reconstruct via `SszList::with_set`, which builds a fresh `Validator` value (whose `OnceLock` is independent); the old reference is dropped, the stale root can never be observed. Real-world memory cost: ~1M active mainnet validators × ~40 bytes per `OnceLock<Hash256>` ≈ ~40 MB additional RSS. Bounded; acceptable.
- `D-treehash-rayon-strategy` — `#[derive(TreeHash)]` emits a balanced binary `rayon::join` tree over per-field roots when the struct has ≥ 4 fields; structs with < 4 fields keep the current serial array build (rayon overhead beats the work). The threshold is a constant on the derive macro side, not a runtime branch.
- `D-conformance-parallelism-shape` — `lib::run` is refactored from a 1718-line `if filter.matches(..)` ladder to a single `Vec<CategorySpec>` table consumed by `rayon::par_iter`, with a fixed merge step that re-sorts rows into the canonical `Report` order before writing `docs/conformance.md`. Bail semantics (`bail: bool`) collapse to "wait for in-flight categories, return after first failure observed" because rayon does not interrupt in-flight workers.
- `D-perf-bench-machine` — All `docs/perf/` numbers MUST be recorded on a single dedicated machine (`PERF_HOST`) tagged in each markdown report; defaults to the developer's 12-core Ryzen workstation. Across-machine comparisons are explicitly out of scope.
- `D-tree-leaf-packing` (M4-perf scope: composite-element only; O3) — For M4-perf, only composite-element leaves are tree-backed; each composite leaf holds one `T` per `Leaf`, which makes `tree_hash_root` byte-identical to the `Vec` backend without a translation layer. Basic-element lists (`SszList<u8/u32/u64, _>`) stay on `Backend::Naive(_)` for M4-perf per Task 1.3; the basic-element packing rule (one `Leaf` per 32-byte packed chunk per `pack(values)` in `simple-serialize.md`) is the design target for the M11 follow-up extension and is documented here for forward reference only — no M4-perf code implements it.

## Assumptions
- A1: `Backend::Tree(Arc<Node<T>>)` placeholder is still present and untouched in `crates/pharos-ssz/src/sequence.rs:49-55`; every method in `sequence.rs` still routes to `Backend::Naive(_)` and falls into `unimplemented!("tree backend lands in a later milestone")` for `Backend::Tree(_)` (verified at planning time at `sequence.rs:69, 78, 195, 234, 241, 253, 275, 297, 348, 393, 403, 425`).
- A2 (addendum, O2): `OnceLock<T: Clone>::clone()` is documented stdlib behaviour as of rustc 1.85 (workspace MSRV) and rustc 1.95 (planning-time toolchain): cloning a populated `OnceLock<T>` produces a populated `OnceLock<T>` carrying the same value; cloning an empty `OnceLock<T>` produces an empty one. This is current stdlib behaviour, not an RFC-guaranteed invariant — a future stdlib change could in principle alter it. Risk is low (the documented `Clone` impl is unlikely to weaken), but regression detection lives in Task 3.3's `validator_clone_carries_cache` test, which will flag the change at the next toolchain bump. If that test ever fails after a stdlib update, `D-validator-cache` and the `Validator` `Clone` strategy must be revisited.
- A2: `rayon = "1"` is a workspace dep (verified at `Cargo.toml:49`). `pharos-ssz` directly depends on `rayon` (verified at `crates/pharos-ssz/Cargo.toml:14`); `pharos-types` does NOT. To make the derive-macro emission resolve from every consumer crate without adding a new `rayon` dependency to each one, `pharos-ssz` re-exports rayon at `pharos_ssz::rayon` (added by Phase 4 Task 4.1.a), and the derive macro emits `::pharos_ssz::rayon::join(...)`. Every `#[derive(TreeHash)]` consumer already has `pharos-ssz` in its dep graph (it imports the `TreeHash` trait), so no new `Cargo.toml` edits are required in downstream crates.
- A3: `proptest = "1"` and `criterion = "0.8"` are workspace deps (verified at `Cargo.toml:87-88`). Neither has a `[[bench]]` entry in any crate's `Cargo.toml` yet; Phase 0 creates the first `[[bench]]` block in `crates/pharos-ssz/Cargo.toml` and `crates/pharos-stf/Cargo.toml`.
- A4: `OnceLock` is in `std::sync::OnceLock` (stable since 1.70); no extra crate dep. Selected over `once_cell::sync::OnceCell` because the workspace MSRV is 1.85 (verified at `Cargo.toml:22`).
- A5: The current `merkleize_padded_inner` algorithm (in `crates/pharos-ssz/src/tree_hash.rs:185-252`) already parallelises within tree levels (commit `9f61883`); the tree-backed impl computes per-subtree roots via direct `hash_concat`, bypassing `merkleize_padded` entirely for the cached path.
- A6: Per-category fixture walkers already parallelise via rayon internally (commit `9db9686`); the remaining sequential layer is the top-level `if filter.matches(..)` ladder in `lib::run`, which is the only thing Phase 5 touches. Nested rayon `par_iter` calls share the global thread pool — rayon's work-stealing scheduler handles nesting without oversubscription — so the new top-level `par_iter` over (fork, category, preset) triples coexists safely with the per-category `par_iter` from commit `9db9686`.
- A7: `Validator` is currently derived via `#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]` at `crates/pharos-types/src/phase0/misc.rs:51`. Replacing the `TreeHash` derive with a hand-written impl is a localised change; the other derives stay as-is and continue to ignore the added `OnceLock` field via field-attribute filtering in the derive macro (Phase 3 adds a `#[ssz(skip)]` attribute to the derives, or — equivalent — Phase 3 routes the `OnceLock` through `#[serde(skip)]`-style interior plumbing on a separate non-derived field; the chosen mechanism is settled in Task 3.1).
- A8: The `make conformance` target (`Makefile` per CLAUDE.md workflow guidance) runs `cargo run -p pharos-conformance --release -- --write` with output capture to `target/test-logs/`; reused verbatim in Phase 0 baseline and Phase 5 final.
- A9: `Hash256` is `pharos_utils::Hash256` (a `FixedBytes<32>` alias); already implements `Default`, `Clone`, `Copy`, `Eq`, `PartialEq`, `Hash`. `OnceLock<Hash256>` is `Send + Sync` because `Hash256: Send + Sync`.
- A10: The conformance writer's current ~657 s baseline is measured single-threaded against `cargo run -p pharos-conformance --release -- --write` after a warm cargo cache, with fixtures at `~/.cache/pharos-spec-tests/`. The baseline Phase 0 task re-measures this number on the current commit; the recorded value supersedes the ~657 s estimate from the roadmap.

## Out of Scope
- LRU cache for repeated `tree_hash_root` calls on stable Validators (deferred to M11 per roadmap line 519).
- Custom SHA-256 paths (`sha2-asm`, AVX-512 intrinsics) — deferred to M11 per roadmap line 521.
- Cross-thread tree-node interning (lock-free `Arc<Node>` dedup) — deferred to M11 per roadmap line 522.
- LC gossip validation bodies — M4c.
- Real ethrex devnet runs — M4d.
- Beacon-API HTTP server perf — out of scope, server lands at M7.
- Validator-client perf — out of scope, integration lands at M8.
- Tree-backed bitfield types (`Bitlist`, `Bitvector`) — out of scope; bitfields stay on their current backing storage (`crates/pharos-ssz/src/bitfield.rs`).
- `SszList::with_truncate` / `with_pop` — not in the M0a trait surface and not used by M4a/M4b call sites; out of scope.

## Existing Patterns
- `crates/pharos-ssz/src/tree_hash.rs:185-252` `merkleize_padded_inner` is the model for the tree-backed root computation: ping-pong buffers across levels, `PAR_PAIRS_THRESHOLD = 16` for `par_iter_mut`. The tree backend lifts this into structural sharing.
- `crates/pharos-ssz/src/sequence.rs:573-650` existing `TreeHash for SszList` / `SszVector` impls show the rayon threshold pattern (`PAR_THRESHOLD = 1024` at lines 597, 636); the tree-backed impl deletes the per-element `par_iter` because the per-node hashes are already cached at the tree level.
- `crates/pharos-ssz-derive/src/lib.rs:347-389` `derive_tree_hash` is the single emission point for the field-level rayon strategy (Phase 4).
- `crates/pharos-conformance/src/lib.rs:49-1655` `run(filter, bail) -> Report` is the single function the conformance binary calls; the Phase 5 refactor preserves its signature exactly.
- `docs/perf-baseline-m1.md` is the template for the `docs/perf/m4-perf-{baseline,after}.md` files (Phase 0 + Phase 6).
- `crates/pharos-types/src/phase0/misc.rs:51-69` `Validator` declaration is the only call site whose `derive(TreeHash)` is replaced; every other container keeps the derive.

## Cross-cutting risks (referenced by Phase tasks)
- R1 — Tree-backed root divergence from `Vec` backend: pinned by the Phase 1 proptest comparing `tree_hash_root` per random sequence-surgery transcript against the `Vec`-backed reference.
- R2 — `Clone` of a `Validator` with a populated `OnceLock` cache silently sharing a stale hash after a field mutation: a cloned `Validator` retains its cached root (`OnceLock<T: Clone>` Clone copies the populated value; verified against rustc 1.95 stdlib). If the clone's fields are identical, the cache is correct. If the caller intends to change a field, it must reconstruct via `SszList::with_set`, which builds a fresh `Validator` value with an empty `OnceLock` (the new struct is built field-by-field by the caller; the new `OnceLock` is `Default::default()`); the old reference is dropped, the stale root can never be observed. Pinned by `validator_clone_carries_cache` and `with_set_resets_validator_cache` tests in Task 3.3.
- R3 — `Default` for `Validator` returns a value whose `OnceLock` is empty; first `tree_hash_root` call must populate it. Pinned by a unit test in Phase 3.
- R4 — Field-level `rayon::join` over a struct holding a non-`Send` field: every M4a/M4b-shipped container is `Send + Sync` (verified via `cargo check` on the workspace at `9f61883`), but a future container with a `Rc<_>` field would fail to compile against the new derive. Documented in the macro doc comment and pinned by a `compile_fail` doctest in Phase 4 (Task 4.4).
- R5 — Top-level conformance parallelism re-orders the rows in `docs/conformance.md`: mitigated by a fixed canonical sort in `Report::finish()` per Phase 5 Task 5.3.
- R6 — Criterion bench numbers drift between machines: `D-perf-bench-machine` pins the host; reports carry a `Host` line. The "before vs after" gate is per-machine, not absolute.
- R7 — `process_slots` benches require a Bellatrix `BeaconState` with non-trivial validator set; the existing M0c minimal fixture (`~/.cache/pharos-spec-tests`) provides one. The bench helper in Phase 0 Task 0.3 loads it once at startup.
- R8 — Bail semantics regression: rayon `par_iter` cannot cooperatively cancel in-flight workers; the M2-shipped `bail: bool` flag in `run()` is downgraded from "stop immediately on first failure" to "stop scheduling new categories after the first failure is observed". Documented in the doc comment on `run()` and pinned by an updated unit test in Phase 5 Task 5.5.
- R9 — Tree-backed `with_set(i, v)` on a list whose depth was sized for `N` but currently holds `len < N` elements with `ZeroSubtree(depth)` filler must produce the same root as the `Vec` backend (which materialises absent elements as `T::default()` in some call sites but uses pure zero-chunk padding for the SSZ list root). The Phase 1 byte-identical proptest catches this.
- R10 — `Arc<Node<T>>` reference counts on a long-lived `BeaconState` clone chain leak memory if `with_set` always allocates fresh `Branch` nodes rather than reusing the shared subtree pointer. The CoW path-copy implementation (Task 1.2) only allocates `O(log N)` new nodes per write; pinned by a Phase 1 unit test asserting `Arc::strong_count` on an untouched subtree stays at 2 across a `with_set` call.

## Implementation Plan

### Phase 0 — Bench baseline + perf doc skeleton
Why this phase: the M4-perf scope hinges on "before vs after" numbers; without a captured baseline on the current commit, the under-60s gate is unmeasurable. Phase 0 also commits the `docs/perf/` directory layout, the criterion bench harnesses, and the flamegraph SVG so every later phase has a stable reporting target.

- [ ] Task 0.1: Create `docs/perf/` directory containing `m4-perf.md` (running ledger across all phases; skeleton: `# M4-perf perf ledger`, `Host:`, `Date:`, `Commit:`, `Workload:`, `## Phase 0 — baseline`, sub-heads `### Conformance writer wall-clock`, `### tree_hash_root(BeaconState)`, `### process_slots`, `### Hotspot flamegraph`). Later phases append their own `## Phase N — <name>` section. The Phase 0 sub-heads are filled by Tasks 0.5, 0.6, 0.7. Decision: a single ledger file, not a per-phase artifact, so the reviewer can diff phase numbers in one place.
- [ ] Task 0.2: Add `[dev-dependencies] criterion = { workspace = true }` and `[[bench]] name = "tree_hash_beacon_state"` + `[[bench]] name = "ssz_sequence_ops"` blocks to `crates/pharos-ssz/Cargo.toml`. Add `[dev-dependencies] criterion = { workspace = true }` and `[[bench]] name = "process_slots"` to `crates/pharos-stf/Cargo.toml`. Add `harness = false` to every `[[bench]]` block (criterion requires it).
- [ ] Task 0.2.a (O5): Add a `make bench` target to the workspace `Makefile`, parallel in shape to the existing `make conformance` target. The target MUST:
  - Run both criterion bench binaries: `cargo bench -p pharos-ssz --bench tree_hash_beacon_state` and `cargo bench -p pharos-stf --bench process_slots` (and `cargo bench -p pharos-ssz --bench ssz_sequence_ops`).
  - Accept a `BENCH_ARGS` variable forwarded to each `cargo bench` via `--`, so callers can pass `--save-baseline m4-perf-pre` and `--baseline m4-perf-pre`.
  - Tee combined output to `target/test-logs/bench-$$(date +%Y%m%d-%H%M%S).log` via the project's standard capture pattern (`mkdir -p target/test-logs && cargo bench ... 2>&1 | tee target/test-logs/bench-<ts>.log`), with `pipefail` semantics matching `make conformance`.
  - Be listed under `make help`.
  Sketch:
  ```make
  BENCH_ARGS ?=
  bench:
  	mkdir -p target/test-logs
  	set -o pipefail; cargo bench -p pharos-ssz --bench tree_hash_beacon_state -- $(BENCH_ARGS) 2>&1 | tee target/test-logs/bench-ssz-$$(date +%Y%m%d-%H%M%S).log
  	set -o pipefail; cargo bench -p pharos-stf --bench process_slots -- $(BENCH_ARGS) 2>&1 | tee target/test-logs/bench-stf-$$(date +%Y%m%d-%H%M%S).log
  ```
  All later bench-running tasks (Task 0.6, 2.5, 3.5, 4.6, 5.7) MUST invoke `make bench` rather than raw `cargo bench`, per CLAUDE.md's mandate to prefer `make` targets for output capture.
- [ ] Task 0.3: Create `crates/pharos-ssz/benches/tree_hash_beacon_state.rs` with two criterion groups: `tree_hash_root/mainnet/BeaconState` and `tree_hash_root/minimal/BeaconState`. Each group loads a `bellatrix::BeaconState<MainnetEthSpec>` (or `MinimalEthSpec`) from `~/.cache/pharos-spec-tests/{mainnet,minimal}/bellatrix/sanity/blocks/pyspec_tests/empty_block_transition/pre.ssz_snappy` via the existing `pharos_conformance::fixtures` helper, then benches a single `state.tree_hash_root()` call. Sample size 30, warm-up 5 s, measurement 30 s.
  **Cold-cache requirement (N3)**: after Phases 1–3 land, both the per-validator `OnceLock<Hash256>` cache (Phase 3) and the per-tree-node `OnceLock<Hash256>` cache (Phase 1) make a second `state.tree_hash_root()` call a no-op cache lookup. The criterion `iter` loop MUST therefore reconstruct or deep-clone the state inside each iteration so every iter starts cold. Recommended template:
  ```rust
  group.bench_function("BeaconState", |b| {
      b.iter_batched(
          || load_fresh_state(),  // re-decodes from .ssz_snappy bytes; OnceLocks are empty
          |state| { criterion::black_box(state.tree_hash_root()); },
          criterion::BatchSize::SmallInput,
      );
  });
  ```
  Document this constraint as a comment block at the top of the bench file so future readers do not silently switch back to `b.iter(|| state.tree_hash_root())`, which would measure cache-hit latency instead. `criterion::black_box` alone does NOT defeat the `OnceLock`; the cache lives on the `BeaconState` value itself, so a fresh value per iter is the only correct path.
- [ ] Task 0.4: Create `crates/pharos-stf/benches/process_slots.rs` with criterion groups `process_slots/1_slot`, `process_slots/32_slots`, `process_slots/1_epoch` (1 epoch = `SLOTS_PER_EPOCH` slots for the preset). The bench targets the public dispatcher `pharos_stf::process_slots_fork::<MainnetEthSpec>` (verified at `crates/pharos-stf/src/lib.rs:244`) with signature `pub fn process_slots_fork<E: EthSpec>(state: &mut E::BeaconState, target_slot: Slot) -> Result<(), StateTransitionError>` — single `E: EthSpec` generic, no const-generic preset params (the preset constants are carried by the `EthSpec` associated types). The bench loads a Bellatrix `E::BeaconState` into the fork-enum `BeaconState` wrapper at startup, then in each iter clones the wrapper and calls `process_slots_fork::<MainnetEthSpec>(&mut state, state.slot() + delta).unwrap()` (use `criterion::black_box` on `state` to defeat the Phase 3 `Validator` cache). Sample size 30. **N3 note**: every iter MUST start from a freshly-cloned `BeaconState` so the per-validator `OnceLock` and per-tree-node `OnceLock` caches that Phases 1–3 introduce are cold, not warm; comment this constraint inline in the bench source.
- [ ] Task 0.5: Run `make conformance` once, capture wall-clock to `target/test-logs/m4-perf-conformance-baseline.log` via `{ time make conformance ; } 2>&1 | tee target/test-logs/m4-perf-conformance-baseline.log`. Copy the `real`/`user`/`sys` lines + a summary of `pass`/`fail`/`skip` totals into `docs/perf/m4-perf.md` under `## Phase 0 — baseline` → `### Conformance writer wall-clock`. Run ONCE per session per CLAUDE.md workflow rules.
- [ ] Task 0.6: Run the two criterion bench binaries via `make bench` (introduced in Task 0.2.a). Each invocation MUST pass `-- --save-baseline m4-perf-pre` so criterion stashes the pre-M4-perf numbers under the named baseline; later phases pass `-- --baseline m4-perf-pre` for automatic regression tables. Concretely: `make bench BENCH_ARGS='--save-baseline m4-perf-pre'` (or, if `make bench` does not yet wrap baseline flags, run `cargo bench -p pharos-ssz --bench tree_hash_beacon_state -- --save-baseline m4-perf-pre` and `cargo bench -p pharos-stf --bench process_slots -- --save-baseline m4-perf-pre` directly, each tee'd via the `make bench` capture wrapper). Copy the `time:` lines from criterion's output into `docs/perf/m4-perf.md` under the matching `##` heads. The hand-written markdown numbers and the criterion-stashed `m4-perf-pre` baseline are both required artifacts; neither is a substitute for the other.
- [ ] Task 0.7: Capture a flamegraph of the conformance writer hot path.
  Pre-checks (run first):
  - `cargo flamegraph --version` must succeed; if not installed, install via `TMPDIR=~/.cache/tmp cargo install flamegraph` (per CLAUDE.md `/tmp` is RAM-backed; the `TMPDIR` override keeps the scratch tree on disk).
  - `cat /proc/sys/kernel/perf_event_paranoid` must be `<= 1` (or `-1`) for `perf record` to attach without `CAP_SYS_ADMIN`. If higher, run `echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid` (transient; reverts on reboot). Document the value used in `docs/perf/m4-perf.md` under the `### Hotspot flamegraph` sub-head.
  Capture command: `cargo flamegraph -p pharos-conformance --profile bench -- --write` (env: `CARGO_PROFILE_BENCH_DEBUG=line-tables-only`). Output SVG to `docs/perf/m4-perf-baseline-flamegraph.svg`.
  Acceptable fallbacks if `cargo flamegraph` is unworkable on the host: (a) `samply record -- target/release/pharos-conformance --write` then export the firefox-profiler view as SVG; (b) `perf record -g -- target/release/pharos-conformance --write` then `perf script | inferno-flamegraph > docs/perf/m4-perf-baseline-flamegraph.svg`. The goal is the SVG/profile artifact; the tool is replaceable.
  The flamegraph is the visible-to-reviewer evidence that sha-256 + `tree_hash_root` dominate; reference it from `docs/perf/m4-perf.md` under `## Phase 0 — baseline` → `### Hotspot flamegraph`.
- [ ] Task 0.8: **Checkpoint: Verify Phase 0 complete**. Confirm `docs/perf/m4-perf.md` Phase 0 section is populated with real numbers (no `TODO`), `docs/perf/m4-perf-baseline-flamegraph.svg` exists and is non-empty, both `[[bench]]` blocks compile (`cargo check -p pharos-ssz --benches`, `cargo check -p pharos-stf --benches`), `make conformance` ran ONCE this session, and the captured wall-clock matches the recorded number in the markdown. List each task and status.

**Commit boundary**: `perf(m4-perf): phase 0 — baseline benches + flamegraph + docs/perf skeleton`.

### Phase 1 — Tree-backed `SszList<T, N>` / `SszVector<T, N>` core
Why this phase: every later perf gain stacks on top of the tree backend; without it, `Validator` caching (Phase 3) only saves a single `tree_hash_root` per validator per slot rather than the path-copy O(log N) win. Phase 1 ships the tree implementation behind the existing `SszSequence` trait so call sites compile unchanged.

- [ ] Task 1.1: Replace `Node<T>` at `crates/pharos-ssz/src/sequence.rs:61-63` with the real shape:
  ```rust
  enum Node<T> {
      Branch { left: Arc<Node<T>>, right: Arc<Node<T>>, hash: OnceLock<Hash256> },
      Leaf(T),
      ZeroSubtree(u8),  // depth; root is zero_hash(depth)
  }
  ```
  Add `use std::sync::OnceLock;` to the file's prelude. Replace the `_marker: PhantomData<T>` field. The `Backend::Tree(Arc<Node<T>>)` enum slot at `sequence.rs:49-55` is unchanged.
- [ ] Task 1.2: Implement CoW operations on `Node<T>` at the bottom of `sequence.rs` (new section `// ── Node ──`):
  - `fn get(self: &Arc<Self>, i: usize, depth: u8) -> Option<&T>` — recursive descent picking left/right by the high bit of `i`.
  - `fn with_set(self: &Arc<Self>, i: usize, v: T, depth: u8) -> Arc<Node<T>>` where `T: Clone` — path-copy: clone only the spine from root to target leaf, reuse the off-path subtree `Arc` unchanged.
  - `fn cached_root(&self) -> Hash256` where `T: TreeHash` — `match self { Leaf(t) => t.tree_hash_root(), ZeroSubtree(d) => zero_hash(*d as usize), Branch { left, right, hash } => *hash.get_or_init(|| hash_concat(left.cached_root().as_ref(), right.cached_root().as_ref())) }`.
  - `fn from_slice(elems: &[T], depth: u8) -> Arc<Node<T>>` where `T: Clone` — bottom-up build, materialising `ZeroSubtree(d)` for absent right-hand subtrees, materialising `Leaf(t)` for each element. Used by `from_vec` and `from_ssz_bytes`.
- [ ] Task 1.3: Add a per-instance `depth: u8` derivation. Add a private helper `const fn depth_for_limit(n: u64) -> u8 { ((64 - n.leading_zeros()) as u8).max(1) }` to `sequence.rs`. On `SszList<T, N>` / `SszVector<T, N>`, the depth is `depth_for_limit(N)` evaluated at use sites (not stored). For composite-element lists, leaves are per-element. Basic-element lists (`SszList<u8, _>`, `SszList<u32, _>`, `SszList<u64, _>`, and any other `T: BasicType`) stay on `Backend::Naive(Vec<T>)` for M4-perf. This is a deliberate scope deferral: their hash cost is dominated by raw byte hashing across packed chunks, not by tree-structure rebuilds, so the tree backend's win is smaller; introducing a chunk-typed `Node<u8>` tree is deferred to a later perf slice (M11ish per `docs/roadmap.md:519-522`). This deferral does not change the Phase 2 file list — `balances` and `inactivity_scores` remain `Naive` and were already going to be `Naive` per the Phase 2 Task 2.1 decision rule.
- [ ] Task 1.4: Replace every `Backend::Tree(_) => unimplemented!("tree backend lands in a later milestone")` branch in `sequence.rs` (10 sites verified at planning time: `:69, :78, :195, :234, :241, :253, :275, :297, :348, :393, :403, :425`) with the real tree-backend implementation:
  - `Clone for Backend<T>::Tree(arc)` — `Backend::Tree(Arc::clone(arc))` (O(1)).
  - `PartialEq` over two trees — element-by-element via `iter().eq(other.iter())`; on mismatched discriminants fall back to comparing `as_slice_via_iter().eq(...)`.
  - `Debug for Backend<T>::Tree` — collect first-16-then-`...` for legibility.
  - `SszList::as_slice` and `SszVector::as_slice` — the tree backend cannot expose a contiguous slice; rename to `as_slice` returning `Cow<'_, [T]>` would break callers. Keep `as_slice(&self) -> &[T]` on the `Naive` path; add `fn to_vec(&self) -> Vec<T> where T: Clone` to the `SszSequence` trait surface (Task 1.6). Callers that need a slice (`Encode::ssz_append`, `Decode::from_ssz_bytes`, internal merkleization) switch to `iter()` or `to_vec()` as documented in the per-method match arm.
  - `SszSequence::{len, get, iter, with_set, with_push}` for the tree backend — each routes to the `Node<T>` helpers in Task 1.2.
- [ ] Task 1.5: Update the SSZ `Encode` impls at `sequence.rs:443-473` and `sequence.rs:501-534`: replace `self.as_slice()` with `let elems: Vec<T> = self.iter().cloned().collect()` for tree-backed values; keep the `Naive` fast path via a `match &self.backend` branch in `ssz_bytes_len` and `ssz_append`. Same for `Decode::from_ssz_bytes` at `sequence.rs:475-497` and `:536-569`: decode into `Vec<T>` as today, then wrap in `Backend::Naive(_)` (decoding always lands in the `Naive` path; the tree backend is only entered explicitly via a new `SszList::from_vec_tree` constructor in Task 1.6).
- [ ] Task 1.6: Add public constructors and the new `to_vec` trait method:
  - `SszList::<T, N>::from_vec_tree(v: Vec<T>) -> Result<Self, SszError>` (composite-element variant; basic-element variant returns `SszError::Custom("tree backend requires composite element type")`).
  - `SszVector::<T, N>::from_vec_tree(v: Vec<T>) -> Result<Self, SszError>` (same composite-element restriction).
  - `SszList::<T, N>::empty_tree() -> Self` — zero-element tree-backed list; backend is `Backend::Tree(Arc::new(Node::ZeroSubtree(depth_for_limit(N))))`; `len = 0`. Root computation yields `mix_in_length(zero_hash(depth_for_limit(N)), 0)`, byte-identical to the `Naive` empty-list root. Composite-element restriction applies as for `from_vec_tree`.
  - `SszVector::<T, N>::empty_tree() -> Self` is intentionally NOT added: SSZ `Vector<T, N>` has fixed length `N` and an "empty" vector is not a valid SSZ value; `BeaconState` vector fields are initialised with `N` default-`T` elements via existing constructors.
  - Add `fn to_vec(&self) -> Vec<T> where T: Clone;` to `trait SszSequence` (default impl: `self.iter().cloned().collect()`).
- [ ] Task 1.7: Implement `TreeHash for SszList<T, N>` and `for SszVector<T, N>` (replacing the bodies at `sequence.rs:573-650`) so that:
  - `Backend::Naive(_)` → unchanged path (already correct).
  - `Backend::Tree(arc)` → `arc.cached_root()` (which folds `OnceLock` caches up the tree). For `SszList`, follow with `mix_in_length(root, len)` per the existing `:608` line.
  - Composite-element `SszList`: when the live element count is `< N`, the tree backend's per-level `ZeroSubtree(d)` filler reproduces the `merkleize_padded(roots, limit=N)` zero-tail.
  - Pin byte-identity vs the `Naive` path with the Phase 1 Task 1.9 proptest.
- [ ] Task 1.8: Mid-phase checkpoint task: **Checkpoint: Verify Phase 1 mid-point**. Run `cargo check -p pharos-ssz`, `cargo test -p pharos-ssz --lib`, `cargo clippy -p pharos-ssz -- -D warnings`. Confirm all 10 `unimplemented!()` sites are gone, all `SszSequence` methods route to both backends. List task statuses.
- [ ] Task 1.9: Add a property test at `crates/pharos-ssz/tests/tree_backend_proptest.rs` that:
  - Generates a random transcript of `set(i, v)`, `push(v)`, `from_vec(...)` operations against both backends in lockstep.
  - After each op asserts (`prop_assert_eq!`) `naive.tree_hash_root() == tree.tree_hash_root()`, `naive.len() == tree.len()`, `(0..naive.len()).all(|i| naive.get(i) == tree.get(i))`, and `naive.as_ssz_bytes() == pharos_ssz::Encode::as_ssz_bytes(&tree)`.
  - Uses `MAX_N = 8192` (large enough to exercise multi-level paths, small enough to keep proptest runs under 60 s). Element type: `u64` for basic-element sanity wrapped via `composite-mode` wrapper struct `#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq)] struct Leaf(u64);`.
  - Runs 256 cases (`#![proptest_config(ProptestConfig { cases: 256, ..Default::default() })]`).
- [ ] Task 1.10: Add a unit test at `crates/pharos-ssz/src/sequence.rs::tests` named `with_set_path_copy_preserves_shared_subtrees`:
  - Build a tree-backed `SszList<Leaf, 1024>` with 1024 elements via `from_vec_tree`.
  - Note the `Arc::strong_count` of the root's left.left child (`root.left.left`).
  - Call `with_set(1023, Leaf(0xdead))` (mutates the rightmost element; the entire left subtree should be untouched).
  - Assert the `Arc::strong_count` of `root.left.left` increased by exactly 1 (the new tree's reference) and that the pointer equality `Arc::ptr_eq(&old.left.left, &new.left.left)` holds.
- [ ] Task 1.11: **Checkpoint: Verify Phase 1 complete**. Run `cargo test -p pharos-ssz`, `cargo test -p pharos-ssz --test tree_backend_proptest`, `cargo clippy -p pharos-ssz -- -D warnings`. Confirm the proptest runs 256 cases without divergence. List each task status. Do not proceed until all are green.

**Commit boundary**: `perf(ssz): phase 1 — tree-backed SszList/SszVector with path-copy CoW + cached roots`.

### Phase 2 — Switch hot-path containers to the tree backend + bench
Why this phase: shipping the tree backend without flipping any call site is dead code. Phase 2 wires the tree backend into the largest, hottest containers — composite-element fields (`validators`, `previous_epoch_attestations`/`current_epoch_attestations`) AND `FixedBytes<32>` fields admitted via the `PACKED_AS_FULL_CHUNK` carveout in commit `20bb167` (`historical_roots`, `state_roots`, `block_roots`, `randao_mixes`) — then re-runs the conformance gate to confirm zero-diff. `state_roots`/`block_roots` mutate every slot, so their per-slot path-copy win is the largest single contribution to the M4-perf goal.

- [ ] Task 2.1: Audit every `SszList<_, _>` and `SszVector<_, _>` field in `crates/pharos-types/src/{phase0,altair,bellatrix}/state.rs` (BeaconState definitions) and `state.rs` (BeaconBlockBody definitions). Produce a tabular comment at the top of `crates/pharos-types/src/lib.rs` listing each field, its element type, its limit, its `Naive` vs `Tree` decision, and the per-slot mutation rate. Decision rule for `Tree`: composite-element OR `T::PACKED_AS_FULL_CHUNK` (currently only `FixedBytes<32>` / `Hash256` / `Root` / `Bytes32`). Genuinely-packed basic types (`u64`, `u8`, `bool`, `FixedBytes<N<32>`) stay `Naive`. Expected `Tree` set: `validators` (all forks), `historical_roots` (all forks — admitted via PACKED_AS_FULL_CHUNK), `state_roots` (all forks — every-slot mutation, biggest win), `block_roots` (all forks — every-slot mutation), `randao_mixes` (all forks), `previous_epoch_attestations`/`current_epoch_attestations` (phase0 only). `inactivity_scores` / `balances` (altair/bellatrix) stay `Naive`: basic-element `SszList<u64, _>`, genuinely multi-per-chunk packed; deferred to M11 per Task 1.3. The table MUST record both the genuinely-deferred basics and the `PACKED_AS_FULL_CHUNK`-admitted basics, citing the appropriate justification per row.
- [ ] Task 2.2: For EVERY field in the Phase-2 Tree set (see Task 2.1): change the `BeaconState::default()` initialiser path so the field constructs an empty `Tree`-backed value. For `SszList` fields use `SszList::empty_tree()`. For `SszVector` fields use `SszVector::from_vec_tree(vec![T::default(); N as usize])?` — the SSZ spec requires `Vector<T, N>` to have exactly `N` elements at all times, so there is no "empty" tree vector; the initialiser builds a tree-backed value populated with `N` default elements (mirrors what `SszVector::default()` does on the Naive backend today).
  Fields to flip (per fork):
  - `validators: SszList<Validator, VALIDATOR_REGISTRY_LIMIT>` (phase0, altair, bellatrix)
  - `historical_roots: SszList<Root, HISTORICAL_ROOTS_LIMIT>` (phase0, altair, bellatrix) — `Root = FixedBytes<32>`, admitted via `PACKED_AS_FULL_CHUNK`
  - `state_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>` (phase0, altair, bellatrix) — `PACKED_AS_FULL_CHUNK`
  - `block_roots: SszVector<Root, SLOTS_PER_HISTORICAL_ROOT>` (phase0, altair, bellatrix) — `PACKED_AS_FULL_CHUNK`
  - `randao_mixes: SszVector<Bytes32, EPOCHS_PER_HISTORICAL_VECTOR>` (phase0, altair, bellatrix) — `Bytes32 = FixedBytes<32>` — `PACKED_AS_FULL_CHUNK`
  - `previous_epoch_attestations: SszList<PendingAttestation<E>, MAX_ATTESTATIONS * SLOTS_PER_EPOCH>` (phase0 only)
  - `current_epoch_attestations: SszList<PendingAttestation<E>, MAX_ATTESTATIONS * SLOTS_PER_EPOCH>` (phase0 only)
  Where SSZ decode lands a `Naive`-backed value (per Task 1.5), add an explicit conversion at decode time in the relevant `Decode for BeaconState<...>` impl — locate each call site by `rg "from_ssz_bytes" crates/pharos-types/src/{phase0,altair,bellatrix}/state.rs`. Add `pub fn into_tree(self) -> Self` on `SszList` (Naive → `from_vec_tree(v)?`, else self) and an analogous `pub fn into_tree(self) -> Self` on `SszVector`.
- [ ] Task 2.2.b: Migrate `as_slice()` callers on tree-backed fields. The tree backend has no contiguous `&[T]` and `as_slice()` is unavailable there (per Task 1.4); every caller whose receiver is a field flipped to `Tree` in Task 2.1 must be migrated to the tree-backend trait API.
  Enumerated call sites (from `rg -n '\.as_slice\(\)' crates/pharos-stf crates/pharos-types crates/pharos-storage` at planning time, filtered to receivers that are tree-flipped fields per Task 2.1):
  - `crates/pharos-types/src/bellatrix/state.rs:223` — `self.validators.as_slice()` (accessor returning `&[Validator]`); migrate the accessor signature to return an iterator (`fn validators(&self) -> impl Iterator<Item = &Validator> + '_ { self.validators.iter() }`) and update callers, OR keep the accessor as a deprecated `to_vec()` returning `Vec<Validator>` and migrate callers to the new iterator-shaped accessor.
  - `crates/pharos-types/src/altair/state.rs:209` — same `self.validators.as_slice()` pattern; same migration.
  - `crates/pharos-types/src/views.rs:269` — `BeaconStateView::validators(&self) -> &[Validator]`; widen to `impl Iterator<Item = &Validator> + '_` (or `Vec<Validator>` if a view consumer requires owned).
  - `crates/pharos-stf/src/phase0/state_write.rs:289` — `self.previous_epoch_attestations.as_slice()` accessor body. Same iterator migration.
  - `crates/pharos-stf/src/phase0/state_write.rs:293` — `self.current_epoch_attestations.as_slice()` accessor body. Same iterator migration.
  - `crates/pharos-stf/src/bellatrix/epoch/mod.rs:358` — `state.validators.as_slice().get(i)?`; migrate to `state.validators.get(i)?` (the existing `SszSequence::get` trait method).
  Mechanical translation table for callers downstream of the accessors above:
  - `.as_slice().get(i)` → `.get(i)` (existing trait method).
  - `.as_slice().iter()` → `.iter()`.
  - `.as_slice().len()` → `.len()`.
  - `.as_slice().to_vec()` → `.to_vec()` (introduced by Task 1.4 / Task 1.6).
  - `.as_slice()` used as `&[T]` argument to a function — change the receiving function's parameter type to `impl IntoIterator<Item = &T>` or call `.to_vec().as_slice()` at the call site if the function cannot be changed (the latter forces a Vec materialisation; only acceptable if profile shows it's cold).
  Gate: `cargo check -p pharos-stf && cargo check -p pharos-types && cargo check -p pharos-storage && cargo check -p pharos-fork-choice && cargo check -p pharos-engine` exits 0; no `as_slice()` call whose receiver is a tree-flipped field remains. Final `rg` to confirm: `rg '\b(validators|previous_epoch_attestations|current_epoch_attestations|historical_roots|state_roots|block_roots|randao_mixes)\.as_slice\(' crates/` returns empty (other-field `as_slice` on `Naive` lists is unaffected).
  Pre-completion sub-task: re-run the widened workspace-wide scan for every tree-flipped field: `rg -n '\b(validators|historical_roots|state_roots|block_roots|randao_mixes|previous_epoch_attestations|current_epoch_attestations)\.as_slice\b' crates/`. Enumerate every newly-discovered call site here as a checklist line and migrate it per the translation table above. The original `rg` (limited to `pharos-stf crates/pharos-types crates/pharos-storage`) missed `pharos-fork-choice` and `pharos-engine`; the M4a fork-choice work may have introduced additional call sites since planning time. As of the widened planning-time scan the additional confirmed sites are:
  - `crates/pharos-stf/src/altair/epoch/registry_updates.rs:119` — `state.validators.as_slice().get(i)`; migrate to `state.validators.get(i)`.
  - `crates/pharos-stf/src/altair/epoch/slashings.rs:93` — `state.validators.as_slice().get(i)`; migrate to `state.validators.get(i)`.
  Implementer MUST re-run the widened `rg` at completion time to catch any additional sites introduced between planning and implementation in `pharos-fork-choice` / `pharos-engine` / any other crate.
- [ ] Task 2.3: For every hot-path STF site that mutates `validators` or another `Tree`-backed list — `set_validator`, `append_validator`, `update_validator_balance` and equivalents — locate the call site via `rg "validators\.with_set\|validators\.with_push\|state\.validators_mut\b" crates/pharos-stf/`. Each call already uses the `with_set`/`with_push` CoW API (M0c constraint); no code change is needed in STF. Verify by spot-checking the `process_registry_updates` site at `crates/pharos-stf/src/phase0/epoch_processing.rs` (use `rg` to find the actual line) and assert it routes through `with_set`.
- [ ] Task 2.4: Run `make conformance` once. Capture wall-clock to `target/test-logs/m4-perf-conformance-phase2.log`. Diff `docs/conformance.md` against the Phase 0 baseline copy (the file in the working tree pre-`make conformance` was already at the baseline numbers; if `make conformance` regenerates it, the diff must be zero on rows). Use `diff docs/conformance.md target/test-logs/conformance.md.baseline` where `target/test-logs/conformance.md.baseline` is a copy stashed at the start of Task 2.4.
- [ ] Task 2.5: Run `make bench BENCH_ARGS='--baseline m4-perf-pre'` (per Task 0.2.a). The combined log lands under `target/test-logs/bench-<ts>.log`. Append a `## Phase 2 — validators → tree backend` section to `docs/perf/m4-perf.md` with the new criterion `time:` numbers and the conformance wall-clock. (The file is the running ledger created in Phase 0 Task 0.1; no rename needed.)
- [ ] Task 2.6: Unit tests in `crates/pharos-types/src/phase0/state.rs::tests` (and altair/bellatrix equivalents): construct a default `BeaconState<MinimalEthSpec>` and assert (via `pub fn backend_is_tree(&self) -> bool` on `SszList` and `SszVector`) that every Phase-2-tree-set field is tree-backed. One test per field: `validators_field_uses_tree_backend`, `historical_roots_field_uses_tree_backend`, `state_roots_field_uses_tree_backend`, `block_roots_field_uses_tree_backend`, `randao_mixes_field_uses_tree_backend`, plus the phase0-only `previous_epoch_attestations` and `current_epoch_attestations`. The `backend_is_tree` accessor lives on both `SszList` and `SszVector` (added in Phase 1's carveout commit `20bb167`); already public.
- [ ] Task 2.7: **Checkpoint: Verify Phase 2 complete**. Run `make pre-commit`. Verify `make conformance` produced zero-diff on `docs/conformance.md`. Verify the `docs/perf/m4-perf.md` ledger has Phase 2 numbers populated. Verify the per-field decision table at `crates/pharos-types/src/lib.rs` top exists. List task statuses.

**Commit boundary**: `perf(types): phase 2 — flip large-N composite validators/historical_roots to tree backend`.

### Phase 3 — Validator-level `OnceLock` cache on `tree_hash_root`
Why this phase: `process_slots` rehashes every validator every slot via `BeaconState::tree_hash_root`; with the tree backend the per-validator hash is the only thing that still recomputes when the validator itself is unchanged. Caching it on the validator struct is the smallest, highest-leverage additional optimisation.

- [ ] Task 3.1: Modify `crates/pharos-types/src/phase0/misc.rs:51` (add `use pharos_ssz::{merkleize, TreeHash, TreeHashType}; use pharos_utils::Hash256;` to the file's `use` block so the hand-written `TreeHash` impl below resolves):
  - Replace `#[derive(Encode, Decode, TreeHash, Clone, Debug, PartialEq, Eq, Default)]` with `#[derive(Encode, Decode, Clone, Debug, Default)]` (drop `TreeHash`, `PartialEq`, `Eq`).
  - Add a new private field `#[doc(hidden)] cached_root: std::sync::OnceLock<pharos_utils::Hash256>` at the END of the struct (after `withdrawable_epoch`).
  - Hand-write a `TreeHash` impl below the struct that:
    ```rust
    impl TreeHash for Validator {
        const TREE_HASH_TYPE: TreeHashType = TreeHashType::Container;
        fn tree_hash_root(&self) -> Hash256 {
            *self.cached_root.get_or_init(|| {
                let roots: &[Hash256] = &[
                    self.pubkey.tree_hash_root(),
                    self.withdrawal_credentials.tree_hash_root(),
                    self.effective_balance.tree_hash_root(),
                    self.slashed.tree_hash_root(),
                    self.activation_eligibility_epoch.tree_hash_root(),
                    self.activation_epoch.tree_hash_root(),
                    self.exit_epoch.tree_hash_root(),
                    self.withdrawable_epoch.tree_hash_root(),
                ];
                // 8 fields = power-of-two; `merkleize(roots)` and
                // `merkleize_padded(roots, 8)` are equivalent here.
                merkleize(roots)
            })
        }
        fn tree_hash_packed_encoding(&self) -> Vec<u8> {
            unreachable!("containers are not basic types and are never packed")
        }
    }
    ```
  - Hand-write `PartialEq` and `Eq` ignoring `cached_root`: `impl PartialEq for Validator { fn eq(&self, o: &Self) -> bool { self.pubkey == o.pubkey && ... && self.withdrawable_epoch == o.withdrawable_epoch } }`.
  - The `#[derive(Clone)]` already produces `OnceLock<Hash256>::clone()` which copies the cached value if populated (`OnceLock` is `Clone` when `T: Clone`; verified at planning time against `std::sync::OnceLock<T> where T: Clone` in stdlib 1.85). This is the correct semantic: a cloned validator with unchanged fields has the same root.
  - Extend `pharos-ssz-derive` for `Encode` and `Decode` to accept a `#[ssz(skip)]` field attribute that excludes the field from both wire encoding and decoding. Apply `#[ssz(skip)]` to the `cached_root` field. This is a localised derive-macro change in `crates/pharos-ssz-derive/src/lib.rs` (Task 3.2 covers the derive-macro work).
- [ ] Task 3.2: Modify `crates/pharos-ssz-derive/src/lib.rs::named_fields`:
  - Return `Vec<NamedField>` whose `NamedField` gains a `skip: bool` boolean parsed from `#[ssz(skip)]`.
  - Filter `skip == true` fields from the `Encode`, `Decode`, and (in case a future caller needs it) `TreeHash` derive emissions. For `Decode`, the constructed struct value uses `Default::default()` for the skipped field — emit `Validator { ..., cached_root: Default::default() }` rather than `Validator { ..., cached_root }` for fields not in the decoded set.
  - Add a unit test in `crates/pharos-ssz-derive/tests/skip_attr.rs` defining `#[derive(Encode, Decode)] struct S { a: u64, #[ssz(skip)] b: std::sync::OnceLock<pharos_utils::Hash256> }`, encoding and decoding round-trips correctly (the skipped field is `Default::default()` on decode), and the encoded bytes equal `a.as_ssz_bytes()`.
- [ ] Task 3.3: Unit tests at `crates/pharos-types/src/phase0/misc.rs::tests`:
  - `validator_root_cache_populates`: build a default `Validator`, observe `Arc::strong_count`-like behaviour — call `tree_hash_root()` twice, assert both calls return the same value, and via a `#[cfg(test)] fn cached_root_is_populated(&self) -> bool { self.cached_root.get().is_some() }` accessor assert population state transitions from `false` → `true` across the first call.
  - `validator_clone_carries_cache`: build a validator, call `tree_hash_root()`, clone, assert the clone's `cached_root_is_populated() == true` and returns the same root without recomputation. (Detection of "no recomputation" is via a global counter incremented inside the `OnceLock` init closure under `#[cfg(test)]`.) Note: `OnceLock<T: Clone>` Clone copies the populated value (empirically verified against rustc 1.95 stdlib); this is the documented and required semantic per `D-validator-cache`.
  - `with_set_resets_validator_cache`: build a `BeaconState` with 8 validators; call `state.validators.tree_hash_root()` to populate the list root and observe the value `R0`; build a `modified` validator with `effective_balance` changed; call `state.validators = state.validators.with_set(7, modified)?` (the CoW write reconstructs the wrapping list, the new `modified` validator's `OnceLock` is empty by construction); call `state.validators.tree_hash_root()` again and assert it differs from `R0` (because the rebuilt validator and its parent list nodes recompute through fresh `OnceLock`s on the spine). Asserts the structural invariant that field changes always go through `with_set`, and the cache cannot serve a stale root.
  - `validator_ssz_byte_identity`: build a validator, encode via `as_ssz_bytes`, decode, assert the decoded validator equals the original (modulo `cached_root`, which is reset on decode).
  - `validator_default_root_matches_pre_m4_perf`: precompute the root of `Validator::default()` from the pre-M4-perf derive output (commit `9db9686` — hardcode the 32-byte hex in the test). After Phase 3 the same `Validator::default().tree_hash_root()` must produce the identical bytes.
- [ ] Task 3.4: Run `make conformance`; capture wall-clock to `target/test-logs/m4-perf-conformance-phase3.log`. Diff `docs/conformance.md` against the running baseline; zero-row-diff or this phase is rolled back.
- [ ] Task 3.5: Run `make bench BENCH_ARGS='--baseline m4-perf-pre'` (per Task 0.2.a). Append `## Phase 3: Validator root cache` section to `docs/perf/m4-perf.md` with the new numbers.
- [ ] Task 3.6: **Checkpoint: Verify Phase 3 complete**. Run `make pre-commit`. Confirm zero-diff on `docs/conformance.md`. Confirm `docs/perf/m4-perf.md` Phase 3 section is populated. List task statuses.

**Commit boundary**: `perf(types): phase 3 — OnceLock cache on Validator::tree_hash_root`.

### Phase 4 — Derive-macro field-level rayon
Why this phase: `BeaconState` has ~25 fields. With the tree backend in place the per-field hashes are independent and many are themselves expensive (e.g., a `Tree`-backed `validators` root that needs to fold `OnceLock`s up its spine). Parallelising the per-field array build via `rayon::join` is essentially free given rayon's work-stealing pool.

- [ ] Task 4.1.a: Re-export `rayon` from `pharos-ssz` so derive-emitted code resolves from every consumer crate without each consumer adding a new `rayon` dependency. Edit `crates/pharos-ssz/src/lib.rs`: add `pub use ::rayon;` (alongside the existing `pub use` block). Smoke-test that `cargo check -p pharos-types` resolves `::pharos_ssz::rayon` from the derive-emitted code introduced in Task 4.2; the path is reachable because every `#[derive(TreeHash)]` user already depends on `pharos-ssz` for the `TreeHash` trait.
- [ ] Task 4.1: Add a new private helper `fn build_balanced_join_tree(field_root_exprs: &[TokenStream2]) -> TokenStream2` to `crates/pharos-ssz-derive/src/lib.rs`. It emits a balanced binary `::pharos_ssz::rayon::join` nesting over the input expressions and returns the `[Hash256; N]` array directly. Sketch:
  ```rust
  // For 4 fields [a, b, c, d]:
  let ((r0, r1), (r2, r3)) = ::pharos_ssz::rayon::join(
      || ::pharos_ssz::rayon::join(|| a, || b),
      || ::pharos_ssz::rayon::join(|| c, || d),
  );
  let roots: &[Hash256] = &[r0, r1, r2, r3];
  ```
  For non-power-of-two field counts, build a balanced tree (left half ceiling, right half floor) recursively. For 1 field, no `rayon::join` (the closure is the field itself). The emission MUST use the `::pharos_ssz::rayon::join` path, not `::rayon::join`, so the macro does not require downstream crates to declare a direct `rayon` dep (Task 4.1.a covers the re-export).
- [ ] Task 4.2: Replace the body of `derive_tree_hash_impl` at `crates/pharos-ssz-derive/src/lib.rs:347-389` so that when `field_root_exprs.len() >= 4`, the emission uses `build_balanced_join_tree`; otherwise keep the current serial array emission. Threshold constant: `const PAR_TREE_HASH_FIELD_THRESHOLD: usize = 4;` at the top of the file.
- [ ] Task 4.3: Add a unit test at `crates/pharos-ssz-derive/tests/tree_hash_join_emission.rs` that defines a 25-field struct (mirroring `BeaconState`'s field count), derives `TreeHash`, and asserts `tree_hash_root()` agrees with a hand-written serial-merkleize-over-the-25-field-roots reference value built by `merkleize(&[f1.tree_hash_root(), f2.tree_hash_root(), ...])`. The test does not assert parallelism (it can't; rayon may schedule serially); it asserts byte-identity to the pre-Phase-4 emission.
- [ ] Task 4.4: Add a compile-fail check showing that a struct with a `Rc<u64>` field fails to compile after the derive change, with the error message referencing `Send`/`Sync`.
  **O4 note**: rustc's compile-error message text is not stable across versions; a brittle `compile_fail` doctest that matches on exact wording will break at toolchain bumps. Two acceptable shapes; implementer chooses one and documents the choice in the test file:
  1. `compile_fail` doctest (default): gated to `cfg(doctest)`. Match ONLY on the error code (e.g., `E0277`) and a stable substring (`Send` and/or `Sync`), not the full error sentence. Accept the toolchain-bump maintenance burden: when the message text changes, update the doctest in the same commit as the toolchain bump.
  2. `trybuild`-based test under `crates/pharos-ssz-derive/tests/compile_fail/` (preferred if the workspace already depends on `trybuild`; otherwise adds a new dev-dep): `.stderr` snapshot file auto-blessed via `TRYBUILD=overwrite cargo test`, which makes toolchain-bump maintenance a single command. Add `trybuild = "1"` to `[dev-dependencies]` of `pharos-ssz-derive/Cargo.toml` if it is not already a workspace dep.
- [ ] Task 4.5: Run `make conformance`; capture wall-clock to `target/test-logs/m4-perf-conformance-phase4.log`. Diff `docs/conformance.md`. Zero-row-diff gate.
- [ ] Task 4.6: Run `make bench BENCH_ARGS='--baseline m4-perf-pre'` (per Task 0.2.a). Append `## Phase 4: derive(TreeHash) field-level rayon` section to `docs/perf/m4-perf.md`.
- [ ] Task 4.7: **Checkpoint: Verify Phase 4 complete**. Run `make pre-commit`. Confirm the 25-field test passes, the `compile_fail` doctest is in place, the per-phase row in `docs/perf/m4-perf.md` is populated, and zero-diff on `docs/conformance.md`. List task statuses.

**Commit boundary**: `perf(ssz-derive): phase 4 — field-level rayon::join in derive(TreeHash)`.

### Phase 5 — Top-level conformance category parallelism
Why this phase: the conformance writer is the explicit perf target (657 s → < 60 s). After Phase 4 every per-category walker is internally parallel (commit `9db9686`) and per-state `tree_hash_root` is parallel + cached; the remaining sequential dimension is the top-level `if filter.matches(..)` ladder spanning 1655 lines. Phase 5 collapses the ladder into a `Vec<CategorySpec>` table and runs it through `par_iter`.

- [ ] Task 5.1: Refactor `crates/pharos-conformance/src/lib.rs::run`:
  - Introduce two types:
    ```rust
    #[derive(Clone)]
    struct CategorySpecMeta {
        fork: &'static str,
        category: &'static str,
        preset: &'static str,
    }
    struct CategorySpec {
        meta: CategorySpecMeta,
        runner: Box<dyn Fn(&Path) -> CategoryResult + Send + Sync>,
    }
    ```
    `CategorySpec` itself cannot be `Clone` (the `Box<dyn Fn>` is not `Clone`); `CategorySpecMeta` is `Clone` and is the only piece carried out of the `par_iter` closure alongside the `CategoryResult`.
  - Build a `Vec<CategorySpec>` enumerating every `(fork, category, preset)` triple currently in the ladder, with each `runner` constructed as a closure that calls the existing per-category function (`ssz_generic::run_ssz_generic`, `ssz_static::run_ssz_static_preset`, `bls::run_bls`, `shuffling::run_shuffling_preset`, etc.). Preserve the exact set and order present in `lib.rs:72-1655`.
  - The `Filter` check (`filter.matches(...)`) moves inside the per-spec closure: each closure first checks the filter, returns a `placeholder` `CategoryResult` if filtered out, else runs the live walker.
- [ ] Task 5.2: Drive the table with rayon, extracting `meta` (which is `Clone`) into the map output alongside the `CategoryResult`:
  ```rust
  use rayon::prelude::*;
  let results: Vec<(CategorySpecMeta, CategoryResult)> = specs
      .par_iter()
      .map(|spec| (spec.meta.clone(), (spec.runner)(&root)))
      .collect();
  ```
  `CategorySpec` is NOT `Clone` (the `Box<dyn Fn>` is not `Clone`); only its `meta: CategorySpecMeta` is. Then sequentially merge `results` into `report.rows` and `report.failures` in the original spec order. The bail check moves to the post-collect loop: walk results in spec order, push rows, stop pushing if `bail && had_failures`. Note: this bail semantics is a strict change from the previous "stop scheduling new categories immediately"; document it in the `run()` doc comment (R8).
- [ ] Task 5.3: Add a `pub fn finish(&mut self)` method on `Report` that sorts `self.rows` by the canonical order encoded in a const `&[(&str, &str, &str)]` table at the top of `crates/pharos-conformance/src/report.rs`. Call `report.finish()` at the end of `run()`. The sort ensures the markdown row ordering matches the pre-M4-perf ordering exactly.
- [ ] Task 5.4: Diff `docs/conformance.md` against the Phase 4 baseline; zero-row-diff gate. If the diff includes row-order changes, fix `Report::finish` and re-run.
- [ ] Task 5.5: Update the existing unit tests at `crates/pharos-conformance/src/lib.rs::tests` (search via `rg -n "mod tests" crates/pharos-conformance/src/lib.rs`) — in particular any test asserting bail semantics — to reflect the new "complete in-flight, do not schedule more" semantics per R8. Add a new test `categories_run_in_parallel_when_unfiltered` that creates a `Filter::all()`, asserts the `CategorySpec` table has > 8 entries, and verifies a rayon-aware sentinel (start time per spec; assert at least 2 specs have overlapping `[start, end]` windows).
- [ ] Task 5.6: Run `make conformance`; capture wall-clock to `target/test-logs/m4-perf-conformance-phase5.log`. The wall-clock target is ≤ 60 s on a 12-core machine per the roadmap. **Decision tree if the target is missed** (O1):
  - If wall-clock ≤ 60 s: target met; proceed to Task 5.7.
  - If 60 s < wall-clock ≤ 120 s: capture a fresh flamegraph (`cargo flamegraph -p pharos-conformance --profile bench -- --write`) to `docs/perf/m4-perf-phase5-flamegraph.svg`; surface to Open Questions as `Q-conformance-target-shortfall`; **accept and ship** (the M4-perf headline win is still substantial vs. 657 s); record the shortfall and a follow-up issue (M11) in `docs/perf/m4-perf.md` under the Phase 5 section.
  - If wall-clock > 120 s: do NOT accept; treat as a milestone blocker; the flamegraph likely shows a non-tree-hash bottleneck (e.g., SSZ decode), which is consistent with the observation that the conformance writer may be SSZ-decode-bound rather than tree-hash-bound (the gdb evidence pointing at sha-256 was sampled from node runtime, not the writer). Extend M4-perf with a follow-up phase or open a new perf slice; surface to the user before commit.
  Note also: even at ≤ 60 s, capture the flamegraph to confirm the post-M4-perf hot path and inform M11 planning.
- [ ] Task 5.7: Run `make bench BENCH_ARGS='--baseline m4-perf-pre'` (or equivalent: `cargo bench -p pharos-ssz --bench tree_hash_beacon_state -- --baseline m4-perf-pre` and `cargo bench -p pharos-stf --bench process_slots -- --baseline m4-perf-pre`) one final time. The `--baseline m4-perf-pre` flag is required (not optional): it instructs criterion to print the automatic regression table against the Phase 0 stashed baseline. Append `## Phase 5: conformance par_iter` section to `docs/perf/m4-perf.md` with the closing numbers and the criterion-emitted change-from-baseline percentages.
- [ ] Task 5.8: **Checkpoint: Verify Phase 5 complete**. Run `make pre-commit`. Confirm conformance wall-clock ≤ 60 s on the recorded host; if not, the milestone gate is unmet and the implementer surfaces this to the user before commit. Confirm zero-diff on `docs/conformance.md`. List task statuses.

**Commit boundary**: `perf(conformance): phase 5 — par_iter over (fork, category, preset) triples`.

### Phase 6 — Wrap-up: ADRs, roadmap, version bump, final audit
Why this phase: every prior milestone closes with ADR drafts to `docs/decisions.md`, roadmap status update, conformance.md zero-diff confirmation, and a workspace version bump. Phase 6 is the audit-only commit boundary; no source changes.

- [ ] Task 6.1: Append seven ADRs to `docs/decisions.md` (one paragraph each, matching the M4b template at `docs/decisions.md` tail): `D-tree-node-shape`, `D-validator-cache`, `D-treehash-rayon-strategy`, `D-conformance-parallelism-shape`, `D-perf-bench-machine`, `D-tree-leaf-packing`, `D-ssz-skip-attribute`. Update the TOC at the top of `docs/decisions.md` to include all seven keys. Each ADR cites the rationale, the rejected alternatives, and the enforced-in file path. `D-ssz-skip-attribute` content covers: (a) why a field attribute on the derive macro rather than a separate trait impl or a wrapper newtype (the cache field is a private impl detail of `Validator`; a newtype would leak `OnceLock` into the public type signature; a separate trait impl on every container that needs to skip a field would balloon the trait surface); (b) the `Default::default()` decode semantic for skipped fields (the field value is reconstructed via `Default` rather than read from the SSZ stream, so encoding and decoding remain SSZ-spec compliant — the field is wire-invisible); (c) `TreeHash` emission ALSO honours `#[ssz(skip)]` (the cache field does not participate in the container's tree-hash root, which is the entire point of caching the root on the side); (d) enforced in `crates/pharos-ssz-derive/src/lib.rs:<line>` (implementer fills in the parsed-attribute filter line).
- [ ] Task 6.2: Update `docs/roadmap.md` lines `474-526`: prepend `[DONE]` to the section header, replace the `Target` line with the actual measured number from Phase 5 Task 5.6, append a `Closed: 2026-MM-DD; commits <hash> → <hash>` line at the end of the section.
- [ ] Task 6.3: Update `CLAUDE.md` "M4-perf status" section (insert after the existing "M4b status" section, mirroring its format): one paragraph summarising the seven ADRs, the conformance wall-clock improvement, and the version bump.
- [ ] Task 6.3.a: Stage and commit `docs/m4-perf-plan.md` as a plan artifact, per the M4a/M4b convention (`docs/m4a-plan.md`, `docs/m4b-plan.md` are tracked in git). The plan file lands in the Phase 6 commit alongside `docs/decisions.md`, `docs/roadmap.md`, `CLAUDE.md`, `Cargo.toml`, `Cargo.lock`, `README.md`, and `docs/perf/m4-perf.md`.
- [ ] Task 6.3.b: Update `README.md` to mark M4-perf done. Edit the status line (or the roadmap status list, whichever the file shape uses) to add an `M4-perf — done` entry mirroring the existing `M4a — done` / `M4b — done` entries. Typically a single-line addition; verify the surrounding format before editing.
- [ ] Task 6.4: Bump workspace version in `/Cargo.toml:20` from `0.4.0` to `0.4.1` (patch bump — no public API change, perf-only slice). Regenerate `Cargo.lock` via `cargo check --workspace`.
- [ ] Task 6.5: Run `make conformance` one final time. Diff `docs/conformance.md` against the Phase 0 baseline copy stashed at Phase 0 Task 0.5 (or, equivalently, against the file on `master` at the start of M4-perf). Zero-row-diff gate; non-zero diff is a milestone blocker.
- [ ] Task 6.6: Final pass through `docs/perf/m4-perf.md`: confirm Phase 0-5 sections are all populated, the headline number ("Conformance writer wall-clock: BEFORE Xs → AFTER Ys, Z× improvement") is in the document header, and the `Host:` line in the header matches `D-perf-bench-machine`.
- [ ] Task 6.7: Run `make pre-push` (= `make ci`, includes slow conformance walk) once. Capture to `target/test-logs/m4-perf-pre-push.log`. Confirm exit 0.
- [ ] Task 6.8: **Final Audit**. Re-read this entire plan. For each task, verify the implementation exists in the codebase by `rg`-ing for the named symbol or by `git diff master..HEAD -- <path>`. List any gaps. All gaps must be resolved before reporting completion. Confirm: every M4-perf bullet from `docs/roadmap.md:474-526` maps to at least one Phase task; every ADR key drafted in `D-*` is in `docs/decisions.md`; `Cargo.toml` version is `0.4.1`; `docs/perf/m4-perf.md` numbers are real; `docs/conformance.md` is zero-diff against baseline.

**Commit boundary**: `docs(m4-perf): phase 6 — ADRs, roadmap update, v0.4.1`.

## Edge Cases & Risks
- R1 — Tree-backed root divergence from `Vec` backend → addressed by Task 1.9 (proptest, 256 cases).
- R2 — `Validator` clone with populated `OnceLock` sharing stale hash after a field mutation → addressed by Task 3.3 (`validator_clone_carries_cache` + `with_set_resets_validator_cache` tests) plus the structural invariant that STF call sites never mutate validator fields in place; every change rebuilds via `SszList::with_set`, which produces a fresh `Validator` with its own empty `OnceLock`.
- R3 — `Default::default()` for `Validator` with empty `OnceLock` not populating on first call → addressed by Task 3.3 (`validator_root_cache_populates`).
- R4 — Field-level `rayon::join` over a non-`Send` field type fails to compile → addressed by Task 4.4 (`compile_fail` doctest documenting the new bound).
- R5 — Top-level conformance parallelism re-orders rows in `docs/conformance.md` → addressed by Task 5.3 (`Report::finish` canonical sort).
- R6 — Criterion bench numbers drift between machines → addressed by `D-perf-bench-machine` (Task 6.1) pinning a single `PERF_HOST` per report.
- R7 — `process_slots` bench requires a Bellatrix `BeaconState` with realistic validator set → addressed by Task 0.4 loading from `~/.cache/pharos-spec-tests/{mainnet,minimal}/bellatrix/sanity/...`.
- R8 — Bail semantics regression in `run(bail=true)` → addressed by Task 5.5 (updated unit test + doc comment) and Open Question `Q-conformance-bail-semantics`.
- R9 — `with_set(i, v)` on a tree with `ZeroSubtree(d)` filler must produce the same root as the `Vec` backend → addressed by Task 1.9 (proptest covers partially-populated lists).
- R10 — `Arc<Node<T>>` reference-count leak from a write path that allocates fresh `Branch` nodes off-spine → addressed by Task 1.10 (`with_set_path_copy_preserves_shared_subtrees` unit test).
- R11 — `as_slice()` callers in `Encode`/`Decode` paths break when backend is `Tree` → addressed by Task 1.5 (per-backend match arms; `iter()` fallback for `Tree`).
- R12 — `SszList::default()` for the `Tree` backend constructing a tree with `ZeroSubtree(depth_for_limit(N))` versus an empty `Vec` backend may produce different roots for empty containers → addressed by Task 1.9 (proptest includes the empty-list case) and verified explicitly by an extra `prop_assert_eq!` at the start of every generated transcript.
- R13 — `make conformance` writer wall-clock target (60 s on 12-core) unmet → surfaced to Open Question `Q-rayon-threshold-tuning` per Task 5.6.
- R14 — Workspace `make conformance` runs Phase 0 + Phase 5 baselines on different commits (Phase 0 baseline is at the M4-perf-start commit; Phase 5 reading is at the Phase-5 commit). Across-phase comparison is `[baseline at Phase 0] vs [Phase 5 post-commit]`; intermediate Phase 2/3/4 readings are recorded but do not gate.

## Acceptance Criteria
- `cargo test --workspace` exits 0 (gate via `make test`).
- `cargo clippy --workspace --all-targets -- -D warnings` exits 0.
- `cargo fmt --all --check` exits 0.
- `make conformance` produces a `docs/conformance.md` whose rows (Fork, Category, Preset, Pass, Fail, Skip, Total) are byte-identical to the file on `master` at the start of M4-perf. `diff docs/conformance.md target/test-logs/conformance.md.baseline` returns no row-line differences (header date + commit hash may differ).
- Conformance writer wall-clock recorded in `docs/perf/m4-perf.md` ≤ 60 s on the `D-perf-bench-machine` host; observable as the `real` line in `target/test-logs/m4-perf-conformance-phase5.log`.
- Criterion bench `tree_hash_root/mainnet/BeaconState` "after" mean is ≥ 4× faster than the Phase 0 baseline (the persistent-tree caching dominates per the M1 baseline doc's 55-60% sha-256 hot path).
- `crates/pharos-ssz/tests/tree_backend_proptest.rs` passes 256 cases without divergence.
- `docs/decisions.md` contains seven new M4-perf ADRs (`D-tree-node-shape`, `D-validator-cache`, `D-treehash-rayon-strategy`, `D-conformance-parallelism-shape`, `D-perf-bench-machine`, `D-tree-leaf-packing`, `D-ssz-skip-attribute`); the TOC at the top of `decisions.md` lists all seven.
- `Cargo.toml:20` reads `version = "0.4.1"`.
- No `unimplemented!("tree backend lands in a later milestone")` strings remain anywhere under `crates/pharos-ssz/` (`rg "tree backend lands" crates/` returns empty).

## Open Questions
- `Q-tree-leaf-storage-form` — Composite-element leaves store `T` directly versus the 32-byte chunk (`Hash256`) of `T::tree_hash_root()`. Default-behaviour recommendation: store `T` (Phase 1 Task 1.1), because `with_set(i, v)` consumers expect to read `v` back, and storing only the hash forces a separate `T`-vec for `get(i)`. Stored-`T` doubles memory vs stored-hash but trades memory for `get(i)` correctness.
- `Q-rayon-threshold-tuning` — `PAR_TREE_HASH_FIELD_THRESHOLD = 4` in the derive macro (Task 4.2) is a guess. If a structurally-shallow 4-field container (e.g., `AttestationData`) shows regression in Phase 4 benches, raise the threshold to 6 or 8. Decision deferred until Phase 4 numbers land in `docs/perf/m4-perf.md`.
- `Q-bench-machine` — Default `D-perf-bench-machine` host is the developer's 12-core workstation. If CI gains a perf runner before M4-perf closes, switch the host to the CI runner and re-baseline. Recommendation: stay on the developer workstation for M4-perf; revisit at M4d.
- `Q-conformance-bail-semantics` — Phase 5 weakens `bail=true` semantics from "stop immediately on first failure" to "stop scheduling new categories after the first observed failure" (R8). If consumers of `run(bail=true)` (currently only the `pharos-conformance` binary's `--bail` flag) rely on the strict semantic, the alternative is to abandon par_iter for the bail-true path and keep sequential there. Default recommendation: accept the relaxed semantic; document it; rev `--bail` documentation.
- `Q-conformance-target-shortfall` (O1) — The 657 s → ≤ 60 s target assumes the writer is tree-hash-bound; the gdb evidence motivating this came from node runtime, not the writer. If the writer is SSZ-decode-bound (a plausible hypothesis given fixtures are loaded from disk), Phase 5 top-level parallelism alone may land in the 60–120 s band even after Phases 1–4. Decision rule encoded in Task 5.6: ≤ 60 s passes; 60–120 s accepts-and-ships with M11 follow-up; > 120 s blocks the milestone. Recommendation: do not pre-decide; let Phase 5's measured number drive the choice. Re-baseline the headline number in `docs/perf/m4-perf.md` against whatever Phase 5 lands at, regardless.
- `Q-oncelock-clone-semantics` (O2) — `OnceLock<T: Clone>::clone()` carries the populated cache by current stdlib behaviour, but this is documentation, not an RFC. Phase 3 Task 3.3's `validator_clone_carries_cache` test will detect regression at the next toolchain bump. If it ever fails, revisit `D-validator-cache` (likely path: replace `#[derive(Clone)]` on `Validator` with a hand-written `Clone` impl that explicitly copies `cached_root`).
- `Q-tree-leaf-packing-basic-element` (O3) — Basic-element list tree backing (`SszList<u8/u32/u64, _>` with packed-chunk leaves) is deferred to M11. The packing rule, leaf type (`Node<[u8; 32]>` chunk leaves), and CoW write semantics on basic-element trees are open design questions and will be settled when M11 picks them up.
- `Q-compile-fail-stability` (O4) — `trybuild` vs `compile_fail` doctest choice for the Task 4.4 negative test. Implementer picks one; revisit if toolchain bumps cause repeated test churn.

## ADR keys to add at wrap-up (Phase 6 Task 6.1)
- `D-tree-node-shape`
- `D-validator-cache`
- `D-treehash-rayon-strategy`
- `D-conformance-parallelism-shape`
- `D-perf-bench-machine`
- `D-tree-leaf-packing`
- `D-ssz-skip-attribute`
