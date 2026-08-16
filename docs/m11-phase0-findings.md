# M11 Phase 0 — Recon & API Verification Findings

All seven Phase 0 tasks verified against `Cargo.lock`, local spec files, and
crate sources in `~/.cargo/registry/src/`.  No code was changed.

---

## Task 0.1 — Weak-subjectivity period formula

**Source:** `~/dev/consensus-specs/specs/phase0/weak-subjectivity.md`
(lines 94–120).

### `compute_weak_subjectivity_period` (exact Python transcription)

```python
def compute_weak_subjectivity_period(state: BeaconState) -> uint64:
    ws_period = MIN_VALIDATOR_WITHDRAWABILITY_DELAY
    N = len(get_active_validator_indices(state, get_current_epoch(state)))
    t = get_total_active_balance(state) // N // ETH_TO_GWEI
    T = MAX_EFFECTIVE_BALANCE // ETH_TO_GWEI
    delta = get_validator_churn_limit(state)
    Delta = MAX_DEPOSITS * SLOTS_PER_EPOCH
    D = SAFETY_DECAY   # = 10

    if T * (200 + 3 * D) < t * (200 + 12 * D):
        epochs_for_validator_set_churn = (
            N * (t * (200 + 12 * D) - T * (200 + 3 * D)) // (600 * delta * (2 * t + T))
        )
        epochs_for_balance_top_ups = N * (200 + 3 * D) // (600 * Delta)
        ws_period += max(epochs_for_validator_set_churn, epochs_for_balance_top_ups)
    else:
        ws_period += 3 * N * D * t // (200 * Delta * (T - t))

    return ws_period
```

**Key variables (Ether arithmetic, NOT Gwei):**
- `N` = active validator count
- `t` = avg effective balance in Ether (`total_active_balance / N / 1e9`)
- `T` = `MAX_EFFECTIVE_BALANCE / ETH_TO_GWEI` (= 32 Ether mainnet)
- `delta` = `get_validator_churn_limit(state)` = `max(MIN_PER_EPOCH_CHURN_LIMIT, N // CHURN_LIMIT_QUOTIENT)`
- `Delta` = `MAX_DEPOSITS * SLOTS_PER_EPOCH`
- `D` = 10 (constant `SAFETY_DECAY`)

**Branching condition:** if average balance `t` relative to `T` satisfies
`T * 230 < t * 320` (i.e. avg balance > ~0.72 * MAX_EFFECTIVE_BALANCE), use
the churn-based formula; otherwise use the balance-deficit formula.  For
mainnet with `t = 28 ETH` at 32768 validators the period is ~504 epochs (from
the spec's reference table).

### EthSpec constants confirmed present

All required constants exist in `crates/pharos-types/src/eth_spec.rs`:

| Constant | Line | Notes |
|---|---|---|
| `MIN_VALIDATOR_WITHDRAWABILITY_DELAY` | 214 | from `configs/mainnet.yaml` = 256 |
| `MIN_PER_EPOCH_CHURN_LIMIT` | 224 | mainnet = 4, minimal = 2 |
| `CHURN_LIMIT_QUOTIENT` | 229 | mainnet = 65536, minimal = 32 |
| `MAX_DEPOSITS` | 152 | from `presets/mainnet/phase0.yaml:81` |
| `SLOTS_PER_EPOCH` | 73 | mainnet = 32, minimal = 8 |
| `MAX_EFFECTIVE_BALANCE` | 60 | mainnet = 32e9, minimal = 32e9 |

`is_within_weak_subjectivity_period` signature (from spec lines 181-191):
```python
def is_within_weak_subjectivity_period(
    store: Store, ws_state: BeaconState, ws_checkpoint: Checkpoint
) -> bool:
    ws_period = compute_weak_subjectivity_period(ws_state)
    ws_state_epoch = compute_epoch_at_slot(ws_state.slot)
    current_epoch = compute_epoch_at_slot(get_current_slot(store))
    return current_epoch <= ws_state_epoch + ws_period
```

The Rust signature for Phase 1 (from plan):
```rust
fn compute_weak_subjectivity_period<E: EthSpec>(
    active_validator_count: u64,
    avg_effective_balance_gwei: u64,
    total_active_balance_gwei: u64,
) -> u64
```
Note: the state-taking spec version must be adapted since `get_validator_churn_limit` and `get_total_active_balance` are pure functions of the state; the Rust impl will take the precomputed values.

---

## Task 0.2 — discv5 0.10.4: NO enrtree/DNS support confirmed

**Source:** `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/discv5-0.10.4/Cargo.toml`

```toml
[features]
libp2p = ["dep:libp2p-identity", "dep:multiaddr"]
serde = ["enr/serde"]
```

Exactly two features: `libp2p` and `serde`.  No `enrtree`, no `dns`, no TXT-query
dependency anywhere in `src/` (rg over the full source dir returned zero matches
for `enrtree`, `dns`, `DNS`, `TXT`).  EIP-1459 resolution MUST be implemented
in-house.

### DNS resolver dependency decision

**Chosen: `hickory-resolver` 0.25.2** (already in `Cargo.lock:1692` as a
transitive dep of `libp2p-dns`).

Rationale:
- Already a transitive dep — zero new dependency edge for the workspace.
- Pinned at 0.25.2; no version negotiation needed.
- Async-native (`async fn txt_lookup<N: IntoName>(&self, query: N) -> Result<TxtLookup, ResolveError>`) at `resolver.rs:444,160`.
- `TxtLookup` iterates `TXT` rdata records; `TXT::txt_data() -> &[Box<[u8]>]` provides the raw bytes.
- Initialisation: `Resolver::builder_tokio().unwrap().build()` (requires `"tokio"` feature, already enabled via libp2p-dns).

This feeds Phase 15 deps: `pharos-network/Cargo.toml` adds
`hickory-resolver.workspace = true` (and the workspace entry already exists
transitively; needs to be made direct/explicit).

**Recurse/record bounds (Phase 15 task 4):** record count cap = 1024;
recursion depth cap = 16. These prevent memory exhaustion from a malicious tree.

---

## Task 0.3 — `metrics` 0.24.6 + `metrics-exporter-prometheus` 0.18.3 API

**Sources:**
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/metrics-0.24.6/src/`
- `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/metrics-exporter-prometheus-0.18.3/src/`
- `Cargo.lock:metrics 0.24.6`, `Cargo.lock:metrics-exporter-prometheus 0.18.3` (resolved by `cargo fetch` during recon; was declared in `[workspace.dependencies]` but unresolved until now).

### `metrics` 0.24.6 macros and handles

Emission macros return typed handles (NOT one-shot):
```rust
counter!("name", "label" => "value").increment(1);
gauge!("name", "label" => "value").set(42.0);
histogram!("name").record(duration.as_secs_f64());
```

Description macros (called once at init):
```rust
describe_counter!("metric_name", Unit::Count, "description");
describe_gauge!("metric_name", Unit::Gauge, "description");
describe_histogram!("metric_name", Unit::Milliseconds, "description");
```

### `PrometheusBuilder` API (builder.rs lines 75–605)

Key methods for Phase 5:
```rust
// Create builder
PrometheusBuilder::new()

// Bind HTTP listener (requires "http-listener" feature, enabled by default)
.with_http_listener(addr: impl Into<SocketAddr>) -> Self   // line 122

// Configure histogram buckets globally
.set_buckets(values: &[f64]) -> Result<Self, BuildError>   // line 301

// Configure per-metric buckets (for the roadmap bucket set)
.set_buckets_for_metric(
    matcher: Matcher,
    values: &[f64],
) -> Result<Self, BuildError>   // line 355

// Install: sets global recorder + spawns HTTP server (tokio task)
.install(self) -> Result<(), BuildError>   // line 456

// Install recorder only (no HTTP server; server driven externally)
.install_recorder(self) -> Result<PrometheusHandle, BuildError>   // line 506

// Build recorder + exporter future (advanced)
.build(self) -> Result<(PrometheusRecorder, ExporterFuture), BuildError>   // line 545
```

**Phase 5 implementation pattern:**
```rust
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

pub fn init_metrics(addr: SocketAddr) -> Result<(), BuildError> {
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .set_buckets(&[0.5, 1.0, 5.0, 25.0, 100.0, 500.0, 2500.0])?
        .install()
}
```

NOTE: `install()` calls `tokio::spawn` internally when inside a Tokio runtime;
it creates a background thread + single-threaded runtime otherwise.  For
`pharos-node`, it is always called from within a Tokio runtime, so it spawns a
task on the current runtime.

The roadmap histogram buckets are `[0.5, 1, 5, 25, 100, 500, 2500] ms` =
`[0.0005, 0.001, 0.005, 0.025, 0.1, 0.5, 2.5]` seconds (metrics records
float seconds; the `describe_histogram!` with `Unit::Milliseconds` is
cosmetic labelling only — the actual values must be in the unit the call site
uses).  Phase 6 call sites should use `duration.as_secs_f64()` and the roadmap
buckets expressed in seconds.

---

## Task 0.4 — `tracing-subscriber` 0.3.23 JSON layer API

**Source:** `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/tracing-subscriber-0.3.23/src/`

### Confirmed API

`FmtSpan` is `pub struct FmtSpan(u8)` at `src/fmt/format/mod.rs:1644` with
constants:
```rust
FmtSpan::NONE    // 0
FmtSpan::NEW     // 1 << 0
FmtSpan::ENTER   // 1 << 1
FmtSpan::EXIT    // 1 << 2
FmtSpan::CLOSE   // 1 << 3
FmtSpan::ACTIVE  // ENTER | EXIT
FmtSpan::FULL    // NEW | ENTER | EXIT | CLOSE
```
Supports `|` and `|=` operators.

`with_span_events(kind: FmtSpan) -> Self` is at `fmt_layer.rs` (builder method
on `Layer`).

JSON layer chain for Phase 7:
```rust
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::{fmt, EnvFilter};

tracing_subscriber::registry()
    .with(EnvFilter::new(filter_str))
    .with(
        fmt::layer()
            .json()
            .with_span_events(FmtSpan::ENTER | FmtSpan::EXIT)
    )
    .init();
```

`EnvFilter` is at `src/filter/env/mod.rs:199`:
```rust
EnvFilter::new(directives: impl AsRef<str>) -> Self   // line 350
EnvFilter::from_env(env: impl AsRef<str>) -> Self     // line 320  (reads env var)
```

**JSON output fields** (from `src/fmt/format/json.rs`): `timestamp`, `level`,
`target`, `span`, `fields`.  Parent span ID is included in the span context
when `with_span_events` is configured — this is the mechanism Phase 7 relies on
for span-parentage oracle.

---

## Task 0.5 — Real `gossipsub::Event` variants in libp2p-gossipsub 0.49.4

**Source:** `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/libp2p-gossipsub-0.49.4/src/behaviour.rs:136-170`

### Complete `Event` enum

```rust
pub enum Event {
    /// A message has been received.
    Message {
        propagation_source: PeerId,
        message_id: MessageId,
        message: Message,
    },
    /// A remote subscribed to a topic.
    Subscribed {
        peer_id: PeerId,
        topic: TopicHash,
    },
    /// A remote unsubscribed from a topic.
    Unsubscribed {
        peer_id: PeerId,
        topic: TopicHash,
    },
    /// A peer that does not support gossipsub has connected.
    GossipsubNotSupported { peer_id: PeerId },
    /// A peer is not able to download messages in time.
    SlowPeer {
        peer_id: PeerId,
        failed_messages: FailedMessages,
    },
}
```

`FailedMessages` struct (`types.rs:37-61`):
```rust
pub struct FailedMessages {
    pub publish: usize,
    pub forward: usize,
    pub priority: usize,
    pub non_priority: usize,
    pub timeout: usize,
}
```

### Signal mapping for Phase 10/11

| gossipsub::Event variant | Misbehaviour signal | Phase 11 action |
|---|---|---|
| `SlowPeer { failed_messages, .. }` | Peer cannot download msgs in time | penalise; `failed_messages.total()` as severity |
| `Unsubscribed { peer_id, topic }` | Peer left a subnet mesh | penalise for subnet-non-propagation if in expected subnet |
| `Message { propagation_source, .. }` | Positive signal — message delivered | reward propagation from that peer |
| `Subscribed { peer_id, topic }` | Positive signal — joined mesh | record subnet subscription for coverage tracking |
| `GossipsubNotSupported { peer_id }` | Peer does not speak gossipsub | hard penalise / ban candidate |

**Existing pharos-network dispatch sites referenced in the plan:**
- `network/mod.rs:801` → `SlowPeer` arm
- `network/mod.rs:787` → `Unsubscribed` arm

Do NOT add any variant that is not in the list above.  There is no `MeshPeer`,
no `Grafted`/`Pruned`, no `Heartbeat` in the public `Event` enum for 0.49.4.

---

## Task 0.6 — Peer-score persistence format decision

**Decision: SSZ via the in-house `pharos-ssz` crate.**

Rationale:
- The durable component of the score table is a flat list of `(PeerId-bytes[32], score_f64, last_ban_epoch_u64, …)` per peer — a straightforward SSZ container.
- Project philosophy: "If a pattern is SSZ-serializable, use in-house SSZ."  No `bincode` or `serde` dep needed.
- `pharos-ssz` is already a dep of `pharos-network` (transitively through types).
- The volatile gossip mesh score is NOT persisted (it resets on restart anyway); only the durable long-term ban/app-specific component is saved.
- If the struct ever grows non-SSZ-friendly fields (e.g. hash maps keyed on `PeerId`), the format decision can be revisited under a new ADR — but for Phase A the struct is simple.

**ADR key:** `D-peer-score-persist-format` (Phase 21 will record this).

**File:** `<data-dir>/network/peer_scores.ssz` (Phase 14).

**Format:** `List[PeerScoreRecord, MAX_PEERS]` where:
```rust
struct PeerScoreRecord {
    peer_id: FixedBytes<32>,   // libp2p PeerId multihash bytes (truncated or padded to 32)
    long_term_score: f64,      // durable app-specific score
    ban_epoch: u64,            // last epoch peer was banned (0 = never)
}
```
Note: `libp2p::PeerId` serialises to a multihash byte vector; the SSZ record
stores the first 32 bytes (peer IDs are typically Ed25519 multihash = 38 bytes;
Phase 14 will decide exact truncation/identity encoding when implementing — this
is a pre-decision on the FORMAT, not the exact byte layout).

---

## Task 0.7 — Slasher crate-vs-module decision

**Decision: `pharos-node` module at `crates/pharos-node/src/slasher/mod.rs`.**

Already stated in the plan's Phase 8 section and confirmed here:

Rationale:
- Phase A is purely in-memory; it has no external consumers outside the node.
- A new crate would add a dependency edge for node-internal functionality.
- Phase B, if it grows storage-heavy, can be promoted to `crates/pharos-slasher` later behind the same internal API (documented in the Phase B ADR).
- The slasher module reads from the same gossip-accept path that fills `op_pools`, so co-location in `pharos-node` avoids channel plumbing.

**Fixed path:** `crates/pharos-node/src/slasher/mod.rs` (Phase A),
`crates/pharos-node/src/slasher/replay.rs` + `proposer.rs` (Phase B).

---

## Additional findings (already-shipped accounting verification)

### `compute_safe_block_hash` — already resolves `latest_verified_ancestor`

**Source:** `crates/pharos-node/src/engine_driver.rs:506-529`

The function implementation at lines 525-529 is CORRECT: it calls
`latest_verified_ancestor(store, store.justified_checkpoint.root)` before
`execution_block_hash_at_root`.  The plan's "already-shipped" accounting is
accurate.

**DISCREPANCY vs the plan assumption:** The doc comment at lines 512-524 still
contains two stale "deferred to M11" notes.  The implementation is NOT deferred;
only the doc comment is stale.  Phase 6 task 6(b) will delete these comments and
add the `D-safe-hash-verified-ancestor` ADR cite.

### `PeerScorer` trait — NO `tick`/time method today

**Source:** `crates/pharos-network/src/scoring.rs:104-113`

```rust
pub trait PeerScorer: Send + Sync + 'static {
    fn record(&mut self, peer: PeerId, event: ScoreEvent);
    fn score(&self, peer: &PeerId) -> f64;
    fn worst_peers(&self, count: usize) -> Vec<PeerId>;
}
```
Confirmed: no `tick`, no `decay_all`, no time-based method.  Phase 10 task 1
must decide lazy-on-`score()` vs explicit `tick`.

### `ScoreEvent` — missing variants for Phase 10/11 signals

The current `ScoreEvent` enum in `scoring.rs` does NOT include variants for:
- `SlowPeer` (gossipsub signal)
- `RateLimitExceeded`
- `SubnetNonPropagation`
- `UnsubscribedFromExpectedSubnet`

Phase 10 must extend `ScoreEvent` with these (per plan Phase 10 task 2: "extend
`ScoreEvent` if it lacks variants for the signals Phase 11 needs").

---

## Cargo.lock note

`metrics-exporter-prometheus 0.18.3` is declared in `[workspace.dependencies]`
but NOT yet in `Cargo.lock` because no crate in the workspace directly depends
on it.  Phase 5 will add `metrics-exporter-prometheus.workspace = true` to
`pharos-utils/Cargo.toml` (or `pharos-node/Cargo.toml`), which will resolve
version 0.18.3 and add its transitive deps (`evmap`, `metrics-util`,
`sketches-ddsketch`, etc.) to the lock file at that point.
