# M10-Deneb plan

Completes the Deneb fork in Pharos: full Deneb STF (EIP-4844 payload
validation + EIP-7044 / EIP-7045 / EIP-7514), Engine API V3, Deneb block +
blob-sidecar production, full conformance, and live devnet acceptance. Built on
the M10-DA substrate (KZG crate, blob types, `Fork::Deneb` plumbing, blob
gossip/req-resp/storage, `is_data_available` import gate) which already shipped.

Deneb is added as a **capella sibling** that delegates to capella for unchanged
logic and overrides only the EIP deltas. Enum-of-forks, in-house SSZ/types/engine,
preset-generic `EthSpec`, conformance-driven (`fail=0` both presets), exhaustive
fork matches (no `unwrap_<fork>` chains).

## Verified baseline (M10-DA already shipped — do NOT re-plan)

Confirmed against the code on 2026-06-11:

- `EthSpec` Deneb associated types + accessors exist: `DenebBeaconState`,
  `DenebBeaconBlock`, `DenebBeaconBlockBody`, `DenebSignedBeaconBlock`,
  `DenebExecutionPayload`, `DenebExecutionPayloadHeader`, `unwrap_deneb_state`,
  `deneb_into_state`, `unwrap_deneb_block`, `deneb_into_block`,
  `unwrap_deneb_signed_block`, `deneb_into_signed_block`
  (`crates/pharos-types/src/eth_spec.rs:1138-1591`, mainnet/minimal impls at
  `:1975+` / `:2242+`).
- Deneb `BeaconState` is the **full** shape (626 lines,
  `crates/pharos-types/src/deneb/state.rs`), `latest_execution_payload_header`
  re-typed to `deneb::ExecutionPayloadHeader` (adds `blob_gas_used`/`excess_blob_gas`).
- `RuntimeConfig.max_blobs_per_block` exists (`crates/pharos-types/src/config/mod.rs:93`;
  EthSpec runtime defaults `eth_spec.rs:1842` mainnet=6 / `:2242` minimal=6). **No new
  EthSpec blob const needed.**
- `Fork::Deneb` / `ForkVariant::Deneb` are in exhaustive matches; deneb
  BeaconBlockBody / ExecutionPayload / Header, blob types, context-bytes codec,
  fork-digest migration, ENR, blob gossip/req-resp/storage, DA gate all shipped.

Five Deneb stub arms in `crates/pharos-stf/src/lib.rs` to fill: `:522`
(state_transition), `:692` (process_block_for_production dispatch), `:739`
(justification/finalization dispatch), `:853` (process_slots_fork advance,
`unreachable!`). Plus the upgrade match: `:882` `ForkVariant::Capella => break`
(Capella→Deneb upgrade — **must be replaced**) and `:886` `ForkVariant::Deneb =>`
(no-successor guard — keep).

## Resolved open questions

- **OQ1 (EIP-7045 gossip window):** gate the widened attestation window on the
  node's current wall epoch ≥ `DENEB_FORK_EPOCH` (matches how the topic
  fork-digest already gates which messages arrive). Per `deneb/p2p-interface.md`,
  accept attestations whose `data.slot` is in the previous-or-current epoch window.
- **OQ2 (`engine_getBlobsV1`):** wire it BOTH as a block-production helper AND as a
  **DA-gate fallback** — when the DA gate is missing sidecars, fetch them from the
  local EL pool via `getBlobsV1` before waiting on gossip. (User decision.)
- **OQ3 (devnet):** **production required.** Phase 6 hard gate includes pharos-vc
  proposing Deneb blocks with blob sidecars accepted by Lighthouse over gossip,
  0 re-orgs over 2+ epochs (M9 precedent), in addition to follow-only. (User decision.)

## Spec references

- `~/dev/consensus-specs/specs/deneb/{beacon-chain,fork,fork-choice,p2p-interface,validator}.md`
- `~/dev/consensus-specs/specs/deneb/light-client/sync-protocol.md`
- `~/dev/execution-apis/src/engine/cancun.md` (Engine V3)
- EIP-4844 (`kzg_commitment_to_versioned_hash`), EIP-7044, EIP-7045, EIP-7514.

---

## Phase 0 — Decision freeze + plan doc

- [ ] 0.1 This doc committed at `docs/m10-deneb-plan.md`.
- [ ] 0.2 Add `## M10-Deneb decisions` to `docs/decisions.md` with PROPOSED ADR stubs:
  `D-deneb-stf-delegates-to-capella`, `D-eip7044-voluntary-exit-fixed-domain`,
  `D-eip7045-attestation-range`, `D-eip7045-gossip-window-node-epoch`,
  `D-eip7514-activation-churn`, `D-engine-v3-newpayload-wire`,
  `D-versioned-hash-in-kzg-crate`, `D-engine-v3-version-selection`,
  `D-getpayloadv3-blobs-bundle`, `D-getblobsv1-da-fallback`,
  `D-deneb-block-production-sidecars`, `D-deneb-lc-header`,
  `D-deneb-execution-engine-trait-arm`.

## Phase 1 — Deneb STF (EIP-4844 / 7044 / 7045 / 7514) + execution-engine trait arm

Spec: `specs/deneb/beacon-chain.md`, `specs/deneb/fork.md`.

- [ ] 1.1 **Versioned-hash helper.** Add `sha2` to `crates/pharos-kzg/Cargo.toml`
  (or reuse an existing sha256 path — check first). Add
  `pub const VERSIONED_HASH_VERSION_KZG: u8 = 0x01;` and
  `pub fn kzg_commitment_to_versioned_hash(commitment: &[u8;48]) -> [u8;32]`
  (SHA256(commitment), overwrite byte[0] = 0x01). Unit-test against an EIP-4844 vector.
- [ ] 1.2 **Churn const.** Add `MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT` to `RuntimeConfig`
  (`config/mod.rs`) + EthSpec runtime defaults (mainnet=8, minimal=4 per
  `configs/{mainnet,minimal}.yaml` — verify). Loader + defaults wired like
  `max_blobs_per_block`.
- [ ] 1.3 **Execution-engine trait arm.** In
  `crates/pharos-stf/src/bellatrix/execution_engine.rs` add a defaulted
  `notify_new_payload_deneb<...>(&self, payload, versioned_hashes: &[[u8;32]],
  parent_beacon_block_root: Root) -> PayloadVerificationStatus` (default strips to
  V1-equivalent). `NullExecutionEngine`/`FixedExecutionEngine` keep conformance
  behavior. Spec: `beacon-chain.md` execution-payload args.
- [ ] 1.4 **`process_execution_payload` (deneb).**
  `crates/pharos-stf/src/deneb/operations/execution_payload.rs`. Sub-checks:
  (a) `body.blob_kzg_commitments.len() <= runtime.max_blobs_per_block`
  (`StateTransitionError::TooManyBlobCommitments`); (b) compute `versioned_hashes`
  via 1.1; (c) `parent_beacon_block_root = state.latest_block_header.parent_root`
  (read before header mutation); (d) call `notify_new_payload_deneb`; (e) cache the
  deneb `ExecutionPayloadHeader` incl. `blob_gas_used`/`excess_blob_gas`. (Note:
  `excess_blob_gas`/`blob_gas_used` consistency is enforced by the EL via
  newPayloadV3, not re-derived in CL — matches lighthouse.) Conformance:
  `deneb/operations/execution_payload`.
- [ ] 1.5 **`process_voluntary_exit` (deneb, EIP-7044).**
  `crates/pharos-stf/src/deneb/operations/voluntary_exit.rs`. Signature accepts
  `runtime_cfg: &RuntimeConfig`; domain computed with
  `compute_domain(DOMAIN_VOLUNTARY_EXIT, runtime_cfg.capella_fork_version,
  genesis_validators_root)` regardless of state fork. All deneb operation callers
  thread `runtime_cfg`. Spec: `beacon-chain.md:510-513`. Conformance:
  `deneb/operations/voluntary_exit`.
- [ ] 1.6 **`process_attestation` (deneb, EIP-7045).**
  `crates/pharos-stf/src/deneb/operations/attestation.rs`. Drop the
  `state.slot <= data.slot + SLOTS_PER_EPOCH` upper bound; keep
  `data.slot + MIN_ATTESTATION_INCLUSION_DELAY <= state.slot`. Else delegate to
  altair. Conformance: `deneb/operations/attestation`.
- [ ] 1.7 **`process_registry_updates` (deneb, EIP-7514).**
  `crates/pharos-stf/src/deneb/epoch/registry_updates.rs`. Add
  `get_validator_activation_churn_limit = min(MAX_PER_EPOCH_ACTIVATION_CHURN_LIMIT,
  get_validator_churn_limit(state))` and use it for the activation queue.
  Conformance: `deneb/epoch_processing/registry_updates`.
- [ ] 1.8 **Block + operations dispatch.**
  `crates/pharos-stf/src/deneb/operations/mod.rs` (`process_operations_deneb`:
  capella ordering, routing exits→deneb domain, attestations→deneb bound) and
  `crates/pharos-stf/src/deneb/block.rs` (deneb per-step `process_block`).
- [ ] **Checkpoint:** `cargo check -p pharos-stf -p pharos-types -p pharos-kzg`.
- [ ] 1.9 **Epoch + upgrade.** `crates/pharos-stf/src/deneb/epoch/mod.rs` (deneb
  `process_epoch` = capella epoch with deneb `process_registry_updates`) and
  `crates/pharos-stf/src/deneb/upgrade.rs` (`upgrade_to_deneb`: capella→deneb,
  re-type `latest_execution_payload_header` adding zeroed blob-gas fields, bump
  `fork.current_version = DENEB_FORK_VERSION`). Spec: `fork.md`. Conformance:
  `deneb/epoch_processing/*`, `deneb/fork`.
- [ ] 1.10 **Module + error.** `crates/pharos-stf/src/deneb/{mod,state_transition,helpers}.rs`,
  `pub mod deneb;` in `lib.rs`, `StateTransitionError::TooManyBlobCommitments` in
  `error.rs`.
- [ ] 1.11 **Wire the 5 dispatch arms + upgrade trait** in `lib.rs`:
  - `:522` state_transition Deneb arm → deneb `state_transition`.
  - `:692` production dispatch Deneb arm (real path; completed in Phase 4).
  - `:739` JaF dispatch: add `DenebJaFDispatch<E>` trait + blanket impl (mirror
    `CapellaJaFDispatch`), wire Deneb arm.
  - `:853` process_slots_fork advance Deneb arm.
  - **`:882` replace `ForkVariant::Capella => break`** with
    `upgrade_to_deneb_dispatch` via a new `DenebUpgradeDispatch<E>` trait + blanket
    impl (mirror `CapellaUpgradeDispatch`; the M6 `D-live-fork-trigger-in-state-transition`
    lesson — a capella-state + deneb-block crossing must upgrade live).
- [ ] 1.12 **Deneb light client.** `crates/pharos-types/src/deneb/light_client.rs`
  (`LightClientHeader { beacon, execution: deneb::ExecutionPayloadHeader,
  execution_branch }` + bootstrap/update/finality/optimistic + views), deneb LC
  assoc types in `eth_spec.rs`, `crates/pharos-stf/src/deneb/light_client.rs`
  (`get_lc_execution_root` deneb branch; EXECUTION_PAYLOAD_GINDEX=25 depth 4). Update
  `altair/light_client_dispatch.rs` to build the deneb header for deneb+ blocks
  using STF-verified `block.state_root` (M4c `D-bellatrix-lc-header-uses-state-root`).
  Conformance: `deneb/light_client/*`.
- [ ] **Checkpoint:** `cargo check --workspace` + `cargo test -p pharos-stf`. No
  `unimplemented!`/`break` left in the deneb fork paths. List each task + status.

## Phase 2 — Deneb conformance (non-network categories)

Prove the Phase 1 STF against spec vectors before integration. Mirror the
`run_*_capella_{mainnet,minimal}` fns.

- [ ] 2.1 `operations.rs`: `run_operations_deneb_*` (execution_payload, voluntary_exit,
  attestation + unchanged handlers).
- [ ] 2.2 `epoch_processing.rs`: `run_epoch_processing_deneb_*` (registry_updates +
  historical_summaries_update + carried-over).
- [ ] 2.3 `{sanity,finality,random,rewards}.rs`: `run_*_deneb_*`.
- [ ] 2.4 `transition.rs`: `run_transition_deneb_*` (capella→deneb); extend
  `ssz_static.rs` deneb to cover LC + new containers (kzg/merkle_proof already green).
- [ ] 2.5 `fork_choice.rs`: `run_fork_choice_deneb_*` (`on_block` + `is_data_available`
  + deneb STF); `light_client.rs`: `run_light_client_deneb_*`.
- [ ] 2.6 Wire all `deneb/<category>/{mainnet,minimal}` entries in `lib.rs` ladder.
- [ ] **Checkpoint:** `cargo run -p pharos-conformance --release -- --filter deneb`
  (background, captured). Every deneb category `fail=0` both presets.

## Phase 3 — Engine API V3 + import threading

Spec: `execution-apis/src/engine/cancun.md`.

- [ ] 3.1 **Wire types** (`crates/pharos-engine/src/types.rs`): `ExecutionPayloadV3`
  (V2 + `blobGasUsed`, `excessBlobGas`), `PayloadAttributesV3` (V2 +
  `parentBeaconBlockRoot`), `BlobsBundleV1 { commitments, proofs, blobs }`,
  `BlobAndProofV1 { blob, proof }`, `GetPayloadV3Response { executionPayload,
  blockValue, blobsBundle, shouldOverrideBuilder }`. **JSON field name for the
  newPayloadV3 second param is `expectedBlobVersionedHashes`** (not
  `blobVersionedHashes`). Verify all casing vs `cancun.md:41-100`.
- [ ] 3.2 **Conversions:** `From<deneb::ExecutionPayload> for ExecutionPayloadV3` and
  `TryFrom<ExecutionPayloadV3>` both presets (mirror V2, ~100 LOC each).
- [ ] 3.3 **Client + enums** (`client.rs`): `V3` arms in `NewPayloadVersion` /
  `ForkchoiceUpdatedVersion` / `GetPayloadVersion`; `NewPayloadWire::V3 { payload,
  versioned_hashes, parent_beacon_block_root }`; methods `new_payload_v3`,
  `forkchoice_updated_v3`, `get_payload_v3`, `get_blobs_v1(versioned_hashes) ->
  Vec<Option<BlobAndProofV1>>` (preserve request order, `null` per miss; handle
  `-38004` too-large ≥128). Add the four method names to `ADVERTISED_CAPABILITIES`.
  newPayloadV3 param order: `(executionPayload, expectedBlobVersionedHashes,
  parentBeaconBlockRoot)`.
- [ ] 3.4 **Actor** (`handle.rs`): `EngineRequest`/`EngineHandle` V3 routing +
  blocking variants (mirror `get_payload_v2_blocking`).
- [ ] 3.5 **Driver** (`crates/pharos-node/src/engine_driver.rs`): implement
  `notify_new_payload_deneb` on `ExecutionEngineHandle` (→ `NewPayloadWire::V3`);
  add deneb-fork version-selection arms at `:133` / `:716` / `:809`; FCU V3 on the
  follow path carries no payload attributes.
- [ ] 3.6 **Import** (`import.rs`, `block_ingestion.rs`): thread versioned hashes
  through deneb `process_execution_payload`; replace the deneb LC-snapshot no-op
  ("Deneb STF not yet implemented") with real deneb LC snapshot writes.
- [ ] 3.7 **DA-gate fallback (OQ2):** when the DA checker reports missing sidecars,
  call `get_blobs_v1` on the local EL for the block's versioned hashes; on full
  retrieval, satisfy the gate without waiting on gossip. Wire into the DA gate in
  `data_availability.rs` / `blob_ingestion.rs`.
- [ ] 3.8 **Engine conformance** (`engine.rs` + YAML): deneb V3 examples
  (newPayloadV3 with versioned hashes + parent beacon block root, getPayloadV3
  blobs-bundle round-trip). `fail=0`.
- [ ] **Checkpoint:** `cargo check -p pharos-engine -p pharos-node` +
  `cargo test -p pharos-engine`. V3 serde round-trips; version selection picks V3
  for deneb; engine YAML passes.

## Phase 4 — EIP-7045 gossip + deneb block + sidecar production

- [ ] 4.1 **EIP-7045 gossip** (`host_impl.rs` `validate_attestation` /
  `validate_aggregate_and_proof`): widen the attestation window to previous-or-current
  epoch per `deneb/p2p-interface.md`, gated on node wall epoch ≥ `DENEB_FORK_EPOCH` (OQ1).
- [ ] 4.2 **Payload prep** (`engine_driver.rs` `prepare_execution_payload_v3`, mirror
  the V2 helper): FCU V3 with `PayloadAttributesV3` (incl. `parentBeaconBlockRoot`),
  then `getPayloadV3` → `(ExecutionPayloadV3, BlobsBundleV1, block_value)`.
- [ ] 4.3 **Deneb block assembly** (`block_production.rs`): deneb `assemble` for
  `E::DenebSignedBeaconBlock` (mirror capella `:838`): body incl.
  `blob_kzg_commitments` (from bundle), `ExecutionPayloadV3` → `deneb::ExecutionPayload`.
  Fill the `lib.rs:692` Deneb production dispatch arm.
- [ ] 4.4 **Sidecar production** (`block_production.rs` or new
  `blob_sidecar_production.rs`): build `BlobSidecar`s from `(BlobsBundleV1,
  signed_block)` — per index: blob, commitment, proof, `signed_block_header`,
  `kzg_commitment_inclusion_proof` (gindex `8192 + index`, depth 17, reuse
  `verify_blob_sidecar_inclusion_proof` machinery). Lengths
  blobs==commitments==proofs.
- [ ] 4.5 **Publish** (`block_ingestion.rs` / production endpoint): persist + publish
  self-produced sidecars on the blob-sidecar gossip topics alongside the block.
- [ ] **Checkpoint:** `cargo check --workspace` + `cargo test -p pharos-node`.

## Phase 5 — Node integration, conformance regen, ADRs, version bump

- [ ] 5.1 **Checkpoint-sync + runtime-cfg threading** (`checkpoint_sync.rs`, storage
  rehydrate): handle `Eth-Consensus-Version: deneb` anchor; ensure ingestion/backfill/
  lookup loops carry the real `DENEB_FORK_EPOCH` (M6 `D-runtime-cfg-threading-live-loops`),
  not `u64::MAX`. Populate deneb fork-schedule placeholders (`backfill.rs:874`,
  `host_impl.rs:2917/2958`).
- [ ] 5.2 **Integration test** `crates/pharos-node/tests/deneb_pipeline.rs`:
  capella→deneb crossing + deneb blob-block import through DA gate + Engine V3
  (axum mock EL → newPayloadV3 VALID), mirror `checkpoint_backfill_pipeline.rs` /
  `blob_da_pipeline.rs`.
- [ ] 5.3 **Conformance regen:** `make conformance` (background, captured); regenerate
  `docs/conformance.md`. Deneb rows `fail=0` both presets; pre-deneb rows
  byte-identical to v0.14.0. Commit `docs/conformance.md`.
- [ ] 5.4 ADRs PROPOSED→ACCEPTED in `docs/decisions.md` with spec citations.
- [ ] 5.5 Version bump `0.14.0` → `0.15.0`; update CLAUDE.md "M10-Deneb status" (do
  NOT `git add` CLAUDE.md).
- [ ] **Checkpoint:** `make pre-push` (background, captured) green.

## Phase 6 — Live Deneb devnet acceptance (production required)

- [ ] 6.1 Extend `~/.cache/pharos-devnet/gen-testnet.sh` to a capella→deneb transition
  testnet (`DENEB_FORK_EPOCH=1`, `cancunTime` in genesis.json, sync pharos specdir).
- [ ] 6.2 **Follow gate:** pharos follows head past `DENEB_FORK_EPOCH` importing
  blob-carrying blocks: `head==wall±1`, DA gate fires ≥1×, getBlobsV1 fallback
  exercised, `newPayloadV3` VALID, sidecars received + DA-satisfied, 0 bans, 0
  panics over 10 min. Capture logs (Lighthouse `--debug-level debug`).
- [ ] 6.3 **Production gate (OQ3):** pharos-vc proposes deneb blocks with sidecars
  accepted by Lighthouse over gossip, kept canonical, 0 re-orgs over 2+ epochs (M9
  precedent). Reuse `~/.cache/pharos-devnet/run-blockprod.sh`.
- [ ] 6.4 For each live-only bug: fix + add `D-<topic>` ADR to an "M10-Deneb
  correctness decisions" subsection; re-verify live. Do NOT defer.
- [ ] **Final audit:** re-read this plan; grep each named symbol/file to confirm it
  exists. 6 fork variants exhaustive everywhere; four EIP deltas present; Engine V3
  four methods wired + version-selected for deneb; deneb production + sidecars; all
  deneb conformance green both presets; pre-deneb byte-identical; devnet follow +
  production gates passed. Resolve all gaps before declaring done.

## Risks

- Engine trait signature churn (`notify_new_payload_deneb` carries versioned hashes +
  parent beacon block root) — defaulted method, no conformance impact (1.3).
- `parent_beacon_block_root` source = `state.latest_block_header.parent_root`, read
  before header mutation (1.4).
- Live fork-crossing freeze (M6 lessons) — `DenebUpgradeDispatch` in
  `process_slots_fork` (1.11) + runtime-cfg threading (5.1).
- Wrong deneb fork-digest → instant ban — shipped in M10-DA; 6.2 verifies live.
- `get_blobs_v1` ordering + null entries + `-38004` (≥128 hashes) (3.3).
- EIP-7045 STF bound vs gossip window are two surfaces (1.6 + 4.1).

## Acceptance criteria

- `--filter deneb` conformance `fail=0` every category both presets.
- `docs/conformance.md` deneb rows green; pre-deneb byte-identical to v0.14.0.
- `cargo test -p pharos-stf` + `deneb_pipeline.rs` pass.
- Engine V3 serde round-trips vs cancun.md; V3 selected for deneb heads.
- `make pre-push` green.
- Live: follow past `DENEB_FORK_EPOCH` (0 bans, newPayloadV3 VALID, DA fires) AND
  pharos-vc production accepted (0 re-orgs 2+ epochs).
