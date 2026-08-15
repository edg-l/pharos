# Cross-client Bellatrix→Capella devnet (M4d/M5/M6/M7 harness)

Hand-rolled, host-process (no Docker/Kurtosis) devnet for cross-client interop
testing: a **lighthouse** BN+VC + **ethrex** EL produce a live **Bellatrix→Capella
transition** chain (`CAPELLA_FORK_EPOCH=1`), and the **pharos** node peers in,
follows head past the fork, and (M7) serves the Beacon API for an external VC.

Originally the M4d interop harness. The M7 plan called for Kurtosis here; we kept
this hand-rolled harness instead — it already drives the exact lighthouse+ethrex
transition chain we need and adding a Kurtosis custom-service definition buys no
extra coverage for a solo devnet (see `D-m7-gate-harness` in `docs/decisions.md`).

## Current status

- ✅ Reference chain (lighthouse + ethrex) produces Bellatrix→Capella blocks.
- ✅ pharos checkpoint-syncs from lighthouse, dials its bootnode, and **follows
  head over gossip past the Capella fork** (M5-follow + M6-Capella).
- ✅ (M7) pharos serves the Beacon API on `:5053`; an external lighthouse VC
  bootstraps against it and reads duties (`run-vc-vs-pharos.sh`). Block/attestation
  PRODUCTION + POST publish are M8 — the VC logs publish errors, which is expected.

## Prerequisites (host PATH)

| Tool | Version used | Install |
|------|--------------|---------|
| `lighthouse` | v8.1.3 | release binary |
| `lcli` | v8.1.3 (match lighthouse) | `cargo install --git https://github.com/sigp/lighthouse --tag v8.1.3 --locked lcli` |
| `ethrex` | v13.0.0 | `cargo install --path ~/dev/ethrex/cmd/ethrex --locked` |
| `eth2-testnet-genesis` | v0.12.0 | `go install github.com/protolambda/eth2-testnet-genesis@latest` (→ `~/go/bin`) |
| consensus-specs | any recent | clone at `~/dev/consensus-specs` (for mainnet presets) |

Also `rg`, `jq`. pharos built: `cargo build -p pharos-node --bin pharos`.

## Usage

```bash
# 1. generate a fresh chain (genesis ~45s out)
scripts/devnet/gen-testnet.sh

# 2. boot the reference chain; confirm head advances
scripts/devnet/run-devnet.sh
curl -s http://127.0.0.1:5052/eth/v2/beacon/blocks/head | jq -r .data.message.slot

# 3. peer pharos in (serves Beacon API on :5053 via --http)
scripts/devnet/run-pharos.sh
# wait until pharos is following head:
curl -s http://127.0.0.1:5053/eth/v1/node/syncing | jq .data

# 4. (M7 gate) point a lighthouse VC at pharos + curl-probe the VC-critical reads
scripts/devnet/run-vc-vs-pharos.sh          # probe + launch VC
PROBE_ONLY=1 scripts/devnet/run-vc-vs-pharos.sh   # read-probe only, no VC

# teardown
scripts/devnet/stop-devnet.sh
```

Everything-in-one-tmux alternative: `~/.cache/pharos-devnet/run-tmux.sh --fresh`
brings up all components (one pane each) for a watch-it-live session.

Re-running requires a **fresh genesis** each time: run `gen-testnet.sh` again
before `run-devnet.sh` (the slashing-DB wipe in run-devnet.sh assumes this).

Runtime data lives in `$DEVNET_DIR` (default `~/.cache/pharos-devnet/`), **not**
in the repo. Override with env: `DEVNET_DIR`, `CONSENSUS_SPECS`,
`ETH2_TESTNET_GENESIS`, `PHAROS_BIN`, `VALIDATOR_COUNT`, `GENESIS_DELAY_SECS`.

## Ports

| | port |
|---|---|
| lighthouse BN http / libp2p / discv5 | 5052 / 9000 / 9000 |
| ethrex (lighthouse's) http / authrpc | 18545 / 18551 |
| ethrex (pharos's) http / authrpc | 28545 / 28551 |
| pharos libp2p / discv5 | 9300 / 9301 |
| pharos Beacon API (M7) | 5053 |

(pharos uses 9300/9301 to dodge 9000/9001 = lighthouse and 9100 = prometheus
node_exporter.)

## Gotchas baked into these scripts (each cost real debugging)

- **`ethrex --syncmode full` is mandatory.** Default `snap` short-circuits every
  `forkchoiceUpdated` to SYNCING and never builds payloads on a peerless devnet.
- **Wipe the VC slashing-protection DB** between chains. It persists in the VC
  datadir; a stale high-water-mark blocks signing the new chain's early slots and
  lighthouse silently never produces. (run-devnet.sh does this.)
- **ethrex genesis.json** needs `depositContractAddress` + `mixHash`. TTD=0 +
  `mergeNetsplitBlock:0` ⇒ Paris at block 0 (no Shanghai ⇒ Bellatrix window).
- **lighthouse testnet-dir** needs the file named `deposit_contract_block.txt`.
- **config.yaml** needs `SECONDS_PER_SLOT` (Heze-era consensus-specs dropped it
  from the config, but lighthouse v8 still requires it) and pharos needs
  `SLOT_DURATION_MS`.
- **One mnemonic** feeds both `eth2-testnet-genesis` (genesis validator set) and
  `lcli mnemonic-validators` (VC keys) so they match.
- **`lcli mock-el` is unusable** for merge-at-genesis (it makes its own EL genesis
  and can't consume a shared `genesis.json`) — use real ethrex.
- **Bellatrix = CL / Paris = EL**; this is the earliest fork that pairs with ethrex
  (ethrex is post-merge only).
