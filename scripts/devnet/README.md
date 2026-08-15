# Cross-client Bellatrix devnet (M4d harness)

Hand-rolled, host-process (no Docker/Kurtosis) devnet for cross-client interop
testing: a **lighthouse** BN+VC + **ethrex** EL produce a live **Bellatrix**
chain (merge-at-genesis), and the **pharos** node peers in to follow it.

This is the M4d interop harness from `docs/roadmap.md`. Kurtosis replaces it at
M7 once the Beacon API ships.

## Current status (read before expecting miracles)

- ✅ Reference chain (lighthouse + ethrex) produces Bellatrix blocks.
- ✅ pharos checkpoint-syncs from lighthouse, dials its bootnode, completes the
  **Status handshake on the bellatrix fork-digest**, and gossip-meshes.
- ❌ pharos does **not** yet follow blocks to head — pending M5 sync/backfill work
  (thread real `genesis_time` from the anchor; register dialed peers for
  req-resp). See the repo handoff / `docs/decisions.md`.

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

# 3. (optional) peer pharos in
scripts/devnet/run-pharos.sh

# teardown
scripts/devnet/stop-devnet.sh
```

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
