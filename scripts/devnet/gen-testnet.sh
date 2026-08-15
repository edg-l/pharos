#!/usr/bin/env bash
# Bellatrix-genesis -> Capella-transition devnet generator (pharos M6/M7 gate).
# Genesis is at Bellatrix; the network forks to Capella at CAPELLA_EPOCH so the
# live `upgrade_to_capella` path (D-live-fork-trigger-in-state-transition) fires
# and pharos must follow head PAST the fork with withdrawals applied. Produces,
# all mutually consistent from a single mnemonic + shared EL genesis.json:
#   - EL genesis.json (Bellatrix genesis; Shanghai/withdrawals at SHANGHAI_TIME)
#   - CL testnet-dir (config.yaml, genesis.ssz, deposit_contract_block.txt)
#   - interop validator keystores (lcli)
#   - a pharos --config-dir spec dir (config + mainnet presets), copied verbatim
#     from testnet/config.yaml so the two CL configs can never drift
#
# See README.md for prerequisites and the full run procedure.
set -Eeuo pipefail

# ---- knobs (override via env) ----------------------------------------------
D="${DEVNET_DIR:-$HOME/.cache/pharos-devnet}"          # runtime data (NOT in repo)
CS="${CONSENSUS_SPECS:-$HOME/dev/consensus-specs}"     # for mainnet presets
E2TG="${ETH2_TESTNET_GENESIS:-$HOME/go/bin/eth2-testnet-genesis}"
CHAINID="${CHAINID:-39438}"
DEPOSIT="${DEPOSIT_CONTRACT:-0x4242424242424242424242424242424242424242}"
COUNT="${VALIDATOR_COUNT:-64}"
SECONDS_PER_SLOT="${SECONDS_PER_SLOT:-12}"
SLOTS_PER_EPOCH=32                                     # mainnet preset
CAPELLA_EPOCH="${CAPELLA_EPOCH:-1}"                    # Bellatrix genesis -> Capella here
GENESIS_DELAY_SECS="${GENESIS_DELAY_SECS:-45}"         # genesis = now + this
FARFUTURE=18446744073709551615
# Public EF-style interop mnemonic (NOT a secret). Used by BOTH lcli and
# eth2-testnet-genesis so the VC keys == the genesis validator set.
MNEMONIC="${DEVNET_MNEMONIC:-giant issue aisle success illegal bike spike question tent bar rely arctic volcano long crawl hungry vocal artwork sniff fantasy very lucky have athlete}"

GENESIS_TIME=$(( $(date +%s) + GENESIS_DELAY_SECS ))
GENESIS_TIME_HEX=$(printf '0x%x' "$GENESIS_TIME")
# Shanghai (EIP-4895 withdrawals) activates on the EL at the Capella fork slot.
SHANGHAI_TIME=$(( GENESIS_TIME + CAPELLA_EPOCH * SLOTS_PER_EPOCH * SECONDS_PER_SLOT ))

command -v lcli >/dev/null || { echo "FATAL: lcli not on PATH (see README)"; exit 1; }
[ -x "$E2TG" ] || { echo "FATAL: eth2-testnet-genesis not at $E2TG (see README)"; exit 1; }
[ -d "$CS/presets/mainnet" ] || { echo "FATAL: consensus-specs presets not at $CS (set CONSENSUS_SPECS)"; exit 1; }

# Fresh chain each run: clear prior genesis/keys/specdir so lcli (which refuses
# to overwrite an existing validators dir) and the generators start clean.
rm -rf "$D/testnet" "$D/keys" "$D/specdir" "$D/tranches" "$D/genesis.json" "$D/mnemonics.yaml"
mkdir -p "$D/testnet" "$D/keys"

# ---- EL genesis.json (Bellatrix genesis; Shanghai/withdrawals at SHANGHAI_TIME) ----
# ethrex requires depositContractAddress + mixHash. TTD=0 + mergeNetsplitBlock:0
# => merged at block 0. shanghaiTime aligns the EL withdrawals fork to Capella.
cat > "$D/genesis.json" <<EOF
{
  "config": {
    "chainId": $CHAINID,
    "homesteadBlock": 0, "eip150Block": 0, "eip155Block": 0, "eip158Block": 0,
    "byzantiumBlock": 0, "constantinopleBlock": 0, "petersburgBlock": 0,
    "istanbulBlock": 0, "berlinBlock": 0, "londonBlock": 0,
    "mergeNetsplitBlock": 0,
    "terminalTotalDifficulty": 0,
    "shanghaiTime": $SHANGHAI_TIME,
    "depositContractAddress": "$DEPOSIT"
  },
  "alloc": {},
  "coinbase": "0x0000000000000000000000000000000000000000",
  "difficulty": "0x0",
  "extraData": "0x",
  "gasLimit": "0x1c9c380",
  "nonce": "0x0000000000000000",
  "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
  "timestamp": "$GENESIS_TIME_HEX",
  "baseFeePerGas": "0x3b9aca00"
}
EOF

# ---- CL config.yaml: mainnet base, Bellatrix genesis, Capella at CAPELLA_EPOCH ----
cp "$CS/configs/mainnet.yaml" "$D/testnet/config.yaml"
cfg="$D/testnet/config.yaml"
set_kv() { # key value
  if rg -q "^$1:" "$cfg"; then sed -i "s|^$1:.*|$1: $2|" "$cfg"; else echo "$1: $2" >> "$cfg"; fi
}
set_kv CONFIG_NAME "'pharos-devnet'"
set_kv SECONDS_PER_SLOT "$SECONDS_PER_SLOT"   # lighthouse v8 needs this in config (Heze-era specs dropped it)
set_kv MIN_GENESIS_ACTIVE_VALIDATOR_COUNT "$COUNT"
set_kv MIN_GENESIS_TIME "$GENESIS_TIME"
set_kv GENESIS_DELAY 0
set_kv ALTAIR_FORK_EPOCH 0
set_kv BELLATRIX_FORK_EPOCH 0
set_kv CAPELLA_FORK_EPOCH "$CAPELLA_EPOCH"
set_kv DENEB_FORK_EPOCH "$FARFUTURE"
set_kv ELECTRA_FORK_EPOCH "$FARFUTURE"
set_kv FULU_FORK_EPOCH "$FARFUTURE"
set_kv GLOAS_FORK_EPOCH "$FARFUTURE"
set_kv HEZE_FORK_EPOCH "$FARFUTURE"
set_kv TERMINAL_TOTAL_DIFFICULTY 0
set_kv TERMINAL_BLOCK_HASH 0x0000000000000000000000000000000000000000000000000000000000000000
set_kv DEPOSIT_CHAIN_ID "$CHAINID"
set_kv DEPOSIT_NETWORK_ID "$CHAINID"
set_kv DEPOSIT_CONTRACT_ADDRESS "$DEPOSIT"

# ---- mnemonics.yaml for eth2-testnet-genesis -------------------------------
cat > "$D/mnemonics.yaml" <<EOF
- mnemonic: "$MNEMONIC"
  count: $COUNT
EOF

echo "==== generating genesis.ssz (eth1-match-genesis-time) ===="
"$E2TG" bellatrix \
  --config="$cfg" \
  --mnemonics="$D/mnemonics.yaml" \
  --eth1-config="$D/genesis.json" \
  --eth1-match-genesis-time=true \
  --state-output="$D/testnet/genesis.ssz" \
  --tranches-dir="$D/tranches"

echo 0 > "$D/testnet/deposit_contract_block.txt"   # lighthouse expects this filename

# ---- sync pharos specdir config (single source of truth: testnet/config.yaml) ----
# pharos's --config-dir loader reads <dir>/configs/pharos-devnet.yaml plus
# <dir>/presets/<PRESET_BASE>/{phase0,altair,bellatrix,capella}.yaml. Copy the
# freshly generated CL config verbatim so CAPELLA_FORK_EPOCH / MIN_GENESIS_TIME
# can never drift between lighthouse and pharos (they drifted before automation).
SD="$D/specdir"
mkdir -p "$SD/configs" "$SD/presets/mainnet"
cp "$cfg" "$SD/configs/pharos-devnet.yaml"
cp "$CS/presets/mainnet/phase0.yaml"    "$SD/presets/mainnet/phase0.yaml"
cp "$CS/presets/mainnet/altair.yaml"    "$SD/presets/mainnet/altair.yaml"
cp "$CS/presets/mainnet/bellatrix.yaml" "$SD/presets/mainnet/bellatrix.yaml"
cp "$CS/presets/mainnet/capella.yaml"   "$SD/presets/mainnet/capella.yaml"

echo "==== deriving validator keystores (lcli, same mnemonic) ===="
lcli mnemonic-validators \
  --base-dir "$D/keys" \
  --count "$COUNT" \
  --mnemonic-phrase "$MNEMONIC" \
  --testnet-dir "$D/testnet" >/dev/null

echo "==== done ===="
echo "genesis_time=$GENESIS_TIME ($GENESIS_TIME_HEX)  data=$D"
echo "capella_fork_epoch=$CAPELLA_EPOCH  shanghai_time=$SHANGHAI_TIME (fork ~$(( CAPELLA_EPOCH * SLOTS_PER_EPOCH * SECONDS_PER_SLOT ))s after genesis)"
echo "validators: $(ls "$D/keys/validators" 2>/dev/null | grep -c '^0x' || echo 0) keystores"
