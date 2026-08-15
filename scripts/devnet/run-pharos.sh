#!/usr/bin/env bash
# Boot pharos's own ethrex EL + the pharos beacon node, peered to the running
# lighthouse BN (must already be up via run-devnet.sh). See README.md.
#
# Status: pharos checkpoint-syncs, dials the lighthouse bootnode, completes the
# Status handshake on the bellatrix fork-digest, and gossip-meshes. Full block
# FOLLOWING (head advancing) is NOT yet working — pending M5 backfill/sync work
# (real genesis_time threading + dialed-peer registration). See repo handoff.
set -Euo pipefail
D="${DEVNET_DIR:-$HOME/.cache/pharos-devnet}"
REPO="${PHAROS_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
PHAROS="${PHAROS_BIN:-$REPO/target/debug/pharos}"

[ -x "$PHAROS" ] || { echo "FATAL: pharos binary not at $PHAROS (cargo build -p pharos-node --bin pharos)"; exit 1; }

pkill -f 'ethrex --network .* --authrpc.port 28551' 2>/dev/null || true
pkill -f 'target/debug/pharos' 2>/dev/null || true
sleep 2
rm -rf "$D/el2" "$D/pharos-data"; mkdir -p "$D/el2"

# Lighthouse ENR (routable, advertises 127.0.0.1) from its log.
LH_ENR=$(rg -o 'enr:[A-Za-z0-9_-]+' "$D/bn.log" | tail -1)
[ -z "$LH_ENR" ] && { echo "FATAL: no lighthouse ENR in $D/bn.log (is run-devnet.sh up?)"; exit 1; }
echo "lighthouse ENR: ${LH_ENR:0:32}..."

echo "==== pharos's ethrex EL (authrpc 28551) ===="
setsid ethrex --network "$D/genesis.json" --datadir "$D/el2" --force \
  --syncmode full \
  --http.addr 127.0.0.1 --http.port 28545 \
  --authrpc.addr 127.0.0.1 --authrpc.port 28551 --authrpc.jwtsecret "$D/jwt.hex" \
  --p2p.disabled > "$D/ethrex-pharos.log" 2>&1 < /dev/null &
echo "pharos-ethrex pid $!"; sleep 3

echo "==== pharos beacon node (libp2p 9300, discv5 9301) ===="
# Ports 9300/9301 avoid 9000/9001 (lighthouse) and 9100 (prometheus node_exporter).
export RUST_LOG="${RUST_LOG:-info,pharos=info,pharos_node=info,pharos_network=info}"
setsid env RUST_BACKTRACE=1 RUST_LOG="$RUST_LOG" "$PHAROS" \
  --config-dir "$D/specdir/configs/pharos-devnet" \
  --checkpoint-sync-url http://127.0.0.1:5052 \
  --execution-endpoint http://127.0.0.1:28551 \
  --jwt-secret "$D/jwt.hex" \
  --bootnode "$LH_ENR" \
  --listen-addr /ip4/0.0.0.0/tcp/9300 \
  --discv5-port 9301 \
  --data-dir "$D/pharos-data" \
  > "$D/pharos.log" 2>&1 < /dev/null &
echo "pharos pid $!"
echo "logs: $D/{ethrex-pharos,pharos}.log"
echo "peered? curl -s http://127.0.0.1:5052/eth/v1/node/peer_count | jq .data  (or grep 'peers:' in bn.log)"
