#!/usr/bin/env bash
# Boot the reference Bellatrix chain: ethrex EL + lighthouse BN + lighthouse VC.
# Run gen-testnet.sh first (fresh genesis), then this. See README.md.
set -Euo pipefail
D="${DEVNET_DIR:-$HOME/.cache/pharos-devnet}"

pkill -f 'ethrex --network' 2>/dev/null || true
pkill -f 'lighthouse bn' 2>/dev/null || true
pkill -f 'lighthouse vc' 2>/dev/null || true
sleep 2
rm -rf "$D/el" "$D/bn" "$D/vc"; mkdir -p "$D/el" "$D/bn" "$D/vc"

# CRITICAL: each launch pairs with a freshly regenerated genesis (new chain), so
# the VC slashing-protection DB from a prior chain is stale; its higher slot
# high-water-mark blocks the VC from signing the new chain's early slots (symptom:
# "Not signing slashable block: SlotViolatesLowerBound", lighthouse never produces).
# Wipe it; lighthouse re-creates it via --init-slashing-protection.
rm -f "$D/keys/validators/slashing_protection.sqlite"*

echo "==== ethrex EL (authrpc 18551) ===="
# --syncmode full is MANDATORY: default snap short-circuits every forkchoiceUpdated
# to SYNCING and never builds payloads on a peerless devnet.
setsid ethrex --network "$D/genesis.json" --datadir "$D/el" --force \
  --syncmode full \
  --http.addr 127.0.0.1 --http.port 18545 \
  --authrpc.addr 127.0.0.1 --authrpc.port 18551 --authrpc.jwtsecret "$D/jwt.hex" \
  --p2p.disabled > "$D/ethrex.log" 2>&1 < /dev/null &
echo "ethrex pid $!"; sleep 3

echo "==== lighthouse BN (http 5052, libp2p 9000) ===="
# --enr-address makes the ENR routable so pharos's discv5 can find it.
setsid lighthouse bn \
  --testnet-dir "$D/testnet" \
  --datadir "$D/bn" \
  --execution-endpoint http://127.0.0.1:18551 \
  --execution-jwt "$D/jwt.hex" \
  --http --http-address 127.0.0.1 --http-port 5052 \
  --disable-packet-filter \
  --enr-address 127.0.0.1 --enr-udp-port 9000 --enr-tcp-port 9000 \
  --target-peers 16 \
  --allow-insecure-genesis-sync \
  --suggested-fee-recipient 0x0000000000000000000000000000000000000001 \
  > "$D/bn.log" 2>&1 < /dev/null &
echo "bn pid $!"; sleep 5

echo "==== lighthouse VC ===="
# --datadir points at the lcli base-dir (has validators/ + secrets/).
setsid lighthouse vc \
  --testnet-dir "$D/testnet" \
  --datadir "$D/keys" \
  --beacon-nodes http://127.0.0.1:5052 \
  --init-slashing-protection \
  --suggested-fee-recipient 0x0000000000000000000000000000000000000001 \
  > "$D/vc.log" 2>&1 < /dev/null &
echo "vc pid $!"
echo "all started; logs in $D/{ethrex,bn,vc}.log"
echo "watch:  curl -s http://127.0.0.1:5052/eth/v2/beacon/blocks/head | jq -r .data.message.slot"
