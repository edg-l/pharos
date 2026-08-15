#!/usr/bin/env bash
# Tear down the whole devnet: lighthouse BN/VC, both ethrex instances, pharos.
set -u
pkill -9 -f 'lighthouse bn'   2>/dev/null || true
pkill -9 -f 'lighthouse vc'   2>/dev/null || true
pkill -9 -f 'ethrex --network' 2>/dev/null || true
pkill -9 -f 'target/debug/pharos' 2>/dev/null || true
sleep 1
if ss -tuln 2>/dev/null | rg -q ':5052|:18551|:28551|:9000|:9300'; then
  echo "WARNING: some devnet ports still bound:"; ss -tuln 2>/dev/null | rg ':5052|:18551|:28551|:9000|:9300'
else
  echo "devnet stopped; ports free"
fi
