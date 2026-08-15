#!/usr/bin/env bash
# M9 validator gate: run `pharos-vc` against the pharos beacon node (:5053),
# signing the pharos-controlled validator set carved out by gen-testnet.sh.
#
# Topology (full M9 acceptance, Task 8.4):
#   ethrex (ref EL) + lighthouse BN + lighthouse VC   <- run-devnet.sh
#   ethrex (pharos EL) + pharos BN                     <- run-pharos.sh
#   pharos-vc -> pharos BN                             <- THIS script
# pharos-vc and the lighthouse VC sign DISJOINT validator sets (gen-testnet.sh
# moves the pharos-vc keys out of the lighthouse datadir), so a pharos-vc-proposed
# block is gossiped, imported by lighthouse, and the pharos validators' attestations
# land in later blocks — with no cross-client double-sign.
#
# Prereqs (in order):
#   1. scripts/devnet/gen-testnet.sh         (creates $D/pharos-vc-keys)
#   2. scripts/devnet/run-devnet.sh          (ref chain; head advancing)
#   3. scripts/devnet/run-pharos.sh          (pharos BN following head on :5053)
#   4. cargo build -p pharos-validator --bin pharos-vc
#
# Then watch $D/pharos-vc.log for "block published" / "attestation submitted",
# and the ref BN for the pharos-vc-proposed blocks:
#   curl -s :5052/eth/v2/beacon/blocks/head | jq '.data.message.body.execution_payload.fee_recipient'
#   (pharos-vc blocks carry fee_recipient 0x..02; lighthouse blocks 0x..01.)
#
# Usage: ./run-pharos-vc.sh
#        DOPPELGANGER=true ./run-pharos-vc.sh   # exercise the 2-epoch holdoff
set -Euo pipefail
D="${DEVNET_DIR:-$HOME/.cache/pharos-devnet}"
REPO="${PHAROS_REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
VC="${PHAROS_VC_BIN:-$REPO/target/debug/pharos-vc}"
PHAROS_API="${PHAROS_API:-http://127.0.0.1:5053}"
PVCK="$D/pharos-vc-keys/keystores"
PVCS="$D/pharos-vc-keys/secrets"
VCDATA="$D/pharos-vc-data"
DOPPELGANGER="${DOPPELGANGER:-false}"

[ -x "$VC" ] || { echo "FATAL: pharos-vc not at $VC (cargo build -p pharos-validator --bin pharos-vc)"; exit 1; }
[ -d "$PVCK" ] || { echo "FATAL: no pharos-vc keystores at $PVCK (run gen-testnet.sh first)"; exit 1; }
ls "$PVCK"/*.json >/dev/null 2>&1 || { echo "FATAL: no *.json keystores in $PVCK"; exit 1; }

# pharos-vc 503-skips every slot while the BN is optimistic/syncing. Surface that
# up front so a "no signatures" run is diagnosed as the BN, not the VC.
SYNC=$(curl -s "$PHAROS_API/eth/v1/node/syncing" | jq -c '.data' 2>/dev/null || echo 'unreachable')
echo "pharos BN $PHAROS_API syncing: $SYNC"
case "$SYNC" in
  *'"is_syncing":false'*'"is_optimistic":false'*|*'"is_optimistic":false'*'"is_syncing":false'*) ;;
  unreachable) echo "FATAL: pharos BN unreachable at $PHAROS_API (run-pharos.sh up?)"; exit 1 ;;
  *) echo "WARN: pharos BN not fully synced/canonical — pharos-vc will 503-skip slots until it follows head." ;;
esac

pkill -f "$VC " 2>/dev/null || true
sleep 1
rm -rf "$VCDATA"; mkdir -p "$VCDATA"

echo "==== pharos-vc -> pharos BN ($PHAROS_API) ===="
echo "keystores: $(ls "$PVCK"/*.json | wc -l)   doppelganger: $DOPPELGANGER   data: $VCDATA"
export RUST_LOG="${RUST_LOG:-info,pharos_validator=info}"
exec env RUST_BACKTRACE=1 RUST_LOG="$RUST_LOG" "$VC" \
  --beacon-node "$PHAROS_API" \
  --keystore-dir "$PVCK" \
  --secrets-dir "$PVCS" \
  --vc-data-dir "$VCDATA" \
  --suggested-fee-recipient 0x0000000000000000000000000000000000000002 \
  --doppelganger-protection "$DOPPELGANGER" \
  2>&1 | tee "$D/pharos-vc.log"
