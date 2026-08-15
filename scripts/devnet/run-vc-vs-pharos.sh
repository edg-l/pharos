#!/usr/bin/env bash
# M7 Beacon API cross-client read gate.
#
# Points an EXTERNAL lighthouse VC at the pharos Beacon API (http://127.0.0.1:5053,
# served by run-pharos.sh --http) and confirms the VC bootstraps and reads duties
# off pharos. Also runs a direct curl read-probe of the VC-critical endpoints.
#
# The gate is duties-READ + a stable connection, NOT attestation submission:
# block/attestation production + POST publish are M8. The lighthouse VC WILL log
# errors when it tries to POST-publish (pharos returns 501/405 there at M7); that
# is expected and does not fail the gate.
#
# Prereqs: run-devnet.sh (lighthouse BN + ethrex) up, then run-pharos.sh up and
# pharos following head (curl :5053/eth/v1/node/syncing -> is_syncing:false).
#
# Usage: ./run-vc-vs-pharos.sh            # probe + launch VC, stream its log
#        PROBE_ONLY=1 ./run-vc-vs-pharos.sh   # curl read-probe only, no VC
set -Euo pipefail
D="${DEVNET_DIR:-$HOME/.cache/pharos-devnet}"
PHAROS_API="${PHAROS_API:-http://127.0.0.1:5053}"

probe() {
  local path="$1" jqf="${2:-.}"
  local body code
  body=$(curl -s -w '\n%{http_code}' "$PHAROS_API$path")
  code=$(printf '%s' "$body" | tail -1)
  body=$(printf '%s' "$body" | sed '$d')
  if [ "$code" = "200" ]; then
    echo "  OK   $path"
    printf '%s' "$body" | jq -c "$jqf" 2>/dev/null | sed 's/^/         /' || true
  else
    echo "  FAIL $path  (HTTP $code)"
    printf '%s' "$body" | sed 's/^/         /'
    return 1
  fi
}

echo "==== M7 read-probe against pharos Beacon API ($PHAROS_API) ===="
# Reach the VC-critical surface: node health, config, genesis, head, duties.
HEAD_EPOCH=$(curl -s "$PHAROS_API/eth/v1/beacon/headers/head" \
  | jq -r '(.data.header.message.slot|tonumber) / 32 | floor' 2>/dev/null || echo 0)
[ -z "$HEAD_EPOCH" ] && HEAD_EPOCH=0
echo "head epoch: $HEAD_EPOCH"

rc=0
probe /eth/v1/node/version            '.data.version'          || rc=1
probe /eth/v1/node/syncing            '.data'                  || rc=1
probe /eth/v1/config/spec             '{SECONDS_PER_SLOT,CAPELLA_FORK_EPOCH}' || rc=1
probe /eth/v1/beacon/genesis          '.data'                  || rc=1
probe /eth/v1/beacon/headers/head     '.data.header.message.slot' || rc=1
probe "/eth/v1/validator/duties/proposer/$HEAD_EPOCH" '{dependent_root,n:(.data|length)}' || rc=1
probe "/eth/v1/beacon/states/head/validators?id=0,1,2" '{n:(.data|length)}' || rc=1

if [ "$rc" != 0 ]; then
  echo "READ-PROBE FAILED — fix before launching the VC."
  exit 1
fi
echo "read-probe: all VC-critical endpoints 200 OK."

if [ "${PROBE_ONLY:-0}" = "1" ]; then
  echo "PROBE_ONLY set — not launching VC."
  exit 0
fi

# Separate datadir + slashing-protection DB so this VC never collides with the
# reference-chain VC (run-devnet.sh) that signs the same interop keys.
VCDIR="$D/vc-vs-pharos"
pkill -f "lighthouse vc .* $VCDIR" 2>/dev/null || true
sleep 1
rm -rf "$VCDIR"; mkdir -p "$VCDIR"

echo "==== lighthouse VC -> pharos ($PHAROS_API), datadir $VCDIR ===="
echo "watch $D/vc-vs-pharos.log for 'Published'/'duties' reads; POST-publish errors are expected (M8)."
exec lighthouse vc \
  --testnet-dir "$D/testnet" \
  --datadir "$VCDIR" \
  --beacon-nodes "$PHAROS_API" \
  --init-slashing-protection \
  --suggested-fee-recipient 0x0000000000000000000000000000000000000001 \
  2>&1 | tee "$D/vc-vs-pharos.log"
