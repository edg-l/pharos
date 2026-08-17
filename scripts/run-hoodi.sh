#!/usr/bin/env bash
# Run a long-lived Hoodi node: ethrex (EL) + pharos (beacon node), each in its
# own pane of a tmux split. ethrex has built-in Hoodi support (--network hoodi);
# the Hoodi CL config + bootnodes are fetched from the eth-clients/hoodi repo.
#
#   scripts/run-hoodi.sh            # build (if needed), fetch config, launch tmux
#   scripts/run-hoodi.sh --no-tmux  # run both with setsid + logs (headless soak)
#   tmux attach -t hoodi            # reattach later;  Ctrl-b d to detach
#   scripts/run-hoodi.sh stop       # kill both clients + the tmux session
#
# Override via env: HOODI_DIR, CHECKPOINT_URL, PHAROS_BIN, ETHREX_BIN,
# CONSENSUS_SPECS (presets source, default ~/dev/consensus-specs),
# TCP_PORT, DISCV5_PORT, HTTP_PORT, AUTHRPC_PORT, RUST_LOG, PHAROS_EXTRA.
set -Euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HOODI_DIR="${HOODI_DIR:-$HOME/.cache/pharos-hoodi}"
CL_CONFIG_REPO="https://github.com/eth-clients/hoodi"
CL_META="$HOODI_DIR/hoodi-meta"               # cloned eth-clients/hoodi
JWT="$HOODI_DIR/jwt.hex"

PHAROS_BIN="${PHAROS_BIN:-$REPO/target/release/pharos}"
ETHREX_BIN="${ETHREX_BIN:-$(command -v ethrex || true)}"

# Ports (mainnet-preset defaults; change only if they clash with another node).
AUTHRPC_PORT="${AUTHRPC_PORT:-8551}"          # ethrex Engine API  <- pharos
EL_HTTP_PORT="${EL_HTTP_PORT:-8545}"          # ethrex JSON-RPC
TCP_PORT="${TCP_PORT:-9000}"                  # pharos libp2p TCP
DISCV5_PORT="${DISCV5_PORT:-9000}"            # pharos discv5 UDP
HTTP_PORT="${HTTP_PORT:-5052}"                # pharos Beacon API
# A public Hoodi checkpoint-sync (Beacon API) endpoint. VERIFY/override if stale.
CHECKPOINT_URL="${CHECKPOINT_URL:-https://checkpoint-sync.hoodi.ethpandaops.io}"
RUST_LOG="${RUST_LOG:-info,pharos=info,pharos_node=info,pharos_network=info}"

say() { printf '\033[1;36m==== %s\033[0m\n' "$*"; }
die() { printf '\033[1;31mFATAL: %s\033[0m\n' "$*" >&2; exit 1; }

stop() {
  say "stopping Hoodi node"
  tmux kill-session -t hoodi 2>/dev/null || true
  pkill -f "ethrex --network hoodi" 2>/dev/null || true
  pkill -f "$PHAROS_BIN" 2>/dev/null || true
  echo "stopped."
}
[ "${1:-}" = "stop" ] && { stop; exit 0; }

NO_TMUX=0
[ "${1:-}" = "--no-tmux" ] && NO_TMUX=1

# ── preflight ────────────────────────────────────────────────────────────────
[ -n "$ETHREX_BIN" ] && [ -x "$ETHREX_BIN" ] || die "ethrex not found (set ETHREX_BIN=/path/to/ethrex)"

if [ ! -x "$PHAROS_BIN" ]; then
  say "building pharos (release)"
  ( cd "$REPO" && cargo build --release -p pharos-node --bin pharos ) || die "pharos build failed"
fi

mkdir -p "$HOODI_DIR" "$HOODI_DIR/ethrex" "$HOODI_DIR/pharos-data"

# Shared JWT for the Engine API (generate once, reuse across restarts).
if [ ! -s "$JWT" ]; then
  say "generating Engine API JWT secret -> $JWT"
  openssl rand -hex 32 > "$JWT" 2>/dev/null || head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$JWT"
fi

# Hoodi CL config (config.yaml) + CL bootnodes from eth-clients/hoodi.
if [ ! -d "$CL_META/.git" ]; then
  say "cloning Hoodi CL metadata ($CL_CONFIG_REPO)"
  git clone --depth 1 "$CL_CONFIG_REPO" "$CL_META" || die "clone of eth-clients/hoodi failed"
fi
# Layout-tolerant: find config.yaml and the CL bootnode list wherever they live.
CONFIG_YAML="$(find "$CL_META" -name config.yaml -print -quit 2>/dev/null || true)"
[ -n "$CONFIG_YAML" ] || die "config.yaml not found under $CL_META"
BOOTNODE_FILE="$(find "$CL_META" \( -name bootstrap_nodes.yaml -o -name bootstrap_nodes.txt -o -name boot_enr.yaml -o -name boot_enr.txt \) -print -quit 2>/dev/null || true)"

# pharos' --config-dir loader follows the consensus-specs layout: it reads
# <prefix>.yaml as the network config, then loads presets from
# <prefix>/../../presets/<PRESET_BASE>/*.yaml. The eth-clients/hoodi repo ships
# only a bare config.yaml (no sibling presets/), so assemble the expected tree
# under $HOODI_DIR/cfg: configs/hoodi.yaml + a presets/ symlink into
# consensus-specs. Pass the extension-less prefix configs/hoodi.
CONSENSUS_SPECS="${CONSENSUS_SPECS:-$HOME/dev/consensus-specs}"
PRESET_BASE="$(grep -E '^PRESET_BASE:' "$CONFIG_YAML" | head -1 | awk '{print $2}' | tr -d "'\"")"
PRESET_BASE="${PRESET_BASE:-mainnet}"
[ -d "$CONSENSUS_SPECS/presets/$PRESET_BASE" ] \
  || die "presets/$PRESET_BASE not found under $CONSENSUS_SPECS (set CONSENSUS_SPECS=/path/to/consensus-specs)"
CFG_ROOT="$HOODI_DIR/cfg"
mkdir -p "$CFG_ROOT/configs"
cp -f "$CONFIG_YAML" "$CFG_ROOT/configs/hoodi.yaml"
ln -sfn "$CONSENSUS_SPECS/presets" "$CFG_ROOT/presets"
CONFIG_PREFIX="$CFG_ROOT/configs/hoodi"

# Collect every `enr:...` token from the CL bootnode file into --bootnode flags.
PHAROS_BOOTNODES=()
if [ -n "$BOOTNODE_FILE" ]; then
  while IFS= read -r enr; do PHAROS_BOOTNODES+=(--bootnode "$enr"); done \
    < <(grep -oE 'enr:[A-Za-z0-9_-]+' "$BOOTNODE_FILE" | sort -u)
fi
say "Hoodi CL config: $CONFIG_PREFIX.yaml (preset=$PRESET_BASE)   (${#PHAROS_BOOTNODES[@]} bootnode flags, file: ${BOOTNODE_FILE:-none})"
[ "${#PHAROS_BOOTNODES[@]}" -gt 0 ] || echo "WARN: no CL bootnodes parsed; discv5 will rely on checkpoint peers only"

# ── command lines ────────────────────────────────────────────────────────────
ETHREX_CMD="$ETHREX_BIN --network hoodi --datadir $HOODI_DIR/ethrex \
  --syncmode full \
  --http.addr 127.0.0.1 --http.port $EL_HTTP_PORT \
  --authrpc.addr 127.0.0.1 --authrpc.port $AUTHRPC_PORT --authrpc.jwtsecret $JWT"

# shellcheck disable=SC2206
PHAROS_ARGS=(
  --config-dir "$CONFIG_PREFIX"
  --checkpoint-sync-url "$CHECKPOINT_URL"
  --execution-endpoint "http://127.0.0.1:$AUTHRPC_PORT"
  --jwt-secret "$JWT"
  --listen-addr "/ip4/0.0.0.0/tcp/$TCP_PORT"
  --discv5-port "$DISCV5_PORT"
  --http --http-address 127.0.0.1 --http-port "$HTTP_PORT"
  --data-dir "$HOODI_DIR/pharos-data"
  --log-file "$HOODI_DIR/pharos.log"
  "${PHAROS_BOOTNODES[@]}"
  ${PHAROS_EXTRA:-}
)

say "ethrex Engine API :$AUTHRPC_PORT   pharos Beacon API :$HTTP_PORT   libp2p :$TCP_PORT"

if [ "$NO_TMUX" = 1 ]; then
  say "headless mode (setsid + logs in $HOODI_DIR)"
  setsid bash -c "$ETHREX_CMD" > "$HOODI_DIR/ethrex.log" 2>&1 < /dev/null &
  echo "ethrex pid $!"; sleep 3
  setsid env RUST_LOG="$RUST_LOG" RUST_BACKTRACE=1 "$PHAROS_BIN" "${PHAROS_ARGS[@]}" \
    > "$HOODI_DIR/pharos.log" 2>&1 < /dev/null &
  echo "pharos pid $!"
  echo "logs: $HOODI_DIR/{ethrex,pharos}.log"
  echo "watch CL head: curl -s http://127.0.0.1:$HTTP_PORT/eth/v1/node/syncing | jq .data"
  exit 0
fi

# ── tmux split ───────────────────────────────────────────────────────────────
command -v tmux >/dev/null || die "tmux not installed"
tmux kill-session -t hoodi 2>/dev/null || true

# Pane 0 (left): ethrex. Pane 1 (right): pharos (started 3s later so the EL
# Engine API is listening). Quote the pharos argv safely for send-keys.
PHAROS_QUOTED=$(printf '%q ' "$PHAROS_BIN" "${PHAROS_ARGS[@]}")

tmux new-session -d -s hoodi -n node -x "$(tput cols 2>/dev/null || echo 200)" -y "$(tput lines 2>/dev/null || echo 50)"
tmux send-keys  -t hoodi:node "$ETHREX_CMD" C-m
tmux split-window -h -t hoodi:node
tmux send-keys  -t hoodi:node.1 "sleep 3; RUST_LOG='$RUST_LOG' RUST_BACKTRACE=1 $PHAROS_QUOTED" C-m
tmux select-pane -t hoodi:node.0
tmux set-option -t hoodi mouse on >/dev/null 2>&1 || true

# Tee each pane to a log file so a detached/headless soak is inspectable.
# pharos writes its own clean (non-ANSI, daily-rolling) file via --log-file
# ($HOODI_DIR/pharos.log.YYYY-MM-DD); capture ethrex's pane output here.
tmux pipe-pane -o -t hoodi:node.0 "cat >> '$HOODI_DIR/ethrex.log'"

say "launched tmux session 'hoodi' (left: ethrex, right: pharos)"
echo "  attach:  tmux attach -t hoodi      detach: Ctrl-b d      stop: $0 stop"
echo "  logs:    $HOODI_DIR/ethrex.log   $HOODI_DIR/pharos.log.<date>"
echo "  CL sync: curl -s http://127.0.0.1:$HTTP_PORT/eth/v1/node/syncing | jq .data"
echo "  peers:   curl -s http://127.0.0.1:$HTTP_PORT/eth/v1/node/peer_count | jq .data"

# Only attach when stdout is an interactive terminal; otherwise leave the
# session running detached (so this is safe to launch from automation).
if [ -t 1 ]; then
  tmux attach -t hoodi
else
  echo "  (no TTY) session 'hoodi' is running detached; attach with: tmux attach -t hoodi"
fi
